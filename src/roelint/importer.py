from __future__ import annotations

import json
import re
import zipfile
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import yaml
from pypdf import PdfReader

from .config import ConfigError, read_yaml
from .scope import extract_targets

_INCLUDE_WORDS = (
    "in scope",
    "included",
    "authorized target",
    "permitted target",
    "scope includes",
    "kapsam dahil",
    "kapsama dahil",
    "kapsam içi",
    "izinli hedef",
    "test edilebilir",
)
_EXCLUDE_WORDS = (
    "out of scope",
    "excluded",
    "do not test",
    "must not test",
    "prohibited target",
    "kapsam dışı",
    "kapsam harici",
    "hariç tutulan",
    "test edilmeyecek",
    "dokunulmayacak",
    "yasak hedef",
)
_EXPIRY_WORDS = (
    "expires",
    "expiry",
    "valid until",
    "end date",
    "expiration",
    "bitiş tarihi",
    "geçerlilik tarihi",
    "geçerlilik sonu",
    "tarihine kadar geçerli",
)
_OWNER_WORDS = (
    "owner",
    "authorizer",
    "authorization contact",
    "security contact",
    "yetkili",
    "onaylayan",
    "güvenlik irtibat",
)
_PROHIBITED_WORDS = ("prohibited", "not permitted", "forbidden", "yasak", "izin verilmez")
_APPROVAL_WORDS = (
    "prior approval",
    "requires approval",
    "written approval",
    "ön onay",
    "onay gerektirir",
    "yazılı onay",
)
_TECHNIQUES = {
    "denial-of-service": ("denial of service", "ddos", "dos attack", "hizmet engelleme"),
    "data-destruction": ("data destruction", "delete data", "veri silme", "veri yok etme"),
    "phishing": ("phishing", "oltalama"),
    "credential-access": ("credential access", "password dumping", "kimlik bilgisi"),
    "social-engineering": ("social engineering", "sosyal mühendislik"),
}
_KNOWN_TOOLS = (
    "nmap",
    "nuclei",
    "curl",
    "burp",
    "sqlmap",
    "metasploit",
    "nessus",
    "masscan",
    "bloodhound",
)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_ISO_DATE_RE = re.compile(r"\b(20\d{2})-(0?[1-9]|1[0-2])-([0-2]?\d|3[01])\b")
_LOCAL_DATE_RE = re.compile(r"\b([0-2]?\d|3[01])[./](0?\d|1[0-2])[./](20\d{2})\b")


@dataclass(frozen=True)
class SourceLine:
    text: str
    page: int | None
    line: int


@dataclass(frozen=True)
class Evidence:
    field: str
    value: str
    confidence: float
    page: int | None
    line: int
    excerpt: str


@dataclass(frozen=True)
class ImportResult:
    policy: dict[str, Any]
    evidence: tuple[Evidence, ...]
    unresolved: tuple[str, ...]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def extract_document(path: Path) -> list[SourceLine]:
    if not path.exists():
        raise ConfigError(f"file not found: {path}")
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return _extract_pdf(path)
    if suffix == ".docx":
        return _extract_docx(path)
    if suffix in {".txt", ".md"}:
        return _to_source_lines(path.read_text(encoding="utf-8"), page=None)
    raise ConfigError("unsupported ROE document; use PDF, DOCX, TXT, or Markdown")


def _to_source_lines(text: str, page: int | None) -> list[SourceLine]:
    return [
        SourceLine(raw.strip(), page, line_number)
        for line_number, raw in enumerate(text.splitlines(), start=1)
        if raw.strip()
    ]


def _extract_pdf(path: Path) -> list[SourceLine]:
    try:
        reader = PdfReader(path)
        lines: list[SourceLine] = []
        for page_number, page in enumerate(reader.pages, start=1):
            lines.extend(_to_source_lines(page.extract_text() or "", page=page_number))
    except Exception as exc:
        raise ConfigError(f"could not read PDF: {exc}") from exc
    if not lines:
        raise ConfigError("PDF contains no extractable text; OCR is required for scanned documents")
    return lines


def _extract_docx(path: Path) -> list[SourceLine]:
    try:
        with zipfile.ZipFile(path) as archive:
            xml = archive.read("word/document.xml")
        root = ElementTree.fromstring(xml)
    except (OSError, KeyError, zipfile.BadZipFile, ElementTree.ParseError) as exc:
        raise ConfigError(f"could not read DOCX: {exc}") from exc
    namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    paragraphs = []
    for paragraph in root.iter(f"{namespace}p"):
        text = "".join(node.text or "" for node in paragraph.iter(f"{namespace}t")).strip()
        if text:
            paragraphs.append(text)
    return _to_source_lines("\n".join(paragraphs), page=None)


def _contains(text: str, phrases: tuple[str, ...]) -> bool:
    lowered = text.casefold()
    return any(phrase in lowered for phrase in phrases)


def _parse_date(text: str) -> str | None:
    match = _ISO_DATE_RE.search(text)
    if match:
        value = date(int(match[1]), int(match[2]), int(match[3]))
        return value.isoformat()
    match = _LOCAL_DATE_RE.search(text)
    if match:
        try:
            value = date(int(match[3]), int(match[2]), int(match[1]))
        except ValueError:
            return None
        return value.isoformat()
    return None


def import_roe(
    path: Path,
    *,
    engagement_id: str | None = None,
    owner_override: str | None = None,
    expires_override: str | None = None,
) -> ImportResult:
    lines = extract_document(path)
    include: set[str] = set()
    exclude: set[str] = set()
    ambiguous: set[str] = set()
    evidence: list[Evidence] = []
    owner: str | None = owner_override
    expires: str | None = expires_override
    section: str | None = None
    prohibited: set[str] = set()
    approval_required: set[str] = set()
    allowed_tools: set[str] = set()

    for source in lines:
        lowered = source.text.casefold()
        targets = extract_targets(source.text)
        line_disposition: str | None = None
        if _contains(lowered, _EXCLUDE_WORDS):
            line_disposition = "exclude"
            if not targets and len(source.text) < 120:
                section = "exclude"
        elif _contains(lowered, _INCLUDE_WORDS):
            line_disposition = "include"
            if not targets and len(source.text) < 120:
                section = "include"

        disposition = line_disposition or section
        for target in targets:
            if disposition == "exclude":
                exclude.add(target)
                confidence = 0.98 if line_disposition else 0.90
                field = "scope.exclude"
            elif disposition == "include":
                include.add(target)
                confidence = 0.96 if line_disposition else 0.88
                field = "scope.include"
            else:
                ambiguous.add(target)
                confidence = 0.45
                field = "scope.unresolved"
            evidence.append(
                Evidence(field, target, confidence, source.page, source.line, source.text[:240])
            )

        parsed_date = _parse_date(source.text)
        if expires is None and parsed_date and _contains(lowered, _EXPIRY_WORDS):
            expires = parsed_date
            evidence.append(
                Evidence(
                    "authorization.expires",
                    expires,
                    0.94,
                    source.page,
                    source.line,
                    source.text[:240],
                )
            )

        emails = _EMAIL_RE.findall(source.text)
        if owner is None and emails and _contains(lowered, _OWNER_WORDS):
            owner = emails[0]
            evidence.append(
                Evidence(
                    "authorization.owner",
                    owner,
                    0.90,
                    source.page,
                    source.line,
                    source.text[:240],
                )
            )

        for technique, aliases in _TECHNIQUES.items():
            if not any(alias in lowered for alias in aliases):
                continue
            if _contains(lowered, _PROHIBITED_WORDS):
                prohibited.add(technique)
                field = "rules.prohibited_techniques"
            elif _contains(lowered, _APPROVAL_WORDS):
                approval_required.add(technique)
                field = "rules.approval_required"
            else:
                continue
            evidence.append(
                Evidence(field, technique, 0.86, source.page, source.line, source.text[:240])
            )

        if _contains(lowered, _INCLUDE_WORDS):
            for tool in _KNOWN_TOOLS:
                if re.search(rf"\b{re.escape(tool)}\b", lowered):
                    allowed_tools.add(tool)
                    evidence.append(
                        Evidence(
                            "rules.allowed_tools",
                            tool,
                            0.84,
                            source.page,
                            source.line,
                            source.text[:240],
                        )
                    )

    include.difference_update(exclude)
    ambiguous.difference_update(include | exclude)
    unresolved: list[str] = []
    if not include:
        unresolved.append("scope.include")
    if ambiguous:
        unresolved.append("scope.unresolved")
    if owner is None:
        unresolved.append("authorization.owner")
    if expires is None:
        unresolved.append("authorization.expires")

    policy: dict[str, Any] = {
        "version": 1,
        "review": {
            "status": "draft",
            "source": path.name,
            "extracted_at": _now(),
            "unresolved": unresolved,
        },
        "engagement": {"id": engagement_id or _engagement_id(path)},
        "authorization": {
            "owner": owner or "REVIEW_REQUIRED",
            "expires": expires or "REVIEW_REQUIRED",
        },
        "scope": {
            "include": sorted(include),
            "exclude": sorted(exclude),
            "unresolved": sorted(ambiguous),
        },
        "rules": {
            "allowed_tools": sorted(allowed_tools),
            "prohibited_techniques": sorted(prohibited),
            "approval_required": sorted(approval_required),
        },
        "approvals": {},
    }
    return ImportResult(policy, tuple(evidence), tuple(unresolved))


def _engagement_id(path: Path) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "-", path.stem).strip("-").upper()
    return value or "ROE-IMPORT"


def write_import(result: ImportResult, policy_path: Path, report_path: Path) -> None:
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        yaml.safe_dump(result.policy, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    report = {
        "status": "review_required",
        "policy": str(policy_path),
        "unresolved": list(result.unresolved),
        "evidence": [asdict(item) for item in result.evidence],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def approve_policy(source: Path, output: Path, reviewed_by: str) -> None:
    data = read_yaml(source)
    review = data.get("review")
    if not isinstance(review, dict) or review.get("status") != "draft":
        raise ConfigError("only an imported draft policy can be approved")
    scope = data.get("scope")
    authorization = data.get("authorization")
    unresolved: list[str] = []
    if not isinstance(scope, dict):
        raise ConfigError("draft scope must be a mapping")
    if not isinstance(authorization, dict):
        raise ConfigError("draft authorization must be a mapping")
    if not scope.get("include"):
        unresolved.append("scope.include")
    elif scope.get("unresolved"):
        unresolved.append("scope.unresolved")
    if "REVIEW_REQUIRED" in authorization.values():
        unresolved.append("authorization")
    if unresolved:
        raise ConfigError(
            "draft has unresolved fields: "
            + ", ".join(unresolved)
            + "; correct the draft or re-import with --owner/--expires"
        )
    review.update(
        {
            "status": "approved",
            "reviewed_by": reviewed_by,
            "reviewed_at": _now(),
            "unresolved": [],
        }
    )
    scope.pop("unresolved", None)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
