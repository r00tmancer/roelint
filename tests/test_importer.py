import json
import zipfile
from pathlib import Path

import pytest
import yaml

from roelint.config import ConfigError, load_policy
from roelint.importer import approve_policy, extract_document, import_roe, write_import


def test_imports_english_roe_with_evidence(tmp_path: Path) -> None:
    source = tmp_path / "client-roe.txt"
    source.write_text(
        """Authorization owner: security@client.example
Valid until: 31.12.2099
In scope
10.20.0.0/16
*.lab.client.example
Out of scope
10.20.10.50
payments.lab.client.example
Permitted targets may be assessed with nmap and nuclei.
Denial of service is prohibited.
Credential access requires prior approval.
""",
        encoding="utf-8",
    )
    result = import_roe(source)
    assert result.policy["authorization"] == {
        "owner": "security@client.example",
        "expires": "2099-12-31",
    }
    assert result.policy["scope"]["include"] == ["*.lab.client.example", "10.20.0.0/16"]
    assert result.policy["scope"]["exclude"] == [
        "10.20.10.50",
        "payments.lab.client.example",
    ]
    assert result.policy["rules"]["allowed_tools"] == ["nmap", "nuclei"]
    assert result.policy["rules"]["prohibited_techniques"] == ["denial-of-service"]
    assert result.policy["rules"]["approval_required"] == ["credential-access"]
    assert result.unresolved == ()
    assert all(item.excerpt for item in result.evidence)


def test_imports_turkish_scope_terms(tmp_path: Path) -> None:
    source = tmp_path / "sozlesme.txt"
    source.write_text(
        """Yetkili: guvenlik@firma.example
Geçerlilik sonu: 15.09.2099
Kapsam içi
172.16.0.0/16
Kapsam dışı
172.16.10.10
Oltalama için ön onay gereklidir.
Veri silme yasaktır.
""",
        encoding="utf-8",
    )
    result = import_roe(source)
    assert result.policy["scope"]["include"] == ["172.16.0.0/16"]
    assert result.policy["scope"]["exclude"] == ["172.16.10.10"]
    assert result.policy["rules"]["approval_required"] == ["phishing"]
    assert result.policy["rules"]["prohibited_techniques"] == ["data-destruction"]


def test_ambiguous_target_is_not_silently_included(tmp_path: Path) -> None:
    source = tmp_path / "unclear.txt"
    source.write_text("Host mentioned: mystery.example.net", encoding="utf-8")
    result = import_roe(source, owner_override="owner@example.test", expires_override="2099-12-31")
    assert result.policy["scope"]["include"] == []
    assert result.policy["scope"]["unresolved"] == ["mystery.example.net"]
    assert "scope.include" in result.unresolved
    assert "scope.unresolved" in result.unresolved


def test_draft_must_be_approved_before_linting(tmp_path: Path) -> None:
    source = tmp_path / "roe.txt"
    source.write_text("In scope: 10.20.0.0/16", encoding="utf-8")
    result = import_roe(source, owner_override="owner@example.test", expires_override="2099-12-31")
    draft = tmp_path / "roe.draft.yml"
    report = tmp_path / "roe.review.json"
    write_import(result, draft, report)
    with pytest.raises(ConfigError, match="still a draft"):
        load_policy(draft)
    report_data = json.loads(report.read_text(encoding="utf-8"))
    assert report_data["evidence"][0]["page"] is None

    approved = tmp_path / "roe.yml"
    approve_policy(draft, approved, "Analyst Name")
    loaded = load_policy(approved)
    assert loaded.include == ("10.20.0.0/16",)
    approved_data = yaml.safe_load(approved.read_text(encoding="utf-8"))
    assert approved_data["review"]["status"] == "approved"
    assert approved_data["review"]["reviewed_by"] == "Analyst Name"


def test_unresolved_draft_cannot_be_approved(tmp_path: Path) -> None:
    source = tmp_path / "roe.txt"
    source.write_text("In scope: 10.20.0.0/16", encoding="utf-8")
    result = import_roe(source)
    draft = tmp_path / "roe.draft.yml"
    write_import(result, draft, tmp_path / "report.json")
    with pytest.raises(ConfigError, match="unresolved fields"):
        approve_policy(draft, tmp_path / "approved.yml", "Reviewer")


def test_extracts_basic_docx_without_external_word_library(tmp_path: Path) -> None:
    document = tmp_path / "roe.docx"
    xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>In scope: 10.20.0.0/16</w:t></w:r></w:p></w:body>
</w:document>"""
    with zipfile.ZipFile(document, "w") as archive:
        archive.writestr("word/document.xml", xml)
    lines = extract_document(document)
    assert lines[0].text == "In scope: 10.20.0.0/16"


def test_unsupported_document_type_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "roe.rtf"
    source.write_text("text", encoding="utf-8")
    with pytest.raises(ConfigError, match="unsupported"):
        extract_document(source)
