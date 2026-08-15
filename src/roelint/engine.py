from __future__ import annotations

import re
import shlex
from datetime import date

from .models import Finding, Policy, Step
from .scope import extract_targets, normalize_target, target_status

_DYNAMIC_TARGET_RE = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_][A-Za-z0-9_]*")
_SECRET_RULES = (
    re.compile(r"(?i)(?:--password|--passwd|-p)\s+(?!\$|\{)[^\s]+"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
_DESTRUCTIVE_RULES = (
    (re.compile(r"(?i)(?:^|[;&|]\s*)rm\s+-[^\n]*(?:r[^\n]*f|f[^\n]*r)"), "recursive deletion"),
    (re.compile(r"(?i)\b(?:shutdown|reboot|poweroff)\b"), "host shutdown or reboot"),
    (re.compile(r"(?i)\b(?:drop\s+(?:table|database)|truncate\s+table)\b"), "data destruction"),
    (re.compile(r"(?i)\b(?:mkfs(?:\.[a-z0-9]+)?|format\s+[a-z]:)\b"), "filesystem formatting"),
)


def _tool_name(command: str) -> str | None:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    while tokens and ("=" in tokens[0] and not tokens[0].startswith(("=", "-"))):
        tokens.pop(0)
    while tokens and tokens[0].lower() in {"sudo", "env", "command", "timeout"}:
        tokens.pop(0)
        while tokens and tokens[0].startswith("-"):
            tokens.pop(0)
    if not tokens:
        return None
    return tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()


def lint(policy: Policy, steps: list[Step], *, today: date | None = None) -> list[Finding]:
    findings: list[Finding] = []
    today = today or date.today()
    try:
        expires = date.fromisoformat(policy.expires)
    except ValueError:
        findings.append(
            Finding(
                "ROE001",
                "error",
                "authorization.expires must use YYYY-MM-DD",
                field="authorization.expires",
            )
        )
    else:
        if expires < today:
            findings.append(
                Finding(
                    "ROE001",
                    "error",
                    f"authorization expired on {expires.isoformat()}",
                    field="authorization.expires",
                    help="Renew written authorization before executing the playbook.",
                )
            )

    for step in steps:
        findings.extend(_lint_step(policy, step))
    return sorted(
        findings,
        key=lambda item: (
            {"error": 0, "warning": 1, "note": 2}[item.severity],
            item.step_id or "",
            item.rule_id,
        ),
    )


def _lint_step(policy: Policy, step: Step) -> list[Finding]:
    findings: list[Finding] = []
    tool = _tool_name(step.command)
    if tool is None:
        findings.append(Finding("ROE009", "error", "command cannot be parsed", step.id, "command"))
    elif policy.allowed_tools and tool not in {item.lower() for item in policy.allowed_tools}:
        findings.append(
            Finding(
                "ROE003",
                "error",
                f"tool '{tool}' is not in rules.allowed_tools",
                step.id,
                "command",
                "Add it to the reviewed allow-list or use an approved tool.",
            )
        )

    targets = {normalize_target(item) for item in step.targets} | extract_targets(step.command)
    if not targets:
        findings.append(
            Finding(
                "ROE008",
                "warning",
                "no statically verifiable target found",
                step.id,
                "targets",
                "Declare step.targets explicitly so scope can be proven before execution.",
            )
        )
    for target in sorted(targets):
        status = target_status(target, policy.include, policy.exclude)
        if status == "excluded":
            findings.append(
                Finding(
                    "ROE002",
                    "error",
                    f"target '{target}' is explicitly excluded",
                    step.id,
                    "targets",
                    _source_help(policy, "scope.exclude", target, match_target=True),
                )
            )
        elif status == "outside":
            findings.append(
                Finding(
                    "ROE002",
                    "error",
                    f"target '{target}' is outside engagement scope",
                    step.id,
                    "targets",
                )
            )

    if _DYNAMIC_TARGET_RE.search(step.command):
        findings.append(
            Finding(
                "ROE008",
                "warning",
                "command contains dynamic shell expansion that static scope checks cannot resolve",
                step.id,
                "command",
                "Declare the resolved value in step.targets and avoid runtime target construction.",
            )
        )

    technique = step.technique.lower()
    prohibited = {item.lower() for item in policy.prohibited_techniques}
    if technique and technique in prohibited:
        findings.append(
            Finding(
                "ROE004",
                "error",
                f"technique '{step.technique}' is prohibited",
                step.id,
                "technique",
            )
        )

    approval_required = {item.lower() for item in policy.approval_required}
    if technique in approval_required and (
        not step.approval or step.approval not in policy.approvals
    ):
        findings.append(
            Finding(
                "ROE005",
                "error",
                f"technique '{step.technique}' requires a valid approval",
                step.id,
                "approval",
            )
        )

    for pattern, label in _DESTRUCTIVE_RULES:
        if pattern.search(step.command):
            findings.append(
                Finding(
                    "ROE006",
                    "error",
                    f"potentially destructive operation detected: {label}",
                    step.id,
                    "command",
                )
            )
            break

    if any(pattern.search(step.command) for pattern in _SECRET_RULES):
        findings.append(
            Finding(
                "ROE007",
                "error",
                "possible plaintext credential or token in command",
                step.id,
                "command",
                "Use a secret manager or an environment reference supplied at runtime.",
            )
        )
    return findings


def _source_help(
    policy: Policy, field: str, value: str, *, match_target: bool = False
) -> str | None:
    for item in policy.evidence:
        if item.field != field:
            continue
        matches = item.value == value
        if match_target:
            matches = target_status(value, (), (item.value,)) == "excluded"
        if not matches:
            continue
        location = f"page {item.page}, line {item.line}" if item.page else f"line {item.line}"
        return f'Source: {item.source}, {location} - "{item.excerpt}"'
    return None
