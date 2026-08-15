from datetime import date

from roelint.engine import lint
from roelint.models import Policy, SourceEvidence, Step


def policy(**changes: object) -> Policy:
    values = {
        "engagement_id": "test",
        "owner": "owner@example.test",
        "expires": "2099-12-31",
        "include": ("10.20.0.0/16", "*.lab.example"),
        "exclude": ("10.20.10.50",),
        "allowed_tools": ("nmap", "curl", "nuclei"),
        "prohibited_techniques": ("denial-of-service",),
        "approval_required": ("credential-access",),
        "approvals": frozenset({"OK-1"}),
    }
    values.update(changes)
    return Policy(**values)  # type: ignore[arg-type]


def rule_ids(findings: list[object]) -> set[str]:
    return {finding.rule_id for finding in findings}  # type: ignore[attr-defined]


def test_safe_playbook_passes() -> None:
    steps = [Step("scan", "nmap -sV 10.20.4.0/24", targets=("10.20.4.0/24",))]
    assert lint(policy(), steps, today=date(2026, 1, 1)) == []


def test_excluded_target_is_blocked() -> None:
    findings = lint(policy(), [Step("scan", "nmap 10.20.10.50")], today=date(2026, 1, 1))
    assert "ROE002" in rule_ids(findings)
    assert "explicitly excluded" in findings[0].message


def test_outside_url_is_blocked() -> None:
    findings = lint(
        policy(), [Step("web", "curl https://outside.example.net")], today=date(2026, 1, 1)
    )
    assert "ROE002" in rule_ids(findings)


def test_unapproved_tool_is_blocked() -> None:
    findings = lint(policy(), [Step("x", "customtool 10.20.1.2")], today=date(2026, 1, 1))
    assert "ROE003" in rule_ids(findings)


def test_prohibited_technique_is_blocked() -> None:
    step = Step("x", "nmap 10.20.1.2", technique="denial-of-service")
    assert "ROE004" in rule_ids(lint(policy(), [step], today=date(2026, 1, 1)))


def test_required_approval_is_enforced() -> None:
    step = Step("x", "nuclei -u https://api.lab.example", technique="credential-access")
    assert "ROE005" in rule_ids(lint(policy(), [step], today=date(2026, 1, 1)))
    approved = Step(
        "x", "nuclei -u https://api.lab.example", technique="credential-access", approval="OK-1"
    )
    assert "ROE005" not in rule_ids(lint(policy(), [approved], today=date(2026, 1, 1)))


def test_destructive_command_is_blocked() -> None:
    step = Step("x", "rm -rf /tmp/target", targets=("10.20.1.2",))
    assert "ROE006" in rule_ids(lint(policy(allowed_tools=()), [step], today=date(2026, 1, 1)))


def test_plaintext_secret_is_blocked() -> None:
    step = Step("x", "curl --password supersecret https://api.lab.example")
    assert "ROE007" in rule_ids(lint(policy(), [step], today=date(2026, 1, 1)))


def test_dynamic_target_gets_warning() -> None:
    step = Step("x", "nmap $TARGET", targets=("10.20.1.2",))
    assert "ROE008" in rule_ids(lint(policy(), [step], today=date(2026, 1, 1)))


def test_expired_authorization_is_blocked() -> None:
    findings = lint(policy(expires="2025-01-01"), [], today=date(2026, 1, 1))
    assert "ROE001" in rule_ids(findings)


def test_excluded_target_finding_cites_source_evidence() -> None:
    evidence = (
        SourceEvidence(
            "scope.exclude",
            "10.20.10.0/24",
            "client-roe.pdf",
            4,
            18,
            "Payment production systems must not be tested.",
        ),
    )
    findings = lint(
        policy(evidence=evidence),
        [Step("scan", "nmap 10.20.10.50")],
        today=date(2026, 1, 1),
    )
    assert findings[0].help is not None
    assert "client-roe.pdf, page 4, line 18" in findings[0].help
