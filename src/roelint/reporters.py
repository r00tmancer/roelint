from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding

RULES = {
    "ROE001": "Authorization is valid",
    "ROE002": "Target is inside scope",
    "ROE003": "Tool is approved",
    "ROE004": "Technique is permitted",
    "ROE005": "Required approval is present",
    "ROE006": "Operation is non-destructive",
    "ROE007": "Command contains no plaintext secret",
    "ROE008": "Target is statically verifiable",
    "ROE009": "Command is parseable",
}


def as_json(findings: list[Finding]) -> str:
    return json.dumps(
        {"tool": "roelint", "version": "0.1.0", "findings": [item.as_dict() for item in findings]},
        indent=2,
    )


def as_text(findings: list[Finding]) -> str:
    if not findings:
        return "ROE-Lint: PASS - no policy violations found"
    icons = {"error": "ERROR", "warning": "WARN ", "note": "NOTE "}
    lines = []
    for item in findings:
        location = f" [{item.step_id}]" if item.step_id else ""
        lines.append(f"{icons[item.severity]} {item.rule_id}{location} {item.message}")
        if item.help:
            lines.append(f"      help: {item.help}")
    errors = sum(item.severity == "error" for item in findings)
    warnings = sum(item.severity == "warning" for item in findings)
    lines.append(f"\nROE-Lint: {errors} error(s), {warnings} warning(s)")
    return "\n".join(lines)


def as_sarif(findings: list[Finding], playbook: Path) -> str:
    rules: list[dict[str, Any]] = [
        {
            "id": rule_id,
            "shortDescription": {"text": description},
            "helpUri": "https://github.com/r00tmancer/roelint#rules",
        }
        for rule_id, description in RULES.items()
    ]
    levels = {"error": "error", "warning": "warning", "note": "note"}
    results = []
    for item in findings:
        result: dict[str, Any] = {
            "ruleId": item.rule_id,
            "level": levels[item.severity],
            "message": {"text": item.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": playbook.as_posix()},
                    },
                    "logicalLocations": (
                        [{"name": item.step_id, "kind": "step"}] if item.step_id else []
                    ),
                }
            ],
        }
        results.append(result)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ROE-Lint", "version": "0.1.0", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
