from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["note", "warning", "error"]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    step_id: str | None = None
    field: str | None = None
    help: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "rule_id": self.rule_id,
                "severity": self.severity,
                "message": self.message,
                "step_id": self.step_id,
                "field": self.field,
                "help": self.help,
            }.items()
            if value is not None
        }


@dataclass(frozen=True)
class Step:
    id: str
    command: str
    name: str = ""
    technique: str = ""
    targets: tuple[str, ...] = ()
    approval: str | None = None


@dataclass(frozen=True)
class Policy:
    engagement_id: str
    owner: str
    expires: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    prohibited_techniques: tuple[str, ...] = ()
    approval_required: tuple[str, ...] = ()
    approvals: frozenset[str] = field(default_factory=frozenset)
    max_rate_per_second: int | None = None
