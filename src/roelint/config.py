from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Policy, Step


class ConfigError(ValueError):
    pass


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be a list of strings")
    return tuple(value)


def read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    return _mapping(raw, str(path))


def load_policy(path: Path) -> Policy:
    data = read_yaml(path)
    if data.get("version") != 1:
        raise ConfigError("policy version must be 1")
    engagement = _mapping(data.get("engagement"), "engagement")
    authorization = _mapping(data.get("authorization"), "authorization")
    scope = _mapping(data.get("scope"), "scope")
    rules = _mapping(data.get("rules", {}), "rules")
    approvals_raw = _mapping(data.get("approvals", {}), "approvals")

    required = {
        "engagement.id": engagement.get("id"),
        "authorization.owner": authorization.get("owner"),
        "authorization.expires": authorization.get("expires"),
    }
    missing = [name for name, value in required.items() if not isinstance(value, str) or not value]
    if missing:
        raise ConfigError("missing required fields: " + ", ".join(missing))

    include = _strings(scope.get("include"), "scope.include")
    if not include:
        raise ConfigError("scope.include must contain at least one target")

    max_rate = rules.get("max_rate_per_second")
    if max_rate is not None and (not isinstance(max_rate, int) or max_rate < 1):
        raise ConfigError("rules.max_rate_per_second must be a positive integer")

    approval_ids = frozenset(
        approval_id
        for approval_id, value in approvals_raw.items()
        if isinstance(approval_id, str)
        and isinstance(value, dict)
        and value.get("approved") is True
    )
    return Policy(
        engagement_id=engagement["id"],
        owner=authorization["owner"],
        expires=authorization["expires"],
        include=include,
        exclude=_strings(scope.get("exclude"), "scope.exclude"),
        allowed_tools=_strings(rules.get("allowed_tools"), "rules.allowed_tools"),
        prohibited_techniques=_strings(
            rules.get("prohibited_techniques"), "rules.prohibited_techniques"
        ),
        approval_required=_strings(rules.get("approval_required"), "rules.approval_required"),
        approvals=approval_ids,
        max_rate_per_second=max_rate,
    )


def load_steps(path: Path) -> list[Step]:
    data = read_yaml(path)
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ConfigError("playbook.steps must be a non-empty list")

    steps: list[Step] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_steps, start=1):
        item = _mapping(raw, f"steps[{index}]")
        step_id = item.get("id")
        command = item.get("command")
        if not isinstance(step_id, str) or not step_id:
            raise ConfigError(f"steps[{index}].id must be a non-empty string")
        if step_id in seen:
            raise ConfigError(f"duplicate step id: {step_id}")
        if not isinstance(command, str) or not command.strip():
            raise ConfigError(f"steps[{index}].command must be a non-empty string")
        seen.add(step_id)
        targets = _strings(item.get("targets"), f"steps[{index}].targets")
        name = item.get("name", "")
        technique = item.get("technique", "")
        approval = item.get("approval")
        if not isinstance(name, str) or not isinstance(technique, str):
            raise ConfigError(f"steps[{index}] name and technique must be strings")
        if approval is not None and not isinstance(approval, str):
            raise ConfigError(f"steps[{index}].approval must be a string")
        steps.append(Step(step_id, command, name, technique, targets, approval))
    return steps
