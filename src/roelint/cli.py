from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .config import ConfigError, load_policy, load_steps
from .engine import lint
from .reporters import as_json, as_sarif, as_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="roelint",
        description="Pre-flight safety checks for authorized red-team playbooks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    check = subparsers.add_parser("check", help="lint a playbook against an ROE policy")
    check.add_argument("playbook", type=Path)
    check.add_argument("--policy", "-p", type=Path, required=True)
    check.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    check.add_argument("--output", "-o", type=Path)
    check.add_argument("--fail-on", choices=("warning", "error"), default="error")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        steps = load_steps(args.playbook)
        findings = lint(policy, steps, today=date.today())
    except ConfigError as exc:
        print(f"roelint: configuration error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = as_json(findings)
    elif args.format == "sarif":
        rendered = as_sarif(findings, args.playbook)
    else:
        rendered = as_text(findings)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    severities = {item.severity for item in findings}
    if "error" in severities or (args.fail_on == "warning" and "warning" in severities):
        return 1
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
