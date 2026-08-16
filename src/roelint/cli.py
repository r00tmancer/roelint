from __future__ import annotations

import argparse
import shlex
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .config import ConfigError, load_policy, load_steps
from .engine import lint
from .importer import approve_policy, import_roe, write_import
from .models import Step
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

    command = subparsers.add_parser(
        "check-command", help="lint one command without creating a playbook"
    )
    command.add_argument("--policy", "-p", type=Path, required=True)
    command.add_argument("--format", choices=("text", "json"), default="text")
    command.add_argument("command", nargs=argparse.REMAINDER)

    import_parser = subparsers.add_parser(
        "import-roe", help="extract a draft policy from a PDF, DOCX, TXT, or Markdown ROE"
    )
    import_parser.add_argument("document", type=Path)
    import_parser.add_argument("--output", "-o", type=Path, default=Path("roe.draft.yml"))
    import_parser.add_argument("--report", type=Path, default=Path("roe.review.json"))
    import_parser.add_argument("--engagement-id")
    import_parser.add_argument("--owner")
    import_parser.add_argument("--expires")

    approve = subparsers.add_parser(
        "approve-policy", help="mark a reviewed imported policy as approved"
    )
    approve.add_argument("draft", type=Path)
    approve.add_argument("--output", "-o", type=Path, default=Path("roe.yml"))
    approve.add_argument("--reviewed-by", required=True)
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.subcommand == "import-roe":
        return _run_import(args)
    if args.subcommand == "approve-policy":
        return _run_approve(args)
    if args.subcommand == "check-command":
        return _run_check_command(args)
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


def _run_import(args: argparse.Namespace) -> int:
    try:
        result = import_roe(
            args.document,
            engagement_id=args.engagement_id,
            owner_override=args.owner,
            expires_override=args.expires,
        )
        write_import(result, args.output, args.report)
    except ConfigError as exc:
        print(f"roelint: import error: {exc}", file=sys.stderr)
        return 2
    include = len(result.policy["scope"]["include"])
    exclude = len(result.policy["scope"]["exclude"])
    ambiguous = len(result.policy["scope"]["unresolved"])
    print(f"ROE-Lint: extracted {include} in-scope and {exclude} excluded target(s)")
    print(f"Review required: {ambiguous} ambiguous target(s), {len(result.unresolved)} issue(s)")
    print(f"Draft: {args.output}")
    print(f"Evidence: {args.report}")
    return 1 if result.unresolved else 0


def _run_approve(args: argparse.Namespace) -> int:
    try:
        approve_policy(args.draft, args.output, args.reviewed_by)
    except ConfigError as exc:
        print(f"roelint: approval error: {exc}", file=sys.stderr)
        return 2
    print(f"ROE-Lint: approved policy written to {args.output}")
    return 0


def _run_check_command(args: argparse.Namespace) -> int:
    tokens = list(args.command)
    if tokens and tokens[0] == "--":
        tokens.pop(0)
    if not tokens:
        print("roelint: check-command requires a command after '--'", file=sys.stderr)
        return 2
    try:
        policy = load_policy(args.policy)
        findings = lint(policy, [Step("command", shlex.join(tokens))], today=date.today())
    except ConfigError as exc:
        print(f"roelint: configuration error: {exc}", file=sys.stderr)
        return 2
    print(as_json(findings) if args.format == "json" else as_text(findings))
    return 1 if any(item.severity == "error" for item in findings) else 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
