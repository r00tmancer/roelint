from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path
from typing import Any

from .config import load_policy
from .engine import lint
from .models import Finding, Step


def authorize(policy_path: Path, command: str, targets: list[str] | None = None) -> dict[str, Any]:
    """Statically evaluate a command. This function never executes it."""
    policy = load_policy(policy_path)
    step = Step("agent-command", command, targets=tuple(targets or ()))
    findings = lint(policy, [step], today=date.today())
    errors = [item for item in findings if item.severity == "error"]
    return {
        "decision": "block" if errors else "allow",
        "command": command,
        "engagement_id": policy.engagement_id,
        "findings": [_finding_dict(item) for item in findings],
        "executed": False,
    }


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return finding.as_dict()


def create_server(policy_path: Path) -> Any:
    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise RuntimeError('MCP support requires: pip install "roelint[agent]"') from exc

    server = MCPServer(
        "ROE-Lint",
        instructions=(
            "Use authorize_command before every red-team or penetration-test command. "
            "A block decision is final. This server performs static analysis and never "
            "executes commands."
        ),
    )

    @server.tool()
    def authorize_command(command: str, targets: list[str] | None = None) -> dict[str, Any]:
        """Allow or block one proposed command against the approved Rules of Engagement."""
        return authorize(policy_path, command, targets)

    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ROE-Lint MCP policy server")
    parser.add_argument("--policy", "-p", type=Path, required=True)
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    policy_path = args.policy.resolve()
    load_policy(policy_path)
    server = create_server(policy_path)
    if args.transport == "streamable-http":
        server.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        server.run()


if __name__ == "__main__":
    main()
