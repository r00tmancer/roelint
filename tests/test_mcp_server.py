from pathlib import Path

from roelint.mcp_server import authorize

ROOT = Path(__file__).parents[1]
POLICY = ROOT / "examples/roe.yml"


def test_agent_command_is_blocked_without_execution() -> None:
    result = authorize(POLICY, "nmap -sV 10.20.10.50")
    assert result["decision"] == "block"
    assert result["executed"] is False
    assert result["findings"][0]["rule_id"] == "ROE002"


def test_agent_command_is_allowed_without_execution() -> None:
    result = authorize(POLICY, "nmap -sV 10.20.4.10")
    assert result["decision"] == "allow"
    assert result["executed"] is False
