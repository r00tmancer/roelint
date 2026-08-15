import json
from pathlib import Path

from roelint.cli import run

ROOT = Path(__file__).parents[1]


def test_safe_example_returns_zero(capsys: object) -> None:
    code = run(
        ["check", str(ROOT / "examples/playbook.safe.yml"), "-p", str(ROOT / "examples/roe.yml")]
    )
    assert code == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "PASS" in output


def test_blocked_example_returns_one(capsys: object) -> None:
    code = run(
        ["check", str(ROOT / "examples/playbook.blocked.yml"), "-p", str(ROOT / "examples/roe.yml")]
    )
    assert code == 1
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "ROE002" in output
    assert "ROE005" in output


def test_json_output_is_machine_readable(capsys: object) -> None:
    code = run(
        [
            "check",
            str(ROOT / "examples/playbook.safe.yml"),
            "-p",
            str(ROOT / "examples/roe.yml"),
            "--format",
            "json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["tool"] == "roelint"
    assert payload["findings"] == []
