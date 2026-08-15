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


def test_import_and_approve_cli(tmp_path: Path, capsys: object) -> None:
    source = tmp_path / "roe.txt"
    source.write_text(
        """Owner: security@client.example
Valid until: 2099-12-31
In scope: 10.20.0.0/16
Out of scope: 10.20.10.50
""",
        encoding="utf-8",
    )
    draft = tmp_path / "draft.yml"
    report = tmp_path / "review.json"
    assert (
        run(
            [
                "import-roe",
                str(source),
                "-o",
                str(draft),
                "--report",
                str(report),
            ]
        )
        == 0
    )
    assert draft.exists() and report.exists()
    assert "Review required" in capsys.readouterr().out  # type: ignore[attr-defined]

    approved = tmp_path / "roe.yml"
    assert (
        run(
            [
                "approve-policy",
                str(draft),
                "-o",
                str(approved),
                "--reviewed-by",
                "Analyst",
            ]
        )
        == 0
    )
    assert approved.exists()
