from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from roelint.importer import import_roe

ROOT = Path(__file__).parent


def main() -> int:
    cases = yaml.safe_load((ROOT / "cases.yml").read_text(encoding="utf-8"))
    passed = 0
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="roelint-benchmark-") as directory:
        temp = Path(directory)
        for index, case in enumerate(cases):
            source = temp / f"case-{index}.txt"
            source.write_text(case["text"], encoding="utf-8")
            result = import_roe(
                source,
                owner_override="owner@example.test",
                expires_override="2099-12-31",
            )
            actual = {
                "include": result.policy["scope"]["include"],
                "exclude": result.policy["scope"]["exclude"],
                "unresolved": result.policy["scope"]["unresolved"],
            }
            expected = {
                "include": sorted(case["include"]),
                "exclude": sorted(case["exclude"]),
                "unresolved": sorted(case["unresolved"]),
            }
            if actual == expected:
                passed += 1
            else:
                failures.append(f"{case['name']}: expected {expected}, got {actual}")

    print(f"ROE import regression corpus: {passed}/{len(cases)} passed")
    for failure in failures:
        print(f"FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
