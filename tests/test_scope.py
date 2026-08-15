import pytest

from roelint.scope import extract_targets, normalize_target, target_status


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://API.LAB.EXAMPLE:8443/path", "api.lab.example"),
        ("10.20.1.2:443", "10.20.1.2"),
        ("Host.Example.", "host.example"),
    ],
)
def test_normalize_target(value: str, expected: str) -> None:
    assert normalize_target(value) == expected


def test_extracts_urls_ips_cidrs_and_domains() -> None:
    command = (
        "tool https://api.lab.example/a 10.2.3.4 10.9.0.0/16 other.example.net *.wild.example.net"
    )
    assert extract_targets(command) == {
        "api.lab.example",
        "10.2.3.4",
        "10.9.0.0/16",
        "other.example.net",
        "*.wild.example.net",
    }


def test_exclusion_wins_over_inclusion() -> None:
    assert target_status("10.20.1.4", ("10.20.0.0/16",), ("10.20.1.4",)) == "excluded"


def test_wildcard_does_not_match_apex() -> None:
    include = ("*.lab.example",)
    assert target_status("api.lab.example", include, ()) == "included"
    assert target_status("lab.example", include, ()) == "outside"


def test_cidr_must_be_fully_contained() -> None:
    assert target_status("10.20.4.0/24", ("10.20.0.0/16",), ()) == "included"
    assert target_status("10.20.0.0/15", ("10.20.0.0/16",), ()) == "outside"
