from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_HOST_RE = re.compile(
    r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?![\w-])"
)
_IP_OR_CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>]+")
_WILDCARD_RE = re.compile(
    r"(?<![\w-])\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?![\w-])"
)


def normalize_target(value: str) -> str:
    candidate = value.strip().rstrip(".,;)")
    if "://" in candidate:
        return (urlsplit(candidate).hostname or candidate).lower().rstrip(".")
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
        candidate = candidate.rsplit(":", 1)[0]
    return candidate.lower().rstrip(".")


def extract_targets(command: str) -> set[str]:
    found: set[str] = set()
    scrubbed = command
    for match in _URL_RE.findall(command):
        found.add(normalize_target(match))
        scrubbed = scrubbed.replace(match, " ")
    for match in _WILDCARD_RE.findall(scrubbed):
        found.add(normalize_target(match))
        scrubbed = scrubbed.replace(match, " ")
    for match in _IP_OR_CIDR_RE.findall(scrubbed):
        try:
            ipaddress.ip_network(match, strict=False)
        except ValueError:
            continue
        found.add(normalize_target(match))
        scrubbed = scrubbed.replace(match, " ")
    for match in _HOST_RE.findall(scrubbed):
        found.add(normalize_target(match))
    return found


def _matches(target: str, pattern: str) -> bool:
    target = normalize_target(target)
    pattern = normalize_target(pattern)
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        try:
            if "/" in target:
                target_network = ipaddress.ip_network(target, strict=False)
                if isinstance(network, ipaddress.IPv4Network) and isinstance(
                    target_network, ipaddress.IPv4Network
                ):
                    return target_network.subnet_of(network)
                if isinstance(network, ipaddress.IPv6Network) and isinstance(
                    target_network, ipaddress.IPv6Network
                ):
                    return target_network.subnet_of(network)
                return False
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    except ValueError:
        pass
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return target.endswith(suffix) and target != pattern[2:]
    return target == pattern


def target_status(target: str, include: tuple[str, ...], exclude: tuple[str, ...]) -> str:
    if any(_matches(target, pattern) for pattern in exclude):
        return "excluded"
    if any(_matches(target, pattern) for pattern in include):
        return "included"
    return "outside"
