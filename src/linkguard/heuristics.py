"""Heuristic rules that need only the parsed URL and normalized host."""

import re
import unicodedata
from urllib.parse import unquote

import idna

from linkguard.host import Domain, Host, IpHost
from linkguard.model import (
    DEFAULT_POLICY,
    Finding,
    Policy,
    Severity,
    escape_text,
    sort_findings,
)
from linkguard.parse import ParsedUrl
from linkguard.reference_rules import reference_findings

# Each dot-separated label ends in a literal dot, so matching stays linear.
_HOSTNAME_LIKE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)


def _redacted_userinfo(userinfo: str) -> str:
    name, colon, _password = userinfo.partition(":")
    return escape_text(name + (":<redacted>" if colon else ""))


def _userinfo_findings(parsed: ParsedUrl) -> list[Finding]:
    if parsed.userinfo is None:
        return []
    evidence = _redacted_userinfo(parsed.userinfo)
    findings = [
        Finding(
            "LG-001",
            Severity.MEDIUM,
            evidence,
            "Credentials in a URL can disguise the real host.",
        )
    ]
    decoded = unquote(parsed.userinfo)
    if "://" in decoded or _HOSTNAME_LIKE.search(decoded):
        findings.append(
            Finding(
                "LG-002",
                Severity.HIGH,
                evidence,
                "The text before the @ looks like a destination.",
            )
        )
    return findings


def _ip_findings(parsed: ParsedUrl, host: Host) -> list[Finding]:
    if not isinstance(host, IpHost):
        return []
    findings = [
        Finding(
            "LG-003",
            Severity.MEDIUM,
            escape_text(str(host.address)),
            "The host is a raw IP address instead of a name.",
        )
    ]
    if not host.canonical:
        findings.append(
            Finding(
                "LG-004",
                Severity.HIGH,
                escape_text(parsed.host),
                "The IP address is written in a non-standard encoding.",
            )
        )
    return findings


def _port_findings(parsed: ParsedUrl) -> list[Finding]:
    if parsed.port is None:
        return []
    return [
        Finding(
            "LG-005",
            Severity.LOW,
            f"port {parsed.port}",
            "The URL uses a non-default port.",
        )
    ]


def _percent_findings(parsed: ParsedUrl, host: Host) -> list[Finding]:
    if not host.percent_encoded:
        return []
    return [
        Finding(
            "LG-014",
            Severity.MEDIUM,
            escape_text(parsed.host),
            "The host contains percent-encoded characters.",
        )
    ]


def _label_scripts(label: str) -> set[str]:
    # The standard library has no script property; the first word of a character's
    # name (LATIN, CYRILLIC, GREEK, ...) is an approximation that suits these scripts.
    names = (unicodedata.name(char, "") for char in label if char.isalpha())
    return {name.split(" ", 1)[0] for name in names if name}


def _mixes_latin_with_lookalike_script(label: str) -> bool:
    scripts = _label_scripts(label)
    return "LATIN" in scripts and bool(scripts & {"CYRILLIC", "GREEK"})


def _name_findings(host: Host, policy: Policy) -> list[Finding]:
    if not isinstance(host, Domain):
        return []
    findings: list[Finding] = []
    if any(label.startswith("xn--") for label in host.name.split(".")):
        findings.append(
            Finding(
                "LG-006",
                Severity.LOW,
                escape_text(host.name),
                "The host uses an internationalized (punycode) label.",
            )
        )
    for label in idna.decode(host.name).split("."):
        if _mixes_latin_with_lookalike_script(label):
            findings.append(
                Finding(
                    "LG-007",
                    Severity.HIGH,
                    escape_text(label),
                    "One label mixes Latin letters with look-alike letters.",
                )
            )
    if len(host.name) > policy.max_hostname_length:
        findings.append(
            Finding(
                "LG-011",
                Severity.LOW,
                f"{len(host.name)} characters",
                "The hostname is unusually long.",
            )
        )
    return findings


def find_findings(
    parsed: ParsedUrl, host: Host, policy: Policy = DEFAULT_POLICY
) -> list[Finding]:
    """Return every finding for a parsed URL, in deterministic order."""
    return sort_findings(
        [
            *_userinfo_findings(parsed),
            *_ip_findings(parsed, host),
            *_port_findings(parsed),
            *_percent_findings(parsed, host),
            *_name_findings(host, policy),
            *reference_findings(host, policy),
        ]
    )
