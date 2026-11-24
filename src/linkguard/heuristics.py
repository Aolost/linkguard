"""Heuristic rules that need only the parsed URL and normalized host."""

import re
from urllib.parse import unquote

from linkguard.host import Host, IpHost
from linkguard.model import Finding, Severity, escape_text, sort_findings
from linkguard.parse import ParsedUrl

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


def find_findings(parsed: ParsedUrl, host: Host) -> list[Finding]:
    """Return every finding for a parsed URL, in deterministic order."""
    return sort_findings(
        [
            *_userinfo_findings(parsed),
            *_ip_findings(parsed, host),
            *_port_findings(parsed),
            *_percent_findings(parsed, host),
        ]
    )
