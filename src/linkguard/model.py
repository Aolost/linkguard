"""Shared result types and the text-safety helper for echoed input."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

EVIDENCE_LIMIT = 200


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    evidence: str
    explanation: str


@dataclass(frozen=True, slots=True)
class Policy:
    """Heuristic thresholds. Nothing here can affect SSRF validation."""

    max_hostname_length: int = 50
    max_subdomain_depth: int = 4


DEFAULT_POLICY = Policy()


def _escape_char(char: str) -> str:
    code = ord(char)
    if char == "\\":
        return "\\\\"
    if " " <= char <= "~":
        return char
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def escape_text(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    """Return printable ASCII for attacker-controlled text, truncated to `limit`."""
    escaped = "".join(_escape_char(char) for char in text)
    if len(escaped) <= limit:
        return escaped
    return escaped[: limit - 3] + "..."


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Order by severity (high first), then rule ID, then evidence."""
    return sorted(findings, key=lambda f: (_RANK[f.severity], f.rule_id, f.evidence))
