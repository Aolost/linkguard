"""Shared result types and the text-safety helper for echoed input."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

SCHEMA_VERSION = "1"

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
    """Options and heuristic thresholds. Nothing here can affect SSRF validation."""

    follow: bool = False
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
    pieces: list[str] = []
    length = 0
    for char in text:
        piece = _escape_char(char)
        pieces.append(piece)
        length += len(piece)
        if length > limit:  # stop early: hostile input can be megabytes long
            return "".join(pieces)[: limit - 3] + "..."
    return "".join(pieces)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Order by severity (high first), then rule ID, then evidence."""
    return sorted(findings, key=lambda f: (_RANK[f.severity], f.rule_id, f.evidence))


class Verdict(StrEnum):
    NO_RED_FLAGS = "NO_RED_FLAGS"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"


def verdict_for(findings: Iterable[Finding]) -> Verdict:
    severities = {finding.severity for finding in findings}
    if Severity.HIGH in severities:
        return Verdict.DANGEROUS
    return Verdict.SUSPICIOUS if severities else Verdict.NO_RED_FLAGS


@dataclass(frozen=True, slots=True)
class Refusal:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class Hop:
    url: str
    http_status: int
    address: str


@dataclass(frozen=True, slots=True)
class FetchSummary:
    status: str = "not_requested"
    hops: tuple[Hop, ...] = ()
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    bytes_read: int = 0
    truncated: bool = False
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "hops": [
                {"url": h.url, "http_status": h.http_status, "address": h.address}
                for h in self.hops
            ],
            "final_url": self.final_url,
            "http_status": self.http_status,
            "content_type": self.content_type,
            "bytes_read": self.bytes_read,
            "truncated": self.truncated,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class Report:
    tool_version: str
    data_version: str
    input: str
    outcome: str
    refusal: Refusal | None
    normalized_url: str | None
    verdict: Verdict | None
    findings: tuple[Finding, ...]
    fetch: FetchSummary = field(default_factory=FetchSummary)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool_version": self.tool_version,
            "data_version": self.data_version,
            "input": self.input,
            "outcome": self.outcome,
            "refusal": (
                None
                if self.refusal is None
                else {"code": self.refusal.code, "message": self.refusal.message}
            ),
            "normalized_url": self.normalized_url,
            "verdict": None if self.verdict is None else str(self.verdict),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": str(f.severity),
                    "evidence": f.evidence,
                    "explanation": f.explanation,
                }
                for f in self.findings
            ],
            "fetch": self.fetch.to_dict(),
        }
