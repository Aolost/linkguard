"""Heuristic rules that depend on the versioned reference data in `linkguard.data`."""

from dataclasses import dataclass

from linkguard.data import (
    BRANDS,
    MULTI_LABEL_SUFFIXES,
    SHORTENERS,
    SUSPICIOUS_TLDS,
)
from linkguard.host import Domain, Host
from linkguard.model import Finding, Policy, Severity, escape_text

_MAX_SUFFIX_LABELS = max(suffix.count(".") + 1 for suffix in MULTI_LABEL_SUFFIXES)


@dataclass(frozen=True, slots=True)
class HostParts:
    """A host split relative to `MULTI_LABEL_SUFFIXES`, not the Public Suffix List."""

    subdomains: tuple[str, ...]
    registrable: str | None
    suffix: str


def split_host(name: str) -> HostParts:
    labels = name.split(".")
    suffix_len = 1
    for count in range(min(len(labels), _MAX_SUFFIX_LABELS), 1, -1):
        if ".".join(labels[-count:]) in MULTI_LABEL_SUFFIXES:
            suffix_len = count
            break
    suffix = ".".join(labels[-suffix_len:])
    if len(labels) <= suffix_len:
        return HostParts((), None, suffix)
    return HostParts(tuple(labels[: -suffix_len - 1]), labels[-suffix_len - 1], suffix)


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance: a swap of adjacent characters costs one."""
    before_previous: list[int] = []
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i, *([0] * len(b))]
        for j, char_b in enumerate(b, 1):
            cost = 0 if char_a == char_b else 1
            current[j] = min(
                previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost
            )
            if i > 1 and j > 1 and char_a == b[j - 2] and a[i - 2] == char_b:
                current[j] = min(current[j], before_previous[j - 2] + 1)
        before_previous, previous = previous, current
    return previous[-1]


def _is_under(name: str, domains: tuple[str, ...] | frozenset[str]) -> bool:
    return any(name == domain or name.endswith("." + domain) for domain in domains)


def _typosquat(parts: HostParts) -> list[Finding]:
    label = parts.registrable
    if label is None or label in BRANDS:
        return []
    limit = 2 if len(label) >= 8 else 1
    for brand in sorted(BRANDS):
        if (
            abs(len(label) - len(brand)) <= limit
            and edit_distance(label, brand) <= limit
        ):
            return [
                Finding(
                    "LG-008",
                    Severity.MEDIUM,
                    escape_text(f"{label} resembles {brand}"),
                    "The domain label is a near-miss of a well-known brand.",
                )
            ]
    return []


def _brand_in_subdomain(name: str, parts: HostParts) -> list[Finding]:
    return [
        Finding(
            "LG-009",
            Severity.HIGH,
            escape_text(f"{subdomain} (brand {brand})"),
            "A brand name is used as a subdomain of a domain that does not own it.",
        )
        for subdomain in parts.subdomains
        for brand, domains in BRANDS.items()
        if brand in subdomain.split("-") and not _is_under(name, domains)
    ]


def reference_findings(host: Host, policy: Policy) -> list[Finding]:
    if not isinstance(host, Domain):
        return []
    parts = split_host(host.name)
    findings = [*_typosquat(parts), *_brand_in_subdomain(host.name, parts)]
    if len(parts.subdomains) > policy.max_subdomain_depth:
        findings.append(
            Finding(
                "LG-010",
                Severity.MEDIUM,
                f"{len(parts.subdomains)} subdomain labels",
                "The host has an unusually deep chain of subdomains.",
            )
        )
    if host.name.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(
            Finding(
                "LG-012",
                Severity.LOW,
                escape_text(parts.suffix),
                "The top-level domain is over-represented in abuse.",
            )
        )
    if _is_under(host.name, SHORTENERS):
        findings.append(
            Finding(
                "LG-013",
                Severity.LOW,
                escape_text(host.name),
                "The host is a URL shortener that hides the real destination.",
            )
        )
    return findings
