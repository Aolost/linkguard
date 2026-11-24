"""Public entry point: turn a URL string into a `Report`."""

import asyncio
from concurrent.futures import ThreadPoolExecutor

from linkguard._version import version
from linkguard.data import DATA_VERSION
from linkguard.fetch import SafeFetcher
from linkguard.heuristics import find_findings
from linkguard.host import normalize_host
from linkguard.model import (
    DEFAULT_POLICY,
    FetchSummary,
    Policy,
    Refusal,
    Report,
    escape_text,
    verdict_for,
)
from linkguard.parse import ParseError, parse_url
from linkguard.urlnorm import normalized_url


def _fetch(url: str) -> FetchSummary:
    """Run the fetch on its own event loop in a helper thread.

    A fresh loop in a fresh thread works whether or not the caller is already inside an
    event loop. `SafeFetcher.fetch` reports problems in its result, not by raising.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, SafeFetcher().fetch(url)).result()


def inspect(url: str, policy: Policy = DEFAULT_POLICY) -> Report:
    """Inspect `url`; refused input yields a refused report instead of raising."""
    shown = escape_text(url)
    try:
        parsed = parse_url(url)
        host = normalize_host(parsed.host)
        normalized = normalized_url(parsed, host)
    except ParseError as error:
        return Report(
            tool_version=version(),
            data_version=DATA_VERSION,
            input=shown,
            outcome="refused",
            refusal=Refusal(error.code, str(error)),
            normalized_url=None,
            verdict=None,
            findings=(),
        )
    findings = tuple(find_findings(parsed, host, policy))
    return Report(
        tool_version=version(),
        data_version=DATA_VERSION,
        input=shown,
        outcome="inspected",
        refusal=None,
        normalized_url=normalized,
        verdict=verdict_for(findings),
        findings=findings,
        fetch=_fetch(normalized) if policy.follow else FetchSummary(),
    )
