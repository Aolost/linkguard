"""Public entry point: turn a URL string into a `Report`."""

from linkguard._version import version
from linkguard.data import DATA_VERSION
from linkguard.heuristics import find_findings
from linkguard.host import normalize_host
from linkguard.model import (
    DEFAULT_POLICY,
    Policy,
    Refusal,
    Report,
    escape_text,
    verdict_for,
)
from linkguard.parse import ParseError, parse_url
from linkguard.urlnorm import normalized_url


def inspect(url: str, policy: Policy = DEFAULT_POLICY) -> Report:
    """Inspect `url`; refused input yields a refused report instead of raising."""
    shown = escape_text(url)
    try:
        parsed = parse_url(url)
        host = normalize_host(parsed.host)
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
        normalized_url=normalized_url(parsed, host),
        verdict=verdict_for(findings),
        findings=findings,
    )
