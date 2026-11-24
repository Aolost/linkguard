"""Public entry point: turn a URL string into a `Report`."""

from ipaddress import IPv4Address
from urllib.parse import quote

from linkguard._version import version
from linkguard.data import DATA_VERSION
from linkguard.heuristics import find_findings
from linkguard.host import Host, IpHost, normalize_host
from linkguard.model import (
    DEFAULT_POLICY,
    Policy,
    Refusal,
    Report,
    escape_text,
    verdict_for,
)
from linkguard.parse import ParsedUrl, ParseError, parse_url

# Everything RFC 3986 allows in a path and query, plus "%" so encoding is idempotent.
_URL_SAFE = "%/?&=:@!$'()*+,;~-._#[]"


def _host_text(host: Host) -> str:
    if not isinstance(host, IpHost):
        return host.name
    address = host.address
    if isinstance(address, IPv4Address):
        return str(address)
    mapped = address.ipv4_mapped
    if mapped is not None:
        # str() of a mapped address differs between Python versions; always use hex.
        packed = int(mapped)
        return f"[::ffff:{packed >> 16:x}:{packed & 0xFFFF:x}]"
    return f"[{address}]"


def _normalized_url(parsed: ParsedUrl, host: Host) -> str:
    port = "" if parsed.port is None else f":{parsed.port}"
    path = quote(parsed.path_query, safe=_URL_SAFE)
    return f"{parsed.scheme}://{_host_text(host)}{port}{path}"


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
        normalized_url=_normalized_url(parsed, host),
        verdict=verdict_for(findings),
        findings=findings,
    )
