"""Rendering of a parsed URL in normalized, printable-ASCII form."""

from ipaddress import IPv4Address
from urllib.parse import quote

from linkguard.host import Host, IpHost
from linkguard.parse import ParsedUrl

# Everything RFC 3986 allows in a path and query, plus "%" so encoding is idempotent.
_URL_SAFE = "%/?&=:@!$'()*+,;~-._#[]"


def host_text(host: Host) -> str:
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


def normalized_target(parsed: ParsedUrl) -> str:
    """The path and query, with non-ASCII characters percent-encoded."""
    return quote(parsed.path_query, safe=_URL_SAFE)


def normalized_url(parsed: ParsedUrl, host: Host) -> str:
    port = "" if parsed.port is None else f":{parsed.port}"
    return f"{parsed.scheme}://{host_text(host)}{port}{normalized_target(parsed)}"
