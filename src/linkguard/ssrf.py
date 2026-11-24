"""Address classification for the fetcher: which addresses must never be connected to.

The table is explicit rather than `ipaddress.is_global`, whose answers differ between
Python patch releases. It fails closed: anything not clearly global is blocked.
"""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

type IPAddress = IPv4Address | IPv6Address

_V4_BLOCKED = tuple(
    (IPv4Network(cidr), reason)
    for cidr, reason in (
        ("0.0.0.0/8", "unspecified"),
        ("10.0.0.0/8", "private"),
        ("100.64.0.0/10", "cgnat"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link_local"),
        ("172.16.0.0/12", "private"),
        ("192.0.0.0/24", "reserved"),
        ("192.0.2.0/24", "documentation"),
        ("192.88.99.0/24", "reserved"),
        ("192.168.0.0/16", "private"),
        ("198.18.0.0/15", "benchmarking"),
        ("198.51.100.0/24", "documentation"),
        ("203.0.113.0/24", "documentation"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved"),
    )
)

_V6_BLOCKED = tuple(
    (IPv6Network(cidr), reason)
    for cidr, reason in (
        ("::/128", "unspecified"),
        ("::1/128", "loopback"),
        ("fc00::/7", "unique_local"),
        ("fe80::/10", "link_local"),
        ("fec0::/10", "site_local"),
        ("ff00::/8", "multicast"),
        ("2001::/23", "reserved"),
        ("2001:db8::/32", "documentation"),
        ("3fff::/20", "documentation"),
    )
)

# Only global unicast space is ever allowed for IPv6; everything else is non_global.
_V6_GLOBAL_UNICAST = IPv6Network("2000::/3")
_NAT64 = IPv6Network("64:ff9b::/96")
_SIX_TO_FOUR = IPv6Network("2002::/16")


def _embedded_ipv4(address: IPv6Address) -> IPv4Address | None:
    """The IPv4 address a mapped, NAT64, or 6to4 address stands for, if any."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address in _NAT64:
        return IPv4Address(int(address) & 0xFFFFFFFF)
    if address in _SIX_TO_FOUR:
        return IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
    return None


def _blocked_v4(address: IPv4Address) -> str | None:
    return next((reason for net, reason in _V4_BLOCKED if address in net), None)


def _blocked_v6(address: IPv6Address) -> str | None:
    embedded = _embedded_ipv4(address)
    if embedded is not None:
        return _blocked_v4(embedded)
    for network, reason in _V6_BLOCKED:
        if address in network:
            return reason
    return None if address in _V6_GLOBAL_UNICAST else "non_global"


def blocked_reason(address: IPAddress) -> str | None:
    """Return why `address` must not be connected to, or None if it is allowed."""
    if isinstance(address, IPv4Address):
        return _blocked_v4(address)
    return _blocked_v6(address)
