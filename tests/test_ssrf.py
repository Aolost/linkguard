from ipaddress import IPv4Address, IPv6Address, ip_address

import pytest
from hypothesis import given
from hypothesis import strategies as st

from linkguard.ssrf import blocked_reason

BLOCKED_V4 = [
    (str(IPv4Address(0)), "unspecified"),
    ("0.1.2.3", "unspecified"),
    ("10.0.0.1", "private"),
    ("10.255.255.255", "private"),
    ("100.64.0.1", "cgnat"),
    ("100.127.255.255", "cgnat"),
    ("127.0.0.1", "loopback"),
    ("127.255.255.254", "loopback"),
    ("169.254.169.254", "link_local"),
    ("172.16.0.1", "private"),
    ("172.31.255.255", "private"),
    ("192.0.0.1", "reserved"),
    ("192.0.2.1", "documentation"),
    ("192.168.1.1", "private"),
    ("198.18.0.1", "benchmarking"),
    ("198.19.255.255", "benchmarking"),
    ("198.51.100.1", "documentation"),
    ("203.0.113.7", "documentation"),
    ("224.0.0.1", "multicast"),
    ("239.255.255.255", "multicast"),
    ("240.0.0.1", "reserved"),
    ("255.255.255.255", "reserved"),
]

ALLOWED_V4 = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "9.255.255.255",
    "11.0.0.0",
    "100.63.255.255",
    "100.128.0.0",
    "126.255.255.255",
    "128.0.0.1",
    "169.253.255.255",
    "169.255.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "192.0.1.1",
    "192.0.3.0",
    "192.167.255.255",
    "192.169.0.0",
    "198.17.255.255",
    "198.20.0.0",
    "223.255.255.255",
]

BLOCKED_V6 = [
    ("::", "unspecified"),
    ("::1", "loopback"),
    ("::2", "non_global"),
    ("::127.0.0.1", "non_global"),
    ("fc00::1", "unique_local"),
    ("fd12:3456::1", "unique_local"),
    ("fe80::1", "link_local"),
    ("febf::1", "link_local"),
    ("fec0::1", "site_local"),
    ("ff02::1", "multicast"),
    ("100::1", "non_global"),
    ("2001::1", "reserved"),
    ("2001:1::1", "reserved"),
    ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "reserved"),
    ("2001:db8::1", "documentation"),
    ("3fff::1", "documentation"),
    ("64:ff9b:1::1", "non_global"),
]

ALLOWED_V6 = [
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "2001:200::1",
    "2a00:1450::1",
]

# (address, reason of the embedded IPv4 address)
EMBEDDED_BLOCKED = [
    ("::ffff:127.0.0.1", "loopback"),
    ("::ffff:7f00:1", "loopback"),
    ("::ffff:10.0.0.1", "private"),
    ("::ffff:169.254.169.254", "link_local"),
    ("64:ff9b::7f00:1", "loopback"),
    ("64:ff9b::a9fe:a9fe", "link_local"),
    ("2002:7f00:1::", "loopback"),
    ("2002:a9fe:a9fe::1", "link_local"),
]

EMBEDDED_ALLOWED = ["::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1"]


@pytest.mark.parametrize(
    ("address", "reason"), BLOCKED_V4 + BLOCKED_V6 + EMBEDDED_BLOCKED
)
def test_blocked_addresses_and_their_reasons(address: str, reason: str) -> None:
    assert blocked_reason(ip_address(address)) == reason


@pytest.mark.parametrize("address", ALLOWED_V4 + ALLOWED_V6 + EMBEDDED_ALLOWED)
def test_public_addresses_are_allowed(address: str) -> None:
    assert blocked_reason(ip_address(address)) is None


@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_everything_python_calls_non_global_is_blocked_for_ipv4(value: int) -> None:
    address = IPv4Address(value)
    if not address.is_global:
        assert blocked_reason(address) is not None


@given(
    st.one_of(
        st.integers(min_value=0, max_value=2**128 - 1),
        st.integers(min_value=2**125, max_value=2**126 - 1),
    )
)
def test_everything_python_calls_non_global_is_blocked_for_ipv6(value: int) -> None:
    address = IPv6Address(value)
    if not address.is_global:
        assert blocked_reason(address) is not None
