from ipaddress import ip_address

import pytest

from linkguard.host import Domain, IpHost, normalize_host
from linkguard.parse import ParseError
from tests.chars import fullwidth


def refusal_code(raw: str) -> str:
    with pytest.raises(ParseError) as caught:
        normalize_host(raw)
    return caught.value.code


@pytest.mark.parametrize(
    "raw",
    [
        "2130706433",
        "0x7f000001",
        "0X7F000001",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "127.1",
        "127.0.1",
        "0x7f.1",
        "0177.1",
        fullwidth("127.0.0.1"),
    ],
)
def test_legacy_ipv4_encodings_resolve_to_loopback_and_are_not_canonical(
    raw: str,
) -> None:
    host = normalize_host(raw)
    assert isinstance(host, IpHost)
    assert host.address == ip_address("127.0.0.1")
    assert host.canonical is False


def test_canonical_dotted_decimal_is_canonical() -> None:
    assert normalize_host("203.0.113.7") == IpHost(
        address=ip_address("203.0.113.7"), canonical=True, percent_encoded=False
    )


def test_trailing_dot_and_percent_encoded_dots_are_normalized_and_not_canonical() -> (
    None
):
    assert normalize_host("127.0.0.1.") == IpHost(
        address=ip_address("127.0.0.1"), canonical=False, percent_encoded=False
    )
    encoded = normalize_host("127%2e0%2e0%2e1")
    assert isinstance(encoded, IpHost)
    assert encoded.address == ip_address("127.0.0.1")
    assert encoded.percent_encoded is True
    assert encoded.canonical is False


def test_ipv4_range_edges() -> None:
    host = normalize_host("4294967295")
    assert isinstance(host, IpHost)
    assert host.address == ip_address("255.255.255.255")
    assert refusal_code("4294967296") == "invalid_host"
    assert refusal_code("256.1.1.1") == "invalid_host"


def test_short_form_uses_the_remaining_bytes_for_the_last_part() -> None:
    host = normalize_host("1.65536")
    assert isinstance(host, IpHost)
    assert host.address == ip_address("1.1.0.0")
    assert refusal_code("1.16777216") == "invalid_host"


@pytest.mark.parametrize(
    "raw",
    [
        "1.2.3.4.5",
        "0x7g.1",
        "089.1",
        "0x",
        "0x.1",
        "example.123",
        "example.0x1",
        "1.2.3.0xzz",
    ],
)
def test_numeric_last_label_that_is_not_valid_ipv4_is_refused(raw: str) -> None:
    assert refusal_code(raw) == "invalid_host"


def test_names_with_numeric_non_final_labels_stay_domains() -> None:
    assert normalize_host("123.example.test") == Domain(
        name="123.example.test", percent_encoded=False
    )


@pytest.mark.parametrize(
    ("raw", "address", "canonical"),
    [
        ("[::1]", "::1", True),
        ("[2001:db8::1]", "2001:db8::1", True),
        ("[::ffff:127.0.0.1]", "::ffff:7f00:1", False),
        ("[::ffff:7f00:1]", "::ffff:7f00:1", False),
        ("[0:0:0:0:0:0:0:1]", "::1", False),
        ("[2001:DB8::1]", "2001:db8::1", False),
        ("[64:ff9b::7f00:1]", "64:ff9b::7f00:1", True),
    ],
)
def test_ipv6_literals(raw: str, address: str, canonical: bool) -> None:
    assert normalize_host(raw) == IpHost(
        address=ip_address(address), canonical=canonical, percent_encoded=False
    )


@pytest.mark.parametrize(
    "raw",
    [
        "[fe80::1%25eth0]",
        "[fe80::1%eth0]",
        "[%3a%3a1]",
        "[]",
        "[::g]",
        "[1.2.3.4]",
        "[::1",
        "[1:2:3:4:5:6:7:8:9]",
    ],
)
def test_invalid_ipv6_and_zone_ids_are_refused(raw: str) -> None:
    assert refusal_code(raw) == "invalid_host"
