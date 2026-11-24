"""Host normalization: domain names, legacy IPv4 spellings, and IPv6 literals."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import unquote_to_bytes

import idna

from linkguard.parse import ParseError


@dataclass(frozen=True, slots=True)
class Domain:
    """An ASCII (A-label) hostname and whether it was percent-encoded in the input."""

    name: str
    percent_encoded: bool


def _percent_decode_once(raw: str) -> str:
    try:
        decoded = unquote_to_bytes(raw).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ParseError("invalid_host", "percent-encoded host is not UTF-8") from error
    if "%" in decoded:
        raise ParseError("invalid_host", "host still contains % after decoding once")
    return decoded


def normalize_domain(raw: str) -> Domain:
    """Return the ASCII form of `raw` or raise `ParseError`."""
    decoded = _percent_decode_once(raw)
    without_dot = decoded[:-1] if decoded.endswith(".") else decoded
    try:
        name = idna.encode(without_dot, uts46=True, std3_rules=True).decode("ascii")
    except UnicodeError as error:
        raise ParseError("invalid_host", "host is not a valid IDNA name") from error
    if name.startswith(".") or name.endswith(".") or ".." in name:
        raise ParseError("invalid_host", "host has an empty label")
    return Domain(name=name, percent_encoded=decoded != raw)


@dataclass(frozen=True, slots=True)
class IpHost:
    """An IP literal; `canonical` is True only for the standard spelling."""

    address: IPv4Address | IPv6Address
    canonical: bool
    percent_encoded: bool


Host = Domain | IpHost

_OCTAL_DIGITS = frozenset("01234567")
_HEX_DIGITS = frozenset("0123456789abcdef")


def _parse_ipv4_part(part: str) -> int:
    if part.startswith("0x"):
        digits, base, allowed = part[2:], 16, _HEX_DIGITS
    elif len(part) > 1 and part.startswith("0"):
        digits, base, allowed = part[1:], 8, _OCTAL_DIGITS
    else:
        digits, base, allowed = part, 10, frozenset("0123456789")
    if not digits or not set(digits) <= allowed:
        raise ParseError("invalid_host", "invalid number in IPv4 host")
    return int(digits, base)


def _parse_legacy_ipv4(name: str) -> IPv4Address:
    parts = name.split(".")
    if len(parts) > 4:
        raise ParseError("invalid_host", "too many parts in IPv4 host")
    numbers = [_parse_ipv4_part(part) for part in parts]
    *leading, last = numbers
    if any(number > 255 for number in leading) or last >= 256 ** (5 - len(numbers)):
        raise ParseError("invalid_host", "IPv4 part out of range")
    value = last + sum(number << (8 * (3 - i)) for i, number in enumerate(leading))
    return IPv4Address(value)


def _ipv6_host(raw: str) -> IpHost:
    inner = raw[1:-1]
    if not raw.endswith("]") or "%" in inner:
        raise ParseError(
            "invalid_host", "unclosed bracket or zone identifier in IPv6 host"
        )
    try:
        address = IPv6Address(inner)
    except ValueError as error:
        raise ParseError("invalid_host", "invalid IPv6 literal") from error
    # str() of an IPv4-mapped address differs between Python versions, so mapped
    # addresses are never canonical rather than depending on the interpreter.
    canonical = address.ipv4_mapped is None and inner == str(address)
    return IpHost(address=address, canonical=canonical, percent_encoded=False)


def normalize_host(raw: str) -> Host:
    """Normalize a raw host from `parse_url` to a `Domain` or an `IpHost`."""
    if raw.startswith("["):
        return _ipv6_host(raw)
    domain = normalize_domain(raw)
    last_label = domain.name.rsplit(".", 1)[-1]
    if not (last_label.isdigit() or last_label.startswith("0x")):
        return domain
    address = _parse_legacy_ipv4(domain.name)
    return IpHost(
        address=address,
        canonical=raw == str(address),
        percent_encoded=domain.percent_encoded,
    )
