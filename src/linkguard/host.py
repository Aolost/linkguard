"""Hostname normalization for names (IP literals are handled separately)."""

from dataclasses import dataclass
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
