"""Strict URL splitting.

Ambiguous input is refused instead of interpreted, because the value of this module is
that the host it reports is the host every other parser would connect to.
"""

import unicodedata
from dataclasses import dataclass

MAX_URL_LENGTH = 2048
_DEFAULT_PORTS = {"http": 80, "https": 443}
_FORBIDDEN_CATEGORIES = {"Cc", "Cs"}


class ParseError(ValueError):
    """The input was refused; `code` is stable and machine readable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    """URL components. `host` is the raw authority host and is normalized elsewhere."""

    scheme: str
    userinfo: str | None
    host: str
    port: int | None
    path_query: str


def _reject_forbidden_characters(url: str) -> None:
    for char in url:
        if (
            char == "\\"
            or char.isspace()
            or unicodedata.category(char) in _FORBIDDEN_CATEGORIES
        ):
            raise ParseError(
                "invalid_character", "control, whitespace, or backslash character"
            )


def _split_authority(rest: str) -> tuple[str, str]:
    without_fragment = rest.split("#", 1)[0]
    ends = [
        i for i in (without_fragment.find("/"), without_fragment.find("?")) if i >= 0
    ]
    cut = min(ends) if ends else len(without_fragment)
    authority, path_query = without_fragment[:cut], without_fragment[cut:]
    if not path_query.startswith("/"):
        path_query = "/" + path_query
    return authority, path_query


def _split_host_port(hostport: str) -> tuple[str, str | None]:
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise ParseError("invalid_host", "unclosed bracket in host")
        host, remainder = hostport[: end + 1], hostport[end + 1 :]
        if remainder and not remainder.startswith(":"):
            raise ParseError("invalid_host", "text after bracketed host")
        return host, remainder[1:] if remainder else None
    host, sep, port_text = hostport.partition(":")
    if ":" in port_text:
        raise ParseError("invalid_host", "unbracketed colon in host")
    return host, port_text if sep else None


def _parse_port(port_text: str | None, scheme: str) -> int | None:
    if port_text is None:
        return None
    if not (port_text.isascii() and port_text.isdigit()):
        raise ParseError("invalid_port", "port must be digits")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ParseError("invalid_port", "port out of range")
    return None if port == _DEFAULT_PORTS[scheme] else port


def parse_url(url: str) -> ParsedUrl:
    """Split `url` into components or raise `ParseError`."""
    if len(url) > MAX_URL_LENGTH:
        raise ParseError("too_long", f"input longer than {MAX_URL_LENGTH} characters")
    _reject_forbidden_characters(url)
    scheme_text, sep, rest = url.partition("://")
    if not sep:
        raise ParseError("missing_authority", "expected scheme://")
    scheme = scheme_text.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ParseError("bad_scheme", "only http and https are accepted")
    authority, path_query = _split_authority(rest)
    userinfo, at, hostport = authority.rpartition("@")
    host, port_text = _split_host_port(hostport)
    if not host:
        raise ParseError("empty_host", "host is empty")
    return ParsedUrl(
        scheme=scheme,
        userinfo=userinfo if at else None,
        host=host,
        port=_parse_port(port_text, scheme),
        path_query=path_query,
    )
