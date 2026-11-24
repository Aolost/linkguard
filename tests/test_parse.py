import pytest

from linkguard.parse import MAX_URL_LENGTH, ParsedUrl, ParseError, parse_url
from tests.chars import LINE_SEPARATOR, NO_BREAK_SPACE


def refusal_code(url: str) -> str:
    with pytest.raises(ParseError) as caught:
        parse_url(url)
    return caught.value.code


def test_parses_all_components() -> None:
    assert parse_url("HTTPS://user:pw@Example.test:8443/a/b?q=1#frag") == ParsedUrl(
        scheme="https",
        userinfo="user:pw",
        host="Example.test",
        port=8443,
        path_query="/a/b?q=1",
    )


def test_minimal_url_gets_root_path_and_no_port() -> None:
    assert parse_url("http://example.test") == ParsedUrl(
        scheme="http", userinfo=None, host="example.test", port=None, path_query="/"
    )


@pytest.mark.parametrize(
    ("url", "port"),
    [
        ("http://h.test:80/", None),
        ("https://h.test:443/", None),
        ("http://h.test:0080/", None),
        ("http://h.test:443/", 443),
        ("https://h.test:80/", 80),
        ("http://h.test:08080/", 8080),
        ("http://h.test:65535/", 65535),
    ],
)
def test_default_port_removed_only_for_matching_scheme(
    url: str, port: int | None
) -> None:
    assert parse_url(url).port == port


def test_query_without_path_gets_root_path() -> None:
    assert parse_url("http://h.test?x=1").path_query == "/?x=1"


def test_fragment_is_dropped_even_when_it_contains_at_sign() -> None:
    parsed = parse_url("http://h.test/p#@evil.test")
    assert parsed.host == "h.test"
    assert parsed.userinfo is None
    assert parsed.path_query == "/p"


def test_userinfo_splits_on_last_at_sign() -> None:
    parsed = parse_url("http://a@b@h.test/")
    assert (parsed.userinfo, parsed.host) == ("a@b", "h.test")


def test_bracketed_ipv6_host_keeps_brackets_and_takes_port() -> None:
    parsed = parse_url("http://[::1]:8080/")
    assert (parsed.host, parsed.port) == ("[::1]", 8080)


def test_length_limit_boundary() -> None:
    prefix = "http://h.test/"
    assert parse_url(prefix + "a" * (MAX_URL_LENGTH - len(prefix))).host == "h.test"
    assert refusal_code(prefix + "a" * (MAX_URL_LENGTH - len(prefix) + 1)) == "too_long"


@pytest.mark.parametrize(
    "url",
    [
        "http://h.test/\x00",
        "http://h.test/\n",
        "http://h.test/\t",
        "http://h.test/\x7f",
        "http://h.test/\x85",
        "http://h.test/ a",
        " http://h.test/",
        f"http://h.test/{NO_BREAK_SPACE}",
        f"http://h.test/{LINE_SEPARATOR}",
        "http://h.test/\ud800",
        "http://good.test\\@evil.test/",
        "http://h.test/a\\b",
    ],
)
def test_control_whitespace_surrogate_and_backslash_are_refused(url: str) -> None:
    assert refusal_code(url) == "invalid_character"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "h.test",
        "//h.test",
        "http:/h.test",
        "http:h.test",
        "ftp://h.test",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/plain,x",
        "://h.test",
    ],
)
def test_non_http_or_malformed_scheme_is_refused(url: str) -> None:
    assert refusal_code(url) in {"bad_scheme", "missing_authority"}


@pytest.mark.parametrize(
    "url", ["http://", "http:///path", "http://:80/", "http://@/", "http://u@:80/"]
)
def test_empty_host_is_refused(url: str) -> None:
    assert refusal_code(url) == "empty_host"


@pytest.mark.parametrize(
    "url",
    [
        "http://h.test:/",
        "http://h.test:0/",
        "http://h.test:65536/",
        "http://h.test:80a/",
        "http://h.test:-1/",
        "http://h.test:1234567/",
    ],
)
def test_invalid_port_is_refused(url: str) -> None:
    assert refusal_code(url) == "invalid_port"


@pytest.mark.parametrize(
    "url",
    [
        "http://::1/",
        "http://[::1/",
        "http://[::1]x/",
        "http://[::1]:/",
        "http://a:b:c/",
    ],
)
def test_malformed_host_or_brackets_are_refused(url: str) -> None:
    assert refusal_code(url) in {"invalid_host", "invalid_port"}
