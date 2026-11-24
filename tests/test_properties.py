from hypothesis import given
from hypothesis import strategies as st

from linkguard.host import Domain, IpHost, normalize_domain, normalize_host
from linkguard.parse import MAX_URL_LENGTH, ParsedUrl, ParseError, parse_url

# Biased towards the characters that make URL and host parsing interesting.
URLISH = st.text(alphabet="abcxX019.:/@[]%#?-\\ \tß。１\ud800ü", max_size=300)


@given(st.text(max_size=3000))
def test_parse_url_returns_a_result_or_parse_error_for_any_text(text: str) -> None:
    try:
        parsed = parse_url(text)
    except ParseError:
        return
    assert isinstance(parsed, ParsedUrl)
    assert len(text) <= MAX_URL_LENGTH


@given(URLISH.map(lambda tail: "http://" + tail))
def test_parse_url_accepted_hosts_have_no_forbidden_characters(url: str) -> None:
    try:
        parsed = parse_url(url)
    except ParseError:
        return
    assert parsed.host
    assert not set(parsed.host) & set("\\ \t/?#")


@given(URLISH)
def test_normalize_host_returns_a_result_or_parse_error_for_any_text(raw: str) -> None:
    try:
        host = normalize_host(raw)
    except ParseError:
        return
    assert isinstance(host, Domain | IpHost)


@given(URLISH)
def test_domain_normalization_is_idempotent(raw: str) -> None:
    try:
        first = normalize_domain(raw)
    except ParseError:
        return
    assert first.name.isascii()
    second = normalize_domain(first.name)
    assert second.name == first.name
    assert second.percent_encoded is False


@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_every_ipv4_value_round_trips_through_decimal_spelling(value: int) -> None:
    host = normalize_host(str(value))
    assert isinstance(host, IpHost)
    assert int(host.address) == value
    assert normalize_host(str(host.address)) == IpHost(
        address=host.address, canonical=True, percent_encoded=False
    )
