import pytest

from linkguard.heuristics import find_findings
from linkguard.host import normalize_host
from linkguard.model import DEFAULT_POLICY, Finding, Policy, Severity
from linkguard.parse import parse_url
from linkguard.reference_rules import HostParts, edit_distance, split_host


def findings_for(url: str, policy: Policy = DEFAULT_POLICY) -> list[Finding]:
    parsed = parse_url(url)
    return find_findings(parsed, normalize_host(parsed.host), policy)


def rule_ids(url: str, policy: Policy = DEFAULT_POLICY) -> list[str]:
    return [finding.rule_id for finding in findings_for(url, policy)]


@pytest.mark.parametrize(
    ("name", "parts"),
    [
        ("example.test", HostParts((), "example", "test")),
        ("www.example.test", HostParts(("www",), "example", "test")),
        ("a.b.example.co.uk", HostParts(("a", "b"), "example", "co.uk")),
        ("example.co.uk", HostParts((), "example", "co.uk")),
        ("co.uk", HostParts((), None, "co.uk")),
        ("localhost", HostParts((), None, "localhost")),
        # Documented wrong answer: the suffix data does not list co.xx, so "co" is
        # taken as the registrable label.
        ("www.example.co.xx", HostParts(("www", "example"), "co", "xx")),
    ],
)
def test_split_host_is_relative_to_the_listed_suffixes(
    name: str, parts: HostParts
) -> None:
    assert split_host(name) == parts


@pytest.mark.parametrize(
    ("a", "b", "distance"),
    [
        ("paypal", "paypal", 0),
        ("paypal", "paypa1", 1),
        ("paypal", "paypla", 1),
        ("paypal", "paypall", 1),
        ("paypal", "pypal", 1),
        ("microsoft", "rnicrosoft", 2),
        ("", "abc", 3),
        ("abc", "xyz", 3),
    ],
)
def test_edit_distance_counts_transpositions_as_one(
    a: str, b: str, distance: int
) -> None:
    assert edit_distance(a, b) == distance


@pytest.mark.parametrize(
    "url",
    [
        "http://paypa1.test/",
        "http://paypla.test/",
        "http://gogle.test/",
        "http://www.paypa1.test/",
        "http://paypa1.co.uk/",
        "http://rnicrosoft.test/",
        "http://micros0ft.test/",
    ],
)
def test_lg008_typosquat(url: str) -> None:
    found = {f.rule_id: f.severity for f in findings_for(url)}
    assert found["LG-008"] is Severity.MEDIUM


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal.com/",
        "http://paypal.test/",
        "http://www.paypal.co.uk/",
        "http://unrelated.test/",
        "http://bay.test/",
        "http://paypxx.test/",
        "http://microsoftxyz.test/",
        "http://paypa1.paypal.com/",
    ],
)
def test_lg008_near_misses(url: str) -> None:
    assert "LG-008" not in rule_ids(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal.evil.test/",
        "http://login-paypal.evil.test/",
        "http://paypal-login.evil.test/",
        "http://paypal.com.evil.test/",
        "http://www.paypal.evil.test/",
        "http://secure.microsoft.evil.co.uk/",
    ],
)
def test_lg009_brand_in_subdomain(url: str) -> None:
    found = {f.rule_id: f.severity for f in findings_for(url)}
    assert found["LG-009"] is Severity.HIGH


@pytest.mark.parametrize(
    "url",
    [
        "http://www.paypal.com/",
        "http://paypal.com/",
        "http://accounts.paypal.com/",
        "http://paypal.co.uk/",
        "http://pineapple.evil.test/",
        "http://paypalx.evil.test/",
        "http://evil.test/paypal",
        "http://login.microsoft.com/",
        "http://login.live.com/",
        "http://203.0.113.7/",
    ],
)
def test_lg009_near_misses(url: str) -> None:
    assert "LG-009" not in rule_ids(url)


@pytest.mark.parametrize(
    ("url", "policy", "fires"),
    [
        ("http://a.b.c.d.example.test/", DEFAULT_POLICY, False),
        ("http://a.b.c.d.e.example.test/", DEFAULT_POLICY, True),
        ("http://a.b.c.d.example.co.uk/", DEFAULT_POLICY, False),
        ("http://a.b.c.d.e.example.co.uk/", DEFAULT_POLICY, True),
        ("http://a.b.example.test/", Policy(max_subdomain_depth=1), True),
        ("http://a.example.test/", Policy(max_subdomain_depth=1), False),
        ("http://203.0.113.7/", Policy(max_subdomain_depth=0), False),
    ],
)
def test_lg010_subdomain_depth(url: str, policy: Policy, fires: bool) -> None:
    assert ("LG-010" in rule_ids(url, policy)) is fires


@pytest.mark.parametrize(
    "url", ["http://example.tk/", "http://example.xyz/", "http://a.b.example.top/"]
)
def test_lg012_suspicious_tld(url: str) -> None:
    found = {f.rule_id: f.severity for f in findings_for(url)}
    assert found["LG-012"] is Severity.LOW


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/",
        "http://example.com/",
        "http://example.tkx/",
        "http://tk.example.com/",
        "http://203.0.113.7/",
    ],
)
def test_lg012_near_misses(url: str) -> None:
    assert "LG-012" not in rule_ids(url)


@pytest.mark.parametrize(
    "url", ["http://bit.ly/abc", "http://www.bit.ly/abc", "http://tinyurl.com/x"]
)
def test_lg013_shortener(url: str) -> None:
    found = {f.rule_id: f.severity for f in findings_for(url)}
    assert found["LG-013"] is Severity.LOW


@pytest.mark.parametrize(
    "url",
    [
        "http://bit.ly.evil.test/",
        "http://notbit.ly/",
        "http://bitly.test/",
        "http://bit.com/",
    ],
)
def test_lg013_near_misses(url: str) -> None:
    assert "LG-013" not in rule_ids(url)
