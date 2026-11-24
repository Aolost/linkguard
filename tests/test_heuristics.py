import time

import pytest

from linkguard.heuristics import _HOSTNAME_LIKE, find_findings
from linkguard.host import normalize_host
from linkguard.model import Finding, Severity
from linkguard.parse import parse_url
from tests.chars import U_DIAERESIS


def findings_for(url: str) -> list[Finding]:
    parsed = parse_url(url)
    return find_findings(parsed, normalize_host(parsed.host))


def rule_ids(url: str) -> list[str]:
    return [finding.rule_id for finding in findings_for(url)]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://u@h.test/", ["LG-001"]),
        ("http://user:pw@h.test/", ["LG-001"]),
        ("http://h.test/", []),
        ("http://h.test/path@x", []),
        ("http://h.test/?next=a@b", []),
    ],
)
def test_lg001_userinfo(url: str, expected: list[str]) -> None:
    assert rule_ids(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal.com@evil.test/",
        "http://paypal.com:x@evil.test/",
        "http://www.paypal.com%2flogin@evil.test/",
        "http://http%3a%2f%2fpaypal.test@evil.test/",
    ],
)
def test_lg002_userinfo_that_looks_like_a_destination(url: str) -> None:
    assert rule_ids(url) == ["LG-002", "LG-001"]


@pytest.mark.parametrize(
    "url", ["http://user@h.test/", "http://a.b@h.test/", "http://user:pw.d@h.test/"]
)
def test_lg002_near_misses(url: str) -> None:
    assert "LG-002" not in rule_ids(url)


def test_userinfo_password_never_appears_in_evidence() -> None:
    evidence = [
        f.evidence for f in findings_for("http://paypal.com:hunter2@evil.test/")
    ]
    assert evidence
    assert all("hunter2" not in text for text in evidence)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://203.0.113.7/", ["LG-003"]),
        ("http://[2001:db8::1]/", ["LG-003"]),
        ("http://example.test/", []),
        ("http://123.example.test/", []),
    ],
)
def test_lg003_raw_ip(url: str, expected: list[str]) -> None:
    assert rule_ids(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",
        "http://0x7f.1/",
        "http://0177.0.0.1/",
        "http://[::ffff:7f00:1]/",
        "http://[0:0:0:0:0:0:0:1]/",
    ],
)
def test_lg004_obfuscated_ip_is_high(url: str) -> None:
    found = {f.rule_id: f.severity for f in findings_for(url)}
    assert found["LG-004"] is Severity.HIGH
    assert "LG-003" in found


@pytest.mark.parametrize("url", ["http://203.0.113.7/", "http://[2001:db8::1]/"])
def test_lg004_canonical_ip_is_not_flagged(url: str) -> None:
    assert "LG-004" not in rule_ids(url)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://h.test:8080/", ["LG-005"]),
        ("http://h.test:443/", ["LG-005"]),
        ("https://h.test:80/", ["LG-005"]),
        ("https://h.test:443/", []),
        ("http://h.test:80/", []),
    ],
)
def test_lg005_non_default_port(url: str, expected: list[str]) -> None:
    assert rule_ids(url) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://ex%41mple.test/", ["LG-014"]),
        ("http://127%2e0%2e0%2e1/", ["LG-003", "LG-004", "LG-014"]),
        ("http://example.test/%41", []),
    ],
)
def test_lg014_percent_encoded_host(url: str, expected: list[str]) -> None:
    assert sorted(rule_ids(url)) == expected


def test_findings_are_sorted_and_deterministic() -> None:
    first = findings_for("http://paypal.com@2130706433:8080/")
    assert first == findings_for("http://paypal.com@2130706433:8080/")
    assert [f.severity for f in first] == sorted(
        (f.severity for f in first),
        key={Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}.__getitem__,
    )


def test_every_finding_has_bounded_ascii_evidence() -> None:
    url = "http://" + "%C3%BC" * 40 + f"@{U_DIAERESIS}.test:8080/"
    for finding in findings_for(url):
        assert finding.evidence.isascii()
        assert len(finding.evidence) <= 200
        assert finding.explanation


def test_hostname_like_detection_is_linear_on_hostile_userinfo() -> None:
    hostile = "a." * 10_000 + "1"
    started = time.perf_counter()
    assert _HOSTNAME_LIKE.search(hostile) is None
    assert time.perf_counter() - started < 1.0
