import json
import re
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from linkguard import inspect, version
from linkguard.model import EVIDENCE_LIMIT, Verdict
from tests.chars import text

GOLDEN = json.loads((Path(__file__).parent / "golden" / "report_v1.json").read_text())


def as_golden_dict(url: str) -> dict[str, object]:
    data = inspect(url).to_dict()
    assert data["tool_version"] == version()
    data["tool_version"] = "<version>"
    return data


def test_report_matches_the_golden_file_for_an_inspected_url() -> None:
    assert (
        as_golden_dict("http://paypal.com@203.0.113.7:8080/a?b") == GOLDEN["inspected"]
    )


def test_report_matches_the_golden_file_for_a_refused_url() -> None:
    assert as_golden_dict("ftp://example.test/") == GOLDEN["refused"]


@pytest.mark.parametrize(
    ("url", "verdict"),
    [
        ("http://example.test/", Verdict.NO_RED_FLAGS),
        ("http://example.test:8080/", Verdict.SUSPICIOUS),
        ("http://example.tk/", Verdict.SUSPICIOUS),
        ("http://paypal.com@evil.test/", Verdict.DANGEROUS),
        ("http://2130706433/", Verdict.DANGEROUS),
    ],
)
def test_verdict_follows_the_highest_severity(url: str, verdict: Verdict) -> None:
    assert inspect(url).verdict is verdict


@pytest.mark.parametrize(
    "url", ["", "http://", "ftp://x.test/", "http://x.test:0/", " http://x.test/"]
)
def test_refused_input_has_no_verdict_and_a_stable_code(url: str) -> None:
    report = inspect(url)
    assert report.outcome == "refused"
    assert report.verdict is None
    assert report.normalized_url is None
    assert report.refusal is not None
    assert report.findings == ()


@pytest.mark.parametrize(
    ("url", "normalized"),
    [
        ("HTTPS://Example.test:443/a?b#frag", "https://example.test/a?b"),
        ("http://2130706433/", "http://127.0.0.1/"),
        ("http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/"),
        ("http://[2001:DB8:0:0::1]:8080/", "http://[2001:db8::1]:8080/"),
        ("http://example.test.", "http://example.test/"),
        ("http://u:p@h.test", "http://h.test/"),
        ("http://127%2e0%2e0%2e1/", "http://127.0.0.1/"),
        (f"http://b%C3%BCcher.test/p{text(0xFC)}", "http://xn--bcher-kva.test/p%C3%BC"),
    ],
)
def test_normalized_url(url: str, normalized: str) -> None:
    assert inspect(url).normalized_url == normalized


def test_input_is_escaped_and_bounded_even_for_huge_input() -> None:
    report = inspect("http://" + "a" * 10_000_000)
    assert report.refusal is not None and report.refusal.code == "too_long"
    assert len(report.input) <= EVIDENCE_LIMIT
    assert inspect("http://x.test/" + text(0x202E, 0x1B)).input.isascii()


def test_output_never_says_safe() -> None:
    urls = ["http://example.test/", "http://paypal.com@evil.test/", "ftp://x/", ""]
    for url in urls:
        assert not re.search(
            r"\bsafe\b", json.dumps(inspect(url).to_dict()), re.IGNORECASE
        )


def test_json_is_printable_ascii_for_hostile_input() -> None:
    url = f"http://{text(0x202E)}p{text(0x430)}ypal.test/{text(0x1F600)}"
    dumped = json.dumps(inspect(url).to_dict(), ensure_ascii=False)
    assert all(" " <= char <= "~" for char in dumped)


URLISH = st.text(
    alphabet="abcxX019.:/@[]%#?-\\ \t" + text(0xFC) + "\ud800", max_size=200
).map(lambda tail: "http://" + tail)


@given(st.text(max_size=3000))
def test_inspect_never_raises_for_any_text(url: str) -> None:
    assert inspect(url).outcome in {"inspected", "refused"}


@given(URLISH)
def test_normalized_url_is_idempotent(url: str) -> None:
    first = inspect(url).normalized_url
    if first is not None:
        assert inspect(first).normalized_url == first
