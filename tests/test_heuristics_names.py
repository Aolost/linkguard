import pytest
from hypothesis import given
from hypothesis import strategies as st

from linkguard.heuristics import find_findings
from linkguard.host import normalize_host
from linkguard.model import DEFAULT_POLICY, Finding, Policy, Severity
from linkguard.parse import ParseError, parse_url


def text(*codepoints: int) -> str:
    """Build text from code points so look-alike characters never sit in the source."""
    return "".join(chr(codepoint) for codepoint in codepoints)


CYRILLIC_A = text(0x0430)
CYRILLIC_ER = text(0x0440)
GREEK_OMICRON = text(0x03BF)
U_DIAERESIS = text(0x00FC)
A_DIAERESIS = text(0x00E4)
CYRILLIC_WORD = text(0x043F, 0x0440, 0x0438, 0x043C, 0x0435, 0x0440)
GREEK_WORD = text(
    0x03C0, 0x03B1, 0x03C1, 0x03AC, 0x03B4, 0x03B5, 0x03B9, 0x03B3, 0x03BC, 0x03B1
)
JAPANESE_WORD = text(0x4F8B, 0x3048)


def findings_for(url: str, policy: Policy = DEFAULT_POLICY) -> list[Finding]:
    parsed = parse_url(url)
    return find_findings(parsed, normalize_host(parsed.host), policy)


def rule_ids(url: str, policy: Policy = DEFAULT_POLICY) -> list[str]:
    return [finding.rule_id for finding in findings_for(url, policy)]


@pytest.mark.parametrize(
    "url",
    [
        "http://xn--bcher-kva.test/",
        f"http://b{U_DIAERESIS}cher.test/",
        "http://www.xn--bcher-kva.test/",
        "http://sub.example.xn--p1ai/",
    ],
)
def test_lg006_punycode_label(url: str) -> None:
    found = {f.rule_id: f.severity for f in findings_for(url)}
    assert found["LG-006"] is Severity.LOW


@pytest.mark.parametrize(
    "url", ["http://example.test/", "http://a-xn--b.test/", "http://xn.test/"]
)
def test_lg006_near_misses(url: str) -> None:
    assert "LG-006" not in rule_ids(url)


@pytest.mark.parametrize(
    "url",
    [
        f"http://p{CYRILLIC_A}ypal.test/",
        f"http://g{GREEK_OMICRON}ogle.test/",
        f"http://{CYRILLIC_ER}aypal.test/",
        f"http://ok.p{CYRILLIC_A}ypal.test/",
    ],
)
def test_lg007_mixed_script_label_is_high(url: str) -> None:
    found = {f.rule_id: f.severity for f in findings_for(url)}
    assert found["LG-007"] is Severity.HIGH
    assert "LG-006" in found


@pytest.mark.parametrize(
    "url",
    [
        f"http://{CYRILLIC_WORD}.test/",
        f"http://{GREEK_WORD}.test/",
        "http://paypal-123.test/",
        f"http://{JAPANESE_WORD}.test/",
        f"http://{CYRILLIC_WORD}-1.test/",
        f"http://p{A_DIAERESIS}ypal.test/",
    ],
)
def test_lg007_near_misses(url: str) -> None:
    assert "LG-007" not in rule_ids(url)


def test_lg007_mixed_scripts_split_across_labels_do_not_fire() -> None:
    assert "LG-007" not in rule_ids(f"http://paypal.{CYRILLIC_WORD}.test/")


def test_lg007_evidence_is_escaped_ascii() -> None:
    (finding,) = [
        f
        for f in findings_for(f"http://p{CYRILLIC_A}ypal.test/")
        if f.rule_id == "LG-007"
    ]
    assert "\\u0430" in finding.evidence
    assert finding.evidence.isascii()


def host_of_length(length: int) -> str:
    suffix = ".test"
    return "a" * (length - len(suffix)) + suffix


@pytest.mark.parametrize(("length", "fires"), [(50, False), (51, True), (10, False)])
def test_lg011_long_hostname_boundary(length: int, fires: bool) -> None:
    url = f"http://{host_of_length(length)}/"
    assert ("LG-011" in rule_ids(url)) is fires


def test_lg011_threshold_comes_from_policy() -> None:
    url = f"http://{host_of_length(30)}/"
    assert "LG-011" not in rule_ids(url)
    assert "LG-011" in rule_ids(url, Policy(max_hostname_length=29))


def test_lg011_does_not_apply_to_ip_hosts() -> None:
    assert "LG-011" not in rule_ids(
        "http://203.0.113.7/", Policy(max_hostname_length=1)
    )


@given(
    st.text(alphabet="abcxn-.0129%" + text(0x00DF, 0x0430, 0x03BF, 0x4F8B), max_size=60)
)
def test_name_rules_never_raise_for_any_accepted_host(raw: str) -> None:
    try:
        host = normalize_host(raw)
    except ParseError:
        return
    parsed = parse_url("http://example.test/")
    assert all(f.evidence.isascii() for f in find_findings(parsed, host, Policy()))
