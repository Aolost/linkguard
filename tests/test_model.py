from linkguard.model import Finding, Severity, escape_text, sort_findings


def test_printable_ascii_passes_through_unchanged() -> None:
    assert escape_text("abc-123_~!?") == "abc-123_~!?"


def test_backslash_control_and_non_ascii_are_escaped() -> None:
    assert escape_text("a\\b") == "a\\\\b"
    assert escape_text("\x1b[31m") == "\\x1b[31m"
    assert escape_text("‮") == "\\u202e"
    assert escape_text("\U0001f600") == "\\U0001f600"
    assert escape_text("\ud800") == "\\ud800"


def test_output_is_always_printable_ascii() -> None:
    escaped = escape_text("".join(chr(i) for i in range(0x250)))
    assert escaped.isascii()
    assert all(" " <= char <= "~" for char in escaped)


def test_truncation_boundary() -> None:
    assert escape_text("a" * 200) == "a" * 200
    truncated = escape_text("a" * 201)
    assert len(truncated) == 200
    assert truncated.endswith("...")


def test_findings_sort_by_severity_then_rule_then_evidence() -> None:
    low = Finding("LG-005", Severity.LOW, "port 8080", "x")
    medium_b = Finding("LG-003", Severity.MEDIUM, "b", "x")
    medium_a = Finding("LG-003", Severity.MEDIUM, "a", "x")
    high = Finding("LG-004", Severity.HIGH, "z", "x")
    assert sort_findings([low, medium_b, high, medium_a]) == [
        high,
        medium_a,
        medium_b,
        low,
    ]
