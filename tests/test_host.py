import pytest

from linkguard.host import Domain, normalize_domain
from linkguard.parse import ParseError


def refusal_code(raw: str) -> str:
    with pytest.raises(ParseError) as caught:
        normalize_domain(raw)
    return caught.value.code


@pytest.mark.parametrize(
    ("raw", "name"),
    [
        ("example.test", "example.test"),
        ("EXAMPLE.Test", "example.test"),
        ("example.test.", "example.test"),
        ("b%C3%BCcher.test", "xn--bcher-kva.test"),
        ("bücher.test", "xn--bcher-kva.test"),
        ("faß.de", "xn--fa-hia.de"),
        ("ｅｘａｍｐｌｅ．ｔｅｓｔ", "example.test"),
        ("xn--bcher-kva.test", "xn--bcher-kva.test"),
    ],
)
def test_names_are_normalized_to_ascii(raw: str, name: str) -> None:
    assert normalize_domain(raw).name == name


@pytest.mark.parametrize(
    ("raw", "name"),
    [("example%2etest", "example.test"), ("ex%41mple.test", "example.test")],
)
def test_percent_decoding_is_applied_once_and_flagged(raw: str, name: str) -> None:
    assert normalize_domain(raw) == Domain(name=name, percent_encoded=True)


def test_plain_host_is_not_flagged_as_percent_encoded() -> None:
    assert normalize_domain("example.test").percent_encoded is False


@pytest.mark.parametrize(
    "raw",
    ["example%252etest", "example%zz.test", "example%.test", "%25.test"],
)
def test_remaining_percent_after_decoding_is_refused(raw: str) -> None:
    assert refusal_code(raw) == "invalid_host"


def test_percent_sequences_that_are_not_utf8_are_refused() -> None:
    assert refusal_code("ex%ffample.test") == "invalid_host"


@pytest.mark.parametrize(
    "raw",
    ["", ".", "example.test..", ".example.test", "a..b.test", "-bad.test", "xn--.test"],
)
def test_empty_labels_and_invalid_labels_are_refused(raw: str) -> None:
    assert refusal_code(raw) == "invalid_host"


@pytest.mark.parametrize(
    "raw", ["under_score.test", "a!b.test", "a$b.test", "a b.test"]
)
def test_characters_outside_letters_digits_hyphen_are_refused(raw: str) -> None:
    assert refusal_code(raw) == "invalid_host"


def test_label_length_boundary() -> None:
    assert normalize_domain("a" * 63 + ".test").name == "a" * 63 + ".test"
    assert refusal_code("a" * 64 + ".test") == "invalid_host"


def test_total_length_boundary() -> None:
    at_limit = ".".join(["a" * 63, "a" * 63, "a" * 63, "a" * 61])
    assert len(at_limit) == 253
    assert normalize_domain(at_limit).name == at_limit
    assert refusal_code(at_limit + "a") == "invalid_host"
