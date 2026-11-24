import re
from pathlib import Path

import pytest

from linkguard.batch import MAX_FILE_BYTES, MAX_URLS
from linkguard.cli import main
from linkguard.fetch import SafeFetcher
from tests.chars import text

CLEAN = "http://example.test/"
SUSPICIOUS = "http://example.test:8080/"
DANGEROUS = "http://paypal.com@evil.test/"


def write(tmp_path: Path, content: str | bytes) -> str:
    path = tmp_path / "urls.txt"
    if isinstance(content, str):
        content = content.encode("utf-8")
    path.write_bytes(content)
    return str(path)


def run_batch(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, content: str | bytes
) -> tuple[int, str, str]:
    code = main(["batch", write(tmp_path, content)])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.mark.parametrize(
    ("urls", "code"),
    [
        ([CLEAN], 0),
        ([CLEAN, SUSPICIOUS], 1),
        ([CLEAN, SUSPICIOUS, DANGEROUS], 2),
        ([DANGEROUS, CLEAN], 2),
        ([CLEAN, "ftp://x.test/"], 3),
        ([DANGEROUS, "ftp://x.test/", CLEAN], 3),
    ],
)
def test_exit_code_is_the_maximum_over_all_entries(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, urls: list[str], code: int
) -> None:
    assert run_batch(capsys, tmp_path, "\n".join(urls) + "\n")[0] == code


def test_one_line_per_url_with_line_number_verdict_input_and_rules(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _, out, _ = run_batch(
        capsys, tmp_path, f"{CLEAN}\n{SUSPICIOUS}\n{DANGEROUS}\nftp://x.test/\n"
    )
    lines = out.splitlines()
    assert re.fullmatch(r"\s+1  NO_RED_FLAGS +http://example\.test/", lines[0])
    assert re.fullmatch(
        r"\s+2  SUSPICIOUS +http://example\.test:8080/  LG-005", lines[1]
    )
    assert re.fullmatch(
        r"\s+3  DANGEROUS +http://paypal\.com@evil\.test/  LG-002,LG-001", lines[2]
    )
    assert re.fullmatch(r"\s+4  REFUSED +ftp://x\.test/  bad_scheme", lines[3])
    assert lines[4] == "4 URLs: 1 NO_RED_FLAGS, 1 SUSPICIOUS, 1 DANGEROUS, 1 REFUSED"


def test_blank_lines_crlf_and_surrounding_whitespace_are_handled(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    content = f"\r\n  {CLEAN}  \r\n\n\t{SUSPICIOUS}\t\n\n"
    code, out, _ = run_batch(capsys, tmp_path, content)
    lines = out.splitlines()
    assert code == 1
    assert re.match(r"\s+2  NO_RED_FLAGS", lines[0])
    assert re.match(r"\s+4  SUSPICIOUS", lines[1])
    assert lines[2].startswith("2 URLs:")


def test_there_is_no_comment_syntax(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, out, _ = run_batch(capsys, tmp_path, f"# a comment\n{CLEAN}\n")
    assert code == 3
    assert "REFUSED" in out.splitlines()[0]


def test_other_line_separators_do_not_split_entries(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    content = f"{CLEAN}{text(0x0B)}{CLEAN}\n{CLEAN}{text(0x2028)}{CLEAN}\n"
    code, out, _ = run_batch(capsys, tmp_path, content)
    assert code == 3
    entries = out.splitlines()[:2]
    assert all("REFUSED" in line and "invalid_character" in line for line in entries)


def test_an_over_long_line_is_refused_on_its_own(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    long_line = "http://example.test/" + "a" * 3000
    code, out, _ = run_batch(capsys, tmp_path, f"{CLEAN}\n{long_line}\n{SUSPICIOUS}\n")
    lines = out.splitlines()
    assert code == 3
    assert "NO_RED_FLAGS" in lines[0]
    assert "REFUSED" in lines[1] and "too_long" in lines[1]
    assert "SUSPICIOUS" in lines[2]
    assert max(len(line) for line in lines) < 400


@pytest.mark.parametrize("content", ["", "\n\n\n", "   \n\t\n"])
def test_a_file_with_no_urls_is_an_error_with_no_stdout(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, content: str
) -> None:
    code, out, err = run_batch(capsys, tmp_path, content)
    assert (code, out) == (3, "")
    assert "no URLs" in err


def test_url_count_limit_boundary(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, out, _ = run_batch(capsys, tmp_path, "\n".join([CLEAN] * MAX_URLS))
    assert code == 0
    assert out.splitlines()[-1] == f"{MAX_URLS} URLs: {MAX_URLS} NO_RED_FLAGS"

    code, out, err = run_batch(capsys, tmp_path, "\n".join([CLEAN] * (MAX_URLS + 1)))
    assert (code, out) == (3, "")
    assert "more than 10000 URLs" in err


def test_file_size_limit_boundary(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    line = "http://example.test/" + "a" * 1900
    body = ("\n".join([line] * 500) + "\n").encode()
    exact = body + b"x" * (MAX_FILE_BYTES - len(body) - 1) + b"\n"
    assert len(exact) == MAX_FILE_BYTES
    code, out, err = run_batch(capsys, tmp_path, exact)
    assert code == 3 and "no URLs" not in err and "larger" not in err
    assert out.count("\n") == 502

    code, out, err = run_batch(capsys, tmp_path, exact + b"x")
    assert (code, out) == (3, "")
    assert "larger than 1 MiB" in err


def test_invalid_utf8_is_an_error_but_nul_bytes_just_refuse_the_entry(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, out, err = run_batch(capsys, tmp_path, b"http://example.test/\xff\xfe\n")
    assert (code, out) == (3, "")
    assert "not valid UTF-8" in err

    code, out, _ = run_batch(
        capsys, tmp_path, b"http://example.test/\x00\n" + CLEAN.encode() + b"\n"
    )
    assert code == 3
    assert (
        "invalid_character" in out.splitlines()[0]
        and "NO_RED_FLAGS" in out.splitlines()[1]
    )


def test_unreadable_files_are_errors(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    for target in (tmp_path / "missing.txt", tmp_path):
        code = main(["batch", str(target)])
        captured = capsys.readouterr()
        assert (code, captured.out) == (3, "")
        assert captured.err.startswith("Error: cannot read file")


def test_output_is_printable_ascii_and_never_says_safe(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    hostile = f"http://{text(0x1B)}x{text(0x202E)}.test/{text(0x1F600)}\nhttp://p{text(0x430)}ypal.test/\n"
    _, out, err = run_batch(capsys, tmp_path, f"{CLEAN}\n{hostile}")
    assert all(c == "\n" or " " <= c <= "~" for c in out + err)
    assert not re.search(r"\bsafe\b", out + err, re.IGNORECASE)


def test_batch_never_fetches(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def forbidden() -> SafeFetcher:
        raise AssertionError("batch built a fetcher")

    monkeypatch.setattr("linkguard.api.SafeFetcher", forbidden)
    assert run_batch(capsys, tmp_path, f"{CLEAN}\n{DANGEROUS}\n")[0] == 2


@pytest.mark.parametrize("option", ["--json", "--follow", "--online"])
def test_batch_has_no_json_follow_or_online_option(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, option: str
) -> None:
    code = main(["batch", write(tmp_path, CLEAN), option])
    captured = capsys.readouterr()
    assert (code, captured.out) == (3, "")
    assert "No such option" in captured.err


def test_batch_help_is_free_of_forbidden_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["batch", "--help"]) == 0
    out = capsys.readouterr().out.lower()
    assert "file" in out
    for forbidden in (
        "--json",
        "--follow",
        "--online",
        "ssrf",
        "insecure",
        "completion",
    ):
        assert forbidden not in out


def test_a_leading_utf8_byte_order_mark_is_ignored(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, out, _ = run_batch(
        capsys,
        tmp_path,
        b"\xef\xbb\xbf" + CLEAN.encode() + b"\n" + SUSPICIOUS.encode() + b"\n",
    )
    assert code == 1
    assert "NO_RED_FLAGS" in out.splitlines()[0] and "SUSPICIOUS" in out.splitlines()[1]
