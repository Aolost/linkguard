import errno
import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from linkguard import inspect, version
from linkguard.cli import main
from linkguard.cli import run as run_cli
from linkguard.fetch import SafeFetcher
from linkguard.model import Policy
from tests.chars import text
from tests.fakes import make, redirect, reply


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def use_fetcher(monkeypatch: pytest.MonkeyPatch, fetcher: SafeFetcher) -> None:
    monkeypatch.setattr("linkguard.api.SafeFetcher", lambda: fetcher)


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://example.test/", 0),
        ("http://example.test:8080/", 1),
        ("http://example.tk/", 1),
        ("http://paypal.com@evil.test/", 2),
        ("http://2130706433/", 2),
        ("ftp://example.test/", 3),
        ("", 3),
        ("http://example.test:0/", 3),
    ],
)
def test_exit_codes_follow_the_verdict(
    capsys: pytest.CaptureFixture[str], url: str, code: int
) -> None:
    assert run(capsys, "check", url)[0] == code


def test_clean_url_says_no_red_flags_found_and_makes_no_safety_claim(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, out, _ = run(capsys, "check", "http://example.test/")
    assert "no red flags found" in out.lower()
    assert "not mean the URL is trustworthy" in out
    assert "NO_RED_FLAGS" in out


def test_findings_are_listed_with_rule_severity_evidence_and_explanation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, out, _ = run(capsys, "check", "http://paypal.com@evil.test:8080/x")
    assert "DANGEROUS" in out
    assert re.search(r"\[high\]\s+LG-002\s+paypal\.com", out)
    assert "The text before the @ looks like a destination." in out
    assert re.search(r"\[low\]\s+LG-005\s+port 8080", out)
    assert "http://evil.test:8080/x" in out


def test_refused_input_prints_the_reason_and_no_verdict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(capsys, "check", "ftp://example.test/")
    assert code == 3
    assert "bad_scheme" in out and "only http and https are accepted" in out
    assert "NO_RED_FLAGS" not in out and "SUSPICIOUS" not in out


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/",
        "http://paypal.com@evil.test/",
        "ftp://x.test/",
        "",
        "http://example.tk/",
    ],
)
def test_output_never_uses_the_word_safe(
    capsys: pytest.CaptureFixture[str], url: str
) -> None:
    for flags in ([], ["--json"]):
        _, out, err = run(capsys, "check", url, *flags)
        assert not re.search(r"\bsafe\b", out + err, re.IGNORECASE)


def test_output_is_printable_ascii_even_for_hostile_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = (
        f"http://{text(0x1B)}[31m{text(0x202E)}evil{text(0x430)}.test/{text(0x1F600)}"
    )
    for url in (
        hostile,
        f"http://p{text(0x430)}ypal.test/",
        f"http://b{text(0xFC)}cher.test/",
    ):
        for flags in ([], ["--json"]):
            _, out, err = run(capsys, "check", url, *flags)
            assert all(c == "\n" or " " <= c <= "~" for c in out + err)


def test_json_output_is_the_report_dictionary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(
        capsys, "check", "http://paypal.com@203.0.113.7:8080/a?b", "--json"
    )
    assert code == 2
    data = json.loads(out)
    assert data == inspect("http://paypal.com@203.0.113.7:8080/a?b").to_dict()
    assert data["schema_version"] == "1" and data["tool_version"] == version()


def test_json_for_refused_input_exits_three(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "check", "ftp://example.test/", "--json")
    assert code == 3
    assert json.loads(out)["outcome"] == "refused"


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["check"],
        ["check", "http://x.test/", "--nope"],
        ["bogus"],
        ["check", "a", "b"],
    ],
)
def test_usage_errors_exit_three_with_a_message_on_stderr(
    capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    code, out, err = run(capsys, *argv)
    assert code == 3
    assert out == ""
    assert err.startswith("Error:") or "Error:" in err


def test_usage_error_text_is_escaped(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(
        capsys, "check", "http://x.test/", f"--{text(0x1B)}bad{text(0x430)}"
    )
    assert code == 3
    assert all(c == "\n" or " " <= c <= "~" for c in err)


def test_help_succeeds_and_offers_only_the_documented_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(capsys, "check", "--help")
    assert code == 0
    assert "--follow" in out and "--json" in out
    for forbidden in ("--online", "ssrf", "insecure", "allow", "private", "completion"):
        assert forbidden not in out.lower()
    top = run(capsys, "--help")[1]
    assert "completion" not in top.lower()


def test_without_follow_no_fetcher_is_ever_built(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden() -> SafeFetcher:
        raise AssertionError("fetcher built without --follow")

    monkeypatch.setattr("linkguard.api.SafeFetcher", forbidden)
    assert run(capsys, "check", "http://example.test/")[0] == 0
    assert inspect("http://example.test/", Policy()).fetch.status == "not_requested"


def test_follow_reports_the_redirect_chain_and_keeps_the_verdict_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["Host"] == "example.test":
            return redirect("http://other.test/next")
        return reply(200, b"hello", {"Content-Type": "text/html"})

    fetcher, _, net = make(handler)
    use_fetcher(monkeypatch, fetcher)
    code, out, _ = run(capsys, "check", "http://example.test/", "--follow")
    assert code == 0
    assert "completed" in out and "http://other.test/next" in out
    assert "hop 1" in out and "hop 2" in out and "8.8.8.8" in out and "1.1.1.1" in out
    assert net.hosts == ["8.8.8.8", "1.1.1.1"]


def test_follow_json_contains_the_fetch_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fetcher, _, _ = make(lambda r: reply(200, b"hello"))
    use_fetcher(monkeypatch, fetcher)
    code, out, _ = run(capsys, "check", "http://example.test/", "--follow", "--json")
    fetch = json.loads(out)["fetch"]
    assert code == 0
    assert fetch["status"] == "completed" and fetch["bytes_read"] == 5
    assert fetch["hops"] == [
        {"url": "http://example.test/", "http_status": 200, "address": "8.8.8.8"}
    ]


def test_a_refused_fetch_exits_three_but_still_prints_the_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fetcher, _, net = make(lambda r: redirect("http://127.0.0.1/admin"))
    use_fetcher(monkeypatch, fetcher)
    code, out, _ = run(capsys, "check", "http://example.test/", "--follow")
    assert code == 3
    assert "NO_RED_FLAGS" in out and "refused" in out and "blocked_address" in out
    assert len(net.requests) == 1


def test_a_failed_fetch_exits_three_even_when_the_verdict_is_dangerous(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    fetcher, _, _ = make(fail, {"evil.test": [["8.8.8.8"]]})
    use_fetcher(monkeypatch, fetcher)
    code, out, _ = run(capsys, "check", "http://paypal.com@evil.test/", "--follow")
    assert code == 3
    assert "DANGEROUS" in out and "error" in out and "timeout" in out


def test_follow_is_not_attempted_for_refused_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden() -> SafeFetcher:
        raise AssertionError("fetcher built for refused input")

    monkeypatch.setattr("linkguard.api.SafeFetcher", forbidden)
    assert run(capsys, "check", "ftp://example.test/", "--follow")[0] == 3


def test_follow_through_the_library(monkeypatch: pytest.MonkeyPatch) -> None:
    fetcher, _, _ = make(lambda r: reply())
    use_fetcher(monkeypatch, fetcher)
    report = inspect("http://example.test/", Policy(follow=True))
    assert report.fetch.status == "completed"
    assert report.to_dict()["fetch"] == report.fetch.to_dict()


def test_server_controlled_content_type_is_escaped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = f"text/html{text(0x1B)}[31m{text(0x202E)}".encode()
    fetcher, _, _ = make(
        lambda r: httpx.Response(
            200, headers=[(b"Content-Type", raw)], stream=httpx.ByteStream(b"x")
        )
    )
    use_fetcher(monkeypatch, fetcher)
    for flags in ([], ["--json"]):
        _, out, _ = run(capsys, "check", "http://example.test/", "--follow", *flags)
        assert text(0x1B) not in out and text(0x202E) not in out
        assert all(c == "\n" or " " <= c <= "~" for c in out)


def test_module_entry_point_propagates_the_exit_code() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "linkguard", "check", "http://paypal.com@evil.test/"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 2
    assert "DANGEROUS" in result.stdout


def test_run_exits_with_the_command_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["linkguard", "check", "http://example.tk/"])
    with pytest.raises(SystemExit) as caught:
        run_cli()
    assert caught.value.code == 1


def test_python_dash_m_entry_point_runs_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["linkguard", "check", "ftp://x.test/"])
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("linkguard", run_name="__main__")
    assert caught.value.code == 3


def test_an_unexpected_error_exits_three_and_reveals_only_its_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("secret detail http://leak.test/")

    monkeypatch.setattr("linkguard.cli.inspect", boom)
    code, out, err = run(capsys, "check", "http://example.test/")
    assert (code, out) == (3, "")
    assert err == "Error: internal error (RuntimeError)\n"


def test_a_broken_pipe_exits_three_quietly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class ClosedPipe:
        def write(self, _text: str) -> int:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        def flush(self) -> None:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    monkeypatch.setattr(sys, "stdout", ClosedPipe())
    code = main(["check", "http://example.test/"])
    assert (code, capsys.readouterr().err) == (3, "")


def test_a_reader_that_closes_stdout_early_gets_exit_three_and_no_traceback(
    tmp_path: Path,
) -> None:
    urls = tmp_path / "urls.txt"
    urls.write_text("http://example.test/\n" * 6000, encoding="utf-8")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv built from sys.executable
        [sys.executable, "-m", "linkguard", "batch", str(urls)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None and proc.stderr is not None
    proc.stdout.readline()
    proc.stdout.close()
    returncode = proc.wait(timeout=120)
    err = proc.stderr.read()
    proc.stderr.close()
    assert returncode == 3
    assert "Traceback" not in err and "Exception ignored" not in err
