import asyncio
import os
import sys
from collections.abc import Coroutine
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest

from linkguard.host import normalize_host
from linkguard.resolve import HopRefused, SubprocessResolver, resolve_hop


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


class FakeResolver:
    """Returns the queued answers in order and counts calls."""

    def __init__(self, *answers: list[str] | OSError) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, float]] = []

    async def __call__(self, host: str, timeout: float) -> list[str]:
        self.calls.append((host, timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, OSError):
            raise answer
        return answer


def hop(host: str, resolver: FakeResolver) -> list[str]:
    addresses = run(resolve_hop(normalize_host(host), resolver, 5.0))
    return [str(address) for address in addresses]


def refusal(host: str, resolver: FakeResolver) -> HopRefused:
    with pytest.raises(HopRefused) as caught:
        hop(host, resolver)
    return caught.value


def test_public_answers_are_returned_in_order_and_resolver_called_once() -> None:
    resolver = FakeResolver(["8.8.8.8", "2606:4700:4700::1111"])
    assert hop("example.test", resolver) == ["8.8.8.8", "2606:4700:4700::1111"]
    assert resolver.calls == [("example.test", 5.0)]


def test_duplicate_answers_are_collapsed() -> None:
    assert hop("example.test", FakeResolver(["8.8.8.8", "8.8.8.8", "1.1.1.1"])) == [
        "8.8.8.8",
        "1.1.1.1",
    ]


@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],
        ["8.8.8.8", "127.0.0.1"],
        ["127.0.0.1", "8.8.8.8"],
        ["8.8.8.8", "169.254.169.254"],
        ["8.8.8.8", "::ffff:10.0.0.1"],
        ["2606:4700:4700::1111", "fe80::1"],
    ],
)
def test_any_blocked_address_refuses_the_whole_hop(answers: list[str]) -> None:
    error = refusal("example.test", FakeResolver(answers))
    assert error.reason == "blocked_address"


def test_rebinding_second_answer_is_never_consulted() -> None:
    resolver = FakeResolver(["8.8.8.8"], ["127.0.0.1"])
    assert hop("example.test", resolver) == ["8.8.8.8"]
    assert len(resolver.calls) == 1
    assert resolver.answers == [["127.0.0.1"]]


def test_empty_answer_is_refused() -> None:
    assert refusal("example.test", FakeResolver([])).reason == "no_addresses"


@pytest.mark.parametrize(
    "answer", [["not-an-ip"], ["8.8.8.8", ""], ["fe80::1%eth0"], ["8.8.8.8 "]]
)
def test_non_address_answers_are_refused_as_dns_failures(answer: list[str]) -> None:
    assert refusal("example.test", FakeResolver(answer)).reason == "dns_failed"


def test_resolver_os_error_is_a_dns_failure() -> None:
    assert refusal("example.test", FakeResolver(OSError("boom"))).reason == "dns_failed"


@pytest.mark.parametrize(
    "literal",
    ["127.0.0.1", "2130706433", "[::1]", "[::ffff:127.0.0.1]", "169.254.169.254"],
)
def test_blocked_ip_literals_are_refused_without_resolving(literal: str) -> None:
    resolver = FakeResolver()
    assert refusal(literal, resolver).reason == "blocked_address"
    assert resolver.calls == []


def test_public_ip_literal_is_allowed_without_resolving() -> None:
    resolver = FakeResolver()
    assert hop("8.8.8.8", resolver) == ["8.8.8.8"]
    assert resolver.calls == []


def child(code: str, *args: str) -> SubprocessResolver:
    return SubprocessResolver((sys.executable, "-I", "-c", code, *args))


def lookup(
    resolver: SubprocessResolver, host: str = "example.test", timeout: float = 5.0
) -> list[str]:
    return run(resolver(host, timeout))


@pytest.mark.parametrize(
    ("host", "expected"), [("127.0.0.1", "127.0.0.1"), ("::1", "::1")]
)
def test_default_child_resolves_numeric_hosts_without_network(
    host: str, expected: str
) -> None:
    assert lookup(SubprocessResolver(), host) == [expected]


def test_default_child_failure_is_a_dns_failure() -> None:
    with pytest.raises(HopRefused) as caught:
        lookup(SubprocessResolver(), "a\x00b")
    assert caught.value.reason == "dns_failed"


def test_child_output_is_parsed_line_by_line() -> None:
    assert lookup(child("print('8.8.8.8'); print('1.1.1.1')")) == ["8.8.8.8", "1.1.1.1"]


def test_child_with_no_output_gives_an_empty_answer() -> None:
    assert lookup(child("pass")) == []


@pytest.mark.parametrize(
    "code",
    [
        "import sys; sys.exit(3)",
        "print('x' * 5000)",
        "print('x' * 2000000)",
        "print('not-an-ip')",
        "print('8.8.8.8'); print('')",
        "print('fe80::1%eth0')",
        "raise SystemExit('boom')",
    ],
)
def test_misbehaving_child_fails_closed(code: str) -> None:
    with pytest.raises(HopRefused) as caught:
        lookup(child(code))
    assert caught.value.reason == "dns_failed"


def test_unstartable_child_fails_closed() -> None:
    with pytest.raises(HopRefused) as caught:
        lookup(SubprocessResolver(("/nonexistent/interpreter",)))
    assert caught.value.reason == "dns_failed"


def test_hung_child_times_out_and_is_killed_and_reaped(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid"
    code = (
        "import os, sys, time\n"
        "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
        "time.sleep(60)"
    )
    with pytest.raises(HopRefused) as caught:
        lookup(child(code, str(pid_file)), timeout=3.0)
    assert caught.value.reason == "dns_timeout"
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_child_that_never_closes_its_output_is_bounded_by_the_timeout() -> None:
    code = (
        "import sys, time\n"
        "sys.stdout.write('8.8.8.8')\n"
        "sys.stdout.flush()\n"
        "time.sleep(60)"
    )
    with pytest.raises(HopRefused) as caught:
        lookup(child(code), timeout=1.0)
    assert caught.value.reason == "dns_timeout"


def test_validation_works_end_to_end_with_the_default_child() -> None:
    addresses = run(resolve_hop(normalize_host("8.8.8.8"), SubprocessResolver(), 5.0))
    assert addresses == [ip_address("8.8.8.8")]
