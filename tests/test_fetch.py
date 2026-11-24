import asyncio
import time
from typing import Any

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from linkguard.fetch import MAX_REDIRECTS, TOTAL_TIMEOUT, SafeFetcher
from linkguard.hop import HopClient
from linkguard.model import FetchSummary, Hop
from tests.fakes import Handler, Net, make, redirect, reply


def fetch(fetcher: SafeFetcher, url: str) -> FetchSummary:
    return asyncio.run(fetcher.fetch(url))


def test_single_hop_completes_and_reports_the_validated_address() -> None:
    fetcher, dns, net = make(
        lambda r: reply(200, b"hello", {"Content-Type": "text/html"})
    )
    result = fetch(fetcher, "HTTP://Example.test/a?b#frag")
    assert result.status == "completed"
    assert result.hops == (Hop("http://example.test/a?b", 200, "8.8.8.8"),)
    assert (result.final_url, result.http_status) == ("http://example.test/a?b", 200)
    assert (result.content_type, result.bytes_read, result.truncated) == (
        "text/html",
        5,
        False,
    )
    assert net.hosts == ["8.8.8.8"]
    assert net.requests[0].headers["Host"] == "example.test"
    assert [call[0] for call in dns.calls] == ["example.test"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_followed_and_every_hop_is_resolved_and_validated(
    status: int,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["Host"] == "example.test":
            return redirect("http://other.test/next", status)
        return reply(200, b"done")

    fetcher, dns, net = make(handler)
    result = fetch(fetcher, "http://example.test/")
    assert result.status == "completed"
    assert [hop.address for hop in result.hops] == ["8.8.8.8", "1.1.1.1"]
    assert result.final_url == "http://other.test/next"
    assert [call[0] for call in dns.calls] == ["example.test", "other.test"]
    assert net.hosts == ["8.8.8.8", "1.1.1.1"]


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("/next?x=1", "http://example.test/next?x=1"),
        ("next", "http://example.test/dir/next"),
        ("?only=query", "http://example.test/dir/page?only=query"),
        ("//other.test/p", "http://other.test/p"),
        ("https://other.test/p", "https://other.test/p"),
        ("http://user:pw@other.test/p", "http://other.test/p"),
    ],
)
def test_location_is_resolved_against_the_current_url(
    location: str, expected: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        first = request.url.path == "/dir/page" and not request.url.query
        return redirect(location) if first else reply()

    fetcher, _, net = make(handler)
    result = fetch(fetcher, "http://example.test/dir/page")
    assert result.status == "completed"
    assert result.final_url == expected
    assert all(not r.url.userinfo for r in net.requests)
    assert all("Authorization" not in r.headers for r in net.requests)


def test_a_redirect_status_without_location_completes() -> None:
    fetcher, _, net = make(lambda r: reply(302, b""))
    assert fetch(fetcher, "http://example.test/").status == "completed"
    assert len(net.requests) == 1


def test_non_redirect_status_with_location_is_not_followed() -> None:
    fetcher, _, net = make(
        lambda r: reply(200, b"", {"Location": "http://other.test/"})
    )
    assert fetch(fetcher, "http://example.test/").status == "completed"
    assert len(net.requests) == 1


def test_up_to_five_redirects_are_followed_and_the_sixth_is_refused() -> None:
    def chain(limit: int) -> Handler:
        def handler(request: httpx.Request) -> httpx.Response:
            step = int(request.url.path.strip("/") or 0)
            return redirect(f"/{step + 1}") if step < limit else reply()

        return handler

    fetcher, _, net = make(chain(MAX_REDIRECTS))
    done = fetch(fetcher, "http://example.test/")
    assert (done.status, len(done.hops)) == ("completed", MAX_REDIRECTS + 1)

    fetcher, _, net = make(chain(MAX_REDIRECTS + 1))
    refused = fetch(fetcher, "http://example.test/")
    assert (refused.status, refused.reason) == ("refused", "redirect_limit")
    assert len(refused.hops) == MAX_REDIRECTS + 1
    assert len(net.requests) == MAX_REDIRECTS + 1


def test_a_redirect_loop_is_bounded() -> None:
    fetcher, _, net = make(lambda r: redirect("/"))
    result = fetch(fetcher, "http://example.test/")
    assert result.reason == "redirect_limit"
    assert len(net.requests) == MAX_REDIRECTS + 1


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/passwd",
        "ftp://other.test/",
        "http://other.test/a b",
        "http://other.test\\@evil.test/",
        "http://",
        "x" * 3000,
        "http://other.test:99999/",
    ],
)
def test_unusable_redirect_targets_are_refused(location: str) -> None:
    fetcher, _, net = make(lambda r: redirect(location))
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("refused", "invalid_redirect")
    assert len(net.requests) == 1


@pytest.mark.parametrize("location", ["javascript:alert(1)", "http://[::1/"])
def test_locations_the_http_library_rejects_fail_closed_as_http_errors(
    location: str,
) -> None:
    # httpx validates Location itself while building its redirect object, before
    # linkguard sees the value. Pinned to the locked version; still fails closed.
    fetcher, _, net = make(lambda r: redirect(location))
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("error", "http_error")
    assert len(net.requests) == 1


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/",
        "http://2130706433/",
        "http://[::1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_redirect_to_a_blocked_ip_literal_is_refused_without_connecting(
    location: str,
) -> None:
    fetcher, dns, net = make(lambda r: redirect(location))
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("refused", "blocked_address")
    assert len(net.requests) == 1
    assert [call[0] for call in dns.calls] == ["example.test"]


def test_redirect_to_a_name_that_resolves_to_a_blocked_address_is_refused() -> None:
    fetcher, _, net = make(
        lambda r: redirect("http://internal.test/"),
        {"example.test": [["8.8.8.8"]], "internal.test": [["10.0.0.5"]]},
    )
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("refused", "blocked_address")
    assert net.hosts == ["8.8.8.8"]


def test_rebinding_between_hops_is_caught_because_every_hop_is_revalidated() -> None:
    fetcher, dns, net = make(
        lambda r: redirect("http://example.test/second"),
        {"example.test": [["8.8.8.8"], ["127.0.0.1"]]},
    )
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("refused", "blocked_address")
    assert net.hosts == ["8.8.8.8"]
    assert len(dns.calls) == 2


def test_one_blocked_answer_among_public_ones_means_no_connection_at_all() -> None:
    fetcher, _, net = make(
        lambda r: reply(), {"example.test": [["8.8.8.8", "10.0.0.1"]]}
    )
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("refused", "blocked_address")
    assert net.requests == []


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1/", "http://[::1]:80/", "http://0x7f.1/"]
)
def test_blocked_ip_literal_in_the_first_url_is_refused_without_resolving(
    url: str,
) -> None:
    fetcher, dns, net = make(lambda r: reply())
    result = fetch(fetcher, url)
    assert (result.status, result.reason) == ("refused", "blocked_address")
    assert dns.calls == [] and net.requests == []


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("http://example.test/", True),
        ("https://example.test/", True),
        ("http://example.test:443/", True),
        ("https://example.test:80/", True),
        ("http://example.test:8080/", False),
        ("https://example.test:8443/", False),
        ("http://example.test:22/", False),
    ],
)
def test_only_ports_80_and_443_are_allowed(url: str, allowed: bool) -> None:
    fetcher, dns, net = make(lambda r: reply())
    result = fetch(fetcher, url)
    if allowed:
        assert result.status == "completed"
    else:
        assert (result.status, result.reason) == ("refused", "port_not_allowed")
        assert dns.calls == [] and net.requests == []


def test_redirect_to_a_disallowed_port_is_refused() -> None:
    fetcher, _, net = make(lambda r: redirect("http://other.test:8080/"))
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("refused", "port_not_allowed")
    assert len(net.requests) == 1


@pytest.mark.parametrize(
    "url", ["", "ftp://example.test/", "http://", "http://example.test:0/"]
)
def test_an_unusable_first_url_is_refused(url: str) -> None:
    fetcher, _, net = make(lambda r: reply())
    result = fetch(fetcher, url)
    assert (result.status, result.reason) == ("refused", "invalid_url")
    assert net.requests == []


def test_set_cookie_is_never_replayed_and_no_credentials_are_sent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return reply(302, b"", {"Location": "/next", "Set-Cookie": "id=1; Path=/"})
        return reply()

    fetcher, _, net = make(handler)
    assert fetch(fetcher, "http://user:pw@example.test/").status == "completed"
    for request in net.requests:
        for name in ("Cookie", "Authorization", "Proxy-Authorization"):
            assert name not in request.headers
        assert not request.url.userinfo


def test_at_most_three_addresses_are_tried_and_only_after_connect_failures() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    fetcher, _, net = make(
        refuse,
        {"example.test": [["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "1.0.0.1"]]},
    )
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("error", "connect_failed")
    assert net.hosts == ["8.8.8.8", "8.8.4.4", "1.1.1.1"]


def test_a_later_address_is_used_when_the_first_refuses_the_connection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "8.8.8.8":
            raise httpx.ConnectError("refused")
        return reply()

    fetcher, dns, _ = make(handler, {"example.test": [["8.8.8.8", "8.8.4.4"]]})
    result = fetch(fetcher, "http://example.test/")
    assert result.status == "completed"
    assert result.hops[0].address == "8.8.4.4"
    assert len(dns.calls) == 1


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (httpx.ReadTimeout("t"), "timeout"),
        (httpx.RemoteProtocolError("bad"), "http_error"),
    ],
)
def test_other_hop_failures_stop_without_trying_more_addresses(
    error: Exception, reason: str
) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise error

    fetcher, _, net = make(fail, {"example.test": [["8.8.8.8", "8.8.4.4"]]})
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("error", reason)
    assert len(net.requests) == 1


def test_dns_failures_are_errors_and_an_empty_answer_is_a_refusal() -> None:
    class Broken:
        async def __call__(self, host: str, timeout: float) -> list[str]:
            raise OSError("no resolver")

    net = Net(lambda r: reply())
    client = HopClient(transport=httpx.MockTransport(net))
    broken = fetch(
        SafeFetcher(resolver=Broken(), hop_client=client), "http://example.test/"
    )
    assert (broken.status, broken.reason) == ("error", "dns_failed")

    fetcher, _, _ = make(lambda r: reply(), {"example.test": [[]]})
    empty = fetch(fetcher, "http://example.test/")
    assert (empty.status, empty.reason) == ("refused", "no_addresses")


def test_dns_wait_is_capped_by_five_seconds_and_by_the_remaining_time() -> None:
    fetcher, dns, _ = make(lambda r: reply())
    fetch(fetcher, "http://example.test/")
    assert 0 < dns.calls[0][1] <= 5.0

    fetcher, dns, _ = make(lambda r: reply(), total_timeout=2.0)
    fetch(fetcher, "http://example.test/")
    assert 0 < dns.calls[0][1] <= 2.0


def test_the_total_limit_can_be_lowered_but_never_raised() -> None:
    assert SafeFetcher(total_timeout=3.0)._total == 3.0
    assert SafeFetcher(total_timeout=9999.0)._total == TOTAL_TIMEOUT == 10.0


def test_a_hung_connection_hits_the_total_deadline() -> None:
    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(60)
        return reply()

    fetcher, _, _ = make(hang, total_timeout=0.4)
    started = time.monotonic()
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("error", "timeout")
    assert time.monotonic() - started < 3


def test_a_hung_resolver_hits_the_total_deadline() -> None:
    async def hang(host: str, timeout: float) -> list[str]:
        await asyncio.sleep(60)
        return ["8.8.8.8"]

    client = HopClient(transport=httpx.MockTransport(Net(lambda r: reply())))
    fetcher = SafeFetcher(resolver=hang, hop_client=client, total_timeout=0.4)
    started = time.monotonic()
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("error", "timeout")
    assert time.monotonic() - started < 3


def test_the_deadline_covers_all_hops_together_and_keeps_completed_hops() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.25)
        return redirect("/again")

    fetcher, _, _ = make(slow, total_timeout=0.6)
    result = fetch(fetcher, "http://example.test/")
    assert (result.status, result.reason) == ("error", "timeout")
    assert 1 <= len(result.hops) <= 3


def test_a_fetcher_can_be_reused_and_run_concurrently() -> None:
    fetcher, _, _ = make(lambda r: reply())

    async def many() -> list[FetchSummary]:
        return list(
            await asyncio.gather(
                *(fetcher.fetch("http://example.test/") for _ in range(5))
            )
        )

    assert {r.status for r in asyncio.run(many())} == {"completed"}


@given(st.text(max_size=300))
def test_any_location_header_yields_a_summary_and_never_raises(location: str) -> None:
    fetcher, _, net = make(lambda r: redirect(location))
    result = fetch(fetcher, "http://example.test/")
    assert result.status in {"completed", "refused", "error"}
    assert all(request.url.host in {"8.8.8.8", "1.1.1.1"} for request in net.requests)


SCHEME_SHAPED = st.builds(
    lambda scheme, rest: scheme + rest,
    st.sampled_from(
        ["javascript:", "http://", "https://", "data:", "file://", "//", "http:", "x:"]
    ),
    st.text(alphabet="abc/@[]:.()%019 \\?#-", max_size=30),
)


@settings(max_examples=300, deadline=None)
@given(SCHEME_SHAPED)
def test_scheme_shaped_location_headers_never_make_fetch_raise(location: str) -> None:
    fetcher, _, net = make(lambda r: redirect(location))
    result = fetch(fetcher, "http://example.test/")
    assert result.status in {"completed", "refused", "error"}
    assert all(request.url.host in {"8.8.8.8", "1.1.1.1"} for request in net.requests)


def test_summary_serializes_to_the_documented_shape() -> None:
    fetcher, _, _ = make(lambda r: reply())
    data: dict[str, Any] = fetch(fetcher, "http://example.test/").to_dict()
    assert set(data) == {
        "status",
        "hops",
        "final_url",
        "http_status",
        "content_type",
        "bytes_read",
        "truncated",
        "reason",
    }
    assert data["hops"] == [
        {"url": "http://example.test/", "http_status": 200, "address": "8.8.8.8"}
    ]
