import asyncio
import ssl
import time
from collections.abc import Callable, Coroutine
from ipaddress import ip_address
from typing import Any

import httpx
import pytest

from linkguard import version
from linkguard.hop import (
    CONNECT_TIMEOUT,
    MAX_BODY_BYTES,
    HopClient,
    HopFailed,
    HopResponse,
)


def reply(
    status: int = 200, body: bytes = b"ok", headers: dict[str, str] | None = None
) -> httpx.Response:
    """A response whose body is still an unread stream, like one from a real socket."""
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


class Recorder:
    def __init__(
        self, respond: Callable[[httpx.Request], httpx.Response] | None = None
    ) -> None:
        self.requests: list[httpx.Request] = []
        self._respond = respond or (lambda request: reply())

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._respond(request)


def get(
    recorder: Callable[[httpx.Request], httpx.Response],
    *,
    scheme: str = "http",
    address: str = "8.8.8.8",
    port: int | None = None,
    hostname: str = "example.test",
    target: str = "/",
    timeout: float = 10.0,
) -> HopResponse:
    client = HopClient(transport=httpx.MockTransport(recorder))
    return run(
        client.get(
            scheme=scheme,
            address=ip_address(address),
            port=port,
            hostname=hostname,
            target=target,
            timeout=timeout,
        )
    )


def test_request_goes_to_the_ip_with_hostname_in_host_header_and_sni() -> None:
    recorder = Recorder()
    get(recorder, scheme="https", hostname="xn--bcher-kva.test", target="/a?b=1")
    (request,) = recorder.requests
    assert request.url.host == "8.8.8.8"
    assert str(request.url) == "https://8.8.8.8/a?b=1"
    assert request.headers["Host"] == "xn--bcher-kva.test"
    assert request.extensions["sni_hostname"] == "xn--bcher-kva.test"
    assert request.method == "GET"


def test_ipv6_literal_is_used_as_the_connection_host() -> None:
    recorder = Recorder()
    get(recorder, address="2606:4700:4700::1111")
    assert recorder.requests[0].url.host == "2606:4700:4700::1111"


@pytest.mark.parametrize(
    ("scheme", "port", "host_header", "url_port"),
    [
        ("http", None, "example.test", None),
        ("http", 443, "example.test:443", 443),
        ("https", 443, "example.test", None),
        ("https", 80, "example.test:80", 80),
    ],
)
def test_host_header_includes_only_non_default_ports(
    scheme: str, port: int | None, host_header: str, url_port: int | None
) -> None:
    recorder = Recorder()
    get(recorder, scheme=scheme, port=port)
    assert recorder.requests[0].headers["Host"] == host_header
    assert recorder.requests[0].url.port == url_port


def test_request_headers_are_fixed_and_carry_no_credentials() -> None:
    recorder = Recorder()
    get(recorder)
    headers = recorder.requests[0].headers
    assert headers["User-Agent"] == f"linkguard/{version()}"
    assert headers["Accept-Encoding"] == "identity"
    for name in ("Cookie", "Authorization", "Proxy-Authorization", "Referer"):
        assert name not in headers


def test_redirects_are_reported_not_followed() -> None:
    recorder = Recorder(lambda r: reply(302, b"", {"Location": "http://127.0.0.1/x"}))
    response = get(recorder)
    assert (response.status, response.location) == (302, "http://127.0.0.1/x")
    assert len(recorder.requests) == 1


def test_content_type_and_missing_location_are_reported() -> None:
    recorder = Recorder(lambda r: reply(200, b"x", {"Content-Type": "text/html"}))
    response = get(recorder)
    assert (response.content_type, response.location) == ("text/html", None)


@pytest.mark.parametrize(
    ("size", "read", "truncated"),
    [
        (0, 0, False),
        (MAX_BODY_BYTES - 1, MAX_BODY_BYTES - 1, False),
        (MAX_BODY_BYTES, MAX_BODY_BYTES, False),
        (MAX_BODY_BYTES + 1, MAX_BODY_BYTES, True),
        (10_000_000, MAX_BODY_BYTES, True),
    ],
)
def test_body_is_capped_at_the_limit(size: int, read: int, truncated: bool) -> None:
    response = get(Recorder(lambda r: reply(200, b"x" * size)))
    assert (response.bytes_read, response.truncated) == (read, truncated)


def test_cookies_set_by_a_response_are_not_sent_on_the_next_request() -> None:
    recorder = Recorder(lambda r: reply(200, b"", {"Set-Cookie": "id=1; Path=/"}))
    client = HopClient(transport=httpx.MockTransport(recorder))
    for _ in range(2):
        run(
            client.get(
                scheme="http",
                address=ip_address("8.8.8.8"),
                port=None,
                hostname="example.test",
                target="/",
                timeout=5,
            )
        )
    assert all("Cookie" not in request.headers for request in recorder.requests)


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (httpx.ConnectTimeout("t"), "timeout"),
        (httpx.ReadTimeout("t"), "timeout"),
        (httpx.ConnectError("refused"), "connect_failed"),
        (httpx.RemoteProtocolError("bad"), "http_error"),
        (httpx.ReadError("reset"), "http_error"),
    ],
)
def test_transport_errors_map_to_stable_reasons(error: Exception, reason: str) -> None:
    def raise_error(request: httpx.Request) -> httpx.Response:
        raise error

    with pytest.raises(HopFailed) as caught:
        get(raise_error)
    assert caught.value.reason == reason


def test_tls_failures_in_the_cause_chain_are_reported_as_tls_errors() -> None:
    def raise_tls(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("handshake") from ssl.SSLCertVerificationError(
            "bad cert"
        )

    with pytest.raises(HopFailed) as caught:
        get(raise_tls)
    assert caught.value.reason == "tls_error"


def test_connect_timeout_is_capped_by_the_remaining_time() -> None:
    recorder = Recorder()
    get(recorder, timeout=60.0)
    get(recorder, timeout=2.0)
    assert recorder.requests[0].extensions["timeout"]["connect"] == CONNECT_TIMEOUT
    assert recorder.requests[1].extensions["timeout"]["connect"] == 2.0
    assert recorder.requests[1].extensions["timeout"]["read"] == 2.0


@pytest.mark.parametrize("mutate", ["verify_none", "no_hostname_check"])
def test_weakened_tls_contexts_are_refused(mutate: str) -> None:
    context = ssl.create_default_context()
    if mutate == "verify_none":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.check_hostname = False
    with pytest.raises(ValueError, match="certificate"):
        HopClient(ssl_context=context)


def test_environment_proxies_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    assert HopClient()._new_client(5.0).trust_env is False


def test_a_hung_transport_is_cancelled_by_the_callers_deadline() -> None:
    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(60)
        return httpx.Response(200)

    client = HopClient(transport=httpx.MockTransport(hang))

    async def attempt() -> None:
        async with asyncio.timeout(0.3):
            await client.get(
                scheme="http",
                address=ip_address("8.8.8.8"),
                port=None,
                hostname="example.test",
                target="/",
                timeout=60,
            )

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        run(attempt())
    assert time.monotonic() - started < 3


@pytest.mark.parametrize("location", ["javascript:alert(1)", "http://[::1/"])
def test_a_location_httpx_cannot_parse_is_a_stable_failure_not_an_exception(
    location: str,
) -> None:
    recorder = Recorder(lambda r: reply(302, b"", {"Location": location}))
    with pytest.raises(HopFailed) as caught:
        get(recorder)
    assert caught.value.reason == "http_error"
