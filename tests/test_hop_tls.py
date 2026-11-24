"""HopClient against real sockets on loopback, including TLS with a throwaway CA."""

import asyncio
import ssl
import time
from collections.abc import Coroutine
from ipaddress import ip_address
from typing import Any

import pytest
import trustme

from linkguard.hop import MAX_BODY_BYTES, HopClient, HopFailed, HopResponse
from tests.loopback import LoopbackServer, ok

pytestmark = pytest.mark.loopback


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


class Pki:
    def __init__(self) -> None:
        self.ca = trustme.CA()

    def server_context(self, *names: str) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ca.issue_cert(*names).configure_cert(context)
        return context

    def client(self) -> HopClient:
        context = ssl.create_default_context()
        self.ca.configure_trust(context)
        return HopClient(ssl_context=context)


async def fetch(
    client: HopClient,
    server: LoopbackServer,
    *,
    scheme: str = "https",
    hostname: str = "example.test",
    timeout: float = 5.0,
) -> HopResponse:
    return await client.get(
        scheme=scheme,
        address=ip_address("127.0.0.1"),
        port=server.port,
        hostname=hostname,
        target="/p?q=1",
        timeout=timeout,
    )


def test_sni_and_host_header_are_the_hostname_not_the_ip() -> None:
    pki = Pki()

    async def scenario() -> tuple[HopResponse, LoopbackServer]:
        async with LoopbackServer(ok(), pki.server_context("example.test")) as server:
            return await fetch(pki.client(), server), server

    response, server = run(scenario())
    assert response.status == 200
    assert server.sni == ["example.test"]
    assert b"Host: example.test:" in server.requests[0]
    assert b"127.0.0.1" not in server.requests[0]


@pytest.mark.parametrize(
    "cert_names", [("other.test",), ("127.0.0.1",), ("*.example.test",)]
)
def test_certificate_for_another_name_is_rejected(cert_names: tuple[str, ...]) -> None:
    pki = Pki()

    async def scenario() -> None:
        async with LoopbackServer(ok(), pki.server_context(*cert_names)) as server:
            await fetch(pki.client(), server)

    with pytest.raises(HopFailed) as caught:
        run(scenario())
    assert caught.value.reason == "tls_error"


def test_untrusted_certificate_authority_is_rejected_by_default() -> None:
    pki = Pki()

    async def scenario() -> None:
        async with LoopbackServer(ok(), pki.server_context("example.test")) as server:
            await fetch(HopClient(), server)

    with pytest.raises(HopFailed) as caught:
        run(scenario())
    assert caught.value.reason == "tls_error"


def test_plain_http_works_and_sends_no_sni() -> None:
    async def scenario() -> tuple[HopResponse, LoopbackServer]:
        async with LoopbackServer(ok()) as server:
            return await fetch(HopClient(), server, scheme="http"), server

    response, server = run(scenario())
    assert response.status == 200
    assert server.sni == []
    assert b"Host: example.test:" in server.requests[0]


def test_server_cookies_are_not_replayed_to_the_next_request() -> None:
    async def scenario() -> LoopbackServer:
        async with LoopbackServer(ok(headers="Set-Cookie: id=1; Path=/\r\n")) as server:
            client = HopClient()
            await fetch(client, server, scheme="http")
            await fetch(client, server, scheme="http")
            return server

    server = run(scenario())
    assert len(server.requests) == 2
    assert all(b"Cookie" not in request for request in server.requests)


def test_body_over_the_cap_is_truncated_on_a_real_connection() -> None:
    async def scenario() -> HopResponse:
        async with LoopbackServer(ok(b"x" * (MAX_BODY_BYTES + 5000))) as server:
            return await fetch(HopClient(), server, scheme="http")

    response = run(scenario())
    assert (response.bytes_read, response.truncated) == (MAX_BODY_BYTES, True)


def test_connection_refused_is_a_stable_failure() -> None:
    async def scenario() -> None:
        async with LoopbackServer(ok()) as server:
            port = server.port
        client = HopClient()
        await client.get(
            scheme="http",
            address=ip_address("127.0.0.1"),
            port=port,
            hostname="example.test",
            target="/",
            timeout=5,
        )

    with pytest.raises(HopFailed) as caught:
        run(scenario())
    assert caught.value.reason == "connect_failed"


def test_oversized_response_headers_are_rejected() -> None:
    async def respond(_head: bytes, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 300_000 + b"\r\n\r\n")
        await writer.drain()

    async def scenario() -> None:
        async with LoopbackServer(respond) as server:
            await fetch(HopClient(), server, scheme="http")

    with pytest.raises(HopFailed) as caught:
        run(scenario())
    assert caught.value.reason == "http_error"


def test_a_handshake_that_never_completes_times_out() -> None:
    async def silent(_head: bytes, _writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(30)

    async def scenario() -> None:
        async with LoopbackServer(silent) as server:
            # The server speaks plain HTTP, so a TLS client hello is never answered.
            await fetch(HopClient(), server, scheme="https", timeout=0.5)

    started = time.monotonic()
    with pytest.raises(HopFailed) as caught:
        run(scenario())
    assert caught.value.reason == "timeout"
    assert time.monotonic() - started < 5


def test_a_slow_drip_body_is_stopped_by_the_callers_deadline() -> None:
    async def drip(_head: bytes, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
        while not writer.is_closing():
            writer.write(b"x")
            await writer.drain()
            await asyncio.sleep(0.05)

    async def scenario() -> None:
        async with LoopbackServer(drip) as server:
            async with asyncio.timeout(0.5):
                await fetch(HopClient(), server, scheme="http", timeout=30)

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        run(scenario())
    assert time.monotonic() - started < 5
