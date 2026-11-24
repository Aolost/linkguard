"""A tiny HTTP/1.1 server on 127.0.0.1 for tests; TLS optional."""

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from types import TracebackType

Responder = Callable[[bytes, asyncio.StreamWriter], Awaitable[None]]


class LoopbackServer:
    def __init__(self, respond: Responder, tls: ssl.SSLContext | None = None) -> None:
        self._respond = respond
        self._tls = tls
        self._server: asyncio.Server | None = None
        self.requests: list[bytes] = []
        self.sni: list[str | None] = []
        self.port = 0

    def _record_sni(
        self, _sock: object, server_name: str | None, _context: ssl.SSLContext
    ) -> None:
        self.sni.append(server_name)

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            self.requests.append(head)
            await self._respond(head, writer)
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    async def __aenter__(self) -> "LoopbackServer":
        if self._tls is not None:
            self._tls.sni_callback = self._record_sni
        self._server = await asyncio.start_server(
            self._serve, "127.0.0.1", 0, ssl=self._tls
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        assert self._server is not None
        self._server.close()
        await asyncio.wait_for(self._server.wait_closed(), 5)


def ok(body: bytes = b"ok", headers: str = "") -> Responder:
    async def respond(_head: bytes, writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n"
            % (len(body), headers.encode())
            + body
        )
        await writer.drain()

    return respond
