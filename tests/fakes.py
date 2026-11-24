"""Fakes shared by the fetcher and CLI tests: a fake resolver and a fake network."""

from collections.abc import Awaitable, Callable

import httpx

from linkguard.fetch import TOTAL_TIMEOUT, SafeFetcher
from linkguard.hop import HopClient

Handler = Callable[[httpx.Request], httpx.Response | Awaitable[httpx.Response]]


def reply(
    status: int = 200, body: bytes = b"ok", headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


def redirect(location: str, status: int = 302) -> httpx.Response:
    # Raw bytes, like a real server: arbitrary text is not guaranteed to be ASCII.
    headers = [(b"Location", location.encode("utf-8"))]
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(b""))


class FakeDns:
    """Maps names to queued answers; the last one repeats. Unknown names are public."""

    def __init__(self, table: dict[str, list[list[str]]]) -> None:
        self.table = {name: list(answers) for name, answers in table.items()}
        self.calls: list[tuple[str, float]] = []

    async def __call__(self, host: str, timeout: float) -> list[str]:
        self.calls.append((host, timeout))
        answers = self.table.get(host, [["8.8.8.8"]])  # unknown names are public
        return answers.pop(0) if len(answers) > 1 else answers[0]


class Net:
    """A fake network: records every request the client actually sends."""

    def __init__(self, handler: Handler) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        result = self._handler(request)
        return result if isinstance(result, httpx.Response) else await result

    @property
    def hosts(self) -> list[str]:
        return [request.url.host for request in self.requests]


def make(
    handler: Handler,
    dns: dict[str, list[list[str]]] | None = None,
    total_timeout: float = TOTAL_TIMEOUT,
) -> tuple[SafeFetcher, FakeDns, Net]:
    resolver = FakeDns(
        dns or {"example.test": [["8.8.8.8"]], "other.test": [["1.1.1.1"]]}
    )
    net = Net(handler)
    fetcher = SafeFetcher(
        resolver=resolver,
        hop_client=HopClient(transport=httpx.MockTransport(net)),
        total_timeout=total_timeout,
    )
    return fetcher, resolver, net
