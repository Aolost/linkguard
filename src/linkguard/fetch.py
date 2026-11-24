"""SafeFetcher: validate every hop before connecting, then follow redirects by hand.

Every hop (the first URL and each redirect target) is parsed again, restricted to
ports 80 and 443, resolved once, and has all of its addresses checked before a single
connection is made. Nothing here can be configured to skip those checks.
"""

import asyncio
from urllib.parse import urljoin, urlsplit

from linkguard.hop import HopClient, HopFailed, HopResponse
from linkguard.host import Domain, normalize_host
from linkguard.model import FetchSummary, Hop, escape_text
from linkguard.parse import MAX_URL_LENGTH, ParseError, parse_url
from linkguard.resolve import HopRefused, Resolver, SubprocessResolver, resolve_hop
from linkguard.ssrf import IPAddress
from linkguard.urlnorm import normalized_target, normalized_url

TOTAL_TIMEOUT = 10.0
DNS_TIMEOUT = 5.0
MAX_REDIRECTS = 5
MAX_ADDRESSES = 3
_ALLOWED_PORTS = frozenset({None, 80, 443})  # None: the scheme's default port
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class _Stop(Exception):
    """Ends the fetch; `refused` separates policy refusals from operational errors."""

    def __init__(self, reason: str, *, refused: bool) -> None:
        super().__init__(reason)
        self.reason = reason
        self.refused = refused


def _stop_for(refusal: HopRefused) -> _Stop:
    return _Stop(
        refusal.reason, refused=refusal.reason in {"blocked_address", "no_addresses"}
    )


class SafeFetcher:
    """Fetches a URL and its redirects without ever connecting to a blocked address.

    The resolver and hop client are injectable so tests run without a network. The
    total time can be lowered for tests but never raised above `TOTAL_TIMEOUT`.
    """

    def __init__(
        self,
        resolver: Resolver | None = None,
        hop_client: HopClient | None = None,
        total_timeout: float = TOTAL_TIMEOUT,
    ) -> None:
        self._resolver: Resolver = resolver or SubprocessResolver()
        self._client = hop_client or HopClient()
        self._total = min(total_timeout, TOTAL_TIMEOUT)

    async def fetch(self, url: str) -> FetchSummary:
        hops: list[Hop] = []
        try:
            deadline = asyncio.get_running_loop().time() + self._total
            async with asyncio.timeout_at(deadline):
                return await self._follow(url, hops, deadline)
        except TimeoutError:
            return FetchSummary("error", tuple(hops), reason="timeout")
        except _Stop as stop:
            status = "refused" if stop.refused else "error"
            return FetchSummary(status, tuple(hops), reason=stop.reason)

    async def _follow(self, url: str, hops: list[Hop], deadline: float) -> FetchSummary:
        current = url
        for redirects_so_far in range(MAX_REDIRECTS + 1):
            response, hop_url, address = await self._hop(
                current, deadline, is_redirect=redirects_so_far > 0
            )
            hops.append(Hop(hop_url, response.status, str(address)))
            target = _redirect_target(response, hop_url)
            if target is None:
                return FetchSummary(
                    "completed",
                    tuple(hops),
                    final_url=hop_url,
                    http_status=response.status,
                    content_type=_escaped(response.content_type),
                    bytes_read=response.bytes_read,
                    truncated=response.truncated,
                )
            current = target
        raise _Stop("redirect_limit", refused=True)

    async def _hop(
        self, url: str, deadline: float, *, is_redirect: bool
    ) -> tuple[HopResponse, str, IPAddress]:
        try:
            parsed = parse_url(url)
            host = normalize_host(parsed.host)
            normalized = normalized_url(parsed, host)
        except ParseError as error:
            code = "invalid_redirect" if is_redirect else "invalid_url"
            raise _Stop(code, refused=True) from error
        if parsed.port not in _ALLOWED_PORTS:
            raise _Stop("port_not_allowed", refused=True)
        loop = asyncio.get_running_loop()
        try:
            addresses = await resolve_hop(
                host,
                self._resolver,
                min(DNS_TIMEOUT, max(deadline - loop.time(), 0.001)),
            )
        except HopRefused as refusal:
            raise _stop_for(refusal) from refusal
        for address in addresses[:MAX_ADDRESSES]:
            try:
                response = await self._client.get(
                    scheme=parsed.scheme,
                    address=address,
                    port=parsed.port,
                    hostname=host.name if isinstance(host, Domain) else str(address),
                    target=normalized_target(parsed),
                    timeout=max(deadline - loop.time(), 0.001),
                )
            except HopFailed as failure:
                if failure.reason != "connect_failed":
                    raise _Stop(failure.reason, refused=False) from failure
                continue
            return response, normalized, address
        raise _Stop("connect_failed", refused=False)


def _escaped(value: str | None) -> str | None:
    # Response headers are attacker-controlled and end up in terminal and JSON output.
    return None if value is None else escape_text(value)


def _redirect_target(response: HopResponse, current_url: str) -> str | None:
    """The redirect URL to try next, or None if the response is not a redirect."""
    if response.status not in _REDIRECT_STATUSES or response.location is None:
        return None
    if len(response.location) > MAX_URL_LENGTH:
        raise _Stop("invalid_redirect", refused=True)
    try:
        # A Location with its own scheme goes to the strict parser untouched: urljoin
        # would "repair" malformed absolute URLs (for example `http://`) by borrowing
        # the current host. Only scheme-less references are joined.
        if urlsplit(response.location).scheme:
            return response.location
        return urljoin(current_url, response.location)
    except ValueError as error:
        raise _Stop("invalid_redirect", refused=True) from error
