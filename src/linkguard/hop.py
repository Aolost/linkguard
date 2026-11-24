"""One pinned HTTP hop: connect to an already-validated IP with the hostname preserved.

This module never decides whether an address is allowed. `SafeFetcher` validates every
address first and is the only caller; nothing here is exported or reachable from the
CLI or `Policy`.
"""

import ssl
from dataclasses import dataclass

import httpx

from linkguard._version import version
from linkguard.ssrf import IPAddress

CONNECT_TIMEOUT = 5.0
MAX_BODY_BYTES = 65536
_DEFAULT_PORTS = {"http": 80, "https": 443}


class HopFailed(Exception):
    """The hop could not be completed; `reason` is a stable machine-readable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class HopResponse:
    status: int
    location: str | None
    content_type: str | None
    bytes_read: int
    truncated: bool


def _has_tls_cause(error: BaseException | None) -> bool:
    while error is not None:
        if isinstance(error, ssl.SSLError):
            return True
        # httpcore re-raises without `from`, so the SSL error is only in __context__.
        error = error.__cause__ or error.__context__
    return False


class HopClient:
    """Performs single GET requests; redirects are reported, never followed."""

    def __init__(
        self,
        ssl_context: ssl.SSLContext | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        context = ssl_context or ssl.create_default_context()
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("TLS context must verify certificates and hostnames")
        self._ssl_context = context
        self._transport = transport

    def _new_client(self, timeout: float) -> httpx.AsyncClient:
        # A fresh client per hop means no cookie jar survives between requests, and
        # trust_env=False keeps proxy and netrc environment from rerouting traffic.
        return httpx.AsyncClient(
            transport=self._transport,
            verify=self._ssl_context,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=min(CONNECT_TIMEOUT, timeout),
                read=timeout,
                write=timeout,
                pool=timeout,
            ),
        )

    async def get(
        self,
        *,
        scheme: str,
        address: IPAddress,
        port: int | None,
        hostname: str,
        target: str,
        timeout: float,
    ) -> HopResponse:
        """GET `target` from `address`, presenting `hostname` as Host and TLS name."""
        ip_text = f"[{address}]" if address.version == 6 else str(address)
        url = f"{scheme}://{ip_text}{'' if port is None else f':{port}'}{target}"
        name = f"[{hostname}]" if ":" in hostname else hostname  # IPv6 literal
        host_header = (
            name if port is None or port == _DEFAULT_PORTS[scheme] else f"{name}:{port}"
        )
        headers = {
            "Host": host_header,
            "User-Agent": f"linkguard/{version()}",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }
        try:
            async with (
                self._new_client(timeout) as client,
                client.stream(
                    "GET",
                    url,
                    headers=headers,
                    extensions={"sni_hostname": hostname},
                ) as response,
            ):
                total = 0
                async for chunk in response.aiter_raw():
                    total += len(chunk)
                    if total > MAX_BODY_BYTES:
                        break
                return HopResponse(
                    status=response.status_code,
                    location=response.headers.get("location"),
                    content_type=response.headers.get("content-type"),
                    bytes_read=min(total, MAX_BODY_BYTES),
                    truncated=total > MAX_BODY_BYTES,
                )
        except httpx.TimeoutException as error:
            raise HopFailed("timeout") from error
        except httpx.ConnectError as error:
            raise HopFailed(
                "tls_error" if _has_tls_cause(error) else "connect_failed"
            ) from error
        except (httpx.HTTPError, httpx.InvalidURL) as error:
            # InvalidURL is not an HTTPError, and httpx lets it escape while it builds
            # its own redirect request from a hostile Location header.
            raise HopFailed("http_error") from error
