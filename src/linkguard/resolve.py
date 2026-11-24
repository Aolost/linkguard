"""DNS resolution and per-hop address validation for the fetcher.

`socket.getaddrinfo` cannot be cancelled and a worker thread running it keeps going
after a timeout. The default resolver therefore runs it in a child process that is
killed on timeout. That bounds linkguard's own wait; it does not bound work a system
resolver daemon has already started on the child's behalf.
"""

import asyncio
import sys
from asyncio.subprocess import DEVNULL, PIPE, Process
from collections.abc import Awaitable, Callable, Sequence
from ipaddress import ip_address
from typing import cast

from linkguard.host import Host, IpHost
from linkguard.ssrf import IPAddress, blocked_reason

type Resolver = Callable[[str, float], Awaitable[list[str]]]

_MAX_OUTPUT_BYTES = 4096

# The hostname arrives on stdin, never in argv, and is already IDNA-validated ASCII.
_CHILD_SOURCE = """
import socket, sys
host = sys.stdin.read()
infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
print("\\n".join(dict.fromkeys(info[4][0] for info in infos)))
"""


class HopRefused(Exception):
    """A hop must not be fetched; `reason` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _parse_address(text: str) -> IPAddress:
    if "%" in text:
        raise HopRefused("dns_failed", "resolver returned a scoped address")
    try:
        return ip_address(text)
    except ValueError as error:
        raise HopRefused("dns_failed", "resolver returned a non-address") from error


async def _read_limited(proc: Process) -> bytes:
    stdout = cast(asyncio.StreamReader, proc.stdout)  # created with PIPE
    chunks: list[bytes] = []
    total = 0
    while chunk := await stdout.read(1024):
        total += len(chunk)
        if total > _MAX_OUTPUT_BYTES:
            raise HopRefused("dns_failed", "resolver output too long")
        chunks.append(chunk)
    return b"".join(chunks)


async def _run_child(proc: Process, host: str) -> list[str]:
    stdin = cast(asyncio.StreamWriter, proc.stdin)  # created with PIPE
    stdin.write(host.encode("utf-8"))
    stdin.close()
    output = await _read_limited(proc)
    if await proc.wait() != 0:
        raise HopRefused("dns_failed", "name lookup failed")
    lines = output.decode("ascii", errors="replace").splitlines()
    for line in lines:
        _parse_address(line)
    return lines


async def _kill_and_reap(proc: Process) -> None:
    """Stop the child and collect it.

    The pipe must be drained after the kill: the stream reader stops reading once its
    buffer fills, the pipe then never reaches EOF, and `wait()` would block forever.
    A killed child can leave at most one pipe buffer of data, so the drain is bounded.
    """
    if proc.returncode is None:
        proc.kill()
    stdout = cast(asyncio.StreamReader, proc.stdout)  # created with PIPE
    while await stdout.read(65536):
        pass
    await proc.wait()


class SubprocessResolver:
    """Resolve names in a killable child process; the argv is injectable for tests."""

    def __init__(self, argv: Sequence[str] | None = None) -> None:
        self._argv = (
            tuple(argv) if argv else (sys.executable, "-I", "-c", _CHILD_SOURCE)
        )

    async def __call__(self, host: str, timeout: float) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *self._argv, stdin=PIPE, stdout=PIPE, stderr=DEVNULL
            )
        except OSError as error:
            raise HopRefused("dns_failed", "cannot start resolver process") from error
        try:
            return await asyncio.wait_for(_run_child(proc, host), timeout)
        except TimeoutError as error:
            raise HopRefused("dns_timeout", "name lookup timed out") from error
        finally:
            await _kill_and_reap(proc)


async def resolve_hop(
    host: Host, resolver: Resolver, timeout: float
) -> list[IPAddress]:
    """Return the validated addresses for one hop, or raise `HopRefused`.

    The resolver is called at most once, and every address it returns must be allowed:
    a mixed answer is treated as a rebinding signal and refuses the whole hop.
    """
    if isinstance(host, IpHost):
        addresses = [host.address]
    else:
        try:
            answers = await resolver(host.name, timeout)
        except OSError as error:
            raise HopRefused("dns_failed", "name lookup failed") from error
        addresses = list(dict.fromkeys(_parse_address(answer) for answer in answers))
    if not addresses:
        raise HopRefused("no_addresses", "name resolved to no addresses")
    for address in addresses:
        reason = blocked_reason(address)
        if reason is not None:
            raise HopRefused("blocked_address", f"{address} is {reason}")
    return addresses
