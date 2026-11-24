import ipaddress
import socket

import pytest


@pytest.fixture(autouse=True)
def _only_loopback_sockets(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail any test that opens a real network connection.

    Only tests marked `loopback` may connect, and only to 127.0.0.0/8 or ::1.
    """
    loopback_allowed = request.node.get_closest_marker("loopback") is not None
    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: object) -> None:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0] if isinstance(address, tuple) else ""
            try:
                is_loopback = ipaddress.ip_address(str(host)).is_loopback
            except ValueError:
                is_loopback = False
            if not (loopback_allowed and is_loopback):
                raise AssertionError(
                    f"test tried a real network connection: {address!r}"
                )
        real_connect(self, address)  # type: ignore[arg-type]

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
