import socket

import pytest


def test_unmarked_tests_cannot_connect_anywhere() -> None:
    with socket.socket() as sock, pytest.raises(AssertionError, match="real network"):
        sock.connect(("127.0.0.1", 9))


def test_hostnames_are_refused_by_the_guard() -> None:
    with socket.socket() as sock, pytest.raises(AssertionError, match="real network"):
        sock.connect(("example.test", 80))


@pytest.mark.loopback
def test_loopback_marked_tests_still_cannot_leave_loopback() -> None:
    with socket.socket() as sock, pytest.raises(AssertionError, match="real network"):
        sock.connect(("8.8.8.8", 53))
    with (
        socket.socket(socket.AF_INET6) as sock,
        pytest.raises(AssertionError, match="real"),
    ):
        sock.connect(("2606:4700:4700::1111", 53, 0, 0))


@pytest.mark.loopback
def test_loopback_marked_tests_may_connect_to_loopback() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket() as client:
            client.connect(listener.getsockname())
