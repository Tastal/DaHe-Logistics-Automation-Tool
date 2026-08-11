from __future__ import annotations

import socket

import pytest

from dahe.system.port_guard import PortInUseError, reserve_loopback_port


def test_port_reservation_uses_requested_loopback_port() -> None:
    with reserve_loopback_port("127.0.0.1", 0) as reservation:
        assert reservation.host == "127.0.0.1"
        assert reservation.port > 0
        assert reservation.socket.getsockname() == (reservation.host, reservation.port)


def test_second_reservation_fails_without_closing_or_replacing_owner() -> None:
    with reserve_loopback_port("127.0.0.1", 0) as owner:
        with pytest.raises(PortInUseError), reserve_loopback_port(owner.host, owner.port):
            pass

        assert owner.socket.fileno() >= 0
        assert owner.socket.getsockname() == (owner.host, owner.port)


def test_port_guard_does_not_enable_reuseaddr() -> None:
    with reserve_loopback_port("127.0.0.1", 0) as reservation:
        assert reservation.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
