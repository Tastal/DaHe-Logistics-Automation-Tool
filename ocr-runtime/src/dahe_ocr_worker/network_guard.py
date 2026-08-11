from __future__ import annotations

import socket
from typing import Any


class NetworkAccessDenied(RuntimeError):
    """Raised when isolated OCR code attempts any Python socket connection."""


def _deny_connection(*_args: Any, **_kwargs: Any) -> None:
    raise NetworkAccessDenied("network access is disabled in the local OCR worker")


def _deny_connect_ex(*_args: Any, **_kwargs: Any) -> int:
    raise NetworkAccessDenied("network access is disabled in the local OCR worker")


def install_python_network_guard() -> None:
    """Deny model downloads, telemetry, and every other Python socket connection."""
    socket.create_connection = _deny_connection
    socket.getaddrinfo = _deny_connection
    socket.socket.connect = _deny_connection
    socket.socket.connect_ex = _deny_connect_ex
