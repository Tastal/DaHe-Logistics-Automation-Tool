from __future__ import annotations

import socket
from types import TracebackType


class PortInUseError(RuntimeError):
    """Raised when the configured local API endpoint cannot be reserved."""


class PortReservation:
    def __init__(self, host: str, port: int) -> None:
        if host != "127.0.0.1":
            raise ValueError("only the canonical loopback host is allowed")
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._closed = False
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.socket.bind((host, port))
            self.socket.listen(1)
            self.port = int(self.socket.getsockname()[1])
        except OSError as exc:
            self.socket.close()
            self._closed = True
            raise PortInUseError(f"port {host}:{port} is unavailable") from exc

    def close(self) -> None:
        if not self._closed:
            self.socket.close()
            self._closed = True

    def __enter__(self) -> PortReservation:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def reserve_loopback_port(host: str, port: int) -> PortReservation:
    return PortReservation(host=host, port=port)
