from __future__ import annotations

import importlib
import socket
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest


@contextmanager
def _network_guard(project_root: Path) -> Iterator[ModuleType]:
    worker_src = str(project_root / "ocr-runtime" / "src")
    sys.path.insert(0, worker_src)
    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    try:
        yield importlib.import_module("dahe_ocr_worker.network_guard")
    finally:
        socket.create_connection = original_create_connection
        socket.getaddrinfo = original_getaddrinfo
        socket.socket.connect = original_connect
        socket.socket.connect_ex = original_connect_ex
        sys.path.remove(worker_src)
        for module_name in tuple(sys.modules):
            if module_name == "dahe_ocr_worker" or module_name.startswith(
                "dahe_ocr_worker."
            ):
                sys.modules.pop(module_name, None)


def test_worker_python_network_guard_denies_resolution_and_connections(
    project_root: Path,
) -> None:
    with _network_guard(project_root) as guard:
        guard.install_python_network_guard()

        with pytest.raises(guard.NetworkAccessDenied):
            socket.getaddrinfo("example.invalid", 443)
        with pytest.raises(guard.NetworkAccessDenied):
            socket.create_connection(("example.invalid", 443))
        with socket.socket() as client, pytest.raises(guard.NetworkAccessDenied):
            client.connect(("127.0.0.1", 9))
