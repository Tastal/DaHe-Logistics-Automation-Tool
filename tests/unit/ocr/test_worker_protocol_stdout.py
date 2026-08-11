from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the isolated OCR worker currently supports Windows only",
)


def _run_worker_harness(
    project_root: Path,
    script: str,
) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.fspath(project_root / "ocr-runtime" / "src")
    return subprocess.run(
        (sys.executable, "-c", script),
        cwd=project_root,
        env=environment,
        check=False,
        capture_output=True,
        text=False,
        timeout=15,
        shell=False,
    )


@contextmanager
def _worker_main(project_root: Path) -> Iterator[ModuleType]:
    worker_src = str(project_root / "ocr-runtime" / "src")
    sys.path.insert(0, worker_src)
    try:
        yield importlib.import_module("dahe_ocr_worker.__main__")
    finally:
        sys.path.remove(worker_src)
        for module_name in tuple(sys.modules):
            if module_name == "dahe_ocr_worker" or module_name.startswith("dahe_ocr_worker."):
                sys.modules.pop(module_name, None)


def test_python_native_fd_and_windows_handle_noise_cannot_enter_protocol_stdout(
    project_root: Path,
) -> None:
    completed = _run_worker_harness(
        project_root,
        r"""
import ctypes
import os
import sys

from dahe_ocr_worker.__main__ import _write
from dahe_ocr_worker.protocol_stdout import isolated_protocol_stdout

with isolated_protocol_stdout() as protocol_stdout:
    print("python-import-noise", flush=True)
    os.write(1, b"\xffnative-fd-predict-noise\n")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.GetStdHandle(-11)
    payload = ctypes.create_string_buffer(b"\xfewindows-handle-noise\n")
    written = ctypes.c_ulong(0)
    if not kernel32.WriteFile(
        handle,
        payload,
        len(payload.raw) - 1,
        ctypes.byref(written),
        None,
    ):
        raise OSError(ctypes.get_last_error(), "WriteFile failed")
    native_stdio = ctypes.CDLL("msvcrt", use_errno=True)
    if native_stdio.printf(b"buffered-native-stdio-no-newline") < 0:
        raise OSError(ctypes.get_errno(), "native printf failed")
    sys.stderr.write("diagnostic-summary\n")
    sys.stderr.flush()
    _write(
        {"kind": "protocol", "status": "ok"},
        protocol_stdout=protocol_stdout,
    )
""",
    )

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8",
        errors="replace",
    )
    protocol_lines = completed.stdout.decode(
        "utf-8",
        errors="strict",
    ).splitlines()
    assert len(protocol_lines) == 1
    assert json.loads(protocol_lines[0]) == {
        "kind": "protocol",
        "status": "ok",
    }
    assert b"python-import-noise" not in completed.stdout
    assert b"native-fd-predict-noise" not in completed.stdout
    assert b"windows-handle-noise" not in completed.stdout
    assert b"buffered-native-stdio-no-newline" not in completed.stdout
    assert b"python-import-noise" in completed.stderr
    assert b"\xffnative-fd-predict-noise" in completed.stderr
    assert b"\xfewindows-handle-noise" in completed.stderr
    assert b"diagnostic-summary" in completed.stderr


def test_isolation_restores_stdout_and_propagates_exceptions(
    project_root: Path,
) -> None:
    completed = _run_worker_harness(
        project_root,
        r"""
import os

from dahe_ocr_worker.protocol_stdout import isolated_protocol_stdout

try:
    with isolated_protocol_stdout():
        print("noise-before-error", flush=True)
        os.write(1, b"native-noise-before-error\n")
        raise RuntimeError("predict failed")
except RuntimeError as exc:
    if str(exc) != "predict failed":
        raise
    print("restored-protocol-stdout", flush=True)
os.write(2, b"restored-stderr\n")
""",
    )

    assert completed.returncode == 0
    assert completed.stdout == b"restored-protocol-stdout\r\n"
    assert b"noise-before-error" in completed.stderr
    assert b"native-noise-before-error" in completed.stderr
    assert b"restored-stderr" in completed.stderr


def test_main_enters_isolation_before_worker_initialization(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    arguments = object()
    protocol_stdout = object()

    class Parser:
        @staticmethod
        def parse_args() -> object:
            events.append("parse")
            return arguments

    @contextmanager
    def isolate() -> Iterator[object]:
        events.append("enter")
        try:
            yield protocol_stdout
        finally:
            events.append("exit")

    def run_worker(
        received_arguments: object,
        *,
        protocol_stdout: object,
    ) -> int:
        assert received_arguments is arguments
        assert protocol_stdout is not None
        events.append("initialize-and-run")
        return 17

    with _worker_main(project_root) as worker_main:
        monkeypatch.setattr(worker_main, "_parser", lambda: Parser())
        monkeypatch.setattr(
            worker_main,
            "isolated_protocol_stdout",
            isolate,
        )
        monkeypatch.setattr(worker_main, "_run_worker", run_worker)

        assert worker_main.main() == 17

    assert events == [
        "parse",
        "enter",
        "initialize-and-run",
        "exit",
    ]


def test_worker_package_version_matches_build_metadata(
    project_root: Path,
) -> None:
    metadata = tomllib.loads(
        (project_root / "ocr-runtime" / "pyproject.toml").read_text(encoding="utf-8")
    )
    with _worker_main(project_root) as worker_main:
        package = importlib.import_module("dahe_ocr_worker")
        assert package.__version__ == metadata["project"]["version"]
        assert worker_main is not None


def test_isolation_closes_reserved_fd_when_inheritability_setup_fails(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    with _worker_main(project_root):
        protocol_stdout = importlib.import_module("dahe_ocr_worker.protocol_stdout")
        monkeypatch.setattr(protocol_stdout.os, "dup", lambda _fd: 7001)

        def fail_inheritability(_fd: int, _inheritable: bool) -> None:
            raise OSError("synthetic inheritability failure")

        monkeypatch.setattr(
            protocol_stdout.os,
            "set_inheritable",
            fail_inheritability,
        )
        monkeypatch.setattr(
            protocol_stdout.os,
            "close",
            closed.append,
        )

        with pytest.raises(
            protocol_stdout.ProtocolStdoutError,
            match="could not be reserved",
        ):
            protocol_stdout.IsolatedProtocolStdout().__enter__()

    assert closed == [7001]


def test_isolation_rolls_back_fd_and_closes_reservation_when_handle_redirect_fails(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicated: list[tuple[int, int]] = []
    closed: list[int] = []
    windows_handle_calls: list[int] = []
    stdout_fd = sys.stdout.fileno()
    stderr_fd = sys.stderr.fileno()
    with _worker_main(project_root):
        protocol_stdout = importlib.import_module("dahe_ocr_worker.protocol_stdout")
        monkeypatch.setattr(protocol_stdout.os, "dup", lambda _fd: 7002)
        monkeypatch.setattr(
            protocol_stdout.os,
            "set_inheritable",
            lambda _fd, _inheritable: None,
        )
        monkeypatch.setattr(
            protocol_stdout.os,
            "dup2",
            lambda source, target, **_kwargs: duplicated.append((source, target)),
        )
        monkeypatch.setattr(
            protocol_stdout.os,
            "close",
            closed.append,
        )

        def redirect_handle(fd: int) -> None:
            windows_handle_calls.append(fd)
            if len(windows_handle_calls) == 1:
                raise protocol_stdout.ProtocolStdoutError("synthetic handle redirect failure")

        monkeypatch.setattr(
            protocol_stdout,
            "_windows_set_stdout_handle_from_fd",
            redirect_handle,
        )

        with pytest.raises(
            protocol_stdout.ProtocolStdoutError,
            match="isolation failed",
        ):
            protocol_stdout.IsolatedProtocolStdout().__enter__()

    assert duplicated == [
        (stderr_fd, stdout_fd),
        (7002, stdout_fd),
    ]
    assert windows_handle_calls == [stderr_fd, stdout_fd]
    assert closed == [7002]
