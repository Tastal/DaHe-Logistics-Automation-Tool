from __future__ import annotations

import ctypes
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from types import TracebackType


class ProtocolStdoutError(RuntimeError):
    """Raised when the worker cannot isolate its NDJSON output handle."""


_STD_OUTPUT_HANDLE = 0xFFFFFFF5


def _windows_set_stdout_handle_from_fd(file_descriptor: int) -> None:
    if os.name != "nt":
        return
    import msvcrt
    from ctypes import wintypes

    try:
        native_handle = msvcrt.get_osfhandle(file_descriptor)
    except OSError as exc:
        raise ProtocolStdoutError("Windows could not resolve the worker output handle") from exc
    if native_handle == -1:
        raise ProtocolStdoutError("Windows returned an invalid worker output handle")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_standard_handle = kernel32.SetStdHandle
    set_standard_handle.argtypes = (
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    set_standard_handle.restype = wintypes.BOOL
    if not set_standard_handle(
        _STD_OUTPUT_HANDLE,
        wintypes.HANDLE(native_handle),
    ):
        raise ProtocolStdoutError("Windows could not redirect the worker output handle")


def _flush_native_standard_streams() -> None:
    library_names = ("ucrtbase", "msvcrt") if os.name == "nt" else (None,)
    available = False
    succeeded = False
    for library_name in library_names:
        try:
            library = ctypes.CDLL(library_name, use_errno=True)
            flush = library.fflush
        except (AttributeError, OSError):
            continue
        available = True
        flush.argtypes = (ctypes.c_void_p,)
        flush.restype = ctypes.c_int
        if flush(None) == 0:
            succeeded = True
    if not available:
        raise ProtocolStdoutError("native output flushing is unavailable")
    if not succeeded:
        raise ProtocolStdoutError("native output buffers could not be flushed safely")


def _flush(stream: object) -> BaseException | None:
    try:
        stream.flush()  # type: ignore[attr-defined]
    except BaseException as exc:
        return exc
    return None


class IsolatedProtocolStdout:
    """Reserve the original stdout pipe and redirect all ambient output."""

    def __init__(self) -> None:
        self._protocol_fd: int | None = None
        self._stdout_fd: int | None = None
        self._write_lock = threading.Lock()

    def __enter__(self) -> IsolatedProtocolStdout:
        if self._protocol_fd is not None:
            raise ProtocolStdoutError("protocol stdout isolation cannot be entered twice")
        try:
            stdout_fd = sys.stdout.fileno()
            stderr_fd = sys.stderr.fileno()
        except (AttributeError, OSError) as exc:
            raise ProtocolStdoutError(
                "worker stdout and stderr must expose operating-system handles"
            ) from exc
        flush_error = _flush(sys.stdout)
        if flush_error is not None:
            raise ProtocolStdoutError(
                "worker stdout could not be flushed before isolation"
            ) from flush_error
        flush_error = _flush(sys.stderr)
        if flush_error is not None:
            raise ProtocolStdoutError(
                "worker stderr could not be flushed before isolation"
            ) from flush_error

        protocol_fd: int | None = None
        try:
            protocol_fd = os.dup(stdout_fd)
            os.set_inheritable(protocol_fd, False)
        except OSError as exc:
            if protocol_fd is not None:
                try:
                    os.close(protocol_fd)
                except OSError as close_exc:
                    exc.add_note(
                        f"reserved protocol handle cleanup also failed: {type(close_exc).__name__}"
                    )
            raise ProtocolStdoutError(
                "worker protocol output handle could not be reserved"
            ) from exc
        redirected = False
        try:
            os.dup2(
                stderr_fd,
                stdout_fd,
                inheritable=False,
            )
            redirected = True
            _windows_set_stdout_handle_from_fd(stderr_fd)
            _flush_native_standard_streams()
        except BaseException as exc:
            restore_error: BaseException | None = None
            if redirected:
                try:
                    os.dup2(
                        protocol_fd,
                        stdout_fd,
                        inheritable=False,
                    )
                    _windows_set_stdout_handle_from_fd(stdout_fd)
                except BaseException as restore_exc:
                    restore_error = restore_exc
            try:
                os.close(protocol_fd)
            except OSError as close_exc:
                restore_error = restore_error or close_exc
            failure = ProtocolStdoutError("worker protocol stdout isolation failed")
            if restore_error is not None:
                failure.add_note(f"stdout restoration also failed: {type(restore_error).__name__}")
            raise failure from exc

        self._stdout_fd = stdout_fd
        self._protocol_fd = protocol_fd
        return self

    def write_line(self, line: str) -> None:
        protocol_fd = self._protocol_fd
        if protocol_fd is None:
            raise ProtocolStdoutError("protocol stdout isolation is not active")
        try:
            encoded = (line + "\n").encode(
                "utf-8",
                errors="strict",
            )
        except UnicodeEncodeError as exc:
            raise ProtocolStdoutError("protocol output is not strict UTF-8") from exc
        remaining = memoryview(encoded)
        with self._write_lock:
            while remaining:
                try:
                    written = os.write(protocol_fd, remaining)
                except InterruptedError:
                    continue
                except OSError as exc:
                    raise ProtocolStdoutError("protocol output pipe could not be written") from exc
                if written <= 0:
                    raise ProtocolStdoutError("protocol output pipe accepted no bytes")
                remaining = remaining[written:]

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, traceback
        protocol_fd = self._protocol_fd
        stdout_fd = self._stdout_fd
        self._protocol_fd = None
        self._stdout_fd = None
        if protocol_fd is None or stdout_fd is None:
            return

        restoration_error = _flush(sys.stdout)
        try:
            _flush_native_standard_streams()
        except BaseException as native_flush_exc:
            restoration_error = restoration_error or native_flush_exc
        try:
            os.dup2(
                protocol_fd,
                stdout_fd,
                inheritable=False,
            )
            _windows_set_stdout_handle_from_fd(stdout_fd)
        except BaseException as restore_exc:
            restoration_error = restoration_error or restore_exc
        try:
            os.close(protocol_fd)
        except OSError as close_exc:
            restoration_error = restoration_error or close_exc

        if restoration_error is None:
            return
        if exc_value is not None:
            exc_value.add_note(
                "worker protocol stdout restoration also failed: "
                f"{type(restoration_error).__name__}"
            )
            return
        raise ProtocolStdoutError(
            "worker protocol stdout could not be restored"
        ) from restoration_error


@contextmanager
def isolated_protocol_stdout() -> Iterator[IsolatedProtocolStdout]:
    """Keep ambient Python and native output off the NDJSON pipe."""

    with IsolatedProtocolStdout() as protocol_stdout:
        yield protocol_stdout
