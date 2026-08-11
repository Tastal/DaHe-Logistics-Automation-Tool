from __future__ import annotations

import contextlib
import ctypes
import hashlib
import os
import queue
import subprocess
import sys
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from threading import RLock, Thread

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
DEFAULT_MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_SAFE_INHERITED_ENVIRONMENT_KEYS = frozenset(
    {
        "COMSPEC",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PROGRAMDATA",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "WINDIR",
    }
)
_SAFE_ENVIRONMENT_OVERRIDES = frozenset(
    {
        "MKL_NUM_THREADS",
        "OMP_NUM_THREADS",
        "PADDLE_PDX_DISABLE_DEVICE_FALLBACK",
        "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK",
    }
)


class ProcessSupervisorError(RuntimeError):
    """Raised when an owned helper cannot be started or stopped safely."""


class ProcessOwnershipError(ProcessSupervisorError):
    """Raised when a stop request does not match an owned process identity."""


class SupervisedLineProcessError(ProcessSupervisorError):
    """Raised when a supervised line-oriented child cannot continue."""


class SupervisedLineProcessTimeout(SupervisedLineProcessError):
    """Raised when a supervised child does not respond before its deadline."""


class SupervisedLineProcessProtocolError(SupervisedLineProcessError):
    """Raised when a child emits bytes outside the bounded UTF-8 line contract."""


@dataclass(frozen=True, slots=True)
class OwnedProcessHandle:
    """Public identity for one process whose real handle remains supervisor-owned."""

    worker_id: str
    pid: int
    process_started_at: str


@dataclass(frozen=True, slots=True)
class _StreamProtocolFailure:
    message: str


def build_isolated_child_environment(
    *,
    runtime_dir: Path,
    inherited: Mapping[str, str],
    overrides: dict[str, str] | None,
) -> dict[str, str]:
    """Build a minimal offline environment without inheriting tokens or proxies."""
    root = runtime_dir.resolve()
    home = root / "worker-home"
    temporary = root / "worker-temp"
    roaming = home / "AppData" / "Roaming"
    local = home / "AppData" / "Local"
    cache = root / "paddlex-cache"
    for directory in (home, temporary, roaming, local, cache):
        directory.mkdir(parents=True, exist_ok=True)

    environment = {
        key: value
        for key, value in inherited.items()
        if key.upper() in _SAFE_INHERITED_ENVIRONMENT_KEYS and value
    }
    system_root = environment.get("SYSTEMROOT") or environment.get("WINDIR")
    if system_root:
        environment["PATH"] = os.pathsep.join(
            (
                os.fspath(Path(system_root) / "System32"),
                os.fspath(Path(system_root)),
            )
        )
    environment.update(
        {
            "APPDATA": os.fspath(roaming),
            "HOME": os.fspath(home),
            "LOCALAPPDATA": os.fspath(local),
            "TEMP": os.fspath(temporary),
            "TMP": os.fspath(temporary),
            "USERPROFILE": os.fspath(home),
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "PYTHONIOENCODING": "utf-8:strict",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "PADDLE_PDX_CACHE_HOME": os.fspath(cache),
            "PADDLE_PDX_DISABLE_DEVICE_FALLBACK": "True",
            "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK": "True",
        }
    )
    if overrides:
        unexpected = set(overrides) - _SAFE_ENVIRONMENT_OVERRIDES
        if unexpected:
            raise ValueError(
                "child environment override is not allowed: " + ", ".join(sorted(unexpected))
            )
        for key, value in overrides.items():
            if key in {"MKL_NUM_THREADS", "OMP_NUM_THREADS"}:
                if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 8:
                    raise ValueError(f"{key} must be an integer from 1 to 8")
            elif value != "True":
                raise ValueError(f"{key} can only remain enabled")
            environment[key] = value
    return environment


@dataclass(slots=True)
class _OwnedProcess:
    identity: OwnedProcessHandle
    process: subprocess.Popen[bytes]


class _IoCounters(ctypes.Structure):
    _fields_ = (
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    )


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    )


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("basic_limit_information", _BasicLimitInformation),
        ("io_info", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    )


class _WindowsJobObject:
    """Own a non-inheritable Windows Job Object with kill-on-close enabled."""

    def __init__(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_job = kernel32.CreateJobObjectW
        create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        create_job.restype = wintypes.HANDLE
        handle = create_job(None, None)
        if not handle:
            raise ProcessSupervisorError(
                f"Windows could not create the worker Job Object ({ctypes.get_last_error()})"
            )
        self._handle: int | None = int(handle)

        set_information = kernel32.SetInformationJobObject
        set_information.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        set_information.restype = wintypes.BOOL
        information = _ExtendedLimitInformation()
        information.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not set_information(
            self._handle,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error_code = ctypes.get_last_error()
            self.close()
            raise ProcessSupervisorError(
                "Windows could not configure kill-on-close for the worker "
                f"Job Object ({error_code})"
            )

    def assign(
        self,
        process: subprocess.Popen[bytes] | subprocess.Popen[str],
    ) -> None:
        if self._handle is None:
            raise ProcessSupervisorError("the worker Job Object is closed")
        process_handle = getattr(process, "_handle", None)
        if not isinstance(process_handle, int) or process_handle <= 0:
            raise ProcessSupervisorError("the spawned process has no usable Windows handle")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        assign = kernel32.AssignProcessToJobObject
        assign.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        assign.restype = wintypes.BOOL
        if not assign(self._handle, process_handle):
            raise ProcessSupervisorError(
                "Windows could not assign the owned process to the worker "
                f"Job Object ({ctypes.get_last_error()})"
            )

    def close(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        if not close_handle(handle):
            raise ProcessSupervisorError(
                f"Windows could not close the worker Job Object ({ctypes.get_last_error()})"
            )


def _windows_process_started_at(
    process: subprocess.Popen[bytes] | subprocess.Popen[str],
) -> str:
    """Read the immutable Windows creation time from the owned process handle."""
    process_handle = getattr(process, "_handle", None)
    if not isinstance(process_handle, int) or process_handle <= 0:
        raise ProcessSupervisorError("the spawned process has no usable Windows handle")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_process_times = kernel32.GetProcessTimes
    get_process_times.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    )
    get_process_times.restype = wintypes.BOOL

    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    succeeded = get_process_times(
        process_handle,
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    )
    if not succeeded:
        error_code = ctypes.get_last_error()
        raise ProcessSupervisorError(
            f"Windows could not read the owned process identity ({error_code})"
        )
    creation_ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return f"windows-filetime:{creation_ticks}"


def _terminate_spawn_failure(
    process: subprocess.Popen[bytes] | subprocess.Popen[str],
) -> None:
    """Best-effort cleanup of only the process handle created by this module."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


class OwnedProcessSupervisor:
    """Own helper handles directly and never discover processes by PID or name."""

    def __init__(self, *, instance_id: str, runtime_dir: Path) -> None:
        if sys.platform != "win32":
            raise ProcessSupervisorError("owned process supervision requires Windows")
        if not instance_id.strip():
            raise ValueError("instance_id cannot be empty")
        self.instance_id = instance_id
        self.runtime_dir = runtime_dir.resolve()
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._owned: dict[str, _OwnedProcess] = {}
        self._closed = False
        self._lock = RLock()
        self._job: _WindowsJobObject | None = _WindowsJobObject()

    def spawn(
        self,
        *,
        worker_id: str,
        argv: Sequence[str],
    ) -> OwnedProcessHandle:
        if not worker_id.strip():
            raise ValueError("worker_id cannot be empty")
        if not argv or any(not isinstance(value, str) or not value for value in argv):
            raise ValueError("argv must contain non-empty strings")

        with self._lock:
            if self._closed:
                raise ProcessSupervisorError("the process supervisor is closed")
            if worker_id in self._owned:
                raise ProcessOwnershipError("the worker_id is already owned")

            process = subprocess.Popen(
                tuple(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=self.runtime_dir,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            try:
                job = self._job
                if job is None:
                    raise ProcessSupervisorError("the worker Job Object is closed")
                job.assign(process)
                process_started_at = _windows_process_started_at(process)
            except BaseException:
                _terminate_spawn_failure(process)
                raise

            identity = OwnedProcessHandle(
                worker_id=worker_id,
                pid=process.pid,
                process_started_at=process_started_at,
            )
            self._owned[worker_id] = _OwnedProcess(
                identity=identity,
                process=process,
            )
            return identity

    def is_alive(self, worker_id: str) -> bool:
        with self._lock:
            owned = self._owned.get(worker_id)
            return owned is not None and owned.process.poll() is None

    def stop_owned(
        self,
        *,
        worker_id: str,
        expected_pid: int,
        expected_process_started_at: str,
        timeout_seconds: float,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        with self._lock:
            owned = self._owned.get(worker_id)
            if owned is None:
                raise ProcessOwnershipError("the worker is not owned by this supervisor")
            if (
                owned.identity.pid != expected_pid
                or owned.identity.process_started_at != expected_process_started_at
            ):
                raise ProcessOwnershipError("the owned process identity does not match")
            self._stop_process(owned, timeout_seconds=timeout_seconds)

    @staticmethod
    def _stop_process(
        owned: _OwnedProcess,
        *,
        timeout_seconds: float,
    ) -> None:
        process = owned.process
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout_seconds)

    def close(self) -> None:
        with self._lock:
            if self._closed and self._job is None:
                return
            self._closed = True
            failures: list[str] = []
            for worker_id, owned in self._owned.items():
                try:
                    self._stop_process(owned, timeout_seconds=3)
                except (OSError, subprocess.SubprocessError):
                    failures.append(worker_id)
            job = self._job
            self._job = None
            if job is not None:
                try:
                    job.close()
                except ProcessSupervisorError:
                    failures.append("job-object")
            if failures:
                raise ProcessSupervisorError(
                    "owned helpers did not stop: " + ", ".join(sorted(failures))
                )


_STREAM_CLOSED = object()


class SupervisedLineProcess:
    """Own one UTF-8 line process without discovering or touching unknown PIDs."""

    def __init__(
        self,
        *,
        worker_id: str,
        argv: Sequence[str],
        runtime_dir: Path,
        environment: dict[str, str] | None = None,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        output_sink: Callable[[str, str, str, bool], None] | None = None,
        below_normal_priority: bool = False,
    ) -> None:
        if sys.platform != "win32":
            raise ProcessSupervisorError("owned process supervision requires Windows")
        if not worker_id.strip():
            raise ValueError("worker_id cannot be empty")
        if not argv or any(not isinstance(value, str) or not value for value in argv):
            raise ValueError("argv must contain non-empty strings")
        self.worker_id = worker_id
        self.runtime_dir = runtime_dir.resolve()
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        if max_request_bytes <= 0 or max_response_bytes <= 0:
            raise ValueError("line process byte limits must be positive")
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._output_sink = output_sink
        child_environment = build_isolated_child_environment(
            runtime_dir=self.runtime_dir,
            inherited=os.environ,
            overrides=environment,
        )

        self._job = _WindowsJobObject()
        creation_flags = subprocess.CREATE_NO_WINDOW
        if below_normal_priority:
            creation_flags |= subprocess.BELOW_NORMAL_PRIORITY_CLASS
        self._process = subprocess.Popen(
            tuple(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.runtime_dir,
            shell=False,
            creationflags=creation_flags,
            text=False,
            bufsize=0,
            env=child_environment,
        )
        try:
            self._job.assign(self._process)
            started_at = _windows_process_started_at(self._process)
        except BaseException:
            _terminate_spawn_failure(self._process)
            self._job.close()
            raise
        self.identity = OwnedProcessHandle(
            worker_id=worker_id,
            pid=self._process.pid,
            process_started_at=started_at,
        )
        self._responses: queue.Queue[str | object | _StreamProtocolFailure] = queue.Queue()
        self._stderr_tail: deque[str] = deque(maxlen=32)
        self._write_lock = RLock()
        self._response_lock = RLock()
        self._lifecycle_lock = RLock()
        self._closed = False
        self._stdout_thread = Thread(
            target=self._read_stdout,
            name=f"{worker_id}-stdout",
            daemon=True,
        )
        self._stderr_thread = Thread(
            target=self._read_stderr,
            name=f"{worker_id}-stderr",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        stream = self._process.stdout
        if stream is None:
            self._responses.put(_STREAM_CLOSED)
            return
        try:
            while True:
                raw_line = stream.readline(self._max_response_bytes + 2)
                if not raw_line:
                    break
                if len(raw_line) > self._max_response_bytes + 1:
                    self._responses.put(
                        _StreamProtocolFailure("the owned worker response exceeded its byte limit")
                    )
                    return
                if not raw_line.endswith(b"\n"):
                    self._responses.put(
                        _StreamProtocolFailure(
                            "the owned worker response was not newline terminated"
                        )
                    )
                    return
                body = raw_line[:-1]
                if body.endswith(b"\r"):
                    body = body[:-1]
                if b"\n" in body or b"\r" in body:
                    self._responses.put(
                        _StreamProtocolFailure(
                            "the owned worker emitted more than one protocol line"
                        )
                    )
                    return
                try:
                    decoded = body.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    self._responses.put(
                        _StreamProtocolFailure("the owned worker response was not strict UTF-8")
                    )
                    return
                if self._output_sink is not None:
                    self._output_sink(self.worker_id, "stdout", decoded, True)
                self._responses.put(decoded)
        finally:
            self._responses.put(_STREAM_CLOSED)

    def _read_stderr(self) -> None:
        stream = self._process.stderr
        if stream is None:
            return
        for raw_line in stream:
            line = raw_line.decode("utf-8", errors="replace")
            cleaned = line.rstrip("\r\n")
            self._stderr_tail.append(cleaned)
            if self._output_sink is not None:
                self._output_sink(self.worker_id, "stderr", cleaned, False)

    @property
    def is_alive(self) -> bool:
        return not self._closed and self._process.poll() is None

    @property
    def stderr_digest(self) -> str | None:
        if not self._stderr_tail:
            return None
        payload = "\n".join(self._stderr_tail).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @property
    def exit_code(self) -> int | None:
        """Return the owned worker exit code without waiting for it."""

        return self._process.poll()

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        return self.request_lines(
            line,
            timeout_seconds=timeout_seconds,
            is_final=lambda _line: True,
        )

    def send_line(self, line: str) -> None:
        """Write one command without claiming the response stream.

        This is used only for cooperative control frames such as abort. The
        active request remains the sole consumer of stdout.
        """

        encoded = self._encode_request(line)
        with self._write_lock:
            if not self.is_alive:
                raise SupervisedLineProcessError("the owned worker is not running")
            stdin = self._process.stdin
            if stdin is None:
                raise SupervisedLineProcessError("the owned worker has no input stream")
            try:
                stdin.write(encoded + b"\n")
                stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise SupervisedLineProcessError(
                    "the owned worker input stream closed"
                ) from exc

    def request_lines(
        self,
        line: str,
        *,
        timeout_seconds: float,
        is_final: Callable[[str], bool],
        on_line: Callable[[str], None] | None = None,
    ) -> str:
        """Read streaming frames until ``is_final`` accepts one line."""

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        with self._response_lock:
            self.send_line(line)
            deadline = time.monotonic() + timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._stop_process(timeout_seconds=1)
                    raise SupervisedLineProcessTimeout(
                        "the owned worker response timed out"
                    )
                try:
                    response = self._responses.get(timeout=remaining)
                except queue.Empty as exc:
                    self._stop_process(timeout_seconds=1)
                    raise SupervisedLineProcessTimeout(
                        "the owned worker response timed out"
                    ) from exc
                if response is _STREAM_CLOSED:
                    return_code = self._process.poll()
                    raise SupervisedLineProcessError(
                        f"the owned worker exited before responding ({return_code})"
                    )
                if isinstance(response, _StreamProtocolFailure):
                    self._stop_process(timeout_seconds=1)
                    raise SupervisedLineProcessProtocolError(response.message)
                if not isinstance(response, str):
                    raise SupervisedLineProcessError(
                        "the owned worker returned an invalid stream item"
                    )
                if on_line is not None:
                    on_line(response)
                if is_final(response):
                    return response

    def _encode_request(self, line: str) -> bytes:
        if "\n" in line or "\r" in line:
            raise ValueError("line requests cannot contain line breaks")
        try:
            encoded = line.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            self._stop_process(timeout_seconds=1)
            raise SupervisedLineProcessProtocolError(
                "the owned worker request was not strict UTF-8"
            ) from exc
        if len(encoded) > self._max_request_bytes:
            self._stop_process(timeout_seconds=1)
            raise SupervisedLineProcessProtocolError(
                "the owned worker request exceeded its byte limit"
            )
        return encoded

    def terminate(self) -> None:
        """Stop only this supervised child without waiting for a response."""

        with self._lifecycle_lock:
            if self._closed:
                return
            self._stop_process(timeout_seconds=1)

    def _stop_process(self, *, timeout_seconds: float) -> None:
        process = self._process
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=timeout_seconds)

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            failure: BaseException | None = None
            try:
                self._stop_process(timeout_seconds=3)
            except (OSError, subprocess.SubprocessError) as exc:
                failure = exc
            for stream in (
                self._process.stdin,
                self._process.stdout,
                self._process.stderr,
            ):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()
            try:
                self._job.close()
            except ProcessSupervisorError as exc:
                failure = failure or exc
            self._stdout_thread.join(timeout=1)
            self._stderr_thread.join(timeout=1)
            if failure is not None:
                raise SupervisedLineProcessError(
                    "the owned worker did not stop cleanly"
                ) from failure
