from __future__ import annotations

import ctypes
import hashlib
import os
import sys
import threading
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Protocol


class ApplicationInstanceLifecycleError(RuntimeError):
    """Raised when the current application instance cannot be tracked safely."""


class LifecycleClosedError(ApplicationInstanceLifecycleError):
    """Raised when a closed lifecycle is started again."""


class LifecycleHeartbeatError(ApplicationInstanceLifecycleError):
    """Raised after a background heartbeat has failed."""


class InstanceRegistrationStore(Protocol):
    """Small persistence boundary required by the lifecycle owner."""

    def register_instance(
        self,
        *,
        instance_id: str,
        data_root_identity: str,
        pid: int,
        process_started_at: str,
        application_version: str,
        port: int,
        now: datetime,
    ) -> None: ...

    def heartbeat_instance(self, *, instance_id: str, now: datetime) -> None: ...

    def stop_instance(self, *, instance_id: str, now: datetime) -> None: ...


@dataclass(frozen=True, slots=True)
class CurrentProcessIdentity:
    """Immutable identity of the application process that owns the lifecycle."""

    pid: int
    process_started_at: str

    def __post_init__(self) -> None:
        if self.pid <= 0:
            raise ValueError("process pid must be positive")
        if not self.process_started_at.strip():
            raise ValueError("process_started_at cannot be empty")


def data_root_identity(data_root: Path) -> str:
    """Return a stable identity without reading or writing the data directory."""
    canonical = os.path.normcase(os.fspath(data_root.resolve())).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def current_process_identity() -> CurrentProcessIdentity:
    """Read only the current Windows process handle; never discover other processes."""
    if sys.platform != "win32":
        raise ApplicationInstanceLifecycleError(
            "application instance process identity requires Windows"
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = ()
    get_current_process.restype = wintypes.HANDLE
    process_handle = get_current_process()

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
        raise ApplicationInstanceLifecycleError(
            "Windows could not read the current process identity "
            f"({ctypes.get_last_error()})"
        )
    creation_ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return CurrentProcessIdentity(
        pid=os.getpid(),
        process_started_at=f"windows-filetime:{creation_ticks}",
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ApplicationInstanceLifecycle:
    """Own registration, periodic heartbeat, and clean stop for one instance."""

    def __init__(
        self,
        store: InstanceRegistrationStore,
        *,
        instance_id: str,
        data_root: Path,
        application_version: str,
        port: int,
        heartbeat_interval: timedelta = timedelta(seconds=5),
        close_timeout: timedelta = timedelta(seconds=10),
        clock: Callable[[], datetime] = _utc_now,
        process_identity_provider: Callable[[], CurrentProcessIdentity] = (
            current_process_identity
        ),
    ) -> None:
        if not instance_id.strip():
            raise ValueError("instance_id cannot be empty")
        if not application_version.strip():
            raise ValueError("application_version cannot be empty")
        if not 0 < port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if heartbeat_interval <= timedelta(0):
            raise ValueError("heartbeat_interval must be positive")
        if close_timeout <= timedelta(0):
            raise ValueError("close_timeout must be positive")

        self._store = store
        self.instance_id = instance_id
        self.data_root_identity = data_root_identity(data_root)
        self.application_version = application_version
        self.port = port
        self._heartbeat_seconds = heartbeat_interval.total_seconds()
        self._close_timeout_seconds = close_timeout.total_seconds()
        self._clock = clock
        self._process_identity_provider = process_identity_provider

        self._condition = threading.Condition(threading.RLock())
        self._stop_requested = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_failure: Exception | None = None
        self._starting = False
        self._started = False
        self._closing = False
        self._closed = False

    @property
    def is_running(self) -> bool:
        with self._condition:
            return self._started and not self._closed

    @property
    def is_closed(self) -> bool:
        with self._condition:
            return self._closed

    def start(self) -> None:
        with self._condition:
            while self._starting or self._closing:
                self._condition.wait()
            if self._closed:
                raise LifecycleClosedError("a closed application lifecycle cannot be restarted")
            if self._started:
                return
            self._starting = True

        try:
            process_identity = self._process_identity_provider()
            self._store.register_instance(
                instance_id=self.instance_id,
                data_root_identity=self.data_root_identity,
                pid=process_identity.pid,
                process_started_at=process_identity.process_started_at,
                application_version=self.application_version,
                port=self.port,
                now=self._clock(),
            )
        except BaseException:
            with self._condition:
                self._starting = False
                self._condition.notify_all()
            raise

        thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"dahe-instance-heartbeat-{self.instance_id}",
            daemon=True,
        )
        with self._condition:
            self._heartbeat_thread = thread
            self._started = True
            self._starting = False
            thread.start()
            self._condition.notify_all()

    def _heartbeat_loop(self) -> None:
        while not self._stop_requested.wait(self._heartbeat_seconds):
            try:
                self._store.heartbeat_instance(
                    instance_id=self.instance_id,
                    now=self._clock(),
                )
            except Exception as exc:
                with self._condition:
                    self._heartbeat_failure = exc
                    self._condition.notify_all()
                return

    def close(self) -> None:
        with self._condition:
            while self._starting or self._closing:
                self._condition.wait()
            if self._closed:
                return
            if not self._started:
                self._closed = True
                self._condition.notify_all()
                return
            self._closing = True
            heartbeat_thread = self._heartbeat_thread
            self._stop_requested.set()

        cleanup_failure: Exception | None = None
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=self._close_timeout_seconds)
            if heartbeat_thread.is_alive():
                cleanup_failure = ApplicationInstanceLifecycleError(
                    "application instance heartbeat did not stop before the close timeout"
                )

        if cleanup_failure is None:
            try:
                self._store.stop_instance(
                    instance_id=self.instance_id,
                    now=self._clock(),
                )
            except Exception as exc:
                cleanup_failure = exc

        with self._condition:
            heartbeat_failure = self._heartbeat_failure
            if cleanup_failure is None:
                self._closed = True
            self._closing = False
            self._condition.notify_all()

        if cleanup_failure is not None:
            raise ApplicationInstanceLifecycleError(
                "application instance could not be marked stopped"
            ) from cleanup_failure
        if heartbeat_failure is not None:
            raise LifecycleHeartbeatError("application instance heartbeat failed") from (
                heartbeat_failure
            )

    def __enter__(self) -> ApplicationInstanceLifecycle:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
