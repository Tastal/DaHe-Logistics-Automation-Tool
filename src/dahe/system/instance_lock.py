from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from uuid import uuid4

ERROR_ALREADY_EXISTS = 183


class AlreadyRunningError(RuntimeError):
    """Raised when another instance owns the same application data profile."""


class InstanceLockError(RuntimeError):
    """Raised when the operating-system instance guard cannot be created."""


class SingleInstanceGuard:
    def __init__(self, data_root: Path, port: int, application_version: str) -> None:
        self.data_root = data_root.resolve()
        identity = os.path.normcase(os.fspath(self.data_root)).encode("utf-8")
        digest = hashlib.sha256(identity).hexdigest()[:32]
        self.mutex_name = f"Local\\DaHeLogistics-{digest}"
        self.instance_id = uuid4().hex
        self.port = port
        self.application_version = application_version
        self.metadata_path = self.data_root / "runtime" / "instance.json"
        self.previous_instance_id: str | None = None
        self._handle: int | None = None

    def acquire(self) -> None:
        if sys.platform != "win32":
            raise InstanceLockError("DaHeLogistics currently supports Windows only")
        if self._handle is not None:
            return

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_mutex = kernel32.CreateMutexW
        create_mutex.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
        create_mutex.restype = wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL

        handle = create_mutex(None, False, self.mutex_name)
        if not handle:
            raise InstanceLockError("Windows could not create the application mutex")
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            close_handle(handle)
            raise AlreadyRunningError("DaHeLogistics is already running for this data directory")

        self._handle = int(handle)
        try:
            self.previous_instance_id = self._read_previous_instance_id()
            self._write_metadata()
        except Exception:
            self.release()
            raise

    def _read_previous_instance_id(self) -> str | None:
        try:
            document = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(document, dict):
            return None
        if (
            document.get("application_id") != "DaHeLogistics"
            or document.get("mutex_name") != self.mutex_name
        ):
            return None
        instance_id = document.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id.strip():
            return None
        return instance_id

    def _write_metadata(self) -> None:
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "application_id": "DaHeLogistics",
            "application_version": self.application_version,
            "instance_id": self.instance_id,
            "mutex_name": self.mutex_name,
            "pid": os.getpid(),
            "port": self.port,
            "started_at": datetime.now(UTC).isoformat(),
            "status": "running",
        }
        temporary = self.metadata_path.with_name(f".{self.metadata_path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.metadata_path)
        finally:
            temporary.unlink(missing_ok=True)

    def release(self) -> None:
        if self._handle is None:
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        close_handle(self._handle)
        self._handle = None

    def __enter__(self) -> SingleInstanceGuard:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()
