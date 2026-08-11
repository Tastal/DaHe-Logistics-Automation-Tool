from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from threading import Event, RLock, Thread
from uuid import uuid4

from dahe.adapters.ocr.protocol import (
    MAX_COMMAND_LINE_BYTES,
    MAX_RESULT_LINE_BYTES,
    OcrCommand,
    OcrOperation,
    OcrProtocolError,
    OcrResult,
    OcrResultStatus,
    parse_result_line,
    validate_result_for_command,
)
from dahe.system.supervision import (
    SupervisedLineProcess,
    SupervisedLineProcessError,
    SupervisedLineProcessProtocolError,
    SupervisedLineProcessTimeout,
)


class WorkerProcessError(RuntimeError):
    """Raised when an owned OCR worker exits or cannot be reached."""


class WorkerTimeoutError(WorkerProcessError):
    """Raised when an owned OCR worker exceeds an atomic-step deadline."""


class WorkerProtocolError(WorkerProcessError):
    """Raised when an owned OCR worker violates the NDJSON contract."""


class SupervisedNdjsonWorker:
    """Translate typed OCR commands across one supervised NDJSON process."""

    def __init__(
        self,
        *,
        worker_id: str,
        argv: Sequence[str],
        runtime_dir: Path,
        environment: dict[str, str] | None = None,
        output_sink: Callable[[str, str, str, bool], None] | None = None,
        below_normal_priority: bool = False,
        idle_timeout_seconds: float | None = None,
    ) -> None:
        self._worker_id = worker_id
        self._argv = tuple(argv)
        self._runtime_dir = runtime_dir
        self._environment = None if environment is None else dict(environment)
        self._output_sink = output_sink
        self._below_normal_priority = below_normal_priority
        if idle_timeout_seconds is not None and idle_timeout_seconds <= 0:
            raise ValueError("OCR idle timeout must be positive")
        self._idle_timeout_seconds = idle_timeout_seconds
        self._last_activity_monotonic = time.monotonic()
        self._idle_stop = Event()
        self._lifecycle_lock = RLock()
        self._closed = False
        self._process = self._spawn_process()
        self._worker_identity: str | None = None
        self._last_heartbeat_monotonic: float | None = None
        self._idle_thread = Thread(
            target=self._release_idle_process,
            name=f"{worker_id}-idle-release",
            daemon=True,
        )
        self._idle_thread.start()

    def _spawn_process(self) -> SupervisedLineProcess:
        return SupervisedLineProcess(
            worker_id=self._worker_id,
            argv=self._argv,
            runtime_dir=self._runtime_dir,
            environment=self._environment,
            max_request_bytes=MAX_COMMAND_LINE_BYTES,
            max_response_bytes=MAX_RESULT_LINE_BYTES,
            output_sink=self._output_sink,
            below_normal_priority=self._below_normal_priority,
        )

    def _release_idle_process(self) -> None:
        while not self._idle_stop.wait(1.0):
            with self._lifecycle_lock:
                timeout = self._idle_timeout_seconds
                if self._closed:
                    return
                if timeout is None or not self._process.is_alive:
                    continue
                if time.monotonic() - self._last_activity_monotonic < timeout:
                    continue
                with contextlib.suppress(SupervisedLineProcessError):
                    self._process.close()

    def set_idle_timeout_seconds(self, value: float | None) -> None:
        if value is not None and value <= 0:
            raise ValueError("OCR idle timeout must be positive")
        with self._lifecycle_lock:
            self._idle_timeout_seconds = value
            self._last_activity_monotonic = time.monotonic()

    def set_cpu_thread_limit(self, value: int) -> None:
        if not 1 <= value <= 8:
            raise ValueError("CPU OCR thread limit must be from 1 to 8")
        with self._lifecycle_lock:
            environment = dict(self._environment or {})
            encoded = str(value)
            if (
                environment.get("OMP_NUM_THREADS") == encoded
                and environment.get("MKL_NUM_THREADS") == encoded
            ):
                return
            environment["OMP_NUM_THREADS"] = encoded
            environment["MKL_NUM_THREADS"] = encoded
            self._environment = environment
            self._last_activity_monotonic = time.monotonic()
            if self._process.is_alive:
                with contextlib.suppress(SupervisedLineProcessError):
                    self._process.close()

    @property
    def identity(self) -> object:
        return self._process.identity

    @property
    def is_alive(self) -> bool:
        return self._process.is_alive

    @property
    def stderr_digest(self) -> str | None:
        return self._process.stderr_digest

    @property
    def last_heartbeat_monotonic(self) -> float | None:
        return self._last_heartbeat_monotonic

    def _close_after_protocol_failure(self) -> None:
        with contextlib.suppress(SupervisedLineProcessError):
            self._process.close()

    def request(
        self,
        command: OcrCommand,
        *,
        timeout_seconds: float,
    ) -> OcrResult:
        with self._lifecycle_lock:
            if self._closed:
                raise WorkerProcessError("the OCR worker session is closed")
            try:
                self._last_activity_monotonic = time.monotonic()
                line = command.to_ndjson().rstrip("\n")
                response = self._process.request_line(
                    line,
                    timeout_seconds=timeout_seconds,
                )
            except SupervisedLineProcessTimeout as exc:
                raise WorkerTimeoutError(str(exc)) from exc
            except SupervisedLineProcessProtocolError as exc:
                self._close_after_protocol_failure()
                raise WorkerProtocolError(str(exc)) from exc
            except SupervisedLineProcessError as exc:
                raise WorkerProcessError(str(exc)) from exc
            except OcrProtocolError as exc:
                self._close_after_protocol_failure()
                raise WorkerProtocolError(str(exc)) from exc
            try:
                result = parse_result_line(response)
                validate_result_for_command(command=command, result=result)
            except OcrProtocolError as exc:
                self._close_after_protocol_failure()
                raise WorkerProtocolError(str(exc)) from exc
            if (
                self._worker_identity is not None
                and result.worker_identity != self._worker_identity
            ):
                self._close_after_protocol_failure()
                raise WorkerProtocolError("OCR worker identity changed within one session")
            self._worker_identity = result.worker_identity
            self._last_activity_monotonic = time.monotonic()
            return result

    def restart(
        self,
        *,
        runtime_fingerprint: str,
        profile_id: str,
        timeout_seconds: float,
    ) -> OcrResult:
        """Replace only this owned worker and re-establish its runtime identity."""

        with self._lifecycle_lock:
            if self._closed:
                raise WorkerProcessError("the OCR worker session is closed")
            try:
                self._process.close()
            except SupervisedLineProcessError as exc:
                raise WorkerProcessError(str(exc)) from exc
            self._process = self._spawn_process()
            self._last_activity_monotonic = time.monotonic()
            self._worker_identity = None
            self._last_heartbeat_monotonic = None
            try:
                return self.hello(
                    runtime_fingerprint=runtime_fingerprint,
                    profile_id=profile_id,
                    timeout_seconds=timeout_seconds,
                )
            except BaseException:
                with contextlib.suppress(SupervisedLineProcessError):
                    self._process.close()
                raise

    def hello(
        self,
        *,
        runtime_fingerprint: str,
        profile_id: str,
        timeout_seconds: float,
    ) -> OcrResult:
        result = self.request(
            OcrCommand(
                operation=OcrOperation.HELLO,
                command_id=f"hello-{uuid4().hex}",
                runtime_fingerprint=runtime_fingerprint,
                profile_id=profile_id,
            ),
            timeout_seconds=timeout_seconds,
        )
        if result.status is not OcrResultStatus.OK:
            self._close_after_protocol_failure()
            raise WorkerProcessError("OCR worker handshake failed")
        self._last_heartbeat_monotonic = time.monotonic()
        return result

    def heartbeat(
        self,
        *,
        runtime_fingerprint: str,
        profile_id: str,
        timeout_seconds: float,
    ) -> OcrResult:
        return self.hello(
            runtime_fingerprint=runtime_fingerprint,
            profile_id=profile_id,
            timeout_seconds=timeout_seconds,
        )

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._idle_stop.set()
            try:
                self._process.close()
            except SupervisedLineProcessError as exc:
                raise WorkerProcessError(str(exc)) from exc
