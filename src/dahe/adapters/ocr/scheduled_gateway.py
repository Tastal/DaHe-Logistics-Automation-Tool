from __future__ import annotations

import json
from threading import RLock
from uuid import uuid4

from dahe.adapters.ocr.errors import OcrErrorKind
from dahe.adapters.ocr.fingerprints import build_ocr_output_fingerprint
from dahe.adapters.ocr.protocol import (
    OCR_PROTOCOL_VERSION,
    OcrCommand,
    OcrOperation,
    OcrResultStatus,
)
from dahe.adapters.ocr.worker_session import (
    SupervisedNdjsonWorker,
    WorkerProcessError,
    WorkerProtocolError,
    WorkerTimeoutError,
)
from dahe.jobs.ocr_execution import (
    OcrImageExecution,
    OcrImageExecutionError,
    OcrImageWork,
    OcrRuntimeIdentity,
)


class NdjsonOcrRuntimeGateway:
    """Bind one supervised worker to an immutable runtime/profile identity."""

    def __init__(
        self,
        *,
        identity: OcrRuntimeIdentity,
        worker: SupervisedNdjsonWorker,
        timeout_seconds: float,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("OCR timeout must be positive")
        self._identity = identity
        self._worker = worker
        self._timeout_seconds = timeout_seconds
        self._lifecycle_lock = RLock()

    @property
    def identity(self) -> OcrRuntimeIdentity:
        return self._identity

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        with self._lifecycle_lock:
            return self._extract_locked(
                image,
                pipeline_fingerprint=pipeline_fingerprint,
            )

    def _restart_after_failure(self, failure: BaseException) -> None:
        try:
            self._worker.restart(
                runtime_fingerprint=self.identity.runtime_fingerprint,
                profile_id=self.identity.profile_id,
                timeout_seconds=self._timeout_seconds,
            )
        except WorkerProcessError as restart_error:
            failure.add_note(
                f"the owned OCR worker replacement also failed: {type(restart_error).__name__}"
            )

    def _ensure_live_worker(self) -> None:
        if self._worker.is_alive:
            return
        try:
            self._worker.restart(
                runtime_fingerprint=self.identity.runtime_fingerprint,
                profile_id=self.identity.profile_id,
                timeout_seconds=self._timeout_seconds,
            )
        except WorkerProcessError as exc:
            raise OcrImageExecutionError(
                OcrErrorKind.WORKER_CRASHED.value,
                "OCR-WORKER-RESTART-FAILED",
                str(exc),
            ) from exc

    def _extract_locked(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        self._ensure_live_worker()
        command = OcrCommand(
            protocol_version=OCR_PROTOCOL_VERSION,
            command_id=uuid4().hex,
            operation=OcrOperation.EXTRACT,
            image_sha256=image.image_sha256,
            relative_path=image.relative_path,
            pipeline_fingerprint=pipeline_fingerprint,
            runtime_fingerprint=self.identity.runtime_fingerprint,
            profile_id=self.identity.profile_id,
        )
        try:
            result = self._worker.request(
                command,
                timeout_seconds=self._timeout_seconds,
            )
        except WorkerTimeoutError as exc:
            self._restart_after_failure(exc)
            raise OcrImageExecutionError(
                OcrErrorKind.WORKER_TIMEOUT.value,
                "OCR-WORKER-TIMEOUT",
                str(exc),
            ) from exc
        except WorkerProtocolError as exc:
            self._restart_after_failure(exc)
            raise OcrImageExecutionError(
                OcrErrorKind.PROTOCOL_ERROR.value,
                "OCR-WORKER-PROTOCOL",
                str(exc),
            ) from exc
        except WorkerProcessError as exc:
            self._restart_after_failure(exc)
            raise OcrImageExecutionError(
                OcrErrorKind.WORKER_CRASHED.value,
                "OCR-WORKER-CRASHED",
                str(exc),
            ) from exc
        if result.status is OcrResultStatus.ERROR:
            assert result.error is not None
            try:
                error_kind = OcrErrorKind(result.error.kind)
            except ValueError:
                error_kind = OcrErrorKind.PROTOCOL_ERROR
            failure = OcrImageExecutionError(
                error_kind.value,
                result.error.diagnostic_code,
                result.error.message,
            )
            self._restart_after_failure(failure)
            raise failure
        output_payload = result.model_dump(mode="json")
        output_json = json.dumps(
            output_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return OcrImageExecution(
            image_sha256=image.image_sha256,
            output_json=output_json,
            output_fingerprint=build_ocr_output_fingerprint(
                image_sha256=image.image_sha256,
                fields=output_payload["fields"],
                role_observation=output_payload["role_observation"],
                text_lines=output_payload["text_lines"],
                verified_image_sha256=output_payload["verified_image_sha256"],
                pipeline_fingerprint=pipeline_fingerprint,
                profile_id=self.identity.profile_id,
                runtime_fingerprint=self.identity.runtime_fingerprint,
                runtime_kind=self.identity.runtime_kind,
            ),
        )

    def close(self) -> None:
        with self._lifecycle_lock:
            self._worker.close()

    def set_idle_timeout_seconds(self, value: float | None) -> None:
        with self._lifecycle_lock:
            self._worker.set_idle_timeout_seconds(value)

    def set_cpu_thread_limit(self, value: int) -> None:
        with self._lifecycle_lock:
            self._worker.set_cpu_thread_limit(value)
