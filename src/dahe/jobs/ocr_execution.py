from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from dahe.jobs.ocr_errors import OcrErrorKind

RuntimeKindName = Literal["cpu", "gpu"]


@dataclass(frozen=True, slots=True)
class OcrRuntimeIdentity:
    """Immutable identity of one qualified OCR gateway."""

    runtime_kind: RuntimeKindName
    profile_id: str
    runtime_fingerprint: str

    def __post_init__(self) -> None:
        if not self.profile_id.strip():
            raise ValueError("OCR profile identity is required")
        if len(self.runtime_fingerprint) != 64 or not _is_lower_hex(self.runtime_fingerprint):
            raise ValueError("OCR runtime fingerprint must be lowercase SHA-256")

    @property
    def resource_name(self) -> str:
        return f"{self.runtime_kind}_ocr_slot"


def qualified_runtime_set_sha256(
    identities: Sequence[Mapping[str, str]],
) -> str:
    """Return the single canonical identity for a qualified OCR runtime set."""

    if not identities:
        raise ValueError("at least one qualified OCR runtime identity is required")
    normalized: list[dict[str, str]] = []
    for identity in identities:
        required = {
            "profile_id",
            "runtime_fingerprint",
            "runtime_kind",
        }
        if set(identity) != required:
            raise ValueError("OCR runtime identity fields are invalid")
        values = {key: identity[key].strip() for key in sorted(required)}
        if any(not value for value in values.values()):
            raise ValueError("OCR runtime identity values are required")
        runtime_fingerprint = values["runtime_fingerprint"]
        if (
            len(runtime_fingerprint) != 64
            or runtime_fingerprint != runtime_fingerprint.lower()
            or any(character not in "0123456789abcdef" for character in runtime_fingerprint)
        ):
            raise ValueError("OCR runtime fingerprint must be lowercase SHA-256")
        normalized.append(values)
    encoded = json.dumps(
        {
            "qualified_runtimes": sorted(
                normalized,
                key=lambda item: (
                    item["runtime_kind"],
                    item["profile_id"],
                    item["runtime_fingerprint"],
                ),
            ),
            "schema_version": 1,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class OcrFormalAuthority:
    """Factory-bound provenance for a verified local OCR composition."""

    data_root: Path
    repository_root: Path
    runtime_set_sha256: str
    runtime_identities: tuple[OcrRuntimeIdentity, ...]
    composition_evidence_sha256: str

    def __post_init__(self) -> None:
        for label, root in (
            ("application data", self.data_root),
            ("repository", self.repository_root),
        ):
            try:
                resolved = root.resolve(strict=True)
            except OSError as exc:
                raise ValueError(f"{label} root must exist") from exc
            if not root.is_absolute() or root != resolved:
                raise ValueError(f"{label} root must be resolved")
        expected_identities = tuple(
            sorted(
                self.runtime_identities,
                key=lambda identity: (
                    identity.runtime_kind,
                    identity.profile_id,
                    identity.runtime_fingerprint,
                ),
            )
        )
        if (
            not expected_identities
            or expected_identities != self.runtime_identities
            or len({identity.runtime_kind for identity in self.runtime_identities})
            != len(self.runtime_identities)
        ):
            raise ValueError("formal OCR runtime identities must be unique and canonical")
        if self.runtime_set_sha256 != qualified_runtime_set_sha256(
            tuple(
                {
                    "profile_id": identity.profile_id,
                    "runtime_fingerprint": (identity.runtime_fingerprint),
                    "runtime_kind": identity.runtime_kind,
                }
                for identity in self.runtime_identities
            )
        ):
            raise ValueError("formal OCR runtime-set fingerprint is invalid")
        if len(self.composition_evidence_sha256) != 64 or not _is_lower_hex(
            self.composition_evidence_sha256
        ):
            raise ValueError("formal OCR composition evidence must be lowercase SHA-256")

    @classmethod
    def _from_verified_composition(
        cls,
        *,
        data_root: Path,
        repository_root: Path,
        runtime_identities: tuple[OcrRuntimeIdentity, ...],
        composition_evidence_sha256: str,
    ) -> OcrFormalAuthority:
        canonical_identities = tuple(
            sorted(
                runtime_identities,
                key=lambda identity: (
                    identity.runtime_kind,
                    identity.profile_id,
                    identity.runtime_fingerprint,
                ),
            )
        )
        return cls(
            data_root=data_root,
            repository_root=repository_root,
            runtime_set_sha256=qualified_runtime_set_sha256(
                tuple(
                    {
                        "profile_id": identity.profile_id,
                        "runtime_fingerprint": (identity.runtime_fingerprint),
                        "runtime_kind": identity.runtime_kind,
                    }
                    for identity in canonical_identities
                )
            ),
            runtime_identities=canonical_identities,
            composition_evidence_sha256=composition_evidence_sha256,
        )


@dataclass(frozen=True, slots=True)
class OcrImageWork:
    image_sha256: str
    relative_path: str

    def __post_init__(self) -> None:
        if len(self.image_sha256) != 64 or not _is_lower_hex(self.image_sha256):
            raise ValueError("OCR image identity must be lowercase SHA-256")
        if not self.relative_path.strip():
            raise ValueError("OCR image relative path is required")


@dataclass(frozen=True, slots=True)
class OcrStageWork:
    """One image-sized scheduler quantum owned by shared evidence work."""

    stage_attempt_id: str
    shared_work_id: str
    pipeline_fingerprint: str
    identity: OcrRuntimeIdentity
    image: OcrImageWork

    def __post_init__(self) -> None:
        if len(self.pipeline_fingerprint) != 64 or not _is_lower_hex(self.pipeline_fingerprint):
            raise ValueError("OCR pipeline fingerprint must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class OcrImageExecution:
    image_sha256: str
    output_json: str
    output_fingerprint: str


@dataclass(frozen=True, slots=True)
class OcrStageExecution:
    stage_attempt_id: str
    shared_work_id: str
    pipeline_fingerprint: str
    identity: OcrRuntimeIdentity
    image: OcrImageWork
    output: OcrImageExecution | None
    error_kind: OcrErrorKind | None
    diagnostic_code: str | None

    @property
    def succeeded(self) -> bool:
        return self.output is not None and self.error_kind is None


class OcrImageExecutionError(RuntimeError):
    def __init__(
        self,
        error_kind: OcrErrorKind | str,
        diagnostic_code: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.error_kind = OcrErrorKind(error_kind)
        self.diagnostic_code = diagnostic_code


class OcrRuntimeGateway(Protocol):
    @property
    def identity(self) -> OcrRuntimeIdentity: ...

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution: ...

    def close(self) -> None: ...


def _is_lower_hex(value: str) -> bool:
    return value == value.lower() and all(character in "0123456789abcdef" for character in value)


def _runtime_pipeline_fingerprint(
    *,
    pipeline_contract_fingerprint: str,
    identity: OcrRuntimeIdentity,
) -> str:
    if len(pipeline_contract_fingerprint) != 64 or not _is_lower_hex(pipeline_contract_fingerprint):
        raise ValueError("local OCR pipeline contract fingerprint must be lowercase SHA-256")
    payload = json.dumps(
        {
            "pipeline_contract_fingerprint": pipeline_contract_fingerprint,
            "profile_id": identity.profile_id,
            "runtime_fingerprint": identity.runtime_fingerprint,
            "runtime_kind": identity.runtime_kind,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


class AsyncOcrExecutionBackend:
    """Execute one fenced image quantum outside scheduler transactions."""

    def __init__(
        self,
        *,
        primary_runtime_kind: RuntimeKindName,
        gateways: dict[RuntimeKindName, OcrRuntimeGateway],
    ) -> None:
        if not gateways:
            raise ValueError("at least one OCR gateway is required")
        if primary_runtime_kind not in gateways:
            raise ValueError("the primary OCR gateway is missing")
        for runtime_kind, gateway in gateways.items():
            if gateway.identity.runtime_kind != runtime_kind:
                raise ValueError("OCR gateway runtime identity is inconsistent")
        self.primary_runtime_kind = primary_runtime_kind
        self._gateways = dict(gateways)
        self._executor = ThreadPoolExecutor(
            max_workers=len(gateways),
            thread_name_prefix="dahe-ocr-stage",
        )
        self._futures: dict[str, Future[OcrStageExecution]] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._formal_authority: OcrFormalAuthority | None = None

    @classmethod
    def _from_verified_composition(
        cls,
        *,
        primary_runtime_kind: RuntimeKindName,
        gateways: dict[RuntimeKindName, OcrRuntimeGateway],
        formal_authority: OcrFormalAuthority,
    ) -> AsyncOcrExecutionBackend:
        gateway_identities = tuple(
            sorted(
                (gateway.identity for gateway in gateways.values()),
                key=lambda identity: (
                    identity.runtime_kind,
                    identity.profile_id,
                    identity.runtime_fingerprint,
                ),
            )
        )
        if gateway_identities != formal_authority.runtime_identities:
            raise ValueError("formal OCR authority does not match the composed gateways")
        backend = cls(
            primary_runtime_kind=primary_runtime_kind,
            gateways=gateways,
        )
        backend._formal_authority = formal_authority
        return backend

    @property
    def formal_authority(self) -> OcrFormalAuthority | None:
        return self._formal_authority

    def identity_for(self, runtime_kind: RuntimeKindName) -> OcrRuntimeIdentity:
        return self._gateways[runtime_kind].identity

    def has_runtime(self, runtime_kind: RuntimeKindName) -> bool:
        return runtime_kind in self._gateways

    def pipeline_fingerprint_for(
        self,
        runtime_kind: RuntimeKindName,
        *,
        pipeline_contract_fingerprint: str,
    ) -> str:
        return _runtime_pipeline_fingerprint(
            pipeline_contract_fingerprint=pipeline_contract_fingerprint,
            identity=self.identity_for(runtime_kind),
        )

    def submit(self, work: OcrStageWork) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("OCR execution backend is closed")
            if work.stage_attempt_id in self._futures:
                raise RuntimeError("OCR stage attempt was submitted twice")
            self._futures[work.stage_attempt_id] = self._executor.submit(
                self._execute_image,
                work,
            )

    def _execute_image(self, work: OcrStageWork) -> OcrStageExecution:
        gateway = self._gateways[work.identity.runtime_kind]
        if gateway.identity != work.identity:
            return self._failure(
                work,
                error_kind=OcrErrorKind.PROTOCOL_ERROR,
                diagnostic_code="OCR-RUNTIME-IDENTITY-CHANGED",
            )
        try:
            output = gateway.extract(
                work.image,
                pipeline_fingerprint=work.pipeline_fingerprint,
            )
            if gateway.identity != work.identity:
                raise OcrImageExecutionError(
                    OcrErrorKind.PROTOCOL_ERROR,
                    "OCR-RUNTIME-IDENTITY-CHANGED",
                    "OCR runtime identity changed during the image quantum",
                )
            if output.image_sha256 != work.image.image_sha256:
                raise OcrImageExecutionError(
                    OcrErrorKind.EVIDENCE_MISMATCH,
                    "OCR-EVIDENCE-IDENTITY-MISMATCH",
                    "OCR runtime returned a different image identity",
                )
        except OcrImageExecutionError as exc:
            return self._failure(
                work,
                error_kind=exc.error_kind,
                diagnostic_code=exc.diagnostic_code,
            )
        except Exception:
            return self._failure(
                work,
                error_kind=OcrErrorKind.WORKER_CRASHED,
                diagnostic_code="OCR-WORKER-UNEXPECTED-FAILURE",
            )
        return OcrStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            shared_work_id=work.shared_work_id,
            pipeline_fingerprint=work.pipeline_fingerprint,
            identity=work.identity,
            image=work.image,
            output=output,
            error_kind=None,
            diagnostic_code=None,
        )

    @staticmethod
    def _failure(
        work: OcrStageWork,
        *,
        error_kind: OcrErrorKind,
        diagnostic_code: str,
    ) -> OcrStageExecution:
        return OcrStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            shared_work_id=work.shared_work_id,
            pipeline_fingerprint=work.pipeline_fingerprint,
            identity=work.identity,
            image=work.image,
            output=None,
            error_kind=error_kind,
            diagnostic_code=diagnostic_code,
        )

    def pop_completed(self) -> dict[str, OcrStageExecution]:
        with self._lock:
            completed_ids = [
                attempt_id for attempt_id, future in self._futures.items() if future.done()
            ]
            completed = {
                attempt_id: self._futures.pop(attempt_id).result() for attempt_id in completed_ids
            }
        return completed

    def has_pending(self) -> bool:
        with self._lock:
            return bool(self._futures)

    def set_idle_timeout_seconds(self, value: float | None) -> None:
        """Release qualified worker processes after idle time without losing identity."""

        with self._lock:
            if self._closed:
                return
            gateways = tuple(self._gateways.values())
        for gateway in gateways:
            setter = getattr(gateway, "set_idle_timeout_seconds", None)
            if setter is not None:
                setter(value)

    def set_cpu_thread_limit(self, value: int) -> None:
        """Apply the configured CPU limit at the next image boundary."""

        with self._lock:
            if self._closed:
                return
            gateway = self._gateways.get("cpu")
        if gateway is None:
            return
        setter = getattr(gateway, "set_cpu_thread_limit", None)
        if setter is not None:
            setter(value)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        first_failure: BaseException | None = None
        try:
            self._executor.shutdown(wait=True, cancel_futures=False)
        except BaseException as exc:
            first_failure = exc
        for gateway in self._gateways.values():
            try:
                gateway.close()
            except BaseException as exc:
                if first_failure is None:
                    first_failure = exc
        if first_failure is not None:
            raise first_failure
