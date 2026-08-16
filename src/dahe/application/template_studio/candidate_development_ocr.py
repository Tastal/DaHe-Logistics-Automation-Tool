from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
    EvidenceIntegrityError,
)
from dahe.adapters.ocr.protocol import OcrResult, OcrResultStatus
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewAuthoritySnapshot,
)
from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewFormalExport,
)
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageWork,
    OcrStageExecution,
    OcrStageWork,
    OcrVehicleImageWork,
    RuntimeKindName,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImageChangedError,
    LockedSetReviewPackage,
)

EVALUATOR_VERSION = "dahe.loop7.candidate-development-ocr.v1"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_KINDS: tuple[RuntimeKindName, RuntimeKindName] = ("cpu", "gpu")
CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME = "protected-candidate-review-ocr"


class CandidateDevelopmentOcrError(RuntimeError):
    """Raised when development-only candidate OCR cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class CandidateDevelopmentOcrEvaluation:
    status: str
    evidence_path: Path
    evidence_sha256: str
    summary_payload: dict[str, object]
    technical_failure_count: int
    runtime_difference_count: int


@dataclass(frozen=True, slots=True)
class _CopiedImage:
    image_sha256: str
    relative_path: str
    byte_size: int
    media_type: str

    def to_payload(self) -> dict[str, object]:
        return {
            "byte_size": self.byte_size,
            "image_sha256": self.image_sha256,
            "media_type": self.media_type,
            "relative_path": self.relative_path,
        }


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CandidateDevelopmentOcrError(
            "candidate development evidence contains invalid JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _resolved_directory(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateDevelopmentOcrError(f"{label} is unavailable") from exc
    if not path.is_absolute() or path != resolved or not resolved.is_dir():
        raise CandidateDevelopmentOcrError(
            f"{label} must be an existing resolved absolute directory"
        )
    return resolved


def _is_same_or_descendant(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _validate_source_bindings(
    *,
    package: LockedSetReviewPackage,
    authority: LockedSetReviewAuthoritySnapshot,
    review_export: CandidateReviewFormalExport,
    reviewer_id: str,
    data_root: Path,
) -> None:
    normalized_reviewer = reviewer_id.strip()
    if not normalized_reviewer or normalized_reviewer != reviewer_id:
        raise CandidateDevelopmentOcrError("reviewer identity is invalid")
    review_root = _resolved_directory(
        package.review_root,
        label="candidate review package root",
    )
    if _is_same_or_descendant(review_root, data_root) or _is_same_or_descendant(
        data_root,
        review_root,
    ):
        raise CandidateDevelopmentOcrError(
            "candidate review and development data roots must be independent"
        )
    if (
        len(package.items) != 50
        or len(package.images_by_sha256) != 100
        or len(authority.latest_records) != 50
        or len(authority.history_records) < 50
        or len(authority.idempotency_records) != len(authority.history_records)
    ):
        raise CandidateDevelopmentOcrError("candidate review authority is incomplete")
    package_samples = {item.sample_id for item in package.items}
    if (
        len(package_samples) != 50
        or {record.sample_id for record in authority.latest_records} != package_samples
        or authority.package_sha256 != package.canonical_sha256
        or authority.payload.get("package_sha256") != package.canonical_sha256
        or authority.payload.get("latest_record_count") != len(authority.latest_records)
        or authority.payload.get("history_record_count") != len(authority.history_records)
        or authority.payload.get("idempotency_record_count") != len(authority.idempotency_records)
        or not _is_sha256(authority.canonical_sha256)
        or _canonical_sha256(authority.payload) != authority.canonical_sha256
    ):
        raise CandidateDevelopmentOcrError("candidate review history authority does not reconcile")

    source = review_export.source_authority_payload
    source_without_hash = {
        key: value for key, value in source.items() if key != "source_authority_sha256"
    }
    manifest_images = {
        image.image_sha256
        for waybill in review_export.manifest.waybills
        for image in waybill.images
    }
    manifest_samples = {waybill.sample_id for waybill in review_export.manifest.waybills}
    if (
        review_export.manifest.dataset_kind != "locked"
        or review_export.manifest.tuning_prohibited is not True
        or len(review_export.manifest.waybills) != 50
        or len(manifest_images) != 100
        or manifest_images != set(package.images_by_sha256)
        or manifest_samples != package_samples
        or review_export.manifest_sha256 != review_export.manifest.canonical_sha256
        or source.get("package_sha256") != package.canonical_sha256
        or source.get("configured_reviewer_id") != normalized_reviewer
        or source.get("record_count") != len(authority.latest_records)
        or source.get("verified_image_count") != 100
        or source.get("manifest_sha256") != review_export.manifest_sha256
        or source.get("record_set_sha256") != review_export.record_set_sha256
        or source.get("source_authority_sha256") != review_export.source_authority_sha256
        or _canonical_sha256(source_without_hash) != review_export.source_authority_sha256
    ):
        raise CandidateDevelopmentOcrError("candidate labels and image authority do not reconcile")
    for digest in (
        package.canonical_sha256,
        review_export.manifest_sha256,
        review_export.record_set_sha256,
        review_export.source_authority_sha256,
        review_export.quality_coverage_sha256,
    ):
        if not _is_sha256(digest):
            raise CandidateDevelopmentOcrError(
                "candidate development source contains an invalid identity"
            )


def _validate_backend(
    backend: AsyncOcrExecutionBackend,
    *,
    data_root: Path,
) -> None:
    if not isinstance(backend, AsyncOcrExecutionBackend):
        raise CandidateDevelopmentOcrError("a factory-qualified OCR backend is required")
    factory_authority = backend.formal_authority
    if factory_authority is None:
        raise CandidateDevelopmentOcrError("a factory-qualified OCR backend is required")
    if factory_authority.data_root != data_root:
        raise CandidateDevelopmentOcrError("qualified OCR backend belongs to another data root")
    if any(not backend.has_runtime(runtime_kind) for runtime_kind in _RUNTIME_KINDS):
        raise CandidateDevelopmentOcrError(
            "candidate development OCR requires qualified CPU and GPU runtimes"
        )
    if not _is_sha256(factory_authority.runtime_set_sha256) or not _is_sha256(
        factory_authority.composition_evidence_sha256
    ):
        raise CandidateDevelopmentOcrError("qualified OCR backend evidence is invalid")


def _verify_all_source_images(
    package: LockedSetReviewPackage,
) -> None:
    for image_sha256 in sorted(package.images_by_sha256):
        try:
            content, _ = package.read_verified_image(image_sha256)
        except (KeyError, LockedSetReviewImageChangedError) as exc:
            raise CandidateDevelopmentOcrError(
                "candidate review image integrity validation failed"
            ) from exc
        if hashlib.sha256(content).hexdigest() != image_sha256:
            raise CandidateDevelopmentOcrError("candidate review image integrity validation failed")


def _copy_images(
    *,
    package: LockedSetReviewPackage,
    data_root: Path,
    protected_root: Path,
) -> tuple[_CopiedImage, ...]:
    store = ContentAddressedEvidenceStore(
        protected_root / "evidence",
    )
    copied: list[_CopiedImage] = []
    for image_sha256 in sorted(package.images_by_sha256):
        try:
            content, media_type = package.read_verified_image(image_sha256)
            stored = store.put_bytes(
                content,
                media_type=media_type,
            )
        except (
            KeyError,
            LockedSetReviewImageChangedError,
            EvidenceIntegrityError,
            OSError,
        ) as exc:
            raise CandidateDevelopmentOcrError(
                "candidate review image copy failed integrity validation"
            ) from exc
        if stored.sha256 != image_sha256:
            raise CandidateDevelopmentOcrError(
                "candidate review image identity changed during copy"
            )
        target = store.path_for(stored.sha256)
        try:
            relative_path = target.relative_to(data_root).as_posix()
        except ValueError as exc:
            raise CandidateDevelopmentOcrError(
                "candidate development image escaped the data root"
            ) from exc
        copied.append(
            _CopiedImage(
                image_sha256=image_sha256,
                relative_path=relative_path,
                byte_size=stored.byte_size,
                media_type=stored.media_type,
            )
        )
    return tuple(copied)


def _failed_attempt(
    *,
    image: _CopiedImage,
    runtime_kind: RuntimeKindName,
    runtime_fingerprint: str,
    profile_id: str,
    pipeline_fingerprint: str,
    wall_elapsed_ms: float,
    error_kind: str,
    diagnostic_code: str,
) -> dict[str, object]:
    return {
        "diagnostic_code": diagnostic_code,
        "error_kind": error_kind,
        "image_sha256": image.image_sha256,
        "pipeline_fingerprint": pipeline_fingerprint,
        "profile_id": profile_id,
        "runtime_fingerprint": runtime_fingerprint,
        "runtime_kind": runtime_kind,
        "status": "failed",
        "wall_elapsed_ms": round(wall_elapsed_ms, 6),
    }


def _successful_attempt(
    *,
    image: _CopiedImage,
    execution: OcrStageExecution,
    wall_elapsed_ms: float,
) -> dict[str, object]:
    if execution.output is None:
        raise CandidateDevelopmentOcrError("successful OCR execution has no output")
    try:
        result = OcrResult.model_validate_json(execution.output.output_json)
    except (TypeError, ValueError):
        return _failed_attempt(
            image=image,
            runtime_kind=execution.identity.runtime_kind,
            runtime_fingerprint=execution.identity.runtime_fingerprint,
            profile_id=execution.identity.profile_id,
            pipeline_fingerprint=execution.pipeline_fingerprint,
            wall_elapsed_ms=wall_elapsed_ms,
            error_kind="invalid_output",
            diagnostic_code="DEVELOPMENT-OCR-INVALID-OUTPUT",
        )
    if (
        result.status is not OcrResultStatus.OK
        or result.runtime_fingerprint != execution.identity.runtime_fingerprint
        or result.verified_image_sha256 != image.image_sha256
        or execution.output.image_sha256 != image.image_sha256
        or not _is_sha256(execution.output.output_fingerprint)
    ):
        return _failed_attempt(
            image=image,
            runtime_kind=execution.identity.runtime_kind,
            runtime_fingerprint=execution.identity.runtime_fingerprint,
            profile_id=execution.identity.profile_id,
            pipeline_fingerprint=execution.pipeline_fingerprint,
            wall_elapsed_ms=wall_elapsed_ms,
            error_kind="invalid_output",
            diagnostic_code="DEVELOPMENT-OCR-EVIDENCE-MISMATCH",
        )
    output_payload = result.model_dump(mode="json")
    fields = cast(dict[str, object], output_payload["fields"])
    text_lines = cast(list[object], output_payload["text_lines"])
    role_observation = cast(
        dict[str, object] | None,
        output_payload["role_observation"],
    )
    fixed_text = [] if role_observation is None else cast(list[str], role_observation["fixed_text"])
    business_output = {
        "fields": fields,
        "role_observation": role_observation,
        "text_lines": text_lines,
    }
    return {
        "business_output_sha256": _canonical_sha256(business_output),
        "fields": fields,
        "image_sha256": image.image_sha256,
        "output_fingerprint": execution.output.output_fingerprint,
        "pipeline_fingerprint": execution.pipeline_fingerprint,
        "profile_id": execution.identity.profile_id,
        "raw_output_sha256": _sha256_text(execution.output.output_json),
        "role_input": {
            "fixed_text": fixed_text,
            "image_sha256": image.image_sha256,
            "text_lines": text_lines,
        },
        "role_observation": role_observation,
        "runtime_fingerprint": result.runtime_fingerprint,
        "runtime_kind": execution.identity.runtime_kind,
        "status": "succeeded",
        "wall_elapsed_ms": round(wall_elapsed_ms, 6),
        "worker_elapsed_ms": result.elapsed_ms,
    }


def _execute_image(
    *,
    backend: AsyncOcrExecutionBackend,
    image: _CopiedImage,
    pipeline_fingerprints: dict[RuntimeKindName, str],
    timeout_seconds: float,
) -> tuple[tuple[dict[str, object], ...], bool]:
    started_ns: dict[RuntimeKindName, int] = {}
    attempt_ids: dict[str, RuntimeKindName] = {}
    for runtime_kind in _RUNTIME_KINDS:
        identity = backend.identity_for(runtime_kind)
        attempt_id = uuid4().hex
        pipeline_fingerprint = pipeline_fingerprints[runtime_kind]
        shared_work_id = _canonical_sha256(
            {
                "image_sha256": image.image_sha256,
                "pipeline_fingerprint": pipeline_fingerprint,
                "purpose": "candidate_review_development_ocr",
            }
        )
        work = OcrStageWork(
            stage_attempt_id=attempt_id,
            pipeline_fingerprint=pipeline_fingerprint,
            identity=identity,
            images=(
                OcrVehicleImageWork(
                    shared_work_id=shared_work_id,
                    role="loading",
                    image=OcrImageWork(
                        image_sha256=image.image_sha256,
                        relative_path=image.relative_path,
                    ),
                ),
            ),
        )
        started_ns[runtime_kind] = time.perf_counter_ns()
        attempt_ids[attempt_id] = runtime_kind
        backend.submit(work)

    completed: dict[RuntimeKindName, OcrStageExecution] = {}
    completed_elapsed_ms: dict[RuntimeKindName, float] = {}
    deadline = time.monotonic() + timeout_seconds
    while len(completed) < len(_RUNTIME_KINDS):
        returned = backend.pop_completed()
        returned_at_ns = time.perf_counter_ns()
        unexpected = set(returned).difference(attempt_ids)
        if unexpected:
            raise CandidateDevelopmentOcrError(
                "dedicated development OCR backend returned unrelated work"
            )
        for attempt_id, returned_execution in returned.items():
            runtime_kind = attempt_ids[attempt_id]
            if runtime_kind in completed:
                raise CandidateDevelopmentOcrError("development OCR runtime completed twice")
            completed[runtime_kind] = returned_execution
            completed_elapsed_ms[runtime_kind] = (
                returned_at_ns - started_ns[runtime_kind]
            ) / 1_000_000
        if len(completed) == len(_RUNTIME_KINDS):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.005)

    attempts: list[dict[str, object]] = []
    timed_out = False
    for runtime_kind in _RUNTIME_KINDS:
        elapsed_ms = completed_elapsed_ms.get(
            runtime_kind,
            (time.perf_counter_ns() - started_ns[runtime_kind]) / 1_000_000,
        )
        identity = backend.identity_for(runtime_kind)
        completed_execution = completed.get(runtime_kind)
        if completed_execution is None:
            timed_out = True
            attempts.append(
                _failed_attempt(
                    image=image,
                    runtime_kind=runtime_kind,
                    runtime_fingerprint=identity.runtime_fingerprint,
                    profile_id=identity.profile_id,
                    pipeline_fingerprint=(pipeline_fingerprints[runtime_kind]),
                    wall_elapsed_ms=elapsed_ms,
                    error_kind="worker_timeout",
                    diagnostic_code="DEVELOPMENT-OCR-TIMEOUT",
                )
            )
        elif not completed_execution.succeeded:
            attempts.append(
                _failed_attempt(
                    image=image,
                    runtime_kind=runtime_kind,
                    runtime_fingerprint=identity.runtime_fingerprint,
                    profile_id=identity.profile_id,
                    pipeline_fingerprint=(pipeline_fingerprints[runtime_kind]),
                    wall_elapsed_ms=elapsed_ms,
                    error_kind=(
                        completed_execution.error_kind.value
                        if completed_execution.error_kind is not None
                        else "runtime_failure"
                    ),
                    diagnostic_code=(
                        completed_execution.diagnostic_code or "DEVELOPMENT-OCR-RUNTIME-FAILURE"
                    ),
                )
            )
        else:
            attempts.append(
                _successful_attempt(
                    image=image,
                    execution=completed_execution,
                    wall_elapsed_ms=elapsed_ms,
                )
            )
    return tuple(attempts), timed_out


def _comparison(
    image_sha256: str,
    attempts: tuple[dict[str, object], ...],
) -> dict[str, object]:
    by_runtime = {cast(str, attempt["runtime_kind"]): attempt for attempt in attempts}
    cpu = by_runtime["cpu"]
    gpu = by_runtime["gpu"]
    if cpu["status"] != "succeeded" or gpu["status"] != "succeeded":
        return {
            "comparison_status": "unavailable",
            "image_sha256": image_sha256,
            "runtime_output_sha256s": {
                runtime_kind: (attempt.get("business_output_sha256"))
                for runtime_kind, attempt in sorted(by_runtime.items())
            },
        }
    differences = tuple(
        section
        for section in ("fields", "role_input", "role_observation")
        if cpu[section] != gpu[section]
    )
    return {
        "comparison_status": ("different" if differences else "same"),
        "difference_sections": list(differences),
        "image_sha256": image_sha256,
        "runtime_output_sha256s": {
            runtime_kind: cast(
                str,
                attempt["business_output_sha256"],
            )
            for runtime_kind, attempt in sorted(by_runtime.items())
        },
    }


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(
        0,
        min(
            len(ordered) - 1,
            math.ceil(percentile * len(ordered)) - 1,
        ),
    )
    return round(ordered[index], 6)


def _latency_summary(
    attempts: tuple[dict[str, object], ...],
) -> dict[str, object]:
    summary: dict[str, object] = {}
    for runtime_kind in _RUNTIME_KINDS:
        successful = [
            attempt
            for attempt in attempts
            if attempt["runtime_kind"] == runtime_kind and attempt["status"] == "succeeded"
        ]
        worker = [float(cast(float, attempt["worker_elapsed_ms"])) for attempt in successful]
        wall = [float(cast(float, attempt["wall_elapsed_ms"])) for attempt in successful]
        summary[runtime_kind] = {
            "sample_count": len(successful),
            "wall_elapsed_ms": {
                "p50": _percentile(wall, 0.50),
                "p95": _percentile(wall, 0.95),
            },
            "worker_elapsed_ms": {
                "p50": _percentile(worker, 0.50),
                "p95": _percentile(worker, 0.95),
            },
        }
    return summary


def _write_protected_evidence(
    protected_root: Path,
    payload: dict[str, object],
) -> tuple[Path, str]:
    evidence_sha256 = _canonical_sha256(payload)
    complete = dict(payload)
    complete["evidence_sha256"] = evidence_sha256
    records_root = protected_root / "records" / "sha256"
    target = records_root / evidence_sha256[:2] / evidence_sha256[2:4] / f"{evidence_sha256}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            complete,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CandidateDevelopmentOcrError(
                "protected development evidence is unreadable"
            ) from exc
        if (
            not isinstance(existing, dict)
            or existing.get("evidence_sha256") != evidence_sha256
            or _canonical_sha256(
                {key: value for key, value in existing.items() if key != "evidence_sha256"}
            )
            != evidence_sha256
        ):
            raise CandidateDevelopmentOcrError("protected development evidence identity conflicts")
        return target, evidence_sha256

    staged = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, target)
        except FileExistsError:
            return _write_protected_evidence(
                protected_root,
                payload,
            )
        except OSError as exc:
            raise CandidateDevelopmentOcrError(
                "protected development evidence could not be committed"
            ) from exc
    finally:
        staged.unlink(missing_ok=True)
    return target, evidence_sha256


def run_candidate_development_ocr_evaluation(
    *,
    package: LockedSetReviewPackage,
    authority: LockedSetReviewAuthoritySnapshot,
    review_export: CandidateReviewFormalExport,
    backend: AsyncOcrExecutionBackend,
    data_root: Path,
    reviewer_id: str,
    application_build_sha256: str,
    timeout_seconds: float,
) -> CandidateDevelopmentOcrEvaluation:
    """Copy reviewed candidates and record development-only raw OCR evidence."""

    resolved_data_root = _resolved_directory(
        data_root,
        label="development data root",
    )
    if not _is_sha256(application_build_sha256):
        raise CandidateDevelopmentOcrError("application build fingerprint is invalid")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise CandidateDevelopmentOcrError("OCR timeout is invalid")
    _validate_backend(
        backend,
        data_root=resolved_data_root,
    )
    _validate_source_bindings(
        package=package,
        authority=authority,
        review_export=review_export,
        reviewer_id=reviewer_id,
        data_root=resolved_data_root,
    )
    _verify_all_source_images(package)

    protected_root = (
        resolved_data_root / "development" / CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME
    )
    copied_images = _copy_images(
        package=package,
        data_root=resolved_data_root,
        protected_root=protected_root,
    )
    factory_authority = backend.formal_authority
    assert factory_authority is not None
    pipeline_contract_sha256 = _canonical_sha256(
        {
            "application_build_sha256": application_build_sha256,
            "evaluator_version": EVALUATOR_VERSION,
            "ocr_composition_evidence_sha256": (factory_authority.composition_evidence_sha256),
            "ocr_protocol_version": 1,
            "purpose": "candidate_review_development_ocr",
            "runtime_set_sha256": factory_authority.runtime_set_sha256,
        }
    )
    pipeline_fingerprints = {
        runtime_kind: backend.pipeline_fingerprint_for(
            runtime_kind,
            pipeline_contract_fingerprint=(pipeline_contract_sha256),
        )
        for runtime_kind in _RUNTIME_KINDS
    }

    all_attempts: list[dict[str, object]] = []
    comparisons: list[dict[str, object]] = []
    for image in copied_images:
        attempts, timed_out = _execute_image(
            backend=backend,
            image=image,
            pipeline_fingerprints=pipeline_fingerprints,
            timeout_seconds=float(timeout_seconds),
        )
        all_attempts.extend(attempts)
        comparisons.append(_comparison(image.image_sha256, attempts))
        if timed_out:
            break

    attempt_tuple = tuple(all_attempts)
    technical_failures = tuple(
        attempt for attempt in attempt_tuple if attempt["status"] == "failed"
    )
    runtime_differences = tuple(
        comparison for comparison in comparisons if comparison["comparison_status"] == "different"
    )
    status = (
        "failed"
        if technical_failures
        else "completed_with_runtime_differences"
        if runtime_differences
        else "completed"
    )
    copied_payload = [image.to_payload() for image in copied_images]
    evidence_payload: dict[str, object] = {
        "application_build_sha256": application_build_sha256,
        "copied_image_set_sha256": _canonical_sha256(copied_payload),
        "copied_images": copied_payload,
        "development_only": True,
        "evaluator_version": EVALUATOR_VERSION,
        "factory_qualification": {
            "composition_evidence_sha256": (factory_authority.composition_evidence_sha256),
            "runtime_identities": [
                {
                    "profile_id": identity.profile_id,
                    "runtime_fingerprint": (identity.runtime_fingerprint),
                    "runtime_kind": identity.runtime_kind,
                }
                for identity in factory_authority.runtime_identities
            ],
            "runtime_set_sha256": (factory_authority.runtime_set_sha256),
        },
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "generated_at": datetime.now(UTC).isoformat(),
        "kind": "candidate_review_development_ocr_evidence",
        "pipeline_contract_sha256": (pipeline_contract_sha256),
        "reviewer_id": reviewer_id,
        "runtime_attempts": all_attempts,
        "runtime_comparisons": comparisons,
        "schema_version": 1,
        "source": {
            "manifest_payload": review_export.manifest_payload,
            "manifest_sha256": review_export.manifest_sha256,
            "package_id": package.package_id,
            "package_sha256": package.canonical_sha256,
            "quality_coverage_payload": (review_export.quality_coverage_payload),
            "quality_coverage_sha256": (review_export.quality_coverage_sha256),
            "record_set_sha256": (review_export.record_set_sha256),
            "review_history_authority_payload": authority.payload,
            "review_history_authority_sha256": (authority.canonical_sha256),
            "source_authority_payload": (review_export.source_authority_payload),
            "source_authority_sha256": (review_export.source_authority_sha256),
        },
        "status": status,
        "technical_failure_count": len(technical_failures),
    }
    evidence_path, evidence_sha256 = _write_protected_evidence(
        protected_root,
        evidence_payload,
    )

    failure_evidence = [
        {
            "diagnostic_code": failure["diagnostic_code"],
            "error_kind": failure["error_kind"],
            "image_sha256": failure["image_sha256"],
            "runtime_kind": failure["runtime_kind"],
        }
        for failure in technical_failures
    ]
    difference_evidence = [
        {
            "difference_sections": comparison["difference_sections"],
            "image_sha256": comparison["image_sha256"],
            "runtime_output_sha256s": comparison["runtime_output_sha256s"],
        }
        for comparison in runtime_differences
    ]
    summary_payload: dict[str, object] = {
        "composition_evidence_sha256": (factory_authority.composition_evidence_sha256),
        "development_only": True,
        "evidence_sha256": evidence_sha256,
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "image_count": len(copied_images),
        "image_set_sha256": _canonical_sha256(
            [
                {
                    "byte_size": image.byte_size,
                    "image_sha256": image.image_sha256,
                }
                for image in copied_images
            ]
        ),
        "kind": "candidate_review_development_ocr_summary",
        "latency": _latency_summary(attempt_tuple),
        "label_authority_sha256": (review_export.source_authority_sha256),
        "package_sha256": package.canonical_sha256,
        "review_history_authority_sha256": (authority.canonical_sha256),
        "runtime_comparison_count": len(comparisons),
        "runtime_difference_count": len(runtime_differences),
        "runtime_difference_evidence_sha256": (_canonical_sha256(difference_evidence)),
        "runtime_execution_count": len(attempt_tuple),
        "runtime_set_sha256": (factory_authority.runtime_set_sha256),
        "schema_version": 1,
        "status": status,
        "successful_execution_count": (len(attempt_tuple) - len(technical_failures)),
        "technical_failure_count": len(technical_failures),
        "technical_failure_evidence_sha256": (_canonical_sha256(failure_evidence)),
    }
    return CandidateDevelopmentOcrEvaluation(
        status=status,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
        summary_payload=summary_payload,
        technical_failure_count=len(technical_failures),
        runtime_difference_count=len(runtime_differences),
    )
