from __future__ import annotations

import hashlib
import json
import math
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import cast

from pydantic import ValidationError

from dahe.adapters.ocr.fingerprints import build_ocr_output_fingerprint
from dahe.adapters.ocr.protocol import OcrResult
from dahe.adapters.ocr.template_role_input import (
    OcrRoleInputError,
    template_role_input_from_ocr_v1,
)
from dahe.application.template_studio.candidate_development_ocr import (
    CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME,
)
from dahe.application.template_studio.candidate_development_ocr import (
    EVALUATOR_VERSION as OCR_EVALUATOR_VERSION,
)
from dahe.application.template_studio.candidate_role_source_authority import (
    _SHA256_PATTERN,
    CandidateRoleEvaluationError,
    _canonical_sha256,
    _mapping,
    _objects,
    _positive_count,
    _required_text,
    _sha256,
    _TruthImage,
    _TruthPair,
    _validate_source,
)
from dahe.application.template_studio.matcher import TemplateRoleInput
from dahe.jobs.ocr_execution import qualified_runtime_set_sha256

_RUNTIME_KINDS = ("cpu", "gpu")
_SUPPORTED_MEDIA_TYPES = frozenset(
    {
        "image/bmp",
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/webp",
    }
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "application_build_sha256",
        "copied_image_set_sha256",
        "copied_images",
        "development_only",
        "evaluator_version",
        "evidence_sha256",
        "factory_qualification",
        "formal_accuracy_claim",
        "formal_release_eligible",
        "generated_at",
        "kind",
        "pipeline_contract_sha256",
        "reviewer_id",
        "runtime_attempts",
        "runtime_comparisons",
        "schema_version",
        "source",
        "status",
        "technical_failure_count",
    }
)
_COPIED_IMAGE_FIELDS = frozenset(
    {
        "byte_size",
        "image_sha256",
        "media_type",
        "relative_path",
    }
)
_SUCCESSFUL_ATTEMPT_FIELDS = frozenset(
    {
        "business_output_sha256",
        "fields",
        "image_sha256",
        "output_fingerprint",
        "pipeline_fingerprint",
        "profile_id",
        "raw_output_sha256",
        "role_input",
        "role_observation",
        "runtime_fingerprint",
        "runtime_kind",
        "status",
        "wall_elapsed_ms",
        "worker_elapsed_ms",
    }
)
_FAILED_ATTEMPT_FIELDS = frozenset(
    {
        "diagnostic_code",
        "error_kind",
        "image_sha256",
        "pipeline_fingerprint",
        "profile_id",
        "runtime_fingerprint",
        "runtime_kind",
        "status",
        "wall_elapsed_ms",
    }
)
_COMPARISON_FIELDS = frozenset(
    {
        "comparison_status",
        "difference_sections",
        "image_sha256",
        "runtime_output_sha256s",
    }
)
_MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
_MAX_LATENCY_MS = 300_000


@dataclass(frozen=True, slots=True)
class _CopiedImage:
    image_sha256: str
    relative_path: str
    byte_size: int
    media_type: str


@dataclass(frozen=True, slots=True)
class _Attempt:
    image_sha256: str
    runtime_kind: str
    role_input: TemplateRoleInput
    worker_elapsed_ms: Decimal
    wall_elapsed_ms: Decimal


@dataclass(frozen=True, slots=True)
class _ValidatedEvidence:
    evidence_sha256: str
    source: dict[str, object]
    truth_images: tuple[_TruthImage, ...]
    truth_pairs: tuple[_TruthPair, ...]
    copied_images: tuple[_CopiedImage, ...]
    attempts: dict[tuple[str, str], _Attempt]
    application_build_sha256: str
    pipeline_contract_sha256: str
    runtime_set_sha256: str
    composition_evidence_sha256: str


def _nonnegative_decimal(
    value: object,
    *,
    label: str,
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CandidateRoleEvaluationError(f"{label} is invalid")
    if isinstance(value, int):
        if value < 0 or value > _MAX_LATENCY_MS:
            raise CandidateRoleEvaluationError(f"{label} is invalid")
        return Decimal(value)
    if not math.isfinite(value) or value < 0 or value > _MAX_LATENCY_MS:
        raise CandidateRoleEvaluationError(f"{label} is invalid")
    return Decimal(str(value))


def _validate_copied_images(
    value: object,
    *,
    expected_images: set[str],
    expected_metadata: Mapping[str, tuple[int, str]],
    declared_sha256: object,
) -> tuple[_CopiedImage, ...]:
    images = _objects(
        value,
        label="copied development images",
    )
    if len(images) != 100 or _sha256(
        declared_sha256,
        label="copied image set SHA-256",
    ) != _canonical_sha256(images):
        raise CandidateRoleEvaluationError("copied development image authority is invalid")
    copied: list[_CopiedImage] = []
    for image in images:
        if set(image) != _COPIED_IMAGE_FIELDS:
            raise CandidateRoleEvaluationError("copied development image contract is invalid")
        identity = _sha256(
            image.get("image_sha256"),
            label="copied development image identity",
        )
        byte_size = _positive_count(
            image.get("byte_size"),
            label="copied development image byte size",
        )
        media_type = _required_text(
            image.get("media_type"),
            label="copied development image media type",
            maximum=100,
        )
        if media_type not in _SUPPORTED_MEDIA_TYPES or expected_metadata.get(identity) != (
            byte_size,
            media_type,
        ):
            raise CandidateRoleEvaluationError(
                "copied development image metadata does not reconcile"
            )
        relative_path = _required_text(
            image.get("relative_path"),
            label="copied development image path",
            maximum=500,
        )
        path = PurePosixPath(relative_path)
        expected_suffix = PurePosixPath(
            "development",
            CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME,
            "evidence",
            "sha256",
            identity[:2],
            identity[2:4],
            f"{identity}.blob",
        )
        if path.is_absolute() or ".." in path.parts or path != expected_suffix:
            raise CandidateRoleEvaluationError("copied development image path is invalid")
        copied.append(
            _CopiedImage(
                image_sha256=identity,
                relative_path=relative_path,
                byte_size=byte_size,
                media_type=media_type,
            )
        )
    identities = [image.image_sha256 for image in copied]
    if (
        identities != sorted(identities)
        or len(set(identities)) != 100
        or set(identities) != expected_images
        or set(expected_metadata) != expected_images
    ):
        raise CandidateRoleEvaluationError("copied development image membership is invalid")
    return tuple(copied)


def _runtime_authority(
    value: object,
) -> tuple[str, str, dict[str, tuple[str, str]]]:
    factory = _mapping(
        value,
        label="OCR factory qualification",
    )
    if set(factory) != {
        "composition_evidence_sha256",
        "runtime_identities",
        "runtime_set_sha256",
    }:
        raise CandidateRoleEvaluationError("OCR factory qualification is invalid")
    composition = _sha256(
        factory["composition_evidence_sha256"],
        label="OCR composition evidence SHA-256",
    )
    runtime_set = _sha256(
        factory["runtime_set_sha256"],
        label="OCR runtime-set SHA-256",
    )
    identities = _objects(
        factory["runtime_identities"],
        label="OCR runtime identities",
    )
    by_runtime: dict[str, tuple[str, str]] = {}
    for identity in identities:
        if set(identity) != {
            "profile_id",
            "runtime_fingerprint",
            "runtime_kind",
        }:
            raise CandidateRoleEvaluationError("OCR runtime identity is invalid")
        runtime_kind = _required_text(
            identity["runtime_kind"],
            label="OCR runtime kind",
            maximum=10,
        )
        if runtime_kind not in _RUNTIME_KINDS or runtime_kind in by_runtime:
            raise CandidateRoleEvaluationError("OCR runtime identity set is invalid")
        by_runtime[runtime_kind] = (
            _required_text(
                identity["profile_id"],
                label="OCR profile ID",
                maximum=128,
            ),
            _sha256(
                identity["runtime_fingerprint"],
                label="OCR runtime fingerprint",
            ),
        )
    if set(by_runtime) != set(_RUNTIME_KINDS):
        raise CandidateRoleEvaluationError("OCR runtime identity set is incomplete")
    try:
        expected_runtime_set = qualified_runtime_set_sha256(
            tuple(
                {
                    "profile_id": by_runtime[runtime_kind][0],
                    "runtime_fingerprint": by_runtime[runtime_kind][1],
                    "runtime_kind": runtime_kind,
                }
                for runtime_kind in sorted(by_runtime)
            )
        )
    except ValueError as exc:
        raise CandidateRoleEvaluationError("OCR runtime identity set is invalid") from exc
    if runtime_set != expected_runtime_set:
        raise CandidateRoleEvaluationError("OCR runtime-set authority does not reconcile")
    return composition, runtime_set, by_runtime


def _validated_role_input(
    attempt: Mapping[str, object],
    *,
    image_sha256: str,
    runtime_fingerprint: str,
) -> TemplateRoleInput:
    business_output = {
        "fields": attempt.get("fields"),
        "role_observation": attempt.get("role_observation"),
        "text_lines": _mapping(
            attempt.get("role_input"),
            label="OCR role input",
        ).get("text_lines"),
    }
    if _sha256(
        attempt.get("business_output_sha256"),
        label="OCR business output SHA-256",
    ) != _canonical_sha256(business_output):
        raise CandidateRoleEvaluationError("OCR business evidence hash does not reconcile")
    role_input_payload = _mapping(
        attempt.get("role_input"),
        label="OCR role input",
    )
    if set(role_input_payload) != {
        "fixed_text",
        "image_sha256",
        "text_lines",
    }:
        raise CandidateRoleEvaluationError("OCR role input contract is invalid")
    if role_input_payload.get("image_sha256") != image_sha256:
        raise CandidateRoleEvaluationError("OCR role input image identity changed")
    try:
        reconstructed = OcrResult.model_validate(
            {
                "command_id": (f"protected-{attempt['runtime_kind']}-{image_sha256[:16]}"),
                "error": None,
                "elapsed_ms": attempt.get("worker_elapsed_ms"),
                "fields": attempt.get("fields"),
                "protocol_version": 1,
                "role_observation": attempt.get("role_observation"),
                "runtime_fingerprint": runtime_fingerprint,
                "status": "ok",
                "text_lines": role_input_payload.get("text_lines"),
                "verified_image_sha256": image_sha256,
                "worker_identity": ("protected-development-evidence"),
            }
        )
        role_input = template_role_input_from_ocr_v1(reconstructed)
    except (
        OcrRoleInputError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CandidateRoleEvaluationError("OCR role input cannot be reconstructed") from exc
    reconstructed_payload = reconstructed.model_dump(mode="json")
    expected_role_input = {
        "fixed_text": (
            []
            if reconstructed.role_observation is None
            else list(reconstructed.role_observation.fixed_text)
        ),
        "image_sha256": image_sha256,
        "text_lines": reconstructed_payload["text_lines"],
    }
    if dict(role_input_payload) != expected_role_input:
        raise CandidateRoleEvaluationError("OCR role input does not match accepted OCR evidence")
    return role_input


def _validate_attempts(
    value: object,
    *,
    expected_images: set[str],
    runtime_identities: Mapping[str, tuple[str, str]],
    pipeline_contract_sha256: str,
) -> tuple[
    dict[tuple[str, str], _Attempt],
    dict[tuple[str, str], Mapping[str, object]],
]:
    attempts = _objects(
        value,
        label="candidate OCR runtime attempts",
    )
    if len(attempts) != 200:
        raise CandidateRoleEvaluationError("candidate OCR runtime attempt coverage is incomplete")
    parsed: dict[tuple[str, str], _Attempt] = {}
    raw_by_key: dict[
        tuple[str, str],
        Mapping[str, object],
    ] = {}
    pipelines: dict[str, set[str]] = {runtime_kind: set() for runtime_kind in _RUNTIME_KINDS}
    for attempt in attempts:
        if set(attempt) != _SUCCESSFUL_ATTEMPT_FIELDS or attempt.get("status") != "succeeded":
            raise CandidateRoleEvaluationError("candidate OCR contains a technical failure")
        image_sha256 = _sha256(
            attempt.get("image_sha256"),
            label="OCR attempt image identity",
        )
        runtime_kind = _required_text(
            attempt.get("runtime_kind"),
            label="OCR attempt runtime kind",
            maximum=10,
        )
        if image_sha256 not in expected_images or runtime_kind not in runtime_identities:
            raise CandidateRoleEvaluationError(
                "candidate OCR runtime attempt membership is invalid"
            )
        key = (image_sha256, runtime_kind)
        if key in parsed:
            raise CandidateRoleEvaluationError("candidate OCR runtime attempt is duplicated")
        profile_id, runtime_fingerprint = runtime_identities[runtime_kind]
        if (
            attempt.get("profile_id") != profile_id
            or attempt.get("runtime_fingerprint") != runtime_fingerprint
        ):
            raise CandidateRoleEvaluationError("candidate OCR runtime authority changed")
        for field in (
            "business_output_sha256",
            "output_fingerprint",
            "pipeline_fingerprint",
            "raw_output_sha256",
            "runtime_fingerprint",
        ):
            _sha256(
                attempt.get(field),
                label=f"OCR attempt {field}",
            )
        pipeline_fingerprint = cast(
            str,
            attempt["pipeline_fingerprint"],
        )
        expected_pipeline_fingerprint = _canonical_sha256(
            {
                "pipeline_contract_fingerprint": (pipeline_contract_sha256),
                "profile_id": profile_id,
                "runtime_fingerprint": runtime_fingerprint,
                "runtime_kind": runtime_kind,
            }
        )
        if pipeline_fingerprint != expected_pipeline_fingerprint:
            raise CandidateRoleEvaluationError("candidate OCR runtime pipeline authority changed")
        pipelines[runtime_kind].add(pipeline_fingerprint)
        worker_elapsed = _nonnegative_decimal(
            attempt.get("worker_elapsed_ms"),
            label="OCR worker latency",
        )
        wall_elapsed = _nonnegative_decimal(
            attempt.get("wall_elapsed_ms"),
            label="OCR wall latency",
        )
        role_input = _validated_role_input(
            attempt,
            image_sha256=image_sha256,
            runtime_fingerprint=runtime_fingerprint,
        )
        expected_output_fingerprint = build_ocr_output_fingerprint(
            image_sha256=image_sha256,
            fields=attempt.get("fields"),
            role_observation=attempt.get("role_observation"),
            text_lines=_mapping(
                attempt.get("role_input"),
                label="OCR role input",
            ).get("text_lines"),
            verified_image_sha256=image_sha256,
            pipeline_fingerprint=pipeline_fingerprint,
            profile_id=profile_id,
            runtime_fingerprint=runtime_fingerprint,
            runtime_kind=runtime_kind,
        )
        if attempt.get("output_fingerprint") != expected_output_fingerprint:
            raise CandidateRoleEvaluationError(
                "OCR attempt output fingerprint does not reconcile"
            )
        parsed[key] = _Attempt(
            image_sha256=image_sha256,
            runtime_kind=runtime_kind,
            role_input=role_input,
            worker_elapsed_ms=worker_elapsed,
            wall_elapsed_ms=wall_elapsed,
        )
        raw_by_key[key] = attempt
    expected_keys = {
        (image_sha256, runtime_kind)
        for image_sha256 in expected_images
        for runtime_kind in _RUNTIME_KINDS
    }
    if set(parsed) != expected_keys or any(len(values) != 1 for values in pipelines.values()):
        raise CandidateRoleEvaluationError("candidate OCR runtime attempt coverage is incomplete")
    return parsed, raw_by_key


def _validate_comparisons(
    value: object,
    *,
    expected_images: set[str],
    raw_attempts: Mapping[
        tuple[str, str],
        Mapping[str, object],
    ],
) -> int:
    comparisons = _objects(
        value,
        label="candidate OCR runtime comparisons",
    )
    if len(comparisons) != 100:
        raise CandidateRoleEvaluationError(
            "candidate OCR runtime comparison coverage is incomplete"
        )
    seen: set[str] = set()
    difference_count = 0
    for comparison in comparisons:
        if set(comparison) != _COMPARISON_FIELDS:
            raise CandidateRoleEvaluationError("candidate OCR runtime comparison is invalid")
        image_sha256 = _sha256(
            comparison.get("image_sha256"),
            label="OCR comparison image identity",
        )
        if image_sha256 not in expected_images or image_sha256 in seen:
            raise CandidateRoleEvaluationError(
                "candidate OCR runtime comparison membership is invalid"
            )
        seen.add(image_sha256)
        cpu = raw_attempts[(image_sha256, "cpu")]
        gpu = raw_attempts[(image_sha256, "gpu")]
        differences = [
            section
            for section in (
                "fields",
                "role_input",
                "role_observation",
            )
            if cpu[section] != gpu[section]
        ]
        expected_status = "different" if differences else "same"
        expected_hashes = {
            runtime_kind: raw_attempts[(image_sha256, runtime_kind)]["business_output_sha256"]
            for runtime_kind in _RUNTIME_KINDS
        }
        if (
            comparison.get("comparison_status") != expected_status
            or comparison.get("difference_sections") != differences
            or comparison.get("runtime_output_sha256s") != expected_hashes
        ):
            raise CandidateRoleEvaluationError(
                "candidate OCR runtime comparison does not reconcile"
            )
        difference_count += bool(differences)
    if seen != expected_images:
        raise CandidateRoleEvaluationError(
            "candidate OCR runtime comparison coverage is incomplete"
        )
    return difference_count


def _validate_evidence(
    value: Mapping[str, object],
) -> _ValidatedEvidence:
    payload = dict(value)
    if set(payload) != _TOP_LEVEL_FIELDS:
        raise CandidateRoleEvaluationError("candidate OCR evidence contract is invalid")
    declared_evidence_sha256 = _sha256(
        payload.get("evidence_sha256"),
        label="candidate OCR evidence SHA-256",
    )
    without_hash = dict(payload)
    without_hash.pop("evidence_sha256")
    if _canonical_sha256(without_hash) != declared_evidence_sha256:
        raise CandidateRoleEvaluationError("candidate OCR evidence self-hash does not match")
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("kind") != "candidate_review_development_ocr_evidence"
        or payload.get("development_only") is not True
        or payload.get("formal_release_eligible") is not False
        or payload.get("formal_accuracy_claim") is not False
        or payload.get("evaluator_version") != OCR_EVALUATOR_VERSION
        or type(payload.get("technical_failure_count")) is not int
        or payload.get("technical_failure_count") != 0
        or payload.get("status")
        not in {
            "completed",
            "completed_with_runtime_differences",
        }
    ):
        raise CandidateRoleEvaluationError(
            "candidate OCR evidence is not a complete development-only run"
        )
    application_build_sha256 = _sha256(
        payload.get("application_build_sha256"),
        label="candidate application build SHA-256",
    )
    pipeline_contract_sha256 = _sha256(
        payload.get("pipeline_contract_sha256"),
        label="candidate OCR pipeline contract SHA-256",
    )
    source, truth_images, truth_pairs = _validate_source(payload.get("source"))
    source_authority = _mapping(
        source["source_authority_payload"],
        label="candidate source authority",
    )
    configured_reviewer = source_authority.get("configured_reviewer_id")
    if payload.get("reviewer_id") != configured_reviewer:
        raise CandidateRoleEvaluationError("candidate OCR reviewer authority changed")
    expected_images = {image.image_sha256 for image in truth_images}
    expected_metadata: dict[str, tuple[int, str]] = {}
    for image in _objects(
        source_authority.get("verified_images"),
        label="candidate verified image authority",
    ):
        identity = _sha256(
            image.get("image_sha256"),
            label="candidate verified image identity",
        )
        if identity in expected_metadata:
            raise CandidateRoleEvaluationError("candidate verified image authority is duplicated")
        expected_metadata[identity] = (
            _positive_count(
                image.get("byte_count"),
                label="candidate verified image byte count",
            ),
            _required_text(
                image.get("media_type"),
                label="candidate verified image media type",
                maximum=100,
            ),
        )
    copied_images = _validate_copied_images(
        payload.get("copied_images"),
        expected_images=expected_images,
        expected_metadata=expected_metadata,
        declared_sha256=payload.get("copied_image_set_sha256"),
    )
    (
        composition_evidence_sha256,
        runtime_set_sha256,
        runtime_identities,
    ) = _runtime_authority(payload.get("factory_qualification"))
    expected_pipeline_contract = _canonical_sha256(
        {
            "application_build_sha256": (application_build_sha256),
            "evaluator_version": OCR_EVALUATOR_VERSION,
            "ocr_composition_evidence_sha256": (composition_evidence_sha256),
            "ocr_protocol_version": 1,
            "purpose": "candidate_review_development_ocr",
            "runtime_set_sha256": runtime_set_sha256,
        }
    )
    if pipeline_contract_sha256 != expected_pipeline_contract:
        raise CandidateRoleEvaluationError("candidate OCR pipeline authority does not reconcile")
    attempts, raw_attempts = _validate_attempts(
        payload.get("runtime_attempts"),
        expected_images=expected_images,
        runtime_identities=runtime_identities,
        pipeline_contract_sha256=pipeline_contract_sha256,
    )
    difference_count = _validate_comparisons(
        payload.get("runtime_comparisons"),
        expected_images=expected_images,
        raw_attempts=raw_attempts,
    )
    expected_status = "completed_with_runtime_differences" if difference_count else "completed"
    if payload.get("status") != expected_status:
        raise CandidateRoleEvaluationError("candidate OCR completion status does not reconcile")
    return _ValidatedEvidence(
        evidence_sha256=declared_evidence_sha256,
        source=source,
        truth_images=truth_images,
        truth_pairs=truth_pairs,
        copied_images=copied_images,
        attempts=attempts,
        application_build_sha256=application_build_sha256,
        pipeline_contract_sha256=pipeline_contract_sha256,
        runtime_set_sha256=runtime_set_sha256,
        composition_evidence_sha256=(composition_evidence_sha256),
    )


def validate_failed_candidate_development_ocr_evidence(
    value: Mapping[str, object],
    *,
    data_root: Path,
) -> None:
    """Validate the immutable scope and actual failure of a terminal run."""

    payload = dict(value)
    if set(payload) != _TOP_LEVEL_FIELDS:
        raise CandidateRoleEvaluationError(
            "failed candidate OCR evidence contract is invalid"
        )
    declared_evidence_sha256 = _sha256(
        payload.get("evidence_sha256"),
        label="failed candidate OCR evidence SHA-256",
    )
    without_hash = dict(payload)
    without_hash.pop("evidence_sha256")
    if _canonical_sha256(without_hash) != declared_evidence_sha256:
        raise CandidateRoleEvaluationError(
            "failed candidate OCR evidence self-hash does not match"
        )
    technical_failure_count = _positive_count(
        payload.get("technical_failure_count"),
        label="failed candidate OCR technical failure count",
    )
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or payload.get("kind")
        != "candidate_review_development_ocr_evidence"
        or payload.get("development_only") is not True
        or payload.get("formal_release_eligible") is not False
        or payload.get("formal_accuracy_claim") is not False
        or payload.get("evaluator_version") != OCR_EVALUATOR_VERSION
        or payload.get("status") != "failed"
    ):
        raise CandidateRoleEvaluationError(
            "candidate OCR evidence is not a terminal technical failure"
        )
    application_build_sha256 = _sha256(
        payload.get("application_build_sha256"),
        label="failed candidate application build SHA-256",
    )
    pipeline_contract_sha256 = _sha256(
        payload.get("pipeline_contract_sha256"),
        label="failed candidate OCR pipeline contract SHA-256",
    )
    source, truth_images, _truth_pairs = _validate_source(
        payload.get("source")
    )
    source_authority = _mapping(
        source["source_authority_payload"],
        label="failed candidate source authority",
    )
    if payload.get("reviewer_id") != source_authority.get(
        "configured_reviewer_id"
    ):
        raise CandidateRoleEvaluationError(
            "failed candidate OCR reviewer authority changed"
        )
    expected_images = {image.image_sha256 for image in truth_images}
    expected_metadata: dict[str, tuple[int, str]] = {}
    for image in _objects(
        source_authority.get("verified_images"),
        label="failed candidate verified image authority",
    ):
        identity = _sha256(
            image.get("image_sha256"),
            label="failed candidate verified image identity",
        )
        if identity in expected_metadata:
            raise CandidateRoleEvaluationError(
                "failed candidate verified image authority is duplicated"
            )
        expected_metadata[identity] = (
            _positive_count(
                image.get("byte_count"),
                label="failed candidate verified image byte count",
            ),
            _required_text(
                image.get("media_type"),
                label="failed candidate verified image media type",
                maximum=100,
            ),
        )
    copied_images = _validate_copied_images(
        payload.get("copied_images"),
        expected_images=expected_images,
        expected_metadata=expected_metadata,
        declared_sha256=payload.get("copied_image_set_sha256"),
    )
    composition_sha256, runtime_set_sha256, runtime_identities = (
        _runtime_authority(payload.get("factory_qualification"))
    )
    expected_pipeline_contract = _canonical_sha256(
        {
            "application_build_sha256": application_build_sha256,
            "evaluator_version": OCR_EVALUATOR_VERSION,
            "ocr_composition_evidence_sha256": composition_sha256,
            "ocr_protocol_version": 1,
            "purpose": "candidate_review_development_ocr",
            "runtime_set_sha256": runtime_set_sha256,
        }
    )
    if pipeline_contract_sha256 != expected_pipeline_contract:
        raise CandidateRoleEvaluationError(
            "failed candidate OCR pipeline authority does not reconcile"
        )
    attempts = _objects(
        payload.get("runtime_attempts"),
        label="failed candidate OCR runtime attempts",
    )
    if not attempts or len(attempts) > 200:
        raise CandidateRoleEvaluationError(
            "failed candidate OCR attempt coverage is invalid"
        )
    seen: set[tuple[str, str]] = set()
    observed_failure_count = 0
    for attempt in attempts:
        status = attempt.get("status")
        expected_fields = (
            _FAILED_ATTEMPT_FIELDS
            if status == "failed"
            else _SUCCESSFUL_ATTEMPT_FIELDS
        )
        if status not in {"failed", "succeeded"} or set(attempt) != expected_fields:
            raise CandidateRoleEvaluationError(
                "failed candidate OCR attempt contract is invalid"
            )
        image_sha256 = _sha256(
            attempt.get("image_sha256"),
            label="failed OCR attempt image identity",
        )
        runtime_kind = _required_text(
            attempt.get("runtime_kind"),
            label="failed OCR attempt runtime kind",
            maximum=10,
        )
        if (
            image_sha256 not in expected_images
            or runtime_kind not in runtime_identities
            or (image_sha256, runtime_kind) in seen
        ):
            raise CandidateRoleEvaluationError(
                "failed candidate OCR attempt membership is invalid"
            )
        seen.add((image_sha256, runtime_kind))
        profile_id, runtime_fingerprint = runtime_identities[runtime_kind]
        expected_pipeline_fingerprint = _canonical_sha256(
            {
                "pipeline_contract_fingerprint": (
                    pipeline_contract_sha256
                ),
                "profile_id": profile_id,
                "runtime_fingerprint": runtime_fingerprint,
                "runtime_kind": runtime_kind,
            }
        )
        if (
            attempt.get("profile_id") != profile_id
            or attempt.get("runtime_fingerprint")
            != runtime_fingerprint
            or attempt.get("pipeline_fingerprint")
            != expected_pipeline_fingerprint
        ):
            raise CandidateRoleEvaluationError(
                "failed candidate OCR runtime authority changed"
            )
        observed_failure_count += status == "failed"
    if observed_failure_count != technical_failure_count:
        raise CandidateRoleEvaluationError(
            "failed candidate OCR technical failure count does not reconcile"
        )
    _validate_protected_image_blobs(
        copied_images,
        data_root=data_root,
    )


def _is_path_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _assert_no_path_links(path: Path) -> None:
    candidates: list[Path] = []
    current = path
    while True:
        candidates.append(current)
        if current.parent == current:
            break
        current = current.parent
    if any(_is_path_link(candidate) for candidate in reversed(candidates)):
        raise CandidateRoleEvaluationError("protected OCR evidence path contains a link")


def _same_or_descendant(
    path: Path,
    root: Path,
) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _protected_image_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(
                lambda: source.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)
    except OSError as exc:
        raise CandidateRoleEvaluationError("protected development image is unavailable") from exc
    return digest.hexdigest()


def _validate_protected_image_blobs(
    copied_images: Sequence[_CopiedImage],
    *,
    data_root: Path,
) -> None:
    evidence_root = (
        data_root
        / "development"
        / CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME
        / "evidence"
        / "sha256"
    )
    for image in copied_images:
        relative_path = PurePosixPath(image.relative_path)
        candidate = data_root.joinpath(*relative_path.parts)
        _assert_no_path_links(candidate)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise CandidateRoleEvaluationError(
                "protected development image is unavailable"
            ) from exc
        if (
            resolved != candidate
            or not resolved.is_file()
            or not _same_or_descendant(
                resolved,
                evidence_root,
            )
            or resolved.parent != evidence_root / image.image_sha256[:2] / image.image_sha256[2:4]
            or resolved.name != f"{image.image_sha256}.blob"
        ):
            raise CandidateRoleEvaluationError("protected development image path is invalid")
        try:
            byte_size = resolved.stat().st_size
        except OSError as exc:
            raise CandidateRoleEvaluationError(
                "protected development image is unavailable"
            ) from exc
        if byte_size != image.byte_size or _protected_image_sha256(resolved) != image.image_sha256:
            raise CandidateRoleEvaluationError(
                "protected development image evidence does not reconcile"
            )


def load_protected_candidate_development_ocr_evidence(
    path: Path,
    *,
    data_root: Path,
) -> dict[str, object]:
    """Load one immutable, content-addressed protected OCR record."""

    if not path.is_absolute() or not data_root.is_absolute():
        raise CandidateRoleEvaluationError("protected OCR evidence paths must be absolute")
    _assert_no_path_links(data_root)
    _assert_no_path_links(path)
    try:
        resolved_root = data_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateRoleEvaluationError("protected OCR evidence is unavailable") from exc
    protected_root = (
        resolved_root
        / "development"
        / CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME
        / "records"
        / "sha256"
    )
    if (
        resolved_root != data_root
        or resolved_path != path
        or not resolved_path.is_file()
        or not _same_or_descendant(
            resolved_path,
            protected_root,
        )
    ):
        raise CandidateRoleEvaluationError("OCR evidence is not a protected development record")
    filename_sha256 = resolved_path.stem
    if (
        resolved_path.suffix.lower() != ".json"
        or _SHA256_PATTERN.fullmatch(filename_sha256) is None
        or resolved_path.parent != protected_root / filename_sha256[:2] / filename_sha256[2:4]
    ):
        raise CandidateRoleEvaluationError("protected OCR evidence path is not content-addressed")
    try:
        if resolved_path.stat().st_size > _MAX_EVIDENCE_BYTES:
            raise CandidateRoleEvaluationError("protected OCR evidence exceeds the size limit")
        decoded = json.loads(resolved_path.read_text(encoding="utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise CandidateRoleEvaluationError("protected OCR evidence is unreadable") from exc
    if not isinstance(decoded, dict):
        raise CandidateRoleEvaluationError("protected OCR evidence must be an object")
    payload = cast(dict[str, object], decoded)
    if payload.get("evidence_sha256") != filename_sha256:
        raise CandidateRoleEvaluationError("protected OCR evidence filename identity changed")
    validated = _validate_evidence(payload)
    _validate_protected_image_blobs(
        validated.copied_images,
        data_root=resolved_root,
    )
    return payload
