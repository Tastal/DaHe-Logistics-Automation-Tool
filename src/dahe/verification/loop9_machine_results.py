from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal, Protocol, cast
from uuid import uuid4

from pydantic import ValidationError

from dahe.adapters.ocr.locked_set_evaluator import EVALUATOR_VERSION
from dahe.adapters.ocr.protocol import OcrResult, OcrResultStatus
from dahe.adapters.ocr.template_role_input import (
    ordinary_net_review_reason_from_ocr_v1,
    template_role_input_from_ocr_v1,
)
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
    ShadowBatchItem,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionContractError,
    FormalShadowSelectionManifest,
)
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
)
from dahe.application.template_studio.matcher import (
    MATCHER_VERSION,
    build_template_set_fingerprint,
    match_ticket_role,
)
from dahe.domain.audit.decisions import evaluate_audit
from dahe.domain.audit.errors import SystemEvidenceError
from dahe.domain.audit.evidence import (
    AuditEvidence,
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightEvidenceIssue,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.domain.audit.weights import (
    WeightComparisonPolicy,
    WeightReading,
    WeightUnit,
)
from dahe.domain.ticket.role_assessment import RoleAssessmentPolicy
from dahe.domain.ticket.templates import TemplateLifecycle, TemplateVersion
from dahe.jobs.ocr_execution import OcrRuntimeIdentity
from dahe.verification.application_build import ApplicationBuildManifest
from dahe.verification.locked_set_acceptance import (
    LOCAL_OCR_RUNTIME_SOURCE,
)
from dahe.verification.locked_set_runner import (
    IndependentLockedImage,
    LockedOcrRuntimeComparison,
    LockedOcrRuntimeOutput,
    LockedRolePrediction,
    LockedSetRunContext,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_KINDS = {"cpu", "gpu"}
_FORMAL_RUNTIME_KINDS = ("cpu", "gpu")
_WEIGHT_DIFFERENCE_FIELDS = frozenset(
    {
        "ordinary_net_amount",
        "ordinary_net_unit",
        "ordinary_net_reliable",
        "safety_route",
        "weight_review_reason",
    }
)
_WEIGHT_POLICY = WeightComparisonPolicy(
    decimal_places=2,
    rule_version="loop9-exact-weight-v1",
)


class Loop9MachineResultError(ValueError):
    """Raised when formal machine evidence is incomplete or changed."""


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise Loop9MachineResultError("machine-result evidence is not canonical JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9MachineResultError(f"{label} must be a lowercase SHA-256")
    return value


def _required_text(
    value: str,
    *,
    label: str,
    maximum: int = 200,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise Loop9MachineResultError(f"{label} is invalid")
    return value


def _decimal_text(value: Decimal | None) -> str | None:
    if value is None:
        return None
    normalized = value.normalize()
    return "0" if normalized == 0 else format(normalized, "f")


def _elapsed(value: Decimal, *, label: str) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise Loop9MachineResultError(f"{label} must be a non-negative decimal")
    return value


@dataclass(frozen=True, slots=True)
class SafeOcrObservation:
    """Bounded OCR evidence that deliberately excludes full recognized text."""

    image_sha256: str
    runtime_kind: Literal["cpu", "gpu"]
    profile_id: str
    runtime_fingerprint: str
    pipeline_fingerprint: str
    output_fingerprint: str
    worker_elapsed_ms: Decimal
    wall_elapsed_ms: Decimal
    ordinary_net_amount: Decimal | None
    ordinary_net_unit: str | None
    ordinary_net_confidence: Decimal | None
    ordinary_net_reliable: bool
    weight_review_reason: str | None
    predicted_role: str
    role_quality: str
    role_confidence: Decimal
    role_high_confidence: bool
    role_assessment_sha256: str
    role_elapsed_ms: Decimal
    orientation_degrees: int
    matched_orientation_degrees: int
    template_set_sha256: str
    template_version_ids: tuple[str, ...]
    template_versions_sha256: str
    observation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for fingerprint_value, fingerprint_label in (
            (self.image_sha256, "image identity"),
            (self.runtime_fingerprint, "runtime fingerprint"),
            (self.pipeline_fingerprint, "pipeline fingerprint"),
            (self.output_fingerprint, "output fingerprint"),
            (self.role_assessment_sha256, "role assessment"),
            (self.template_set_sha256, "template set"),
            (self.template_versions_sha256, "template-version set"),
        ):
            _required_sha256(
                fingerprint_value,
                label=fingerprint_label,
            )
        if self.runtime_kind not in _RUNTIME_KINDS:
            raise Loop9MachineResultError("runtime kind is invalid")
        _required_text(self.profile_id, label="runtime profile")
        _elapsed(self.worker_elapsed_ms, label="worker elapsed time")
        _elapsed(self.wall_elapsed_ms, label="wall elapsed time")
        _elapsed(self.role_elapsed_ms, label="role elapsed time")
        if (
            not isinstance(self.ordinary_net_reliable, bool)
            or not isinstance(self.role_high_confidence, bool)
            or self.orientation_degrees not in {0, 90, 180, 270}
            or self.matched_orientation_degrees not in {0, 90, 180, 270}
        ):
            raise Loop9MachineResultError("OCR observation flags are invalid")
        for confidence_value, confidence_label in (
            (self.ordinary_net_confidence, "ordinary-net confidence"),
            (self.role_confidence, "role confidence"),
        ):
            if confidence_value is not None and (
                not isinstance(confidence_value, Decimal)
                or not confidence_value.is_finite()
                or not Decimal(0) <= confidence_value <= Decimal(1)
            ):
                raise Loop9MachineResultError(f"{confidence_label} is invalid")
        if self.ordinary_net_amount is not None and (
            not isinstance(self.ordinary_net_amount, Decimal)
            or not self.ordinary_net_amount.is_finite()
            or self.ordinary_net_amount < 0
        ):
            raise Loop9MachineResultError("ordinary-net amount is invalid")
        if not self.template_version_ids or self.template_version_ids != tuple(
            sorted(set(self.template_version_ids))
        ):
            raise Loop9MachineResultError("template version identities must be sorted and unique")
        object.__setattr__(
            self,
            "observation_sha256",
            _canonical_sha256(self._payload_without_hash()),
        )

    def _payload_without_hash(self) -> dict[str, object]:
        return {
            "image_sha256": self.image_sha256,
            "ordinary_net": {
                "amount": _decimal_text(self.ordinary_net_amount),
                "confidence": _decimal_text(self.ordinary_net_confidence),
                "reliable": self.ordinary_net_reliable,
                "review_reason": self.weight_review_reason,
                "unit": self.ordinary_net_unit,
            },
            "output_fingerprint": self.output_fingerprint,
            "pipeline_fingerprint": self.pipeline_fingerprint,
            "profile_id": self.profile_id,
            "role": {
                "assessment_sha256": self.role_assessment_sha256,
                "confidence": _decimal_text(self.role_confidence),
                "elapsed_ms": _decimal_text(self.role_elapsed_ms),
                "high_confidence": self.role_high_confidence,
                "matched_orientation_degrees": (self.matched_orientation_degrees),
                "orientation_degrees": self.orientation_degrees,
                "predicted": self.predicted_role,
                "quality": self.role_quality,
            },
            "runtime_fingerprint": self.runtime_fingerprint,
            "runtime_kind": self.runtime_kind,
            "schema_version": 1,
            "template": {
                "set_sha256": self.template_set_sha256,
                "version_ids": list(self.template_version_ids),
                "versions_sha256": self.template_versions_sha256,
            },
            "timing": {
                "wall_elapsed_ms": _decimal_text(self.wall_elapsed_ms),
                "worker_elapsed_ms": _decimal_text(self.worker_elapsed_ms),
            },
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._payload_without_hash(),
            "observation_sha256": self.observation_sha256,
        }


def _ordinary_net(
    result: OcrResult,
) -> tuple[Decimal | None, str | None, Decimal | None]:
    field = result.fields.get("ordinary_net")
    if field is None:
        return None, None, None
    amount: Decimal | None = None
    if field.amount is not None:
        try:
            parsed = Decimal(field.amount)
        except InvalidOperation:
            parsed = None
        if parsed is not None and parsed.is_finite() and parsed >= 0:
            amount = parsed
    unit = None if field.unit is None else field.unit.strip().lower()
    return amount, unit, field.confidence


def project_safe_ocr_observation(
    *,
    output_json: str,
    expected_image_sha256: str,
    expected_runtime_fingerprint: str,
    runtime_kind: Literal["cpu", "gpu"],
    profile_id: str,
    pipeline_fingerprint: str,
    output_fingerprint: str,
    templates: tuple[TemplateVersion, ...],
    role_policy: RoleAssessmentPolicy,
    wall_elapsed_ms: Decimal,
) -> SafeOcrObservation:
    """Project one accepted OCR protocol result without exporting text lines."""

    for value, label in (
        (expected_image_sha256, "expected image identity"),
        (expected_runtime_fingerprint, "expected runtime fingerprint"),
        (pipeline_fingerprint, "pipeline fingerprint"),
        (output_fingerprint, "output fingerprint"),
    ):
        _required_sha256(value, label=label)
    if runtime_kind not in _RUNTIME_KINDS:
        raise Loop9MachineResultError("runtime kind is invalid")
    _required_text(profile_id, label="runtime profile")
    _elapsed(wall_elapsed_ms, label="wall elapsed time")
    if (
        not templates
        or any(
            not isinstance(template, TemplateVersion)
            or template.lifecycle is not TemplateLifecycle.SHADOW
            for template in templates
        )
        or not isinstance(role_policy, RoleAssessmentPolicy)
    ):
        raise Loop9MachineResultError("current shadow template authority is invalid")
    try:
        result = OcrResult.model_validate_json(output_json)
    except (ValidationError, ValueError) as exc:
        raise Loop9MachineResultError("OCR output does not match the accepted protocol") from exc
    if (
        result.status is not OcrResultStatus.OK
        or result.verified_image_sha256 != expected_image_sha256
        or result.runtime_fingerprint != expected_runtime_fingerprint
    ):
        raise Loop9MachineResultError("OCR output identity or status is invalid")
    try:
        role_input = template_role_input_from_ocr_v1(result)
        role_run = match_ticket_role(role_input, templates, role_policy)
    except Exception as exc:
        raise Loop9MachineResultError(
            "OCR output could not be projected by the accepted role contract"
        ) from exc
    amount, unit, confidence = _ordinary_net(result)
    template_versions = tuple(
        sorted(
            (
                {
                    "content_sha256": template.content_sha256,
                    "family_id": template.definition.family_id,
                    "role": template.definition.role.value,
                    "version_id": template.version_id,
                    "version_number": template.version_number,
                }
                for template in templates
            ),
            key=lambda value: str(value["version_id"]),
        )
    )
    return SafeOcrObservation(
        image_sha256=expected_image_sha256,
        runtime_kind=runtime_kind,
        profile_id=profile_id,
        runtime_fingerprint=expected_runtime_fingerprint,
        pipeline_fingerprint=pipeline_fingerprint,
        output_fingerprint=output_fingerprint,
        worker_elapsed_ms=Decimal(str(result.elapsed_ms)),
        wall_elapsed_ms=wall_elapsed_ms,
        ordinary_net_amount=amount,
        ordinary_net_unit=unit,
        ordinary_net_confidence=confidence,
        ordinary_net_reliable=role_input.ordinary_net_reliable,
        weight_review_reason=ordinary_net_review_reason_from_ocr_v1(result),
        predicted_role=role_run.assessment.role.value,
        role_quality=role_run.assessment.quality.value,
        role_confidence=role_run.assessment.confidence,
        role_high_confidence=role_run.assessment.high_confidence,
        role_assessment_sha256=role_run.assessment.fingerprint,
        role_elapsed_ms=role_run.elapsed_ms,
        orientation_degrees=(
            0 if result.role_observation is None else result.role_observation.orientation_degrees
        ),
        matched_orientation_degrees=(role_run.observation.orientation_degrees),
        template_set_sha256=build_template_set_fingerprint(templates),
        template_version_ids=tuple(str(value["version_id"]) for value in template_versions),
        template_versions_sha256=_canonical_sha256(template_versions),
    )


@dataclass(frozen=True, slots=True)
class SafeOcrObservationProjector:
    """Injectable projector that never returns full OCR protocol text."""

    templates: tuple[TemplateVersion, ...]
    role_policy: RoleAssessmentPolicy

    def __post_init__(self) -> None:
        if (
            not self.templates
            or any(
                not isinstance(template, TemplateVersion)
                or template.lifecycle is not TemplateLifecycle.SHADOW
                for template in self.templates
            )
            or not isinstance(self.role_policy, RoleAssessmentPolicy)
        ):
            raise Loop9MachineResultError(
                "safe OCR projector requires the current shadow authority"
            )

    def project(
        self,
        *,
        output_json: str,
        expected_image_sha256: str,
        expected_runtime_fingerprint: str,
        runtime_kind: Literal["cpu", "gpu"],
        profile_id: str,
        pipeline_fingerprint: str,
        output_fingerprint: str,
        wall_elapsed_ms: Decimal,
    ) -> SafeOcrObservation:
        return project_safe_ocr_observation(
            output_json=output_json,
            expected_image_sha256=expected_image_sha256,
            expected_runtime_fingerprint=expected_runtime_fingerprint,
            runtime_kind=runtime_kind,
            profile_id=profile_id,
            pipeline_fingerprint=pipeline_fingerprint,
            output_fingerprint=output_fingerprint,
            templates=self.templates,
            role_policy=self.role_policy,
            wall_elapsed_ms=wall_elapsed_ms,
        )


def nearest_rank_percentiles(
    values: Iterable[Decimal],
) -> dict[str, int | str | None]:
    """Summarize elapsed milliseconds with deterministic nearest-rank P50/P95."""

    samples = sorted(_elapsed(value, label="timing sample") for value in values)
    if not samples:
        return {
            "sample_size": 0,
            "p50_ms": None,
            "p95_ms": None,
        }

    def percentile(probability: Decimal) -> Decimal:
        rank = max(1, math.ceil(float(probability * len(samples))))
        return samples[rank - 1]

    return {
        "sample_size": len(samples),
        "p50_ms": _decimal_text(percentile(Decimal("0.50"))),
        "p95_ms": _decimal_text(percentile(Decimal("0.95"))),
    }


@dataclass(frozen=True, slots=True)
class SchedulerStageAttemptProjection:
    stage_attempt_id: str
    stage: str
    status: str
    resource_name: str | None
    attempt_number: int
    started_sequence: int
    finished_sequence: int | None
    diagnostic_code: str | None
    runtime_kind: str | None
    profile_id: str | None
    runtime_fingerprint: str | None
    pipeline_fingerprint: str | None
    input_fingerprint: str | None
    output_fingerprint: str | None
    discarded: bool
    error_kind: str | None

    def to_payload(self) -> dict[str, object]:
        return {
            "attempt_number": self.attempt_number,
            "diagnostic_code": self.diagnostic_code,
            "discarded": self.discarded,
            "error_kind": self.error_kind,
            "finished_sequence": self.finished_sequence,
            "input_fingerprint": self.input_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "pipeline_fingerprint": self.pipeline_fingerprint,
            "profile_id": self.profile_id,
            "resource_name": self.resource_name,
            "runtime_fingerprint": self.runtime_fingerprint,
            "runtime_kind": self.runtime_kind,
            "stage": self.stage,
            "stage_attempt_id": self.stage_attempt_id,
            "started_sequence": self.started_sequence,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class SchedulerGenerationProjection:
    generation_id: str
    pipeline_fingerprint: str
    primary_runtime_kind: str
    next_runtime_kind: str
    status: str
    committed_runtime_kind: str | None
    committed_profile_id: str | None
    committed_runtime_fingerprint: str | None
    loading_output_fingerprint: str | None
    unloading_output_fingerprint: str | None
    diagnostic_code: str | None
    record_version: int

    def to_payload(self) -> dict[str, object]:
        return {
            "committed_profile_id": self.committed_profile_id,
            "committed_runtime_fingerprint": (self.committed_runtime_fingerprint),
            "committed_runtime_kind": self.committed_runtime_kind,
            "diagnostic_code": self.diagnostic_code,
            "generation_id": self.generation_id,
            "loading_output_fingerprint": self.loading_output_fingerprint,
            "next_runtime_kind": self.next_runtime_kind,
            "pipeline_fingerprint": self.pipeline_fingerprint,
            "primary_runtime_kind": self.primary_runtime_kind,
            "record_version": self.record_version,
            "status": self.status,
            "unloading_output_fingerprint": (self.unloading_output_fingerprint),
        }


@dataclass(frozen=True, slots=True)
class SchedulerItemProjection:
    item_identity_sha256: str
    work_item_id: str
    item_index: int
    record_version: int
    status: str
    current_stage: str
    business_outcome: str | None
    decision: str | None
    review_reason: str | None
    diagnostic_code: str | None
    generation: SchedulerGenerationProjection
    stage_attempts: tuple[SchedulerStageAttemptProjection, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "business_outcome": self.business_outcome,
            "current_stage": self.current_stage,
            "decision": self.decision,
            "diagnostic_code": self.diagnostic_code,
            "generation": self.generation.to_payload(),
            "item_identity_sha256": self.item_identity_sha256,
            "item_index": self.item_index,
            "record_version": self.record_version,
            "review_reason": self.review_reason,
            "stage_attempts": [attempt.to_payload() for attempt in self.stage_attempts],
            "status": self.status,
            "work_item_id": self.work_item_id,
        }


@dataclass(frozen=True, slots=True)
class SchedulerBatchProjection:
    job_id: str
    job_record_version: int
    job_status: str
    target_kind: str
    source_batch_sha256: str
    items: tuple[SchedulerItemProjection, ...]
    projection_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_text(self.job_id, label="scheduler job ID")
        _required_sha256(
            self.source_batch_sha256,
            label="scheduler source batch",
        )
        if (
            not isinstance(self.job_record_version, int)
            or isinstance(self.job_record_version, bool)
            or self.job_record_version < 1
            or not self.items
            or tuple(item.item_index for item in self.items) != tuple(range(len(self.items)))
        ):
            raise Loop9MachineResultError("scheduler batch projection is incomplete")
        object.__setattr__(
            self,
            "projection_sha256",
            _canonical_sha256(self._payload_without_hash()),
        )

    def _payload_without_hash(self) -> dict[str, object]:
        return {
            "items": [item.to_payload() for item in self.items],
            "job_id": self.job_id,
            "job_record_version": self.job_record_version,
            "job_status": self.job_status,
            "schema_version": 1,
            "source_batch_sha256": self.source_batch_sha256,
            "target_kind": self.target_kind,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._payload_without_hash(),
            "projection_sha256": self.projection_sha256,
        }


def _optional_text(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _required_text(cast(str, value), label=label)


def _optional_sha256(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _required_sha256(cast(str, value), label=label)


def _required_int(value: object, *, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise Loop9MachineResultError(f"{label} is invalid")
    return value


def _read_only_connection(database: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.Error as exc:
        raise Loop9MachineResultError("scheduler database cannot be opened read-only") from exc


def read_scheduler_batch_projection(
    *,
    data_root: Path,
    batch: ChengfengShadowBatchManifest,
    job_id: str,
) -> SchedulerBatchProjection:
    """Read one sealed scheduler result without exporting OCR protocol data."""

    if not isinstance(data_root, Path) or not data_root.is_absolute():
        raise Loop9MachineResultError("scheduler data root must be absolute")
    try:
        root = data_root.resolve(strict=True)
        database = (root / "database" / "dahe.sqlite3").resolve(strict=True)
        database.relative_to(root)
    except (OSError, ValueError) as exc:
        raise Loop9MachineResultError("scheduler database is unavailable") from exc
    if data_root.is_symlink() or not root.is_dir() or not database.is_file():
        raise Loop9MachineResultError("scheduler data root or database is unsafe")
    if not isinstance(batch, ChengfengShadowBatchManifest):
        raise Loop9MachineResultError("shadow batch is invalid")
    batch.verify_integrity()
    requested_job_id = _required_text(job_id, label="scheduler job ID")
    expected_scope = f"chengfeng-shadow:{batch.target_kind.value}:{batch.canonical_sha256}"
    connection = _read_only_connection(database)
    try:
        job = connection.execute(
            """
            SELECT job_id, task_type, scope_fixture_id, run_mode, status,
                   job_kind, ocr_execution_mode, record_version
            FROM jobs
            WHERE job_id = ?
            """,
            (requested_job_id,),
        ).fetchone()
        if job is None:
            raise Loop9MachineResultError("scheduler job is unavailable")
        if (
            job["task_type"] != "audit"
            or job["scope_fixture_id"] != expected_scope
            or job["run_mode"] != "shadow"
            or job["job_kind"] != "business"
            or job["ocr_execution_mode"] != "local"
        ):
            raise Loop9MachineResultError("scheduler job is not bound to the formal shadow batch")
        rows = connection.execute(
            """
            SELECT work_item_id, record_version, waybill_number, status,
                   current_stage, business_outcome, decision, review_reason,
                   diagnostic_code, item_index, loading_image_sha256,
                   unloading_image_sha256, pipeline_fingerprint,
                   fixture_platform_loading_net,
                   fixture_platform_unloading_net,
                   platform_loading_net, platform_unloading_net,
                   ocr_generation_id
            FROM work_items
            WHERE job_id = ?
            ORDER BY item_index, work_item_id
            """,
            (requested_job_id,),
        ).fetchall()
        expected_items = tuple(
            sorted(
                batch.items,
                key=lambda value: value.item_identity_sha256,
            )
        )
        if len(rows) != len(expected_items):
            raise Loop9MachineResultError("scheduler work-item count does not match the batch")
        projections: list[SchedulerItemProjection] = []
        for index, (row, source_item) in enumerate(zip(rows, expected_items, strict=True)):
            images = {image.slot: image for image in source_item.images}
            if (
                row["item_index"] != index
                or row["waybill_number"] != f"CF-{source_item.item_identity_sha256}"
                or row["loading_image_sha256"] != images["loading"].sha256
                or row["unloading_image_sha256"] != images["unloading"].sha256
                or row["pipeline_fingerprint"] != batch.pipeline_fingerprint
                or row["fixture_platform_loading_net"] != source_item.platform_loading_net
                or row["fixture_platform_unloading_net"] != source_item.platform_unloading_net
                or row["platform_loading_net"] != source_item.platform_loading_net
                or row["platform_unloading_net"] != source_item.platform_unloading_net
            ):
                raise Loop9MachineResultError("scheduler work-item evidence changed")
            generation_id = _required_text(
                row["ocr_generation_id"],
                label="scheduler OCR generation ID",
            )
            generation_row = connection.execute(
                """
                SELECT generation_id, work_item_id, pipeline_fingerprint,
                       primary_runtime_kind, next_runtime_kind, status,
                       committed_runtime_kind, committed_profile_id,
                       committed_runtime_fingerprint,
                       loading_output_fingerprint,
                       unloading_output_fingerprint, diagnostic_code,
                       record_version
                FROM ocr_run_generations
                WHERE generation_id = ? AND work_item_id = ?
                """,
                (generation_id, row["work_item_id"]),
            ).fetchone()
            if generation_row is None:
                raise Loop9MachineResultError("scheduler OCR generation is unavailable")
            generation = SchedulerGenerationProjection(
                generation_id=generation_id,
                pipeline_fingerprint=_required_sha256(
                    generation_row["pipeline_fingerprint"],
                    label="scheduler generation pipeline",
                ),
                primary_runtime_kind=_required_text(
                    generation_row["primary_runtime_kind"],
                    label="scheduler primary runtime",
                ),
                next_runtime_kind=_required_text(
                    generation_row["next_runtime_kind"],
                    label="scheduler next runtime",
                ),
                status=_required_text(
                    generation_row["status"],
                    label="scheduler generation status",
                ),
                committed_runtime_kind=_optional_text(
                    generation_row["committed_runtime_kind"],
                    label="scheduler committed runtime",
                ),
                committed_profile_id=_optional_text(
                    generation_row["committed_profile_id"],
                    label="scheduler committed profile",
                ),
                committed_runtime_fingerprint=_optional_sha256(
                    generation_row["committed_runtime_fingerprint"],
                    label="scheduler committed runtime fingerprint",
                ),
                loading_output_fingerprint=_optional_sha256(
                    generation_row["loading_output_fingerprint"],
                    label="scheduler loading output fingerprint",
                ),
                unloading_output_fingerprint=_optional_sha256(
                    generation_row["unloading_output_fingerprint"],
                    label="scheduler unloading output fingerprint",
                ),
                diagnostic_code=_optional_text(
                    generation_row["diagnostic_code"],
                    label="scheduler generation diagnostic",
                ),
                record_version=_required_int(
                    generation_row["record_version"],
                    label="scheduler generation record version",
                    minimum=1,
                ),
            )
            attempt_rows = connection.execute(
                """
                SELECT stage_attempt_id, stage, status, resource_name,
                       attempt_number, started_sequence, finished_sequence,
                       diagnostic_code, runtime_kind, profile_id,
                       runtime_fingerprint, pipeline_fingerprint,
                       input_fingerprint, output_fingerprint, discarded,
                       error_kind
                FROM stage_attempts
                WHERE consumer_job_id = ? AND work_item_id = ?
                ORDER BY started_sequence, attempt_number, stage_attempt_id
                """,
                (requested_job_id, row["work_item_id"]),
            ).fetchall()
            attempts = tuple(
                SchedulerStageAttemptProjection(
                    stage_attempt_id=_required_text(
                        attempt["stage_attempt_id"],
                        label="stage-attempt ID",
                    ),
                    stage=_required_text(
                        attempt["stage"],
                        label="scheduler stage",
                    ),
                    status=_required_text(
                        attempt["status"],
                        label="stage-attempt status",
                    ),
                    resource_name=_optional_text(
                        attempt["resource_name"],
                        label="stage-attempt resource",
                    ),
                    attempt_number=_required_int(
                        attempt["attempt_number"],
                        label="stage-attempt number",
                        minimum=1,
                    ),
                    started_sequence=_required_int(
                        attempt["started_sequence"],
                        label="stage-attempt start sequence",
                    ),
                    finished_sequence=(
                        None
                        if attempt["finished_sequence"] is None
                        else _required_int(
                            attempt["finished_sequence"],
                            label="stage-attempt finish sequence",
                        )
                    ),
                    diagnostic_code=_optional_text(
                        attempt["diagnostic_code"],
                        label="stage-attempt diagnostic",
                    ),
                    runtime_kind=_optional_text(
                        attempt["runtime_kind"],
                        label="stage-attempt runtime kind",
                    ),
                    profile_id=_optional_text(
                        attempt["profile_id"],
                        label="stage-attempt profile",
                    ),
                    runtime_fingerprint=_optional_sha256(
                        attempt["runtime_fingerprint"],
                        label="stage-attempt runtime fingerprint",
                    ),
                    pipeline_fingerprint=_optional_sha256(
                        attempt["pipeline_fingerprint"],
                        label="stage-attempt pipeline fingerprint",
                    ),
                    input_fingerprint=_optional_sha256(
                        attempt["input_fingerprint"],
                        label="stage-attempt input fingerprint",
                    ),
                    output_fingerprint=_optional_sha256(
                        attempt["output_fingerprint"],
                        label="stage-attempt output fingerprint",
                    ),
                    discarded=bool(attempt["discarded"]),
                    error_kind=_optional_text(
                        attempt["error_kind"],
                        label="stage-attempt error kind",
                    ),
                )
                for attempt in attempt_rows
            )
            projections.append(
                SchedulerItemProjection(
                    item_identity_sha256=source_item.item_identity_sha256,
                    work_item_id=_required_text(
                        row["work_item_id"],
                        label="scheduler work-item ID",
                    ),
                    item_index=index,
                    record_version=_required_int(
                        row["record_version"],
                        label="scheduler work-item record version",
                        minimum=1,
                    ),
                    status=_required_text(
                        row["status"],
                        label="scheduler work-item status",
                    ),
                    current_stage=_required_text(
                        row["current_stage"],
                        label="scheduler current stage",
                    ),
                    business_outcome=_optional_text(
                        row["business_outcome"],
                        label="scheduler business outcome",
                    ),
                    decision=_optional_text(
                        row["decision"],
                        label="scheduler decision",
                    ),
                    review_reason=_optional_text(
                        row["review_reason"],
                        label="scheduler review reason",
                    ),
                    diagnostic_code=_optional_text(
                        row["diagnostic_code"],
                        label="scheduler diagnostic",
                    ),
                    generation=generation,
                    stage_attempts=attempts,
                )
            )
        return SchedulerBatchProjection(
            job_id=requested_job_id,
            job_record_version=_required_int(
                job["record_version"],
                label="scheduler job record version",
                minimum=1,
            ),
            job_status=_required_text(
                job["status"],
                label="scheduler job status",
            ),
            target_kind=batch.target_kind.value,
            source_batch_sha256=batch.canonical_sha256,
            items=tuple(projections),
        )
    except sqlite3.Error as exc:
        raise Loop9MachineResultError("scheduler database projection failed") from exc
    finally:
        connection.close()


@dataclass(frozen=True, slots=True)
class FormalHumanTruthBinding:
    """Verified human-truth prerequisite for one exact formal batch."""

    review_kind: str
    source_batch_sha256: str
    source_build_sha256: str
    package_sha256: str
    seal_sha256: str
    review_count: int
    image_truth_count: int
    binding_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            kind = ShadowBatchTargetKind(self.review_kind)
        except ValueError as exc:
            raise Loop9MachineResultError("human truth review kind is invalid") from exc
        for value, label in (
            (self.source_batch_sha256, "human truth source batch"),
            (self.source_build_sha256, "human truth source build"),
            (self.package_sha256, "human truth package"),
            (self.seal_sha256, "human truth seal"),
        ):
            _required_sha256(value, label=label)
        if (
            self.review_count != kind.expected_count
            or self.image_truth_count != kind.expected_count * 2
        ):
            raise Loop9MachineResultError("human truth seal counts are incomplete")
        object.__setattr__(
            self,
            "binding_sha256",
            _canonical_sha256(self._payload_without_hash()),
        )

    def _payload_without_hash(self) -> dict[str, object]:
        return {
            "image_truth_count": self.image_truth_count,
            "package_sha256": self.package_sha256,
            "review_count": self.review_count,
            "review_kind": self.review_kind,
            "schema_version": 1,
            "seal_sha256": self.seal_sha256,
            "source_batch_sha256": self.source_batch_sha256,
            "source_build_sha256": self.source_build_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._payload_without_hash(),
            "binding_sha256": self.binding_sha256,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> FormalHumanTruthBinding:
        if not isinstance(value, dict) or set(value) != {
            "binding_sha256",
            "image_truth_count",
            "package_sha256",
            "review_count",
            "review_kind",
            "schema_version",
            "seal_sha256",
            "source_batch_sha256",
            "source_build_sha256",
        }:
            raise Loop9MachineResultError("human truth binding contract is invalid")
        if value.get("schema_version") != 1:
            raise Loop9MachineResultError("human truth binding version is invalid")
        binding = cls(
            review_kind=cast(str, value.get("review_kind")),
            source_batch_sha256=cast(
                str,
                value.get("source_batch_sha256"),
            ),
            source_build_sha256=cast(
                str,
                value.get("source_build_sha256"),
            ),
            package_sha256=cast(str, value.get("package_sha256")),
            seal_sha256=cast(str, value.get("seal_sha256")),
            review_count=cast(int, value.get("review_count")),
            image_truth_count=cast(
                int,
                value.get("image_truth_count"),
            ),
        )
        if binding.to_payload() != value:
            raise Loop9MachineResultError("human truth binding integrity is invalid")
        return binding


def formal_human_truth_binding_from_seal(
    *,
    package_dir: Path,
    seal_path: Path,
    batch: ChengfengShadowBatchManifest,
) -> FormalHumanTruthBinding:
    """Validate package and seal before exposing their immutable binding."""

    from dahe.verification.loop9_human_review import (
        _load_and_validate_seal,
        load_loop9_review_package,
    )

    try:
        package = load_loop9_review_package(package_dir)
        seal = _load_and_validate_seal(
            package=package,
            seal_path=seal_path,
        )
    except Exception as exc:
        raise Loop9MachineResultError("human truth seal is missing or invalid") from exc
    if (
        package.source_batch.canonical_sha256 != batch.canonical_sha256
        or package.source_batch.source_build_sha256 != batch.source_build_sha256
        or package.source_batch.target_kind is not batch.target_kind
    ):
        raise Loop9MachineResultError("human truth seal belongs to a different batch")
    return FormalHumanTruthBinding(
        review_kind=batch.target_kind.value,
        source_batch_sha256=batch.canonical_sha256,
        source_build_sha256=batch.source_build_sha256,
        package_sha256=cast(str, package.payload["canonical_sha256"]),
        seal_sha256=cast(str, seal["canonical_sha256"]),
        review_count=cast(int, seal["review_count"]),
        image_truth_count=cast(int, seal["image_truth_count"]),
    )


def _formal_pipeline_contract_sha256(
    run_context: Mapping[str, object],
) -> str:
    return _canonical_sha256(
        {
            "application_build_sha256": (
                run_context["application_build_sha256"]
            ),
            "evaluator_version": EVALUATOR_VERSION,
            "expected_runtime_kinds": (
                run_context["expected_runtime_kinds"]
            ),
            "matcher_sha256": run_context["matcher_sha256"],
            "ocr_composition_evidence_sha256": (
                run_context["ocr_composition_evidence_sha256"]
            ),
            "policy_sha256": run_context["policy_sha256"],
            "purpose": "formal_locked_set_role_evaluation",
            "runtime_set_sha256": run_context["runtime_set_sha256"],
            "template_set_sha256": run_context["template_set_sha256"],
        }
    )


def _formal_runtime_pipeline_sha256(
    *,
    pipeline_contract_sha256: str,
    runtime_kind: str,
    profile_id: str,
    runtime_fingerprint: str,
) -> str:
    return _canonical_sha256(
        {
            "pipeline_contract_fingerprint": (
                pipeline_contract_sha256
            ),
            "profile_id": profile_id,
            "runtime_fingerprint": runtime_fingerprint,
            "runtime_kind": runtime_kind,
        }
    )


@dataclass(frozen=True, slots=True)
class FormalMachineAuthority:
    """Current-build authority supplied by trusted application composition."""

    current_loop9_build_sha256: str
    development_authority_sha256: str
    run_context: LockedSetRunContext
    templates: tuple[TemplateVersion, ...]
    runtime_identities: tuple[OcrRuntimeIdentity, ...]
    runtime_pipeline_fingerprints: Mapping[str, str]
    authority_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_sha256(
            self.current_loop9_build_sha256,
            label="current Loop 9 build",
        )
        _required_sha256(
            self.development_authority_sha256,
            label="development authority",
        )
        if not isinstance(self.run_context, LockedSetRunContext):
            raise Loop9MachineResultError("formal machine run context is invalid")
        if self.run_context.expected_runtime_kinds != _FORMAL_RUNTIME_KINDS:
            raise Loop9MachineResultError("formal machine evaluation requires CPU and GPU")
        if (
            not self.templates
            or any(
                not isinstance(template, TemplateVersion)
                or template.lifecycle is not TemplateLifecycle.SHADOW
                for template in self.templates
            )
            or {template.definition.role for template in self.templates}
            != {TicketRole.LOADING, TicketRole.UNLOADING}
            or build_template_set_fingerprint(self.templates)
            != self.run_context.template_set_sha256
        ):
            raise Loop9MachineResultError("formal shadow template authority changed")
        ordered_identities = tuple(
            sorted(
                self.runtime_identities,
                key=lambda value: value.runtime_kind,
            )
        )
        if (
            ordered_identities != self.runtime_identities
            or tuple(value.runtime_kind for value in ordered_identities) != _FORMAL_RUNTIME_KINDS
        ):
            raise Loop9MachineResultError("formal runtime identities must be CPU and GPU")
        runtime_payloads = [
            {
                "profile_id": identity.profile_id,
                "runtime_fingerprint": identity.runtime_fingerprint,
                "runtime_kind": identity.runtime_kind,
            }
            for identity in ordered_identities
        ]
        if (
            current_template_ocr_runtime_set_fingerprint(runtime_payloads)
            != self.run_context.runtime_set_sha256
        ):
            raise Loop9MachineResultError("formal runtime set does not match the run context")
        pipeline_map = dict(self.runtime_pipeline_fingerprints)
        if set(pipeline_map) != set(_FORMAL_RUNTIME_KINDS) or any(
            _SHA256.fullmatch(value) is None for value in pipeline_map.values()
        ):
            raise Loop9MachineResultError("formal runtime pipeline identities are invalid")
        pipeline_contract_sha256 = _formal_pipeline_contract_sha256(
            self.run_context.to_payload()
        )
        if any(
            pipeline_map[identity.runtime_kind]
            != _formal_runtime_pipeline_sha256(
                pipeline_contract_sha256=pipeline_contract_sha256,
                runtime_kind=identity.runtime_kind,
                profile_id=identity.profile_id,
                runtime_fingerprint=identity.runtime_fingerprint,
            )
            for identity in ordered_identities
        ):
            raise Loop9MachineResultError(
                "formal runtime pipeline identities changed"
            )
        object.__setattr__(
            self,
            "runtime_pipeline_fingerprints",
            pipeline_map,
        )
        object.__setattr__(
            self,
            "authority_sha256",
            _canonical_sha256(self._payload_without_hash()),
        )

    def _payload_without_hash(self) -> dict[str, object]:
        return {
            "current_loop9_build_sha256": (self.current_loop9_build_sha256),
            "development_authority_sha256": (self.development_authority_sha256),
            "run_context": self.run_context.to_payload(),
            "runtime_identities": [
                {
                    "pipeline_fingerprint": (
                        self.runtime_pipeline_fingerprints[identity.runtime_kind]
                    ),
                    "profile_id": identity.profile_id,
                    "runtime_fingerprint": identity.runtime_fingerprint,
                    "runtime_kind": identity.runtime_kind,
                }
                for identity in self.runtime_identities
            ],
            "schema_version": 1,
            "templates": [
                {
                    "content_sha256": template.content_sha256,
                    "family_id": template.definition.family_id,
                    "lifecycle": template.lifecycle.value,
                    "role": template.definition.role.value,
                    "version_id": template.version_id,
                    "version_number": template.version_number,
                }
                for template in sorted(
                    self.templates,
                    key=lambda value: value.version_id,
                )
            ],
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._payload_without_hash(),
            "authority_sha256": self.authority_sha256,
        }

    def runtime_identity(self, runtime_kind: str) -> OcrRuntimeIdentity:
        for identity in self.runtime_identities:
            if identity.runtime_kind == runtime_kind:
                return identity
        raise Loop9MachineResultError("formal runtime identity is unavailable")


class FormalMachineEvaluatorAuthority(Protocol):
    """Minimal trusted composition exposed by the formal OCR evaluator."""

    @property
    def run_context(self) -> LockedSetRunContext: ...

    @property
    def templates(self) -> tuple[TemplateVersion, ...]: ...

    @property
    def runtime_identities(self) -> tuple[OcrRuntimeIdentity, ...]: ...

    @property
    def runtime_pipeline_fingerprints(self) -> Mapping[str, str]: ...


def formal_machine_authority_from_evaluator(
    *,
    current_loop9_build_sha256: str,
    development_authority_sha256: str,
    evaluator: FormalMachineEvaluatorAuthority,
) -> FormalMachineAuthority:
    """Build authority from trusted composition, never caller-supplied parts."""

    try:
        run_context = evaluator.run_context
        templates = evaluator.templates
        runtime_identities = evaluator.runtime_identities
        runtime_pipeline_fingerprints = evaluator.runtime_pipeline_fingerprints
    except AttributeError as exc:
        raise Loop9MachineResultError("formal evaluator does not expose trusted authority") from exc
    return FormalMachineAuthority(
        current_loop9_build_sha256=current_loop9_build_sha256,
        development_authority_sha256=development_authority_sha256,
        run_context=run_context,
        templates=templates,
        runtime_identities=runtime_identities,
        runtime_pipeline_fingerprints=runtime_pipeline_fingerprints,
    )


def _missing_weight() -> WeightFieldEvidence:
    return WeightFieldEvidence(
        reading=None,
        quality=EvidenceQuality.MISSING,
    )


def _platform_weight(value: str) -> WeightFieldEvidence:
    try:
        reading = WeightReading(
            amount=Decimal(value),
            unit=WeightUnit.TONNE,
            raw_text=value,
        )
    except (InvalidOperation, ValueError) as exc:
        raise Loop9MachineResultError("platform weight evidence is invalid") from exc
    return WeightFieldEvidence(
        reading=reading,
        quality=EvidenceQuality.RELIABLE,
    )


def _runtime_weight(
    output: LockedOcrRuntimeOutput,
    *,
    runtime_disagreement: bool,
) -> WeightFieldEvidence:
    if output.ordinary_net_amount is None or output.ordinary_net_unit is None:
        return _missing_weight()
    unit = (
        WeightUnit.TONNE
        if output.ordinary_net_unit == "t"
        else WeightUnit.KILOGRAM
        if output.ordinary_net_unit == "kg"
        else None
    )
    if unit is None:
        return WeightFieldEvidence(
            reading=None,
            quality=EvidenceQuality.UNCERTAIN,
        )
    reading = WeightReading(
        amount=output.ordinary_net_amount,
        unit=unit,
        raw_text=(f"{_decimal_text(output.ordinary_net_amount)} {output.ordinary_net_unit}"),
    )
    if runtime_disagreement:
        return WeightFieldEvidence(
            reading=reading,
            quality=EvidenceQuality.UNCERTAIN,
            issue=WeightEvidenceIssue.RUNTIME_DISAGREEMENT,
        )
    if output.weight_review_reason == "ticket_weight_format_suspicious":
        return WeightFieldEvidence(
            reading=reading,
            quality=EvidenceQuality.UNCERTAIN,
            issue=WeightEvidenceIssue.FORMAT_SUSPICIOUS,
        )
    return WeightFieldEvidence(
        reading=reading,
        quality=(
            EvidenceQuality.RELIABLE if output.ordinary_net_reliable else EvidenceQuality.UNCERTAIN
        ),
    )


def _ticket_evidence(
    *,
    slot: TicketSlot,
    image_sha256: str,
    selected: LockedOcrRuntimeOutput,
    comparison_differences: frozenset[str],
) -> TicketEvidence:
    role_disagreement = bool(comparison_differences.difference(_WEIGHT_DIFFERENCE_FIELDS))
    weight_disagreement = bool(comparison_differences.intersection(_WEIGHT_DIFFERENCE_FIELDS))
    missing = _missing_weight()
    return TicketEvidence(
        slot=slot,
        image_sha256=image_sha256,
        machine_role=(TicketRole.UNKNOWN if role_disagreement else selected.role),
        role_quality=(EvidenceQuality.UNCERTAIN if role_disagreement else selected.role_quality),
        weights=TicketWeightEvidence(
            ordinary_net=_runtime_weight(
                selected,
                runtime_disagreement=weight_disagreement,
            ),
            factory_net=missing,
            gross=missing,
            tare=missing,
        ),
        extraction_fingerprint=selected.output_fingerprint,
        role_fingerprint=selected.assessment_fingerprint,
    )


def _runtime_output_payload(
    *,
    output: LockedOcrRuntimeOutput,
    authority: FormalMachineAuthority,
) -> dict[str, object]:
    identity = authority.runtime_identity(output.runtime_kind)
    if output.runtime_fingerprint != identity.runtime_fingerprint:
        raise Loop9MachineResultError("formal OCR runtime identity changed")
    if output.role_elapsed_ms is None:
        raise Loop9MachineResultError(
            "formal OCR runtime role timing is missing"
        )
    core: dict[str, object] = {
        "assessment_sha256": output.assessment_fingerprint,
        "ordinary_net": {
            "amount": _decimal_text(output.ordinary_net_amount),
            "confidence": _decimal_text(output.ordinary_net_confidence),
            "reliable": output.ordinary_net_reliable,
            "review_reason": output.weight_review_reason,
            "unit": output.ordinary_net_unit,
        },
        "output_fingerprint": output.output_fingerprint,
        "pipeline_fingerprint": (authority.runtime_pipeline_fingerprints[output.runtime_kind]),
        "profile_id": identity.profile_id,
        "role": {
            "confidence": _decimal_text(output.role_confidence),
            "elapsed_ms": _decimal_text(output.role_elapsed_ms),
            "high_confidence": output.role_high_confidence,
            "predicted": output.role.value,
            "quality": output.role_quality.value,
            "safety_route": output.safety_route,
        },
        "runtime_fingerprint": output.runtime_fingerprint,
        "runtime_kind": output.runtime_kind,
        "timing": {
            "wall_elapsed_ms": _decimal_text(output.wall_elapsed_ms),
            "worker_elapsed_ms": _decimal_text(output.worker_elapsed_ms),
        },
    }
    return {
        **core,
        "observation_sha256": _canonical_sha256(core),
    }


def _formal_image_payload(
    *,
    slot: str,
    image_sha256: str,
    prediction: LockedRolePrediction,
    authority: FormalMachineAuthority,
) -> dict[str, object]:
    comparison = prediction.runtime_comparison
    outputs = tuple(sorted(comparison.outputs, key=lambda value: value.runtime_kind))
    if (
        comparison.status not in {"dual_consistent", "dual_different"}
        or tuple(value.runtime_kind for value in outputs) != _FORMAL_RUNTIME_KINDS
        or comparison.failures
        or comparison.selected_runtime_kind not in _RUNTIME_KINDS
    ):
        raise Loop9MachineResultError("formal CPU/GPU observation is incomplete")
    selected = next(
        (output for output in outputs if output.runtime_kind == comparison.selected_runtime_kind),
        None,
    )
    if selected is None or prediction.image_sha256 != image_sha256:
        raise Loop9MachineResultError("formal OCR selected output is invalid")
    return {
        "image_sha256": image_sha256,
        "incremental_elapsed_ms": _decimal_text(prediction.incremental_elapsed_ms),
        "runtime_comparison": {
            "comparison_sha256": comparison.comparison_sha256,
            "critical_fields_match": comparison.critical_fields_match,
            "differences": list(comparison.differences),
            "selected_runtime_kind": comparison.selected_runtime_kind,
            "status": comparison.status,
        },
        "runtime_observations": [
            _runtime_output_payload(output=output, authority=authority) for output in outputs
        ],
        "selected": {
            "assessment_sha256": prediction.assessment_fingerprint,
            "automatic_review_reason": prediction.automatic_review_reason,
            "ordinary_net": {
                "amount": _decimal_text(selected.ordinary_net_amount),
                "confidence": _decimal_text(selected.ordinary_net_confidence),
                "reliable": selected.ordinary_net_reliable,
                "review_reason": selected.weight_review_reason,
                "unit": selected.ordinary_net_unit,
            },
            "role": prediction.role.value,
            "role_confidence": _decimal_text(prediction.confidence),
            "role_high_confidence": prediction.high_confidence,
            "role_quality": prediction.quality.value,
            "runtime_kind": comparison.selected_runtime_kind,
        },
        "slot": slot,
    }


def _machine_decision(
    *,
    source_item: ShadowBatchItem,
    image_payloads: Sequence[Mapping[str, object]],
) -> tuple[str, str, tuple[str, ...]]:
    by_slot = {cast(str, image["slot"]): image for image in image_payloads}
    tickets: dict[str, TicketEvidence] = {}
    for slot_name, slot_kind in (
        ("loading", TicketSlot.LOADING),
        ("unloading", TicketSlot.UNLOADING),
    ):
        image = by_slot[slot_name]
        comparison = cast(
            Mapping[str, object],
            image["runtime_comparison"],
        )
        observations = cast(
            Sequence[Mapping[str, object]],
            image["runtime_observations"],
        )
        selected_payload = cast(Mapping[str, object], image["selected"])
        selected_kind = cast(str, selected_payload["runtime_kind"])
        selected_raw = next(
            value for value in observations if value["runtime_kind"] == selected_kind
        )
        ordinary_net = cast(
            Mapping[str, object],
            selected_raw["ordinary_net"],
        )
        role = cast(Mapping[str, object], selected_raw["role"])
        output = LockedOcrRuntimeOutput(
            image_sha256=cast(str, image["image_sha256"]),
            runtime_kind=selected_kind,
            runtime_fingerprint=cast(
                str,
                selected_raw["runtime_fingerprint"],
            ),
            output_fingerprint=cast(
                str,
                selected_raw["output_fingerprint"],
            ),
            worker_elapsed_ms=Decimal(
                cast(
                    str,
                    cast(Mapping[str, object], selected_raw["timing"])["worker_elapsed_ms"],
                )
            ),
            wall_elapsed_ms=Decimal(
                cast(
                    str,
                    cast(Mapping[str, object], selected_raw["timing"])["wall_elapsed_ms"],
                )
            ),
            ordinary_net_amount=(
                None
                if ordinary_net["amount"] is None
                else Decimal(cast(str, ordinary_net["amount"]))
            ),
            ordinary_net_unit=cast(str | None, ordinary_net["unit"]),
            ordinary_net_confidence=(
                None
                if ordinary_net["confidence"] is None
                else Decimal(cast(str, ordinary_net["confidence"]))
            ),
            ordinary_net_reliable=cast(bool, ordinary_net["reliable"]),
            role=TicketRole(cast(str, role["predicted"])),
            role_quality=EvidenceQuality(cast(str, role["quality"])),
            role_confidence=Decimal(cast(str, role["confidence"])),
            role_high_confidence=cast(bool, role["high_confidence"]),
            safety_route=cast(str, role["safety_route"]),
            assessment_fingerprint=cast(
                str,
                selected_raw["assessment_sha256"],
            ),
            weight_review_reason=cast(
                str | None,
                ordinary_net["review_reason"],
            ),
            role_elapsed_ms=Decimal(cast(str, role["elapsed_ms"])),
        )
        tickets[slot_name] = _ticket_evidence(
            slot=slot_kind,
            image_sha256=cast(str, image["image_sha256"]),
            selected=output,
            comparison_differences=frozenset(cast(Sequence[str], comparison["differences"])),
        )
    try:
        decision = evaluate_audit(
            AuditEvidence(
                snapshot_id=source_item.item_identity_sha256,
                platform_loading_net=_platform_weight(source_item.platform_loading_net),
                platform_unloading_net=_platform_weight(source_item.platform_unloading_net),
                loading_ticket_quality=EvidenceQuality.RELIABLE,
                unloading_ticket_quality=EvidenceQuality.RELIABLE,
                loading_ticket=tickets["loading"],
                unloading_ticket=tickets["unloading"],
            ),
            _WEIGHT_POLICY,
        )
    except SystemEvidenceError as exc:
        raise Loop9MachineResultError("technical evidence cannot become a business review") from exc
    return (
        decision.business_outcome.value,
        decision.kind.value,
        tuple(reason.value for reason in decision.reasons),
    )


def _technical_result(
    *,
    source_item: ShadowBatchItem,
    scheduler_item: SchedulerItemProjection,
    diagnostic_code: str,
    image_evaluations: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    core: dict[str, object] = {
        "automatic_outcome": "technical_failed",
        "decision": None,
        "diagnostic_code": diagnostic_code,
        "image_evaluations": list(image_evaluations),
        "issue_codes": [],
        "item_identity_sha256": source_item.item_identity_sha256,
        "platform_weights": {
            "loading": source_item.platform_loading_net,
            "unloading": source_item.platform_unloading_net,
        },
        "protected_identity": {
            "platform_waybill_id_sha256": (source_item.platform_waybill_id_digest),
            "vehicle_number_sha256": source_item.vehicle_number_digest,
            "waybill_number_sha256": source_item.waybill_number_digest,
        },
        "scheduler": scheduler_item.to_payload(),
    }
    return {
        **core,
        "result_sha256": _canonical_sha256(core),
    }


def build_formal_machine_result_manifest(
    *,
    batch: ChengfengShadowBatchManifest,
    source_selection: FormalShadowSelectionManifest,
    scheduler: SchedulerBatchProjection,
    authority: FormalMachineAuthority,
    evaluator: Callable[[IndependentLockedImage], LockedRolePrediction],
    human_truth_binding: FormalHumanTruthBinding | None = None,
) -> dict[str, object]:
    """Run exact CPU/GPU evidence and build one replayable machine manifest."""

    if not isinstance(batch, ChengfengShadowBatchManifest):
        raise Loop9MachineResultError("shadow batch is invalid")
    batch.verify_integrity()
    if not isinstance(source_selection, FormalShadowSelectionManifest):
        raise Loop9MachineResultError(
            "formal selection authority is required"
        )
    try:
        source_selection.verify_integrity()
    except FormalShadowSelectionContractError as exc:
        raise Loop9MachineResultError(
            "formal selection authority is invalid"
        ) from exc
    if (
        source_selection.target_kind is not batch.target_kind
        or source_selection.batch_manifest.to_payload()
        != batch.to_payload()
    ):
        raise Loop9MachineResultError(
            "formal selection does not match the machine batch"
        )
    if not isinstance(scheduler, SchedulerBatchProjection):
        raise Loop9MachineResultError("scheduler projection is invalid")
    if not isinstance(authority, FormalMachineAuthority):
        raise Loop9MachineResultError("formal machine authority is invalid")
    if (
        scheduler.source_batch_sha256 != batch.canonical_sha256
        or scheduler.target_kind != batch.target_kind.value
        or len(scheduler.items) != len(batch.items)
        or batch.source_build_sha256 != authority.current_loop9_build_sha256
        or batch.pipeline_fingerprint
        != authority.run_context.application_build_sha256
    ):
        raise Loop9MachineResultError("formal machine inputs have different authorities")
    if batch.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50 and human_truth_binding is None:
        raise Loop9MachineResultError("current locked formal run requires a valid human truth seal")
    if human_truth_binding is not None and (
        human_truth_binding.review_kind != batch.target_kind.value
        or human_truth_binding.source_batch_sha256 != batch.canonical_sha256
        or human_truth_binding.source_build_sha256 != batch.source_build_sha256
    ):
        raise Loop9MachineResultError("human truth seal does not match the formal batch")
    source_items = tuple(sorted(batch.items, key=lambda value: value.item_identity_sha256))
    scheduler_by_identity = {item.item_identity_sha256: item for item in scheduler.items}
    if set(scheduler_by_identity) != {item.item_identity_sha256 for item in source_items}:
        raise Loop9MachineResultError("scheduler projection does not cover the exact shadow batch")

    results: list[dict[str, object]] = []
    timing_samples: dict[str, list[Decimal]] = {
        "cpu_role": [],
        "cpu_wall": [],
        "cpu_worker": [],
        "gpu_role": [],
        "gpu_wall": [],
        "gpu_worker": [],
        "image_incremental": [],
    }
    successful_observations = 0
    runtime_failure_count = 0
    technical_failure_count = 0
    for source_item in source_items:
        scheduler_item = scheduler_by_identity[source_item.item_identity_sha256]
        image_evaluations: list[dict[str, object]] = []
        formal_images: list[dict[str, object]] = []
        item_error: str | None = None
        for source_image in source_item.images:
            try:
                prediction = evaluator(
                    IndependentLockedImage(
                        image_sha256=source_image.sha256,
                        relative_path=f"evidence/{source_image.relative_path}",
                    )
                )
                image_payload = _formal_image_payload(
                    slot=source_image.slot,
                    image_sha256=source_image.sha256,
                    prediction=prediction,
                    authority=authority,
                )
            except Loop9MachineResultError:
                raise
            except Exception:
                runtime_failure_count += 1
                item_error = "LOOP9-FORMAL-OCR-TECHNICAL-FAILURE"
                image_evaluations.append(
                    {
                        "diagnostic_code": item_error,
                        "image_sha256": source_image.sha256,
                        "slot": source_image.slot,
                        "status": "technical_failed",
                    }
                )
                continue
            image_evaluations.append(
                {
                    **image_payload,
                    "status": "succeeded",
                }
            )
            formal_images.append(image_payload)
            timing_samples["image_incremental"].append(prediction.incremental_elapsed_ms)
            for output in prediction.runtime_comparison.outputs:
                successful_observations += 1
                if output.role_elapsed_ms is None:
                    raise Loop9MachineResultError(
                        "formal OCR runtime role timing is missing"
                    )
                timing_samples[f"{output.runtime_kind}_role"].append(
                    output.role_elapsed_ms
                )
                timing_samples[f"{output.runtime_kind}_worker"].append(output.worker_elapsed_ms)
                timing_samples[f"{output.runtime_kind}_wall"].append(output.wall_elapsed_ms)
        if scheduler_item.generation.status != "succeeded" or scheduler_item.status != "succeeded":
            item_error = (
                scheduler_item.diagnostic_code
                or scheduler_item.generation.diagnostic_code
                or "LOOP9-SCHEDULER-WORK-INCOMPLETE"
            )
        if item_error is not None or len(formal_images) != 2:
            technical_failure_count += 1
            results.append(
                _technical_result(
                    source_item=source_item,
                    scheduler_item=scheduler_item,
                    diagnostic_code=(item_error or "LOOP9-FORMAL-OCR-TECHNICAL-FAILURE"),
                    image_evaluations=image_evaluations,
                )
            )
            continue
        outcome, decision, issue_codes = _machine_decision(
            source_item=source_item,
            image_payloads=formal_images,
        )
        core = {
            "automatic_outcome": outcome,
            "decision": decision,
            "diagnostic_code": None,
            "image_evaluations": image_evaluations,
            "issue_codes": list(issue_codes),
            "item_identity_sha256": source_item.item_identity_sha256,
            "platform_weights": {
                "loading": source_item.platform_loading_net,
                "unloading": source_item.platform_unloading_net,
            },
            "protected_identity": {
                "platform_waybill_id_sha256": (source_item.platform_waybill_id_digest),
                "vehicle_number_sha256": (source_item.vehicle_number_digest),
                "waybill_number_sha256": (source_item.waybill_number_digest),
            },
            "scheduler": scheduler_item.to_payload(),
        }
        results.append(
            {
                **core,
                "result_sha256": _canonical_sha256(core),
            }
        )
    without_hash: dict[str, object] = {
        "authority": authority.to_payload(),
        "human_truth_binding": (
            None if human_truth_binding is None else human_truth_binding.to_payload()
        ),
        "image_count": len(source_items) * 2,
        "item_count": len(source_items),
        "kind": "loop9_formal_machine_results",
        "performance": {
            "cpu_role": nearest_rank_percentiles(timing_samples["cpu_role"]),
            "cpu_wall": nearest_rank_percentiles(timing_samples["cpu_wall"]),
            "cpu_worker": nearest_rank_percentiles(timing_samples["cpu_worker"]),
            "gpu_role": nearest_rank_percentiles(timing_samples["gpu_role"]),
            "gpu_wall": nearest_rank_percentiles(timing_samples["gpu_wall"]),
            "gpu_worker": nearest_rank_percentiles(timing_samples["gpu_worker"]),
            "image_incremental": nearest_rank_percentiles(timing_samples["image_incremental"]),
        },
        "results": results,
        "runtime_failure_count": runtime_failure_count,
        "scheduler": scheduler.to_payload(),
        "schema_version": 1,
        "source": {
            "contract_canonical_sha256": (batch.contract_canonical_sha256),
            "contract_selection_sha256": (batch.contract_selection_sha256),
            "formal_selection_sha256": (
                source_selection.canonical_sha256
            ),
            "identity_context_sha256": batch.identity_context_sha256,
            "locked_gate_evidence_sha256": (
                source_selection.locked_gate_evidence_sha256
            ),
            "pipeline_fingerprint": batch.pipeline_fingerprint,
            "source_batch_sha256": batch.canonical_sha256,
            "source_build_sha256": batch.source_build_sha256,
            "target_kind": batch.target_kind.value,
        },
        "successful_runtime_observation_count": successful_observations,
        "technical_failure_count": technical_failure_count,
    }
    return {
        **without_hash,
        "canonical_sha256": _canonical_sha256(without_hash),
    }


def build_shadow_review_auxiliary(
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Project rich formal evidence into the existing human-review contract."""

    machine = _validate_machine_result_payload(payload)
    source = cast(Mapping[str, object], machine["source"])
    if source["target_kind"] != ShadowBatchTargetKind.REAL_SHADOW_30.value:
        raise Loop9MachineResultError("shadow review auxiliary requires the 30-item batch")
    results: list[dict[str, object]] = []
    for rich_result in cast(
        Sequence[Mapping[str, object]],
        machine["results"],
    ):
        outcome = cast(str, rich_result["automatic_outcome"])
        images: list[dict[str, object]] = []
        if outcome != "technical_failed":
            for image in cast(
                Sequence[Mapping[str, object]],
                rich_result["image_evaluations"],
            ):
                selected = cast(
                    Mapping[str, object],
                    image["selected"],
                )
                role = cast(str, selected["role"])
                ordinary_net = cast(
                    Mapping[str, object],
                    selected["ordinary_net"],
                )
                reliable = (
                    selected["role_quality"] == EvidenceQuality.RELIABLE.value
                    and ordinary_net["reliable"] is True
                    and ordinary_net["amount"] is not None
                )
                projected_role = role if reliable else TicketRole.UNKNOWN.value
                images.append(
                    {
                        "image_sha256": image["image_sha256"],
                        "ordinary_net": (
                            None
                            if projected_role == TicketRole.UNKNOWN.value
                            else format(
                                Decimal(cast(str, ordinary_net["amount"])).quantize(
                                    Decimal("0.01")
                                ),
                                "f",
                            )
                        ),
                        "predicted_role": projected_role,
                        "role_high_confidence": (
                            selected["role_high_confidence"]
                            if projected_role != TicketRole.UNKNOWN.value
                            else False
                        ),
                        "slot": image["slot"],
                    }
                )
        issue_codes = cast(Sequence[str], rich_result["issue_codes"])
        core: dict[str, object] = {
            "automatic_outcome": outcome,
            "diagnostic_code": rich_result["diagnostic_code"],
            "images": sorted(images, key=lambda value: cast(str, value["slot"])),
            "issue_code": None if not issue_codes else issue_codes[0],
            "item_identity_sha256": rich_result["item_identity_sha256"],
        }
        results.append(
            {
                **core,
                "result_sha256": _canonical_sha256(core),
            }
        )
    without_hash = {
        "kind": "loop9_machine_audit_results",
        "pipeline_fingerprint": source["pipeline_fingerprint"],
        "results": results,
        "schema_version": 1,
        "source_batch_sha256": source["source_batch_sha256"],
        "source_build_sha256": source["source_build_sha256"],
        "source_contract_sha256": source["contract_canonical_sha256"],
        "target_kind": source["target_kind"],
    }
    return {
        **without_hash,
        "canonical_sha256": _canonical_sha256(without_hash),
    }


def persist_shadow_review_auxiliary(
    *,
    data_root: Path,
    payload: Mapping[str, object],
) -> Path:
    """Persist the existing shadow-review projection without overwrite."""

    if not isinstance(data_root, Path) or not data_root.is_absolute():
        raise Loop9MachineResultError("formal data root must be absolute")
    try:
        root = data_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9MachineResultError("formal data root is unavailable") from exc
    normalized = dict(payload)
    declared = normalized.get("canonical_sha256")
    without_hash = {key: value for key, value in normalized.items() if key != "canonical_sha256"}
    if (
        normalized.get("schema_version") != 1
        or normalized.get("kind") != "loop9_machine_audit_results"
        or declared != _canonical_sha256(without_hash)
    ):
        raise Loop9MachineResultError("shadow review auxiliary integrity is invalid")
    digest = _required_sha256(
        declared,
        label="shadow review auxiliary",
    )
    output_root = root / "verification" / "loop9" / "shadow-review-auxiliaries"
    output_root.mkdir(parents=True, exist_ok=True)
    bucket = output_root / digest[:2]
    bucket.mkdir(exist_ok=True)
    output = bucket / f"{digest}.json"
    content = (_canonical_json(normalized) + "\n").encode("utf-8")
    if output.exists():
        if output.is_symlink() or output.read_bytes() != content:
            raise Loop9MachineResultError("persisted shadow review auxiliary conflicts")
        return output
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, output)
        except FileExistsError:
            if output.read_bytes() != content:
                raise Loop9MachineResultError(
                    "persisted shadow review auxiliary conflicts"
                ) from None
        except OSError as exc:
            raise Loop9MachineResultError("shadow review auxiliary could not be published") from exc
        return output
    finally:
        staged.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class _SerializedMachineAuthority:
    current_build_sha256: str
    pipeline_contract_sha256: str
    authority_sha256: str
    runtimes: Mapping[str, Mapping[str, str]]


def _exact_mapping(
    value: object,
    *,
    fields: set[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise Loop9MachineResultError(f"{label} contract is invalid")
    return dict(value)


def _canonical_decimal(
    value: object,
    *,
    label: str,
    optional: bool = False,
    canonical: bool = True,
) -> Decimal | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise Loop9MachineResultError(f"{label} is invalid")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise Loop9MachineResultError(f"{label} is invalid") from exc
    if (
        not parsed.is_finite()
        or parsed < 0
        or (canonical and _decimal_text(parsed) != value)
    ):
        raise Loop9MachineResultError(f"{label} is invalid")
    return parsed


def _validate_formal_machine_authority_payload(
    value: object,
) -> _SerializedMachineAuthority:
    authority = _exact_mapping(
        value,
        fields={
            "authority_sha256",
            "current_loop9_build_sha256",
            "development_authority_sha256",
            "run_context",
            "runtime_identities",
            "schema_version",
            "templates",
        },
        label="formal machine authority",
    )
    if authority["schema_version"] != 1:
        raise Loop9MachineResultError(
            "formal machine authority version is invalid"
        )
    current_build = _required_sha256(
        cast(str, authority["current_loop9_build_sha256"]),
        label="current Loop 9 build",
    )
    _required_sha256(
        cast(str, authority["development_authority_sha256"]),
        label="development authority",
    )
    declared_authority = _required_sha256(
        cast(str, authority["authority_sha256"]),
        label="formal machine authority",
    )
    authority_core = {
        key: nested
        for key, nested in authority.items()
        if key != "authority_sha256"
    }
    if declared_authority != _canonical_sha256(authority_core):
        raise Loop9MachineResultError(
            "formal machine authority integrity is invalid"
        )

    run_context = _exact_mapping(
        authority["run_context"],
        fields={
            "application_build_manifest",
            "application_build_sha256",
            "expected_runtime_kinds",
            "matcher_sha256",
            "ocr_composition_evidence_sha256",
            "policy_sha256",
            "runtime_set_sha256",
            "template_set_sha256",
        },
        label="formal machine run context",
    )
    try:
        application_build = ApplicationBuildManifest.from_payload(
            run_context["application_build_manifest"]
        )
    except Exception as exc:
        raise Loop9MachineResultError(
            "formal machine application build is invalid"
        ) from exc
    application_build_sha256 = _required_sha256(
        cast(str, run_context["application_build_sha256"]),
        label="formal machine application build",
    )
    if (
        application_build.canonical_sha256 != application_build_sha256
        or application_build.to_payload()
        != run_context["application_build_manifest"]
        or run_context["expected_runtime_kinds"] != ["cpu", "gpu"]
    ):
        raise Loop9MachineResultError(
            "formal machine run context is inconsistent"
        )
    for field_name, label in (
        ("matcher_sha256", "formal matcher"),
        ("ocr_composition_evidence_sha256", "OCR composition"),
        ("policy_sha256", "formal policy"),
        ("runtime_set_sha256", "formal runtime set"),
        ("template_set_sha256", "formal template set"),
    ):
        _required_sha256(
            cast(str, run_context[field_name]),
            label=label,
        )

    runtime_values = authority["runtime_identities"]
    if not isinstance(runtime_values, list) or len(runtime_values) != 2:
        raise Loop9MachineResultError(
            "formal runtime identities must be CPU and GPU"
        )
    runtimes: dict[str, Mapping[str, str]] = {}
    normalized_runtime_set: list[dict[str, str]] = []
    for runtime_value in runtime_values:
        runtime = _exact_mapping(
            runtime_value,
            fields={
                "pipeline_fingerprint",
                "profile_id",
                "runtime_fingerprint",
                "runtime_kind",
            },
            label="formal runtime identity",
        )
        runtime_kind = cast(str, runtime["runtime_kind"])
        if runtime_kind not in _RUNTIME_KINDS or runtime_kind in runtimes:
            raise Loop9MachineResultError(
                "formal runtime identities must be CPU and GPU"
            )
        profile_id = _required_text(
            cast(str, runtime["profile_id"]),
            label="formal runtime profile",
        )
        runtime_fingerprint = _required_sha256(
            cast(str, runtime["runtime_fingerprint"]),
            label="formal runtime fingerprint",
        )
        pipeline_fingerprint = _required_sha256(
            cast(str, runtime["pipeline_fingerprint"]),
            label="formal runtime pipeline",
        )
        runtimes[runtime_kind] = {
            "pipeline_fingerprint": pipeline_fingerprint,
            "profile_id": profile_id,
            "runtime_fingerprint": runtime_fingerprint,
            "runtime_kind": runtime_kind,
        }
        normalized_runtime_set.append(
            {
                "profile_id": profile_id,
                "runtime_fingerprint": runtime_fingerprint,
                "runtime_kind": runtime_kind,
            }
        )
    if (
        [cast(Mapping[str, object], item)["runtime_kind"]
         for item in runtime_values]
        != ["cpu", "gpu"]
        or set(runtimes) != _RUNTIME_KINDS
        or current_template_ocr_runtime_set_fingerprint(
            normalized_runtime_set
        )
        != run_context["runtime_set_sha256"]
    ):
        raise Loop9MachineResultError(
            "formal runtime set does not match the run context"
        )

    template_values = authority["templates"]
    if not isinstance(template_values, list) or not template_values:
        raise Loop9MachineResultError(
            "formal shadow template authority changed"
        )
    template_identities: list[dict[str, object]] = []
    family_ids: set[str] = set()
    version_ids: set[str] = set()
    roles: set[str] = set()
    for template_value in template_values:
        template = _exact_mapping(
            template_value,
            fields={
                "content_sha256",
                "family_id",
                "lifecycle",
                "role",
                "version_id",
                "version_number",
            },
            label="formal shadow template",
        )
        content_sha256 = _required_sha256(
            cast(str, template["content_sha256"]),
            label="formal template content",
        )
        family_id = _required_text(
            cast(str, template["family_id"]),
            label="formal template family",
        )
        version_id = _required_text(
            cast(str, template["version_id"]),
            label="formal template version",
        )
        version_number = template["version_number"]
        role = cast(str, template["role"])
        if (
            template["lifecycle"] != TemplateLifecycle.SHADOW.value
            or role
            not in {
                TicketRole.LOADING.value,
                TicketRole.UNLOADING.value,
            }
            or isinstance(version_number, bool)
            or not isinstance(version_number, int)
            or version_number < 1
            or family_id in family_ids
            or version_id in version_ids
        ):
            raise Loop9MachineResultError(
                "formal shadow template authority changed"
            )
        family_ids.add(family_id)
        version_ids.add(version_id)
        roles.add(role)
        template_identities.append(
            {
                "content_sha256": content_sha256,
                "family_id": family_id,
                "role": role,
                "version_id": version_id,
                "version_number": version_number,
            }
        )
    if (
        roles
        != {
            TicketRole.LOADING.value,
            TicketRole.UNLOADING.value,
        }
        or [
            cast(Mapping[str, object], item)["version_id"]
            for item in template_values
        ]
        != sorted(version_ids)
        or _canonical_sha256(
            {
                "matcher_version": MATCHER_VERSION,
                "schema_version": 1,
                "shadow_templates": template_identities,
            }
        )
        != run_context["template_set_sha256"]
    ):
        raise Loop9MachineResultError(
            "formal shadow template authority changed"
        )
    pipeline_contract_sha256 = _formal_pipeline_contract_sha256(
        run_context
    )
    if any(
        runtime["pipeline_fingerprint"]
        != _formal_runtime_pipeline_sha256(
            pipeline_contract_sha256=pipeline_contract_sha256,
            runtime_kind=runtime_kind,
            profile_id=runtime["profile_id"],
            runtime_fingerprint=runtime["runtime_fingerprint"],
        )
        for runtime_kind, runtime in runtimes.items()
    ):
        raise Loop9MachineResultError(
            "formal runtime pipeline identities changed"
        )
    return _SerializedMachineAuthority(
        current_build_sha256=current_build,
        pipeline_contract_sha256=application_build_sha256,
        authority_sha256=declared_authority,
        runtimes=runtimes,
    )


def _validate_runtime_observation(
    value: object,
    *,
    image_sha256: str,
    authority: _SerializedMachineAuthority,
) -> LockedOcrRuntimeOutput:
    observation = _exact_mapping(
        value,
        fields={
            "assessment_sha256",
            "observation_sha256",
            "ordinary_net",
            "output_fingerprint",
            "pipeline_fingerprint",
            "profile_id",
            "role",
            "runtime_fingerprint",
            "runtime_kind",
            "timing",
        },
        label="formal runtime observation",
    )
    declared = _required_sha256(
        cast(str, observation["observation_sha256"]),
        label="formal runtime observation",
    )
    observation_core = {
        key: nested
        for key, nested in observation.items()
        if key != "observation_sha256"
    }
    if declared != _canonical_sha256(observation_core):
        raise Loop9MachineResultError(
            "formal runtime observation integrity is invalid"
        )
    runtime_kind = cast(str, observation["runtime_kind"])
    expected_runtime = authority.runtimes.get(runtime_kind)
    if expected_runtime is None:
        raise Loop9MachineResultError(
            "formal runtime observation kind is invalid"
        )
    for field_name in (
        "pipeline_fingerprint",
        "profile_id",
        "runtime_fingerprint",
        "runtime_kind",
    ):
        if observation[field_name] != expected_runtime[field_name]:
            raise Loop9MachineResultError(
                f"formal runtime {field_name.replace('_', ' ')} changed"
            )
    ordinary_net = _exact_mapping(
        observation["ordinary_net"],
        fields={
            "amount",
            "confidence",
            "reliable",
            "review_reason",
            "unit",
        },
        label="formal runtime ordinary net",
    )
    role = _exact_mapping(
        observation["role"],
        fields={
            "confidence",
            "elapsed_ms",
            "high_confidence",
            "predicted",
            "quality",
            "safety_route",
        },
        label="formal runtime role",
    )
    timing = _exact_mapping(
        observation["timing"],
        fields={"wall_elapsed_ms", "worker_elapsed_ms"},
        label="formal runtime timing",
    )
    _required_sha256(
        cast(str, observation["assessment_sha256"]),
        label="formal role assessment",
    )
    _required_sha256(
        cast(str, observation["output_fingerprint"]),
        label="formal OCR output",
    )
    try:
        output = LockedOcrRuntimeOutput(
            image_sha256=image_sha256,
            runtime_kind=runtime_kind,
            runtime_fingerprint=cast(
                str,
                observation["runtime_fingerprint"],
            ),
            output_fingerprint=cast(
                str,
                observation["output_fingerprint"],
            ),
            worker_elapsed_ms=cast(
                Decimal,
                _canonical_decimal(
                    timing["worker_elapsed_ms"],
                    label="formal worker elapsed time",
                ),
            ),
            wall_elapsed_ms=cast(
                Decimal,
                _canonical_decimal(
                    timing["wall_elapsed_ms"],
                    label="formal wall elapsed time",
                ),
            ),
            ordinary_net_amount=_canonical_decimal(
                ordinary_net["amount"],
                label="formal ordinary-net amount",
                optional=True,
            ),
            ordinary_net_unit=cast(
                str | None,
                ordinary_net["unit"],
            ),
            ordinary_net_confidence=_canonical_decimal(
                ordinary_net["confidence"],
                label="formal ordinary-net confidence",
                optional=True,
            ),
            ordinary_net_reliable=cast(
                bool,
                ordinary_net["reliable"],
            ),
            role=TicketRole(cast(str, role["predicted"])),
            role_quality=EvidenceQuality(cast(str, role["quality"])),
            role_confidence=cast(
                Decimal,
                _canonical_decimal(
                    role["confidence"],
                    label="formal role confidence",
                ),
            ),
            role_high_confidence=cast(
                bool,
                role["high_confidence"],
            ),
            safety_route=cast(str, role["safety_route"]),
            assessment_fingerprint=cast(
                str,
                observation["assessment_sha256"],
            ),
            weight_review_reason=cast(
                str | None,
                ordinary_net["review_reason"],
            ),
            role_elapsed_ms=cast(
                Decimal,
                _canonical_decimal(
                    role["elapsed_ms"],
                    label="formal role elapsed time",
                ),
            ),
        )
    except Exception as exc:
        raise Loop9MachineResultError(
            "formal runtime observation is invalid"
        ) from exc
    return output


def _validate_successful_image(
    value: object,
    *,
    expected_slot: str,
    expected_image_sha256: str,
    authority: _SerializedMachineAuthority,
) -> tuple[
    dict[str, object],
    tuple[LockedOcrRuntimeOutput, LockedOcrRuntimeOutput],
    Decimal,
]:
    image = _exact_mapping(
        value,
        fields={
            "image_sha256",
            "incremental_elapsed_ms",
            "runtime_comparison",
            "runtime_observations",
            "selected",
            "slot",
            "status",
        },
        label="formal image evaluation",
    )
    if (
        image["status"] != "succeeded"
        or image["slot"] != expected_slot
        or image["image_sha256"] != expected_image_sha256
    ):
        raise Loop9MachineResultError(
            "formal image identity or slot changed"
        )
    incremental_elapsed_ms = cast(
        Decimal,
        _canonical_decimal(
            image["incremental_elapsed_ms"],
            label="formal image elapsed time",
        ),
    )
    observation_values = image["runtime_observations"]
    if (
        not isinstance(observation_values, list)
        or len(observation_values) != 2
    ):
        raise Loop9MachineResultError(
            "formal image requires exactly one CPU and one GPU observation"
        )
    outputs = tuple(
        _validate_runtime_observation(
            observation,
            image_sha256=expected_image_sha256,
            authority=authority,
        )
        for observation in observation_values
    )
    if tuple(output.runtime_kind for output in outputs) != _FORMAL_RUNTIME_KINDS:
        raise Loop9MachineResultError(
            "formal image requires exactly one CPU and one GPU observation"
        )
    comparison = _exact_mapping(
        image["runtime_comparison"],
        fields={
            "comparison_sha256",
            "critical_fields_match",
            "differences",
            "selected_runtime_kind",
            "status",
        },
        label="formal runtime comparison",
    )
    declared_comparison_sha256 = _required_sha256(
        cast(str, comparison["comparison_sha256"]),
        label="formal runtime comparison",
    )
    expected_differences = [
        field_name
        for field_name in sorted(outputs[0].critical_payload())
        if outputs[0].critical_payload()[field_name]
        != outputs[1].critical_payload()[field_name]
    ]
    if expected_differences:
        comparison_valid = (
            comparison["status"] == "dual_different"
            and comparison["critical_fields_match"] is False
            and comparison["selected_runtime_kind"] == "cpu"
            and comparison["differences"] == expected_differences
        )
    else:
        comparison_valid = (
            comparison["status"] == "dual_consistent"
            and comparison["critical_fields_match"] is True
            and comparison["selected_runtime_kind"] in _RUNTIME_KINDS
            and comparison["differences"] == []
        )
    if not comparison_valid:
        raise Loop9MachineResultError(
            "formal runtime comparison is inconsistent"
        )
    try:
        reconstructed_comparison = LockedOcrRuntimeComparison(
            status=cast(str, comparison["status"]),
            source=LOCAL_OCR_RUNTIME_SOURCE,
            reason=(
                "critical_outputs_differ"
                if expected_differences
                else None
            ),
            selected_runtime_kind=cast(
                str,
                comparison["selected_runtime_kind"],
            ),
            critical_fields_match=cast(
                bool,
                comparison["critical_fields_match"],
            ),
            differences=tuple(expected_differences),
            outputs=outputs,
            failures=(),
        )
    except Exception as exc:
        raise Loop9MachineResultError(
            "formal runtime comparison is invalid"
        ) from exc
    if (
        reconstructed_comparison.comparison_sha256
        != declared_comparison_sha256
    ):
        raise Loop9MachineResultError(
            "formal runtime comparison integrity is invalid"
        )
    selected = _exact_mapping(
        image["selected"],
        fields={
            "assessment_sha256",
            "automatic_review_reason",
            "ordinary_net",
            "role",
            "role_confidence",
            "role_high_confidence",
            "role_quality",
            "runtime_kind",
        },
        label="formal selected observation",
    )
    selected_output = next(
        (
            output
            for output in outputs
            if output.runtime_kind == selected["runtime_kind"]
        ),
        None,
    )
    selected_net = _exact_mapping(
        selected["ordinary_net"],
        fields={
            "amount",
            "confidence",
            "reliable",
            "review_reason",
            "unit",
        },
        label="formal selected ordinary net",
    )
    if selected_output is None or (
        selected["runtime_kind"]
        != comparison["selected_runtime_kind"]
        or selected["assessment_sha256"]
        != selected_output.assessment_fingerprint
        or selected["role"] != selected_output.role.value
        or selected["role_quality"]
        != selected_output.role_quality.value
        or selected["role_confidence"]
        != _decimal_text(selected_output.role_confidence)
        or selected["role_high_confidence"]
        is not selected_output.role_high_confidence
        or selected_net["amount"]
        != _decimal_text(selected_output.ordinary_net_amount)
        or selected_net["confidence"]
        != _decimal_text(selected_output.ordinary_net_confidence)
        or selected_net["reliable"]
        is not selected_output.ordinary_net_reliable
        or selected_net["review_reason"]
        != selected_output.weight_review_reason
        or selected_net["unit"] != selected_output.ordinary_net_unit
    ):
        raise Loop9MachineResultError(
            "formal selected observation does not match its runtime"
        )
    expected_review_reason = (
        "ocr_weight_disagreement"
        if (
            expected_differences
            and _WEIGHT_DIFFERENCE_FIELDS.intersection(
                expected_differences
            )
        )
        else selected_output.weight_review_reason
    )
    if (
        selected["automatic_review_reason"]
        != expected_review_reason
    ):
        raise Loop9MachineResultError(
            "formal selected review reason is inconsistent"
        )
    return (
        image,
        cast(
            tuple[
                LockedOcrRuntimeOutput,
                LockedOcrRuntimeOutput,
            ],
            outputs,
        ),
        incremental_elapsed_ms,
    )


def _validate_machine_result_payload(
    payload: Mapping[str, object],
    *,
    batch: ChengfengShadowBatchManifest | None = None,
    source_selection: FormalShadowSelectionManifest | None = None,
) -> dict[str, object]:
    if not isinstance(payload, Mapping):
        raise Loop9MachineResultError("machine-result manifest must be an object")
    normalized = dict(payload)
    expected = {
        "authority",
        "canonical_sha256",
        "human_truth_binding",
        "image_count",
        "item_count",
        "kind",
        "performance",
        "results",
        "runtime_failure_count",
        "scheduler",
        "schema_version",
        "source",
        "successful_runtime_observation_count",
        "technical_failure_count",
    }
    declared = normalized.get("canonical_sha256")
    without_hash = {key: value for key, value in normalized.items() if key != "canonical_sha256"}
    if (
        set(normalized) != expected
        or normalized.get("schema_version") != 1
        or normalized.get("kind") != "loop9_formal_machine_results"
        or declared != _canonical_sha256(without_hash)
    ):
        raise Loop9MachineResultError("machine-result manifest integrity is invalid")
    authority = _validate_formal_machine_authority_payload(
        normalized["authority"]
    )
    source = _exact_mapping(
        normalized["source"],
        fields={
            "contract_canonical_sha256",
            "contract_selection_sha256",
            "formal_selection_sha256",
            "identity_context_sha256",
            "locked_gate_evidence_sha256",
            "pipeline_fingerprint",
            "source_batch_sha256",
            "source_build_sha256",
            "target_kind",
        },
        label="machine-result source binding",
    )
    for field_name, label in (
        ("contract_canonical_sha256", "source contract"),
        ("contract_selection_sha256", "source contract selection"),
        ("formal_selection_sha256", "source formal selection"),
        ("identity_context_sha256", "source identity context"),
        ("pipeline_fingerprint", "source pipeline"),
        ("source_batch_sha256", "source batch"),
        ("source_build_sha256", "source build"),
    ):
        _required_sha256(cast(str, source[field_name]), label=label)
    try:
        target_kind = ShadowBatchTargetKind(
            cast(str, source["target_kind"])
        )
    except ValueError as exc:
        raise Loop9MachineResultError(
            "machine-result target kind is invalid"
        ) from exc
    if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        if source["locked_gate_evidence_sha256"] is not None:
            raise Loop9MachineResultError(
                "current locked machine result must not bind its own Gate"
            )
    else:
        _required_sha256(
            cast(str, source["locked_gate_evidence_sha256"]),
            label="source current locked Gate",
        )
    if (
        source["source_build_sha256"] != authority.current_build_sha256
        or source["pipeline_fingerprint"]
        != authority.pipeline_contract_sha256
    ):
        raise Loop9MachineResultError(
            "machine-result build or pipeline authority changed"
        )
    if (batch is None) is not (source_selection is None):
        raise Loop9MachineResultError(
            "machine-result batch and selection must be verified together"
        )
    if batch is not None and source_selection is not None:
        batch.verify_integrity()
        try:
            source_selection.verify_integrity()
        except FormalShadowSelectionContractError as exc:
            raise Loop9MachineResultError(
                "machine-result formal selection is invalid"
            ) from exc
        if (
            source_selection.target_kind is not batch.target_kind
            or source_selection.batch_manifest.to_payload()
            != batch.to_payload()
        ):
            raise Loop9MachineResultError(
                "machine-result formal selection does not match the batch"
            )
        expected_source = {
            "contract_canonical_sha256": (
                batch.contract_canonical_sha256
            ),
            "contract_selection_sha256": (
                batch.contract_selection_sha256
            ),
            "formal_selection_sha256": (
                source_selection.canonical_sha256
            ),
            "identity_context_sha256": batch.identity_context_sha256,
            "locked_gate_evidence_sha256": (
                source_selection.locked_gate_evidence_sha256
            ),
            "pipeline_fingerprint": batch.pipeline_fingerprint,
            "source_batch_sha256": batch.canonical_sha256,
            "source_build_sha256": batch.source_build_sha256,
            "target_kind": batch.target_kind.value,
        }
        if source != expected_source:
            raise Loop9MachineResultError(
                "machine results do not match the source batch"
            )

    truth_value = normalized.get("human_truth_binding")
    if (
        target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50
        and truth_value is None
    ):
        raise Loop9MachineResultError("current locked machine result has no human truth seal")
    if truth_value is not None:
        truth_binding = FormalHumanTruthBinding.from_payload(truth_value)
        if (
            truth_binding.review_kind != target_kind.value
            or truth_binding.source_batch_sha256 != source.get("source_batch_sha256")
            or truth_binding.source_build_sha256 != source.get("source_build_sha256")
        ):
            raise Loop9MachineResultError("machine-result human truth binding changed")

    scheduler = _exact_mapping(
        normalized["scheduler"],
        fields={
            "items",
            "job_id",
            "job_record_version",
            "job_status",
            "projection_sha256",
            "schema_version",
            "source_batch_sha256",
            "target_kind",
        },
        label="machine-result scheduler projection",
    )
    scheduler_core = {
        key: nested
        for key, nested in scheduler.items()
        if key != "projection_sha256"
    }
    if (
        scheduler["schema_version"] != 1
        or scheduler["source_batch_sha256"]
        != source["source_batch_sha256"]
        or scheduler["target_kind"] != target_kind.value
        or scheduler["projection_sha256"]
        != _canonical_sha256(scheduler_core)
        or not isinstance(scheduler["items"], list)
    ):
        raise Loop9MachineResultError(
            "machine-result scheduler projection is invalid"
        )
    _required_text(
        cast(str, scheduler["job_id"]),
        label="scheduler job ID",
    )
    _required_int(
        scheduler["job_record_version"],
        label="scheduler job record version",
        minimum=1,
    )
    _required_text(
        cast(str, scheduler["job_status"]),
        label="scheduler job status",
    )
    scheduler_items: dict[str, Mapping[str, object]] = {}
    for item_value in cast(list[object], scheduler["items"]):
        if not isinstance(item_value, Mapping):
            raise Loop9MachineResultError(
                "machine-result scheduler item is invalid"
            )
        item_identity = _required_sha256(
            cast(str, item_value.get("item_identity_sha256")),
            label="scheduler item identity",
        )
        if item_identity in scheduler_items:
            raise Loop9MachineResultError(
                "machine-result scheduler items contain duplicates"
            )
        scheduler_items[item_identity] = item_value

    results = normalized.get("results")
    if (
        not isinstance(results, list)
        or normalized.get("item_count") != len(results)
        or len(scheduler_items) != len(results)
    ):
        raise Loop9MachineResultError("machine-result counts are inconsistent")
    if batch is not None and len(results) != len(batch.items):
        raise Loop9MachineResultError(
            "machine results do not cover the exact source batch"
        )
    batch_items = (
        {
            item.item_identity_sha256: item
            for item in batch.items
        }
        if batch is not None
        else {}
    )
    identities: set[str] = set()
    observation_count = 0
    technical_count = 0
    runtime_failure_count = 0
    image_count = 0
    timing_samples: dict[str, list[Decimal]] = {
        "cpu_role": [],
        "cpu_wall": [],
        "cpu_worker": [],
        "gpu_role": [],
        "gpu_wall": [],
        "gpu_worker": [],
        "image_incremental": [],
    }
    for value in results:
        if not isinstance(value, dict):
            raise Loop9MachineResultError("machine-result item is invalid")
        result = cast(dict[str, object], value)
        result_hash = result.get("result_sha256")
        result_core = {key: nested for key, nested in result.items() if key != "result_sha256"}
        identity = result.get("item_identity_sha256")
        if (
            set(result)
            != {
                "automatic_outcome",
                "decision",
                "diagnostic_code",
                "image_evaluations",
                "issue_codes",
                "item_identity_sha256",
                "platform_weights",
                "protected_identity",
                "result_sha256",
                "scheduler",
            }
            or _SHA256.fullmatch(cast(str, identity)) is None
            or identity in identities
            or result_hash != _canonical_sha256(result_core)
        ):
            raise Loop9MachineResultError("machine-result item integrity is invalid")
        item_identity = cast(str, identity)
        identities.add(item_identity)
        scheduler_item = scheduler_items.get(item_identity)
        if scheduler_item is None or result["scheduler"] != scheduler_item:
            raise Loop9MachineResultError(
                "machine-result scheduler item binding changed"
            )
        source_item = batch_items.get(item_identity)
        if batch is not None and source_item is None:
            raise Loop9MachineResultError(
                "machine results do not cover the exact source batch"
            )
        platform_weights = _exact_mapping(
            result["platform_weights"],
            fields={"loading", "unloading"},
            label="machine-result platform weights",
        )
        protected_identity = _exact_mapping(
            result["protected_identity"],
            fields={
                "platform_waybill_id_sha256",
                "vehicle_number_sha256",
                "waybill_number_sha256",
            },
            label="machine-result protected identity",
        )
        for protected_value in protected_identity.values():
            _required_sha256(
                cast(str, protected_value),
                label="machine-result protected identity",
            )
        for platform_value in platform_weights.values():
            _canonical_decimal(
                platform_value,
                label="machine-result platform weight",
                canonical=False,
            )
        if source_item is not None and (
            platform_weights
            != {
                "loading": source_item.platform_loading_net,
                "unloading": source_item.platform_unloading_net,
            }
            or protected_identity
            != {
                "platform_waybill_id_sha256": (
                    source_item.platform_waybill_id_digest
                ),
                "vehicle_number_sha256": (
                    source_item.vehicle_number_digest
                ),
                "waybill_number_sha256": (
                    source_item.waybill_number_digest
                ),
            }
        ):
            raise Loop9MachineResultError(
                "machine-result source item binding changed"
            )

        image_values = result["image_evaluations"]
        if not isinstance(image_values, list) or len(image_values) != 2:
            raise Loop9MachineResultError(
                "machine-result item requires exactly two images"
            )
        image_by_slot: dict[str, dict[str, object]] = {}
        for image_value in image_values:
            if not isinstance(image_value, Mapping):
                raise Loop9MachineResultError(
                    "machine-result image evaluation is invalid"
                )
            slot = image_value.get("slot")
            image_sha256 = _required_sha256(
                cast(str, image_value.get("image_sha256")),
                label="machine-result image",
            )
            if slot not in {"loading", "unloading"} or slot in image_by_slot:
                raise Loop9MachineResultError(
                    "machine-result image slots are incomplete"
                )
            expected_image_sha256 = image_sha256
            if source_item is not None:
                expected_image_sha256 = next(
                    image.sha256
                    for image in source_item.images
                    if image.slot == slot
                )
                if image_sha256 != expected_image_sha256:
                    raise Loop9MachineResultError(
                        "machine-result image identity changed"
                    )
            if image_value.get("status") == "succeeded":
                image, outputs, incremental_elapsed_ms = (
                    _validate_successful_image(
                        image_value,
                        expected_slot=cast(str, slot),
                        expected_image_sha256=expected_image_sha256,
                        authority=authority,
                    )
                )
                timing_samples["image_incremental"].append(
                    incremental_elapsed_ms
                )
                for output in outputs:
                    if output.role_elapsed_ms is None:
                        raise Loop9MachineResultError(
                            "formal OCR runtime role timing is missing"
                        )
                    timing_samples[
                        f"{output.runtime_kind}_role"
                    ].append(output.role_elapsed_ms)
                    timing_samples[
                        f"{output.runtime_kind}_worker"
                    ].append(output.worker_elapsed_ms)
                    timing_samples[
                        f"{output.runtime_kind}_wall"
                    ].append(output.wall_elapsed_ms)
                observation_count += 2
            elif image_value.get("status") == "technical_failed":
                image = _exact_mapping(
                    image_value,
                    fields={
                        "diagnostic_code",
                        "image_sha256",
                        "slot",
                        "status",
                    },
                    label="technical image evaluation",
                )
                _required_text(
                    cast(str, image["diagnostic_code"]),
                    label="technical image diagnostic",
                )
                runtime_failure_count += 1
            else:
                raise Loop9MachineResultError(
                    "machine-result image status is invalid"
                )
            image_by_slot[cast(str, slot)] = image
        if set(image_by_slot) != {"loading", "unloading"}:
            raise Loop9MachineResultError(
                "machine-result image slots are incomplete"
            )
        image_count += len(image_by_slot)

        automatic_outcome = result["automatic_outcome"]
        if automatic_outcome == "technical_failed":
            technical_count += 1
            if (
                result["decision"] is not None
                or result["issue_codes"] != []
                or not isinstance(result["diagnostic_code"], str)
            ):
                raise Loop9MachineResultError(
                    "technical machine result is inconsistent"
                )
        else:
            if (
                result["diagnostic_code"] is not None
                or any(
                    image["status"] != "succeeded"
                    for image in image_by_slot.values()
                )
                or (source_item is None and batch is not None)
            ):
                raise Loop9MachineResultError(
                    "business machine result contains technical evidence"
                )
            if source_item is not None:
                try:
                    expected_outcome, expected_decision, expected_issues = (
                        _machine_decision(
                            source_item=source_item,
                            image_payloads=(
                                image_by_slot["loading"],
                                image_by_slot["unloading"],
                            ),
                        )
                    )
                except Exception as exc:
                    raise Loop9MachineResultError(
                        "machine-result decision replay failed"
                    ) from exc
                if (
                    automatic_outcome != expected_outcome
                    or result["decision"] != expected_decision
                    or result["issue_codes"] != list(expected_issues)
                ):
                    raise Loop9MachineResultError(
                        "machine-result decision replay changed"
                    )
    if (
        normalized.get("successful_runtime_observation_count") != observation_count
        or normalized.get("technical_failure_count") != technical_count
        or normalized.get("runtime_failure_count")
        != runtime_failure_count
        or normalized.get("image_count") != image_count
        or image_count != len(results) * 2
        or set(scheduler_items) != identities
        or (
            batch is not None
            and identities != set(batch_items)
        )
    ):
        raise Loop9MachineResultError("machine-result observation counts are inconsistent")
    expected_performance = {
        key: nearest_rank_percentiles(values)
        for key, values in timing_samples.items()
    }
    if normalized.get("performance") != expected_performance:
        raise Loop9MachineResultError(
            "machine-result performance summary is inconsistent"
        )
    return normalized


def persist_machine_result_manifest(
    *,
    data_root: Path,
    payload: Mapping[str, object],
) -> Path:
    """Publish a canonical machine manifest without replacing prior evidence."""

    if not isinstance(data_root, Path) or not data_root.is_absolute():
        raise Loop9MachineResultError("formal data root must be absolute")
    try:
        root = data_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9MachineResultError("formal data root is unavailable") from exc
    if data_root.is_symlink() or not root.is_dir():
        raise Loop9MachineResultError("formal data root is unsafe")
    normalized = _validate_machine_result_payload(payload)
    digest = cast(str, normalized["canonical_sha256"])
    output_root = root / "verification" / "loop9" / "machine-results"
    output_root.mkdir(parents=True, exist_ok=True)
    bucket = output_root / digest[:2]
    bucket.mkdir(exist_ok=True)
    output = bucket / f"{digest}.json"
    content = (_canonical_json(normalized) + "\n").encode("utf-8")
    if output.exists():
        existing = load_machine_result_manifest(output)
        if existing != normalized:
            raise Loop9MachineResultError("persisted machine-result manifest conflicts")
        return output
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, output)
        except FileExistsError:
            existing = load_machine_result_manifest(output)
            if existing != normalized:
                raise Loop9MachineResultError(
                    "persisted machine-result manifest conflicts"
                ) from None
        except OSError as exc:
            raise Loop9MachineResultError(
                "machine-result manifest could not be published atomically"
            ) from exc
        return output
    finally:
        staged.unlink(missing_ok=True)


def load_machine_result_manifest(path: Path) -> dict[str, object]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9MachineResultError("machine-result path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
        payload = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Loop9MachineResultError("machine-result manifest is unreadable") from exc
    if (
        path.is_symlink()
        or not resolved.is_file()
        or not isinstance(payload, dict)
        or content != (_canonical_json(payload) + "\n").encode("utf-8")
    ):
        raise Loop9MachineResultError("machine-result manifest is not canonical")
    normalized = _validate_machine_result_payload(cast(dict[str, object], payload))
    digest = cast(str, normalized["canonical_sha256"])
    if resolved.name != f"{digest}.json":
        raise Loop9MachineResultError("machine-result path is not content-addressed")
    return normalized


def _normalized_machine_weight(
    selected: Mapping[str, object],
) -> str | None:
    role = selected.get("role")
    ordinary_net = selected.get("ordinary_net")
    if (
        role == TicketRole.UNKNOWN.value
        or not isinstance(ordinary_net, Mapping)
        or ordinary_net.get("amount") is None
        or ordinary_net.get("unit") != "t"
        or ordinary_net.get("reliable") is not True
    ):
        return None
    try:
        amount = Decimal(cast(str, ordinary_net["amount"]))
    except (InvalidOperation, TypeError):
        return None
    if not amount.is_finite() or amount <= 0 or amount >= Decimal("1000"):
        return None
    return format(amount.quantize(Decimal("0.01")), "f")


def _human_expected_outcome(
    *,
    source_item: ShadowBatchItem,
    review: Mapping[str, object],
) -> str:
    if review.get("pair_condition") != "normal_pair":
        return "awaiting_review"
    human_weights = {
        cast(str, image["slot"]): image["ordinary_net"]
        for image in cast(
            Sequence[Mapping[str, object]],
            review["images"],
        )
    }
    platform_weights = {
        "loading": format(
            Decimal(source_item.platform_loading_net).quantize(Decimal("0.01")),
            "f",
        ),
        "unloading": format(
            Decimal(source_item.platform_unloading_net).quantize(Decimal("0.01")),
            "f",
        ),
    }
    return "normal_ready" if human_weights == platform_weights else "awaiting_review"


def _evaluate_machine_truth(
    *,
    batch: ChengfengShadowBatchManifest,
    source_selection: FormalShadowSelectionManifest,
    machine_payload: Mapping[str, object],
    reviews: Sequence[Mapping[str, object]],
    package_sha256: str,
    seal_sha256: str,
) -> dict[str, object]:
    machine = _validate_machine_result_payload(
        machine_payload,
        batch=batch,
        source_selection=source_selection,
    )
    expected_count = batch.target_kind.expected_count
    if expected_count is None:
        raise Loop9MachineResultError(
            "operational captures cannot enter formal machine evaluation"
        )
    source = cast(Mapping[str, object], machine["source"])
    if (
        source["source_batch_sha256"] != batch.canonical_sha256
        or source["source_build_sha256"] != batch.source_build_sha256
        or source["target_kind"] != batch.target_kind.value
        or machine["item_count"] != expected_count
        or machine["image_count"] != expected_count * 2
    ):
        raise Loop9MachineResultError("machine results do not match the sealed review batch")
    _required_sha256(package_sha256, label="review package")
    _required_sha256(seal_sha256, label="human review seal")
    truth_value = machine["human_truth_binding"]
    if truth_value is not None:
        truth_binding = FormalHumanTruthBinding.from_payload(truth_value)
        if (
            truth_binding.package_sha256 != package_sha256
            or truth_binding.seal_sha256 != seal_sha256
        ):
            raise Loop9MachineResultError(
                "machine results are bound to a different human truth seal"
            )
    elif batch.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        raise Loop9MachineResultError("current locked machine results require a human truth seal")
    items_by_identity = {item.item_identity_sha256: item for item in batch.items}
    results_by_identity = {
        cast(str, result["item_identity_sha256"]): result
        for result in cast(
            Sequence[Mapping[str, object]],
            machine["results"],
        )
    }
    reviews_by_identity = {cast(str, review["item_identity_sha256"]): review for review in reviews}
    if set(results_by_identity) != set(items_by_identity) or set(reviews_by_identity) != set(
        items_by_identity
    ):
        raise Loop9MachineResultError("machine results and human truth must cover the exact batch")
    differences: list[dict[str, object]] = []
    wrong_auto_pass_count = 0
    selected_image_difference_count = 0
    high_confidence_role_error_count = 0
    technical_failure_count = 0
    runtime_observation_count = 0
    for identity in sorted(items_by_identity):
        source_item = items_by_identity[identity]
        machine_result = results_by_identity[identity]
        review = reviews_by_identity[identity]
        outcome = cast(str, machine_result["automatic_outcome"])
        expected_outcome = _human_expected_outcome(
            source_item=source_item,
            review=review,
        )
        if outcome == "technical_failed":
            technical_failure_count += 1
            differences.append(
                {
                    "actual_outcome": outcome,
                    "classification": "technical_failure",
                    "diagnostic_code": machine_result["diagnostic_code"],
                    "expected_outcome": expected_outcome,
                    "high_confidence_role_error_count": 0,
                    "image_difference_count": 0,
                    "item_identity_sha256": identity,
                    "wrong_auto_pass": False,
                }
            )
            continue
        truth_by_slot = {
            cast(str, image["slot"]): image
            for image in cast(
                Sequence[Mapping[str, object]],
                review["images"],
            )
        }
        item_image_differences = 0
        item_high_confidence_errors = 0
        for image in cast(
            Sequence[Mapping[str, object]],
            machine_result["image_evaluations"],
        ):
            truth = truth_by_slot[cast(str, image["slot"])]
            selected = cast(Mapping[str, object], image["selected"])
            selected_role_error = selected["role"] != truth["role"]
            selected_weight_error = _normalized_machine_weight(selected) != truth["ordinary_net"]
            if selected_role_error or selected_weight_error:
                item_image_differences += 1
            for observation in cast(
                Sequence[Mapping[str, object]],
                image["runtime_observations"],
            ):
                runtime_observation_count += 1
                role = cast(Mapping[str, object], observation["role"])
                if role["predicted"] != truth["role"] and role["high_confidence"] is True:
                    item_high_confidence_errors += 1
        wrong_auto_pass = outcome == "normal_ready" and (
            expected_outcome != "normal_ready" or item_image_differences > 0
        )
        if wrong_auto_pass:
            wrong_auto_pass_count += 1
        selected_image_difference_count += item_image_differences
        high_confidence_role_error_count += item_high_confidence_errors
        exact = outcome == expected_outcome and item_image_differences == 0
        differences.append(
            {
                "actual_outcome": outcome,
                "classification": (
                    "match"
                    if exact
                    else ("wrong_auto_pass" if wrong_auto_pass else "reviewed_difference")
                ),
                "diagnostic_code": None,
                "expected_outcome": expected_outcome,
                "high_confidence_role_error_count": (item_high_confidence_errors),
                "image_difference_count": item_image_differences,
                "item_identity_sha256": identity,
                "wrong_auto_pass": wrong_auto_pass,
            }
        )
    expected_runtime_observations = expected_count * 2 * 2
    gate_passed = (
        technical_failure_count == 0
        and wrong_auto_pass_count == 0
        and high_confidence_role_error_count == 0
        and runtime_observation_count == expected_runtime_observations
    )
    without_hash: dict[str, object] = {
        "authority_sha256": cast(
            Mapping[str, object],
            machine["authority"],
        )["authority_sha256"],
        "gate_passed": gate_passed,
        "high_confidence_role_error_count": (high_confidence_role_error_count),
        "image_count": expected_count * 2,
        "item_count": expected_count,
        "item_results": differences,
        "kind": "loop9_machine_truth_evaluation",
        "machine_result_sha256": machine["canonical_sha256"],
        "package_sha256": package_sha256,
        "performance": machine["performance"],
        "review_kind": batch.target_kind.value,
        "runtime_observation_count": runtime_observation_count,
        "schema_version": 1,
        "seal_sha256": seal_sha256,
        "selected_image_difference_count": (selected_image_difference_count),
        "source_batch_sha256": batch.canonical_sha256,
        "technical_failure_count": technical_failure_count,
        "wrong_auto_pass_count": wrong_auto_pass_count,
    }
    return {
        **without_hash,
        "canonical_sha256": _canonical_sha256(without_hash),
    }


def evaluate_sealed_machine_results(
    *,
    package_dir: Path,
    seal_path: Path,
    machine_result_path: Path,
) -> dict[str, object]:
    """Evaluate formal machine results only after a verified human-truth seal."""

    from dahe.verification.loop9_human_review import (
        _load_and_validate_seal,
        load_loop9_review_package,
    )

    try:
        package = load_loop9_review_package(package_dir)
        seal = _load_and_validate_seal(
            package=package,
            seal_path=seal_path,
        )
    except Exception as exc:
        raise Loop9MachineResultError("human truth package or seal is invalid") from exc
    machine = load_machine_result_manifest(machine_result_path)
    return _evaluate_machine_truth(
        batch=package.source_batch,
        source_selection=package.formal_selection,
        machine_payload=machine,
        reviews=cast(
            Sequence[Mapping[str, object]],
            seal["reviews"],
        ),
        package_sha256=cast(
            str,
            package.payload["canonical_sha256"],
        ),
        seal_sha256=cast(str, seal["canonical_sha256"]),
    )


def persist_machine_truth_evaluation(
    *,
    data_root: Path,
    payload: Mapping[str, object],
) -> Path:
    """Persist one sealed-truth evaluation as immutable canonical evidence."""

    if not isinstance(data_root, Path) or not data_root.is_absolute():
        raise Loop9MachineResultError("formal data root must be absolute")
    try:
        root = data_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9MachineResultError("formal data root is unavailable") from exc
    normalized = dict(payload)
    declared = normalized.get("canonical_sha256")
    without_hash = {key: value for key, value in normalized.items() if key != "canonical_sha256"}
    if (
        normalized.get("schema_version") != 1
        or normalized.get("kind") != "loop9_machine_truth_evaluation"
        or declared != _canonical_sha256(without_hash)
    ):
        raise Loop9MachineResultError("machine truth evaluation integrity is invalid")
    digest = _required_sha256(
        declared,
        label="machine truth evaluation",
    )
    output_root = root / "verification" / "loop9" / "machine-truth-evaluations"
    output_root.mkdir(parents=True, exist_ok=True)
    bucket = output_root / digest[:2]
    bucket.mkdir(exist_ok=True)
    output = bucket / f"{digest}.json"
    content = (_canonical_json(normalized) + "\n").encode("utf-8")
    if output.exists():
        if output.read_bytes() != content:
            raise Loop9MachineResultError("persisted machine truth evaluation conflicts")
        return output
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, output)
        except FileExistsError:
            if output.read_bytes() != content:
                raise Loop9MachineResultError(
                    "persisted machine truth evaluation conflicts"
                ) from None
        except OSError as exc:
            raise Loop9MachineResultError(
                "machine truth evaluation could not be published"
            ) from exc
        return output
    finally:
        staged.unlink(missing_ok=True)


def load_machine_truth_evaluation(path: Path) -> dict[str, object]:
    """Load one immutable, content-addressed machine truth evaluation."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9MachineResultError(
            "machine truth evaluation path must be absolute"
        )
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
        payload = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Loop9MachineResultError(
            "machine truth evaluation is unreadable"
        ) from exc
    if (
        path.is_symlink()
        or not resolved.is_file()
        or not isinstance(payload, dict)
        or content != (_canonical_json(payload) + "\n").encode("utf-8")
    ):
        raise Loop9MachineResultError(
            "machine truth evaluation is not canonical"
        )
    normalized = cast(dict[str, object], payload)
    expected = {
        "authority_sha256",
        "canonical_sha256",
        "gate_passed",
        "high_confidence_role_error_count",
        "image_count",
        "item_count",
        "item_results",
        "kind",
        "machine_result_sha256",
        "package_sha256",
        "performance",
        "review_kind",
        "runtime_observation_count",
        "schema_version",
        "seal_sha256",
        "selected_image_difference_count",
        "source_batch_sha256",
        "technical_failure_count",
        "wrong_auto_pass_count",
    }
    core = {
        key: value
        for key, value in normalized.items()
        if key != "canonical_sha256"
    }
    declared = normalized.get("canonical_sha256")
    if (
        set(normalized) != expected
        or normalized.get("schema_version") != 1
        or normalized.get("kind") != "loop9_machine_truth_evaluation"
        or not isinstance(normalized.get("gate_passed"), bool)
        or declared != _canonical_sha256(core)
    ):
        raise Loop9MachineResultError(
            "machine truth evaluation integrity is invalid"
        )
    digest = _required_sha256(
        declared,
        label="machine truth evaluation",
    )
    for field_name, label in (
        ("authority_sha256", "machine truth authority"),
        ("machine_result_sha256", "machine result"),
        ("package_sha256", "human review package"),
        ("seal_sha256", "human review seal"),
        ("source_batch_sha256", "source batch"),
    ):
        _required_sha256(
            cast(str, normalized.get(field_name)),
            label=label,
        )
    if resolved.name != f"{digest}.json":
        raise Loop9MachineResultError(
            "machine truth evaluation path is not content-addressed"
        )
    return normalized
