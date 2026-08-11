from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Protocol, cast
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection, RowMapping

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildManifestError,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
)
from dahe.verification.locked_set import (
    LockedSetExclusionSnapshot,
    LockedSetManifest,
    LockedSetReleaseAttestation,
    LockedTicketImage,
    LockedWaybill,
)
from dahe.verification.locked_set_acceptance import (
    DERIVED_ADVERSARIAL_GENERATOR_VERSION,
    RUNTIME_EXECUTION_GATE_VERSION,
    LockedSetAcceptanceError,
    candidate_review_source_authority_binding_sha256,
    evaluate_locked_set_release,
    validate_candidate_review_source_authority_binding,
)
from dahe.verification.locked_set_runner import (
    RUNNER_VERSION,
    LockedSetRunContext,
    LockedSetRunnerError,
)

EXCLUSION_CATEGORIES = frozenset(
    {
        "template_reference_image",
        "development_image",
        "calibration_image",
        "shadow_image",
        "prior_locked_image",
        "prior_waybill_identity",
    }
)
LOCKED_SET_INFLUENCE_KINDS = frozenset(
    {
        "code",
        "preprocessing",
        "configuration",
        "template",
        "model",
        "threshold",
        "rule",
        "mapping",
        "adapter",
        "error_handling",
        "label",
    }
)
RUNNER_REPORT_ONLY_FIELDS = frozenset(
    {
        "image_results",
        "pair_results",
        "run_context",
        "runner_report_sha256",
        "runner_version",
    }
)
_DEVELOPMENT_IMPORT_SOURCE_KIND = "candidate_review_development_import"
_CODE_OWNED_FINGERPRINT_SOURCE_KIND = "code_owned_perceptual_fingerprint"
_DEVELOPMENT_IMPORT_HOLD_KIND = "development_exclusion_import"
_FORMAL_AUTHORITY_SOURCE_KIND = "formal_development_authority"
_FORMAL_AUTHORITY_FINGERPRINT_KIND = "formal_authority_fingerprint"


class LockedSetPersistenceError(RuntimeError):
    """Base error for durable locked-set authority operations."""


class LockedSetNotFoundError(LockedSetPersistenceError, LookupError):
    """Raised when a durable locked set does not exist."""


class LockedSetConflictError(LockedSetPersistenceError):
    """Raised when an immutable locked-set identity conflicts."""


class LockedSetIdempotencyConflictError(LockedSetPersistenceError):
    """Raised when an idempotency key has different input."""


class LockedSetRecordVersionConflictError(LockedSetPersistenceError):
    """Raised when a caller acts on a stale locked-set record."""


class LockedSetInventoryChangedError(LockedSetPersistenceError):
    """Raised when the exclusion inventory changed after snapshot creation."""


class LockedSetInventoryFingerprintIncompleteError(LockedSetPersistenceError):
    """Raised when formal authority lacks a fingerprint for an excluded image."""


class LockedSetInventoryEvidenceMissingError(LockedSetPersistenceError):
    """Raised when an image exclusion has no durable evidence blob."""


class LockedSetStateTransitionError(LockedSetPersistenceError):
    """Raised when a locked-set lifecycle transition is not allowed."""


class StagedLockedImageEvidenceLike(Protocol):
    """Truth-free, file-verified metadata prepared outside a DB transaction."""

    @property
    def image_sha256(self) -> str: ...

    @property
    def relative_path(self) -> str: ...

    @property
    def storage_relative_path(self) -> str: ...

    @property
    def byte_size(self) -> int: ...

    @property
    def media_type(self) -> str: ...


@dataclass(frozen=True, slots=True)
class PersistedPerceptualFingerprint:
    content_sha256: str
    perceptual_fingerprint_json: str
    fingerprint_sha256: str
    algorithm_version: str

    @property
    def image_sha256(self) -> str:
        return self.content_sha256

    @property
    def fingerprint_json(self) -> str:
        return self.perceptual_fingerprint_json

    @property
    def fingerprint_json_sha256(self) -> str:
        return self.fingerprint_sha256

    def to_image_fingerprint(self) -> ImagePerceptualFingerprint:
        try:
            payload = json.loads(self.perceptual_fingerprint_json)
        except json.JSONDecodeError as exc:
            raise LockedSetPersistenceError(
                "persisted perceptual fingerprint JSON is invalid"
            ) from exc
        fingerprint = _image_fingerprint_from_payload(payload)
        if (
            fingerprint.content_sha256 != self.content_sha256
            or fingerprint.algorithm_version != self.algorithm_version
            or hashlib.sha256(self.perceptual_fingerprint_json.encode("utf-8")).hexdigest()
            != self.fingerprint_sha256
        ):
            raise LockedSetConflictError(
                "persisted perceptual fingerprint authority is inconsistent"
            )
        return fingerprint


@dataclass(frozen=True, slots=True)
class PersistedExclusionSnapshot:
    snapshot_id: str
    inventory_high_watermark: int
    snapshot: LockedSetExclusionSnapshot
    inventory_image_count: int
    fingerprinted_image_count: int
    missing_fingerprint_count: int
    fingerprint_algorithm_versions: tuple[str, ...]
    perceptual_fingerprints: tuple[PersistedPerceptualFingerprint, ...]
    created_at: str


@dataclass(frozen=True, slots=True)
class LockedSetDatasetRecord:
    dataset_id: str
    manifest_sha256: str
    member_identity_sha256: str
    state: str
    record_version: int
    created_by: str
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class LockedSetCandidateReviewSourceAuthorityRecord:
    dataset_id: str
    manifest_sha256: str
    seal_sha256: str
    package_sha256: str
    record_set_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    payload_json: str
    created_at: str


@dataclass(frozen=True, slots=True)
class LockedSetDevelopmentAuthorityRecord:
    dataset_id: str
    manifest_sha256: str
    authority_sha256: str
    source_exclusion_snapshot_sha256: str
    formal_exclusion_snapshot_sha256: str
    source_inventory_high_watermark: int
    shadow_template_set_fingerprint: str
    payload_json: str
    created_at: str


@dataclass(frozen=True, slots=True)
class LockedSetSealOutcome:
    dataset: LockedSetDatasetRecord
    created: bool


@dataclass(frozen=True, slots=True)
class LockedSetEvidenceMembershipOutcome:
    dataset_id: str
    manifest_sha256: str
    image_count: int
    total_bytes: int
    applied: bool


@dataclass(frozen=True, slots=True)
class DevelopmentExclusionEvidence:
    """Content-addressed image metadata prepared outside the DB transaction."""

    image_sha256: str
    storage_relative_path: str
    byte_size: int
    media_type: str
    perceptual_fingerprint: ImagePerceptualFingerprint


@dataclass(frozen=True, slots=True)
class DevelopmentExclusionImportOutcome:
    source_authority_sha256: str
    development_image_count: int
    prior_waybill_identity_count: int
    applied: bool


@dataclass(frozen=True, slots=True)
class _LockedSetEvidenceMetadata:
    image_sha256: str
    relative_path: str
    storage_relative_path: str
    byte_size: int
    media_type: str


@dataclass(frozen=True, slots=True)
class LockedSetPreflightAttestationRecord:
    attestation_id: str
    dataset_id: str
    manifest_sha256: str
    exclusion_snapshot_id: str
    exclusion_snapshot_sha256: str
    exclusion_source_id: str
    inventory_high_watermark: int
    waybill_count: int
    image_count: int
    total_bytes: int
    attestation_sha256: str
    actor_id: str
    completed_at: str


@dataclass(frozen=True, slots=True)
class LockedSetPreflightOutcome:
    dataset: LockedSetDatasetRecord
    attestation: LockedSetPreflightAttestationRecord
    applied: bool


@dataclass(frozen=True, slots=True)
class UnfingerprintedExclusionImage:
    category: str
    sha256: str
    relative_path: str


@dataclass(frozen=True, slots=True)
class LockedSetSimilarityScanRecord:
    scan_id: str
    dataset_id: str
    manifest_sha256: str
    exclusion_snapshot_id: str
    exclusion_snapshot_sha256: str
    inventory_high_watermark: int
    scan_json: str
    scan_fingerprint: str
    detector_fingerprint: str
    locked_image_count: int
    excluded_image_count: int
    candidate_count: int
    locked_image_fingerprints_json: str
    locked_image_fingerprints_sha256: str
    locked_image_fingerprints: tuple[ImagePerceptualFingerprint, ...]
    actor_id: str
    completed_at: str


@dataclass(frozen=True, slots=True)
class LockedSetSimilarityScanOutcome:
    scan: LockedSetSimilarityScanRecord
    applied: bool


@dataclass(frozen=True, slots=True)
class LockedSetFormalEvaluationRecord:
    evaluation_id: str
    dataset_id: str
    manifest_sha256: str
    exclusion_snapshot_id: str
    exclusion_snapshot_sha256: str
    inventory_high_watermark: int
    preflight_attestation_id: str
    scan_id: str
    scan_fingerprint: str
    idempotency_key: str
    request_hash: str
    runner_report_json: str
    runner_report_sha256: str
    committed_report_json: str
    committed_report_sha256: str
    quality_coverage_json: str
    quality_coverage_sha256: str
    decision_set_json: str
    decision_set_sha256: str
    run_context_sha256: str
    gate_passed: bool
    formal_report: bool
    formal_accuracy_claim: bool
    formal_accuracy_claim_scope: str
    derived_scenario_accuracy_claim: bool
    derived_prevalence_claim: bool
    actor_id: str
    completed_at: str


@dataclass(frozen=True, slots=True)
class LockedSetFormalEvaluationOutcome:
    dataset: LockedSetDatasetRecord
    evaluation: LockedSetFormalEvaluationRecord
    applied: bool


@dataclass(frozen=True, slots=True)
class LockedSetPreflightAuthority:
    """DB-owned inputs that a formal gate must consume in one transaction."""

    dataset: LockedSetDatasetRecord
    attestation: LockedSetPreflightAttestationRecord
    exclusion_snapshot: PersistedExclusionSnapshot
    eligibility_history: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class LockedSetInvalidationRecord:
    invalidation_id: str
    dataset_id: str
    influence_kind: str
    reason: str
    actor_id: str
    idempotency_key: str
    created_at: str


@dataclass(frozen=True, slots=True)
class LockedSetInvalidationOutcome:
    dataset: LockedSetDatasetRecord
    invalidation: LockedSetInvalidationRecord
    applied: bool


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validated_runner_context_sha256(
    report: Mapping[str, object],
) -> str:
    if report.get("runner_version") != RUNNER_VERSION:
        raise LockedSetPersistenceError("formal runner version is unsupported")
    raw_context = report.get("run_context")
    expected_fields = {
        "application_build_manifest",
        "application_build_sha256",
        "runtime_set_sha256",
        "ocr_composition_evidence_sha256",
        "template_set_sha256",
        "matcher_sha256",
        "policy_sha256",
        "expected_runtime_kinds",
    }
    if not isinstance(raw_context, dict) or set(raw_context) != expected_fields:
        raise LockedSetPersistenceError("formal runner context contract is invalid")

    def fingerprint(field: str) -> str:
        value = raw_context.get(field)
        if not isinstance(value, str):
            raise LockedSetPersistenceError("formal runner context contract is invalid")
        return _required_sha256(
            value,
            f"formal runner context {field}",
        )

    raw_expected_runtime_kinds = raw_context.get("expected_runtime_kinds")
    if not isinstance(raw_expected_runtime_kinds, list) or any(
        not isinstance(item, str) for item in raw_expected_runtime_kinds
    ):
        raise LockedSetPersistenceError("formal runner context contract is invalid")
    expected_runtime_kinds = tuple(raw_expected_runtime_kinds)
    try:
        application_build_manifest = ApplicationBuildManifest.from_payload(
            raw_context.get("application_build_manifest")
        )
        context = LockedSetRunContext(
            application_build_sha256=fingerprint("application_build_sha256"),
            application_build_manifest=application_build_manifest,
            runtime_set_sha256=fingerprint("runtime_set_sha256"),
            ocr_composition_evidence_sha256=fingerprint("ocr_composition_evidence_sha256"),
            template_set_sha256=fingerprint("template_set_sha256"),
            matcher_sha256=fingerprint("matcher_sha256"),
            policy_sha256=fingerprint("policy_sha256"),
            expected_runtime_kinds=expected_runtime_kinds,
        )
    except (ApplicationBuildManifestError, LockedSetRunnerError) as exc:
        raise LockedSetPersistenceError("formal runner context contract is invalid") from exc
    payload = context.to_payload()
    if payload != raw_context:
        raise LockedSetPersistenceError("formal runner context contract is invalid")
    return _canonical_sha256(payload)


def _runner_expected_runtime_kinds(
    report: Mapping[str, object],
) -> tuple[str, ...]:
    raw_context = report.get("run_context")
    if not isinstance(raw_context, Mapping):
        raise LockedSetPersistenceError("formal runner context contract is invalid")
    raw_expected = raw_context.get("expected_runtime_kinds")
    if not isinstance(raw_expected, list) or any(
        not isinstance(item, str) for item in raw_expected
    ):
        raise LockedSetPersistenceError("formal runner context contract is invalid")
    expected = tuple(raw_expected)
    if expected not in {("cpu",), ("cpu", "gpu")}:
        raise LockedSetPersistenceError("formal runner context contract is invalid")
    return expected


def _formal_evaluation_request_hash(
    *,
    actor_id: str,
    committed_report_sha256: str,
    dataset_id: str,
    decision_set_sha256: str,
    inventory_high_watermark: int,
    manifest_sha256: str,
    quality_coverage_sha256: str,
    run_context_sha256: str,
    runner_report_sha256: str,
    scan_fingerprint: str,
    snapshot_sha256: str,
) -> str:
    return _canonical_sha256(
        {
            "actor_id": actor_id,
            "committed_report_sha256": committed_report_sha256,
            "dataset_id": dataset_id,
            "decision_set_sha256": decision_set_sha256,
            "inventory_high_watermark": inventory_high_watermark,
            "manifest_sha256": manifest_sha256,
            "quality_coverage_sha256": quality_coverage_sha256,
            "run_context_sha256": run_context_sha256,
            "runner_report_sha256": runner_report_sha256,
            "scan_fingerprint": scan_fingerprint,
            "snapshot_sha256": snapshot_sha256,
        }
    )


def _pure_runner_report(report: Mapping[str, object]) -> dict[str, object]:
    return {
        field: value for field, value in report.items() if field not in RUNNER_REPORT_ONLY_FIELDS
    }


def _strict_bool_field(
    payload: Mapping[str, object],
    field: str,
    *,
    label: str,
) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise LockedSetPersistenceError(f"{label} {field} must be a boolean")
    return value


def _strict_mapping_field(
    payload: Mapping[str, object],
    field: str,
    *,
    label: str,
) -> dict[str, object]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise LockedSetPersistenceError(f"{label} {field} must be an object")
    return value


def _strict_sha256_field(
    payload: Mapping[str, object],
    field: str,
    *,
    label: str,
) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise LockedSetPersistenceError(f"{label} {field} must be a SHA-256")
    return _required_sha256(value, f"{label} {field}")


def _require_schema_version(
    payload: Mapping[str, object],
    expected: int,
    *,
    label: str,
) -> None:
    value = payload.get("schema_version")
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        raise LockedSetPersistenceError(f"{label} schema version is unsupported")


def _validate_derived_report_contract(report: Mapping[str, object]) -> bool:
    suite = _strict_mapping_field(
        report,
        "derived_adversarial_suite",
        label="formal report",
    )
    results = _strict_mapping_field(
        report,
        "derived_adversarial_results",
        label="formal report",
    )
    gate = _strict_mapping_field(
        report,
        "derived_adversarial_gate",
        label="formal report",
    )
    _require_schema_version(suite, 1, label="formal report derived suite")
    if suite.get("generator_version") != DERIVED_ADVERSARIAL_GENERATOR_VERSION:
        raise LockedSetPersistenceError("formal report derived suite is invalid")
    suite_sha256 = _strict_sha256_field(
        suite,
        "suite_sha256",
        label="derived suite",
    )
    if suite_sha256 != _canonical_sha256(
        {field: value for field, value in suite.items() if field != "suite_sha256"}
    ):
        raise LockedSetPersistenceError("formal report derived suite integrity is invalid")
    scenarios = suite.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 4:
        raise LockedSetPersistenceError("formal report derived scenarios are incomplete")
    scenarios_by_id: dict[str, Mapping[str, object]] = {}
    for raw_scenario in scenarios:
        if not isinstance(raw_scenario, Mapping):
            raise LockedSetPersistenceError("formal report derived scenario is invalid")
        scenario_id = raw_scenario.get("scenario_id")
        if not isinstance(scenario_id, str) or scenario_id in scenarios_by_id:
            raise LockedSetPersistenceError("formal report derived scenario is invalid")
        _strict_sha256_field(
            raw_scenario,
            "loading_slot_image_sha256",
            label="derived scenario",
        )
        _strict_sha256_field(
            raw_scenario,
            "unloading_slot_image_sha256",
            label="derived scenario",
        )
        if not isinstance(raw_scenario.get("expected_automatic_outcome"), str) or not isinstance(
            raw_scenario.get("expected_role_issue"), str
        ):
            raise LockedSetPersistenceError("formal report derived scenario is invalid")
        scenarios_by_id[scenario_id] = raw_scenario

    _require_schema_version(results, 1, label="formal report derived results")
    if (
        results.get("generator_version") != DERIVED_ADVERSARIAL_GENERATOR_VERSION
        or results.get("suite_sha256") != suite_sha256
    ):
        raise LockedSetPersistenceError("formal report derived results are invalid")
    results_sha256 = _strict_sha256_field(
        results,
        "results_sha256",
        label="derived results",
    )
    if results_sha256 != _canonical_sha256(
        {field: value for field, value in results.items() if field != "results_sha256"}
    ):
        raise LockedSetPersistenceError("formal report derived results integrity is invalid")
    raw_results = results.get("results")
    if not isinstance(raw_results, list) or len(raw_results) != 4:
        raise LockedSetPersistenceError("formal report derived results are incomplete")
    failed_scenarios: list[str] = []
    seen_results: set[str] = set()
    for raw_result in raw_results:
        if not isinstance(raw_result, Mapping):
            raise LockedSetPersistenceError("formal report derived result is invalid")
        scenario_id = raw_result.get("scenario_id")
        scenario = scenarios_by_id.get(scenario_id if isinstance(scenario_id, str) else "")
        if scenario is None or not isinstance(scenario_id, str) or scenario_id in seen_results:
            raise LockedSetPersistenceError("formal report derived result is invalid")
        seen_results.add(scenario_id)
        if raw_result.get("loading_slot_image_sha256") != scenario.get(
            "loading_slot_image_sha256"
        ) or raw_result.get("unloading_slot_image_sha256") != scenario.get(
            "unloading_slot_image_sha256"
        ):
            raise LockedSetPersistenceError("formal report derived result membership is invalid")
        if raw_result.get("automatic_outcome") != scenario.get(
            "expected_automatic_outcome"
        ) or raw_result.get("role_issue") != scenario.get("expected_role_issue"):
            failed_scenarios.append(scenario_id)
    if seen_results != set(scenarios_by_id):
        raise LockedSetPersistenceError("formal report derived results are incomplete")
    fingerprint = report.get("derived_adversarial_fingerprint")
    if not isinstance(fingerprint, str) or _required_sha256(
        fingerprint,
        "derived_adversarial_fingerprint",
    ) != _canonical_sha256(
        {
            "generator_version": DERIVED_ADVERSARIAL_GENERATOR_VERSION,
            "results_sha256": results_sha256,
            "suite_sha256": suite_sha256,
        }
    ):
        raise LockedSetPersistenceError("formal report derived adversarial fingerprint is invalid")
    if set(gate) != {"scenario_count", "passed_count", "failed_scenarios", "passed"}:
        raise LockedSetPersistenceError("formal report derived gate is invalid")
    gate_passed = _strict_bool_field(
        gate,
        "passed",
        label="derived gate",
    )
    if (
        gate.get("scenario_count") != 4
        or isinstance(gate.get("scenario_count"), bool)
        or gate.get("passed_count") != 4 - len(failed_scenarios)
        or isinstance(gate.get("passed_count"), bool)
        or gate.get("failed_scenarios") != failed_scenarios
        or gate_passed is not (not failed_scenarios)
    ):
        raise LockedSetPersistenceError("formal report derived gate is inconsistent")
    return gate_passed


def _validate_runtime_execution_gate_contract(
    report: Mapping[str, object],
) -> bool:
    gate = _strict_mapping_field(
        report,
        "runtime_execution_gate",
        label="formal report",
    )
    expected_fields = {
        "schema_version",
        "expected_runtime_kinds",
        "image_count",
        "status_counts",
        "failed_image_count",
        "runtime_summaries",
        "evidence_sha256",
        "passed",
    }
    if set(gate) != expected_fields:
        raise LockedSetPersistenceError("formal report runtime gate is invalid")
    _require_schema_version(
        gate,
        RUNTIME_EXECUTION_GATE_VERSION,
        label="runtime execution gate",
    )
    expected_runtime_kinds = _runner_expected_runtime_kinds(report)
    if gate.get("expected_runtime_kinds") != list(expected_runtime_kinds):
        raise LockedSetPersistenceError("formal report runtime gate composition is inconsistent")
    image_count = gate.get("image_count")
    failed_image_count = gate.get("failed_image_count")
    if (
        not isinstance(image_count, int)
        or isinstance(image_count, bool)
        or image_count != 100
        or not isinstance(failed_image_count, int)
        or isinstance(failed_image_count, bool)
    ):
        raise LockedSetPersistenceError("formal report runtime gate counts are invalid")
    status_counts = _strict_mapping_field(
        gate,
        "status_counts",
        label="runtime execution gate",
    )
    expected_statuses = {
        "not_measured",
        "single_cpu",
        "dual_consistent",
        "dual_different",
        "gpu_failed_cpu_fallback",
    }
    if set(status_counts) != expected_statuses or any(
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in status_counts.values()
    ):
        raise LockedSetPersistenceError("formal report runtime status counts are invalid")
    expected_status = "single_cpu" if expected_runtime_kinds == ("cpu",) else "dual_consistent"
    expected_failed_image_count = image_count - cast(
        int,
        status_counts[expected_status],
    )
    if (
        sum(cast(int, count) for count in status_counts.values()) != image_count
        or status_counts["not_measured"] != 0
        or failed_image_count != expected_failed_image_count
    ):
        raise LockedSetPersistenceError("formal report runtime status counts are inconsistent")

    runtime_summaries = _strict_mapping_field(
        gate,
        "runtime_summaries",
        label="runtime execution gate",
    )
    if set(runtime_summaries) != set(expected_runtime_kinds):
        raise LockedSetPersistenceError("formal report runtime summaries are invalid")
    for runtime_kind in expected_runtime_kinds:
        summary = runtime_summaries.get(runtime_kind)
        if not isinstance(summary, dict) or set(summary) != {
            "success_count",
            "failure_count",
            "wall_elapsed_ms",
            "worker_elapsed_ms",
        }:
            raise LockedSetPersistenceError("formal report runtime summary is invalid")
        success_count = summary.get("success_count")
        failure_count = summary.get("failure_count")
        if (
            not isinstance(success_count, int)
            or isinstance(success_count, bool)
            or success_count < 0
            or success_count > image_count
            or not isinstance(failure_count, int)
            or isinstance(failure_count, bool)
            or failure_count < 0
            or failure_count > image_count
            or success_count + failure_count > image_count
        ):
            raise LockedSetPersistenceError("formal report runtime summary counts are invalid")
        for latency_kind in ("wall_elapsed_ms", "worker_elapsed_ms"):
            latency = summary.get(latency_kind)
            if not isinstance(latency, dict) or set(latency) != {
                "sample_count",
                "p50",
                "p95",
            }:
                raise LockedSetPersistenceError("formal report runtime latency is invalid")
            sample_count = latency.get("sample_count")
            p50 = latency.get("p50")
            p95 = latency.get("p95")
            if (
                not isinstance(sample_count, int)
                or isinstance(sample_count, bool)
                or sample_count != success_count
                or (sample_count == 0 and (p50 is not None or p95 is not None))
                or (sample_count > 0 and (not isinstance(p50, str) or not isinstance(p95, str)))
            ):
                raise LockedSetPersistenceError("formal report runtime latency is invalid")
    _strict_sha256_field(
        gate,
        "evidence_sha256",
        label="runtime execution gate",
    )
    passed = _strict_bool_field(
        gate,
        "passed",
        label="runtime execution gate",
    )
    if passed is not (failed_image_count == 0):
        raise LockedSetPersistenceError("formal report runtime gate is inconsistent")
    return passed


def _validate_report_gate_contract(report: Mapping[str, object]) -> bool:
    _require_schema_version(report, 2, label="formal report")
    try:
        source_authority = validate_candidate_review_source_authority_binding(
            report.get("candidate_review_source_authority")
        )
        source_authority_sha256 = candidate_review_source_authority_binding_sha256(source_authority)
    except LockedSetAcceptanceError as exc:
        raise LockedSetPersistenceError(
            "formal report candidate-review source authority is invalid"
        ) from exc
    if (
        report.get("candidate_review_source_authority") != source_authority
        or report.get("candidate_review_source_authority_sha256") != source_authority_sha256
    ):
        raise LockedSetPersistenceError(
            "formal report candidate-review source authority is invalid"
        )
    observed_gate = _strict_mapping_field(
        report,
        "observed_locked_set_gate",
        label="formal report",
    )
    if set(observed_gate) != {
        "zero_error_gates_passed",
        "quality_coverage_passed",
        "near_duplicate_passed",
        "passed",
    }:
        raise LockedSetPersistenceError("formal report observed gate is invalid")
    observed_parts = tuple(
        _strict_bool_field(
            observed_gate,
            field,
            label="observed gate",
        )
        for field in (
            "zero_error_gates_passed",
            "quality_coverage_passed",
            "near_duplicate_passed",
        )
    )
    observed_passed = _strict_bool_field(
        observed_gate,
        "passed",
        label="observed gate",
    )
    if observed_passed is not all(observed_parts):
        raise LockedSetPersistenceError("formal report observed gate is inconsistent")
    derived_passed = _validate_derived_report_contract(report)
    runtime_passed = _validate_runtime_execution_gate_contract(report)
    gate_passed = _strict_bool_field(
        report,
        "gate_passed",
        label="formal report",
    )
    if gate_passed is not (observed_passed and derived_passed and runtime_passed):
        raise LockedSetPersistenceError("formal report combined gate is inconsistent")
    claim_scope = _strict_mapping_field(
        report,
        "claim_scope",
        label="formal report",
    )
    expected_claim_scope = {
        "real_locked_set_image_count": 100,
        "real_locked_set_pair_count": 50,
        "derived_adversarial_scenario_count": 4,
        "derived_adversarial_in_reconciliation": False,
        "derived_adversarial_in_confusion_matrix": False,
        "derived_adversarial_in_accuracy_metrics": False,
        "derived_adversarial_in_latency_metrics": False,
        "derived_adversarial_role_routing_only": True,
    }
    if set(claim_scope) != set(expected_claim_scope):
        raise LockedSetPersistenceError("formal report claim scope is invalid")
    for field, expected in expected_claim_scope.items():
        value = claim_scope.get(field)
        if isinstance(expected, bool):
            if not isinstance(value, bool) or value is not expected:
                raise LockedSetPersistenceError("formal report claim scope is invalid")
        elif not isinstance(value, int) or isinstance(value, bool) or value != expected:
            raise LockedSetPersistenceError("formal report claim scope is invalid")
    if report.get("eligible_accuracy_scope") != "observed_real_locked_set_only":
        raise LockedSetPersistenceError("formal report eligible accuracy scope is invalid")
    if (
        _strict_bool_field(
            report,
            "derived_scenario_accuracy_claim",
            label="formal report",
        )
        is not False
        or _strict_bool_field(
            report,
            "derived_prevalence_claim",
            label="formal report",
        )
        is not False
    ):
        raise LockedSetPersistenceError("formal report derived claims must be false")
    _strict_sha256_field(
        report,
        "quality_coverage_sha256",
        label="formal report",
    )
    _strict_sha256_field(
        report,
        "runtime_comparison_evidence_sha256",
        label="formal report",
    )
    return gate_passed


def _validate_uncommitted_runner_report(report: Mapping[str, object]) -> bool:
    gate_passed = _validate_report_gate_contract(report)
    pure_report = _pure_runner_report(report)
    pure_report_sha256 = _strict_sha256_field(
        pure_report,
        "report_sha256",
        label="runner base report",
    )
    if pure_report_sha256 != _canonical_sha256(
        {field: value for field, value in pure_report.items() if field != "report_sha256"}
    ):
        raise LockedSetPersistenceError("runner base report integrity is invalid")
    if (
        _strict_bool_field(
            report,
            "formal_report",
            label="runner report",
        )
        is not False
        or _strict_bool_field(
            report,
            "formal_accuracy_claim",
            label="runner report",
        )
        is not False
        or report.get("formal_accuracy_claim_scope") != "none_uncommitted"
        or report.get("claim_status") != "uncommitted"
    ):
        raise LockedSetPersistenceError("runner report claim scope is not uncommitted")
    return gate_passed


def _validate_persisted_formal_reports(
    *,
    runner_report: Mapping[str, object],
    committed_report: Mapping[str, object],
    quality_coverage: Mapping[str, object],
) -> bool:
    gate_passed = _validate_uncommitted_runner_report(runner_report)
    committed_gate_passed = _validate_report_gate_contract(committed_report)
    expected_committed = dict(runner_report)
    expected_committed["formal_report"] = True
    expected_committed["formal_accuracy_claim"] = gate_passed
    expected_committed["formal_accuracy_claim_scope"] = (
        "observed_real_locked_set_only" if gate_passed else "none"
    )
    expected_committed["claim_status"] = (
        "formal_accuracy_claim" if gate_passed else "formal_report_without_accuracy_claim"
    )
    if (
        committed_gate_passed is not gate_passed
        or committed_report != expected_committed
        or _strict_bool_field(
            committed_report,
            "formal_report",
            label="committed report",
        )
        is not True
        or _strict_bool_field(
            committed_report,
            "formal_accuracy_claim",
            label="committed report",
        )
        is not gate_passed
    ):
        raise LockedSetPersistenceError("persisted formal report promotion is inconsistent")
    _require_schema_version(quality_coverage, 2, label="quality coverage")
    if set(quality_coverage) != {
        "schema_version",
        "dataset_id",
        "manifest_sha256",
        "required_conditions",
        "entries",
        "derived_adversarial_suite",
        "quality_coverage_sha256",
    } or quality_coverage.get("derived_adversarial_suite") != runner_report.get(
        "derived_adversarial_suite"
    ):
        raise LockedSetPersistenceError("persisted quality coverage contract is invalid")
    quality_root_sha256 = _strict_sha256_field(
        quality_coverage,
        "quality_coverage_sha256",
        label="quality coverage",
    )
    if (
        quality_root_sha256
        != _canonical_sha256(
            {
                field: value
                for field, value in quality_coverage.items()
                if field != "quality_coverage_sha256"
            }
        )
        or runner_report.get("quality_coverage_sha256") != quality_root_sha256
    ):
        raise LockedSetPersistenceError("persisted quality coverage integrity is invalid")
    return gate_passed


def _fingerprint_set_sha256(
    fingerprints: Sequence[ImagePerceptualFingerprint],
) -> str:
    return _canonical_sha256(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "members": [
                {
                    "content_sha256": fingerprint.content_sha256,
                    "fingerprint_sha256": fingerprint.canonical_sha256,
                }
                for fingerprint in sorted(
                    fingerprints,
                    key=lambda value: value.content_sha256,
                )
            ],
            "schema_version": 1,
        }
    )


def _expected_similarity_detector_fingerprint() -> str:
    return _canonical_sha256(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "comparison_scopes": [
                "probe_to_inventory",
                "probe_to_probe",
            ],
            "required_probe_count": 100,
            "scan_schema_version": 1,
        }
    )


def _image_fingerprint_payload(
    fingerprint: ImagePerceptualFingerprint,
) -> dict[str, object]:
    if not isinstance(fingerprint, ImagePerceptualFingerprint):
        raise LockedSetPersistenceError("code-owned perceptual fingerprint is required")
    try:
        fingerprint.verify_integrity()
    except ImageSimilarityContractError as exc:
        raise LockedSetPersistenceError("perceptual fingerprint integrity is invalid") from exc
    return fingerprint.to_record()


def _image_fingerprint_from_payload(
    value: object,
) -> ImagePerceptualFingerprint:
    if not isinstance(value, Mapping):
        raise LockedSetPersistenceError("persisted perceptual fingerprint is invalid")
    try:
        fingerprint = ImagePerceptualFingerprint.from_record(
            dict(value),
        )
        fingerprint.verify_integrity()
    except ImageSimilarityContractError as exc:
        raise LockedSetPersistenceError("persisted perceptual fingerprint is invalid") from exc
    if _image_fingerprint_payload(fingerprint) != dict(value):
        raise LockedSetPersistenceError("persisted perceptual fingerprint is not canonical")
    return fingerprint


def _required_text(value: str, name: str, *, maximum: int = 200) -> str:
    if not isinstance(value, str):
        raise LockedSetPersistenceError(f"{name} must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise LockedSetPersistenceError(f"{name} is invalid")
    return normalized


def _required_sha256(value: str, name: str) -> str:
    normalized = _required_text(value, name, maximum=64)
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise LockedSetPersistenceError(f"{name} must be a lowercase SHA-256")
    return normalized


def _candidate_review_source_authority_payload_json(
    payload: Mapping[str, object],
    *,
    dataset_id: str,
    manifest_sha256: str,
    package_sha256: str,
    record_set_sha256: str,
    source_authority_sha256: str,
) -> str:
    if not isinstance(payload, Mapping):
        raise LockedSetPersistenceError(
            "candidate-review source authority payload must be an object"
        )
    try:
        payload_json = json.dumps(
            dict(payload),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        normalized = json.loads(payload_json)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LockedSetPersistenceError(
            "candidate-review source authority payload must be canonical JSON"
        ) from exc
    if not isinstance(normalized, dict):
        raise LockedSetPersistenceError(
            "candidate-review source authority payload must be an object"
        )
    if (
        not isinstance(normalized.get("schema_version"), int)
        or isinstance(normalized.get("schema_version"), bool)
        or normalized.get("schema_version") not in {2, 3}
        or normalized.get("kind") != "candidate_review_formal_source_authority"
        or normalized.get("dataset_id") != dataset_id
        or normalized.get("manifest_sha256") != manifest_sha256
        or normalized.get("package_sha256") != package_sha256
        or normalized.get("record_set_sha256") != record_set_sha256
        or normalized.get("source_authority_sha256") != source_authority_sha256
    ):
        raise LockedSetPersistenceError(
            "candidate-review source authority payload bindings are inconsistent"
        )
    without_hash = dict(normalized)
    without_hash.pop("source_authority_sha256")
    try:
        computed_sha256 = hashlib.sha256(
            json.dumps(
                without_hash,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError) as exc:  # pragma: no cover - normalized above
        raise LockedSetPersistenceError(
            "candidate-review source authority payload must be canonical JSON"
        ) from exc
    if computed_sha256 != source_authority_sha256:
        raise LockedSetPersistenceError("candidate-review source authority SHA-256 is inconsistent")
    return payload_json


def _development_authority_payload_json(
    payload: Mapping[str, object],
    *,
    authority_sha256: str,
    source_exclusion_snapshot_sha256: str,
    source_inventory_high_watermark: int,
    shadow_template_set_fingerprint: str,
) -> str:
    if not isinstance(payload, Mapping):
        raise LockedSetPersistenceError(
            "formal development authority payload must be an object"
        )
    try:
        payload_json = _canonical_json(dict(payload))
        normalized = json.loads(payload_json)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LockedSetPersistenceError(
            "formal development authority payload must be canonical JSON"
        ) from exc
    if not isinstance(normalized, dict):
        raise LockedSetPersistenceError(
            "formal development authority payload must be an object"
        )
    without_hash = dict(normalized)
    without_hash.pop("authority_sha256", None)
    if (
        normalized.get("schema_version") != 1
        or isinstance(normalized.get("schema_version"), bool)
        or normalized.get("kind") != "loop7_formal_development_authority"
        or normalized.get("authority_sha256") != authority_sha256
        or _canonical_sha256(without_hash) != authority_sha256
        or normalized.get("source_exclusion_snapshot_sha256")
        != source_exclusion_snapshot_sha256
        or normalized.get("source_inventory_high_watermark")
        != source_inventory_high_watermark
        or normalized.get("shadow_template_set_fingerprint")
        != shadow_template_set_fingerprint
    ):
        raise LockedSetPersistenceError(
            "formal development authority payload bindings are inconsistent"
        )
    return payload_json


def _locked_evidence_paths(image_sha256: str) -> tuple[str, str]:
    storage_relative_path = f"sha256/{image_sha256[:2]}/{image_sha256[2:4]}/{image_sha256}.blob"
    return f"evidence/{storage_relative_path}", storage_relative_path


def _locked_evidence_members(
    images: Sequence[StagedLockedImageEvidenceLike],
) -> tuple[_LockedSetEvidenceMetadata, ...]:
    if len(images) != 100:
        raise LockedSetPersistenceError(
            "locked-set evidence registration requires exactly 100 images"
        )
    normalized: list[_LockedSetEvidenceMetadata] = []
    seen: set[str] = set()
    for raw in images:
        try:
            image_sha256 = _required_sha256(
                raw.image_sha256,
                "image_sha256",
            )
            relative_path = _required_text(
                raw.relative_path,
                "relative_path",
                maximum=300,
            )
            storage_relative_path = _required_text(
                raw.storage_relative_path,
                "storage_relative_path",
                maximum=300,
            )
            byte_size = raw.byte_size
            media_type = _required_text(
                raw.media_type,
                "media_type",
                maximum=100,
            )
        except AttributeError as exc:
            raise LockedSetPersistenceError(
                "locked-set staged evidence metadata is incomplete"
            ) from exc
        if image_sha256 in seen:
            raise LockedSetPersistenceError(
                "locked-set staged evidence contains a duplicate identity"
            )
        if not isinstance(byte_size, int) or isinstance(byte_size, bool) or byte_size <= 0:
            raise LockedSetPersistenceError("locked-set staged evidence byte size is invalid")
        expected_relative_path, expected_storage_relative_path = _locked_evidence_paths(
            image_sha256
        )
        if (
            relative_path != expected_relative_path
            or storage_relative_path != expected_storage_relative_path
        ):
            raise LockedSetPersistenceError(
                "locked-set staged evidence path is not content-addressed"
            )
        if media_type != "application/octet-stream":
            raise LockedSetPersistenceError("locked-set staged evidence media type is invalid")
        seen.add(image_sha256)
        normalized.append(
            _LockedSetEvidenceMetadata(
                image_sha256=image_sha256,
                relative_path=relative_path,
                storage_relative_path=storage_relative_path,
                byte_size=byte_size,
                media_type=media_type,
            )
        )
    return tuple(sorted(normalized, key=lambda candidate: candidate.image_sha256))


def _development_exclusion_members(
    images: Sequence[DevelopmentExclusionEvidence],
) -> tuple[DevelopmentExclusionEvidence, ...]:
    if not images:
        raise LockedSetPersistenceError("development exclusion import requires image evidence")
    normalized: list[DevelopmentExclusionEvidence] = []
    seen: set[str] = set()
    for raw in images:
        if not isinstance(raw, DevelopmentExclusionEvidence):
            raise LockedSetPersistenceError("development exclusion evidence contract is invalid")
        image_sha256 = _required_sha256(
            raw.image_sha256,
            "development exclusion image_sha256",
        )
        if image_sha256 in seen:
            raise LockedSetPersistenceError(
                "development exclusion evidence contains a duplicate identity"
            )
        storage_relative_path = _required_text(
            raw.storage_relative_path,
            "development exclusion storage_relative_path",
            maximum=300,
        )
        _, expected_storage_relative_path = _locked_evidence_paths(image_sha256)
        if storage_relative_path != expected_storage_relative_path:
            raise LockedSetPersistenceError(
                "development exclusion evidence path is not content-addressed"
            )
        if (
            isinstance(raw.byte_size, bool)
            or not isinstance(raw.byte_size, int)
            or raw.byte_size < 1
        ):
            raise LockedSetPersistenceError("development exclusion evidence byte size is invalid")
        media_type = _required_text(
            raw.media_type,
            "development exclusion media_type",
            maximum=100,
        )
        fingerprint_payload = _image_fingerprint_payload(raw.perceptual_fingerprint)
        if fingerprint_payload.get("content_sha256") != image_sha256:
            raise LockedSetPersistenceError(
                "development exclusion fingerprint does not match image identity"
            )
        seen.add(image_sha256)
        normalized.append(
            DevelopmentExclusionEvidence(
                image_sha256=image_sha256,
                storage_relative_path=storage_relative_path,
                byte_size=raw.byte_size,
                media_type=media_type,
                perceptual_fingerprint=raw.perceptual_fingerprint,
            )
        )
    return tuple(
        sorted(
            normalized,
            key=lambda candidate: candidate.image_sha256,
        )
    )


def _development_waybill_identities(
    values: Sequence[str],
) -> tuple[str, ...]:
    if not values:
        raise LockedSetPersistenceError("development exclusion import requires waybill identities")
    normalized = tuple(
        sorted(
            _required_sha256(
                value,
                "development exclusion waybill identity",
            )
            for value in values
        )
    )
    if len(normalized) != len(set(normalized)):
        raise LockedSetPersistenceError(
            "development exclusion waybill identities contain a duplicate"
        )
    return normalized


def _dataset_from_row(row: RowMapping) -> LockedSetDatasetRecord:
    return LockedSetDatasetRecord(
        dataset_id=str(row["dataset_id"]),
        manifest_sha256=str(row["manifest_sha256"]),
        member_identity_sha256=str(row["member_identity_sha256"]),
        state=str(row["state"]),
        record_version=int(row["record_version"]),
        created_by=str(row["created_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _candidate_review_source_authority_from_row(
    row: RowMapping,
) -> LockedSetCandidateReviewSourceAuthorityRecord:
    try:
        dataset_id = _required_text(
            str(row["dataset_id"]),
            "persisted candidate-review dataset_id",
        )
        manifest_sha256 = _required_sha256(
            str(row["manifest_sha256"]),
            "persisted candidate-review manifest_sha256",
        )
        seal_sha256 = _required_sha256(
            str(row["seal_sha256"]),
            "persisted candidate-review seal_sha256",
        )
        package_sha256 = _required_sha256(
            str(row["package_sha256"]),
            "persisted candidate-review package_sha256",
        )
        record_set_sha256 = _required_sha256(
            str(row["record_set_sha256"]),
            "persisted candidate-review record_set_sha256",
        )
        history_sha256 = _required_sha256(
            str(row["review_history_authority_sha256"]),
            "persisted candidate-review history SHA-256",
        )
        source_sha256 = _required_sha256(
            str(row["source_authority_sha256"]),
            "persisted candidate-review source SHA-256",
        )
        payload_json = str(row["payload_json"])
        payload = json.loads(payload_json)
        if not isinstance(payload, dict):
            raise LockedSetPersistenceError("persisted candidate-review payload is invalid")
        canonical_payload_json = _candidate_review_source_authority_payload_json(
            payload,
            dataset_id=dataset_id,
            manifest_sha256=manifest_sha256,
            package_sha256=package_sha256,
            record_set_sha256=record_set_sha256,
            source_authority_sha256=source_sha256,
        )
        created_at = _required_text(
            str(row["created_at"]),
            "persisted candidate-review creation time",
            maximum=40,
        )
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        LockedSetPersistenceError,
    ) as exc:
        raise LockedSetConflictError(
            "persisted candidate-review source authority is inconsistent"
        ) from exc
    if payload_json != canonical_payload_json:
        raise LockedSetConflictError("persisted candidate-review source authority is inconsistent")
    return LockedSetCandidateReviewSourceAuthorityRecord(
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
        seal_sha256=seal_sha256,
        package_sha256=package_sha256,
        record_set_sha256=record_set_sha256,
        review_history_authority_sha256=history_sha256,
        source_authority_sha256=source_sha256,
        payload_json=payload_json,
        created_at=created_at,
    )


def _development_authority_from_row(
    row: RowMapping,
) -> LockedSetDevelopmentAuthorityRecord:
    try:
        dataset_id = _required_text(
            str(row["dataset_id"]),
            "persisted development-authority dataset_id",
        )
        manifest_sha256 = _required_sha256(
            str(row["manifest_sha256"]),
            "persisted development-authority manifest_sha256",
        )
        authority_sha256 = _required_sha256(
            str(row["authority_sha256"]),
            "persisted development authority SHA-256",
        )
        source_snapshot_sha256 = _required_sha256(
            str(row["source_exclusion_snapshot_sha256"]),
            "persisted source exclusion snapshot SHA-256",
        )
        formal_snapshot_sha256 = _required_sha256(
            str(row["formal_exclusion_snapshot_sha256"]),
            "persisted formal exclusion snapshot SHA-256",
        )
        source_watermark = int(row["source_inventory_high_watermark"])
        if source_watermark < 1:
            raise LockedSetPersistenceError(
                "persisted development-authority watermark is invalid"
            )
        template_set_fingerprint = _required_sha256(
            str(row["shadow_template_set_fingerprint"]),
            "persisted shadow template-set fingerprint",
        )
        payload_json = str(row["payload_json"])
        payload = json.loads(payload_json)
        if not isinstance(payload, dict):
            raise LockedSetPersistenceError(
                "persisted development-authority payload is invalid"
            )
        canonical_payload_json = _development_authority_payload_json(
            payload,
            authority_sha256=authority_sha256,
            source_exclusion_snapshot_sha256=source_snapshot_sha256,
            source_inventory_high_watermark=source_watermark,
            shadow_template_set_fingerprint=template_set_fingerprint,
        )
        created_at = _required_text(
            str(row["created_at"]),
            "persisted development-authority creation time",
            maximum=40,
        )
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        LockedSetPersistenceError,
    ) as exc:
        raise LockedSetConflictError(
            "persisted formal development authority is inconsistent"
        ) from exc
    if payload_json != canonical_payload_json:
        raise LockedSetConflictError(
            "persisted formal development authority is inconsistent"
        )
    return LockedSetDevelopmentAuthorityRecord(
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
        authority_sha256=authority_sha256,
        source_exclusion_snapshot_sha256=source_snapshot_sha256,
        formal_exclusion_snapshot_sha256=formal_snapshot_sha256,
        source_inventory_high_watermark=source_watermark,
        shadow_template_set_fingerprint=template_set_fingerprint,
        payload_json=payload_json,
        created_at=created_at,
    )


def _require_development_authority_runner_binding(
    record: LockedSetDevelopmentAuthorityRecord,
    *,
    manifest_sha256: str,
    formal_exclusion_snapshot_sha256: str,
    runner_report: Mapping[str, object],
) -> None:
    try:
        payload = json.loads(record.payload_json)
    except json.JSONDecodeError as exc:  # pragma: no cover - row loader validates
        raise LockedSetConflictError(
            "formal development authority payload is unreadable"
        ) from exc
    context = runner_report.get("run_context")
    contract = payload.get("eligibility_contract") if isinstance(payload, dict) else None
    if (
        record.manifest_sha256 != manifest_sha256
        or record.formal_exclusion_snapshot_sha256
        != formal_exclusion_snapshot_sha256
        or not isinstance(context, Mapping)
        or not isinstance(contract, Mapping)
        or context.get("application_build_sha256")
        != contract.get("build_fingerprint")
        or context.get("runtime_set_sha256")
        != contract.get("runtime_fingerprint")
        or context.get("matcher_sha256")
        != contract.get("matcher_fingerprint")
        or context.get("policy_sha256")
        != contract.get("policy_fingerprint")
        or context.get("template_set_sha256")
        != record.shadow_template_set_fingerprint
    ):
        raise LockedSetConflictError(
            "runner report development authority is inconsistent"
        )


def _candidate_review_binding_from_record(
    record: LockedSetCandidateReviewSourceAuthorityRecord,
) -> dict[str, object]:
    try:
        return validate_candidate_review_source_authority_binding(
            {
                "schema_version": 1,
                "seal_sha256": record.seal_sha256,
                "package_sha256": record.package_sha256,
                "record_set_sha256": record.record_set_sha256,
                "review_history_authority_sha256": (record.review_history_authority_sha256),
                "source_authority_sha256": (record.source_authority_sha256),
            }
        )
    except LockedSetAcceptanceError as exc:
        raise LockedSetConflictError(
            "persisted candidate-review source authority is inconsistent"
        ) from exc


def _attestation_from_row(
    row: RowMapping,
) -> LockedSetPreflightAttestationRecord:
    return LockedSetPreflightAttestationRecord(
        attestation_id=str(row["attestation_id"]),
        dataset_id=str(row["dataset_id"]),
        manifest_sha256=str(row["manifest_sha256"]),
        exclusion_snapshot_id=str(row["exclusion_snapshot_id"]),
        exclusion_snapshot_sha256=str(row["exclusion_snapshot_sha256"]),
        exclusion_source_id=str(row["exclusion_source_id"]),
        inventory_high_watermark=int(row["inventory_high_watermark"]),
        waybill_count=int(row["waybill_count"]),
        image_count=int(row["image_count"]),
        total_bytes=int(row["total_bytes"]),
        attestation_sha256=str(row["attestation_sha256"]),
        actor_id=str(row["actor_id"]),
        completed_at=str(row["completed_at"]),
    )


def _similarity_scan_from_row(
    row: RowMapping,
) -> LockedSetSimilarityScanRecord:
    try:
        raw_fingerprints = json.loads(str(row["locked_image_fingerprints_json"]))
    except json.JSONDecodeError as exc:
        raise LockedSetPersistenceError("persisted locked-image fingerprints are invalid") from exc
    if not isinstance(raw_fingerprints, list):
        raise LockedSetPersistenceError("persisted locked-image fingerprints are invalid")
    fingerprints = tuple(_image_fingerprint_from_payload(raw) for raw in raw_fingerprints)
    fingerprints_json = _canonical_json([_image_fingerprint_payload(item) for item in fingerprints])
    if (
        fingerprints_json != str(row["locked_image_fingerprints_json"])
        or hashlib.sha256(fingerprints_json.encode("utf-8")).hexdigest()
        != str(row["locked_image_fingerprints_sha256"])
        or len(fingerprints) != int(row["locked_image_count"])
    ):
        raise LockedSetPersistenceError("persisted locked-image fingerprint integrity is invalid")
    try:
        scan = json.loads(str(row["scan_json"]))
    except json.JSONDecodeError as exc:
        raise LockedSetPersistenceError("persisted similarity scan is invalid") from exc
    if (
        not isinstance(scan, dict)
        or _canonical_json(scan) != str(row["scan_json"])
        or scan.get("scan_fingerprint") != str(row["scan_fingerprint"])
        or _canonical_sha256(
            {field: value for field, value in scan.items() if field != "scan_fingerprint"}
        )
        != str(row["scan_fingerprint"])
    ):
        raise LockedSetPersistenceError("persisted similarity scan integrity is invalid")
    return LockedSetSimilarityScanRecord(
        scan_id=str(row["scan_id"]),
        dataset_id=str(row["dataset_id"]),
        manifest_sha256=str(row["manifest_sha256"]),
        exclusion_snapshot_id=str(row["exclusion_snapshot_id"]),
        exclusion_snapshot_sha256=str(row["exclusion_snapshot_sha256"]),
        inventory_high_watermark=int(row["inventory_high_watermark"]),
        scan_json=str(row["scan_json"]),
        scan_fingerprint=str(row["scan_fingerprint"]),
        detector_fingerprint=str(row["detector_fingerprint"]),
        locked_image_count=int(row["locked_image_count"]),
        excluded_image_count=int(row["excluded_image_count"]),
        candidate_count=int(row["candidate_count"]),
        locked_image_fingerprints_json=fingerprints_json,
        locked_image_fingerprints_sha256=str(row["locked_image_fingerprints_sha256"]),
        locked_image_fingerprints=fingerprints,
        actor_id=str(row["actor_id"]),
        completed_at=str(row["completed_at"]),
    )


def _formal_evaluation_from_row(
    row: RowMapping,
) -> LockedSetFormalEvaluationRecord:
    try:
        runner_report = json.loads(str(row["runner_report_json"]))
        committed_report = json.loads(str(row["committed_report_json"]))
        quality_coverage = json.loads(str(row["quality_coverage_json"]))
        decision_set = json.loads(str(row["decision_set_json"]))
    except json.JSONDecodeError as exc:
        raise LockedSetPersistenceError("persisted formal report JSON is invalid") from exc
    if (
        not isinstance(runner_report, dict)
        or not isinstance(
            committed_report,
            dict,
        )
        or not isinstance(quality_coverage, dict)
        or not isinstance(
            decision_set,
            list,
        )
    ):
        raise LockedSetPersistenceError("persisted formal report must be an object")
    runner_report_json = _canonical_json(runner_report)
    committed_report_json = _canonical_json(committed_report)
    quality_coverage_json = _canonical_json(quality_coverage)
    decision_set_json = _canonical_json(decision_set)
    runner_report_sha256 = str(row["runner_report_sha256"])
    committed_report_sha256 = str(row["committed_report_sha256"])
    quality_coverage_sha256 = str(row["quality_coverage_sha256"])
    decision_set_sha256 = str(row["decision_set_sha256"])
    run_context_sha256 = _validated_runner_context_sha256(runner_report)
    persisted_run_context_sha256 = _required_sha256(
        str(row["run_context_sha256"]),
        "persisted run_context_sha256",
    )
    request_hash = _required_sha256(
        str(row["request_hash"]),
        "persisted formal request_hash",
    )
    expected_request_hash = _formal_evaluation_request_hash(
        actor_id=str(row["actor_id"]),
        committed_report_sha256=committed_report_sha256,
        dataset_id=str(row["dataset_id"]),
        decision_set_sha256=decision_set_sha256,
        inventory_high_watermark=int(row["inventory_high_watermark"]),
        manifest_sha256=str(row["manifest_sha256"]),
        quality_coverage_sha256=quality_coverage_sha256,
        run_context_sha256=run_context_sha256,
        runner_report_sha256=runner_report_sha256,
        scan_fingerprint=str(row["scan_fingerprint"]),
        snapshot_sha256=str(row["exclusion_snapshot_sha256"]),
    )
    if run_context_sha256 != persisted_run_context_sha256:
        raise LockedSetPersistenceError("persisted formal runner context hash is inconsistent")
    if request_hash != expected_request_hash:
        raise LockedSetPersistenceError("persisted formal request hash is inconsistent")
    raw_gate_passed = row["gate_passed"]
    raw_formal_report = row["formal_report"]
    raw_formal_accuracy_claim = row["formal_accuracy_claim"]
    if (
        not isinstance(raw_gate_passed, int)
        or isinstance(raw_gate_passed, bool)
        or raw_gate_passed not in {0, 1}
        or not isinstance(raw_formal_report, int)
        or isinstance(raw_formal_report, bool)
        or raw_formal_report != 1
        or not isinstance(raw_formal_accuracy_claim, int)
        or isinstance(raw_formal_accuracy_claim, bool)
        or raw_formal_accuracy_claim not in {0, 1}
    ):
        raise LockedSetPersistenceError("persisted formal report flags are invalid")
    gate_passed = _validate_persisted_formal_reports(
        runner_report=runner_report,
        committed_report=committed_report,
        quality_coverage=quality_coverage,
    )
    if (
        runner_report_json != str(row["runner_report_json"])
        or runner_report.get("runner_report_sha256") != runner_report_sha256
        or _canonical_sha256(
            {
                field: value
                for field, value in runner_report.items()
                if field != "runner_report_sha256"
            }
        )
        != runner_report_sha256
        or committed_report_json != str(row["committed_report_json"])
        or hashlib.sha256(committed_report_json.encode("utf-8")).hexdigest()
        != committed_report_sha256
        or quality_coverage_json != str(row["quality_coverage_json"])
        or hashlib.sha256(quality_coverage_json.encode("utf-8")).hexdigest()
        != quality_coverage_sha256
        or decision_set_json != str(row["decision_set_json"])
        or hashlib.sha256(decision_set_json.encode("utf-8")).hexdigest() != decision_set_sha256
        or str(row["evaluation_id"]) != committed_report_sha256
        or gate_passed is not bool(raw_gate_passed)
        or gate_passed is not bool(raw_formal_accuracy_claim)
        or runner_report.get("dataset_id") != str(row["dataset_id"])
        or runner_report.get("manifest_sha256") != str(row["manifest_sha256"])
        or runner_report.get("exclusion_snapshot_sha256") != str(row["exclusion_snapshot_sha256"])
        or quality_coverage.get("dataset_id") != str(row["dataset_id"])
        or quality_coverage.get("manifest_sha256") != str(row["manifest_sha256"])
    ):
        raise LockedSetPersistenceError("persisted formal report integrity is inconsistent")
    return LockedSetFormalEvaluationRecord(
        evaluation_id=str(row["evaluation_id"]),
        dataset_id=str(row["dataset_id"]),
        manifest_sha256=str(row["manifest_sha256"]),
        exclusion_snapshot_id=str(row["exclusion_snapshot_id"]),
        exclusion_snapshot_sha256=str(row["exclusion_snapshot_sha256"]),
        inventory_high_watermark=int(row["inventory_high_watermark"]),
        preflight_attestation_id=str(row["preflight_attestation_id"]),
        scan_id=str(row["scan_id"]),
        scan_fingerprint=str(row["scan_fingerprint"]),
        idempotency_key=str(row["idempotency_key"]),
        request_hash=request_hash,
        runner_report_json=runner_report_json,
        runner_report_sha256=runner_report_sha256,
        committed_report_json=committed_report_json,
        committed_report_sha256=committed_report_sha256,
        quality_coverage_json=quality_coverage_json,
        quality_coverage_sha256=quality_coverage_sha256,
        decision_set_json=decision_set_json,
        decision_set_sha256=decision_set_sha256,
        run_context_sha256=run_context_sha256,
        gate_passed=gate_passed,
        formal_report=True,
        formal_accuracy_claim=gate_passed,
        formal_accuracy_claim_scope=str(committed_report["formal_accuracy_claim_scope"]),
        derived_scenario_accuracy_claim=False,
        derived_prevalence_claim=False,
        actor_id=str(row["actor_id"]),
        completed_at=str(row["completed_at"]),
    )


def _invalidation_from_row(row: RowMapping) -> LockedSetInvalidationRecord:
    return LockedSetInvalidationRecord(
        invalidation_id=str(row["invalidation_id"]),
        dataset_id=str(row["dataset_id"]),
        influence_kind=str(row["influence_kind"]),
        reason=str(row["reason"]),
        actor_id=str(row["actor_id"]),
        idempotency_key=str(row["idempotency_key"]),
        created_at=str(row["created_at"]),
    )


def _manifest_payload(manifest: LockedSetManifest) -> dict[str, object]:
    return {
        "dataset_id": manifest.dataset_id,
        "dataset_kind": manifest.dataset_kind,
        "schema_version": 1,
        "tuning_prohibited": manifest.tuning_prohibited,
        "waybills": [
            {
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "ordinary_net": (
                            None if image.ordinary_net is None else format(image.ordinary_net, "f")
                        ),
                        "relative_path": image.relative_path,
                        "role": image.role.value,
                        "submitted_slot": image.slot.value,
                    }
                    for image in waybill.images
                ],
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": waybill.waybill_identity_sha256,
            }
            for waybill in manifest.waybills
        ],
    }


def _member_identity_payload(manifest: LockedSetManifest) -> dict[str, object]:
    return {
        "schema_version": 1,
        "waybills": [
            {
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "ordinary_net": (
                            None if image.ordinary_net is None else format(image.ordinary_net, "f")
                        ),
                        "role": image.role.value,
                        "submitted_slot": image.slot.value,
                    }
                    for image in sorted(
                        waybill.images,
                        key=lambda candidate: candidate.image_sha256,
                    )
                ],
                "waybill_identity_sha256": waybill.waybill_identity_sha256,
            }
            for waybill in sorted(
                manifest.waybills,
                key=lambda candidate: candidate.waybill_identity_sha256,
            )
        ],
    }


def _truth_manifest_payload(
    manifest: LockedSetManifest,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "waybill_count": manifest.waybill_count,
        "image_count": manifest.image_count,
        "pairs": [
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "truth_role": image.role.value,
                    }
                    for image in waybill.images
                ],
                "submitted_slots": {
                    image.slot.value: image.image_sha256 for image in waybill.images
                },
            }
            for waybill in manifest.waybills
        ],
    }


def _preflight_attestation_payload(
    attestation: LockedSetPreflightAttestationRecord,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": attestation.dataset_id,
        "manifest_sha256": attestation.manifest_sha256,
        "attestation_sha256": attestation.attestation_sha256,
        "exclusion_snapshot_sha256": (attestation.exclusion_snapshot_sha256),
        "waybill_count": attestation.waybill_count,
        "image_count": attestation.image_count,
    }


def _eligibility_history_from_attestation(
    attestation: LockedSetPreflightAttestationRecord,
) -> dict[str, object]:
    eligibility_event: dict[str, object] = {
        "actor_id": attestation.actor_id,
        "event_id": attestation.attestation_id,
        "event_type": "preflight_passed",
        "recorded_at": attestation.completed_at,
    }
    eligibility_event["event_sha256"] = _canonical_sha256(eligibility_event)
    eligibility_history: dict[str, object] = {
        "dataset_id": attestation.dataset_id,
        "events": [eligibility_event],
        "manifest_sha256": attestation.manifest_sha256,
        "schema_version": 1,
        "status": "eligible",
    }
    eligibility_history["history_sha256"] = _canonical_sha256(eligibility_history)
    return eligibility_history


def _current_inventory_high_watermark(connection: Connection) -> int:
    return int(
        connection.execute(
            text("SELECT COALESCE(MAX(entry_sequence), 0) FROM locked_set_exclusion_inventory")
        ).scalar_one()
    )


def register_exclusion_identity(
    connection: Connection,
    *,
    category: str,
    identity_sha256: str,
    source_kind: str,
    source_id: str,
    created_at: str,
    perceptual_fingerprint_json: str | None = None,
    fingerprint_sha256: str | None = None,
    algorithm_version: str | None = None,
) -> bool:
    """Register one authoritative exclusion in the caller's transaction."""

    if category not in EXCLUSION_CATEGORIES:
        raise LockedSetPersistenceError("exclusion category is invalid")
    identity = _required_sha256(identity_sha256, "identity_sha256")
    source = _required_text(source_kind, "source_kind", maximum=50)
    source_identity = _required_text(source_id, "source_id")
    timestamp = _required_text(created_at, "created_at", maximum=40)
    fingerprint_values = (
        perceptual_fingerprint_json,
        fingerprint_sha256,
        algorithm_version,
    )
    if category == "prior_waybill_identity" and perceptual_fingerprint_json is not None:
        raise LockedSetPersistenceError("waybill identities cannot carry image fingerprints")
    if any(value is None for value in fingerprint_values) and not all(
        value is None for value in fingerprint_values
    ):
        raise LockedSetPersistenceError(
            "perceptual fingerprint JSON, hash, and algorithm are one unit"
        )
    normalized_fingerprint_json: str | None = None
    normalized_fingerprint_sha256: str | None = None
    normalized_algorithm_version: str | None = None
    if perceptual_fingerprint_json is not None:
        try:
            fingerprint_payload = json.loads(perceptual_fingerprint_json)
        except json.JSONDecodeError as exc:
            raise LockedSetPersistenceError("perceptual fingerprint JSON is invalid") from exc
        if not isinstance(fingerprint_payload, dict):
            raise LockedSetPersistenceError("perceptual fingerprint JSON must be an object")
        normalized_fingerprint_json = _canonical_json(fingerprint_payload)
        normalized_fingerprint_sha256 = _required_sha256(
            cast(str, fingerprint_sha256),
            "fingerprint_sha256",
        )
        if (
            hashlib.sha256(normalized_fingerprint_json.encode("utf-8")).hexdigest()
            != normalized_fingerprint_sha256
        ):
            raise LockedSetPersistenceError(
                "perceptual fingerprint hash does not match canonical JSON"
            )
        normalized_algorithm_version = _required_text(
            cast(str, algorithm_version),
            "algorithm_version",
            maximum=100,
        )
        if (
            fingerprint_payload.get("content_sha256") != identity
            or fingerprint_payload.get("algorithm_version") != normalized_algorithm_version
        ):
            raise LockedSetPersistenceError(
                "perceptual fingerprint does not match inventory identity"
            )
    result = connection.execute(
        text(
            """
            INSERT OR IGNORE INTO locked_set_exclusion_inventory (
                category, identity_sha256, source_kind, source_id,
                perceptual_fingerprint_json, fingerprint_sha256,
                algorithm_version, created_at
            ) VALUES (
                :category, :identity_sha256, :source_kind, :source_id,
                :perceptual_fingerprint_json, :fingerprint_sha256,
                :algorithm_version, :created_at
            )
            """
        ),
        {
            "category": category,
            "identity_sha256": identity,
            "source_kind": source,
            "source_id": source_identity,
            "perceptual_fingerprint_json": normalized_fingerprint_json,
            "fingerprint_sha256": normalized_fingerprint_sha256,
            "algorithm_version": normalized_algorithm_version,
            "created_at": timestamp,
        },
    )
    return result.rowcount == 1


def require_current_preflight_authority(
    connection: Connection,
    *,
    dataset_id: str,
    manifest_sha256: str,
    exclusion_snapshot_sha256: str,
    inventory_high_watermark: int,
) -> LockedSetPreflightAuthority:
    """Fail closed when a frozen runner's preflight authority is stale."""

    dataset_identity = _required_text(dataset_id, "dataset_id")
    manifest_identity = _required_sha256(manifest_sha256, "manifest_sha256")
    snapshot_identity = _required_sha256(
        exclusion_snapshot_sha256,
        "exclusion_snapshot_sha256",
    )
    row = (
        connection.execute(
            text(
                """
                SELECT
                    attestation.attestation_id,
                    attestation.dataset_id,
                    attestation.manifest_sha256,
                    attestation.exclusion_snapshot_id,
                    attestation.exclusion_snapshot_sha256,
                    attestation.exclusion_source_id,
                    attestation.inventory_high_watermark,
                    attestation.waybill_count,
                    attestation.image_count,
                    attestation.total_bytes,
                    attestation.attestation_sha256,
                    attestation.actor_id,
                    attestation.completed_at,
                    dataset.member_identity_sha256,
                    dataset.state,
                    dataset.record_version,
                    dataset.created_by,
                    dataset.created_at,
                    dataset.updated_at
                FROM locked_set_preflight_attestations AS attestation
                JOIN locked_set_datasets AS dataset
                  ON dataset.dataset_id = attestation.dataset_id
                LEFT JOIN locked_set_invalidations AS invalidation
                  ON invalidation.dataset_id = dataset.dataset_id
                WHERE dataset.dataset_id = :dataset_id
                  AND dataset.state = 'preflight_passed'
                  AND dataset.manifest_sha256 = :manifest_sha256
                  AND attestation.exclusion_snapshot_sha256 =
                      :exclusion_snapshot_sha256
                  AND attestation.inventory_high_watermark =
                      :inventory_high_watermark
                  AND invalidation.invalidation_id IS NULL
                """
            ),
            {
                "dataset_id": dataset_identity,
                "manifest_sha256": manifest_identity,
                "exclusion_snapshot_sha256": snapshot_identity,
                "inventory_high_watermark": inventory_high_watermark,
            },
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise LockedSetStateTransitionError(
            "locked-set preflight authority is missing or invalidated"
        )
    if _current_inventory_high_watermark(connection) != inventory_high_watermark:
        raise LockedSetInventoryChangedError(
            "locked-set exclusion inventory changed after preflight"
        )
    attestation = _attestation_from_row(row)
    snapshot = SqliteLockedSetRepository._load_snapshot(
        connection,
        attestation.exclusion_snapshot_id,
    )
    if (
        snapshot.snapshot_id != snapshot_identity
        or snapshot.inventory_high_watermark != inventory_high_watermark
        or snapshot.snapshot.source_id != attestation.exclusion_source_id
    ):
        raise LockedSetConflictError(
            "locked-set preflight authority has inconsistent exclusion evidence"
        )
    if snapshot.missing_fingerprint_count != 0:
        raise LockedSetInventoryFingerprintIncompleteError(
            "locked-set exclusion inventory fingerprints are incomplete"
        )
    dataset = LockedSetDatasetRecord(
        dataset_id=str(row["dataset_id"]),
        manifest_sha256=str(row["manifest_sha256"]),
        member_identity_sha256=str(row["member_identity_sha256"]),
        state=str(row["state"]),
        record_version=int(row["record_version"]),
        created_by=str(row["created_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )
    eligibility_history = _eligibility_history_from_attestation(attestation)
    return LockedSetPreflightAuthority(
        dataset=dataset,
        attestation=attestation,
        exclusion_snapshot=snapshot,
        eligibility_history=eligibility_history,
    )


class SqliteLockedSetRepository:
    """Persist locked-set authority without storing external absolute paths."""

    def __init__(
        self,
        *,
        runtime: SqliteRuntime,
        failpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.runtime = runtime
        self._failpoint = failpoint

    @staticmethod
    def _load_dataset(
        connection: Connection,
        dataset_id: str,
    ) -> tuple[LockedSetDatasetRecord, str]:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        dataset_id, manifest_sha256, member_identity_sha256,
                        manifest_json, state, record_version, created_by,
                        created_at, updated_at
                    FROM locked_set_datasets
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise LockedSetNotFoundError("locked set does not exist")
        return _dataset_from_row(row), str(row["manifest_json"])

    def get_dataset(self, dataset_id: str) -> LockedSetDatasetRecord:
        identity = _required_text(dataset_id, "dataset_id")
        with self.runtime.engine.connect() as connection:
            dataset, _ = self._load_dataset(connection, identity)
        return dataset

    def get_manifest(self, dataset_id: str) -> LockedSetManifest:
        """Rebuild and verify the sealed manifest without reading external files."""

        identity = _required_text(dataset_id, "dataset_id")
        with self.runtime.engine.connect() as connection:
            dataset, manifest_json = self._load_dataset(connection, identity)
        return self._manifest_from_dataset(dataset, manifest_json)

    @staticmethod
    def _load_candidate_review_source_authority(
        connection: Connection,
        dataset_id: str,
    ) -> LockedSetCandidateReviewSourceAuthorityRecord | None:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        dataset_id, manifest_sha256, seal_sha256,
                        package_sha256, record_set_sha256,
                        review_history_authority_sha256,
                        source_authority_sha256, payload_json, created_at
                    FROM locked_set_candidate_review_source_authority
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return _candidate_review_source_authority_from_row(row)

    def get_candidate_review_source_authority(
        self,
        dataset_id: str,
    ) -> LockedSetCandidateReviewSourceAuthorityRecord:
        """Load and revalidate one immutable candidate-review authority."""

        identity = _required_text(dataset_id, "dataset_id")
        with self.runtime.engine.connect() as connection:
            record = self._load_candidate_review_source_authority(
                connection,
                identity,
            )
        if record is None:
            raise LockedSetNotFoundError("candidate-review source authority does not exist")
        return record

    def register_candidate_review_source_authority(
        self,
        *,
        dataset_id: str,
        manifest_sha256: str,
        seal_sha256: str,
        package_sha256: str,
        record_set_sha256: str,
        review_history_authority_sha256: str,
        source_authority_sha256: str,
        payload: Mapping[str, object],
    ) -> LockedSetCandidateReviewSourceAuthorityRecord:
        """Register one manifest-bound authority or replay identical input."""

        identity = _required_text(dataset_id, "dataset_id")
        manifest_identity = _required_sha256(
            manifest_sha256,
            "manifest_sha256",
        )
        seal_identity = _required_sha256(
            seal_sha256,
            "seal_sha256",
        )
        package_identity = _required_sha256(
            package_sha256,
            "package_sha256",
        )
        record_set_identity = _required_sha256(
            record_set_sha256,
            "record_set_sha256",
        )
        history_identity = _required_sha256(
            review_history_authority_sha256,
            "review_history_authority_sha256",
        )
        source_identity = _required_sha256(
            source_authority_sha256,
            "source_authority_sha256",
        )
        payload_json = _candidate_review_source_authority_payload_json(
            payload,
            dataset_id=identity,
            manifest_sha256=manifest_identity,
            package_sha256=package_identity,
            record_set_sha256=record_set_identity,
            source_authority_sha256=source_identity,
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            dataset, manifest_json = self._load_dataset(
                connection,
                identity,
            )
            manifest = self._manifest_from_dataset(
                dataset,
                manifest_json,
            )
            if (
                dataset.manifest_sha256 != manifest_identity
                or manifest.canonical_sha256 != manifest_identity
            ):
                raise LockedSetConflictError(
                    "candidate-review source authority manifest does not match the locked set"
                )
            existing = self._load_candidate_review_source_authority(
                connection,
                identity,
            )
            if existing is not None:
                if (
                    existing.manifest_sha256 == manifest_identity
                    and existing.seal_sha256 == seal_identity
                    and existing.package_sha256 == package_identity
                    and existing.record_set_sha256 == record_set_identity
                    and existing.review_history_authority_sha256 == history_identity
                    and existing.source_authority_sha256 == source_identity
                    and existing.payload_json == payload_json
                ):
                    return existing
                raise LockedSetConflictError(
                    "locked set already has a different candidate-review source authority"
                )
            connection.execute(
                text(
                    """
                    INSERT INTO
                        locked_set_candidate_review_source_authority (
                            dataset_id, manifest_sha256, seal_sha256,
                            package_sha256, record_set_sha256,
                            review_history_authority_sha256,
                            source_authority_sha256, payload_json,
                            created_at
                        ) VALUES (
                            :dataset_id, :manifest_sha256, :seal_sha256,
                            :package_sha256, :record_set_sha256,
                            :review_history_authority_sha256,
                            :source_authority_sha256, :payload_json,
                            :created_at
                        )
                    """
                ),
                {
                    "dataset_id": identity,
                    "manifest_sha256": manifest_identity,
                    "seal_sha256": seal_identity,
                    "package_sha256": package_identity,
                    "record_set_sha256": record_set_identity,
                    "review_history_authority_sha256": (history_identity),
                    "source_authority_sha256": source_identity,
                    "payload_json": payload_json,
                    "created_at": now,
                },
            )
            created = self._load_candidate_review_source_authority(
                connection,
                identity,
            )
            if created is None:  # pragma: no cover - same transaction
                raise LockedSetPersistenceError(
                    "candidate-review source authority was not persisted"
                )
            return created

    @staticmethod
    def _load_development_authority(
        connection: Connection,
        dataset_id: str,
    ) -> LockedSetDevelopmentAuthorityRecord | None:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        dataset_id, manifest_sha256, authority_sha256,
                        source_exclusion_snapshot_sha256,
                        formal_exclusion_snapshot_sha256,
                        source_inventory_high_watermark,
                        shadow_template_set_fingerprint,
                        payload_json, created_at
                    FROM locked_set_development_authority
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return _development_authority_from_row(row)

    def get_development_authority(
        self,
        dataset_id: str,
    ) -> LockedSetDevelopmentAuthorityRecord:
        """Load one immutable formal development-authority binding."""

        identity = _required_text(dataset_id, "dataset_id")
        with self.runtime.engine.connect() as connection:
            record = self._load_development_authority(
                connection,
                identity,
            )
        if record is None:
            raise LockedSetNotFoundError(
                "formal development authority does not exist"
            )
        return record

    def register_development_authority(
        self,
        *,
        dataset_id: str,
        manifest_sha256: str,
        authority_sha256: str,
        source_exclusion_snapshot_sha256: str,
        formal_exclusion_snapshot_sha256: str,
        source_inventory_high_watermark: int,
        shadow_template_set_fingerprint: str,
        payload: Mapping[str, object],
    ) -> LockedSetDevelopmentAuthorityRecord:
        """Bind one live-verified development authority to a formal dataset."""

        identity = _required_text(dataset_id, "dataset_id")
        manifest_identity = _required_sha256(
            manifest_sha256,
            "manifest_sha256",
        )
        authority_identity = _required_sha256(
            authority_sha256,
            "formal development authority SHA-256",
        )
        source_snapshot_identity = _required_sha256(
            source_exclusion_snapshot_sha256,
            "source exclusion snapshot SHA-256",
        )
        formal_snapshot_identity = _required_sha256(
            formal_exclusion_snapshot_sha256,
            "formal exclusion snapshot SHA-256",
        )
        if (
            isinstance(source_inventory_high_watermark, bool)
            or not isinstance(source_inventory_high_watermark, int)
            or source_inventory_high_watermark < 1
        ):
            raise LockedSetPersistenceError(
                "source inventory high watermark is invalid"
            )
        template_set_identity = _required_sha256(
            shadow_template_set_fingerprint,
            "shadow template-set fingerprint",
        )
        payload_json = _development_authority_payload_json(
            payload,
            authority_sha256=authority_identity,
            source_exclusion_snapshot_sha256=source_snapshot_identity,
            source_inventory_high_watermark=source_inventory_high_watermark,
            shadow_template_set_fingerprint=template_set_identity,
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            dataset, manifest_json = self._load_dataset(
                connection,
                identity,
            )
            manifest = self._manifest_from_dataset(
                dataset,
                manifest_json,
            )
            if (
                dataset.manifest_sha256 != manifest_identity
                or manifest.canonical_sha256 != manifest_identity
            ):
                raise LockedSetConflictError(
                    "formal development authority manifest does not match the locked set"
                )
            attestation = (
                connection.execute(
                    text(
                        """
                        SELECT exclusion_snapshot_sha256
                        FROM locked_set_preflight_attestations
                        WHERE dataset_id = :dataset_id
                        ORDER BY completed_at DESC, attestation_id DESC
                        LIMIT 1
                        """
                    ),
                    {"dataset_id": identity},
                )
                .mappings()
                .one_or_none()
            )
            if (
                attestation is None
                or str(attestation["exclusion_snapshot_sha256"])
                != formal_snapshot_identity
            ):
                raise LockedSetConflictError(
                    "formal development authority does not match preflight exclusions"
                )
            existing = self._load_development_authority(
                connection,
                identity,
            )
            if existing is not None:
                expected = LockedSetDevelopmentAuthorityRecord(
                    dataset_id=identity,
                    manifest_sha256=manifest_identity,
                    authority_sha256=authority_identity,
                    source_exclusion_snapshot_sha256=source_snapshot_identity,
                    formal_exclusion_snapshot_sha256=formal_snapshot_identity,
                    source_inventory_high_watermark=(
                        source_inventory_high_watermark
                    ),
                    shadow_template_set_fingerprint=template_set_identity,
                    payload_json=payload_json,
                    created_at=existing.created_at,
                )
                if existing == expected:
                    return existing
                raise LockedSetConflictError(
                    "locked set already has a different development authority"
                )
            connection.execute(
                text(
                    """
                    INSERT INTO locked_set_development_authority (
                        dataset_id, manifest_sha256, authority_sha256,
                        source_exclusion_snapshot_sha256,
                        formal_exclusion_snapshot_sha256,
                        source_inventory_high_watermark,
                        shadow_template_set_fingerprint,
                        payload_json, created_at
                    ) VALUES (
                        :dataset_id, :manifest_sha256, :authority_sha256,
                        :source_exclusion_snapshot_sha256,
                        :formal_exclusion_snapshot_sha256,
                        :source_inventory_high_watermark,
                        :shadow_template_set_fingerprint,
                        :payload_json, :created_at
                    )
                    """
                ),
                {
                    "dataset_id": identity,
                    "manifest_sha256": manifest_identity,
                    "authority_sha256": authority_identity,
                    "source_exclusion_snapshot_sha256": (
                        source_snapshot_identity
                    ),
                    "formal_exclusion_snapshot_sha256": (
                        formal_snapshot_identity
                    ),
                    "source_inventory_high_watermark": (
                        source_inventory_high_watermark
                    ),
                    "shadow_template_set_fingerprint": template_set_identity,
                    "payload_json": payload_json,
                    "created_at": now,
                },
            )
            created = self._load_development_authority(
                connection,
                identity,
            )
            if created is None:  # pragma: no cover - same transaction
                raise LockedSetPersistenceError(
                    "formal development authority was not persisted"
                )
            return created

    @staticmethod
    def _verify_evidence_membership(
        connection: Connection,
        *,
        dataset_id: str,
        manifest_sha256: str,
        images: tuple[_LockedSetEvidenceMetadata, ...],
    ) -> None:
        expected = {image.image_sha256: image for image in images}
        reference_rows = tuple(
            connection.execute(
                text(
                    """
                    SELECT
                        reference.sha256,
                        reference.role,
                        reference.idempotency_key,
                        reference.released_at,
                        blob.relative_path,
                        blob.byte_size,
                        blob.media_type,
                        blob.storage_state
                    FROM evidence_references AS reference
                    JOIN evidence_blobs AS blob
                      ON blob.sha256 = reference.sha256
                    WHERE reference.owner_kind = 'locked_set_dataset'
                      AND reference.owner_id = :dataset_id
                    ORDER BY reference.sha256
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .all()
        )
        hold_rows = tuple(
            connection.execute(
                text(
                    """
                    SELECT
                        sha256, idempotency_key, released_at
                    FROM evidence_holds
                    WHERE hold_kind = 'locked_set_member'
                      AND owner_id = :dataset_id
                    ORDER BY sha256
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .all()
        )
        if len(reference_rows) != 100 or len(hold_rows) != 100:
            raise LockedSetConflictError("locked-set evidence membership is incomplete")
        reference_hashes = [str(row["sha256"]) for row in reference_rows]
        hold_hashes = [str(row["sha256"]) for row in hold_rows]
        if (
            len(set(reference_hashes)) != 100
            or len(set(hold_hashes)) != 100
            or set(reference_hashes) != set(expected)
            or set(hold_hashes) != set(expected)
        ):
            raise LockedSetConflictError(
                "locked-set evidence membership does not match its sealed manifest"
            )
        for row in reference_rows:
            image = expected[str(row["sha256"])]
            expected_key = f"locked-set-ref:{manifest_sha256}:{image.image_sha256}"
            if (
                str(row["role"]) != "locked_image"
                or str(row["idempotency_key"]) != expected_key
                or row["released_at"] is not None
                or str(row["relative_path"]) != image.storage_relative_path
                or int(row["byte_size"]) != image.byte_size
                or str(row["media_type"]) != image.media_type
                or str(row["storage_state"]) != "available"
            ):
                raise LockedSetConflictError(
                    "locked-set evidence metadata conflicts with durable authority"
                )
        for row in hold_rows:
            image_sha256 = str(row["sha256"])
            expected_key = f"locked-set-hold:{manifest_sha256}:{image_sha256}"
            if str(row["idempotency_key"]) != expected_key or row["released_at"] is not None:
                raise LockedSetConflictError(
                    "locked-set evidence hold conflicts with durable authority"
                )

    def register_evidence_membership(
        self,
        *,
        dataset_id: str,
        manifest_sha256: str,
        images: Sequence[StagedLockedImageEvidenceLike],
    ) -> LockedSetEvidenceMembershipOutcome:
        """Atomically retain the 100 file-verified members of one sealed set."""

        identity = _required_text(dataset_id, "dataset_id")
        manifest_identity = _required_sha256(
            manifest_sha256,
            "manifest_sha256",
        )
        members = _locked_evidence_members(images)
        total_bytes = sum(member.byte_size for member in members)
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            dataset, manifest_json = self._load_dataset(connection, identity)
            manifest = self._manifest_from_dataset(dataset, manifest_json)
            expected_hashes = {
                image.image_sha256 for waybill in manifest.waybills for image in waybill.images
            }
            member_hashes = {member.image_sha256 for member in members}
            if (
                dataset.manifest_sha256 != manifest_identity
                or manifest.canonical_sha256 != manifest_identity
                or len(expected_hashes) != 100
                or member_hashes != expected_hashes
            ):
                raise LockedSetConflictError(
                    "staged evidence does not match the sealed locked-set manifest"
                )
            preflight = (
                connection.execute(
                    text(
                        """
                        SELECT image_count, total_bytes
                        FROM locked_set_preflight_attestations
                        WHERE dataset_id = :dataset_id
                          AND manifest_sha256 = :manifest_sha256
                        """
                    ),
                    {
                        "dataset_id": identity,
                        "manifest_sha256": manifest_identity,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if (
                preflight is None
                or int(preflight["image_count"]) != 100
                or int(preflight["total_bytes"]) != total_bytes
            ):
                raise LockedSetConflictError(
                    "staged evidence metadata does not match locked-set preflight"
                )

            existing_references = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM evidence_references
                        WHERE owner_kind = 'locked_set_dataset'
                          AND owner_id = :dataset_id
                        """
                    ),
                    {"dataset_id": identity},
                ).scalar_one()
            )
            existing_holds = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM evidence_holds
                        WHERE hold_kind = 'locked_set_member'
                          AND owner_id = :dataset_id
                        """
                    ),
                    {"dataset_id": identity},
                ).scalar_one()
            )
            if existing_references or existing_holds:
                self._verify_evidence_membership(
                    connection,
                    dataset_id=identity,
                    manifest_sha256=manifest_identity,
                    images=members,
                )
                return LockedSetEvidenceMembershipOutcome(
                    dataset_id=identity,
                    manifest_sha256=manifest_identity,
                    image_count=100,
                    total_bytes=total_bytes,
                    applied=False,
                )
            if dataset.state != "preflight_passed":
                raise LockedSetStateTransitionError(
                    "locked-set evidence can be registered only after preflight"
                )

            for member in members:
                connection.execute(
                    text(
                        """
                        INSERT OR IGNORE INTO evidence_blobs (
                            sha256, relative_path, byte_size, media_type,
                            storage_state, record_version, created_at,
                            verified_at
                        ) VALUES (
                            :sha256, :relative_path, :byte_size, :media_type,
                            'available', 1, :created_at, :verified_at
                        )
                        """
                    ),
                    {
                        "sha256": member.image_sha256,
                        "relative_path": member.storage_relative_path,
                        "byte_size": member.byte_size,
                        "media_type": member.media_type,
                        "created_at": now,
                        "verified_at": now,
                    },
                )
                blob = (
                    connection.execute(
                        text(
                            """
                            SELECT
                                relative_path, byte_size, media_type,
                                storage_state
                            FROM evidence_blobs
                            WHERE sha256 = :sha256
                            """
                        ),
                        {"sha256": member.image_sha256},
                    )
                    .mappings()
                    .one()
                )
                if (
                    str(blob["relative_path"]) != member.storage_relative_path
                    or int(blob["byte_size"]) != member.byte_size
                    or str(blob["media_type"]) != member.media_type
                    or str(blob["storage_state"]) != "available"
                ):
                    raise LockedSetConflictError(
                        "existing evidence metadata conflicts with locked-set staging"
                    )
                active_cleanup = connection.execute(
                    text(
                        """
                        SELECT claim_id
                        FROM evidence_cleanup_claims
                        WHERE sha256 = :sha256
                          AND status = 'active'
                        """
                    ),
                    {"sha256": member.image_sha256},
                ).scalar_one_or_none()
                if active_cleanup is not None:
                    raise LockedSetConflictError("cleanup already owns locked-set evidence")

                reference_key = f"locked-set-ref:{manifest_identity}:{member.image_sha256}"
                hold_key = f"locked-set-hold:{manifest_identity}:{member.image_sha256}"
                connection.execute(
                    text(
                        """
                        INSERT INTO evidence_references (
                            reference_id, sha256, snapshot_id,
                            owner_kind, owner_id, role,
                            idempotency_key, record_version, created_at
                        ) VALUES (
                            :reference_id, :sha256, NULL,
                            'locked_set_dataset', :owner_id, 'locked_image',
                            :idempotency_key, 1, :created_at
                        )
                        """
                    ),
                    {
                        "reference_id": uuid4().hex,
                        "sha256": member.image_sha256,
                        "owner_id": identity,
                        "idempotency_key": reference_key,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO evidence_holds (
                            hold_id, sha256, hold_kind, owner_id, reason,
                            idempotency_key, record_version, created_at
                        ) VALUES (
                            :hold_id, :sha256, 'locked_set_member',
                            :owner_id, :reason, :idempotency_key, 1,
                            :created_at
                        )
                        """
                    ),
                    {
                        "hold_id": uuid4().hex,
                        "sha256": member.image_sha256,
                        "owner_id": identity,
                        "reason": ("Retain locked-set evidence for audit and recovery"),
                        "idempotency_key": hold_key,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        UPDATE evidence_blobs
                        SET record_version = record_version + 2
                        WHERE sha256 = :sha256
                        """
                    ),
                    {"sha256": member.image_sha256},
                )
                if self._failpoint is not None:
                    self._failpoint("after_locked_set_evidence_member")

            self._verify_evidence_membership(
                connection,
                dataset_id=identity,
                manifest_sha256=manifest_identity,
                images=members,
            )
            return LockedSetEvidenceMembershipOutcome(
                dataset_id=identity,
                manifest_sha256=manifest_identity,
                image_count=100,
                total_bytes=total_bytes,
                applied=True,
            )

    @staticmethod
    def _verify_development_exclusion_import(
        connection: Connection,
        *,
        source_authority_sha256: str,
        images: tuple[DevelopmentExclusionEvidence, ...],
        waybill_identity_sha256s: tuple[str, ...],
    ) -> None:
        expected_authority_rows = {
            ("development_image", image.image_sha256) for image in images
        } | {("prior_waybill_identity", identity) for identity in waybill_identity_sha256s}
        authority_rows = tuple(
            connection.execute(
                text(
                    """
                    SELECT
                        category, identity_sha256,
                        perceptual_fingerprint_json,
                        fingerprint_sha256, algorithm_version
                    FROM locked_set_exclusion_inventory
                    WHERE source_kind = :source_kind
                      AND source_id = :source_id
                    ORDER BY category, identity_sha256
                    """
                ),
                {
                    "source_kind": (_DEVELOPMENT_IMPORT_SOURCE_KIND),
                    "source_id": source_authority_sha256,
                },
            )
            .mappings()
            .all()
        )
        if (
            {
                (
                    str(row["category"]),
                    str(row["identity_sha256"]),
                )
                for row in authority_rows
            }
            != expected_authority_rows
            or len(authority_rows) != len(expected_authority_rows)
            or any(
                row["perceptual_fingerprint_json"] is not None
                or row["fingerprint_sha256"] is not None
                or row["algorithm_version"] is not None
                for row in authority_rows
            )
        ):
            raise LockedSetConflictError(
                "development exclusion import authority is partial or inconsistent"
            )

        expected_holds = {
            image.image_sha256: (
                f"development-exclusion:{source_authority_sha256}:{image.image_sha256}"
            )
            for image in images
        }
        hold_rows = tuple(
            connection.execute(
                text(
                    """
                    SELECT
                        sha256, idempotency_key, released_at
                    FROM evidence_holds
                    WHERE hold_kind = :hold_kind
                      AND owner_id = :owner_id
                    ORDER BY sha256
                    """
                ),
                {
                    "hold_kind": _DEVELOPMENT_IMPORT_HOLD_KIND,
                    "owner_id": source_authority_sha256,
                },
            )
            .mappings()
            .all()
        )
        if (
            len(hold_rows) != len(expected_holds)
            or {str(row["sha256"]) for row in hold_rows} != set(expected_holds)
            or any(
                str(row["idempotency_key"]) != expected_holds[str(row["sha256"])]
                or row["released_at"] is not None
                for row in hold_rows
            )
        ):
            raise LockedSetConflictError(
                "development exclusion import holds are partial or inconsistent"
            )

        for image in images:
            blob = (
                connection.execute(
                    text(
                        """
                        SELECT
                            relative_path, byte_size, media_type,
                            storage_state
                        FROM evidence_blobs
                        WHERE sha256 = :sha256
                        """
                    ),
                    {"sha256": image.image_sha256},
                )
                .mappings()
                .one_or_none()
            )
            if (
                blob is None
                or str(blob["relative_path"]) != image.storage_relative_path
                or int(blob["byte_size"]) != image.byte_size
                or str(blob["media_type"]) != image.media_type
                or str(blob["storage_state"]) != "available"
            ):
                raise LockedSetConflictError(
                    "development exclusion evidence metadata is inconsistent"
                )
            fingerprint_payload = _image_fingerprint_payload(image.perceptual_fingerprint)
            fingerprint_json = _canonical_json(fingerprint_payload)
            fingerprint_sha256 = hashlib.sha256(fingerprint_json.encode("utf-8")).hexdigest()
            fingerprint_row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            perceptual_fingerprint_json,
                            fingerprint_sha256, algorithm_version
                        FROM locked_set_exclusion_inventory
                        WHERE category = 'development_image'
                          AND identity_sha256 = :identity_sha256
                          AND source_kind = :source_kind
                          AND source_id = :source_id
                        """
                    ),
                    {
                        "identity_sha256": image.image_sha256,
                        "source_kind": (_CODE_OWNED_FINGERPRINT_SOURCE_KIND),
                        "source_id": fingerprint_sha256,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if (
                fingerprint_row is None
                or str(fingerprint_row["perceptual_fingerprint_json"]) != fingerprint_json
                or str(fingerprint_row["fingerprint_sha256"]) != fingerprint_sha256
                or str(fingerprint_row["algorithm_version"])
                != image.perceptual_fingerprint.algorithm_version
            ):
                raise LockedSetConflictError(
                    "development exclusion fingerprint authority is inconsistent"
                )
            active_cleanup = connection.execute(
                text(
                    """
                    SELECT claim_id
                    FROM evidence_cleanup_claims
                    WHERE sha256 = :sha256
                      AND status = 'active'
                    """
                ),
                {"sha256": image.image_sha256},
            ).scalar_one_or_none()
            if active_cleanup is not None:
                raise LockedSetConflictError("cleanup already owns development exclusion evidence")

    def import_development_exclusions(
        self,
        *,
        source_authority_sha256: str,
        images: Sequence[DevelopmentExclusionEvidence],
        waybill_identity_sha256s: Sequence[str],
    ) -> DevelopmentExclusionImportOutcome:
        """Atomically import one fully verified development exclusion set."""

        authority = _required_sha256(
            source_authority_sha256,
            "development exclusion source authority SHA-256",
        )
        members = _development_exclusion_members(images)
        waybill_identities = _development_waybill_identities(waybill_identity_sha256s)
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            existing_authority_count = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM locked_set_exclusion_inventory
                        WHERE source_kind = :source_kind
                          AND source_id = :source_id
                        """
                    ),
                    {
                        "source_kind": (_DEVELOPMENT_IMPORT_SOURCE_KIND),
                        "source_id": authority,
                    },
                ).scalar_one()
            )
            existing_hold_count = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM evidence_holds
                        WHERE hold_kind = :hold_kind
                          AND owner_id = :owner_id
                        """
                    ),
                    {
                        "hold_kind": (_DEVELOPMENT_IMPORT_HOLD_KIND),
                        "owner_id": authority,
                    },
                ).scalar_one()
            )
            if existing_authority_count:
                self._verify_development_exclusion_import(
                    connection,
                    source_authority_sha256=authority,
                    images=members,
                    waybill_identity_sha256s=waybill_identities,
                )
                return DevelopmentExclusionImportOutcome(
                    source_authority_sha256=authority,
                    development_image_count=len(members),
                    prior_waybill_identity_count=len(waybill_identities),
                    applied=False,
                )
            if existing_hold_count:
                raise LockedSetConflictError(
                    "development exclusion import holds exist without authority"
                )

            for image in members:
                connection.execute(
                    text(
                        """
                        INSERT OR IGNORE INTO evidence_blobs (
                            sha256, relative_path, byte_size,
                            media_type, storage_state,
                            record_version, created_at, verified_at
                        ) VALUES (
                            :sha256, :relative_path, :byte_size,
                            :media_type, 'available',
                            1, :created_at, :verified_at
                        )
                        """
                    ),
                    {
                        "sha256": image.image_sha256,
                        "relative_path": (image.storage_relative_path),
                        "byte_size": image.byte_size,
                        "media_type": image.media_type,
                        "created_at": now,
                        "verified_at": now,
                    },
                )
                blob = (
                    connection.execute(
                        text(
                            """
                            SELECT
                                relative_path, byte_size, media_type,
                                storage_state
                            FROM evidence_blobs
                            WHERE sha256 = :sha256
                            """
                        ),
                        {"sha256": image.image_sha256},
                    )
                    .mappings()
                    .one()
                )
                if (
                    str(blob["relative_path"]) != image.storage_relative_path
                    or int(blob["byte_size"]) != image.byte_size
                    or str(blob["media_type"]) != image.media_type
                    or str(blob["storage_state"]) != "available"
                ):
                    raise LockedSetConflictError(
                        "existing evidence metadata conflicts with development import"
                    )
                active_cleanup = connection.execute(
                    text(
                        """
                        SELECT claim_id
                        FROM evidence_cleanup_claims
                        WHERE sha256 = :sha256
                          AND status = 'active'
                        """
                    ),
                    {"sha256": image.image_sha256},
                ).scalar_one_or_none()
                if active_cleanup is not None:
                    raise LockedSetConflictError(
                        "cleanup already owns development exclusion evidence"
                    )

                inserted_authority = register_exclusion_identity(
                    connection,
                    category="development_image",
                    identity_sha256=image.image_sha256,
                    source_kind=(_DEVELOPMENT_IMPORT_SOURCE_KIND),
                    source_id=authority,
                    created_at=now,
                )
                if not inserted_authority:
                    raise LockedSetConflictError(
                        "development exclusion import authority appeared during commit"
                    )

                fingerprint_payload = _image_fingerprint_payload(image.perceptual_fingerprint)
                fingerprint_json = _canonical_json(fingerprint_payload)
                fingerprint_sha256 = hashlib.sha256(fingerprint_json.encode("utf-8")).hexdigest()
                register_exclusion_identity(
                    connection,
                    category="development_image",
                    identity_sha256=image.image_sha256,
                    source_kind=(_CODE_OWNED_FINGERPRINT_SOURCE_KIND),
                    source_id=fingerprint_sha256,
                    created_at=now,
                    perceptual_fingerprint_json=fingerprint_json,
                    fingerprint_sha256=fingerprint_sha256,
                    algorithm_version=(image.perceptual_fingerprint.algorithm_version),
                )

                hold_key = f"development-exclusion:{authority}:{image.image_sha256}"
                connection.execute(
                    text(
                        """
                        INSERT INTO evidence_holds (
                            hold_id, sha256, hold_kind, owner_id,
                            reason, idempotency_key,
                            record_version, created_at
                        ) VALUES (
                            :hold_id, :sha256, :hold_kind,
                            :owner_id, :reason, :idempotency_key,
                            1, :created_at
                        )
                        """
                    ),
                    {
                        "hold_id": uuid4().hex,
                        "sha256": image.image_sha256,
                        "hold_kind": (_DEVELOPMENT_IMPORT_HOLD_KIND),
                        "owner_id": authority,
                        "reason": (
                            "Retain development evidence for "
                            "dataset isolation and similarity checks"
                        ),
                        "idempotency_key": hold_key,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        UPDATE evidence_blobs
                        SET record_version = record_version + 1
                        WHERE sha256 = :sha256
                        """
                    ),
                    {"sha256": image.image_sha256},
                )
                if self._failpoint is not None:
                    self._failpoint("after_development_exclusion_image")

            for waybill_identity in waybill_identities:
                inserted_waybill = register_exclusion_identity(
                    connection,
                    category="prior_waybill_identity",
                    identity_sha256=waybill_identity,
                    source_kind=(_DEVELOPMENT_IMPORT_SOURCE_KIND),
                    source_id=authority,
                    created_at=now,
                )
                if not inserted_waybill:
                    raise LockedSetConflictError(
                        "development waybill authority appeared during commit"
                    )
            if self._failpoint is not None:
                self._failpoint("after_development_exclusion_waybills")
            self._verify_development_exclusion_import(
                connection,
                source_authority_sha256=authority,
                images=members,
                waybill_identity_sha256s=waybill_identities,
            )
            return DevelopmentExclusionImportOutcome(
                source_authority_sha256=authority,
                development_image_count=len(members),
                prior_waybill_identity_count=len(waybill_identities),
                applied=True,
            )

    def import_formal_development_exclusions(
        self,
        *,
        authority_sha256: str,
        exclusion_snapshot: LockedSetExclusionSnapshot,
        perceptual_fingerprints: Sequence[PersistedPerceptualFingerprint],
    ) -> PersistedExclusionSnapshot:
        """Atomically materialize a sealed development authority in a fresh root."""

        authority = _required_sha256(
            authority_sha256,
            "formal development authority SHA-256",
        )
        if not isinstance(exclusion_snapshot, LockedSetExclusionSnapshot):
            raise LockedSetPersistenceError("formal development exclusion snapshot is invalid")
        categories: dict[str, frozenset[str]] = {
            "template_reference_image": (exclusion_snapshot.template_reference_image_hashes),
            "development_image": exclusion_snapshot.development_image_hashes,
            "calibration_image": exclusion_snapshot.calibration_image_hashes,
            "shadow_image": exclusion_snapshot.shadow_image_hashes,
            "prior_locked_image": exclusion_snapshot.prior_locked_image_hashes,
            "prior_waybill_identity": (exclusion_snapshot.prior_waybill_identity_hashes),
        }
        image_identities = frozenset(
            categories["template_reference_image"]
            | categories["development_image"]
            | categories["calibration_image"]
            | categories["shadow_image"]
            | categories["prior_locked_image"]
        )
        if not image_identities or not categories["prior_waybill_identity"]:
            raise LockedSetPersistenceError(
                "formal development authority exclusions must be non-empty"
            )
        fingerprints = tuple(
            sorted(
                perceptual_fingerprints,
                key=lambda item: item.content_sha256,
            )
        )
        if (
            len(fingerprints) != len(image_identities)
            or {item.content_sha256 for item in fingerprints} != image_identities
        ):
            raise LockedSetPersistenceError(
                "formal development authority fingerprints are incomplete"
            )
        validated_fingerprints: dict[
            str,
            tuple[str, str, str],
        ] = {}
        for persisted in fingerprints:
            fingerprint = persisted.to_image_fingerprint()
            payload_json = _canonical_json(_image_fingerprint_payload(fingerprint))
            fingerprint_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            if (
                persisted.perceptual_fingerprint_json != payload_json
                or persisted.fingerprint_sha256 != fingerprint_sha256
                or persisted.algorithm_version != fingerprint.algorithm_version
            ):
                raise LockedSetPersistenceError("formal development authority fingerprint changed")
            validated_fingerprints[persisted.content_sha256] = (
                payload_json,
                fingerprint_sha256,
                fingerprint.algorithm_version,
            )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            existing_rows = tuple(
                connection.execute(
                    text(
                        """
                        SELECT
                            category, identity_sha256, source_kind,
                            source_id, perceptual_fingerprint_json,
                            fingerprint_sha256, algorithm_version
                        FROM locked_set_exclusion_inventory
                        ORDER BY entry_sequence
                        """
                    )
                )
                .mappings()
                .all()
            )
            if existing_rows:
                authority_rows = tuple(
                    row
                    for row in existing_rows
                    if str(row["source_kind"]) == _FORMAL_AUTHORITY_SOURCE_KIND
                )
                fingerprint_rows = tuple(
                    row
                    for row in existing_rows
                    if str(row["source_kind"]) == _FORMAL_AUTHORITY_FINGERPRINT_KIND
                )
                observed_categories = {
                    category: {
                        str(row["identity_sha256"])
                        for row in authority_rows
                        if str(row["category"]) == category
                    }
                    for category in EXCLUSION_CATEGORIES
                }
                observed_fingerprints = {
                    str(row["identity_sha256"]): (
                        str(row["perceptual_fingerprint_json"]),
                        str(row["fingerprint_sha256"]),
                        str(row["algorithm_version"]),
                    )
                    for row in fingerprint_rows
                }
                if (
                    len(authority_rows)
                    != sum(len(identities) for identities in categories.values())
                    or len(fingerprint_rows) != len(image_identities)
                    or len(existing_rows)
                    != len(authority_rows) + len(fingerprint_rows)
                    or any(str(row["source_id"]) != authority for row in authority_rows)
                    or observed_categories
                    != {
                        category: set(identities)
                        for category, identities in categories.items()
                    }
                    or observed_fingerprints != validated_fingerprints
                    or any(
                        str(row["source_id"]) != str(row["fingerprint_sha256"])
                        for row in fingerprint_rows
                    )
                ):
                    raise LockedSetConflictError(
                        "formal data root contains a partial or different exclusion authority"
                    )
            else:
                for category, identities in sorted(categories.items()):
                    for identity in sorted(identities):
                        inserted = register_exclusion_identity(
                            connection,
                            category=category,
                            identity_sha256=identity,
                            source_kind=_FORMAL_AUTHORITY_SOURCE_KIND,
                            source_id=authority,
                            created_at=now,
                        )
                        if not inserted:  # pragma: no cover - empty transaction
                            raise LockedSetConflictError(
                                "formal development exclusion appeared during import"
                            )
                        if self._failpoint is not None:
                            self._failpoint("after_formal_authority_exclusion")
                for identity, (
                    fingerprint_json,
                    fingerprint_sha256,
                    algorithm_version,
                ) in sorted(validated_fingerprints.items()):
                    fingerprint_category = next(
                        category
                        for category in (
                            "template_reference_image",
                            "development_image",
                            "calibration_image",
                            "shadow_image",
                            "prior_locked_image",
                        )
                        if identity in categories[category]
                    )
                    inserted = register_exclusion_identity(
                        connection,
                        category=fingerprint_category,
                        identity_sha256=identity,
                        source_kind=_FORMAL_AUTHORITY_FINGERPRINT_KIND,
                        source_id=fingerprint_sha256,
                        created_at=now,
                        perceptual_fingerprint_json=fingerprint_json,
                        fingerprint_sha256=fingerprint_sha256,
                        algorithm_version=algorithm_version,
                    )
                    if not inserted:  # pragma: no cover - empty transaction
                        raise LockedSetConflictError(
                            "formal development fingerprint appeared during import"
                        )
                    if self._failpoint is not None:
                        self._failpoint("after_formal_authority_fingerprint")
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT category, identity_sha256
                        FROM locked_set_exclusion_inventory
                        GROUP BY category, identity_sha256
                        ORDER BY category, identity_sha256
                        """
                    )
                )
                .mappings()
                .all()
            )
            observed = {
                category: {
                    str(row["identity_sha256"]) for row in rows if str(row["category"]) == category
                }
                for category in EXCLUSION_CATEGORIES
            }
            if any(
                observed[category] != set(identities) for category, identities in categories.items()
            ):
                raise LockedSetConflictError(
                    "formal development exclusion import does not reconcile"
                )
        return self.build_exclusion_snapshot()

    @staticmethod
    def _manifest_from_dataset(
        dataset: LockedSetDatasetRecord,
        manifest_json: str,
    ) -> LockedSetManifest:
        try:
            payload = json.loads(manifest_json)
        except json.JSONDecodeError as exc:
            raise LockedSetPersistenceError("sealed locked-set manifest JSON is invalid") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise LockedSetPersistenceError("sealed locked-set manifest schema is invalid")
        raw_waybills = payload.get("waybills")
        if not isinstance(raw_waybills, list):
            raise LockedSetPersistenceError("sealed locked-set manifest waybills are invalid")
        waybills: list[LockedWaybill] = []
        seen_images: set[str] = set()
        seen_waybills: set[str] = set()
        for raw_waybill in raw_waybills:
            if not isinstance(raw_waybill, Mapping):
                raise LockedSetPersistenceError("sealed locked-set waybill is invalid")
            sample_id = _required_text(
                str(raw_waybill.get("sample_id", "")),
                "sample_id",
            )
            waybill_identity = _required_sha256(
                str(raw_waybill.get("waybill_identity_sha256", "")),
                "waybill_identity_sha256",
            )
            if sample_id in seen_waybills or waybill_identity in seen_waybills:
                raise LockedSetPersistenceError("sealed locked-set waybill identity is duplicated")
            seen_waybills.update((sample_id, waybill_identity))
            raw_images = raw_waybill.get("images")
            if not isinstance(raw_images, list) or len(raw_images) != 2:
                raise LockedSetPersistenceError("sealed locked-set waybill images are invalid")
            images: list[LockedTicketImage] = []
            for raw_image in raw_images:
                if not isinstance(raw_image, Mapping):
                    raise LockedSetPersistenceError("sealed locked-set image is invalid")
                image_sha256 = _required_sha256(
                    str(raw_image.get("image_sha256", "")),
                    "image_sha256",
                )
                if image_sha256 in seen_images:
                    raise LockedSetPersistenceError("sealed locked-set image is duplicated")
                seen_images.add(image_sha256)
                try:
                    slot = TicketSlot(
                        _required_text(
                            str(raw_image.get("submitted_slot", "")),
                            "submitted_slot",
                            maximum=20,
                        )
                    )
                    role = TicketRole(
                        _required_text(
                            str(raw_image.get("role", "")),
                            "role",
                            maximum=20,
                        )
                    )
                except ValueError as exc:
                    raise LockedSetPersistenceError(
                        "sealed locked-set image role or slot is invalid"
                    ) from exc
                raw_ordinary_net = raw_image.get("ordinary_net")
                ordinary_net: Decimal | None
                if raw_ordinary_net is None:
                    ordinary_net = None
                elif isinstance(raw_ordinary_net, str):
                    try:
                        ordinary_net = Decimal(raw_ordinary_net)
                    except InvalidOperation as exc:
                        raise LockedSetPersistenceError(
                            "sealed locked-set ordinary net is invalid"
                        ) from exc
                    if (
                        not ordinary_net.is_finite()
                        or ordinary_net <= 0
                        or ordinary_net.as_tuple().exponent != -2
                    ):
                        raise LockedSetPersistenceError("sealed locked-set ordinary net is invalid")
                else:
                    raise LockedSetPersistenceError("sealed locked-set ordinary net is invalid")
                relative_path = _required_text(
                    str(raw_image.get("relative_path", "")),
                    "relative_path",
                    maximum=500,
                )
                images.append(
                    LockedTicketImage(
                        image_sha256=image_sha256,
                        relative_path=relative_path,
                        slot=slot,
                        role=role,
                        ordinary_net=ordinary_net,
                    )
                )
            if {image.slot for image in images} != {
                TicketSlot.LOADING,
                TicketSlot.UNLOADING,
            }:
                raise LockedSetPersistenceError("sealed locked-set submitted slots are invalid")
            waybills.append(
                LockedWaybill(
                    sample_id=sample_id,
                    waybill_identity_sha256=waybill_identity,
                    images=cast(
                        tuple[LockedTicketImage, LockedTicketImage],
                        tuple(images),
                    ),
                )
            )
        manifest = LockedSetManifest(
            dataset_id=_required_text(
                str(payload.get("dataset_id", "")),
                "dataset_id",
            ),
            dataset_kind=str(payload.get("dataset_kind", "")),
            tuning_prohibited=payload.get("tuning_prohibited") is True,
            waybills=tuple(waybills),
        )
        if (
            manifest.dataset_id != dataset.dataset_id
            or manifest.dataset_kind != "locked"
            or manifest.tuning_prohibited is not True
            or manifest.waybill_count != 50
            or manifest.image_count != 100
            or _canonical_json(_manifest_payload(manifest)) != manifest_json
            or manifest.canonical_sha256 != dataset.manifest_sha256
            or _canonical_sha256(_member_identity_payload(manifest))
            != dataset.member_identity_sha256
        ):
            raise LockedSetConflictError("sealed locked-set manifest authority is inconsistent")
        return manifest

    def list_unfingerprinted_exclusion_images(
        self,
    ) -> tuple[UnfingerprintedExclusionImage, ...]:
        """List only evidence-backed image exclusions needing fingerprints."""

        with self.runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT DISTINCT
                            inventory.category,
                            inventory.identity_sha256,
                            evidence.relative_path,
                            evidence.storage_state
                        FROM locked_set_exclusion_inventory AS inventory
                        LEFT JOIN evidence_blobs AS evidence
                          ON evidence.sha256 = inventory.identity_sha256
                        WHERE inventory.category != 'prior_waybill_identity'
                          AND NOT EXISTS (
                              SELECT 1
                              FROM locked_set_exclusion_inventory AS fingerprint
                              WHERE fingerprint.identity_sha256 =
                                    inventory.identity_sha256
                                AND fingerprint.perceptual_fingerprint_json
                                    IS NOT NULL
                          )
                        ORDER BY
                            inventory.category,
                            inventory.identity_sha256
                        """
                    )
                )
                .mappings()
                .all()
            )
        missing_evidence = [
            row
            for row in rows
            if row["relative_path"] is None or str(row["storage_state"]) != "available"
        ]
        if missing_evidence:
            raise LockedSetInventoryEvidenceMissingError(
                "an image exclusion has no available evidence blob"
            )
        return tuple(
            UnfingerprintedExclusionImage(
                category=str(row["category"]),
                sha256=str(row["identity_sha256"]),
                relative_path=str(row["relative_path"]),
            )
            for row in rows
        )

    def register_exclusion_fingerprint(
        self,
        *,
        category: str,
        identity_sha256: str,
        fingerprint: ImagePerceptualFingerprint,
    ) -> bool:
        """Append one code-owned fingerprint after bytes were read outside SQL."""

        if category not in EXCLUSION_CATEGORIES or category == ("prior_waybill_identity"):
            raise LockedSetPersistenceError("fingerprint exclusion category is invalid")
        identity = _required_sha256(identity_sha256, "identity_sha256")
        payload = _image_fingerprint_payload(fingerprint)
        if fingerprint.content_sha256 != identity:
            raise LockedSetPersistenceError("fingerprint content does not match exclusion identity")
        payload_json = _canonical_json(payload)
        fingerprint_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            inventory_exists = connection.execute(
                text(
                    """
                    SELECT 1
                    FROM locked_set_exclusion_inventory
                    WHERE category = :category
                      AND identity_sha256 = :identity_sha256
                    LIMIT 1
                    """
                ),
                {
                    "category": category,
                    "identity_sha256": identity,
                },
            ).scalar_one_or_none()
            evidence_exists = connection.execute(
                text(
                    """
                    SELECT 1
                    FROM evidence_blobs
                    WHERE sha256 = :identity_sha256
                      AND storage_state = 'available'
                    """
                ),
                {"identity_sha256": identity},
            ).scalar_one_or_none()
            if inventory_exists is None or evidence_exists is None:
                raise LockedSetInventoryEvidenceMissingError(
                    "fingerprint requires an evidence-backed exclusion"
                )
            return register_exclusion_identity(
                connection,
                category=category,
                identity_sha256=identity,
                source_kind="code_owned_perceptual_fingerprint",
                source_id=fingerprint_sha256,
                created_at=now,
                perceptual_fingerprint_json=payload_json,
                fingerprint_sha256=fingerprint_sha256,
                algorithm_version=fingerprint.algorithm_version,
            )

    @staticmethod
    def _snapshot_from_row(row: RowMapping) -> PersistedExclusionSnapshot:
        try:
            payload = json.loads(str(row["payload_json"]))
        except json.JSONDecodeError as exc:
            raise LockedSetPersistenceError("persisted exclusion snapshot is invalid") from exc
        if not isinstance(payload, dict):
            raise LockedSetPersistenceError("persisted exclusion snapshot must be an object")
        snapshot = LockedSetExclusionSnapshot.create(
            source_id=str(payload.get("source_id", "")),
            template_reference_image_hashes=set(
                cast(list[str], payload.get("template_reference_image_hashes", []))
            ),
            development_image_hashes=set(
                cast(list[str], payload.get("development_image_hashes", []))
            ),
            calibration_image_hashes=set(
                cast(list[str], payload.get("calibration_image_hashes", []))
            ),
            shadow_image_hashes=set(cast(list[str], payload.get("shadow_image_hashes", []))),
            prior_locked_image_hashes=set(
                cast(list[str], payload.get("prior_locked_image_hashes", []))
            ),
            prior_waybill_identity_hashes=set(
                cast(list[str], payload.get("prior_waybill_identity_hashes", []))
            ),
        )
        if snapshot.canonical_sha256 != str(
            row["canonical_sha256"]
        ) or snapshot.canonical_sha256 != str(row["snapshot_id"]):
            raise LockedSetPersistenceError("persisted exclusion snapshot hash is inconsistent")
        raw_fingerprints = payload.get("perceptual_fingerprints")
        raw_versions = payload.get("fingerprint_algorithm_versions")
        if not isinstance(raw_fingerprints, list) or not isinstance(
            raw_versions,
            list,
        ):
            raise LockedSetPersistenceError("persisted fingerprint inventory is invalid")
        fingerprints: list[PersistedPerceptualFingerprint] = []
        for raw in raw_fingerprints:
            if not isinstance(raw, dict):
                raise LockedSetPersistenceError("persisted fingerprint inventory is invalid")
            content_sha256 = _required_sha256(
                str(raw.get("content_sha256", "")),
                "fingerprint content_sha256",
            )
            fingerprint_json = str(raw.get("perceptual_fingerprint_json", ""))
            fingerprint_sha256 = _required_sha256(
                str(raw.get("fingerprint_sha256", "")),
                "fingerprint_sha256",
            )
            algorithm_version = _required_text(
                str(raw.get("algorithm_version", "")),
                "algorithm_version",
                maximum=100,
            )
            if hashlib.sha256(fingerprint_json.encode("utf-8")).hexdigest() != fingerprint_sha256:
                raise LockedSetPersistenceError("persisted fingerprint hash is inconsistent")
            try:
                fingerprint_payload = json.loads(fingerprint_json)
            except json.JSONDecodeError as exc:
                raise LockedSetPersistenceError("persisted fingerprint JSON is invalid") from exc
            if _canonical_json(fingerprint_payload) != fingerprint_json:
                raise LockedSetPersistenceError("persisted fingerprint JSON is not canonical")
            persisted_fingerprint = PersistedPerceptualFingerprint(
                content_sha256=content_sha256,
                perceptual_fingerprint_json=fingerprint_json,
                fingerprint_sha256=fingerprint_sha256,
                algorithm_version=algorithm_version,
            )
            persisted_fingerprint.to_image_fingerprint()
            fingerprints.append(persisted_fingerprint)
        inventory_image_count = int(row["inventory_image_count"])
        fingerprinted_image_count = int(row["fingerprinted_image_count"])
        missing_fingerprint_count = int(row["missing_fingerprint_count"])
        versions = tuple(str(value) for value in raw_versions)
        if (
            len(fingerprints) != fingerprinted_image_count
            or fingerprinted_image_count + missing_fingerprint_count != inventory_image_count
            or versions != tuple(sorted(set(versions)))
            or str(row["fingerprint_algorithm_versions_json"]) != _canonical_json(list(versions))
        ):
            raise LockedSetPersistenceError("persisted fingerprint completeness is inconsistent")
        return PersistedExclusionSnapshot(
            snapshot_id=str(row["snapshot_id"]),
            inventory_high_watermark=int(row["inventory_high_watermark"]),
            snapshot=snapshot,
            inventory_image_count=inventory_image_count,
            fingerprinted_image_count=fingerprinted_image_count,
            missing_fingerprint_count=missing_fingerprint_count,
            fingerprint_algorithm_versions=versions,
            perceptual_fingerprints=tuple(fingerprints),
            created_at=str(row["created_at"]),
        )

    @classmethod
    def _load_snapshot(
        cls,
        connection: Connection,
        snapshot_id: str,
    ) -> PersistedExclusionSnapshot:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        snapshot_id, inventory_high_watermark,
                        payload_json, canonical_sha256,
                        inventory_image_count, fingerprinted_image_count,
                        missing_fingerprint_count,
                        fingerprint_algorithm_versions_json, created_at
                    FROM locked_set_exclusion_snapshots
                    WHERE snapshot_id = :snapshot_id
                    """
                ),
                {"snapshot_id": snapshot_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise LockedSetNotFoundError("locked-set exclusion snapshot does not exist")
        return cls._snapshot_from_row(row)

    def build_exclusion_snapshot(self) -> PersistedExclusionSnapshot:
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT
                            category, identity_sha256, source_kind, source_id,
                            perceptual_fingerprint_json, fingerprint_sha256,
                            algorithm_version
                        FROM locked_set_exclusion_inventory
                        ORDER BY category, identity_sha256, entry_sequence
                        """
                    )
                )
                .mappings()
                .all()
            )
            identities: dict[str, set[str]] = {category: set() for category in EXCLUSION_CATEGORIES}
            fingerprint_by_image: dict[
                str,
                PersistedPerceptualFingerprint,
            ] = {}
            digest_rows: list[dict[str, object]] = []
            for row in rows:
                category = str(row["category"])
                image_identity = str(row["identity_sha256"])
                identities[category].add(image_identity)
                fingerprint_json_value = row["perceptual_fingerprint_json"]
                fingerprint_sha_value = row["fingerprint_sha256"]
                algorithm_value = row["algorithm_version"]
                digest_rows.append(
                    {
                        "algorithm_version": (
                            None if algorithm_value is None else str(algorithm_value)
                        ),
                        "category": category,
                        "fingerprint_sha256": (
                            None if fingerprint_sha_value is None else str(fingerprint_sha_value)
                        ),
                        "identity_sha256": image_identity,
                        "source_id": str(row["source_id"]),
                        "source_kind": str(row["source_kind"]),
                    }
                )
                if fingerprint_json_value is None:
                    continue
                fingerprint = PersistedPerceptualFingerprint(
                    content_sha256=image_identity,
                    perceptual_fingerprint_json=str(fingerprint_json_value),
                    fingerprint_sha256=str(fingerprint_sha_value),
                    algorithm_version=str(algorithm_value),
                )
                existing_fingerprint = fingerprint_by_image.get(image_identity)
                if existing_fingerprint is not None and existing_fingerprint != fingerprint:
                    raise LockedSetConflictError(
                        "inventory image has conflicting perceptual fingerprints"
                    )
                fingerprint_by_image[image_identity] = fingerprint
            image_identities = (
                identities["template_reference_image"]
                | identities["development_image"]
                | identities["calibration_image"]
                | identities["shadow_image"]
                | identities["prior_locked_image"]
            )
            if not set(fingerprint_by_image).issubset(image_identities):
                raise LockedSetConflictError(
                    "perceptual fingerprint belongs to a non-image identity"
                )
            inventory_image_count = len(image_identities)
            fingerprinted_image_count = len(fingerprint_by_image)
            missing_fingerprint_count = inventory_image_count - fingerprinted_image_count
            fingerprint_versions = tuple(
                sorted(
                    {fingerprint.algorithm_version for fingerprint in fingerprint_by_image.values()}
                )
            )
            watermark = _current_inventory_high_watermark(connection)
            inventory_digest = _canonical_sha256(
                {
                    "categories": {
                        category: sorted(values) for category, values in sorted(identities.items())
                    },
                    "fingerprint_algorithm_versions": list(fingerprint_versions),
                    "fingerprinted_image_count": fingerprinted_image_count,
                    "inventory_image_count": inventory_image_count,
                    "inventory_rows": digest_rows,
                    "missing_fingerprint_count": missing_fingerprint_count,
                    "schema_version": 1,
                }
            )
            source_id = f"sqlite-inventory-v1:{watermark}:{inventory_digest}"
            snapshot = LockedSetExclusionSnapshot.create(
                source_id=source_id,
                template_reference_image_hashes=identities["template_reference_image"],
                development_image_hashes=identities["development_image"],
                calibration_image_hashes=identities["calibration_image"],
                shadow_image_hashes=identities["shadow_image"],
                prior_locked_image_hashes=identities["prior_locked_image"],
                prior_waybill_identity_hashes=identities["prior_waybill_identity"],
            )
            payload = {
                "calibration_image_hashes": sorted(snapshot.calibration_image_hashes),
                "development_image_hashes": sorted(snapshot.development_image_hashes),
                "prior_waybill_identity_hashes": sorted(snapshot.prior_waybill_identity_hashes),
                "prior_locked_image_hashes": sorted(snapshot.prior_locked_image_hashes),
                "fingerprint_algorithm_versions": list(fingerprint_versions),
                "fingerprinted_image_count": fingerprinted_image_count,
                "inventory_image_count": inventory_image_count,
                "missing_fingerprint_count": missing_fingerprint_count,
                "perceptual_fingerprints": [
                    {
                        "algorithm_version": fingerprint.algorithm_version,
                        "content_sha256": fingerprint.content_sha256,
                        "fingerprint_sha256": (fingerprint.fingerprint_sha256),
                        "perceptual_fingerprint_json": (fingerprint.perceptual_fingerprint_json),
                    }
                    for fingerprint in sorted(
                        fingerprint_by_image.values(),
                        key=lambda value: value.content_sha256,
                    )
                ],
                "schema_version": 1,
                "shadow_image_hashes": sorted(snapshot.shadow_image_hashes),
                "source_id": snapshot.source_id,
                "template_reference_image_hashes": sorted(snapshot.template_reference_image_hashes),
            }
            payload_json = _canonical_json(payload)
            snapshot_id = snapshot.canonical_sha256
            connection.execute(
                text(
                    """
                    INSERT OR IGNORE INTO locked_set_exclusion_snapshots (
                        snapshot_id, source_id, inventory_high_watermark,
                        payload_json, canonical_sha256,
                        template_reference_count, development_count,
                        calibration_count, shadow_count, prior_locked_count,
                        prior_waybill_count,
                        inventory_image_count, fingerprinted_image_count,
                        missing_fingerprint_count,
                        fingerprint_algorithm_versions_json,
                        created_at
                    ) VALUES (
                        :snapshot_id, :source_id, :inventory_high_watermark,
                        :payload_json, :canonical_sha256,
                        :template_reference_count, :development_count,
                        :calibration_count, :shadow_count, :prior_locked_count,
                        :prior_waybill_count,
                        :inventory_image_count, :fingerprinted_image_count,
                        :missing_fingerprint_count,
                        :fingerprint_algorithm_versions_json,
                        :created_at
                    )
                    """
                ),
                {
                    "snapshot_id": snapshot_id,
                    "source_id": source_id,
                    "inventory_high_watermark": watermark,
                    "payload_json": payload_json,
                    "canonical_sha256": snapshot.canonical_sha256,
                    "template_reference_count": len(snapshot.template_reference_image_hashes),
                    "development_count": len(snapshot.development_image_hashes),
                    "calibration_count": len(snapshot.calibration_image_hashes),
                    "shadow_count": len(snapshot.shadow_image_hashes),
                    "prior_locked_count": len(snapshot.prior_locked_image_hashes),
                    "prior_waybill_count": len(snapshot.prior_waybill_identity_hashes),
                    "inventory_image_count": inventory_image_count,
                    "fingerprinted_image_count": fingerprinted_image_count,
                    "missing_fingerprint_count": missing_fingerprint_count,
                    "fingerprint_algorithm_versions_json": _canonical_json(
                        list(fingerprint_versions)
                    ),
                    "created_at": now,
                },
            )
            row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            snapshot_id, inventory_high_watermark,
                            payload_json, canonical_sha256,
                            inventory_image_count, fingerprinted_image_count,
                            missing_fingerprint_count,
                            fingerprint_algorithm_versions_json, created_at
                        FROM locked_set_exclusion_snapshots
                        WHERE snapshot_id = :snapshot_id
                        """
                    ),
                    {"snapshot_id": snapshot_id},
                )
                .mappings()
                .one()
            )
            return self._snapshot_from_row(row)

    def get_exclusion_snapshot(
        self,
        snapshot_id: str,
    ) -> PersistedExclusionSnapshot:
        identity = _required_sha256(snapshot_id, "snapshot_id")
        with self.runtime.engine.connect() as connection:
            return self._load_snapshot(connection, identity)

    @staticmethod
    def _load_similarity_scan(
        connection: Connection,
        dataset_id: str,
    ) -> LockedSetSimilarityScanRecord:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        scan_id, dataset_id, manifest_sha256,
                        exclusion_snapshot_id, exclusion_snapshot_sha256,
                        inventory_high_watermark, scan_json,
                        scan_fingerprint, detector_fingerprint,
                        locked_image_count, excluded_image_count,
                        candidate_count, locked_image_fingerprints_json,
                        locked_image_fingerprints_sha256, actor_id,
                        completed_at
                    FROM locked_set_similarity_scans
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise LockedSetNotFoundError("locked-set similarity scan does not exist")
        return _similarity_scan_from_row(row)

    def get_similarity_scan(
        self,
        dataset_id: str,
    ) -> LockedSetSimilarityScanRecord:
        identity = _required_text(dataset_id, "dataset_id")
        with self.runtime.engine.connect() as connection:
            return self._load_similarity_scan(connection, identity)

    def persist_similarity_scan(
        self,
        *,
        dataset_id: str,
        manifest_sha256: str,
        exclusion_snapshot_sha256: str,
        inventory_high_watermark: int,
        scan: Mapping[str, object],
        locked_image_fingerprints: Sequence[ImagePerceptualFingerprint],
        actor_id: str,
    ) -> LockedSetSimilarityScanOutcome:
        """Persist a completed code-owned scan in a short authority transaction."""

        identity = _required_text(dataset_id, "dataset_id")
        manifest_identity = _required_sha256(
            manifest_sha256,
            "manifest_sha256",
        )
        snapshot_identity = _required_sha256(
            exclusion_snapshot_sha256,
            "exclusion_snapshot_sha256",
        )
        actor = _required_text(actor_id, "actor_id")
        if (
            not isinstance(inventory_high_watermark, int)
            or isinstance(inventory_high_watermark, bool)
            or inventory_high_watermark < 0
        ):
            raise LockedSetPersistenceError("inventory_high_watermark is invalid")
        if not isinstance(scan, Mapping):
            raise LockedSetPersistenceError("code-owned similarity scan is required")
        scan_payload = dict(scan)
        scan_fingerprint = _required_sha256(
            str(scan_payload.get("scan_fingerprint", "")),
            "scan_fingerprint",
        )
        if scan_fingerprint != _canonical_sha256(
            {key: value for key, value in scan_payload.items() if key != "scan_fingerprint"}
        ):
            raise LockedSetPersistenceError("similarity scan fingerprint is invalid")
        if (
            scan_payload.get("schema_version") != 1
            or scan_payload.get("dataset_id") != identity
            or scan_payload.get("manifest_sha256") != manifest_identity
            or scan_payload.get("exclusion_snapshot_sha256") != snapshot_identity
            or scan_payload.get("completed") is not True
            or scan_payload.get("locked_image_count") != 100
        ):
            raise LockedSetPersistenceError("similarity scan authority binding is invalid")
        detector_fingerprint = _required_sha256(
            str(scan_payload.get("detector_fingerprint", "")),
            "detector_fingerprint",
        )
        if detector_fingerprint != (_expected_similarity_detector_fingerprint()):
            raise LockedSetPersistenceError("similarity scan detector is not code-owned")
        excluded_image_count = scan_payload.get("excluded_image_count")
        if (
            not isinstance(excluded_image_count, int)
            or isinstance(excluded_image_count, bool)
            or excluded_image_count < 0
        ):
            raise LockedSetPersistenceError("similarity scan excluded image count is invalid")
        fingerprints = tuple(locked_image_fingerprints)
        if len(fingerprints) != 100:
            raise LockedSetPersistenceError(
                "similarity scan requires 100 locked-image fingerprints"
            )
        fingerprint_payloads = sorted(
            (_image_fingerprint_payload(fingerprint) for fingerprint in fingerprints),
            key=lambda value: str(value["content_sha256"]),
        )
        fingerprint_identities = [str(value["content_sha256"]) for value in fingerprint_payloads]
        if len(set(fingerprint_identities)) != 100:
            raise LockedSetPersistenceError(
                "locked-image fingerprints contain duplicate identities"
            )
        fingerprints_json = _canonical_json(fingerprint_payloads)
        fingerprints_sha256 = hashlib.sha256(fingerprints_json.encode("utf-8")).hexdigest()
        raw_candidates = scan_payload.get("candidates")
        if not isinstance(raw_candidates, list):
            raise LockedSetPersistenceError("similarity scan candidates are invalid")
        candidate_ids: set[str] = set()
        for raw_candidate in raw_candidates:
            if not isinstance(raw_candidate, Mapping):
                raise LockedSetPersistenceError("similarity scan candidate is invalid")
            candidate_id = _required_text(
                str(raw_candidate.get("candidate_id", "")),
                "candidate_id",
            )
            if candidate_id in candidate_ids:
                raise LockedSetPersistenceError("similarity scan candidate identity is duplicated")
            candidate_ids.add(candidate_id)

        completed_at = _utc_now()
        scan_json = _canonical_json(scan_payload)
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            authority = require_current_preflight_authority(
                connection,
                dataset_id=identity,
                manifest_sha256=manifest_identity,
                exclusion_snapshot_sha256=snapshot_identity,
                inventory_high_watermark=inventory_high_watermark,
            )
            dataset, manifest_json = self._load_dataset(
                connection,
                identity,
            )
            manifest = self._manifest_from_dataset(
                dataset,
                manifest_json,
            )
            manifest_image_hashes = {
                image.image_sha256 for waybill in manifest.waybills for image in waybill.images
            }
            if set(fingerprint_identities) != manifest_image_hashes:
                raise LockedSetConflictError(
                    "locked-image fingerprints do not match sealed members"
                )
            excluded_image_hashes = (
                authority.exclusion_snapshot.snapshot.template_reference_image_hashes
                | authority.exclusion_snapshot.snapshot.development_image_hashes
                | authority.exclusion_snapshot.snapshot.calibration_image_hashes
                | authority.exclusion_snapshot.snapshot.shadow_image_hashes
                | authority.exclusion_snapshot.snapshot.prior_locked_image_hashes
            )
            if excluded_image_count != len(excluded_image_hashes):
                raise LockedSetConflictError("similarity scan excluded image count is stale")
            inventory_fingerprints: list[ImagePerceptualFingerprint] = []
            for persisted_fingerprint in authority.exclusion_snapshot.perceptual_fingerprints:
                try:
                    raw_fingerprint = json.loads(persisted_fingerprint.perceptual_fingerprint_json)
                except json.JSONDecodeError as exc:
                    raise LockedSetPersistenceError(
                        "inventory fingerprint JSON is invalid"
                    ) from exc
                fingerprint = _image_fingerprint_from_payload(raw_fingerprint)
                if (
                    fingerprint.content_sha256 != persisted_fingerprint.content_sha256
                    or hashlib.sha256(
                        persisted_fingerprint.perceptual_fingerprint_json.encode("utf-8")
                    ).hexdigest()
                    != persisted_fingerprint.fingerprint_sha256
                    or fingerprint.algorithm_version != persisted_fingerprint.algorithm_version
                ):
                    raise LockedSetConflictError("inventory fingerprint authority is inconsistent")
                inventory_fingerprints.append(fingerprint)
            if {
                fingerprint.content_sha256 for fingerprint in inventory_fingerprints
            } != excluded_image_hashes:
                raise LockedSetConflictError("inventory fingerprint members do not match snapshot")
            probe_set_fingerprint = _required_sha256(
                str(scan_payload.get("probe_set_fingerprint", "")),
                "probe_set_fingerprint",
            )
            inventory_set_fingerprint = _required_sha256(
                str(scan_payload.get("inventory_set_fingerprint", "")),
                "inventory_set_fingerprint",
            )
            if probe_set_fingerprint != _fingerprint_set_sha256(
                fingerprints
            ) or inventory_set_fingerprint != _fingerprint_set_sha256(inventory_fingerprints):
                raise LockedSetConflictError(
                    "similarity scan fingerprint sets do not match authority"
                )
            for raw_candidate in raw_candidates:
                candidate = cast(Mapping[str, object], raw_candidate)
                locked_image_sha256 = _required_sha256(
                    str(candidate.get("locked_image_sha256", "")),
                    "candidate locked_image_sha256",
                )
                compared_image_sha256 = _required_sha256(
                    str(candidate.get("excluded_image_sha256", "")),
                    "candidate excluded_image_sha256",
                )
                comparison_scope = _required_text(
                    str(candidate.get("comparison_scope", "")),
                    "comparison_scope",
                    maximum=40,
                )
                if locked_image_sha256 not in manifest_image_hashes:
                    raise LockedSetConflictError(
                        "similarity scan candidate is outside its authority"
                    )
                if (
                    comparison_scope == "probe_to_inventory"
                    and compared_image_sha256 not in excluded_image_hashes
                ) or (
                    comparison_scope == "probe_to_probe"
                    and (
                        compared_image_sha256 not in manifest_image_hashes
                        or compared_image_sha256 == locked_image_sha256
                    )
                ):
                    raise LockedSetConflictError(
                        "similarity scan candidate is outside its comparison scope"
                    )
                if comparison_scope not in {
                    "probe_to_inventory",
                    "probe_to_probe",
                }:
                    raise LockedSetConflictError(
                        "similarity scan candidate comparison scope is invalid"
                    )
            existing = (
                connection.execute(
                    text(
                        """
                        SELECT
                            scan_id, dataset_id, manifest_sha256,
                            exclusion_snapshot_id,
                            exclusion_snapshot_sha256,
                            inventory_high_watermark, scan_json,
                            scan_fingerprint, detector_fingerprint,
                            locked_image_count, excluded_image_count,
                            candidate_count,
                            locked_image_fingerprints_json,
                            locked_image_fingerprints_sha256,
                            actor_id, completed_at
                        FROM locked_set_similarity_scans
                        WHERE dataset_id = :dataset_id
                        """
                    ),
                    {"dataset_id": identity},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                persisted = _similarity_scan_from_row(existing)
                if (
                    persisted.manifest_sha256 != manifest_identity
                    or persisted.exclusion_snapshot_sha256 != snapshot_identity
                    or persisted.inventory_high_watermark != inventory_high_watermark
                    or persisted.scan_json != scan_json
                    or persisted.locked_image_fingerprints_json != fingerprints_json
                ):
                    raise LockedSetConflictError(
                        "locked-set similarity scan already has different evidence"
                    )
                return LockedSetSimilarityScanOutcome(
                    scan=persisted,
                    applied=False,
                )
            connection.execute(
                text(
                    """
                    INSERT INTO locked_set_similarity_scans (
                        scan_id, dataset_id, manifest_sha256,
                        exclusion_snapshot_id,
                        exclusion_snapshot_sha256,
                        inventory_high_watermark, scan_json,
                        scan_fingerprint, detector_fingerprint,
                        locked_image_count, excluded_image_count,
                        candidate_count,
                        locked_image_fingerprints_json,
                        locked_image_fingerprints_sha256,
                        actor_id, completed_at
                    ) VALUES (
                        :scan_id, :dataset_id, :manifest_sha256,
                        :exclusion_snapshot_id,
                        :exclusion_snapshot_sha256,
                        :inventory_high_watermark, :scan_json,
                        :scan_fingerprint, :detector_fingerprint,
                        100, :excluded_image_count, :candidate_count,
                        :locked_image_fingerprints_json,
                        :locked_image_fingerprints_sha256,
                        :actor_id, :completed_at
                    )
                    """
                ),
                {
                    "scan_id": scan_fingerprint,
                    "dataset_id": identity,
                    "manifest_sha256": manifest_identity,
                    "exclusion_snapshot_id": (authority.exclusion_snapshot.snapshot_id),
                    "exclusion_snapshot_sha256": snapshot_identity,
                    "inventory_high_watermark": inventory_high_watermark,
                    "scan_json": scan_json,
                    "scan_fingerprint": scan_fingerprint,
                    "detector_fingerprint": detector_fingerprint,
                    "excluded_image_count": excluded_image_count,
                    "candidate_count": len(candidate_ids),
                    "locked_image_fingerprints_json": fingerprints_json,
                    "locked_image_fingerprints_sha256": fingerprints_sha256,
                    "actor_id": actor,
                    "completed_at": completed_at,
                },
            )
            return LockedSetSimilarityScanOutcome(
                scan=self._load_similarity_scan(connection, identity),
                applied=True,
            )

    def _load_formal_evaluation(
        self,
        connection: Connection,
        dataset_id: str,
    ) -> LockedSetFormalEvaluationRecord:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        evaluation_id, dataset_id, manifest_sha256,
                        exclusion_snapshot_id,
                        exclusion_snapshot_sha256,
                        inventory_high_watermark,
                        preflight_attestation_id,
                        scan_id, scan_fingerprint,
                        idempotency_key, request_hash,
                        runner_report_json, runner_report_sha256,
                        committed_report_json,
                        committed_report_sha256,
                        quality_coverage_json,
                        quality_coverage_sha256,
                        decision_set_json, decision_set_sha256,
                        run_context_sha256,
                        gate_passed, formal_report,
                        formal_accuracy_claim, actor_id, completed_at
                    FROM locked_set_formal_evaluations
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise LockedSetNotFoundError("locked-set formal evaluation does not exist")
        record = _formal_evaluation_from_row(row)
        self._require_reproduced_formal_evaluation(
            connection,
            record,
        )
        return record

    def _require_reproduced_formal_evaluation(
        self,
        connection: Connection,
        record: LockedSetFormalEvaluationRecord,
    ) -> None:
        """Recompute the pure report from persisted DB authority on every read."""

        dataset, manifest_json = self._load_dataset(
            connection,
            record.dataset_id,
        )
        manifest = self._manifest_from_dataset(dataset, manifest_json)
        if (
            dataset.manifest_sha256 != record.manifest_sha256
            or manifest.canonical_sha256 != record.manifest_sha256
        ):
            raise LockedSetConflictError(
                "persisted formal evaluation manifest authority is inconsistent"
            )
        source_authority = self._load_candidate_review_source_authority(
            connection,
            record.dataset_id,
        )
        if source_authority is None:
            raise LockedSetConflictError(
                "persisted formal evaluation candidate-review source authority is missing"
            )
        if source_authority.manifest_sha256 != record.manifest_sha256:
            raise LockedSetConflictError(
                "persisted formal evaluation candidate-review source authority is inconsistent"
            )
        candidate_review_source_authority = _candidate_review_binding_from_record(source_authority)
        development_authority = self._load_development_authority(
            connection,
            record.dataset_id,
        )
        if development_authority is None:
            raise LockedSetConflictError(
                "persisted formal evaluation development authority is missing"
            )
        attestation_row = (
            connection.execute(
                text(
                    """
                    SELECT
                        attestation_id, dataset_id, manifest_sha256,
                        exclusion_snapshot_id, exclusion_snapshot_sha256,
                        exclusion_source_id, inventory_high_watermark,
                        waybill_count, image_count, total_bytes,
                        attestation_sha256, actor_id, completed_at
                    FROM locked_set_preflight_attestations
                    WHERE attestation_id = :attestation_id
                      AND dataset_id = :dataset_id
                    """
                ),
                {
                    "attestation_id": record.preflight_attestation_id,
                    "dataset_id": record.dataset_id,
                },
            )
            .mappings()
            .one_or_none()
        )
        if attestation_row is None:
            raise LockedSetConflictError(
                "persisted formal evaluation preflight authority is missing"
            )
        attestation = _attestation_from_row(attestation_row)
        snapshot = self._load_snapshot(
            connection,
            attestation.exclusion_snapshot_id,
        )
        reconstructed_attestation = LockedSetReleaseAttestation(
            dataset_id=attestation.dataset_id,
            manifest_sha256=attestation.manifest_sha256,
            exclusion_source_id=attestation.exclusion_source_id,
            exclusion_snapshot_sha256=attestation.exclusion_snapshot_sha256,
            waybill_count=attestation.waybill_count,
            image_count=attestation.image_count,
            total_bytes=attestation.total_bytes,
            exclusion_counts=snapshot.snapshot.exclusion_counts,
        )
        if (
            attestation.attestation_id != attestation.attestation_sha256
            or attestation.attestation_sha256 != reconstructed_attestation.attestation_sha256
            or attestation.dataset_id != record.dataset_id
            or attestation.manifest_sha256 != record.manifest_sha256
            or attestation.exclusion_snapshot_id != record.exclusion_snapshot_id
            or attestation.exclusion_snapshot_sha256 != record.exclusion_snapshot_sha256
            or attestation.inventory_high_watermark != record.inventory_high_watermark
            or attestation.waybill_count != 50
            or attestation.image_count != 100
            or snapshot.snapshot_id != record.exclusion_snapshot_id
            or snapshot.inventory_high_watermark != record.inventory_high_watermark
            or snapshot.snapshot.source_id != attestation.exclusion_source_id
        ):
            raise LockedSetConflictError(
                "persisted formal evaluation preflight authority is inconsistent"
            )
        runner_report = json.loads(record.runner_report_json)
        if not isinstance(runner_report, dict):
            raise LockedSetPersistenceError(
                "persisted formal evaluation runner report is invalid"
            )
        _require_development_authority_runner_binding(
            development_authority,
            manifest_sha256=record.manifest_sha256,
            formal_exclusion_snapshot_sha256=(
                record.exclusion_snapshot_sha256
            ),
            runner_report=runner_report,
        )
        scan_record = self._load_similarity_scan(
            connection,
            record.dataset_id,
        )
        if (
            scan_record.scan_id != record.scan_id
            or scan_record.scan_fingerprint != record.scan_fingerprint
            or scan_record.manifest_sha256 != record.manifest_sha256
            or scan_record.exclusion_snapshot_id != record.exclusion_snapshot_id
            or scan_record.exclusion_snapshot_sha256 != record.exclusion_snapshot_sha256
            or scan_record.inventory_high_watermark != record.inventory_high_watermark
        ):
            raise LockedSetConflictError(
                "persisted formal evaluation scan authority is inconsistent"
            )
        quality_coverage = json.loads(record.quality_coverage_json)
        decisions = json.loads(record.decision_set_json)
        scan_payload = json.loads(scan_record.scan_json)
        if (
            not isinstance(runner_report, dict)
            or not isinstance(quality_coverage, dict)
            or not isinstance(decisions, list)
            or not isinstance(scan_payload, dict)
        ):
            raise LockedSetPersistenceError("persisted formal evaluation authority is invalid")
        try:
            independently_evaluated = evaluate_locked_set_release(
                preflight_attestation=_preflight_attestation_payload(attestation),
                truth_manifest=_truth_manifest_payload(manifest),
                image_results=runner_report.get("image_results"),
                pair_results=runner_report.get("pair_results"),
                quality_coverage=quality_coverage,
                near_duplicate_scan=scan_payload,
                near_duplicate_decisions=decisions,
                eligibility_history=_eligibility_history_from_attestation(attestation),
                candidate_review_source_authority=(candidate_review_source_authority),
                expected_runtime_kinds=(_runner_expected_runtime_kinds(runner_report)),
            )
        except LockedSetAcceptanceError as exc:
            raise LockedSetPersistenceError(
                "persisted formal evaluation cannot be reproduced from DB authority"
            ) from exc
        if _pure_runner_report(runner_report) != independently_evaluated:
            raise LockedSetConflictError(
                "persisted formal report differs from reproduced DB authority"
            )

    def get_formal_release_evaluation(
        self,
        dataset_id: str,
    ) -> LockedSetFormalEvaluationRecord:
        identity = _required_text(dataset_id, "dataset_id")
        with self.runtime.engine.connect() as connection:
            return self._load_formal_evaluation(connection, identity)

    @staticmethod
    def _require_replayable_formal_state(
        connection: Connection,
        dataset: LockedSetDatasetRecord,
    ) -> None:
        invalidation_id = connection.execute(
            text(
                "SELECT invalidation_id FROM locked_set_invalidations "
                "WHERE dataset_id = :dataset_id"
            ),
            {"dataset_id": dataset.dataset_id},
        ).scalar_one_or_none()
        if dataset.state != "formal_evaluated" or invalidation_id is not None:
            raise LockedSetStateTransitionError(
                "a permanently invalidated locked set cannot replay accuracy"
            )

    def get_replayable_formal_release_evaluation(
        self,
        dataset_id: str,
    ) -> LockedSetFormalEvaluationRecord:
        """Linearize a formal replay check against permanent invalidation."""

        identity = _required_text(dataset_id, "dataset_id")
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            dataset, _ = self._load_dataset(connection, identity)
            self._require_replayable_formal_state(connection, dataset)
            return self._load_formal_evaluation(connection, identity)

    def persist_formal_release_evaluation(
        self,
        *,
        dataset_id: str,
        manifest_sha256: str,
        exclusion_snapshot_sha256: str,
        inventory_high_watermark: int,
        scan_fingerprint: str,
        runner_report: Mapping[str, object],
        quality_coverage: Mapping[str, object],
        near_duplicate_decisions: Sequence[Mapping[str, object]],
        actor_id: str,
        idempotency_key: str,
    ) -> LockedSetFormalEvaluationOutcome:
        """Atomically commit one formal result and its future exclusions."""

        identity = _required_text(dataset_id, "dataset_id")
        manifest_identity = _required_sha256(
            manifest_sha256,
            "manifest_sha256",
        )
        snapshot_identity = _required_sha256(
            exclusion_snapshot_sha256,
            "exclusion_snapshot_sha256",
        )
        scan_identity = _required_sha256(
            scan_fingerprint,
            "scan_fingerprint",
        )
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        if (
            not isinstance(inventory_high_watermark, int)
            or isinstance(inventory_high_watermark, bool)
            or inventory_high_watermark < 0
        ):
            raise LockedSetPersistenceError("inventory_high_watermark is invalid")
        if not isinstance(runner_report, Mapping):
            raise LockedSetPersistenceError("uncommitted runner report is required")
        report = dict(runner_report)
        raw_runner_hash = _required_sha256(
            str(report.get("runner_report_sha256", "")),
            "runner_report_sha256",
        )
        if raw_runner_hash != _canonical_sha256(
            {field: value for field, value in report.items() if field != "runner_report_sha256"}
        ):
            raise LockedSetPersistenceError("runner report integrity is invalid")
        if (
            report.get("dataset_id") != identity
            or report.get("manifest_sha256") != manifest_identity
            or report.get("exclusion_snapshot_sha256") != snapshot_identity
        ):
            raise LockedSetConflictError("runner report authority binding is invalid")
        run_context_sha256 = _validated_runner_context_sha256(report)
        gate_passed = _validate_uncommitted_runner_report(report)
        reconciliation = report.get("reconciliation")
        if not isinstance(reconciliation, Mapping) or any(
            reconciliation.get(field) != expected
            for field, expected in (
                ("expected_image_count", 100),
                ("result_image_count", 100),
                ("expected_pair_count", 50),
                ("result_pair_count", 50),
            )
        ):
            raise LockedSetPersistenceError("runner report reconciliation is incomplete")
        for field in (
            "missing_image_results",
            "unexpected_image_results",
            "duplicate_image_results",
            "missing_pair_results",
            "unexpected_pair_results",
            "duplicate_pair_results",
        ):
            if reconciliation.get(field) not in (None, []):
                raise LockedSetPersistenceError(
                    "runner report reconciliation has unresolved members"
                )
        raw_image_results = report.get("image_results")
        raw_pair_results = report.get("pair_results")
        if (
            not isinstance(raw_image_results, list)
            or len(raw_image_results) != 100
            or not isinstance(raw_pair_results, list)
            or len(raw_pair_results) != 50
        ):
            raise LockedSetPersistenceError("runner report member results are incomplete")
        if not isinstance(quality_coverage, Mapping):
            raise LockedSetPersistenceError("quality coverage evidence is required")
        quality_payload = dict(quality_coverage)
        if (
            quality_payload.get("dataset_id") != identity
            or quality_payload.get("manifest_sha256") != manifest_identity
        ):
            raise LockedSetConflictError("quality coverage evidence is not bound to the manifest")
        _require_schema_version(quality_payload, 2, label="quality coverage")
        if quality_payload.get("derived_adversarial_suite") != report.get(
            "derived_adversarial_suite"
        ):
            raise LockedSetConflictError(
                "quality coverage is not bound to the derived adversarial suite"
            )
        quality_root_sha256 = _strict_sha256_field(
            quality_payload,
            "quality_coverage_sha256",
            label="quality coverage",
        )
        if (
            quality_root_sha256
            != _canonical_sha256(
                {
                    field: value
                    for field, value in quality_payload.items()
                    if field != "quality_coverage_sha256"
                }
            )
            or report.get("quality_coverage_sha256") != quality_root_sha256
        ):
            raise LockedSetPersistenceError("quality coverage integrity is invalid")
        quality_json = _canonical_json(quality_payload)
        quality_sha256 = hashlib.sha256(quality_json.encode("utf-8")).hexdigest()
        decisions = tuple(dict(decision) for decision in near_duplicate_decisions)
        decisions_json = _canonical_json(list(decisions))
        decisions_sha256 = hashlib.sha256(decisions_json.encode("utf-8")).hexdigest()
        runner_report_json = _canonical_json(report)
        committed_report = dict(report)
        committed_report["formal_report"] = True
        committed_report["formal_accuracy_claim"] = gate_passed
        committed_report["formal_accuracy_claim_scope"] = (
            "observed_real_locked_set_only" if gate_passed else "none"
        )
        committed_report["claim_status"] = (
            "formal_accuracy_claim" if gate_passed else "formal_report_without_accuracy_claim"
        )
        committed_report_json = _canonical_json(committed_report)
        committed_report_sha256 = hashlib.sha256(committed_report_json.encode("utf-8")).hexdigest()
        request_hash = _formal_evaluation_request_hash(
            actor_id=actor,
            committed_report_sha256=committed_report_sha256,
            dataset_id=identity,
            decision_set_sha256=decisions_sha256,
            inventory_high_watermark=inventory_high_watermark,
            manifest_sha256=manifest_identity,
            quality_coverage_sha256=quality_sha256,
            run_context_sha256=run_context_sha256,
            runner_report_sha256=raw_runner_hash,
            scan_fingerprint=scan_identity,
            snapshot_sha256=snapshot_identity,
        )
        completed_at = _utc_now()
        evaluation_id = committed_report_sha256
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay_row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            evaluation_id, dataset_id, manifest_sha256,
                            exclusion_snapshot_id,
                            exclusion_snapshot_sha256,
                            inventory_high_watermark,
                            preflight_attestation_id,
                            scan_id, scan_fingerprint,
                            idempotency_key, request_hash,
                            runner_report_json, runner_report_sha256,
                            committed_report_json,
                            committed_report_sha256,
                            quality_coverage_json,
                            quality_coverage_sha256,
                            decision_set_json, decision_set_sha256,
                            run_context_sha256,
                            gate_passed, formal_report,
                            formal_accuracy_claim, actor_id, completed_at
                        FROM locked_set_formal_evaluations
                        WHERE idempotency_key = :idempotency_key
                        """
                    ),
                    {"idempotency_key": key},
                )
                .mappings()
                .one_or_none()
            )
            if replay_row is not None:
                if str(replay_row["request_hash"]) != request_hash:
                    raise LockedSetIdempotencyConflictError(
                        "formal evaluation idempotency key belongs to different input"
                    )
                persisted = _formal_evaluation_from_row(replay_row)
                self._require_reproduced_formal_evaluation(
                    connection,
                    persisted,
                )
                if persisted.dataset_id != identity:
                    raise LockedSetIdempotencyConflictError(
                        "formal evaluation idempotency key belongs to another dataset"
                    )
                dataset, _ = self._load_dataset(connection, identity)
                self._require_replayable_formal_state(
                    connection,
                    dataset,
                )
                return LockedSetFormalEvaluationOutcome(
                    dataset=dataset,
                    evaluation=persisted,
                    applied=False,
                )
            authority = require_current_preflight_authority(
                connection,
                dataset_id=identity,
                manifest_sha256=manifest_identity,
                exclusion_snapshot_sha256=snapshot_identity,
                inventory_high_watermark=inventory_high_watermark,
            )
            development_authority = self._load_development_authority(
                connection,
                identity,
            )
            if development_authority is None:
                raise LockedSetConflictError(
                    "formal evaluation requires development authority"
                )
            _require_development_authority_runner_binding(
                development_authority,
                manifest_sha256=manifest_identity,
                formal_exclusion_snapshot_sha256=snapshot_identity,
                runner_report=report,
            )
            source_authority = self._load_candidate_review_source_authority(
                connection,
                identity,
            )
            if source_authority is None:
                raise LockedSetConflictError(
                    "formal evaluation requires candidate-review source authority"
                )
            if source_authority.manifest_sha256 != manifest_identity:
                raise LockedSetConflictError("candidate-review source authority is stale")
            candidate_review_source_authority = _candidate_review_binding_from_record(
                source_authority
            )
            if report.get(
                "candidate_review_source_authority"
            ) != candidate_review_source_authority or report.get(
                "candidate_review_source_authority_sha256"
            ) != candidate_review_source_authority_binding_sha256(
                candidate_review_source_authority
            ):
                raise LockedSetConflictError(
                    "runner report candidate-review source authority is inconsistent"
                )
            scan_record = self._load_similarity_scan(
                connection,
                identity,
            )
            if (
                scan_record.scan_fingerprint != scan_identity
                or scan_record.manifest_sha256 != manifest_identity
                or scan_record.exclusion_snapshot_sha256 != snapshot_identity
                or scan_record.inventory_high_watermark != inventory_high_watermark
                or scan_record.exclusion_snapshot_id != authority.exclusion_snapshot.snapshot_id
            ):
                raise LockedSetConflictError("formal evaluation scan authority is stale")
            scan_payload = cast(
                dict[str, object],
                json.loads(scan_record.scan_json),
            )
            raw_candidates = scan_payload.get("candidates")
            if not isinstance(raw_candidates, list):
                raise LockedSetPersistenceError("persisted scan candidates are invalid")
            candidates_by_id = {
                str(cast(Mapping[str, object], candidate).get("candidate_id")): (
                    cast(Mapping[str, object], candidate)
                )
                for candidate in raw_candidates
                if isinstance(candidate, Mapping)
            }
            decisions_by_id: dict[str, Mapping[str, object]] = {}
            for decision in decisions:
                candidate_id = _required_text(
                    str(decision.get("candidate_id", "")),
                    "decision candidate_id",
                )
                if (
                    candidate_id in decisions_by_id
                    or candidate_id not in candidates_by_id
                    or decision.get("scan_fingerprint") != scan_identity
                    or decision.get("verdict") not in {"distinct", "duplicate"}
                ):
                    raise LockedSetConflictError(
                        "near-duplicate decisions do not match persisted scan"
                    )
                decisions_by_id[candidate_id] = decision
            if set(decisions_by_id) != set(candidates_by_id):
                raise LockedSetConflictError("persisted scan candidates require complete decisions")
            duplicate_count = sum(decision.get("verdict") == "duplicate" for decision in decisions)
            near_duplicate_gate = report.get("near_duplicate_gate")
            if (
                not isinstance(near_duplicate_gate, Mapping)
                or near_duplicate_gate.get("candidate_count") != len(candidates_by_id)
                or near_duplicate_gate.get("duplicate_count") != duplicate_count
                or (
                    duplicate_count > 0
                    and (gate_passed or near_duplicate_gate.get("passed") is not False)
                )
            ):
                raise LockedSetConflictError("runner report near-duplicate gate is inconsistent")
            dataset, manifest_json = self._load_dataset(
                connection,
                identity,
            )
            manifest = self._manifest_from_dataset(
                dataset,
                manifest_json,
            )
            expected_images = {
                image.image_sha256: waybill.sample_id
                for waybill in manifest.waybills
                for image in waybill.images
            }
            result_images: dict[str, str] = {}
            for raw_result in raw_image_results:
                if not isinstance(raw_result, Mapping):
                    raise LockedSetPersistenceError("runner image result is invalid")
                image_sha256 = _required_sha256(
                    str(raw_result.get("image_sha256", "")),
                    "result image_sha256",
                )
                sample_id = _required_text(
                    str(raw_result.get("sample_id", "")),
                    "result sample_id",
                )
                if image_sha256 in result_images or expected_images.get(image_sha256) != sample_id:
                    raise LockedSetConflictError("runner image results do not match sealed members")
                result_images[image_sha256] = sample_id
            if set(result_images) != set(expected_images):
                raise LockedSetConflictError("runner image results do not reconcile")
            expected_pairs = {
                waybill.sample_id: {image.slot: image.image_sha256 for image in waybill.images}
                for waybill in manifest.waybills
            }
            result_pairs: set[str] = set()
            for raw_result in raw_pair_results:
                if not isinstance(raw_result, Mapping):
                    raise LockedSetPersistenceError("runner pair result is invalid")
                sample_id = _required_text(
                    str(raw_result.get("sample_id", "")),
                    "pair result sample_id",
                )
                expected = expected_pairs.get(sample_id)
                if (
                    expected is None
                    or sample_id in result_pairs
                    or raw_result.get("loading_slot_image_sha256") != expected[TicketSlot.LOADING]
                    or raw_result.get("unloading_slot_image_sha256")
                    != expected[TicketSlot.UNLOADING]
                ):
                    raise LockedSetConflictError("runner pair results do not match sealed members")
                result_pairs.add(sample_id)
            if result_pairs != set(expected_pairs):
                raise LockedSetConflictError("runner pair results do not reconcile")
            try:
                independently_evaluated = evaluate_locked_set_release(
                    preflight_attestation=(_preflight_attestation_payload(authority.attestation)),
                    truth_manifest=_truth_manifest_payload(manifest),
                    image_results=raw_image_results,
                    pair_results=raw_pair_results,
                    quality_coverage=quality_payload,
                    near_duplicate_scan=scan_payload,
                    near_duplicate_decisions=list(decisions),
                    eligibility_history=authority.eligibility_history,
                    candidate_review_source_authority=(candidate_review_source_authority),
                    expected_runtime_kinds=(_runner_expected_runtime_kinds(report)),
                )
            except LockedSetAcceptanceError as exc:
                raise LockedSetPersistenceError(
                    "runner report cannot be reproduced from DB authority"
                ) from exc
            if set(report) != set(independently_evaluated).union(RUNNER_REPORT_ONLY_FIELDS) or any(
                report.get(field) != value for field, value in independently_evaluated.items()
            ):
                raise LockedSetConflictError(
                    "runner report differs from independent DB-authority evaluation"
                )
            connection.execute(
                text(
                    """
                    INSERT INTO locked_set_formal_evaluations (
                        evaluation_id, dataset_id, manifest_sha256,
                        exclusion_snapshot_id,
                        exclusion_snapshot_sha256,
                        inventory_high_watermark,
                        preflight_attestation_id,
                        scan_id, scan_fingerprint,
                        idempotency_key, request_hash,
                        runner_report_json, runner_report_sha256,
                        committed_report_json,
                        committed_report_sha256,
                        quality_coverage_json,
                        quality_coverage_sha256,
                        decision_set_json, decision_set_sha256,
                        run_context_sha256,
                        gate_passed, formal_report,
                        formal_accuracy_claim, actor_id, completed_at
                    ) VALUES (
                        :evaluation_id, :dataset_id, :manifest_sha256,
                        :exclusion_snapshot_id,
                        :exclusion_snapshot_sha256,
                        :inventory_high_watermark,
                        :preflight_attestation_id,
                        :scan_id, :scan_fingerprint,
                        :idempotency_key, :request_hash,
                        :runner_report_json, :runner_report_sha256,
                        :committed_report_json,
                        :committed_report_sha256,
                        :quality_coverage_json,
                        :quality_coverage_sha256,
                        :decision_set_json, :decision_set_sha256,
                        :run_context_sha256,
                        :gate_passed, 1,
                        :formal_accuracy_claim, :actor_id, :completed_at
                    )
                    """
                ),
                {
                    "evaluation_id": evaluation_id,
                    "dataset_id": identity,
                    "manifest_sha256": manifest_identity,
                    "exclusion_snapshot_id": (authority.exclusion_snapshot.snapshot_id),
                    "exclusion_snapshot_sha256": snapshot_identity,
                    "inventory_high_watermark": inventory_high_watermark,
                    "preflight_attestation_id": (authority.attestation.attestation_id),
                    "scan_id": scan_record.scan_id,
                    "scan_fingerprint": scan_identity,
                    "idempotency_key": key,
                    "request_hash": request_hash,
                    "runner_report_json": runner_report_json,
                    "runner_report_sha256": raw_runner_hash,
                    "committed_report_json": committed_report_json,
                    "committed_report_sha256": (committed_report_sha256),
                    "quality_coverage_json": quality_json,
                    "quality_coverage_sha256": quality_sha256,
                    "decision_set_json": decisions_json,
                    "decision_set_sha256": decisions_sha256,
                    "run_context_sha256": run_context_sha256,
                    "gate_passed": int(gate_passed),
                    "formal_accuracy_claim": int(gate_passed),
                    "actor_id": actor,
                    "completed_at": completed_at,
                },
            )
            if self._failpoint is not None:
                self._failpoint("after_formal_evaluation_insert")
            for fingerprint in scan_record.locked_image_fingerprints:
                fingerprint_payload = _image_fingerprint_payload(fingerprint)
                fingerprint_json = _canonical_json(fingerprint_payload)
                register_exclusion_identity(
                    connection,
                    category="prior_locked_image",
                    identity_sha256=fingerprint.content_sha256,
                    source_kind="formal_locked_set_evaluation",
                    source_id=identity,
                    created_at=completed_at,
                    perceptual_fingerprint_json=fingerprint_json,
                    fingerprint_sha256=hashlib.sha256(fingerprint_json.encode("utf-8")).hexdigest(),
                    algorithm_version=fingerprint.algorithm_version,
                )
            if self._failpoint is not None:
                self._failpoint("after_prior_locked_image_inventory")
            for waybill in manifest.waybills:
                register_exclusion_identity(
                    connection,
                    category="prior_waybill_identity",
                    identity_sha256=waybill.waybill_identity_sha256,
                    source_kind="formal_locked_set_evaluation",
                    source_id=identity,
                    created_at=completed_at,
                )
            if self._failpoint is not None:
                self._failpoint("after_prior_waybill_inventory")
            updated = connection.execute(
                text(
                    """
                    UPDATE locked_set_datasets
                    SET state = 'formal_evaluated',
                        record_version = record_version + 1,
                        updated_at = :updated_at
                    WHERE dataset_id = :dataset_id
                      AND state = 'preflight_passed'
                      AND record_version = :record_version
                    """
                ),
                {
                    "dataset_id": identity,
                    "record_version": authority.dataset.record_version,
                    "updated_at": completed_at,
                },
            )
            if updated.rowcount != 1:
                raise LockedSetRecordVersionConflictError(
                    "locked set changed before formal evaluation commit"
                )
            persisted = self._load_formal_evaluation(
                connection,
                identity,
            )
            persisted_dataset, _ = self._load_dataset(
                connection,
                identity,
            )
            return LockedSetFormalEvaluationOutcome(
                dataset=persisted_dataset,
                evaluation=persisted,
                applied=True,
            )

    def seal_manifest(
        self,
        manifest: LockedSetManifest,
        *,
        actor_id: str,
    ) -> LockedSetSealOutcome:
        if not isinstance(manifest, LockedSetManifest):
            raise LockedSetPersistenceError("locked-set manifest is invalid")
        if manifest.waybill_count != 50 or manifest.image_count != 100:
            raise LockedSetPersistenceError(
                "sealed locked set requires exactly 50 waybills and 100 images"
            )
        dataset_id = _required_text(manifest.dataset_id, "dataset_id")
        actor = _required_text(actor_id, "actor_id")
        payload = _manifest_payload(manifest)
        manifest_json = _canonical_json(payload)
        manifest_sha256 = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        member_identity_sha256 = _canonical_sha256(_member_identity_payload(manifest))
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            existing = (
                connection.execute(
                    text(
                        """
                        SELECT
                            dataset_id, manifest_sha256,
                            member_identity_sha256, manifest_json, state,
                            record_version, created_by, created_at, updated_at
                        FROM locked_set_datasets
                        WHERE dataset_id = :dataset_id
                        """
                    ),
                    {"dataset_id": dataset_id},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                if (
                    str(existing["manifest_sha256"]) != manifest_sha256
                    or str(existing["member_identity_sha256"]) != member_identity_sha256
                    or str(existing["manifest_json"]) != manifest_json
                ):
                    raise LockedSetConflictError(
                        "locked-set dataset identity belongs to a different manifest"
                    )
                return LockedSetSealOutcome(
                    dataset=_dataset_from_row(existing),
                    created=False,
                )
            reused_members = connection.execute(
                text(
                    """
                    SELECT dataset_id
                    FROM locked_set_datasets
                    WHERE manifest_sha256 = :manifest_sha256
                       OR member_identity_sha256 = :member_identity_sha256
                    """
                ),
                {
                    "manifest_sha256": manifest_sha256,
                    "member_identity_sha256": member_identity_sha256,
                },
            ).scalar_one_or_none()
            if reused_members is not None:
                raise LockedSetConflictError(
                    "locked-set manifest or member identity is already sealed"
                )
            connection.execute(
                text(
                    """
                    INSERT INTO locked_set_datasets (
                        dataset_id, manifest_sha256, member_identity_sha256,
                        manifest_json, state, record_version, created_by,
                        created_at, updated_at
                    ) VALUES (
                        :dataset_id, :manifest_sha256,
                        :member_identity_sha256, :manifest_json,
                        'sealed', 1, :created_by, :created_at, :updated_at
                    )
                    """
                ),
                {
                    "dataset_id": dataset_id,
                    "manifest_sha256": manifest_sha256,
                    "member_identity_sha256": member_identity_sha256,
                    "manifest_json": manifest_json,
                    "created_by": actor,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            dataset, _ = self._load_dataset(connection, dataset_id)
            return LockedSetSealOutcome(dataset=dataset, created=True)

    def persist_preflight_attestation(
        self,
        *,
        dataset_id: str,
        expected_record_version: int,
        snapshot: PersistedExclusionSnapshot,
        attestation: LockedSetReleaseAttestation,
        actor_id: str,
    ) -> LockedSetPreflightOutcome:
        identity = _required_text(dataset_id, "dataset_id")
        actor = _required_text(actor_id, "actor_id")
        if (
            not isinstance(expected_record_version, int)
            or isinstance(expected_record_version, bool)
            or expected_record_version < 1
        ):
            raise LockedSetPersistenceError("expected_record_version is invalid")
        if not isinstance(snapshot, PersistedExclusionSnapshot):
            raise LockedSetPersistenceError("persisted exclusion snapshot is required")
        if not isinstance(attestation, LockedSetReleaseAttestation):
            raise LockedSetPersistenceError("locked-set release attestation is invalid")
        if (
            attestation.dataset_id != identity
            or attestation.waybill_count != 50
            or attestation.image_count != 100
            or attestation.total_bytes <= 0
            or attestation.exclusion_source_id != snapshot.snapshot.source_id
            or attestation.exclusion_snapshot_sha256 != snapshot.snapshot.canonical_sha256
        ):
            raise LockedSetPersistenceError(
                "locked-set preflight attestation does not match its authority"
            )
        completed_at = _utc_now()
        attestation_id = attestation.attestation_sha256
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            dataset, _ = self._load_dataset(connection, identity)
            if dataset.state == "invalidated_to_development":
                raise LockedSetStateTransitionError(
                    "invalidated locked set cannot regain preflight authority"
                )
            existing = (
                connection.execute(
                    text(
                        """
                        SELECT
                            attestation_id, dataset_id, manifest_sha256,
                            exclusion_snapshot_id,
                            exclusion_snapshot_sha256, exclusion_source_id,
                            inventory_high_watermark, waybill_count, image_count,
                            total_bytes, attestation_sha256, actor_id,
                            completed_at
                        FROM locked_set_preflight_attestations
                        WHERE attestation_id = :attestation_id
                        """
                    ),
                    {"attestation_id": attestation_id},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                persisted = _attestation_from_row(existing)
                if (
                    dataset.state != "preflight_passed"
                    or persisted.dataset_id != identity
                    or persisted.manifest_sha256 != attestation.manifest_sha256
                    or persisted.exclusion_snapshot_id != snapshot.snapshot_id
                    or persisted.inventory_high_watermark != snapshot.inventory_high_watermark
                ):
                    raise LockedSetConflictError("preflight attestation identity conflicts")
                return LockedSetPreflightOutcome(
                    dataset=dataset,
                    attestation=persisted,
                    applied=False,
                )
            if dataset.state != "sealed":
                raise LockedSetStateTransitionError("locked set is not awaiting preflight")
            if dataset.record_version != expected_record_version:
                raise LockedSetRecordVersionConflictError(
                    "locked set changed before preflight commit"
                )
            if dataset.manifest_sha256 != attestation.manifest_sha256:
                raise LockedSetConflictError("preflight manifest does not match sealed dataset")
            persisted_snapshot = self._load_snapshot(
                connection,
                snapshot.snapshot_id,
            )
            if persisted_snapshot != snapshot:
                raise LockedSetConflictError(
                    "preflight exclusion snapshot is not the persisted authority"
                )
            if _current_inventory_high_watermark(connection) != snapshot.inventory_high_watermark:
                raise LockedSetInventoryChangedError(
                    "locked-set exclusion inventory changed after snapshot"
                )
            connection.execute(
                text(
                    """
                    INSERT INTO locked_set_preflight_attestations (
                        attestation_id, dataset_id, manifest_sha256,
                        exclusion_snapshot_id, exclusion_snapshot_sha256,
                        exclusion_source_id, inventory_high_watermark,
                        waybill_count, image_count, total_bytes,
                        attestation_sha256, actor_id, completed_at
                    ) VALUES (
                        :attestation_id, :dataset_id, :manifest_sha256,
                        :exclusion_snapshot_id, :exclusion_snapshot_sha256,
                        :exclusion_source_id, :inventory_high_watermark,
                        :waybill_count, :image_count, :total_bytes,
                        :attestation_sha256, :actor_id, :completed_at
                    )
                    """
                ),
                {
                    "attestation_id": attestation_id,
                    "dataset_id": identity,
                    "manifest_sha256": attestation.manifest_sha256,
                    "exclusion_snapshot_id": snapshot.snapshot_id,
                    "exclusion_snapshot_sha256": (attestation.exclusion_snapshot_sha256),
                    "exclusion_source_id": attestation.exclusion_source_id,
                    "inventory_high_watermark": (snapshot.inventory_high_watermark),
                    "waybill_count": attestation.waybill_count,
                    "image_count": attestation.image_count,
                    "total_bytes": attestation.total_bytes,
                    "attestation_sha256": attestation.attestation_sha256,
                    "actor_id": actor,
                    "completed_at": completed_at,
                },
            )
            if self._failpoint is not None:
                self._failpoint("after_preflight_attestation")
            updated = connection.execute(
                text(
                    """
                    UPDATE locked_set_datasets
                    SET state = 'preflight_passed',
                        record_version = record_version + 1,
                        updated_at = :updated_at
                    WHERE dataset_id = :dataset_id
                      AND state = 'sealed'
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "dataset_id": identity,
                    "expected_record_version": expected_record_version,
                    "updated_at": completed_at,
                },
            )
            if updated.rowcount != 1:
                raise LockedSetRecordVersionConflictError(
                    "locked set changed before preflight commit"
                )
            persisted_dataset, _ = self._load_dataset(connection, identity)
            row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            attestation_id, dataset_id, manifest_sha256,
                            exclusion_snapshot_id,
                            exclusion_snapshot_sha256, exclusion_source_id,
                            inventory_high_watermark, waybill_count, image_count,
                            total_bytes, attestation_sha256, actor_id,
                            completed_at
                        FROM locked_set_preflight_attestations
                        WHERE attestation_id = :attestation_id
                        """
                    ),
                    {"attestation_id": attestation_id},
                )
                .mappings()
                .one()
            )
            return LockedSetPreflightOutcome(
                dataset=persisted_dataset,
                attestation=_attestation_from_row(row),
                applied=True,
            )

    def invalidate_locked_set(
        self,
        *,
        dataset_id: str,
        expected_record_version: int,
        influence_kind: str,
        reason: str,
        actor_id: str,
        idempotency_key: str,
    ) -> LockedSetInvalidationOutcome:
        identity = _required_text(dataset_id, "dataset_id")
        influence = _required_text(
            influence_kind,
            "influence_kind",
            maximum=40,
        )
        if influence not in LOCKED_SET_INFLUENCE_KINDS:
            raise LockedSetPersistenceError("locked-set invalidation influence kind is invalid")
        explanation = _required_text(reason, "reason", maximum=500)
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        if (
            not isinstance(expected_record_version, int)
            or isinstance(expected_record_version, bool)
            or expected_record_version < 1
        ):
            raise LockedSetPersistenceError("expected_record_version is invalid")
        request_hash = _canonical_sha256(
            {
                "actor_id": actor,
                "dataset_id": identity,
                "influence_kind": influence,
                "reason": explanation,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay_row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            invalidation_id, dataset_id, influence_kind,
                            reason, actor_id, idempotency_key,
                            request_hash, created_at
                        FROM locked_set_invalidations
                        WHERE idempotency_key = :idempotency_key
                        """
                    ),
                    {"idempotency_key": key},
                )
                .mappings()
                .one_or_none()
            )
            if replay_row is not None:
                if str(replay_row["request_hash"]) != request_hash:
                    raise LockedSetIdempotencyConflictError(
                        "invalidation idempotency key belongs to different input"
                    )
                dataset, _ = self._load_dataset(connection, identity)
                return LockedSetInvalidationOutcome(
                    dataset=dataset,
                    invalidation=_invalidation_from_row(replay_row),
                    applied=False,
                )
            dataset, manifest_json = self._load_dataset(connection, identity)
            if dataset.record_version != expected_record_version:
                raise LockedSetRecordVersionConflictError("locked set changed before invalidation")
            if dataset.state == "invalidated_to_development":
                raise LockedSetStateTransitionError(
                    "locked set already has a different invalidation"
                )
            existing_invalidation = connection.execute(
                text(
                    "SELECT invalidation_id FROM locked_set_invalidations "
                    "WHERE dataset_id = :dataset_id"
                ),
                {"dataset_id": identity},
            ).scalar_one_or_none()
            if existing_invalidation is not None:
                raise LockedSetStateTransitionError(
                    "locked set already has a different invalidation"
                )
            try:
                payload = json.loads(manifest_json)
            except json.JSONDecodeError as exc:
                raise LockedSetPersistenceError("sealed locked-set manifest is invalid") from exc
            waybills = payload.get("waybills") if isinstance(payload, dict) else None
            if not isinstance(waybills, list) or len(waybills) != 50:
                raise LockedSetPersistenceError("sealed locked-set manifest is incomplete")
            invalidation_id = uuid4().hex
            connection.execute(
                text(
                    """
                    INSERT INTO locked_set_invalidations (
                        invalidation_id, dataset_id, influence_kind, reason,
                        actor_id, idempotency_key, request_hash, created_at
                    ) VALUES (
                        :invalidation_id, :dataset_id, :influence_kind,
                        :reason, :actor_id, :idempotency_key,
                        :request_hash, :created_at
                    )
                    """
                ),
                {
                    "invalidation_id": invalidation_id,
                    "dataset_id": identity,
                    "influence_kind": influence,
                    "reason": explanation,
                    "actor_id": actor,
                    "idempotency_key": key,
                    "request_hash": request_hash,
                    "created_at": now,
                },
            )
            image_count = 0
            for raw_waybill in waybills:
                if not isinstance(raw_waybill, Mapping):
                    raise LockedSetPersistenceError("sealed locked-set waybill is invalid")
                waybill_identity = _required_sha256(
                    str(raw_waybill.get("waybill_identity_sha256", "")),
                    "waybill_identity_sha256",
                )
                register_exclusion_identity(
                    connection,
                    category="prior_waybill_identity",
                    identity_sha256=waybill_identity,
                    source_kind="invalidated_locked_set",
                    source_id=identity,
                    created_at=now,
                )
                images = raw_waybill.get("images")
                if not isinstance(images, list) or len(images) != 2:
                    raise LockedSetPersistenceError("sealed locked-set waybill images are invalid")
                for raw_image in images:
                    if not isinstance(raw_image, Mapping):
                        raise LockedSetPersistenceError("sealed locked-set image is invalid")
                    register_exclusion_identity(
                        connection,
                        category="development_image",
                        identity_sha256=_required_sha256(
                            str(raw_image.get("image_sha256", "")),
                            "image_sha256",
                        ),
                        source_kind="invalidated_locked_set",
                        source_id=identity,
                        created_at=now,
                    )
                    image_count += 1
            if image_count != 100:
                raise LockedSetPersistenceError("sealed locked-set image count is invalid")
            if self._failpoint is not None:
                self._failpoint("after_invalidation_inventory")
            updated = connection.execute(
                text(
                    """
                    UPDATE locked_set_datasets
                    SET state = 'invalidated_to_development',
                        record_version = record_version + 1,
                        updated_at = :updated_at
                    WHERE dataset_id = :dataset_id
                      AND state IN (
                          'sealed',
                          'preflight_passed',
                          'formal_evaluated'
                      )
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "dataset_id": identity,
                    "expected_record_version": expected_record_version,
                    "updated_at": now,
                },
            )
            if updated.rowcount != 1:
                raise LockedSetRecordVersionConflictError("locked set changed before invalidation")
            persisted_dataset, _ = self._load_dataset(connection, identity)
            return LockedSetInvalidationOutcome(
                dataset=persisted_dataset,
                invalidation=LockedSetInvalidationRecord(
                    invalidation_id=invalidation_id,
                    dataset_id=identity,
                    influence_kind=influence,
                    reason=explanation,
                    actor_id=actor,
                    idempotency_key=key,
                    created_at=now,
                ),
                applied=True,
            )
