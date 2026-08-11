from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from dahe.application.template_studio.candidate_role_evaluation import (
    EVALUATOR_VERSION as CANDIDATE_ROLE_EVALUATOR_VERSION,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    CandidateDevelopmentRoleEvaluation,
)
from dahe.application.template_studio.development_evaluation import (
    DevelopmentEvaluationReport,
)

COMPOSITE_EVALUATOR_VERSION = "dahe.loop7.composite-lifecycle-evaluation.v1"
AUTHORIZATION_SCOPE = "ticket_role_evidence"
_RUNTIME_KINDS = ("cpu", "gpu")
_DIRECT_ROLES = frozenset({"loading", "unloading"})
_SUPPORT_CONTRACT = "human_role_correct_and_template_evidence_hit_and_final_role_correct"
_SHA256_LENGTH = 64
_REAL_IMAGE_COUNT = 100
_REAL_PAIR_COUNT = 50
_REAL_ATTEMPT_COUNT = _REAL_IMAGE_COUNT * len(_RUNTIME_KINDS)
_REAL_COMPONENT_KEYS = frozenset(
    {
        "attempt_contract",
        "authorizing_lifecycle_evidence",
        "cpu_gpu_role_consistency",
        "development_only",
        "evaluation_sha256",
        "evaluator_version",
        "formal_accuracy_claim",
        "formal_release_eligible",
        "kind",
        "runtimes",
        "schema_version",
        "source",
        "status",
        "template_contract",
    }
)
_REAL_SOURCE_KEYS = frozenset(
    {
        "composition_evidence_sha256",
        "manifest_sha256",
        "ocr_capture_build_sha256",
        "ocr_evidence_sha256",
        "ocr_pipeline_contract_sha256",
        "package_sha256",
        "quality_coverage_sha256",
        "record_set_sha256",
        "review_history_authority_sha256",
        "reviewer_id_sha256",
        "role_evaluator_build_sha256",
        "runtime_set_sha256",
        "source_authority_sha256",
    }
)
_REAL_TEMPLATE_CONTRACT_KEYS = frozenset(
    {
        "candidate_count",
        "candidates",
        "current_shadow_count",
        "dataset_id_sha256",
        "matcher_fingerprint",
        "policy_fingerprint",
        "selected_template_count",
        "template_set_fingerprint",
    }
)
_REAL_CANDIDATE_KEYS = frozenset(
    {
        "content_sha256",
        "family_id_sha256",
        "lifecycle",
        "role",
        "version_id",
    }
)
_REAL_RUNTIME_KEYS = frozenset(
    {
        "candidate_support",
        "matcher_latency_ms",
        "ocr_latency_ms",
        "orientation",
        "pair_status",
        "role",
        "runtime_kind",
        "sample_count",
    }
)


class CompositeLifecycleEvaluationError(RuntimeError):
    """Raised when the two lifecycle evidence components do not reconcile."""


@dataclass(frozen=True, slots=True)
class CompositeLifecycleEvaluation:
    payload: dict[str, object]
    evaluation_id: str
    evaluation_sha256: str
    dataset_id: str
    dataset_manifest_sha256: str
    stable_outcome_sha256: str
    gate_passed: bool


@dataclass(frozen=True, slots=True)
class _RealBindings:
    ocr_capture_build_sha256: str
    role_evaluator_build_sha256: str
    runtime_set_sha256: str
    matcher_fingerprint: str
    policy_fingerprint: str
    template_set_fingerprint: str
    candidate_set_sha256: str
    source_authority_sha256: str
    ocr_evidence_sha256: str
    candidates: tuple[tuple[str, str], ...]


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CompositeLifecycleEvaluationError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(
        value,
        (str, bytes, bytearray),
    ):
        raise CompositeLifecycleEvaluationError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise CompositeLifecycleEvaluationError(f"{label} must be non-empty text")
    return value


def _sha256(value: object, *, label: str) -> str:
    digest = _text(value, label=label)
    if (
        len(digest) != _SHA256_LENGTH
        or digest != digest.lower()
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise CompositeLifecycleEvaluationError(f"{label} must be a lowercase SHA-256")
    return digest


def _integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CompositeLifecycleEvaluationError(f"{label} must be an integer")
    return value


def _require_exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    observed = set(value)
    if observed == expected:
        return
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if unexpected:
        details.append("unexpected " + ", ".join(unexpected))
    raise CompositeLifecycleEvaluationError(f"{label} schema is invalid: " + "; ".join(details))


def _validate_latency_schema(
    value: object,
    *,
    label: str,
) -> None:
    latency = _mapping(value, label=label)
    _require_exact_keys(
        latency,
        frozenset({"p50", "p95", "sample_count"}),
        label=label,
    )


def _validate_current_real_component_schema(
    payload: Mapping[str, object],
) -> None:
    """Reject legacy, partial, or extended candidate-role evidence."""

    _require_exact_keys(
        payload,
        _REAL_COMPONENT_KEYS,
        label="real component",
    )
    if payload.get("evaluator_version") != CANDIDATE_ROLE_EVALUATOR_VERSION:
        raise CompositeLifecycleEvaluationError("real component evaluator version is not current")
    attempt_contract = _mapping(
        payload.get("attempt_contract"),
        label="real attempt contract",
    )
    _require_exact_keys(
        attempt_contract,
        frozenset(
            {
                "completed_attempt_count",
                "expected_attempt_count",
                "technical_failure_count",
            }
        ),
        label="real attempt contract",
    )
    consistency = _mapping(
        payload.get("cpu_gpu_role_consistency"),
        label="CPU/GPU role consistency",
    )
    _require_exact_keys(
        consistency,
        frozenset(
            {
                "agreement_rate",
                "match_count",
                "mismatch_count",
                "mismatches",
                "sample_count",
            }
        ),
        label="CPU/GPU role consistency",
    )
    source = _mapping(
        payload.get("source"),
        label="real component source",
    )
    _require_exact_keys(
        source,
        _REAL_SOURCE_KEYS,
        label="real component source",
    )
    for field in _REAL_SOURCE_KEYS:
        _sha256(
            source.get(field),
            label=f"real source {field}",
        )
    template_contract = _mapping(
        payload.get("template_contract"),
        label="real template contract",
    )
    _require_exact_keys(
        template_contract,
        _REAL_TEMPLATE_CONTRACT_KEYS,
        label="real template contract",
    )
    for field in (
        "dataset_id_sha256",
        "matcher_fingerprint",
        "policy_fingerprint",
        "template_set_fingerprint",
    ):
        _sha256(
            template_contract.get(field),
            label=f"real template contract {field}",
        )
    for raw_candidate in _sequence(
        template_contract.get("candidates"),
        label="real candidates",
    ):
        candidate = _mapping(
            raw_candidate,
            label="real candidate",
        )
        _require_exact_keys(
            candidate,
            _REAL_CANDIDATE_KEYS,
            label="real candidate",
        )
        _sha256(
            candidate.get("family_id_sha256"),
            label="real candidate family identity",
        )
        _text(
            candidate.get("lifecycle"),
            label="real candidate lifecycle",
        )

    runtimes = _mapping(
        payload.get("runtimes"),
        label="real runtime results",
    )
    if set(runtimes) != set(_RUNTIME_KINDS):
        raise CompositeLifecycleEvaluationError("real runtime result schema is invalid")
    for runtime_kind in _RUNTIME_KINDS:
        runtime = _mapping(
            runtimes[runtime_kind],
            label=f"{runtime_kind} runtime result",
        )
        _require_exact_keys(
            runtime,
            _REAL_RUNTIME_KEYS,
            label=f"{runtime_kind} runtime result",
        )
        support = _mapping(
            runtime.get("candidate_support"),
            label=f"{runtime_kind} candidate support",
        )
        _require_exact_keys(
            support,
            frozenset(
                {
                    "results",
                    "support_contract",
                    "supported_candidate_count",
                }
            ),
            label=f"{runtime_kind} candidate support",
        )
        for raw_row in _sequence(
            support.get("results"),
            label=f"{runtime_kind} candidate support results",
        ):
            _require_exact_keys(
                _mapping(
                    raw_row,
                    label=f"{runtime_kind} candidate support result",
                ),
                frozenset(
                    {
                        "candidate_version_id",
                        "support_count",
                        "supporting_subject_sha256s",
                    }
                ),
                label=f"{runtime_kind} candidate support result",
            )
        _validate_latency_schema(
            runtime.get("matcher_latency_ms"),
            label=f"{runtime_kind} matcher latency",
        )
        ocr_latency = _mapping(
            runtime.get("ocr_latency_ms"),
            label=f"{runtime_kind} OCR latency",
        )
        _require_exact_keys(
            ocr_latency,
            frozenset({"wall", "worker"}),
            label=f"{runtime_kind} OCR latency",
        )
        for latency_kind in ("wall", "worker"):
            _validate_latency_schema(
                ocr_latency.get(latency_kind),
                label=f"{runtime_kind} OCR {latency_kind} latency",
            )
        orientation = _mapping(
            runtime.get("orientation"),
            label=f"{runtime_kind} orientation metrics",
        )
        _require_exact_keys(
            orientation,
            frozenset(
                {
                    "agreement_rate",
                    "confusion_matrix",
                    "match_count",
                    "mismatch_count",
                    "sample_count",
                }
            ),
            label=f"{runtime_kind} orientation metrics",
        )
        pair_status = _mapping(
            runtime.get("pair_status"),
            label=f"{runtime_kind} pair metrics",
        )
        _require_exact_keys(
            pair_status,
            frozenset(
                {
                    "confusion_matrix",
                    "expected_counts",
                    "mismatch_count",
                    "predicted_counts",
                    "results",
                    "sample_count",
                }
            ),
            label=f"{runtime_kind} pair metrics",
        )
        for raw_row in _sequence(
            pair_status.get("results"),
            label=f"{runtime_kind} pair results",
        ):
            _require_exact_keys(
                _mapping(
                    raw_row,
                    label=f"{runtime_kind} pair result",
                ),
                frozenset(
                    {
                        "domain_issue",
                        "expected_status",
                        "matches_truth",
                        "pair_sha256",
                        "predicted_status",
                    }
                ),
                label=f"{runtime_kind} pair result",
            )
        role = _mapping(
            runtime.get("role"),
            label=f"{runtime_kind} role metrics",
        )
        _require_exact_keys(
            role,
            frozenset(
                {
                    "confusion_matrix",
                    "direct_loading_unloading_error_count",
                    "high_confidence_error_count",
                    "results",
                    "unknown_rate",
                }
            ),
            label=f"{runtime_kind} role metrics",
        )
        for raw_row in _sequence(
            role.get("results"),
            label=f"{runtime_kind} role results",
        ):
            _require_exact_keys(
                _mapping(
                    raw_row,
                    label=f"{runtime_kind} role result",
                ),
                frozenset(
                    {
                        "assessment_sha256",
                        "confidence",
                        "detected_orientation_degrees",
                        "expected_orientation_degrees",
                        "high_confidence",
                        "matched_template_version_ids",
                        "prediction",
                        "subject_sha256",
                        "truth",
                    }
                ),
                label=f"{runtime_kind} role result",
            )


def _candidate_identities_from_real(
    template_contract: Mapping[str, object],
) -> tuple[tuple[tuple[str, str], ...], dict[str, str]]:
    raw_candidates = _sequence(
        template_contract.get("candidates"),
        label="real candidate set",
    )
    candidates: list[tuple[str, str]] = []
    roles: dict[str, str] = {}
    version_ids: set[str] = set()
    for raw_candidate in raw_candidates:
        candidate = _mapping(raw_candidate, label="real candidate")
        version_id = _text(
            candidate.get("version_id"),
            label="real candidate version ID",
        )
        content_sha256 = _sha256(
            candidate.get("content_sha256"),
            label="real candidate content SHA-256",
        )
        role = _text(
            candidate.get("role"),
            label="real candidate role",
        )
        if role not in _DIRECT_ROLES:
            raise CompositeLifecycleEvaluationError("real candidate role is invalid")
        if version_id in version_ids:
            raise CompositeLifecycleEvaluationError(
                "real candidate set contains duplicate versions"
            )
        version_ids.add(version_id)
        candidates.append((version_id, content_sha256))
        roles[version_id] = role
    stated_count = _integer(
        template_contract.get("candidate_count"),
        label="real candidate count",
    )
    if not candidates or stated_count != len(candidates):
        raise CompositeLifecycleEvaluationError("real candidate set count does not reconcile")
    return tuple(sorted(candidates)), roles


def _candidate_set_sha256(
    candidates: Sequence[tuple[str, str]],
) -> str:
    return _canonical_sha256(
        [
            {
                "content_sha256": content_sha256,
                "version_id": version_id,
            }
            for version_id, content_sha256 in candidates
        ]
    )


def _validate_role_rows(
    runtime: Mapping[str, object],
    *,
    runtime_kind: str,
) -> Mapping[str, Mapping[str, object]]:
    role = _mapping(
        runtime.get("role"),
        label=f"{runtime_kind} role metrics",
    )
    rows = _sequence(
        role.get("results"),
        label=f"{runtime_kind} role results",
    )
    if len(rows) != _REAL_IMAGE_COUNT:
        raise CompositeLifecycleEvaluationError(
            f"{runtime_kind} role result coverage is incomplete"
        )
    by_subject: dict[str, Mapping[str, object]] = {}
    direct_error_count = 0
    high_confidence_error_count = 0
    for raw_row in rows:
        row = _mapping(
            raw_row,
            label=f"{runtime_kind} role result",
        )
        subject_sha256 = _sha256(
            row.get("subject_sha256"),
            label=f"{runtime_kind} role subject SHA-256",
        )
        if subject_sha256 in by_subject:
            raise CompositeLifecycleEvaluationError(f"{runtime_kind} role subjects are duplicated")
        truth = _text(
            row.get("truth"),
            label=f"{runtime_kind} role truth",
        )
        prediction = _text(
            row.get("prediction"),
            label=f"{runtime_kind} role prediction",
        )
        if truth not in {"loading", "unloading", "unknown"} or prediction not in {
            "loading",
            "unloading",
            "unknown",
        }:
            raise CompositeLifecycleEvaluationError(f"{runtime_kind} role result is invalid")
        high_confidence = row.get("high_confidence")
        if not isinstance(high_confidence, bool):
            raise CompositeLifecycleEvaluationError(
                f"{runtime_kind} high-confidence flag is invalid"
            )
        matched_template_ids = _sequence(
            row.get("matched_template_version_ids"),
            label=f"{runtime_kind} matched template versions",
        )
        normalized_template_ids = [
            _text(
                version_id,
                label=f"{runtime_kind} matched template version",
            )
            for version_id in matched_template_ids
        ]
        if normalized_template_ids != sorted(normalized_template_ids) or len(
            set(normalized_template_ids)
        ) != len(normalized_template_ids):
            raise CompositeLifecycleEvaluationError(
                f"{runtime_kind} matched template versions are invalid"
            )
        mismatch = truth != prediction
        direct_error_count += mismatch and truth in _DIRECT_ROLES and prediction in _DIRECT_ROLES
        high_confidence_error_count += mismatch and high_confidence
        by_subject[subject_sha256] = row
    stated_direct = _integer(
        role.get("direct_loading_unloading_error_count"),
        label=f"{runtime_kind} direct role error count",
    )
    if stated_direct != direct_error_count or direct_error_count != 0:
        raise CompositeLifecycleEvaluationError(
            f"{runtime_kind} direct loading/unloading role error gate failed"
        )
    stated_high_confidence = _integer(
        role.get("high_confidence_error_count"),
        label=f"{runtime_kind} high-confidence error count",
    )
    if stated_high_confidence != high_confidence_error_count or high_confidence_error_count != 0:
        raise CompositeLifecycleEvaluationError(
            f"{runtime_kind} high-confidence role error gate failed"
        )
    return by_subject


def _validate_pairs(
    runtime: Mapping[str, object],
    *,
    runtime_kind: str,
) -> None:
    pairs = _mapping(
        runtime.get("pair_status"),
        label=f"{runtime_kind} pair metrics",
    )
    rows = _sequence(
        pairs.get("results"),
        label=f"{runtime_kind} pair results",
    )
    sample_count = _integer(
        pairs.get("sample_count"),
        label=f"{runtime_kind} pair sample count",
    )
    mismatch_count = _integer(
        pairs.get("mismatch_count"),
        label=f"{runtime_kind} pair mismatch count",
    )
    if sample_count != _REAL_PAIR_COUNT or len(rows) != _REAL_PAIR_COUNT:
        raise CompositeLifecycleEvaluationError(f"{runtime_kind} pair coverage is incomplete")
    recomputed_mismatches = 0
    pair_ids: set[str] = set()
    for raw_row in rows:
        row = _mapping(raw_row, label=f"{runtime_kind} pair result")
        pair_sha256 = _sha256(
            row.get("pair_sha256"),
            label=f"{runtime_kind} pair SHA-256",
        )
        if pair_sha256 in pair_ids:
            raise CompositeLifecycleEvaluationError(f"{runtime_kind} pair results are duplicated")
        pair_ids.add(pair_sha256)
        matches_truth = row.get("matches_truth")
        if not isinstance(matches_truth, bool):
            raise CompositeLifecycleEvaluationError(
                f"{runtime_kind} pair reconciliation is invalid"
            )
        expected = _text(
            row.get("expected_status"),
            label=f"{runtime_kind} expected pair status",
        )
        predicted = _text(
            row.get("predicted_status"),
            label=f"{runtime_kind} predicted pair status",
        )
        actual_match = expected == predicted
        if matches_truth is not actual_match:
            raise CompositeLifecycleEvaluationError(
                f"{runtime_kind} pair reconciliation is inconsistent"
            )
        recomputed_mismatches += not actual_match
    if mismatch_count != recomputed_mismatches or recomputed_mismatches != 0:
        raise CompositeLifecycleEvaluationError(f"{runtime_kind} pair gate failed")


def _validate_candidate_support(
    runtime: Mapping[str, object],
    *,
    runtime_kind: str,
    candidates: Sequence[tuple[str, str]],
    candidate_roles: Mapping[str, str],
    role_rows: Mapping[str, Mapping[str, object]],
) -> None:
    support = _mapping(
        runtime.get("candidate_support"),
        label=f"{runtime_kind} candidate support",
    )
    if support.get("support_contract") != _SUPPORT_CONTRACT:
        raise CompositeLifecycleEvaluationError(
            f"{runtime_kind} candidate support contract is invalid"
        )
    rows = _sequence(
        support.get("results"),
        label=f"{runtime_kind} candidate support results",
    )
    expected_versions = {version_id for version_id, _ in candidates}
    observed_versions: set[str] = set()
    for raw_row in rows:
        row = _mapping(
            raw_row,
            label=f"{runtime_kind} candidate support result",
        )
        version_id = _text(
            row.get("candidate_version_id"),
            label=f"{runtime_kind} supported candidate version",
        )
        if version_id in observed_versions:
            raise CompositeLifecycleEvaluationError(
                f"{runtime_kind} candidate support contains duplicates"
            )
        observed_versions.add(version_id)
        count = _integer(
            row.get("support_count"),
            label=f"{runtime_kind} candidate support count",
        )
        subjects = _sequence(
            row.get("supporting_subject_sha256s"),
            label=f"{runtime_kind} supporting subjects",
        )
        subject_hashes = {
            _sha256(
                subject,
                label=f"{runtime_kind} supporting subject SHA-256",
            )
            for subject in subjects
        }
        if count < 1 or count != len(subjects) or len(subject_hashes) != len(subjects):
            raise CompositeLifecycleEvaluationError(f"{runtime_kind} candidate support gate failed")
        candidate_role = candidate_roles.get(version_id)
        for subject_sha256 in subject_hashes:
            result = role_rows.get(subject_sha256)
            if result is None:
                raise CompositeLifecycleEvaluationError(
                    f"{runtime_kind} candidate support subject is missing"
                )
            matched_template_ids = _sequence(
                result.get("matched_template_version_ids"),
                label=f"{runtime_kind} supported template matches",
            )
            if (
                result.get("truth") != candidate_role
                or result.get("prediction") != candidate_role
                or version_id not in matched_template_ids
            ):
                raise CompositeLifecycleEvaluationError(
                    f"{runtime_kind} candidate support evidence is invalid"
                )
    supported_count = _integer(
        support.get("supported_candidate_count"),
        label=f"{runtime_kind} supported candidate count",
    )
    if observed_versions != expected_versions or supported_count != len(expected_versions):
        raise CompositeLifecycleEvaluationError(
            f"{runtime_kind} candidate support coverage is incomplete"
        )


def _validate_real_gate(
    payload: Mapping[str, object],
    *,
    candidates: Sequence[tuple[str, str]],
    candidate_roles: Mapping[str, str],
) -> None:
    attempt_contract = _mapping(
        payload.get("attempt_contract"),
        label="real attempt contract",
    )
    expected_attempts = _integer(
        attempt_contract.get("expected_attempt_count"),
        label="real expected attempt count",
    )
    completed_attempts = _integer(
        attempt_contract.get("completed_attempt_count"),
        label="real completed attempt count",
    )
    technical_failures = _integer(
        attempt_contract.get("technical_failure_count"),
        label="real technical failure count",
    )
    if expected_attempts != _REAL_ATTEMPT_COUNT or completed_attempts != _REAL_ATTEMPT_COUNT:
        raise CompositeLifecycleEvaluationError("real runtime attempt coverage is incomplete")
    if technical_failures != 0:
        raise CompositeLifecycleEvaluationError("real runtime technical failure gate failed")

    runtimes = _mapping(
        payload.get("runtimes"),
        label="real runtime results",
    )
    if set(runtimes) != set(_RUNTIME_KINDS):
        raise CompositeLifecycleEvaluationError("real runtime result set is incomplete")
    role_rows: dict[str, Mapping[str, Mapping[str, object]]] = {}
    for runtime_kind in _RUNTIME_KINDS:
        runtime = _mapping(
            runtimes[runtime_kind],
            label=f"{runtime_kind} runtime result",
        )
        if runtime.get("runtime_kind") != runtime_kind:
            raise CompositeLifecycleEvaluationError(f"{runtime_kind} runtime identity changed")
        if (
            _integer(
                runtime.get("sample_count"),
                label=f"{runtime_kind} sample count",
            )
            != _REAL_IMAGE_COUNT
        ):
            raise CompositeLifecycleEvaluationError(
                f"{runtime_kind} role result coverage is incomplete"
            )
        role_rows[runtime_kind] = _validate_role_rows(
            runtime,
            runtime_kind=runtime_kind,
        )
        _validate_pairs(runtime, runtime_kind=runtime_kind)
        _validate_candidate_support(
            runtime,
            runtime_kind=runtime_kind,
            candidates=candidates,
            candidate_roles=candidate_roles,
            role_rows=role_rows[runtime_kind],
        )

    consistency = _mapping(
        payload.get("cpu_gpu_role_consistency"),
        label="CPU/GPU role consistency",
    )
    if (
        _integer(
            consistency.get("sample_count"),
            label="CPU/GPU role consistency sample count",
        )
        != _REAL_IMAGE_COUNT
        or _integer(
            consistency.get("match_count"),
            label="CPU/GPU role consistency match count",
        )
        != _REAL_IMAGE_COUNT
        or _integer(
            consistency.get("mismatch_count"),
            label="CPU/GPU role consistency mismatch count",
        )
        != 0
        or list(
            _sequence(
                consistency.get("mismatches"),
                label="CPU/GPU role consistency mismatches",
            )
        )
    ):
        raise CompositeLifecycleEvaluationError("CPU/GPU final role consistency gate failed")
    cpu_rows = role_rows["cpu"]
    gpu_rows = role_rows["gpu"]
    if set(cpu_rows) != set(gpu_rows):
        raise CompositeLifecycleEvaluationError("CPU/GPU final role membership is incomplete")
    if any(
        cpu_rows[subject].get("prediction") != gpu_rows[subject].get("prediction")
        for subject in cpu_rows
    ):
        raise CompositeLifecycleEvaluationError("CPU/GPU final role consistency gate failed")


def _validate_real_component(
    component: CandidateDevelopmentRoleEvaluation,
    *,
    expected_role_evaluator_build_sha256: str,
    expected_runtime_set_sha256: str,
) -> _RealBindings:
    if not isinstance(component, CandidateDevelopmentRoleEvaluation):
        raise CompositeLifecycleEvaluationError(
            "real component must be a CandidateDevelopmentRoleEvaluation"
        )
    payload = _mapping(component.payload, label="real component")
    stated_evaluation_sha256 = _sha256(
        payload.get("evaluation_sha256"),
        label="real component evaluation SHA-256",
    )
    payload_without_hash = {
        key: value for key, value in payload.items() if key != "evaluation_sha256"
    }
    expected_evaluation_sha256 = _canonical_sha256(payload_without_hash)
    if (
        component.evaluation_sha256 != stated_evaluation_sha256
        or stated_evaluation_sha256 != expected_evaluation_sha256
    ):
        raise CompositeLifecycleEvaluationError("real component evaluation hash does not reconcile")
    _validate_current_real_component_schema(payload)
    if (
        payload.get("kind") != "candidate_review_development_role_template_evaluation"
        or payload.get("schema_version") != 2
        or payload.get("status") != "completed"
        or payload.get("development_only") is not True
        or payload.get("formal_accuracy_claim") is not False
        or payload.get("formal_release_eligible") is not False
        or payload.get("authorizing_lifecycle_evidence") is not False
    ):
        raise CompositeLifecycleEvaluationError(
            "real component development-only contract is invalid"
        )
    source = _mapping(payload.get("source"), label="real component source")
    ocr_capture_build_sha256 = _sha256(
        source.get("ocr_capture_build_sha256"),
        label="OCR capture build SHA-256",
    )
    role_evaluator_build_sha256 = _sha256(
        source.get("role_evaluator_build_sha256"),
        label="role evaluator build SHA-256",
    )
    runtime_set_sha256 = _sha256(
        source.get("runtime_set_sha256"),
        label="real runtime-set SHA-256",
    )
    if role_evaluator_build_sha256 != expected_role_evaluator_build_sha256:
        raise CompositeLifecycleEvaluationError("role evaluator build binding does not match")
    if runtime_set_sha256 != expected_runtime_set_sha256:
        raise CompositeLifecycleEvaluationError("runtime-set binding does not match")
    template_contract = _mapping(
        payload.get("template_contract"),
        label="real template contract",
    )
    candidates, candidate_roles = _candidate_identities_from_real(template_contract)
    _validate_real_gate(
        payload,
        candidates=candidates,
        candidate_roles=candidate_roles,
    )
    return _RealBindings(
        ocr_capture_build_sha256=ocr_capture_build_sha256,
        role_evaluator_build_sha256=role_evaluator_build_sha256,
        runtime_set_sha256=runtime_set_sha256,
        matcher_fingerprint=_sha256(
            template_contract.get("matcher_fingerprint"),
            label="real matcher fingerprint",
        ),
        policy_fingerprint=_sha256(
            template_contract.get("policy_fingerprint"),
            label="real role policy fingerprint",
        ),
        template_set_fingerprint=_sha256(
            template_contract.get("template_set_fingerprint"),
            label="real template-set fingerprint",
        ),
        candidate_set_sha256=_candidate_set_sha256(candidates),
        source_authority_sha256=_sha256(
            source.get("source_authority_sha256"),
            label="real source authority SHA-256",
        ),
        ocr_evidence_sha256=_sha256(
            source.get("ocr_evidence_sha256"),
            label="real OCR evidence SHA-256",
        ),
        candidates=candidates,
    )


def _validate_synthetic_component(
    component: DevelopmentEvaluationReport,
) -> tuple[tuple[tuple[str, str], ...], str]:
    if not isinstance(component, DevelopmentEvaluationReport):
        raise CompositeLifecycleEvaluationError(
            "synthetic component must be a DevelopmentEvaluationReport"
        )
    if (
        component.dataset_kind != "authorizing_observation_dataset"
        or not component.gate_passed
        or component.expected_count != component.result_count
        or not component.items
        or not component.pair_items
        or any(item.truth_source != "code_authored_synthetic" for item in component.items)
    ):
        raise CompositeLifecycleEvaluationError("frozen synthetic component is not authorizing")
    candidates = tuple(
        sorted(
            (
                candidate.version_id,
                candidate.content_sha256,
            )
            for candidate in component.candidates
        )
    )
    return candidates, _candidate_set_sha256(candidates)


def composite_lifecycle_policy_fingerprint() -> str:
    """Return the immutable gate policy identity for composite lifecycle evidence."""

    return _canonical_sha256(
        {
            "authorization_scope": AUTHORIZATION_SCOPE,
            "candidate_support": {
                "minimum_per_candidate_per_runtime": 1,
                "required_contract": _SUPPORT_CONTRACT,
            },
            "components_required": [
                "reviewed_real_candidate_roles",
                "code_owned_frozen_synthetic",
            ],
            "cpu_gpu_final_role_mismatch_count": 0,
            "direct_loading_unloading_error_count_per_runtime": 0,
            "high_confidence_error_count_per_runtime": 0,
            "real_attempts": {
                "completed": _REAL_ATTEMPT_COUNT,
                "technical_failures": 0,
            },
            "real_pairs": {
                "matches_truth": _REAL_PAIR_COUNT,
                "sample_count": _REAL_PAIR_COUNT,
            },
            "runtime_kinds": list(_RUNTIME_KINDS),
            "schema_version": 1,
            "unknown_rate_threshold": None,
        }
    )


def validate_persisted_candidate_role_lifecycle_component(
    payload: Mapping[str, object],
    *,
    expected_evaluation_sha256: str,
    expected_role_evaluator_build_sha256: str,
    expected_runtime_set_sha256: str,
    expected_matcher_fingerprint: str,
    expected_policy_fingerprint: str,
    expected_template_set_fingerprint: str,
    expected_candidate_set_sha256: str,
) -> None:
    """Revalidate the full stored real component under current bindings."""

    component_payload = dict(_mapping(payload, label="persisted real candidate component"))
    evaluation_sha256 = _sha256(
        component_payload.get("evaluation_sha256"),
        label="persisted real candidate evaluation SHA-256",
    )
    if evaluation_sha256 != _sha256(
        expected_evaluation_sha256,
        label="expected real candidate evaluation SHA-256",
    ):
        raise CompositeLifecycleEvaluationError(
            "persisted real candidate evaluation binding changed"
        )
    bindings = _validate_real_component(
        CandidateDevelopmentRoleEvaluation(
            payload=component_payload,
            evaluation_sha256=evaluation_sha256,
        ),
        expected_role_evaluator_build_sha256=(
            _sha256(
                expected_role_evaluator_build_sha256,
                label="expected role evaluator build SHA-256",
            )
        ),
        expected_runtime_set_sha256=(
            _sha256(
                expected_runtime_set_sha256,
                label="expected runtime-set SHA-256",
            )
        ),
    )
    expected_bindings = {
        "candidate set": (
            bindings.candidate_set_sha256,
            _sha256(
                expected_candidate_set_sha256,
                label="expected candidate-set SHA-256",
            ),
        ),
        "matcher": (
            bindings.matcher_fingerprint,
            _sha256(
                expected_matcher_fingerprint,
                label="expected matcher fingerprint",
            ),
        ),
        "policy": (
            bindings.policy_fingerprint,
            _sha256(
                expected_policy_fingerprint,
                label="expected role policy fingerprint",
            ),
        ),
        "template set": (
            bindings.template_set_fingerprint,
            _sha256(
                expected_template_set_fingerprint,
                label="expected template-set fingerprint",
            ),
        ),
    }
    mismatches = [
        name for name, (actual, expected) in expected_bindings.items() if actual != expected
    ]
    if mismatches:
        raise CompositeLifecycleEvaluationError(
            "persisted real candidate binding mismatch: " + ", ".join(sorted(mismatches))
        )


def build_composite_lifecycle_evaluation(
    *,
    real_component: CandidateDevelopmentRoleEvaluation,
    synthetic_component: DevelopmentEvaluationReport,
    expected_role_evaluator_build_sha256: str,
    expected_runtime_set_sha256: str,
) -> CompositeLifecycleEvaluation:
    """Conjoin real reviewed evidence and code-owned synthetic evidence.

    The function accepts in-process typed component results only. In particular,
    it does not accept a caller-supplied JSON role report. The real component
    remains explicitly development-only; only the returned parent identity is
    eligible to cross the repository lifecycle boundary.
    """

    expected_build = _sha256(
        expected_role_evaluator_build_sha256,
        label="expected role evaluator build SHA-256",
    )
    expected_runtime = _sha256(
        expected_runtime_set_sha256,
        label="expected runtime-set SHA-256",
    )
    real = _validate_real_component(
        real_component,
        expected_role_evaluator_build_sha256=expected_build,
        expected_runtime_set_sha256=expected_runtime,
    )
    synthetic_candidates, synthetic_candidate_set_sha256 = _validate_synthetic_component(
        synthetic_component
    )
    binding_mismatches: list[str] = []
    if real.candidates != synthetic_candidates:
        binding_mismatches.append("candidate set")
    if real.candidate_set_sha256 != synthetic_candidate_set_sha256:
        binding_mismatches.append("candidate-set fingerprint")
    if real.matcher_fingerprint != synthetic_component.matcher_fingerprint:
        binding_mismatches.append("matcher")
    if real.policy_fingerprint != synthetic_component.policy_fingerprint:
        binding_mismatches.append("policy")
    if real.template_set_fingerprint != synthetic_component.template_set_fingerprint:
        binding_mismatches.append("template set")
    if binding_mismatches:
        raise CompositeLifecycleEvaluationError(
            "component binding mismatch: " + ", ".join(binding_mismatches)
        )

    composite_policy_sha256 = composite_lifecycle_policy_fingerprint()
    bindings = {
        "candidate_set_sha256": real.candidate_set_sha256,
        "composite_gate_policy_sha256": composite_policy_sha256,
        "frozen_synthetic_dataset_sha256": (synthetic_component.dataset_manifest_sha256),
        "matcher_fingerprint": real.matcher_fingerprint,
        "ocr_capture_build_sha256": real.ocr_capture_build_sha256,
        "policy_fingerprint": real.policy_fingerprint,
        "role_evaluator_build_sha256": real.role_evaluator_build_sha256,
        "runtime_set_sha256": real.runtime_set_sha256,
        "template_set_fingerprint": real.template_set_fingerprint,
    }
    dataset_manifest_sha256 = _canonical_sha256(
        {
            "authorization_scope": AUTHORIZATION_SCOPE,
            "candidate_set_sha256": real.candidate_set_sha256,
            "frozen_synthetic_dataset_sha256": (synthetic_component.dataset_manifest_sha256),
            "ocr_evidence_sha256": real.ocr_evidence_sha256,
            "real_source_authority_sha256": real.source_authority_sha256,
            "schema_version": 1,
        }
    )
    dataset_id = f"loop7-role-composite-{dataset_manifest_sha256[:20]}"
    checks = {
        "candidate_support_per_runtime": True,
        "cpu_gpu_final_role_consistency": True,
        "direct_loading_unloading_errors_zero": True,
        "frozen_synthetic_gate_passed": True,
        "high_confidence_errors_zero": True,
        "real_attempts_complete": True,
        "real_pair_results_all_match": True,
        "technical_failures_zero": True,
    }
    components = {
        "frozen_synthetic": {
            "dataset_id": synthetic_component.fixture_id,
            "dataset_manifest_sha256": (synthetic_component.dataset_manifest_sha256),
            "gate_passed": synthetic_component.gate_passed,
            "stable_outcome_sha256": (synthetic_component.stable_outcome_sha256),
        },
        "real_candidate_roles": {
            "authorizing_lifecycle_evidence": False,
            "development_only": True,
            "evaluation_sha256": real_component.evaluation_sha256,
            "formal_accuracy_claim": False,
            "formal_release_eligible": False,
            "ocr_evidence_sha256": real.ocr_evidence_sha256,
        },
    }
    stable_outcome_sha256 = _canonical_sha256(
        {
            "authorization_scope": AUTHORIZATION_SCOPE,
            "bindings": bindings,
            "components": components,
            "dataset_manifest_sha256": dataset_manifest_sha256,
            "gate_checks": checks,
            "schema_version": 1,
        }
    )
    evaluation_id = f"dev-role-composite-{stable_outcome_sha256[:28]}"
    payload: dict[str, object] = {
        "authorization_scope": AUTHORIZATION_SCOPE,
        "authorizing_lifecycle_evidence": True,
        "bindings": bindings,
        "components": components,
        "dataset_id": dataset_id,
        "dataset_manifest_sha256": dataset_manifest_sha256,
        "evaluation_id": evaluation_id,
        "evaluator_version": COMPOSITE_EVALUATOR_VERSION,
        "gate": {
            "checks": checks,
            "passed": True,
        },
        "kind": "composite_template_lifecycle_evaluation",
        "schema_version": 1,
        "stable_outcome_sha256": stable_outcome_sha256,
    }
    evaluation_sha256 = _canonical_sha256(payload)
    payload["evaluation_sha256"] = evaluation_sha256
    return CompositeLifecycleEvaluation(
        payload=payload,
        evaluation_id=evaluation_id,
        evaluation_sha256=evaluation_sha256,
        dataset_id=dataset_id,
        dataset_manifest_sha256=dataset_manifest_sha256,
        stable_outcome_sha256=stable_outcome_sha256,
        gate_passed=True,
    )


def validate_persisted_composite_lifecycle_evaluation(
    payload: Mapping[str, object],
    *,
    persisted_real_component: Mapping[str, object],
    expected_evaluation_id: str,
    expected_dataset_id: str,
    expected_dataset_manifest_sha256: str,
    expected_stable_outcome_sha256: str,
    expected_role_evaluator_build_sha256: str,
    expected_runtime_set_sha256: str,
    expected_matcher_fingerprint: str,
    expected_policy_fingerprint: str,
    expected_template_set_fingerprint: str,
    expected_candidate_set_sha256: str,
) -> None:
    """Revalidate a stored parent against current repository authority."""

    parent = _mapping(payload, label="persisted composite parent")
    if (
        parent.get("kind") != "composite_template_lifecycle_evaluation"
        or parent.get("schema_version") != 1
        or parent.get("evaluator_version") != COMPOSITE_EVALUATOR_VERSION
        or parent.get("authorizing_lifecycle_evidence") is not True
    ):
        raise CompositeLifecycleEvaluationError("persisted composite parent contract is invalid")
    if parent.get("authorization_scope") != AUTHORIZATION_SCOPE:
        raise CompositeLifecycleEvaluationError(
            "persisted composite authorization scope is invalid"
        )
    if parent.get("evaluation_id") != expected_evaluation_id:
        raise CompositeLifecycleEvaluationError("persisted composite evaluation identity changed")
    if parent.get("dataset_id") != expected_dataset_id:
        raise CompositeLifecycleEvaluationError("persisted composite dataset identity changed")
    dataset_manifest_sha256 = _sha256(
        parent.get("dataset_manifest_sha256"),
        label="persisted composite dataset manifest SHA-256",
    )
    if dataset_manifest_sha256 != _sha256(
        expected_dataset_manifest_sha256,
        label="expected composite dataset manifest SHA-256",
    ):
        raise CompositeLifecycleEvaluationError("persisted composite dataset binding changed")
    stable_outcome_sha256 = _sha256(
        parent.get("stable_outcome_sha256"),
        label="persisted composite stable outcome SHA-256",
    )
    if stable_outcome_sha256 != _sha256(
        expected_stable_outcome_sha256,
        label="expected composite stable outcome SHA-256",
    ):
        raise CompositeLifecycleEvaluationError(
            "persisted composite stable outcome binding changed"
        )
    bindings = _mapping(
        parent.get("bindings"),
        label="persisted composite bindings",
    )
    expected_bindings = {
        "candidate_set_sha256": _sha256(
            expected_candidate_set_sha256,
            label="expected candidate-set SHA-256",
        ),
        "matcher_fingerprint": _sha256(
            expected_matcher_fingerprint,
            label="expected matcher fingerprint",
        ),
        "policy_fingerprint": _sha256(
            expected_policy_fingerprint,
            label="expected role policy fingerprint",
        ),
        "role_evaluator_build_sha256": _sha256(
            expected_role_evaluator_build_sha256,
            label="expected role evaluator build SHA-256",
        ),
        "runtime_set_sha256": _sha256(
            expected_runtime_set_sha256,
            label="expected runtime-set SHA-256",
        ),
        "template_set_fingerprint": _sha256(
            expected_template_set_fingerprint,
            label="expected template-set fingerprint",
        ),
    }
    mismatches = [
        name
        for name, expected_value in expected_bindings.items()
        if bindings.get(name) != expected_value
    ]
    if bindings.get("composite_gate_policy_sha256") != composite_lifecycle_policy_fingerprint():
        mismatches.append("composite_gate_policy_sha256")
    frozen_dataset_sha256 = _sha256(
        bindings.get("frozen_synthetic_dataset_sha256"),
        label="persisted frozen synthetic dataset SHA-256",
    )
    _sha256(
        bindings.get("ocr_capture_build_sha256"),
        label="persisted OCR capture build SHA-256",
    )
    if mismatches:
        raise CompositeLifecycleEvaluationError(
            "persisted composite binding mismatch: " + ", ".join(sorted(mismatches))
        )
    components = _mapping(
        parent.get("components"),
        label="persisted composite components",
    )
    if set(components) != {
        "frozen_synthetic",
        "real_candidate_roles",
    }:
        raise CompositeLifecycleEvaluationError("persisted composite component set is invalid")
    real = _mapping(
        components["real_candidate_roles"],
        label="persisted real component",
    )
    if (
        real.get("authorizing_lifecycle_evidence") is not False
        or real.get("development_only") is not True
        or real.get("formal_accuracy_claim") is not False
        or real.get("formal_release_eligible") is not False
    ):
        raise CompositeLifecycleEvaluationError("persisted real component authority is invalid")
    _sha256(
        real.get("evaluation_sha256"),
        label="persisted real component evaluation SHA-256",
    )
    _sha256(
        real.get("ocr_evidence_sha256"),
        label="persisted real component OCR evidence SHA-256",
    )
    full_real_component = _mapping(
        persisted_real_component,
        label="persisted full real candidate component",
    )
    validate_persisted_candidate_role_lifecycle_component(
        full_real_component,
        expected_evaluation_sha256=_sha256(
            real.get("evaluation_sha256"),
            label="persisted real component evaluation SHA-256",
        ),
        expected_role_evaluator_build_sha256=(expected_role_evaluator_build_sha256),
        expected_runtime_set_sha256=expected_runtime_set_sha256,
        expected_matcher_fingerprint=expected_matcher_fingerprint,
        expected_policy_fingerprint=expected_policy_fingerprint,
        expected_template_set_fingerprint=(expected_template_set_fingerprint),
        expected_candidate_set_sha256=expected_candidate_set_sha256,
    )
    full_real_source = _mapping(
        full_real_component.get("source"),
        label="persisted full real candidate source",
    )
    if bindings.get("ocr_capture_build_sha256") != full_real_source.get(
        "ocr_capture_build_sha256"
    ) or real.get("ocr_evidence_sha256") != full_real_source.get("ocr_evidence_sha256"):
        raise CompositeLifecycleEvaluationError(
            "persisted composite parent and real component OCR bindings changed"
        )
    synthetic = _mapping(
        components["frozen_synthetic"],
        label="persisted frozen synthetic component",
    )
    if (
        synthetic.get("gate_passed") is not True
        or synthetic.get("dataset_manifest_sha256") != frozen_dataset_sha256
    ):
        raise CompositeLifecycleEvaluationError("persisted frozen synthetic component is invalid")
    _sha256(
        synthetic.get("stable_outcome_sha256"),
        label="persisted synthetic stable outcome SHA-256",
    )
    _text(
        synthetic.get("dataset_id"),
        label="persisted synthetic dataset ID",
    )
    gate = _mapping(
        parent.get("gate"),
        label="persisted composite gate",
    )
    checks = _mapping(
        gate.get("checks"),
        label="persisted composite gate checks",
    )
    expected_checks = {
        "candidate_support_per_runtime",
        "cpu_gpu_final_role_consistency",
        "direct_loading_unloading_errors_zero",
        "frozen_synthetic_gate_passed",
        "high_confidence_errors_zero",
        "real_attempts_complete",
        "real_pair_results_all_match",
        "technical_failures_zero",
    }
    if (
        gate.get("passed") is not True
        or set(checks) != expected_checks
        or any(value is not True for value in checks.values())
    ):
        raise CompositeLifecycleEvaluationError("persisted composite gate checks are invalid")
    expected_stable = _canonical_sha256(
        {
            "authorization_scope": AUTHORIZATION_SCOPE,
            "bindings": bindings,
            "components": components,
            "dataset_manifest_sha256": dataset_manifest_sha256,
            "gate_checks": checks,
            "schema_version": 1,
        }
    )
    if stable_outcome_sha256 != expected_stable:
        raise CompositeLifecycleEvaluationError(
            "persisted composite stable outcome hash is invalid"
        )
    evaluation_sha256 = _sha256(
        parent.get("evaluation_sha256"),
        label="persisted composite evaluation SHA-256",
    )
    expected_evaluation_sha256 = _canonical_sha256(
        {key: value for key, value in parent.items() if key != "evaluation_sha256"}
    )
    if evaluation_sha256 != expected_evaluation_sha256:
        raise CompositeLifecycleEvaluationError("persisted composite evaluation hash is invalid")
