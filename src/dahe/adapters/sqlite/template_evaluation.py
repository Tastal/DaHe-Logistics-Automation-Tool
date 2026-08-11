from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.template_lifecycle_attempts import (
    CompositeLifecycleAttemptScope,
    make_composite_lifecycle_attempt_scope,
)
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateEvaluationCandidateInput,
    TemplateEvaluationItemInput,
    TemplateEvaluationPairInput,
    TemplateEvaluationRecord,
)
from dahe.application.template_studio.authorizing_registry import (
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.candidate_development_ocr_run_authority import (
    load_authorized_candidate_development_ocr_evidence,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    CandidateDevelopmentRoleEvaluation,
    evaluate_candidate_development_roles,
)
from dahe.application.template_studio.composite_lifecycle_evaluation import (
    CompositeLifecycleEvaluation,
    build_composite_lifecycle_evaluation,
    composite_lifecycle_policy_fingerprint,
)
from dahe.application.template_studio.development_evaluation import (
    DevelopmentEvaluationItem,
    DevelopmentEvaluationReport,
    FrozenDevelopmentFixtureError,
    development_matcher_fingerprint,
    development_policy_fingerprint,
    run_authorizing_development_evaluation,
)
from dahe.application.template_studio.matcher import (
    build_development_evaluation_template_set,
)
from dahe.domain.audit.ticket_roles import TicketRole

_PREPARED_COMPOSITE_SEAL = object()


class CompositeLifecyclePersistenceError(RuntimeError):
    """Raised when composite lifecycle evidence cannot cross persistence."""


@dataclass(frozen=True, slots=True)
class PreparedCompositeLifecycleEvaluation:
    real_component: CandidateDevelopmentRoleEvaluation
    synthetic_component: DevelopmentEvaluationReport
    composite: CompositeLifecycleEvaluation
    _seal: object


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _unknown_reason(item: DevelopmentEvaluationItem) -> str | None:
    if item.result_role is not TicketRole.UNKNOWN:
        return None
    if item.role_conflict:
        return "conflicting_role_evidence"
    if item.unknown_layout:
        return "unknown_layout"
    return "insufficient_role_evidence"


def _persist_code_owned_development_evaluation(
    repository: SqliteTemplateRepository,
    report: DevelopmentEvaluationReport,
    *,
    actor_id: str,
) -> TemplateEvaluationRecord:
    """Persist a report that was produced in this call chain by the frozen runner."""

    if report.dataset_kind != "authorizing_observation_dataset":
        raise FrozenDevelopmentFixtureError(
            "only an authorizing_observation_dataset report can persist as "
            "frozen lifecycle evidence"
        )
    runtime_fingerprint = repository.accepted_runtime_fingerprint
    if runtime_fingerprint is None:
        raise ValueError("an accepted OCR runtime fingerprint is required")
    build_fingerprint = repository.accepted_build_fingerprint
    payload = report.to_record_evaluation_payload(
        build_fingerprint=build_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
        actor_id=actor_id,
    )
    metrics = report.to_repository_metrics()
    return repository._record_frozen_development_evaluation(
        evaluation_id=str(payload["evaluation_id"]),
        dataset_id=report.fixture_id,
        dataset_manifest_sha256=report.dataset_manifest_sha256,
        template_set_fingerprint=report.template_set_fingerprint,
        matcher_fingerprint=report.matcher_fingerprint,
        policy_fingerprint=report.policy_fingerprint,
        build_fingerprint=build_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
        expected_count=report.expected_count,
        result_count=report.result_count,
        metrics=metrics,
        metrics_sha256=_canonical_sha256(metrics),
        gate_passed=report.gate_passed,
        candidates=tuple(
            TemplateEvaluationCandidateInput(
                version_id=candidate.version_id,
                content_sha256=candidate.content_sha256,
            )
            for candidate in report.candidates
        ),
        items=tuple(
            TemplateEvaluationItemInput(
                sample_id=item.sample_id,
                waybill_id=f"{report.fixture_id}:{item.case_id}",
                waybill_identity_sha256=_canonical_sha256(
                    {
                        "case_id": item.case_id,
                        "dataset_id": report.fixture_id,
                        "identity_kind": "authorizing_development_case_v1",
                    }
                ),
                image_sha256=item.image_sha256,
                truth=item.expected_role,
                prediction=item.result_role,
                confidence=item.confidence,
                high_confidence=item.high_confidence,
                orientation_degrees=item.detected_orientation_degrees,
                evidence={
                    "case_id": item.case_id,
                    "expected_orientation_degrees": item.orientation_degrees,
                    "identity_kind": item.identity_kind,
                    "quality_tags": list(item.quality_tags),
                    "routing": {
                        "anchors_passed": item.anchors_passed,
                        "direct_completion": item.direct_completion,
                        "fallback_required": item.fallback_required,
                        "geometry_matched": item.geometry_matched,
                        "role_conflict": item.role_conflict,
                        "unknown_layout": item.unknown_layout,
                        "wrong_template": item.wrong_template,
                    },
                    "sources": [evidence.to_payload() for evidence in item.evidence],
                    "truth_source": item.truth_source,
                },
                assessment_fingerprint=item.assessment_fingerprint,
                elapsed_ms=item.elapsed_ms,
                pair_issue=None,
                unknown_reason=_unknown_reason(item),
            )
            for item in report.items
        ),
        pairs=tuple(
            TemplateEvaluationPairInput(
                case_id=item.case_id,
                expected_issue=item.expected_issue,
                result_issue=item.result_issue,
                expected_matches_result=item.expected_matches_result,
            )
            for item in report.pair_items
        ),
        stable_outcome_sha256=report.stable_outcome_sha256,
        actor_id=actor_id,
    )


def run_and_persist_frozen_development_evaluation(
    repository: SqliteTemplateRepository,
    *,
    manifest_path: Path,
    candidate_version_ids: Sequence[str],
    actor_id: str,
) -> tuple[DevelopmentEvaluationReport, TemplateEvaluationRecord]:
    """Run and atomically persist the approved code-owned development contract.

    Truth labels and observations come only from the path and canonical digest
    pinned in the code-owned registry. Candidate definitions are loaded only
    from explicit SQLite version identities. Policy, matcher, current shadows,
    and predictions are obtained inside this boundary. The repository then
    independently checks every accepted contract fingerprint before allowing
    the result to become lifecycle evidence.
    """

    dataset = load_approved_authorizing_development_dataset(manifest_path)
    candidates = tuple(repository.get_version(version_id) for version_id in candidate_version_ids)
    current_shadow = (
        repository.list_current_shadow_versions_for_development_evaluation(
            candidates=candidates,
        )
    )
    report = run_authorizing_development_evaluation(
        dataset,
        candidates=candidates,
        current_shadow=current_shadow,
    )
    evaluation = _persist_code_owned_development_evaluation(
        repository,
        report,
        actor_id=actor_id,
    )
    return report, evaluation


def prepare_composite_lifecycle_evaluation(
    repository: SqliteTemplateRepository,
    *,
    candidate_ocr_run_repository: (
        SqliteCandidateDevelopmentOcrRunRepository
    ),
    manifest_path: Path,
    candidate_ocr_evidence_path: Path,
    candidate_ocr_data_root: Path,
    candidate_version_ids: Sequence[str],
    role_evaluator_build_sha256: str,
    runtime_set_sha256: str,
) -> PreparedCompositeLifecycleEvaluation:
    """Run both lifecycle components without accepting an external role report."""

    dataset = load_approved_authorizing_development_dataset(manifest_path)
    candidates = tuple(
        repository.get_version(version_id)
        for version_id in candidate_version_ids
    )
    current_shadow = (
        repository.list_current_shadow_versions_for_development_evaluation(
            candidates=candidates,
        )
    )
    authorized_evidence = (
        load_authorized_candidate_development_ocr_evidence(
            candidate_ocr_run_repository,
            data_root=candidate_ocr_data_root,
            evidence_path=candidate_ocr_evidence_path,
            expected_evidence_sha256=(
                candidate_ocr_evidence_path.stem
            ),
        )
    )
    real_component = evaluate_candidate_development_roles(
        authorized_evidence.payload,
        candidates=candidates,
        current_shadow=current_shadow,
        role_evaluator_build_sha256=role_evaluator_build_sha256,
    )
    synthetic_component = run_authorizing_development_evaluation(
        dataset,
        candidates=candidates,
        current_shadow=current_shadow,
    )
    composite = build_composite_lifecycle_evaluation(
        real_component=real_component,
        synthetic_component=synthetic_component,
        expected_role_evaluator_build_sha256=(
            role_evaluator_build_sha256
        ),
        expected_runtime_set_sha256=runtime_set_sha256,
    )
    return PreparedCompositeLifecycleEvaluation(
        real_component=real_component,
        synthetic_component=synthetic_component,
        composite=composite,
        _seal=_PREPARED_COMPOSITE_SEAL,
    )


def prepare_composite_lifecycle_attempt_scope(
    repository: SqliteTemplateRepository,
    *,
    candidate_ocr_run_repository: (
        SqliteCandidateDevelopmentOcrRunRepository
    ),
    manifest_path: Path,
    candidate_ocr_evidence_path: Path,
    candidate_version_ids: Sequence[str],
    role_evaluator_build_sha256: str,
    runtime_set_sha256: str,
) -> CompositeLifecycleAttemptScope:
    """Freeze a failure-recording scope before running either gate."""

    dataset = load_approved_authorizing_development_dataset(manifest_path)
    candidates = tuple(
        repository.get_version(version_id)
        for version_id in candidate_version_ids
    )
    current_shadow = (
        repository.list_current_shadow_versions_for_development_evaluation(
            candidates=candidates,
        )
    )
    template_set = build_development_evaluation_template_set(
        candidates=candidates,
        current_shadow=current_shadow,
    )
    evidence_sha256 = candidate_ocr_evidence_path.stem
    ocr_authority = candidate_ocr_run_repository.get(evidence_sha256)
    candidate_ocr_run_repository.require_latest_success(
        evidence_sha256
    )
    candidate_set_sha256 = _canonical_sha256(
        [
            {
                "content_sha256": candidate.content_sha256,
                "version_id": candidate.version_id,
            }
            for candidate in sorted(
                candidates,
                key=lambda item: item.version_id,
            )
        ]
    )
    return make_composite_lifecycle_attempt_scope(
        ocr_evidence_sha256=ocr_authority.evidence_sha256,
        package_sha256=ocr_authority.package_sha256,
        review_history_authority_sha256=(
            ocr_authority.review_history_authority_sha256
        ),
        source_authority_sha256=(
            ocr_authority.source_authority_sha256
        ),
        reviewer_id=ocr_authority.reviewer_id,
        ocr_capture_build_sha256=(
            ocr_authority.application_build_sha256
        ),
        role_evaluator_build_sha256=(
            role_evaluator_build_sha256
        ),
        composition_evidence_sha256=(
            ocr_authority.composition_evidence_sha256
        ),
        runtime_set_sha256=runtime_set_sha256,
        pipeline_contract_sha256=(
            ocr_authority.pipeline_contract_sha256
        ),
        dataset_manifest_sha256=dataset.manifest_sha256,
        candidate_set_sha256=candidate_set_sha256,
        matcher_fingerprint=development_matcher_fingerprint(),
        policy_fingerprint=development_policy_fingerprint(),
        template_set_fingerprint=template_set.fingerprint,
        composite_policy_sha256=(
            composite_lifecycle_policy_fingerprint()
        ),
    )


def _validated_composite_bindings(
    repository: SqliteTemplateRepository,
    prepared: PreparedCompositeLifecycleEvaluation,
) -> None:
    if (
        not isinstance(prepared, PreparedCompositeLifecycleEvaluation)
        or prepared._seal is not _PREPARED_COMPOSITE_SEAL
    ):
        raise CompositeLifecyclePersistenceError(
            "composite lifecycle evidence was not prepared in this call chain"
        )
    composite = prepared.composite
    if (
        not composite.gate_passed
        or composite.payload.get("authorizing_lifecycle_evidence") is not True
        or composite.payload.get("authorization_scope")
        != "ticket_role_evidence"
    ):
        raise CompositeLifecyclePersistenceError(
            "composite lifecycle gate did not pass"
        )
    bindings = composite.payload.get("bindings")
    if not isinstance(bindings, dict):
        raise CompositeLifecyclePersistenceError(
            "composite lifecycle bindings are invalid"
        )
    expected = {
        "frozen_synthetic_dataset_sha256": (
            prepared.synthetic_component.dataset_manifest_sha256
        ),
        "matcher_fingerprint": (
            prepared.synthetic_component.matcher_fingerprint
        ),
        "policy_fingerprint": (
            prepared.synthetic_component.policy_fingerprint
        ),
        "role_evaluator_build_sha256": (
            repository.accepted_build_fingerprint
        ),
        "runtime_set_sha256": repository.accepted_runtime_fingerprint,
        "template_set_fingerprint": (
            prepared.synthetic_component.template_set_fingerprint
        ),
    }
    mismatches = sorted(
        name
        for name, value in expected.items()
        if value is None or bindings.get(name) != value
    )
    if (
        repository.accepted_development_manifest_sha256
        != composite.dataset_manifest_sha256
    ):
        mismatches.append("composite_dataset_manifest_sha256")
    if (
        repository.accepted_matcher_fingerprint
        != prepared.synthetic_component.matcher_fingerprint
    ):
        mismatches.append("accepted_matcher_fingerprint")
    if (
        repository.accepted_policy_fingerprint
        != prepared.synthetic_component.policy_fingerprint
    ):
        mismatches.append("accepted_policy_fingerprint")
    if mismatches:
        raise CompositeLifecyclePersistenceError(
            "composite lifecycle repository binding mismatch: "
            + ", ".join(sorted(set(mismatches)))
        )


def persist_composite_lifecycle_evaluation(
    repository: SqliteTemplateRepository,
    prepared: PreparedCompositeLifecycleEvaluation,
    *,
    actor_id: str,
) -> TemplateEvaluationRecord:
    """Persist one authorizing parent identity for the conjoined components."""

    _validated_composite_bindings(repository, prepared)
    composite = prepared.composite
    synthetic = prepared.synthetic_component
    build_fingerprint = repository.accepted_build_fingerprint
    runtime_fingerprint = repository.accepted_runtime_fingerprint
    if build_fingerprint is None or runtime_fingerprint is None:
        raise CompositeLifecyclePersistenceError(
            "composite lifecycle repository contract is incomplete"
        )
    metrics = synthetic.to_repository_metrics()
    metrics["composite_lifecycle"] = composite.payload
    metrics["composite_lifecycle_components"] = {
        "real_candidate_roles": prepared.real_component.payload,
        "frozen_synthetic": {
            "dataset_id": synthetic.fixture_id,
            "dataset_manifest_sha256": (
                synthetic.dataset_manifest_sha256
            ),
            "stable_outcome_sha256": (
                synthetic.stable_outcome_sha256
            ),
        },
    }
    metrics["lifecycle_authorization_schema_version"] = 2
    return repository._record_frozen_development_evaluation(
        evaluation_id=composite.evaluation_id,
        dataset_id=composite.dataset_id,
        dataset_manifest_sha256=composite.dataset_manifest_sha256,
        template_set_fingerprint=synthetic.template_set_fingerprint,
        matcher_fingerprint=synthetic.matcher_fingerprint,
        policy_fingerprint=synthetic.policy_fingerprint,
        build_fingerprint=build_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
        expected_count=synthetic.expected_count,
        result_count=synthetic.result_count,
        metrics=metrics,
        metrics_sha256=_canonical_sha256(metrics),
        gate_passed=True,
        candidates=tuple(
            TemplateEvaluationCandidateInput(
                version_id=candidate.version_id,
                content_sha256=candidate.content_sha256,
            )
            for candidate in synthetic.candidates
        ),
        items=tuple(
            TemplateEvaluationItemInput(
                sample_id=item.sample_id,
                waybill_id=f"{synthetic.fixture_id}:{item.case_id}",
                waybill_identity_sha256=_canonical_sha256(
                    {
                        "case_id": item.case_id,
                        "dataset_id": synthetic.fixture_id,
                        "identity_kind": (
                            "authorizing_development_case_v1"
                        ),
                    }
                ),
                image_sha256=item.image_sha256,
                truth=item.expected_role,
                prediction=item.result_role,
                confidence=item.confidence,
                high_confidence=item.high_confidence,
                orientation_degrees=item.detected_orientation_degrees,
                evidence={
                    "case_id": item.case_id,
                    "expected_orientation_degrees": (
                        item.orientation_degrees
                    ),
                    "identity_kind": item.identity_kind,
                    "quality_tags": list(item.quality_tags),
                    "routing": {
                        "anchors_passed": item.anchors_passed,
                        "direct_completion": item.direct_completion,
                        "fallback_required": item.fallback_required,
                        "geometry_matched": item.geometry_matched,
                        "role_conflict": item.role_conflict,
                        "unknown_layout": item.unknown_layout,
                        "wrong_template": item.wrong_template,
                    },
                    "sources": [
                        evidence.to_payload()
                        for evidence in item.evidence
                    ],
                    "truth_source": item.truth_source,
                },
                assessment_fingerprint=item.assessment_fingerprint,
                elapsed_ms=item.elapsed_ms,
                pair_issue=None,
                unknown_reason=_unknown_reason(item),
            )
            for item in synthetic.items
        ),
        pairs=tuple(
            TemplateEvaluationPairInput(
                case_id=item.case_id,
                expected_issue=item.expected_issue,
                result_issue=item.result_issue,
                expected_matches_result=item.expected_matches_result,
            )
            for item in synthetic.pair_items
        ),
        stable_outcome_sha256=composite.stable_outcome_sha256,
        actor_id=actor_id,
    )
