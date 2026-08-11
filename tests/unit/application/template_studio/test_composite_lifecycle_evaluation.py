from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from typing import cast

import pytest

from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    EVALUATOR_VERSION as CANDIDATE_ROLE_EVALUATOR_VERSION,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    CandidateDevelopmentRoleEvaluation,
)
from dahe.application.template_studio.composite_lifecycle_evaluation import (
    CompositeLifecycleEvaluationError,
    build_composite_lifecycle_evaluation,
    composite_lifecycle_policy_fingerprint,
    validate_persisted_candidate_role_lifecycle_component,
    validate_persisted_composite_lifecycle_evaluation,
)
from dahe.application.template_studio.development_evaluation import (
    DevelopmentEvaluationReport,
    run_authorizing_development_evaluation,
)
from tests.fixtures.loop7_current_candidate_templates import (
    current_candidate_versions,
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _synthetic_report() -> DevelopmentEvaluationReport:
    candidates = current_candidate_versions()
    dataset = load_approved_authorizing_development_dataset(
        approved_authorizing_development_dataset_path()
    )
    report = run_authorizing_development_evaluation(
        dataset,
        candidates=candidates,
    )
    assert report.gate_passed is True
    return report


def _real_component(
    synthetic: DevelopmentEvaluationReport,
) -> CandidateDevelopmentRoleEvaluation:
    build_sha256 = _sha256("role-evaluator-build")
    runtime_sha256 = _sha256("cpu-gpu-runtime-set")
    roles_by_family = {
        candidate.definition.family_id: candidate.definition.role.value
        for candidate in current_candidate_versions()
    }
    candidates = [
        {
            "content_sha256": candidate.content_sha256,
            "family_id_sha256": _canonical_sha256(candidate.family_id),
            "lifecycle": candidate.lifecycle.value,
            "role": roles_by_family[candidate.family_id],
            "version_id": candidate.version_id,
        }
        for candidate in synthetic.candidates
    ]
    results = [
        {
            "assessment_sha256": _sha256(f"assessment-{index}"),
            "confidence": "0.95",
            "detected_orientation_degrees": 0,
            "expected_orientation_degrees": 0,
            "high_confidence": True,
            "matched_template_version_ids": sorted(
                candidate["version_id"]
                for candidate in candidates
                if candidate["role"]
                == ("loading" if index < 50 else "unloading" if index < 99 else "unknown")
            ),
            "prediction": ("loading" if index < 50 else "unloading" if index < 99 else "unknown"),
            "subject_sha256": _sha256(f"subject-{index}"),
            "truth": ("loading" if index < 50 else "unloading" if index < 99 else "unknown"),
        }
        for index in range(100)
    ]
    pair_results = [
        {
            "domain_issue": None,
            "expected_status": "normal",
            "matches_truth": True,
            "pair_sha256": _sha256(f"pair-{index}"),
            "predicted_status": "normal",
        }
        for index in range(50)
    ]
    runtimes = {
        runtime_kind: {
            "candidate_support": {
                "results": [
                    {
                        "candidate_version_id": candidate["version_id"],
                        "support_count": 1,
                        "supporting_subject_sha256s": [
                            next(
                                row["subject_sha256"]
                                for row in results
                                if row["truth"] == candidate["role"]
                            )
                        ],
                    }
                    for candidate in candidates
                ],
                "support_contract": (
                    "human_role_correct_and_template_evidence_hit_and_final_role_correct"
                ),
                "supported_candidate_count": len(candidates),
            },
            "matcher_latency_ms": {
                "p50": "1",
                "p95": "2",
                "sample_count": 100,
            },
            "ocr_latency_ms": {
                "wall": {
                    "p50": "10",
                    "p95": "20",
                    "sample_count": 100,
                },
                "worker": {
                    "p50": "8",
                    "p95": "18",
                    "sample_count": 100,
                },
            },
            "orientation": {
                "agreement_rate": "1",
                "confusion_matrix": {},
                "match_count": 100,
                "mismatch_count": 0,
                "sample_count": 100,
            },
            "pair_status": {
                "confusion_matrix": {},
                "expected_counts": {"normal": 50},
                "mismatch_count": 0,
                "predicted_counts": {"normal": 50},
                "results": pair_results,
                "sample_count": 50,
            },
            "role": {
                "confusion_matrix": {},
                "direct_loading_unloading_error_count": 0,
                "high_confidence_error_count": 0,
                "results": results,
                "unknown_rate": "0.01",
            },
            "runtime_kind": runtime_kind,
            "sample_count": 100,
        }
        for runtime_kind in ("cpu", "gpu")
    }
    payload: dict[str, object] = {
        "attempt_contract": {
            "completed_attempt_count": 200,
            "expected_attempt_count": 200,
            "technical_failure_count": 0,
        },
        "authorizing_lifecycle_evidence": False,
        "cpu_gpu_role_consistency": {
            "agreement_rate": "1",
            "match_count": 100,
            "mismatch_count": 0,
            "mismatches": [],
            "sample_count": 100,
        },
        "development_only": True,
        "evaluator_version": "dahe.loop7.candidate-role-evaluation.v3",
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "kind": "candidate_review_development_role_template_evaluation",
        "runtimes": runtimes,
        "schema_version": 2,
        "source": {
            "composition_evidence_sha256": _sha256("composition-evidence"),
            "manifest_sha256": _sha256("review-manifest"),
            "ocr_capture_build_sha256": _sha256("ocr-capture-build"),
            "ocr_evidence_sha256": _sha256("ocr-evidence"),
            "ocr_pipeline_contract_sha256": _sha256("ocr-pipeline-contract"),
            "package_sha256": _sha256("review-package"),
            "quality_coverage_sha256": _sha256("quality-coverage"),
            "record_set_sha256": _sha256("record-set"),
            "review_history_authority_sha256": _sha256("review-history-authority"),
            "reviewer_id_sha256": _canonical_sha256(
                "reviewer-sensitive"
            ),
            "role_evaluator_build_sha256": build_sha256,
            "runtime_set_sha256": runtime_sha256,
            "source_authority_sha256": _sha256("review-source-authority"),
        },
        "status": "completed",
        "template_contract": {
            "candidate_count": len(candidates),
            "candidates": candidates,
            "current_shadow_count": 0,
            "dataset_id_sha256": _sha256("review-dataset"),
            "matcher_fingerprint": synthetic.matcher_fingerprint,
            "policy_fingerprint": synthetic.policy_fingerprint,
            "selected_template_count": len(candidates),
            "template_set_fingerprint": synthetic.template_set_fingerprint,
        },
    }
    evaluation_sha256 = _canonical_sha256(payload)
    payload["evaluation_sha256"] = evaluation_sha256
    return CandidateDevelopmentRoleEvaluation(
        payload=payload,
        evaluation_sha256=evaluation_sha256,
    )


def _build(
    real: CandidateDevelopmentRoleEvaluation,
    synthetic: DevelopmentEvaluationReport,
):
    source = real.payload["source"]
    assert isinstance(source, dict)
    return build_composite_lifecycle_evaluation(
        real_component=real,
        synthetic_component=synthetic,
        expected_role_evaluator_build_sha256=str(source["role_evaluator_build_sha256"]),
        expected_runtime_set_sha256=str(source["runtime_set_sha256"]),
    )


def _reseal(
    component: CandidateDevelopmentRoleEvaluation,
) -> CandidateDevelopmentRoleEvaluation:
    payload = component.payload
    payload.pop("evaluation_sha256", None)
    evaluation_sha256 = _canonical_sha256(payload)
    payload["evaluation_sha256"] = evaluation_sha256
    return CandidateDevelopmentRoleEvaluation(
        payload=payload,
        evaluation_sha256=evaluation_sha256,
    )


def _reseal_parent(payload: dict[str, object]) -> None:
    payload.pop("evaluation_sha256", None)
    gate = payload["gate"]
    assert isinstance(gate, dict)
    bindings = payload["bindings"]
    assert isinstance(bindings, dict)
    components = payload["components"]
    assert isinstance(components, dict)
    payload["stable_outcome_sha256"] = _canonical_sha256(
        {
            "authorization_scope": payload["authorization_scope"],
            "bindings": bindings,
            "components": components,
            "dataset_manifest_sha256": payload["dataset_manifest_sha256"],
            "gate_checks": gate["checks"],
            "schema_version": payload["schema_version"],
        }
    )
    payload["evaluation_sha256"] = _canonical_sha256(payload)


def test_composite_gate_requires_both_components_and_has_one_parent_identity() -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)

    result = _build(real, synthetic)

    assert result.gate_passed is True
    assert result.payload["authorizing_lifecycle_evidence"] is True
    assert result.payload["authorization_scope"] == "ticket_role_evidence"
    assert result.payload["evaluation_id"].startswith("dev-role-composite-")
    assert result.payload["evaluation_id"] == result.evaluation_id
    assert result.payload["stable_outcome_sha256"] == result.stable_outcome_sha256
    assert result.payload["bindings"]["composite_gate_policy_sha256"] == (
        composite_lifecycle_policy_fingerprint()
    )
    assert (
        result.payload["components"]["real_candidate_roles"]["authorizing_lifecycle_evidence"]
        is False
    )
    assert result.payload["components"]["frozen_synthetic"]["gate_passed"] is True


def test_unknown_predictions_do_not_have_an_arbitrary_rejection_threshold() -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    for runtime in real.payload["runtimes"].values():
        role = runtime["role"]
        for row in role["results"][1:41]:
            row["truth"] = "unknown"
            row["prediction"] = "unknown"
    real = _reseal(real)

    result = _build(real, synthetic)

    assert result.gate_passed is True
    assert "unknown_rate" not in result.payload["gate"]["checks"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("attempt_count", "attempt"),
        ("technical_failure", "technical"),
        ("high_confidence_error", "high-confidence"),
        ("direct_role_error", "direct"),
        ("pair_mismatch", "pair"),
        ("runtime_mismatch", "CPU/GPU"),
        ("candidate_support", "candidate support"),
    ),
)
def test_real_component_gate_fails_closed(
    mutation: str,
    message: str,
) -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    if mutation == "attempt_count":
        real.payload["attempt_contract"]["completed_attempt_count"] = 199
    elif mutation == "technical_failure":
        real.payload["attempt_contract"]["technical_failure_count"] = 1
    elif mutation == "high_confidence_error":
        real.payload["runtimes"]["cpu"]["role"]["high_confidence_error_count"] = 1
    elif mutation == "direct_role_error":
        row = real.payload["runtimes"]["cpu"]["role"]["results"][0]
        row["prediction"] = "unloading"
        row["high_confidence"] = False
        row["confidence"] = "0.1"
        real.payload["runtimes"]["cpu"]["role"]["direct_loading_unloading_error_count"] = 1
    elif mutation == "pair_mismatch":
        pair_status = real.payload["runtimes"]["gpu"]["pair_status"]
        pair_status["mismatch_count"] = 1
        pair_status["results"][0]["matches_truth"] = False
        pair_status["results"][0]["predicted_status"] = "unknown"
    elif mutation == "runtime_mismatch":
        consistency = real.payload["cpu_gpu_role_consistency"]
        consistency["match_count"] = 99
        consistency["mismatch_count"] = 1
        consistency["mismatches"] = [
            {
                "cpu_role": "loading",
                "gpu_role": "unknown",
                "subject_sha256": _sha256("runtime-mismatch"),
            }
        ]
    else:
        support = real.payload["runtimes"]["cpu"]["candidate_support"]
        support["supported_candidate_count"] -= 1
        support["results"][0]["support_count"] = 0
        support["results"][0]["supporting_subject_sha256s"] = []
    real = _reseal(real)

    with pytest.raises(CompositeLifecycleEvaluationError, match=message):
        _build(real, synthetic)


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown_subject",
        "missing_template_match",
        "wrong_candidate_role",
    ),
)
def test_candidate_support_is_recomputed_from_role_rows(
    mutation: str,
) -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    support = real.payload["runtimes"]["cpu"]["candidate_support"]["results"][0]
    subject = support["supporting_subject_sha256s"][0]
    role_row = next(
        row
        for row in real.payload["runtimes"]["cpu"]["role"]["results"]
        if row["subject_sha256"] == subject
    )
    if mutation == "unknown_subject":
        support["supporting_subject_sha256s"] = [_sha256("not-a-real-role-subject")]
    elif mutation == "missing_template_match":
        role_row["matched_template_version_ids"] = []
    else:
        real.payload["template_contract"]["candidates"][0]["role"] = (
            "unloading" if role_row["truth"] == "loading" else "loading"
        )
    real = _reseal(real)

    with pytest.raises(
        CompositeLifecycleEvaluationError,
        match="candidate support",
    ):
        _build(real, synthetic)


@pytest.mark.parametrize(
    "binding",
    (
        "role_evaluator_build",
        "runtime_set",
        "matcher",
        "policy",
        "template_set",
        "candidate_set",
    ),
)
def test_component_binding_mismatch_fails_closed(binding: str) -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    if binding == "role_evaluator_build":
        expected_build = _sha256("different-build")
        expected_runtime = real.payload["source"]["runtime_set_sha256"]
    elif binding == "runtime_set":
        expected_build = real.payload["source"]["role_evaluator_build_sha256"]
        expected_runtime = _sha256("different-runtime")
    else:
        expected_build = real.payload["source"]["role_evaluator_build_sha256"]
        expected_runtime = real.payload["source"]["runtime_set_sha256"]
        if binding == "matcher":
            real.payload["template_contract"]["matcher_fingerprint"] = _sha256("different-matcher")
        elif binding == "policy":
            real.payload["template_contract"]["policy_fingerprint"] = _sha256("different-policy")
        elif binding == "template_set":
            real.payload["template_contract"]["template_set_fingerprint"] = _sha256(
                "different-template-set"
            )
        else:
            real.payload["template_contract"]["candidates"][0]["content_sha256"] = _sha256(
                "different-candidate"
            )
        real = _reseal(real)

    with pytest.raises(
        CompositeLifecycleEvaluationError,
        match=r"binding|candidate",
    ):
        build_composite_lifecycle_evaluation(
            real_component=real,
            synthetic_component=synthetic,
            expected_role_evaluator_build_sha256=str(expected_build),
            expected_runtime_set_sha256=str(expected_runtime),
        )


def test_failed_or_non_authorizing_synthetic_component_cannot_authorize() -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)

    with pytest.raises(
        CompositeLifecycleEvaluationError,
        match="synthetic",
    ):
        _build(
            real,
            replace(synthetic, gate_passed=False),
        )


def test_external_role_json_mapping_cannot_cross_composite_boundary() -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)

    with pytest.raises(
        (CompositeLifecycleEvaluationError, TypeError),
        match=r"component|CandidateDevelopmentRoleEvaluation",
    ):
        build_composite_lifecycle_evaluation(
            real_component=copy.deepcopy(real.payload),  # type: ignore[arg-type]
            synthetic_component=synthetic,
            expected_role_evaluator_build_sha256=_sha256("role-evaluator-build"),
            expected_runtime_set_sha256=_sha256("cpu-gpu-runtime-set"),
        )


def test_composite_stable_identity_is_deterministic() -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)

    first = _build(real, synthetic)
    second = _build(real, synthetic)

    assert second.evaluation_id == first.evaluation_id
    assert second.stable_outcome_sha256 == first.stable_outcome_sha256
    assert second.payload == first.payload


def test_persisted_parent_revalidates_every_repository_binding() -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    result = _build(real, synthetic)
    bindings = result.payload["bindings"]

    validate_persisted_composite_lifecycle_evaluation(
        result.payload,
        persisted_real_component=real.payload,
        expected_evaluation_id=result.evaluation_id,
        expected_dataset_id=result.dataset_id,
        expected_dataset_manifest_sha256=(result.dataset_manifest_sha256),
        expected_stable_outcome_sha256=result.stable_outcome_sha256,
        expected_role_evaluator_build_sha256=bindings["role_evaluator_build_sha256"],
        expected_runtime_set_sha256=bindings["runtime_set_sha256"],
        expected_matcher_fingerprint=bindings["matcher_fingerprint"],
        expected_policy_fingerprint=bindings["policy_fingerprint"],
        expected_template_set_fingerprint=bindings["template_set_fingerprint"],
        expected_candidate_set_sha256=bindings["candidate_set_sha256"],
    )


def test_persisted_real_component_revalidates_the_fixed_gate() -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    source = real.payload["source"]
    template_contract = real.payload["template_contract"]
    candidate_set_sha256 = _canonical_sha256(
        [
            {
                "content_sha256": row["content_sha256"],
                "version_id": row["version_id"],
            }
            for row in sorted(
                template_contract["candidates"],
                key=lambda item: item["version_id"],
            )
        ]
    )

    validate_persisted_candidate_role_lifecycle_component(
        real.payload,
        expected_evaluation_sha256=real.evaluation_sha256,
        expected_role_evaluator_build_sha256=source["role_evaluator_build_sha256"],
        expected_runtime_set_sha256=source["runtime_set_sha256"],
        expected_matcher_fingerprint=template_contract["matcher_fingerprint"],
        expected_policy_fingerprint=template_contract["policy_fingerprint"],
        expected_template_set_fingerprint=template_contract["template_set_fingerprint"],
        expected_candidate_set_sha256=candidate_set_sha256,
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "self_hash",
        "stable_outcome",
        "scope",
        "real_authority",
        "synthetic_gate",
        "gate_policy",
    ),
)
def test_persisted_parent_tampering_fails_closed(mutation: str) -> None:
    synthetic = _synthetic_report()
    real_component = _real_component(synthetic)
    result = _build(real_component, synthetic)
    payload = copy.deepcopy(result.payload)
    bindings = result.payload["bindings"]
    if mutation == "self_hash":
        payload["evaluation_sha256"] = _sha256("forged")
    elif mutation == "stable_outcome":
        payload["stable_outcome_sha256"] = _sha256("forged")
    elif mutation == "scope":
        payload["authorization_scope"] = "all_template_capabilities"
    elif mutation == "real_authority":
        payload["components"]["real_candidate_roles"]["authorizing_lifecycle_evidence"] = True
    elif mutation == "synthetic_gate":
        payload["components"]["frozen_synthetic"]["gate_passed"] = False
    else:
        payload["bindings"]["composite_gate_policy_sha256"] = _sha256("forged")

    with pytest.raises(
        CompositeLifecycleEvaluationError,
        match=r"persisted|binding|scope|component|policy|hash",
    ):
        validate_persisted_composite_lifecycle_evaluation(
            payload,
            persisted_real_component=real_component.payload,
            expected_evaluation_id=result.evaluation_id,
            expected_dataset_id=result.dataset_id,
            expected_dataset_manifest_sha256=(result.dataset_manifest_sha256),
            expected_stable_outcome_sha256=result.stable_outcome_sha256,
            expected_role_evaluator_build_sha256=bindings["role_evaluator_build_sha256"],
            expected_runtime_set_sha256=bindings["runtime_set_sha256"],
            expected_matcher_fingerprint=bindings["matcher_fingerprint"],
            expected_policy_fingerprint=bindings["policy_fingerprint"],
            expected_template_set_fingerprint=bindings["template_set_fingerprint"],
            expected_candidate_set_sha256=bindings["candidate_set_sha256"],
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "legacy_evaluator",
        "unknown_top_level_field",
        "missing_source_field",
        "missing_runtime_field",
        "missing_template_field",
    ),
)
def test_real_component_requires_the_exact_current_evaluator_schema(
    mutation: str,
) -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    if mutation == "legacy_evaluator":
        real.payload["evaluator_version"] = "dahe.loop7.candidate-role-evaluation.v1"
    elif mutation == "unknown_top_level_field":
        real.payload["forged_authority_extension"] = True
    elif mutation == "missing_source_field":
        real.payload["source"].pop("composition_evidence_sha256")
    elif mutation == "missing_runtime_field":
        real.payload["runtimes"]["gpu"].pop("orientation")
    else:
        real.payload["template_contract"].pop("dataset_id_sha256")
    real = _reseal(real)

    with pytest.raises(
        CompositeLifecycleEvaluationError,
        match=r"evaluator|schema",
    ):
        _build(real, synthetic)


@pytest.mark.parametrize(
    "mutation",
    (
        "capture_build",
        "ocr_evidence",
    ),
)
def test_coordinated_parent_rehash_cannot_break_real_component_binding(
    mutation: str,
) -> None:
    synthetic = _synthetic_report()
    real = _real_component(synthetic)
    result = _build(real, synthetic)
    payload = copy.deepcopy(result.payload)
    bindings = result.payload["bindings"]
    if mutation == "capture_build":
        payload["bindings"]["ocr_capture_build_sha256"] = _sha256("forged-capture-build")
    else:
        payload["components"]["real_candidate_roles"]["ocr_evidence_sha256"] = _sha256(
            "forged-ocr-evidence"
        )
    _reseal_parent(payload)

    with pytest.raises(
        CompositeLifecycleEvaluationError,
        match=r"real component|OCR|capture|binding",
    ):
        validate_persisted_composite_lifecycle_evaluation(
            payload,
            persisted_real_component=real.payload,
            expected_evaluation_id=result.evaluation_id,
            expected_dataset_id=result.dataset_id,
            expected_dataset_manifest_sha256=(result.dataset_manifest_sha256),
            expected_stable_outcome_sha256=cast(
                str,
                payload["stable_outcome_sha256"],
            ),
            expected_role_evaluator_build_sha256=bindings["role_evaluator_build_sha256"],
            expected_runtime_set_sha256=bindings["runtime_set_sha256"],
            expected_matcher_fingerprint=bindings["matcher_fingerprint"],
            expected_policy_fingerprint=bindings["policy_fingerprint"],
            expected_template_set_fingerprint=bindings["template_set_fingerprint"],
            expected_candidate_set_sha256=bindings["candidate_set_sha256"],
        )

    assert real.payload["evaluator_version"] == CANDIDATE_ROLE_EVALUATOR_VERSION
