from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from decimal import Decimal

import pytest

from dahe.domain.audit.evidence import EvidenceQuality
from dahe.domain.audit.ticket_roles import (
    RoleAssessment,
    TicketRole,
    TicketSlot,
)
from dahe.verification import locked_set_runner as runner_module
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildSource,
)
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedSetReleaseAttestation,
    LockedTicketImage,
    LockedWaybill,
)
from dahe.verification.locked_set_acceptance import (
    LockedSetAcceptanceError,
    build_locked_set_derived_adversarial_suite,
    locked_set_quality_coverage_sha256,
    quality_review_evidence_sha256,
)
from dahe.verification.locked_set_runner import (
    RUNNER_VERSION,
    IndependentLockedImage,
    LockedOcrRuntimeComparison,
    LockedOcrRuntimeOutput,
    LockedRolePrediction,
    LockedSetRunContext,
    LockedSetRunnerError,
    content_addressed_evidence_relative_path,
    run_locked_set_role_evaluation,
)


def _sha256(index: int) -> str:
    return f"{index:064x}"


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _manifest(
    *,
    swapped_first: bool = False,
    role_labeled_paths: bool = False,
) -> LockedSetManifest:
    waybills: list[LockedWaybill] = []
    for index in range(50):
        loading_role = TicketRole.LOADING
        unloading_role = TicketRole.UNLOADING
        if swapped_first and index == 0:
            loading_role = TicketRole.UNLOADING
            unloading_role = TicketRole.LOADING
        elif index == 2:
            loading_role = TicketRole.UNKNOWN
            unloading_role = TicketRole.UNKNOWN
        waybills.append(
            LockedWaybill(
                sample_id=f"locked-{index + 1:03d}",
                waybill_identity_sha256=_sha256(10_000 + index),
                images=(
                    LockedTicketImage(
                        image_sha256=_sha256(index * 2 + 1),
                        relative_path=(
                            f"truth/loading/{index * 2 + 1:03d}.png"
                            if role_labeled_paths
                            else f"images/{index * 2 + 1:03d}.png"
                        ),
                        slot=TicketSlot.LOADING,
                        role=loading_role,
                        ordinary_net=(
                            None if loading_role is TicketRole.UNKNOWN else Decimal("30.00")
                        ),
                    ),
                    LockedTicketImage(
                        image_sha256=_sha256(index * 2 + 2),
                        relative_path=(
                            f"truth/unloading/{index * 2 + 2:03d}.png"
                            if role_labeled_paths
                            else f"images/{index * 2 + 2:03d}.png"
                        ),
                        slot=TicketSlot.UNLOADING,
                        role=unloading_role,
                        ordinary_net=(
                            None if unloading_role is TicketRole.UNKNOWN else Decimal("29.98")
                        ),
                    ),
                ),
            )
        )
    return LockedSetManifest(
        dataset_id="unseen-locked-set-001",
        dataset_kind="locked",
        tuning_prohibited=True,
        waybills=tuple(waybills),
    )


def _attestation(manifest_sha256: str) -> LockedSetReleaseAttestation:
    return LockedSetReleaseAttestation(
        dataset_id="unseen-locked-set-001",
        manifest_sha256=manifest_sha256,
        exclusion_source_id="persisted-exclusion-snapshot-001",
        exclusion_snapshot_sha256=_sha256(70_003),
        waybill_count=50,
        image_count=100,
        total_bytes=100_000,
        exclusion_counts={
            "calibration_images": 1,
            "development_images": 2,
            "prior_waybill_identities": 3,
            "shadow_images": 4,
            "template_reference_images": 5,
        },
    )


def _quality_coverage(manifest: LockedSetManifest) -> dict[str, object]:
    conditions = (
        "blur",
        "crop",
        "glare",
        "printed",
        "rotation_0",
        "rotation_90",
        "rotation_180",
        "rotation_270",
        "screen",
        "unknown_layout",
    )
    images = [image for waybill in manifest.waybills for image in waybill.images]
    unknown_images = [image.image_sha256 for image in images if image.role is TicketRole.UNKNOWN]
    image_for_condition = {
        "blur": images[8].image_sha256,
        "crop": images[9].image_sha256,
        "glare": images[10].image_sha256,
        "printed": images[11].image_sha256,
        "rotation_0": images[12].image_sha256,
        "rotation_90": images[13].image_sha256,
        "rotation_180": images[14].image_sha256,
        "rotation_270": images[15].image_sha256,
        "screen": images[16].image_sha256,
        "unknown_layout": unknown_images[0],
    }
    entries: list[dict[str, object]] = []
    for condition in conditions:
        entry: dict[str, object] = {
            "condition": condition,
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2026-07-26T09:00:00+08:00",
            "notes": "Direct review.",
            "image_sha256": image_for_condition[condition],
        }
        entry["review_evidence_sha256"] = quality_review_evidence_sha256(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            entry=entry,
        )
        entries.append(entry)
    truth_manifest = {
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
    coverage: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": "unseen-locked-set-001",
        "manifest_sha256": manifest.canonical_sha256,
        "required_conditions": list(conditions),
        "entries": entries,
        "derived_adversarial_suite": (build_locked_set_derived_adversarial_suite(truth_manifest)),
    }
    coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(coverage)
    return coverage


def _similarity_scan(manifest_sha256: str) -> dict[str, object]:
    scan: dict[str, object] = {
        "schema_version": 1,
        "dataset_id": "unseen-locked-set-001",
        "manifest_sha256": manifest_sha256,
        "exclusion_snapshot_sha256": _sha256(70_003),
        "scan_fingerprint": _sha256(70_004),
        "detector_fingerprint": _sha256(70_005),
        "locked_image_count": 100,
        "excluded_image_count": 1,
        "completed": True,
        "candidates": [],
    }
    scan["scan_fingerprint"] = _canonical_sha256(
        {key: value for key, value in scan.items() if key != "scan_fingerprint"}
    )
    return scan


def _history(manifest_sha256: str) -> dict[str, object]:
    event: dict[str, object] = {
        "event_id": "sealed-001",
        "event_type": "sealed",
        "recorded_at": "2026-07-26T08:00:00+08:00",
        "actor_id": "reviewer-01",
    }
    event["event_sha256"] = _canonical_sha256(event)
    history: dict[str, object] = {
        "schema_version": 1,
        "dataset_id": "unseen-locked-set-001",
        "manifest_sha256": manifest_sha256,
        "status": "eligible",
        "events": [event],
    }
    history["history_sha256"] = _canonical_sha256(history)
    return history


def _candidate_review_source_authority() -> dict[str, object]:
    return {
        "schema_version": 1,
        "seal_sha256": _sha256(72_001),
        "package_sha256": _sha256(72_002),
        "record_set_sha256": _sha256(72_003),
        "review_history_authority_sha256": _sha256(72_004),
        "source_authority_sha256": _sha256(72_005),
    }


def _run_context() -> LockedSetRunContext:
    manifest = _application_build_manifest()
    return LockedSetRunContext(
        application_build_sha256=manifest.canonical_sha256,
        application_build_manifest=manifest,
        runtime_set_sha256=_sha256(71_002),
        ocr_composition_evidence_sha256=_sha256(71_006),
        template_set_sha256=_sha256(71_003),
        matcher_sha256=_sha256(71_004),
        policy_sha256=_sha256(71_005),
        expected_runtime_kinds=("cpu", "gpu"),
    )


def _application_build_manifest() -> ApplicationBuildManifest:
    return ApplicationBuildManifest(
        application_version="test-build",
        sources=(
            ApplicationBuildSource(
                path="verification/locked_set_runner.py",
                sha256=_sha256(71_000),
            ),
        ),
    )


def test_run_context_requires_hash_bound_application_build_evidence() -> None:
    manifest = _application_build_manifest()
    values = {
        "application_build_manifest": manifest,
        "runtime_set_sha256": _sha256(71_002),
        "ocr_composition_evidence_sha256": _sha256(71_006),
        "template_set_sha256": _sha256(71_003),
        "matcher_sha256": _sha256(71_004),
        "policy_sha256": _sha256(71_005),
        "expected_runtime_kinds": ("cpu", "gpu"),
    }

    context = LockedSetRunContext(
        application_build_sha256=manifest.canonical_sha256,
        **values,
    )

    assert context.to_payload()["application_build_manifest"] == manifest.to_payload()
    with pytest.raises(LockedSetRunnerError, match="application build"):
        LockedSetRunContext(
            application_build_sha256=_sha256(71_001),
            **values,
        )


class _TruthEchoEvaluator:
    def __init__(
        self,
        manifest: LockedSetManifest,
        *,
        bind_run_context: bool = True,
        measured_runtime_latency_ms: Decimal | None = Decimal("2.5"),
        review_reason_by_image: dict[str, str] | None = None,
    ) -> None:
        self.truth = {
            image.image_sha256: image.role
            for waybill in manifest.waybills
            for image in waybill.images
        }
        self.inputs: list[IndependentLockedImage] = []
        self.run_context = _run_context() if bind_run_context else None
        self.measured_runtime_latency_ms = measured_runtime_latency_ms
        self.review_reason_by_image = review_reason_by_image or {}

    def __call__(self, image: IndependentLockedImage) -> LockedRolePrediction:
        self.inputs.append(image)
        role = self.truth[image.image_sha256]
        prediction = LockedRolePrediction(
            image_sha256=image.image_sha256,
            role=role,
            quality=(
                EvidenceQuality.UNCERTAIN
                if role is TicketRole.UNKNOWN
                else EvidenceQuality.RELIABLE
            ),
            confidence=(Decimal("0.40") if role is TicketRole.UNKNOWN else Decimal("0.95")),
            high_confidence=role is not TicketRole.UNKNOWN,
            assessment_fingerprint=_sha256(80_000 + len(self.inputs)),
            incremental_elapsed_ms=Decimal(len(self.inputs)),
            automatic_review_reason=self.review_reason_by_image.get(
                image.image_sha256
            ),
        )
        if self.measured_runtime_latency_ms is None:
            return prediction
        ordinary_net = None if role is TicketRole.UNKNOWN else Decimal("30.00")
        ordinary_reliable = ordinary_net is not None
        safety_route = (
            "eligible_for_downstream_comparison"
            if role is not TicketRole.UNKNOWN and ordinary_reliable
            else "non_automatic"
        )
        outputs = tuple(
            LockedOcrRuntimeOutput(
                image_sha256=image.image_sha256,
                runtime_kind=runtime_kind,
                runtime_fingerprint=_sha256(81_001 if runtime_kind == "gpu" else 81_002),
                output_fingerprint=_sha256(82_001 if runtime_kind == "gpu" else 82_002),
                worker_elapsed_ms=self.measured_runtime_latency_ms,
                wall_elapsed_ms=self.measured_runtime_latency_ms + Decimal("1"),
                ordinary_net_amount=ordinary_net,
                ordinary_net_unit=("t" if ordinary_reliable else None),
                ordinary_net_confidence=(Decimal("0.98") if ordinary_reliable else None),
                ordinary_net_reliable=ordinary_reliable,
                role=prediction.role,
                role_quality=prediction.quality,
                role_confidence=prediction.confidence,
                role_high_confidence=prediction.high_confidence,
                safety_route=safety_route,
                assessment_fingerprint=(
                    prediction.assessment_fingerprint if runtime_kind == "gpu" else _sha256(83_002)
                ),
            )
            for runtime_kind in ("cpu", "gpu")
        )
        return replace(
            prediction,
            runtime_comparison=LockedOcrRuntimeComparison(
                status="dual_consistent",
                source="local_ocr_locked_evaluator",
                reason=None,
                selected_runtime_kind="gpu",
                critical_fields_match=True,
                differences=(),
                outputs=outputs,
                failures=(),
            ),
        )


def _run(
    manifest: LockedSetManifest,
    evaluator: object,
    *,
    run_context: LockedSetRunContext | None = None,
    candidate_review_source_authority: object | None = None,
) -> dict[str, object]:
    manifest_sha256 = manifest.canonical_sha256
    return run_locked_set_role_evaluation(
        manifest=manifest,
        preflight_attestation=_attestation(manifest_sha256),
        evaluator=evaluator,
        run_context=run_context or _run_context(),
        quality_coverage=_quality_coverage(manifest),
        near_duplicate_scan=_similarity_scan(manifest_sha256),
        near_duplicate_decisions=[],
        eligibility_history=_history(manifest_sha256),
        candidate_review_source_authority=(
            candidate_review_source_authority
            if candidate_review_source_authority is not None
            else _candidate_review_source_authority()
        ),
    )


def test_runner_binds_candidate_review_source_authority_into_both_hashes() -> None:
    manifest = _manifest()
    binding = _candidate_review_source_authority()

    report = _run(
        manifest,
        _TruthEchoEvaluator(manifest),
        candidate_review_source_authority=binding,
    )

    assert report["candidate_review_source_authority"] == binding
    assert report["candidate_review_source_authority_sha256"] == (
        _canonical_sha256(binding)
    )
    base_without_hash = {
        field: value
        for field, value in report.items()
        if field
        not in {
            "image_results",
            "pair_results",
            "report_sha256",
            "run_context",
            "runner_report_sha256",
            "runner_version",
        }
    }
    assert report["report_sha256"] == _canonical_sha256(
        base_without_hash
    )
    assert report["runner_report_sha256"] == _canonical_sha256(
        {
            field: value
            for field, value in report.items()
            if field != "runner_report_sha256"
        }
    )


def test_runner_routes_runtime_weight_disagreement_to_human_review() -> None:
    manifest = _manifest()
    affected = manifest.waybills[0].images[0].image_sha256

    report = _run(
        manifest,
        _TruthEchoEvaluator(
            manifest,
            review_reason_by_image={
                affected: "ocr_weight_disagreement",
            },
        ),
    )

    first = report["pair_results"][0]
    assert first["automatic_outcome"] == "awaiting_review"
    assert first["role_issue"] is None
    assert first["review_reason"] == "ocr_weight_disagreement"


def test_runner_rejects_cpu_only_context_before_invoking_ocr() -> None:
    manifest = _manifest()
    cpu_only_context = replace(
        _run_context(),
        expected_runtime_kinds=("cpu",),
    )
    evaluator = _TruthEchoEvaluator(manifest)
    evaluator.run_context = cpu_only_context

    with pytest.raises(
        LockedSetRunnerError,
        match="CPU plus GPU",
    ):
        _run(
            manifest,
            evaluator,
            run_context=cpu_only_context,
        )

    assert evaluator.inputs == []


def test_runner_passes_only_independent_image_identity_to_role_evaluator() -> None:
    manifest = _manifest()
    evaluator = _TruthEchoEvaluator(manifest)

    report = _run(manifest, evaluator)

    assert report["gate_passed"] is True
    assert report["run_context"]["application_build_sha256"] == (
        _application_build_manifest().canonical_sha256
    )
    first_runtime_comparison = report["image_results"][0]["runtime_comparison"]
    assert first_runtime_comparison["status"] == "dual_consistent"
    assert first_runtime_comparison["critical_fields_match"] is True
    assert len(first_runtime_comparison["outputs"]) == 2
    assert first_runtime_comparison["failures"] == []
    assert report["runtime_execution_gate"]["passed"] is True
    assert len(evaluator.inputs) == 100
    assert set(IndependentLockedImage.__dataclass_fields__) == {
        "image_sha256",
        "relative_path",
    }
    assert evaluator.inputs[0] == IndependentLockedImage(
        image_sha256=_sha256(1),
        relative_path=content_addressed_evidence_relative_path(_sha256(1)),
    )
    assert report["derived_adversarial_gate"] == {
        "scenario_count": 4,
        "passed_count": 4,
        "failed_scenarios": [],
        "passed": True,
    }
    assert [
        (
            result["scenario_id"],
            result["automatic_outcome"],
            result["role_issue"],
        )
        for result in report["derived_adversarial_results"]["results"]
    ] == [
        ("swapped_slots", "awaiting_review", "suspected_swapped"),
        ("both_loading", "awaiting_review", "both_loading"),
        ("both_unloading", "awaiting_review", "both_unloading"),
        ("exact_duplicate_image", "awaiting_review", "duplicate_image"),
    ]
    assert len(evaluator.inputs) == 100


def test_runner_exposes_the_application_build_source_manifest() -> None:
    manifest = _manifest()

    report = _run(manifest, _TruthEchoEvaluator(manifest))

    assert report["run_context"]["application_build_manifest"] == (
        _application_build_manifest().to_payload()
    )


def test_runner_hash_binds_per_image_dual_runtime_comparison_evidence() -> None:
    manifest = _manifest()
    first = _run(
        manifest,
        _TruthEchoEvaluator(
            manifest,
            measured_runtime_latency_ms=Decimal("2.5"),
        ),
    )
    second = _run(
        manifest,
        _TruthEchoEvaluator(
            manifest,
            measured_runtime_latency_ms=Decimal("3.5"),
        ),
    )

    first_image = first["image_results"][0]
    comparison = first_image["runtime_comparison"]
    assert comparison["status"] == "dual_consistent"
    assert comparison["selected_runtime_kind"] == "gpu"
    assert comparison["critical_fields_match"] is True
    assert {item["runtime_kind"] for item in comparison["outputs"]} == {
        "cpu",
        "gpu",
    }
    assert comparison["comparison_sha256"] == _canonical_sha256(
        {key: value for key, value in comparison.items() if key != "comparison_sha256"}
    )
    assert first_image["result_id"] == _canonical_sha256(
        {
            "assessment_fingerprint": (_sha256(80_001)),
            "image_sha256": first_image["image_sha256"],
            "runner_version": RUNNER_VERSION,
            "runtime_comparison_sha256": comparison["comparison_sha256"],
        }
    )
    assert first["runner_report_sha256"] != second["runner_report_sha256"]
    assert first_image["result_id"] != second["image_results"][0]["result_id"]


def test_runtime_comparison_cannot_claim_consistency_for_different_outputs() -> None:
    manifest = _manifest()
    evaluator = _TruthEchoEvaluator(
        manifest,
        measured_runtime_latency_ms=Decimal("2.5"),
    )
    prediction = evaluator(
        IndependentLockedImage(
            image_sha256=_sha256(1),
            relative_path=content_addressed_evidence_relative_path(_sha256(1)),
        )
    )
    cpu, gpu = prediction.runtime_comparison.outputs
    changed_cpu = replace(
        cpu,
        ordinary_net_amount=Decimal("30.01"),
    )

    with pytest.raises(LockedSetRunnerError, match="status is inconsistent"):
        LockedOcrRuntimeComparison(
            status="dual_consistent",
            source="local_ocr_locked_evaluator",
            reason=None,
            selected_runtime_kind="gpu",
            critical_fields_match=True,
            differences=(),
            outputs=(changed_cpu, gpu),
            failures=(),
        )


def test_prediction_must_match_the_selected_runtime_output() -> None:
    manifest = _manifest()
    evaluator = _TruthEchoEvaluator(
        manifest,
        measured_runtime_latency_ms=Decimal("2.5"),
    )
    prediction = evaluator(
        IndependentLockedImage(
            image_sha256=_sha256(1),
            relative_path=content_addressed_evidence_relative_path(_sha256(1)),
        )
    )

    with pytest.raises(LockedSetRunnerError, match="selected runtime"):
        replace(
            prediction,
            role=TicketRole.UNLOADING,
        )


def test_runner_derived_suite_is_independent_of_manifest_order() -> None:
    manifest = _manifest()
    reordered = replace(
        manifest,
        waybills=tuple(
            replace(waybill, images=tuple(reversed(waybill.images)))
            for waybill in reversed(manifest.waybills)
        ),
    )

    first = _run(manifest, _TruthEchoEvaluator(manifest))
    second = _run(reordered, _TruthEchoEvaluator(reordered))

    assert second["derived_adversarial_suite"] == first["derived_adversarial_suite"]
    assert second["derived_adversarial_fingerprint"] == (first["derived_adversarial_fingerprint"])


def test_runner_rejects_divergence_from_production_role_routing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()

    def incorrectly_pass_every_pair(
        _loading: object,
        _unloading: object,
    ) -> RoleAssessment:
        return RoleAssessment(issue=None, roles_valid=True)

    monkeypatch.setattr(
        runner_module,
        "assess_ticket_roles",
        incorrectly_pass_every_pair,
    )

    with pytest.raises(
        LockedSetAcceptanceError,
        match="production role assessment",
    ):
        _run(manifest, _TruthEchoEvaluator(manifest))


def test_runner_rejects_an_unbound_truth_echo_evaluator() -> None:
    manifest = _manifest()
    evaluator = _TruthEchoEvaluator(
        manifest,
        bind_run_context=False,
    )

    with pytest.raises(
        LockedSetRunnerError,
        match=r"evaluator.*context|authoritative evaluator",
    ):
        _run(manifest, evaluator)


def test_runner_rejects_a_context_not_bound_to_the_evaluator() -> None:
    manifest = _manifest()
    evaluator = _TruthEchoEvaluator(manifest)
    forged_context = replace(
        _run_context(),
        policy_sha256=_sha256(71_999),
    )

    with pytest.raises(
        LockedSetRunnerError,
        match=r"evaluator.*context|run context",
    ):
        _run(
            manifest,
            evaluator,
            run_context=forged_context,
        )


def test_runner_replaces_role_labeled_paths_with_opaque_evidence_paths() -> None:
    manifest = _manifest(role_labeled_paths=True)
    evaluator = _TruthEchoEvaluator(manifest)

    report = _run(manifest, evaluator)

    assert report["gate_passed"] is True
    assert len(evaluator.inputs) == 100
    assert all(
        item.relative_path == content_addressed_evidence_relative_path(item.image_sha256)
        for item in evaluator.inputs
    )
    assert all(
        "loading" not in item.relative_path and "unloading" not in item.relative_path
        for item in evaluator.inputs
    )


def test_runner_detects_swapped_truth_without_automatic_pass() -> None:
    manifest = _manifest(swapped_first=True)
    evaluator = _TruthEchoEvaluator(manifest)

    report = _run(manifest, evaluator)

    metrics = report["metrics"]
    assert isinstance(metrics, dict)
    assert metrics["wrong_auto_pass_count"] == 0
    pair_results = report["pair_results"]
    assert isinstance(pair_results, list)
    assert pair_results[0]["automatic_outcome"] == "awaiting_review"
    assert pair_results[0]["role_issue"] == "suspected_swapped"
    assert report["gate_passed"] is True


@pytest.mark.parametrize(
    ("loading_role", "unloading_role", "expected_issue"),
    [
        (TicketRole.LOADING, TicketRole.LOADING, "both_loading"),
        (TicketRole.UNKNOWN, TicketRole.UNLOADING, "role_unknown"),
    ],
)
def test_runner_keeps_same_role_and_non_ticket_truth_out_of_automatic_pass(
    loading_role: TicketRole,
    unloading_role: TicketRole,
    expected_issue: str,
) -> None:
    manifest = _manifest()
    first = manifest.waybills[0]
    changed = replace(
        first,
        images=(
            replace(
                first.images[0],
                role=loading_role,
                ordinary_net=(None if loading_role is TicketRole.UNKNOWN else Decimal("30.00")),
            ),
            replace(
                first.images[1],
                role=unloading_role,
                ordinary_net=(None if unloading_role is TicketRole.UNKNOWN else Decimal("29.98")),
            ),
        ),
    )
    manifest = replace(
        manifest,
        waybills=(changed, *manifest.waybills[1:]),
    )

    report = _run(manifest, _TruthEchoEvaluator(manifest))

    assert report["pair_results"][0]["automatic_outcome"] == "awaiting_review"
    assert report["pair_results"][0]["role_issue"] == expected_issue
    assert report["metrics"]["wrong_auto_pass_count"] == 0
    assert report["gate_passed"] is True


def test_runner_rejects_prediction_for_another_image() -> None:
    manifest = _manifest()
    evaluator = _TruthEchoEvaluator(manifest)

    def wrong_identity(image: IndependentLockedImage) -> LockedRolePrediction:
        prediction = evaluator(image)
        return LockedRolePrediction(
            image_sha256=_sha256(999),
            role=prediction.role,
            quality=prediction.quality,
            confidence=prediction.confidence,
            high_confidence=prediction.high_confidence,
            assessment_fingerprint=prediction.assessment_fingerprint,
            incremental_elapsed_ms=prediction.incremental_elapsed_ms,
        )

    wrong_identity.run_context = _run_context()  # type: ignore[attr-defined]
    with pytest.raises(LockedSetRunnerError, match="image identity"):
        _run(manifest, wrong_identity)


def test_runner_propagates_technical_failure_instead_of_creating_review_item() -> None:
    manifest = _manifest()

    def failed(_: IndependentLockedImage) -> LockedRolePrediction:
        raise RuntimeError("synthetic worker crash")

    failed.run_context = _run_context()  # type: ignore[attr-defined]
    with pytest.raises(LockedSetRunnerError, match="technical failure"):
        _run(manifest, failed)


def test_runner_rejects_unreliable_known_role_contract() -> None:
    manifest = _manifest()

    def unreliable(image: IndependentLockedImage) -> LockedRolePrediction:
        return LockedRolePrediction(
            image_sha256=image.image_sha256,
            role=TicketRole.LOADING,
            quality=EvidenceQuality.UNCERTAIN,
            confidence=Decimal("0.8"),
            high_confidence=False,
            assessment_fingerprint=_sha256(90_001),
            incremental_elapsed_ms=Decimal("1"),
        )

    unreliable.run_context = _run_context()  # type: ignore[attr-defined]
    with pytest.raises(LockedSetRunnerError, match="prediction contract"):
        _run(manifest, unreliable)
