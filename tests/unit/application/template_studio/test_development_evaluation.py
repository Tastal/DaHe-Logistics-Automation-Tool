from __future__ import annotations

import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from dahe.application.template_studio import development_evaluation
from dahe.application.template_studio.development_evaluation import (
    AUTHORIZING_TRUTH_SOURCE,
    FrozenDevelopmentFixtureError,
    MeasurementStatus,
    authorizing_observation_sha256,
    load_authorizing_development_dataset,
    load_frozen_development_fixture,
    run_authorizing_development_evaluation,
    run_development_evaluation,
    run_frozen_development_evaluation,
)
from dahe.application.template_studio.matcher import ObservedTextLine
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    NormalizedRect,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
)

PROJECT_ROOT = Path(__file__).resolve().parents[4]
FROZEN_MANIFEST = (
    PROJECT_ROOT
    / "verification"
    / "loops"
    / "loop-7"
    / "20260725T232143+0800"
    / "fixture-manifest.json"
)


def _rect_payload(rectangle: NormalizedRect) -> dict[str, str]:
    return {
        "height": str(rectangle.height),
        "width": str(rectangle.width),
        "x": str(rectangle.x),
        "y": str(rectangle.y),
    }


def _write_authorizing_manifest(
    path: Path,
    *,
    loading_candidate: TemplateVersion,
    unloading_candidate: TemplateVersion,
    cover_loading: bool = True,
) -> Path:
    loading_definition = loading_candidate.definition
    unloading_definition = unloading_candidate.definition

    def lines(
        definition: TemplateDefinition,
        *,
        covered: bool = True,
    ) -> list[dict[str, object]]:
        if not covered:
            return [
                {
                    "box": {
                        "height": "0.05",
                        "width": "0.20",
                        "x": "0.60",
                        "y": "0.40",
                    },
                    "confidence": "0.99",
                    "text": "unrelated document",
                }
            ]
        return [
            {
                "box": _rect_payload(anchor.box),
                "confidence": "0.98",
                "text": anchor.expected_text,
            }
            for anchor in definition.anchors
        ]

    def identity(
        *,
        case_id: str,
        sample_id: str,
        rows: list[dict[str, object]],
    ) -> str:
        observed = tuple(
            ObservedTextLine(
                text=str(row["text"]),
                confidence=Decimal(str(row["confidence"])),
                box=NormalizedRect(
                    x=Decimal(str(row["box"]["x"])),  # type: ignore[index]
                    y=Decimal(str(row["box"]["y"])),  # type: ignore[index]
                    width=Decimal(str(row["box"]["width"])),  # type: ignore[index]
                    height=Decimal(str(row["box"]["height"])),  # type: ignore[index]
                ),
            )
            for row in rows
        )
        return authorizing_observation_sha256(
            case_id=case_id,
            sample_id=sample_id,
            orientation_degrees=0,
            text_lines=observed,
        )

    loading_lines = lines(
        loading_definition,
        covered=cover_loading,
    )
    unloading_lines = lines(unloading_definition)
    payload = {
        "schema_version": 1,
        "kind": "authorizing_observation_dataset",
        "dataset_id": "loop7-authorizing-observations-v1",
        "production_data": False,
        "contains_credentials": False,
        "contains_personal_data": False,
        "observations": [
            {
                "case_id": "loading-observation",
                "truth_role": "loading",
                "truth_source": AUTHORIZING_TRUTH_SOURCE,
                "quality_tags": ["printed"],
                "rotations": [
                    {
                        "sample_id": "loading-observation@0",
                        "orientation_degrees": 0,
                        "observation_sha256": identity(
                            case_id="loading-observation",
                            sample_id="loading-observation@0",
                            rows=loading_lines,
                        ),
                        "ocr_lines": loading_lines,
                    }
                ],
            },
            {
                "case_id": "unloading-observation",
                "truth_role": "unloading",
                "truth_source": AUTHORIZING_TRUTH_SOURCE,
                "quality_tags": ["screen"],
                "rotations": [
                    {
                        "sample_id": "unloading-observation@0",
                        "orientation_degrees": 0,
                        "observation_sha256": identity(
                            case_id="unloading-observation",
                            sample_id="unloading-observation@0",
                            rows=unloading_lines,
                        ),
                        "ocr_lines": unloading_lines,
                    }
                ],
            },
        ],
        "pair_cases": [
            {
                "case_id": "normal-pair",
                "loading_sample_id": "loading-observation@0",
                "unloading_sample_id": "unloading-observation@0",
                "expected_issue": None,
            },
            {
                "case_id": "swapped-pair",
                "loading_sample_id": "unloading-observation@0",
                "unloading_sample_id": "loading-observation@0",
                "expected_issue": "suspected_swapped",
            },
        ],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def _contains_forbidden_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key) in {"slot", "web_weight", "platform_weight", "expected_weight"}
            or _contains_forbidden_key(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_key(child) for child in value)
    return False


def test_frozen_manifest_parser_normalizes_raw_role_evidence_without_mutating_input() -> None:
    before = FROZEN_MANIFEST.read_bytes()

    fixture = load_frozen_development_fixture(
        FROZEN_MANIFEST,
        candidate_lifecycle=TemplateLifecycle.DRAFT,
    )

    assert FROZEN_MANIFEST.read_bytes() == before
    assert len(fixture.candidates) == 2
    assert {candidate.definition.family_id for candidate in fixture.candidates} == {
        "synthetic_loading_scale",
        "synthetic_unloading_scale",
    }
    loading_title = fixture.candidates[0].definition.anchors[0]
    assert loading_title.loading_evidence.as_integer_ratio() == (1, 1)
    assert loading_title.unloading_evidence.as_integer_ratio() == (-1, 1)
    assert all(
        candidate.lifecycle is TemplateLifecycle.DRAFT
        for candidate in fixture.candidates
    )


def test_generated_synthetic_manifest_is_not_an_authorizing_dataset() -> None:
    with pytest.raises(
        FrozenDevelopmentFixtureError,
        match="authorizing_observation_dataset",
    ):
        load_authorizing_development_dataset(FROZEN_MANIFEST)


def test_frozen_evaluation_runs_all_rotations_and_reconciles_expected_results() -> None:
    report = run_frozen_development_evaluation(FROZEN_MANIFEST)

    assert report.expected_count == 15
    assert report.result_count == 15
    assert len(report.items) == 15
    assert len({item.sample_id for item in report.items}) == 15
    assert {
        item.orientation_degrees
        for item in report.items
        if item.case_id == "loading-clear"
    } == {0, 90, 180, 270}
    assert all(item.expected_matches_result for item in report.items)
    assert report.metrics.expected_result_reconciliation.value == {
        "expected_count": 15,
        "matched_count": 15,
        "mismatch_count": 0,
        "result_count": 15,
    }
    assert report.metrics.confusion_matrix.value == {
        "loading": {"loading": 4, "unknown": 0, "unloading": 0},
        "unknown": {"loading": 0, "unknown": 7, "unloading": 0},
        "unloading": {"loading": 0, "unknown": 0, "unloading": 4},
    }
    assert report.metrics.unknown_rate.value == "0.4666666666666666666666666667"
    assert report.metrics.high_confidence_errors.value == 0
    assert report.gate_passed is True


def test_development_report_exposes_measured_routing_metrics_and_honest_gap() -> None:
    report = run_frozen_development_evaluation(FROZEN_MANIFEST)
    metrics = report.metrics

    for measurement in (
        metrics.geometry_match_rate,
        metrics.anchor_pass_rate,
        metrics.direct_completion_rate,
        metrics.fallback_rate,
        metrics.wrong_template_rate,
        metrics.role_conflict_rate,
        metrics.unknown_layout_rate,
        metrics.p50_elapsed_ms,
        metrics.p95_elapsed_ms,
    ):
        assert measurement.status is MeasurementStatus.MEASURED
        assert measurement.value is not None
        assert measurement.definition

    assert metrics.field_reliability.status is MeasurementStatus.NOT_MEASURED
    assert metrics.field_reliability.value is None
    assert "field extraction" in metrics.field_reliability.definition


def test_development_report_counts_synthetic_samples_and_quality_tags() -> None:
    report = run_frozen_development_evaluation(FROZEN_MANIFEST)

    assert report.metrics.sample_count.value == {
        "observation_cases": 8,
        "observation_runs": 15,
        "pair_cases": 5,
    }
    assert report.metrics.quality_tag_distribution.value == {
        "observation_cases": {
            "blur": 1,
            "crop": 1,
            "glare": 1,
            "other_document": 1,
            "printed": 2,
            "screen": 2,
        },
        "observation_runs": {
            "blur": 1,
            "crop": 1,
            "glare": 1,
            "other_document": 1,
            "printed": 5,
            "screen": 6,
        },
    }
    assert report.metrics.development_sample_scope.value == {
        "dataset_kind": "generated_synthetic",
        "formal_acceptance_eligible": False,
        "production_data": False,
        "warning": (
            "Small synthetic development sample; do not use as a formal "
            "locked-set or production-shadow gate."
        ),
    }


def test_development_report_adds_pair_rates_and_wilson_intervals_without_gate_change() -> None:
    report = run_frozen_development_evaluation(FROZEN_MANIFEST)
    metrics = report.metrics

    assert metrics.synthetic_swapped_pair_recall.value == "1"
    assert metrics.normal_pair_false_positive_rate.value == "0"
    assert metrics.unknown_rate_wilson_95_ci.value == {
        "confidence_level": "0.95",
        "lower": "0.248095",
        "method": "wilson_score",
        "sample_count": 15,
        "success_count": 7,
        "upper": "0.69883",
    }
    assert metrics.wrong_template_rate_wilson_95_ci.value == {
        "confidence_level": "0.95",
        "lower": "0",
        "method": "wilson_score",
        "sample_count": 15,
        "success_count": 0,
        "upper": "0.203883",
    }
    swapped_interval = metrics.synthetic_swapped_pair_recall_wilson_95_ci.value
    normal_interval = metrics.normal_pair_false_positive_rate_wilson_95_ci.value
    assert isinstance(swapped_interval, dict)
    assert isinstance(normal_interval, dict)
    assert Decimal(str(swapped_interval["lower"])) < Decimal("0.21")
    assert swapped_interval["upper"] == "1"
    assert Decimal(str(normal_interval["upper"])) > Decimal("0.79")
    assert normal_interval["lower"] == "0"
    assert "synthetic" in metrics.synthetic_swapped_pair_recall.definition.lower()
    assert "small" in metrics.normal_pair_false_positive_rate.definition.lower()
    assert report.gate_passed is True

    payload = report.to_record_evaluation_payload(
        build_fingerprint="a" * 64,
        runtime_fingerprint="b" * 64,
    )
    persisted = payload["metrics"]
    assert isinstance(persisted, dict)
    development_metrics = persisted["development_metrics"]
    assert isinstance(development_metrics, dict)
    for key in (
        "sample_count",
        "quality_tag_distribution",
        "synthetic_swapped_pair_recall",
        "normal_pair_false_positive_rate",
        "unknown_rate_wilson_95_ci",
        "wrong_template_rate_wilson_95_ci",
        "synthetic_swapped_pair_recall_wilson_95_ci",
        "normal_pair_false_positive_rate_wilson_95_ci",
        "development_sample_scope",
    ):
        assert key in development_metrics


def test_pair_cases_call_existing_pair_contract_and_reconcile_expected_issue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, object]] = []
    original = development_evaluation.assess_ticket_roles

    def recording_assessment(loading: object, unloading: object) -> Any:
        calls.append((loading, unloading))
        return original(loading, unloading)  # type: ignore[arg-type]

    monkeypatch.setattr(
        development_evaluation,
        "assess_ticket_roles",
        recording_assessment,
    )

    report = run_frozen_development_evaluation(FROZEN_MANIFEST)

    assert len(calls) == 5
    assert [(item.case_id, item.result_issue) for item in report.pair_items] == [
        ("normal-pair", None),
        ("suspected-swapped", "suspected_swapped"),
        ("duplicate-image", "duplicate_image"),
        ("both-loading", "both_loading"),
        ("unknown-role", "role_unknown"),
    ]
    assert all(item.expected_matches_result for item in report.pair_items)
    assert report.metrics.pair_reconciliation.value == {
        "expected_count": 5,
        "matched_count": 5,
        "mismatch_count": 0,
        "result_count": 5,
    }


def test_report_payload_is_json_only_safe_for_repository_and_has_stable_hashes() -> None:
    first = run_frozen_development_evaluation(FROZEN_MANIFEST)
    second = run_frozen_development_evaluation(FROZEN_MANIFEST)

    payload = first.to_record_evaluation_payload(
        build_fingerprint="a" * 64,
        runtime_fingerprint="b" * 64,
    )
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    assert json.loads(encoded) == payload
    assert first.evaluation_fingerprint == second.evaluation_fingerprint
    assert first.stable_outcome_sha256 == second.stable_outcome_sha256
    assert len(first.evaluation_fingerprint) == 64
    assert len(first.stable_outcome_sha256) == 64
    assert payload["dataset_kind"] == "development"
    assert payload["expected_count"] == payload["result_count"] == 15
    assert len(payload["candidates"]) == 2
    assert len(payload["items"]) == 15
    metrics = payload["metrics"]
    assert isinstance(metrics, dict)
    assert len(metrics["pair_results"]) == 5
    assert metrics["stable_outcome_sha256"] == first.stable_outcome_sha256
    assert _contains_forbidden_key(payload) is False
    assert {
        item["truth"] for item in payload["items"]  # type: ignore[index,union-attr]
    } == {role.value for role in TicketRole}


def test_core_runner_binds_report_candidates_to_actual_repository_versions() -> None:
    fixture = load_frozen_development_fixture(FROZEN_MANIFEST)
    actual_candidates = tuple(
        replace(
            candidate,
            version_id=f"repo-{index}-v7",
            lifecycle=TemplateLifecycle.DEVELOPMENT_TESTED,
            record_version=7,
            version_number=7,
        )
        for index, candidate in enumerate(fixture.candidates, start=1)
    )

    report = run_development_evaluation(
        fixture,
        candidates=actual_candidates,
    )
    reordered = run_development_evaluation(
        fixture,
        candidates=tuple(reversed(actual_candidates)),
    )
    payload = report.to_record_evaluation_payload(
        build_fingerprint="a" * 64,
        runtime_fingerprint="b" * 64,
    )

    assert report.gate_passed is True
    assert report.evaluation_fingerprint == reordered.evaluation_fingerprint
    assert report.stable_outcome_sha256 == reordered.stable_outcome_sha256
    assert payload["candidates"] == [
        {
            "content_sha256": candidate.content_sha256,
            "version_id": candidate.version_id,
        }
        for candidate in actual_candidates
    ]


def test_core_runner_rejects_repository_candidate_definition_drift() -> None:
    fixture = load_frozen_development_fixture(FROZEN_MANIFEST)
    candidate = fixture.candidates[0]
    drifted = replace(
        candidate,
        version_id="repo-drifted-v2",
        definition=replace(
            candidate.definition,
            name="Definition not represented by the frozen manifest",
        ),
    )

    with pytest.raises(FrozenDevelopmentFixtureError, match="content"):
        run_development_evaluation(
            fixture,
            candidates=(drifted, fixture.candidates[1]),
        )


def test_core_runner_uses_matching_current_shadow_for_non_candidate_family() -> None:
    fixture = load_frozen_development_fixture(FROZEN_MANIFEST)
    loading_candidate = replace(
        fixture.candidates[0],
        version_id="repo-loading-v3",
        lifecycle=TemplateLifecycle.DEVELOPMENT_TESTED,
        record_version=3,
        version_number=3,
    )
    unloading_shadow = replace(
        fixture.candidates[1],
        version_id="repo-unloading-shadow-v2",
        lifecycle=TemplateLifecycle.SHADOW,
        record_version=4,
        version_number=2,
    )

    report = run_development_evaluation(
        fixture,
        candidates=(loading_candidate,),
        current_shadow=(unloading_shadow,),
    )

    assert report.gate_passed is True
    assert tuple(candidate.version_id for candidate in report.candidates) == (
        "repo-loading-v3",
    )


def test_authorizing_dataset_is_independent_from_random_ui_family_ids(
    tmp_path: Path,
) -> None:
    regression_fixture = load_frozen_development_fixture(FROZEN_MANIFEST)
    loading = replace(
        regression_fixture.candidates[0],
        version_id=f"ui-version-{uuid4().hex}",
        definition=replace(
            regression_fixture.candidates[0].definition,
            family_id=f"ui-family-{uuid4().hex}",
        ),
    )
    unloading = replace(
        regression_fixture.candidates[1],
        version_id=f"ui-version-{uuid4().hex}",
        definition=replace(
            regression_fixture.candidates[1].definition,
            family_id=f"ui-family-{uuid4().hex}",
        ),
    )
    manifest = _write_authorizing_manifest(
        tmp_path / "authorizing-observations.json",
        loading_candidate=loading,
        unloading_candidate=unloading,
    )

    dataset = load_authorizing_development_dataset(manifest)
    report = run_authorizing_development_evaluation(
        dataset,
        candidates=(loading, unloading),
    )

    assert report.gate_passed is True
    assert report.expected_count == report.result_count == 2
    assert {candidate.family_id for candidate in report.candidates} == {
        loading.definition.family_id,
        unloading.definition.family_id,
    }
    assert report.metrics.development_sample_scope.value == {
        "dataset_kind": "authorizing_observation_dataset",
        "formal_acceptance_eligible": False,
        "production_data": False,
        "warning": (
            "Code-authored synthetic development evidence only; it cannot "
            "prove real-image accuracy or replace the independent locked-set "
            "and production-shadow gates."
        ),
    }


def test_authorizing_dataset_fails_when_a_candidate_has_no_observation_coverage(
    tmp_path: Path,
) -> None:
    regression_fixture = load_frozen_development_fixture(FROZEN_MANIFEST)
    manifest = _write_authorizing_manifest(
        tmp_path / "uncovered-authorizing-observations.json",
        loading_candidate=regression_fixture.candidates[0],
        unloading_candidate=regression_fixture.candidates[1],
        cover_loading=False,
    )
    dataset = load_authorizing_development_dataset(manifest)

    with pytest.raises(FrozenDevelopmentFixtureError, match="not covered"):
        run_authorizing_development_evaluation(
            dataset,
            candidates=regression_fixture.candidates,
        )


def test_authorizing_dataset_rejects_observation_identity_mismatch(
    tmp_path: Path,
) -> None:
    regression_fixture = load_frozen_development_fixture(FROZEN_MANIFEST)
    manifest = _write_authorizing_manifest(
        tmp_path / "identity-mismatch.json",
        loading_candidate=regression_fixture.candidates[0],
        unloading_candidate=regression_fixture.candidates[1],
    )
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["observations"][0]["rotations"][0]["observation_sha256"] = "0" * 64
    manifest.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        FrozenDevelopmentFixtureError,
        match="does not match canonical OCR observation",
    ):
        load_authorizing_development_dataset(manifest)
