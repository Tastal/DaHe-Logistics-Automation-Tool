"""RED contracts for the formal Loop 7 locked-set acceptance toolchain.

These tests deliberately target a module that does not exist yet. They freeze
the release boundary without treating the current development evaluator or the
caller-assembled exclusion preflight as formal locked-set evidence.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
from types import ModuleType

import pytest

from dahe.verification.locked_set_acceptance import (
    build_locked_set_derived_adversarial_suite,
    locked_set_quality_coverage_sha256,
    not_measured_runtime_comparison_payload,
    quality_review_evidence_sha256,
)

DATASET_ID = "unseen-locked-set-001"
MANIFEST_SHA256 = f"{70_001:064x}"
ATTESTATION_SHA256 = f"{70_002:064x}"
EXCLUSION_SNAPSHOT_SHA256 = f"{70_003:064x}"
REQUIRED_NATURAL_QUALITY_CONDITIONS = (
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


@pytest.fixture(scope="module")
def acceptance_contract() -> ModuleType:
    """Load the not-yet-implemented acceptance boundary.

    Keeping the import inside a fixture lets pytest collect every intended
    contract. The RED phase is an explicit missing-module failure instead of an
    accidental collection crash.
    """

    try:
        return importlib.import_module("dahe.verification.locked_set_acceptance")
    except ModuleNotFoundError:
        pytest.fail(
            "formal Loop 7 locked-set acceptance module is not implemented",
            pytrace=False,
        )


def _truth_manifest() -> dict[str, object]:
    pairs: list[dict[str, object]] = []
    for index in range(50):
        loading_index = index * 2 + 1
        unloading_index = index * 2 + 2
        loading_role = "loading"
        unloading_role = "unloading"
        if index == 2:
            loading_role = "unknown"
            unloading_role = "unknown"
        pairs.append(
            {
                "sample_id": f"locked-{index + 1:03d}",
                "waybill_identity_sha256": _sha256(10_000 + index),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": _sha256(loading_index),
                        "truth_role": loading_role,
                    },
                    {
                        "image_sha256": _sha256(unloading_index),
                        "truth_role": unloading_role,
                    },
                ],
                "submitted_slots": {
                    "loading": _sha256(loading_index),
                    "unloading": _sha256(unloading_index),
                },
            }
        )
    return {
        "schema_version": 1,
        "dataset_id": DATASET_ID,
        "manifest_sha256": MANIFEST_SHA256,
        "waybill_count": 50,
        "image_count": 100,
        "pairs": pairs,
    }


def _preflight_attestation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": DATASET_ID,
        "manifest_sha256": MANIFEST_SHA256,
        "attestation_sha256": ATTESTATION_SHA256,
        "exclusion_snapshot_sha256": EXCLUSION_SNAPSHOT_SHA256,
        "waybill_count": 50,
        "image_count": 100,
    }


def _image_results(
    truth_manifest: dict[str, object] | None = None,
    *,
    runtime_status: str = "dual_consistent",
) -> list[dict[str, object]]:
    manifest = truth_manifest or _truth_manifest()
    raw_pairs = manifest["pairs"]
    assert isinstance(raw_pairs, list)
    results: list[dict[str, object]] = []
    for pair in raw_pairs:
        assert isinstance(pair, dict)
        images = pair["images"]
        assert isinstance(images, list)
        for image in images:
            assert isinstance(image, dict)
            image_sha256 = image["image_sha256"]
            assert isinstance(image_sha256, str)
            image_index = int(image_sha256, 16)
            role = str(image["truth_role"])
            high_confidence = role != "unknown"
            if runtime_status == "dual_consistent":
                runtime_comparison = _dual_runtime_comparison(
                    image_sha256=image_sha256,
                    role=role,
                    high_confidence=high_confidence,
                )
            elif runtime_status == "single_cpu":
                runtime_comparison = _single_cpu_runtime_comparison(
                    image_sha256=image_sha256,
                    role=role,
                    high_confidence=high_confidence,
                )
            elif runtime_status == "gpu_failed_cpu_fallback":
                runtime_comparison = _gpu_failed_cpu_fallback_comparison(
                    image_sha256=image_sha256,
                    role=role,
                    high_confidence=high_confidence,
                )
            elif runtime_status == "not_measured":
                runtime_comparison = not_measured_runtime_comparison_payload()
            else:
                raise AssertionError(f"unsupported test runtime status: {runtime_status}")
            results.append(
                {
                    "result_id": f"image-result-{image_index:03d}",
                    "sample_id": pair["sample_id"],
                    "image_sha256": image_sha256,
                    "predicted_role": role,
                    "high_confidence": high_confidence,
                    "incremental_elapsed_ms": f"{image_index}.000",
                    "runtime_comparison": runtime_comparison,
                }
            )
    return results


def _dual_runtime_comparison(
    *,
    image_sha256: str,
    role: str,
    high_confidence: bool,
) -> dict[str, object]:
    ordinary_reliable = role != "unknown"
    critical_output: dict[str, object] = {
        "ordinary_net_amount": "30" if ordinary_reliable else None,
        "ordinary_net_unit": "t" if ordinary_reliable else None,
        "ordinary_net_reliable": ordinary_reliable,
        "weight_review_reason": None,
        "role": role,
        "role_quality": "reliable" if ordinary_reliable else "uncertain",
        "role_high_confidence": high_confidence,
        "safety_route": (
            "eligible_for_downstream_comparison" if ordinary_reliable else "non_automatic"
        ),
    }
    outputs = [
        {
            "assessment_fingerprint": _sha256(72_001 if runtime_kind == "cpu" else 72_002),
            "critical_output": copy.deepcopy(critical_output),
            "image_sha256": image_sha256,
            "ordinary_net_confidence": ("0.98" if ordinary_reliable else None),
            "output_fingerprint": _sha256(73_001 if runtime_kind == "cpu" else 73_002),
            "role_confidence": "0.95" if ordinary_reliable else "0.40",
            "runtime_fingerprint": _sha256(74_001 if runtime_kind == "cpu" else 74_002),
            "runtime_kind": runtime_kind,
            "wall_elapsed_ms": ("8.500" if runtime_kind == "cpu" else "2.500"),
            "worker_elapsed_ms": ("8.000" if runtime_kind == "cpu" else "2.000"),
        }
        for runtime_kind in ("cpu", "gpu")
    ]
    payload: dict[str, object] = {
        "critical_fields_match": True,
        "differences": [],
        "failures": [],
        "outputs": outputs,
        "reason": None,
        "schema_version": 1,
        "selected_runtime_kind": "gpu",
        "source": "local_ocr_locked_evaluator",
        "status": "dual_consistent",
    }
    payload["comparison_sha256"] = _canonical_sha256(payload)
    return payload


def _single_cpu_runtime_comparison(
    *,
    image_sha256: str,
    role: str,
    high_confidence: bool,
) -> dict[str, object]:
    payload = _dual_runtime_comparison(
        image_sha256=image_sha256,
        role=role,
        high_confidence=high_confidence,
    )
    outputs = payload["outputs"]
    assert isinstance(outputs, list)
    payload.update(
        {
            "critical_fields_match": None,
            "outputs": [copy.deepcopy(outputs[0])],
            "reason": "single_qualified_cpu",
            "selected_runtime_kind": "cpu",
            "status": "single_cpu",
        }
    )
    payload["comparison_sha256"] = _canonical_sha256(
        {field: value for field, value in payload.items() if field != "comparison_sha256"}
    )
    return payload


def _gpu_failed_cpu_fallback_comparison(
    *,
    image_sha256: str,
    role: str,
    high_confidence: bool,
) -> dict[str, object]:
    payload = _single_cpu_runtime_comparison(
        image_sha256=image_sha256,
        role=role,
        high_confidence=high_confidence,
    )
    payload.update(
        {
            "failures": [
                {
                    "diagnostic_code": "LOCKED-OCR-GPU-FAILURE",
                    "error_kind": "runtime_failure",
                    "image_sha256": image_sha256,
                    "runtime_fingerprint": _sha256(74_002),
                    "runtime_kind": "gpu",
                    "wall_elapsed_ms": "3.000",
                }
            ],
            "reason": "gpu_runtime_failed",
            "status": "gpu_failed_cpu_fallback",
        }
    )
    payload["comparison_sha256"] = _canonical_sha256(
        {field: value for field, value in payload.items() if field != "comparison_sha256"}
    )
    return payload


def _dual_different_runtime_comparison(
    *,
    image_sha256: str,
    role: str,
    high_confidence: bool,
) -> dict[str, object]:
    payload = _dual_runtime_comparison(
        image_sha256=image_sha256,
        role=role,
        high_confidence=high_confidence,
    )
    outputs = payload["outputs"]
    assert isinstance(outputs, list)
    gpu_output = outputs[1]
    assert isinstance(gpu_output, dict)
    critical = gpu_output["critical_output"]
    assert isinstance(critical, dict)
    critical["ordinary_net_amount"] = "30.01"
    payload.update(
        {
            "critical_fields_match": False,
            "differences": ["ordinary_net_amount"],
            "reason": "critical_outputs_differ",
            "selected_runtime_kind": "cpu",
            "status": "dual_different",
        }
    )
    payload["comparison_sha256"] = _canonical_sha256(
        {field: value for field, value in payload.items() if field != "comparison_sha256"}
    )
    return payload


def _replace_image_prediction(
    result: dict[str, object],
    *,
    role: str,
    high_confidence: bool,
) -> None:
    result["predicted_role"] = role
    result["high_confidence"] = high_confidence
    result["runtime_comparison"] = _dual_runtime_comparison(
        image_sha256=str(result["image_sha256"]),
        role=role,
        high_confidence=high_confidence,
    )


def _pair_results(
    truth_manifest: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    manifest = truth_manifest or _truth_manifest()
    raw_pairs = manifest["pairs"]
    assert isinstance(raw_pairs, list)
    results: list[dict[str, object]] = []
    for pair in raw_pairs:
        assert isinstance(pair, dict)
        slots = pair["submitted_slots"]
        assert isinstance(slots, dict)
        images = pair["images"]
        assert isinstance(images, list)
        truth_by_hash = {
            image["image_sha256"]: image["truth_role"]
            for image in images
            if isinstance(image, dict)
        }
        roles_valid = (
            truth_by_hash[slots["loading"]] == "loading"
            and truth_by_hash[slots["unloading"]] == "unloading"
        )
        loading_role = truth_by_hash[slots["loading"]]
        unloading_role = truth_by_hash[slots["unloading"]]
        if roles_valid:
            role_issue = None
        elif loading_role == "unloading" and unloading_role == "loading":
            role_issue = "suspected_swapped"
        elif loading_role == "loading" and unloading_role == "loading":
            role_issue = "both_loading"
        elif loading_role == "unloading" and unloading_role == "unloading":
            role_issue = "both_unloading"
        else:
            role_issue = "role_unknown"
        results.append(
            {
                "result_id": f"pair-result-{pair['sample_id']}",
                "sample_id": pair["sample_id"],
                "loading_slot_image_sha256": slots["loading"],
                "unloading_slot_image_sha256": slots["unloading"],
                "automatic_outcome": ("normal_ready" if roles_valid else "awaiting_review"),
                "role_issue": role_issue,
                "review_reason": None,
            }
        )
    return results


def _quality_coverage(
    truth_manifest: dict[str, object] | None = None,
) -> dict[str, object]:
    manifest = truth_manifest or _truth_manifest()
    image_for_condition = {
        "blur": _sha256(7),
        "crop": _sha256(8),
        "glare": _sha256(9),
        "printed": _sha256(10),
        "rotation_0": _sha256(11),
        "rotation_90": _sha256(12),
        "rotation_180": _sha256(13),
        "rotation_270": _sha256(14),
        "screen": _sha256(15),
        "unknown_layout": _sha256(6),
    }
    entries: list[dict[str, object]] = []
    for condition in REQUIRED_NATURAL_QUALITY_CONDITIONS:
        entry: dict[str, object] = {
            "condition": condition,
            "reviewer_id": "independent-reviewer-01",
            "reviewed_at": "2026-07-26T00:00:00Z",
            "notes": f"Direct image review confirmed {condition}.",
            "image_sha256": image_for_condition[condition],
        }
        entry["review_evidence_sha256"] = quality_review_evidence_sha256(
            dataset_id=DATASET_ID,
            manifest_sha256=MANIFEST_SHA256,
            entry=entry,
        )
        entries.append(entry)
    coverage: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": DATASET_ID,
        "manifest_sha256": MANIFEST_SHA256,
        "required_conditions": list(REQUIRED_NATURAL_QUALITY_CONDITIONS),
        "entries": entries,
        "derived_adversarial_suite": (build_locked_set_derived_adversarial_suite(manifest)),
    }
    coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(coverage)
    return coverage


def _near_duplicate_scan() -> dict[str, object]:
    scan: dict[str, object] = {
        "schema_version": 1,
        "dataset_id": DATASET_ID,
        "manifest_sha256": MANIFEST_SHA256,
        "exclusion_snapshot_sha256": EXCLUSION_SNAPSHOT_SHA256,
        "detector_fingerprint": _sha256(30_001),
        "locked_image_count": 100,
        "excluded_image_count": 7,
        "completed": True,
        "candidates": [
            {
                "candidate_id": "near-duplicate-001",
                "locked_image_sha256": _sha256(1),
                "excluded_image_sha256": _sha256(30_002),
                "detector": "perceptual-candidate-v1",
                "similarity": "0.9700",
            }
        ],
    }
    scan["scan_fingerprint"] = _canonical_sha256(scan)
    return scan


def _near_duplicate_decisions() -> list[dict[str, object]]:
    scan_fingerprint = _near_duplicate_scan()["scan_fingerprint"]
    return [
        {
            "candidate_id": "near-duplicate-001",
            "scan_fingerprint": scan_fingerprint,
            "verdict": "distinct",
            "reviewer_id": "independent-reviewer-02",
            "decided_at": "2026-07-26T00:05:00Z",
            "reason": "Different source ticket confirmed by direct image review.",
            "decision_evidence_sha256": _sha256(30_003),
        }
    ]


def _eligibility_history() -> dict[str, object]:
    event: dict[str, object] = {
        "event_id": "locked-set-sealed-001",
        "event_type": "sealed",
        "recorded_at": "2026-07-26T00:10:00Z",
        "actor_id": "independent-reviewer-01",
    }
    event["event_sha256"] = _canonical_sha256(event)
    history: dict[str, object] = {
        "schema_version": 1,
        "dataset_id": DATASET_ID,
        "manifest_sha256": MANIFEST_SHA256,
        "status": "eligible",
        "events": [event],
    }
    history["history_sha256"] = _canonical_sha256(history)
    return history


def _candidate_review_source_authority() -> dict[str, object]:
    return {
        "schema_version": 1,
        "seal_sha256": _sha256(40_001),
        "package_sha256": _sha256(40_002),
        "record_set_sha256": _sha256(40_003),
        "review_history_authority_sha256": _sha256(40_004),
        "source_authority_sha256": _sha256(40_005),
    }


def _evaluate(
    module: ModuleType,
    *,
    preflight_attestation: dict[str, object] | None = None,
    truth_manifest: dict[str, object] | None = None,
    image_results: list[dict[str, object]] | None = None,
    pair_results: list[dict[str, object]] | None = None,
    quality_coverage: dict[str, object] | None = None,
    near_duplicate_scan: dict[str, object] | None = None,
    near_duplicate_decisions: list[dict[str, object]] | None = None,
    eligibility_history: dict[str, object] | None = None,
    candidate_review_source_authority: object | None = None,
    expected_runtime_kinds: tuple[str, ...] = ("cpu", "gpu"),
) -> dict[str, object]:
    manifest = truth_manifest or _truth_manifest()
    report = module.evaluate_locked_set_release(
        preflight_attestation=(
            preflight_attestation if preflight_attestation is not None else _preflight_attestation()
        ),
        truth_manifest=manifest,
        image_results=(image_results if image_results is not None else _image_results(manifest)),
        pair_results=pair_results if pair_results is not None else _pair_results(manifest),
        quality_coverage=(
            quality_coverage if quality_coverage is not None else _quality_coverage(manifest)
        ),
        near_duplicate_scan=(
            near_duplicate_scan if near_duplicate_scan is not None else _near_duplicate_scan()
        ),
        near_duplicate_decisions=(
            near_duplicate_decisions
            if near_duplicate_decisions is not None
            else _near_duplicate_decisions()
        ),
        eligibility_history=(
            eligibility_history if eligibility_history is not None else _eligibility_history()
        ),
        candidate_review_source_authority=(
            candidate_review_source_authority
            if candidate_review_source_authority is not None
            else _candidate_review_source_authority()
        ),
        expected_runtime_kinds=expected_runtime_kinds,
    )
    assert isinstance(report, dict)
    return report


def test_formal_report_binds_candidate_review_source_authority(
    acceptance_contract: ModuleType,
) -> None:
    binding = _candidate_review_source_authority()

    report = _evaluate(
        acceptance_contract,
        candidate_review_source_authority=binding,
    )

    assert report["candidate_review_source_authority"] == binding
    assert report["candidate_review_source_authority_sha256"] == (
        _canonical_sha256(binding)
    )

    for invalid in (
        {},
        {**binding, "seal_sha256": "A" * 64},
        {**binding, "schema_version": True},
        {**binding, "unexpected": "field"},
    ):
        with pytest.raises(
            acceptance_contract.LockedSetAcceptanceError,
            match="candidate-review source authority",
        ):
            _evaluate(
                acceptance_contract,
                candidate_review_source_authority=invalid,
            )


@pytest.mark.parametrize(
    "contract_name",
    ("truth_manifest", "preflight_attestation"),
)
def test_primary_contract_schema_version_rejects_boolean_true(
    acceptance_contract: ModuleType,
    contract_name: str,
) -> None:
    kwargs: dict[str, object] = {}
    if contract_name == "truth_manifest":
        manifest = _truth_manifest()
        manifest["schema_version"] = True
        kwargs["truth_manifest"] = manifest
    else:
        attestation = _preflight_attestation()
        attestation["schema_version"] = True
        kwargs["preflight_attestation"] = attestation

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="schema version",
    ):
        _evaluate(acceptance_contract, **kwargs)


@pytest.mark.parametrize(
    "contract_name",
    (
        "eligibility_history",
        "quality_coverage",
        "near_duplicate_scan",
        "near_duplicate_decision",
        "derived_adversarial_suite",
    ),
)
def test_nested_contract_schema_version_rejects_boolean_true(
    acceptance_contract: ModuleType,
    contract_name: str,
) -> None:
    kwargs: dict[str, object] = {}
    if contract_name == "eligibility_history":
        history = _eligibility_history()
        history["schema_version"] = True
        history["history_sha256"] = _canonical_sha256(
            {key: value for key, value in history.items() if key != "history_sha256"}
        )
        kwargs["eligibility_history"] = history
    elif contract_name == "quality_coverage":
        coverage = _quality_coverage()
        coverage["schema_version"] = True
        coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(coverage)
        kwargs["quality_coverage"] = coverage
    elif contract_name == "near_duplicate_scan":
        scan = _near_duplicate_scan()
        scan["schema_version"] = True
        scan["scan_fingerprint"] = _canonical_sha256(
            {key: value for key, value in scan.items() if key != "scan_fingerprint"}
        )
        kwargs["near_duplicate_scan"] = scan
    elif contract_name == "near_duplicate_decision":
        decisions = _near_duplicate_decisions()
        decisions[0]["schema_version"] = True
        kwargs["near_duplicate_decisions"] = decisions
    else:
        coverage = _quality_coverage()
        suite = coverage["derived_adversarial_suite"]
        assert isinstance(suite, dict)
        suite["schema_version"] = True
        coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(coverage)
        kwargs["quality_coverage"] = coverage

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="schema",
    ):
        _evaluate(acceptance_contract, **kwargs)


def test_release_report_reconciles_100_images_and_50_pairs(
    acceptance_contract: ModuleType,
) -> None:
    report = _evaluate(acceptance_contract)

    assert report["dataset_id"] == DATASET_ID
    assert report["manifest_sha256"] == MANIFEST_SHA256
    assert report["preflight_attestation_sha256"] == ATTESTATION_SHA256
    assert report["reconciliation"] == {
        "expected_image_count": 100,
        "result_image_count": 100,
        "expected_pair_count": 50,
        "result_pair_count": 50,
        "missing_image_results": [],
        "unexpected_image_results": [],
        "duplicate_image_results": [],
        "missing_pair_results": [],
        "unexpected_pair_results": [],
        "duplicate_pair_results": [],
    }
    image_results = _image_results()
    assert report["runtime_comparison_evidence_sha256"] == _canonical_sha256(
        {
            "items": [
                {
                    "comparison_sha256": result["runtime_comparison"]["comparison_sha256"],
                    "image_sha256": result["image_sha256"],
                }
                for result in sorted(
                    image_results,
                    key=lambda item: item["image_sha256"],
                )
            ],
            "schema_version": 1,
        }
    )
    runtime_gate = report["runtime_execution_gate"]
    assert runtime_gate == {
        "schema_version": 1,
        "expected_runtime_kinds": ["cpu", "gpu"],
        "image_count": 100,
        "status_counts": {
            "dual_consistent": 100,
            "dual_different": 0,
            "gpu_failed_cpu_fallback": 0,
            "not_measured": 0,
            "single_cpu": 0,
        },
        "failed_image_count": 0,
        "runtime_summaries": {
            "cpu": {
                "success_count": 100,
                "failure_count": 0,
                "wall_elapsed_ms": {
                    "sample_count": 100,
                    "p50": "8.500",
                    "p95": "8.500",
                },
                "worker_elapsed_ms": {
                    "sample_count": 100,
                    "p50": "8.000",
                    "p95": "8.000",
                },
            },
            "gpu": {
                "success_count": 100,
                "failure_count": 0,
                "wall_elapsed_ms": {
                    "sample_count": 100,
                    "p50": "2.500",
                    "p95": "2.500",
                },
                "worker_elapsed_ms": {
                    "sample_count": 100,
                    "p50": "2.000",
                    "p95": "2.000",
                },
            },
        },
        "evidence_sha256": _canonical_sha256(
            {
                "expected_runtime_kinds": ["cpu", "gpu"],
                "items": [
                    {
                        "comparison_sha256": result["runtime_comparison"][
                            "comparison_sha256"
                        ],
                        "image_sha256": result["image_sha256"],
                    }
                    for result in sorted(
                        image_results,
                        key=lambda item: item["image_sha256"],
                    )
                ],
                "schema_version": 1,
            }
        ),
        "passed": True,
    }
    assert report["gate_passed"] is True


def test_all_gpu_fallbacks_are_preserved_but_fail_the_dual_runtime_gate(
    acceptance_contract: ModuleType,
) -> None:
    report = _evaluate(
        acceptance_contract,
        image_results=_image_results(runtime_status="gpu_failed_cpu_fallback"),
    )

    gate = report["runtime_execution_gate"]
    assert gate["passed"] is False
    assert gate["failed_image_count"] == 100
    assert gate["status_counts"]["gpu_failed_cpu_fallback"] == 100
    assert gate["runtime_summaries"]["cpu"]["success_count"] == 100
    assert gate["runtime_summaries"]["gpu"]["success_count"] == 0
    assert gate["runtime_summaries"]["gpu"]["failure_count"] == 100
    assert report["gate_passed"] is False


def test_one_gpu_fallback_fails_an_otherwise_dual_consistent_runtime_gate(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results()
    first = image_results[0]
    first["runtime_comparison"] = _gpu_failed_cpu_fallback_comparison(
        image_sha256=str(first["image_sha256"]),
        role=str(first["predicted_role"]),
        high_confidence=bool(first["high_confidence"]),
    )

    report = _evaluate(acceptance_contract, image_results=image_results)

    gate = report["runtime_execution_gate"]
    assert gate["passed"] is False
    assert gate["failed_image_count"] == 1
    assert gate["status_counts"]["dual_consistent"] == 99
    assert gate["status_counts"]["gpu_failed_cpu_fallback"] == 1
    assert report["gate_passed"] is False


def test_dual_output_difference_is_diagnostic_evidence_and_fails_the_gate(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results()
    first = image_results[0]
    first["runtime_comparison"] = _dual_different_runtime_comparison(
        image_sha256=str(first["image_sha256"]),
        role=str(first["predicted_role"]),
        high_confidence=bool(first["high_confidence"]),
    )

    report = _evaluate(acceptance_contract, image_results=image_results)

    gate = report["runtime_execution_gate"]
    assert gate["passed"] is False
    assert gate["failed_image_count"] == 1
    assert gate["status_counts"]["dual_different"] == 1
    assert gate["runtime_summaries"]["cpu"]["success_count"] == 100
    assert gate["runtime_summaries"]["gpu"]["success_count"] == 100
    assert report["gate_passed"] is False


def test_formal_evaluation_rejects_cpu_only_and_single_cpu_runtime_evidence(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results(runtime_status="single_cpu")

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="CPU plus GPU",
    ):
        _evaluate(
            acceptance_contract,
            image_results=image_results,
            expected_runtime_kinds=("cpu",),
        )

    dual_expected = _evaluate(
        acceptance_contract,
        image_results=image_results,
        expected_runtime_kinds=("cpu", "gpu"),
    )

    dual_gate = dual_expected["runtime_execution_gate"]
    assert dual_gate["expected_runtime_kinds"] == ["cpu", "gpu"]
    assert dual_gate["image_count"] == 100
    assert dual_gate["status_counts"]["dual_consistent"] == 0
    assert dual_gate["status_counts"]["single_cpu"] == 100
    assert dual_gate["status_counts"]["dual_different"] == 0
    assert dual_gate["status_counts"]["gpu_failed_cpu_fallback"] == 0
    assert dual_gate["failed_image_count"] == 100
    assert dual_gate["passed"] is False
    assert dual_expected["gate_passed"] is False


def test_formal_evaluation_rejects_unmeasured_and_gpu_only_runtime_contracts(
    acceptance_contract: ModuleType,
) -> None:
    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="not_measured",
    ):
        _evaluate(
            acceptance_contract,
            image_results=_image_results(runtime_status="not_measured"),
        )

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="expected runtime",
    ):
        _evaluate(
            acceptance_contract,
            expected_runtime_kinds=("gpu",),
        )


@pytest.mark.parametrize(
    "mutation",
    ["missing", "wrong_hash", "forged_not_measured_source"],
)
def test_runtime_comparison_requires_explicit_integrity_checked_contract(
    acceptance_contract: ModuleType,
    mutation: str,
) -> None:
    image_results = _image_results()
    first = image_results[0]
    comparison = first["runtime_comparison"]
    assert isinstance(comparison, dict)
    if mutation == "missing":
        first.pop("runtime_comparison")
    elif mutation == "wrong_hash":
        comparison["comparison_sha256"] = "f" * 64
    else:
        comparison["source"] = "fake-runtime"
        comparison["comparison_sha256"] = _canonical_sha256(
            {field: value for field, value in comparison.items() if field != "comparison_sha256"}
        )

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="runtime comparison",
    ):
        _evaluate(acceptance_contract, image_results=image_results)


def test_runtime_comparison_accepts_measured_dual_evidence_and_rejects_disguise(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results()
    first = image_results[0]
    first["runtime_comparison"] = _dual_runtime_comparison(
        image_sha256=str(first["image_sha256"]),
        role=str(first["predicted_role"]),
        high_confidence=bool(first["high_confidence"]),
    )

    report = _evaluate(acceptance_contract, image_results=image_results)

    assert isinstance(report["runtime_comparison_evidence_sha256"], str)
    forged = copy.deepcopy(image_results)
    forged_comparison = forged[0]["runtime_comparison"]
    assert isinstance(forged_comparison, dict)
    forged_outputs = forged_comparison["outputs"]
    assert isinstance(forged_outputs, list)
    cpu_output = forged_outputs[0]
    assert isinstance(cpu_output, dict)
    cpu_critical = cpu_output["critical_output"]
    assert isinstance(cpu_critical, dict)
    cpu_critical["ordinary_net_amount"] = "30.01"
    forged_comparison["comparison_sha256"] = _canonical_sha256(
        {field: value for field, value in forged_comparison.items() if field != "comparison_sha256"}
    )
    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="status is inconsistent",
    ):
        _evaluate(acceptance_contract, image_results=forged)


def test_release_derives_order_independent_adversarial_role_routing_suite(
    acceptance_contract: ModuleType,
) -> None:
    manifest = _truth_manifest()
    report = _evaluate(acceptance_contract, truth_manifest=manifest)

    suite = report["derived_adversarial_suite"]
    assert suite["generator_version"] == "dahe.loop7.derived-role-adversarial.v1"
    assert suite["scenarios"] == [
        {
            "scenario_id": "swapped_slots",
            "source_sample_ids": ["locked-001"],
            "loading_slot_image_sha256": _sha256(2),
            "unloading_slot_image_sha256": _sha256(1),
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "suspected_swapped",
        },
        {
            "scenario_id": "both_loading",
            "source_sample_ids": ["locked-001", "locked-002"],
            "loading_slot_image_sha256": _sha256(1),
            "unloading_slot_image_sha256": _sha256(3),
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "both_loading",
        },
        {
            "scenario_id": "both_unloading",
            "source_sample_ids": ["locked-001", "locked-002"],
            "loading_slot_image_sha256": _sha256(2),
            "unloading_slot_image_sha256": _sha256(4),
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "both_unloading",
        },
        {
            "scenario_id": "exact_duplicate_image",
            "source_sample_ids": ["locked-001"],
            "loading_slot_image_sha256": _sha256(1),
            "unloading_slot_image_sha256": _sha256(1),
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "duplicate_image",
        },
    ]
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
    assert report["derived_adversarial_gate"] == {
        "scenario_count": 4,
        "passed_count": 4,
        "failed_scenarios": [],
        "passed": True,
    }
    assert report["observed_locked_set_gate"] == {
        "zero_error_gates_passed": True,
        "quality_coverage_passed": True,
        "near_duplicate_passed": True,
        "passed": True,
    }
    assert report["claim_scope"] == {
        "real_locked_set_image_count": 100,
        "real_locked_set_pair_count": 50,
        "derived_adversarial_scenario_count": 4,
        "derived_adversarial_in_reconciliation": False,
        "derived_adversarial_in_confusion_matrix": False,
        "derived_adversarial_in_accuracy_metrics": False,
        "derived_adversarial_in_latency_metrics": False,
        "derived_adversarial_role_routing_only": True,
    }
    assert report["formal_accuracy_claim_scope"] == "none_uncommitted"
    assert report["eligible_accuracy_scope"] == "observed_real_locked_set_only"
    assert report["derived_scenario_accuracy_claim"] is False
    assert report["derived_prevalence_claim"] is False
    suite_without_hash = dict(suite)
    suite_hash = suite_without_hash.pop("suite_sha256")
    assert suite_hash == _canonical_sha256(suite_without_hash)
    results = report["derived_adversarial_results"]
    results_without_hash = dict(results)
    results_hash = results_without_hash.pop("results_sha256")
    assert results_hash == _canonical_sha256(results_without_hash)
    assert report["reconciliation"]["result_image_count"] == 100
    assert report["reconciliation"]["result_pair_count"] == 50
    assert (
        sum(
            sum(predictions.values())
            for predictions in report["metrics"]["confusion_matrix"].values()
        )
        == 100
    )

    reordered = copy.deepcopy(manifest)
    pairs = reordered["pairs"]
    assert isinstance(pairs, list)
    pairs.reverse()
    for pair in pairs:
        assert isinstance(pair, dict)
        images = pair["images"]
        assert isinstance(images, list)
        images.reverse()
    reordered_report = _evaluate(
        acceptance_contract,
        truth_manifest=reordered,
        image_results=list(reversed(_image_results(reordered))),
        pair_results=list(reversed(_pair_results(reordered))),
    )
    assert (
        reordered_report["derived_adversarial_fingerprint"]
        == report["derived_adversarial_fingerprint"]
    )
    assert reordered_report["derived_adversarial_suite"] == suite


def test_derived_adversarial_gate_fails_closed_on_wrong_source_prediction(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results()
    _replace_image_prediction(
        image_results[0],
        role="unknown",
        high_confidence=False,
    )
    pair_results = _pair_results()
    pair_results[0]["automatic_outcome"] = "awaiting_review"
    pair_results[0]["role_issue"] = "role_unknown"

    report = _evaluate(
        acceptance_contract,
        image_results=image_results,
        pair_results=pair_results,
    )

    assert report["zero_error_gates"]["wrong_auto_pass_zero"]["passed"] is True
    assert report["zero_error_gates"]["high_confidence_role_error_zero"]["passed"] is True
    assert report["observed_locked_set_gate"]["passed"] is True
    assert report["derived_adversarial_gate"]["passed"] is False
    assert set(report["derived_adversarial_gate"]["failed_scenarios"]) == {
        "swapped_slots",
        "both_loading",
    }
    assert report["gate_passed"] is False


def test_derived_adversarial_suite_requires_two_confirmed_images_per_known_role(
    acceptance_contract: ModuleType,
) -> None:
    manifest = _truth_manifest()
    pairs = manifest["pairs"]
    assert isinstance(pairs, list)
    for pair in pairs:
        assert isinstance(pair, dict)
        images = pair["images"]
        assert isinstance(images, list)
        for image in images:
            assert isinstance(image, dict)
            image["truth_role"] = "unknown"

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="derived adversarial suite",
    ):
        _evaluate(
            acceptance_contract,
            truth_manifest=manifest,
            image_results=_image_results(manifest),
            pair_results=_pair_results(manifest),
        )


def test_release_report_records_confusion_unknown_and_nearest_rank_latency(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results()
    _replace_image_prediction(
        image_results[-1],
        role="unknown",
        high_confidence=False,
    )
    pair_results = _pair_results()
    pair_results[-1]["automatic_outcome"] = "awaiting_review"
    pair_results[-1]["role_issue"] = "role_unknown"

    report = _evaluate(
        acceptance_contract,
        image_results=image_results,
        pair_results=pair_results,
    )
    metrics = report["metrics"]
    assert isinstance(metrics, dict)
    assert metrics["confusion_matrix"] == {
        "loading": {"loading": 49, "unloading": 0, "unknown": 0},
        "unloading": {"loading": 0, "unloading": 48, "unknown": 1},
        "unknown": {"loading": 0, "unloading": 0, "unknown": 2},
    }
    assert metrics["unknown_count"] == 3
    assert metrics["unknown_rate"] == "0.03"
    assert metrics["real_image_sample_count"] == 100
    assert metrics["real_pair_sample_count"] == 50
    assert metrics["truth_role_distribution"] == {
        "loading": 49,
        "unloading": 49,
        "unknown": 2,
    }
    assert metrics["truth_pair_issue_distribution"] == {
        "both_loading": 0,
        "both_unloading": 0,
        "normal_pair": 49,
        "suspected_swapped": 0,
        "unknown_or_non_ticket": 1,
    }
    assert metrics["unknown_rate_wilson_95"] == {
        "confidence_level": "0.95",
        "lower": "0.010255",
        "method": "wilson_score",
        "sample_count": 100,
        "success_count": 3,
        "upper": "0.084519",
    }
    assert metrics["normal_pair_false_positive"] == {
        "status": "measured",
        "sample_count": 49,
        "false_positive_count": 1,
        "rate": "0.02040816326530612244897959184",
        "wilson_95": {
            "confidence_level": "0.95",
            "lower": "0.003612",
            "method": "wilson_score",
            "sample_count": 49,
            "success_count": 1,
            "upper": "0.106935",
        },
    }
    assert metrics["real_swapped_recall"] == {
        "status": "not_measured",
        "sample_count": 0,
        "reason": ("The formal locked set contains no naturally occurring suspected-swapped pair."),
    }
    assert metrics["layout_distribution"] == {
        "status": "not_measured",
        "reason": ("The formal truth manifest has no exhaustive per-image layout labels."),
    }
    assert metrics["quality_distribution"] == {
        "status": "not_measured",
        "reason": ("The formal truth manifest has no exhaustive per-image quality labels."),
    }
    assert metrics["p50_incremental_elapsed_ms"] == "50.000"
    assert metrics["p95_incremental_elapsed_ms"] == "95.000"
    assert metrics["wrong_auto_pass_count"] == 0
    assert metrics["high_confidence_role_error_count"] == 0
    assert report["gate_passed"] is True


def test_normal_pair_false_positive_is_not_measured_without_normal_pairs(
    acceptance_contract: ModuleType,
) -> None:
    loading_hash = _sha256(1)
    unloading_hash = _sha256(2)
    metrics = acceptance_contract._metrics(
        image_truth={
            loading_hash: ("sample-001", "loading"),
            unloading_hash: ("sample-001", "loading"),
        },
        image_results={
            loading_hash: {
                "predicted_role": "loading",
                "high_confidence": True,
                "incremental_elapsed_ms": "1.000",
            },
            unloading_hash: {
                "predicted_role": "loading",
                "high_confidence": True,
                "incremental_elapsed_ms": "2.000",
            },
        },
        pair_slots={
            "sample-001": (loading_hash, unloading_hash),
        },
        pair_results={
            "sample-001": {
                "automatic_outcome": "awaiting_review",
                "role_issue": "both_loading",
            },
        },
    )

    assert metrics["normal_pair_false_positive"] == {
        "status": "not_measured",
        "sample_count": 0,
        "reason": ("The formal locked set contains no naturally occurring normal pair."),
    }


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unexpected"])
def test_image_result_reconciliation_is_fail_closed(
    acceptance_contract: ModuleType,
    mutation: str,
) -> None:
    image_results = _image_results()
    if mutation == "missing":
        image_results.pop()
    elif mutation == "duplicate":
        image_results[-1] = copy.deepcopy(image_results[0])
    else:
        unexpected = copy.deepcopy(image_results[-1])
        unexpected["result_id"] = "image-result-unexpected"
        unexpected["image_sha256"] = _sha256(999)
        image_results.append(unexpected)

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="image result reconciliation",
    ):
        _evaluate(acceptance_contract, image_results=image_results)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong_membership"])
def test_pair_result_reconciliation_is_fail_closed(
    acceptance_contract: ModuleType,
    mutation: str,
) -> None:
    pair_results = _pair_results()
    if mutation == "missing":
        pair_results.pop()
    elif mutation == "duplicate":
        pair_results[-1] = copy.deepcopy(pair_results[0])
    else:
        pair_results[0]["loading_slot_image_sha256"] = _sha256(999)

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="pair result reconciliation",
    ):
        _evaluate(acceptance_contract, pair_results=pair_results)


def test_swapped_pair_must_not_be_automatically_passed(
    acceptance_contract: ModuleType,
) -> None:
    truth_manifest = _truth_manifest()
    pairs = truth_manifest["pairs"]
    assert isinstance(pairs, list)
    first_pair = pairs[0]
    assert isinstance(first_pair, dict)
    images = first_pair["images"]
    assert isinstance(images, list)
    assert isinstance(images[0], dict)
    assert isinstance(images[1], dict)
    images[0]["truth_role"] = "unloading"
    images[1]["truth_role"] = "loading"
    pair_results = _pair_results(truth_manifest)
    pair_results[0]["automatic_outcome"] = "normal_ready"
    pair_results[0]["role_issue"] = None

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="production role assessment",
    ):
        _evaluate(
            acceptance_contract,
            truth_manifest=truth_manifest,
            pair_results=pair_results,
        )


def test_natural_swapped_recall_requires_the_exact_pair_role_issue(
    acceptance_contract: ModuleType,
) -> None:
    truth_manifest = _truth_manifest()
    pairs = truth_manifest["pairs"]
    assert isinstance(pairs, list)
    first_pair = pairs[0]
    assert isinstance(first_pair, dict)
    images = first_pair["images"]
    assert isinstance(images, list)
    assert isinstance(images[0], dict)
    assert isinstance(images[1], dict)
    images[0]["truth_role"] = "unloading"
    images[1]["truth_role"] = "loading"

    detected_results = _pair_results(truth_manifest)
    detected = _evaluate(
        acceptance_contract,
        truth_manifest=truth_manifest,
        pair_results=detected_results,
    )
    assert detected["metrics"]["real_swapped_recall"] == {
        "status": "measured",
        "sample_count": 1,
        "detected_count": 1,
        "rate": "1",
        "wilson_95": {
            "confidence_level": "0.95",
            "lower": "0.206549",
            "method": "wilson_score",
            "sample_count": 1,
            "success_count": 1,
            "upper": "1",
        },
    }

    uncertain_image_results = _image_results(truth_manifest)
    _replace_image_prediction(
        uncertain_image_results[0],
        role="unknown",
        high_confidence=False,
    )
    uncertain_pair_results = _pair_results(truth_manifest)
    uncertain_pair_results[0]["role_issue"] = "role_unknown"
    missed = _evaluate(
        acceptance_contract,
        truth_manifest=truth_manifest,
        image_results=uncertain_image_results,
        pair_results=uncertain_pair_results,
    )
    assert missed["metrics"]["real_swapped_recall"] == {
        "status": "measured",
        "sample_count": 1,
        "detected_count": 0,
        "rate": "0",
        "wilson_95": {
            "confidence_level": "0.95",
            "lower": "0",
            "method": "wilson_score",
            "sample_count": 1,
            "success_count": 0,
            "upper": "0.793451",
        },
    }


@pytest.mark.parametrize(
    ("role_issue", "automatic_outcome"),
    [
        ("missing", "awaiting_review"),
        ("", "awaiting_review"),
        (False, "awaiting_review"),
        ("role_unknown", "normal_ready"),
        (None, "awaiting_review"),
    ],
)
def test_pair_role_issue_contract_is_fail_closed(
    acceptance_contract: ModuleType,
    role_issue: object,
    automatic_outcome: str,
) -> None:
    pair_results = _pair_results()
    pair_results[0]["automatic_outcome"] = automatic_outcome
    if role_issue == "missing":
        pair_results[0].pop("role_issue")
    else:
        pair_results[0]["role_issue"] = role_issue

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="pair result",
    ):
        _evaluate(acceptance_contract, pair_results=pair_results)


def test_pair_result_rejects_an_unknown_nonempty_role_issue(
    acceptance_contract: ModuleType,
) -> None:
    pair_results = _pair_results()
    pair_results[0]["automatic_outcome"] = "awaiting_review"
    pair_results[0]["role_issue"] = "totally_unknown_issue"

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="production role assessment",
    ):
        _evaluate(acceptance_contract, pair_results=pair_results)


def test_pair_result_rejects_the_wrong_legal_issue_for_swapped_predictions(
    acceptance_contract: ModuleType,
) -> None:
    truth_manifest = _truth_manifest()
    pairs = truth_manifest["pairs"]
    assert isinstance(pairs, list)
    first_pair = pairs[0]
    assert isinstance(first_pair, dict)
    images = first_pair["images"]
    assert isinstance(images, list)
    assert isinstance(images[0], dict)
    assert isinstance(images[1], dict)
    images[0]["truth_role"] = "unloading"
    images[1]["truth_role"] = "loading"
    pair_results = _pair_results(truth_manifest)
    pair_results[0]["role_issue"] = "role_unknown"

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="production role assessment",
    ):
        _evaluate(
            acceptance_contract,
            truth_manifest=truth_manifest,
            pair_results=pair_results,
        )


def test_pair_result_rejects_a_fake_review_outcome_for_normal_predictions(
    acceptance_contract: ModuleType,
) -> None:
    pair_results = _pair_results()
    pair_results[-1]["automatic_outcome"] = "awaiting_review"
    pair_results[-1]["role_issue"] = "role_unknown"

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="production role assessment",
    ):
        _evaluate(acceptance_contract, pair_results=pair_results)


def test_high_confidence_wrong_role_fails_its_zero_error_gate(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results()
    _replace_image_prediction(
        image_results[0],
        role="unloading",
        high_confidence=True,
    )
    image_results[0]["high_confidence"] = True
    pair_results = _pair_results()
    pair_results[0]["automatic_outcome"] = "awaiting_review"
    pair_results[0]["role_issue"] = "both_unloading"

    report = _evaluate(
        acceptance_contract,
        image_results=image_results,
        pair_results=pair_results,
    )
    metrics = report["metrics"]
    assert isinstance(metrics, dict)
    assert metrics["wrong_auto_pass_count"] == 0
    assert metrics["high_confidence_role_error_count"] == 1
    gates = report["zero_error_gates"]
    assert isinstance(gates, dict)
    assert gates["high_confidence_role_error_zero"] == {
        "error_count": 1,
        "passed": False,
    }
    assert report["gate_passed"] is False


def test_machine_cannot_confirm_a_problem_instead_of_requesting_review(
    acceptance_contract: ModuleType,
) -> None:
    image_results = _image_results()
    _replace_image_prediction(
        image_results[0],
        role="unknown",
        high_confidence=False,
    )
    pair_results = _pair_results()
    pair_results[0]["automatic_outcome"] = "confirmed_problem"

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="automatic outcome",
    ):
        _evaluate(
            acceptance_contract,
            image_results=image_results,
            pair_results=pair_results,
        )


@pytest.mark.parametrize(
    "mutation",
    ["missing_condition", "unknown_image", "missing_reviewer", "missing_evidence"],
)
def test_quality_coverage_manifest_is_reviewable_and_fail_closed(
    acceptance_contract: ModuleType,
    mutation: str,
) -> None:
    coverage = _quality_coverage()
    entries = coverage["entries"]
    assert isinstance(entries, list)
    if mutation == "missing_condition":
        entries.pop()
    elif mutation == "unknown_image":
        entries[0]["image_sha256"] = _sha256(999)
    elif mutation == "missing_reviewer":
        entries[0]["reviewer_id"] = ""
    else:
        entries[0]["review_evidence_sha256"] = ""

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="quality coverage",
    ):
        _evaluate(acceptance_contract, quality_coverage=coverage)


@pytest.mark.parametrize(
    "mutation",
    [
        "all_image_conditions_same",
        "unknown_truth_mismatch",
        "naive_review_time",
    ],
)
def test_quality_coverage_is_bound_to_real_image_truth(
    acceptance_contract: ModuleType,
    mutation: str,
) -> None:
    coverage = _quality_coverage()
    entries = coverage["entries"]
    assert isinstance(entries, list)
    if mutation == "all_image_conditions_same":
        for entry in entries:
            entry["image_sha256"] = _sha256(7)
    elif mutation == "unknown_truth_mismatch":
        unknown_entry = next(
            entry for entry in entries if entry["condition"] == "unknown_layout"
        )
        unknown_entry["image_sha256"] = _sha256(7)
        unknown_entry["review_evidence_sha256"] = quality_review_evidence_sha256(
            dataset_id=DATASET_ID,
            manifest_sha256=MANIFEST_SHA256,
            entry=unknown_entry,
        )
    else:
        entries[0]["reviewed_at"] = "2026-07-26T00:00:00"

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="quality coverage",
    ):
        _evaluate(acceptance_contract, quality_coverage=coverage)


def test_real_quality_coverage_requires_only_the_ten_natural_image_conditions(
    acceptance_contract: ModuleType,
) -> None:
    coverage = _quality_coverage()
    entries = coverage["entries"]
    assert isinstance(entries, list)

    gate = _evaluate(
        acceptance_contract,
        quality_coverage=coverage,
    )["quality_coverage_gate"]
    suite = coverage["derived_adversarial_suite"]
    assert isinstance(suite, dict)
    assert gate == {
        "covered_conditions": sorted(REQUIRED_NATURAL_QUALITY_CONDITIONS),
        "entry_count": 10,
        "image_entry_count": 10,
        "pair_entry_count": 0,
        "derived_adversarial_suite_sha256": suite["suite_sha256"],
        "quality_coverage_sha256": coverage["quality_coverage_sha256"],
        "passed": True,
    }

    unsupported = dict(entries[0])
    unsupported["condition"] = "duplicate_upload"
    unsupported.pop("review_evidence_sha256")
    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="condition is invalid",
    ):
        quality_review_evidence_sha256(
            dataset_id=DATASET_ID,
            manifest_sha256=MANIFEST_SHA256,
            entry=unsupported,
        )


def test_quality_coverage_binds_the_code_generated_suite_and_root_hash(
    acceptance_contract: ModuleType,
) -> None:
    coverage = _quality_coverage()
    suite = coverage["derived_adversarial_suite"]
    assert isinstance(suite, dict)
    scenarios = suite["scenarios"]
    assert isinstance(scenarios, list)
    scenario = scenarios[0]
    assert isinstance(scenario, dict)
    scenario["expected_role_issue"] = "both_loading"
    suite["suite_sha256"] = _canonical_sha256(
        {key: value for key, value in suite.items() if key != "suite_sha256"}
    )
    coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(coverage)

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="derived adversarial suite",
    ):
        _evaluate(acceptance_contract, quality_coverage=coverage)

    coverage = _quality_coverage()
    coverage["quality_coverage_sha256"] = _sha256(999)
    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="quality coverage integrity",
    ):
        _evaluate(acceptance_contract, quality_coverage=coverage)


@pytest.mark.parametrize(
    "mutation",
    ["incomplete_scan", "missing_decision", "stale_decision", "extra_decision"],
)
def test_near_duplicate_candidates_require_complete_bound_manual_decisions(
    acceptance_contract: ModuleType,
    mutation: str,
) -> None:
    scan = _near_duplicate_scan()
    decisions = _near_duplicate_decisions()
    if mutation == "incomplete_scan":
        scan["locked_image_count"] = 99
    elif mutation == "missing_decision":
        decisions.clear()
    elif mutation == "stale_decision":
        decisions[0]["scan_fingerprint"] = _sha256(999)
    else:
        extra = copy.deepcopy(decisions[0])
        extra["candidate_id"] = "near-duplicate-not-in-scan"
        decisions.append(extra)

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="near-duplicate",
    ):
        _evaluate(
            acceptance_contract,
            near_duplicate_scan=scan,
            near_duplicate_decisions=decisions,
        )


def test_confirmed_cross_set_near_duplicate_blocks_release(
    acceptance_contract: ModuleType,
) -> None:
    decisions = _near_duplicate_decisions()
    decisions[0]["verdict"] = "duplicate"
    decisions[0]["reason"] = "The same ticket was re-encoded before collection."

    report = _evaluate(
        acceptance_contract,
        near_duplicate_decisions=decisions,
    )

    assert report["near_duplicate_gate"] == {
        "candidate_count": 1,
        "distinct_count": 0,
        "duplicate_count": 1,
        "undecided_count": 0,
        "passed": False,
    }
    assert report["gate_passed"] is False


def test_tampered_near_duplicate_scan_cannot_reuse_its_old_fingerprint(
    acceptance_contract: ModuleType,
) -> None:
    scan = _near_duplicate_scan()
    scan["candidates"] = []

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match=r"near-duplicate.*integrity",
    ):
        _evaluate(
            acceptance_contract,
            near_duplicate_scan=scan,
            near_duplicate_decisions=[],
        )


def test_executable_influence_permanently_invalidates_the_locked_set(
    acceptance_contract: ModuleType,
) -> None:
    history = acceptance_contract.record_locked_set_result_use(
        eligibility_history=_eligibility_history(),
        use_event={
            "event_id": "locked-result-use-001",
            "result_fingerprint": _sha256(50_001),
            "influenced_executable_system": True,
            "artifact_kind": "template",
            "artifact_sha256": _sha256(50_002),
            "actor_id": "developer-01",
            "recorded_at": "2026-07-26T00:20:00Z",
            "reason": "A locked-set difference changed an executable template.",
        },
    )

    assert history["status"] == "permanently_invalidated"
    events = history["events"]
    assert isinstance(events, list)
    assert events[-1]["event_type"] == "executable_influence"
    assert events[-1]["result_fingerprint"] == _sha256(50_001)
    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="permanently invalidated",
    ):
        _evaluate(acceptance_contract, eligibility_history=history)

    forged_reactivation = copy.deepcopy(history)
    forged_reactivation["status"] = "eligible"
    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match="permanently invalidated",
    ):
        _evaluate(
            acceptance_contract,
            eligibility_history=forged_reactivation,
        )


def test_non_executable_analysis_does_not_invalidate_the_locked_set(
    acceptance_contract: ModuleType,
) -> None:
    history = acceptance_contract.record_locked_set_result_use(
        eligibility_history=_eligibility_history(),
        use_event={
            "event_id": "locked-result-use-002",
            "result_fingerprint": _sha256(50_003),
            "influenced_executable_system": False,
            "artifact_kind": "acceptance_report",
            "artifact_sha256": _sha256(50_004),
            "actor_id": "independent-reviewer-01",
            "recorded_at": "2026-07-26T00:25:00Z",
            "reason": "The result was recorded without changing executable behavior.",
        },
    )

    assert history["status"] == "eligible"
    report = _evaluate(acceptance_contract, eligibility_history=history)
    assert report["gate_passed"] is True


def test_tampered_history_event_cannot_hide_permanent_invalidation(
    acceptance_contract: ModuleType,
) -> None:
    history = acceptance_contract.record_locked_set_result_use(
        eligibility_history=_eligibility_history(),
        use_event={
            "event_id": "locked-result-use-tamper-test",
            "result_fingerprint": _sha256(50_005),
            "influenced_executable_system": True,
            "artifact_kind": "rule",
            "artifact_sha256": _sha256(50_006),
            "actor_id": "developer-01",
            "recorded_at": "2026-07-26T00:30:00Z",
            "reason": "A locked-set difference changed an executable rule.",
        },
    )
    events = history["events"]
    assert isinstance(events, list)
    invalidation = events[-1]
    assert isinstance(invalidation, dict)
    history["status"] = "eligible"
    invalidation["event_type"] = "acceptance_report_recorded"
    invalidation["influenced_executable_system"] = False

    with pytest.raises(
        acceptance_contract.LockedSetAcceptanceError,
        match=r"eligibility.*integrity|permanently invalidated",
    ):
        _evaluate(
            acceptance_contract,
            eligibility_history=history,
        )
