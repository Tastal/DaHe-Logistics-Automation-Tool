from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from dahe.application.template_studio.composite_lifecycle_evaluation import (
    COMPOSITE_EVALUATOR_VERSION,
    composite_lifecycle_policy_fingerprint,
)


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


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def add_composite_lifecycle_authority(
    metrics: Mapping[str, object],
    *,
    evaluation_id: str,
    dataset_id: str,
    dataset_manifest_sha256: str,
    template_set_fingerprint: str,
    matcher_fingerprint: str,
    policy_fingerprint: str,
    build_fingerprint: str,
    runtime_fingerprint: str,
    candidates: Sequence[tuple[str, str]],
    reviewer_id: str = "developer-tastal",
) -> tuple[dict[str, object], str]:
    """Build deterministic composite authority for repository contract tests."""

    candidate_rows = [
        {
            "content_sha256": content_sha256,
            "family_id_sha256": _sha256(f"family:{version_id}"),
            "lifecycle": "draft",
            "role": ("loading" if index % 2 == 0 else "unloading"),
            "version_id": version_id,
        }
        for index, (version_id, content_sha256) in enumerate(sorted(candidates))
    ]
    candidate_set_sha256 = _canonical_sha256(
        [
            {
                "content_sha256": row["content_sha256"],
                "version_id": row["version_id"],
            }
            for row in candidate_rows
        ]
    )
    role_results = [
        {
            "assessment_sha256": _sha256(f"assessment:{index}"),
            "confidence": "0.95",
            "detected_orientation_degrees": 0,
            "expected_orientation_degrees": 0,
            "high_confidence": True,
            "matched_template_version_ids": [
                row["version_id"]
                for row in candidate_rows
                if row["role"] == ("loading" if index < 50 else "unloading")
            ],
            "prediction": ("loading" if index < 50 else "unloading"),
            "subject_sha256": _sha256(f"subject:{index}"),
            "truth": "loading" if index < 50 else "unloading",
        }
        for index in range(100)
    ]
    pair_results = [
        {
            "domain_issue": None,
            "expected_status": "normal",
            "matches_truth": True,
            "pair_sha256": _sha256(f"pair:{index}"),
            "predicted_status": "normal",
        }
        for index in range(50)
    ]
    runtime_payloads = {
        runtime_kind: {
            "candidate_support": {
                "results": [
                    {
                        "candidate_version_id": row["version_id"],
                        "support_count": 1,
                        "supporting_subject_sha256s": [
                            next(
                                role_row["subject_sha256"]
                                for role_row in role_results
                                if role_row["truth"] == row["role"]
                            )
                        ],
                    }
                    for row in candidate_rows
                ],
                "support_contract": (
                    "human_role_correct_and_template_evidence_hit_and_final_role_correct"
                ),
                "supported_candidate_count": len(candidate_rows),
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
                "results": role_results,
                "unknown_rate": "0",
            },
            "runtime_kind": runtime_kind,
            "sample_count": 100,
        }
        for runtime_kind in ("cpu", "gpu")
    }
    real_payload: dict[str, object] = {
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
        "runtimes": runtime_payloads,
        "schema_version": 2,
        "source": {
            "composition_evidence_sha256": _sha256(f"composition:{evaluation_id}"),
            "manifest_sha256": _sha256(f"manifest:{evaluation_id}"),
            "ocr_capture_build_sha256": _sha256(f"capture:{evaluation_id}"),
            "ocr_evidence_sha256": _sha256(f"ocr-evidence:{evaluation_id}"),
            "ocr_pipeline_contract_sha256": _sha256(f"pipeline:{evaluation_id}"),
            "package_sha256": _sha256(f"package:{evaluation_id}"),
            "quality_coverage_sha256": _sha256(f"quality:{evaluation_id}"),
            "record_set_sha256": _sha256(f"record-set:{evaluation_id}"),
            "review_history_authority_sha256": _sha256(f"review-history:{evaluation_id}"),
            "reviewer_id_sha256": _canonical_sha256(
                reviewer_id
            ),
            "role_evaluator_build_sha256": build_fingerprint,
            "runtime_set_sha256": runtime_fingerprint,
            "source_authority_sha256": _sha256(f"source-authority:{evaluation_id}"),
        },
        "status": "completed",
        "template_contract": {
            "candidate_count": len(candidate_rows),
            "candidates": candidate_rows,
            "current_shadow_count": 0,
            "dataset_id_sha256": _sha256(f"dataset:{evaluation_id}"),
            "matcher_fingerprint": matcher_fingerprint,
            "policy_fingerprint": policy_fingerprint,
            "selected_template_count": len(candidate_rows),
            "template_set_fingerprint": template_set_fingerprint,
        },
    }
    real_evaluation_sha256 = _canonical_sha256(real_payload)
    real_payload["evaluation_sha256"] = real_evaluation_sha256
    frozen_dataset_sha256 = _sha256(f"synthetic-dataset:{evaluation_id}")
    frozen_stable_sha256 = _sha256(f"synthetic-stable:{evaluation_id}")
    bindings = {
        "candidate_set_sha256": candidate_set_sha256,
        "composite_gate_policy_sha256": (composite_lifecycle_policy_fingerprint()),
        "frozen_synthetic_dataset_sha256": frozen_dataset_sha256,
        "matcher_fingerprint": matcher_fingerprint,
        "ocr_capture_build_sha256": real_payload["source"]["ocr_capture_build_sha256"],
        "policy_fingerprint": policy_fingerprint,
        "role_evaluator_build_sha256": build_fingerprint,
        "runtime_set_sha256": runtime_fingerprint,
        "template_set_fingerprint": template_set_fingerprint,
    }
    components = {
        "frozen_synthetic": {
            "dataset_id": f"synthetic:{evaluation_id}",
            "dataset_manifest_sha256": frozen_dataset_sha256,
            "gate_passed": True,
            "stable_outcome_sha256": frozen_stable_sha256,
        },
        "real_candidate_roles": {
            "authorizing_lifecycle_evidence": False,
            "development_only": True,
            "evaluation_sha256": real_evaluation_sha256,
            "formal_accuracy_claim": False,
            "formal_release_eligible": False,
            "ocr_evidence_sha256": real_payload["source"]["ocr_evidence_sha256"],
        },
    }
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
    stable_outcome_sha256 = _canonical_sha256(
        {
            "authorization_scope": "ticket_role_evidence",
            "bindings": bindings,
            "components": components,
            "dataset_manifest_sha256": dataset_manifest_sha256,
            "gate_checks": checks,
            "schema_version": 1,
        }
    )
    parent_payload: dict[str, object] = {
        "authorization_scope": "ticket_role_evidence",
        "authorizing_lifecycle_evidence": True,
        "bindings": bindings,
        "components": components,
        "dataset_id": dataset_id,
        "dataset_manifest_sha256": dataset_manifest_sha256,
        "evaluation_id": evaluation_id,
        "evaluator_version": COMPOSITE_EVALUATOR_VERSION,
        "gate": {"checks": checks, "passed": True},
        "kind": "composite_template_lifecycle_evaluation",
        "schema_version": 1,
        "stable_outcome_sha256": stable_outcome_sha256,
    }
    parent_payload["evaluation_sha256"] = _canonical_sha256(parent_payload)
    result = dict(metrics)
    result["composite_lifecycle"] = parent_payload
    result["composite_lifecycle_components"] = {
        "frozen_synthetic": {
            "dataset_id": f"synthetic:{evaluation_id}",
            "dataset_manifest_sha256": frozen_dataset_sha256,
            "stable_outcome_sha256": frozen_stable_sha256,
        },
        "real_candidate_roles": real_payload,
    }
    result["lifecycle_authorization_schema_version"] = 2
    return result, stable_outcome_sha256
