from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.candidate_development_ocr_run_authority import (
    CandidateDevelopmentOcrRunAuthorityError,
    load_authorized_candidate_development_ocr_evidence,
    record_candidate_development_ocr_run_authority,
)
from tests.unit.application.template_studio.test_candidate_role_evaluation import (
    _candidate_ocr_evidence,
    _reseal,
    _write_protected_evidence,
)


def _runtime_and_repository(
    *,
    data_root: Path,
    project_root: Path,
    instance_id: str,
) -> tuple[
    SqliteRuntime,
    SqliteCandidateDevelopmentOcrRunRepository,
]:
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=instance_id,
    )
    return (
        runtime,
        SqliteCandidateDevelopmentOcrRunRepository(runtime=runtime),
    )


def test_successful_ocr_write_is_bound_to_exact_file_and_database_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime, repository = _runtime_and_repository(
        data_root=data_root,
        project_root=project_root,
        instance_id="candidate-run-authority-success",
    )
    try:
        recorded, created = (
            record_candidate_development_ocr_run_authority(
                repository,
                data_root=data_root,
                evidence_path=evidence_path,
            )
        )
        authorized = load_authorized_candidate_development_ocr_evidence(
            repository,
            data_root=data_root,
            evidence_path=evidence_path,
            expected_evidence_sha256=str(
                evidence["evidence_sha256"]
            ),
        )

        assert created is True
        assert authorized.authority == recorded
        assert authorized.payload == evidence
        assert authorized.record_content == evidence_path.read_bytes()
        assert recorded.evidence_blob_sha256 == hashlib.sha256(
            evidence_path.read_bytes()
        ).hexdigest()
        assert recorded.review_history_authority_sha256 == (
            evidence["source"]["review_history_authority_sha256"]  # type: ignore[index]
        )
        assert recorded.completion_status == (
            "completed_with_runtime_differences"
        )
    finally:
        runtime.close()


def test_same_logical_json_with_changed_file_bytes_does_not_match_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime, repository = _runtime_and_repository(
        data_root=data_root,
        project_root=project_root,
        instance_id="candidate-run-authority-file-bytes",
    )
    try:
        record_candidate_development_ocr_run_authority(
            repository,
            data_root=data_root,
            evidence_path=evidence_path,
        )
        evidence_path.write_text(
            json.dumps(
                evidence,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        with pytest.raises(
            CandidateDevelopmentOcrRunAuthorityError,
            match="do not reconcile",
        ):
            load_authorized_candidate_development_ocr_evidence(
                repository,
                data_root=data_root,
                evidence_path=evidence_path,
                expected_evidence_sha256=str(
                    evidence["evidence_sha256"]
                ),
            )
    finally:
        runtime.close()


def test_coordinated_reseal_without_database_authority_is_rejected(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    attempts = evidence["runtime_attempts"]
    assert isinstance(attempts, list)
    original_first_attempt = copy.deepcopy(attempts[0])
    assert isinstance(original_first_attempt, dict)
    evidence["status"] = "failed"
    evidence["technical_failure_count"] = 1
    attempts[0] = {
        "diagnostic_code": "OCR-FORGED-RECOVERY",
        "error_kind": "worker_crashed",
        "image_sha256": original_first_attempt["image_sha256"],
        "runtime_kind": original_first_attempt["runtime_kind"],
        "status": "failed",
    }

    # A coordinated rewrite can make the JSON internally successful again,
    # but it cannot create the append-only authority of the original write.
    attempts[0] = original_first_attempt
    evidence["status"] = "completed_with_runtime_differences"
    evidence["technical_failure_count"] = 0
    evidence["generated_at"] = "2026-07-26T11:00:00+08:00"
    _reseal(evidence)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime, repository = _runtime_and_repository(
        data_root=data_root,
        project_root=project_root,
        instance_id="candidate-run-authority-missing",
    )
    try:
        with pytest.raises(
            CandidateDevelopmentOcrRunAuthorityError,
            match="authority does not exist",
        ):
            load_authorized_candidate_development_ocr_evidence(
                repository,
                data_root=data_root,
                evidence_path=evidence_path,
                expected_evidence_sha256=str(
                    evidence["evidence_sha256"]
                ),
            )
    finally:
        runtime.close()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("minimal_attempt", r"attempt|contract|technical"),
        ("runtime_profile_swap", r"runtime authority"),
        ("business_output_comparison", r"comparison|output"),
        ("reviewer_mismatch", r"reviewer authority"),
    ),
)
def test_seed_authority_reuses_full_ocr_contract_and_rejects_forgery(
    tmp_path: Path,
    project_root: Path,
    mutation: str,
    message: str,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    mutated = copy.deepcopy(evidence)
    attempts = mutated["runtime_attempts"]
    comparisons = mutated["runtime_comparisons"]
    assert isinstance(attempts, list)
    assert isinstance(comparisons, list)
    first = attempts[0]
    assert isinstance(first, dict)

    if mutation == "minimal_attempt":
        mutated["runtime_attempts"] = [
            {
                "image_sha256": attempt["image_sha256"],
                "runtime_kind": attempt["runtime_kind"],
                "status": "succeeded",
            }
            for attempt in attempts
            if isinstance(attempt, dict)
        ]
    elif mutation == "runtime_profile_swap":
        counterpart = next(
            attempt
            for attempt in attempts
            if isinstance(attempt, dict)
            and attempt["runtime_kind"] != first["runtime_kind"]
        )
        first["profile_id"] = counterpart["profile_id"]
    elif mutation == "business_output_comparison":
        fields = first["fields"]
        assert isinstance(fields, dict)
        ordinary_net = fields["ordinary_net"]
        assert isinstance(ordinary_net, dict)
        ordinary_net["amount"] = "99.99"
        first["business_output_sha256"] = hashlib.sha256(
            json.dumps(
                {
                    "fields": first["fields"],
                    "role_observation": first["role_observation"],
                    "text_lines": first["role_input"]["text_lines"],  # type: ignore[index]
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        matching = next(
            comparison
            for comparison in comparisons
            if isinstance(comparison, dict)
            and comparison["image_sha256"]
            == first["image_sha256"]
        )
        matching["comparison_status"] = "same"
        matching["difference_sections"] = []
    else:
        mutated["reviewer_id"] = "other-reviewer"
    _reseal(mutated)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        mutated,
    )
    runtime, repository = _runtime_and_repository(
        data_root=data_root,
        project_root=project_root,
        instance_id=f"candidate-run-forgery-{mutation}",
    )
    try:
        with pytest.raises(
            CandidateDevelopmentOcrRunAuthorityError,
            match=message,
        ):
            record_candidate_development_ocr_run_authority(
                repository,
                data_root=data_root,
                evidence_path=evidence_path,
            )
    finally:
        runtime.close()
