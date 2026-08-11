from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from sqlalchemy import text

from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_evaluation import (
    prepare_composite_lifecycle_evaluation,
)
from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
)
from dahe.application.template_studio.candidate_development_ocr_run_authority import (
    CandidateDevelopmentOcrRunAuthorityError,
    load_authorized_candidate_development_ocr_evidence,
    record_candidate_development_ocr_run_authority,
    record_candidate_development_ocr_terminal_attempt,
)
from tests.unit.application.template_studio.test_candidate_role_evaluation import (
    ROLE_EVALUATOR_BUILD_SHA256,
    _candidate_ocr_evidence,
    _write_protected_evidence,
)
from tests.unit.application.template_studio.test_composite_lifecycle_persistence import (
    _CandidateRepository,
    _sha256,
    _synthetic_report,
)


def _assert_no_composite_persisted(runtime: SqliteRuntime) -> None:
    with runtime.engine.connect() as connection:
        count = connection.execute(
            text("SELECT COUNT(*) FROM template_evaluations")
        ).scalar_one()
    assert count == 0


def _mark_one_ocr_attempt_failed(
    evidence: dict[str, object],
) -> None:
    attempts = evidence["runtime_attempts"]
    assert isinstance(attempts, list)
    first = attempts[0]
    assert isinstance(first, dict)
    attempts[0] = {
        "diagnostic_code": "DEVELOPMENT-OCR-RUNTIME-FAILURE",
        "error_kind": "runtime_failure",
        "image_sha256": first["image_sha256"],
        "pipeline_fingerprint": first["pipeline_fingerprint"],
        "profile_id": first["profile_id"],
        "runtime_fingerprint": first["runtime_fingerprint"],
        "runtime_kind": first["runtime_kind"],
        "status": "failed",
        "wall_elapsed_ms": first["wall_elapsed_ms"],
    }
    evidence["status"] = "failed"
    evidence["technical_failure_count"] = 1
    evidence.pop("evidence_sha256", None)
    evidence["evidence_sha256"] = hashlib.sha256(
        json.dumps(
            evidence,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_self_hashed_protected_file_without_db_authority_cannot_prepare_composite(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="composite-missing-ocr-run-authority",
    )
    try:
        run_repository = (
            SqliteCandidateDevelopmentOcrRunRepository(
                runtime=runtime
            )
        )
        candidate_repository = _CandidateRepository(
            _synthetic_report()
        )

        with pytest.raises(
            CandidateDevelopmentOcrRunAuthorityError,
            match="authority does not exist",
        ):
            prepare_composite_lifecycle_evaluation(
                candidate_repository,  # type: ignore[arg-type]
                candidate_ocr_run_repository=run_repository,
                manifest_path=(
                    approved_authorizing_development_dataset_path()
                ),
                candidate_ocr_evidence_path=evidence_path,
                candidate_ocr_data_root=data_root,
                candidate_version_ids=tuple(
                    candidate_repository._versions
                ),
                role_evaluator_build_sha256=(
                    ROLE_EVALUATOR_BUILD_SHA256
                ),
                runtime_set_sha256=_sha256("runtime-set"),
            )

        _assert_no_composite_persisted(runtime)
    finally:
        runtime.close()


def test_composite_rejects_same_logical_evidence_when_file_bytes_changed(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="composite-ocr-run-file-mismatch",
    )
    try:
        run_repository = (
            SqliteCandidateDevelopmentOcrRunRepository(
                runtime=runtime
            )
        )
        record_candidate_development_ocr_run_authority(
            run_repository,
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
        candidate_repository = _CandidateRepository(
            _synthetic_report()
        )

        with pytest.raises(
            CandidateDevelopmentOcrRunAuthorityError,
            match="do not reconcile",
        ):
            prepare_composite_lifecycle_evaluation(
                candidate_repository,  # type: ignore[arg-type]
                candidate_ocr_run_repository=run_repository,
                manifest_path=(
                    approved_authorizing_development_dataset_path()
                ),
                candidate_ocr_evidence_path=evidence_path,
                candidate_ocr_data_root=data_root,
                candidate_version_ids=tuple(
                    candidate_repository._versions
                ),
                role_evaluator_build_sha256=(
                    ROLE_EVALUATOR_BUILD_SHA256
                ),
                runtime_set_sha256=_sha256("runtime-set"),
            )

        _assert_no_composite_persisted(runtime)
    finally:
        runtime.close()


def test_failed_protected_ocr_output_is_recorded_as_terminal_failure(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    _mark_one_ocr_attempt_failed(evidence)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="failed-protected-ocr-terminal-attempt",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        attempt, created = (
            record_candidate_development_ocr_terminal_attempt(
                repository,
                data_root=data_root,
                evidence_path=evidence_path,
            )
        )

        assert created is True
        assert attempt.terminal_status == "technical_failed"
        assert attempt.completion_status == "failed"
        with pytest.raises(CandidateDevelopmentOcrRunAuthorityError):
            record_candidate_development_ocr_run_authority(
                repository,
                data_root=data_root,
                evidence_path=evidence_path,
            )
    finally:
        runtime.close()


def test_authorized_loader_rejects_old_success_after_newer_same_scope_failure(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    data_root, success_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="authorized-loader-latest-terminal-failure",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        record_candidate_development_ocr_run_authority(
            repository,
            data_root=data_root,
            evidence_path=success_path,
        )
        failed = dict(evidence)
        failed["generated_at"] = "2020-01-01T00:00:00+00:00"
        _mark_one_ocr_attempt_failed(failed)
        _, failure_path = _write_protected_evidence(
            tmp_path,
            failed,
        )
        record_candidate_development_ocr_terminal_attempt(
            repository,
            data_root=data_root,
            evidence_path=failure_path,
        )

        with pytest.raises(
            CandidateDevelopmentOcrRunAuthorityError,
            match="latest terminal attempt",
        ):
            load_authorized_candidate_development_ocr_evidence(
                repository,
                data_root=data_root,
                evidence_path=success_path,
                expected_evidence_sha256=success_path.stem,
            )
    finally:
        runtime.close()


def test_forged_failed_ocr_scope_cannot_append_a_terminal_attempt(
    tmp_path: Path,
    project_root: Path,
) -> None:
    evidence, _ = _candidate_ocr_evidence(tmp_path)
    _mark_one_ocr_attempt_failed(evidence)
    source = evidence["source"]
    assert isinstance(source, dict)
    source["package_sha256"] = "d" * 64
    evidence.pop("evidence_sha256", None)
    evidence["evidence_sha256"] = hashlib.sha256(
        json.dumps(
            evidence,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="forged-failed-ocr-scope",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        with pytest.raises(
            CandidateDevelopmentOcrRunAuthorityError,
            match="source",
        ):
            record_candidate_development_ocr_terminal_attempt(
                repository,
                data_root=data_root,
                evidence_path=evidence_path,
            )
        with runtime.engine.connect() as connection:
            count = connection.execute(
                text(
                    "SELECT count(*) "
                    "FROM candidate_development_ocr_attempts"
                )
            ).scalar_one()
        assert count == 0
    finally:
        runtime.close()
