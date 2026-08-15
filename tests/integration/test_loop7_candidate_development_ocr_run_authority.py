from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.candidate_development_ocr import (
    CandidateDevelopmentOcrRunAuthorityInput,
    CandidateDevelopmentOcrRunPersistenceError,
    CandidateDevelopmentOcrTerminalAttemptInput,
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime


def _authority_input() -> CandidateDevelopmentOcrRunAuthorityInput:
    return CandidateDevelopmentOcrRunAuthorityInput(
        evidence_sha256="1" * 64,
        evidence_blob_sha256="2" * 64,
        evidence_relative_path=(
            "development/protected-candidate-review-ocr/records/"
            f"sha256/{'1' * 2}/{'1' * 2}/{'1' * 64}.json"
        ),
        evidence_byte_size=4096,
        package_sha256="3" * 64,
        review_history_authority_sha256="4" * 64,
        source_authority_sha256="5" * 64,
        reviewer_id="operator-a",
        application_build_sha256="6" * 64,
        composition_evidence_sha256="7" * 64,
        runtime_set_sha256="8" * 64,
        pipeline_contract_sha256="9" * 64,
        completion_status="completed",
        completed_at="2026-07-26T12:00:00+00:00",
    )


def test_completed_candidate_ocr_run_authority_is_append_only_and_replay_safe(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="candidate-development-ocr-authority",
    )
    try:
        assert (
            runtime.current_revision()
            == "0042_daily_capture_range"
        )
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        first, created = repository.record_completed_run(
            _authority_input()
        )
        replay, replay_created = repository.record_completed_run(
            _authority_input()
        )

        assert created is True
        assert replay_created is False
        assert replay == first
        assert repository.get(first.evidence_sha256) == first
        assert first.authority_sha256
        assert first.created_at

        with (
            runtime.engine.begin() as connection,
            pytest.raises(IntegrityError, match="append-only"),
        ):
            connection.execute(
                text(
                    "UPDATE candidate_development_ocr_runs "
                    "SET reviewer_id = 'changed' "
                    "WHERE evidence_sha256 = :evidence_sha256"
                ),
                {"evidence_sha256": first.evidence_sha256},
            )
        with (
            runtime.engine.begin() as connection,
            pytest.raises(IntegrityError, match="append-only"),
        ):
            connection.execute(
                text(
                    "DELETE FROM candidate_development_ocr_runs "
                    "WHERE evidence_sha256 = :evidence_sha256"
                ),
                {"evidence_sha256": first.evidence_sha256},
            )
    finally:
        runtime.close()


def test_same_logical_evidence_cannot_be_rebound_to_other_bytes(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="candidate-development-ocr-conflict",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        repository.record_completed_run(_authority_input())

        with pytest.raises(
            CandidateDevelopmentOcrRunPersistenceError,
            match="conflicts",
        ):
            repository.record_completed_run(
                replace(
                    _authority_input(),
                    evidence_blob_sha256="a" * 64,
                )
            )
    finally:
        runtime.close()


def test_repository_read_revalidates_the_canonical_authority_payload(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="candidate-development-ocr-corruption",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        record, _ = repository.record_completed_run(
            _authority_input()
        )
        with runtime.engine.begin() as connection:
            connection.exec_driver_sql(
                "DROP TRIGGER "
                "candidate_development_ocr_runs_immutable_update"
            )
            connection.execute(
                text(
                    "UPDATE candidate_development_ocr_runs "
                    "SET authority_sha256 = :authority_sha256 "
                    "WHERE evidence_sha256 = :evidence_sha256"
                ),
                {
                    "authority_sha256": "a" * 64,
                    "evidence_sha256": record.evidence_sha256,
                },
            )

        with pytest.raises(
            CandidateDevelopmentOcrRunPersistenceError,
            match="authority",
        ):
            repository.get(record.evidence_sha256)
    finally:
        runtime.close()


def _failed_attempt_input(
    *,
    evidence_sha256: str = "a" * 64,
    runtime_set_sha256: str = "8" * 64,
    completed_at: str = "2020-07-26T12:00:00+00:00",
) -> CandidateDevelopmentOcrTerminalAttemptInput:
    source = _authority_input()
    return CandidateDevelopmentOcrTerminalAttemptInput(
        evidence_sha256=evidence_sha256,
        evidence_blob_sha256="b" * 64,
        evidence_relative_path=(
            "development/protected-candidate-review-ocr/records/"
            f"sha256/{evidence_sha256[:2]}/{evidence_sha256[2:4]}/"
            f"{evidence_sha256}.json"
        ),
        evidence_byte_size=2048,
        package_sha256=source.package_sha256,
        review_history_authority_sha256=(
            source.review_history_authority_sha256
        ),
        source_authority_sha256=source.source_authority_sha256,
        reviewer_id=source.reviewer_id,
        application_build_sha256=source.application_build_sha256,
        composition_evidence_sha256=(
            source.composition_evidence_sha256
        ),
        runtime_set_sha256=runtime_set_sha256,
        pipeline_contract_sha256=source.pipeline_contract_sha256,
        completion_status="failed",
        completed_at=completed_at,
        terminal_status="technical_failed",
    )


def test_latest_terminal_attempt_uses_db_sequence_and_blocks_older_success(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="candidate-development-ocr-latest-failure",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        success, _ = repository.record_completed_run(
            replace(
                _authority_input(),
                completed_at="2030-07-26T12:00:00+00:00",
            )
        )
        failure, created = repository.record_failed_run(
            _failed_attempt_input()
        )

        latest = repository.get_latest_terminal_attempt_for_scope(
            _authority_input()
        )
        assert created is True
        assert failure.attempt_sequence > 0
        assert latest == failure
        assert latest.terminal_status == "technical_failed"
        with pytest.raises(
            CandidateDevelopmentOcrRunPersistenceError,
            match="latest terminal attempt",
        ):
            repository.require_latest_success(success.evidence_sha256)
    finally:
        runtime.close()


def test_terminal_failure_in_a_different_ocr_scope_does_not_revoke_success(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="candidate-development-ocr-scope-isolation",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        success, _ = repository.record_completed_run(_authority_input())
        repository.record_failed_run(
            _failed_attempt_input(runtime_set_sha256="c" * 64)
        )

        latest = repository.require_latest_success(
            success.evidence_sha256
        )
        assert latest.evidence_sha256 == success.evidence_sha256
        assert latest.terminal_status == "succeeded"
    finally:
        runtime.close()


def test_candidate_ocr_terminal_attempts_are_immutable(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="candidate-development-ocr-attempt-immutable",
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        attempt, _ = repository.record_failed_run(
            _failed_attempt_input()
        )
        with (
            runtime.engine.begin() as connection,
            pytest.raises(IntegrityError, match="append-only"),
        ):
            connection.execute(
                text(
                    "UPDATE candidate_development_ocr_attempts "
                    "SET terminal_status = 'succeeded' "
                    "WHERE attempt_sequence = :attempt_sequence"
                ),
                {"attempt_sequence": attempt.attempt_sequence},
            )
        with (
            runtime.engine.begin() as connection,
            pytest.raises(IntegrityError, match="append-only"),
        ):
            connection.execute(
                text(
                    "DELETE FROM candidate_development_ocr_attempts "
                    "WHERE attempt_sequence = :attempt_sequence"
                ),
                {"attempt_sequence": attempt.attempt_sequence},
            )
    finally:
        runtime.close()
