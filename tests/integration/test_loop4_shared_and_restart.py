from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest
from sqlalchemy import select, update

from dahe.adapters.fake.loop3 import (
    SHARED_LOADING_IMAGE_SHA256,
    get_loop3_fixture,
)
from dahe.adapters.sqlite.repository import TemporarySqliteJobRepository
from dahe.adapters.sqlite.schema import (
    CHECKPOINTS,
    SHARED_EVIDENCE_CONSUMERS,
    SHARED_EVIDENCE_WORK,
    STAGE_ATTEMPTS,
    WORK_ITEMS,
)
from dahe.jobs.scheduler import CooperativeScheduler

pytestmark = pytest.mark.integration

FAILURE_CODE = "LOOP4-SHARED-OCR-EXHAUSTED"


def _create_fixture(
    repository: TemporarySqliteJobRepository,
    fixture_id: str,
) -> str:
    job, created = repository.create_scheduled_job(
        fixture=get_loop3_fixture(fixture_id),
        scope_label=f"Loop 4 contract: {fixture_id}",
        idempotency_key=f"loop4-{fixture_id}",
        request_hash=f"loop4-{fixture_id}-request",
        expected_record_version=0,
    )
    assert created is True
    return job.job_id


def _require_method(
    repository: TemporarySqliteJobRepository,
    name: str,
) -> Callable[..., Any]:
    method = getattr(repository, name, None)
    assert callable(method), f"Loop 4 repository contract requires {name}(...)"
    return method


def _committed_checkpoint_count(
    repository: TemporarySqliteJobRepository,
    *,
    owner_kind: str,
    owner_id: str,
    stage: str,
) -> int:
    with repository.engine.connect() as connection:
        rows = connection.execute(
            select(CHECKPOINTS.c.payload_json).where(
                CHECKPOINTS.c.owner_kind == owner_kind,
                CHECKPOINTS.c.owner_id == owner_id,
                CHECKPOINTS.c.stage == stage,
            )
        )
        return sum(
            json.loads(str(payload_json)).get("committed") is True for (payload_json,) in rows
        )


def _shared_loading_row(
    repository: TemporarySqliteJobRepository,
) -> dict[str, Any]:
    with repository.engine.connect() as connection:
        row = (
            connection.execute(
                select(SHARED_EVIDENCE_WORK).where(
                    SHARED_EVIDENCE_WORK.c.image_sha256 == SHARED_LOADING_IMAGE_SHA256
                )
            )
            .mappings()
            .one()
        )
        return dict(row)


def _stage_shared_failure(
    repository: TemporarySqliteJobRepository,
    *,
    exhausted: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    shared = _shared_loading_row(repository)
    with repository.commit_gate.transaction(repository.engine) as connection:
        failure_values: dict[str, Any] = {
            "status": "failed",
            "diagnostic_code": FAILURE_CODE,
        }
        if "record_version" in SHARED_EVIDENCE_WORK.c:
            failure_values["record_version"] = SHARED_EVIDENCE_WORK.c.record_version + 1
        if exhausted:
            failure_values["retry_generation"] = SHARED_EVIDENCE_WORK.c.retry_budget
        connection.execute(
            update(SHARED_EVIDENCE_WORK)
            .where(SHARED_EVIDENCE_WORK.c.shared_work_id == shared["shared_work_id"])
            .values(**failure_values)
        )
        consumers = [
            dict(row)
            for row in connection.execute(
                select(
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                    SHARED_EVIDENCE_CONSUMERS.c.status.label("consumer_status"),
                    WORK_ITEMS.c.status.label("work_item_status"),
                    WORK_ITEMS.c.record_version,
                    WORK_ITEMS.c.attempt_count,
                )
                .join(
                    WORK_ITEMS,
                    WORK_ITEMS.c.work_item_id == SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                )
                .where(SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == shared["shared_work_id"])
                .order_by(SHARED_EVIDENCE_CONSUMERS.c.work_item_id)
            ).mappings()
        ]
    return _shared_loading_row(repository), consumers


def _run_until_shared_loading_is_running(
    repository: TemporarySqliteJobRepository,
) -> dict[str, Any]:
    for _ in range(100):
        shared = _shared_loading_row(repository)
        if shared["status"] == "running":
            return shared
        repository.scheduler_tick(set())
    raise AssertionError("shared loading OCR did not start")


def _shared_loading_consumers(
    repository: TemporarySqliteJobRepository,
) -> list[dict[str, Any]]:
    shared = _shared_loading_row(repository)
    with repository.engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                select(
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                    SHARED_EVIDENCE_CONSUMERS.c.status.label("consumer_status"),
                    WORK_ITEMS.c.status.label("work_item_status"),
                    WORK_ITEMS.c.record_version,
                    WORK_ITEMS.c.attempt_count,
                    WORK_ITEMS.c.loading_ocr_complete,
                    WORK_ITEMS.c.diagnostic_code,
                )
                .join(
                    WORK_ITEMS,
                    WORK_ITEMS.c.work_item_id == SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                )
                .where(
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == shared["shared_work_id"],
                    SHARED_EVIDENCE_CONSUMERS.c.image_role == "loading",
                )
                .order_by(SHARED_EVIDENCE_CONSUMERS.c.work_item_id)
            ).mappings()
        ]


def test_new_instance_never_blesses_a_legacy_running_attempt(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "legacy-running"
    first = TemporarySqliteJobRepository(data_root)
    try:
        _create_fixture(first, "audit-batch-short-002")
        assert CooperativeScheduler(first).tick() is True
        running = [
            attempt for attempt in first.list_stage_attempts() if attempt["status"] == "running"
        ]
        assert len(running) == 1
        legacy = running[0]
        committed_before = _committed_checkpoint_count(
            first,
            owner_kind=str(legacy["owner_kind"]),
            owner_id=str(legacy["owner_id"]),
            stage=str(legacy["stage"]),
        )
    finally:
        first.close()

    restarted = TemporarySqliteJobRepository(data_root)
    try:
        recover = _require_method(restarted, "recover_abandoned_attempts")
        recover(recovering_instance_id="loop4-new-instance")
        CooperativeScheduler(restarted).tick()
        recovered = next(
            attempt
            for attempt in restarted.list_stage_attempts()
            if attempt["stage_attempt_id"] == legacy["stage_attempt_id"]
        )
        committed_after = _committed_checkpoint_count(
            restarted,
            owner_kind=str(legacy["owner_kind"]),
            owner_id=str(legacy["owner_id"]),
            stage=str(legacy["stage"]),
        )
    finally:
        restarted.close()

    assert recovered["status"] != "succeeded"
    assert committed_after == committed_before


def test_shared_failure_is_propagated_once_to_each_active_consumer(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "failure-once")
    try:
        _create_fixture(repository, "audit-batch-long-001")
        _create_fixture(repository, "audit-batch-short-002")
        shared, before = _stage_shared_failure(repository, exhausted=True)
        assert len(before) == 2
        assert {row["consumer_status"] for row in before} == {"waiting"}

        propagate = _require_method(
            repository,
            "propagate_shared_failure_once",
        )
        first_count = propagate(
            shared_work_id=str(shared["shared_work_id"]),
            diagnostic_code=FAILURE_CODE,
        )
        second_count = propagate(
            shared_work_id=str(shared["shared_work_id"]),
            diagnostic_code=FAILURE_CODE,
        )

        with repository.engine.connect() as connection:
            after = [
                dict(row)
                for row in connection.execute(
                    select(
                        SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                        SHARED_EVIDENCE_CONSUMERS.c.status.label("consumer_status"),
                        WORK_ITEMS.c.status.label("work_item_status"),
                        WORK_ITEMS.c.record_version,
                        WORK_ITEMS.c.attempt_count,
                        WORK_ITEMS.c.diagnostic_code,
                    )
                    .join(
                        WORK_ITEMS,
                        WORK_ITEMS.c.work_item_id == SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                    )
                    .where(SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == shared["shared_work_id"])
                    .order_by(SHARED_EVIDENCE_CONSUMERS.c.work_item_id)
                ).mappings()
            ]
    finally:
        repository.close()

    before_by_id = {row["work_item_id"]: row for row in before}
    assert first_count == 2
    assert second_count == 0
    assert {row["consumer_status"] for row in after} == {"failed"}
    assert {row["work_item_status"] for row in after} == {"failed"}
    assert {row["diagnostic_code"] for row in after} == {FAILURE_CODE}
    for row in after:
        original = before_by_id[row["work_item_id"]]
        assert row["record_version"] == original["record_version"] + 1
        assert row["attempt_count"] == original["attempt_count"] + 1


def test_shared_failure_cannot_propagate_while_global_retry_budget_remains(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "failure-before-budget")
    try:
        _create_fixture(repository, "audit-batch-short-002")
        shared, before = _stage_shared_failure(repository)

        with pytest.raises(RuntimeError, match="retry budget is not exhausted"):
            repository.propagate_shared_failure_once(
                shared_work_id=str(shared["shared_work_id"]),
                diagnostic_code=FAILURE_CODE,
            )

        after = _shared_loading_consumers(repository)
    finally:
        repository.close()

    assert len(before) == 1
    assert len(after) == 1
    assert after[0]["consumer_status"] == "waiting"
    assert after[0]["work_item_status"] != "failed"
    assert after[0]["diagnostic_code"] is None


def test_first_shared_failure_retries_once_then_each_consumer_uses_success_once(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "retry-then-success")
    try:
        _create_fixture(repository, "audit-batch-long-001")
        _create_fixture(repository, "audit-batch-short-002")
        initial = _run_until_shared_loading_is_running(repository)

        repository.scheduler_tick({SHARED_LOADING_IMAGE_SHA256})
        after_first_failure = _shared_loading_row(repository)
        waiting = _shared_loading_consumers(repository)
        attempts_after_failure = [
            row
            for row in repository.list_stage_attempts()
            if row["owner_kind"] == "shared_evidence"
            and row["owner_id"] == initial["shared_work_id"]
        ]

        for _ in range(10):
            repository.scheduler_tick(set())
            consumers = _shared_loading_consumers(repository)
            if {row["consumer_status"] for row in consumers} == {"consumed"}:
                break
        else:
            raise AssertionError("shared retry result was not consumed")

        completed = _shared_loading_row(repository)
        attempts = [
            row
            for row in repository.list_stage_attempts()
            if row["owner_kind"] == "shared_evidence"
            and row["owner_id"] == initial["shared_work_id"]
        ]
        with repository.engine.connect() as connection:
            consumption_checkpoints = [
                dict(row)
                for row in connection.execute(
                    select(CHECKPOINTS).where(
                        CHECKPOINTS.c.owner_kind == "work_item",
                        CHECKPOINTS.c.stage == "audit.recognize.loading",
                    )
                ).mappings()
                if json.loads(str(row["payload_json"])).get("shared_work_id")
                == initial["shared_work_id"]
            ]
    finally:
        repository.close()

    assert after_first_failure["retry_generation"] == 1
    assert after_first_failure["retry_budget"] == 1
    assert after_first_failure["status"] in {"queued", "running"}
    assert after_first_failure["diagnostic_code"] is None
    assert {row["consumer_status"] for row in waiting} == {"waiting"}
    assert "failed" not in {row["work_item_status"] for row in waiting}
    assert len(attempts_after_failure) == 2
    assert sum(row["status"] == "failed" for row in attempts_after_failure) == 1
    assert completed["status"] == "succeeded"
    assert {row["consumer_status"] for row in consumers} == {"consumed"}
    assert {row["loading_ocr_complete"] for row in consumers} == {1}
    assert len(consumption_checkpoints) == 2
    assert len({row["work_item_id"] for row in consumption_checkpoints}) == 2
    assert len(attempts) == 2
    assert {row["status"] for row in attempts} == {"failed", "succeeded"}


def test_exhausted_shared_retry_propagates_one_source_failure_once(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "retry-exhausted")
    try:
        _create_fixture(repository, "audit-batch-long-001")
        _create_fixture(repository, "audit-batch-short-002")
        initial = _run_until_shared_loading_is_running(repository)

        repository.scheduler_tick({SHARED_LOADING_IMAGE_SHA256})
        _run_until_shared_loading_is_running(repository)
        before_terminal = _shared_loading_consumers(repository)
        repository.scheduler_tick({SHARED_LOADING_IMAGE_SHA256})
        exhausted = _shared_loading_row(repository)
        failed = _shared_loading_consumers(repository)
        replay_count = repository.propagate_shared_failure_once(
            shared_work_id=str(initial["shared_work_id"]),
            diagnostic_code="LOOP3-FAKE-OCR-FAILURE",
        )
        replayed = _shared_loading_consumers(repository)
    finally:
        repository.close()

    before_by_id = {row["work_item_id"]: row for row in before_terminal}
    assert exhausted["status"] == "failed"
    assert exhausted["retry_generation"] == exhausted["retry_budget"] == 1
    assert exhausted["failure_propagation_id"]
    assert {row["consumer_status"] for row in failed} == {"failed"}
    assert {row["work_item_status"] for row in failed} == {"failed"}
    assert {row["diagnostic_code"] for row in failed} == {"LOOP3-FAKE-OCR-FAILURE"}
    for row in failed:
        original = before_by_id[row["work_item_id"]]
        assert row["record_version"] == original["record_version"] + 1
        assert row["attempt_count"] == original["attempt_count"] + 1
    assert replay_count == 0
    assert replayed == failed


def test_late_work_item_result_is_explicitly_ignored_after_terminal_failure(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "late-terminal-result")
    try:
        job_id = _create_fixture(repository, "audit-batch-short-002")
        repository.scheduler_tick(set())
        with repository.commit_gate.transaction(repository.engine) as connection:
            attempt = (
                connection.execute(
                    select(STAGE_ATTEMPTS)
                    .join(
                        WORK_ITEMS,
                        WORK_ITEMS.c.work_item_id == STAGE_ATTEMPTS.c.owner_id,
                    )
                    .where(
                        STAGE_ATTEMPTS.c.owner_kind == "work_item",
                        WORK_ITEMS.c.job_id == job_id,
                    )
                    .order_by(STAGE_ATTEMPTS.c.stage_attempt_id)
                )
                .mappings()
                .first()
            )
            assert attempt is not None
            work_item_id = str(attempt["owner_id"])
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == work_item_id)
                .values(status="failed")
            )
            repository._loop3._scheduler._finish_work_item_attempt(
                connection,
                attempt=attempt,
                sequence=10_000,
            )

        with repository.engine.connect() as connection:
            ignored_terminal_payloads = [
                payload
                for (payload_json,) in connection.execute(
                    select(CHECKPOINTS.c.payload_json).where(
                        CHECKPOINTS.c.owner_kind == "work_item",
                        CHECKPOINTS.c.owner_id == work_item_id,
                    )
                )
                if (payload := json.loads(str(payload_json))).get(
                    "ignored_for_terminal_item"
                )
            ]
    finally:
        repository.close()

    assert len(ignored_terminal_payloads) == 1
    assert ignored_terminal_payloads[0]["committed"] is False


def test_two_concurrent_safe_retries_create_one_shared_production_attempt(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "retry-race")
    try:
        _create_fixture(repository, "audit-batch-short-002")
        shared, _ = _stage_shared_failure(repository)
        safe_retry = _require_method(repository, "safe_retry_shared_work")
        assert "record_version" in shared, (
            "Loop 4 shared work requires record_version for retry CAS"
        )
        before_attempt_ids = {
            str(row["stage_attempt_id"])
            for row in repository.list_stage_attempts()
            if row["owner_kind"] == "shared_evidence"
            and row["owner_id"] == shared["shared_work_id"]
        }
        barrier = Barrier(3)

        def retry(index: int) -> Any:
            barrier.wait(timeout=3)
            return safe_retry(
                shared_work_id=str(shared["shared_work_id"]),
                expected_record_version=int(shared["record_version"]),
                idempotency_key=f"loop4-shared-retry-{index}",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(retry, index) for index in range(2)]
            barrier.wait(timeout=3)
            results = [future.result(timeout=3) for future in futures]

        attempts = [
            row
            for row in repository.list_stage_attempts()
            if row["owner_kind"] == "shared_evidence"
            and row["owner_id"] == shared["shared_work_id"]
            and row["stage_attempt_id"] not in before_attempt_ids
        ]
        current_shared = _shared_loading_row(repository)
    finally:
        repository.close()

    assert len(attempts) == 1
    assert attempts[0]["stage"] == "audit.recognize"
    assert attempts[0]["status"] in {"queued", "running"}
    assert {result.stage_attempt_id for result in results} == {attempts[0]["stage_attempt_id"]}
    assert sum(result.created is True for result in results) == 1
    assert current_shared["status"] in {"queued", "running"}
    assert current_shared["diagnostic_code"] is None
    assert current_shared["record_version"] == shared["record_version"] + 1


def test_shared_retry_budget_cannot_be_bypassed_with_a_new_idempotency_key(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "retry-budget")
    try:
        _create_fixture(repository, "audit-batch-short-002")
        shared, _ = _stage_shared_failure(repository)
        repository.safe_retry_shared_work(
            shared_work_id=str(shared["shared_work_id"]),
            expected_record_version=int(shared["record_version"]),
            idempotency_key="loop4-first-retry",
        )
        with repository.commit_gate.transaction(repository.engine) as connection:
            current_version = int(
                connection.execute(
                    select(SHARED_EVIDENCE_WORK.c.record_version).where(
                        SHARED_EVIDENCE_WORK.c.shared_work_id == shared["shared_work_id"]
                    )
                ).scalar_one()
            )
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(
                    SHARED_EVIDENCE_WORK.c.shared_work_id == shared["shared_work_id"],
                    SHARED_EVIDENCE_WORK.c.record_version == current_version,
                )
                .values(
                    status="failed",
                    diagnostic_code=FAILURE_CODE,
                    record_version=current_version + 1,
                )
            )
        retried = _shared_loading_row(repository)

        with pytest.raises(RuntimeError, match="retry budget is exhausted"):
            repository.safe_retry_shared_work(
                shared_work_id=str(shared["shared_work_id"]),
                expected_record_version=int(retried["record_version"]),
                idempotency_key="loop4-disallowed-second-retry",  # gitleaks:allow
            )
    finally:
        repository.close()
