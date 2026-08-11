from __future__ import annotations

import threading
import time

import pytest

from dahe.jobs.daily_execution import (
    AsyncDailyExecutionBackend,
    DailyStageExecution,
    DailyStageWork,
)


def _work(attempt: str = "attempt-1") -> DailyStageWork:
    return DailyStageWork(
        stage_attempt_id=attempt,
        job_id="job-1",
        work_item_id="item-1",
        stage="daily.list_page",
    )


def test_daily_backend_runs_one_stage_and_returns_completed_result() -> None:
    release = threading.Event()

    def execute(work: DailyStageWork) -> DailyStageExecution:
        release.wait(timeout=2)
        return DailyStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="succeeded",
            completed_stage=work.stage,
            next_stage="daily.save_snapshot",
            checkpoint_revision=1,
            diagnostic_code=None,
        )

    backend = AsyncDailyExecutionBackend(execute=execute)
    try:
        backend.submit(_work())
        assert backend.pop_completed() == {}
        release.set()
        result: dict[str, DailyStageExecution] = {}
        for _ in range(100):
            result = backend.pop_completed()
            if result:
                break
            time.sleep(0.005)
        assert result["attempt-1"].next_stage == "daily.save_snapshot"
    finally:
        backend.close()


def test_daily_backend_rejects_duplicate_attempt_and_sanitizes_crash() -> None:
    release = threading.Event()

    def crash(work: DailyStageWork) -> DailyStageExecution:
        del work
        release.wait(timeout=2)
        raise RuntimeError("Authorization=secret C:\\private\\profile")

    backend = AsyncDailyExecutionBackend(execute=crash)
    try:
        backend.submit(_work())
        with pytest.raises(RuntimeError, match="submitted twice"):
            backend.submit(_work())
        release.set()
        result: dict[str, DailyStageExecution] = {}
        for _ in range(100):
            result = backend.pop_completed()
            if result:
                break
            time.sleep(0.005)
        execution = result["attempt-1"]
        assert execution.outcome == "failed"
        assert execution.diagnostic_code == "DAILY-STAGE-EXECUTION-FAILED"
        assert "secret" not in repr(execution)
    finally:
        backend.close()


def test_daily_backend_close_waits_for_owned_stage() -> None:
    started = threading.Event()
    release = threading.Event()

    def execute(work: DailyStageWork) -> DailyStageExecution:
        started.set()
        release.wait(timeout=2)
        return DailyStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="failed",
            completed_stage=work.stage,
            next_stage=None,
            checkpoint_revision=None,
            diagnostic_code="CF-BROWSER-CLOSED",
        )

    backend = AsyncDailyExecutionBackend(execute=execute)
    backend.submit(_work())
    assert started.wait(timeout=2)
    release.set()
    backend.close()
    assert backend.closed is True
