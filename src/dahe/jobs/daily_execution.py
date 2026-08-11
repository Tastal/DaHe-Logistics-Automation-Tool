from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal

DailyExecutionOutcome = Literal[
    "succeeded",
    "retry",
    "waiting_external",
    "failed",
]


@dataclass(frozen=True, slots=True)
class DailyStageWork:
    stage_attempt_id: str
    job_id: str
    work_item_id: str
    stage: str

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or not value
            for value in (
                self.stage_attempt_id,
                self.job_id,
                self.work_item_id,
            )
        ) or not self.stage.startswith("daily."):
            raise ValueError("daily stage work identity is invalid")


@dataclass(frozen=True, slots=True)
class DailyStageExecution:
    stage_attempt_id: str
    outcome: DailyExecutionOutcome
    completed_stage: str
    next_stage: str | None
    checkpoint_revision: int | None
    diagnostic_code: str | None

    def __post_init__(self) -> None:
        if (
            type(self.stage_attempt_id) is not str
            or not self.stage_attempt_id
            or type(self.completed_stage) is not str
            or not self.completed_stage.startswith("daily.")
            or self.outcome
            not in {
                "succeeded",
                "retry",
                "waiting_external",
                "failed",
            }
        ):
            raise ValueError("daily stage execution identity is invalid")
        if (
            self.next_stage is not None
            and not self.next_stage.startswith("daily.")
        ):
            raise ValueError("daily next stage is invalid")
        if (
            self.checkpoint_revision is not None
            and (
                type(self.checkpoint_revision) is not int
                or self.checkpoint_revision < 1
            )
        ):
            raise ValueError("daily checkpoint revision is invalid")
        if self.outcome == "succeeded":
            if self.diagnostic_code is not None:
                raise ValueError(
                    "successful daily execution cannot have a diagnostic"
                )
        elif not self.diagnostic_code:
            raise ValueError(
                "failed or retried daily execution requires a diagnostic"
            )


class AsyncDailyExecutionBackend:
    """Run one browser-bound daily stage at a time outside DB transactions."""

    def __init__(
        self,
        *,
        execute: Callable[[DailyStageWork], DailyStageExecution],
        reconcile_terminal: Callable[[str], None] | None = None,
    ) -> None:
        self._execute = execute
        self._reconcile_terminal = reconcile_terminal
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="dahe-daily-stage",
        )
        self._lock = threading.RLock()
        self._futures: dict[
            str,
            Future[DailyStageExecution],
        ] = {}
        self._closed = False

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def submit(self, work: DailyStageWork) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("daily execution backend is closed")
            if work.stage_attempt_id in self._futures:
                raise RuntimeError(
                    "daily stage attempt was submitted twice"
                )
            self._futures[work.stage_attempt_id] = self._executor.submit(
                self._run_safely,
                work,
            )

    def _run_safely(self, work: DailyStageWork) -> DailyStageExecution:
        try:
            result = self._execute(work)
            if result.stage_attempt_id != work.stage_attempt_id:
                raise ValueError(
                    "daily stage execution returned another attempt"
                )
            return result
        except BaseException:
            return DailyStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="failed",
                completed_stage=work.stage,
                next_stage=None,
                checkpoint_revision=None,
                diagnostic_code="DAILY-STAGE-EXECUTION-FAILED",
            )

    def pop_completed(self) -> dict[str, DailyStageExecution]:
        completed: dict[str, DailyStageExecution] = {}
        with self._lock:
            for attempt_id, future in tuple(self._futures.items()):
                if not future.done():
                    continue
                completed[attempt_id] = future.result()
                del self._futures[attempt_id]
        return completed

    def has_pending(self) -> bool:
        with self._lock:
            return bool(self._futures)

    def has_completed(self) -> bool:
        with self._lock:
            return any(future.done() for future in self._futures.values())

    def reconcile_terminal(self, job_id: str) -> None:
        """Reconcile one terminal job after its scheduler commit."""
        if type(job_id) is not str or not job_id:
            raise ValueError("daily terminal job identity is invalid")
        with self._lock:
            callback = self._reconcile_terminal
        if callback is not None:
            callback(job_id)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=False)
