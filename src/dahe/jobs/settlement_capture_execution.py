from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal

SettlementCaptureOutcome = Literal[
    "succeeded",
    "retry",
    "waiting_external",
    "failed",
]
SETTLEMENT_CAPTURE_STAGE = "settlement_capture.read"


@dataclass(frozen=True, slots=True)
class SettlementCaptureStageWork:
    stage_attempt_id: str
    job_id: str
    work_item_id: str
    stage: str
    attempt_count: int = 0

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not value
            for value in (
                self.stage_attempt_id,
                self.job_id,
                self.work_item_id,
            )
        ) or self.stage != SETTLEMENT_CAPTURE_STAGE:
            raise ValueError(
                "settlement capture stage work identity is invalid"
            )
        if (
            isinstance(self.attempt_count, bool)
            or not isinstance(self.attempt_count, int)
            or self.attempt_count < 0
        ):
            raise ValueError(
                "settlement capture attempt count is invalid"
            )


@dataclass(frozen=True, slots=True)
class SettlementCaptureStageExecution:
    stage_attempt_id: str
    outcome: SettlementCaptureOutcome
    completed_stage: str
    next_stage: str | None
    platform_read_performed: bool
    checkpoint_revision: int | None
    manifest_sha256: str | None
    diagnostic_code: str | None
    selection_manifest_sha256: str | None = None
    batch_manifest_sha256: str | None = None
    operational_capture_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.stage_attempt_id, str)
            or not self.stage_attempt_id
            or self.completed_stage != SETTLEMENT_CAPTURE_STAGE
            or self.outcome
            not in {
                "succeeded",
                "retry",
                "waiting_external",
                "failed",
            }
            or type(self.platform_read_performed) is not bool
        ):
            raise ValueError(
                "settlement capture stage execution is invalid"
            )
        if (
            self.next_stage is not None
            and self.next_stage != SETTLEMENT_CAPTURE_STAGE
        ):
            raise ValueError("settlement capture next stage is invalid")
        if (
            self.checkpoint_revision is not None
            and (
                type(self.checkpoint_revision) is not int
                or self.checkpoint_revision < 1
            )
        ):
            raise ValueError(
                "settlement capture checkpoint revision is invalid"
            )
        for value in (
            self.manifest_sha256,
            self.selection_manifest_sha256,
            self.batch_manifest_sha256,
            self.operational_capture_sha256,
        ):
            if value is not None and (
                len(value) != 64
                or value != value.lower()
                or any(
                    character not in "0123456789abcdef"
                    for character in value
                )
            ):
                raise ValueError(
                    "settlement capture manifest identity is invalid"
                )
        if self.outcome == "succeeded":
            if self.diagnostic_code is not None:
                raise ValueError(
                    "successful settlement capture cannot have a diagnostic"
                )
            formal_terminal = (
                self.manifest_sha256 is not None,
                self.selection_manifest_sha256 is not None,
                self.batch_manifest_sha256 is not None,
            )
            operational_terminal = (
                self.operational_capture_sha256 is not None
            )
            if (
                self.next_stage is None
                and (
                    (formal_terminal == (True, True, True))
                    == operational_terminal
                )
            ) or (
                self.next_stage is not None
                and (
                    formal_terminal != (False, False, False)
                    or operational_terminal
                )
            ):
                raise ValueError(
                    "terminal settlement capture requires all manifests"
                )
        else:
            if not self.diagnostic_code:
                raise ValueError(
                    "failed settlement capture requires a diagnostic"
                )
            if any(
                value is not None
                for value in (
                    self.manifest_sha256,
                    self.selection_manifest_sha256,
                    self.batch_manifest_sha256,
                    self.operational_capture_sha256,
                )
            ):
                raise ValueError(
                    "failed settlement capture cannot have a manifest"
                )
            if self.outcome in {"retry", "waiting_external"} and (
                self.next_stage != SETTLEMENT_CAPTURE_STAGE
            ):
                raise ValueError(
                    "nonterminal settlement capture must retain its stage"
                )
            if self.outcome == "failed" and self.next_stage is not None:
                raise ValueError(
                    "failed settlement capture cannot have a next stage"
                )


class AsyncSettlementCaptureExecutionBackend:
    """Run one browser-bound capture quantum outside DB transactions."""

    def __init__(
        self,
        *,
        execute: Callable[
            [SettlementCaptureStageWork],
            SettlementCaptureStageExecution,
        ],
        reconcile_terminal: Callable[[str], None] | None = None,
    ) -> None:
        self._execute = execute
        self._reconcile_terminal = reconcile_terminal
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="dahe-settlement-capture",
        )
        self._lock = threading.RLock()
        self._futures: dict[
            str,
            Future[SettlementCaptureStageExecution],
        ] = {}
        self._closed = False

    def submit(self, work: SettlementCaptureStageWork) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError(
                    "settlement capture execution backend is closed"
                )
            if work.stage_attempt_id in self._futures:
                raise RuntimeError(
                    "settlement capture attempt was submitted twice"
                )
            self._futures[work.stage_attempt_id] = self._executor.submit(
                self._run_safely,
                work,
            )

    def _run_safely(
        self,
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        try:
            result = self._execute(work)
            if result.stage_attempt_id != work.stage_attempt_id:
                raise ValueError(
                    "settlement capture returned another attempt"
                )
            return result
        except BaseException:
            return SettlementCaptureStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="failed",
                completed_stage=work.stage,
                next_stage=None,
                platform_read_performed=False,
                checkpoint_revision=None,
                manifest_sha256=None,
                diagnostic_code="SETTLEMENT-CAPTURE-EXECUTION-FAILED",
            )

    def pop_completed(
        self,
    ) -> dict[str, SettlementCaptureStageExecution]:
        completed: dict[str, SettlementCaptureStageExecution] = {}
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
        """Reconcile one terminal capture after its scheduler commit."""

        if not isinstance(job_id, str) or not job_id:
            raise ValueError(
                "settlement capture terminal job identity is invalid"
            )
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
