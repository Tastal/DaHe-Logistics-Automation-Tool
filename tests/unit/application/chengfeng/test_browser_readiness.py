from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from dahe.adapters.chengfeng.browser_runtime import BrowserRuntimeError
from dahe.adapters.sqlite.browser_control import BrowserControlRecord
from dahe.application.chengfeng.browser_readiness import (
    reconcile_operational_browser_readiness,
    reconcile_terminal_automated_browser_holder,
)


class _BrowserControl:
    def __init__(self, record: BrowserControlRecord) -> None:
        self.record = record
        self.mark_ready_calls = 0

    def get(self, session_id: str) -> BrowserControlRecord:
        assert session_id == self.record.session_id
        return self.record

    def mark_ready(
        self,
        *,
        session_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> BrowserControlRecord:
        del now
        assert session_id == self.record.session_id
        assert expected_record_version == self.record.record_version
        self.mark_ready_calls += 1
        self.record = replace(
            self.record,
            browser_lifecycle="ready",
            record_version=self.record.record_version + 1,
        )
        return self.record


class _BrowserRuntime:
    def __init__(self, *, running: bool) -> None:
        self.running = running
        self.start_calls = 0
        self.close_calls = 0

    def start_operational(self) -> str:
        self.start_calls += 1
        self.running = True
        return "msedge"

    def close(self) -> None:
        self.close_calls += 1
        self.running = False


class _Lifecycle:
    def __init__(self) -> None:
        from contextlib import nullcontext

        self.hold = nullcontext


def _record(*, lifecycle: str = "stopped") -> BrowserControlRecord:
    return BrowserControlRecord(
        session_id="chengfeng",
        browser_lifecycle=lifecycle,
        browser_control_mode="idle",
        holder_kind=None,
        holder_id=None,
        instance_id=None,
        worker_id=None,
        job_id=None,
        control_epoch=1,
        record_version=3,
    )


def test_reconcile_restarts_missing_runtime_behind_stale_ready_state() -> None:
    control = _BrowserControl(_record(lifecycle="ready"))
    runtime = _BrowserRuntime(running=False)

    result = reconcile_operational_browser_readiness(
        browser_control=control,
        browser_runtime=runtime,
        browser_lifecycle=_Lifecycle(),
        session_id="chengfeng",
        now=datetime(2026, 8, 12, tzinfo=UTC),
    )

    assert runtime.start_calls == 1
    assert runtime.running is True
    assert control.mark_ready_calls == 0
    assert result.browser_lifecycle == "ready"


def test_reconcile_marks_stopped_state_ready_after_runtime_start() -> None:
    control = _BrowserControl(_record())
    runtime = _BrowserRuntime(running=False)

    result = reconcile_operational_browser_readiness(
        browser_control=control,
        browser_runtime=runtime,
        browser_lifecycle=_Lifecycle(),
        session_id="chengfeng",
        now=datetime(2026, 8, 12, tzinfo=UTC),
    )

    assert runtime.start_calls == 1
    assert control.mark_ready_calls == 1
    assert result.browser_lifecycle == "ready"


def test_reconcile_rebuilds_failed_worker_once_inside_same_start() -> None:
    class FailOnceRuntime(_BrowserRuntime):
        def start_operational(self) -> str:
            self.start_calls += 1
            if self.start_calls == 1:
                raise BrowserRuntimeError("fixture worker failed")
            self.running = True
            return "msedge"

    control = _BrowserControl(_record())
    runtime = FailOnceRuntime(running=False)

    result = reconcile_operational_browser_readiness(
        browser_control=control,
        browser_runtime=runtime,
        browser_lifecycle=_Lifecycle(),
        session_id="chengfeng",
        now=datetime(2026, 8, 13, tzinfo=UTC),
    )

    assert runtime.start_calls == 2
    assert runtime.close_calls == 1
    assert result.browser_lifecycle == "ready"


def test_reconcile_terminal_automated_holder_uses_exact_business_callback() -> None:
    control = _BrowserControl(
        replace(
            _record(lifecycle="ready"),
            browser_control_mode="automated",
            holder_kind="worker",
            holder_id="attempt-one",
            instance_id="old-instance",
            worker_id="old-worker",
            job_id="terminal-job",
        )
    )
    runtime = _BrowserRuntime(running=False)
    reconciled: list[tuple[str, str]] = []

    result = reconcile_terminal_automated_browser_holder(
        browser_control=control,
        browser_runtime=runtime,
        session_id="chengfeng",
        load_job_state=lambda job_id: ("settlement_capture", job_id == "terminal-job"),
        reconcile_settlement=lambda job_id: reconciled.append(("settlement", job_id)),
        reconcile_daily=lambda job_id: reconciled.append(("daily", job_id)),
    )

    assert result == "terminal-job"
    assert reconciled == [("settlement", "terminal-job")]
