from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from dahe.adapters.sqlite.loop3_resource_store import SqliteLoop3ResourceStore
from dahe.jobs.scheduler import CooperativeSchedulerRunner, choose_candidate
from dahe.jobs.shared_evidence import shared_evidence_fingerprint


def _candidate(
    *,
    job_id: str,
    job_kind: str,
    ready_sequence: int,
    item_index: int = 0,
) -> dict[str, object]:
    return {
        "job_id": job_id,
        "job_kind": job_kind,
        "ready_sequence": ready_sequence,
        "item_index": item_index,
    }


def test_scheduler_priority_uses_business_first_then_bounded_aging() -> None:
    business = _candidate(
        job_id="business",
        job_kind="business",
        ready_sequence=10,
    )
    fixture = _candidate(
        job_id="fixture",
        job_kind="test_fixture",
        ready_sequence=10,
    )

    selected = choose_candidate(
        [fixture, business],
        last_granted_job_id=None,
        sequence=10,
    )
    assert selected == business

    old_fixture = _candidate(
        job_id="old-fixture",
        job_kind="test_fixture",
        ready_sequence=0,
    )
    fresh_business = _candidate(
        job_id="fresh-business",
        job_kind="business",
        ready_sequence=15,
    )
    selected_after_aging = choose_candidate(
        [fresh_business, old_fixture],
        last_granted_job_id=None,
        sequence=20,
    )
    assert selected_after_aging == old_fixture


def test_scheduler_rotation_and_fifo_are_deterministic() -> None:
    first = _candidate(job_id="a", job_kind="business", ready_sequence=1)
    second = _candidate(job_id="b", job_kind="business", ready_sequence=2)
    later_same_job = _candidate(
        job_id="a",
        job_kind="business",
        ready_sequence=3,
        item_index=1,
    )

    rotated = choose_candidate(
        [later_same_job, second, first],
        last_granted_job_id="a",
        sequence=4,
    )
    fifo = choose_candidate(
        [later_same_job, second, first],
        last_granted_job_id=None,
        sequence=4,
    )

    assert rotated == second
    assert fifo == first


def test_scheduler_finishes_same_truck_pair_before_job_rotation() -> None:
    paired = {
        **_candidate(job_id="a", job_kind="business", ready_sequence=8),
        "pair_continuation": True,
        "last_granted_sequence": 8,
    }
    other_job = {
        **_candidate(job_id="b", job_kind="business", ready_sequence=2),
        "last_granted_sequence": 0,
    }

    selected = choose_candidate(
        [other_job, paired],
        last_granted_job_id="a",
        sequence=9,
    )

    assert selected == paired


def test_three_sustained_jobs_rotate_without_starvation() -> None:
    candidates = [
        {
            **_candidate(
                job_id=job_id,
                job_kind="business",
                ready_sequence=1,
            ),
            "last_granted_sequence": 0,
        }
        for job_id in ("a", "b", "c")
    ]
    selected_jobs: list[str] = []

    for sequence in range(2, 8):
        selected = choose_candidate(
            candidates,
            last_granted_job_id=(
                None if not selected_jobs else selected_jobs[-1]
            ),
            sequence=sequence,
        )
        assert selected is not None
        selected_job = str(selected["job_id"])
        selected_jobs.append(selected_job)
        for candidate in candidates:
            if candidate["job_id"] == selected_job:
                candidate["last_granted_sequence"] = sequence

    assert selected_jobs == ["a", "b", "c", "a", "b", "c"]


def test_shared_evidence_identity_includes_pipeline_fingerprint() -> None:
    first = shared_evidence_fingerprint("a" * 64, "pipeline-a")
    same = shared_evidence_fingerprint("a" * 64, "pipeline-a")
    different_pipeline = shared_evidence_fingerprint("a" * 64, "pipeline-b")

    assert first == same
    assert first != different_pipeline


def test_runner_waits_between_atomic_ticks_and_can_stop_during_wait() -> None:
    class ObservableScheduler:
        def __init__(self) -> None:
            self.tick_count = 0
            self.first_tick = threading.Event()
            self.second_tick = threading.Event()

        def tick(self) -> bool:
            self.tick_count += 1
            if self.tick_count == 1:
                self.first_tick.set()
            if self.tick_count == 2:
                self.second_tick.set()
            return True

        def has_automatic_work(self) -> bool:
            return self.tick_count < 2

    scheduler = ObservableScheduler()
    runner = CooperativeSchedulerRunner(
        scheduler,  # type: ignore[arg-type]
        tick_interval_seconds=0.2,
    )

    runner.start()
    try:
        runner.notify()
        assert scheduler.first_tick.wait(timeout=1)
        assert scheduler.second_tick.wait(timeout=0.04) is False
    finally:
        runner.close()

    assert scheduler.tick_count == 1


def test_runner_default_interval_does_not_busy_spin_while_work_is_pending() -> None:
    class ObservableScheduler:
        def __init__(self) -> None:
            self.tick_count = 0
            self.first_tick = threading.Event()
            self.second_tick = threading.Event()

        def tick(self) -> bool:
            self.tick_count += 1
            if self.tick_count == 1:
                self.first_tick.set()
            if self.tick_count == 2:
                self.second_tick.set()
            return True

        def has_automatic_work(self) -> bool:
            return self.tick_count < 2

    scheduler = ObservableScheduler()
    runner = CooperativeSchedulerRunner(
        scheduler,  # type: ignore[arg-type]
        tick_interval_seconds=0,
    )

    runner.start()
    try:
        runner.notify()
        assert scheduler.first_tick.wait(timeout=1)
        assert scheduler.second_tick.wait(timeout=0.1) is False
        assert scheduler.second_tick.wait(timeout=0.4)
    finally:
        runner.close()


def test_runner_uses_external_poll_interval_but_notify_wakes_it_early() -> None:
    class ObservableScheduler:
        def __init__(self) -> None:
            self.tick_count = 0
            self.first_tick = threading.Event()
            self.second_tick = threading.Event()

        def tick(self) -> bool:
            self.tick_count += 1
            if self.tick_count == 1:
                self.first_tick.set()
            if self.tick_count == 2:
                self.second_tick.set()
            return True

        def has_automatic_work(self) -> bool:
            return self.tick_count < 2

        def automatic_poll_interval_seconds(self) -> float:
            return 2.0

    scheduler = ObservableScheduler()
    runner = CooperativeSchedulerRunner(
        scheduler,  # type: ignore[arg-type]
        tick_interval_seconds=0,
    )

    runner.start()
    try:
        runner.notify()
        assert scheduler.first_tick.wait(timeout=1)
        assert scheduler.second_tick.wait(timeout=0.35) is False
        runner.notify()
        assert scheduler.second_tick.wait(timeout=0.35)
    finally:
        runner.close()


def test_runner_heartbeats_external_work_without_full_scheduler_scans() -> None:
    class ObservableScheduler:
        def __init__(self) -> None:
            self.tick_count = 0
            self.maintenance_count = 0
            self.first_tick = threading.Event()
            self.second_tick = threading.Event()

        def tick(self) -> bool:
            self.tick_count += 1
            if self.tick_count == 1:
                self.first_tick.set()
            if self.tick_count == 2:
                self.second_tick.set()
            return True

        def has_automatic_work(self) -> bool:
            return self.tick_count < 2

        def automatic_poll_interval_seconds(self) -> float:
            return 0.25

        def maintain_automatic_work(self) -> bool:
            self.maintenance_count += 1
            return self.maintenance_count >= 2

    scheduler = ObservableScheduler()
    runner = CooperativeSchedulerRunner(
        scheduler,  # type: ignore[arg-type]
        tick_interval_seconds=0,
    )

    runner.start()
    try:
        runner.notify()
        assert scheduler.first_tick.wait(timeout=1)
        assert scheduler.second_tick.wait(timeout=0.35) is False
        assert scheduler.second_tick.wait(timeout=0.35)
    finally:
        runner.close()

    assert scheduler.maintenance_count == 2
    assert scheduler.tick_count == 2


def test_external_browser_grant_uses_low_overhead_poll_interval() -> None:
    store = object.__new__(SqliteLoop3ResourceStore)
    store._grant_lock = threading.RLock()  # type: ignore[attr-defined]
    store._process_grants = {}  # type: ignore[attr-defined]
    assert store.automatic_poll_interval_seconds() == 0.25

    store._process_grants = {  # type: ignore[attr-defined]
        "capture": SimpleNamespace(execution_kind="settlement_capture")
    }
    assert store.automatic_poll_interval_seconds() == 1.0


def test_identical_resource_wait_does_not_require_another_state_write() -> None:
    item = {
        "status": "waiting_resource",
        "waiting_reason_kind": "resource",
        "waiting_reason": "resource:gpu_ocr_slot",
    }

    assert (
        SqliteLoop3ResourceStore._needs_waiting_resource_transition(
            item,
            resource_name="gpu_ocr_slot",
        )
        is False
    )
    assert (
        SqliteLoop3ResourceStore._needs_waiting_resource_transition(
            item,
            resource_name="cpu_ocr_slot",
        )
        is True
    )
    assert (
        SqliteLoop3ResourceStore._needs_waiting_resource_transition(
            {**item, "status": "queued"},
            resource_name="gpu_ocr_slot",
        )
        is True
    )


def test_runner_close_waits_without_timeout_for_the_active_atomic_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tick_started = threading.Event()
    release_tick = threading.Event()
    close_returned = threading.Event()

    class BlockingScheduler:
        def tick(self) -> bool:
            tick_started.set()
            assert release_tick.wait(timeout=2)
            return True

        def has_automatic_work(self) -> bool:
            return True

    runner = CooperativeSchedulerRunner(
        BlockingScheduler(),  # type: ignore[arg-type]
        tick_interval_seconds=0,
    )
    observed_join_timeouts: list[float | None] = []
    original_join = runner._thread.join

    def observe_join(timeout: float | None = None) -> None:
        observed_join_timeouts.append(timeout)
        original_join(timeout)

    monkeypatch.setattr(runner._thread, "join", observe_join)
    runner.start()
    runner.notify()
    assert tick_started.wait(timeout=1)

    close_thread = threading.Thread(
        target=lambda: (runner.close(), close_returned.set()),
        name="test-scheduler-close",
    )
    close_thread.start()
    try:
        assert close_returned.wait(timeout=0.05) is False
        release_tick.set()
        assert close_returned.wait(timeout=1)
    finally:
        release_tick.set()
        close_thread.join(timeout=1)

    assert observed_join_timeouts == [None]
