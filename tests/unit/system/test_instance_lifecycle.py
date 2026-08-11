from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from dahe.system.instance_lifecycle import (
    ApplicationInstanceLifecycle,
    CurrentProcessIdentity,
    LifecycleClosedError,
    LifecycleHeartbeatError,
    data_root_identity,
)

T0 = datetime(2026, 7, 25, 8, 0, tzinfo=UTC)


class RecordingRecoveryStore:
    def __init__(self, *, fail_heartbeat: bool = False) -> None:
        self.fail_heartbeat = fail_heartbeat
        self.registrations: list[dict[str, Any]] = []
        self.heartbeats: list[dict[str, Any]] = []
        self.stops: list[dict[str, Any]] = []
        self.heartbeat_attempted = threading.Event()

    def register_instance(self, **values: Any) -> None:
        self.registrations.append(values)

    def heartbeat_instance(self, **values: Any) -> None:
        self.heartbeats.append(values)
        self.heartbeat_attempted.set()
        if self.fail_heartbeat:
            raise RuntimeError("synthetic heartbeat failure")

    def stop_instance(self, **values: Any) -> None:
        self.stops.append(values)


class BlockingRegistrationStore(RecordingRecoveryStore):
    def __init__(self) -> None:
        super().__init__()
        self.registration_started = threading.Event()
        self.allow_registration = threading.Event()

    def register_instance(self, **values: Any) -> None:
        self.registration_started.set()
        if not self.allow_registration.wait(timeout=1):
            raise TimeoutError("test did not release registration")
        super().register_instance(**values)


def _identity() -> CurrentProcessIdentity:
    return CurrentProcessIdentity(
        pid=os.getpid(),
        process_started_at="test-process:2026-07-25T08:00:00+00:00",
    )


def _lifecycle(
    store: RecordingRecoveryStore,
    data_root: Path,
) -> ApplicationInstanceLifecycle:
    return ApplicationInstanceLifecycle(
        store,
        instance_id="instance-loop4",
        data_root=data_root,
        application_version="0.6.0",
        port=8877,
        heartbeat_interval=timedelta(milliseconds=10),
        clock=lambda: T0,
        process_identity_provider=_identity,
    )


def test_start_heartbeats_and_close_are_idempotent(tmp_path: Path) -> None:
    store = RecordingRecoveryStore()
    lifecycle = _lifecycle(store, tmp_path / "profile")

    lifecycle.start()
    lifecycle.start()
    assert store.heartbeat_attempted.wait(timeout=1)

    lifecycle.close()
    lifecycle.close()

    assert len(store.registrations) == 1
    assert store.registrations[0] == {
        "instance_id": "instance-loop4",
        "data_root_identity": data_root_identity(tmp_path / "profile"),
        "pid": os.getpid(),
        "process_started_at": "test-process:2026-07-25T08:00:00+00:00",
        "application_version": "0.6.0",
        "port": 8877,
        "now": T0,
    }
    assert len(store.heartbeats) >= 1
    assert store.stops == [{"instance_id": "instance-loop4", "now": T0}]


def test_context_manager_marks_the_registered_instance_stopped(tmp_path: Path) -> None:
    store = RecordingRecoveryStore()
    lifecycle = _lifecycle(store, tmp_path)

    with lifecycle as running:
        assert running is lifecycle
        assert lifecycle.is_running

    assert lifecycle.is_closed
    assert len(store.stops) == 1


def test_heartbeat_failure_is_reported_after_clean_stop(tmp_path: Path) -> None:
    store = RecordingRecoveryStore(fail_heartbeat=True)
    lifecycle = _lifecycle(store, tmp_path)
    lifecycle.start()
    assert store.heartbeat_attempted.wait(timeout=1)

    with pytest.raises(LifecycleHeartbeatError, match="heartbeat failed"):
        lifecycle.close()

    assert len(store.stops) == 1
    assert lifecycle.is_closed
    lifecycle.close()
    assert len(store.stops) == 1


def test_close_before_start_is_final_and_idempotent(tmp_path: Path) -> None:
    store = RecordingRecoveryStore()
    lifecycle = _lifecycle(store, tmp_path)

    lifecycle.close()
    lifecycle.close()

    assert lifecycle.is_closed
    assert store.registrations == []
    assert store.stops == []
    with pytest.raises(LifecycleClosedError):
        lifecycle.start()


def test_close_waits_for_an_in_progress_registration(tmp_path: Path) -> None:
    store = BlockingRegistrationStore()
    lifecycle = _lifecycle(store, tmp_path)
    errors: list[BaseException] = []

    def start() -> None:
        try:
            lifecycle.start()
        except BaseException as exc:
            errors.append(exc)

    def close() -> None:
        try:
            lifecycle.close()
        except BaseException as exc:
            errors.append(exc)

    start_thread = threading.Thread(target=start)
    close_thread = threading.Thread(target=close)
    start_thread.start()
    assert store.registration_started.wait(timeout=1)
    close_thread.start()
    assert close_thread.is_alive()

    store.allow_registration.set()
    start_thread.join(timeout=1)
    close_thread.join(timeout=1)

    assert not start_thread.is_alive()
    assert not close_thread.is_alive()
    assert errors == []
    assert len(store.registrations) == 1
    assert len(store.stops) == 1
    assert lifecycle.is_closed


def test_data_root_identity_is_stable_for_the_resolved_windows_path(tmp_path: Path) -> None:
    data_root = tmp_path / "profile" / ".." / "profile"

    assert data_root_identity(data_root) == data_root_identity(data_root.resolve())
