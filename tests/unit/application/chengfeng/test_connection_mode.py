from __future__ import annotations

import pytest

from dahe.application.chengfeng.connection_mode import (
    ChengfengConnectionMode,
    ChengfengConnectionModeConflictError,
    ChengfengConnectionModeStore,
)


def test_connection_mode_defaults_to_operational_and_switches_once() -> None:
    store = ChengfengConnectionModeStore()

    initial = store.get()
    switched = store.switch(
        mode=ChengfengConnectionMode.STRICT_SHADOW,
        expected_record_version=initial.record_version,
        idempotency_key="switch-to-strict",
        request_hash="a" * 64,
        switching_allowed=True,
    )
    replay = store.switch(
        mode=ChengfengConnectionMode.STRICT_SHADOW,
        expected_record_version=initial.record_version,
        idempotency_key="switch-to-strict",
        request_hash="a" * 64,
        switching_allowed=False,
    )

    assert initial.mode is ChengfengConnectionMode.OPERATIONAL_COMPAT
    assert switched.mode is ChengfengConnectionMode.STRICT_SHADOW
    assert switched.record_version == initial.record_version + 1
    assert replay == switched


def test_connection_mode_rejects_active_or_stale_switches() -> None:
    store = ChengfengConnectionModeStore()

    with pytest.raises(ChengfengConnectionModeConflictError):
        store.switch(
            mode=ChengfengConnectionMode.STRICT_SHADOW,
            expected_record_version=1,
            idempotency_key="active-switch",
            request_hash="b" * 64,
            switching_allowed=False,
        )
    with pytest.raises(ChengfengConnectionModeConflictError):
        store.switch(
            mode=ChengfengConnectionMode.STRICT_SHADOW,
            expected_record_version=99,
            idempotency_key="stale-switch",
            request_hash="c" * 64,
            switching_allowed=True,
        )
