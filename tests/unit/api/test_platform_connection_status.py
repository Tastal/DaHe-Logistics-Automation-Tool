from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from dahe.adapters.sqlite.browser_control import BrowserControlRecord
from dahe.api.platform import _connection_status_payload
from dahe.application.chengfeng.transient_progress import (
    TransientBusinessProgressStore,
)


def _record(**changes: object) -> BrowserControlRecord:
    base = BrowserControlRecord(
        session_id="session",
        browser_lifecycle="ready",
        browser_control_mode="idle",
        holder_kind=None,
        holder_id=None,
        instance_id=None,
        worker_id=None,
        job_id=None,
        control_epoch=1,
        record_version=1,
    )
    return replace(base, **changes)


@pytest.mark.parametrize(
    ("available", "running", "record", "expected"),
    [
        (False, False, _record(), ("error", "连接异常")),
        (True, False, _record(browser_lifecycle="stopped"), ("browser_closed", "浏览器关闭")),
        (True, True, _record(browser_lifecycle="recovering"), ("opening", "正在打开")),
        (True, True, _record(browser_control_mode="human_login"), ("login_required", "等待登录")),
        (True, True, _record(browser_control_mode="idle"), ("ready", "连接就绪")),
        (
            True,
            True,
            _record(browser_control_mode="automated", job_id="job"),
            ("reading", "正在读取"),
        ),
    ],
)
def test_connection_status_mapping(
    available: bool,
    running: bool,
    record: BrowserControlRecord,
    expected: tuple[str, str],
) -> None:
    payload = _connection_status_payload(
        record,
        runtime=SimpleNamespace(available=available, running=running),
    )

    assert (payload["code"], payload["label"]) == expected


def test_connection_status_reports_image_transfer_as_downloading() -> None:
    progress = TransientBusinessProgressStore()
    progress.publish("job", "image", 1, 2)

    payload = _connection_status_payload(
        _record(browser_control_mode="automated", job_id="job"),
        runtime=SimpleNamespace(available=True, running=True),
        transient_progress_store=progress,
    )

    assert payload == {"code": "downloading", "label": "正在下载"}
