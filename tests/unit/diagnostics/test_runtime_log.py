from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dahe.diagnostics.runtime_log import RuntimeLogStore


def test_runtime_log_redacts_sensitive_text_and_protocol_stdout(
    tmp_path: Path,
) -> None:
    store = RuntimeLogStore(tmp_path / "logs")
    store.append(
        level="error",
        source="worker",
        event_code="worker_stderr",
        stream="stderr",
        message=(
            "password=secret Cookie: session=abc Authorization: Bearer token "
            "https://example.test/a?token=secret "
            r"C:\Users\example\private\record.json user@example.com 13800000000 "
            "raw_ocr=private-ticket-text"
        ),
    )
    store.append_process_output(
        source="ocr",
        stream="stdout",
        text='{"raw_ocr":"3270","text":"private ticket text"}',
        protocol_stdout=True,
    )

    serialized = "\n".join(
        event["message"] for event in store.query(limit=20)["events"]
    ).lower()
    for forbidden in (
        "secret",
        "session=abc",
        "bearer token",
        "?token=",
        r"c:\users",
        "user@example.com",
        "13800000000",
        "3270",
        "private ticket text",
        "private-ticket-text",
    ):
        assert forbidden not in serialized
    assert "protocol stdout" in serialized


def test_runtime_log_redacts_multivalue_headers_ocr_tails_and_spaced_paths(
    tmp_path: Path,
) -> None:
    store = RuntimeLogStore(tmp_path / "logs")
    store.append(
        level="error",
        source="browser-worker",
        event_code="browser_stderr",
        stream="stderr",
        message="Cookie: SESSION=abc; tenant=secret; uid=123",
    )
    store.append(
        level="error",
        source="worker",
        event_code="ocr_stderr",
        stream="stderr",
        message="raw OCR: 车牌 陕A00000 净重 32.70",
    )
    store.append(
        level="error",
        source="worker",
        event_code="path_failure",
        stream="stderr",
        message=r"failed C:\Users\example\My Folder\secret.txt",
    )
    store.append_process_output(
        source="ocr-gpu-worker",
        stream="stderr",
        text="unlabelled ticket content 陕A00000 32.70",
    )

    queried = "\n".join(
        str(event["message"])
        for event in store.query(limit=20)["events"]
    )
    exported = store.export_text().decode("utf-8")
    for rendered in (queried, exported):
        for forbidden in (
            "SESSION=abc",
            "tenant=secret",
            "uid=123",
            "陕A00000",
            "32.70",
            r"C:\Users",
            "My Folder",
            "secret.txt",
            "unlabelled ticket content",
        ):
            assert forbidden not in rendered
        assert "[REDACTED]" in rendered or "content excluded" in rendered


def test_runtime_log_re_redacts_existing_segments_before_query_or_export(
    tmp_path: Path,
) -> None:
    log_root = tmp_path / "logs"
    log_root.mkdir()
    legacy_event = {
        "event_id": "100",
        "created_at": "2026-07-30T08:00:00+00:00",
        "level": "error",
        "source": "worker",
        "event_code": "legacy_event",
        "stream": "stderr",
        "message": (
            "Cookie: SESSION=legacy; tenant=secret "
            r"C:\Users\example\My Folder\secret.txt"
        ),
        "diagnostic_code": None,
        "job_id": None,
        "work_item_id": None,
    }
    (log_root / "runtime-20260730-0001.jsonl").write_text(
        json.dumps(legacy_event, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    store = RuntimeLogStore(
        log_root,
        now=lambda: datetime(2026, 7, 30, 9, tzinfo=UTC),
    )
    queried = json.dumps(store.query(limit=10), ensure_ascii=False)
    exported = store.export_text().decode("utf-8")

    for rendered in (queried, exported):
        assert "SESSION=legacy" not in rendered
        assert "tenant=secret" not in rendered
        assert r"C:\Users" not in rendered
        assert "[REDACTED]" in rendered


def test_runtime_log_is_concurrent_restart_safe_and_filterable(
    tmp_path: Path,
) -> None:
    log_root = tmp_path / "logs"
    store = RuntimeLogStore(log_root)

    def write(index: int) -> None:
        store.append(
            level="info",
            source="scheduler" if index % 2 else "api",
            event_code="test_event",
            stream="application",
            message=f"event {index}",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write, range(100)))

    first = store.query(limit=100)
    ids = [int(event["event_id"]) for event in first["events"]]
    assert len(ids) == 100
    assert ids == sorted(set(ids))

    restarted = RuntimeLogStore(log_root)
    event = restarted.append(
        level="warning",
        source="scheduler",
        event_code="restart_event",
        stream="application",
        message="after restart",
    )
    assert int(event["event_id"]) > ids[-1]
    filtered = restarted.query(level="warning", source="scheduler", limit=20)
    assert [item["event_code"] for item in filtered["events"]] == [
        "restart_event"
    ]


def test_runtime_log_rotates_and_enforces_age_and_total_limits(
    tmp_path: Path,
) -> None:
    current = datetime(2026, 7, 28, tzinfo=UTC)
    store = RuntimeLogStore(
        tmp_path / "logs",
        segment_bytes=350,
        total_bytes=900,
        retention=timedelta(days=7),
        now=lambda: current,
    )
    for index in range(30):
        store.append(
            level="info",
            source="test",
            event_code="rotation",
            stream="application",
            message=f"line {index} " + ("x" * 80),
        )

    files = list((tmp_path / "logs").glob("runtime-*.jsonl"))
    assert len(files) > 1
    assert sum(path.stat().st_size for path in files) <= 900

    old = tmp_path / "logs" / "runtime-20260701-0001.jsonl"
    old.write_text("{}\n", encoding="utf-8")
    store.prune()
    assert not old.exists()


def test_runtime_log_write_failure_does_not_raise(tmp_path: Path) -> None:
    occupied = tmp_path / "not-a-directory"
    occupied.write_text("occupied", encoding="utf-8")
    store = RuntimeLogStore(occupied)

    result = store.append(
        level="info",
        source="application",
        event_code="startup",
        stream="application",
        message="started",
    )

    assert result is None
    assert store.health_status()["status"] == "attention"
