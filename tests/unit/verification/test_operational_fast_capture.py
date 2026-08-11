from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from dahe.verification.operational_fast_capture import (
    OperationalFastCaptureEvidenceError,
    build_operational_fast_capture_evidence,
    publish_operational_fast_capture_evidence,
)

JOB_ID = "a" * 32


def _prepare_daily_capture(data_root: Path) -> None:
    database = data_root / "database" / "dahe.sqlite3"
    database.parent.mkdir(parents=True)
    evidence_root = data_root / "evidence"
    evidence_root.mkdir()
    images: dict[str, dict[str, object]] = {}
    tickets: list[dict[str, str]] = []
    for slot, content in (("loading", b"loading-image"), ("unloading", b"unloading-image")):
        sha256 = hashlib.sha256(content).hexdigest()
        relative_path = f"sha256/{sha256}.jpeg"
        (evidence_root / relative_path).parent.mkdir(parents=True, exist_ok=True)
        (evidence_root / relative_path).write_bytes(content)
        ticket_ref = f"ticket-{slot}"
        tickets.append(
            {
                "slot": slot,
                "ticket_ref": ticket_ref,
            }
        )
        images[ticket_ref] = {
            "ticket_ref": ticket_ref,
            "sha256": sha256,
            "relative_path": relative_path,
            "byte_size": len(content),
            "media_type": "image/jpeg",
        }
    items = [
        {
            "platform_waybill_id": "platform-1",
            "vehicle_number": "TEST-1",
            "waybill_number": "YD-1",
        }
    ]
    items_json = json.dumps(
        items,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    checkpoint = {
        "job_id": JOB_ID,
        "scope": "daily:2026-07-31",
        "page_number": 1,
        "page_size": 15,
        "page": {"items": items},
        "details": [
            {
                "platform_waybill_id": "platform-1",
                "tickets": tickets,
            }
        ],
        "ticket_images": images,
    }
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE jobs (
                job_id TEXT PRIMARY KEY,
                task_type TEXT NOT NULL,
                status TEXT NOT NULL,
                diagnostic_code TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE operational_capture_runs (
                job_id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                total INTEGER NOT NULL,
                items_json TEXT NOT NULL,
                items_sha256 TEXT NOT NULL,
                next_item_index INTEGER NOT NULL,
                committed_batch_count INTEGER NOT NULL,
                batch_size INTEGER NOT NULL,
                detail_concurrency INTEGER NOT NULL,
                image_concurrency INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE checkpoints (
                owner_kind TEXT NOT NULL,
                job_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE daily_operational_ocr_batches (
                daily_job_id TEXT NOT NULL,
                batch_number INTEGER NOT NULL,
                ocr_job_id TEXT,
                eligible_item_count INTEGER NOT NULL,
                missing_ticket_count INTEGER NOT NULL
            );
            CREATE TABLE work_items (
                job_id TEXT NOT NULL,
                status TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO jobs VALUES (?, 'daily', 'succeeded', NULL, ?)",
            (JOB_ID, "2026-08-01T00:00:00+00:00"),
        )
        connection.execute(
            "INSERT INTO jobs VALUES (?, 'audit', 'succeeded', NULL, ?)",
            ("b" * 32, "2026-08-01T00:00:01+00:00"),
        )
        connection.execute(
            "INSERT INTO operational_capture_runs VALUES "
            "(?, 'daily:2026-07-31', 1, ?, ?, 1, 1, 15, 4, 6, "
            "'complete', ?, ?)",
            (
                JOB_ID,
                items_json,
                hashlib.sha256(items_json.encode()).hexdigest(),
                "2026-08-01T00:00:01+00:00",
                "2026-08-01T00:00:02+00:00",
            ),
        )
        connection.execute(
            "INSERT INTO checkpoints VALUES ('chengfeng_capture', ?, 1, ?)",
            (JOB_ID, json.dumps(checkpoint, ensure_ascii=False)),
        )
        connection.execute(
            "INSERT INTO daily_operational_ocr_batches VALUES (?, 1, ?, 1, 0)",
            (JOB_ID, "b" * 32),
        )
        connection.execute(
            "INSERT INTO work_items VALUES (?, 'succeeded')",
            ("b" * 32,),
        )


def _expand_capture_to_full_batch(data_root: Path) -> None:
    database = data_root / "database" / "dahe.sqlite3"
    with sqlite3.connect(database) as connection:
        checkpoint = json.loads(
            str(
                connection.execute(
                    "SELECT payload_json FROM checkpoints WHERE job_id = ?",
                    (JOB_ID,),
                ).fetchone()[0]
            )
        )
        source_images = checkpoint["ticket_images"]
        loading_image = source_images["ticket-loading"]
        unloading_image = source_images["ticket-unloading"]
        items: list[dict[str, str]] = []
        details: list[dict[str, object]] = []
        images: dict[str, dict[str, object]] = {}
        for index in range(1, 16):
            platform_id = f"platform-{index}"
            items.append(
                {
                    "platform_waybill_id": platform_id,
                    "vehicle_number": f"TEST-{index}",
                    "waybill_number": f"YD-{index}",
                }
            )
            tickets: list[dict[str, str]] = []
            for slot, source_image in (
                ("loading", loading_image),
                ("unloading", unloading_image),
            ):
                ticket_ref = f"ticket-{slot}-{index}"
                tickets.append({"slot": slot, "ticket_ref": ticket_ref})
                images[ticket_ref] = {
                    **source_image,
                    "ticket_ref": ticket_ref,
                }
            details.append(
                {
                    "platform_waybill_id": platform_id,
                    "tickets": tickets,
                }
            )
        items_json = json.dumps(
            items,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        checkpoint.update(
            page={"items": items},
            details=details,
            ticket_images=images,
        )
        connection.execute(
            "UPDATE operational_capture_runs SET total = 15, items_json = ?, "
            "items_sha256 = ?, next_item_index = 15 WHERE job_id = ?",
            (
                items_json,
                hashlib.sha256(items_json.encode()).hexdigest(),
                JOB_ID,
            ),
        )
        connection.execute(
            "UPDATE checkpoints SET payload_json = ? WHERE job_id = ?",
            (json.dumps(checkpoint, ensure_ascii=False), JOB_ID),
        )


def test_builds_complete_daily_fast_capture_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    _prepare_daily_capture(data_root)

    evidence = build_operational_fast_capture_evidence(
        project_root=project_root,
        data_root=data_root,
        job_id=JOB_ID,
    )

    assert evidence.payload["kind"] == "operational_fast_capture_evidence"
    assert evidence.payload["capture"] == {
        "dynamic_total": 1,
        "fetched": 1,
        "unique_identity_count": 1,
        "identity_manifest_sha256": hashlib.sha256(
            json.dumps(
                [
                    {
                        "platform_waybill_id": "platform-1",
                        "vehicle_number": "TEST-1",
                        "waybill_number": "YD-1",
                    }
                ],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "committed_batch_count": 1,
        "batch_size": 15,
        "detail_concurrency": 4,
        "image_concurrency": 6,
        "ticket_image_count": 2,
        "ticket_image_manifest_sha256": evidence.payload["capture"][
            "ticket_image_manifest_sha256"
        ],
        "missing_ticket_count": 0,
    }
    assert evidence.payload["ocr"] == {
        "eligible": 1,
        "missing_ticket": 0,
        "recognized": 1,
        "technical_failed": 0,
    }
    assert evidence.payload["performance"]["gate_passed"] is True
    assert evidence.payload["performance"]["throughput_gate_applied"] is False
    assert evidence.payload["performance"]["throughput_gate_passed"] is None


def test_daily_capture_records_slow_throughput_without_failing(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    _prepare_daily_capture(data_root)
    database = data_root / "database" / "dahe.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE operational_capture_runs SET updated_at = ? WHERE job_id = ?",
            ("2026-08-01T00:10:00+00:00", JOB_ID),
        )

    evidence = build_operational_fast_capture_evidence(
        project_root=project_root,
        data_root=data_root,
        job_id=JOB_ID,
    )

    assert evidence.payload["performance"]["waybills_per_minute"] == 0.1
    assert evidence.payload["performance"]["throughput_gate_applied"] is False
    assert evidence.payload["performance"]["throughput_gate_passed"] is None
    assert evidence.payload["performance"]["gate_passed"] is True


def test_builds_current_settlement_fast_capture_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    _prepare_daily_capture(data_root)
    _expand_capture_to_full_batch(data_root)
    database = data_root / "database" / "dahe.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE jobs SET task_type = 'settlement_capture' WHERE job_id = ?",
            (JOB_ID,),
        )
        connection.execute(
            "UPDATE operational_capture_runs SET scope = 'current' "
            "WHERE job_id = ?",
            (JOB_ID,),
        )
        checkpoint = json.loads(
            str(
                connection.execute(
                    "SELECT payload_json FROM checkpoints WHERE job_id = ?",
                    (JOB_ID,),
                ).fetchone()[0]
            )
        )
        checkpoint["scope"] = "current"
        connection.execute(
            "UPDATE checkpoints SET payload_json = ? WHERE job_id = ?",
            (json.dumps(checkpoint, ensure_ascii=False), JOB_ID),
        )

    evidence = build_operational_fast_capture_evidence(
        project_root=project_root,
        data_root=data_root,
        job_id=JOB_ID,
    )

    assert evidence.payload["task_type"] == "settlement_capture"
    assert evidence.payload["scope"] == "current"
    assert evidence.payload["ocr"] is None
    assert evidence.payload["performance"]["throughput_gate_applied"] is True
    assert evidence.payload["performance"]["throughput_gate_passed"] is True


def test_small_settlement_capture_records_throughput_without_applying_gate(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    _prepare_daily_capture(data_root)
    database = data_root / "database" / "dahe.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE jobs SET task_type = 'settlement_capture' WHERE job_id = ?",
            (JOB_ID,),
        )
        connection.execute(
            "UPDATE operational_capture_runs SET scope = 'current', updated_at = ? "
            "WHERE job_id = ?",
            ("2026-08-01T00:10:00+00:00", JOB_ID),
        )
        checkpoint = json.loads(
            str(
                connection.execute(
                    "SELECT payload_json FROM checkpoints WHERE job_id = ?",
                    (JOB_ID,),
                ).fetchone()[0]
            )
        )
        checkpoint["scope"] = "current"
        connection.execute(
            "UPDATE checkpoints SET payload_json = ? WHERE job_id = ?",
            (json.dumps(checkpoint, ensure_ascii=False), JOB_ID),
        )

    evidence = build_operational_fast_capture_evidence(
        project_root=project_root,
        data_root=data_root,
        job_id=JOB_ID,
    )

    performance = evidence.payload["performance"]
    assert performance["waybills_per_minute"] == 0.1
    assert performance["throughput_gate_applied"] is False
    assert performance["throughput_gate_reason"] == (
        "dynamic_total_below_one_batch"
    )
    assert performance["throughput_gate_passed"] is None
    assert performance["gate_passed"] is True


def test_rejects_slow_settlement_capture(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    _prepare_daily_capture(data_root)
    _expand_capture_to_full_batch(data_root)
    database = data_root / "database" / "dahe.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE jobs SET task_type = 'settlement_capture' WHERE job_id = ?",
            (JOB_ID,),
        )
        connection.execute(
            "UPDATE operational_capture_runs SET scope = 'current', updated_at = ? "
            "WHERE job_id = ?",
            ("2026-08-01T00:10:00+00:00", JOB_ID),
        )
        checkpoint = json.loads(
            str(
                connection.execute(
                    "SELECT payload_json FROM checkpoints WHERE job_id = ?",
                    (JOB_ID,),
                ).fetchone()[0]
            )
        )
        checkpoint["scope"] = "current"
        connection.execute(
            "UPDATE checkpoints SET payload_json = ? WHERE job_id = ?",
            (json.dumps(checkpoint, ensure_ascii=False), JOB_ID),
        )

    with pytest.raises(
        OperationalFastCaptureEvidenceError,
        match="capture performance gate did not pass",
    ):
        build_operational_fast_capture_evidence(
            project_root=project_root,
            data_root=data_root,
            job_id=JOB_ID,
        )


def test_rejects_tampered_content_addressed_image(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    _prepare_daily_capture(data_root)
    image = next(
        candidate
        for candidate in (data_root / "evidence").rglob("*")
        if candidate.is_file()
    )
    image.write_bytes(b"tampered")

    with pytest.raises(
        OperationalFastCaptureEvidenceError,
        match="content-addressed ticket image",
    ):
        build_operational_fast_capture_evidence(
            project_root=project_root,
            data_root=data_root,
            job_id=JOB_ID,
        )


def test_publishes_once_without_overwrite(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    _prepare_daily_capture(data_root)
    evidence = build_operational_fast_capture_evidence(
        project_root=project_root,
        data_root=data_root,
        job_id=JOB_ID,
    )
    output = (tmp_path / "result.json").resolve()

    assert publish_operational_fast_capture_evidence(
        evidence=evidence,
        output=output,
    ) == output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["canonical_sha256"] == evidence.canonical_sha256
    with pytest.raises(
        OperationalFastCaptureEvidenceError,
        match="already exists",
    ):
        publish_operational_fast_capture_evidence(
            evidence=evidence,
            output=output,
        )
