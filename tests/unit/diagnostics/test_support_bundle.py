from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dahe.diagnostics.breadcrumbs import BreadcrumbStore
from dahe.diagnostics.support_bundle import _runtime_version, build_support_bundle


def test_runtime_version_supports_browser_installation_manifest(tmp_path: Path) -> None:
    runtime_root = tmp_path / "browser"
    runtime_root.mkdir()
    (runtime_root / "runtime-installation.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "runtime_kind": "browser",
                "smoke_selected_browser": "msedge",
                "worker_source_sha256": "a" * 64,
                "packages": [
                    "playwright==1.61.0",
                    "dahe-browser-worker @ file:///C:/sensitive/developer/path",
                ],
            }
        ),
        encoding="utf-8",
    )

    version = _runtime_version(runtime_root)

    assert version == f"msedge; playwright=1.61.0; worker={'a' * 64}"
    assert "sensitive" not in version


def test_runtime_version_prefers_active_composition_generation(tmp_path: Path) -> None:
    runtime_root = tmp_path / "ocr"
    runtime_root.mkdir()
    (runtime_root / "active-composition.json").write_text(
        json.dumps({"generation_id": "ocr-generation-1"}),
        encoding="utf-8",
    )

    assert _runtime_version(runtime_root) == "ocr-generation-1"


def test_breadcrumbs_keep_only_the_small_allowed_action_contract(
    tmp_path: Path,
) -> None:
    store = BreadcrumbStore(tmp_path / "breadcrumbs.jsonl")

    store.append(
        page="settlement",
        action_type="start_job",
        job_id="a" * 32,
        result="succeeded",
        error_code=None,
        occurred_at=datetime.now(UTC),
    )
    store.append(
        page="运单号-SENSITIVE",
        action_type="cookie=secret",
        job_id="SXYD2026081000001",
        result="unknown",
        error_code="Bearer token",
        occurred_at=datetime.now(UTC),
    )

    events = [json.loads(line) for line in store.export(maximum_bytes=100_000).splitlines()]
    assert events[0]["job_id"] == "a" * 32
    assert events[1] == {
        "occurred_at": events[1]["occurred_at"],
        "page": "application",
        "action_type": "local_action",
        "job_id": None,
        "result": "failed",
        "error_code": None,
    }


def test_support_bundle_excludes_sensitive_data_and_redacts_logs(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    for name in ("database", "evidence", "browser-profile", "credentials"):
        directory = data_root / name
        directory.mkdir(parents=True)
        (directory / "SENSITIVE.bin").write_bytes(b"PRIVATE-PLATFORM-DATA")
    logs = data_root / "logs"
    logs.mkdir()
    (logs / "runtime-0001.jsonl").write_text(
        json.dumps(
            {
                "event_id": "1",
                "created_at": datetime.now(UTC).isoformat(),
                "level": "error",
                "source": "application",
                "event_code": "test",
                "stream": "application",
                "message": "token=secret-value",
                "diagnostic_code": "TEST-1",
                "job_id": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    breadcrumbs = BreadcrumbStore(data_root / "diagnostics" / "breadcrumbs.jsonl")
    content = build_support_bundle(
        data_root=data_root,
        snapshot={"application": {"version": "1.0.0"}},
        breadcrumbs=breadcrumbs,
        maximum_bytes=1024 * 1024,
    )

    assert len(content) <= 1024 * 1024
    with zipfile.ZipFile(io.BytesIO(content)) as bundle:
        assert set(bundle.namelist()) == {
            "README.txt",
            "breadcrumbs.jsonl",
            "environment.json",
            "runtime-logs.jsonl",
        }
        combined = b"".join(bundle.read(name) for name in bundle.namelist())
    assert b"PRIVATE-PLATFORM-DATA" not in combined
    assert b"secret-value" not in combined
    assert b"[REDACTED]" in combined


def test_support_bundle_keeps_only_runtime_logs_from_the_last_seven_days(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 12, 0, 0, tzinfo=UTC)
    data_root = tmp_path / "data"
    logs = data_root / "logs"
    logs.mkdir(parents=True)
    events = [
        {
            "event_id": "old",
            "created_at": (now - timedelta(days=7, seconds=1)).isoformat(),
            "level": "info",
            "source": "application",
            "event_code": "old_event",
            "stream": "application",
            "message": "old",
            "diagnostic_code": None,
            "job_id": None,
        },
        {
            "event_id": "recent",
            "created_at": (now - timedelta(days=7)).isoformat(),
            "level": "info",
            "source": "application",
            "event_code": "recent_event",
            "stream": "application",
            "message": "recent",
            "diagnostic_code": None,
            "job_id": None,
        },
    ]
    (logs / "runtime-0001.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    breadcrumbs = BreadcrumbStore(data_root / "diagnostics" / "breadcrumbs.jsonl")

    content = build_support_bundle(
        data_root=data_root,
        snapshot={"application": {"version": "1.0.0"}},
        breadcrumbs=breadcrumbs,
        maximum_bytes=1024 * 1024,
        now=now,
    )

    with zipfile.ZipFile(io.BytesIO(content)) as bundle:
        retained = [
            json.loads(line)
            for line in bundle.read("runtime-logs.jsonl").splitlines()
        ]
    assert [event["event_id"] for event in retained] == ["recent"]
