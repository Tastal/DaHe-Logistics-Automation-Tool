from __future__ import annotations

import hashlib
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dahe import __version__
from dahe.adapters.fake.audit import FAKE_UNLOADING_IMAGE_SHA256
from dahe.adapters.sqlite.repository import TemporarySchemaMismatchError
from dahe.api.app import create_app as create_application

CLIENT_VERSION = __version__
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def create_app(**values: Any) -> FastAPI:
    return create_application(
        project_root=PROJECT_ROOT,
        instance_id=f"test-{uuid4().hex}",
        **values,
    )


def _headers(host: str, port: int) -> dict[str, str]:
    origin = f"http://{host}:{port}"
    return {
        "Host": f"{host}:{port}",
        "Origin": origin,
        "X-DaHe-Client-Version": CLIENT_VERSION,
    }


def _session(client: TestClient, host: str, port: int) -> str:
    response = client.get("/api/v1/session", headers=_headers(host, port))
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def _create_job(
    client: TestClient,
    *,
    host: str,
    port: int,
    csrf_token: str,
    key: str,
) -> str:
    response = client.post(
        "/api/v1/jobs",
        json={
            "task_type": "audit",
            "scope": {
                "label": "Loop 2 failure fixture",
                "fixture_id": "audit-normal-001",
            },
            "expected_record_version": 0,
        },
        headers={
            **_headers(host, port),
            "X-CSRF-Token": csrf_token,
            "X-Idempotency-Key": key,
        },
    )
    assert response.status_code == 200
    return str(response.json()["job"]["job_id"])


def _wait_for_terminal(
    client: TestClient,
    job_id: str,
    *,
    host: str,
    port: int,
) -> dict[str, object]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get(
            f"/api/v1/jobs/{job_id}",
            headers=_headers(host, port),
        )
        assert response.status_code == 200
        job = dict(response.json())
        if job["job_status"] in {"succeeded", "failed", "cancelled"}:
            return job
        time.sleep(0.01)
    raise AssertionError("job did not reach a terminal state")


def test_failed_job_persists_diagnostic_without_business_review(
    tmp_path: Path,
) -> None:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=True,
        stage_delay_seconds=0,
    )
    app.state.scheduler.inject_ocr_failure(FAKE_UNLOADING_IMAGE_SHA256)
    with TestClient(app) as client:
        csrf = _session(client, "127.0.0.1", 8877)
        job_id = _create_job(
            client,
            host="127.0.0.1",
            port=8877,
            csrf_token=csrf,
            key="loop2-failed-diagnostic",
        )
        job = _wait_for_terminal(
            client,
            job_id,
            host="127.0.0.1",
            port=8877,
        )
        items_response = client.get(
            f"/api/v1/jobs/{job_id}/items",
            headers=_headers("127.0.0.1", 8877),
        )

    assert job["job_status"] == "failed"
    assert job["diagnostic_code"] == "LOOP3-FAKE-OCR-FAILURE"
    assert "系统处理失败" in str(job["progress_label"])
    assert "LOOP3-FAKE-OCR-FAILURE" in str(job["progress_label"])
    assert job["counts"] == {
        "total": 1,
        "processed": 1,
        "remaining": 0,
        "waiting_user": 0,
        "failed": 1,
    }
    item = items_response.json()["items"][0]
    assert item["status"] == "failed"
    assert item["business_outcome"] is None
    assert item["review_reason"] is None


def test_normal_audit_uses_the_unified_resource_scheduler(
    tmp_path: Path,
) -> None:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=True,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        csrf = _session(client, "127.0.0.1", 8877)
        job_id = _create_job(
            client,
            host="127.0.0.1",
            port=8877,
            csrf_token=csrf,
            key="loop2-ocr-port-guard",
        )
        job = _wait_for_terminal(
            client,
            job_id,
            host="127.0.0.1",
            port=8877,
        )

    assert job["job_status"] == "succeeded"
    attempts = app.state.repository.list_stage_attempts()
    resources = {
        attempt["resource_name"]
        for attempt in attempts
        if attempt["consumer_job_id"] == job_id
        and attempt["resource_name"] is not None
    }
    assert resources == {"platform_browser", "gpu_ocr_slot"}
    assert not hasattr(app.state, "runner")


def test_configured_non_default_host_and_port_define_local_boundary(
    tmp_path: Path,
) -> None:
    host = "127.0.0.1"
    port = 9123
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
        host=host,
        port=port,
    )
    with TestClient(app) as client:
        csrf = _session(client, host, port)
        meta = client.get("/api/v1/meta", headers=_headers(host, port))
        wrong_host = client.get(
            "/api/v1/meta",
            headers={
                "Host": "127.0.0.1:8877",
                "X-DaHe-Client-Version": CLIENT_VERSION,
            },
        )
        job_id = _create_job(
            client,
            host=host,
            port=port,
            csrf_token=csrf,
            key="loop2-non-default-port",
        )

    assert meta.status_code == 200
    assert wrong_host.status_code == 400
    assert job_id


def test_old_temporary_schema_is_ignored_without_modification(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    database_path = runtime_dir / "loop2-temporary.sqlite3"
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute(
            "CREATE TABLE system_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO system_meta (key, value) VALUES (?, ?)",
            ("temporary_schema_version", "2"),
        )
        connection.commit()
    original_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()

    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app):
        pass

    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == original_sha256
    assert not database_path.with_name(f"{database_path.name}-wal").exists()
    assert not database_path.with_name(f"{database_path.name}-shm").exists()
    assert (tmp_path / "database" / "dahe.sqlite3").is_file()


def test_unmanaged_formal_database_fails_without_write_or_lock(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("CREATE TABLE jobs (diagnostic_code TEXT)")
        connection.execute("CREATE TABLE work_items (placeholder TEXT)")
        connection.commit()
    original_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()

    with pytest.raises(
        TemporarySchemaMismatchError,
        match=r"no Alembic identity",
    ):
        create_app(
            data_root=tmp_path,
            auto_run_jobs=False,
            stage_delay_seconds=0,
        )

    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == original_sha256
    assert not database_path.with_name(f"{database_path.name}-wal").exists()
    assert not database_path.with_name(f"{database_path.name}-shm").exists()
