from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dahe import __version__
from dahe.api.app import create_app as create_application

CLIENT_VERSION = __version__
ORIGIN = "http://127.0.0.1:8877"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def create_app(**values: Any) -> FastAPI:
    return create_application(
        project_root=PROJECT_ROOT,
        instance_id=f"test-{uuid4().hex}",
        **values,
    )


def _session(client: TestClient) -> str:
    response = client.get(
        "/api/v1/session",
        headers={
            "Host": "127.0.0.1:8877",
            "Origin": ORIGIN,
            "X-DaHe-Client-Version": CLIENT_VERSION,
        },
    )
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def _read_headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": CLIENT_VERSION,
    }


def _write_headers(csrf_token: str, idempotency_key: str) -> dict[str, str]:
    return {
        **_read_headers(),
        "X-CSRF-Token": csrf_token,
        "X-Idempotency-Key": idempotency_key,
    }


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=True,
        stage_delay_seconds=0.001,
    )
    with TestClient(app) as test_client:
        yield test_client


def _create_normal_job(client: TestClient, csrf_token: str, key: str) -> dict[str, Any]:
    response = client.post(
        "/api/v1/jobs",
        json={
            "task_type": "audit",
            "scope": {
                "label": "单条假数据审核",
                "fixture_id": "audit-normal-001",
            },
            "expected_record_version": 0,
        },
        headers=_write_headers(csrf_token, key),
    )
    assert response.status_code == 200
    return dict(response.json())


def _wait_for_terminal_job(client: TestClient, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get(
            f"/api/v1/jobs/{job_id}",
            headers=_read_headers(),
        )
        assert response.status_code == 200
        job = dict(response.json())
        if job["job_status"] in {"succeeded", "failed", "cancelled"}:
            return job
        time.sleep(0.01)
    raise AssertionError("the deterministic fake job did not reach a terminal state")


def test_meta_exposes_one_version_and_fake_adapter_boundary(client: TestClient) -> None:
    response = client.get(
        "/api/v1/meta",
        headers={
            "Host": "127.0.0.1:8877",
            "X-DaHe-Client-Version": CLIENT_VERSION,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "application_id": "DaHeLogistics",
        "application_version": CLIENT_VERSION,
        "api_version": "v1",
        "run_mode": "shadow",
        "real_platform_access": False,
        "platform_adapter": "fake",
        "ocr_adapter": "fake",
        "locked_set_review_enabled": False,
        "production_read_only": False,
    }


def test_version_mismatch_stops_before_reading_business_state(client: TestClient) -> None:
    response = client.get(
        "/api/v1/jobs",
        headers={
            "Host": "127.0.0.1:8877",
            "Origin": ORIGIN,
            "X-DaHe-Client-Version": "0.0.0-stale",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "client_version_mismatch"
    assert "刷新" in response.json()["error"]["message"]


def test_local_writes_require_session_csrf_and_idempotency(client: TestClient) -> None:
    response = client.post(
        "/api/v1/jobs",
        json={
            "task_type": "audit",
            "scope": {
                "label": "单条假数据审核",
                "fixture_id": "audit-normal-001",
            },
        },
        headers=_read_headers(),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "local_write_protection_failed"


def test_duplicate_start_uses_idempotency_key_and_finishes_one_normal_item(
    client: TestClient,
) -> None:
    csrf_token = _session(client)

    first = _create_normal_job(client, csrf_token, "loop2-create-normal")
    duplicate = _create_normal_job(client, csrf_token, "loop2-create-normal")

    assert first["created"] is True
    assert duplicate["created"] is False
    assert duplicate["job"]["job_id"] == first["job"]["job_id"]

    job = _wait_for_terminal_job(client, first["job"]["job_id"])
    assert job["job_status"] == "succeeded"
    assert job["run_mode"] == "shadow"
    assert job["display_name"] == "单条假数据审核"
    assert job["scope_label"] == "单条假数据审核"
    assert job["progress_label"] == "已处理 1/1，影子审核完成"  # noqa: RUF001
    assert job["counts"] == {
        "total": 1,
        "processed": 1,
        "remaining": 0,
        "waiting_user": 0,
        "failed": 0,
    }
    assert job["actions"]["view_results"] == {
        "visible": True,
        "enabled": True,
        "reason": None,
        "label": "查看审核结果",
    }

    items = client.get(
        f"/api/v1/jobs/{job['job_id']}/items",
        headers=_read_headers(),
    )
    assert items.status_code == 200
    assert items.json()["items"] == [
        {
            "work_item_id": items.json()["items"][0]["work_item_id"],
            "record_version": items.json()["items"][0]["record_version"],
            "waybill_number": "TEST-20260725-001",
            "vehicle_number": "测试车辆01",
            "status": "succeeded",
            "current_stage": "audit.finalize",
            "business_outcome": "normal_ready",
            "is_terminal_outcome": True,
            "platform_loading_net": "30.00",
            "platform_unloading_net": "29.80",
            "ticket_loading_net": "30.00",
            "ticket_unloading_net": "29.80",
            "decision": "pass",
            "review_reason": None,
        }
    ]


def test_queued_job_actions_are_entirely_supplied_by_backend(tmp_path: Path) -> None:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        csrf_token = _session(client)
        created = _create_normal_job(client, csrf_token, "loop2-queued")
        job = created["job"]

        assert job["job_status"] == "queued"
        assert job["status_label"] == "已排队，等待开始"  # noqa: RUF001
        assert job["actions"] == {
            "view_details": {
                "visible": True,
                "enabled": True,
                "reason": None,
                "label": "查看任务详情",
            },
            "pause": {
                "visible": True,
                "enabled": True,
                "reason": None,
                "label": "暂停此审核任务",
                "expected_record_version": job["record_version"],
            },
            "cancel": {
                "visible": True,
                "enabled": True,
                "reason": None,
                "label": "取消本次审核",
                "expected_record_version": job["record_version"],
            },
        }
        snapshot = client.get("/api/v1/jobs", headers=_read_headers())
        assert snapshot.status_code == 200
        assert snapshot.json()["start_actions"]["start_audit"] == {
            "visible": True,
            "enabled": False,
            "reason": "相同范围的审核任务正在运行",
            "label": "开始审核",
            "expected_record_version": 1,
        }


def test_normal_audit_can_pause_resume_and_cancel_through_the_api(
    tmp_path: Path,
) -> None:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        csrf_token = _session(client)
        job = _create_normal_job(
            client,
            csrf_token,
            "normal-controls-create",
        )["job"]

        pause = client.post(
            f"/api/v1/jobs/{job['job_id']}/pause",
            json={"expected_record_version": job["record_version"]},
            headers=_write_headers(csrf_token, "normal-controls-pause"),
        )
        assert pause.status_code == 200
        app.state.scheduler.tick()
        paused = client.get(
            f"/api/v1/jobs/{job['job_id']}",
            headers=_read_headers(),
        ).json()
        assert paused["job_status"] == "paused"
        assert "resume" in paused["actions"]

        resume = client.post(
            f"/api/v1/jobs/{job['job_id']}/resume",
            json={"expected_record_version": paused["record_version"]},
            headers=_write_headers(csrf_token, "normal-controls-resume"),
        )
        assert resume.status_code == 200
        resumed = resume.json()["job"]
        assert resumed["job_status"] == "queued"

        cancel = client.post(
            f"/api/v1/jobs/{job['job_id']}/cancel",
            json={"expected_record_version": resumed["record_version"]},
            headers=_write_headers(csrf_token, "normal-controls-cancel"),
        )
        assert cancel.status_code == 200
        app.state.scheduler.tick()
        cancelled = client.get(
            f"/api/v1/jobs/{job['job_id']}",
            headers=_read_headers(),
        ).json()
        assert cancelled["job_status"] == "cancelled"
        assert cancelled["counts"]["processed"] == 0
        assert cancelled["counts"]["remaining"] == 1


def test_page_refresh_can_restore_job_from_file_backed_temporary_sqlite(
    tmp_path: Path,
) -> None:
    first_app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(first_app) as first_client:
        csrf_token = _session(first_client)
        created = _create_normal_job(first_client, csrf_token, "loop2-persist")
        job_id = created["job"]["job_id"]

    second_app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(second_app) as second_client:
        _session(second_client)
        response = second_client.get("/api/v1/jobs", headers=_read_headers())

        assert response.status_code == 200
        assert [job["job_id"] for job in response.json()["jobs"]] == [job_id]
        assert response.json()["event_cursor"] >= 1


def test_unknown_host_and_forbidden_financial_routes_are_rejected(
    client: TestClient,
) -> None:
    unknown_host = client.get(
        "/api/v1/meta",
        headers={
            "Host": "attacker.example",
            "X-DaHe-Client-Version": CLIENT_VERSION,
        },
    )
    assert unknown_host.status_code == 400

    absent_write_route = client.post(
        "/api/v1/settlement/confirm",
        headers=_read_headers(),
    )
    assert absent_write_route.status_code == 404


def test_built_console_is_served_without_exposing_arbitrary_files(
    tmp_path: Path,
) -> None:
    static_dir = tmp_path / "frontend"
    static_dir.mkdir()
    (static_dir / "index.html").write_text(
        "<!doctype html><title>大禾物流</title>",
        encoding="utf-8",
    )
    (static_dir / "app.js").write_text("globalThis.daheLoaded = true;", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("must-not-be-served", encoding="utf-8")

    app = create_app(
        data_root=tmp_path / "data",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        static_dir=static_dir,
    )
    with TestClient(app) as static_client:
        index = static_client.get("/", headers={"Host": "127.0.0.1:8877"})
        asset = static_client.get("/app.js", headers={"Host": "127.0.0.1:8877"})
        traversal = static_client.get(
            "/../outside.txt",
            headers={"Host": "127.0.0.1:8877"},
        )

    assert index.status_code == 200
    assert "大禾物流" in index.text
    assert asset.status_code == 200
    assert "daheLoaded" in asset.text
    assert traversal.status_code == 404
