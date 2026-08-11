from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from fastapi.testclient import TestClient

from dahe import __version__
from dahe.adapters.chengfeng.browser_runtime import BrowserRuntime
from dahe.api.app import create_app

ORIGIN = "http://127.0.0.1:8877"


class _BrowserWithoutPlatformActions:
    def __init__(self) -> None:
        self.action_calls: list[str] = []
        self.close_count = 0

    @property
    def available(self) -> bool:
        return True

    @property
    def running(self) -> bool:
        return False

    @property
    def selected_browser(self) -> str | None:
        return None

    @property
    def discovery_capturing(self) -> bool:
        return False

    def start_human_login(self) -> str:
        self.action_calls.append("start_human_login")
        raise AssertionError("scheduler probe must not start a platform browser")

    def start_discovery_capture(self) -> None:
        self.action_calls.append("start_discovery_capture")
        raise AssertionError("scheduler probe must not capture platform traffic")

    def stop_discovery_capture(self) -> list[dict[str, object]]:
        self.action_calls.append("stop_discovery_capture")
        raise AssertionError("scheduler probe must not capture platform traffic")

    def prepare_automated(
        self,
        *,
        scope: str = "current",
    ) -> object:
        del scope
        self.action_calls.append("prepare_automated")
        raise AssertionError("scheduler probe must not issue a platform request")

    def prepare_daily(self) -> dict[str, object]:
        self.action_calls.append("prepare_daily")
        raise AssertionError("scheduler probe must not issue a platform request")

    def close(self) -> None:
        self.close_count += 1


def _read_headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }


def _write_headers(csrf: str, key: str) -> dict[str, str]:
    return {
        **_read_headers(),
        "X-CSRF-Token": csrf,
        "Idempotency-Key": key,
    }


def _post_job(
    client: TestClient,
    csrf: str,
    *,
    fixture_id: str,
    task_type: str,
    job_kind: str,
    key: str,
) -> Any:
    return client.post(
        "/api/v1/jobs",
        json={
            "task_type": task_type,
            "job_kind": job_kind,
            "scope": {
                "label": fixture_id,
                "fixture_id": fixture_id,
            },
            "expected_record_version": 0,
        },
        headers=_write_headers(csrf, key),
    )


def test_shadow_scheduler_probe_is_the_only_fixture_and_never_uses_platform(
    project_root: Path,
    tmp_path: Path,
) -> None:
    browser = _BrowserWithoutPlatformActions()
    app = create_app(
        data_root=tmp_path / "shadow-data",
        project_root=project_root,
        instance_id="loop9-safe-scheduler-probe",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_chengfeng_shadow=True,
        enable_loop9_scheduler_probe=True,
        platform_build_sha256="a" * 64,
        browser_runtime=cast(BrowserRuntime, browser),
    )

    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_read_headers())
        assert session.status_code == 200
        csrf = str(session.json()["csrf_token"])

        start_state = client.get("/api/v1/jobs", headers=_read_headers())
        assert start_state.status_code == 200
        assert set(start_state.json()["start_actions"]) == {
            "start_loading_probe"
        }

        audit_fixture = _post_job(
            client,
            csrf,
            fixture_id="audit-batch-long-001",
            task_type="audit",
            job_kind="test_fixture",
            key="loop9-reject-audit-fixture",
        )
        assert audit_fixture.status_code == 403
        assert audit_fixture.json()["error"]["code"] == "test_fixture_disabled"

        ordinary_audit = _post_job(
            client,
            csrf,
            fixture_id="audit-normal-001",
            task_type="audit",
            job_kind="business",
            key="loop9-reject-ordinary-audit",
        )
        assert ordinary_audit.status_code == 403
        assert ordinary_audit.json()["error"]["code"] == (
            "loop9_scheduler_probe_only"
        )

        created = _post_job(
            client,
            csrf,
            fixture_id="loading-probe-001",
            task_type="loading_probe",
            job_kind="test_fixture",
            key="loop9-create-safe-probe",
        )
        assert created.status_code == 200, created.text
        job = dict(created.json()["job"])
        assert job["job_kind"] == "test_fixture"
        assert job["scope"]["fixture_id"] == "loading-probe-001"

        for _ in range(30):
            app.state.scheduler.tick()
            if not app.state.scheduler.has_automatic_work():
                break
        else:
            raise AssertionError("scheduler probe did not become quiescent")

        items = client.get(
            f"/api/v1/jobs/{job['job_id']}/items",
            headers=_read_headers(),
        )
        assert items.status_code == 200
        assert len(items.json()["items"]) == 2
        assert all(
            item["business_outcome"] is None
            for item in items.json()["items"]
        )
        final_job = client.get(
            f"/api/v1/jobs/{job['job_id']}",
            headers=_read_headers(),
        )
        assert final_job.status_code == 200
        assert final_job.json()["job_status"] == "succeeded"
        assert browser.action_calls == []

    assert browser.action_calls == []
    assert browser.close_count == 1
