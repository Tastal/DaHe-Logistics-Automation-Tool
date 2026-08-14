from __future__ import annotations

import hashlib
import json
from pathlib import Path
from threading import Event
from types import SimpleNamespace

from fastapi.testclient import TestClient

from dahe import __version__
from dahe.api import app as api_app
from dahe.api.app import create_app
from dahe.jobs.models import JobStatus
from dahe.release.identity import ReleaseIdentity
from dahe.release.update_service import UpdateService

PROJECT_ROOT = Path(__file__).parents[2]
ORIGIN = "http://127.0.0.1:8877"


def _manifest() -> bytes:
    version = "1.1.1"
    root = "https://github.com/Tastal/DaHe-Logistics-Automation-Tool"
    payload = {
        "schema_version": 1,
        "repository": "Tastal/DaHe-Logistics-Automation-Tool",
        "version": version,
        "release_tag": f"v{version}",
        "build_git_commit": "d" * 40,
        "application": {
            "file_name": f"DaHe-Logistics-Automation-Tool-{version}-win-x64.zip",
            "sha256": "a" * 64,
            "size": 100,
            "url": (
                f"{root}/releases/download/v{version}/"
                f"DaHe-Logistics-Automation-Tool-{version}-win-x64.zip"
            ),
        },
        "gpu_addon": {
            "file_name": (
                f"DaHe-Logistics-Automation-Tool-{version}-gpu-addon-win-x64.zip"
            ),
            "sha256": "b" * 64,
            "size": 100,
            "url": (
                f"{root}/releases/download/v{version}/"
                f"DaHe-Logistics-Automation-Tool-{version}-gpu-addon-win-x64.zip"
            ),
        },
        "minimum_schema_revision": "0039_network_batch_default",
        "target_schema_revision": "0041_contract_subject_scope",
        "alembic_revision": "0041_contract_subject_scope",
        "minimum_updater_version": "1.0.0",
        "resource_sha256": "c" * 64,
    }
    return json.dumps(payload).encode()


class Fetcher:
    def fetch(self) -> bytes:
        return _manifest()


class Launcher:
    def __init__(self) -> None:
        self.calls = 0

    def launch(self, **_: object) -> None:
        self.calls += 1


def _headers(*, csrf: str | None = None) -> dict[str, str]:
    headers = {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }
    if csrf is not None:
        headers.update(
            {
                "X-CSRF-Token": csrf,
                "Idempotency-Key": "update-api-test",
            }
        )
    return headers


def _app(tmp_path: Path, launcher: Launcher):
    updater = tmp_path / "install" / "DaHeUpdater.exe"
    updater.parent.mkdir()
    updater.write_bytes(b"updater")
    service = UpdateService(
        current_version=__version__,
        updater_version="1.0.0",
        data_root=tmp_path / "data",
        updater_path=updater,
        fetcher=Fetcher(),
        launcher=launcher,
    )
    app = create_app(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="system-update-api-test",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        update_service=service,
        release_identity=ReleaseIdentity(
            application_version=__version__,
            build_git_commit="d" * 40,
            resource_sha256="e" * 64,
        ),
    )
    return app


def test_readiness_exposes_exact_release_and_schema_without_a_session(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path, Launcher())
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/system/readiness",
            headers={"Host": "127.0.0.1:8877"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "ready": True,
        "application_version": __version__,
        "build_git_commit": "d" * 40,
        "resource_sha256": "e" * 64,
        "schema_revision": "0041_contract_subject_scope",
    }


def test_update_check_is_explicit_and_install_requests_safe_shutdown(
    tmp_path: Path,
) -> None:
    launcher = Launcher()
    app = _app(tmp_path, launcher)
    shutdown = Event()
    app.state.request_shutdown = shutdown.set
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        checked = client.post(
            "/api/v1/system/updates/check",
            headers=_headers(csrf=csrf),
        )
        installed = client.post(
            "/api/v1/system/updates/install",
            headers=_headers(csrf=csrf),
        )

        assert checked.status_code == 200
        assert checked.json()["state"] == "available"
        assert installed.status_code == 202
        assert installed.json()["state"] == "installing"
        assert shutdown.wait(timeout=1)
    assert launcher.calls == 1


def test_update_install_is_blocked_while_any_job_can_resume(
    tmp_path: Path,
) -> None:
    launcher = Launcher()
    app = _app(tmp_path, launcher)
    app.state.request_shutdown = lambda: None
    app.state.repository.create_job(
        task_type="audit",
        scope_label="active",
        scope_fixture_id="audit-normal-001",
        idempotency_key="active-job",
        request_hash="f" * 64,
    )
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        client.post(
            "/api/v1/system/updates/check",
            headers=_headers(csrf=csrf),
        )
        response = client.post(
            "/api/v1/system/updates/install",
            headers=_headers(csrf=csrf),
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "software_update_blocked"
    assert launcher.calls == 0


def test_waiting_review_results_do_not_block_an_update() -> None:
    jobs = [
        SimpleNamespace(status=JobStatus.WAITING_USER),
        SimpleNamespace(status=JobStatus.SUCCEEDED),
        SimpleNamespace(status=JobStatus.RUNNING),
        SimpleNamespace(status=JobStatus.PAUSED),
        SimpleNamespace(status=JobStatus.RETRY_WAIT),
        SimpleNamespace(status=JobStatus.WAITING_EXTERNAL),
    ]

    assert api_app._count_update_blocking_jobs(jobs) == 4


def test_local_update_import_streams_and_uses_the_same_install_action(
    tmp_path: Path,
) -> None:
    launcher = Launcher()
    app = _app(tmp_path, launcher)
    app.state.request_shutdown = lambda: None
    archive = b"verified local application zip"
    manifest = json.loads(_manifest().decode())
    manifest["application"]["size"] = len(archive)
    manifest["application"]["sha256"] = hashlib.sha256(archive).hexdigest()
    content = json.dumps(manifest).encode()
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        created = client.post(
            "/api/v1/system/updates/imports",
            headers={**_headers(csrf=csrf), "Content-Type": "application/json"},
            content=content,
        )
        assert created.status_code == 201, created.text
        imported = created.json()
        uploaded = client.put(
            f"/api/v1/system/updates/imports/{imported['import_id']}",
            headers={
                **_headers(csrf=csrf),
                "Content-Type": "application/octet-stream",
                "X-DaHe-Update-File-Name": imported["application_file_name"],
            },
            content=archive,
        )
        installed = client.post(
            "/api/v1/system/updates/install",
            headers=_headers(csrf=csrf),
        )

    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["state"] == "available"
    assert installed.status_code == 202, installed.text
    assert launcher.calls == 1


def test_local_update_import_rejects_a_wrong_application_zip(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path, Launcher())
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        created = client.post(
            "/api/v1/system/updates/imports",
            headers={**_headers(csrf=csrf), "Content-Type": "application/json"},
            content=_manifest(),
        )
        imported = created.json()
        uploaded = client.put(
            f"/api/v1/system/updates/imports/{imported['import_id']}",
            headers={
                **_headers(csrf=csrf),
                "Content-Type": "application/octet-stream",
                "X-DaHe-Update-File-Name": imported["application_file_name"],
            },
            content=b"wrong",
        )

    assert uploaded.status_code == 422
    assert uploaded.json()["error"]["code"] == "update_import_asset_invalid"
