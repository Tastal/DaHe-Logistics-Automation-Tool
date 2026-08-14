from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from dahe import __version__
from dahe.api.app import create_app
from dahe.release.identity import ReleaseIdentity

PROJECT_ROOT = Path(__file__).parents[2]
ORIGIN = "http://127.0.0.1:8877"


def _headers(csrf: str | None = None) -> dict[str, str]:
    headers = {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }
    if csrf is not None:
        headers.update(
            {
                "X-CSRF-Token": csrf,
                "Idempotency-Key": "diagnostics-api-test",
            }
        )
    return headers


def test_local_diagnostic_package_and_environment_exclude_business_data(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    app = create_app(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id="system-diagnostics-api-test",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        release_identity=ReleaseIdentity(
            application_version=__version__,
            build_git_commit="a" * 40,
            resource_sha256="b" * 64,
        ),
    )
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        recorded = client.post(
            "/api/v1/diagnostics/breadcrumbs",
            headers=_headers(csrf),
            json={"page": "system", "action_type": "page_opened"},
        )
        environment = client.get(
            "/api/v1/diagnostics/environment",
            headers=_headers(),
        )
        exported = client.get(
            "/api/v1/diagnostics/support-bundle",
            headers=_headers(),
        )

    assert recorded.status_code == 202
    assert environment.status_code == 200
    assert environment.json()["database"]["schema_revision"] == (
        "0041_contract_subject_scope"
    )
    runtime = environment.json()["runtime"]
    assert set(runtime) == {
        "edge_worker",
        "ocr_cpu",
        "gpu_addon_state",
        "gpu_qualified",
        "primary_runtime",
        "cpu_fallback_available",
        "gpu_package_version",
        "diagnostic_code",
    }
    assert runtime["gpu_addon_state"] == "cpu_unavailable"
    assert runtime["gpu_qualified"] is False
    assert runtime["primary_runtime"] == "none"
    assert runtime["cpu_fallback_available"] is False
    assert runtime["gpu_package_version"] is None
    assert runtime["diagnostic_code"] == "ocr_cpu_unavailable"
    assert exported.status_code == 200
    assert len(exported.content) <= 20 * 1024 * 1024
    with zipfile.ZipFile(io.BytesIO(exported.content)) as bundle:
        assert "database/dahe.sqlite3" not in bundle.namelist()
        breadcrumbs = [
            json.loads(line)
            for line in bundle.read("breadcrumbs.jsonl").splitlines()
        ]
    assert any(event["action_type"] == "page_opened" for event in breadcrumbs)
    assert all("waybill" not in event for event in breadcrumbs)
