from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from dahe import __version__
from dahe.api.app import create_app
from dahe.application.chengfeng.shadow_batch import ShadowBatchTargetKind
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec

ORIGIN = "http://127.0.0.1:8877"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_SHA = "a" * 64
PIPELINE_SHA = "b" * 64


class _StubShadowJobSource:
    def __init__(self) -> None:
        self.calls: list[tuple[ShadowBatchTargetKind, str]] = []

    def resolve(
        self,
        *,
        target_kind: ShadowBatchTargetKind,
        manifest_sha256: str,
    ) -> ScheduledJobSpec:
        self.calls.append((target_kind, manifest_sha256))
        return ScheduledJobSpec(
            fixture_id=f"chengfeng-shadow:{target_kind.value}:{manifest_sha256}",
            job_kind="business",
            task_type="audit",
            scope_label=target_kind.value,
            conflict_key=(
                f"audit:chengfeng-shadow:{target_kind.value}:{manifest_sha256}"
            ),
            pipeline_fingerprint=PIPELINE_SHA,
            ocr_execution_mode="local",
            items=tuple(
                ScheduledWorkItemSpec(
                    item_key=f"CF-{index:03d}",
                    expected_outcome=None,
                    loading_image_sha256=f"{index + 1:064x}",
                    unloading_image_sha256=f"{index + 101:064x}",
                    loading_image_relative_path=(
                        f"evidence/sha256/{index + 1:064x}.blob"
                    ),
                    unloading_image_relative_path=(
                        f"evidence/sha256/{index + 101:064x}.blob"
                    ),
                    platform_loading_net="30.10",
                    platform_unloading_net="29.90",
                )
                for index in range(target_kind.expected_count)
            ),
        )


def _read_headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }


def _session(client: TestClient) -> str:
    response = client.get("/api/v1/session", headers=_read_headers())
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def _write_headers(csrf: str, key: str) -> dict[str, str]:
    return {
        **_read_headers(),
        "X-CSRF-Token": csrf,
        "Idempotency-Key": key,
    }


@pytest.fixture
def shadow_source() -> _StubShadowJobSource:
    return _StubShadowJobSource()


@pytest.fixture
def client(
    tmp_path: Path,
    shadow_source: _StubShadowJobSource,
) -> Iterator[TestClient]:
    app = create_app(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id=f"loop9-shadow-api-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_chengfeng_shadow=True,
        platform_build_sha256="c" * 64,
        chengfeng_shadow_job_source=shadow_source,
    )
    with TestClient(app) as test_client:
        yield test_client


def test_protected_shadow_source_creates_exact_existing_scheduler_job(
    client: TestClient,
    shadow_source: _StubShadowJobSource,
) -> None:
    csrf = _session(client)
    payload = {
        "input_source": "chengfeng_shadow",
        "task_type": "audit",
        "job_kind": "business",
        "chengfeng_shadow": {
            "target_kind": "real_shadow_30",
            "manifest_sha256": MANIFEST_SHA,
        },
        "expected_record_version": 0,
    }

    first = client.post(
        "/api/v1/jobs",
        json=payload,
        headers=_write_headers(csrf, "shadow-create-001"),
    )
    replay = client.post(
        "/api/v1/jobs",
        json=payload,
        headers=_write_headers(csrf, "shadow-create-001"),
    )

    assert first.status_code == 200
    assert replay.status_code == 200
    assert first.json()["created"] is True
    assert replay.json()["created"] is False
    assert first.json()["job"]["job_id"] == replay.json()["job"]["job_id"]
    assert first.json()["job"]["counts"]["total"] == 30
    assert shadow_source.calls == [
        (ShadowBatchTargetKind.REAL_SHADOW_30, MANIFEST_SHA),
        (ShadowBatchTargetKind.REAL_SHADOW_30, MANIFEST_SHA),
    ]


def test_shadow_source_rejects_fixture_fields_and_unknown_input(
    client: TestClient,
) -> None:
    csrf = _session(client)
    response = client.post(
        "/api/v1/jobs",
        json={
            "input_source": "chengfeng_shadow",
            "task_type": "audit",
            "job_kind": "business",
            "scope": {
                "label": "must not mix",
                "fixture_id": "audit-normal-001",
            },
            "chengfeng_shadow": {
                "target_kind": "real_shadow_30",
                "manifest_sha256": MANIFEST_SHA,
            },
            "expected_record_version": 0,
        },
        headers=_write_headers(csrf, "shadow-invalid-001"),
    )

    assert response.status_code == 422
