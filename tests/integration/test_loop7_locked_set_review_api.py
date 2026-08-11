from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image

from dahe import __version__
from dahe.api import locked_set_review as locked_set_review_api
from dahe.api.app import create_app
from dahe.application.template_studio.candidate_review_seal import (
    CandidateReviewSealError,
)
from tests.fixtures.formal_development_authority import (
    formal_development_authority,
)

pytestmark = pytest.mark.integration

CLIENT_VERSION = __version__
ORIGIN = "http://127.0.0.1:8877"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _png_bytes(index: int) -> bytes:
    output = io.BytesIO()
    Image.new(
        "RGB",
        (3, 2),
        color=(index % 251, (index * 19) % 251, (index * 37) % 251),
    ).save(output, format="PNG")
    return output.getvalue()


def _write_review_package(data_root: Path) -> dict[str, object]:
    review_root = data_root / "locked-set-review"
    image_root = review_root / "images"
    image_root.mkdir(parents=True)
    development_authority = formal_development_authority()
    waybills: list[dict[str, object]] = []
    for position in range(1, 51):
        images: list[dict[str, object]] = []
        for slot_offset, slot in enumerate(("loading", "unloading")):
            content = _png_bytes((position - 1) * 2 + slot_offset)
            digest = hashlib.sha256(content).hexdigest()
            relative_path = f"images/{digest}.png"
            (review_root / relative_path).write_bytes(content)
            images.append(
                {
                    "submitted_slot": slot,
                    "image_sha256": digest,
                    "relative_path": relative_path,
                    "width": 3,
                    "height": 2,
                    "selection_clues": ["rotation_0_hint"],
                    "human_review": {
                        "role": None,
                        "ordinary_net": None,
                        "quality_conditions": [],
                        "notes": None,
                    },
                }
            )
        waybills.append(
            {
                "sample_id": f"L7-{position:03d}",
                "candidate_id": f"candidate-{position:03d}",
                "waybill_identity_sha256": hashlib.sha256(
                    f"waybill-{position}".encode()
                ).hexdigest(),
                "selection_clues": ["legacy_review_hint"] if position == 2 else [],
                "images": images,
                "pair_review": {"conditions": [], "notes": None},
                "review_status": "pending",
                "record_version": 0,
                "reviewer_id": None,
                "reviewed_at": None,
            }
        )
    external_core = {
        "image_sha256s": sorted(development_authority.image_sha256s),
        "schema_version": 1,
        "source_file_sha256s": [
            development_authority.authority_sha256
        ],
        "waybill_identity_sha256s": sorted(
            development_authority.waybill_identity_sha256s
        ),
    }
    external_snapshot = {
        "schema_version": 1,
        "image_identity_count": len(development_authority.image_sha256s),
        "waybill_identity_count": len(
            development_authority.waybill_identity_sha256s
        ),
        "source_file_sha256s": external_core["source_file_sha256s"],
        "canonical_sha256": _canonical_sha256(external_core),
        "image_sha256s": external_core["image_sha256s"],
        "waybill_identity_sha256s": external_core[
            "waybill_identity_sha256s"
        ],
    }
    (review_root / "external-exclusion-snapshot.json").write_text(
        json.dumps(external_snapshot, ensure_ascii=False),
        encoding="utf-8",
    )
    (review_root / "development-authority.json").write_bytes(
        (
            json.dumps(
                development_authority.payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )
    without_hash: dict[str, object] = {
        "schema_version": 1,
        "kind": "locked_set_candidate_review",
        "package_id": "loop7-review-api-test",
        "status": "awaiting_human_review",
        "generated_at": "2026-07-26T00:00:00+00:00",
        "tuning_prohibited": True,
        "source_snapshot": {
            "manifest_sha256s": ["a" * 64],
            "candidate_index_sha256": "b" * 64,
            "exclusion_snapshot_sha256": _canonical_sha256(
                {
                    "excluded_image_sha256s": external_core[
                        "image_sha256s"
                    ],
                    "excluded_waybill_identity_sha256s": external_core[
                        "waybill_identity_sha256s"
                    ],
                    "schema_version": 1,
                }
            ),
            "external_exclusion_snapshot_sha256": external_snapshot[
                "canonical_sha256"
            ],
            "external_exclusion_file_sha256": _canonical_sha256(
                external_snapshot
            ),
            "development_authority_sha256": (
                development_authority.authority_sha256
            ),
            "development_authority_file_sha256": _canonical_sha256(
                development_authority.payload
            ),
            "excluded_waybill_count": 0,
            "conflicting_source_waybill_count": 0,
        },
        "waybills": waybills,
    }
    payload = {
        **without_hash,
        "canonical_sha256": _canonical_sha256(without_hash),
    }
    (review_root / "review-package.json").write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
    return payload


def _app(data_root: Path, **values: Any) -> FastAPI:
    return create_app(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id=f"loop7-review-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_locked_set_review=True,
        **values,
    )


def _read_headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": CLIENT_VERSION,
    }


def _session(client: TestClient) -> str:
    response = client.get("/api/v1/session", headers=_read_headers())
    assert response.status_code == 200
    assert response.json()["locked_set_review_enabled"] is True
    return str(response.json()["csrf_token"])


def _write_headers(csrf_token: str, idempotency_key: str) -> dict[str, str]:
    return {
        **_read_headers(),
        "X-CSRF-Token": csrf_token,
        "Idempotency-Key": idempotency_key,
    }


def _confirmed_payload(*, expected_record_version: int) -> dict[str, object]:
    return {
        "expected_record_version": expected_record_version,
        "decision": "confirmed",
        "images": [
            {
                "submitted_slot": "loading",
                "role": "loading",
                "ordinary_net": "31.25",
                "quality_conditions": ["printed", "rotation_0"],
                "notes": None,
            },
            {
                "submitted_slot": "unloading",
                "role": "unloading",
                "ordinary_net": "31.20",
                "quality_conditions": ["screen", "rotation_90"],
                "notes": "右侧轻微裁边",
            },
        ],
        "pair_conditions": ["normal_pair"],
        "pair_notes": None,
        "replace_reason": None,
    }


def test_review_api_exposes_authoritative_progress_and_optimistic_writes(
    tmp_path: Path,
) -> None:
    _write_review_package(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        csrf = _session(client)
        meta = client.get("/api/v1/meta", headers=_read_headers())
        assert meta.status_code == 200
        assert meta.json()["locked_set_review_enabled"] is True
        assert meta.json()["ocr_adapter"] == "disabled"

        index = client.get("/api/v1/locked-set-review", headers=_read_headers())
        assert index.status_code == 200
        assert index.json()["package"] == {
            "package_id": "loop7-review-api-test",
            "status": "awaiting_human_review",
        }
        assert index.json()["progress"] == {
            "total": 50,
            "completed": 0,
            "remaining": 50,
            "replace_candidate": 0,
        }
        assert index.json()["items"][0] == {
            "sample_id": "L7-001",
            "position": 1,
            "review_status": "pending",
            "record_version": 0,
            "decision": None,
        }

        detail = client.get(
            "/api/v1/locked-set-review/items/L7-001",
            headers=_read_headers(),
        )
        assert detail.status_code == 200
        assert detail.json()["record_version"] == 0
        assert "reviewer_id" not in detail.json()
        assert detail.json()["images"][0]["image_url"].startswith(
            "/api/v1/locked-set-review/images/"
        )

        saved = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=_confirmed_payload(expected_record_version=0),
            headers=_write_headers(csrf, "confirm-l7-001-v1"),
        )
        assert saved.status_code == 200, saved.text
        assert saved.json()["item"]["record_version"] == 1
        assert saved.json()["item"]["review_status"] == "confirmed"
        assert saved.json()["item"]["images"][0]["human_review"]["ordinary_net"] == "31.25"
        assert saved.json()["progress"]["completed"] == 1

        replay = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=_confirmed_payload(expected_record_version=0),
            headers=_write_headers(csrf, "confirm-l7-001-v1"),
        )
        assert replay.status_code == 200
        assert replay.json()["item"]["record_version"] == 1

        updated_payload = _confirmed_payload(expected_record_version=1)
        updated_payload["pair_notes"] = "second immutable version"
        updated = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=updated_payload,
            headers=_write_headers(csrf, "confirm-l7-001-v2"),
        )
        assert updated.status_code == 200
        assert updated.json()["item"]["record_version"] == 2

        exact_replay = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=_confirmed_payload(expected_record_version=0),
            headers=_write_headers(csrf, "confirm-l7-001-v1"),
        )
        assert exact_replay.status_code == 200
        assert exact_replay.json()["item"]["record_version"] == 1
        assert exact_replay.json()["item"]["pair_review"]["notes"] is None

        current = client.get(
            "/api/v1/locked-set-review/items/L7-001",
            headers=_read_headers(),
        )
        assert current.status_code == 200
        assert current.json()["record_version"] == 2
        assert (
            current.json()["pair_review"]["notes"]
            == "second immutable version"
        )

        reused_payload = _confirmed_payload(expected_record_version=0)
        reused_payload["pair_notes"] = "different review input"
        reused = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=reused_payload,
            headers=_write_headers(csrf, "confirm-l7-001-v1"),
        )
        assert reused.status_code == 409
        assert reused.json()["error"]["code"] == "idempotency_key_reused"

        stale = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=_confirmed_payload(expected_record_version=0),
            headers=_write_headers(csrf, "stale-l7-001"),
        )
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "record_version_conflict"

        replacement = client.post(
            "/api/v1/locked-set-review/items/L7-002/review",
            json={
                "expected_record_version": 0,
                "decision": "replace_candidate",
                "replace_reason": "图片无法辨认, 需要重新选样",
            },
            headers=_write_headers(csrf, "replace-l7-002-v1"),
        )
        assert replacement.status_code == 200, replacement.text
        assert replacement.json()["item"]["review_status"] == "replace_candidate"
        assert replacement.json()["progress"] == {
            "total": 50,
            "completed": 2,
            "remaining": 48,
            "replace_candidate": 1,
        }


def test_review_api_rejects_a_client_reviewer_field(
    tmp_path: Path,
) -> None:
    _write_review_package(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        csrf = _session(client)
        payload = _confirmed_payload(expected_record_version=0)
        payload["reviewer_id"] = "forged-reviewer"

        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=payload,
            headers=_write_headers(csrf, "forged-reviewer"),
        )

        assert response.status_code == 422
        detail = client.get(
            "/api/v1/locked-set-review/items/L7-001",
            headers=_read_headers(),
        )
        assert detail.json()["record_version"] == 0
        assert "reviewer_id" not in detail.json()


def test_review_api_rejects_writes_after_formal_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_review_package(tmp_path)
    app = _app(tmp_path)
    monkeypatch.setattr(
        locked_set_review_api,
        "is_candidate_review_sealed",
        lambda _review_root: True,
        raising=False,
    )

    with TestClient(app) as client:
        csrf = _session(client)
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=_confirmed_payload(expected_record_version=0),
            headers=_write_headers(csrf, "sealed-review-write"),
        )

        assert response.status_code == 409
        assert response.json()["error"]["code"] == (
            "locked_set_review_formally_sealed"
        )
        detail = client.get(
            "/api/v1/locked-set-review/items/L7-001",
            headers=_read_headers(),
        )
        assert detail.json()["record_version"] == 0


def test_review_api_fails_closed_when_formal_seal_store_is_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_review_package(tmp_path)
    app = _app(tmp_path)

    def invalid_seal_store(_review_root: Path) -> bool:
        raise CandidateReviewSealError("corrupt seal test")

    monkeypatch.setattr(
        locked_set_review_api,
        "is_candidate_review_sealed",
        invalid_seal_store,
    )

    with TestClient(app) as client:
        csrf = _session(client)
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=_confirmed_payload(expected_record_version=0),
            headers=_write_headers(csrf, "invalid-seal-review-write"),
        )

        assert response.status_code == 409
        assert response.json()["error"]["code"] == (
            "locked_set_review_seal_invalid"
        )
        detail = client.get(
            "/api/v1/locked-set-review/items/L7-001",
            headers=_read_headers(),
        )
        assert detail.json()["record_version"] == 0


def test_review_api_validates_weight_rotation_and_replacement_reason(
    tmp_path: Path,
) -> None:
    _write_review_package(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        csrf = _session(client)
        invalid_weight = _confirmed_payload(expected_record_version=0)
        images = invalid_weight["images"]
        assert isinstance(images, list)
        images[0]["ordinary_net"] = "31250"
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=invalid_weight,
            headers=_write_headers(csrf, "invalid-weight"),
        )
        assert response.status_code == 422

        contradictory_pair = _confirmed_payload(expected_record_version=0)
        contradictory_pair["pair_conditions"] = [
            "normal_pair",
            "swapped_pair",
        ]
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=contradictory_pair,
            headers=_write_headers(csrf, "contradictory-pair"),
        )
        assert response.status_code == 422

        inconsistent_pair = _confirmed_payload(expected_record_version=0)
        inconsistent_pair["pair_conditions"] = ["swapped_pair"]
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=inconsistent_pair,
            headers=_write_headers(csrf, "inconsistent-pair"),
        )
        assert response.status_code == 422

        non_ticket_with_known_role = _confirmed_payload(
            expected_record_version=0
        )
        images = non_ticket_with_known_role["images"]
        assert isinstance(images, list)
        images[0]["quality_conditions"] = ["non_ticket", "rotation_0"]
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=non_ticket_with_known_role,
            headers=_write_headers(csrf, "non-ticket-known-role"),
        )
        assert response.status_code == 422

        unknown_layout_with_known_role = _confirmed_payload(
            expected_record_version=0
        )
        images = unknown_layout_with_known_role["images"]
        assert isinstance(images, list)
        images[0]["quality_conditions"] = [
            "unknown_layout",
            "rotation_0",
        ]
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=unknown_layout_with_known_role,
            headers=_write_headers(csrf, "unknown-layout-known-role"),
        )
        assert response.status_code == 422

        missing_rotation = _confirmed_payload(expected_record_version=0)
        images = missing_rotation["images"]
        assert isinstance(images, list)
        images[0]["quality_conditions"] = ["printed"]
        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=missing_rotation,
            headers=_write_headers(csrf, "invalid-rotation"),
        )
        assert response.status_code == 422

        response = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json={
                "expected_record_version": 0,
                "decision": "replace_candidate",
            },
            headers=_write_headers(csrf, "missing-replace-reason"),
        )
        assert response.status_code == 422


@pytest.mark.parametrize(
    "conflicting_options",
    [
        {"enable_test_fixtures": True},
        {"developer_access_code": "template-maintenance"},
    ],
)
def test_review_app_rejects_tuning_and_test_modes(
    tmp_path: Path,
    conflicting_options: dict[str, object],
) -> None:
    _write_review_package(tmp_path)

    with pytest.raises(ValueError, match="must run alone"):
        _app(tmp_path, **conflicting_options)


def test_review_mode_excludes_jobs_and_business_background_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_review_package(tmp_path)
    static_dir = tmp_path / "review-console"
    static_dir.mkdir()
    (static_dir / "index.html").write_text(
        "<main>isolated locked-set review</main>",
        encoding="utf-8",
    )

    def unexpected_business_lifecycle(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            f"isolated review started business lifecycle: {args!r} {kwargs!r}"
        )

    monkeypatch.setattr(
        "dahe.api.app.SqliteJobRepository.recover_abandoned_attempts",
        unexpected_business_lifecycle,
    )
    monkeypatch.setattr(
        "dahe.api.app.SqliteJobRepository.abandon_instance_attempts",
        unexpected_business_lifecycle,
    )
    monkeypatch.setattr(
        "dahe.api.app.SqliteTemplateRepository.expire_staged_reference_uploads",
        unexpected_business_lifecycle,
    )
    monkeypatch.setattr(
        "dahe.api.app.CooperativeSchedulerRunner.start",
        unexpected_business_lifecycle,
    )
    monkeypatch.setattr(
        "dahe.api.app.CooperativeSchedulerRunner.notify",
        unexpected_business_lifecycle,
    )

    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=f"isolated-review-{uuid4().hex}",
        auto_run_jobs=True,
        stage_delay_seconds=0,
        enable_locked_set_review=True,
        static_dir=static_dir,
    )
    route_paths = set(app.openapi()["paths"])
    assert "/api/v1/session" in route_paths
    assert "/api/v1/locked-set-review" in route_paths
    assert set(app.openapi()["paths"]["/api/v1/jobs"]) == {"get"}
    assert not any(
        path.startswith("/api/v1/jobs/")
        or path.startswith("/api/v1/template-studio")
        for path in route_paths
    )
    assert not hasattr(app.state, "scheduler")
    assert not hasattr(app.state, "template_repository")

    with TestClient(app) as client:
        csrf = _session(client)
        rejected = client.post(
            "/api/v1/jobs",
            json={
                "task_type": "audit",
                "scope": {
                    "label": "must-not-start",
                    "fixture_id": "audit-normal-001",
                },
                "expected_record_version": 0,
            },
            headers=_write_headers(csrf, "must-not-start"),
        )
        assert rejected.status_code == 405
        assert client.get(
            "/api/v1/jobs",
            headers=_read_headers(),
        ).json() == {
            "jobs": [],
            "event_cursor": 0,
            "resources": [],
            "start_actions": {},
        }
        assert client.get(
            "/api/v1/resources",
            headers=_read_headers(),
        ).json() == {"resources": []}
        console = client.get(
            "/",
            headers={"Host": "127.0.0.1:8877"},
        )
        assert console.status_code == 200
        assert "isolated locked-set review" in console.text


def test_review_state_survives_app_restart_and_image_bytes_are_rechecked(
    tmp_path: Path,
) -> None:
    payload = _write_review_package(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        csrf = _session(client)
        saved = client.post(
            "/api/v1/locked-set-review/items/L7-001/review",
            json=_confirmed_payload(expected_record_version=0),
            headers=_write_headers(csrf, "persistent-l7-001"),
        )
        assert saved.status_code == 200

    with TestClient(_app(tmp_path)) as client:
        _session(client)
        detail = client.get(
            "/api/v1/locked-set-review/items/L7-001",
            headers=_read_headers(),
        )
        assert detail.status_code == 200
        assert detail.json()["record_version"] == 1
        assert detail.json()["decision"] == "confirmed"

        waybills = payload["waybills"]
        assert isinstance(waybills, list)
        first = waybills[0]
        assert isinstance(first, dict)
        images = first["images"]
        assert isinstance(images, list)
        first_image = images[0]
        assert isinstance(first_image, dict)
        digest = first_image["image_sha256"]
        relative_path = first_image["relative_path"]
        assert isinstance(digest, str)
        assert isinstance(relative_path, str)
        (tmp_path / "locked-set-review" / relative_path).write_bytes(_png_bytes(240))
        image = client.get(
            f"/api/v1/locked-set-review/images/{digest}?client_version={CLIENT_VERSION}",
            headers={
                "Host": "127.0.0.1:8877",
                "Origin": ORIGIN,
            },
        )
        assert image.status_code == 409
        assert image.json()["error"]["code"] == "locked_set_review_image_changed"


def test_review_routes_and_feature_flags_are_absent_by_default(
    tmp_path: Path,
) -> None:
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=f"default-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_read_headers())
        assert session.status_code == 200
        assert session.json()["locked_set_review_enabled"] is False
        meta = client.get("/api/v1/meta", headers=_read_headers())
        assert meta.json()["locked_set_review_enabled"] is False
        assert (
            client.get(
                "/api/v1/locked-set-review",
                headers=_read_headers(),
            ).status_code
            == 404
        )


def test_review_mode_starts_without_a_configured_human_identity(
    tmp_path: Path,
) -> None:
    _write_review_package(tmp_path)

    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=f"identity-free-review-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_locked_set_review=True,
    )
    with TestClient(app) as client:
        assert _session(client)
