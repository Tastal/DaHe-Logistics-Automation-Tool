from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import text

from dahe import __version__
from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.adapters.sqlite.candidate_development_ocr import (
    CandidateDevelopmentOcrRunAuthorityInput,
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateEvaluationCandidateInput,
    TemplateEvaluationItemInput,
    TemplateEvaluationPairInput,
)
from dahe.api.app import create_app as create_application
from dahe.application.template_studio.matcher import (
    build_development_evaluation_template_set,
)
from dahe.domain.audit.ticket_roles import TicketRole
from tests.fixtures.loop7_composite_lifecycle import (
    add_composite_lifecycle_authority,
)

CLIENT_VERSION = __version__
ORIGIN = "http://127.0.0.1:8877"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEVELOPER_ACCESS_CODE = "loop7-test-developer-code"
REFERENCE_IMAGE_BYTES = b"loop-7-synthetic-reference-image"
REFERENCE_IMAGE_SHA256 = hashlib.sha256(REFERENCE_IMAGE_BYTES).hexdigest()
REFERENCE_MASK_BYTES = b"loop-7-synthetic-reference-mask"
REFERENCE_MASK_SHA256 = hashlib.sha256(REFERENCE_MASK_BYTES).hexdigest()


def _valid_reference_png() -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (96, 64), color=(245, 245, 245)).save(
        output,
        format="PNG",
    )
    return output.getvalue()


def _workbench_draft() -> dict[str, object]:
    return {
        "anchors": [
            {
                "anchor_id": "anchor-1",
                "expected_text": "净重",
                "match_mode": "contains",
                "required": True,
                "role_evidence": "loading",
                "importance": "primary",
                "bounds": {
                    "x": "0.10",
                    "y": "0.10",
                    "width": "0.20",
                    "height": "0.10",
                },
            }
        ],
        "regions": [],
    }


def _app(data_root: Path, **values: Any) -> FastAPI:
    values.setdefault("enable_test_fixtures", True)
    values.setdefault(
        "accepted_template_development_manifest_sha256",
        "1" * 64,
    )
    values.setdefault("accepted_template_runtime_fingerprint", "6" * 64)
    return create_application(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id=f"loop7-api-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
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
    return str(response.json()["csrf_token"])


def _write_headers(
    csrf_token: str,
    idempotency_key: str,
    *,
    developer_authorization: str | None = None,
) -> dict[str, str]:
    headers = {
        **_read_headers(),
        "X-CSRF-Token": csrf_token,
        "X-Idempotency-Key": idempotency_key,
    }
    if developer_authorization is not None:
        headers["X-DaHe-Developer-Authorization"] = developer_authorization
    return headers


def _draft_payload() -> dict[str, object]:
    return {
        "definition": {
            "family_id": "scale-slip-alpha",
            "name": "Alpha loading scale slip",
            "role": "loading",
            "anchors": [
                {
                    "anchor_id": "loading-title",
                    "expected_text": "装货磅单",
                    "box": {"x": "0.10", "y": "0.05", "width": "0.35", "height": "0.10"},
                    "required": True,
                    "weight": "1.00",
                    "max_edit_distance": "0.15",
                    "loading_evidence": "0.80",
                    "unloading_evidence": "-0.20",
                }
            ],
            "regions": [
                {
                    "region_id": "net-weight",
                    "field": "ordinary_net",
                    "box": {"x": "0.10", "y": "0.55", "width": "0.35", "height": "0.12"},
                    "relative_to_anchor_id": None,
                    "unit": "t",
                    "format_pattern": r"^\d{1,3}(?:\.\d{1,2})?$",
                    "required": True,
                    "layout_scope": "full_ticket",
                }
            ],
        },
        "reference_image_sha256": REFERENCE_IMAGE_SHA256,
        "reference_mask_sha256": REFERENCE_MASK_SHA256,
        "alignment_fingerprint": "c" * 64,
    }


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _record_development_evaluation(
    client: TestClient,
    *,
    version_id: str,
    evaluation_id: str,
    gate_passed: bool = True,
) -> str:
    repository = client.app.state.template_repository
    version = repository.get_version(version_id)

    def measured(value: object) -> dict[str, object]:
        return {
            "definition": "API projection contract measurement.",
            "status": "measured",
            "value": value,
        }

    prediction = TicketRole.LOADING if gate_passed else TicketRole.UNKNOWN
    confidence = Decimal("0.96") if gate_passed else Decimal("0")
    confusion_matrix = {
        "loading": {
            "loading": 1 if gate_passed else 0,
            "unknown": 0 if gate_passed else 1,
            "unloading": 0,
        },
        "unknown": {"loading": 0, "unknown": 0, "unloading": 0},
        "unloading": {"loading": 0, "unknown": 0, "unloading": 0},
    }
    unknown_rate = "0" if gate_passed else "1"
    metrics = {
        "confusion_matrix": confusion_matrix,
        "high_confidence_error_count": 0,
        "p50_elapsed_ms": "1.25",
        "p95_elapsed_ms": "1.25",
        "pair_results": [
            {
                "case_id": "api-normal-pair-001",
                "expected_issue": None,
                "expected_matches_result": True,
                "result_issue": None,
            }
        ],
        "sample_count": 1,
        "unknown_rate": unknown_rate,
        "development_metrics": {
            "anchor_pass_rate": measured("1"),
            "confusion_matrix": measured(confusion_matrix),
            "direct_completion_rate": measured("1"),
            "expected_result_reconciliation": measured(
                {
                    "expected_count": 1,
                    "matched_count": 1,
                    "mismatch_count": 0,
                    "result_count": 1,
                }
            ),
            "fallback_rate": measured("0"),
            "field_reliability": {
                "definition": "Field extraction is not measured by role evaluation.",
                "status": "not_measured",
                "value": None,
            },
            "geometry_match_rate": measured("1"),
            "high_confidence_errors": measured(0),
            "p50_elapsed_ms": measured("1.25"),
            "p95_elapsed_ms": measured("1.25"),
            "pair_reconciliation": measured(
                {
                    "expected_count": 1,
                    "matched_count": 1,
                    "mismatch_count": 0,
                    "result_count": 1,
                }
            ),
            "role_conflict_rate": measured("0"),
            "unknown_layout_rate": measured("0"),
            "unknown_rate": measured(unknown_rate),
            "wrong_template_rate": measured("0"),
        },
    }
    template_set = build_development_evaluation_template_set(
        candidates=(version,),
        current_shadow=repository.list_current_eligible_shadow_versions(),
    )
    stable_outcome_sha256 = _canonical_sha256(
        {
            "evaluation_id": evaluation_id,
            "prediction": prediction.value,
            "template_set_fingerprint": template_set.fingerprint,
        }
    )
    if gate_passed:
        metrics, stable_outcome_sha256 = add_composite_lifecycle_authority(
            metrics,
            evaluation_id=evaluation_id,
            dataset_id="api-test-development-set",
            dataset_manifest_sha256="1" * 64,
            template_set_fingerprint=template_set.fingerprint,
            matcher_fingerprint=str(repository.accepted_matcher_fingerprint),
            policy_fingerprint=str(repository.accepted_policy_fingerprint),
            build_fingerprint=repository.accepted_build_fingerprint,
            runtime_fingerprint=str(repository.accepted_runtime_fingerprint),
            candidates=((version.version_id, version.content_sha256),),
            reviewer_id="api-test-evaluator",
        )
        real_source = metrics["composite_lifecycle_components"][
            "real_candidate_roles"
        ]["source"]
        evidence_sha256 = str(real_source["ocr_evidence_sha256"])
        SqliteCandidateDevelopmentOcrRunRepository(
            runtime=repository.runtime
        ).record_completed_run(
            CandidateDevelopmentOcrRunAuthorityInput(
                evidence_sha256=evidence_sha256,
                evidence_blob_sha256=_canonical_sha256(
                    {"evaluation_id": evaluation_id}
                ),
                evidence_relative_path=(
                    "development/protected-candidate-review-ocr/"
                    f"records/sha256/{evidence_sha256[:2]}/"
                    f"{evidence_sha256[2:4]}/{evidence_sha256}.json"
                ),
                evidence_byte_size=4096,
                package_sha256=str(real_source["package_sha256"]),
                review_history_authority_sha256=str(
                    real_source["review_history_authority_sha256"]
                ),
                source_authority_sha256=str(
                    real_source["source_authority_sha256"]
                ),
                reviewer_id="api-test-evaluator",
                application_build_sha256=str(
                    real_source["ocr_capture_build_sha256"]
                ),
                composition_evidence_sha256=str(
                    real_source["composition_evidence_sha256"]
                ),
                runtime_set_sha256=str(
                    real_source["runtime_set_sha256"]
                ),
                pipeline_contract_sha256=str(
                    real_source["ocr_pipeline_contract_sha256"]
                ),
                completion_status="completed",
                completed_at="2026-07-26T12:00:00+00:00",
            )
        )
    previous_authority = (
        None
        if gate_passed
        else repository.get_latest_valid_development_evaluation(
            version.version_id
        )
    )
    repository._record_frozen_development_evaluation(
        evaluation_id=evaluation_id,
        dataset_id="api-test-development-set",
        dataset_manifest_sha256="1" * 64,
        template_set_fingerprint=template_set.fingerprint,
        matcher_fingerprint=str(repository.accepted_matcher_fingerprint),
        policy_fingerprint=str(repository.accepted_policy_fingerprint),
        build_fingerprint=repository.accepted_build_fingerprint,
        runtime_fingerprint=str(repository.accepted_runtime_fingerprint),
        expected_count=1,
        result_count=1,
        metrics=metrics,
        metrics_sha256=_canonical_sha256(metrics),
        gate_passed=gate_passed,
        candidates=(
            TemplateEvaluationCandidateInput(
                version_id=version.version_id,
                content_sha256=version.content_sha256,
            ),
        ),
        items=(
            TemplateEvaluationItemInput(
                sample_id="api-development-image-001",
                waybill_id="api-development-waybill-001",
                waybill_identity_sha256="6" * 64,
                image_sha256="7" * 64,
                truth=TicketRole.LOADING,
                prediction=prediction,
                confidence=confidence,
                high_confidence=gate_passed,
                orientation_degrees=0,
                evidence={"sources": ["fixed_text", "template", "layout"]},
                assessment_fingerprint="8" * 64,
                elapsed_ms=Decimal("1.25"),
                pair_issue=None,
                unknown_reason=(None if gate_passed else "insufficient_role_evidence"),
            ),
        ),
        pairs=(
            TemplateEvaluationPairInput(
                case_id="api-normal-pair-001",
                expected_issue=None,
                result_issue=None,
                expected_matches_result=True,
            ),
        ),
        stable_outcome_sha256=stable_outcome_sha256,
        actor_id="api-test-evaluator",
    )
    if previous_authority is not None:
        repository.record_composite_lifecycle_failure(
            scope=repository.get_composite_lifecycle_attempt_scope(
                previous_authority.evaluation_id
            ),
            terminal_status="business_failed",
            failure_code="LOOP7-API-FIXTURE-BUSINESS-GATE",
            actor_id="api-test-evaluator",
        )
    return evaluation_id


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = _app(tmp_path, developer_access_code=DEVELOPER_ACCESS_CODE)
    store = ContentAddressedEvidenceStore(tmp_path / "evidence")
    evidence_records = (
        store.put_bytes(
            REFERENCE_IMAGE_BYTES,
            media_type="image/png",
        ),
        store.put_bytes(
            REFERENCE_MASK_BYTES,
            media_type="image/png",
        ),
    )
    runtime = app.state.template_repository.runtime
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        for evidence in evidence_records:
            connection.execute(
                text(
                    """
                    INSERT INTO evidence_blobs (
                        sha256, relative_path, byte_size, media_type,
                        storage_state, record_version, created_at, verified_at
                    ) VALUES (
                        :sha256, :relative_path, :byte_size, :media_type,
                        'available', 1, :created_at, :verified_at
                    )
                    """
                ),
                {
                    "sha256": evidence.sha256,
                    "relative_path": evidence.relative_path,
                    "byte_size": evidence.byte_size,
                    "media_type": evidence.media_type,
                    "created_at": "2026-07-25T12:00:00+00:00",
                    "verified_at": "2026-07-25T12:00:00+00:00",
                },
            )
    with TestClient(app) as test_client:
        yield test_client


def test_empty_database_can_stage_reference_and_create_first_draft(
    tmp_path: Path,
) -> None:
    with TestClient(_app(tmp_path, developer_access_code=DEVELOPER_ACCESS_CODE)) as empty_client:
        csrf_token = _session(empty_client)
        initial = empty_client.get(
            "/api/v1/template-studio/families",
            headers=_read_headers(),
        )
        assert initial.status_code == 200
        assert initial.json()["families"] == []
        assert initial.json()["actions"]["create_template"]["enabled"] is False

        unauthorized_upload = empty_client.post(
            "/api/v1/template-studio/reference-images",
            content=_valid_reference_png(),
            headers={
                **_write_headers(csrf_token, "reject-unmaintained-upload"),
                "Content-Type": "image/png",
            },
        )
        assert unauthorized_upload.status_code == 403

        unlocked = empty_client.post(
            "/api/v1/template-studio/developer/revalidate",
            json={
                "access_code": DEVELOPER_ACCESS_CODE,
                "action": "template.maintenance_session",
                "resource_id": "template-studio",
            },
            headers=_write_headers(csrf_token, "unlock-empty-template-studio"),
        )
        assert unlocked.status_code == 200
        assert unlocked.json()["actions"]["create_template"]["enabled"] is True

        upload_headers = {
            **_write_headers(csrf_token, "stage-first-reference"),
            "Content-Type": "image/png",
            "X-DaHe-File-Name": "%E8%A3%85%E8%B4%A7%E7%A3%85%E5%8D%95.png",
        }
        staged = empty_client.post(
            "/api/v1/template-studio/reference-images",
            content=_valid_reference_png(),
            headers=upload_headers,
        )
        assert staged.status_code == 200
        upload = staged.json()["upload"]
        assert upload["alt"] == "装货磅单.png"
        assert (upload["width"], upload["height"]) == (96, 64)
        assert upload["content_url"].endswith(f"?client_version={CLIENT_VERSION}")
        browser_image = empty_client.get(
            upload["content_url"],
            headers={"Host": "127.0.0.1:8877"},
        )
        assert browser_image.status_code == 200
        assert browser_image.headers["content-type"] == "image/png"
        assert hashlib.sha256(browser_image.content).hexdigest() == upload["image_id"]
        stale_browser_image = empty_client.get(
            upload["content_url"].replace(
                f"client_version={CLIENT_VERSION}",
                "client_version=stale",
            ),
            headers={"Host": "127.0.0.1:8877"},
        )
        assert stale_browser_image.status_code == 409
        assert stale_browser_image.json()["error"]["code"] == "client_version_mismatch"
        replayed_stage = empty_client.post(
            "/api/v1/template-studio/reference-images",
            content=_valid_reference_png(),
            headers=upload_headers,
        )
        assert replayed_stage.status_code == 200
        assert (
            replayed_stage.json()["upload"]["staged_reference_id"] == upload["staged_reference_id"]
        )

        first_template_draft = _workbench_draft()
        first_template_draft["regions"] = [
            {
                "region_id": "loading-time",
                "field": "loading_weigh_time",
                "value_type": "time",
                "unit": "printed",
                "required": False,
                "anchor_id": "anchor-1",
                "bounds": {
                    "x": "0.10",
                    "y": "0.30",
                    "width": "0.20",
                    "height": "0.08",
                },
            },
            {
                "region_id": "unloading-tare-time",
                "field": "unloading_tare_time",
                "value_type": "time",
                "unit": "printed",
                "required": False,
                "anchor_id": "anchor-1",
                "bounds": {
                    "x": "0.35",
                    "y": "0.30",
                    "width": "0.20",
                    "height": "0.08",
                },
            },
            {
                "region_id": "print-time",
                "field": "print_time",
                "value_type": "time",
                "unit": "printed",
                "required": False,
                "anchor_id": "anchor-1",
                "bounds": {
                    "x": "0.60",
                    "y": "0.30",
                    "width": "0.20",
                    "height": "0.08",
                },
            },
        ]
        create_payload = {
            "staged_reference_id": upload["staged_reference_id"],
            "expected_record_version": upload["record_version"],
            "family_name": "一号装货磅单",
            "role": "loading",
            "draft": first_template_draft,
        }
        free_label_payload = json.loads(json.dumps(create_payload))
        free_label_payload["draft"]["anchors"][0]["label"] = "自定义名称"
        free_label = empty_client.post(
            "/api/v1/template-studio/templates/from-staged-reference",
            json=free_label_payload,
            headers=_write_headers(csrf_token, "reject-free-anchor-label"),
        )
        assert free_label.status_code == 422

        generic_time_payload = json.loads(json.dumps(create_payload))
        generic_time_payload["draft"]["regions"][0]["field"] = "weighing_time"
        generic_time = empty_client.post(
            "/api/v1/template-studio/templates/from-staged-reference",
            json=generic_time_payload,
            headers=_write_headers(csrf_token, "reject-generic-time-field"),
        )
        assert generic_time.status_code == 422

        placeholder_payload = json.loads(json.dumps(create_payload))
        placeholder_payload["draft"]["anchors"][0]["expected_text"] = "请替换为票面固定文字"
        placeholder = empty_client.post(
            "/api/v1/template-studio/templates/from-staged-reference",
            json=placeholder_payload,
            headers=_write_headers(
                csrf_token,
                "reject-placeholder-first-template",
            ),
        )
        assert placeholder.status_code == 400
        assert placeholder.json()["error"]["code"] == "invalid_template_definition"

        create_headers = _write_headers(
            csrf_token,
            "create-first-template-from-reference",
        )
        created = empty_client.post(
            "/api/v1/template-studio/templates/from-staged-reference",
            json=create_payload,
            headers=create_headers,
        )
        assert created.status_code == 200
        assert created.json()["created"] is True
        assert created.json()["template"]["family_name"] == "一号装货磅单"
        assert created.json()["template"]["lifecycle"] == "draft"
        assert created.json()["template"]["reference_image"]["width"] == 96
        assert created.json()["template"]["reference_image"]["height"] == 64
        assert [region["field"] for region in created.json()["template"]["draft"]["regions"]] == [
            "loading_weigh_time",
            "unloading_tare_time",
            "print_time",
        ]
        assert [region["label"] for region in created.json()["template"]["draft"]["regions"]] == [
            "装货过磅时间",
            "卸货皮重时间",
            "打印时间",
        ]
        family_id = str(created.json()["template"]["family_id"])
        version_history = empty_client.get(
            f"/api/v1/template-studio/families/{family_id}/versions",
            headers=_read_headers(),
        )
        assert version_history.status_code == 200
        assert version_history.json()["current_shadow"] is None
        assert version_history.json()["versions"] == [
            {
                "version_id": created.json()["template"]["version_id"],
                "version_number": 1,
                "lifecycle_label": "草稿",
                "is_current_shadow": False,
                "can_rollback": False,
                "label": "草稿 1",
            }
        ]

        replayed_create = empty_client.post(
            "/api/v1/template-studio/templates/from-staged-reference",
            json=create_payload,
            headers=create_headers,
        )
        assert replayed_create.status_code == 200
        assert replayed_create.json()["created"] is False
        assert (
            replayed_create.json()["template"]["version_id"]
            == created.json()["template"]["version_id"]
        )
        repository = empty_client.app.state.template_repository
        assert isinstance(repository, SqliteTemplateRepository)
        original_current = repository.get_family_current(
            str(created.json()["template"]["family_id"])
        )
        revised_draft = json.loads(json.dumps(first_template_draft))
        revised_draft["anchors"][0]["bounds"]["x"] = "0.25"
        save_headers = _write_headers(
            csrf_token,
            "revise-first-template-anchor-geometry",
        )
        saved = empty_client.put(
            (f"/api/v1/template-studio/templates/{created.json()['template']['version_id']}/draft"),
            json={
                "expected_record_version": created.json()["template"]["record_version"],
                "draft": revised_draft,
            },
            headers=save_headers,
        )
        assert saved.status_code == 200
        assert [region["field"] for region in saved.json()["draft"]["regions"]] == [
            "loading_weigh_time",
            "unloading_tare_time",
            "print_time",
        ]
        revised_current = repository.get_family_current(
            str(created.json()["template"]["family_id"])
        )
        assert revised_current.reference_mask_sha256 != original_current.reference_mask_sha256
        with repository.runtime.engine.connect() as connection:
            mask_hold_sha256 = connection.execute(
                text(
                    """
                    SELECT sha256
                    FROM evidence_holds
                    WHERE hold_kind = 'template_reference_mask'
                      AND owner_id = :version_id
                      AND released_at IS NULL
                    """
                ),
                {"version_id": revised_current.version.version_id},
            ).scalar_one()
        assert str(mask_hold_sha256) == revised_current.reference_mask_sha256

        replayed_save = empty_client.put(
            (f"/api/v1/template-studio/templates/{created.json()['template']['version_id']}/draft"),
            json={
                "expected_record_version": created.json()["template"]["record_version"],
                "draft": revised_draft,
            },
            headers=save_headers,
        )
        assert replayed_save.status_code == 200
        assert replayed_save.json()["version_id"] == saved.json()["version_id"]
        final_index = empty_client.get(
            "/api/v1/template-studio/families",
            headers=_read_headers(),
        )
        assert len(final_index.json()["families"]) == 1


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b"not an image", "image/png"),
        (_valid_reference_png(), "image/jpeg"),
        (b"<svg/>", "image/svg+xml"),
    ],
)
def test_reference_upload_rejects_corrupt_or_spoofed_images(
    client: TestClient,
    content: bytes,
    content_type: str,
) -> None:
    csrf_token = _session(client)
    unlocked = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.maintenance_session",
            "resource_id": "template-studio",
        },
        headers=_write_headers(csrf_token, f"unlock-invalid-{content_type}"),
    )
    assert unlocked.status_code == 200
    response = client.post(
        "/api/v1/template-studio/reference-images",
        content=content,
        headers={
            **_write_headers(csrf_token, f"invalid-upload-{content_type}"),
            "Content-Type": content_type,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_template_reference_image"


def test_finance_session_cannot_write_until_developer_maintenance_revalidation(
    client: TestClient,
) -> None:
    csrf_token = _session(client)
    ordinary = client.post(
        "/api/v1/template-studio/test-fixtures/templates",
        json=_draft_payload(),
        headers=_write_headers(csrf_token, "finance-cannot-create"),
    )
    assert ordinary.status_code == 403
    assert ordinary.json()["error"]["code"] == "developer_revalidation_required"

    wrong_code = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": "wrong-code",
            "action": "template.maintenance_session",
            "resource_id": "template-studio",
        },
        headers=_write_headers(csrf_token, "wrong-developer-code"),
    )
    assert wrong_code.status_code == 403
    assert wrong_code.json()["error"]["code"] == "developer_revalidation_failed"

    authorization = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.maintenance_session",
            "resource_id": "template-studio",
        },
        headers=_write_headers(csrf_token, "revalidate-create-draft"),
    )
    assert authorization.status_code == 200
    assert authorization.json()["maintenance"]["authorized"] is True

    created = client.post(
        "/api/v1/template-studio/test-fixtures/templates",
        json=_draft_payload(),
        headers=_write_headers(csrf_token, "developer-create-draft"),
    )
    assert created.status_code == 200
    assert created.json()["template"]["lifecycle"] == "draft"

    blank_evaluation = client.post(
        (
            "/api/v1/template-studio/templates/"
            f"{created.json()['template']['version_id']}/development-tested"
        ),
        json={
            "expected_record_version": 1,
            "evaluation_id": "   ",
        },
        headers=_write_headers(csrf_token, "reject-blank-evaluation"),
    )
    assert blank_evaluation.status_code == 422


def test_template_api_exposes_no_active_or_platform_write_entry_point(
    tmp_path: Path,
) -> None:
    app = _app(
        tmp_path,
        developer_access_code=DEVELOPER_ACCESS_CODE,
        enable_test_fixtures=False,
    )
    paths = set(app.openapi()["paths"])

    assert "/api/v1/template-studio/developer/revalidate" in paths
    assert "/api/v1/template-studio/templates/from-staged-reference" in paths
    assert "/api/v1/template-studio/templates" not in paths
    assert "/api/v1/template-studio/test-fixtures/templates" not in paths
    assert "/api/v1/template-studio/templates/{version_id}/development-tested" in paths
    assert "/api/v1/template-studio/templates/{version_id}/shadow" in paths
    assert "/api/v1/template-studio/families/{family_id}/rollback" in paths
    assert all("active" not in path.lower() for path in paths)
    assert paths.isdisjoint(
        {
            "/api/v1/settlement/confirm",
            "/api/v1/settlement/pay",
        }
    )
    assert all("payment" not in path.lower() for path in paths)
    assert all("receipt-cancellation" not in path.lower() for path in paths)
    assert all("platform-write" not in path.lower() for path in paths)


def test_shadow_publish_requires_action_specific_developer_revalidation(
    client: TestClient,
) -> None:
    csrf_token = _session(client)
    maintenance = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.maintenance_session",
            "resource_id": "template-studio",
        },
        headers=_write_headers(csrf_token, "open-maintenance-for-shadow"),
    )
    assert maintenance.status_code == 200

    created = client.post(
        "/api/v1/template-studio/test-fixtures/templates",
        json=_draft_payload(),
        headers=_write_headers(csrf_token, "create-shadow-candidate"),
    )
    assert created.status_code == 200
    version_id = str(created.json()["template"]["version_id"])
    draft_record_version = int(created.json()["template"]["record_version"])

    fabricated_evaluation = client.post(
        f"/api/v1/template-studio/templates/{version_id}/development-tested",
        json={
            "expected_record_version": draft_record_version,
            "evaluation_id": "fabricated-evaluation-id",
        },
        headers=_write_headers(csrf_token, "reject-fabricated-evaluation"),
    )
    assert fabricated_evaluation.status_code == 409
    assert fabricated_evaluation.json()["error"]["code"] == "template_evaluation_gate_failed"

    evaluation_id = _record_development_evaluation(
        client,
        version_id=version_id,
        evaluation_id="api-development-evaluation-001",
    )
    projected = client.get(
        "/api/v1/template-studio/families/scale-slip-alpha",
        headers=_read_headers(),
    )
    assert projected.status_code == 200
    assert projected.json()["check_report"]["summary_label"] == "开发样本检查通过"
    assert len(projected.json()["check_report"]["metrics"]) == 10
    development_action = projected.json()["actions"]["run_development_check"]
    assert development_action["enabled"] is True
    assert development_action["evaluation_id"] == evaluation_id

    development_tested = client.post(
        f"/api/v1/template-studio/templates/{version_id}/development-tested",
        json={
            "expected_record_version": draft_record_version,
            "evaluation_id": evaluation_id,
        },
        headers=_write_headers(csrf_token, "mark-development-tested"),
    )
    assert development_tested.status_code == 200
    tested_record_version = int(development_tested.json()["record_version"])

    missing_action_grant = client.post(
        f"/api/v1/template-studio/templates/{version_id}/shadow",
        json={
            "expected_record_version": tested_record_version,
            "evaluation_id": evaluation_id,
        },
        headers=_write_headers(csrf_token, "publish-shadow-without-grant"),
    )
    assert missing_action_grant.status_code == 403
    assert missing_action_grant.json()["error"]["code"] == "developer_action_revalidation_required"

    action_grant = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.publish_shadow",
            "resource_id": version_id,
        },
        headers=_write_headers(csrf_token, "authorize-shadow-publish"),
    )
    assert action_grant.status_code == 200
    authorization_token = str(action_grant.json()["authorization_token"])

    publish_headers = _write_headers(
        csrf_token,
        "publish-shadow-with-grant",
        developer_authorization=authorization_token,
    )
    publish_payload = {
        "expected_record_version": tested_record_version,
        "evaluation_id": evaluation_id,
    }
    published = client.post(
        f"/api/v1/template-studio/templates/{version_id}/shadow",
        json=publish_payload,
        headers=publish_headers,
    )
    assert published.status_code == 200
    assert published.json()["lifecycle"] == "shadow"

    retried = client.post(
        f"/api/v1/template-studio/templates/{version_id}/shadow",
        json=publish_payload,
        headers=publish_headers,
    )
    assert retried.status_code == 200
    assert retried.json()["lifecycle"] == "shadow"


def test_invalidated_evaluation_disables_and_blocks_shadow_publish(
    client: TestClient,
) -> None:
    csrf_token = _session(client)
    maintenance = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.maintenance_session",
            "resource_id": "template-studio",
        },
        headers=_write_headers(csrf_token, "open-invalidated-maintenance"),
    )
    assert maintenance.status_code == 200
    created = client.post(
        "/api/v1/template-studio/test-fixtures/templates",
        json=_draft_payload(),
        headers=_write_headers(csrf_token, "create-invalidated-shadow-candidate"),
    )
    assert created.status_code == 200
    version_id = str(created.json()["template"]["version_id"])
    draft_record_version = int(created.json()["template"]["record_version"])
    evaluation_id = _record_development_evaluation(
        client,
        version_id=version_id,
        evaluation_id="api-development-evaluation-invalidated",
    )

    development_tested = client.post(
        f"/api/v1/template-studio/templates/{version_id}/development-tested",
        json={
            "expected_record_version": draft_record_version,
            "evaluation_id": evaluation_id,
        },
        headers=_write_headers(csrf_token, "mark-invalidated-development-tested"),
    )
    assert development_tested.status_code == 200
    tested_record_version = int(development_tested.json()["record_version"])

    repository = client.app.state.template_repository
    assert isinstance(repository, SqliteTemplateRepository)
    repository.invalidate_evaluation(
        evaluation_id=evaluation_id,
        reason="fixture changed after development check",
        actor_id="loop7-api-test",
    )

    detail = client.get(
        "/api/v1/template-studio/families/scale-slip-alpha",
        headers=_read_headers(),
    )
    assert detail.status_code == 200
    shadow_action = detail.json()["actions"]["start_shadow"]
    assert shadow_action["enabled"] is False
    assert shadow_action["evaluation_id"] is None
    assert shadow_action["reason"] == "开发样本检查已失效"

    action_grant = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.publish_shadow",
            "resource_id": version_id,
        },
        headers=_write_headers(csrf_token, "authorize-invalidated-shadow"),
    )
    assert action_grant.status_code == 200
    publish = client.post(
        f"/api/v1/template-studio/templates/{version_id}/shadow",
        json={
            "expected_record_version": tested_record_version,
            "evaluation_id": evaluation_id,
        },
        headers=_write_headers(
            csrf_token,
            "reject-invalidated-shadow",
            developer_authorization=str(action_grant.json()["authorization_token"]),
        ),
    )
    assert publish.status_code == 409
    assert publish.json()["error"]["code"] == "template_evaluation_gate_failed"


def test_newer_failed_evaluation_supersedes_an_older_pass(
    client: TestClient,
) -> None:
    csrf_token = _session(client)
    maintenance = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.maintenance_session",
            "resource_id": "template-studio",
        },
        headers=_write_headers(csrf_token, "open-superseded-maintenance"),
    )
    assert maintenance.status_code == 200
    created = client.post(
        "/api/v1/template-studio/test-fixtures/templates",
        json=_draft_payload(),
        headers=_write_headers(csrf_token, "create-superseded-shadow-candidate"),
    )
    assert created.status_code == 200
    version_id = str(created.json()["template"]["version_id"])
    draft_record_version = int(created.json()["template"]["record_version"])
    passed_evaluation_id = _record_development_evaluation(
        client,
        version_id=version_id,
        evaluation_id="api-development-evaluation-older-pass",
    )
    development_tested = client.post(
        f"/api/v1/template-studio/templates/{version_id}/development-tested",
        json={
            "expected_record_version": draft_record_version,
            "evaluation_id": passed_evaluation_id,
        },
        headers=_write_headers(csrf_token, "mark-superseded-development-tested"),
    )
    assert development_tested.status_code == 200
    tested_record_version = int(development_tested.json()["record_version"])

    _record_development_evaluation(
        client,
        version_id=version_id,
        evaluation_id="api-development-evaluation-newer-failure",
        gate_passed=False,
    )
    detail = client.get(
        "/api/v1/template-studio/families/scale-slip-alpha",
        headers=_read_headers(),
    )
    assert detail.status_code == 200
    assert detail.json()["check_report"] is None
    assert detail.json()["actions"]["start_shadow"]["enabled"] is False

    action_grant = client.post(
        "/api/v1/template-studio/developer/revalidate",
        json={
            "access_code": DEVELOPER_ACCESS_CODE,
            "action": "template.publish_shadow",
            "resource_id": version_id,
        },
        headers=_write_headers(csrf_token, "authorize-superseded-shadow"),
    )
    assert action_grant.status_code == 200
    publish = client.post(
        f"/api/v1/template-studio/templates/{version_id}/shadow",
        json={
            "expected_record_version": tested_record_version,
            "evaluation_id": passed_evaluation_id,
        },
        headers=_write_headers(
            csrf_token,
            "reject-superseded-shadow",
            developer_authorization=str(action_grant.json()["authorization_token"]),
        ),
    )
    assert publish.status_code == 409
    assert publish.json()["error"]["code"] == "template_evaluation_gate_failed"


def test_template_mutations_remain_disabled_without_developer_configuration(
    tmp_path: Path,
) -> None:
    with TestClient(_app(tmp_path)) as client:
        csrf_token = _session(client)
        response = client.post(
            "/api/v1/template-studio/developer/revalidate",
            json={
                "access_code": DEVELOPER_ACCESS_CODE,
                "action": "template.maintenance_session",
                "resource_id": "template-studio",
            },
            headers=_write_headers(csrf_token, "developer-not-configured"),
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "developer_access_not_configured"
