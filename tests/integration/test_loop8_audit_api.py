from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from dahe import __version__
from dahe.adapters.sqlite.schema import IDEMPOTENCY_RECORDS, JOBS, WORK_ITEMS
from dahe.api.app import create_app

PROJECT_ROOT = Path(__file__).parents[2]
ORIGIN = "http://127.0.0.1:8877"


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }


def _seed_waiting_item(app: object) -> None:
    runtime = app.state.sqlite_runtime
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id="a" * 32,
                task_type="audit",
                scope_label="Loop 8 离线批次",
                scope_fixture_id="loop8-offline-v1",
                scope_fingerprint=_sha("loop8-scope"),
                run_mode="shadow",
                status="waiting_user",
                current_stage="audit.compare",
                job_kind="business",
                ocr_execution_mode="fake",
                conflict_key="audit:loop8-offline-v1",
                created_sequence=1,
                record_version=1,
                created_at="2026-07-27T00:00:00+00:00",
                updated_at="2026-07-27T00:00:00+00:00",
            )
        )
        connection.execute(
            WORK_ITEMS.insert().values(
                work_item_id="b" * 32,
                job_id="a" * 32,
                record_version=1,
                waybill_number="OFFLINE-003",
                vehicle_number="匿名车辆-003",
                status="waiting_user",
                current_stage="audit.compare",
                business_outcome="awaiting_review",
                platform_loading_net="30.00",
                platform_unloading_net="29.80",
                ticket_loading_net="30.00",
                ticket_unloading_net="29.70",
                decision="review",
                review_reason="numeric_mismatch",
                item_index=2,
                attempt_count=0,
                loading_image_sha256=_sha("loading"),
                unloading_image_sha256=_sha("unloading"),
                pipeline_fingerprint=_sha("pipeline"),
                fixture_outcome="awaiting_review",
                fixture_review_reason="numeric_mismatch",
                download_complete=1,
                loading_ocr_complete=1,
                unloading_ocr_complete=1,
                ready_sequence=1,
            )
        )
    app.state.audit_workflow_repository.append_initial_revision(
        work_item_id="b" * 32,
        platform_snapshot_sha256=_sha("snapshot"),
        loading_image_sha256=_sha("loading"),
        unloading_image_sha256=_sha("unloading"),
        platform_loading_net="30.00",
        platform_unloading_net="29.80",
        ticket_loading_net="30.00",
        ticket_unloading_net="29.70",
        business_outcome="awaiting_review",
        review_reason="numeric_mismatch",
        decision="review",
        rules_fingerprint=_sha("rules"),
    )


def _client(tmp_path: Path) -> tuple[object, TestClient]:
    app = create_app(
        data_root=tmp_path / uuid4().hex,
        project_root=PROJECT_ROOT,
        instance_id=f"ux-api-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    return app, TestClient(app)


def test_workspace_exposes_backend_actions_and_retires_corrections(
    tmp_path: Path,
) -> None:
    app, client_context = _client(tmp_path)
    with client_context as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        _seed_waiting_item(app)

        workspace = client.get(
            "/api/v1/audit/items?view=waiting_review",
            headers=_headers(),
        )
        assert workspace.status_code == 200
        assert workspace.json()["counts"] == {
            "all": 1,
            "waiting_review": 1,
            "confirmed_problem": 0,
            "normal_ready": 0,
        }
        item = workspace.json()["items"][0]
        assert item["run_mode"] == "shadow"
        assert item["available_actions"]["confirm_normal"]["enabled"] is True
        assert item["available_actions"]["confirm_problem"]["enabled"] is True

        retired = client.post(
            f"/api/v1/audit/items/{'b' * 32}/corrections",
            headers={
                **_headers(),
                "X-CSRF-Token": csrf,
                "Idempotency-Key": "retired-correction",
            },
            json={
                "expected_record_version": 1,
                "target": "unloading_ordinary_net",
                "reason": "ocr_digit_error",
                "correct_value": "29.80",
            },
        )
        assert retired.status_code == 404


def test_workspace_counts_share_the_job_scope_with_filtered_items(
    tmp_path: Path,
) -> None:
    app, client_context = _client(tmp_path)
    with client_context as client:
        assert client.get("/api/v1/session", headers=_headers()).status_code == 200
        _seed_waiting_item(app)
        runtime = app.state.sqlite_runtime
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            for index, outcome in enumerate(
                ("normal_ready", "confirmed_problem"),
                start=1,
            ):
                connection.execute(
                    WORK_ITEMS.insert().values(
                        work_item_id=str(index) * 32,
                        job_id="a" * 32,
                        record_version=1,
                        waybill_number=f"OFFLINE-{index + 3:03d}",
                        vehicle_number=f"TEST-{index}",
                        status="succeeded",
                        current_stage="audit.compare",
                        business_outcome=outcome,
                        decision="pass" if outcome == "normal_ready" else "problem",
                        review_reason=None,
                        item_index=index + 2,
                        attempt_count=0,
                        fixture_outcome=outcome,
                        download_complete=1,
                        loading_ocr_complete=1,
                        unloading_ocr_complete=1,
                        ready_sequence=index + 1,
                    )
                )

        response = client.get(
            f"/api/v1/audit/items?view=normal_ready&job_id={'a' * 32}",
            headers=_headers(),
        )
        assert response.status_code == 200
        assert [item["business_outcome"] for item in response.json()["items"]] == [
            "normal_ready"
        ]
        assert response.json()["counts"] == {
            "all": 3,
            "waiting_review": 1,
            "confirmed_problem": 1,
            "normal_ready": 1,
        }


def test_ready_waybill_numbers_are_scoped_to_latest_settlement_fetch(
    tmp_path: Path,
) -> None:
    app, client_context = _client(tmp_path)
    with client_context as client:
        assert client.get("/api/v1/session", headers=_headers()).status_code == 200
        _seed_waiting_item(app)
        capture_job_id = "c" * 32
        runtime = app.state.sqlite_runtime
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                WORK_ITEMS.update()
                .where(WORK_ITEMS.c.work_item_id == "b" * 32)
                .values(
                    status="succeeded",
                    business_outcome="normal_ready",
                    decision="pass",
                    review_reason=None,
                    platform_unloading_net="29.70",
                )
            )
            connection.execute(
                JOBS.insert().values(
                    job_id=capture_job_id,
                    task_type="settlement_capture",
                    scope_label="运费结算数据获取",
                    scope_fixture_id="capture:operational_compat",
                    scope_fingerprint=_sha("ready-api-scope"),
                    run_mode="operational",
                    status="succeeded",
                    current_stage="settlement_capture.complete",
                    job_kind="business",
                    ocr_execution_mode="none",
                    conflict_key="settlement_capture:operational_compat",
                    created_sequence=2,
                    record_version=2,
                    created_at="2026-08-07T00:00:00+00:00",
                    updated_at="2026-08-07T00:02:00+00:00",
                )
            )
            connection.execute(
                IDEMPOTENCY_RECORDS.insert().values(
                    operation="POST:/api/v1/jobs",
                    idempotency_key=(
                        f"operational-materialize:{capture_job_id}:batch:1:fixture"
                    ),
                    request_hash=_sha("ready-api-materialize"),
                    job_id="a" * 32,
                    created_at="2026-08-07T00:01:00+00:00",
                )
            )

        response = client.get(
            "/api/v1/settlement/ready-waybill-numbers",
            headers=_headers(),
        )
        assert response.status_code == 200
        assert response.json() == {
            "count": 1,
            "waybill_numbers": ["OFFLINE-003"],
        }


def test_runtime_log_query_stream_cursor_and_export_are_redacted(
    tmp_path: Path,
) -> None:
    app, client_context = _client(tmp_path)
    with client_context as client:
        assert client.get("/api/v1/session", headers=_headers()).status_code == 200
        first = app.state.runtime_log_store.append(
            level="error",
            source="worker",
            event_code="worker_failed",
            stream="stderr",
            message=r"password=secret C:\private\input.png",
            diagnostic_code="DIAG-001",
        )
        assert first is not None

        queried = client.get(
            "/api/v1/diagnostics/logs?level=error&source=worker",
            headers=_headers(),
        )
        assert queried.status_code == 200
        assert queried.json()["events"][0]["event_id"] == first["event_id"]
        assert "secret" not in queried.text
        assert "C:\\private" not in queried.text

        exported = client.get(
            "/api/v1/diagnostics/logs/export",
            headers=_headers(),
        )
        assert exported.status_code == 200
        assert exported.headers["content-type"].startswith("text/plain")
        assert (
            exported.headers["content-disposition"]
            == 'attachment; filename="dahe-runtime-logs.log"'
        )
        assert "secret" not in exported.text
        assert "C:\\private" not in exported.text

        invalid_cursor = client.get(
            "/api/v1/diagnostics/logs/stream",
            headers={**_headers(), "Last-Event-ID": "not-a-cursor"},
        )
        assert invalid_cursor.status_code == 400
        assert invalid_cursor.json()["error"]["code"] == "invalid_log_cursor"


def test_problem_decision_derives_reason_and_rejects_form_fields(
    tmp_path: Path,
) -> None:
    app, client_context = _client(tmp_path)
    with client_context as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        _seed_waiting_item(app)
        endpoint = f"/api/v1/audit/items/{'b' * 32}/problem-confirmations"
        headers = {
            **_headers(),
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "problem-offline-003",
        }

        invalid = client.post(
            endpoint,
            headers=headers,
            json={
                "expected_record_version": 1,
                "correct_value": "29.80",
            },
        )
        assert invalid.status_code == 422

        confirmed = client.post(
            endpoint,
            headers=headers,
            json={"expected_record_version": 1},
        )
        assert confirmed.status_code == 200, confirmed.text
        item = confirmed.json()["item"]
        assert item["business_outcome"] == "confirmed_problem"
        assert item["review_actions"][0]["reason_code"] == (
            "confirmed_weight_mismatch"
        )
        assert item["review_actions"][0]["correct_value"] is None
        assert item["review_actions"][0]["note"] is None


def test_confirm_normal_is_direct_versioned_and_does_not_change_weights(
    tmp_path: Path,
) -> None:
    app, client_context = _client(tmp_path)
    with client_context as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        _seed_waiting_item(app)

        confirmed = client.post(
            f"/api/v1/audit/items/{'b' * 32}/problem-dismissals",
            headers={
                **_headers(),
                "X-CSRF-Token": csrf,
                "Idempotency-Key": "normal-offline-003",
            },
            json={"expected_record_version": 1},
        )
        assert confirmed.status_code == 200, confirmed.text
        item = confirmed.json()["item"]
        assert item["business_outcome"] == "normal_ready"
        assert item["ticket_unloading_net"] == "29.70"
        assert item["platform_unloading_net"] == "29.80"
        assert item["review_actions"][0]["reason_code"] == (
            "manual_visual_check"
        )

        serialized = confirmed.text.lower()
        for forbidden in (
            "operator_id",
            "reviewer_id",
            "actor_id",
        ):
            assert forbidden not in serialized


def test_diagnostics_export_is_read_only_and_redacted(tmp_path: Path) -> None:
    app, client_context = _client(tmp_path)
    with client_context as client:
        session = client.get("/api/v1/session", headers=_headers())
        assert session.status_code == 200
        _seed_waiting_item(app)

        diagnostics = client.get("/api/v1/diagnostics", headers=_headers())
        exported = client.get(
            "/api/v1/diagnostics/export",
            headers=_headers(),
        )

        assert diagnostics.status_code == 200
        assert exported.status_code == 200
        assert exported.headers["cache-control"] == "no-store"
        assert (
            exported.headers["content-disposition"]
            == 'attachment; filename="dahe-diagnostics.json"'
        )
        assert exported.json()["health"] == diagnostics.json()["health"]
        assert (
            exported.json()["recent_issues"]
            == diagnostics.json()["recent_issues"]
        )

        serialized = exported.text.lower()
        for forbidden in (
            "operator",
            "reviewer",
            "actor_id",
            "password",
            "cookie",
            "token",
            "platform_loading_net",
            "ticket_loading_net",
            "loading_image_sha256",
            "raw_ocr",
            "correct_value",
            "c:\\",
            str(tmp_path).lower(),
        ):
            assert forbidden not in serialized
