from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dahe.adapters.ocr.protocol import (
    NormalizedBox,
    OcrFieldValue,
    OcrResult,
    OcrResultStatus,
    OcrRoleObservation,
    OcrTextLine,
)
from dahe.adapters.sqlite.audit_workflow import (
    SqliteAuditWorkflowRepository,
)
from dahe.adapters.sqlite.production_guard import ProductionReadOnlyGuardStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    AUDIT_OCR_OBSERVATIONS,
    IDEMPOTENCY_RECORDS,
    JOBS,
    OCR_RUN_GENERATIONS,
    OPERATIONAL_CAPTURE_RUNS,
    OPERATIONAL_REVIEW_LINKS,
    WORK_ITEMS,
)
from dahe.jobs.audit_execution import LocalAuditObservationProjection
from dahe.ports.jobs import (
    IdempotencyConflictError,
    RecordVersionConflictError,
)

PROJECT_ROOT = Path(__file__).parents[2]


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _ocr_result(
    *,
    image_sha256: str,
    runtime_sha256: str,
    role: str,
    amount: str,
) -> str:
    return OcrResult(
        command_id=f"{role}-command",
        status=OcrResultStatus.OK,
        worker_identity="loop9-workflow-test-worker",
        runtime_fingerprint=runtime_sha256,
        verified_image_sha256=image_sha256,
        elapsed_ms=12,
        text_lines=(
            OcrTextLine(
                text=f"sensitive full OCR text for {role}",
                confidence=Decimal("0.99"),
                box=NormalizedBox(
                    x=Decimal("0.10"),
                    y=Decimal("0.10"),
                    width=Decimal("0.20"),
                    height=Decimal("0.10"),
                ),
            ),
        ),
        fields={
            "ordinary_net": OcrFieldValue(
                raw_text=f"{amount} t",
                amount=amount,
                unit="t",
                confidence=Decimal("0.99"),
            )
        },
        role_observation=OcrRoleObservation(
            fixed_text=(role, "ticket"),
            layout_fingerprint=f"{role}-layout",
            orientation_degrees=0,
        ),
        error=None,
    ).model_dump_json()


class _RoleProjector:
    def project_observation(
        self,
        *,
        output_json: str,
        expected_image_sha256: str,
        expected_runtime_fingerprint: str,
    ) -> LocalAuditObservationProjection:
        result = OcrResult.model_validate_json(output_json)
        role = (
            "loading"
            if result.verified_image_sha256 == _sha("real-loading")
            else "unloading"
        )
        field = result.fields["ordinary_net"]
        return LocalAuditObservationProjection(
            ticket_role=role,
            role_quality="reliable",
            role_fingerprint=_sha(f"{role}-role"),
            role_high_confidence=True,
            template_set_fingerprint=_sha("shadow-template-set"),
            ordinary_net_amount=field.amount,
            ordinary_net_unit=field.unit,
            ordinary_net_reliable=True,
            weight_review_reason=None,
        )


@pytest.fixture
def workflow(
    tmp_path: Path,
) -> tuple[SqliteRuntime, SqliteAuditWorkflowRepository]:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="loop8-test",
    )
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id="j" * 32,
                task_type="audit",
                scope_label="离线验收",
                scope_fixture_id="loop8-offline-v1",
                scope_fingerprint=_sha("scope"),
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
                work_item_id="w" * 32,
                job_id="j" * 32,
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
    repository = SqliteAuditWorkflowRepository(runtime)
    repository.append_initial_revision(
        work_item_id="w" * 32,
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
    yield runtime, repository
    runtime.close()


def test_new_correction_writes_are_rejected(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    _, repository = workflow
    with pytest.raises(ValueError, match="retired"):
        repository.record_action(
            work_item_id="w" * 32,
            action_type="correction",
            reason_code="unloading:ocr_digit_error",
            correct_value="29.80",
            note=None,
            expected_record_version=1,
            idempotency_key="retired-correction",
            request_hash=_sha("retired-correction"),
        )


def test_audit_workspace_excludes_capture_control_items(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id="c" * 32,
                task_type="settlement_capture",
                scope_label="capture:operational_compat",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("capture-scope"),
                run_mode="shadow",
                status="failed",
                current_stage="settlement_capture.read",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=2,
                record_version=1,
                created_at="2026-08-06T00:00:00+00:00",
                updated_at="2026-08-06T00:00:01+00:00",
            )
        )
        connection.execute(
            WORK_ITEMS.insert().values(
                work_item_id="c" * 32,
                job_id="c" * 32,
                record_version=1,
                waybill_number="capture:operational_compat",
                vehicle_number="待结算数据采集",
                status="failed",
                current_stage="settlement_capture.read",
                business_outcome=None,
                decision="failed",
                item_index=0,
                attempt_count=1,
                ready_sequence=2,
            )
        )

    workspace = repository.get_audit_workspace(view="all")
    assert workspace["counts"]["all"] == 1
    assert [item["waybill_id"] for item in workspace["items"]] == [
        "OFFLINE-003"
    ]
    assert [item["waybill_id"] for item in repository.list_waybills()] == [
        "OFFLINE-003"
    ]


def test_settlement_workspace_projects_only_the_latest_linked_capture(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    capture_job_id = "s" * 32
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id=capture_job_id,
                task_type="settlement_capture",
                scope_label="运费结算数据获取",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("settlement-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="settlement_capture.complete",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=3,
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
                request_hash=_sha("materialize-request"),
                job_id="j" * 32,
                created_at="2026-08-07T00:01:00+00:00",
            )
        )

    workspace = repository.get_settlement_workspace(view="all")
    assert workspace["counts"] == {
        "all": 1,
        "waiting_review": 1,
        "confirmed_problem": 0,
        "normal_ready": 0,
    }
    assert [item["waybill_id"] for item in workspace["items"]] == [
        "OFFLINE-003"
    ]
    assert workspace["latest_fetch"]["status"] == "complete"
    assert workspace["latest_fetch"]["phase_label"] == "已完成"
    assert workspace["latest_fetch"]["estimate_state"] == "complete"
    assert workspace["latest_fetch"]["estimated_remaining_seconds"] == 0
    assert workspace["latest_fetch"]["elapsed_seconds"] >= 0
    field_issues = workspace["items"][0]["field_issues"]
    assert field_issues["loading_ocr_weight"]["has_issue"] is False
    assert field_issues["loading_platform_weight"]["has_issue"] is False
    assert field_issues["unloading_ocr_weight"]["has_issue"] is True
    assert field_issues["unloading_platform_weight"]["has_issue"] is False
    assert workspace["items"][0]["review_highlight_roles"] == ["unloading"]
    assert workspace["items"][0]["field_issue_diagnostic_code"] is None


def test_unknown_review_reason_uses_visible_safe_fallback(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    capture_job_id = "u" * 32
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            WORK_ITEMS.update()
            .where(WORK_ITEMS.c.work_item_id == "w" * 32)
            .values(review_reason="future_unknown_reason")
        )
        connection.execute(
            JOBS.insert().values(
                job_id=capture_job_id,
                task_type="settlement_capture",
                scope_label="运费结算数据获取",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("unknown-review-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="settlement_capture.complete",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=3,
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
                request_hash=_sha("unknown-review-link"),
                job_id="j" * 32,
                created_at="2026-08-07T00:01:00+00:00",
            )
        )

    item = repository.get_settlement_workspace(view="waiting_review")["items"][0]
    assert item["field_issue_diagnostic_code"] == "AUDIT-FIELD-ISSUE-FALLBACK"
    assert item["field_issues"]["loading_ocr_weight"]["has_issue"] is True
    assert item["field_issues"]["unloading_ocr_weight"]["has_issue"] is True
    assert item["field_issues"]["loading_ticket"]["has_issue"] is False
    assert item["field_issues"]["unloading_ticket"]["has_issue"] is False
    assert item["review_highlight_roles"] == ["loading", "unloading"]


def test_settlement_workspace_reports_partial_ocr_image_progress(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    capture_job_id = "p" * 32
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            WORK_ITEMS.update()
            .where(WORK_ITEMS.c.work_item_id == "w" * 32)
            .values(
                status="running",
                current_stage="audit.recognize",
                business_outcome=None,
                decision=None,
                review_reason=None,
                loading_ocr_complete=1,
                unloading_ocr_complete=0,
            )
        )
        connection.execute(
            JOBS.insert().values(
                job_id=capture_job_id,
                task_type="settlement_capture",
                scope_label="运费结算数据获取",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("partial-ocr-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="settlement_capture.complete",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=3,
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
                request_hash=_sha("partial-ocr-materialize-request"),
                job_id="j" * 32,
                created_at="2026-08-07T00:01:00+00:00",
            )
        )

    workspace = repository.get_settlement_workspace(view="all")
    assert workspace["latest_fetch"]["ocr_images_completed"] == 1
    assert workspace["latest_fetch"]["ocr_images_total"] == 2


def test_whole_run_workspace_exposes_only_the_contiguous_review_prefix(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    capture_job_id = "q" * 32
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            WORK_ITEMS.update()
            .where(WORK_ITEMS.c.work_item_id == "w" * 32)
            .values(item_index=0, ready_sequence=9)
        )
        for index, status in ((1, "running"), (2, "waiting_user")):
            connection.execute(
                WORK_ITEMS.insert().values(
                    work_item_id=str(index) * 32,
                    job_id="j" * 32,
                    record_version=1,
                    waybill_number=f"WHOLE-{index}",
                    vehicle_number=f"vehicle-{index}",
                    status=status,
                    current_stage="audit.recognize",
                    business_outcome=(
                        "awaiting_review" if status == "waiting_user" else None
                    ),
                    decision="review" if status == "waiting_user" else None,
                    review_reason=(
                        "missing_ticket" if status == "waiting_user" else None
                    ),
                    item_index=index,
                    attempt_count=0,
                    download_complete=1,
                    loading_ocr_complete=int(status == "waiting_user"),
                    unloading_ocr_complete=int(status == "waiting_user"),
                    ready_sequence=0,
                )
            )
        connection.execute(
            JOBS.insert().values(
                job_id=capture_job_id,
                task_type="settlement_capture",
                scope_label="运费结算数据获取",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("whole-run-prefix-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="settlement_capture.complete",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=3,
                record_version=2,
                created_at="2026-08-07T03:00:00+00:00",
                updated_at="2026-08-07T03:02:00+00:00",
            )
        )
        connection.execute(
            OPERATIONAL_CAPTURE_RUNS.insert().values(
                job_id=capture_job_id,
                scope="current",
                total=3,
                items_json="[]",
                items_sha256=_sha("whole-run-items"),
                next_item_index=3,
                committed_batch_count=1,
                capture_mode="whole_run_v1",
                batch_size=3,
                detail_concurrency=4,
                image_concurrency=6,
                status="complete",
                record_version=2,
                metadata_checked_count=3,
                reused_count=0,
                images_downloaded_count=6,
                created_at="2026-08-07T03:00:00+00:00",
                updated_at="2026-08-07T03:01:00+00:00",
            )
        )
        connection.execute(
            OPERATIONAL_REVIEW_LINKS.insert().values(
                source_job_id=capture_job_id,
                business_kind="settlement",
                review_job_id="j" * 32,
                eligible_item_count=3,
                missing_item_count=0,
                source_manifest_sha256=_sha("whole-run-manifest"),
                created_at="2026-08-07T03:01:00+00:00",
            )
        )

    workspace = repository.get_settlement_workspace(view="all")

    assert workspace["latest_fetch"]["phase"] == "offline_review"
    assert workspace["latest_fetch"]["visible_prefix_count"] == 1
    assert workspace["latest_fetch"]["progress_total"] == 3
    assert workspace["latest_fetch"]["status"] == "running"
    assert workspace["counts"]["all"] == 1
    assert [item["waybill_id"] for item in workspace["items"]] == ["OFFLINE-003"]


def test_whole_run_workspace_completes_with_waiting_human_review_items(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    capture_job_id = "v" * 32
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.update()
            .where(JOBS.c.job_id == "j" * 32)
            .values(status="waiting_user")
        )
        connection.execute(
            WORK_ITEMS.update()
            .where(WORK_ITEMS.c.work_item_id == "w" * 32)
            .values(item_index=0)
        )
        connection.execute(
            JOBS.insert().values(
                job_id=capture_job_id,
                task_type="settlement_capture",
                scope_label="settlement whole run",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("whole-run-complete-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="settlement_capture.complete",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=4,
                record_version=2,
                created_at="2026-08-07T04:00:00+00:00",
                updated_at="2026-08-07T04:02:00+00:00",
            )
        )
        connection.execute(
            OPERATIONAL_CAPTURE_RUNS.insert().values(
                job_id=capture_job_id,
                scope="current",
                total=1,
                items_json="[]",
                items_sha256=_sha("whole-run-complete-items"),
                next_item_index=1,
                committed_batch_count=1,
                capture_mode="whole_run_v1",
                batch_size=1,
                detail_concurrency=4,
                image_concurrency=6,
                status="complete",
                record_version=2,
                metadata_checked_count=1,
                reused_count=0,
                images_downloaded_count=2,
                created_at="2026-08-07T04:00:00+00:00",
                updated_at="2026-08-07T04:01:00+00:00",
            )
        )
        connection.execute(
            OPERATIONAL_REVIEW_LINKS.insert().values(
                source_job_id=capture_job_id,
                business_kind="settlement",
                review_job_id="j" * 32,
                eligible_item_count=1,
                missing_item_count=0,
                source_manifest_sha256=_sha("whole-run-complete-manifest"),
                created_at="2026-08-07T04:01:00+00:00",
            )
        )

    workspace = repository.get_settlement_workspace(view="all")

    assert workspace["latest_fetch"]["phase"] == "complete"
    assert workspace["latest_fetch"]["is_complete"] is True
    assert workspace["latest_fetch"]["is_terminal"] is True
    assert workspace["latest_fetch"]["visible_prefix_count"] == 1
    assert workspace["counts"]["all"] == 1


def test_latest_settlement_ready_waybill_numbers_use_only_current_capture(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    capture_job_id = "r" * 32
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            WORK_ITEMS.update()
            .where(WORK_ITEMS.c.work_item_id == "w" * 32)
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
                scope_fingerprint=_sha("ready-settlement-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="settlement_capture.complete",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=3,
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
                request_hash=_sha("ready-materialize-request"),
                job_id="j" * 32,
                created_at="2026-08-07T00:01:00+00:00",
            )
        )

    assert repository.list_latest_settlement_ready_waybill_numbers() == (
        "OFFLINE-003",
    )


def test_completed_empty_settlement_capture_does_not_reuse_old_results(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id="z" * 32,
                task_type="settlement_capture",
                scope_label="运费结算数据获取",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("empty-settlement-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="settlement_capture.complete",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                created_sequence=4,
                record_version=2,
                created_at="2026-08-07T01:00:00+00:00",
                updated_at="2026-08-07T01:01:00+00:00",
            )
        )

    workspace = repository.get_settlement_workspace(view="all")
    assert workspace["items"] == ()
    assert workspace["counts"]["all"] == 0
    assert workspace["latest_fetch"]["status"] == "complete"
    assert workspace["latest_fetch"]["progress_total"] == 0


def test_paused_login_wait_projects_one_business_login_phase(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    runtime, repository = workflow
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id="l" * 32,
                task_type="settlement_capture",
                scope_label="运费结算数据获取",
                scope_fixture_id="capture:operational_compat",
                scope_fingerprint=_sha("login-wait-scope"),
                run_mode="operational",
                status="paused",
                current_stage="settlement_capture.read",
                job_kind="business",
                ocr_execution_mode="none",
                conflict_key="settlement_capture:operational_compat",
                diagnostic_code="CF-CREDENTIAL-REQUIRED",
                created_sequence=5,
                record_version=3,
                created_at="2026-08-07T02:00:00+00:00",
                updated_at="2026-08-07T02:01:00+00:00",
            )
        )

    workspace = repository.get_settlement_workspace(view="all")
    assert workspace["items"] == ()
    assert workspace["latest_fetch"]["status"] == "running"
    assert workspace["latest_fetch"]["phase_label"] == "正在登录平台"


def test_problem_decision_is_identity_free_idempotent_and_versioned(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    _, repository = workflow
    request_hash = _sha("problem-request")
    item, replay = repository.record_action(
        work_item_id="w" * 32,
        action_type="problem_confirmation",
        reason_code="confirmed_weight_mismatch",
        correct_value=None,
        note=None,
        expected_record_version=1,
        idempotency_key="problem-offline-003",
        request_hash=request_hash,
    )
    assert replay is False
    assert item["business_outcome"] == "confirmed_problem"
    assert item["record_version"] == 2

    replayed, replay = repository.record_action(
        work_item_id="w" * 32,
        action_type="problem_confirmation",
        reason_code="confirmed_weight_mismatch",
        correct_value=None,
        note=None,
        expected_record_version=1,
        idempotency_key="problem-offline-003",
        request_hash=request_hash,
    )
    assert replay is True
    assert replayed["record_version"] == 2


def test_stale_or_reused_action_is_rejected(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    _, repository = workflow
    repository.record_action(
        work_item_id="w" * 32,
        action_type="problem_confirmation",
        reason_code="confirmed_weight_mismatch",
        correct_value=None,
        note=None,
        expected_record_version=1,
        idempotency_key="problem-offline-003",
        request_hash=_sha("problem-request"),
    )
    with pytest.raises(RecordVersionConflictError):
        repository.record_action(
            work_item_id="w" * 32,
            action_type="problem_dismissal",
            reason_code="manual_visual_check",
            correct_value=None,
            note=None,
            expected_record_version=1,
            idempotency_key="dismiss-stale",
            request_hash=_sha("dismiss-stale"),
        )
    with pytest.raises(IdempotencyConflictError):
        repository.record_action(
            work_item_id="w" * 32,
            action_type="problem_confirmation",
            reason_code="other_business_problem",
            correct_value=None,
            note=None,
            expected_record_version=2,
            idempotency_key="problem-offline-003",
            request_hash=_sha("different-request"),
        )


def test_revocation_appends_history_and_restores_review_state(
    workflow: tuple[SqliteRuntime, SqliteAuditWorkflowRepository],
) -> None:
    _, repository = workflow
    decided, _ = repository.record_action(
        work_item_id="w" * 32,
        action_type="problem_confirmation",
        reason_code="confirmed_weight_mismatch",
        correct_value=None,
        note=None,
        expected_record_version=1,
        idempotency_key="problem-before-revoke",
        request_hash=_sha("problem-before-revoke"),
    )
    original_action_id = str(decided["review_actions"][0]["action_id"])

    restored, _ = repository.record_action(
        work_item_id="w" * 32,
        action_type="revocation",
        reason_code="decision_entered_in_error",
        correct_value=None,
        note=None,
        expected_record_version=2,
        idempotency_key="revoke-problem",
        request_hash=_sha("revoke-problem"),
        revokes_action_id=original_action_id,
    )

    assert restored["status"] == "waiting_user"
    assert restored["business_outcome"] == "awaiting_review"
    assert [event["event_type"] for event in restored["timeline"]] == [
        "audit_decision_created",
        "problem_confirmation",
        "revocation",
    ]


def test_real_local_audit_result_is_materialized_without_raw_ocr_text(
    tmp_path: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="loop9-real-workflow",
    )
    job_id = "r" * 32
    work_item_id = "x" * 32
    generation_id = "g" * 32
    loading_sha = _sha("real-loading")
    unloading_sha = _sha("real-unloading")
    runtime_sha = _sha("real-runtime")
    pipeline_sha = _sha("real-pipeline")
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id=job_id,
                task_type="audit",
                scope_label="30 条真实影子",
                scope_fixture_id=(
                    "chengfeng-shadow:current_shadow_30:" + _sha("batch")
                ),
                scope_fingerprint=_sha("real-scope"),
                run_mode="shadow",
                status="waiting_user",
                current_stage="audit.finalize",
                job_kind="business",
                ocr_execution_mode="local",
                conflict_key="audit:real-shadow-30",
                created_sequence=2,
                record_version=1,
                created_at="2026-07-30T00:00:00+00:00",
                updated_at="2026-07-30T00:00:00+00:00",
            )
        )
        connection.execute(
            WORK_ITEMS.insert().values(
                work_item_id=work_item_id,
                job_id=job_id,
                record_version=3,
                waybill_number="CF-REAL-001",
                vehicle_number="测试车辆",
                status="waiting_user",
                current_stage="audit.finalize",
                business_outcome="awaiting_review",
                platform_loading_net="30.00",
                platform_unloading_net="29.80",
                ticket_loading_net="30.00",
                ticket_unloading_net="29.70",
                decision="weight_mismatch",
                review_reason="numeric_mismatch",
                item_index=0,
                attempt_count=3,
                loading_image_sha256=loading_sha,
                unloading_image_sha256=unloading_sha,
                pipeline_fingerprint=pipeline_sha,
                fixture_platform_loading_net="30.00",
                fixture_platform_unloading_net="29.80",
                download_complete=1,
                loading_ocr_complete=1,
                unloading_ocr_complete=1,
                ready_sequence=2,
                ocr_generation_id=generation_id,
            )
        )
        connection.execute(
            OCR_RUN_GENERATIONS.insert().values(
                generation_id=generation_id,
                work_item_id=work_item_id,
                pipeline_fingerprint=pipeline_sha,
                primary_runtime_kind="gpu",
                next_runtime_kind="gpu",
                status="succeeded",
                committed_runtime_kind="gpu",
                committed_profile_id="gpu-qualified",
                committed_runtime_fingerprint=runtime_sha,
                loading_output_json=_ocr_result(
                    image_sha256=loading_sha,
                    runtime_sha256=runtime_sha,
                    role="loading",
                    amount="30.00",
                ),
                unloading_output_json=_ocr_result(
                    image_sha256=unloading_sha,
                    runtime_sha256=runtime_sha,
                    role="unloading",
                    amount="29.70",
                ),
                loading_output_fingerprint=_sha("loading-output"),
                unloading_output_fingerprint=_sha("unloading-output"),
                diagnostic_code=None,
                record_version=2,
                created_at="2026-07-30T00:00:00+00:00",
                updated_at="2026-07-30T00:00:01+00:00",
            )
        )

    repository = SqliteAuditWorkflowRepository(
        runtime,
        local_observation_projector=_RoleProjector(),
    )
    try:
        workspace = repository.get_audit_workspace(
            view="waiting_review",
            job_id=job_id,
        )
        assert workspace["counts"]["all"] == 1
        item = workspace["items"][0]
        assert item["evidence"] is not None
        assert item["available_actions"]["confirm_normal"]["enabled"] is True
        assert item["available_actions"]["confirm_problem"]["enabled"] is True

        detail = repository.get_item(work_item_id)
        assert detail["timeline"][0]["event_type"] == "audit_decision_created"
        with runtime.engine.connect() as connection:
            observations = tuple(
                connection.execute(
                    AUDIT_OCR_OBSERVATIONS.select().where(
                        AUDIT_OCR_OBSERVATIONS.c.evidence_revision_id
                        == detail["evidence"]["evidence_revision_id"]
                    )
                ).mappings()
            )
        assert len(observations) == 2
        assert {str(row["runtime_kind"]) for row in observations} == {"gpu"}
        assert {
            str(row["ticket_role"]) for row in observations
        } == {"loading", "unloading"}
        assert all(
            len(
                str(
                    json.loads(str(row["payload_json"]))[
                        "template_set_fingerprint"
                    ]
                )
            )
            == 64
            for row in observations
        )
        assert all(
            "sensitive full OCR text" not in str(row["payload_json"])
            for row in observations
        )
        assert all(
            key not in json.loads(str(row["payload_json"]))
            for row in observations
            for key in ("reviewer_id", "operator_id", "actor_id")
        )
    finally:
        runtime.close()


def test_invalid_committed_ocr_is_never_registered_as_business_review(
    tmp_path: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="production-invalid-ocr",
    )
    job_id = "q" * 32
    work_item_id = "z" * 32
    generation_id = "h" * 32
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id=job_id,
                task_type="audit",
                scope_label="生产无效识别证据",
                scope_fixture_id="operational:invalid-ocr",
                scope_fingerprint=_sha("invalid-scope"),
                run_mode="operational",
                status="succeeded",
                current_stage="audit.complete",
                job_kind="business",
                ocr_execution_mode="local",
                conflict_key="audit:operational:invalid-ocr",
                created_sequence=3,
                record_version=1,
                created_at="2026-08-02T00:00:00+00:00",
                updated_at="2026-08-02T00:00:01+00:00",
            )
        )
        connection.execute(
            WORK_ITEMS.insert().values(
                work_item_id=work_item_id,
                job_id=job_id,
                record_version=1,
                waybill_number="CF-INVALID-OCR",
                vehicle_number="测试车辆",
                status="succeeded",
                current_stage="audit.complete",
                business_outcome="normal_ready",
                platform_loading_net="30.00",
                platform_unloading_net="29.80",
                ticket_loading_net="30.00",
                ticket_unloading_net="29.80",
                decision="pass",
                item_index=0,
                attempt_count=1,
                loading_image_sha256=_sha("invalid-loading"),
                unloading_image_sha256=_sha("invalid-unloading"),
                pipeline_fingerprint=_sha("invalid-pipeline"),
                download_complete=1,
                loading_ocr_complete=1,
                unloading_ocr_complete=1,
                ready_sequence=1,
                ocr_generation_id=generation_id,
            )
        )
        connection.execute(
            OCR_RUN_GENERATIONS.insert().values(
                generation_id=generation_id,
                work_item_id=work_item_id,
                pipeline_fingerprint=_sha("invalid-pipeline"),
                primary_runtime_kind="gpu",
                next_runtime_kind="gpu",
                status="succeeded",
                committed_runtime_kind="gpu",
                committed_profile_id="gpu-qualified",
                committed_runtime_fingerprint=_sha("invalid-runtime"),
                loading_output_json="{}",
                unloading_output_json="{}",
                loading_output_fingerprint=_sha("invalid-loading-output"),
                unloading_output_fingerprint=_sha("invalid-unloading-output"),
                diagnostic_code=None,
                record_version=2,
                created_at="2026-08-02T00:00:00+00:00",
                updated_at="2026-08-02T00:00:01+00:00",
            )
        )

    guard = MagicMock(spec=ProductionReadOnlyGuardStore)
    repository = SqliteAuditWorkflowRepository(
        runtime,
        local_observation_projector=_RoleProjector(),
        production_guard=guard,
    )
    try:
        assert repository.sync_business_audit_results() == 1
        guard.register_result.assert_not_called()
        with runtime.engine.connect() as connection:
            item = connection.execute(
                WORK_ITEMS.select().where(
                    WORK_ITEMS.c.work_item_id == work_item_id
                )
            ).one()
        assert item.status == "failed"
        assert item.business_outcome is None
        assert item.review_reason is None
        assert item.diagnostic_code == "AUDIT-COMMITTED-EVIDENCE-INVALID"
    finally:
        runtime.close()
