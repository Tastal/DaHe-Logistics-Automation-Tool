from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
    EvidenceIntegrityError,
    InvalidEvidenceIdentityError,
)
from dahe.adapters.sqlite.audit_workflow import (
    AuditActionConflictError,
    AuditItemNotFoundError,
    SqliteAuditWorkflowRepository,
)
from dahe.adapters.sqlite.production_guard import ProductionReadOnlyGuardStore
from dahe.api.errors import ApiError
from dahe.application.chengfeng.contract_subject import require_contract_subject_code
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.ports.jobs import (
    IdempotencyConflictError,
    RecordVersionConflictError,
)


class _VersionedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=1)


class ProblemConfirmationRequest(_VersionedAction):
    pass


class ProblemDismissalRequest(_VersionedAction):
    pass


class RevokeActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=1)
    reason: Literal[
        "decision_entered_in_error",
        "evidence_rechecked",
        "other_revocation_reason",
    ]


def _request_hash(
    *,
    operation: str,
    identifier: str,
    payload: BaseModel,
) -> str:
    encoded = json.dumps(
        {
            "identifier": identifier,
            "operation": operation,
            "payload": payload.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_audit_workflow_router(
    *,
    repository: SqliteAuditWorkflowRepository,
    evidence_store: ContentAddressedEvidenceStore,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
    after_action: Callable[[], object] | None = None,
    load_resources: Callable[[], list[dict[str, object]]] | None = None,
    runtime_log_store: RuntimeLogStore | None = None,
    production_guard: ProductionReadOnlyGuardStore | None = None,
) -> APIRouter:
    router = APIRouter()

    def _record(
        *,
        work_item_id: str,
        action_type: str,
        reason_code: str,
        correct_value: str | None,
        note: str | None,
        expected_record_version: int,
        idempotency_key: str,
        payload: BaseModel,
        revokes_action_id: str | None = None,
    ) -> dict[str, object]:
        try:
            item, replay = repository.record_action(
                work_item_id=work_item_id,
                action_type=action_type,
                reason_code=reason_code,
                correct_value=correct_value,
                note=note,
                expected_record_version=expected_record_version,
                idempotency_key=idempotency_key,
                request_hash=_request_hash(
                    operation=action_type,
                    identifier=work_item_id,
                    payload=payload,
                ),
                revokes_action_id=revokes_action_id,
            )
        except AuditItemNotFoundError as exc:
            raise ApiError(
                404,
                "audit_item_not_found",
                "没有找到该运单审核项。",
            ) from exc
        except RecordVersionConflictError as exc:
            raise ApiError(
                409,
                "record_version_conflict",
                "该运单已更新, 请刷新后重试。",
            ) from exc
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "该操作编号已用于其他请求, 请刷新后重试。",
            ) from exc
        except (AuditActionConflictError, ValueError) as exc:
            raise ApiError(409, "review_action_not_allowed", str(exc)) from exc
        if not replay and production_guard is not None:
            actions = item.get("review_actions")
            if isinstance(actions, list) and actions:
                action_id = str(actions[-1].get("action_id", ""))
                if action_id:
                    production_guard.record_manual_decision(
                        work_item_id=work_item_id,
                        action_id=action_id,
                        manual_outcome=(
                            "confirmed_problem"
                            if action_type == "problem_confirmation"
                            else "normal_ready"
                        ),
                    )
        if not replay and after_action is not None:
            after_action()
        return {"idempotent_replay": replay, "item": item}

    @router.get("/api/v1/audit/review-items")
    def list_review_items(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        return {"items": repository.list_review_items()}

    @router.get("/api/v1/production-read-only/status")
    def production_read_only_status(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        if production_guard is None:
            raise ApiError(
                403,
                "production_read_only_disabled",
                "当前未启用只读生产保护。",
            )
        return production_guard.status().to_payload()

    @router.get("/api/v1/audit/items")
    def list_audit_items(
        _: None = Depends(require_session),
        view: Literal[
            "all",
            "waiting_review",
            "confirmed_problem",
            "normal_ready",
        ] = Query(default="all"),
        job_id: str | None = Query(default=None, min_length=32, max_length=32),
    ) -> dict[str, object]:
        return repository.get_audit_workspace(view=view, job_id=job_id)

    @router.get("/api/v1/settlement/workspace")
    def get_settlement_workspace(
        _: None = Depends(require_session),
        view: Literal[
            "all",
            "waiting_review",
            "confirmed_problem",
            "normal_ready",
        ] = Query(default="all"),
        contract_subject_code: str = Query(default="shanxi_guienbo"),
    ) -> dict[str, object]:
        return repository.get_settlement_workspace(
            view=view,
            contract_subject_code=require_contract_subject_code(
                contract_subject_code
            ),
        )

    @router.get("/api/v1/settlement/ready-waybill-numbers")
    def get_ready_waybill_numbers(
        _: None = Depends(require_session),
        contract_subject_code: str = Query(default="shanxi_guienbo"),
    ) -> dict[str, object]:
        values = repository.list_latest_settlement_ready_waybill_numbers(
            contract_subject_code=require_contract_subject_code(
                contract_subject_code
            )
        )
        return {"count": len(values), "waybill_numbers": values}

    @router.get("/api/v1/audit/items/{work_item_id}")
    def get_audit_item(
        work_item_id: str,
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        try:
            return repository.get_item(work_item_id)
        except AuditItemNotFoundError as exc:
            raise ApiError(
                404,
                "audit_item_not_found",
                "没有找到该运单审核项。",
            ) from exc

    @router.post(
        "/api/v1/audit/items/{work_item_id}/problem-confirmations"
    )
    def confirm_problem(
        work_item_id: str,
        payload: ProblemConfirmationRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        item = repository.get_item(work_item_id)
        if item.get("business_outcome") == "confirmed_problem":
            return {"idempotent_replay": True, "item": item}
        return _record(
            work_item_id=work_item_id,
            action_type="problem_confirmation",
            reason_code=_problem_reason(str(item.get("review_reason") or "")),
            correct_value=None,
            note=None,
            expected_record_version=payload.expected_record_version,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    @router.post(
        "/api/v1/audit/items/{work_item_id}/problem-dismissals"
    )
    def dismiss_problem(
        work_item_id: str,
        payload: ProblemDismissalRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        item = repository.get_item(work_item_id)
        if item.get("business_outcome") == "normal_ready":
            return {"idempotent_replay": True, "item": item}
        return _record(
            work_item_id=work_item_id,
            action_type="problem_dismissal",
            reason_code="manual_visual_check",
            correct_value=None,
            note=None,
            expected_record_version=payload.expected_record_version,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    @router.post("/api/v1/audit/review-actions/{action_id}/revoke")
    def revoke_action(
        action_id: str,
        payload: RevokeActionRequest,
        work_item_id: str = Query(min_length=1, max_length=32),
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        return _record(
            work_item_id=work_item_id,
            action_type="revocation",
            reason_code=payload.reason,
            correct_value=None,
            note=None,
            expected_record_version=payload.expected_record_version,
            idempotency_key=idempotency_key,
            payload=payload,
            revokes_action_id=action_id,
        )

    def _diagnostics_payload() -> dict[str, object]:
        resources = [] if load_resources is None else load_resources()
        jobs = repository.list_audit_items(view="all")
        failed = [
            item
            for item in jobs
            if item.get("status") == "failed"
            or item.get("diagnostic_code") is not None
        ]
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "health": [
                {
                    "id": "database",
                    "label": "本地数据",
                    "status": "normal",
                    "summary": "数据库可读取",
                },
                {
                    "id": "tasks",
                    "label": "审核任务",
                    "status": "attention" if failed else "normal",
                    "summary": (
                        f"{len(failed)} 条技术问题"
                        if failed
                        else "没有技术问题"
                    ),
                },
                {
                    "id": "resources",
                    "label": "本地资源",
                    "status": "normal",
                    "summary": f"{len(resources)} 项资源已登记",
                },
            ]
            + (
                [runtime_log_store.health_status()]
                if runtime_log_store is not None
                else []
            ),
            "recent_issues": [
                {
                    "diagnostic_code": item.get("diagnostic_code"),
                    "location": "运费结算",
                    "message": "该运单发生技术问题",
                    "work_item_id": item.get("work_item_id"),
                }
                for item in failed[:20]
            ],
        }

    @router.get("/api/v1/diagnostics")
    def get_diagnostics(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        return _diagnostics_payload()

    @router.get("/api/v1/diagnostics/export")
    def export_diagnostics(
        _: None = Depends(require_session),
    ) -> Response:
        content = json.dumps(
            _diagnostics_payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": (
                    'attachment; filename="dahe-diagnostics.json"'
                ),
                "Cache-Control": "no-store",
            },
        )

    @router.get("/api/v1/diagnostics/logs")
    def get_runtime_logs(
        _: None = Depends(require_session),
        before: int | None = Query(default=None, ge=0),
        after: int | None = Query(default=None, ge=0),
        limit: int = Query(default=200, ge=1, le=1000),
        level: Literal["debug", "info", "warning", "error"] | None = None,
        source: str | None = Query(default=None, max_length=80),
        text: str | None = Query(default=None, max_length=200),
    ) -> dict[str, object]:
        if runtime_log_store is None:
            return {
                "events": [],
                "earliest_cursor": None,
                "latest_cursor": None,
                "has_more_older": False,
            }
        return runtime_log_store.query(
            before=before,
            after=after,
            limit=limit,
            level=level,
            source=source,
            text=text,
        )

    @router.get("/api/v1/diagnostics/logs/stream")
    async def stream_runtime_logs(
        request: Request,
        _: None = Depends(require_session),
        after: int = Query(default=0, ge=0),
    ) -> StreamingResponse:
        cursor = after
        last_event_id = request.headers.get("last-event-id")
        if last_event_id is not None:
            try:
                cursor = max(cursor, int(last_event_id))
            except ValueError as exc:
                raise ApiError(
                    400,
                    "invalid_log_cursor",
                    "日志续传位置无效。",
                ) from exc

        async def generate() -> AsyncIterator[str]:
            current = cursor
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    return
                page = (
                    {"events": []}
                    if runtime_log_store is None
                    else await asyncio.to_thread(
                        runtime_log_store.query,
                        after=current,
                        limit=200,
                    )
                )
                events = page["events"]
                assert isinstance(events, list)
                for event in events:
                    event_id = int(str(event["event_id"]))
                    if event_id <= current:
                        continue
                    current = event_id
                    payload = json.dumps(
                        event,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    yield (
                        f"id: {current}\n"
                        "event: runtime-log\n"
                        f"data: {payload}\n\n"
                    )
                if not events:
                    yield ": keepalive\n\n"
                if runtime_log_store is None:
                    await asyncio.sleep(1)
                else:
                    await asyncio.to_thread(
                        runtime_log_store.wait_for_newer,
                        current,
                        1.0,
                    )

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    @router.get("/api/v1/diagnostics/logs/export")
    def export_runtime_logs(
        _: None = Depends(require_session),
    ) -> Response:
        content = (
            b""
            if runtime_log_store is None
            else runtime_log_store.export_text()
        )
        return Response(
            content=content,
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": (
                    'attachment; filename="dahe-runtime-logs.log"'
                ),
                "Cache-Control": "no-store",
            },
        )

    @router.get("/api/v1/history/waybills")
    def list_history(
        _: None = Depends(require_session),
        q: str | None = Query(default=None, max_length=100),
        business_outcome: str | None = Query(default=None, max_length=50),
        contract_subject_code: str = Query(default="shanxi_guienbo"),
    ) -> dict[str, object]:
        return {
            "items": repository.list_waybills(
                query=q,
                business_outcome=business_outcome,
                contract_subject_code=require_contract_subject_code(
                    contract_subject_code
                ),
            )
        }

    @router.get("/api/v1/history/waybills/{waybill_id}")
    def get_history(
        waybill_id: str,
        _: None = Depends(require_session),
        contract_subject_code: str = Query(default="shanxi_guienbo"),
    ) -> dict[str, object]:
        matches = repository.list_waybills(
            query=waybill_id,
            contract_subject_code=require_contract_subject_code(
                contract_subject_code
            ),
        )
        exact = next(
            (item for item in matches if item["waybill_id"] == waybill_id),
            None,
        )
        if exact is None:
            raise ApiError(404, "waybill_not_found", "没有找到该运单。")
        return repository.get_item(str(exact["work_item_id"]))

    @router.get("/api/v1/evidence/{sha256}")
    def get_evidence(
        sha256: str,
        _: None = Depends(require_session),
    ) -> Response:
        try:
            content = evidence_store.read_bytes(sha256)
        except (EvidenceIntegrityError, InvalidEvidenceIdentityError) as exc:
            raise ApiError(
                404,
                "evidence_not_found",
                "没有找到该证据图片。",
            ) from exc
        media_type = (
            "image/png"
            if content.startswith(b"\x89PNG\r\n\x1a\n")
            else "image/jpeg"
            if content.startswith(b"\xff\xd8")
            else "application/octet-stream"
        )
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Cache-Control": "private, immutable, max-age=31536000",
                "X-Content-SHA256": sha256,
            },
        )

    return router


def _problem_reason(review_reason: str) -> str:
    if review_reason == "numeric_mismatch":
        return "confirmed_weight_mismatch"
    if review_reason == "suspected_swapped":
        return "swapped_tickets"
    if review_reason == "missing_ticket":
        return "missing_ticket"
    if review_reason in {
        "both_loading",
        "both_unloading",
        "duplicate_image",
        "wrong_ticket",
    }:
        return "wrong_ticket"
    if review_reason in {
        "role_unknown",
        "ticket_weight_format_suspicious",
        "ocr_weight_disagreement",
    }:
        return "key_content_unconfirmed"
    return "other_business_problem"
