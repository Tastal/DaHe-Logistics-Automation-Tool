from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from dahe.jobs.actions import JobActionFacts, build_action_matrix, serialize_actions
from dahe.jobs.models import JobRecord, JobStatus, WorkItemRecord, WorkItemStatus

STATUS_LABELS: dict[JobStatus, str] = {
    JobStatus.CREATED: "正在建立任务",
    JobStatus.QUEUED: "已排队，等待开始",  # noqa: RUF001
    JobStatus.RUNNING: "正在处理",
    JobStatus.WAITING_RESOURCE: "等待系统资源",
    JobStatus.WAITING_USER: "需要您处理",
    JobStatus.WAITING_EXTERNAL: "等待外部条件恢复",
    JobStatus.RETRY_WAIT: "等待自动重试",
    JobStatus.PAUSE_REQUESTED: "正在安全暂停",
    JobStatus.PAUSED: "已暂停",
    JobStatus.CANCEL_REQUESTED: "正在安全取消",
    JobStatus.CANCELLED: "已取消",
    JobStatus.SUCCEEDED: "已完成",
    JobStatus.FAILED: "本任务处理失败",
}

STAGE_LABELS = {
    "audit.acquire_list": "正在获取运单清单",
    "audit.download_evidence": "正在获取磅单图片",
    "audit.recognize": "正在识别磅单",
    "audit.compare": "正在核对数字",
    "audit.finalize": "正在整理审核结果",
    "audit.recognize.loading": "正在识别装货磅单",
    "audit.recognize.unloading": "正在识别卸货磅单",
    "loading_probe.query": "正在执行装卸车调度探针",
    "loading_probe.complete": "装卸车调度探针已完成",
    "settlement_capture.read": "正在读取运单",
    "settlement_capture.complete": "运单获取完成",
    "daily.acquire_list": "正在读取装卸车运单",
    "daily.download_evidence": "正在下载磅单",
    "daily.recognize": "正在识别磅单",
    "daily.finalize": "正在整理装卸车结果",
    "daily.complete": "装卸车明细处理完成",
    "audit.recognize.complete": "磅单识别完成",
}

RESOURCE_LABELS = {
    "platform_browser": "获取资料",
    "gpu_ocr_slot": "图像识别（主要）",  # noqa: RUF001
    "cpu_ocr_slot": "图像识别（备用）",  # noqa: RUF001
    "db_commit_gate": "保存数据",
    "maintenance_exclusive": "系统维护",
    "platform_human_control": "成丰登录窗口",
}

CHECKPOINT_LABELS = {
    "job.paused": "任务已安全暂停",
    "job.cancelled": "任务已安全取消",
}


def _stage_label(stage: str | None) -> str | None:
    if stage is None:
        return None
    return STAGE_LABELS.get(stage, "正在处理")


def _public_stage(stage: str | None) -> str | None:
    if stage is None:
        return None
    normalized = stage.lower()
    if "login" in normalized:
        return "login"
    if any(value in normalized for value in ("download", "evidence")):
        return "download"
    if any(value in normalized for value in ("recognize", "ocr")):
        return "recognize"
    if any(value in normalized for value in ("compare", "role_validate")):
        return "compare"
    if any(value in normalized for value in ("final", "complete")):
        return "finalize"
    if any(value in normalized for value in ("acquire", "list", "query", "read")):
        return "read"
    return "processing"


def _resource_label(resource_name: str) -> str:
    return RESOURCE_LABELS.get(resource_name, "本地处理资源")


def _business_display_name(job: JobRecord) -> str:
    if job.scope_label == "单条假数据审核":
        return job.scope_label
    if job.job_kind == "test_fixture":
        return "单条假数据审核" if job.task_type == "audit" else "系统验证任务"
    if job.task_type == "daily":
        suffix = job.scope_label.rsplit(" ", 1)[-1]
        return f"装卸车明细 {suffix}" if suffix[:4].isdigit() else "装卸车明细"
    if job.task_type in {"settlement_capture", "audit"}:
        return "运费结算数据获取" if job.task_type == "settlement_capture" else "运费结算"
    return "业务处理任务"


def _waiting_reason(blockers: list[dict[str, object]]) -> str | None:
    if not blockers:
        return None
    first = blockers[0]
    reason = str(first.get("reason", ""))
    kind = str(first.get("kind", ""))
    if kind == "resource" and reason.startswith("resource:"):
        label = _resource_label(reason.removeprefix("resource:"))
        message = f"正在等待{label}"
    elif kind == "user" and reason == "suspected_swapped":
        message = "有运单疑似装卸磅单放反，等待人员确认"  # noqa: RUF001
    elif kind == "user" and reason == "numeric_mismatch":
        message = "有运单数字不一致，等待人员处理"  # noqa: RUF001
    elif kind == "user":
        message = "有运单等待人员处理"
    else:
        message = reason or "正在等待明确的处理条件"
    if len(blockers) == 1:
        return message
    return f"{message}；另有 {len(blockers) - 1} 项等待"  # noqa: RUF001


def project_resources(
    resources: Sequence[dict[str, object]],
) -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for resource in resources:
        resource_name = str(resource["resource_name"])
        leases = cast(list[dict[str, object]], resource["active_leases"])
        queue = cast(list[dict[str, object]], resource["queue"])
        in_use = len(leases)
        waiting_jobs = len({str(item["job_id"]) for item in queue})
        if in_use:
            status_label = "正在使用"
        elif waiting_jobs:
            status_label = "有任务等待"
        else:
            status_label = "空闲"
        projected.append(
            {
                **resource,
                "resource_id": resource_name,
                "display_name": _resource_label(resource_name),
                "status_label": status_label,
                "in_use": in_use,
                "waiting_jobs": waiting_jobs,
                "holder_label": (None if not leases else f"{in_use} 个任务步骤正在使用"),
            }
        )
    return projected


def project_job(
    job: JobRecord,
    items: Sequence[WorkItemRecord],
    runtime: dict[str, object] | None = None,
    *,
    expose_internal_codes: bool = True,
) -> dict[str, object]:
    runtime = runtime or {
        "active_stages": [],
        "blockers": [],
        "checkpoint": None,
        "leases": [],
    }
    runtime_leases = cast(list[dict[str, object]], runtime["leases"])
    runtime_blockers = cast(list[dict[str, object]], runtime["blockers"])
    runtime_stages = cast(list[str], runtime["active_stages"])
    runtime_checkpoint = cast(dict[str, object] | None, runtime["checkpoint"])
    processed = sum(
        item.status in {WorkItemStatus.SUCCEEDED, WorkItemStatus.FAILED} for item in items
    )
    waiting_user = sum(item.status is WorkItemStatus.WAITING_USER for item in items)
    failed = sum(item.status is WorkItemStatus.FAILED for item in items)
    actions = build_action_matrix(
        JobActionFacts(
            task_type=job.task_type,
            status=job.status,
            has_active_attempt=job.status is JobStatus.RUNNING,
            supports_controls=True,
            record_version=job.record_version,
        )
    )
    current_step_text: str | None
    if job.status is JobStatus.CANCELLED:
        remaining = len(items) - processed
        progress_label = f"任务已取消；已处理 {processed}/{len(items)}，{remaining} 项未处理"  # noqa: RUF001
        current_step_text = "任务已安全取消"
    elif job.status is JobStatus.FAILED:
        diagnostic_code = job.diagnostic_code or "UNKNOWN"
        progress_label = f"系统处理失败。数据已保护。诊断编号 {diagnostic_code}"
        current_step_text = "系统处理失败，未进入人工复核"  # noqa: RUF001
    elif job.status is JobStatus.SUCCEEDED:
        progress_label = f"已处理 {processed}/{len(items)}，影子审核完成"  # noqa: RUF001
        current_step_text = _stage_label(job.current_stage)
    elif job.current_stage is not None:
        progress_label = f"{_stage_label(job.current_stage)}，已处理 {processed}/{len(items)}"  # noqa: RUF001
        current_step_text = _stage_label(job.current_stage)
    else:
        progress_label = f"已处理 {processed}/{len(items)}"
        current_step_text = None
    return {
        "job_id": job.job_id,
        "record_version": job.record_version,
        "task_type": job.task_type,
        "display_name": _business_display_name(job),
        "scope_label": _business_display_name(job),
        "progress_label": progress_label,
        "task_name": _business_display_name(job),
        "scope": {
            "label": _business_display_name(job),
            "fixture_id": job.scope_fixture_id if expose_internal_codes else None,
        },
        "run_mode": job.run_mode,
        "job_kind": job.job_kind,
        "conflict_key": job.conflict_key if expose_internal_codes else None,
        "shadow_label": "影子测试",
        "job_status": job.status.value,
        "status_label": STATUS_LABELS[job.status],
        "current_stage": (
            job.current_stage if expose_internal_codes else _public_stage(job.current_stage)
        ),
        "current_stage_label": current_step_text,
        "current_step_text": current_step_text,
        "diagnostic_code": job.diagnostic_code,
        "active_stages": (
            runtime["active_stages"]
            if expose_internal_codes
            else [_public_stage(stage) for stage in runtime_stages]
        ),
        "active_stage_labels": [
            label for stage in runtime_stages if (label := _stage_label(stage)) is not None
        ],
        "blockers": runtime["blockers"] if expose_internal_codes else [],
        "waiting_reason": _waiting_reason(runtime_blockers),
        "checkpoint": runtime["checkpoint"] if expose_internal_codes else None,
        "latest_checkpoint_label": (
            None
            if runtime_checkpoint is None
            else CHECKPOINT_LABELS.get(
                str(runtime_checkpoint["stage"]),
                _stage_label(str(runtime_checkpoint["stage"])),
            )
        ),
        "leases": runtime_leases if expose_internal_codes else [],
        "active_resources": [
            {
                "resource_id": lease["resource_name"],
                "display_name": _resource_label(str(lease["resource_name"])),
            }
            for lease in runtime_leases
        ],
        "counts": {
            "total": len(items),
            "processed": processed,
            "remaining": len(items) - processed,
            "waiting_user": waiting_user,
            "failed": failed,
        },
        "actions": serialize_actions(actions),
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }


def project_item(
    item: WorkItemRecord,
    *,
    include_runtime: bool = False,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "work_item_id": item.work_item_id,
        "record_version": item.record_version,
        "waybill_number": item.waybill_number,
        "vehicle_number": item.vehicle_number,
        "status": item.status.value,
        "current_stage": item.current_stage,
        "business_outcome": item.business_outcome,
        "is_terminal_outcome": (
            item.status is WorkItemStatus.SUCCEEDED and item.business_outcome is not None
        ),
        "platform_loading_net": item.platform_loading_net,
        "platform_unloading_net": item.platform_unloading_net,
        "ticket_loading_net": item.ticket_loading_net,
        "ticket_unloading_net": item.ticket_unloading_net,
        "decision": item.decision,
        "review_reason": item.review_reason,
    }
    if include_runtime:
        projection.update(
            {
                "end_reason": item.end_reason,
                "waiting_reason_kind": item.waiting_reason_kind,
                "waiting_reason": item.waiting_reason,
                "attempt_count": item.attempt_count,
                "diagnostic_code": item.diagnostic_code,
            }
        )
    return projection
