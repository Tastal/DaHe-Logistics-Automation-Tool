from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from dahe.jobs.models import JobStatus


@dataclass(frozen=True, slots=True)
class JobAction:
    visible: bool
    enabled: bool
    reason: str | None
    label: str
    expected_record_version: int | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "visible": self.visible,
            "enabled": self.enabled,
            "reason": self.reason,
            "label": self.label,
        }
        if self.expected_record_version is not None:
            payload["expected_record_version"] = self.expected_record_version
        return payload


@dataclass(frozen=True, slots=True)
class JobActionFacts:
    task_type: str
    status: JobStatus
    has_active_attempt: bool
    supports_controls: bool = False
    record_version: int | None = None


@dataclass(frozen=True, slots=True)
class ProtectedStartActionFacts:
    label: str
    active_conflict: bool
    expected_record_version: int


def build_action_matrix(facts: JobActionFacts) -> dict[str, JobAction]:
    """Return only controls implemented safely for the selected job."""
    if facts.task_type not in {
        "audit",
        "loading_probe",
        "settlement_capture",
        "daily",
    }:
        return {}
    if facts.task_type == "audit":
        pause_label = "暂停此审核任务"
        resume_label = "继续此审核任务"
        cancel_label = "取消本次审核"
    elif facts.task_type == "loading_probe":
        pause_label = "暂停此装卸车演练"
        resume_label = "继续此装卸车演练"
        cancel_label = "取消本次装卸车演练"
    elif facts.task_type == "settlement_capture":
        pause_label = "暂停获取运单"
        resume_label = "继续获取运单"
        cancel_label = "取消获取运单"
    else:
        pause_label = "暂停获取装卸车明细"
        resume_label = "继续获取装卸车明细"
        cancel_label = "取消获取装卸车明细"
    if facts.supports_controls:
        actions: dict[str, JobAction] = {
            "view_details": JobAction(
                visible=True,
                enabled=True,
                reason=None,
                label="查看任务详情",
            )
        }
        if facts.status in {
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.WAITING_RESOURCE,
        }:
            actions["pause"] = JobAction(
                True,
                True,
                None,
                pause_label,
                facts.record_version,
            )
            actions["cancel"] = JobAction(
                True,
                True,
                None,
                cancel_label,
                facts.record_version,
            )
        elif facts.status is JobStatus.PAUSED:
            actions["resume"] = JobAction(
                True,
                True,
                None,
                resume_label,
                facts.record_version,
            )
            actions["cancel"] = JobAction(
                True,
                True,
                None,
                cancel_label,
                facts.record_version,
            )
        elif facts.status in {
            JobStatus.PAUSE_REQUESTED,
            JobStatus.CANCEL_REQUESTED,
        }:
            actions["cancel"] = JobAction(
                True,
                facts.status is JobStatus.PAUSE_REQUESTED,
                (
                    None
                    if facts.status is JobStatus.PAUSE_REQUESTED
                    else "任务正在安全取消"
                ),
                cancel_label,
                facts.record_version,
            )
        elif facts.status is JobStatus.WAITING_USER:
            actions["pause"] = JobAction(
                True,
                False,
                "等待人工处理时不占用自动资源",
                pause_label,
                facts.record_version,
            )
            actions["cancel"] = JobAction(
                True,
                True,
                None,
                cancel_label,
                facts.record_version,
            )
        elif facts.status is JobStatus.SUCCEEDED and facts.task_type == "audit":
            actions = {
                "view_results": JobAction(
                    visible=True,
                    enabled=True,
                    reason=None,
                    label="查看审核结果",
                )
            }
        return actions
    if facts.status is JobStatus.SUCCEEDED:
        return {
            "view_results": JobAction(
                visible=True,
                enabled=True,
                reason=None,
                label="查看审核结果",
            )
        }
    return {
        "view_details": JobAction(
            visible=True,
            enabled=True,
            reason=None,
            label="查看任务详情",
        )
    }


def build_start_action_matrix(
    *,
    has_active_scope_conflict: bool,
    expected_record_version: int | None = None,
) -> dict[str, JobAction]:
    return {
        "start_audit": JobAction(
            visible=True,
            enabled=not has_active_scope_conflict,
            reason=(
                "相同范围的审核任务正在运行"
                if has_active_scope_conflict
                else None
            ),
            label="开始审核",
            expected_record_version=expected_record_version,
        )
    }


def build_protected_start_action_matrix(
    facts_by_action: Mapping[str, ProtectedStartActionFacts],
) -> dict[str, JobAction]:
    return {
        action_id: JobAction(
            visible=True,
            enabled=not facts.active_conflict,
            reason=(
                "相同范围的演练任务正在运行"
                if facts.active_conflict
                else None
            ),
            label=facts.label,
            expected_record_version=facts.expected_record_version,
        )
        for action_id, facts in facts_by_action.items()
    }


def serialize_actions(actions: dict[str, JobAction]) -> dict[str, dict[str, object]]:
    return {name: action.as_dict() for name, action in actions.items()}
