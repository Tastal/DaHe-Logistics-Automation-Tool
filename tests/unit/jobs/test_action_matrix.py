from __future__ import annotations

from dahe.jobs.actions import (
    JobActionFacts,
    build_action_matrix,
    build_start_action_matrix,
    serialize_actions,
)
from dahe.jobs.models import JobStatus


def test_queued_loop2_job_only_exposes_a_safe_details_action() -> None:
    actions = build_action_matrix(
        JobActionFacts(
            task_type="audit",
            status=JobStatus.QUEUED,
            has_active_attempt=False,
        )
    )

    assert tuple(actions) == ("view_details",)
    assert actions["view_details"].visible is True
    assert actions["view_details"].enabled is True
    assert actions["view_details"].label == "查看任务详情"


def test_succeeded_loop2_job_exposes_results_without_inventing_controls() -> None:
    actions = build_action_matrix(
        JobActionFacts(
            task_type="audit",
            status=JobStatus.SUCCEEDED,
            has_active_attempt=False,
        )
    )

    assert tuple(actions) == ("view_results",)
    assert actions["view_results"].label == "查看审核结果"


def test_start_action_reports_the_real_conflict_reason() -> None:
    available = build_start_action_matrix(
        has_active_scope_conflict=False,
        expected_record_version=0,
    )
    blocked = build_start_action_matrix(
        has_active_scope_conflict=True,
        expected_record_version=3,
    )

    assert available["start_audit"].enabled is True
    assert available["start_audit"].reason is None
    assert available["start_audit"].expected_record_version == 0
    assert blocked["start_audit"].enabled is False
    assert blocked["start_audit"].reason == "相同范围的审核任务正在运行"
    assert blocked["start_audit"].expected_record_version == 3


def test_versioned_controls_serialize_the_authoritative_job_version() -> None:
    matrix = build_action_matrix(
        JobActionFacts(
            task_type="audit",
            status=JobStatus.RUNNING,
            has_active_attempt=True,
            supports_controls=True,
            record_version=7,
        )
    )

    serialized = serialize_actions(matrix)

    assert serialized["pause"]["expected_record_version"] == 7
    assert serialized["cancel"]["expected_record_version"] == 7
    assert "expected_record_version" not in serialized["view_details"]


def test_production_business_jobs_expose_cooperative_controls() -> None:
    for task_type in ("settlement_capture", "daily"):
        running = build_action_matrix(
            JobActionFacts(
                task_type=task_type,
                status=JobStatus.RUNNING,
                has_active_attempt=True,
                supports_controls=True,
                record_version=11,
            )
        )
        paused = build_action_matrix(
            JobActionFacts(
                task_type=task_type,
                status=JobStatus.PAUSED,
                has_active_attempt=False,
                supports_controls=True,
                record_version=12,
            )
        )

        assert tuple(running) == ("view_details", "pause", "cancel")
        assert running["pause"].expected_record_version == 11
        assert tuple(paused) == ("view_details", "resume", "cancel")
        assert paused["resume"].expected_record_version == 12
        assert "审核" not in running["pause"].label
