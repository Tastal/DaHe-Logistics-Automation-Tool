from __future__ import annotations

from dahe.application.audit.projections import project_job
from dahe.jobs.models import JobRecord, JobStatus


def _job(*, task_type: str, scope_label: str, stage: str) -> JobRecord:
    return JobRecord(
        job_id="projection-job",
        task_type=task_type,
        scope_label=scope_label,
        scope_fixture_id="",
        scope_fingerprint="projection-fixture",
        run_mode="operational",
        status=JobStatus.RUNNING,
        current_stage=stage,
        diagnostic_code=None,
        record_version=1,
        created_at="2026-08-05T19:57:00+08:00",
        updated_at="2026-08-05T20:07:00+08:00",
    )


def test_production_projection_never_falls_back_to_internal_task_or_stage_codes() -> None:
    projected = project_job(
        _job(
            task_type="settlement_capture",
            scope_label="capture:operational_compat",
            stage="settlement_capture.unknown_internal_stage",
        ),
        (),
        expose_internal_codes=False,
    )

    assert projected["display_name"] == "运费结算数据获取"
    assert projected["current_stage_label"] == "正在处理"
    assert "capture:operational_compat" not in str(projected)
    assert "unknown_internal_stage" not in str(projected["current_stage_label"])


def test_daily_projection_uses_business_date_without_exposing_raw_scope() -> None:
    projected = project_job(
        _job(
            task_type="daily",
            scope_label="daily:operational_compat 2026-08-05",
            stage="daily.recognize",
        ),
        (),
        expose_internal_codes=False,
    )

    assert projected["display_name"] == "装卸车明细 2026-08-05"
    assert projected["current_stage_label"] == "正在识别磅单"
    assert "operational_compat" not in str(projected)
