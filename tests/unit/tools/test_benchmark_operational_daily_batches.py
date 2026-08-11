from __future__ import annotations

from pathlib import Path

import tools.benchmark_operational_daily_batches as benchmark_module
from tools.benchmark_operational_daily_batches import (
    MAX_AUTOMATIC_RESUMES,
    _safe_automatic_recovery_allowed,
)


def test_benchmark_requests_and_records_network_only_measurement() -> None:
    source = Path(benchmark_module.__file__).read_text(encoding="utf-8")
    assert source.count('"network_only_measurement": True') == 3


def _paused_job() -> dict[str, object]:
    return {
        "job_status": "paused",
        "diagnostic_code": "CF-BROWSER-CLOSED",
        "waiting_reason": "access_window_expired",
        "actions": {
            "resume": {
                "enabled": True,
                "expected_record_version": 6,
            }
        },
    }


def test_safe_browser_handoff_can_request_official_recovery() -> None:
    assert _safe_automatic_recovery_allowed(
        _paused_job(), automatic_recoveries=0
    )


def test_daily_login_required_can_request_official_recovery() -> None:
    job = _paused_job()
    job["diagnostic_code"] = "CF-DAILY-LOGIN-REQUIRED"
    assert _safe_automatic_recovery_allowed(job, automatic_recoveries=0)


def test_login_and_contract_failures_are_never_automatically_resumed() -> None:
    for diagnostic_code in (
        "CF-LOGIN-CAPTCHA-REQUIRED",
        "CF-LOGIN-CREDENTIALS-INVALID",
        "CF-DAILY-CONTRACT-RESPONSE-MISMATCH",
    ):
        job = _paused_job()
        job["diagnostic_code"] = diagnostic_code
        assert not _safe_automatic_recovery_allowed(
            job, automatic_recoveries=0
        )


def test_safe_resume_stops_after_bounded_attempts() -> None:
    assert (
        not _safe_automatic_recovery_allowed(
            _paused_job(),
            automatic_recoveries=MAX_AUTOMATIC_RESUMES,
        )
    )
