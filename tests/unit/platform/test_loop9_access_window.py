from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowError,
    AccessWindowGrant,
    authorize_access_window,
    issue_access_window,
)

NOW = datetime(2026, 7, 28, 15, 0, tzinfo=UTC)


def _issue(**overrides: object) -> AccessWindowGrant:
    values: dict[str, object] = {
        "purpose": AccessPurpose.CONTRACT_DISCOVERY,
        "job_id": "job-loop9-discovery",
        "session_id": "chengfeng-session",
        "build_sha256": "a" * 64,
        "duration_minutes": 60,
        "legacy_idle_confirmed": True,
        "no_settlement_or_payment_confirmed": True,
        "same_account_session_risk_accepted": True,
        "run_mode": "shadow",
        "now": NOW,
    }
    values.update(overrides)
    return issue_access_window(**values)  # type: ignore[arg-type]


def test_access_window_requires_every_current_safety_confirmation() -> None:
    for field in (
        "legacy_idle_confirmed",
        "no_settlement_or_payment_confirmed",
        "same_account_session_risk_accepted",
    ):
        with pytest.raises(AccessWindowError, match="confirmation"):
            _issue(**{field: False})


def test_access_window_is_shadow_only_and_bounded_to_two_hours() -> None:
    with pytest.raises(AccessWindowError, match="shadow"):
        _issue(run_mode="operational")
    with pytest.raises(AccessWindowError, match="between 1 and 120"):
        _issue(duration_minutes=121)


def test_operational_access_window_allows_one_workday_only_for_compat() -> None:
    grant = _issue(
        purpose=AccessPurpose.OPERATIONAL_READ,
        job_id="operational-job",
        duration_minutes=720,
        run_mode="operational",
    )

    assert grant.purpose is AccessPurpose.OPERATIONAL_READ
    assert grant.expires_at - grant.issued_at == timedelta(hours=12)


def test_operational_duration_is_rejected_for_formal_shadow() -> None:
    with pytest.raises(AccessWindowError, match="between 1 and 120"):
        _issue(
            purpose=AccessPurpose.FORMAL_LOCKED_SET,
            duration_minutes=720,
        )


def test_access_window_is_bound_to_purpose_job_session_and_build() -> None:
    grant = _issue()

    authorized = authorize_access_window(
        grant,
        purpose=AccessPurpose.CONTRACT_DISCOVERY,
        job_id="job-loop9-discovery",
        session_id="chengfeng-session",
        build_sha256="a" * 64,
        now=NOW + timedelta(minutes=59),
    )

    assert authorized.access_window_id == grant.access_window_id
    for override in (
        {"job_id": "other-job"},
        {"session_id": "other-session"},
        {"build_sha256": "b" * 64},
        {"purpose": AccessPurpose.FORMAL_LOCKED_SET},
    ):
        with pytest.raises(AccessWindowError, match="does not match"):
            authorize_access_window(
                grant,
                purpose=override.get("purpose", AccessPurpose.CONTRACT_DISCOVERY),
                job_id=override.get("job_id", "job-loop9-discovery"),
                session_id=override.get("session_id", "chengfeng-session"),
                build_sha256=override.get("build_sha256", "a" * 64),
                now=NOW,
            )


def test_expired_or_consumed_access_window_cannot_be_authorized() -> None:
    grant = _issue()
    with pytest.raises(AccessWindowError, match="expired"):
        authorize_access_window(
            grant,
            purpose=grant.purpose,
            job_id=grant.job_id,
            session_id=grant.session_id,
            build_sha256=grant.build_sha256,
            now=grant.expires_at,
        )

    with pytest.raises(AccessWindowError, match="consumed"):
        authorize_access_window(
            grant.consume(now=NOW + timedelta(minutes=1)),
            purpose=grant.purpose,
            job_id=grant.job_id,
            session_id=grant.session_id,
            build_sha256=grant.build_sha256,
            now=NOW + timedelta(minutes=2),
        )


def test_access_window_contains_no_person_identity_and_hides_raw_token() -> None:
    grant = _issue()

    assert "token=" not in repr(grant)
    assert grant.token not in repr(grant)
    assert set(grant.to_persisted_payload()).isdisjoint(
        {"operator", "operator_id", "reviewer_id", "actor_id", "windows_sid"}
    )
    assert "token" not in grant.to_persisted_payload()
