from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dahe.adapters.sqlite.business_connection import (
    SqliteBusinessConnectionSessionStore,
)
from dahe.adapters.sqlite.platform_access import (
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.settlement_capture import (
    SqliteSettlementCaptureStore,
)
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.application.chengfeng.business_session import (
    BUSINESS_SESSION_DURATION,
    BusinessConnectionSessionError,
    confirmation_sha256,
)
from dahe.application.chengfeng.shadow_batch import ShadowBatchTargetKind


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_confirmation_requires_every_current_safety_statement() -> None:
    with pytest.raises(
        BusinessConnectionSessionError,
        match="every current safety confirmation",
    ):
        confirmation_sha256(
            legacy_idle_confirmed=True,
            no_settlement_or_payment_confirmed=False,
            same_account_session_risk_accepted=True,
        )


def test_business_session_reuses_confirmation_and_records_each_read(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 1, 1, 2, 3, tzinfo=UTC)
    runtime = SqliteRuntime(
        data_root=tmp_path.resolve(),
        project_root=Path(__file__).resolve().parents[2],
        instance_id="loop9-business-session-test",
    )
    access = SqlitePlatformAccessRepository(runtime)
    sessions = SqliteBusinessConnectionSessionStore(runtime)
    captures = SqliteSettlementCaptureStore(runtime)
    build_sha256 = _sha("build")
    confirmation = confirmation_sha256(
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
    )
    login_request_hash = _sha("login-window")
    login_window, replayed = access.issue(
        purpose=AccessPurpose.PRODUCTION_SHADOW,
        job_id="business-login",
        session_id="platform-session",
        build_sha256=build_sha256,
        duration_minutes=720,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="operational",
        idempotency_key="login-window",
        request_hash=login_request_hash,
        now=now,
    )
    assert replayed is False

    session, replayed = sessions.start(
        platform_session_id="platform-session",
        build_sha256=build_sha256,
        login_access_window_id=login_window.access_window_id,
        confirmation_sha256=confirmation,
        expires_at=now + BUSINESS_SESSION_DURATION,
        idempotency_key="business-session",
        request_hash=_sha("business-session"),
        now=now,
    )
    assert replayed is False
    assert session.record_version == 1
    same_session, replayed = sessions.start(
        platform_session_id="platform-session",
        build_sha256=build_sha256,
        login_access_window_id=login_window.access_window_id,
        confirmation_sha256=confirmation,
        expires_at=now + BUSINESS_SESSION_DURATION,
        idempotency_key="business-session",
        request_hash=_sha("business-session"),
        now=now,
    )
    assert replayed is True
    assert same_session == session

    access.consume(
        access_window_id=login_window.access_window_id,
        expected_record_version=1,
        now=now + timedelta(minutes=1),
    )
    captures.create_start(
        target_kind=ShadowBatchTargetKind.OPERATIONAL_COMPAT,
        session_id="platform-session",
        source_build_sha256=build_sha256,
        contract_canonical_sha256=_sha("contract"),
        contract_file_sha256=_sha("contract-file"),
        contract_selection_sha256=_sha("selection"),
        identity_context_sha256=_sha("identity"),
        duration_minutes=120,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        idempotency_key="business-read-capture",
        request_hash=_sha("business-read-capture"),
        now=now + timedelta(minutes=2),
        business_session_id=session.business_session_id,
        business_session_expected_record_version=1,
    )
    session = sessions.latest(platform_session_id="platform-session")
    assert session is not None
    assert session.record_version == 2

    closed, replayed = sessions.close(
        business_session_id=session.business_session_id,
        expected_record_version=2,
        reason="explicit",
        idempotency_key="business-close",
        request_hash=_sha("business-close"),
        now=now + timedelta(minutes=3),
    )
    assert replayed is False
    assert closed.status == "closed"
    assert closed.close_reason == "explicit"
    runtime.close()


def test_business_session_rejects_a_second_active_session(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 1, 1, 2, 3, tzinfo=UTC)
    runtime = SqliteRuntime(
        data_root=tmp_path.resolve(),
        project_root=Path(__file__).resolve().parents[2],
        instance_id="loop9-business-session-conflict-test",
    )
    access = SqlitePlatformAccessRepository(runtime)
    sessions = SqliteBusinessConnectionSessionStore(runtime)
    build_sha256 = _sha("build")
    confirmation = confirmation_sha256(
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
    )
    first_window, _ = access.issue(
        purpose=AccessPurpose.PRODUCTION_SHADOW,
        job_id="business-login-one",
        session_id="platform-session",
        build_sha256=build_sha256,
        duration_minutes=720,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="operational",
        idempotency_key="login-one",
        request_hash=_sha("login-one"),
        now=now,
    )
    sessions.start(
        platform_session_id="platform-session",
        build_sha256=build_sha256,
        login_access_window_id=first_window.access_window_id,
        confirmation_sha256=confirmation,
        expires_at=now + BUSINESS_SESSION_DURATION,
        idempotency_key="session-one",
        request_hash=_sha("session-one"),
        now=now,
    )
    access.consume(
        access_window_id=first_window.access_window_id,
        expected_record_version=1,
        now=now + timedelta(minutes=1),
    )
    second_window, _ = access.issue(
        purpose=AccessPurpose.PRODUCTION_SHADOW,
        job_id="business-login-two",
        session_id="platform-session",
        build_sha256=build_sha256,
        duration_minutes=720,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="operational",
        idempotency_key="login-two",
        request_hash=_sha("login-two"),
        now=now + timedelta(minutes=2),
    )
    with pytest.raises(
        BusinessConnectionSessionError,
        match="active business connection session",
    ):
        sessions.start(
            platform_session_id="platform-session",
            build_sha256=build_sha256,
            login_access_window_id=second_window.access_window_id,
            confirmation_sha256=confirmation,
            expires_at=now + BUSINESS_SESSION_DURATION,
            idempotency_key="session-two",
            request_hash=_sha("session-two"),
            now=now + timedelta(minutes=2),
        )
    runtime.close()
