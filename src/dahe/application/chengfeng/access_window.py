from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class AccessWindowError(RuntimeError):
    """Raised when a real-platform access window is absent or no longer valid."""


class AccessPurpose(StrEnum):
    CONTRACT_DISCOVERY = "contract_discovery"
    FORMAL_LOCKED_SET = "formal_locked_set"
    PRODUCTION_SHADOW = "production_shadow"
    OPERATIONAL_READ = "operational_read"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AccessWindowError("access window timestamps must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class AccessWindowGrant:
    access_window_id: str
    purpose: AccessPurpose
    job_id: str
    session_id: str
    build_sha256: str
    issued_at: datetime
    expires_at: datetime
    token_digest: str
    consumed_at: datetime | None = None
    token: str = field(default="", repr=False, compare=False)

    def consume(self, *, now: datetime) -> AccessWindowGrant:
        instant = _utc(now)
        if self.consumed_at is not None:
            raise AccessWindowError("access window is already consumed")
        if instant >= self.expires_at:
            raise AccessWindowError("access window is expired")
        return replace(self, consumed_at=instant, token="")

    def to_persisted_payload(self) -> dict[str, object]:
        return {
            "access_window_id": self.access_window_id,
            "purpose": self.purpose.value,
            "job_id": self.job_id,
            "session_id": self.session_id,
            "build_sha256": self.build_sha256,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "token_digest": self.token_digest,
            "consumed_at": (
                None if self.consumed_at is None else self.consumed_at.isoformat()
            ),
        }


def issue_access_window(
    *,
    purpose: AccessPurpose,
    job_id: str,
    session_id: str,
    build_sha256: str,
    duration_minutes: int,
    legacy_idle_confirmed: bool,
    no_settlement_or_payment_confirmed: bool,
    same_account_session_risk_accepted: bool,
    run_mode: str,
    now: datetime,
) -> AccessWindowGrant:
    if not isinstance(purpose, AccessPurpose):
        raise AccessWindowError("access window purpose is invalid")
    operational_window = bool(
        run_mode == "operational"
        and purpose
        in {
            AccessPurpose.OPERATIONAL_READ,
            AccessPurpose.PRODUCTION_SHADOW,
        }
    )
    expected_run_mode = (
        "operational"
        if purpose is AccessPurpose.OPERATIONAL_READ
        else "shadow"
    )
    if run_mode != expected_run_mode and not operational_window:
        raise AccessWindowError(
            f"{purpose.value} access requires {expected_run_mode} mode"
        )
    if (
        not legacy_idle_confirmed
        or not no_settlement_or_payment_confirmed
        or not same_account_session_risk_accepted
    ):
        raise AccessWindowError("every current safety confirmation is required")
    maximum_minutes = (
        720
        if operational_window
        else 120
    )
    if (
        isinstance(duration_minutes, bool)
        or not isinstance(duration_minutes, int)
        or not 1 <= duration_minutes <= maximum_minutes
    ):
        raise AccessWindowError(
            "duration must be between 1 and "
            f"{maximum_minutes} minutes"
        )
    if not job_id or not session_id:
        raise AccessWindowError("job and browser session identities are required")
    if not SHA256_PATTERN.fullmatch(build_sha256):
        raise AccessWindowError("build identity must be lowercase SHA-256")

    issued_at = _utc(now)
    raw_token = secrets.token_urlsafe(32)
    return AccessWindowGrant(
        access_window_id=secrets.token_urlsafe(18),
        purpose=purpose,
        job_id=job_id,
        session_id=session_id,
        build_sha256=build_sha256,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=duration_minutes),
        token_digest=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        token=raw_token,
    )


def authorize_access_window(
    grant: AccessWindowGrant,
    *,
    purpose: AccessPurpose,
    job_id: str,
    session_id: str,
    build_sha256: str,
    now: datetime,
) -> AccessWindowGrant:
    if grant.consumed_at is not None:
        raise AccessWindowError("access window is consumed")
    if _utc(now) >= grant.expires_at:
        raise AccessWindowError("access window is expired")
    if (
        grant.purpose is not purpose
        or grant.job_id != job_id
        or grant.session_id != session_id
        or grant.build_sha256 != build_sha256
    ):
        raise AccessWindowError("access window does not match the requested operation")
    return grant
