from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

BUSINESS_SESSION_DURATION = timedelta(hours=12)


class BusinessConnectionSessionError(RuntimeError):
    """Raised when a working-day business session cannot advance safely."""


def confirmation_sha256(
    *,
    legacy_idle_confirmed: bool,
    no_settlement_or_payment_confirmed: bool,
    same_account_session_risk_accepted: bool,
) -> str:
    confirmations = {
        "legacy_idle_confirmed": legacy_idle_confirmed,
        "no_settlement_or_payment_confirmed": (
            no_settlement_or_payment_confirmed
        ),
        "same_account_session_risk_accepted": (
            same_account_session_risk_accepted
        ),
    }
    if not all(value is True for value in confirmations.values()):
        raise BusinessConnectionSessionError(
            "every current safety confirmation is required"
        )
    canonical = json.dumps(
        confirmations,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class BusinessConnectionSession:
    business_session_id: str
    platform_session_id: str
    build_sha256: str
    login_access_window_id: str
    confirmation_sha256: str
    status: str
    expires_at: datetime
    closed_at: datetime | None
    close_reason: str | None
    record_version: int
    created_at: datetime
    updated_at: datetime

    def is_expired(self, *, now: datetime) -> bool:
        if now.tzinfo is None or now.utcoffset() is None:
            raise BusinessConnectionSessionError(
                "business session timestamp must be timezone-aware"
            )
        return now.astimezone(UTC) >= self.expires_at
