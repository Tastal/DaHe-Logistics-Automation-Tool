from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from dahe.domain.daily.calendar import (
    SHANGHAI,
    CandidateQueryWindow,
    DailyDomainError,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _required_text(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DailyDomainError(f"{field} is required")
    return value


def _optional_text(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise DailyDomainError(f"missing {field} must be None")
    return value


def _sha256(
    value: str | None,
    *,
    field: str,
    optional: bool = False,
) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DailyDomainError(f"{field} must be a lowercase SHA-256")
    return value


def _aware(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DailyDomainError(f"{field} must be timezone-aware")
    if value.utcoffset() is None:
        raise DailyDomainError(f"{field} must be timezone-aware")
    return value.astimezone(SHANGHAI)


def _optional_aware(
    value: datetime | None,
    *,
    field: str,
) -> datetime | None:
    if value is None:
        return None
    return _aware(value, field=field)


def _optional_decimal(
    value: Decimal | None,
    *,
    field: str,
) -> Decimal | None:
    if value is None:
        return None
    if not isinstance(value, Decimal) or not value.is_finite():
        raise DailyDomainError(f"{field} must be a finite Decimal or None")
    if value < 0:
        raise DailyDomainError(f"{field} cannot be negative")
    return value


def _canonical(payload: object) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _fingerprint(payload: object) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _date_value(value: object | None, *, field: str) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise DailyDomainError(f"{field} is invalid")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise DailyDomainError(f"{field} is invalid") from exc


def _datetime_value(
    value: object | None,
    *,
    field: str,
) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise DailyDomainError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise DailyDomainError(f"{field} is invalid") from exc
    return _aware(parsed, field=field)


def _decimal_value(
    value: object | None,
    *,
    field: str,
) -> Decimal | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise DailyDomainError(f"{field} is invalid")
    try:
        return _optional_decimal(Decimal(value), field=field)
    except InvalidOperation as exc:
        raise DailyDomainError(f"{field} is invalid") from exc


@dataclass(frozen=True, slots=True)
class DailyCandidate:
    platform_waybill_id: str
    waybill_number: str | None
    vehicle_number: str | None = None
    platform_loading_time: datetime | None = None

    def __post_init__(self) -> None:
        _required_text(
            self.platform_waybill_id,
            field="platform_waybill_id",
        )
        _optional_text(self.waybill_number, field="waybill_number")
        _optional_text(self.vehicle_number, field="vehicle_number")
        _optional_aware(
            self.platform_loading_time,
            field="platform_loading_time",
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "platform_waybill_id": self.platform_waybill_id,
            "platform_loading_time": (
                None
                if self.platform_loading_time is None
                else _aware(
                    self.platform_loading_time,
                    field="platform_loading_time",
                ).isoformat()
            ),
            "vehicle_number": self.vehicle_number,
            "waybill_number": self.waybill_number,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DailyCandidate:
        if not isinstance(payload, dict):
            raise DailyDomainError("candidate payload is invalid")
        return cls(
            platform_waybill_id=str(payload.get("platform_waybill_id", "")),
            waybill_number=(
                None if payload.get("waybill_number") is None else str(payload["waybill_number"])
            ),
            vehicle_number=_payload_optional_text(
                payload,
                "vehicle_number",
            ),
            platform_loading_time=_datetime_value(
                payload.get("platform_loading_time"),
                field="platform_loading_time",
            ),
        )


@dataclass(frozen=True, slots=True)
class DailyCandidateSnapshot:
    snapshot_id: str
    target_business_date: date
    receive_place: str
    query_window: CandidateQueryWindow
    source_contract_sha256: str
    candidates: tuple[DailyCandidate, ...]
    captured_at: datetime
    platform_display_total: int | None = None
    response_total: int | None = None
    response_page_count: int | None = None
    unique_identity_total: int | None = None
    query_scope_sha256: str | None = None
    scope_complete: bool = True
    scope_diagnostic_code: str | None = None

    def __post_init__(self) -> None:
        _required_text(self.snapshot_id, field="snapshot_id")
        if not isinstance(self.target_business_date, date) or isinstance(
            self.target_business_date, datetime
        ):
            raise DailyDomainError("target_business_date must be a date")
        _required_text(self.receive_place, field="receive_place")
        if not isinstance(self.query_window, CandidateQueryWindow):
            raise DailyDomainError("query_window is invalid")
        if self.query_window.business_date != self.target_business_date:
            raise DailyDomainError("query window must match target_business_date")
        _sha256(
            self.source_contract_sha256,
            field="source_contract_sha256",
        )
        if not isinstance(self.candidates, tuple):
            raise DailyDomainError("candidates must be an immutable tuple")
        identities = [candidate.platform_waybill_id for candidate in self.candidates]
        if len(identities) != len(set(identities)):
            raise DailyDomainError("candidate snapshot contains duplicate identity")
        _aware(self.captured_at, field="captured_at")
        if self.captured_at.astimezone(SHANGHAI) < self.query_window.end:
            raise DailyDomainError("captured_at cannot precede query end")
        for field_name, value in (
            ("platform_display_total", self.platform_display_total),
            ("response_total", self.response_total),
            ("response_page_count", self.response_page_count),
            ("unique_identity_total", self.unique_identity_total),
        ):
            if value is not None and (type(value) is not int or value < 0):
                raise DailyDomainError(f"{field_name} must be a non-negative integer")
        if self.query_scope_sha256 is not None:
            _sha256(self.query_scope_sha256, field="query_scope_sha256")
        if self.response_page_count is not None and self.response_page_count < 1:
            raise DailyDomainError("response_page_count must be positive")
        if type(self.scope_complete) is not bool:
            raise DailyDomainError("scope_complete must be a boolean")
        if self.scope_diagnostic_code is not None:
            _required_text(
                self.scope_diagnostic_code,
                field="scope_diagnostic_code",
            )
        totals = (
            self.platform_display_total,
            self.response_total,
            self.unique_identity_total,
        )
        known_totals = tuple(value for value in totals if value is not None)
        if self.scope_complete and known_totals and len(set(known_totals)) != 1:
            raise DailyDomainError("complete scope totals must reconcile")
        if not self.scope_complete and self.scope_diagnostic_code is None:
            raise DailyDomainError("incomplete scope requires a diagnostic code")

    def constructor_payload(self) -> dict[str, object]:
        return {
            "snapshot_id": self.snapshot_id,
            "target_business_date": self.target_business_date,
            "receive_place": self.receive_place,
            "query_window": self.query_window,
            "source_contract_sha256": self.source_contract_sha256,
            "candidates": self.candidates,
            "captured_at": self.captured_at,
            "platform_display_total": self.platform_display_total,
            "response_total": self.response_total,
            "response_page_count": self.response_page_count,
            "unique_identity_total": self.unique_identity_total,
            "query_scope_sha256": self.query_scope_sha256,
            "scope_complete": self.scope_complete,
            "scope_diagnostic_code": self.scope_diagnostic_code,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            "candidate_count": len(self.candidates),
            "candidates": [candidate.to_payload() for candidate in self.candidates],
            "captured_at": _aware(
                self.captured_at,
                field="captured_at",
            ).isoformat(),
            "query_end": self.query_window.end.isoformat(),
            "query_safety_end": self.query_window.safety_end.isoformat(),
            "query_start": self.query_window.start.isoformat(),
            "receive_place": self.receive_place,
            "snapshot_id": self.snapshot_id,
            "source_contract_sha256": self.source_contract_sha256,
            "target_business_date": self.target_business_date.isoformat(),
            "platform_display_total": self.platform_display_total,
            "response_total": self.response_total,
            "response_page_count": self.response_page_count,
            "unique_identity_total": self.unique_identity_total,
            "query_scope_sha256": self.query_scope_sha256,
            "scope_complete": self.scope_complete,
            "scope_diagnostic_code": self.scope_diagnostic_code,
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_payload())

    @classmethod
    def from_payload(cls, payload: object) -> DailyCandidateSnapshot:
        if not isinstance(payload, dict):
            raise DailyDomainError("snapshot payload is invalid")
        business_date = _date_value(
            payload.get("target_business_date"),
            field="target_business_date",
        )
        if business_date is None:
            raise DailyDomainError("target_business_date is required")
        start = _datetime_value(payload.get("query_start"), field="query_start")
        end = _datetime_value(payload.get("query_end"), field="query_end")
        safety_end = _datetime_value(
            payload.get("query_safety_end"),
            field="query_safety_end",
        )
        captured_at = _datetime_value(
            payload.get("captured_at"),
            field="captured_at",
        )
        if start is None or end is None or safety_end is None or captured_at is None:
            raise DailyDomainError("snapshot timestamps are required")
        raw_candidates = payload.get("candidates")
        if not isinstance(raw_candidates, list):
            raise DailyDomainError("snapshot candidates are invalid")
        candidates = tuple(DailyCandidate.from_payload(candidate) for candidate in raw_candidates)
        if payload.get("candidate_count") != len(candidates):
            raise DailyDomainError("snapshot candidate count is inconsistent")
        return cls(
            snapshot_id=str(payload.get("snapshot_id", "")),
            target_business_date=business_date,
            receive_place=str(payload.get("receive_place", "")),
            query_window=CandidateQueryWindow(
                business_date=business_date,
                start=start,
                end=end,
                safety_end=safety_end,
            ),
            source_contract_sha256=str(payload.get("source_contract_sha256", "")),
            candidates=candidates,
            captured_at=captured_at,
            platform_display_total=_optional_non_negative_integer(
                payload.get("platform_display_total"),
                field="platform_display_total",
            ),
            response_total=_optional_non_negative_integer(
                payload.get("response_total"),
                field="response_total",
            ),
            response_page_count=_optional_non_negative_integer(
                payload.get("response_page_count"),
                field="response_page_count",
            ),
            unique_identity_total=_optional_non_negative_integer(
                payload.get("unique_identity_total"),
                field="unique_identity_total",
            ),
            query_scope_sha256=_payload_optional_text(
                payload,
                "query_scope_sha256",
            ),
            scope_complete=(
                True
                if "scope_complete" not in payload
                else _payload_boolean(payload, "scope_complete")
            ),
            scope_diagnostic_code=_payload_optional_text(
                payload,
                "scope_diagnostic_code",
            ),
        )


@dataclass(frozen=True, slots=True)
class DailyObservationFields:
    shipping_mine: str | None
    planned_date: date | None
    loading_time: datetime | None
    vehicle_number: str | None
    loading_net_tonnes: Decimal | None
    unloading_net_tonnes: Decimal | None
    coal_type: str | None
    unloading_place: str | None
    unloading_time: datetime | None

    def __post_init__(self) -> None:
        for field, value in (
            ("shipping_mine", self.shipping_mine),
            ("vehicle_number", self.vehicle_number),
            ("coal_type", self.coal_type),
            ("unloading_place", self.unloading_place),
        ):
            _optional_text(value, field=field)
        if self.planned_date is not None and (
            not isinstance(self.planned_date, date) or isinstance(self.planned_date, datetime)
        ):
            raise DailyDomainError("planned_date must be a date or None")
        _optional_aware(self.loading_time, field="loading_time")
        _optional_aware(self.unloading_time, field="unloading_time")
        _optional_decimal(
            self.loading_net_tonnes,
            field="loading_net_tonnes",
        )
        _optional_decimal(
            self.unloading_net_tonnes,
            field="unloading_net_tonnes",
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "coal_type": self.coal_type,
            "loading_net_tonnes": (
                None if self.loading_net_tonnes is None else str(self.loading_net_tonnes)
            ),
            "loading_time": (
                None
                if self.loading_time is None
                else _aware(
                    self.loading_time,
                    field="loading_time",
                ).isoformat()
            ),
            "planned_date": (None if self.planned_date is None else self.planned_date.isoformat()),
            "shipping_mine": self.shipping_mine,
            "unloading_net_tonnes": (
                None if self.unloading_net_tonnes is None else str(self.unloading_net_tonnes)
            ),
            "unloading_place": self.unloading_place,
            "unloading_time": (
                None
                if self.unloading_time is None
                else _aware(
                    self.unloading_time,
                    field="unloading_time",
                ).isoformat()
            ),
            "vehicle_number": self.vehicle_number,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DailyObservationFields:
        if not isinstance(payload, dict):
            raise DailyDomainError("daily observation fields are invalid")
        return cls(
            shipping_mine=_payload_optional_text(payload, "shipping_mine"),
            planned_date=_date_value(
                payload.get("planned_date"),
                field="planned_date",
            ),
            loading_time=_datetime_value(
                payload.get("loading_time"),
                field="loading_time",
            ),
            vehicle_number=_payload_optional_text(payload, "vehicle_number"),
            loading_net_tonnes=_decimal_value(
                payload.get("loading_net_tonnes"),
                field="loading_net_tonnes",
            ),
            unloading_net_tonnes=_decimal_value(
                payload.get("unloading_net_tonnes"),
                field="unloading_net_tonnes",
            ),
            coal_type=_payload_optional_text(payload, "coal_type"),
            unloading_place=_payload_optional_text(
                payload,
                "unloading_place",
            ),
            unloading_time=_datetime_value(
                payload.get("unloading_time"),
                field="unloading_time",
            ),
        )


def _payload_optional_text(
    payload: dict[object, object],
    key: str,
) -> str | None:
    value = payload.get(key)
    return None if value is None else str(value)


def _optional_non_negative_integer(
    value: object,
    *,
    field: str,
) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise DailyDomainError(f"{field} must be a non-negative integer")
    return value


def _payload_boolean(
    payload: dict[object, object],
    key: str,
) -> bool:
    value = payload.get(key)
    if type(value) is not bool:
        raise DailyDomainError(f"{key} must be a boolean")
    return value


@dataclass(frozen=True, slots=True)
class DailyWaybillObservation:
    observation_id: str
    snapshot_id: str
    platform_waybill_id: str
    waybill_number: str | None
    fields: DailyObservationFields
    loading_ticket_sha256: str | None
    unloading_ticket_sha256: str | None
    source_detail_sha256: str
    observed_at: datetime

    def __post_init__(self) -> None:
        _required_text(self.observation_id, field="observation_id")
        _required_text(self.snapshot_id, field="snapshot_id")
        _required_text(
            self.platform_waybill_id,
            field="platform_waybill_id",
        )
        _optional_text(self.waybill_number, field="waybill_number")
        if not isinstance(self.fields, DailyObservationFields):
            raise DailyDomainError("fields are invalid")
        _sha256(
            self.loading_ticket_sha256,
            field="loading_ticket_sha256",
            optional=True,
        )
        _sha256(
            self.unloading_ticket_sha256,
            field="unloading_ticket_sha256",
            optional=True,
        )
        _sha256(
            self.source_detail_sha256,
            field="source_detail_sha256",
        )
        _aware(self.observed_at, field="observed_at")

    def field_payload(self) -> dict[str, object]:
        return {
            "fields": self.fields.to_payload(),
            "loading_ticket_sha256": self.loading_ticket_sha256,
            "unloading_ticket_sha256": self.unloading_ticket_sha256,
            "waybill_number": self.waybill_number,
        }

    @property
    def field_fingerprint(self) -> str:
        return _fingerprint(self.field_payload())

    def to_payload(self) -> dict[str, object]:
        return {
            **self.field_payload(),
            "observation_id": self.observation_id,
            "observed_at": _aware(
                self.observed_at,
                field="observed_at",
            ).isoformat(),
            "platform_waybill_id": self.platform_waybill_id,
            "snapshot_id": self.snapshot_id,
            "source_detail_sha256": self.source_detail_sha256,
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_payload())

    @classmethod
    def from_payload(cls, payload: object) -> DailyWaybillObservation:
        if not isinstance(payload, dict):
            raise DailyDomainError("observation payload is invalid")
        observed_at = _datetime_value(
            payload.get("observed_at"),
            field="observed_at",
        )
        if observed_at is None:
            raise DailyDomainError("observed_at is required")
        return cls(
            observation_id=str(payload.get("observation_id", "")),
            snapshot_id=str(payload.get("snapshot_id", "")),
            platform_waybill_id=str(payload.get("platform_waybill_id", "")),
            waybill_number=_payload_optional_text(payload, "waybill_number"),
            fields=DailyObservationFields.from_payload(payload.get("fields")),
            loading_ticket_sha256=_payload_optional_text(
                payload,
                "loading_ticket_sha256",
            ),
            unloading_ticket_sha256=_payload_optional_text(
                payload,
                "unloading_ticket_sha256",
            ),
            source_detail_sha256=str(payload.get("source_detail_sha256", "")),
            observed_at=observed_at,
        )


@dataclass(frozen=True, slots=True)
class DailyRecordRevision:
    revision_id: str
    platform_waybill_id: str
    revision_number: int
    observation_id: str
    field_fingerprint: str
    fields: DailyObservationFields
    waybill_number: str | None
    loading_ticket_sha256: str | None
    unloading_ticket_sha256: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        _required_text(self.revision_id, field="revision_id")
        _required_text(
            self.platform_waybill_id,
            field="platform_waybill_id",
        )
        if not isinstance(self.revision_number, int) or self.revision_number < 1:
            raise DailyDomainError("revision_number must be positive")
        _required_text(self.observation_id, field="observation_id")
        _sha256(self.field_fingerprint, field="field_fingerprint")
        if not isinstance(self.fields, DailyObservationFields):
            raise DailyDomainError("fields are invalid")
        _optional_text(self.waybill_number, field="waybill_number")
        _sha256(
            self.loading_ticket_sha256,
            field="loading_ticket_sha256",
            optional=True,
        )
        _sha256(
            self.unloading_ticket_sha256,
            field="unloading_ticket_sha256",
            optional=True,
        )
        _aware(self.created_at, field="created_at")

    def to_payload(self) -> dict[str, object]:
        return {
            "created_at": _aware(
                self.created_at,
                field="created_at",
            ).isoformat(),
            "field_fingerprint": self.field_fingerprint,
            "fields": self.fields.to_payload(),
            "loading_ticket_sha256": self.loading_ticket_sha256,
            "observation_id": self.observation_id,
            "platform_waybill_id": self.platform_waybill_id,
            "revision_id": self.revision_id,
            "revision_number": self.revision_number,
            "unloading_ticket_sha256": self.unloading_ticket_sha256,
            "waybill_number": self.waybill_number,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DailyRecordRevision:
        if not isinstance(payload, dict):
            raise DailyDomainError("revision payload is invalid")
        created_at = _datetime_value(
            payload.get("created_at"),
            field="created_at",
        )
        if created_at is None:
            raise DailyDomainError("created_at is required")
        revision_number = payload.get("revision_number")
        if not isinstance(revision_number, int):
            raise DailyDomainError("revision_number is invalid")
        return cls(
            revision_id=str(payload.get("revision_id", "")),
            platform_waybill_id=str(payload.get("platform_waybill_id", "")),
            revision_number=revision_number,
            observation_id=str(payload.get("observation_id", "")),
            field_fingerprint=str(payload.get("field_fingerprint", "")),
            fields=DailyObservationFields.from_payload(payload.get("fields")),
            waybill_number=_payload_optional_text(payload, "waybill_number"),
            loading_ticket_sha256=_payload_optional_text(
                payload,
                "loading_ticket_sha256",
            ),
            unloading_ticket_sha256=_payload_optional_text(
                payload,
                "unloading_ticket_sha256",
            ),
            created_at=created_at,
        )


def canonical_json(payload: object) -> str:
    """Return the stable JSON form used by immutable SQLite records."""

    return _canonical(payload)


def revision_id_for(
    *,
    platform_waybill_id: str,
    revision_number: int,
    field_fingerprint: str,
) -> str:
    payload: dict[str, Any] = {
        "field_fingerprint": field_fingerprint,
        "platform_waybill_id": platform_waybill_id,
        "revision_number": revision_number,
    }
    return _fingerprint(payload)[:32]
