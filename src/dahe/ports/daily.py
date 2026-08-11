from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Protocol

from dahe.domain.daily.calendar import CandidateQueryWindow
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyRecordRevision,
    DailyWaybillObservation,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CAPABILITY = re.compile(r"^[^\s?#:/\\]{1,512}$")
_TICKET_SLOTS = frozenset({"loading", "unloading"})


def _safe_identity(value: object, *, maximum: int) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and value == value.strip()
        and len(value) <= maximum
        and not any(
            ord(character) < 32 or ord(character) == 127
            for character in value
        )
    )


class DailyDetailCaptureContractError(ValueError):
    """Raised when durable daily detail evidence violates its safe schema."""


@dataclass(frozen=True, slots=True)
class DailyTicketSlotCapture:
    """One upload-slot capability and its independently committed image."""

    slot: str
    ticket_ref: str
    media_type: str
    image_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            self.slot not in _TICKET_SLOTS
            or _SAFE_CAPABILITY.fullmatch(self.ticket_ref) is None
            or not isinstance(self.media_type, str)
            or not self.media_type
            or len(self.media_type) > 100
            or (
                self.image_sha256 is not None
                and _SHA256.fullmatch(self.image_sha256) is None
            )
        ):
            raise DailyDetailCaptureContractError(
                "daily ticket slot capture is invalid"
            )

    def to_payload(self) -> dict[str, object]:
        return {
            "image_sha256": self.image_sha256,
            "media_type": self.media_type,
            "slot": self.slot,
            "ticket_ref": self.ticket_ref,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DailyTicketSlotCapture:
        if not isinstance(payload, dict) or set(payload) != {
            "image_sha256",
            "media_type",
            "slot",
            "ticket_ref",
        }:
            raise DailyDetailCaptureContractError(
                "daily ticket slot capture fields do not match schema"
            )
        values = (
            payload["slot"],
            payload["ticket_ref"],
            payload["media_type"],
        )
        if any(type(value) is not str for value in values) or (
            payload["image_sha256"] is not None
            and type(payload["image_sha256"]) is not str
        ):
            raise DailyDetailCaptureContractError(
                "daily ticket slot capture field type is invalid"
            )
        return cls(
            slot=payload["slot"],
            ticket_ref=payload["ticket_ref"],
            media_type=payload["media_type"],
            image_sha256=payload["image_sha256"],
        )


@dataclass(frozen=True, slots=True)
class DailyDetailCaptureState:
    """Restartable detail and per-slot image state without signed URLs."""

    platform_waybill_id: str
    waybill_number: str | None
    fields: DailyObservationFields
    tickets: tuple[DailyTicketSlotCapture, ...]
    capability_authority_id: str
    capability_access_window_id: str
    detail_read_access_window_ids: tuple[str, ...]
    image_read_access_window_ids: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        image_windows = dict(self.image_read_access_window_ids)
        if (
            not isinstance(self.platform_waybill_id, str)
            or not self.platform_waybill_id
            or len(self.platform_waybill_id) > 200
            or (
                self.waybill_number is not None
                and (
                    not isinstance(self.waybill_number, str)
                    or not self.waybill_number
                    or len(self.waybill_number) > 200
                )
            )
            or not isinstance(self.fields, DailyObservationFields)
            or any(
                not isinstance(ticket, DailyTicketSlotCapture)
                for ticket in self.tickets
            )
            or len({ticket.slot for ticket in self.tickets})
            != len(self.tickets)
            or len({ticket.ticket_ref for ticket in self.tickets})
            != len(self.tickets)
            or set(image_windows) - _TICKET_SLOTS
            or len(image_windows) != len(self.image_read_access_window_ids)
            or not _safe_identity(
                self.capability_authority_id,
                maximum=200,
            )
            or not _safe_identity(
                self.capability_access_window_id,
                maximum=100,
            )
            or any(
                not _safe_identity(value, maximum=100)
                for value in (
                    *self.detail_read_access_window_ids,
                    *image_windows.values(),
                )
            )
            or not self.detail_read_access_window_ids
            or self.detail_read_access_window_ids[-1]
            != self.capability_access_window_id
            or any(
                ticket.image_sha256 is not None
                and ticket.slot not in image_windows
                for ticket in self.tickets
            )
            or any(
                ticket.image_sha256 is None
                and ticket.slot in image_windows
                for ticket in self.tickets
            )
        ):
            raise DailyDetailCaptureContractError(
                "daily detail capture state is invalid"
            )

    @property
    def complete(self) -> bool:
        return all(
            ticket.image_sha256 is not None for ticket in self.tickets
        )

    @property
    def detail_read_count(self) -> int:
        return len(self.detail_read_access_window_ids)

    @property
    def image_read_count(self) -> int:
        return len(self.image_read_access_window_ids)

    def ticket(self, slot: str) -> DailyTicketSlotCapture | None:
        return next(
            (ticket for ticket in self.tickets if ticket.slot == slot),
            None,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "capability_access_window_id": (
                self.capability_access_window_id
            ),
            "capability_authority_id": self.capability_authority_id,
            "detail_read_access_window_ids": list(
                self.detail_read_access_window_ids
            ),
            "fields": self.fields.to_payload(),
            "image_read_access_window_ids": {
                slot: access_window_id
                for slot, access_window_id in (
                    self.image_read_access_window_ids
                )
            },
            "platform_waybill_id": self.platform_waybill_id,
            "schema_version": 1,
            "tickets": [
                ticket.to_payload() for ticket in self.tickets
            ],
            "waybill_number": self.waybill_number,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DailyDetailCaptureState:
        if not isinstance(payload, dict) or set(payload) != {
            "capability_access_window_id",
            "capability_authority_id",
            "detail_read_access_window_ids",
            "fields",
            "image_read_access_window_ids",
            "platform_waybill_id",
            "schema_version",
            "tickets",
            "waybill_number",
        } or payload["schema_version"] != 1:
            raise DailyDetailCaptureContractError(
                "daily detail capture state fields do not match schema"
            )
        tickets = payload["tickets"]
        detail_windows = payload["detail_read_access_window_ids"]
        image_windows = payload["image_read_access_window_ids"]
        if (
            not isinstance(tickets, list)
            or not isinstance(detail_windows, list)
            or not isinstance(image_windows, dict)
            or any(type(value) is not str for value in detail_windows)
            or any(
                type(key) is not str or type(value) is not str
                for key, value in image_windows.items()
            )
            or any(
                type(payload[field]) is not str
                for field in (
                    "capability_access_window_id",
                    "capability_authority_id",
                    "platform_waybill_id",
                )
            )
            or (
                payload["waybill_number"] is not None
                and type(payload["waybill_number"]) is not str
            )
        ):
            raise DailyDetailCaptureContractError(
                "daily detail capture state field type is invalid"
            )
        try:
            fields = DailyObservationFields.from_payload(
                payload["fields"]
            )
        except (TypeError, ValueError) as exc:
            raise DailyDetailCaptureContractError(
                "daily detail capture fields are invalid"
            ) from exc
        return cls(
            platform_waybill_id=payload["platform_waybill_id"],
            waybill_number=payload["waybill_number"],
            fields=fields,
            tickets=tuple(
                DailyTicketSlotCapture.from_payload(ticket)
                for ticket in tickets
            ),
            capability_authority_id=payload[
                "capability_authority_id"
            ],
            capability_access_window_id=payload[
                "capability_access_window_id"
            ],
            detail_read_access_window_ids=tuple(detail_windows),
            image_read_access_window_ids=tuple(
                sorted(image_windows.items())
            ),
        )


@dataclass(frozen=True, slots=True)
class DailyDetailCaptureStep:
    state: DailyDetailCaptureState
    evidence: DailyDetailEvidence | None
    platform_read_performed: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.state, DailyDetailCaptureState)
            or type(self.platform_read_performed) is not bool
            or (self.evidence is None) == self.state.complete
        ):
            raise DailyDetailCaptureContractError(
                "daily detail capture step is inconsistent"
            )


@dataclass(frozen=True, slots=True)
class DailyWaybillSummary:
    platform_waybill_id: str
    waybill_number: str
    vehicle_number: str | None
    platform_loading_time: datetime | None


@dataclass(frozen=True, slots=True)
class DailyWaybillPage:
    page_number: int
    page_size: int
    total: int
    items: tuple[DailyWaybillSummary, ...]
    platform_display_total: int | None = None
    response_total: int | None = None
    response_page_count: int | None = None
    query_scope_sha256: str | None = None
    scope_complete: bool = True
    scope_diagnostic_code: str | None = None


@dataclass(frozen=True, slots=True)
class DailyDetailEvidence:
    platform_waybill_id: str
    waybill_number: str | None
    fields: DailyObservationFields
    loading_ticket_sha256: str | None
    unloading_ticket_sha256: str | None
    source_detail_sha256: str

    def constructor_payload(self) -> dict[str, object]:
        return {
            "platform_waybill_id": self.platform_waybill_id,
            "waybill_number": self.waybill_number,
            "fields": self.fields,
            "loading_ticket_sha256": self.loading_ticket_sha256,
            "unloading_ticket_sha256": self.unloading_ticket_sha256,
            "source_detail_sha256": self.source_detail_sha256,
        }


@dataclass(frozen=True, slots=True)
class DailySnapshotSaveResult:
    snapshot: DailyCandidateSnapshot
    replayed: bool


@dataclass(frozen=True, slots=True)
class DailyObservationSaveResult:
    observation: DailyWaybillObservation
    revision: DailyRecordRevision
    replayed: bool
    revision_appended: bool


@dataclass(frozen=True, slots=True)
class DailySnapshotCaptureAuthority:
    """Bind one snapshot to the durable execution that produced it."""

    snapshot: DailyCandidateSnapshot
    invocation_id: str
    job_id: str
    access_window_id: str
    capture_build_sha256: str
    access_purpose: str
    access_consumed: bool
    invocation_contract_sha256: str
    invocation_status: str
    invocation_next_stage: str
    invocation_diagnostic_code: str | None
    job_status: str
    job_current_stage: str | None
    job_diagnostic_code: str | None
    work_item_count: int
    succeeded_work_item_count: int
    completed_stage_work_item_count: int
    observation_count: int
    request_audit_sha256: str
    request_audit_job_id_sha256: str
    request_audit_purpose: str
    request_audit_authority: Mapping[str, object]
    request_audit_request_counts: Mapping[str, int]
    request_audit_operation_counts: Mapping[
        str,
        Mapping[str, int],
    ]
    request_audit_event_count: int
    request_audit_event_chain_sha256: str
    request_audit_expected_succeeded_operations: Mapping[str, int]
    request_audit_kind: str
    request_audit_schema_version: int
    forbidden_request_count: int
    platform_write_request_count: int
    redirect_count: int
    access_window_ids: tuple[str, ...] = ()
    read_access_window_ids: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )


class DailyPlatformReadPort(Protocol):
    def list_waybills(
        self,
        *,
        query_window: CandidateQueryWindow,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyWaybillPage: ...


class DailyDetailEvidencePort(Protocol):
    def advance(
        self,
        *,
        candidate: DailyCandidate,
        state: DailyDetailCaptureState | None,
    ) -> DailyDetailCaptureStep: ...


class DailyReadStore(Protocol):
    def save_snapshot(
        self,
        snapshot: DailyCandidateSnapshot,
    ) -> DailySnapshotSaveResult: ...

    def get_snapshot(self, snapshot_id: str) -> DailyCandidateSnapshot: ...

    def get_formal_snapshot_authority(
        self,
        snapshot_id: str,
    ) -> DailySnapshotCaptureAuthority: ...

    def list_snapshot_observations(
        self,
        snapshot_id: str,
    ) -> tuple[DailyWaybillObservation, ...]: ...

    def save_observation(
        self,
        observation: DailyWaybillObservation,
    ) -> DailyObservationSaveResult: ...

    def list_revisions(
        self,
        platform_waybill_id: str,
    ) -> tuple[DailyRecordRevision, ...]: ...
