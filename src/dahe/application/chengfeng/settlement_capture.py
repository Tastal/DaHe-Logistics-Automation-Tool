from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, cast

from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditEvidenceStore,
)
from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    DurableCaptureCheckpointStore,
    DurableChengfengCaptureCoordinator,
    capture_read_key,
    detail_read_success_count,
)
from dahe.application.chengfeng.shadow_batch import (
    HISTORICAL_CAPTURE_MAX_PAGES,
    HISTORICAL_CAPTURE_PAGE_SIZE,
    ChengfengShadowBatchContractError,
    SafeImageReader,
    ShadowBatchItem,
    ShadowBatchSource,
    ShadowCaptureBinding,
    _binding_authority,
    _checkpoint_items,
    _checkpoint_source,
    _validate_authority,
    _validate_complete_pagination,
    chengfeng_shadow_identity_context_sha256,
)
from dahe.ports.chengfeng import (
    CURRENT_PENDING_SETTLEMENT_SCOPE,
    HISTORICAL_SETTLED_SCOPE,
    BrowserCommandAuthority,
    ChengfengStage,
)

SCHEMA_VERSION = 3
LINEAGE_SCHEMA_VERSION = 2
LEGACY_SCHEMA_VERSION = 1
SOURCE_KIND = "chengfeng_pending_settlement_capture"
SETTLEMENT_CAPTURE_STAGE = "settlement_capture.read"
SETTLEMENT_CAPTURE_PAGE_SIZE = 50
HISTORICAL_SETTLEMENT_CAPTURE_PAGE_SIZE = HISTORICAL_CAPTURE_PAGE_SIZE
HISTORICAL_SETTLEMENT_CAPTURE_MAX_PAGES = HISTORICAL_CAPTURE_MAX_PAGES
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SettlementCaptureContractError(ValueError):
    """Raised when a pending-settlement capture cannot be sealed safely."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SettlementCaptureContractError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _required_text(
    value: object,
    *,
    label: str,
    maximum: int = 500,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SettlementCaptureContractError(f"{label} is invalid")
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise SettlementCaptureContractError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise SettlementCaptureContractError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _validate_request_audit_binding(
    *,
    request_audit_sha256: object,
    request_audit_counts: object,
    source_build_sha256: str,
    contract_canonical_sha256: str,
    contract_selection_sha256: str,
    source_job_id: str,
    purpose: str,
    list_count: int,
    detail_count: int,
    image_count: int,
) -> dict[str, object]:
    audit_sha256 = _required_sha256(
        request_audit_sha256,
        label="settlement request audit SHA-256",
    )
    raw = _mapping(
        request_audit_counts,
        label="settlement request audit counts",
    )
    expected_keys = {
        "authority",
        "event_chain_sha256",
        "event_count",
        "expected_succeeded_operations",
        "job_id_sha256",
        "kind",
        "operation_counts",
        "platform_write_request_count",
        "purpose",
        "redirect_count",
        "request_counts",
        "schema_version",
    }
    if set(raw) != expected_keys:
        raise SettlementCaptureContractError(
            "settlement request audit counts are invalid"
        )
    authority = _mapping(
        raw.get("authority"),
        label="settlement request audit authority",
    )
    if set(authority) != {
        "build_sha256",
        "daily_contract_selection_sha256",
        "daily_contract_sha256",
        "settlement_contract_selection_sha256",
        "settlement_contract_sha256",
    }:
        raise SettlementCaptureContractError(
            "settlement request audit authority is invalid"
        )
    if (
        authority.get("build_sha256") != source_build_sha256
        or authority.get("settlement_contract_sha256")
        != contract_canonical_sha256
        or authority.get("settlement_contract_selection_sha256")
        != contract_selection_sha256
        or authority.get("daily_contract_sha256") is not None
        or authority.get("daily_contract_selection_sha256") is not None
    ):
        raise SettlementCaptureContractError(
            "settlement request audit authority changed"
        )
    expected_purpose = {
        "formal_locked_set": "current_locked_50",
        "production_shadow": "real_shadow_30",
    }.get(purpose)
    expected_operations = {
        "download_ticket_image": image_count,
        "get_waybill_detail": detail_count,
        "list_waybills": list_count,
    }
    if (
        expected_purpose is None
        or raw.get("purpose") != expected_purpose
        or raw.get("kind") != "loop9_platform_read_audit"
        or raw.get("schema_version") != 1
        or raw.get("job_id_sha256")
        != hashlib.sha256(source_job_id.encode("utf-8")).hexdigest()
        or raw.get("expected_succeeded_operations")
        != expected_operations
        or raw.get("platform_write_request_count") != 0
        or raw.get("redirect_count") != 0
    ):
        raise SettlementCaptureContractError(
            "settlement request audit binding changed"
        )
    _required_sha256(
        raw.get("event_chain_sha256"),
        label="settlement request audit event chain",
    )
    request_counts = _mapping(
        raw.get("request_counts"),
        label="settlement request counts",
    )
    request_phases = {"allowed", "attempted", "denied", "succeeded"}
    if (
        set(request_counts) != request_phases
        or any(
            type(request_counts.get(phase)) is not int
            or cast(int, request_counts.get(phase)) < 0
            for phase in request_phases
        )
        or request_counts.get("denied") != 0
    ):
        raise SettlementCaptureContractError(
            "settlement request audit counts are invalid"
        )
    operation_counts = _mapping(
        raw.get("operation_counts"),
        label="settlement operation counts",
    )
    operation_names = {
        "download_ticket_image",
        "get_waybill_detail",
        "list_daily_waybills",
        "list_waybills",
    }
    operation_phases = {
        "allowed",
        "attempted",
        "denied",
        "failed",
        "redirect",
        "succeeded",
    }
    if set(operation_counts) != operation_names:
        raise SettlementCaptureContractError(
            "settlement request audit counts are invalid"
        )
    totals = {phase: 0 for phase in request_phases}
    event_count = 0
    for operation in operation_names:
        counts = _mapping(
            operation_counts.get(operation),
            label="settlement operation counts",
        )
        if (
            set(counts) != operation_phases
            or any(
                type(counts.get(phase)) is not int
                or cast(int, counts.get(phase)) < 0
                for phase in operation_phases
            )
            or counts.get("attempted")
            != cast(int, counts.get("allowed"))
            + cast(int, counts.get("denied"))
            or counts.get("allowed")
            != cast(int, counts.get("succeeded"))
            + cast(int, counts.get("failed"))
            + cast(int, counts.get("redirect"))
            or counts.get("denied") != 0
            or counts.get("redirect") != 0
            or counts.get("succeeded")
            != expected_operations.get(operation, 0)
        ):
            raise SettlementCaptureContractError(
                "settlement request audit counts are inconsistent"
            )
        for phase in request_phases:
            totals[phase] += cast(int, counts.get(phase))
        event_count += sum(
            cast(int, counts.get(phase))
            for phase in operation_phases
        )
    if (
        dict(request_counts) != totals
        or type(raw.get("event_count")) is not int
        or raw.get("event_count") != event_count
        or _canonical_sha256(raw) != audit_sha256
    ):
        raise SettlementCaptureContractError(
            "settlement request audit integrity is invalid"
        )
    return cast(
        dict[str, object],
        json.loads(_canonical_json(raw)),
    )


@dataclass(frozen=True, slots=True)
class ProtectedBusinessIdentity:
    """Installation-local identity that must never enter outward evidence."""

    item_identity_sha256: str
    platform_waybill_id: str
    waybill_number: str
    vehicle_number: str | None
    source_page_number: int

    def __post_init__(self) -> None:
        _required_sha256(
            self.item_identity_sha256,
            label="protected item identity",
        )
        _required_text(
            self.platform_waybill_id,
            label="protected platform waybill identity",
        )
        _required_text(
            self.waybill_number,
            label="protected waybill number",
        )
        if self.vehicle_number is not None:
            _required_text(
                self.vehicle_number,
                label="protected vehicle number",
            )
        if (
            isinstance(self.source_page_number, bool)
            or not isinstance(self.source_page_number, int)
            or self.source_page_number < 1
        ):
            raise SettlementCaptureContractError(
                "protected source page number is invalid"
            )


@dataclass(frozen=True, slots=True)
class SettlementCaptureAccessWindowLineage:
    """Append-only authorization lineage for one capture invocation."""

    job_id: str
    session_id: str
    purpose: str
    source_build_sha256: str
    contract_canonical_sha256: str
    contract_file_sha256: str
    contract_selection_sha256: str
    identity_context_sha256: str
    access_window_ids: tuple[str, ...]
    authority_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_text(self.job_id, label="lineage job ID", maximum=100)
        _required_text(
            self.session_id,
            label="lineage session ID",
            maximum=100,
        )
        if self.purpose not in {
            "formal_locked_set",
            "production_shadow",
        }:
            raise SettlementCaptureContractError(
                "settlement capture lineage purpose is invalid"
            )
        for label, value in (
            ("source build SHA-256", self.source_build_sha256),
            ("contract canonical SHA-256", self.contract_canonical_sha256),
            ("contract file SHA-256", self.contract_file_sha256),
            ("contract selection SHA-256", self.contract_selection_sha256),
            ("identity context SHA-256", self.identity_context_sha256),
        ):
            _required_sha256(value, label=label)
        if (
            not isinstance(self.access_window_ids, tuple)
            or not self.access_window_ids
            or len(set(self.access_window_ids))
            != len(self.access_window_ids)
        ):
            raise SettlementCaptureContractError(
                "settlement capture access-window lineage is invalid"
            )
        for access_window_id in self.access_window_ids:
            _required_text(
                access_window_id,
                label="lineage access-window ID",
                maximum=32,
            )
        object.__setattr__(
            self,
            "authority_sha256",
            _canonical_sha256(self._authority_payload()),
        )

    def _authority_payload(self) -> dict[str, object]:
        return {
            "access_window_ids": list(self.access_window_ids),
            "contract_canonical_sha256": (
                self.contract_canonical_sha256
            ),
            "contract_file_sha256": self.contract_file_sha256,
            "contract_selection_sha256": (
                self.contract_selection_sha256
            ),
            "identity_context_sha256": self.identity_context_sha256,
            "job_id": self.job_id,
            "purpose": self.purpose,
            "session_id": self.session_id,
            "source_build_sha256": self.source_build_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._authority_payload(),
            "authority_sha256": self.authority_sha256,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> SettlementCaptureAccessWindowLineage:
        raw = _mapping(value, label="settlement capture lineage")
        expected = {
            "access_window_ids",
            "authority_sha256",
            "contract_canonical_sha256",
            "contract_file_sha256",
            "contract_selection_sha256",
            "identity_context_sha256",
            "job_id",
            "purpose",
            "session_id",
            "source_build_sha256",
        }
        if set(raw) != expected:
            raise SettlementCaptureContractError(
                "settlement capture lineage contract is invalid"
            )
        lineage = cls(
            job_id=cast(str, raw.get("job_id")),
            session_id=cast(str, raw.get("session_id")),
            purpose=cast(str, raw.get("purpose")),
            source_build_sha256=cast(
                str,
                raw.get("source_build_sha256"),
            ),
            contract_canonical_sha256=cast(
                str,
                raw.get("contract_canonical_sha256"),
            ),
            contract_file_sha256=cast(
                str,
                raw.get("contract_file_sha256"),
            ),
            contract_selection_sha256=cast(
                str,
                raw.get("contract_selection_sha256"),
            ),
            identity_context_sha256=cast(
                str,
                raw.get("identity_context_sha256"),
            ),
            access_window_ids=tuple(
                cast(str, item)
                for item in _array(
                    raw.get("access_window_ids"),
                    label="lineage access-window IDs",
                )
            ),
        )
        if raw.get("authority_sha256") != lineage.authority_sha256:
            raise SettlementCaptureContractError(
                "settlement capture lineage authority is invalid"
            )
        return lineage


@dataclass(frozen=True, slots=True)
class SettlementCaptureReadAccessBinding:
    """Outward-safe attribution of one committed platform read."""

    capture_id: str
    read_kind: str
    subject_sha256: str
    access_window_id: str

    def __post_init__(self) -> None:
        _required_text(
            self.capture_id,
            label="read binding capture ID",
            maximum=200,
        )
        if self.read_kind not in {"list", "detail", "image"}:
            raise SettlementCaptureContractError(
                "settlement capture read kind is invalid"
            )
        _required_sha256(
            self.subject_sha256,
            label="read binding subject SHA-256",
        )
        _required_text(
            self.access_window_id,
            label="read binding access-window ID",
            maximum=32,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "access_window_id": self.access_window_id,
            "capture_id": self.capture_id,
            "read_kind": self.read_kind,
            "subject_sha256": self.subject_sha256,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> SettlementCaptureReadAccessBinding:
        raw = _mapping(value, label="settlement capture read binding")
        expected = {
            "access_window_id",
            "capture_id",
            "read_kind",
            "subject_sha256",
        }
        if set(raw) != expected:
            raise SettlementCaptureContractError(
                "settlement capture read binding contract is invalid"
            )
        return cls(
            capture_id=cast(str, raw.get("capture_id")),
            read_kind=cast(str, raw.get("read_kind")),
            subject_sha256=cast(str, raw.get("subject_sha256")),
            access_window_id=cast(str, raw.get("access_window_id")),
        )


@dataclass(frozen=True, slots=True)
class SettlementCaptureManifest:
    """Outward-safe sealed inventory from one complete platform pagination."""

    source_build_sha256: str
    contract_canonical_sha256: str
    contract_file_sha256: str
    contract_selection_sha256: str
    identity_context_sha256: str
    sources: tuple[ShadowBatchSource, ...]
    items: tuple[ShadowBatchItem, ...]
    access_window_lineage: (
        SettlementCaptureAccessWindowLineage | None
    ) = None
    read_access_bindings: tuple[
        SettlementCaptureReadAccessBinding,
        ...,
    ] = ()
    request_audit_sha256: str | None = None
    request_audit_counts: Mapping[str, object] | None = None
    source_kind: str = SOURCE_KIND
    schema_version: int = LEGACY_SCHEMA_VERSION
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            self.source_kind != SOURCE_KIND
            or type(self.schema_version) is not int
            or self.schema_version
            not in {
                LEGACY_SCHEMA_VERSION,
                LINEAGE_SCHEMA_VERSION,
                SCHEMA_VERSION,
            }
        ):
            raise SettlementCaptureContractError(
                "settlement capture manifest version is unsupported"
            )
        for label, value in (
            ("source build SHA-256", self.source_build_sha256),
            ("contract canonical SHA-256", self.contract_canonical_sha256),
            ("contract file SHA-256", self.contract_file_sha256),
            ("contract selection SHA-256", self.contract_selection_sha256),
            ("identity context SHA-256", self.identity_context_sha256),
        ):
            _required_sha256(value, label=label)
        if (
            not isinstance(self.sources, tuple)
            or not self.sources
            or any(
                not isinstance(source, ShadowBatchSource)
                for source in self.sources
            )
        ):
            raise SettlementCaptureContractError(
                "settlement capture sources are invalid"
            )
        if (
            not isinstance(self.items, tuple)
            or not self.items
            or any(not isinstance(item, ShadowBatchItem) for item in self.items)
        ):
            raise SettlementCaptureContractError(
                "settlement capture contains no eligible waybills"
            )
        if len({source.capture_id for source in self.sources}) != len(
            self.sources
        ):
            raise SettlementCaptureContractError(
                "settlement capture contains duplicate source checkpoints"
            )
        platform_ids = [
            item.platform_waybill_id_digest for item in self.items
        ]
        waybill_ids = [item.waybill_number_digest for item in self.items]
        item_ids = [item.item_identity_sha256 for item in self.items]
        if len(platform_ids) != len(set(platform_ids)):
            raise SettlementCaptureContractError(
                "settlement capture contains duplicate platform identity"
            )
        if len(waybill_ids) != len(set(waybill_ids)):
            raise SettlementCaptureContractError(
                "settlement capture contains duplicate waybill identity"
            )
        if len(item_ids) != len(set(item_ids)):
            raise SettlementCaptureContractError(
                "settlement capture contains duplicate item identity"
            )
        if self.schema_version == LEGACY_SCHEMA_VERSION:
            if (
                self.access_window_lineage is not None
                or self.read_access_bindings
                or self.request_audit_sha256 is not None
                or self.request_audit_counts is not None
            ):
                raise SettlementCaptureContractError(
                    "legacy settlement capture cannot contain access lineage"
                )
        else:
            lineage = self.access_window_lineage
            if not isinstance(
                lineage,
                SettlementCaptureAccessWindowLineage,
            ):
                raise SettlementCaptureContractError(
                    "settlement capture access lineage is required"
                )
            if (
                not isinstance(self.read_access_bindings, tuple)
                or not self.read_access_bindings
                or any(
                    not isinstance(
                        binding,
                        SettlementCaptureReadAccessBinding,
                    )
                    for binding in self.read_access_bindings
                )
            ):
                raise SettlementCaptureContractError(
                    "settlement capture read access bindings are invalid"
                )
            if (
                lineage.job_id != self.source_job_id
                or lineage.source_build_sha256
                != self.source_build_sha256
                or lineage.contract_canonical_sha256
                != self.contract_canonical_sha256
                or lineage.contract_file_sha256
                != self.contract_file_sha256
                or lineage.contract_selection_sha256
                != self.contract_selection_sha256
                or lineage.identity_context_sha256
                != self.identity_context_sha256
            ):
                raise SettlementCaptureContractError(
                    "settlement capture lineage authority does not match"
                )
            capture_ids = {
                source.capture_id for source in self.sources
            }
            identities = [
                (
                    binding.capture_id,
                    binding.read_kind,
                    binding.subject_sha256,
                )
                for binding in self.read_access_bindings
            ]
            if (
                len(identities) != len(set(identities))
                or any(
                    binding.capture_id not in capture_ids
                    or binding.access_window_id
                    not in lineage.access_window_ids
                    for binding in self.read_access_bindings
                )
            ):
                raise SettlementCaptureContractError(
                    "settlement capture read access lineage is invalid"
                )
            window_position = {
                access_window_id: index
                for index, access_window_id in enumerate(
                    lineage.access_window_ids
                )
            }
            positions = [
                window_position[binding.access_window_id]
                for binding in self.read_access_bindings
            ]
            if positions != sorted(positions):
                raise SettlementCaptureContractError(
                    "settlement capture access lineage is not append-only"
                )
            list_bindings = {
                binding.capture_id: binding
                for binding in self.read_access_bindings
                if binding.read_kind == "list"
            }
            if (
                set(list_bindings) != capture_ids
                or any(
                    list_bindings[source.capture_id].access_window_id
                    != source.access_window_id
                    for source in self.sources
                )
            ):
                raise SettlementCaptureContractError(
                    "settlement capture source window attribution is invalid"
                )
            if self.schema_version == LINEAGE_SCHEMA_VERSION:
                if (
                    self.request_audit_sha256 is not None
                    or self.request_audit_counts is not None
                ):
                    raise SettlementCaptureContractError(
                        "lineage-only settlement capture cannot bind request audit"
                    )
            else:
                if (
                    self.request_audit_sha256 is None
                    or self.request_audit_counts is None
                ):
                    raise SettlementCaptureContractError(
                        "settlement capture request audit is required"
                    )
                normalized_audit = _validate_request_audit_binding(
                    request_audit_sha256=self.request_audit_sha256,
                    request_audit_counts=self.request_audit_counts,
                    source_build_sha256=self.source_build_sha256,
                    contract_canonical_sha256=(
                        self.contract_canonical_sha256
                    ),
                    contract_selection_sha256=(
                        self.contract_selection_sha256
                    ),
                    source_job_id=self.source_job_id,
                    purpose=lineage.purpose,
                    list_count=sum(
                        binding.read_kind == "list"
                        for binding in self.read_access_bindings
                    ),
                    detail_count=sum(
                        binding.read_kind == "detail"
                        for binding in self.read_access_bindings
                    ),
                    image_count=sum(
                        binding.read_kind == "image"
                        for binding in self.read_access_bindings
                    ),
                )
                object.__setattr__(
                    self,
                    "request_audit_counts",
                    normalized_audit,
                )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    @property
    def source_access_window_id(self) -> str:
        if self.access_window_lineage is not None:
            return self.access_window_lineage.access_window_ids[-1]
        values = {source.access_window_id for source in self.sources}
        if len(values) != 1:
            raise SettlementCaptureContractError(
                "settlement capture spans multiple access windows"
            )
        return next(iter(values))

    @property
    def source_job_id(self) -> str:
        values = {source.job_id for source in self.sources}
        if len(values) != 1:
            raise SettlementCaptureContractError(
                "settlement capture spans multiple jobs"
            )
        return next(iter(values))

    def _canonical_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "contract_canonical_sha256": self.contract_canonical_sha256,
            "contract_file_sha256": self.contract_file_sha256,
            "contract_selection_sha256": (
                self.contract_selection_sha256
            ),
            "identity_context_sha256": self.identity_context_sha256,
            "items": [
                item.to_payload()
                for item in sorted(
                    self.items,
                    key=lambda candidate: candidate.item_identity_sha256,
                )
            ],
            "schema_version": self.schema_version,
            "source_build_sha256": self.source_build_sha256,
            "source_kind": self.source_kind,
            "sources": [
                source._canonical_payload()
                for source in sorted(
                    self.sources,
                    key=lambda value: (
                        value.job_id,
                        value.page_number,
                        value.capture_id,
                    ),
                )
            ],
        }
        if self.schema_version in {
            LINEAGE_SCHEMA_VERSION,
            SCHEMA_VERSION,
        }:
            assert self.access_window_lineage is not None
            payload["access_window_lineage"] = (
                self.access_window_lineage.to_payload()
            )
            payload["read_access_bindings"] = [
                binding.to_payload()
                for binding in self.read_access_bindings
            ]
        if self.schema_version == SCHEMA_VERSION:
            assert self.request_audit_sha256 is not None
            assert self.request_audit_counts is not None
            payload["request_audit_counts"] = dict(
                self.request_audit_counts
            )
            payload["request_audit_sha256"] = self.request_audit_sha256
        return payload

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != (
            self.canonical_sha256
        ):
            raise SettlementCaptureContractError(
                "settlement capture manifest integrity is invalid"
            )
        _ = (self.source_access_window_id, self.source_job_id)

    @classmethod
    def from_payload(cls, value: object) -> SettlementCaptureManifest:
        raw = _mapping(value, label="settlement capture manifest")
        legacy_expected = {
            "canonical_sha256",
            "contract_canonical_sha256",
            "contract_file_sha256",
            "contract_selection_sha256",
            "identity_context_sha256",
            "items",
            "schema_version",
            "source_build_sha256",
            "source_kind",
            "sources",
        }
        schema_version = cast(int, raw.get("schema_version"))
        lineage_expected = {
            *legacy_expected,
            "access_window_lineage",
            "read_access_bindings",
        }
        current_expected = {
            *lineage_expected,
            "request_audit_counts",
            "request_audit_sha256",
        }
        if (
            schema_version == LEGACY_SCHEMA_VERSION
            and set(raw) != legacy_expected
        ) or (
            schema_version == LINEAGE_SCHEMA_VERSION
            and set(raw) != lineage_expected
        ) or (
            schema_version == SCHEMA_VERSION
            and set(raw) != current_expected
        ):
            raise SettlementCaptureContractError(
                "settlement capture manifest contract is invalid"
            )
        if schema_version not in {
            LEGACY_SCHEMA_VERSION,
            LINEAGE_SCHEMA_VERSION,
            SCHEMA_VERSION,
        }:
            raise SettlementCaptureContractError(
                "settlement capture manifest version is unsupported"
            )
        manifest = cls(
            source_build_sha256=cast(
                str,
                raw.get("source_build_sha256"),
            ),
            contract_canonical_sha256=cast(
                str,
                raw.get("contract_canonical_sha256"),
            ),
            contract_file_sha256=cast(
                str,
                raw.get("contract_file_sha256"),
            ),
            contract_selection_sha256=cast(
                str,
                raw.get("contract_selection_sha256"),
            ),
            identity_context_sha256=cast(
                str,
                raw.get("identity_context_sha256"),
            ),
            sources=tuple(
                ShadowBatchSource.from_payload(source)
                for source in _array(
                    raw.get("sources"),
                    label="settlement capture sources",
                )
            ),
            items=tuple(
                ShadowBatchItem.from_payload(item)
                for item in _array(
                    raw.get("items"),
                    label="settlement capture items",
                )
            ),
            access_window_lineage=(
                None
                if schema_version == LEGACY_SCHEMA_VERSION
                else SettlementCaptureAccessWindowLineage.from_payload(
                    raw.get("access_window_lineage")
                )
            ),
            read_access_bindings=(
                ()
                if schema_version == LEGACY_SCHEMA_VERSION
                else tuple(
                    SettlementCaptureReadAccessBinding.from_payload(
                        item
                    )
                    for item in _array(
                        raw.get("read_access_bindings"),
                        label=(
                            "settlement capture read access bindings"
                        ),
                    )
                )
            ),
            request_audit_sha256=(
                None
                if schema_version != SCHEMA_VERSION
                else cast(str, raw.get("request_audit_sha256"))
            ),
            request_audit_counts=(
                None
                if schema_version != SCHEMA_VERSION
                else _mapping(
                    raw.get("request_audit_counts"),
                    label="settlement request audit counts",
                )
            ),
            source_kind=cast(str, raw.get("source_kind")),
            schema_version=schema_version,
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="settlement capture canonical SHA-256",
        )
        if declared != manifest.canonical_sha256:
            raise SettlementCaptureContractError(
                "settlement capture manifest integrity is invalid"
            )
        manifest.verify_integrity()
        return manifest


def build_settlement_capture_manifest(
    *,
    bindings: Sequence[ShadowCaptureBinding],
    identity_salt: bytes,
    identity_namespace: str,
    image_reader: SafeImageReader,
    access_window_lineage: (
        SettlementCaptureAccessWindowLineage | None
    ) = None,
    request_audit_sha256: str | None = None,
    request_audit_counts: Mapping[str, object] | None = None,
) -> tuple[
    SettlementCaptureManifest,
    tuple[ProtectedBusinessIdentity, ...],
]:
    """Seal complete pagination while separating outward and local identity."""

    if (
        not isinstance(bindings, Sequence)
        or isinstance(bindings, (str, bytes))
        or not bindings
        or any(
            not isinstance(binding, ShadowCaptureBinding)
            for binding in bindings
        )
    ):
        raise SettlementCaptureContractError(
            "one or more capture bindings are required"
        )
    if not isinstance(identity_salt, bytes) or len(identity_salt) < 16:
        raise SettlementCaptureContractError(
            "identity salt must contain at least 16 bytes"
        )
    namespace = _required_text(
        identity_namespace,
        label="identity namespace",
        maximum=100,
    )
    if not hasattr(image_reader, "read_verified_image"):
        raise SettlementCaptureContractError("safe image reader is invalid")

    normalized = tuple(bindings)
    read_access_bindings: tuple[
        SettlementCaptureReadAccessBinding,
        ...,
    ] = ()
    if access_window_lineage is not None:
        normalized_with_read_authority: list[
            ShadowCaptureBinding
        ] = []
        attributed_reads: list[
            SettlementCaptureReadAccessBinding
        ] = []
        for binding in sorted(
            normalized,
            key=lambda value: value.checkpoint.page_number,
        ):
            checkpoint = binding.checkpoint
            ordered_reads: list[tuple[str, str, str]] = [
                (
                    "list",
                    _canonical_sha256(
                        {
                            "capture_id": checkpoint.capture_id,
                            "read_kind": "list",
                        }
                    ),
                    capture_read_key(ChengfengStage.LIST_QUERY),
                )
            ]
            ordered_reads.extend(
                (
                    "detail",
                    hashlib.sha256(
                        detail.platform_waybill_id.encode("utf-8")
                    ).hexdigest(),
                    capture_read_key(
                        ChengfengStage.DETAIL_QUERY,
                        detail.platform_waybill_id,
                    ),
                )
                for detail in checkpoint.details
            )
            ordered_reads.extend(
                (
                    "image",
                    hashlib.sha256(
                        ticket.ticket_ref.encode("utf-8")
                    ).hexdigest(),
                    capture_read_key(
                        ChengfengStage.IMAGE_DOWNLOAD,
                        ticket.ticket_ref,
                    ),
                )
                for detail in checkpoint.details
                for ticket in detail.tickets
            )
            access_by_read = dict(
                checkpoint.read_access_window_ids
            )
            ordered_reads.extend(
                (
                    "detail",
                    hashlib.sha256(
                        key.encode("utf-8")
                    ).hexdigest(),
                    key,
                )
                for key in access_by_read
                if key.startswith("detail-refresh:")
            )
            if (
                not access_by_read
                and len(access_window_lineage.access_window_ids) == 1
            ):
                access_by_read = {
                    key: access_window_lineage.access_window_ids[0]
                    for _kind, _subject, key in ordered_reads
                }
            expected_keys = {
                key for _kind, _subject, key in ordered_reads
            }
            if set(access_by_read) != expected_keys:
                raise SettlementCaptureContractError(
                    "settlement capture checkpoint lacks read access lineage"
                )
            list_access_window_id = access_by_read["list"]
            normalized_with_read_authority.append(
                ShadowCaptureBinding(
                    checkpoint=checkpoint,
                    access_window_id=list_access_window_id,
                    source_build_sha256=(
                        binding.source_build_sha256
                    ),
                    contract_canonical_sha256=(
                        binding.contract_canonical_sha256
                    ),
                    contract_file_sha256=(
                        binding.contract_file_sha256
                    ),
                    contract_selection_sha256=(
                        binding.contract_selection_sha256
                    ),
                )
            )
            attributed_reads.extend(
                SettlementCaptureReadAccessBinding(
                    capture_id=checkpoint.capture_id,
                    read_kind=read_kind,
                    subject_sha256=subject_sha256,
                    access_window_id=access_by_read[key],
                )
                for read_kind, subject_sha256, key in ordered_reads
            )
        normalized = tuple(normalized_with_read_authority)
        window_position = {
            access_window_id: index
            for index, access_window_id in enumerate(
                access_window_lineage.access_window_ids
            )
        }
        kind_position = {
            "list": 0,
            "detail": 1,
            "image": 2,
        }
        read_access_bindings = tuple(
            sorted(
                attributed_reads,
                key=lambda value: (
                    window_position[value.access_window_id],
                    kind_position[value.read_kind],
                    value.capture_id,
                    value.subject_sha256,
                ),
            )
        )
    try:
        _validate_authority(normalized)
        if access_window_lineage is None:
            _validate_complete_pagination(normalized)
        else:
            pagination_authority = (
                access_window_lineage.access_window_ids[0]
            )
            _validate_complete_pagination(
                tuple(
                    ShadowCaptureBinding(
                        checkpoint=binding.checkpoint,
                        access_window_id=pagination_authority,
                        source_build_sha256=(
                            binding.source_build_sha256
                        ),
                        contract_canonical_sha256=(
                            binding.contract_canonical_sha256
                        ),
                        contract_file_sha256=(
                            binding.contract_file_sha256
                        ),
                        contract_selection_sha256=(
                            binding.contract_selection_sha256
                        ),
                    )
                    for binding in normalized
                )
            )
    except ChengfengShadowBatchContractError as exc:
        raise SettlementCaptureContractError(str(exc)) from exc

    capture_ids = [
        binding.checkpoint.capture_id for binding in normalized
    ]
    if len(capture_ids) != len(set(capture_ids)):
        raise SettlementCaptureContractError(
            "capture bindings contain duplicate capture IDs"
        )

    outward_items: list[ShadowBatchItem] = []
    protected_items: list[ProtectedBusinessIdentity] = []
    try:
        for binding in sorted(
            normalized,
            key=lambda value: value.checkpoint.page_number,
        ):
            checkpoint_items = _checkpoint_items(
                checkpoint=binding.checkpoint,
                salt=identity_salt,
                namespace=namespace,
                image_reader=image_reader,
            )
            page = binding.checkpoint.page
            assert page is not None
            details = {
                detail.platform_waybill_id: detail
                for detail in binding.checkpoint.details
            }
            if len(checkpoint_items) != len(page.items):
                raise SettlementCaptureContractError(
                    "capture candidate count does not match its page"
                )
            for summary, outward in zip(
                page.items,
                checkpoint_items,
                strict=True,
            ):
                detail = details[summary.platform_waybill_id]
                protected_items.append(
                    ProtectedBusinessIdentity(
                        item_identity_sha256=outward.item_identity_sha256,
                        platform_waybill_id=detail.platform_waybill_id,
                        waybill_number=detail.waybill_number,
                        vehicle_number=(
                            detail.vehicle_number
                            or summary.vehicle_number
                        ),
                        source_page_number=page.page_number,
                    )
                )
            outward_items.extend(checkpoint_items)
    except ChengfengShadowBatchContractError as exc:
        raise SettlementCaptureContractError(str(exc)) from exc

    authority = _binding_authority(normalized[0])
    manifest = SettlementCaptureManifest(
        source_build_sha256=authority[0],
        contract_canonical_sha256=authority[1],
        contract_file_sha256=authority[2],
        contract_selection_sha256=authority[3],
        identity_context_sha256=(
            chengfeng_shadow_identity_context_sha256(
                salt=identity_salt,
                namespace=namespace,
            )
        ),
        sources=tuple(_checkpoint_source(binding) for binding in normalized),
        items=tuple(outward_items),
        access_window_lineage=access_window_lineage,
        read_access_bindings=read_access_bindings,
        request_audit_sha256=request_audit_sha256,
        request_audit_counts=request_audit_counts,
        schema_version=(
            SCHEMA_VERSION
            if request_audit_sha256 is not None
            and request_audit_counts is not None
            else LINEAGE_SCHEMA_VERSION
            if access_window_lineage is not None
            else LEGACY_SCHEMA_VERSION
        ),
    )
    if {
        item.item_identity_sha256 for item in manifest.items
    } != {
        item.item_identity_sha256 for item in protected_items
    }:
        raise SettlementCaptureContractError(
            "protected identity mapping does not reconcile"
        )
    manifest.verify_integrity()
    return manifest, tuple(protected_items)


class SettlementCaptureInvocationView(Protocol):
    invocation_id: str
    job_id: str
    access_window_id: str
    scope: str
    page_size: int
    source_build_sha256: str
    contract_canonical_sha256: str
    contract_file_sha256: str
    contract_selection_sha256: str
    identity_context_sha256: str
    status: str
    manifest_sha256: str | None
    record_version: int


class SettlementCaptureInvocationPort(Protocol):
    def get(
        self,
        invocation_id: str,
    ) -> SettlementCaptureInvocationView: ...

    def seal(
        self,
        *,
        invocation_id: str,
        expected_record_version: int,
        manifest: SettlementCaptureManifest,
        protected_identities: tuple[ProtectedBusinessIdentity, ...],
        now: datetime,
    ) -> SettlementCaptureInvocationView: ...

    def load_manifest(
        self,
        invocation_id: str,
    ) -> SettlementCaptureManifest: ...

    def access_window_lineage(
        self,
        invocation_id: str,
    ) -> SettlementCaptureAccessWindowLineage: ...


class SettlementCaptureOutwardStore(Protocol):
    def seal(self, manifest: SettlementCaptureManifest) -> object: ...


class SettlementCaptureAuthorityValidator(Protocol):
    def __call__(
        self,
        invocation: SettlementCaptureInvocationView,
        authority: BrowserCommandAuthority,
        now: datetime,
    ) -> None: ...


class SettlementCaptureClock(Protocol):
    def __call__(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class SettlementCaptureStepResult:
    invocation_id: str
    job_id: str
    has_more: bool
    platform_read_performed: bool
    checkpoint_revision: int | None
    manifest_sha256: str | None


class PaginatedSettlementCaptureCoordinator:
    """Advance one durable platform quantum, then seal only when complete."""

    def __init__(
        self,
        *,
        durable_coordinator: DurableChengfengCaptureCoordinator,
        checkpoint_store: DurableCaptureCheckpointStore,
        invocation_store: SettlementCaptureInvocationPort,
        outward_store: SettlementCaptureOutwardStore,
        image_reader: SafeImageReader,
        identity_salt: bytes,
        identity_namespace: str,
        validate_authority: SettlementCaptureAuthorityValidator,
        clock: SettlementCaptureClock,
        request_audit_store: PlatformReadAuditEvidenceStore,
    ) -> None:
        self._durable = durable_coordinator
        self._checkpoints = checkpoint_store
        self._invocations = invocation_store
        self._outward = outward_store
        self._image_reader = image_reader
        self._identity_salt = identity_salt
        self._identity_namespace = identity_namespace
        self._validate_authority = validate_authority
        self._clock = clock
        self._request_audit_store = request_audit_store

    @staticmethod
    def _checkpoint_complete(
        checkpoint: object,
    ) -> bool:
        if checkpoint is None:
            return False
        if not hasattr(checkpoint, "page") or not hasattr(
            checkpoint,
            "details",
        ):
            return False
        typed = cast(DurableCaptureCheckpoint, checkpoint)
        if typed.page is None:
            return False
        if len(typed.details) != len(typed.page.items):
            return False
        expected_refs = {
            ticket.ticket_ref
            for detail in typed.details
            for ticket in detail.tickets
        }
        return set(typed.ticket_images) == expected_refs

    def _load_page(
        self,
        *,
        invocation: SettlementCaptureInvocationView,
        page_number: int,
    ) -> DurableCaptureCheckpoint | None:
        return self._checkpoints.load(
            job_id=invocation.job_id,
            scope=invocation.scope,
            page_number=page_number,
            page_size=invocation.page_size,
        )

    @staticmethod
    def _expected_pages(
        invocation: SettlementCaptureInvocationView,
        *,
        total: int,
    ) -> int:
        if (
            invocation.scope == HISTORICAL_SETTLED_SCOPE
            and invocation.page_size
            == HISTORICAL_SETTLEMENT_CAPTURE_PAGE_SIZE
        ):
            return min(
                max(
                    1,
                    (total + invocation.page_size - 1)
                    // invocation.page_size,
                ),
                HISTORICAL_SETTLEMENT_CAPTURE_MAX_PAGES,
            )
        if (
            invocation.scope == CURRENT_PENDING_SETTLEMENT_SCOPE
            and invocation.page_size == SETTLEMENT_CAPTURE_PAGE_SIZE
        ):
            return max(
                1,
                (total + invocation.page_size - 1)
                // invocation.page_size,
            )
        raise SettlementCaptureContractError(
            "settlement capture scope contract is invalid"
        )

    def _next_page(
        self,
        *,
        invocation: SettlementCaptureInvocationView,
    ) -> tuple[int, int | None]:
        first = self._load_page(
            invocation=invocation,
            page_number=1,
        )
        if not self._checkpoint_complete(first):
            revision = None if first is None else first.revision
            return 1, revision
        assert first is not None
        assert first.page is not None
        total = first.page.total
        if total < 1:
            raise SettlementCaptureContractError(
                "pending-settlement capture contains no eligible waybills"
            )
        expected_pages = self._expected_pages(
            invocation,
            total=total,
        )
        latest_revision = first.revision
        for page_number in range(2, expected_pages + 1):
            checkpoint = self._load_page(
                invocation=invocation,
                page_number=page_number,
            )
            if checkpoint is not None:
                latest_revision = max(
                    latest_revision,
                    checkpoint.revision,
                )
            if not self._checkpoint_complete(checkpoint):
                return page_number, latest_revision
        return expected_pages + 1, latest_revision

    def _complete_bindings(
        self,
        *,
        invocation: SettlementCaptureInvocationView,
        lineage: SettlementCaptureAccessWindowLineage,
    ) -> tuple[ShadowCaptureBinding, ...]:
        first = self._load_page(
            invocation=invocation,
            page_number=1,
        )
        if first is None or first.page is None:
            raise SettlementCaptureContractError(
                "capture pagination has no first page"
            )
        expected_pages = self._expected_pages(
            invocation,
            total=first.page.total,
        )
        bindings: list[ShadowCaptureBinding] = []
        for page_number in range(1, expected_pages + 1):
            checkpoint = self._load_page(
                invocation=invocation,
                page_number=page_number,
            )
            if not self._checkpoint_complete(checkpoint):
                raise SettlementCaptureContractError(
                    "capture pagination is partial"
                )
            assert checkpoint is not None
            read_access = dict(
                checkpoint.read_access_window_ids
            )
            if not read_access:
                if len(lineage.access_window_ids) != 1:
                    raise SettlementCaptureContractError(
                        "capture checkpoint lacks read access lineage"
                    )
                list_access_window_id = (
                    lineage.access_window_ids[0]
                )
            else:
                try:
                    list_access_window_id = read_access["list"]
                except KeyError as exc:
                    raise SettlementCaptureContractError(
                        "capture list read lacks access-window authority"
                    ) from exc
            bindings.append(
                ShadowCaptureBinding(
                    checkpoint=checkpoint,
                    access_window_id=list_access_window_id,
                    source_build_sha256=(
                        invocation.source_build_sha256
                    ),
                    contract_canonical_sha256=(
                        invocation.contract_canonical_sha256
                    ),
                    contract_file_sha256=(
                        invocation.contract_file_sha256
                    ),
                    contract_selection_sha256=(
                        invocation.contract_selection_sha256
                    ),
                )
            )
        return tuple(bindings)

    def advance(
        self,
        *,
        invocation_id: str,
        authority: BrowserCommandAuthority,
    ) -> SettlementCaptureStepResult:
        invocation = self._invocations.get(invocation_id)
        if authority.job_id != invocation.job_id:
            raise SettlementCaptureContractError(
                "browser authority does not own settlement capture"
            )
        now = self._clock()
        self._validate_authority(invocation, authority, now)
        if invocation.status == "sealed":
            manifest = self._invocations.load_manifest(invocation_id)
            self._outward.seal(manifest)
            return SettlementCaptureStepResult(
                invocation_id=invocation_id,
                job_id=invocation.job_id,
                has_more=False,
                platform_read_performed=False,
                checkpoint_revision=None,
                manifest_sha256=manifest.canonical_sha256,
            )
        if invocation.status != "collecting":
            raise SettlementCaptureContractError(
                "settlement capture invocation is terminal"
            )

        page_number, previous_revision = self._next_page(
            invocation=invocation,
        )
        first = self._load_page(
            invocation=invocation,
            page_number=1,
        )
        expected_pages = None
        if first is not None and first.page is not None:
            expected_pages = self._expected_pages(
                invocation,
                total=first.page.total,
            )
        if expected_pages is None or page_number <= expected_pages:
            step = self._durable.advance(
                authority=authority,
                scope=invocation.scope,
                page_number=page_number,
                page_size=invocation.page_size,
                access_window_id=invocation.access_window_id,
            )
            if step.has_more:
                return SettlementCaptureStepResult(
                    invocation_id=invocation_id,
                    job_id=invocation.job_id,
                    has_more=True,
                    platform_read_performed=(
                        step.platform_read_performed
                    ),
                    checkpoint_revision=step.checkpoint.revision,
                    manifest_sha256=None,
                )
            previous_revision = max(
                previous_revision or 0,
                step.checkpoint.revision,
            )
            next_page, previous_revision = self._next_page(
                invocation=invocation,
            )
            first = self._load_page(
                invocation=invocation,
                page_number=1,
            )
            assert first is not None
            assert first.page is not None
            expected_pages = self._expected_pages(
                invocation,
                total=first.page.total,
            )
            if next_page <= expected_pages:
                return SettlementCaptureStepResult(
                    invocation_id=invocation_id,
                    job_id=invocation.job_id,
                    has_more=True,
                    platform_read_performed=(
                        step.platform_read_performed
                    ),
                    checkpoint_revision=previous_revision,
                    manifest_sha256=None,
                )
            platform_read_performed = step.platform_read_performed
        else:
            platform_read_performed = False

        self._validate_authority(
            invocation,
            authority,
            self._clock(),
        )
        lineage = self._invocations.access_window_lineage(
            invocation_id
        )
        complete_bindings = self._complete_bindings(
            invocation=invocation,
            lineage=lineage,
        )
        purpose = {
            "formal_locked_set": "current_locked_50",
            "production_shadow": "real_shadow_30",
        }.get(lineage.purpose)
        if purpose is None:
            raise SettlementCaptureContractError(
                "settlement capture request audit purpose is invalid"
            )
        audit = self._request_audit_store.seal(
            job_id=invocation.job_id,
            authority=PlatformReadAuditAuthority(
                build_sha256=invocation.source_build_sha256,
                settlement_contract_sha256=(
                    invocation.contract_canonical_sha256
                ),
                settlement_contract_selection_sha256=(
                    invocation.contract_selection_sha256
                ),
            ),
            purpose=purpose,
            expected_succeeded_operations={
                "download_ticket_image": sum(
                    len(binding.checkpoint.ticket_images)
                    for binding in complete_bindings
                ),
                "get_waybill_detail": sum(
                    detail_read_success_count(binding.checkpoint)
                    for binding in complete_bindings
                ),
                "list_waybills": len(complete_bindings),
            },
        )
        audit_payload = audit.to_payload()
        audit_sha256 = cast(str, audit_payload.pop("canonical_sha256"))
        manifest, protected = build_settlement_capture_manifest(
            bindings=complete_bindings,
            identity_salt=self._identity_salt,
            identity_namespace=self._identity_namespace,
            image_reader=self._image_reader,
            access_window_lineage=lineage,
            request_audit_sha256=audit_sha256,
            request_audit_counts=audit_payload,
        )
        sealed = self._invocations.seal(
            invocation_id=invocation_id,
            expected_record_version=invocation.record_version,
            manifest=manifest,
            protected_identities=protected,
            now=self._clock(),
        )
        if (
            sealed.status != "sealed"
            or sealed.manifest_sha256 != manifest.canonical_sha256
        ):
            raise SettlementCaptureContractError(
                "settlement capture seal did not commit"
            )
        self._outward.seal(manifest)
        return SettlementCaptureStepResult(
            invocation_id=invocation_id,
            job_id=invocation.job_id,
            has_more=False,
            platform_read_performed=platform_read_performed,
            checkpoint_revision=previous_revision,
            manifest_sha256=manifest.canonical_sha256,
        )
