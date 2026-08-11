from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Protocol

from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserContextClosedError,
    BrowserNavigationAuthorizer,
    ChengfengReadPort,
    ChengfengStage,
    DownloadedTicketImage,
    TicketImageCapabilityExpiredError,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)

LEGACY_CHECKPOINT_SCHEMA_VERSION = 1
CHECKPOINT_SCHEMA_VERSION = 2


class CaptureCheckpointError(RuntimeError):
    """Raised when durable capture state is stale, malformed, or inconsistent."""


class CaptureInvocationMismatchError(CaptureCheckpointError):
    """Raised when a durable capture identity is reused with different input."""


def capture_read_key(
    stage: ChengfengStage,
    subject: str | None = None,
) -> str:
    """Return a stable checkpoint key without duplicating raw platform IDs."""

    if stage is ChengfengStage.LIST_QUERY:
        if subject is not None:
            raise CaptureCheckpointError(
                "list read access binding cannot contain a subject"
            )
        return "list"
    if stage not in {
        ChengfengStage.DETAIL_QUERY,
        ChengfengStage.IMAGE_DOWNLOAD,
    }:
        raise CaptureCheckpointError(
            "capture stage does not perform an attributable platform read"
        )
    if not isinstance(subject, str) or not subject:
        raise CaptureCheckpointError(
            "capture read access binding requires a subject"
        )
    prefix = (
        "detail"
        if stage is ChengfengStage.DETAIL_QUERY
        else "image"
    )
    return (
        f"{prefix}:"
        f"{hashlib.sha256(subject.encode('utf-8')).hexdigest()}"
    )


def capture_detail_refresh_read_key(
    *,
    platform_waybill_id: str,
    worker_id: str,
    access_window_id: str,
    refresh_index: int,
) -> str:
    if (
        not isinstance(platform_waybill_id, str)
        or not platform_waybill_id
        or not isinstance(worker_id, str)
        or not worker_id
        or not isinstance(access_window_id, str)
        or not access_window_id
        or isinstance(refresh_index, bool)
        or not isinstance(refresh_index, int)
        or refresh_index < 1
    ):
        raise CaptureCheckpointError(
            "detail refresh read identity is invalid"
        )
    platform_digest = hashlib.sha256(
        platform_waybill_id.encode("utf-8")
    ).hexdigest()
    worker_digest = hashlib.sha256(worker_id.encode("utf-8")).hexdigest()
    window_digest = hashlib.sha256(
        access_window_id.encode("utf-8")
    ).hexdigest()
    return (
        f"detail-refresh:{platform_digest}:{worker_digest}:"
        f"{window_digest}:{refresh_index}"
    )


def _is_detail_refresh_read_key(
    value: str,
    *,
    platform_identity_sha256s: set[str],
) -> bool:
    parts = value.split(":")
    return (
        len(parts) == 5
        and parts[0] == "detail-refresh"
        and parts[1] in platform_identity_sha256s
        and len(parts[2]) == 64
        and all(character in "0123456789abcdef" for character in parts[2])
        and len(parts[3]) == 64
        and all(character in "0123456789abcdef" for character in parts[3])
        and parts[4].isdigit()
        and int(parts[4]) >= 1
    )


def detail_read_success_count(
    checkpoint: DurableCaptureCheckpoint,
) -> int:
    return len(checkpoint.details) + sum(
        key.startswith("detail-refresh:")
        for key in checkpoint.read_access_window_ids
    )


def _expected_read_keys(
    checkpoint: DurableCaptureCheckpoint,
) -> tuple[str, ...]:
    keys: list[str] = []
    if checkpoint.page is not None:
        keys.append(capture_read_key(ChengfengStage.LIST_QUERY))
    keys.extend(
        capture_read_key(
            ChengfengStage.DETAIL_QUERY,
            detail.platform_waybill_id,
        )
        for detail in checkpoint.details
    )
    keys.extend(
        capture_read_key(
            ChengfengStage.IMAGE_DOWNLOAD,
            ticket_ref,
        )
        for ticket_ref in checkpoint.ticket_images
    )
    return tuple(keys)


def _next_read_access_mapping(
    checkpoint: DurableCaptureCheckpoint,
    *,
    stage: ChengfengStage,
    subject: str | None,
    access_window_id: str | None,
) -> Mapping[str, str]:
    if access_window_id is None:
        if checkpoint.read_access_window_ids:
            raise CaptureCheckpointError(
                "capture read access window is required"
            )
        return {}
    if (
        not isinstance(access_window_id, str)
        or not access_window_id
        or len(access_window_id) > 32
    ):
        raise CaptureCheckpointError(
            "capture read access window is invalid"
        )
    current = dict(checkpoint.read_access_window_ids)
    if not current:
        current.update(
            {
                key: access_window_id
                for key in _expected_read_keys(checkpoint)
            }
        )
    key = capture_read_key(stage, subject)
    existing = current.get(key)
    if existing is not None and existing != access_window_id:
        raise CaptureCheckpointError(
            "capture read access binding cannot be replaced"
        )
    current[key] = access_window_id
    return current


def _next_detail_refresh_access_mapping(
    checkpoint: DurableCaptureCheckpoint,
    *,
    platform_waybill_id: str,
    worker_id: str,
    access_window_id: str | None,
) -> Mapping[str, str]:
    if access_window_id is None:
        if checkpoint.read_access_window_ids:
            raise CaptureCheckpointError(
                "capture read access window is required"
            )
        return {}
    current = dict(checkpoint.read_access_window_ids)
    platform_digest = hashlib.sha256(
        platform_waybill_id.encode("utf-8")
    ).hexdigest()
    prefix = f"detail-refresh:{platform_digest}:"
    refresh_index = (
        sum(key.startswith(prefix) for key in current) + 1
    )
    key = capture_detail_refresh_read_key(
        platform_waybill_id=platform_waybill_id,
        worker_id=worker_id,
        access_window_id=access_window_id,
        refresh_index=refresh_index,
    )
    current[key] = access_window_id
    return current


def _validate_persistable_ticket_ref(ticket_ref: str) -> None:
    if not isinstance(ticket_ref, str):
        raise CaptureCheckpointError("ticket_ref must be a string")
    normalized = ticket_ref.casefold()
    forbidden_fragments = (
        "://",
        "?",
        "#",
        "&",
        "=",
        "signature",
        "credential",
        "access_token",
        "accesstoken",
    )
    if not ticket_ref or any(fragment in normalized for fragment in forbidden_fragments):
        raise CaptureCheckpointError(
            "ticket_ref must be an opaque identifier, not a signed URL or credential"
        )


@dataclass(frozen=True, slots=True)
class CaptureResult:
    page: WaybillPage
    details: tuple[WaybillDetail, ...]
    images: tuple[DownloadedTicketImage, ...]


@dataclass(frozen=True, slots=True)
class PersistedTicketImage:
    ticket_ref: str
    sha256: str
    relative_path: str
    byte_size: int
    media_type: str

    def __post_init__(self) -> None:
        _validate_persistable_ticket_ref(self.ticket_ref)
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise CaptureCheckpointError("persisted image identity is not lowercase SHA-256")
        expected_path = f"sha256/{self.sha256[:2]}/{self.sha256[2:4]}/{self.sha256}.blob"
        if self.relative_path != expected_path:
            raise CaptureCheckpointError("persisted image path does not match its content identity")
        if (
            isinstance(self.byte_size, bool)
            or not isinstance(self.byte_size, int)
            or self.byte_size < 1
        ):
            raise CaptureCheckpointError("persisted image byte_size must be positive")
        if self.media_type not in {"image/jpeg", "image/png"}:
            raise CaptureCheckpointError("persisted image media_type is unsupported")


@dataclass(frozen=True, slots=True)
class DurableCaptureCheckpoint:
    """Serializable result boundary with no browser token or raw response body."""

    capture_id: str
    job_id: str
    scope: str
    page_number: int
    page_size: int
    stage: ChengfengStage
    revision: int
    completed_list: bool
    completed_detail_ids: tuple[str, ...]
    ticket_images: Mapping[str, PersistedTicketImage]
    page: WaybillPage | None
    details: tuple[WaybillDetail, ...]
    read_access_window_ids: Mapping[str, str] = field(
        default_factory=dict
    )
    detail_capability_worker_ids: Mapping[str, str] = field(
        default_factory=dict
    )
    detail_capability_access_window_ids: Mapping[str, str] = field(
        default_factory=dict
    )
    schema_version: int = CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("capture_id", "job_id", "scope"):
            if not getattr(self, name):
                raise CaptureCheckpointError(f"{name} is required")
        if (
            isinstance(self.page_number, bool)
            or not isinstance(self.page_number, int)
            or self.page_number < 1
            or isinstance(self.page_size, bool)
            or not isinstance(self.page_size, int)
            or self.page_size < 1
        ):
            raise CaptureCheckpointError("page_number and page_size must be positive")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise CaptureCheckpointError("checkpoint revision cannot be negative")
        if (
            type(self.schema_version) is not int
            or self.schema_version
            not in {
                LEGACY_CHECKPOINT_SCHEMA_VERSION,
                CHECKPOINT_SCHEMA_VERSION,
            }
        ):
            raise CaptureCheckpointError("unsupported capture checkpoint schema")
        if not isinstance(self.stage, ChengfengStage):
            raise CaptureCheckpointError("checkpoint stage is invalid")
        if not isinstance(self.completed_detail_ids, tuple) or not isinstance(
            self.details,
            tuple,
        ):
            raise CaptureCheckpointError("checkpoint result collections must be tuples")
        if not isinstance(self.ticket_images, Mapping):
            raise CaptureCheckpointError("checkpoint ticket_images must be a mapping")
        if not isinstance(self.read_access_window_ids, Mapping):
            raise CaptureCheckpointError(
                "checkpoint read access bindings must be a mapping"
            )
        if not isinstance(self.detail_capability_worker_ids, Mapping):
            raise CaptureCheckpointError(
                "checkpoint detail capability bindings must be a mapping"
            )
        if not isinstance(
            self.detail_capability_access_window_ids,
            Mapping,
        ):
            raise CaptureCheckpointError(
                "checkpoint detail capability window bindings must be a mapping"
            )
        if self.completed_list is not (self.page is not None):
            raise CaptureCheckpointError("completed_list does not match the persisted page")
        detail_ids = tuple(detail.platform_waybill_id for detail in self.details)
        if detail_ids != self.completed_detail_ids:
            raise CaptureCheckpointError("completed detail identities do not match results")
        if len(set(detail_ids)) != len(detail_ids):
            raise CaptureCheckpointError("duplicate persisted detail identity")
        if self.page is not None:
            if (
                self.page.page_number != self.page_number
                or self.page.page_size != self.page_size
                or self.page.total < len(self.page.items)
            ):
                raise CaptureCheckpointError("persisted page does not match capture pagination")
            page_ids = {item.platform_waybill_id for item in self.page.items}
            if len(page_ids) != len(self.page.items):
                raise CaptureCheckpointError("persisted page contains duplicate waybills")
            if not set(detail_ids).issubset(page_ids):
                raise CaptureCheckpointError("persisted detail is absent from the list result")
            summaries = {item.platform_waybill_id: item.waybill_number for item in self.page.items}
            if any(
                summaries[detail.platform_waybill_id] != detail.waybill_number
                for detail in self.details
            ):
                raise CaptureCheckpointError(
                    "persisted detail identity disagrees with its list item"
                )
        ticket_ref_values = [
            ticket.ticket_ref for detail in self.details for ticket in detail.tickets
        ]
        if len(set(ticket_ref_values)) != len(ticket_ref_values):
            raise CaptureCheckpointError("persisted details contain duplicate ticket references")
        ticket_refs = set(ticket_ref_values)
        for ticket_ref in ticket_ref_values:
            _validate_persistable_ticket_ref(ticket_ref)
        if not set(self.ticket_images).issubset(ticket_refs):
            raise CaptureCheckpointError("persisted image is absent from detail results")
        for ticket_ref, image in self.ticket_images.items():
            if not isinstance(image, PersistedTicketImage):
                raise CaptureCheckpointError("persisted image record has an invalid type")
            if ticket_ref != image.ticket_ref:
                raise CaptureCheckpointError("persisted image map key does not match ticket_ref")
        read_access_window_ids = dict(self.read_access_window_ids)
        if any(
            not isinstance(key, str)
            or not key
            or not isinstance(access_window_id, str)
            or not access_window_id
            or len(access_window_id) > 32
            for key, access_window_id in read_access_window_ids.items()
        ):
            raise CaptureCheckpointError(
                "checkpoint read access binding is invalid"
            )
        expected_read_keys = set(_expected_read_keys(self))
        platform_identity_sha256s = {
            hashlib.sha256(
                detail.platform_waybill_id.encode("utf-8")
            ).hexdigest()
            for detail in self.details
        }
        extra_read_keys = set(read_access_window_ids) - expected_read_keys
        if (
            read_access_window_ids
            and (
                not expected_read_keys.issubset(read_access_window_ids)
                or any(
                    not _is_detail_refresh_read_key(
                        key,
                        platform_identity_sha256s=(
                            platform_identity_sha256s
                        ),
                    )
                    for key in extra_read_keys
                )
            )
        ):
            raise CaptureCheckpointError(
                "checkpoint read access bindings do not match results"
            )
        detail_capability_worker_ids = dict(
            self.detail_capability_worker_ids
        )
        if (
            self.schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION
            and detail_capability_worker_ids
        ) or any(
            platform_waybill_id not in set(detail_ids)
            or not isinstance(worker_id, str)
            or not worker_id
            or len(worker_id) > 200
            or worker_id != worker_id.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in worker_id
            )
            for platform_waybill_id, worker_id in (
                detail_capability_worker_ids.items()
            )
        ):
            raise CaptureCheckpointError(
                "checkpoint detail capability binding is invalid"
            )
        detail_capability_access_window_ids = dict(
            self.detail_capability_access_window_ids
        )
        if (
            self.schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION
            and detail_capability_access_window_ids
        ) or any(
            platform_waybill_id not in set(detail_ids)
            or not isinstance(capability_window_id, str)
            or not capability_window_id
            or len(capability_window_id) > 32
            or capability_window_id != capability_window_id.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in capability_window_id
            )
            for platform_waybill_id, capability_window_id in (
                detail_capability_access_window_ids.items()
            )
        ):
            raise CaptureCheckpointError(
                "checkpoint detail capability window binding is invalid"
            )
        if set(detail_capability_access_window_ids) - set(
            detail_capability_worker_ids
        ):
            raise CaptureCheckpointError(
                "checkpoint detail capability window lacks worker authority"
            )
        object.__setattr__(
            self,
            "ticket_images",
            MappingProxyType(dict(self.ticket_images)),
        )
        object.__setattr__(
            self,
            "read_access_window_ids",
            MappingProxyType(read_access_window_ids),
        )
        object.__setattr__(
            self,
            "detail_capability_worker_ids",
            MappingProxyType(detail_capability_worker_ids),
        )
        object.__setattr__(
            self,
            "detail_capability_access_window_ids",
            MappingProxyType(detail_capability_access_window_ids),
        )

    @classmethod
    def initial(
        cls,
        *,
        capture_id: str,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint:
        return cls(
            capture_id=capture_id,
            job_id=job_id,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
            stage=ChengfengStage.BROWSER_START,
            revision=0,
            completed_list=False,
            completed_detail_ids=(),
            ticket_images={},
            page=None,
            details=(),
        )

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "capture_id": self.capture_id,
            "job_id": self.job_id,
            "scope": self.scope,
            "page_number": self.page_number,
            "page_size": self.page_size,
            "stage": self.stage.value,
            "revision": self.revision,
            "completed_list": self.completed_list,
            "completed_detail_ids": list(self.completed_detail_ids),
            "ticket_images": {
                ticket_ref: {
                    "ticket_ref": image.ticket_ref,
                    "sha256": image.sha256,
                    "relative_path": image.relative_path,
                    "byte_size": image.byte_size,
                    "media_type": image.media_type,
                }
                for ticket_ref, image in self.ticket_images.items()
            },
            "read_access_window_ids": dict(
                sorted(self.read_access_window_ids.items())
            ),
            "page": None if self.page is None else _page_to_payload(self.page),
            "details": [_detail_to_payload(detail) for detail in self.details],
        }
        if self.schema_version == CHECKPOINT_SCHEMA_VERSION:
            payload["detail_capability_worker_ids"] = dict(
                sorted(self.detail_capability_worker_ids.items())
            )
            payload["detail_capability_access_window_ids"] = dict(
                sorted(
                    self.detail_capability_access_window_ids.items()
                )
            )
        return payload

    @classmethod
    def from_payload(cls, payload: object) -> DurableCaptureCheckpoint:
        if not isinstance(payload, dict):
            raise CaptureCheckpointError("capture checkpoint payload must be an object")
        legacy_keys = {
            "schema_version",
            "capture_id",
            "job_id",
            "scope",
            "page_number",
            "page_size",
            "stage",
            "revision",
            "completed_list",
            "completed_detail_ids",
            "ticket_images",
            "page",
            "details",
        }
        schema_version = _required_int(
            payload.get("schema_version"),
            field_name="schema_version",
        )
        lineage_keys = {*legacy_keys, "read_access_window_ids"}
        current_keys = {
            *lineage_keys,
            "detail_capability_access_window_ids",
            "detail_capability_worker_ids",
        }
        allowed_keys = (
            {frozenset(legacy_keys), frozenset(lineage_keys)}
            if schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION
            else {frozenset(current_keys)}
            if schema_version == CHECKPOINT_SCHEMA_VERSION
            else set()
        )
        if frozenset(payload) not in allowed_keys:
            raise CaptureCheckpointError("capture checkpoint fields do not match schema")
        completed_detail_ids = _string_tuple(
            payload["completed_detail_ids"],
            field_name="completed_detail_ids",
        )
        raw_images = payload["ticket_images"]
        if not isinstance(raw_images, dict):
            raise CaptureCheckpointError("ticket_images must be an object")
        ticket_images: dict[str, PersistedTicketImage] = {}
        for key, value in raw_images.items():
            ticket_ref = _required_string(key, field_name="ticket_images key")
            image = _image_from_payload(value)
            ticket_images[ticket_ref] = image
        raw_details = payload["details"]
        if not isinstance(raw_details, list):
            raise CaptureCheckpointError("details must be a list")
        raw_read_access = payload.get("read_access_window_ids", {})
        if not isinstance(raw_read_access, dict) or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            for key, value in raw_read_access.items()
        ):
            raise CaptureCheckpointError(
                "read_access_window_ids must be a string mapping"
            )
        raw_detail_capabilities = payload.get(
            "detail_capability_worker_ids",
            {},
        )
        if not isinstance(raw_detail_capabilities, dict) or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            for key, value in raw_detail_capabilities.items()
        ):
            raise CaptureCheckpointError(
                "detail_capability_worker_ids must be a string mapping"
            )
        raw_detail_capability_windows = payload.get(
            "detail_capability_access_window_ids",
            {},
        )
        if not isinstance(raw_detail_capability_windows, dict) or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            for key, value in raw_detail_capability_windows.items()
        ):
            raise CaptureCheckpointError(
                "detail_capability_access_window_ids must be a string mapping"
            )
        return cls(
            schema_version=schema_version,
            capture_id=_required_string(payload["capture_id"], field_name="capture_id"),
            job_id=_required_string(payload["job_id"], field_name="job_id"),
            scope=_required_string(payload["scope"], field_name="scope"),
            page_number=_required_int(payload["page_number"], field_name="page_number"),
            page_size=_required_int(payload["page_size"], field_name="page_size"),
            stage=ChengfengStage(_required_string(payload["stage"], field_name="stage")),
            revision=_required_int(payload["revision"], field_name="revision"),
            completed_list=_required_bool(
                payload["completed_list"],
                field_name="completed_list",
            ),
            completed_detail_ids=completed_detail_ids,
            ticket_images=ticket_images,
            read_access_window_ids=raw_read_access,
            detail_capability_worker_ids=raw_detail_capabilities,
            detail_capability_access_window_ids=(
                raw_detail_capability_windows
            ),
            page=(None if payload["page"] is None else _page_from_payload(payload["page"])),
            details=tuple(_detail_from_payload(detail) for detail in raw_details),
        )


class DurableCaptureCheckpointStore(Protocol):
    def capture_id(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> str: ...

    def load(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None: ...

    def commit_checkpoint(
        self,
        checkpoint: DurableCaptureCheckpoint,
        authority: BrowserCommandAuthority,
    ) -> DurableCaptureCheckpoint: ...

    def commit_image(
        self,
        checkpoint: DurableCaptureCheckpoint,
        image: DownloadedTicketImage,
        authority: BrowserCommandAuthority,
        *,
        access_window_id: str | None = None,
    ) -> DurableCaptureCheckpoint: ...

    def read_image(self, image: PersistedTicketImage) -> bytes: ...


RecoveryCallback = Callable[
    [BrowserCommandAuthority, ChengfengStage],
    BrowserCommandAuthority,
]
_CAPABILITY_REFRESH_REQUIRED = object()


@dataclass(frozen=True, slots=True)
class CaptureStepResult:
    checkpoint: DurableCaptureCheckpoint
    has_more: bool
    next_stage: ChengfengStage | None
    platform_read_performed: bool
    authority: BrowserCommandAuthority


class DurableChengfengCaptureCoordinator:
    """Advance at most one atomic platform read so the scheduler can rotate."""

    def __init__(
        self,
        *,
        adapter: ChengfengReadPort,
        navigation_authorizer: BrowserNavigationAuthorizer,
        checkpoint_store: DurableCaptureCheckpointStore,
        recover_browser: RecoveryCallback | None = None,
        interleave_images: bool = False,
    ) -> None:
        self._adapter = adapter
        self._navigation_authorizer = navigation_authorizer
        self._checkpoint_store = checkpoint_store
        self._recover_browser = recover_browser
        self._interleave_images = interleave_images

    def _authorize(self, authority: BrowserCommandAuthority) -> None:
        self._navigation_authorizer.authorize(authority)

    @staticmethod
    def _validate_replacement(
        old: BrowserCommandAuthority,
        replacement: BrowserCommandAuthority,
    ) -> None:
        if (
            replacement.session_id != old.session_id
            or replacement.instance_id != old.instance_id
            or replacement.job_id != old.job_id
        ):
            raise CaptureCheckpointError("replacement browser authority changed capture ownership")
        if replacement.control_epoch <= old.control_epoch:
            raise CaptureCheckpointError(
                "replacement browser authority did not advance its control epoch"
            )
        if replacement.fencing_token == old.fencing_token:
            raise CaptureCheckpointError(
                "replacement browser authority reused the stale fencing token"
            )

    def _read_with_recovery(
        self,
        *,
        authority: BrowserCommandAuthority,
        checkpoint: ChengfengStage,
        read: Callable[[BrowserCommandAuthority], object],
    ) -> tuple[object, BrowserCommandAuthority]:
        self._authorize(authority)
        try:
            result = read(authority)
            self._authorize(authority)
            return result, authority
        except BrowserContextClosedError:
            if self._recover_browser is None:
                raise
            replacement = self._recover_browser(authority, checkpoint)
            self._validate_replacement(authority, replacement)
            self._authorize(replacement)
            if checkpoint is ChengfengStage.IMAGE_DOWNLOAD:
                return _CAPABILITY_REFRESH_REQUIRED, replacement
            result = read(replacement)
            self._authorize(replacement)
            return result, replacement

    def _ticket_capability_authority_id(
        self,
        authority: BrowserCommandAuthority,
    ) -> str:
        value = getattr(
            self._adapter,
            "ticket_capability_authority_id",
            authority.worker_id,
        )
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 200
            or value != value.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in value
            )
        ):
            raise CaptureCheckpointError(
                "ticket capability authority is invalid"
            )
        return value

    def _ticket_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool:
        probe = getattr(
            self._adapter,
            "ticket_image_capability_is_current",
            None,
        )
        if not callable(probe):
            return True
        return bool(probe(ticket_ref))

    def _detail_requires_capability_refresh(
        self,
        *,
        checkpoint: DurableCaptureCheckpoint,
        detail: WaybillDetail,
        authority: BrowserCommandAuthority,
        access_window_id: str | None,
    ) -> bool:
        missing_tickets = tuple(
            ticket
            for ticket in detail.tickets
            if ticket.ticket_ref not in checkpoint.ticket_images
        )
        if not missing_tickets:
            return False
        platform_waybill_id = detail.platform_waybill_id
        if (
            checkpoint.detail_capability_worker_ids.get(
                platform_waybill_id
            )
            != self._ticket_capability_authority_id(authority)
        ):
            return True
        if (
            access_window_id is not None
            and checkpoint.detail_capability_access_window_ids.get(
                platform_waybill_id
            )
            != access_window_id
        ):
            return True
        return any(
            not self._ticket_capability_is_current(ticket.ticket_ref)
            for ticket in missing_tickets
        )

    def _merge_refreshed_detail(
        self,
        *,
        checkpoint: DurableCaptureCheckpoint,
        prior: WaybillDetail,
        refreshed: WaybillDetail,
    ) -> WaybillDetail:
        if (
            refreshed.platform_waybill_id
            != prior.platform_waybill_id
            or refreshed.waybill_number != prior.waybill_number
            or refreshed.vehicle_number != prior.vehicle_number
            or refreshed.loading_net != prior.loading_net
            or refreshed.unloading_net != prior.unloading_net
        ):
            raise CaptureCheckpointError(
                "refreshed detail changed persisted business evidence"
            )
        prior_by_slot = {
            ticket.slot: ticket for ticket in prior.tickets
        }
        refreshed_by_slot = {
            ticket.slot: ticket for ticket in refreshed.tickets
        }
        if (
            len(prior_by_slot) != len(prior.tickets)
            or len(refreshed_by_slot) != len(refreshed.tickets)
            or set(prior_by_slot) != set(refreshed_by_slot)
        ):
            raise CaptureCheckpointError(
                "refreshed detail changed ticket slot identity"
            )
        if any(
            refreshed_by_slot[slot].media_type
            != prior_ticket.media_type
            for slot, prior_ticket in prior_by_slot.items()
        ):
            raise CaptureCheckpointError(
                "refreshed detail changed ticket media type"
            )
        prior_refs = {
            ticket.ticket_ref
            for detail in checkpoint.details
            for ticket in detail.tickets
        }
        refreshed_refs = {
            ticket.ticket_ref for ticket in refreshed.tickets
        }
        if (
            len(refreshed_refs) != len(refreshed.tickets)
            or any(
                not self._ticket_capability_is_current(ticket_ref)
                for ticket_ref in refreshed_refs & prior_refs
            )
        ):
            raise CaptureCheckpointError(
                "refreshed detail reused a stale ticket reference"
            )
        completed_refs = set(checkpoint.ticket_images)
        return replace(
            prior,
            tickets=tuple(
                (
                    prior_ticket
                    if prior_ticket.ticket_ref in completed_refs
                    else refreshed_by_slot[prior_ticket.slot]
                )
                for prior_ticket in prior.tickets
            ),
        )

    def _invalidate_detail_capability(
        self,
        *,
        checkpoint: DurableCaptureCheckpoint,
        platform_waybill_id: str,
        authority: BrowserCommandAuthority,
    ) -> DurableCaptureCheckpoint:
        worker_ids = dict(checkpoint.detail_capability_worker_ids)
        worker_ids.pop(platform_waybill_id, None)
        access_window_ids = dict(
            checkpoint.detail_capability_access_window_ids
        )
        access_window_ids.pop(platform_waybill_id, None)
        return self._checkpoint_store.commit_checkpoint(
            replace(
                checkpoint,
                stage=ChengfengStage.IMAGE_DOWNLOAD,
                detail_capability_worker_ids=worker_ids,
                detail_capability_access_window_ids=(
                    access_window_ids
                ),
                schema_version=CHECKPOINT_SCHEMA_VERSION,
            ),
            authority,
        )

    def _load_or_create(
        self,
        *,
        authority: BrowserCommandAuthority,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint:
        checkpoint = self._checkpoint_store.load(
            job_id=authority.job_id,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )
        if checkpoint is not None:
            return checkpoint
        return DurableCaptureCheckpoint.initial(
            capture_id=self._checkpoint_store.capture_id(
                job_id=authority.job_id,
                scope=scope,
                page_number=page_number,
                page_size=page_size,
            ),
            job_id=authority.job_id,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )

    def _next_stage(
        self,
        checkpoint: DurableCaptureCheckpoint,
    ) -> ChengfengStage | None:
        if checkpoint.revision == 0:
            return ChengfengStage.BROWSER_START
        if checkpoint.stage is ChengfengStage.BROWSER_START:
            return ChengfengStage.LOGIN_CHECK
        if checkpoint.page is None:
            return ChengfengStage.LIST_QUERY
        completed_details = set(checkpoint.completed_detail_ids)
        completed_images = set(checkpoint.ticket_images)
        if self._interleave_images:
            details_by_id = {
                detail.platform_waybill_id: detail
                for detail in checkpoint.details
            }
            for item in checkpoint.page.items:
                if item.platform_waybill_id not in completed_details:
                    return ChengfengStage.DETAIL_QUERY
                detail = details_by_id[item.platform_waybill_id]
                if any(
                    ticket.ticket_ref not in completed_images
                    for ticket in detail.tickets
                ):
                    return ChengfengStage.IMAGE_DOWNLOAD
            return None
        if any(item.platform_waybill_id not in completed_details for item in checkpoint.page.items):
            return ChengfengStage.DETAIL_QUERY
        if any(
            ticket.ticket_ref not in completed_images
            for detail in checkpoint.details
            for ticket in detail.tickets
        ):
            return ChengfengStage.IMAGE_DOWNLOAD
        return None

    def _step_result(
        self,
        checkpoint: DurableCaptureCheckpoint,
        *,
        platform_read_performed: bool,
        authority: BrowserCommandAuthority,
    ) -> CaptureStepResult:
        next_stage = self._next_stage(checkpoint)
        return CaptureStepResult(
            checkpoint=checkpoint,
            has_more=next_stage is not None,
            next_stage=next_stage,
            platform_read_performed=platform_read_performed,
            authority=authority,
        )

    def advance(
        self,
        *,
        authority: BrowserCommandAuthority,
        scope: str,
        page_number: int,
        page_size: int,
        access_window_id: str | None = None,
    ) -> CaptureStepResult:
        checkpoint = self._load_or_create(
            authority=authority,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )
        current_authority = authority

        if checkpoint.revision == 0:
            self._authorize(current_authority)
            checkpoint = self._checkpoint_store.commit_checkpoint(
                checkpoint,
                current_authority,
            )
            return self._step_result(
                checkpoint,
                platform_read_performed=False,
                authority=current_authority,
            )
        if checkpoint.page is None:
            raw_page, current_authority = self._read_with_recovery(
                authority=current_authority,
                checkpoint=ChengfengStage.LIST_QUERY,
                read=lambda read_authority: self._adapter.list_waybills(
                    authority=read_authority,
                    scope=scope,
                    page_number=page_number,
                    page_size=page_size,
                ),
            )
            if not isinstance(raw_page, WaybillPage):
                raise TypeError("Chengfeng list adapter returned an invalid result")
            checkpoint = self._checkpoint_store.commit_checkpoint(
                replace(
                    checkpoint,
                    stage=ChengfengStage.LIST_QUERY,
                    completed_list=True,
                    page=raw_page,
                    read_access_window_ids=_next_read_access_mapping(
                        checkpoint,
                        stage=ChengfengStage.LIST_QUERY,
                        subject=None,
                        access_window_id=access_window_id,
                    ),
                ),
                current_authority,
            )
            return self._step_result(
                checkpoint,
                platform_read_performed=True,
                authority=current_authority,
            )

        assert checkpoint.page is not None
        page = checkpoint.page
        details_by_id = {detail.platform_waybill_id: detail for detail in checkpoint.details}
        for item in page.items:
            if item.platform_waybill_id in details_by_id:
                continue
            if self._interleave_images and any(
                ticket.ticket_ref not in checkpoint.ticket_images
                for detail in checkpoint.details
                for ticket in detail.tickets
            ):
                break
            def read_detail(
                read_authority: BrowserCommandAuthority,
                requested_id: str = item.platform_waybill_id,
            ) -> WaybillDetail:
                return self._adapter.get_waybill_detail(
                    authority=read_authority,
                    platform_waybill_id=requested_id,
                )

            raw_detail, current_authority = self._read_with_recovery(
                authority=current_authority,
                checkpoint=ChengfengStage.DETAIL_QUERY,
                read=read_detail,
            )
            if not isinstance(raw_detail, WaybillDetail):
                raise TypeError("Chengfeng detail adapter returned an invalid result")
            if raw_detail.platform_waybill_id != item.platform_waybill_id:
                raise CaptureCheckpointError("detail result does not match the requested waybill")
            capability_authority_id = (
                self._ticket_capability_authority_id(
                    current_authority
                )
            )
            capability_access_windows = dict(
                checkpoint.detail_capability_access_window_ids
            )
            if access_window_id is not None:
                capability_access_windows[
                    raw_detail.platform_waybill_id
                ] = access_window_id
            checkpoint = self._checkpoint_store.commit_checkpoint(
                replace(
                    checkpoint,
                    stage=ChengfengStage.DETAIL_QUERY,
                    completed_detail_ids=(
                        *checkpoint.completed_detail_ids,
                        raw_detail.platform_waybill_id,
                    ),
                    details=(*checkpoint.details, raw_detail),
                    detail_capability_worker_ids={
                        **checkpoint.detail_capability_worker_ids,
                        raw_detail.platform_waybill_id: (
                            capability_authority_id
                        ),
                    },
                    detail_capability_access_window_ids=(
                        capability_access_windows
                    ),
                    schema_version=CHECKPOINT_SCHEMA_VERSION,
                    read_access_window_ids=_next_read_access_mapping(
                        checkpoint,
                        stage=ChengfengStage.DETAIL_QUERY,
                        subject=raw_detail.platform_waybill_id,
                        access_window_id=access_window_id,
                    ),
                ),
                current_authority,
            )
            return self._step_result(
                checkpoint,
                platform_read_performed=True,
                authority=current_authority,
            )

        for item in page.items:
            detail = details_by_id.get(item.platform_waybill_id)
            if detail is None:
                continue
            has_missing_images = any(
                ticket.ticket_ref not in checkpoint.ticket_images
                for ticket in detail.tickets
            )
            if not has_missing_images:
                continue
            if not self._detail_requires_capability_refresh(
                checkpoint=checkpoint,
                detail=detail,
                authority=current_authority,
                access_window_id=access_window_id,
            ):
                if self._interleave_images:
                    break
                continue

            def refresh_detail(
                read_authority: BrowserCommandAuthority,
                requested_id: str = item.platform_waybill_id,
            ) -> WaybillDetail:
                return self._adapter.get_waybill_detail(
                    authority=read_authority,
                    platform_waybill_id=requested_id,
                )

            raw_refreshed, current_authority = (
                self._read_with_recovery(
                    authority=current_authority,
                    checkpoint=ChengfengStage.DETAIL_QUERY,
                    read=refresh_detail,
                )
            )
            if not isinstance(raw_refreshed, WaybillDetail):
                raise TypeError(
                    "Chengfeng detail adapter returned an invalid result"
                )
            merged_detail = self._merge_refreshed_detail(
                checkpoint=checkpoint,
                prior=detail,
                refreshed=raw_refreshed,
            )
            capability_authority_id = (
                self._ticket_capability_authority_id(
                    current_authority
                )
            )
            capability_windows = dict(
                checkpoint.detail_capability_access_window_ids
            )
            if access_window_id is None:
                capability_windows.pop(
                    detail.platform_waybill_id,
                    None,
                )
            else:
                capability_windows[
                    detail.platform_waybill_id
                ] = access_window_id
            checkpoint = self._checkpoint_store.commit_checkpoint(
                replace(
                    checkpoint,
                    stage=ChengfengStage.DETAIL_QUERY,
                    details=tuple(
                        (
                            merged_detail
                            if existing.platform_waybill_id
                            == detail.platform_waybill_id
                            else existing
                        )
                        for existing in checkpoint.details
                    ),
                    detail_capability_worker_ids={
                        **checkpoint.detail_capability_worker_ids,
                        detail.platform_waybill_id: (
                            capability_authority_id
                        ),
                    },
                    detail_capability_access_window_ids=(
                        capability_windows
                    ),
                    read_access_window_ids=(
                        _next_detail_refresh_access_mapping(
                            checkpoint,
                            platform_waybill_id=(
                                detail.platform_waybill_id
                            ),
                            worker_id=capability_authority_id,
                            access_window_id=access_window_id,
                        )
                    ),
                    schema_version=CHECKPOINT_SCHEMA_VERSION,
                ),
                current_authority,
            )
            return self._step_result(
                checkpoint,
                platform_read_performed=True,
                authority=current_authority,
            )

        details_by_id = {
            detail.platform_waybill_id: detail
            for detail in checkpoint.details
        }
        for item in page.items:
            detail = details_by_id.get(item.platform_waybill_id)
            if detail is None:
                continue
            for ticket in detail.tickets:
                if ticket.ticket_ref in checkpoint.ticket_images:
                    continue
                def read_image(
                    read_authority: BrowserCommandAuthority,
                    requested_ref: str = ticket.ticket_ref,
                ) -> DownloadedTicketImage:
                    return self._adapter.download_ticket_image(
                        authority=read_authority,
                        ticket_ref=requested_ref,
                    )

                try:
                    raw_image, current_authority = (
                        self._read_with_recovery(
                            authority=current_authority,
                            checkpoint=(
                                ChengfengStage.IMAGE_DOWNLOAD
                            ),
                            read=read_image,
                        )
                    )
                except TicketImageCapabilityExpiredError:
                    checkpoint = self._invalidate_detail_capability(
                        checkpoint=checkpoint,
                        platform_waybill_id=(
                            detail.platform_waybill_id
                        ),
                        authority=current_authority,
                    )
                    return self._step_result(
                        checkpoint,
                        platform_read_performed=False,
                        authority=current_authority,
                    )
                if raw_image is _CAPABILITY_REFRESH_REQUIRED:
                    checkpoint = self._invalidate_detail_capability(
                        checkpoint=checkpoint,
                        platform_waybill_id=(
                            detail.platform_waybill_id
                        ),
                        authority=current_authority,
                    )
                    return self._step_result(
                        checkpoint,
                        platform_read_performed=False,
                        authority=current_authority,
                    )
                if not isinstance(raw_image, DownloadedTicketImage):
                    raise TypeError("Chengfeng image adapter returned an invalid result")
                if raw_image.ticket_ref != ticket.ticket_ref:
                    raise CaptureCheckpointError("image result does not match the requested ticket")
                pending_image = replace(
                    checkpoint,
                    stage=ChengfengStage.IMAGE_DOWNLOAD,
                )
                if access_window_id is None:
                    checkpoint = self._checkpoint_store.commit_image(
                        pending_image,
                        raw_image,
                        current_authority,
                    )
                else:
                    checkpoint = self._checkpoint_store.commit_image(
                        pending_image,
                        raw_image,
                        current_authority,
                        access_window_id=access_window_id,
                    )
                return self._step_result(
                    checkpoint,
                    platform_read_performed=True,
                    authority=current_authority,
                )

        return self._step_result(
            checkpoint,
            platform_read_performed=False,
            authority=current_authority,
        )

    def capture_result(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> CaptureResult:
        checkpoint = self._checkpoint_store.load(
            job_id=job_id,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )
        if checkpoint is None:
            raise CaptureCheckpointError("capture result has no durable checkpoint")
        if self._next_stage(checkpoint) is not None or checkpoint.page is None:
            raise CaptureCheckpointError("capture result is not complete")
        images = tuple(
            DownloadedTicketImage(
                ticket_ref=ticket.ticket_ref,
                media_type=checkpoint.ticket_images[ticket.ticket_ref].media_type,
                content=self._checkpoint_store.read_image(
                    checkpoint.ticket_images[ticket.ticket_ref]
                ),
                sha256=checkpoint.ticket_images[ticket.ticket_ref].sha256,
            )
            for detail in checkpoint.details
            for ticket in detail.tickets
        )
        return CaptureResult(
            page=checkpoint.page,
            details=checkpoint.details,
            images=images,
        )


def _required_string(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise CaptureCheckpointError(f"{field_name} must be a non-empty string")
    return value


def _required_int(value: object, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CaptureCheckpointError(f"{field_name} must be an integer")
    return value


def _required_bool(value: object, *, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise CaptureCheckpointError(f"{field_name} must be a boolean")
    return value


def _optional_string(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_string(value, field_name=field_name)


def _string_tuple(value: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CaptureCheckpointError(f"{field_name} must be a list")
    return tuple(_required_string(item, field_name=f"{field_name} item") for item in value)


def _strict_object(value: object, *, keys: set[str], field_name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CaptureCheckpointError(f"{field_name} fields do not match schema")
    return value


def _summary_to_payload(summary: WaybillSummary) -> dict[str, object]:
    return {
        "platform_waybill_id": summary.platform_waybill_id,
        "waybill_number": summary.waybill_number,
        "vehicle_number": summary.vehicle_number,
    }


def _summary_from_payload(payload: object) -> WaybillSummary:
    value = _strict_object(
        payload,
        keys={"platform_waybill_id", "waybill_number", "vehicle_number"},
        field_name="waybill summary",
    )
    return WaybillSummary(
        platform_waybill_id=_required_string(
            value["platform_waybill_id"],
            field_name="platform_waybill_id",
        ),
        waybill_number=_required_string(
            value["waybill_number"],
            field_name="waybill_number",
        ),
        vehicle_number=_optional_string(
            value["vehicle_number"],
            field_name="vehicle_number",
        ),
    )


def _page_to_payload(page: WaybillPage) -> dict[str, object]:
    return {
        "page_number": page.page_number,
        "page_size": page.page_size,
        "total": page.total,
        "items": [_summary_to_payload(item) for item in page.items],
    }


def _page_from_payload(payload: object) -> WaybillPage:
    value = _strict_object(
        payload,
        keys={"page_number", "page_size", "total", "items"},
        field_name="waybill page",
    )
    items = value["items"]
    if not isinstance(items, list):
        raise CaptureCheckpointError("waybill page items must be a list")
    return WaybillPage(
        page_number=_required_int(value["page_number"], field_name="page_number"),
        page_size=_required_int(value["page_size"], field_name="page_size"),
        total=_required_int(value["total"], field_name="total"),
        items=tuple(_summary_from_payload(item) for item in items),
    )


def _ticket_to_payload(ticket: TicketReference) -> dict[str, object]:
    return {
        "slot": ticket.slot,
        "ticket_ref": ticket.ticket_ref,
        "media_type": ticket.media_type,
    }


def _ticket_from_payload(payload: object) -> TicketReference:
    value = _strict_object(
        payload,
        keys={"slot", "ticket_ref", "media_type"},
        field_name="ticket reference",
    )
    return TicketReference(
        slot=_required_string(value["slot"], field_name="slot"),
        ticket_ref=_required_string(value["ticket_ref"], field_name="ticket_ref"),
        media_type=_required_string(value["media_type"], field_name="media_type"),
    )


def _detail_to_payload(detail: WaybillDetail) -> dict[str, object]:
    return {
        "platform_waybill_id": detail.platform_waybill_id,
        "waybill_number": detail.waybill_number,
        "vehicle_number": detail.vehicle_number,
        "loading_net": detail.loading_net,
        "unloading_net": detail.unloading_net,
        "tickets": [_ticket_to_payload(ticket) for ticket in detail.tickets],
    }


def _detail_from_payload(payload: object) -> WaybillDetail:
    value = _strict_object(
        payload,
        keys={
            "platform_waybill_id",
            "waybill_number",
            "vehicle_number",
            "loading_net",
            "unloading_net",
            "tickets",
        },
        field_name="waybill detail",
    )
    tickets = value["tickets"]
    if not isinstance(tickets, list):
        raise CaptureCheckpointError("waybill detail tickets must be a list")
    return WaybillDetail(
        platform_waybill_id=_required_string(
            value["platform_waybill_id"],
            field_name="platform_waybill_id",
        ),
        waybill_number=_required_string(
            value["waybill_number"],
            field_name="waybill_number",
        ),
        vehicle_number=_optional_string(
            value["vehicle_number"],
            field_name="vehicle_number",
        ),
        loading_net=_optional_string(value["loading_net"], field_name="loading_net"),
        unloading_net=_optional_string(
            value["unloading_net"],
            field_name="unloading_net",
        ),
        tickets=tuple(_ticket_from_payload(ticket) for ticket in tickets),
    )


def _image_from_payload(payload: object) -> PersistedTicketImage:
    value = _strict_object(
        payload,
        keys={"ticket_ref", "sha256", "relative_path", "byte_size", "media_type"},
        field_name="persisted ticket image",
    )
    return PersistedTicketImage(
        ticket_ref=_required_string(value["ticket_ref"], field_name="ticket_ref"),
        sha256=_required_string(value["sha256"], field_name="sha256"),
        relative_path=_required_string(
            value["relative_path"],
            field_name="relative_path",
        ),
        byte_size=_required_int(value["byte_size"], field_name="byte_size"),
        media_type=_required_string(value["media_type"], field_name="media_type"),
    )
