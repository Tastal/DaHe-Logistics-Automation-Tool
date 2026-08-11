from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

CURRENT_PENDING_SETTLEMENT_SCOPE = "current"
HISTORICAL_SETTLED_SCOPE = "settled_history"
APPROVED_SETTLEMENT_SCOPES = frozenset(
    {
        CURRENT_PENDING_SETTLEMENT_SCOPE,
        HISTORICAL_SETTLED_SCOPE,
    }
)


class ChengfengOperation(StrEnum):
    """The complete automatic platform surface accepted by the first MVP."""

    LIST_WAYBILLS = "list_waybills"
    GET_WAYBILL_DETAIL = "get_waybill_detail"
    DOWNLOAD_TICKET_IMAGE = "download_ticket_image"


class ChengfengStage(StrEnum):
    BROWSER_START = "browser_start"
    LOGIN_CHECK = "login_check"
    LIST_QUERY = "list_query"
    DETAIL_QUERY = "detail_query"
    IMAGE_DOWNLOAD = "image_download"


@dataclass(frozen=True, slots=True)
class BrowserCommandAuthority:
    """Short-lived process authority; never persist or log the raw token."""

    session_id: str
    instance_id: str
    worker_id: str
    job_id: str
    control_epoch: int
    fencing_token: str = field(repr=False)

    def __post_init__(self) -> None:
        for field_name in (
            "session_id",
            "instance_id",
            "worker_id",
            "job_id",
            "fencing_token",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} is required")
        if isinstance(self.control_epoch, bool) or self.control_epoch < 1:
            raise ValueError("control_epoch must be a positive integer")


@dataclass(frozen=True, slots=True)
class WaybillSummary:
    platform_waybill_id: str
    waybill_number: str
    vehicle_number: str | None


@dataclass(frozen=True, slots=True)
class WaybillPage:
    page_number: int
    page_size: int
    total: int
    items: tuple[WaybillSummary, ...]


@dataclass(frozen=True, slots=True)
class TicketReference:
    slot: str
    ticket_ref: str
    media_type: str


@dataclass(frozen=True, slots=True)
class WaybillDetail:
    platform_waybill_id: str
    waybill_number: str
    vehicle_number: str | None
    loading_net: str | None
    unloading_net: str | None
    tickets: tuple[TicketReference, ...]


@dataclass(frozen=True, slots=True)
class DownloadedTicketImage:
    ticket_ref: str
    media_type: str
    content: bytes
    sha256: str
    validator_sha256: str | None = None
    reused_from_cache: bool = False


@dataclass(frozen=True, slots=True)
class TicketImageReuseCandidate:
    slot: str
    sha256: str
    media_type: str
    validator_sha256: str


@dataclass(frozen=True, slots=True)
class WaybillReuseCandidate:
    platform_waybill_id: str
    source_revision_sha256: str
    images: tuple[TicketImageReuseCandidate, ...]


@dataclass(frozen=True, slots=True)
class OperationalWaybillEvidence:
    detail: WaybillDetail
    images: tuple[DownloadedTicketImage, ...]
    source_revision_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ConnectorDiagnostic:
    code: str
    blocking: bool
    stage: ChengfengStage


class ChengfengReadError(RuntimeError):
    """Typed connector failure that cannot be mistaken for a business review."""

    def __init__(
        self,
        message: str,
        *,
        stage: ChengfengStage,
        diagnostic_code: str,
        retryable: bool,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.diagnostic_code = diagnostic_code
        self.retryable = retryable


class LoginRequiredError(ChengfengReadError):
    def __init__(self, *, stage: ChengfengStage) -> None:
        super().__init__(
            "the Chengfeng session requires an explicit human login",
            stage=stage,
            diagnostic_code="CF-LOGIN-REQUIRED",
            retryable=False,
        )


class PageContractChangedError(ChengfengReadError):
    def __init__(
        self,
        *,
        stage: ChengfengStage,
        diagnostic_code: str = "CF-PAGE-CONTRACT-CHANGED",
        safe_discovery: tuple[dict[str, object], ...] = (),
    ) -> None:
        super().__init__(
            "the frozen Chengfeng response contract no longer matches",
            stage=stage,
            diagnostic_code=diagnostic_code,
            retryable=False,
        )
        self.safe_discovery = safe_discovery


class DetailCandidateUnavailableError(ChengfengReadError):
    """Raised when one daily-list candidate no longer has a readable detail."""

    def __init__(self) -> None:
        super().__init__(
            "the selected daily candidate no longer has an available detail",
            stage=ChengfengStage.DETAIL_QUERY,
            diagnostic_code="CF-DETAIL-CANDIDATE-UNAVAILABLE",
            retryable=False,
        )


class ImageDownloadTimeoutError(ChengfengReadError):
    def __init__(self) -> None:
        super().__init__(
            "the ticket image download timed out",
            stage=ChengfengStage.IMAGE_DOWNLOAD,
            diagnostic_code="CF-IMAGE-TIMEOUT",
            retryable=True,
        )


class TransientNetworkError(ChengfengReadError):
    def __init__(self, *, stage: ChengfengStage) -> None:
        super().__init__(
            "the approved read request failed temporarily",
            stage=stage,
            diagnostic_code="CF-NETWORK-TRANSIENT",
            retryable=True,
        )


class OperationalBatchTimeoutError(ChengfengReadError):
    """Raised after one complete operational batch exceeds its owned deadline."""

    def __init__(self) -> None:
        super().__init__(
            "the operational Chengfeng batch exceeded its owned deadline",
            stage=ChengfengStage.DETAIL_QUERY,
            diagnostic_code="CF-BATCH-TIMEOUT",
            retryable=True,
        )


class BrowserContextClosedError(ChengfengReadError):
    def __init__(self, *, stage: ChengfengStage) -> None:
        super().__init__(
            "the controlled browser context closed before the atomic read committed",
            stage=stage,
            diagnostic_code="CF-BROWSER-CLOSED",
            retryable=True,
        )


class TicketImageCapabilityExpiredError(ChengfengReadError):
    def __init__(self) -> None:
        super().__init__(
            "the short-lived ticket image capability is unavailable",
            stage=ChengfengStage.IMAGE_DOWNLOAD,
            diagnostic_code="CF-IMAGE-CAPABILITY-EXPIRED",
            retryable=True,
        )


class ConnectorProtocolError(ChengfengReadError):
    def __init__(self, *, stage: ChengfengStage) -> None:
        super().__init__(
            "the connector process protocol is invalid",
            stage=stage,
            diagnostic_code="CF-PROTOCOL-ERROR",
            retryable=False,
        )


class ChengfengReadPort(Protocol):
    @property
    def ticket_capability_authority_id(self) -> str: ...

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool: ...

    def list_waybills(
        self,
        *,
        authority: BrowserCommandAuthority,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> WaybillPage: ...

    def get_waybill_detail(
        self,
        *,
        authority: BrowserCommandAuthority,
        platform_waybill_id: str,
    ) -> WaybillDetail: ...

    def download_ticket_image(
        self,
        *,
        authority: BrowserCommandAuthority,
        ticket_ref: str,
    ) -> DownloadedTicketImage: ...


class BrowserNavigationAuthorizer(Protocol):
    def authorize(self, authority: BrowserCommandAuthority) -> None: ...
