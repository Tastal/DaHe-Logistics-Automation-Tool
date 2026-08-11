from __future__ import annotations

import hashlib
from collections import Counter, defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from dahe.adapters.chengfeng.manifest import (
    FrozenContractManifest,
    FrozenResponse,
)
from dahe.adapters.chengfeng.policy import (
    AuthorizedRequest,
    ReadOnlyRequestFirewall,
    ReadRequest,
)
from dahe.ports.chengfeng import (
    BrowserContextClosedError,
    ChengfengOperation,
    ChengfengStage,
    ConnectorDiagnostic,
    DownloadedTicketImage,
    ImageDownloadTimeoutError,
    LoginRequiredError,
    PageContractChangedError,
    TicketReference,
    TransientNetworkError,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)


class FrozenFault(StrEnum):
    """Deterministic offline failures used to verify connector recovery."""

    LOGIN_REQUIRED = "login_required"
    PAGE_CONTRACT_CHANGED = "page_contract_changed"
    IMAGE_TIMEOUT = "image_timeout"
    NETWORK_TRANSIENT = "network_transient"
    BROWSER_CLOSED = "browser_closed"


@dataclass(frozen=True, slots=True)
class FrozenDiagnosticProbe:
    """A socket-free probe whose result is fixed by the test input."""

    dns_ok: bool = True

    def check_dns(self) -> bool:
        return self.dns_ok


class _DiagnosticProbe(Protocol):
    def check_dns(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class _FrozenTransportResponse:
    status_code: int
    media_type: str
    content: bytes


class _SyntheticImageTimeout(RuntimeError):
    pass


class _SyntheticNetworkFailure(RuntimeError):
    pass


class _SyntheticBrowserClosed(RuntimeError):
    pass


class FrozenTransport:
    """Replay verified fixture bytes without creating a network transport."""

    def __init__(self, *, manifest: FrozenContractManifest) -> None:
        self._manifest = manifest
        self._failures: dict[str, deque[FrozenFault]] = defaultdict(deque)
        self._request_counts: Counter[str] = Counter()

    def fail_next(self, *, operation: str, fault: FrozenFault) -> None:
        if type(operation) is not str or operation not in self._manifest.allowed_operations:
            raise ValueError("fault operation must be one frozen read operation")
        if not isinstance(fault, FrozenFault):
            raise TypeError("fault must be a FrozenFault")
        self._failures[operation].append(fault)

    def request_count(self, operation: str) -> int:
        return self._request_counts[operation]

    def send(self, request: AuthorizedRequest) -> _FrozenTransportResponse:
        operation = request.operation
        declared = self._manifest.find_request(operation, request.parameters)
        if declared is None or declared != request.contract_request:
            raise RuntimeError("authorized request is not part of this frozen transport")

        self._request_counts[operation] += 1
        failure = self._failures[operation].popleft() if self._failures[operation] else None
        if failure is FrozenFault.IMAGE_TIMEOUT:
            raise _SyntheticImageTimeout("synthetic image timeout")
        if failure is FrozenFault.NETWORK_TRANSIENT:
            raise _SyntheticNetworkFailure("synthetic transient network failure")
        if failure is FrozenFault.BROWSER_CLOSED:
            raise _SyntheticBrowserClosed("synthetic browser context closed")
        if failure is FrozenFault.LOGIN_REQUIRED:
            return self._response(self._manifest.fault_responses["login_required"])
        if failure is FrozenFault.PAGE_CONTRACT_CHANGED:
            return self._response(self._manifest.fault_responses["page_contract_changed"])
        return self._response(request.contract_request.response)

    def _response(self, response: FrozenResponse) -> _FrozenTransportResponse:
        return _FrozenTransportResponse(
            status_code=response.status_code,
            media_type=response.media_type,
            content=self._manifest.read_response_body(response),
        )


class _SummaryPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    platform_waybill_id: str
    waybill_number: str
    vehicle_number: str | None

    @field_validator("platform_waybill_id", "waybill_number")
    @classmethod
    def require_identity(cls, value: str) -> str:
        if not value:
            raise ValueError("waybill identity cannot be empty")
        return value


class _ListDataPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    page_number: int
    page_size: int
    total: int
    items: tuple[_SummaryPayload, ...]


class _ListPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    ok: Literal[True]
    data: _ListDataPayload


class _TicketPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    slot: str
    ticket_ref: str
    media_type: Literal["image/png"]

    @field_validator("slot", "ticket_ref")
    @classmethod
    def require_ticket_identity(cls, value: str) -> str:
        if not value:
            raise ValueError("ticket identity cannot be empty")
        return value


class _DetailDataPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    platform_waybill_id: str
    waybill_number: str
    vehicle_number: str | None
    loading_net: str | None
    unloading_net: str | None
    tickets: tuple[_TicketPayload, ...]

    @field_validator("platform_waybill_id", "waybill_number")
    @classmethod
    def require_identity(cls, value: str) -> str:
        if not value:
            raise ValueError("waybill identity cannot be empty")
        return value


class _DetailPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    ok: Literal[True]
    data: _DetailDataPayload


class FrozenChengfengAdapter:
    """Three-operation offline adapter guarded by the exact request contract."""

    def __init__(
        self,
        *,
        manifest: FrozenContractManifest,
        transport: FrozenTransport,
        diagnostic_probe: _DiagnosticProbe | None = None,
    ) -> None:
        self._manifest = manifest
        self._transport = transport
        self._firewall = ReadOnlyRequestFirewall(manifest)
        self._diagnostic_probe = diagnostic_probe or FrozenDiagnosticProbe()
        self.diagnostics: list[ConnectorDiagnostic] = []

    def list_waybills(
        self,
        *,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> WaybillPage:
        parameters: dict[str, object] = {
            "scope": scope,
            "page_number": page_number,
            "page_size": page_size,
        }
        response = self._read(
            operation=ChengfengOperation.LIST_WAYBILLS,
            parameters=parameters,
            stage=ChengfengStage.LIST_QUERY,
        )
        payload = self._parse_json(response, _ListPayload, ChengfengStage.LIST_QUERY)
        if not isinstance(payload, _ListPayload):
            raise AssertionError("list payload parser returned the wrong model")
        data = payload.data
        if (
            data.page_number != page_number
            or data.page_size != page_size
            or data.total < len(data.items)
            or len({item.platform_waybill_id for item in data.items}) != len(data.items)
        ):
            raise PageContractChangedError(stage=ChengfengStage.LIST_QUERY)
        return WaybillPage(
            page_number=data.page_number,
            page_size=data.page_size,
            total=data.total,
            items=tuple(
                WaybillSummary(
                    platform_waybill_id=item.platform_waybill_id,
                    waybill_number=item.waybill_number,
                    vehicle_number=item.vehicle_number,
                )
                for item in data.items
            ),
        )

    def get_waybill_detail(self, platform_waybill_id: str) -> WaybillDetail:
        response = self._read(
            operation=ChengfengOperation.GET_WAYBILL_DETAIL,
            parameters={"platform_waybill_id": platform_waybill_id},
            stage=ChengfengStage.DETAIL_QUERY,
        )
        payload = self._parse_json(response, _DetailPayload, ChengfengStage.DETAIL_QUERY)
        if not isinstance(payload, _DetailPayload):
            raise AssertionError("detail payload parser returned the wrong model")
        data = payload.data
        ticket_refs = [ticket.ticket_ref for ticket in data.tickets]
        if data.platform_waybill_id != platform_waybill_id or len(set(ticket_refs)) != len(
            ticket_refs
        ):
            raise PageContractChangedError(stage=ChengfengStage.DETAIL_QUERY)
        return WaybillDetail(
            platform_waybill_id=data.platform_waybill_id,
            waybill_number=data.waybill_number,
            vehicle_number=data.vehicle_number,
            loading_net=data.loading_net,
            unloading_net=data.unloading_net,
            tickets=tuple(
                TicketReference(
                    slot=ticket.slot,
                    ticket_ref=ticket.ticket_ref,
                    media_type=ticket.media_type,
                )
                for ticket in data.tickets
            ),
        )

    def download_ticket_image(self, ticket_ref: str) -> DownloadedTicketImage:
        response = self._read(
            operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
            parameters={"ticket_ref": ticket_ref},
            stage=ChengfengStage.IMAGE_DOWNLOAD,
        )
        if response.status_code != 200 or response.media_type != "image/png":
            raise PageContractChangedError(stage=ChengfengStage.IMAGE_DOWNLOAD)
        return DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type=response.media_type,
            content=response.content,
            sha256=hashlib.sha256(response.content).hexdigest(),
        )

    def _read(
        self,
        *,
        operation: ChengfengOperation,
        parameters: Mapping[str, object],
        stage: ChengfengStage,
    ) -> _FrozenTransportResponse:
        declared = self._manifest.request_for(operation.value, parameters)
        request = ReadRequest(
            operation=operation.value,
            method=declared.method,
            url=f"{self._manifest.origin}{declared.path}",
            parameters_location=declared.parameters_location,
            parameters=parameters,
        )
        authorized = self._firewall.authorize(request)
        self._record_nonblocking_diagnostic(stage)
        try:
            response = self._transport.send(authorized)
        except _SyntheticImageTimeout as exc:
            raise ImageDownloadTimeoutError() from exc
        except _SyntheticNetworkFailure as exc:
            raise TransientNetworkError(stage=stage) from exc
        except _SyntheticBrowserClosed as exc:
            raise BrowserContextClosedError(stage=stage) from exc
        self._classify_html(response, stage)
        return response

    def _record_nonblocking_diagnostic(self, stage: ChengfengStage) -> None:
        try:
            dns_ok = self._diagnostic_probe.check_dns()
        except Exception:
            dns_ok = False
        if not dns_ok:
            self.diagnostics.append(
                ConnectorDiagnostic(
                    code="CF-DNS-DIAGNOSTIC",
                    blocking=False,
                    stage=stage,
                )
            )

    @staticmethod
    def _classify_html(response: _FrozenTransportResponse, stage: ChengfengStage) -> None:
        if response.media_type != "text/html":
            return
        try:
            body = response.content.decode("utf-8").casefold()
        except UnicodeDecodeError as exc:
            raise PageContractChangedError(stage=stage) from exc
        if 'id="login-form"' in body:
            raise LoginRequiredError(stage=stage)
        raise PageContractChangedError(stage=stage)

    @staticmethod
    def _parse_json(
        response: _FrozenTransportResponse,
        model: type[BaseModel],
        stage: ChengfengStage,
    ) -> BaseModel:
        if response.status_code != 200 or response.media_type != "application/json":
            raise PageContractChangedError(stage=stage)
        try:
            return model.model_validate_json(response.content, strict=True)
        except ValidationError as exc:
            raise PageContractChangedError(stage=stage) from exc
