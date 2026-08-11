from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from dahe.adapters.chengfeng.connector_staging import (
    ConnectorStagingError,
    begin_command_staging,
    command_staging_directory_name,
    recover_connector_staging,
)
from dahe.adapters.chengfeng.frozen import FrozenChengfengAdapter
from dahe.adapters.chengfeng.payload_codec import (
    encode_waybill_detail,
    encode_waybill_page,
)
from dahe.adapters.chengfeng.protocol import (
    ConnectorCommand,
    ConnectorDiagnosticClassification,
    ConnectorPayloadKind,
    ConnectorPayloadReference,
    ConnectorResult,
    ConnectorResultOutcome,
)
from dahe.ports.chengfeng import (
    BrowserContextClosedError,
    BrowserNavigationAuthorizer,
    ChengfengOperation,
    ChengfengReadError,
    ChengfengStage,
    DownloadedTicketImage,
    ImageDownloadTimeoutError,
    LoginRequiredError,
    PageContractChangedError,
    TransientNetworkError,
    WaybillDetail,
    WaybillPage,
)

_STAGE_BY_OPERATION = {
    ChengfengOperation.LIST_WAYBILLS: ChengfengStage.LIST_QUERY,
    ChengfengOperation.GET_WAYBILL_DETAIL: ChengfengStage.DETAIL_QUERY,
    ChengfengOperation.DOWNLOAD_TICKET_IMAGE: ChengfengStage.IMAGE_DOWNLOAD,
}
_DIAGNOSTIC_BY_ERROR = {
    LoginRequiredError: ConnectorDiagnosticClassification.LOGIN_REQUIRED,
    PageContractChangedError: ConnectorDiagnosticClassification.PAGE_CONTRACT_CHANGED,
    ImageDownloadTimeoutError: ConnectorDiagnosticClassification.IMAGE_TIMEOUT,
    TransientNetworkError: ConnectorDiagnosticClassification.TRANSIENT_NETWORK,
    BrowserContextClosedError: ConnectorDiagnosticClassification.BROWSER_CONTEXT_CLOSED,
}


class ConnectorRuntimePort(Protocol):
    """The isolated connector accepts and returns one strict NDJSON record."""

    @property
    def ticket_capability_authority_id(self) -> str: ...

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool: ...

    def execute(self, command_ndjson: str | bytes) -> str | bytes: ...


class FrozenConnectorRuntime:
    """Offline child-process boundary backed only by the frozen adapter."""

    def __init__(
        self,
        *,
        adapter: FrozenChengfengAdapter,
        data_root: Path,
        authorizer: BrowserNavigationAuthorizer,
    ) -> None:
        self._adapter = adapter
        self._data_root = data_root.absolute()
        self._authorizer = authorizer
        recover_connector_staging(self._data_root)

    @property
    def ticket_capability_authority_id(self) -> str:
        return hashlib.sha256(b"frozen-connector-v1").hexdigest()

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool:
        return isinstance(ticket_ref, str) and bool(ticket_ref)

    def execute(self, command_ndjson: str | bytes) -> str:
        command = ConnectorCommand.from_ndjson(command_ndjson)
        stage = _STAGE_BY_OPERATION[command.operation]
        if command.credential_reference is not None:
            return self._failure(
                command,
                stage=stage,
                classification=ConnectorDiagnosticClassification.PROTOCOL_ERROR,
            ).to_ndjson()
        try:
            self._authorizer.authorize(command.authority)
            kind, media_type, content = self._perform_read(command)
            reference = self._stage_payload(
                command=command,
                kind=kind,
                media_type=media_type,
                content=content,
            )
        except ChengfengReadError as error:
            classification = _DIAGNOSTIC_BY_ERROR.get(
                type(error),
                ConnectorDiagnosticClassification.PROTOCOL_ERROR,
            )
            return self._failure(
                command,
                stage=stage,
                classification=classification,
            ).to_ndjson()
        except (ConnectorStagingError, KeyError, OSError, TypeError, ValueError):
            return self._failure(
                command,
                stage=stage,
                classification=ConnectorDiagnosticClassification.PROTOCOL_ERROR,
            ).to_ndjson()
        return ConnectorResult(
            protocol_version=command.protocol_version,
            command_id=command.command_id,
            operation=command.operation,
            outcome=ConnectorResultOutcome.SUCCEEDED,
            stage=stage,
            diagnostic_classification=ConnectorDiagnosticClassification.NONE,
            payload_references=(reference,),
        ).to_ndjson()

    def _perform_read(
        self,
        command: ConnectorCommand,
    ) -> tuple[ConnectorPayloadKind, str, bytes]:
        parameters = command.parameters
        if command.operation is ChengfengOperation.LIST_WAYBILLS:
            page = self._adapter.list_waybills(
                scope=cast(str, parameters["scope"]),
                page_number=cast(int, parameters["page_number"]),
                page_size=cast(int, parameters["page_size"]),
            )
            if not isinstance(page, WaybillPage):
                raise TypeError("frozen list result is invalid")
            return ConnectorPayloadKind.WAYBILL_PAGE, "application/json", encode_waybill_page(page)
        if command.operation is ChengfengOperation.GET_WAYBILL_DETAIL:
            detail = self._adapter.get_waybill_detail(
                cast(str, parameters["platform_waybill_id"])
            )
            if not isinstance(detail, WaybillDetail):
                raise TypeError("frozen detail result is invalid")
            return (
                ConnectorPayloadKind.WAYBILL_DETAIL,
                "application/json",
                encode_waybill_detail(detail),
            )
        image = self._adapter.download_ticket_image(cast(str, parameters["ticket_ref"]))
        if not isinstance(image, DownloadedTicketImage):
            raise TypeError("frozen image result is invalid")
        if hashlib.sha256(image.content).hexdigest() != image.sha256:
            raise ValueError("frozen image identity is invalid")
        return ConnectorPayloadKind.TICKET_IMAGE, image.media_type, image.content

    def _stage_payload(
        self,
        *,
        command: ConnectorCommand,
        kind: ConnectorPayloadKind,
        media_type: str,
        content: bytes,
    ) -> ConnectorPayloadReference:
        command_directory = command_staging_directory_name(command.command_id)
        relative_directory = Path("connector-staging") / command_directory
        directory = begin_command_staging(
            data_root=self._data_root,
            command_id=command.command_id,
        )
        suffix = {
            "application/json": ".json",
            "image/jpeg": ".jpg",
            "image/png": ".png",
        }[media_type]
        target = directory / f"payload{suffix}"
        staged = directory / f".{uuid4().hex}.part"
        try:
            with staged.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staged, target)
        finally:
            staged.unlink(missing_ok=True)
        digest = hashlib.sha256(content).hexdigest()
        return ConnectorPayloadReference(
            kind=kind,
            relative_path=(relative_directory / target.name).as_posix(),
            sha256=digest,
            media_type=media_type,
            byte_size=len(content),
        )

    @staticmethod
    def _failure(
        command: ConnectorCommand,
        *,
        stage: ChengfengStage,
        classification: ConnectorDiagnosticClassification,
    ) -> ConnectorResult:
        return ConnectorResult(
            protocol_version=command.protocol_version,
            command_id=command.command_id,
            operation=command.operation,
            outcome=ConnectorResultOutcome.FAILED,
            stage=stage,
            diagnostic_classification=classification,
            payload_references=(),
        )
