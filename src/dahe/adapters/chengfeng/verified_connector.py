from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from pathlib import Path
from uuid import uuid4

from dahe.adapters.chengfeng.connector_runtime import ConnectorRuntimePort
from dahe.adapters.chengfeng.connector_staging import (
    ConnectorStagingError,
    cleanup_command_staging,
)
from dahe.adapters.chengfeng.payload_codec import (
    ConnectorPayloadError,
    decode_waybill_detail,
    decode_waybill_page,
)
from dahe.adapters.chengfeng.protocol import (
    ConnectorCommand,
    ConnectorDiagnosticClassification,
    ConnectorResult,
    ConnectorResultOutcome,
)
from dahe.adapters.chengfeng.result_verifier import (
    ResultFileVerificationError,
    VerifiedConnectorPayload,
    verify_connector_result_files,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserContextClosedError,
    BrowserNavigationAuthorizer,
    ChengfengOperation,
    ChengfengStage,
    ConnectorProtocolError,
    DetailCandidateUnavailableError,
    DownloadedTicketImage,
    ImageDownloadTimeoutError,
    LoginRequiredError,
    OperationalWaybillEvidence,
    PageContractChangedError,
    TicketImageCapabilityExpiredError,
    TransientNetworkError,
    WaybillDetail,
    WaybillPage,
    WaybillReuseCandidate,
    WaybillSummary,
)

_STAGE_BY_OPERATION = {
    ChengfengOperation.LIST_WAYBILLS: ChengfengStage.LIST_QUERY,
    ChengfengOperation.GET_WAYBILL_DETAIL: ChengfengStage.DETAIL_QUERY,
    ChengfengOperation.DOWNLOAD_TICKET_IMAGE: ChengfengStage.IMAGE_DOWNLOAD,
}


class VerifiedChengfengConnector:
    """Main-process connector client that accepts only reverified staged results."""

    def __init__(
        self,
        *,
        runtime: ConnectorRuntimePort,
        data_root: Path,
        authorizer: BrowserNavigationAuthorizer,
    ) -> None:
        self._runtime = runtime
        self._data_root = data_root.absolute()
        self._authorizer = authorizer
        self._fallback_capability_authority_id = hashlib.sha256(
            f"verified-connector:{uuid4().hex}".encode()
        ).hexdigest()

    @property
    def ticket_capability_authority_id(self) -> str:
        value = getattr(
            self._runtime,
            "ticket_capability_authority_id",
            None,
        )
        if isinstance(value, str) and value:
            return value
        return self._fallback_capability_authority_id

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool:
        probe = getattr(
            self._runtime,
            "ticket_image_capability_is_current",
            None,
        )
        if callable(probe):
            return bool(probe(ticket_ref))
        return True

    def list_waybills(
        self,
        *,
        authority: BrowserCommandAuthority,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> WaybillPage:
        payload = self._execute(
            authority=authority,
            operation=ChengfengOperation.LIST_WAYBILLS,
            parameters={
                "scope": scope,
                "page_number": page_number,
                "page_size": page_size,
            },
        )
        try:
            page = decode_waybill_page(payload.content)
        except ConnectorPayloadError as error:
            raise ConnectorProtocolError(stage=ChengfengStage.LIST_QUERY) from error
        if page.page_number != page_number or page.page_size != page_size:
            raise ConnectorProtocolError(stage=ChengfengStage.LIST_QUERY)
        return page

    def get_waybill_detail(
        self,
        *,
        authority: BrowserCommandAuthority,
        platform_waybill_id: str,
    ) -> WaybillDetail:
        payload = self._execute(
            authority=authority,
            operation=ChengfengOperation.GET_WAYBILL_DETAIL,
            parameters={"platform_waybill_id": platform_waybill_id},
        )
        try:
            detail = decode_waybill_detail(payload.content)
        except ConnectorPayloadError as error:
            raise ConnectorProtocolError(stage=ChengfengStage.DETAIL_QUERY) from error
        if detail.platform_waybill_id != platform_waybill_id:
            raise ConnectorProtocolError(stage=ChengfengStage.DETAIL_QUERY)
        return detail

    def download_ticket_image(
        self,
        *,
        authority: BrowserCommandAuthority,
        ticket_ref: str,
    ) -> DownloadedTicketImage:
        payload = self._execute(
            authority=authority,
            operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
            parameters={"ticket_ref": ticket_ref},
        )
        return DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type=payload.media_type,
            content=payload.content,
            sha256=payload.sha256,
        )

    def read_waybill_batch(
        self,
        *,
        authority: BrowserCommandAuthority,
        summaries: tuple[WaybillSummary, ...],
        detail_concurrency: int,
        image_concurrency: int,
        reuse_candidates: tuple[WaybillReuseCandidate, ...] = (),
        active_job_id: str | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> tuple[OperationalWaybillEvidence, ...]:
        """Use the live runtime batch path, with a safe sequential fallback."""

        reader = getattr(self._runtime, "read_waybill_batch", None)
        if callable(reader):
            self._authorizer.authorize(authority)
            reader_kwargs: dict[str, object] = {
                "authority": authority,
                "summaries": summaries,
                "detail_concurrency": detail_concurrency,
                "image_concurrency": image_concurrency,
            }
            if reuse_candidates:
                reader_kwargs["reuse_candidates"] = reuse_candidates
            if active_job_id is not None:
                reader_kwargs["active_job_id"] = active_job_id
            if progress_callback is not None:
                reader_kwargs["progress_callback"] = progress_callback
            evidence = reader(**reader_kwargs)
            self._authorizer.authorize(authority)
            if (
                not isinstance(evidence, tuple)
                or len(evidence) != len(summaries)
                or any(
                    not isinstance(item, OperationalWaybillEvidence)
                    for item in evidence
                )
            ):
                raise ConnectorProtocolError(
                    stage=ChengfengStage.DETAIL_QUERY
                )
            return evidence
        result: list[OperationalWaybillEvidence] = []
        for summary in summaries:
            detail = self.get_waybill_detail(
                authority=authority,
                platform_waybill_id=summary.platform_waybill_id,
            )
            images = tuple(
                self.download_ticket_image(
                    authority=authority,
                    ticket_ref=ticket.ticket_ref,
                )
                for ticket in detail.tickets
            )
            result.append(
                OperationalWaybillEvidence(
                    detail=detail,
                    images=images,
                )
            )
        return tuple(result)

    def read_waybill_whole_run(
        self,
        *,
        authority: BrowserCommandAuthority,
        summaries: tuple[WaybillSummary, ...],
        detail_concurrency: int,
        image_concurrency: int,
        active_job_id: str | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> tuple[OperationalWaybillEvidence, ...]:
        """Keep whole-run reads on the dedicated all-or-nothing runtime path."""

        reader = getattr(self._runtime, "read_waybill_whole_run", None)
        if not callable(reader):
            raise ConnectorProtocolError(
                stage=ChengfengStage.DETAIL_QUERY
            )
        self._authorizer.authorize(authority)
        reader_kwargs: dict[str, object] = {
            "authority": authority,
            "summaries": summaries,
            "detail_concurrency": detail_concurrency,
            "image_concurrency": image_concurrency,
        }
        if active_job_id is not None:
            reader_kwargs["active_job_id"] = active_job_id
        if progress_callback is not None:
            reader_kwargs["progress_callback"] = progress_callback
        evidence = reader(**reader_kwargs)
        self._authorizer.authorize(authority)
        if (
            not isinstance(evidence, tuple)
            or len(evidence) != len(summaries)
            or any(
                not isinstance(item, OperationalWaybillEvidence)
                for item in evidence
            )
        ):
            raise ConnectorProtocolError(
                stage=ChengfengStage.DETAIL_QUERY
            )
        return evidence

    def _execute(
        self,
        *,
        authority: BrowserCommandAuthority,
        operation: ChengfengOperation,
        parameters: Mapping[str, object],
    ) -> VerifiedConnectorPayload:
        command = ConnectorCommand(
            protocol_version=1,
            command_id=f"cmd-{uuid4().hex}",
            operation=operation,
            authority=authority,
            parameters=parameters,
            credential_reference=None,
        )
        stage = _STAGE_BY_OPERATION[operation]
        try:
            self._authorizer.authorize(authority)
            raw_result = self._runtime.execute(command.to_ndjson())
            try:
                result = ConnectorResult.from_ndjson(raw_result)
                result.validate_for(command)
            except (TypeError, ValueError) as error:
                raise ConnectorProtocolError(stage=stage) from error
            if result.outcome is ConnectorResultOutcome.FAILED:
                self._authorizer.authorize(authority)
                self._raise_failed_result(result)
            try:
                verified = verify_connector_result_files(
                    command=command,
                    result=result,
                    data_root=self._data_root,
                    authorizer=self._authorizer,
                )
            except (ResultFileVerificationError, TypeError, ValueError) as error:
                raise ConnectorProtocolError(stage=stage) from error
            if len(verified) != 1:
                raise ConnectorProtocolError(stage=stage)
            return verified[0]
        finally:
            try:
                cleanup_command_staging(
                    data_root=self._data_root,
                    command_id=command.command_id,
                )
            except ConnectorStagingError as error:
                raise ConnectorProtocolError(stage=stage) from error

    @staticmethod
    def _raise_failed_result(result: ConnectorResult) -> None:
        classification = result.diagnostic_classification
        if classification is ConnectorDiagnosticClassification.LOGIN_REQUIRED:
            raise LoginRequiredError(stage=result.stage)
        if classification is ConnectorDiagnosticClassification.PAGE_CONTRACT_CHANGED:
            raise PageContractChangedError(stage=result.stage)
        if classification is ConnectorDiagnosticClassification.IMAGE_TIMEOUT:
            raise ImageDownloadTimeoutError()
        if classification is ConnectorDiagnosticClassification.TRANSIENT_NETWORK:
            raise TransientNetworkError(stage=result.stage)
        if classification is ConnectorDiagnosticClassification.BROWSER_CONTEXT_CLOSED:
            raise BrowserContextClosedError(stage=result.stage)
        if (
            classification
            is ConnectorDiagnosticClassification.IMAGE_CAPABILITY_EXPIRED
        ):
            raise TicketImageCapabilityExpiredError()
        if (
            classification
            is ConnectorDiagnosticClassification.DETAIL_CANDIDATE_UNAVAILABLE
        ):
            raise DetailCandidateUnavailableError()
        raise ConnectorProtocolError(stage=result.stage)
