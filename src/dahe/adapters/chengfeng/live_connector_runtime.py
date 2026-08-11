from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import cast
from uuid import uuid4

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserReadPayload,
    BrowserRuntime,
    BrowserRuntimeError,
)
from dahe.adapters.chengfeng.connector_staging import (
    ConnectorStagingError,
    begin_command_staging,
    command_staging_directory_name,
    recover_connector_staging,
)
from dahe.adapters.chengfeng.live_manifest import (
    ImageReadCapability,
    ImageReadCapabilityPolicy,
    LiveAuthorizedImageRequest,
    LiveAuthorizedRequest,
    LiveReadContractManifest,
)
from dahe.adapters.chengfeng.live_payload import (
    LivePayloadError,
    decode_live_settled_waybill_page,
    decode_live_waybill_detail,
    decode_live_waybill_page,
)
from dahe.adapters.chengfeng.live_request_builder import (
    ChengfengLiveRequestBuilder,
    LiveRequestBuilderError,
)
from dahe.adapters.chengfeng.payload_codec import (
    encode_waybill_detail,
    encode_waybill_page,
)
from dahe.adapters.chengfeng.policy import ReadRequest, RequestDeniedError
from dahe.adapters.chengfeng.protocol import (
    ConnectorCommand,
    ConnectorDiagnosticClassification,
    ConnectorPayloadKind,
    ConnectorPayloadReference,
    ConnectorResult,
    ConnectorResultOutcome,
)
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditEvidenceStore,
    PlatformReadAuditToken,
)
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserContextClosedError,
    BrowserNavigationAuthorizer,
    ChengfengOperation,
    ChengfengReadError,
    ChengfengStage,
    DetailCandidateUnavailableError,
    DownloadedTicketImage,
    ImageDownloadTimeoutError,
    LoginRequiredError,
    OperationalBatchTimeoutError,
    OperationalWaybillEvidence,
    PageContractChangedError,
    TicketImageCapabilityExpiredError,
    TransientNetworkError,
    WaybillReuseCandidate,
    WaybillSummary,
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
    TicketImageCapabilityExpiredError: (
        ConnectorDiagnosticClassification.IMAGE_CAPABILITY_EXPIRED
    ),
    DetailCandidateUnavailableError: (
        ConnectorDiagnosticClassification.DETAIL_CANDIDATE_UNAVAILABLE
    ),
}
_SUFFIX_BY_MEDIA_TYPE = {
    "application/json": ".json",
    "image/bmp": ".bmp",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tiff",
    "image/webp": ".webp",
}
_UUID_DIGIT_TO_LETTER = str.maketrans(
    "0123456789",
    "ghijklmnop",
)
_LIST_BODY_DIAGNOSTIC_BY_BROWSER_ERROR = {
    "browser_session_list_body_mismatch": (
        "CF-BROWSER-SESSION-LIST-BODY-MISMATCH"
    ),
    "browser_session_list_body_field_set_mismatch": (
        "CF-BROWSER-SESSION-LIST-BODY-FIELD-SET-MISMATCH"
    ),
    "browser_session_list_body_fields_added": (
        "CF-BROWSER-SESSION-LIST-BODY-FIELDS-ADDED"
    ),
    "browser_session_list_body_fields_removed": (
        "CF-BROWSER-SESSION-LIST-BODY-FIELDS-REMOVED"
    ),
    "browser_session_list_body_fields_changed": (
        "CF-BROWSER-SESSION-LIST-BODY-FIELDS-CHANGED"
    ),
    "browser_session_list_body_filter_mismatch": (
        "CF-BROWSER-SESSION-LIST-BODY-FILTER-MISMATCH"
    ),
    "browser_session_list_body_hash_mismatch": (
        "CF-BROWSER-SESSION-LIST-BODY-HASH-MISMATCH"
    ),
}
_PRE_NETWORK_DENIAL_BROWSER_ERRORS = frozenset(
    {
        "browser_image_not_registered",
        "browser_image_origin_denied",
    }
)
_DETAIL_DIAGNOSTIC_BY_BROWSER_ERROR = {
    "browser_detail_data_null_success": (
        "CF-BROWSER-DETAIL-DATA-NULL-SUCCESS"
    ),
    "browser_detail_data_null_auth": (
        "CF-BROWSER-DETAIL-DATA-NULL-AUTH"
    ),
    "browser_detail_data_null_failure": (
        "CF-BROWSER-DETAIL-DATA-NULL-FAILURE"
    ),
    "browser_detail_data_null_missing": (
        "CF-BROWSER-DETAIL-DATA-NULL-MISSING"
    ),
    "browser_detail_data_object": "CF-BROWSER-DETAIL-DATA-OBJECT",
    "browser_detail_data_string": "CF-BROWSER-DETAIL-DATA-STRING",
    "browser_detail_data_integer": "CF-BROWSER-DETAIL-DATA-INTEGER",
    "browser_detail_data_unsupported": (
        "CF-BROWSER-DETAIL-DATA-UNSUPPORTED"
    ),
    "browser_detail_cardinality_changed": (
        "CF-BROWSER-DETAIL-CARDINALITY-CHANGED"
    ),
    "browser_detail_item_contract_changed": (
        "CF-BROWSER-DETAIL-ITEM-CONTRACT-CHANGED"
    ),
    "browser_detail_identity_mismatch": (
        "CF-BROWSER-DETAIL-IDENTITY-MISMATCH"
    ),
}


def _opaque_ticket_reference() -> str:
    """Return a UUID-strength capability that cannot resemble a phone number."""

    return f"ticket-{uuid4().hex.translate(_UUID_DIGIT_TO_LETTER)}"


@dataclass(frozen=True, slots=True)
class _TicketGrant:
    capability: ImageReadCapability
    authority_id: str
    image_url: str = field(repr=False)


@dataclass(slots=True)
class _RequestAuditLifecycle:
    store: PlatformReadAuditEvidenceStore
    token: PlatformReadAuditToken
    phase: str = "attempted"

    def allowed(self) -> None:
        self.store.allowed(self.token)
        self.phase = "allowed"

    def succeeded(self) -> None:
        self.store.succeeded(self.token)
        self.phase = "succeeded"

    def denied_if_not_sent(self) -> None:
        if self.phase == "attempted":
            self.store.denied(self.token)
            self.phase = "denied"

    def failed_if_sent(self) -> None:
        if self.phase == "allowed":
            self.store.failed(self.token)
            self.phase = "failed"

    def redirected_if_sent(self) -> None:
        if self.phase == "allowed":
            self.store.redirected(self.token)
            self.phase = "redirect"


@dataclass(frozen=True, slots=True)
class _AuditEnvelope:
    job_id: str
    operation: str


class LiveConnectorRuntime:
    """Run frozen live reads inside the existing verified connector boundary."""

    def __init__(
        self,
        *,
        browser: BrowserRuntime,
        manifest: LiveReadContractManifest,
        data_root: Path,
        authorizer: BrowserNavigationAuthorizer,
        build_sha256: str,
        contract_selection_sha256: str,
        clock: Callable[[], datetime],
        runtime_log_store: RuntimeLogStore | None = None,
        request_audit_store: PlatformReadAuditEvidenceStore | None = None,
    ) -> None:
        self._browser = browser
        self._manifest = manifest
        self._data_root = data_root.resolve()
        self._authorizer = authorizer
        self._build_sha256 = build_sha256
        self._contract_selection_sha256 = contract_selection_sha256
        self._clock = clock
        self._runtime_log_store = runtime_log_store
        self._builder = ChengfengLiveRequestBuilder(manifest)
        self._image_policy = ImageReadCapabilityPolicy(
            allowed_origins=manifest.image_origins,
            maximum_lifetime=timedelta(minutes=5),
        )
        self._ticket_grants: dict[str, _TicketGrant] = {}
        self._ticket_lock = RLock()
        self._connector_generation_id = uuid4().hex
        self._browser_fallback_generation_id = uuid4().hex
        self._request_audit = (
            request_audit_store
            if request_audit_store is not None
            else PlatformReadAuditEvidenceStore(
                self._data_root,
                clock=clock,
            )
        )
        recover_connector_staging(self._data_root)

    @property
    def ticket_capability_authority_id(self) -> str:
        browser_generation = getattr(
            self._browser,
            "capability_generation_id",
            None,
        )
        if not isinstance(browser_generation, str):
            browser_generation = self._browser_fallback_generation_id
        return hashlib.sha256(
            (
                f"{self._connector_generation_id}:"
                f"{browser_generation}"
            ).encode()
        ).hexdigest()

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool:
        if not isinstance(ticket_ref, str) or not ticket_ref:
            return False
        now = self._clock()
        authority_id = self.ticket_capability_authority_id
        with self._ticket_lock:
            self._prune_ticket_grants(now=now)
            grant = self._ticket_grants.get(ticket_ref)
            return (
                grant is not None
                and grant.authority_id == authority_id
                and grant.capability.expires_at
                > now + timedelta(seconds=5)
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
        """Run the non-formal operational batch without exporting private URLs."""

        if not summaries or len(summaries) > 100:
            raise ValueError("operational batch size is invalid")
        detail_audits = tuple(
            _RequestAuditLifecycle(
                store=self._request_audit,
                token=self._request_audit.attempt(
                    job_id=authority.job_id,
                    build_sha256=self._build_sha256,
                    contract_sha256=self._manifest.canonical_sha256,
                    contract_selection_sha256=(
                        self._contract_selection_sha256
                    ),
                    operation="get_waybill_detail",
                ),
            )
            for _summary in summaries
        )
        try:
            self._authorizer.authorize(authority)
        except Exception:
            for audit in detail_audits:
                audit.denied_if_not_sent()
            raise
        try:
            requests = tuple(
                (
                    summary.platform_waybill_id,
                    self._builder.get_waybill_detail(
                        platform_waybill_id=summary.platform_waybill_id
                    ),
                )
                for summary in summaries
            )
        except Exception:
            for audit in detail_audits:
                audit.denied_if_not_sent()
            raise
        for audit in detail_audits:
            audit.allowed()
        try:
            if reuse_candidates:
                browser_items = self._browser.read_operational_batch(
                    requests,
                    detail_concurrency=detail_concurrency,
                    image_concurrency=image_concurrency,
                    reuse_candidates=reuse_candidates,
                    active_job_id=active_job_id,
                    progress_callback=progress_callback,
                )
            else:
                browser_items = self._browser.read_operational_batch(
                    requests,
                    detail_concurrency=detail_concurrency,
                    image_concurrency=image_concurrency,
                    active_job_id=active_job_id,
                    progress_callback=progress_callback,
                )
        except BrowserRuntimeError as error:
            for audit in detail_audits:
                if error.code == "browser_read_redirect_rejected":
                    audit.redirected_if_sent()
                else:
                    audit.failed_if_sent()
            self._raise_operational_batch_error(error)
            raise AssertionError("unreachable") from error
        try:
            self._authorizer.authorize(authority)
        except Exception:
            for audit in detail_audits:
                audit.failed_if_sent()
            raise
        evidence: list[OperationalWaybillEvidence] = []
        try:
            for summary, browser_item, detail_audit in zip(
                summaries,
                browser_items,
                detail_audits,
                strict=True,
            ):
                if (
                    browser_item.platform_waybill_id
                    != summary.platform_waybill_id
                ):
                    raise PageContractChangedError(
                        stage=ChengfengStage.DETAIL_QUERY
                    )
                payload_by_slot = dict(browser_item.images)
                images: list[DownloadedTicketImage] = []

                def ticket_reference(
                    slot: str,
                    marker: str,
                    *,
                    _payload_by_slot: dict[
                        str, BrowserReadPayload
                    ] = payload_by_slot,
                    _images: list[DownloadedTicketImage] = images,
                ) -> str:
                    if (
                        marker != f"worker-image:{slot}"
                        or slot not in _payload_by_slot
                    ):
                        raise LivePayloadError(
                            "batch_image_marker_invalid",
                            "operational batch image marker is invalid",
                        )
                    payload = _payload_by_slot[slot]
                    ticket_ref = _opaque_ticket_reference()
                    _images.append(
                        DownloadedTicketImage(
                            ticket_ref=ticket_ref,
                            media_type=payload.media_type,
                            content=payload.content,
                            sha256=payload.sha256,
                            validator_sha256=(
                                payload.validator_sha256
                            ),
                            reused_from_cache=(
                                payload.reused_from_cache
                            ),
                        )
                    )
                    return ticket_ref

                try:
                    detail = decode_live_waybill_detail(
                        browser_item.detail.content,
                        expected_platform_waybill_id=(
                            summary.platform_waybill_id
                        ),
                        ticket_reference=ticket_reference,
                    )
                except LivePayloadError as error:
                    raise PageContractChangedError(
                        stage=ChengfengStage.DETAIL_QUERY
                    ) from error
                if (
                    detail.waybill_number != summary.waybill_number
                    or set(payload_by_slot)
                    != {ticket.slot for ticket in detail.tickets}
                    or len(images) != len(detail.tickets)
                ):
                    raise PageContractChangedError(
                        stage=ChengfengStage.DETAIL_QUERY
                    )
                detail_audit.succeeded()
                for _image in images:
                    # The isolated worker already enforced the frozen image
                    # origin and GET-only policy before returning this opaque
                    # payload. Record each completed image read without
                    # exporting its private signed URL to the main process.
                    image_audit = _RequestAuditLifecycle(
                        store=self._request_audit,
                        token=self._request_audit.attempt(
                            job_id=authority.job_id,
                            build_sha256=self._build_sha256,
                            contract_sha256=(
                                self._manifest.canonical_sha256
                            ),
                            contract_selection_sha256=(
                                self._contract_selection_sha256
                            ),
                            operation="download_ticket_image",
                        ),
                    )
                    image_audit.allowed()
                    image_audit.succeeded()
                evidence.append(
                    OperationalWaybillEvidence(
                        detail=detail,
                        images=tuple(images),
                        source_revision_sha256=(
                            browser_item.source_revision_sha256
                        ),
                    )
                )
        except Exception:
            for audit in detail_audits:
                audit.failed_if_sent()
            raise
        return tuple(evidence)

    @staticmethod
    def _raise_operational_batch_error(error: BrowserRuntimeError) -> None:
        if error.code == "browser_detail_data_null_failure":
            raise DetailCandidateUnavailableError() from error
        if error.code in {
            "browser_read_login_required",
            "browser_detail_data_null_auth",
            "browser_saved_credential_missing",
            "browser_saved_login_captcha_required",
            "browser_saved_login_failed",
            "browser_saved_login_structure_changed",
        }:
            raise LoginRequiredError(
                stage=ChengfengStage.DETAIL_QUERY
            ) from error
        if error.code in {
            "browser_context_closed",
            "browser_worker_unavailable",
        }:
            raise BrowserContextClosedError(
                stage=ChengfengStage.DETAIL_QUERY
            ) from error
        if error.code == "browser_worker_timeout":
            raise OperationalBatchTimeoutError() from error
        if error.code in {
            "browser_read_network_failed",
            "browser_read_http_failed",
            "browser_read_rate_limited",
            "browser_read_server_transient",
        }:
            raise TransientNetworkError(
                stage=ChengfengStage.DETAIL_QUERY
            ) from error
        if error.code in _DETAIL_DIAGNOSTIC_BY_BROWSER_ERROR:
            raise PageContractChangedError(
                stage=ChengfengStage.DETAIL_QUERY,
                diagnostic_code=_DETAIL_DIAGNOSTIC_BY_BROWSER_ERROR[
                    error.code
                ],
            ) from error
        raise PageContractChangedError(
            stage=ChengfengStage.DETAIL_QUERY
        ) from error

    def execute(self, command_ndjson: str | bytes) -> str:
        envelope = _extract_audit_envelope(command_ndjson)
        audit = _RequestAuditLifecycle(
            store=self._request_audit,
            token=self._request_audit.attempt(
                job_id=envelope.job_id,
                build_sha256=self._build_sha256,
                contract_sha256=self._manifest.canonical_sha256,
                contract_selection_sha256=(
                    self._contract_selection_sha256
                ),
                operation=envelope.operation,
            ),
        )
        try:
            command = ConnectorCommand.from_ndjson(command_ndjson)
        except (TypeError, ValueError):
            audit.denied_if_not_sent()
            raise
        stage = _STAGE_BY_OPERATION[command.operation]
        if command.credential_reference is not None:
            audit.denied_if_not_sent()
            return self._failure(
                command,
                stage=stage,
                classification=ConnectorDiagnosticClassification.PROTOCOL_ERROR,
            ).to_ndjson()
        try:
            self._authorizer.authorize(command.authority)
            kind, media_type, content = self._perform_read(
                command,
                audit=audit,
            )
            self._authorizer.authorize(command.authority)
            reference = self._stage_payload(
                command=command,
                kind=kind,
                media_type=media_type,
                content=content,
            )
        except ChengfengReadError as error:
            audit.denied_if_not_sent()
            classification = _DIAGNOSTIC_BY_ERROR.get(
                type(error),
                ConnectorDiagnosticClassification.PROTOCOL_ERROR,
            )
            self._record_safe_failure(
                stage=stage,
                event_code="read_platform_failure",
                reason_code=error.diagnostic_code.casefold().replace("-", "_"),
                diagnostic_code=error.diagnostic_code,
            )
            return self._failure(
                command,
                stage=stage,
                classification=classification,
            ).to_ndjson()
        except LivePayloadError as error:
            audit.denied_if_not_sent()
            self._record_safe_failure(
                stage=stage,
                event_code="read_response_contract_changed",
                reason_code=error.code,
                diagnostic_code=(
                    f"CF-LIVE-PAYLOAD-{error.code.upper().replace('_', '-')}"
                ),
            )
            return self._failure(
                command,
                stage=stage,
                classification=(
                    ConnectorDiagnosticClassification.PAGE_CONTRACT_CHANGED
                ),
            ).to_ndjson()
        except (
            ConnectorStagingError,
            KeyError,
            LiveRequestBuilderError,
            OSError,
            RequestDeniedError,
            TypeError,
            ValueError,
        ) as error:
            audit.denied_if_not_sent()
            reason_code = type(error).__name__.removesuffix("Error").casefold()
            self._record_safe_failure(
                stage=stage,
                event_code="read_local_protocol_failure",
                reason_code=reason_code,
                diagnostic_code="CF-LIVE-LOCAL-PROTOCOL",
            )
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

    def _record_safe_failure(
        self,
        *,
        stage: ChengfengStage,
        event_code: str,
        reason_code: str,
        diagnostic_code: str,
    ) -> None:
        if self._runtime_log_store is None:
            return
        self._runtime_log_store.append(
            level="warning",
            source="chengfeng-connector",
            event_code=event_code,
            stream="application",
            message=(
                f"Frozen Chengfeng read failed safely at {stage.value} "
                f"({reason_code})."
            ),
            diagnostic_code=diagnostic_code,
        )

    def _record_safe_list_structure(
        self,
        *,
        error: BrowserRuntimeError,
    ) -> None:
        if self._runtime_log_store is None or len(error.safe_discovery) != 1:
            return
        fields = error.safe_discovery[0].get("request_fields")
        if not isinstance(fields, list):
            return
        paths = tuple(
            str(field.get("path"))
            for field in fields
            if isinstance(field, dict) and isinstance(field.get("path"), str)
        )
        if len(paths) != len(fields) or not paths:
            return
        body: dict[str, object] = {
            "schema_version": 1,
            "kind": "chengfeng_reset_list_structure_diagnostic",
            "classification": "development_only",
            "created_at": self._clock().isoformat(),
            "parent_contract_canonical_sha256": (
                self._manifest.canonical_sha256
            ),
            "observation": error.safe_discovery[0],
            "platform_write_authorization": False,
            "request_values_retained": False,
            "response_values_retained": False,
            "credential_material_retained": False,
        }
        canonical_body = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        canonical_sha256 = hashlib.sha256(canonical_body).hexdigest()
        document = {
            **body,
            "canonical_sha256": canonical_sha256,
        }
        content = (
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        diagnostic_root = (
            self._data_root / "platform-contract-diagnostics"
        )
        diagnostic_path = diagnostic_root / f"{canonical_sha256}.json"
        try:
            diagnostic_root.mkdir(parents=True, exist_ok=True)
            if diagnostic_root.is_symlink():
                raise OSError("diagnostic root is a symbolic link")
            if diagnostic_path.exists():
                if (
                    diagnostic_path.is_symlink()
                    or diagnostic_path.read_bytes() != content
                ):
                    raise OSError("diagnostic evidence identity changed")
            else:
                temporary = (
                    diagnostic_root
                    / f".{canonical_sha256}.{uuid4().hex}.tmp"
                )
                try:
                    with temporary.open("xb") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, diagnostic_path)
                finally:
                    temporary.unlink(missing_ok=True)
        except OSError:
            self._runtime_log_store.append(
                level="error",
                source="chengfeng-connector",
                event_code="read_request_structure_evidence_failed",
                stream="application",
                message=(
                    "Changed Chengfeng request structure could not be "
                    "sealed."
                ),
                diagnostic_code=(
                    "CF-CONTRACT-REQUEST-STRUCTURE-EVIDENCE-FAILED"
                ),
            )
            return
        self._runtime_log_store.append(
            level="warning",
            source="chengfeng-connector",
            event_code="read_request_structure_changed",
            stream="application",
            message=(
                "Current locally reset Chengfeng list field paths: "
                f"{','.join(paths)}. Structure evidence "
                f"{canonical_sha256}."
            ),
            diagnostic_code=_LIST_BODY_DIAGNOSTIC_BY_BROWSER_ERROR.get(
                error.code,
                "CF-BROWSER-SESSION-LIST-BODY-MISMATCH",
            ),
        )

    def _perform_read(
        self,
        command: ConnectorCommand,
        *,
        audit: _RequestAuditLifecycle,
    ) -> tuple[ConnectorPayloadKind, str, bytes]:
        if command.operation is ChengfengOperation.LIST_WAYBILLS:
            scope = cast(str, command.parameters["scope"])
            page_number = cast(int, command.parameters["page_number"])
            page_size = cast(int, command.parameters["page_size"])
            authorized = self._builder.list_waybills(
                scope=scope,
                page_number=page_number,
                page_size=page_size,
            )
            payload = self._read_browser(
                authorized,
                stage=ChengfengStage.LIST_QUERY,
                audit=audit,
            )
            if scope == "settled_history":
                page = decode_live_settled_waybill_page(
                    payload.content,
                    expected_page_number=page_number,
                    maximum_page_size=page_size,
                )
            else:
                page = decode_live_waybill_page(
                    payload.content,
                    expected_page_number=page_number,
                    maximum_page_size=page_size,
                )
            return (
                ConnectorPayloadKind.WAYBILL_PAGE,
                "application/json",
                encode_waybill_page(page),
            )
        if command.operation is ChengfengOperation.GET_WAYBILL_DETAIL:
            platform_id = cast(str, command.parameters["platform_waybill_id"])
            authorized = self._builder.get_waybill_detail(
                platform_waybill_id=platform_id
            )
            payload = self._read_browser(
                authorized,
                stage=ChengfengStage.DETAIL_QUERY,
                audit=audit,
            )
            pending: dict[str, _TicketGrant] = {}
            issued_at = self._clock()
            capability_authority_id = (
                self.ticket_capability_authority_id
            )

            def ticket_reference(slot: str, image_url: str) -> str:
                ticket_ref = _opaque_ticket_reference()
                capability = self._image_policy.issue(
                    source_request=authorized,
                    image_url=image_url,
                    validated_response_sha256=payload.sha256,
                    issued_at=issued_at,
                    lifetime=timedelta(minutes=5),
                )
                pending[ticket_ref] = _TicketGrant(
                    capability=capability,
                    authority_id=capability_authority_id,
                    image_url=image_url,
                )
                return ticket_ref

            detail = decode_live_waybill_detail(
                payload.content,
                expected_platform_waybill_id=platform_id,
                ticket_reference=ticket_reference,
            )
            self._authorizer.authorize(command.authority)
            with self._ticket_lock:
                self._prune_ticket_grants(now=issued_at)
                if set(pending) & set(self._ticket_grants):
                    raise ValueError("opaque ticket reference collision")
                self._ticket_grants.update(pending)
            return (
                ConnectorPayloadKind.WAYBILL_DETAIL,
                "application/json",
                encode_waybill_detail(detail),
            )
        ticket_ref = cast(str, command.parameters["ticket_ref"])
        now = self._clock()
        with self._ticket_lock:
            self._prune_ticket_grants(now=now)
            grant = self._ticket_grants.get(ticket_ref)
        if grant is None:
            raise TicketImageCapabilityExpiredError()
        if grant.authority_id != self.ticket_capability_authority_id:
            raise TicketImageCapabilityExpiredError()
        authorized_image = self._image_policy.authorize(
            capability=grant.capability,
            request=ReadRequest(
                operation="download_ticket_image",
                method="GET",
                url=grant.image_url,
                parameters_location="query",
                parameters={},
            ),
            now=now,
        )
        payload = self._read_browser(
            authorized_image,
            stage=ChengfengStage.IMAGE_DOWNLOAD,
            audit=audit,
        )
        if not payload.media_type.startswith("image/"):
            raise PageContractChangedError(stage=ChengfengStage.IMAGE_DOWNLOAD)
        return (
            ConnectorPayloadKind.TICKET_IMAGE,
            payload.media_type,
            payload.content,
        )

    def _read_browser(
        self,
        request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
        *,
        stage: ChengfengStage,
        audit: _RequestAuditLifecycle,
    ) -> BrowserReadPayload:
        try:
            payload = self._browser.read(request)
        except BrowserRuntimeError as error:
            if error.code == "browser_detail_data_null_failure":
                audit.allowed()
                audit.succeeded()
                raise DetailCandidateUnavailableError() from error
            if error.code in _PRE_NETWORK_DENIAL_BROWSER_ERRORS:
                audit.denied_if_not_sent()
            elif error.code == "browser_read_redirect_rejected":
                audit.allowed()
                audit.redirected_if_sent()
            else:
                audit.allowed()
                audit.failed_if_sent()
            if error.code == "browser_read_login_required":
                raise LoginRequiredError(stage=stage) from error
            if error.code in {
                "browser_context_closed",
                "browser_worker_unavailable",
            }:
                raise BrowserContextClosedError(stage=stage) from error
            if error.code == "browser_worker_timeout" and stage is ChengfengStage.IMAGE_DOWNLOAD:
                raise ImageDownloadTimeoutError() from error
            if error.code in {
                "browser_read_network_failed",
                "browser_read_http_failed",
                "browser_worker_timeout",
            }:
                raise TransientNetworkError(stage=stage) from error
            if error.code in {
                "browser_image_contract_changed",
                "browser_image_origin_denied",
                "browser_image_not_registered",
                "browser_read_redirect_rejected",
                "browser_read_contract_changed",
                "browser_read_size_invalid",
            }:
                raise PageContractChangedError(stage=stage) from error
            if error.code in _DETAIL_DIAGNOSTIC_BY_BROWSER_ERROR:
                raise PageContractChangedError(
                    stage=stage,
                    diagnostic_code=_DETAIL_DIAGNOSTIC_BY_BROWSER_ERROR[
                        error.code
                    ],
                ) from error
            if error.code in _LIST_BODY_DIAGNOSTIC_BY_BROWSER_ERROR:
                self._record_safe_list_structure(error=error)
                raise PageContractChangedError(
                    stage=stage,
                    diagnostic_code=_LIST_BODY_DIAGNOSTIC_BY_BROWSER_ERROR[
                        error.code
                    ],
                    safe_discovery=error.safe_discovery,
                ) from error
            raise BrowserContextClosedError(stage=stage) from error
        except Exception:
            audit.allowed()
            audit.failed_if_sent()
            raise
        audit.allowed()
        audit.succeeded()
        return payload

    def _prune_ticket_grants(self, *, now: datetime) -> None:
        expired = tuple(
            ticket_ref
            for ticket_ref, grant in self._ticket_grants.items()
            if grant.capability.expires_at <= now
        )
        for ticket_ref in expired:
            del self._ticket_grants[ticket_ref]

    def _stage_payload(
        self,
        *,
        command: ConnectorCommand,
        kind: ConnectorPayloadKind,
        media_type: str,
        content: bytes,
    ) -> ConnectorPayloadReference:
        suffix = _SUFFIX_BY_MEDIA_TYPE.get(media_type)
        if suffix is None or not content:
            raise ValueError("live connector payload type is invalid")
        command_directory = command_staging_directory_name(command.command_id)
        relative_directory = Path("connector-staging") / command_directory
        directory = begin_command_staging(
            data_root=self._data_root,
            command_id=command.command_id,
        )
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


def _extract_audit_envelope(
    command_ndjson: str | bytes,
) -> _AuditEnvelope:
    if isinstance(command_ndjson, bytes):
        text = command_ndjson.decode("utf-8", errors="strict")
    elif isinstance(command_ndjson, str):
        text = command_ndjson
    else:
        raise TypeError("connector command must be text or bytes")
    if not text or len(text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("connector command size is invalid")
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ValueError("connector command must contain one record")
    payload = json.loads(lines[0])
    if not isinstance(payload, dict):
        raise TypeError("connector command must be a JSON object")
    operation = payload.get("operation")
    authority = payload.get("authority")
    if (
        not isinstance(operation, str)
        or not operation
        or len(operation) > 200
        or not isinstance(authority, dict)
        or not isinstance(authority.get("job_id"), str)
    ):
        raise ValueError("connector command audit envelope is invalid")
    return _AuditEnvelope(
        job_id=cast(str, authority["job_id"]),
        operation=operation,
    )
