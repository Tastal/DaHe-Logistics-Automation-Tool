from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import NoReturn

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeError,
)
from dahe.adapters.chengfeng.daily_contract_selection import (
    SelectedDailyReadContract,
)
from dahe.adapters.chengfeng.daily_manifest import DailyReadContractManifest
from dahe.adapters.chengfeng.daily_payload import (
    DailyPayloadError,
    decode_daily_waybill_page,
)
from dahe.adapters.chengfeng.daily_request_builder import (
    ChengfengDailyRequestBuilder,
    DailyRequestBuilderError,
)
from dahe.adapters.chengfeng.live_contract_validation import (
    DailyContractValidationCandidatePage,
)
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
    EvidenceIntegrityError,
)
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditEvidenceStore,
    PlatformReadAuditToken,
)
from dahe.domain.daily.calendar import (
    CandidateQueryWindow,
    candidate_query_window,
    latest_completed_business_date,
)
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyObservationFields,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserContextClosedError,
    BrowserNavigationAuthorizer,
    ChengfengReadPort,
    ChengfengStage,
    ConnectorProtocolError,
    LoginRequiredError,
    PageContractChangedError,
    TransientNetworkError,
)
from dahe.ports.daily import (
    DailyDetailCaptureContractError,
    DailyDetailCaptureState,
    DailyDetailCaptureStep,
    DailyDetailEvidence,
    DailyDetailEvidencePort,
    DailyPlatformReadPort,
    DailyTicketSlotCapture,
    DailyWaybillPage,
)


@dataclass(slots=True)
class _DailyRequestAudit:
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


class ChengfengDailyListAdapter(DailyPlatformReadPort):
    """Read one frozen daily-list page without retaining the raw response."""

    def __init__(
        self,
        *,
        browser: BrowserRuntime,
        manifest: DailyReadContractManifest,
        authority: BrowserCommandAuthority,
        authorizer: BrowserNavigationAuthorizer,
        request_audit_store: PlatformReadAuditEvidenceStore | None = None,
        build_sha256: str | None = None,
        contract_selection_sha256: str | None = None,
    ) -> None:
        if (
            request_audit_store is None
            or build_sha256 is None
            or contract_selection_sha256 is None
        ) and any(
            value is not None
            for value in (
                request_audit_store,
                build_sha256,
                contract_selection_sha256,
            )
        ):
            raise ValueError("daily request audit configuration is incomplete")
        self._browser = browser
        self._builder = ChengfengDailyRequestBuilder(manifest)
        self._manifest = manifest
        self._authority = authority
        self._authorizer = authorizer
        self._request_audit_store = request_audit_store
        self._build_sha256 = build_sha256
        self._contract_selection_sha256 = contract_selection_sha256

    def list_waybills(
        self,
        *,
        query_window: CandidateQueryWindow,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyWaybillPage:
        audit = self._start_request_audit()
        try:
            request = self._builder.list_waybills(
                query_window=query_window,
                receive_place=receive_place,
                page_number=page_number,
                page_size=page_size,
            )
            self._authorizer.authorize(self._authority)
            if audit is not None:
                audit.allowed()
            payload = self._browser.read_daily(request)
            if audit is not None:
                audit.succeeded()
            self._authorizer.authorize(self._authority)
            return decode_daily_waybill_page(
                payload.content,
                expected_page_number=page_number,
                requested_page_size=page_size,
            )
        except BrowserRuntimeError as exc:
            if audit is not None:
                if exc.code == "browser_read_redirect_rejected":
                    audit.redirected_if_sent()
                else:
                    audit.failed_if_sent()
            self._raise_browser_failure(exc)
        except DailyPayloadError as exc:
            raise PageContractChangedError(
                stage=ChengfengStage.LIST_QUERY,
                diagnostic_code=(
                    "CF-DAILY-PAYLOAD-"
                    f"{exc.code.upper().replace('_', '-')}"
                ),
            ) from exc
        except DailyRequestBuilderError as exc:
            if audit is not None:
                audit.denied_if_not_sent()
            raise ConnectorProtocolError(
                stage=ChengfengStage.LIST_QUERY
            ) from exc
        except Exception:
            if audit is not None:
                audit.denied_if_not_sent()
                audit.failed_if_sent()
            raise

    def _start_request_audit(self) -> _DailyRequestAudit | None:
        if (
            self._request_audit_store is None
            or self._build_sha256 is None
            or self._contract_selection_sha256 is None
        ):
            return None
        return _DailyRequestAudit(
            store=self._request_audit_store,
            token=self._request_audit_store.attempt(
                job_id=self._authority.job_id,
                build_sha256=self._build_sha256,
                contract_sha256=self._manifest.canonical_sha256,
                contract_selection_sha256=(
                    self._contract_selection_sha256
                ),
                operation="list_daily_waybills",
            ),
        )

    @staticmethod
    def _raise_browser_failure(error: BrowserRuntimeError) -> NoReturn:
        if error.code in {
            "browser_read_login_required",
            "browser_daily_prepare_required",
        }:
            raise LoginRequiredError(stage=ChengfengStage.LIST_QUERY) from error
        if error.code in {
            "browser_context_closed",
            "browser_worker_unavailable",
        }:
            raise BrowserContextClosedError(
                stage=ChengfengStage.LIST_QUERY
            ) from error
        if error.code in {
            "browser_worker_timeout",
            "browser_read_network_failed",
            "browser_read_http_failed",
        }:
            raise TransientNetworkError(
                stage=ChengfengStage.LIST_QUERY
            ) from error
        if error.code in {
            "browser_daily_response_contract_changed",
            "browser_daily_scope_not_applied",
            "browser_daily_scope_items_invalid",
            "browser_daily_scope_request_invalid",
            "browser_daily_scope_request_time_invalid",
            "browser_daily_scope_range_invalid",
            "browser_daily_scope_item_invalid",
            "browser_daily_scope_loading_time_type_invalid",
            "browser_daily_scope_loading_time_format_changed",
            "browser_daily_request_contract_changed",
            "browser_daily_request_fields_changed",
            "browser_daily_filter_contract_changed",
            "browser_daily_business_parameters_invalid",
            "browser_daily_probe_cache_unavailable",
            "browser_daily_probe_fields_mismatch",
            "browser_daily_probe_start_mismatch",
            "browser_daily_probe_end_mismatch",
            "browser_daily_probe_source_place_mismatch",
            "browser_daily_probe_requested_place_mismatch",
            "browser_daily_probe_pagination_mismatch",
            "browser_daily_probe_baseline_mismatch",
            "browser_read_contract_changed",
            "browser_read_redirect_rejected",
            "browser_read_size_invalid",
            "browser_read_staging_failed",
        }:
            raise PageContractChangedError(
                stage=ChengfengStage.LIST_QUERY,
                diagnostic_code=(
                    "CF-DAILY-CONTRACT-"
                    f"{error.code.upper().replace('_', '-')}"
                ),
                safe_discovery=error.safe_discovery,
            ) from error
        raise BrowserContextClosedError(
            stage=ChengfengStage.LIST_QUERY
        ) from error


class ChengfengDailyContractValidationSource:
    """Read one nonempty daily candidate page after an automated transition."""

    def __init__(
        self,
        *,
        browser: BrowserRuntime,
        selected: SelectedDailyReadContract,
        authorizer: BrowserNavigationAuthorizer,
        clock: Callable[[], datetime],
        request_audit_store: PlatformReadAuditEvidenceStore | None = None,
        build_sha256: str | None = None,
    ) -> None:
        if (request_audit_store is None) != (build_sha256 is None):
            raise ValueError(
                "daily validation request audit configuration is incomplete"
            )
        self._browser = browser
        self._selected = selected
        self._authorizer = authorizer
        self._clock = clock
        self._request_audit_store = request_audit_store
        self._build_sha256 = build_sha256

    @property
    def selected(self) -> SelectedDailyReadContract:
        return self._selected

    def prepare_and_list(
        self,
        *,
        authority: BrowserCommandAuthority,
    ) -> DailyContractValidationCandidatePage:
        prepare_audit: _DailyRequestAudit | None = None
        if (
            self._request_audit_store is not None
            and self._build_sha256 is not None
        ):
            prepare_audit = _DailyRequestAudit(
                store=self._request_audit_store,
                token=self._request_audit_store.attempt(
                    job_id=authority.job_id,
                    build_sha256=self._build_sha256,
                    contract_sha256=(
                        self._selected.manifest.canonical_sha256
                    ),
                    contract_selection_sha256=(
                        self._selected.selection_sha256
                    ),
                    operation="list_daily_waybills",
                ),
            )
        try:
            self._authorizer.authorize(authority)
            if prepare_audit is not None:
                prepare_audit.allowed()
            observation = self._browser.prepare_daily_from_automated()
            if prepare_audit is not None:
                prepare_audit.succeeded()
            self._authorizer.authorize(authority)
        except Exception:
            if prepare_audit is not None:
                prepare_audit.denied_if_not_sent()
                prepare_audit.failed_if_sent()
            raise
        if not _observation_matches_selection(
            observation,
            self._selected,
        ):
            raise PageContractChangedError(
                stage=ChengfengStage.LIST_QUERY,
                diagnostic_code=(
                    "CF-DAILY-AUTOMATED-PREPARE-CONTRACT-CHANGED"
                ),
            )
        now = self._clock()
        latest_business_date = latest_completed_business_date(now)
        cached_adapter = ChengfengDailyListAdapter(
            browser=self._browser,
            manifest=self._selected.manifest,
            authority=authority,
            authorizer=self._authorizer,
        )
        fallback_adapter = ChengfengDailyListAdapter(
            browser=self._browser,
            manifest=self._selected.manifest,
            authority=authority,
            authorizer=self._authorizer,
            request_audit_store=self._request_audit_store,
            build_sha256=self._build_sha256,
            contract_selection_sha256=(
                None
                if self._request_audit_store is None
                else self._selected.selection_sha256
            ),
        )
        page: DailyWaybillPage | None = None
        read_attempt_count = 0
        business_date = latest_business_date
        query_window = candidate_query_window(business_date, now=now)
        for days_back in range(7):
            business_date = latest_business_date - timedelta(days=days_back)
            query_window = candidate_query_window(
                business_date,
                now=now,
            )
            adapter = (
                cached_adapter
                if days_back == 0
                else fallback_adapter
            )
            page = adapter.list_waybills(
                query_window=query_window,
                receive_place="榆林",
                page_number=1,
                page_size=5,
            )
            read_attempt_count += 1
            if page.items:
                break
        if page is None:
            raise RuntimeError("daily validation did not execute")
        query_scope = {
            "business_date": business_date.isoformat(),
            "start": query_window.start.isoformat(),
            "end": query_window.end.isoformat(),
            "safety_end": query_window.safety_end.isoformat(),
            "receive_place": "榆林",
            "contract_selection_sha256": (
                self._selected.selection_sha256
            ),
        }
        return DailyContractValidationCandidatePage(
            business_date=business_date.isoformat(),
            query_scope_sha256=hashlib.sha256(
                json.dumps(
                    query_scope,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            page_number=page.page_number,
            page_size=page.page_size,
            total=page.total,
            platform_waybill_ids=tuple(
                item.platform_waybill_id for item in page.items
            ),
            read_attempt_count=read_attempt_count,
        )


def _observation_matches_selection(
    observation: dict[str, object],
    selected: SelectedDailyReadContract,
) -> bool:
    request_fields = observation.get("request_fields")
    response_fields = observation.get("response_fields")
    if not isinstance(request_fields, list) or not isinstance(
        response_fields,
        list,
    ):
        return False
    observed_request = {
        str(item.get("path"))[2:]: item.get("type")
        for item in request_fields
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and str(item["path"]).startswith("$.")
    }
    expected_request = {
        name: rule.type
        for name, rule in selected.manifest.request_fields.items()
    }
    observed_response = {
        str(item.get("path")): item.get("type")
        for item in response_fields
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
    }
    expected_response = {
        field.path: frozenset(field.types)
        for field in selected.manifest.response_fields
    }
    return (
        len(observed_request) == len(request_fields)
        and len(observed_response) == len(response_fields)
        and observed_request == expected_request
        and set(observed_response) == set(expected_response)
        and all(
            observed_response[path] in expected_response[path]
            for path in expected_response
        )
    )


class ChengfengDailyDetailEvidenceAdapter(DailyDetailEvidencePort):
    """Advance exactly one detail or slot-image read per durable step."""

    def __init__(
        self,
        *,
        connector: ChengfengReadPort,
        authority: BrowserCommandAuthority,
        evidence_store: ContentAddressedEvidenceStore,
        access_window_id: str,
    ) -> None:
        self._connector = connector
        self._authority = authority
        self._evidence_store = evidence_store
        if (
            not isinstance(access_window_id, str)
            or not access_window_id
            or len(access_window_id) > 100
        ):
            raise ValueError("daily access window identity is invalid")
        self._access_window_id = access_window_id

    @property
    def _capability_authority_id(self) -> str:
        value = self._connector.ticket_capability_authority_id
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
            raise ConnectorProtocolError(
                stage=ChengfengStage.DETAIL_QUERY
            )
        return value

    def advance(
        self,
        *,
        candidate: DailyCandidate,
        state: DailyDetailCaptureState | None,
    ) -> DailyDetailCaptureStep:
        if state is None:
            captured = self._read_detail(
                candidate=candidate,
                previous=None,
            )
            return DailyDetailCaptureStep(
                state=captured,
                evidence=(
                    self._evidence(captured)
                    if captured.complete
                    else None
                ),
                platform_read_performed=True,
            )
        self._validate_state_candidate(
            state=state,
            candidate=candidate,
        )
        if state.complete:
            return DailyDetailCaptureStep(
                state=state,
                evidence=self._evidence(state),
                platform_read_performed=False,
            )
        if self._requires_refresh(state):
            refreshed = self._read_detail(
                candidate=candidate,
                previous=state,
            )
            return DailyDetailCaptureStep(
                state=refreshed,
                evidence=(
                    self._evidence(refreshed)
                    if refreshed.complete
                    else None
                ),
                platform_read_performed=True,
            )
        slot = next(
            ticket
            for ticket in state.tickets
            if ticket.image_sha256 is None
        )
        image = self._connector.download_ticket_image(
            authority=self._authority,
            ticket_ref=slot.ticket_ref,
        )
        if (
            image.ticket_ref != slot.ticket_ref
            or hashlib.sha256(image.content).hexdigest() != image.sha256
        ):
            raise PageContractChangedError(
                stage=ChengfengStage.IMAGE_DOWNLOAD,
                diagnostic_code=(
                    "CF-DAILY-TICKET-INTEGRITY-INVALID"
                ),
            )
        try:
            stored = self._evidence_store.put_bytes(
                image.content,
                media_type=image.media_type,
            )
        except (EvidenceIntegrityError, OSError) as exc:
            raise ConnectorProtocolError(
                stage=ChengfengStage.IMAGE_DOWNLOAD
            ) from exc
        if stored.sha256 != image.sha256:
            raise ConnectorProtocolError(
                stage=ChengfengStage.IMAGE_DOWNLOAD
            )
        image_windows = dict(state.image_read_access_window_ids)
        image_windows[slot.slot] = self._access_window_id
        updated = replace(
            state,
            tickets=tuple(
                (
                    replace(ticket, image_sha256=stored.sha256)
                    if ticket.slot == slot.slot
                    else ticket
                )
                for ticket in state.tickets
            ),
            image_read_access_window_ids=tuple(
                sorted(image_windows.items())
            ),
        )
        return DailyDetailCaptureStep(
            state=updated,
            evidence=(self._evidence(updated) if updated.complete else None),
            platform_read_performed=True,
        )

    def observe(
        self,
        *,
        candidate: DailyCandidate,
    ) -> DailyDetailEvidence:
        """Compatibility helper for non-durable callers and old fixtures."""
        state: DailyDetailCaptureState | None = None
        while True:
            step = self.advance(candidate=candidate, state=state)
            state = step.state
            if step.evidence is not None:
                return step.evidence

    def _read_detail(
        self,
        *,
        candidate: DailyCandidate,
        previous: DailyDetailCaptureState | None,
    ) -> DailyDetailCaptureState:
        detail = self._connector.get_waybill_detail(
            authority=self._authority,
            platform_waybill_id=candidate.platform_waybill_id,
        )
        if (
            detail.platform_waybill_id != candidate.platform_waybill_id
            or (
                candidate.waybill_number is not None
                and detail.waybill_number != candidate.waybill_number
            )
        ):
            raise PageContractChangedError(
                stage=ChengfengStage.DETAIL_QUERY,
                diagnostic_code="CF-DAILY-DETAIL-IDENTITY-MISMATCH",
            )

        ticket_by_slot: dict[str, DailyTicketSlotCapture] = {}
        for ticket in detail.tickets:
            if (
                ticket.slot not in {"loading", "unloading"}
                or ticket.slot in ticket_by_slot
            ):
                raise PageContractChangedError(
                    stage=ChengfengStage.DETAIL_QUERY,
                    diagnostic_code="CF-DAILY-TICKET-SLOT-INVALID",
                )
            try:
                ticket_by_slot[ticket.slot] = DailyTicketSlotCapture(
                    slot=ticket.slot,
                    ticket_ref=ticket.ticket_ref,
                    media_type=ticket.media_type,
                )
            except DailyDetailCaptureContractError as exc:
                raise PageContractChangedError(
                    stage=ChengfengStage.DETAIL_QUERY,
                    diagnostic_code=(
                        "CF-DAILY-TICKET-REFERENCE-INVALID"
                    ),
                ) from exc

        loading_net = _decimal(detail.loading_net, field="loading_net")
        unloading_net = _decimal(
            detail.unloading_net,
            field="unloading_net",
        )
        fields = DailyObservationFields(
            shipping_mine=None,
            planned_date=None,
            loading_time=None,
            vehicle_number=(
                detail.vehicle_number or candidate.vehicle_number
            ),
            loading_net_tonnes=loading_net,
            unloading_net_tonnes=unloading_net,
            coal_type=None,
            unloading_place=None,
            unloading_time=None,
        )
        ordered = tuple(
            ticket_by_slot[slot]
            for slot in ("loading", "unloading")
            if slot in ticket_by_slot
        )
        if previous is not None:
            if (
                previous.platform_waybill_id
                != detail.platform_waybill_id
                or previous.waybill_number != detail.waybill_number
                or previous.fields != fields
                or {ticket.slot for ticket in previous.tickets}
                != set(ticket_by_slot)
                or any(
                    ticket_by_slot[ticket.slot].media_type
                    != ticket.media_type
                    for ticket in previous.tickets
                )
            ):
                raise PageContractChangedError(
                    stage=ChengfengStage.DETAIL_QUERY,
                    diagnostic_code=(
                        "CF-DAILY-DETAIL-REFRESH-CHANGED"
                    ),
                )
            completed_by_slot = {
                ticket.slot: ticket
                for ticket in previous.tickets
                if ticket.image_sha256 is not None
            }
            ordered = tuple(
                completed_by_slot.get(ticket.slot, ticket)
                for ticket in ordered
            )
        return DailyDetailCaptureState(
            platform_waybill_id=detail.platform_waybill_id,
            waybill_number=detail.waybill_number,
            fields=fields,
            tickets=ordered,
            capability_authority_id=(
                self._capability_authority_id
            ),
            capability_access_window_id=self._access_window_id,
            detail_read_access_window_ids=(
                (
                    self._access_window_id,
                )
                if previous is None
                else (
                    *previous.detail_read_access_window_ids,
                    self._access_window_id,
                )
            ),
            image_read_access_window_ids=(
                ()
                if previous is None
                else previous.image_read_access_window_ids
            ),
        )

    def _requires_refresh(
        self,
        state: DailyDetailCaptureState,
    ) -> bool:
        return (
            state.capability_authority_id
            != self._capability_authority_id
            or state.capability_access_window_id
            != self._access_window_id
            or any(
                not self._connector.ticket_image_capability_is_current(
                    ticket.ticket_ref
                )
                for ticket in state.tickets
                if ticket.image_sha256 is None
            )
        )

    @staticmethod
    def _validate_state_candidate(
        *,
        state: DailyDetailCaptureState,
        candidate: DailyCandidate,
    ) -> None:
        if (
            state.platform_waybill_id
            != candidate.platform_waybill_id
            or (
                candidate.waybill_number is not None
                and state.waybill_number
                != candidate.waybill_number
            )
        ):
            raise PageContractChangedError(
                stage=ChengfengStage.DETAIL_QUERY,
                diagnostic_code=(
                    "CF-DAILY-DETAIL-IDENTITY-MISMATCH"
                ),
            )

    @staticmethod
    def _evidence(
        state: DailyDetailCaptureState,
    ) -> DailyDetailEvidence:
        ticket_hashes = {
            ticket.slot: ticket.image_sha256
            for ticket in state.tickets
        }
        normalized_detail = {
            "fields": state.fields.to_payload(),
            "loading_ticket_sha256": ticket_hashes.get("loading"),
            "platform_waybill_id": state.platform_waybill_id,
            "unloading_ticket_sha256": ticket_hashes.get("unloading"),
            "waybill_number": state.waybill_number,
        }
        source_detail_sha256 = hashlib.sha256(
            json.dumps(
                normalized_detail,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return DailyDetailEvidence(
            platform_waybill_id=state.platform_waybill_id,
            waybill_number=state.waybill_number,
            fields=state.fields,
            loading_ticket_sha256=ticket_hashes.get("loading"),
            unloading_ticket_sha256=ticket_hashes.get("unloading"),
            source_detail_sha256=source_detail_sha256,
        )


def _decimal(value: str | None, *, field: str) -> Decimal | None:
    if value is None:
        return None
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise PageContractChangedError(
            stage=ChengfengStage.DETAIL_QUERY,
            diagnostic_code=f"CF-DAILY-{field.upper()}-INVALID",
        ) from exc
    if not parsed.is_finite() or parsed < 0:
        raise PageContractChangedError(
            stage=ChengfengStage.DETAIL_QUERY,
            diagnostic_code=f"CF-DAILY-{field.upper()}-INVALID",
        )
    return parsed
