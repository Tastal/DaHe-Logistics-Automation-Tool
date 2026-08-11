from __future__ import annotations

import contextlib
import hashlib
import json
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeError,
    BrowserRuntimeLifecycle,
)
from dahe.adapters.chengfeng.daily_contract_freezer import (
    DailyContractFreezeError,
    DailyContractFreezeResult,
    freeze_daily_read_contract,
)
from dahe.adapters.chengfeng.daily_contract_selection import (
    DailyContractSelectionError,
    SelectedDailyReadContract,
    load_selected_daily_read_contract,
    select_daily_read_contract,
)
from dahe.adapters.chengfeng.discovery import (
    DiscoveryEvidenceError,
    DiscoveryEvidenceResult,
    DiscoveryEvidenceStore,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    SelectedLiveReadContract,
)
from dahe.adapters.chengfeng.live_contract_validation import (
    LiveContractValidationError,
    LiveContractValidationPort,
    LiveContractValidationResult,
)
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditError,
)
from dahe.adapters.sqlite.browser_control import (
    BrowserControlError,
    BrowserControlRecord,
    BrowserControlStore,
)
from dahe.adapters.sqlite.business_connection import (
    SqliteBusinessConnectionSessionStore,
)
from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationAuthority,
    DailyInvocationConflictError,
    SqliteDailyInvocationStore,
)
from dahe.adapters.sqlite.daily_operational_ocr import (
    SqliteDailyOperationalOcrStore,
)
from dahe.adapters.sqlite.platform_access import (
    PlatformAccessConflictError,
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.settlement_capture import (
    SettlementCaptureStoreConflictError,
    SqliteSettlementCaptureStore,
)
from dahe.api.errors import ApiError
from dahe.application.audit.projections import project_job
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowError,
    AccessWindowGrant,
)
from dahe.application.chengfeng.business_session import (
    BUSINESS_SESSION_DURATION,
    BusinessConnectionSession,
    BusinessConnectionSessionError,
    confirmation_sha256,
)
from dahe.application.chengfeng.connection_mode import (
    ChengfengConnectionMode,
    ChengfengConnectionModeConflictError,
    ChengfengConnectionModeStore,
)
from dahe.application.chengfeng.credential_service import (
    PlatformCredentialConfig,
    PlatformCredentialConflictError,
    PlatformCredentialService,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.transient_progress import (
    TransientBusinessProgressStore,
)
from dahe.application.daily.capture import (
    DailyCaptureError,
    DailyCaptureRequest,
)
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.domain.daily.calendar import (
    SHANGHAI,
    DailyDomainError,
    business_date_for,
    candidate_query_window,
    latest_completed_business_date,
)
from dahe.jobs.models import (
    JobRecord,
    JobStatus,
    WorkItemRecord,
    WorkItemStatus,
)
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.ports.chengfeng import BrowserCommandAuthority, ChengfengReadError
from dahe.ports.jobs import (
    ActiveScopeConflictError,
    IdempotencyConflictError,
    JobNotFoundError,
    RecordVersionConflictError,
)
from dahe.ports.platform_credentials import PlatformCredentialError

_FORMAL_DAILY_PAGE_SIZE = 5

_SAFE_BROWSER_VALIDATION_FAILURES = {
    "browser_read_login_required": (
        "session_continuity_missing",
        "CF-BROWSER-SESSION-CONTINUITY-MISSING",
    ),
    "browser_worker_timeout": (
        "worker_timeout",
        "CF-BROWSER-PREPARE-TIMEOUT",
    ),
    "browser_prepare_automated_failed": (
        "automated_page_isolation_failed",
        "CF-BROWSER-AUTOMATED-ISOLATION-FAILED",
    ),
    "browser_session_settlement_route_unavailable": (
        "settlement_route_unavailable",
        "CF-BROWSER-SETTLEMENT-ROUTE-UNAVAILABLE",
    ),
    "browser_session_waybill_control_unavailable": (
        "waybill_control_unavailable",
        "CF-BROWSER-WAYBILL-CONTROL-UNAVAILABLE",
    ),
    "browser_session_settlement_scope_control_unavailable": (
        "settlement_scope_control_unavailable",
        "CF-BROWSER-SETTLEMENT-SCOPE-CONTROL-UNAVAILABLE",
    ),
    "browser_session_credit_scope_control_unavailable": (
        "credit_scope_control_unavailable",
        "CF-BROWSER-CREDIT-SCOPE-CONTROL-UNAVAILABLE",
    ),
    "browser_session_query_control_unavailable": (
        "query_control_unavailable",
        "CF-BROWSER-QUERY-CONTROL-UNAVAILABLE",
    ),
    "browser_session_existing_page_freeze_failed": (
        "existing_page_freeze_failed",
        "CF-BROWSER-EXISTING-PAGE-FREEZE-FAILED",
    ),
    "browser_session_future_page_freeze_failed": (
        "future_page_freeze_failed",
        "CF-BROWSER-FUTURE-PAGE-FREEZE-FAILED",
    ),
    "browser_session_trigger_failed": (
        "session_trigger_failed",
        "CF-BROWSER-SESSION-TRIGGER-FAILED",
    ),
    "browser_session_headers_rejected": (
        "session_headers_rejected",
        "CF-BROWSER-SESSION-HEADERS-REJECTED",
    ),
    "browser_session_fixed_values_rejected": (
        "session_fixed_values_rejected",
        "CF-BROWSER-SESSION-FIXED-VALUES-REJECTED",
    ),
    "browser_session_fixed_values_unavailable": (
        "session_fixed_values_unavailable",
        "CF-BROWSER-SESSION-FIXED-VALUES-UNAVAILABLE",
    ),
    "browser_session_cache_query_rejected": (
        "session_cache_query_rejected",
        "CF-BROWSER-SESSION-CACHE-QUERY-REJECTED",
    ),
    "browser_session_cache_query_unavailable": (
        "session_cache_query_unavailable",
        "CF-BROWSER-SESSION-CACHE-QUERY-UNAVAILABLE",
    ),
    "browser_session_list_body_rejected": (
        "session_list_body_rejected",
        "CF-BROWSER-SESSION-LIST-BODY-REJECTED",
    ),
    "browser_session_list_body_unavailable": (
        "session_list_body_unavailable",
        "CF-BROWSER-SESSION-LIST-BODY-UNAVAILABLE",
    ),
    "browser_session_list_body_mismatch": (
        "session_list_body_mismatch",
        "CF-BROWSER-SESSION-LIST-BODY-MISMATCH",
    ),
    "browser_session_request_not_constructed": (
        "session_request_not_constructed",
        "CF-BROWSER-SESSION-REQUEST-NOT-CONSTRUCTED",
    ),
    "browser_session_native_probe_not_constructed": (
        "native_probe_not_constructed",
        "CF-BROWSER-NATIVE-PROBE-NOT-CONSTRUCTED",
    ),
    "browser_session_native_probe_failed": (
        "native_probe_failed",
        "CF-BROWSER-NATIVE-PROBE-FAILED",
    ),
    "browser_session_native_probe_network_failed": (
        "native_probe_network_failed",
        "CF-BROWSER-NATIVE-PROBE-NETWORK-FAILED",
    ),
    "browser_session_native_probe_http_failed": (
        "native_probe_http_failed",
        "CF-BROWSER-NATIVE-PROBE-HTTP-FAILED",
    ),
    "browser_session_native_probe_contract_changed": (
        "native_probe_contract_changed",
        "CF-BROWSER-NATIVE-PROBE-CONTRACT-CHANGED",
    ),
    "browser_settlement_view_probe_contract_changed": (
        "settlement_view_probe_contract_changed",
        "CF-BROWSER-SETTLEMENT-VIEW-CONTRACT-CHANGED",
    ),
    "browser_settlement_view_probe_not_distinct": (
        "settlement_view_probe_not_distinct",
        "CF-BROWSER-SETTLEMENT-VIEWS-NOT-DISTINCT",
    ),
    "browser_settlement_view_probe_not_constructed": (
        "settlement_view_probe_not_constructed",
        "CF-BROWSER-SETTLEMENT-VIEW-NOT-CONSTRUCTED",
    ),
    "browser_settlement_view_probe_failed": (
        "settlement_view_probe_failed",
        "CF-BROWSER-SETTLEMENT-VIEW-PROBE-FAILED",
    ),
    "browser_session_list_path_variant": (
        "session_list_path_variant",
        "CF-BROWSER-SESSION-LIST-PATH-VARIANT",
    ),
    "browser_session_query_present": (
        "session_query_present",
        "CF-BROWSER-SESSION-QUERY-PRESENT",
    ),
    "browser_session_other_api_constructed": (
        "session_other_api_constructed",
        "CF-BROWSER-SESSION-OTHER-API-CONSTRUCTED",
    ),
    "browser_session_non_api_constructed": (
        "session_non_api_constructed",
        "CF-BROWSER-SESSION-NON-API-CONSTRUCTED",
    ),
    "browser_session_resource_mismatch": (
        "session_resource_mismatch",
        "CF-BROWSER-SESSION-RESOURCE-MISMATCH",
    ),
    "browser_session_method_mismatch": (
        "session_method_mismatch",
        "CF-BROWSER-SESSION-METHOD-MISMATCH",
    ),
    "browser_session_origin_mismatch": (
        "session_origin_mismatch",
        "CF-BROWSER-SESSION-ORIGIN-MISMATCH",
    ),
    "browser_session_url_invalid": (
        "session_url_invalid",
        "CF-BROWSER-SESSION-URL-INVALID",
    ),
    "browser_worker_unavailable": (
        "worker_unavailable",
        "CF-BROWSER-WORKER-UNAVAILABLE",
    ),
    "browser_context_closed": (
        "browser_context_closed",
        "CF-BROWSER-CONTEXT-CLOSED",
    ),
    "browser_read_network_failed": (
        "read_network_failed",
        "CF-BROWSER-READ-NETWORK-FAILED",
    ),
    "browser_read_http_failed": (
        "read_http_failed",
        "CF-BROWSER-READ-HTTP-FAILED",
    ),
    "browser_read_contract_changed": (
        "read_contract_changed",
        "CF-BROWSER-READ-CONTRACT-CHANGED",
    ),
    "browser_image_contract_changed": (
        "image_contract_changed",
        "CF-BROWSER-IMAGE-CONTRACT-CHANGED",
    ),
}
_SAFE_CONTRACT_VALIDATION_FAILURES = {
    "pending_list_empty_confirmed": (
        "pending_list_empty_confirmed",
        "CF-CONTRACT-PENDING-LIST-EMPTY-CONFIRMED",
    ),
    "detail_candidate_missing": (
        "detail_candidate_missing",
        "CF-CONTRACT-DETAIL-CANDIDATE-MISSING",
    ),
    "image_integrity_failed": (
        "image_integrity_failed",
        "CF-CONTRACT-IMAGE-INTEGRITY-FAILED",
    ),
    "image_pair_incomplete": (
        "image_pair_incomplete",
        "CF-CONTRACT-IMAGE-PAIR-INCOMPLETE",
    ),
    "daily_shared_validation_empty": (
        "daily_shared_validation_empty",
        "CF-CONTRACT-DAILY-SHARED-VALIDATION-EMPTY",
    ),
}


class CreateAccessWindowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: Literal[
        "contract_discovery",
        "formal_locked_set",
        "production_shadow",
    ]
    job_id: str = Field(min_length=1, max_length=100)
    duration_minutes: int = Field(default=60, ge=1, le=720)
    legacy_idle_confirmed: bool
    no_settlement_or_payment_confirmed: bool
    same_account_session_risk_accepted: bool
    expected_record_version: Literal[0]


class HumanLoginControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_window_id: str = Field(min_length=1, max_length=32)
    expected_record_version: int = Field(ge=1)


class SettlementFilterHandoffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: Literal[0]


class ClosePlatformSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_window_id: str = Field(min_length=1, max_length=32)
    expected_record_version: int = Field(ge=1)


class CreateDailyJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=0)
    scope: Literal["current", "last_completed"] = "current"


class CreateSettlementCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_kind: Literal[
        "current_locked_50",
        "real_shadow_30",
        "operational_compat",
    ]
    source_scope: Literal["current", "settled_history"] = "current"
    duration_minutes: int = Field(default=60, ge=60, le=720)
    legacy_idle_confirmed: bool
    no_settlement_or_payment_confirmed: bool
    same_account_session_risk_accepted: bool
    expected_record_version: Literal[0]


class StartBusinessSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    legacy_idle_confirmed: bool
    no_settlement_or_payment_confirmed: bool
    same_account_session_risk_accepted: bool
    expected_record_version: Literal[0]


class BusinessSessionReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    business_session_id: str = Field(min_length=1, max_length=32)
    expected_record_version: int = Field(ge=1)
    expected_browser_record_version: int = Field(ge=1)


class CloseBusinessSessionRequest(BusinessSessionReadRequest):
    pass


class SetConnectionModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["operational_compat", "strict_shadow"]
    expected_record_version: int = Field(ge=1)


class SavePlatformCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=512)
    password: SecretStr = Field(min_length=1, max_length=512)
    expected_record_version: int = Field(ge=0)


class DeletePlatformCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=0)


class CreateBusinessReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    business_scope: Literal["settlement", "daily"]
    business_date: date | None = None
    network_only_measurement: bool = False
    expected_record_version: int = Field(ge=0)

    def validated_business_date(self) -> date | None:
        if self.business_scope == "settlement":
            if self.business_date is not None:
                raise ValueError(
                    "settlement reads do not accept a business date"
                )
            if self.network_only_measurement:
                raise ValueError(
                    "network-only measurement is limited to daily reads"
                )
            return None
        if self.business_date is None:
            raise ValueError("daily reads require a business date")
        return self.business_date


class RebindSettlementCaptureAccessWindowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_window_id: str = Field(min_length=1, max_length=32)
    expected_record_version: int = Field(ge=1)


def _daily_now() -> datetime:
    return datetime.now(SHANGHAI)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _business_progress_timing(
    *,
    started_at: str,
    phase_started_at: str,
    updated_at: str,
    current: int,
    total: int,
    is_terminal: bool,
) -> dict[str, object]:
    """Return a server-clock baseline for elapsed and remaining time."""

    now = datetime.now(UTC)
    started = _parse_utc(started_at)
    phase_started = _parse_utc(phase_started_at)
    finished = _parse_utc(updated_at) if is_terminal else None
    elapsed_at = finished or now
    elapsed = max(0, int((elapsed_at - started).total_seconds()))
    phase_elapsed = max(0, (now - phase_started).total_seconds())
    if is_terminal:
        remaining: int | None = 0
        estimate_state = "complete"
    elif current >= 3 and total > current and phase_elapsed >= 5:
        remaining = max(
            1,
            round((total - current) / (current / phase_elapsed)),
        )
        estimate_state = "estimated"
    else:
        remaining = None
        estimate_state = "estimating"
    return {
        "started_at": started_at,
        "phase_started_at": phase_started_at,
        "updated_at": updated_at if is_terminal else now.isoformat(),
        "finished_at": None if finished is None else updated_at,
        "elapsed_seconds": elapsed,
        "estimated_remaining_seconds": remaining,
        "estimate_state": estimate_state,
        "is_terminal": is_terminal,
    }


def _daily_business_date_from_items(
    items: Sequence[WorkItemRecord],
) -> date:
    if len(items) != 1:
        raise ValueError("a daily job must contain exactly one frozen target")
    item_key = items[0].waybill_number
    prefix = "daily:"
    if not item_key.startswith(prefix):
        raise ValueError("the daily target item is malformed")
    raw_date = item_key[len(prefix) :]
    try:
        business_date = date.fromisoformat(raw_date)
    except ValueError as exc:
        raise ValueError("the daily target item is malformed") from exc
    if raw_date != business_date.isoformat():
        raise ValueError("the daily target item is not canonical")
    return business_date


def _daily_job_can_start(
    job: JobRecord,
    items: Sequence[WorkItemRecord],
) -> bool:
    return bool(
        job.task_type == "daily"
        and job.job_kind == "business"
        and job.status is JobStatus.QUEUED
        and job.current_stage == "daily.list_page"
        and len(items) == 1
        and items[0].status is WorkItemStatus.QUEUED
        and items[0].current_stage == "daily.list_page"
    )


def _request_hash(payload: BaseModel) -> str:
    raw = json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _window_payload(
    grant: object,
    *,
    record_version: int,
    idempotent_replay: bool,
) -> dict[str, object]:
    from dahe.application.chengfeng.access_window import AccessWindowGrant

    assert isinstance(grant, AccessWindowGrant)
    now = datetime.now(UTC)
    return {
        "access_window_id": grant.access_window_id,
        "purpose": grant.purpose.value,
        "job_id": grant.job_id,
        "session_id": grant.session_id,
        "build_sha256": grant.build_sha256,
        "issued_at": grant.issued_at.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
        "consumed_at": (None if grant.consumed_at is None else grant.consumed_at.isoformat()),
        "expired": now >= grant.expires_at,
        "record_version": record_version,
        "idempotent_replay": idempotent_replay,
    }


def _browser_payload(
    record: BrowserControlRecord,
    *,
    runtime: BrowserRuntime,
    idempotent_replay: bool = False,
) -> dict[str, object]:
    visible_browser_running = (
        record.browser_lifecycle == "ready" and runtime.running
    )
    human_handoff_ready = (
        visible_browser_running
        and record.browser_control_mode in {"idle", "human_handoff"}
        and record.job_id is None
    )
    if not visible_browser_running:
        login_state = "unavailable"
    elif record.browser_control_mode == "human_login":
        login_state = "login_required"
    else:
        login_state = "ready"
    return {
        "session_id": record.session_id,
        "browser_lifecycle": record.browser_lifecycle,
        "browser_control_mode": record.browser_control_mode,
        "control_epoch": record.control_epoch,
        "record_version": record.record_version,
        "runtime_available": runtime.available,
        "runtime_running": runtime.running,
        "selected_browser": runtime.selected_browser,
        "discovery_capturing": runtime.discovery_capturing,
        "visible_browser_running": visible_browser_running,
        "control_mode": record.browser_control_mode,
        "human_handoff_ready": human_handoff_ready,
        "login_state": login_state,
        "active_job_id": record.job_id,
        "warm_session_reusable": human_handoff_ready,
        "idempotent_replay": idempotent_replay,
    }


def _business_session_payload(
    session: BusinessConnectionSession,
    *,
    now: datetime,
    idempotent_replay: bool = False,
) -> dict[str, object]:
    return {
        "business_session_id": session.business_session_id,
        "status": session.status,
        "expires_at": session.expires_at.isoformat(),
        "expired": session.is_expired(now=now),
        "record_version": session.record_version,
        "idempotent_replay": idempotent_replay,
    }


def _discovery_payload(
    result: DiscoveryEvidenceResult,
    *,
    idempotent_replay: bool,
) -> dict[str, object]:
    return {
        "evidence_id": result.evidence_id,
        "canonical_sha256": result.canonical_sha256,
        "observation_count": result.observation_count,
        "idempotent_replay": idempotent_replay,
    }


def _contract_validation_payload(
    result: LiveContractValidationResult,
    *,
    idempotent_replay: bool,
) -> dict[str, object]:
    return {
        "evidence_id": result.evidence_id,
        "canonical_sha256": result.canonical_sha256,
        "selection_sha256": result.selection_sha256,
        "list_item_count": result.list_item_count,
        "detail_attempt_count": result.detail_attempt_count,
        "image_count": result.image_count,
        "idempotent_replay": idempotent_replay,
    }


def _daily_contract_payload(
    *,
    evidence: DiscoveryEvidenceResult,
    selected: SelectedDailyReadContract,
    idempotent_replay: bool,
) -> dict[str, object]:
    return {
        "discovery_evidence_sha256": evidence.canonical_sha256,
        "discovery_observation_count": evidence.observation_count,
        "contract_canonical_sha256": selected.manifest.canonical_sha256,
        "contract_file_sha256": selected.contract_file_sha256,
        "freeze_evidence_sha256": selected.freeze_evidence_sha256,
        "selection_sha256": selected.selection_sha256,
        "idempotent_replay": idempotent_replay,
    }


def _daily_observation_matches_selection(
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


def build_platform_router(
    *,
    enabled: bool,
    build_sha256: str,
    data_root: Path,
    access_repository: SqlitePlatformAccessRepository,
    business_session_store: SqliteBusinessConnectionSessionStore,
    credential_service: PlatformCredentialService,
    connection_mode_store: ChengfengConnectionModeStore,
    browser_control: BrowserControlStore,
    browser_runtime: BrowserRuntime,
    browser_lifecycle: BrowserRuntimeLifecycle,
    discovery_evidence: DiscoveryEvidenceStore,
    contract_validator: LiveContractValidationPort | None,
    job_repository: SqliteJobRepository,
    daily_invocation_store: SqliteDailyInvocationStore,
    daily_operational_ocr_store: SqliteDailyOperationalOcrStore,
    transient_progress_store: TransientBusinessProgressStore,
    selected_daily_contract: SelectedDailyReadContract | None,
    daily_execution_available: bool,
    settlement_capture_store: SqliteSettlementCaptureStore | None,
    selected_settlement_contract: SelectedLiveReadContract | None,
    settlement_identity_context_sha256: str | None,
    settlement_capture_execution_available: bool,
    verify_settlement_capture_prerequisites: (
        Callable[[ShadowBatchTargetKind], object] | None
    ),
    notify_scheduler: Callable[[], None],
    runtime_log_store: RuntimeLogStore,
    instance_id: str,
    session_id: str,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
    load_settlement_ready_waybill_numbers: (
        Callable[[], tuple[str, ...]] | None
    ) = None,
    expose_internal_codes: bool = True,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/platform")
    login_recovery_stop = threading.Event()
    login_recovery_lock = threading.Lock()
    login_recovery_threads: dict[str, threading.Thread] = {}

    login_diagnostics = frozenset(
        {
            "CF-BROWSER-CLOSED",
            "CF-CREDENTIAL-REQUIRED",
            "CF-DAILY-LOGIN-REQUIRED",
            "CF-LOGIN-INTERVENTION-REQUIRED",
            "CF-LOGIN-REQUIRED",
        }
    )

    def access_window_for_job(job_id: str, task_type: str) -> str:
        if task_type == "settlement_capture":
            if settlement_capture_store is None:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture store is unavailable"
                )
            return settlement_capture_store.get_by_job(job_id).access_window_id
        if task_type == "daily":
            return daily_invocation_store.get_by_job(job_id).access_window_id
        raise ValueError("unsupported automatic login task")

    def effective_job_diagnostic(job_id: str) -> str | None:
        job = job_repository.get_job(job_id)
        if job.diagnostic_code is not None:
            return job.diagnostic_code
        item_diagnostics = {
            item.diagnostic_code
            for item in job_repository.list_items(job_id)
            if item.diagnostic_code is not None
        }
        return next(iter(item_diagnostics)) if len(item_diagnostics) == 1 else None

    def automatic_login_worker(job_id: str) -> None:
        attempt_id = uuid4().hex
        try:
            while not login_recovery_stop.wait(0.5):
                job = job_repository.get_job(job_id)
                if job.status.is_terminal:
                    return
                # The scheduler persists external-login waits as a safe pause
                # with an external blocker.  Treat that projection as the
                # canonical login-recovery state; older jobs may still expose
                # the pre-normalized waiting_external value.
                if job.status.value not in {"paused", "waiting_external"}:
                    continue
                if effective_job_diagnostic(job_id) not in login_diagnostics:
                    return
                access_window_id = access_window_for_job(
                    job_id,
                    job.task_type,
                )
                current = browser_control.get(session_id)
                if not (
                    current.browser_control_mode == "human_login"
                    and current.holder_id == access_window_id
                ):
                    try:
                        start_human_login(
                            HumanLoginControlRequest(
                                access_window_id=access_window_id,
                                expected_record_version=current.record_version,
                            ),
                            idempotency_key=(
                                f"automatic-login-start:{job_id}:{attempt_id}"
                            ),
                        )
                    except ApiError as exc:
                        runtime_log_store.append(
                            level="warning",
                            source="chengfeng-browser",
                            event_code="automatic_login_start_failed",
                            stream="application",
                            message="Automatic login handoff could not start safely.",
                            diagnostic_code=exc.code,
                            job_id=job_id,
                        )
                        return

                while not login_recovery_stop.wait(1.0):
                    current = browser_control.get(session_id)
                    if not (
                        current.browser_control_mode == "human_login"
                        and current.holder_id == access_window_id
                    ):
                        return
                    try:
                        return_human_login(
                            HumanLoginControlRequest(
                                access_window_id=access_window_id,
                                expected_record_version=current.record_version,
                            ),
                            idempotency_key=(
                                f"automatic-login-return:{job_id}:{attempt_id}"
                            ),
                        )
                    except ApiError as exc:
                        if exc.code == "human_login_pending":
                            continue
                        runtime_log_store.append(
                            level="warning",
                            source="chengfeng-browser",
                            event_code="automatic_login_return_failed",
                            stream="application",
                            message="Automatic login handoff stopped safely.",
                            diagnostic_code=exc.code,
                            job_id=job_id,
                        )
                        return
                    return
        except (
            BrowserControlError,
            DailyInvocationConflictError,
            SettlementCaptureStoreConflictError,
        ) as exc:
            runtime_log_store.append(
                level="warning",
                source="chengfeng-browser",
                event_code="automatic_login_coordinator_failed",
                stream="application",
                message="Automatic login coordination stopped safely.",
                diagnostic_code=type(exc).__name__,
                job_id=job_id,
            )
        finally:
            with login_recovery_lock:
                login_recovery_threads.pop(job_id, None)

    def ensure_automatic_login(job_id: str) -> None:
        with login_recovery_lock:
            current = login_recovery_threads.get(job_id)
            if current is not None and current.is_alive():
                return
            thread = threading.Thread(
                target=automatic_login_worker,
                args=(job_id,),
                name=f"dahe-platform-login-{job_id[:8]}",
                daemon=True,
            )
            login_recovery_threads[job_id] = thread
            thread.start()

    def resume_automatic_login_coordinators() -> None:
        for job in job_repository.list_jobs():
            if (
                not job.status.is_terminal
                and job.run_mode == "operational"
                and job.task_type in {"settlement_capture", "daily"}
            ):
                ensure_automatic_login(job.job_id)

    def close_automatic_login_coordinators() -> None:
        login_recovery_stop.set()
        with login_recovery_lock:
            threads = tuple(login_recovery_threads.values())
        deadline = time.monotonic() + 1.0
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))

    router.add_event_handler("startup", resume_automatic_login_coordinators)
    router.add_event_handler("shutdown", close_automatic_login_coordinators)

    @router.post("/settlement-handoffs")
    def prepare_settlement_handoff(
        payload: SettlementFilterHandoffRequest,
        _: str = Depends(require_write),
    ) -> dict[str, object]:
        del payload
        if not enabled:
            raise ApiError(
                403,
                "real_platform_access_disabled",
                "当前启动未启用成丰只读访问。",
            )
        active_jobs = tuple(
            job
            for job in job_repository.list_jobs()
            if not job.status.is_terminal
            and job.task_type in {"settlement_capture", "daily"}
        )
        if active_jobs:
            raise ApiError(
                409,
                "platform_business_read_active",
                "请等待当前成丰读取完成后再打开批量筛选。",
            )
        if load_settlement_ready_waybill_numbers is None:
            raise ApiError(
                409,
                "settlement_handoff_unavailable",
                "当前版本未启用批量筛选交接。",
            )
        waybill_numbers = load_settlement_ready_waybill_numbers()
        if not waybill_numbers:
            raise ApiError(
                409,
                "settlement_ready_waybills_empty",
                "当前没有可批量筛选的运单。",
            )
        if len(waybill_numbers) > 2000:
            raise ApiError(
                409,
                "settlement_ready_waybills_limit",
                "可结算运单超过成丰单次批量筛选上限。",
            )
        with browser_lifecycle.hold():
            control = browser_control.get(session_id)
            if control.browser_control_mode != "idle":
                raise ApiError(
                    409,
                    "browser_control_conflict",
                    "成丰窗口正在使用中, 请稍后重试。",
                )
            try:
                result = browser_runtime.prepare_settlement_filter_handoff(
                    waybill_numbers
                )
            except BrowserRuntimeError as exc:
                raise ApiError(
                    409,
                    exc.code,
                    str(exc),
                ) from exc
        requested_count = int(result["requested_count"])
        matched_count = int(result["matched_count"])
        missing_count = int(result["missing_count"])
        message = (
            f"已在成丰筛选 {matched_count} 条可结算运单, "
            "请在平台人工结算。"
            if missing_count == 0
            else (
                f"成功筛选 {matched_count}/{requested_count}, "
                f"{missing_count} 条已不在可结算范围。"
            )
        )
        return {
            "count": len(waybill_numbers),
            "matched_count": matched_count,
            "missing_count": missing_count,
            "message": message,
        }

    @router.get("/business-reads/{job_id}/progress")
    def get_business_read_progress(
        job_id: str,
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        try:
            job = job_repository.get_job(job_id)
        except JobNotFoundError as exc:
            raise ApiError(
                404,
                "business_read_not_found",
                "业务读取任务不存在。",
            ) from exc
        if job.task_type not in {"daily", "settlement_capture"}:
            raise ApiError(
                409,
                "business_read_scope_invalid",
                "该任务不是业务读取任务。",
            )
        transient = transient_progress_store.get(job_id)
        if job.task_type == "settlement_capture":
            current = 0 if transient is None else transient.completed
            total = 0 if transient is None else transient.total
            phase = "read" if transient is None else (
                "download" if transient.phase == "image" else "read"
            )
            if job.status is JobStatus.SUCCEEDED:
                phase, current = "complete", total
            elif job.status in {JobStatus.FAILED, JobStatus.CANCELLED}:
                phase = "incomplete"
            labels = {
                "read": "正在读取运单",
                "download": "正在下载磅单",
                "complete": "已完成",
                "incomplete": "本次获取未完整",
            }
            settlement_payload: dict[str, object] = {
                "job_id": job_id,
                "total": total,
                "fetched": current,
                "recognized": 0,
                "missing_fields": 0,
                "technical_failed": 0,
                "committed_batches": 0,
                "phase": phase,
                "phase_label": labels[phase],
                "progress_current": current,
                "progress_total": total,
                "transient_revision": 0 if transient is None else transient.revision,
            }
            settlement_payload.update(
                _business_progress_timing(
                    started_at=job.created_at,
                    phase_started_at=job.created_at,
                    updated_at=(
                        job.updated_at
                        if transient is None
                        else transient.updated_at.isoformat()
                    ),
                    current=current,
                    total=total,
                    is_terminal=job.status.is_terminal,
                )
            )
            return settlement_payload
        progress = daily_operational_ocr_store.progress(
            daily_job_id=job_id
        )
        resolved = (
            progress.recognized
            + progress.missing_ticket
            + progress.technical_failed
        )
        complete = bool(
            job.status is JobStatus.SUCCEEDED
            and resolved >= progress.total
        )
        if job.status in {JobStatus.FAILED, JobStatus.CANCELLED}:
            phase = "incomplete"
            phase_label = "本次获取未完整"
            current = min(progress.fetched, progress.total)
        elif complete:
            phase = "complete"
            phase_label = "已完成"
            current = progress.total
        elif progress.fetched < progress.total or progress.total == 0:
            phase = "download" if progress.total else "read"
            phase_label = (
                "正在下载磅单" if progress.total else "正在读取运单"
            )
            current = min(progress.fetched, progress.total)
        elif resolved < progress.total:
            phase = "recognize"
            phase_label = "正在识别磅单"
            current = min(resolved, progress.total)
        else:
            phase = "finalize"
            phase_label = "正在整理结果"
            current = min(resolved, progress.total)
        progress_total = progress.total
        network_capture_active = bool(
            not job.status.is_terminal
            and (progress.total == 0 or progress.fetched < progress.total)
        )
        if transient is not None and network_capture_active:
            phase = "download" if transient.phase == "image" else "read"
            phase_label = (
                "正在下载磅单" if phase == "download" else "正在读取运单"
            )
            current = transient.completed
            progress_total = transient.total
        phase_started_at = (
            progress.first_ocr_batch_at
            if phase in {"recognize", "finalize", "complete"}
            and progress.first_ocr_batch_at is not None
            else job.created_at
        )
        daily_payload: dict[str, object] = {
            "job_id": job_id,
            "total": progress.total,
            "fetched": progress.fetched,
            "recognized": progress.recognized,
            "missing_fields": progress.missing_ticket,
            "technical_failed": progress.technical_failed,
            "committed_batches": progress.committed_batches,
            "phase": phase,
            "phase_label": phase_label,
            "progress_current": current,
            "progress_total": progress_total,
            "transient_revision": 0 if transient is None else transient.revision,
        }
        daily_payload.update(
            _business_progress_timing(
                started_at=job.created_at,
                phase_started_at=phase_started_at,
                updated_at=(
                    progress.last_ocr_job_updated_at
                    if complete and progress.last_ocr_job_updated_at is not None
                    else job.updated_at
                ),
                current=current,
                total=progress_total,
                is_terminal=(
                    complete
                    or job.status in {JobStatus.FAILED, JobStatus.CANCELLED}
                ),
            )
        )
        return daily_payload

    @router.get("/business-reads/{job_id}/progress/stream")
    def stream_business_read_progress(
        job_id: str,
        after: int = 0,
        _: None = Depends(require_session),
    ) -> StreamingResponse:
        try:
            job = job_repository.get_job(job_id)
        except JobNotFoundError as exc:
            raise ApiError(404, "business_read_not_found", "业务读取任务不存在。") from exc
        if job.task_type not in {"daily", "settlement_capture"}:
            raise ApiError(409, "business_read_scope_invalid", "该任务不是业务读取任务。")

        def generate() -> Iterator[str]:
            revision = max(0, after)
            initial_payload = get_business_read_progress(job_id)
            raw_initial_revision = initial_payload.get("transient_revision", 0)
            initial_revision = (
                raw_initial_revision if type(raw_initial_revision) is int else 0
            )
            if initial_revision >= revision:
                revision = initial_revision
                data = json.dumps(
                    initial_payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                yield f"id: {revision}\nevent: progress\ndata: {data}\n\n"
                if bool(initial_payload.get("is_terminal")):
                    return
            while True:
                event = transient_progress_store.wait_after(job_id, revision, 15.0)
                if event is None:
                    current_payload = get_business_read_progress(job_id)
                    if bool(current_payload.get("is_terminal")):
                        return
                    yield ": keepalive\n\n"
                    continue
                revision = event.revision
                payload = get_business_read_progress(job_id)
                payload["transient_revision"] = event.revision
                data = json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                yield f"id: {event.revision}\nevent: progress\ndata: {data}\n\n"
                if bool(payload.get("is_terminal")):
                    return

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
        )

    def credential_payload(
        config: PlatformCredentialConfig,
    ) -> dict[str, object]:
        return {
            "configured": config.configured,
            "masked_username": config.masked_username,
            "record_version": config.record_version,
        }

    @router.get("/credentials")
    def get_platform_credentials(
        response: Response,
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        response.headers["Cache-Control"] = "no-store"
        try:
            return credential_payload(credential_service.status())
        except PlatformCredentialError as exc:
            raise ApiError(
                503,
                "credential_store_unavailable",
                "成丰登录信息暂时无法读取。",
            ) from exc

    @router.put("/credentials")
    def save_platform_credentials(
        payload: SavePlatformCredentialRequest,
        response: Response,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        response.headers["Cache-Control"] = "no-store"
        try:
            result = credential_service.save(
                username=payload.username,
                password=payload.password.get_secret_value(),
                expected_record_version=payload.expected_record_version,
                idempotency_key=idempotency_key,
            )
        except PlatformCredentialConflictError as exc:
            raise ApiError(
                409,
                "credential_record_version_conflict",
                "成丰登录信息已变化。请刷新后重试。",
            ) from exc
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "This operation key belongs to another request.",
            ) from exc
        except ValueError as exc:
            raise ApiError(
                422,
                "credential_value_invalid",
                "成丰账号或密码格式不正确。",
            ) from exc
        except PlatformCredentialError as exc:
            raise ApiError(
                503,
                "credential_store_unavailable",
                "成丰登录信息未能安全保存。",
            ) from exc
        return credential_payload(result)

    @router.delete("/credentials")
    def delete_platform_credentials(
        payload: DeletePlatformCredentialRequest,
        response: Response,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        response.headers["Cache-Control"] = "no-store"
        try:
            result = credential_service.delete(
                expected_record_version=payload.expected_record_version,
                idempotency_key=idempotency_key,
            )
        except PlatformCredentialConflictError as exc:
            raise ApiError(
                409,
                "credential_record_version_conflict",
                "成丰登录信息已变化。请刷新后重试。",
            ) from exc
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "This operation key belongs to another request.",
            ) from exc
        except PlatformCredentialError as exc:
            raise ApiError(
                503,
                "credential_store_unavailable",
                "成丰登录信息未能安全删除。",
            ) from exc
        return credential_payload(result)

    def settlement_validation_gate_passed() -> bool:
        if contract_validator is None:
            return False
        try:
            return contract_validator.has_successful_validation(
                build_sha256
            )
        except LiveContractValidationError:
            return False

    def daily_invocation_authority() -> DailyInvocationAuthority:
        if (
            selected_daily_contract is None
            or selected_settlement_contract is None
        ):
            raise DailyInvocationConflictError(
                "formal daily authorities are unavailable"
            )
        return DailyInvocationAuthority(
            source_build_sha256=build_sha256,
            daily_contract_sha256=(
                selected_daily_contract.manifest.canonical_sha256
            ),
            daily_contract_file_sha256=(
                selected_daily_contract.contract_file_sha256
            ),
            daily_contract_selection_sha256=(
                selected_daily_contract.selection_sha256
            ),
            settlement_contract_sha256=(
                selected_settlement_contract.manifest.canonical_sha256
            ),
            settlement_contract_selection_sha256=(
                selected_settlement_contract.selection_sha256
            ),
        )

    @router.get("/session")
    def get_platform_session(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        record = browser_control.get(session_id)
        connection_mode = connection_mode_store.get()
        business_session = business_session_store.latest(
            platform_session_id=session_id
        )
        latest = access_repository.latest_for_session(session_id)
        closed_human_holder: str | None = None
        if (
            record.browser_lifecycle == "ready"
            and record.browser_control_mode in {"human_login", "human_handoff"}
            and not browser_runtime.running
            and latest is not None
            and record.holder_id == latest[0].access_window_id
        ):
            closed_human_holder = record.holder_id
            try:
                record = browser_control.mark_human_session_closed(
                    session_id=session_id,
                    human_session_id=latest[0].access_window_id,
                    expected_record_version=record.record_version,
                    now=now,
                )
            except BrowserControlError:
                record = browser_control.get(session_id)
        elif (
            record.browser_lifecycle == "ready"
            and record.browser_control_mode == "idle"
            and not browser_runtime.running
        ):
            try:
                record = browser_control.mark_idle_runtime_missing(
                    session_id=session_id,
                    expected_record_version=record.record_version,
                    now=now,
                )
            except BrowserControlError:
                record = browser_control.get(session_id)
        if (
            closed_human_holder is not None
            and business_session is not None
            and business_session.status == "active"
            and business_session_store.owns_access_window(
                business_session_id=(
                    business_session.business_session_id
                ),
                access_window_id=closed_human_holder,
            )
        ):
            recovery_identity = hashlib.sha256(
                (
                    f"{business_session.business_session_id}:"
                    f"{closed_human_holder}:browser_closed"
                ).encode()
            ).hexdigest()
            with contextlib.suppress(
                BusinessConnectionSessionError,
                IdempotencyConflictError,
            ):
                business_session_store.close(
                    business_session_id=(
                        business_session.business_session_id
                    ),
                    expected_record_version=(
                        business_session.record_version
                    ),
                    reason="browser_closed",
                    idempotency_key=(
                        f"business-browser-closed:{recovery_identity}"
                    ),
                    request_hash=recovery_identity,
                    now=now,
                )
            with contextlib.suppress(PlatformAccessConflictError):
                closed_window, closed_window_version = (
                    access_repository.get_with_version(
                        closed_human_holder
                    )
                )
                if closed_window.consumed_at is None:
                    access_repository.retire(
                        access_window_id=closed_human_holder,
                        expected_record_version=(
                            closed_window_version
                        ),
                        now=now,
                    )
            business_session = business_session_store.latest(
                platform_session_id=session_id
            )
            latest = access_repository.latest_for_session(session_id)
        current_window = (
            latest
            if latest is not None
            and latest[0].session_id == session_id
            and latest[0].build_sha256 == build_sha256
            else None
        )
        window_payload = (
            None
            if current_window is None
            else _window_payload(
                current_window[0],
                record_version=current_window[1],
                idempotent_replay=False,
            )
        )
        active_window = (
            current_window is not None
            and current_window[0].consumed_at is None
            and now < current_window[0].expires_at
        )
        platform_waiting_job = None
        if current_window is not None:
            try:
                candidate_job = job_repository.get_job(
                    current_window[0].job_id
                )
            except JobNotFoundError:
                pass
            else:
                if candidate_job.status in {
                    JobStatus.PAUSED,
                    JobStatus.WAITING_EXTERNAL,
                } and any(
                    item.status is WorkItemStatus.WAITING_EXTERNAL
                    for item in job_repository.list_items(
                        candidate_job.job_id
                    )
                ):
                    platform_waiting_job = candidate_job
        business_session_active = bool(
            business_session is not None
            and business_session.status == "active"
            and not business_session.is_expired(now=now)
            and business_session.build_sha256 == build_sha256
        )
        business_session_readable = bool(
            business_session_active
            and business_session is not None
            and business_session.expires_at - now
            >= timedelta(minutes=60)
        )
        active_business_read_job_id = (
            None
            if business_session is None
            else business_session_store.active_read_job_id(
                business_session_id=(
                    business_session.business_session_id
                )
            )
        )
        active_jobs_present = any(
            not job.status.is_terminal
            for job in job_repository.list_jobs()
        )
        formal_validation_available = bool(
            enabled
            and contract_validator is not None
            and active_window
            and current_window is not None
            and current_window[0].purpose is AccessPurpose.FORMAL_LOCKED_SET
            and record.browser_lifecycle == "ready"
            and record.browser_control_mode == "idle"
            and browser_runtime.running
        )
        daily_discovery_available = bool(
            enabled
            and active_window
            and current_window is not None
            and current_window[0].purpose is AccessPurpose.CONTRACT_DISCOVERY
            and record.browser_lifecycle == "ready"
            and record.browser_control_mode == "idle"
            and browser_runtime.running
            and not browser_runtime.discovery_capturing
        )
        daily_job_creation_available = bool(
            enabled
            and selected_daily_contract is not None
            and daily_execution_available
            and settlement_validation_gate_passed()
        )
        daily_job_start_available = False
        if (
            current_window is not None
            and current_window[0].purpose is AccessPurpose.PRODUCTION_SHADOW
        ):
            try:
                daily_job = job_repository.get_job(
                    current_window[0].job_id
                )
                daily_items = job_repository.list_items(daily_job.job_id)
            except JobNotFoundError:
                pass
            else:
                daily_job_start_available = _daily_job_can_start(
                    daily_job,
                    daily_items,
                )
        daily_capture_start_available = bool(
            daily_job_creation_available
            and active_window
            and current_window is not None
            and current_window[0].purpose is AccessPurpose.PRODUCTION_SHADOW
            and daily_job_start_available
            and record.browser_lifecycle == "ready"
            and record.browser_control_mode == "idle"
            and browser_runtime.running
        )
        waiting_reason = "real_platform_access_disabled"
        if enabled:
            if record.browser_control_mode == "human_login":
                waiting_reason = "human_login_in_progress"
            elif record.browser_control_mode == "human_handoff":
                waiting_reason = (
                    "business_platform_available"
                    if connection_mode.mode
                    is ChengfengConnectionMode.OPERATIONAL_COMPAT
                    else "contract_discovery_in_progress"
                )
            elif platform_waiting_job is not None:
                waiting_reason = (
                    "credential_required"
                    if platform_waiting_job.diagnostic_code
                    == "CF-CREDENTIAL-REQUIRED"
                    else "login_required"
                )
            elif active_window and record.browser_lifecycle == "ready":
                waiting_reason = (
                    "read_contract_validation_available"
                    if formal_validation_available
                    else "browser_control_returned"
                )
            elif active_window:
                waiting_reason = "human_login_available"
            else:
                waiting_reason = "access_window_required"
        return {
            "enabled": enabled,
            "run_mode": (
                "operational"
                if connection_mode.mode
                is ChengfengConnectionMode.OPERATIONAL_COMPAT
                else "shadow"
            ),
            "connection_mode": connection_mode.mode.value,
            "connection_mode_label": (
                "业务连接"
                if connection_mode.mode
                is ChengfengConnectionMode.OPERATIONAL_COMPAT
                else "验证连接"
            ),
            "connection_mode_record_version": (
                connection_mode.record_version
            ),
            **_browser_payload(record, runtime=browser_runtime),
            "access_window": window_payload,
            "business_session": (
                None
                if business_session is None
                else _business_session_payload(
                    business_session,
                    now=now,
                )
            ),
            "contract_candidate_selected": contract_validator is not None,
            "contract_selection_sha256": (
                None
                if contract_validator is None
                else contract_validator.selection_sha256
            ),
            "waiting_reason": waiting_reason,
            "available_actions": {
                "start_business_session": {
                    "enabled": bool(
                        enabled
                        and connection_mode.mode
                        is ChengfengConnectionMode.OPERATIONAL_COMPAT
                        and not business_session_active
                        and record.browser_lifecycle == "stopped"
                        and record.browser_control_mode == "idle"
                        and not browser_runtime.running
                        and not active_window
                        and active_business_read_job_id is None
                    ),
                    "reason": (
                        None
                        if (
                            enabled
                            and connection_mode.mode
                            is ChengfengConnectionMode.OPERATIONAL_COMPAT
                            and not business_session_active
                            and record.browser_lifecycle == "stopped"
                            and record.browser_control_mode == "idle"
                            and not browser_runtime.running
                            and not active_window
                            and active_business_read_job_id is None
                        )
                        else "business_session_or_task_active"
                    ),
                },
                "begin_business_read": {
                    "enabled": bool(
                        enabled
                        and connection_mode.mode
                        is ChengfengConnectionMode.OPERATIONAL_COMPAT
                        and business_session_readable
                        and settlement_capture_store is not None
                        and selected_settlement_contract is not None
                        and settlement_identity_context_sha256 is not None
                        and settlement_capture_execution_available
                        and browser_runtime.running
                        and (
                            (
                                record.browser_lifecycle == "ready"
                                and record.browser_control_mode == "idle"
                            )
                            or record.browser_control_mode == "human_handoff"
                        )
                        and active_business_read_job_id is None
                    ),
                    "reason": (
                        None
                        if (
                            enabled
                            and business_session_readable
                            and browser_runtime.running
                            and active_business_read_job_id is None
                            and record.browser_control_mode
                            in {"idle", "human_handoff"}
                        )
                        else "business_read_not_ready"
                    ),
                },
                "close_business_session": {
                    "enabled": bool(
                        business_session is not None
                        and business_session.status == "active"
                        and record.browser_control_mode != "automated"
                    ),
                    "reason": (
                        None
                        if (
                            business_session is not None
                            and business_session.status == "active"
                            and record.browser_control_mode != "automated"
                        )
                        else "business_read_in_progress_or_session_closed"
                    ),
                },
                "create_access_window": {
                    "enabled": enabled,
                    "reason": None if enabled else "real_platform_access_disabled",
                },
                "switch_connection_mode": {
                    "enabled": bool(
                        record.browser_lifecycle == "stopped"
                        and record.browser_control_mode == "idle"
                        and not active_window
                        and not active_jobs_present
                    ),
                    "reason": (
                        None
                        if (
                            record.browser_lifecycle == "stopped"
                            and record.browser_control_mode == "idle"
                            and not active_window
                            and not active_jobs_present
                        )
                        else "browser_or_task_active"
                    ),
                },
                "start_operational_capture": {
                    "enabled": bool(
                        enabled
                        and connection_mode.mode
                        is ChengfengConnectionMode.OPERATIONAL_COMPAT
                        and settlement_capture_store is not None
                        and selected_settlement_contract is not None
                        and settlement_identity_context_sha256
                        is not None
                        and settlement_capture_execution_available
                        and not active_window
                        and not business_session_active
                        and record.browser_lifecycle == "stopped"
                        and record.browser_control_mode == "idle"
                    ),
                    "reason": (
                        None
                        if (
                            enabled
                            and connection_mode.mode
                            is ChengfengConnectionMode.OPERATIONAL_COMPAT
                            and settlement_capture_store is not None
                            and selected_settlement_contract is not None
                            and settlement_identity_context_sha256
                            is not None
                            and settlement_capture_execution_available
                            and not active_window
                            and not business_session_active
                            and record.browser_lifecycle == "stopped"
                            and record.browser_control_mode == "idle"
                        )
                        else "business_connection_not_ready"
                    ),
                },
                "start_human_login": {
                    "enabled": bool(
                        enabled
                        and active_window
                        and browser_runtime.available
                        and record.browser_control_mode == "idle"
                    ),
                    "reason": (
                        None
                        if (
                            enabled
                            and active_window
                            and browser_runtime.available
                            and record.browser_control_mode == "idle"
                        )
                        else "access_window_or_browser_runtime_required"
                    ),
                },
                "return_human_login": {
                    "enabled": record.browser_control_mode == "human_login",
                    "reason": (
                        None
                        if record.browser_control_mode == "human_login"
                        else "human_login_not_active"
                    ),
                },
                "start_discovery_capture": {
                    "enabled": bool(
                        enabled
                        and active_window
                        and current_window is not None
                        and current_window[0].purpose is AccessPurpose.CONTRACT_DISCOVERY
                        and record.browser_lifecycle == "ready"
                        and record.browser_control_mode == "idle"
                        and browser_runtime.running
                        and not browser_runtime.discovery_capturing
                    ),
                    "reason": (
                        None
                        if (
                            enabled
                            and active_window
                            and current_window is not None
                            and current_window[0].purpose is AccessPurpose.CONTRACT_DISCOVERY
                            and record.browser_lifecycle == "ready"
                            and record.browser_control_mode == "idle"
                            and browser_runtime.running
                            and not browser_runtime.discovery_capturing
                        )
                        else "login_return_required"
                    ),
                },
                "stop_discovery_capture": {
                    "enabled": bool(
                        record.browser_control_mode == "human_handoff"
                        and browser_runtime.discovery_capturing
                    ),
                    "reason": (
                        None
                        if (
                            record.browser_control_mode == "human_handoff"
                            and browser_runtime.discovery_capturing
                        )
                        else "contract_discovery_not_active"
                    ),
                },
                "validate_read_contract": {
                    "enabled": formal_validation_available,
                    "reason": (
                        None
                        if formal_validation_available
                        else (
                            "read_contract_candidate_required"
                            if contract_validator is None
                            else "login_return_required"
                        )
                    ),
                },
                "discover_daily_contract": {
                    "enabled": daily_discovery_available,
                    "reason": (
                        None
                        if daily_discovery_available
                        else "contract_discovery_window_and_login_return_required"
                    ),
                },
                "create_daily_job": {
                    "enabled": daily_job_creation_available,
                    "reason": (
                        None
                        if daily_job_creation_available
                        else (
                            "daily_settlement_gate_required"
                            if (
                                enabled
                                and selected_daily_contract is not None
                                and daily_execution_available
                            )
                            else "daily_contract_and_execution_backend_required"
                        )
                    ),
                },
                "start_daily_capture": {
                    "enabled": daily_capture_start_available,
                    "reason": (
                        None
                        if daily_capture_start_available
                        else "production_shadow_window_and_login_return_required"
                    ),
                },
                "close_session": {
                    "enabled": bool(active_window or record.browser_lifecycle != "stopped"),
                    "reason": (
                        None
                        if active_window or record.browser_lifecycle != "stopped"
                        else "browser_session_not_running"
                    ),
                },
            },
        }

    @router.post("/business-session/start")
    def start_business_session(
        payload: StartBusinessSessionRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if (
            not enabled
            or connection_mode_store.get().mode
            is not ChengfengConnectionMode.OPERATIONAL_COMPAT
        ):
            raise ApiError(
                409,
                "business_connection_unavailable",
                "请先切换到业务连接。",
            )
        now = datetime.now(UTC)
        try:
            confirmation = confirmation_sha256(
                legacy_idle_confirmed=payload.legacy_idle_confirmed,
                no_settlement_or_payment_confirmed=(
                    payload.no_settlement_or_payment_confirmed
                ),
                same_account_session_risk_accepted=(
                    payload.same_account_session_risk_accepted
                ),
            )
        except BusinessConnectionSessionError as exc:
            raise ApiError(
                409,
                "business_confirmation_required",
                "开始业务连接前，需要确认旧程序和平台业务均处于安全状态。",  # noqa: RUF001
            ) from exc
        with browser_lifecycle.hold():
            browser = browser_control.get(session_id)
            if (
                browser.record_version < 1
                or browser.browser_lifecycle != "stopped"
                or browser.browser_control_mode != "idle"
                or browser_runtime.running
            ):
                raise ApiError(
                    409,
                    "business_browser_active",
                    "已有成丰窗口或读取任务正在使用，请先完成或关闭。",  # noqa: RUF001
                )
            key_sha256 = hashlib.sha256(
                idempotency_key.encode("utf-8")
            ).hexdigest()
            request_hash = _request_hash(payload)
            try:
                login_window, window_replay = access_repository.issue(
                    purpose=AccessPurpose.PRODUCTION_SHADOW,
                    job_id=f"business-login-{key_sha256[:32]}",
                    session_id=session_id,
                    build_sha256=build_sha256,
                    duration_minutes=720,
                    legacy_idle_confirmed=True,
                    no_settlement_or_payment_confirmed=True,
                    same_account_session_risk_accepted=True,
                    run_mode="operational",
                    idempotency_key=f"business-access:{key_sha256}",
                    request_hash=request_hash,
                    now=now,
                )
                business_session, session_replay = (
                    business_session_store.start(
                        platform_session_id=session_id,
                        build_sha256=build_sha256,
                        login_access_window_id=(
                            login_window.access_window_id
                        ),
                        confirmation_sha256=confirmation,
                        expires_at=now + BUSINESS_SESSION_DURATION,
                        idempotency_key=(
                            f"business-session:{key_sha256}"
                        ),
                        request_hash=request_hash,
                        now=now,
                    )
                )
            except (
                BusinessConnectionSessionError,
                PlatformAccessConflictError,
            ) as exc:
                raise ApiError(
                    409,
                    "business_session_start_conflict",
                    str(exc),
                ) from exc
        return {
            "created": not (window_replay or session_replay),
            "business_session": _business_session_payload(
                business_session,
                now=now,
                idempotent_replay=(window_replay or session_replay),
            ),
            "access_window": _window_payload(
                login_window,
                record_version=(
                    access_repository.get_with_version(
                        login_window.access_window_id
                    )[1]
                ),
                idempotent_replay=window_replay,
            ),
            "platform_session": _browser_payload(
                browser,
                runtime=browser_runtime,
            ),
        }

    @router.post("/business-session/read")
    def begin_business_read(
        payload: BusinessSessionReadRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if (
            not enabled
            or settlement_capture_store is None
            or selected_settlement_contract is None
            or settlement_identity_context_sha256 is None
            or not settlement_capture_execution_available
            or connection_mode_store.get().mode
            is not ChengfengConnectionMode.OPERATIONAL_COMPAT
        ):
            raise ApiError(
                409,
                "business_read_unavailable",
                "业务读取能力尚未准备完成。",
            )
        read_idempotency_key = (
            "business-read:"
            f"{hashlib.sha256(idempotency_key.encode()).hexdigest()}"
        )
        read_request_hash = _request_hash(payload)
        try:
            replayed_start = settlement_capture_store.replay_start(
                target_kind=(
                    ShadowBatchTargetKind.OPERATIONAL_COMPAT
                ),
                idempotency_key=read_idempotency_key,
                request_hash=read_request_hash,
                business_session_id=payload.business_session_id,
            )
        except (
            IdempotencyConflictError,
            SettlementCaptureStoreConflictError,
        ) as exc:
            raise ApiError(
                409,
                "business_read_replay_conflict",
                str(exc),
            ) from exc
        if replayed_start is not None:
            replayed_session = business_session_store.get(
                payload.business_session_id
            )
            replayed_job = job_repository.get_job(
                replayed_start.job_id
            )
            replayed_items = job_repository.list_items(
                replayed_start.job_id
            )
            return {
                "created": False,
                "business_session": _business_session_payload(
                    replayed_session,
                    now=datetime.now(UTC),
                    idempotent_replay=True,
                ),
                "job": project_job(
                    replayed_job,
                    replayed_items,
                    job_repository.runtime_projection(
                        replayed_start.job_id
                    ),
                    expose_internal_codes=expose_internal_codes,
                ),
            }
        now = datetime.now(UTC)
        try:
            business_session = business_session_store.get(
                payload.business_session_id
            )
        except BusinessConnectionSessionError as exc:
            raise ApiError(
                409,
                "business_session_missing",
                str(exc),
            ) from exc
        if (
            business_session.status != "active"
            or business_session.record_version
            != payload.expected_record_version
            or business_session.platform_session_id != session_id
            or business_session.build_sha256 != build_sha256
            or business_session.is_expired(now=now)
        ):
            raise ApiError(
                409,
                "business_session_stale",
                "业务连接已变化或到期，请刷新后重试。",  # noqa: RUF001
            )
        if business_session_store.active_read_job_id(
            business_session_id=business_session.business_session_id
        ) is not None:
            raise ApiError(
                409,
                "business_read_already_active",
                "当前业务读取尚未结束。",
            )
        with browser_lifecycle.hold():
            browser = browser_control.get(session_id)
            if (
                browser.record_version
                != payload.expected_browser_record_version
            ):
                raise ApiError(
                    409,
                    "browser_control_conflict",
                    "成丰窗口状态已变化，请刷新后重试。",  # noqa: RUF001
                )
            if browser.browser_control_mode == "human_login":
                raise ApiError(
                    409,
                    "return_human_login_required",
                    "登录完成后请先将窗口交给程序读取。",
                )
            if browser.browser_control_mode == "human_handoff":
                if (
                    browser.holder_id is None
                    or not business_session_store.owns_access_window(
                        business_session_id=(
                            business_session.business_session_id
                        ),
                        access_window_id=browser.holder_id,
                    )
                ):
                    raise ApiError(
                        409,
                        "business_handoff_mismatch",
                        "当前人工窗口不属于这个业务连接。",
                    )
                try:
                    returned, _ = (
                        browser_control.return_human_session_control(
                            session_id=session_id,
                            human_session_id=browser.holder_id,
                            expected_record_version=browser.record_version,
                            idempotency_key=(
                                f"business-return:{hashlib.sha256(idempotency_key.encode()).hexdigest()}"
                            ),
                            request_hash=_request_hash(payload),
                            now=now,
                        )
                    )
                    browser_runtime.close()
                    stopped, _ = browser_control.mark_stopped(
                        session_id=session_id,
                        access_window_id=browser.holder_id,
                        expected_record_version=returned.record_version,
                        idempotency_key=(
                            f"business-rebuild-stop:{hashlib.sha256(idempotency_key.encode()).hexdigest()}"
                        ),
                        request_hash=_request_hash(payload),
                        now=now,
                    )
                    browser_runtime.start_human_login()
                    browser = browser_control.mark_ready(
                        session_id=session_id,
                        expected_record_version=stopped.record_version,
                        now=now,
                    )
                except (BrowserControlError, BrowserRuntimeError) as exc:
                    with contextlib.suppress(BrowserRuntimeError):
                        browser_runtime.close()
                    raise ApiError(
                        409,
                        "business_context_rebuild_failed",
                        "成丰窗口无法安全重建，本次未开始读取。",  # noqa: RUF001
                    ) from exc
            if (
                browser.browser_lifecycle != "ready"
                or browser.browser_control_mode != "idle"
                or not browser_runtime.running
            ):
                raise ApiError(
                    409,
                    "business_login_required",
                    "请先打开成丰并完成登录。",
                )
            login_window, login_version = (
                access_repository.get_with_version(
                    business_session.login_access_window_id
                )
            )
            if login_window.consumed_at is None:
                access_repository.retire(
                    access_window_id=login_window.access_window_id,
                    expected_record_version=login_version,
                    now=now,
                )
            remaining_minutes = int(
                (business_session.expires_at - now).total_seconds() // 60
            )
            if remaining_minutes < 60:
                raise ApiError(
                    409,
                    "business_session_expiring",
                    "业务连接即将到期，请重新建立连接后读取。",  # noqa: RUF001
                )
            try:
                started = settlement_capture_store.create_start(
                    target_kind=ShadowBatchTargetKind.OPERATIONAL_COMPAT,
                    session_id=session_id,
                    source_build_sha256=build_sha256,
                    contract_canonical_sha256=(
                        selected_settlement_contract
                        .manifest.canonical_sha256
                    ),
                    contract_file_sha256=(
                        selected_settlement_contract.contract_file_sha256
                    ),
                    contract_selection_sha256=(
                        selected_settlement_contract.selection_sha256
                    ),
                    identity_context_sha256=(
                        settlement_identity_context_sha256
                    ),
                    duration_minutes=min(120, remaining_minutes),
                    legacy_idle_confirmed=True,
                    no_settlement_or_payment_confirmed=True,
                    same_account_session_risk_accepted=True,
                    idempotency_key=read_idempotency_key,
                    request_hash=read_request_hash,
                    now=now,
                    business_session_id=(
                        business_session.business_session_id
                    ),
                    business_session_expected_record_version=(
                        business_session.record_version
                    ),
                )
            except (
                ActiveScopeConflictError,
                IdempotencyConflictError,
                SettlementCaptureStoreConflictError,
            ) as exc:
                raise ApiError(
                    409,
                    "business_read_start_conflict",
                    str(exc),
                ) from exc
        notify_scheduler()
        updated_business_session = business_session_store.get(
            business_session.business_session_id
        )
        job = job_repository.get_job(started.job_id)
        items = job_repository.list_items(started.job_id)
        return {
            "created": started.created,
            "business_session": _business_session_payload(
                updated_business_session,
                now=now,
                idempotent_replay=not started.created,
            ),
            "job": project_job(
                job,
                items,
                job_repository.runtime_projection(started.job_id),
                expose_internal_codes=expose_internal_codes,
            ),
        }

    @router.post("/business-session/close")
    def close_business_session(
        payload: CloseBusinessSessionRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        close_identity = hashlib.sha256(
            idempotency_key.encode()
        ).hexdigest()
        close_idempotency_key = f"business-close:{close_identity}"
        close_request_hash = _request_hash(payload)
        try:
            business_session = business_session_store.get(
                payload.business_session_id
            )
        except BusinessConnectionSessionError as exc:
            raise ApiError(409, "business_session_missing", str(exc)) from exc
        if (
            business_session.record_version
            != payload.expected_record_version
            or business_session.status != "active"
        ):
            try:
                closed, replay = business_session_store.close(
                    business_session_id=(
                        business_session.business_session_id
                    ),
                    expected_record_version=(
                        payload.expected_record_version
                    ),
                    reason="explicit",
                    idempotency_key=close_idempotency_key,
                    request_hash=close_request_hash,
                    now=now,
                )
            except (
                BusinessConnectionSessionError,
                IdempotencyConflictError,
            ) as exc:
                raise ApiError(
                    409,
                    "business_session_stale",
                    "业务连接已变化，请刷新后重试。",  # noqa: RUF001
                ) from exc
            return {
                "business_session": _business_session_payload(
                    closed,
                    now=now,
                    idempotent_replay=replay,
                ),
                "platform_session": _browser_payload(
                    browser_control.get(session_id),
                    runtime=browser_runtime,
                    idempotent_replay=replay,
                ),
            }
        if business_session_store.active_read_job_id(
            business_session_id=business_session.business_session_id
        ) is not None:
            raise ApiError(
                409,
                "business_read_in_progress",
                "当前业务读取尚未结束，完成或取消后才能关闭。",  # noqa: RUF001
            )
        with browser_lifecycle.hold():
            browser = browser_control.get(session_id)
            if (
                browser.record_version
                != payload.expected_browser_record_version
            ):
                raise ApiError(
                    409,
                    "browser_control_conflict",
                    "成丰窗口状态已变化，请刷新后重试。",  # noqa: RUF001
                )
            if browser.browser_control_mode == "automated":
                raise ApiError(
                    409,
                    "business_read_in_progress",
                    "正在读取成丰数据，完成当前原子步骤后才能关闭。",  # noqa: RUF001
                )
            stop_access_window_id = (
                browser.holder_id
                if browser.browser_control_mode
                in {"human_login", "human_handoff"}
                and browser.holder_id is not None
                else business_session.login_access_window_id
            )
            if browser.browser_control_mode in {
                "human_login",
                "human_handoff",
            }:
                if not business_session_store.owns_access_window(
                    business_session_id=business_session.business_session_id,
                    access_window_id=stop_access_window_id,
                ):
                    raise ApiError(
                        409,
                        "business_handoff_mismatch",
                        "当前成丰窗口不属于这个业务连接。",
                    )
                browser, _ = browser_control.return_human_session_control(
                    session_id=session_id,
                    human_session_id=stop_access_window_id,
                    expected_record_version=browser.record_version,
                    idempotency_key=(
                        f"business-close-return:{hashlib.sha256(idempotency_key.encode()).hexdigest()}"
                    ),
                    request_hash=_request_hash(payload),
                    now=now,
                )
            with contextlib.suppress(BrowserRuntimeError):
                browser_runtime.close()
            if browser.browser_lifecycle in {"ready", "recovering"}:
                browser, _ = browser_control.mark_stopped(
                    session_id=session_id,
                    access_window_id=stop_access_window_id,
                    expected_record_version=browser.record_version,
                    idempotency_key=(
                        f"business-close-stop:{hashlib.sha256(idempotency_key.encode()).hexdigest()}"
                    ),
                    request_hash=_request_hash(payload),
                    now=now,
                )
            login_window, login_version = (
                access_repository.get_with_version(
                    business_session.login_access_window_id
                )
            )
            if login_window.consumed_at is None:
                access_repository.retire(
                    access_window_id=login_window.access_window_id,
                    expected_record_version=login_version,
                    now=now,
                )
            try:
                closed, replay = business_session_store.close(
                    business_session_id=(
                        business_session.business_session_id
                    ),
                    expected_record_version=(
                        business_session.record_version
                    ),
                    reason="explicit",
                    idempotency_key=close_idempotency_key,
                    request_hash=close_request_hash,
                    now=now,
                )
            except BusinessConnectionSessionError as exc:
                raise ApiError(
                    409,
                    "business_session_close_conflict",
                    str(exc),
                ) from exc
        return {
            "business_session": _business_session_payload(
                closed,
                now=now,
                idempotent_replay=replay,
            ),
            "platform_session": _browser_payload(
                browser,
                runtime=browser_runtime,
            ),
        }

    @router.post("/connection-mode")
    def set_connection_mode(
        payload: SetConnectionModeRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        browser = browser_control.get(session_id)
        latest = access_repository.latest_for_session(session_id)
        active_window = bool(
            latest is not None
            and latest[0].consumed_at is None
            and datetime.now(UTC) < latest[0].expires_at
        )
        active_jobs = any(
            not job.status.is_terminal
            for job in job_repository.list_jobs()
        )
        try:
            state = connection_mode_store.switch(
                mode=ChengfengConnectionMode(payload.mode),
                expected_record_version=(
                    payload.expected_record_version
                ),
                idempotency_key=idempotency_key,
                request_hash=_request_hash(payload),
                switching_allowed=bool(
                    browser.browser_lifecycle == "stopped"
                    and browser.browser_control_mode == "idle"
                    and not browser_runtime.running
                    and not active_window
                    and not active_jobs
                ),
            )
        except ChengfengConnectionModeConflictError as exc:
            raise ApiError(
                409,
                "connection_mode_conflict",
                str(exc),
            ) from exc
        return {
            "connection_mode": state.mode.value,
            "record_version": state.record_version,
        }

    @router.post("/access-windows")
    def create_access_window(
        payload: CreateAccessWindowRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if not enabled:
            raise ApiError(
                403,
                "real_platform_access_disabled",
                "当前启动未启用成丰只读影子访问。",
            )
        try:
            with browser_lifecycle.hold():
                control = browser_control.get(session_id)
                stale_windows = tuple(
                    item
                    for item in access_repository.unconsumed_for_session(
                        session_id
                    )
                    if item[0].build_sha256 != build_sha256
                )
                if stale_windows:
                    if (
                        control.browser_control_mode != "idle"
                        or browser_runtime.running
                    ):
                        raise PlatformAccessConflictError(
                            "a prior-build access window still owns the browser session"
                        )
                    instant = datetime.now(UTC)
                    for stale, stale_version in stale_windows:
                        access_repository.retire(
                            access_window_id=stale.access_window_id,
                            expected_record_version=stale_version,
                            now=instant,
                        )
                grant, replay = access_repository.issue(
                    purpose=AccessPurpose(payload.purpose),
                    job_id=payload.job_id,
                    session_id=session_id,
                    build_sha256=build_sha256,
                    duration_minutes=payload.duration_minutes,
                    legacy_idle_confirmed=payload.legacy_idle_confirmed,
                    no_settlement_or_payment_confirmed=(
                        payload.no_settlement_or_payment_confirmed
                    ),
                    same_account_session_risk_accepted=(
                        payload.same_account_session_risk_accepted
                    ),
                    run_mode="shadow",
                    idempotency_key=idempotency_key,
                    request_hash=_request_hash(payload),
                    now=datetime.now(UTC),
                )
                _, record_version = access_repository.get_with_version(
                    grant.access_window_id
                )
        except AccessWindowError as exc:
            raise ApiError(409, "access_window_rejected", str(exc)) from exc
        except PlatformAccessConflictError as exc:
            raise ApiError(409, "platform_access_conflict", str(exc)) from exc
        return {
            "access_window": _window_payload(
                grant,
                record_version=record_version,
                idempotent_replay=replay,
            )
        }

    def authorize_window(access_window_id: str) -> AccessWindowGrant:
        try:
            grant = access_repository.get(access_window_id)
            return access_repository.authorize(
                access_window_id=access_window_id,
                purpose=grant.purpose,
                job_id=grant.job_id,
                session_id=session_id,
                build_sha256=build_sha256,
                now=datetime.now(UTC),
            )
        except (AccessWindowError, PlatformAccessConflictError) as exc:
            raise ApiError(409, "access_window_invalid", str(exc)) from exc

    def authorize_discovery_window(access_window_id: str) -> AccessWindowGrant:
        grant = authorize_window(access_window_id)
        if grant.purpose is not AccessPurpose.CONTRACT_DISCOVERY:
            raise ApiError(
                409,
                "contract_discovery_window_required",
                "当前只读窗口不允许记录合同结构。",
            )
        return grant

    def authorize_validation_window(access_window_id: str) -> AccessWindowGrant:
        grant = authorize_window(access_window_id)
        if grant.purpose is not AccessPurpose.FORMAL_LOCKED_SET:
            raise ApiError(
                409,
                "formal_locked_set_window_required",
                "当前只读窗口不允许验证正式读取合同。",
            )
        return grant

    def authorize_daily_capture_window(
        access_window_id: str,
        *,
        job_id: str,
    ) -> AccessWindowGrant:
        try:
            return access_repository.authorize(
                access_window_id=access_window_id,
                purpose=AccessPurpose.PRODUCTION_SHADOW,
                job_id=job_id,
                session_id=session_id,
                build_sha256=build_sha256,
                now=datetime.now(UTC),
            )
        except (
            AccessWindowError,
            PlatformAccessConflictError,
        ) as exc:
            raise ApiError(
                409,
                "production_shadow_window_required",
                "A valid production-shadow window bound to this job is required.",
            ) from exc

    @router.post("/session/human-login/start")
    def start_human_login(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if not enabled:
            raise ApiError(403, "real_platform_access_disabled", "当前启动未启用成丰只读影子访问。")
        authorize_window(payload.access_window_id)
        request_hash = _request_hash(payload)
        with browser_lifecycle.hold():
            # Re-authorize after entering the lifecycle lock. A rollover may
            # have consumed this window while the request waited for control.
            authorize_window(payload.access_window_id)
            record = browser_control.get(session_id)
            expected_record_version = payload.expected_record_version
            if (
                record.browser_lifecycle == "ready"
                and record.browser_control_mode == "idle"
                and not browser_runtime.running
            ):
                prior_version = record.record_version
                try:
                    record = browser_control.mark_idle_runtime_missing(
                        session_id=session_id,
                        expected_record_version=prior_version,
                        now=datetime.now(UTC),
                    )
                except BrowserControlError as exc:
                    raise ApiError(
                        409,
                        "browser_control_conflict",
                        "浏览器状态已变化。请刷新后重试。",
                    ) from exc
                if payload.expected_record_version != prior_version:
                    raise ApiError(
                        409,
                        "browser_control_conflict",
                        "浏览器状态已变化。请刷新后重试。",
                    )
                expected_record_version = record.record_version
            started_runtime = False
            if record.browser_lifecycle == "stopped":
                if record.record_version != expected_record_version:
                    raise ApiError(
                        409,
                        "browser_control_conflict",
                        "浏览器状态已变化。请刷新后重试。",
                    )
                if not browser_runtime.available:
                    raise ApiError(
                        409,
                        "browser_runtime_unavailable",
                        "独立浏览器运行时尚未通过检查。",
                    )
                try:
                    browser_runtime.start_human_login()
                    started_runtime = True
                    record = browser_control.mark_ready(
                        session_id=session_id,
                        expected_record_version=record.record_version,
                        now=datetime.now(UTC),
                    )
                except (BrowserRuntimeError, BrowserControlError) as exc:
                    browser_runtime.close()
                    raise ApiError(
                        409,
                        "browser_start_failed",
                        str(exc),
                    ) from exc
            elif (
                record.browser_control_mode == "idle"
                and record.record_version != expected_record_version
            ):
                raise ApiError(
                    409,
                    "browser_control_conflict",
                    "浏览器状态已变化。请刷新后重试。",
                )
            if (
                not started_runtime
                and
                record.browser_lifecycle == "ready"
                and record.browser_control_mode == "idle"
            ):
                try:
                    browser_runtime.start_human_login()
                    started_runtime = True
                except BrowserRuntimeError as exc:
                    browser_runtime.close()
                    with contextlib.suppress(BrowserControlError):
                        record = browser_control.mark_idle_runtime_missing(
                            session_id=session_id,
                            expected_record_version=record.record_version,
                            now=datetime.now(UTC),
                        )
                    raise ApiError(
                        409,
                        "browser_start_failed",
                        str(exc),
                    ) from exc
            try:
                updated, replay = browser_control.acquire_human_session_control(
                    session_id=session_id,
                    control_mode="human_login",
                    human_session_id=payload.access_window_id,
                    expected_record_version=record.record_version,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    now=datetime.now(UTC),
                )
            except BrowserControlError as exc:
                if started_runtime:
                    browser_runtime.close()
                raise ApiError(
                    409,
                    "browser_control_conflict",
                    str(exc),
                ) from exc
            return {
                "platform_session": _browser_payload(
                    updated,
                    runtime=browser_runtime,
                    idempotent_replay=replay,
                )
            }

    @router.post("/session/human-login/return")
    def return_human_login(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        access_grant = authorize_window(payload.access_window_id)
        batch_job_id: str | None = None
        if settlement_capture_store is not None:
            try:
                if (
                    settlement_capture_store.capture_strategy(
                        access_grant.job_id
                    )
                    == "batch_v1"
                ):
                    batch_job_id = access_grant.job_id
            except SettlementCaptureStoreConflictError:
                batch_job_id = None
        if batch_job_id is None:
            try:
                access_job = job_repository.get_job(access_grant.job_id)
                if (
                    access_job.task_type == "daily"
                    and daily_invocation_store.capture_strategy(
                        access_grant.job_id
                    )
                    == "batch_v1"
                ):
                    batch_job_id = access_grant.job_id
            except (
                DailyInvocationConflictError,
                JobNotFoundError,
            ):
                batch_job_id = None
        with browser_lifecycle.hold():
            current = browser_control.get(session_id)
            if (
                current.browser_control_mode == "human_login"
                and current.holder_id == payload.access_window_id
                and not browser_runtime.running
            ):
                with contextlib.suppress(BrowserControlError):
                    browser_control.mark_human_session_closed(
                        session_id=session_id,
                        human_session_id=payload.access_window_id,
                        expected_record_version=current.record_version,
                        now=datetime.now(UTC),
                    )
                raise ApiError(
                    409,
                    "browser_window_closed",
                    "成丰窗口已经关闭。已保留本次只读窗口，可重新打开登录页。",  # noqa: RUF001
                )
            try:
                browser_runtime.freeze_human_session()
            except BrowserRuntimeError as exc:
                if exc.code == "browser_read_login_required":
                    raise ApiError(
                        409,
                        "human_login_pending",
                        "请在成丰窗口完成登录，系统会自动继续。",  # noqa: RUF001
                    ) from exc
                freeze_reason, freeze_diagnostic = (
                    _SAFE_BROWSER_VALIDATION_FAILURES.get(
                        exc.code,
                        (
                            "freeze_failed",
                            "CF-BROWSER-FREEZE-FAILED",
                        ),
                    )
                )
                runtime_log_store.append(
                    level="warning",
                    source="chengfeng-browser",
                    event_code="human_login_freeze_failed",
                    stream="application",
                    message=(
                        "Controlled Chengfeng page freeze stopped safely "
                        f"({freeze_reason})."
                    ),
                    diagnostic_code=freeze_diagnostic,
                )
                with contextlib.suppress(BrowserRuntimeError):
                    browser_runtime.close()
                with contextlib.suppress(BrowserControlError):
                    browser_control.mark_human_session_closed(
                        session_id=session_id,
                        human_session_id=payload.access_window_id,
                        expected_record_version=current.record_version,
                        now=datetime.now(UTC),
                    )
                raise ApiError(
                    409,
                    "browser_session_freeze_failed",
                    "成丰窗口无法安全冻结，已关闭本次窗口。",  # noqa: RUF001
                ) from exc
            try:
                updated, replay = browser_control.return_human_session_control(
                    session_id=session_id,
                    human_session_id=payload.access_window_id,
                    expected_record_version=payload.expected_record_version,
                    idempotency_key=idempotency_key,
                    request_hash=_request_hash(payload),
                    now=datetime.now(UTC),
                )
            except BrowserControlError as exc:
                raise ApiError(409, "browser_control_conflict", str(exc)) from exc
            if batch_job_id is not None:
                browser_runtime.close()
                updated = browser_control.mark_idle_runtime_missing(
                    session_id=session_id,
                    expected_record_version=updated.record_version,
                    now=datetime.now(UTC),
                )
                job_repository.resume_platform_waiting_job(
                    job_id=batch_job_id,
                    allowed_diagnostic_codes=frozenset(
                        {
                            "CF-BROWSER-CLOSED",
                            "CF-CREDENTIAL-REQUIRED",
                            "CF-DAILY-LOGIN-REQUIRED",
                            "CF-LOGIN-INTERVENTION-REQUIRED",
                            "CF-LOGIN-REQUIRED",
                        }
                    ),
                )
        notify_scheduler()
        return {
            "platform_session": _browser_payload(
                updated,
                runtime=browser_runtime,
                idempotent_replay=replay,
            )
        }

    @router.post("/diagnostics/settlement-views")
    def probe_settlement_views(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        del idempotency_key
        grant = authorize_window(payload.access_window_id)
        if grant.purpose not in {
            AccessPurpose.FORMAL_LOCKED_SET,
            AccessPurpose.PRODUCTION_SHADOW,
        }:
            raise ApiError(
                409,
                "settlement_view_probe_window_required",
                "A formal read-only access window is required.",
            )
        worker_id = f"settlement-view-probe-{uuid4().hex}"
        acquired_at = datetime.now(UTC)
        control_ttl = min(
            timedelta(minutes=3),
            grant.expires_at - acquired_at,
        )
        if control_ttl <= timedelta(0):
            raise ApiError(
                409,
                "access_window_rejected",
                "The read-only access window has expired.",
            )
        with browser_lifecycle.hold():
            record = browser_control.get(session_id)
            if (
                record.record_version != payload.expected_record_version
                or record.browser_lifecycle != "ready"
                or record.browser_control_mode != "idle"
                or not browser_runtime.running
            ):
                raise ApiError(
                    409,
                    "login_return_required",
                    "Return the controlled browser before probing.",
                )
            try:
                acquired = browser_control.acquire_automated(
                    session_id=session_id,
                    instance_id=instance_id,
                    worker_id=worker_id,
                    job_id=grant.job_id,
                    expected_record_version=record.record_version,
                    now=acquired_at,
                    ttl=control_ttl,
                )
            except BrowserControlError as exc:
                raise ApiError(
                    409,
                    "browser_control_conflict",
                    "The controlled browser state changed.",
                ) from exc
        if acquired.fencing_token is None:
            raise ApiError(
                409,
                "browser_control_conflict",
                "Automated read-only control is invalid.",
            )

        probe = None
        probe_failure: BrowserRuntimeError | None = None
        cleanup_failure: Exception | None = None
        released: BrowserControlRecord | None = None
        try:
            probe = browser_runtime.probe_settlement_views()
        except BrowserRuntimeError as exc:
            probe_failure = exc
        finally:
            with browser_lifecycle.hold():
                try:
                    released = browser_control.release_automated(
                        session_id=session_id,
                        instance_id=instance_id,
                        worker_id=worker_id,
                        job_id=grant.job_id,
                        control_epoch=acquired.control_epoch,
                        fencing_token=acquired.fencing_token,
                        now=datetime.now(UTC),
                    )
                except Exception as exc:
                    cleanup_failure = exc
        if cleanup_failure is not None or released is None:
            with contextlib.suppress(BrowserRuntimeError):
                browser_runtime.close()
            raise ApiError(
                409,
                "settlement_view_probe_cleanup_failed",
                "The read-only browser probe could not release control safely.",
            ) from cleanup_failure
        if probe_failure is not None:
            reason, diagnostic = _SAFE_BROWSER_VALIDATION_FAILURES.get(
                probe_failure.code,
                (
                    "settlement_view_probe_failed",
                    "CF-BROWSER-SETTLEMENT-VIEW-PROBE-FAILED",
                ),
            )
            runtime_log_store.append(
                level="warning",
                source="chengfeng-browser",
                event_code="settlement_view_probe_failed",
                stream="application",
                message=(
                    "Chengfeng settlement view probe stopped safely "
                    f"({reason})."
                ),
                diagnostic_code=diagnostic,
            )
            raise ApiError(
                409,
                "settlement_view_probe_failed",
                "The read-only settlement view probe stopped safely.",
            ) from probe_failure
        assert probe is not None
        runtime_log_store.append(
            level="info",
            source="chengfeng-browser",
            event_code="settlement_view_probe_completed",
            stream="application",
            message=(
                "Chengfeng settlement view probe completed with "
                f"settlement={probe.settlement_total_count} and "
                f"credit={probe.credit_total_count}."
            ),
        )
        return {
            "platform_session": _browser_payload(
                released,
                runtime=browser_runtime,
                idempotent_replay=False,
            ),
            "settlement_views": {
                "settlement": {
                    "total_count": probe.settlement_total_count,
                    "list_length": probe.settlement_list_length,
                },
                "credit": {
                    "total_count": probe.credit_total_count,
                    "list_length": probe.credit_list_length,
                },
                "page_number": probe.page_number,
                "page_size": probe.page_size,
                "response_structure_sha256": {
                    "settlement": (
                        probe.settlement_response_structure_sha256
                    ),
                    "credit": probe.credit_response_structure_sha256,
                },
            },
        }

    @router.post("/business-reads")
    def create_business_read(
        payload: CreateBusinessReadRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        try:
            business_date = payload.validated_business_date()
        except ValueError as exc:
            raise ApiError(
                422,
                "business_read_scope_invalid",
                str(exc),
            ) from exc
        if not enabled:
            raise ApiError(
                409,
                "business_read_unavailable",
                "成丰业务连接尚未启用。",
            )
        if (
            connection_mode_store.get().mode
            is not ChengfengConnectionMode.OPERATIONAL_COMPAT
        ):
            raise ApiError(
                409,
                "connection_mode_mismatch",
                "请先切换到业务连接。",
            )

        if payload.business_scope == "settlement":
            if (
                settlement_capture_store is None
                or selected_settlement_contract is None
                or settlement_identity_context_sha256 is None
                or not settlement_capture_execution_available
            ):
                raise ApiError(
                    409,
                    "business_read_unavailable",
                    "成丰待结算读取尚未准备完成。",
                )
            conflict_key = "settlement_capture:operational_compat"
            try:
                started = settlement_capture_store.create_start(
                    target_kind=(
                        ShadowBatchTargetKind.OPERATIONAL_COMPAT
                    ),
                    session_id=session_id,
                    source_build_sha256=build_sha256,
                    contract_canonical_sha256=(
                        selected_settlement_contract
                        .manifest.canonical_sha256
                    ),
                    contract_file_sha256=(
                        selected_settlement_contract.contract_file_sha256
                    ),
                    contract_selection_sha256=(
                        selected_settlement_contract.selection_sha256
                    ),
                    identity_context_sha256=(
                        settlement_identity_context_sha256
                    ),
                    duration_minutes=720,
                    legacy_idle_confirmed=True,
                    no_settlement_or_payment_confirmed=True,
                    same_account_session_risk_accepted=True,
                    idempotency_key=idempotency_key,
                    request_hash=_request_hash(payload),
                    now=datetime.now(UTC),
                    capture_strategy="batch_v1",
                )
                job = job_repository.get_job(started.job_id)
                created = started.created
            except ActiveScopeConflictError:
                existing = job_repository.active_job_for_conflict_key(
                    conflict_key
                )
                if existing is None:
                    raise ApiError(
                        409,
                        "active_scope_conflict",
                        "同一范围的运单获取任务正在启动。",
                    ) from None
                job = existing
                created = False
            except IdempotencyConflictError as exc:
                raise ApiError(
                    409,
                    "idempotency_key_reused",
                    "This operation key belongs to another request.",
                ) from exc
            except SettlementCaptureStoreConflictError as exc:
                raise ApiError(
                    409,
                    "business_read_start_conflict",
                    str(exc),
                ) from exc
            items = job_repository.list_items(job.job_id)
            notify_scheduler()
            ensure_automatic_login(job.job_id)
            return {
                "created": created,
                "attached": not created,
                "job": project_job(
                    job,
                    items,
                    job_repository.runtime_projection(job.job_id),
                    expose_internal_codes=expose_internal_codes,
                ),
            }

        assert business_date is not None
        if selected_daily_contract is None or not daily_execution_available:
            raise ApiError(
                409,
                "business_read_unavailable",
                "装卸车读取尚未准备完成。",
            )
        daily_now = _daily_now()
        try:
            candidate_query_window(business_date, now=daily_now)
        except DailyDomainError as exc:
            raise ApiError(
                422,
                "daily_business_date_unavailable",
                "所选业务日尚未开始。请使用当前业务日或更早日期。",
            ) from exc
        conflict_key = f"daily:{business_date.isoformat()}"
        spec = ScheduledJobSpec(
            fixture_id=(
                (
                    "daily-operational-network-only-v1:"
                    if payload.network_only_measurement
                    else "daily-operational-batch-v1:"
                )
                + business_date.isoformat()
            ),
            job_kind="business",
            task_type="daily",
            scope_label=f"装卸车明细 {business_date.isoformat()}",
            conflict_key=conflict_key,
            items=(
                ScheduledWorkItemSpec(
                    item_key=f"daily:{business_date.isoformat()}",
                    expected_outcome=None,
                    required_resource="platform_browser",
                ),
            ),
            run_mode="operational",
        )
        created = False
        try:
            _active, start_version = (
                job_repository.fixture_start_state(conflict_key)
            )
            job, created = job_repository.create_scheduled_job(
                fixture=spec,
                scope_label=spec.scope_label,
                idempotency_key=idempotency_key,
                request_hash=_request_hash(payload),
                expected_record_version=start_version,
            )
        except ActiveScopeConflictError:
            existing = job_repository.active_job_for_conflict_key(
                conflict_key
            )
            if existing is None:
                raise ApiError(
                    409,
                    "active_scope_conflict",
                    "同一业务日的装卸车任务正在启动。",
                ) from None
            job = existing
        except (IdempotencyConflictError, RecordVersionConflictError) as exc:
            raise ApiError(
                409,
                "business_read_start_conflict",
                "装卸车任务状态已变化。请刷新后重试。",
            ) from exc

        access_key = f"business-read-access:{job.job_id}"
        access_hash = hashlib.sha256(
            f"daily:{job.job_id}:{business_date.isoformat()}".encode()
        ).hexdigest()
        try:
            grant, _replayed = access_repository.issue(
                purpose=AccessPurpose.PRODUCTION_SHADOW,
                job_id=job.job_id,
                session_id=session_id,
                build_sha256=build_sha256,
                duration_minutes=720,
                legacy_idle_confirmed=True,
                no_settlement_or_payment_confirmed=True,
                same_account_session_risk_accepted=True,
                run_mode="operational",
                idempotency_key=access_key,
                request_hash=access_hash,
                now=datetime.now(UTC),
            )
            try:
                invocation = daily_invocation_store.get_by_job(job.job_id)
            except DailyInvocationConflictError:
                invocation = None
            if invocation is None:
                start_key = f"business-read-daily:{job.job_id}"
                start_hash = hashlib.sha256(
                    f"daily-start:{job.job_id}:{grant.access_window_id}".encode()
                ).hexdigest()
                start_record, _ = daily_invocation_store.reserve_start(
                    idempotency_key=start_key,
                    request_hash=start_hash,
                    job_id=job.job_id,
                    access_window_id=grant.access_window_id,
                    now=datetime.now(UTC),
                )
                invocation = daily_invocation_store.create(
                    job_id=job.job_id,
                    access_window_id=grant.access_window_id,
                    authority=daily_invocation_authority(),
                    request=DailyCaptureRequest(
                        invocation_id=job.job_id,
                        business_date=business_date,
                        receive_place="榆林",
                        now=daily_now,
                        source_contract_sha256=(
                            selected_daily_contract
                            .manifest.canonical_sha256
                        ),
                        page_size=100,
                    ),
                    now=daily_now,
                )
                daily_invocation_store.complete_start(
                    idempotency_key=start_key,
                    expected_record_version=(
                        start_record.record_version
                    ),
                    invocation_id=invocation.invocation_id,
                    now=daily_now,
                )
        except (
            AccessWindowError,
            DailyCaptureError,
            DailyInvocationConflictError,
            PlatformAccessConflictError,
        ) as exc:
            raise ApiError(
                409,
                "business_read_start_conflict",
                "装卸车任务未能完整建立。",
            ) from exc
        items = job_repository.list_items(job.job_id)
        notify_scheduler()
        ensure_automatic_login(job.job_id)
        return {
            "created": created,
            "attached": not created,
            "job": project_job(
                job,
                items,
                job_repository.runtime_projection(job.job_id),
                expose_internal_codes=expose_internal_codes,
            ),
        }

    @router.post("/daily-jobs")
    def create_daily_job(
        payload: CreateDailyJobRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if (
            not enabled
            or selected_daily_contract is None
            or not daily_execution_available
        ):
            raise ApiError(
                409,
                "daily_capture_unavailable",
                "The daily read contract and execution backend are required.",
            )
        if not settlement_validation_gate_passed():
            raise ApiError(
                409,
                "daily_settlement_gate_required",
                "A successful read-only settlement validation is required.",
            )
        now = _daily_now()
        business_date = (
            business_date_for(now)
            if payload.scope == "current"
            else latest_completed_business_date(now)
        )
        conflict_key = f"daily:{business_date.isoformat()}"
        spec = ScheduledJobSpec(
            fixture_id="daily-capture-v1",
            job_kind="business",
            task_type="daily",
            scope_label=f"装卸车明细 {business_date.isoformat()}",
            conflict_key=conflict_key,
            items=(
                ScheduledWorkItemSpec(
                    item_key=f"daily:{business_date.isoformat()}",
                    expected_outcome=None,
                    required_resource="platform_browser",
                ),
            ),
        )
        try:
            job, created = job_repository.create_scheduled_job(
                fixture=spec,
                scope_label=spec.scope_label,
                idempotency_key=idempotency_key,
                request_hash=_request_hash(payload),
                expected_record_version=payload.expected_record_version,
            )
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "This operation key belongs to another request.",
            ) from exc
        except ActiveScopeConflictError as exc:
            raise ApiError(
                409,
                "active_scope_conflict",
                "A daily capture for this business date is already active.",
            ) from exc
        except RecordVersionConflictError as exc:
            raise ApiError(
                409,
                "record_version_conflict",
                "The daily start state changed. Refresh before retrying.",
            ) from exc
        items = job_repository.list_items(job.job_id)
        frozen_business_date = _daily_business_date_from_items(items)
        return {
            "created": created,
            "job": project_job(
                job,
                items,
                job_repository.runtime_projection(job.job_id),
                expose_internal_codes=expose_internal_codes,
            ),
            "daily_scope": {
                "business_date": frozen_business_date.isoformat(),
                "receive_place": "榆林",
            },
        }

    @router.post("/settlement-captures")
    def create_settlement_capture(
        payload: CreateSettlementCaptureRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if (
            not enabled
            or settlement_capture_store is None
            or selected_settlement_contract is None
            or settlement_identity_context_sha256 is None
            or not settlement_capture_execution_available
        ):
            raise ApiError(
                409,
                "settlement_capture_unavailable",
                "The formal read-only capture authorities are unavailable.",
            )
        target_kind = ShadowBatchTargetKind(payload.target_kind)
        if (
            payload.source_scope == "settled_history"
            and target_kind
            is not ShadowBatchTargetKind.CURRENT_LOCKED_50
        ):
            raise ApiError(
                409,
                "settlement_capture_scope_mismatch",
                "Only the locked set may use settled history.",
            )
        connection_mode = connection_mode_store.get().mode
        is_operational = (
            target_kind
            is ShadowBatchTargetKind.OPERATIONAL_COMPAT
        )
        if is_operational and (
            connection_mode
            is not ChengfengConnectionMode.OPERATIONAL_COMPAT
        ):
            raise ApiError(
                409,
                "connection_mode_mismatch",
                "请先切换到业务连接。",
            )
        if not is_operational and not settlement_validation_gate_passed():
            raise ApiError(
                409,
                "settlement_validation_gate_required",
                "A current read-only contract validation is required.",
            )
        if not is_operational:
            if verify_settlement_capture_prerequisites is None:
                raise ApiError(
                    409,
                    "settlement_capture_prerequisites_failed",
                    "The formal authorities are not ready.",
                )
            try:
                verify_settlement_capture_prerequisites(target_kind)
            except Exception as exc:
                raise ApiError(
                    409,
                    "settlement_capture_prerequisites_failed",
                    "The formal exclusion and contract authorities are not ready.",
                ) from exc
            if (
                connection_mode
                is not ChengfengConnectionMode.STRICT_SHADOW
            ):
                raise ApiError(
                    409,
                    "connection_mode_mismatch",
                    "请先切换到验证连接。",
                )
        try:
            now = datetime.now(UTC)
            compatibility_confirmation = (
                confirmation_sha256(
                    legacy_idle_confirmed=(
                        payload.legacy_idle_confirmed
                    ),
                    no_settlement_or_payment_confirmed=(
                        payload.no_settlement_or_payment_confirmed
                    ),
                    same_account_session_risk_accepted=(
                        payload.same_account_session_risk_accepted
                    ),
                )
                if is_operational
                else None
            )
            started = settlement_capture_store.create_start(
                target_kind=target_kind,
                source_scope=payload.source_scope,
                session_id=session_id,
                source_build_sha256=build_sha256,
                contract_canonical_sha256=(
                    selected_settlement_contract
                    .manifest.canonical_sha256
                ),
                contract_file_sha256=(
                    selected_settlement_contract.contract_file_sha256
                ),
                contract_selection_sha256=(
                    selected_settlement_contract.selection_sha256
                ),
                identity_context_sha256=(
                    settlement_identity_context_sha256
                ),
                duration_minutes=payload.duration_minutes,
                legacy_idle_confirmed=payload.legacy_idle_confirmed,
                no_settlement_or_payment_confirmed=(
                    payload.no_settlement_or_payment_confirmed
                ),
                same_account_session_risk_accepted=(
                    payload.same_account_session_risk_accepted
                ),
                idempotency_key=idempotency_key,
                request_hash=_request_hash(payload),
                now=now,
                business_session_confirmation_sha256=(
                    compatibility_confirmation
                ),
                business_session_expires_at=(
                    now + BUSINESS_SESSION_DURATION
                    if is_operational
                    else None
                ),
            )
            job = job_repository.get_job(started.job_id)
            items = job_repository.list_items(started.job_id)
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "This operation key belongs to another request.",
            ) from exc
        except ActiveScopeConflictError as exc:
            raise ApiError(
                409,
                "active_scope_conflict",
                "A capture for this formal target is already active.",
            ) from exc
        except (
            BusinessConnectionSessionError,
            SettlementCaptureStoreConflictError,
        ) as exc:
            raise ApiError(
                409,
                "settlement_capture_start_conflict",
                str(exc),
            ) from exc
        if not is_operational:
            notify_scheduler()
        compatibility_business_session = (
            business_session_store.latest(
                platform_session_id=session_id
            )
            if is_operational
            else None
        )
        if is_operational and compatibility_business_session is None:
            raise ApiError(
                409,
                "business_session_start_incomplete",
                "业务连接会话未能完整建立。",
            )
        return {
            "created": started.created,
            "job": project_job(
                job,
                items,
                job_repository.runtime_projection(started.job_id),
                expose_internal_codes=expose_internal_codes,
            ),
            "access_window": _window_payload(
                started.access_window,
                record_version=started.access_record_version,
                idempotent_replay=not started.created,
            ),
            "capture": {
                "target_kind": started.target_kind.value,
                "source_scope": started.invocation.scope,
                "status": started.invocation.status,
                "record_version": started.invocation.record_version,
            },
            "business_session": (
                _business_session_payload(
                    compatibility_business_session,
                    now=now,
                )
                if compatibility_business_session is not None
                else None
            ),
        }

    @router.post(
        "/settlement-captures/{job_id}/access-window"
    )
    def rebind_settlement_capture_access_window(
        job_id: str,
        payload: RebindSettlementCaptureAccessWindowRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if (
            not enabled
            or settlement_capture_store is None
            or selected_settlement_contract is None
            or not settlement_capture_execution_available
        ):
            raise ApiError(
                409,
                "settlement_capture_rollover_unavailable",
                "The formal read-only capture authorities are unavailable.",
            )
        try:
            with browser_lifecycle.hold():
                browser = browser_control.get(session_id)
                rollover = settlement_capture_store.rebind_access_window(
                    job_id=job_id,
                    new_access_window_id=payload.access_window_id,
                    expected_invocation_record_version=(
                        payload.expected_record_version
                    ),
                    expected_browser_record_version=browser.record_version,
                    session_id=session_id,
                    source_build_sha256=build_sha256,
                    contract_canonical_sha256=(
                        selected_settlement_contract
                        .manifest.canonical_sha256
                    ),
                    contract_file_sha256=(
                        selected_settlement_contract.contract_file_sha256
                    ),
                    contract_selection_sha256=(
                        selected_settlement_contract.selection_sha256
                    ),
                    idempotency_key=idempotency_key,
                    request_hash=_request_hash(payload),
                    now=datetime.now(UTC),
                )
            job = job_repository.get_job(job_id)
            items = job_repository.list_items(job_id)
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "This operation key belongs to another request.",
            ) from exc
        except (
            BrowserControlError,
            JobNotFoundError,
            SettlementCaptureStoreConflictError,
        ) as exc:
            raise ApiError(
                409,
                "settlement_capture_rollover_conflict",
                str(exc),
            ) from exc
        return {
            "idempotent_replay": rollover.idempotent_replay,
            "job": project_job(
                job,
                items,
                job_repository.runtime_projection(job_id),
                expose_internal_codes=expose_internal_codes,
            ),
            "capture": {
                "access_window_id": (
                    rollover.invocation.access_window_id
                ),
                "status": rollover.invocation.status,
                "record_version": (
                    rollover.invocation.record_version
                ),
            },
        }

    @router.post("/daily-captures")
    def start_daily_capture(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if (
            not enabled
            or selected_daily_contract is None
            or not daily_execution_available
        ):
            raise ApiError(
                409,
                "daily_capture_unavailable",
                "The daily read contract and execution backend are required.",
            )
        if not settlement_validation_gate_passed():
            raise ApiError(
                409,
                "daily_settlement_gate_required",
                "A successful read-only settlement validation is required.",
            )
        try:
            grant = access_repository.get(payload.access_window_id)
            job = job_repository.get_job(grant.job_id)
        except (
            PlatformAccessConflictError,
            JobNotFoundError,
        ) as exc:
            raise ApiError(
                409,
                "daily_capture_job_invalid",
                "The production-shadow window is not bound to a daily job.",
            ) from exc
        if (
            job.task_type != "daily"
            or job.job_kind != "business"
        ):
            raise ApiError(
                409,
                "daily_capture_job_invalid",
                "The production-shadow window is not bound to a daily job.",
            )
        try:
            items = job_repository.list_items(job.job_id)
            business_date = _daily_business_date_from_items(items)
        except (JobNotFoundError, ValueError) as exc:
            raise ApiError(
                409,
                "daily_capture_job_invalid",
                "The daily job has no valid frozen business-date target.",
            ) from exc
        request_hash = _request_hash(payload)
        try:
            start_record = daily_invocation_store.get_start(
                idempotency_key
            )
        except DailyInvocationConflictError as exc:
            raise ApiError(
                409,
                "daily_capture_start_invalid",
                "The saved daily capture start request is invalid.",
            ) from exc
        if start_record is not None and (
            start_record.request_hash != request_hash
            or start_record.job_id != job.job_id
            or start_record.access_window_id != payload.access_window_id
        ):
            raise ApiError(
                409,
                "idempotency_key_reused",
                "This operation key belongs to another request.",
            )
        try:
            existing_invocation = daily_invocation_store.get_by_job(
                job.job_id
            )
        except DailyInvocationConflictError:
            existing_invocation = None
        if (
            start_record is not None
            and start_record.status == "completed"
            and existing_invocation is None
        ):
            raise ApiError(
                409,
                "daily_capture_start_invalid",
                "The completed start request has no matching invocation.",
            )
        completed_replay = bool(
            existing_invocation is not None
            and start_record is not None
            and start_record.status == "completed"
        )
        if not completed_replay and not _daily_job_can_start(job, items):
            raise ApiError(
                409,
                "daily_capture_job_invalid",
                "The daily job is not in a startable state.",
            )
        if existing_invocation is not None:
            if (
                existing_invocation.access_window_id
                != payload.access_window_id
                or existing_invocation.invocation_id != job.job_id
            ):
                raise ApiError(
                    409,
                    "daily_capture_invocation_conflict",
                    "The daily job is already bound to another invocation.",
                )
            if start_record is None:
                if job.current_stage != "daily.list_page":
                    raise ApiError(
                        409,
                        "daily_capture_job_invalid",
                        "The daily job is no longer waiting to start.",
                    )
                try:
                    start_record, _ = (
                        daily_invocation_store.reserve_start(
                            idempotency_key=idempotency_key,
                            request_hash=request_hash,
                            job_id=job.job_id,
                            access_window_id=payload.access_window_id,
                            now=datetime.now(UTC),
                        )
                    )
                except DailyInvocationConflictError as exc:
                    raise ApiError(
                        409,
                        "daily_capture_start_conflict",
                        "The daily job already has another start request.",
                    ) from exc
            if start_record.status != "completed":
                try:
                    start_record = (
                        daily_invocation_store.complete_start(
                            idempotency_key=idempotency_key,
                            expected_record_version=(
                                start_record.record_version
                            ),
                            invocation_id=existing_invocation.invocation_id,
                            now=datetime.now(UTC),
                        )
                    )
                except DailyInvocationConflictError as exc:
                    raise ApiError(
                        409,
                        "daily_capture_start_conflict",
                        "The saved start request could not be completed.",
                    ) from exc
            return {
                "created": False,
                "job_id": job.job_id,
                "invocation_id": existing_invocation.invocation_id,
                "invocation_status": existing_invocation.status,
                "next_stage": (
                    None
                    if existing_invocation.next_stage is None
                    else existing_invocation.next_stage.value
                ),
                "record_version": existing_invocation.record_version,
                "idempotent_replay": True,
            }

        if job.current_stage != "daily.list_page":
            raise ApiError(
                409,
                "daily_capture_job_invalid",
                "The daily job is no longer waiting to start.",
            )
        authorize_daily_capture_window(
            payload.access_window_id,
            job_id=job.job_id,
        )
        record = browser_control.get(session_id)
        if (
            (
                start_record is None
                and record.record_version
                != payload.expected_record_version
            )
            or record.browser_lifecycle != "ready"
            or record.browser_control_mode != "idle"
            or not browser_runtime.running
        ):
            raise ApiError(
                409,
                "login_return_required",
                "Complete login and return browser control before capture.",
            )
        try:
            start_record, start_replay = (
                daily_invocation_store.reserve_start(
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    job_id=job.job_id,
                    access_window_id=payload.access_window_id,
                    now=datetime.now(UTC),
                )
            )
        except DailyInvocationConflictError as exc:
            raise ApiError(
                409,
                "daily_capture_start_conflict",
                "The daily job already has another start request.",
            ) from exc
        worker_id = f"daily-capture-preflight-{uuid4().hex}"
        acquired: BrowserControlRecord | None = None
        try:
            acquired = browser_control.acquire_automated(
                session_id=session_id,
                instance_id=instance_id,
                worker_id=worker_id,
                job_id=job.job_id,
                expected_record_version=record.record_version,
                now=datetime.now(UTC),
                ttl=timedelta(minutes=5),
            )
            if acquired.fencing_token is None:
                raise BrowserControlError(
                    "daily preflight has no fencing token"
                )
            observation = browser_runtime.prepare_daily()
            if not _daily_observation_matches_selection(
                observation,
                selected_daily_contract,
            ):
                raise BrowserRuntimeError(
                    "daily request shape does not match the selected contract",
                    code="browser_daily_response_contract_changed",
                )
            returned = browser_control.release_automated(
                session_id=session_id,
                instance_id=instance_id,
                worker_id=worker_id,
                job_id=job.job_id,
                control_epoch=acquired.control_epoch,
                fencing_token=acquired.fencing_token,
                now=datetime.now(UTC),
            )
        except (
            BrowserControlError,
            BrowserRuntimeError,
        ) as exc:
            if acquired is not None and acquired.fencing_token is not None:
                with contextlib.suppress(BrowserControlError):
                    browser_control.release_automated(
                        session_id=session_id,
                        instance_id=instance_id,
                        worker_id=worker_id,
                        job_id=job.job_id,
                        control_epoch=acquired.control_epoch,
                        fencing_token=acquired.fencing_token,
                        now=datetime.now(UTC),
                    )
            raise ApiError(
                409,
                "daily_capture_preflight_failed",
                "The daily read-only browser preflight failed safely.",
            ) from exc
        now = _daily_now()
        try:
            invocation = daily_invocation_store.create(
                job_id=job.job_id,
                access_window_id=payload.access_window_id,
                authority=daily_invocation_authority(),
                request=DailyCaptureRequest(
                    invocation_id=job.job_id,
                    business_date=business_date,
                    receive_place="榆林",
                    now=now,
                    source_contract_sha256=(
                        selected_daily_contract.manifest.canonical_sha256
                    ),
                    page_size=_FORMAL_DAILY_PAGE_SIZE,
                ),
                now=now,
            )
            start_record = daily_invocation_store.complete_start(
                idempotency_key=idempotency_key,
                expected_record_version=start_record.record_version,
                invocation_id=invocation.invocation_id,
                now=now,
            )
        except (
            DailyCaptureError,
            DailyInvocationConflictError,
        ) as exc:
            raise ApiError(
                409,
                "daily_capture_invocation_failed",
                "The daily capture invocation could not be created safely.",
            ) from exc
        notify_scheduler()
        return {
            "created": not start_replay,
            "job_id": job.job_id,
            "invocation_id": invocation.invocation_id,
            "invocation_status": invocation.status,
            "next_stage": (
                None
                if invocation.next_stage is None
                else invocation.next_stage.value
            ),
            "record_version": invocation.record_version,
            "browser_record_version": returned.record_version,
            "idempotent_replay": start_replay,
        }

    @router.post("/daily-captures/{job_id}/access-window")
    def rebind_daily_capture_access_window(
        job_id: str,
        payload: RebindSettlementCaptureAccessWindowRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if (
            not enabled
            or selected_daily_contract is None
            or selected_settlement_contract is None
            or not daily_execution_available
        ):
            raise ApiError(
                409,
                "daily_capture_rollover_unavailable",
                "The formal daily read authorities are unavailable.",
            )
        try:
            with browser_lifecycle.hold():
                browser = browser_control.get(session_id)
                rollover = daily_invocation_store.rebind_access_window(
                    job_id=job_id,
                    new_access_window_id=payload.access_window_id,
                    expected_invocation_record_version=(
                        payload.expected_record_version
                    ),
                    expected_browser_record_version=(
                        browser.record_version
                    ),
                    session_id=session_id,
                    authority=daily_invocation_authority(),
                    idempotency_key=idempotency_key,
                    request_hash=_request_hash(payload),
                    now=datetime.now(UTC),
                )
            job = job_repository.get_job(job_id)
            items = job_repository.list_items(job_id)
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "This operation key belongs to another request.",
            ) from exc
        except (
            BrowserControlError,
            DailyInvocationConflictError,
            JobNotFoundError,
        ) as exc:
            raise ApiError(
                409,
                "daily_capture_rollover_conflict",
                str(exc),
            ) from exc
        return {
            "idempotent_replay": rollover.idempotent_replay,
            "job": project_job(
                job,
                items,
                job_repository.runtime_projection(job_id),
                expose_internal_codes=expose_internal_codes,
            ),
            "capture": {
                "access_window_id": (
                    rollover.invocation.access_window_id
                ),
                "status": rollover.invocation.status,
                "record_version": (
                    rollover.invocation.record_version
                ),
            },
        }

    @router.post("/contract-validation")
    def validate_read_contract(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        if contract_validator is None:
            raise ApiError(
                409,
                "read_contract_candidate_required",
                "尚未选择经过封存的只读合同候选。",
            )
        try:
            stored_grant, _ = access_repository.get_with_version(
                payload.access_window_id
            )
            existing = contract_validator.existing_for_access_window(
                payload.access_window_id
            )
        except (
            LiveContractValidationError,
            PlatformAccessConflictError,
        ) as exc:
            raise ApiError(
                409,
                "read_contract_validation_evidence_invalid",
                "只读合同验证证据不可用。",
            ) from exc
        if (
            stored_grant.consumed_at is not None
            and stored_grant.session_id == session_id
            and stored_grant.build_sha256 == build_sha256
            and existing is not None
        ):
            return {
                "platform_session": _browser_payload(
                    browser_control.get(session_id),
                    runtime=browser_runtime,
                    idempotent_replay=True,
                ),
                "contract_validation": _contract_validation_payload(
                    existing,
                    idempotent_replay=True,
                ),
            }
        grant = authorize_validation_window(payload.access_window_id)
        record = browser_control.get(session_id)
        if (
            record.record_version != payload.expected_record_version
            or record.browser_lifecycle != "ready"
            or record.browser_control_mode != "idle"
            or not browser_runtime.running
        ):
            raise ApiError(
                409,
                "login_return_required",
                "请先完成登录并归还浏览器控制。",
            )
        worker_id = f"contract-validator-{uuid4().hex}"
        acquired_at = datetime.now(UTC)
        control_ttl = min(
            timedelta(minutes=5),
            grant.expires_at - acquired_at,
        )
        if control_ttl <= timedelta(0):
            raise ApiError(
                409,
                "access_window_rejected",
                "本次只读授权窗口已经到期。",
            )
        try:
            acquired = browser_control.acquire_automated(
                session_id=session_id,
                instance_id=instance_id,
                worker_id=worker_id,
                job_id=grant.job_id,
                expected_record_version=record.record_version,
                now=acquired_at,
                ttl=control_ttl,
            )
        except BrowserControlError as exc:
            raise ApiError(
                409,
                "browser_control_conflict",
                "浏览器状态已变化。请刷新后重试。",
            ) from exc
        if acquired.fencing_token is None:
            raise ApiError(
                409,
                "browser_control_conflict",
                "自动读取控制权无效。",
            )
        authority = BrowserCommandAuthority(
            session_id=session_id,
            instance_id=instance_id,
            worker_id=worker_id,
            job_id=grant.job_id,
            control_epoch=acquired.control_epoch,
            fencing_token=acquired.fencing_token,
        )
        result: LiveContractValidationResult | None = None
        validation_failure: Exception | None = None
        cleanup_failure: Exception | None = None
        stopped: BrowserControlRecord | None = None
        try:
            try:
                settlement_probe = browser_runtime.prepare_automated(
                    scope="current"
                )
                result = contract_validator.validate(
                    authority=authority,
                    access_window_id=payload.access_window_id,
                    build_sha256=build_sha256,
                    settlement_probe=settlement_probe,
                )
            except (
                BrowserRuntimeError,
                ChengfengReadError,
                LiveContractValidationError,
                PlatformReadAuditError,
            ) as exc:
                validation_failure = exc
        finally:
            with browser_lifecycle.hold():
                returned: BrowserControlRecord | None = None
                try:
                    returned = browser_control.release_automated(
                        session_id=session_id,
                        instance_id=instance_id,
                        worker_id=worker_id,
                        job_id=grant.job_id,
                        control_epoch=acquired.control_epoch,
                        fencing_token=acquired.fencing_token,
                        now=datetime.now(UTC),
                    )
                except Exception as exc:
                    cleanup_failure = exc
                try:
                    current_grant, window_version = (
                        access_repository.get_with_version(
                            payload.access_window_id
                        )
                    )
                    if current_grant.consumed_at is None:
                        access_repository.consume(
                            access_window_id=payload.access_window_id,
                            expected_record_version=window_version,
                            now=datetime.now(UTC),
                        )
                except Exception as exc:
                    cleanup_failure = cleanup_failure or exc
                try:
                    browser_runtime.close()
                except Exception as exc:
                    cleanup_failure = cleanup_failure or exc
                if returned is not None:
                    try:
                        stopped, _ = browser_control.mark_stopped(
                            session_id=session_id,
                            access_window_id=payload.access_window_id,
                            expected_record_version=returned.record_version,
                            idempotency_key=(
                                f"{idempotency_key}:validation-stop"
                            ),
                            request_hash=_request_hash(payload),
                            now=datetime.now(UTC),
                        )
                    except Exception as exc:
                        cleanup_failure = cleanup_failure or exc
        if validation_failure is not None:
            if isinstance(validation_failure, BrowserRuntimeError):
                reason, runtime_diagnostic = _SAFE_BROWSER_VALIDATION_FAILURES.get(
                    validation_failure.code,
                    (
                        "browser_runtime_failed",
                        "CF-BROWSER-RUNTIME-FAILED",
                    ),
                )
                runtime_log_store.append(
                    level="warning",
                    source="chengfeng-browser",
                    event_code="formal_read_browser_failed",
                    stream="application",
                    message=(
                        "Formal Chengfeng read stopped safely before completion "
                        f"({reason})."
                    ),
                    diagnostic_code=runtime_diagnostic,
                )
            elif isinstance(validation_failure, LiveContractValidationError):
                reason, validation_diagnostic = (
                    _SAFE_CONTRACT_VALIDATION_FAILURES.get(
                        validation_failure.code,
                        (
                            "validation_failed",
                            "CF-CONTRACT-VALIDATION-FAILED",
                        ),
                    )
                )
                runtime_log_store.append(
                    level="warning",
                    source="chengfeng-validator",
                    event_code="formal_read_validation_failed",
                    stream="application",
                    message=(
                        "Formal Chengfeng read validation stopped safely "
                        f"({reason})."
                    ),
                    diagnostic_code=validation_diagnostic,
                )
            elif isinstance(validation_failure, ChengfengReadError):
                runtime_log_store.append(
                    level="warning",
                    source="chengfeng-validator",
                    event_code="formal_read_connector_failed",
                    stream="application",
                    message=(
                        "Formal Chengfeng read stopped at connector stage "
                        f"({validation_failure.stage.value})."
                    ),
                    diagnostic_code=validation_failure.diagnostic_code,
                )
            elif isinstance(validation_failure, PlatformReadAuditError):
                runtime_log_store.append(
                    level="error",
                    source="chengfeng-validator",
                    event_code="formal_read_audit_invalid",
                    stream="application",
                    message=(
                        "Formal Chengfeng read stopped because its local "
                        "request-audit chain was invalid."
                    ),
                    diagnostic_code=(
                        "CF-PLATFORM-READ-AUDIT-INVALID"
                    ),
                )
            safe_discovery = (
                getattr(validation_failure, "safe_discovery", ())
                if isinstance(validation_failure, ChengfengReadError)
                else ()
            )
            if safe_discovery:
                try:
                    structure_evidence = discovery_evidence.seal(
                        observations=[
                            dict(observation)
                            for observation in safe_discovery
                        ],
                        build_sha256=build_sha256,
                        access_window_id=payload.access_window_id,
                        captured_at=datetime.now(UTC),
                    )
                    runtime_log_store.append(
                        level="warning",
                        source="chengfeng-validator",
                        event_code="request_structure_evidence_sealed",
                        stream="application",
                        message=(
                            "Changed Chengfeng request structure was sealed "
                            f"as development evidence "
                            f"({structure_evidence.canonical_sha256})."
                        ),
                        diagnostic_code=(
                            "CF-CONTRACT-REQUEST-STRUCTURE-CHANGED"
                        ),
                    )
                except DiscoveryEvidenceError:
                    runtime_log_store.append(
                        level="error",
                        source="chengfeng-validator",
                        event_code="request_structure_evidence_failed",
                        stream="application",
                        message=(
                            "Changed Chengfeng request structure could not "
                            "be sealed."
                        ),
                        diagnostic_code=(
                            "CF-CONTRACT-REQUEST-STRUCTURE-EVIDENCE-FAILED"
                        ),
                    )
            diagnostic_code = (
                validation_failure.diagnostic_code
                if isinstance(validation_failure, ChengfengReadError)
                else None
            )
            message = "只读合同验证未通过，未进入正式采集。"  # noqa: RUF001
            if diagnostic_code is not None:
                message = f"{message} 诊断编号：{diagnostic_code}。"  # noqa: RUF001
            raise ApiError(
                409,
                "read_contract_validation_failed",
                message,
            ) from validation_failure
        if cleanup_failure is not None or stopped is None or result is None:
            raise ApiError(
                409,
                "read_contract_validation_cleanup_failed",
                "验证结束后的浏览器状态未能安全封存。",
            ) from cleanup_failure
        return {
            "platform_session": _browser_payload(
                stopped,
                runtime=browser_runtime,
                idempotent_replay=False,
            ),
            "contract_validation": _contract_validation_payload(
                result,
                idempotent_replay=False,
            ),
        }

    @router.post("/daily-contract-discovery")
    def discover_daily_read_contract(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        try:
            stored_grant, _ = access_repository.get_with_version(
                payload.access_window_id
            )
            existing_evidence = discovery_evidence.existing_for_access_window(
                payload.access_window_id
            )
            existing_selection = load_selected_daily_read_contract(data_root)
        except DailyContractSelectionError:
            existing_selection = None
        except (
            DiscoveryEvidenceError,
            PlatformAccessConflictError,
        ) as exc:
            raise ApiError(
                409,
                "daily_contract_evidence_invalid",
                "Daily read-contract evidence is unavailable or invalid.",
            ) from exc
        if stored_grant.consumed_at is not None:
            if (
                stored_grant.session_id != session_id
                or stored_grant.build_sha256 != build_sha256
                or existing_evidence is None
                or existing_selection is None
                or existing_selection.manifest.source_discovery_sha256
                != existing_evidence.canonical_sha256
            ):
                raise ApiError(
                    409,
                    "daily_contract_evidence_invalid",
                    "Daily read-contract evidence is unavailable or invalid.",
                )
            return {
                "platform_session": _browser_payload(
                    browser_control.get(session_id),
                    runtime=browser_runtime,
                    idempotent_replay=True,
                ),
                "daily_contract": _daily_contract_payload(
                    evidence=existing_evidence,
                    selected=existing_selection,
                    idempotent_replay=True,
                ),
            }

        grant = authorize_discovery_window(payload.access_window_id)
        record = browser_control.get(session_id)
        if (
            record.record_version != payload.expected_record_version
            or record.browser_lifecycle != "ready"
            or record.browser_control_mode != "idle"
            or not browser_runtime.running
        ):
            raise ApiError(
                409,
                "login_return_required",
                "Complete login and return browser control before discovery.",
            )
        worker_id = f"daily-contract-discovery-{uuid4().hex}"
        acquired_at = datetime.now(UTC)
        control_ttl = min(
            timedelta(minutes=5),
            grant.expires_at - acquired_at,
        )
        if control_ttl <= timedelta(0):
            raise ApiError(
                409,
                "access_window_rejected",
                "The read-only access window has expired.",
            )
        try:
            acquired = browser_control.acquire_automated(
                session_id=session_id,
                instance_id=instance_id,
                worker_id=worker_id,
                job_id=grant.job_id,
                expected_record_version=record.record_version,
                now=acquired_at,
                ttl=control_ttl,
            )
        except BrowserControlError as exc:
            raise ApiError(
                409,
                "browser_control_conflict",
                "Browser control changed. Refresh before retrying.",
            ) from exc
        if acquired.fencing_token is None:
            raise ApiError(
                409,
                "browser_control_conflict",
                "Automated browser control is invalid.",
            )

        evidence: DiscoveryEvidenceResult | None = None
        frozen: DailyContractFreezeResult | None = None
        discovery_failure: Exception | None = None
        cleanup_failure: Exception | None = None
        stopped: BrowserControlRecord | None = None
        try:
            try:
                observation = browser_runtime.prepare_daily()
                evidence = discovery_evidence.seal(
                    observations=[observation],
                    build_sha256=build_sha256,
                    access_window_id=payload.access_window_id,
                    captured_at=datetime.now(UTC),
                )
                frozen = freeze_daily_read_contract(
                    discovery_evidence_path=evidence.path,
                    data_root=data_root,
                )
            except (
                BrowserRuntimeError,
                DiscoveryEvidenceError,
                DailyContractFreezeError,
            ) as exc:
                discovery_failure = exc
        finally:
            with browser_lifecycle.hold():
                returned: BrowserControlRecord | None = None
                try:
                    returned = browser_control.release_automated(
                        session_id=session_id,
                        instance_id=instance_id,
                        worker_id=worker_id,
                        job_id=grant.job_id,
                        control_epoch=acquired.control_epoch,
                        fencing_token=acquired.fencing_token,
                        now=datetime.now(UTC),
                    )
                except Exception as exc:
                    cleanup_failure = exc
                try:
                    current_grant, window_version = (
                        access_repository.get_with_version(
                            payload.access_window_id
                        )
                    )
                    if current_grant.consumed_at is None:
                        access_repository.consume(
                            access_window_id=payload.access_window_id,
                            expected_record_version=window_version,
                            now=datetime.now(UTC),
                        )
                except Exception as exc:
                    cleanup_failure = cleanup_failure or exc
                try:
                    browser_runtime.close()
                except Exception as exc:
                    cleanup_failure = cleanup_failure or exc
                if returned is not None:
                    try:
                        stopped, _ = browser_control.mark_stopped(
                            session_id=session_id,
                            access_window_id=payload.access_window_id,
                            expected_record_version=returned.record_version,
                            idempotency_key=(
                                f"{idempotency_key}:daily-contract-stop"
                            ),
                            request_hash=_request_hash(payload),
                            now=datetime.now(UTC),
                        )
                    except Exception as exc:
                        cleanup_failure = cleanup_failure or exc

        if discovery_failure is not None:
            diagnostic_code = (
                discovery_failure.code
                if isinstance(discovery_failure, BrowserRuntimeError)
                else "CF-DAILY-CONTRACT-DISCOVERY-FAILED"
            )
            safe_discovery = (
                discovery_failure.safe_discovery
                if isinstance(discovery_failure, BrowserRuntimeError)
                else ()
            )
            if safe_discovery:
                try:
                    structure_evidence = discovery_evidence.seal(
                        observations=[
                            dict(observation)
                            for observation in safe_discovery
                        ],
                        build_sha256=build_sha256,
                        access_window_id=payload.access_window_id,
                        captured_at=datetime.now(UTC),
                    )
                    runtime_log_store.append(
                        level="warning",
                        source="chengfeng-browser",
                        event_code="daily_contract_change_evidence_sealed",
                        stream="application",
                        message=(
                            "Changed daily read structure was sealed as "
                            "development evidence "
                            f"({structure_evidence.canonical_sha256})."
                        ),
                        diagnostic_code=(
                            "CF-DAILY-CONTRACT-STRUCTURE-CHANGED"
                        ),
                    )
                except DiscoveryEvidenceError:
                    runtime_log_store.append(
                        level="error",
                        source="chengfeng-browser",
                        event_code="daily_contract_change_evidence_failed",
                        stream="application",
                        message=(
                            "Changed daily read structure could not be sealed."
                        ),
                        diagnostic_code=(
                            "CF-DAILY-CONTRACT-STRUCTURE-EVIDENCE-FAILED"
                        ),
                    )
            runtime_log_store.append(
                level="warning",
                source="chengfeng-browser",
                event_code="daily_contract_discovery_failed",
                stream="application",
                message=(
                    "Daily read-contract discovery stopped safely before "
                    "completion."
                ),
                diagnostic_code=diagnostic_code,
            )
            raise ApiError(
                409,
                "daily_contract_discovery_failed",
                "Daily read-contract discovery did not pass its safety checks.",
            ) from discovery_failure
        if (
            cleanup_failure is not None
            or stopped is None
            or evidence is None
            or frozen is None
        ):
            raise ApiError(
                409,
                "daily_contract_discovery_cleanup_failed",
                "Daily discovery could not be closed and sealed safely.",
            ) from cleanup_failure
        try:
            selected = select_daily_read_contract(
                data_root=data_root,
                frozen=frozen,
            )
        except DailyContractSelectionError as exc:
            raise ApiError(
                409,
                "daily_contract_discovery_failed",
                "Daily read-contract discovery did not pass its safety checks.",
            ) from exc
        return {
            "platform_session": _browser_payload(
                stopped,
                runtime=browser_runtime,
                idempotent_replay=False,
            ),
            "daily_contract": _daily_contract_payload(
                evidence=evidence,
                selected=selected,
                idempotent_replay=False,
            ),
        }

    @router.post("/discovery/start")
    def start_discovery_capture(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        authorize_discovery_window(payload.access_window_id)
        with browser_lifecycle.hold():
            record = browser_control.get(session_id)
            if record.record_version != payload.expected_record_version:
                raise ApiError(
                    409,
                    "browser_control_conflict",
                    "浏览器状态已变化。请刷新后重试。",
                )
            replay_candidate = bool(
                record.browser_control_mode == "human_handoff"
                and browser_runtime.discovery_capturing
            )
            if not replay_candidate and (
                record.browser_lifecycle != "ready"
                or record.browser_control_mode != "idle"
                or not browser_runtime.running
            ):
                raise ApiError(
                    409,
                    "login_return_required",
                    "请先完成登录并归还浏览器控制。",
                )
            started_capture = False
            try:
                if not replay_candidate:
                    browser_runtime.start_discovery_capture()
                    started_capture = True
                updated, replay = (
                    browser_control.acquire_human_session_control(
                        session_id=session_id,
                        control_mode="human_handoff",
                        human_session_id=payload.access_window_id,
                        expected_record_version=record.record_version,
                        idempotency_key=idempotency_key,
                        request_hash=_request_hash(payload),
                        now=datetime.now(UTC),
                    )
                )
            except (BrowserRuntimeError, BrowserControlError) as exc:
                if started_capture and browser_runtime.discovery_capturing:
                    try:
                        browser_runtime.stop_discovery_capture()
                    except BrowserRuntimeError:
                        browser_runtime.close()
                raise ApiError(
                    409,
                    "contract_discovery_start_failed",
                    str(exc),
                ) from exc
            return {
                "platform_session": _browser_payload(
                    updated,
                    runtime=browser_runtime,
                    idempotent_replay=replay,
                )
            }

    @router.post("/discovery/stop")
    def stop_discovery_capture(
        payload: HumanLoginControlRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        try:
            grant, _ = access_repository.get_with_version(payload.access_window_id)
            prior = discovery_evidence.existing_for_access_window(payload.access_window_id)
            if (
                grant.consumed_at is not None
                and grant.session_id == session_id
                and grant.build_sha256 == build_sha256
                and prior is not None
            ):
                return {
                    "platform_session": _browser_payload(
                        browser_control.get(session_id),
                        runtime=browser_runtime,
                        idempotent_replay=True,
                    ),
                    "discovery_evidence": _discovery_payload(
                        prior,
                        idempotent_replay=True,
                    ),
                }
            authorize_discovery_window(payload.access_window_id)
            existing = discovery_evidence.existing_for_access_window(payload.access_window_id)
            if existing is None:
                record = browser_control.get(session_id)
                if (
                    record.browser_control_mode != "human_handoff"
                    or record.record_version != payload.expected_record_version
                ):
                    raise BrowserControlError("discovery browser control does not match")
                observations = browser_runtime.stop_discovery_capture()
                existing = discovery_evidence.seal(
                    observations=observations,
                    build_sha256=build_sha256,
                    access_window_id=payload.access_window_id,
                    captured_at=datetime.now(UTC),
                )
                evidence_replay = False
            else:
                evidence_replay = True
            with browser_lifecycle.hold():
                record = browser_control.get(session_id)
                if record.browser_control_mode == "human_handoff":
                    record, _ = (
                        browser_control.return_human_session_control(
                            session_id=session_id,
                            human_session_id=payload.access_window_id,
                            expected_record_version=(
                                payload.expected_record_version
                            ),
                            idempotency_key=f"{idempotency_key}:return",
                            request_hash=_request_hash(payload),
                            now=datetime.now(UTC),
                        )
                    )
                grant, window_version = (
                    access_repository.get_with_version(
                        payload.access_window_id
                    )
                )
                if grant.consumed_at is None:
                    access_repository.consume(
                        access_window_id=payload.access_window_id,
                        expected_record_version=window_version,
                        now=datetime.now(UTC),
                    )
                browser_runtime.close()
                stopped, replay = browser_control.mark_stopped(
                    session_id=session_id,
                    access_window_id=payload.access_window_id,
                    expected_record_version=record.record_version,
                    idempotency_key=f"{idempotency_key}:stop",
                    request_hash=_request_hash(payload),
                    now=datetime.now(UTC),
                )
        except (
            BrowserRuntimeError,
            BrowserControlError,
            DiscoveryEvidenceError,
            PlatformAccessConflictError,
        ) as exc:
            raise ApiError(409, "contract_discovery_stop_failed", str(exc)) from exc
        return {
            "platform_session": _browser_payload(
                stopped,
                runtime=browser_runtime,
                idempotent_replay=replay,
            ),
            "discovery_evidence": _discovery_payload(
                existing,
                idempotent_replay=evidence_replay,
            ),
        }

    @router.post("/session/close")
    def close_platform_session(
        payload: ClosePlatformSessionRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        with browser_lifecycle.hold():
            try:
                grant, window_version = (
                    access_repository.get_with_version(
                        payload.access_window_id
                    )
                )
                if (
                    grant.session_id != session_id
                    or grant.build_sha256 != build_sha256
                ):
                    raise PlatformAccessConflictError(
                        "access window does not match this session"
                    )
                record = browser_control.get(session_id)
                if record.browser_control_mode in {
                    "human_login",
                    "human_handoff",
                }:
                    record, _ = (
                        browser_control.return_human_session_control(
                            session_id=session_id,
                            human_session_id=payload.access_window_id,
                            expected_record_version=(
                                payload.expected_record_version
                            ),
                            idempotency_key=f"{idempotency_key}:return",
                            request_hash=_request_hash(payload),
                            now=datetime.now(UTC),
                        )
                    )
                    stop_expected_version = record.record_version
                else:
                    if (
                        grant.consumed_at is None
                        and record.record_version
                        != payload.expected_record_version
                    ):
                        raise BrowserControlError(
                            "browser control record version is stale"
                        )
                    stop_expected_version = (
                        payload.expected_record_version
                    )
                if grant.consumed_at is None:
                    access_repository.consume(
                        access_window_id=payload.access_window_id,
                        expected_record_version=window_version,
                        now=datetime.now(UTC),
                    )
                browser_runtime.close()
                stopped, replay = browser_control.mark_stopped(
                    session_id=session_id,
                    access_window_id=payload.access_window_id,
                    expected_record_version=stop_expected_version,
                    idempotency_key=f"{idempotency_key}:stop",
                    request_hash=_request_hash(payload),
                    now=datetime.now(UTC),
                )
            except (
                PlatformAccessConflictError,
                BrowserControlError,
            ) as exc:
                raise ApiError(
                    409,
                    "platform_session_close_conflict",
                    str(exc),
                ) from exc
        return {
            "platform_session": _browser_payload(
                stopped,
                runtime=browser_runtime,
                idempotent_replay=replay,
            )
        }

    return router
