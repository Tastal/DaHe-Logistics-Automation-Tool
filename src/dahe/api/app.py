from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import secrets
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.responses import Response
from starlette.staticfiles import StaticFiles

from dahe import __version__
from dahe.adapters.chengfeng.browser_gate import (
    SqliteBrowserNavigationAuthorizer,
)
from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeLifecycle,
    BrowserRuntimeLifecycleGuard,
    IsolatedBrowserRuntime,
    default_browser_runtime_root,
)
from dahe.adapters.chengfeng.daily_contract_selection import (
    SelectedDailyReadContract,
    load_selected_daily_read_contract,
)
from dahe.adapters.chengfeng.daily_live_adapter import (
    ChengfengDailyContractValidationSource,
)
from dahe.adapters.chengfeng.discovery import DiscoveryEvidenceStore
from dahe.adapters.chengfeng.live_connector_runtime import LiveConnectorRuntime
from dahe.adapters.chengfeng.live_contract_selection import (
    SelectedLiveReadContract,
    load_selected_live_read_contract,
)
from dahe.adapters.chengfeng.live_contract_validation import (
    LiveContractValidationPort,
    LiveContractValidationRunner,
)
from dahe.adapters.chengfeng.verified_connector import (
    VerifiedChengfengConnector,
)
from dahe.adapters.fake.audit import (
    FIXTURE_ID,
    NORMAL_AUDIT_JOB_SPEC,
)
from dahe.adapters.fake.loop3 import LOOP3_FIXTURES, get_loop3_fixture
from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditEvidenceStore,
)
from dahe.adapters.files.settlement_capture_manifest import (
    SettlementCaptureManifestStore,
)
from dahe.adapters.files.shadow_batch_manifest import (
    ContentAddressedShadowImageReader,
    ShadowBatchManifestStore,
)
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
)
from dahe.adapters.sqlite.audit_workflow import SqliteAuditWorkflowRepository
from dahe.adapters.sqlite.browser_control import (
    BrowserControlError,
    BrowserControlStore,
)
from dahe.adapters.sqlite.business_connection import (
    SqliteBusinessConnectionSessionStore,
)
from dahe.adapters.sqlite.chengfeng_capture import SqliteChengfengCaptureStore
from dahe.adapters.sqlite.daily_invocation_store import (
    SqliteDailyInvocationStore,
)
from dahe.adapters.sqlite.daily_items import SqliteDailyItemRepository
from dahe.adapters.sqlite.daily_operational_ocr import (
    SqliteDailyOperationalOcrStore,
)
from dahe.adapters.sqlite.daily_reports import SqliteDailyReportRepository
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.locked_set_review import (
    SqliteLockedSetReviewRepository,
)
from dahe.adapters.sqlite.platform_access import SqlitePlatformAccessRepository
from dahe.adapters.sqlite.platform_credentials import (
    SqlitePlatformCredentialConfigStore,
)
from dahe.adapters.sqlite.production_guard import ProductionReadOnlyGuardStore
from dahe.adapters.sqlite.recovery import PersistentRecoveryStore
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.settlement_capture import (
    SqliteSettlementCaptureStore,
)
from dahe.adapters.sqlite.template_studio import SqliteTemplateRepository
from dahe.adapters.windows.credential_manager import WindowsCredentialVault
from dahe.api.audit_workflow import build_audit_workflow_router
from dahe.api.daily_items import build_daily_item_router
from dahe.api.daily_reports import build_daily_report_router
from dahe.api.errors import ApiError
from dahe.api.locked_set_review import build_locked_set_review_router
from dahe.api.loop9_review import (
    Loop9ReviewWorkspace,
    build_loop9_review_router,
)
from dahe.api.performance_settings import (
    PerformanceSettingsRecord,
    PerformanceSettingsRepository,
    build_performance_settings_router,
)
from dahe.api.platform import build_platform_router
from dahe.api.template_studio import build_template_studio_router
from dahe.application.audit.local_ocr_decision import LocalOcrAuditEvaluator
from dahe.application.audit.offline_batch import load_loop8_offline_batch
from dahe.application.audit.projections import (
    project_item,
    project_job,
    project_resources,
)
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.application.chengfeng.browser_readiness import (
    reconcile_operational_browser_readiness,
)
from dahe.application.chengfeng.connection_mode import (
    ChengfengConnectionModeStore,
)
from dahe.application.chengfeng.credential_service import (
    PlatformCredentialService,
)
from dahe.application.chengfeng.durable_capture import (
    DurableChengfengCaptureCoordinator,
)
from dahe.application.chengfeng.expiry_reconciler import (
    PlatformAccessExpiryReconciler,
)
from dahe.application.chengfeng.identity_authority import (
    Loop9IdentityAuthority,
    load_or_create_loop9_identity_authority,
)
from dahe.application.chengfeng.operational_capture import (
    FastOperationalSettlementCaptureCoordinator,
    OperationalSettlementCaptureCoordinator,
    load_complete_operational_checkpoints,
    scheduled_job_from_operational_batch,
    scheduled_job_from_operational_checkpoints,
)
from dahe.application.chengfeng.settlement_capture import (
    PaginatedSettlementCaptureCoordinator,
    SettlementCaptureContractError,
    SettlementCaptureInvocationPort,
    SettlementCaptureInvocationView,
    SettlementCaptureManifest,
)
from dahe.application.chengfeng.settlement_live_execution import (
    SettlementCaptureLiveStageExecutor,
)
from dahe.application.chengfeng.shadow_batch import ShadowBatchTargetKind
from dahe.application.chengfeng.shadow_job_source import (
    ChengfengShadowJobSource,
    ChengfengShadowJobSourceError,
    ChengfengShadowJobSourceResolver,
    ShadowJobExecutionAuthority,
)
from dahe.application.chengfeng.transient_progress import (
    TransientBusinessProgressStore,
)
from dahe.application.daily.live_execution import DailyLiveStageExecutor
from dahe.application.daily.operational_capture import (
    FastOperationalDailyCaptureCoordinator,
)
from dahe.application.template_studio.development_evaluation import (
    default_development_policy,
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
    current_template_pipeline_build_fingerprint,
)
from dahe.application.template_studio.operational_bundle import (
    OperationalTemplateBundleError,
    load_operational_template_bundle,
)
from dahe.config.paths import resolve_desktop_directory
from dahe.diagnostics.breadcrumbs import BreadcrumbStore
from dahe.diagnostics.outbox_bridge import RuntimeOutboxLogBridge
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.diagnostics.support_bundle import (
    build_support_bundle,
    environment_snapshot,
)
from dahe.jobs.actions import (
    ProtectedStartActionFacts,
    build_protected_start_action_matrix,
    build_start_action_matrix,
    serialize_actions,
)
from dahe.jobs.daily_execution import AsyncDailyExecutionBackend
from dahe.jobs.models import JobRecord, JobStatus
from dahe.jobs.ocr_execution import AsyncOcrExecutionBackend
from dahe.jobs.scheduler import CooperativeScheduler, CooperativeSchedulerRunner
from dahe.jobs.settlement_capture_execution import (
    AsyncSettlementCaptureExecutionBackend,
)
from dahe.jobs.specs import ScheduledJobSpec
from dahe.ports.chengfeng import BrowserCommandAuthority
from dahe.ports.jobs import (
    ActiveScopeConflictError,
    IdempotencyConflictError,
    JobControlError,
    JobNotFoundError,
    RecordVersionConflictError,
)
from dahe.ports.platform_credentials import PlatformCredentialVault
from dahe.release.identity import ReleaseIdentity, load_release_identity
from dahe.release.update_service import UpdateInstallBlocked, UpdateService
from dahe.system.instance_lifecycle import ApplicationInstanceLifecycle
from dahe.system.supervision import OwnedProcessSupervisor
from dahe.verification.locked_set_review_package import (
    load_locked_set_review_package,
)
from dahe.verification.loop9_exclusion_authority import (
    Loop9VerifiedExclusionSnapshot,
    load_verified_loop9_exclusion_snapshot_from_persisted_authority,
)
from dahe.verification.loop9_human_review import (
    load_loop9_review_package,
)

API_VERSION = "v1"
SESSION_COOKIE = "dahe_local_session"
_UPDATE_BLOCKING_JOB_STATUSES = frozenset(
    {
        JobStatus.CREATED,
        JobStatus.QUEUED,
        JobStatus.RUNNING,
        JobStatus.WAITING_RESOURCE,
        JobStatus.WAITING_EXTERNAL,
        JobStatus.RETRY_WAIT,
        JobStatus.PAUSE_REQUESTED,
        JobStatus.PAUSED,
        JobStatus.CANCEL_REQUESTED,
    }
)


def _count_update_blocking_jobs(jobs: Sequence[JobRecord]) -> int:
    return sum(job.status in _UPDATE_BLOCKING_JOB_STATUSES for job in jobs)


class JobScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=200)
    fixture_id: Literal[
        "audit-normal-001",
        "audit-batch-long-001",
        "audit-batch-short-002",
        "loading-probe-001",
    ]


class ChengfengShadowSourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_kind: Literal["current_locked_50", "real_shadow_30"]
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CreateJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_source: Literal["fixture", "chengfeng_shadow"] = "fixture"
    task_type: Literal["audit", "loading_probe"]
    job_kind: Literal["business", "test_fixture"] = "business"
    scope: JobScopeRequest | None = None
    chengfeng_shadow: ChengfengShadowSourceRequest | None = None
    expected_record_version: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_input_source(self) -> CreateJobRequest:
        if self.input_source == "fixture":
            if self.scope is None or self.chengfeng_shadow is not None:
                raise ValueError("fixture input requires scope and forbids Chengfeng source")
        elif self.scope is not None or self.chengfeng_shadow is None:
            raise ValueError(
                "Chengfeng input requires one protected source and forbids fixture scope"
            )
        return self


class ControlJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=1)


class BreadcrumbRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: Literal["settlement", "daily", "history", "system"]
    action_type: Literal["page_opened"]


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def _request_hash(request: CreateJobRequest) -> str:
    payload = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _control_request_hash(
    job_id: str,
    action: str,
    request: ControlJobRequest,
) -> str:
    payload = json.dumps(
        {
            "job_id": job_id,
            "action": action,
            **request.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def format_sse_message(event: dict[str, object]) -> str:
    """Encode a default SSE message so browser EventSource.onmessage receives it."""
    event_id = int(str(event["event_id"]))
    event_json = json.dumps(
        event,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"id: {event_id}\ndata: {event_json}\n\n"


def _create_locked_set_review_app(
    *,
    data_root: Path,
    project_root: Path,
    instance_id: str,
    previous_instance_id: str | None,
    static_dir: Path | None,
    host: str,
    port: int,
    loop9_review_package_path: Path | None = None,
) -> FastAPI:
    """Build the isolated human-review surface without business runtimes."""

    canonical_host = f"{host}:{port}"
    canonical_origin = f"http://{host}:{port}"
    resolved_static_dir: Path | None = None
    if static_dir is not None:
        resolved_static_dir = static_dir.resolve(strict=True)
        if not resolved_static_dir.is_dir():
            raise ValueError("static_dir must be a directory")
    legacy_package = (
        load_locked_set_review_package(data_root) if loop9_review_package_path is None else None
    )
    loop9_package = (
        load_loop9_review_package(loop9_review_package_path)
        if loop9_review_package_path is not None
        else None
    )
    if legacy_package is not None:
        package_sha256 = legacy_package.canonical_sha256
    else:
        assert loop9_package is not None
        package_sha256 = cast(
            str,
            loop9_package.payload["canonical_sha256"],
        )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=instance_id,
    )
    try:
        review_repository = SqliteLockedSetReviewRepository(
            runtime=runtime,
            package_sha256=package_sha256,
        )
    except BaseException:
        runtime.close()
        raise
    recovery_store = PersistentRecoveryStore(
        runtime.engine,
        runtime.commit_gate,
    )
    instance_lifecycle = ApplicationInstanceLifecycle(
        recovery_store,
        instance_id=instance_id,
        data_root=data_root,
        application_version=__version__,
        port=port,
    )
    session_secret = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        lifecycle_started = False
        try:
            instance_lifecycle.start()
            lifecycle_started = True
            if previous_instance_id is not None:
                recovery_store.mark_instance_crashed(
                    instance_id=previous_instance_id,
                    replacement_instance_id=instance_id,
                    data_root_identity=instance_lifecycle.data_root_identity,
                    single_instance_proof=True,
                    now=datetime.now(UTC),
                )
            yield
        finally:
            try:
                if lifecycle_started:
                    instance_lifecycle.close()
            finally:
                runtime.close()

    app = FastAPI(
        title=(
            "DaHe Logistics Loop 9 Review API"
            if loop9_package is not None
            else "DaHe Logistics Locked-set Review API"
        ),
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.state.instance_lifecycle = instance_lifecycle
    app.state.locked_set_review_package = legacy_package
    app.state.loop9_review_package = loop9_package
    app.state.locked_set_review_repository = review_repository

    @app.exception_handler(ApiError)
    async def handle_api_error(_: Request, exc: ApiError) -> JSONResponse:
        return _error(exc.status_code, exc.code, exc.message)

    @app.middleware("http")
    async def protect_local_boundary(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_host = request.headers.get("host")
        if request_host != canonical_host:
            return _error(400, "invalid_local_host", "本地访问地址无效")
        if request.url.path.startswith("/api/"):
            client_version = request.headers.get("x-dahe-client-version")
            if (
                client_version is None
                and request.method == "GET"
                and (
                    request.url.path == "/api/v1/events"
                    or request.url.path.startswith("/api/v1/locked-set-review/images/")
                    or request.url.path.startswith("/api/v1/loop9-review/images/")
                )
            ):
                client_version = request.query_params.get("client_version")
            if client_version != __version__:
                return _error(
                    409,
                    "client_version_mismatch",
                    "页面版本已过期。请刷新后重试",
                )
            origin = request.headers.get("origin")
            if origin is not None and origin != canonical_origin:
                return _error(
                    403,
                    "invalid_local_origin",
                    "本地页面来源无效",
                )
        response = await call_next(request)
        response.headers["X-DaHe-Application-Version"] = __version__
        response.headers["X-DaHe-API-Version"] = API_VERSION
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data: blob:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    def require_session(request: Request) -> None:
        supplied = request.cookies.get(SESSION_COOKIE)
        if supplied is None or not secrets.compare_digest(
            supplied,
            session_secret,
        ):
            raise ApiError(
                403,
                "local_session_required",
                "本地会话已失效。请刷新页面",
            )

    def require_write(
        request: Request,
        x_csrf_token: str | None = Header(default=None),
        x_idempotency_key: str | None = Header(default=None),
        standard_idempotency_key: str | None = Header(
            default=None,
            alias="Idempotency-Key",
        ),
    ) -> str:
        supplied_session = request.cookies.get(SESSION_COOKIE)
        session_ok = supplied_session is not None and secrets.compare_digest(
            supplied_session, session_secret
        )
        csrf_ok = x_csrf_token is not None and secrets.compare_digest(x_csrf_token, csrf_token)
        origin_ok = request.headers.get("origin") == canonical_origin
        normalized_x_key = None if x_idempotency_key is None else x_idempotency_key.strip()
        normalized_standard_key = (
            None if standard_idempotency_key is None else standard_idempotency_key.strip()
        )
        idempotency_keys_agree = (
            normalized_x_key is None
            or normalized_standard_key is None
            or normalized_x_key == normalized_standard_key
        )
        selected_idempotency_key = normalized_standard_key or normalized_x_key
        idempotency_ok = (
            selected_idempotency_key is not None
            and bool(selected_idempotency_key)
            and len(selected_idempotency_key) <= 200
            and idempotency_keys_agree
        )
        if not (session_ok and csrf_ok and origin_ok and idempotency_ok):
            raise ApiError(
                403,
                "local_write_protection_failed",
                "本地操作验证失败。请刷新页面后重试",
            )
        assert selected_idempotency_key is not None
        return selected_idempotency_key

    @app.get("/api/v1/meta")
    def get_meta() -> dict[str, object]:
        return {
            "application_id": "DaHeLogistics",
            "application_version": __version__,
            "api_version": API_VERSION,
            "run_mode": "shadow",
            "real_platform_access": False,
            "platform_adapter": "fake",
            "ocr_adapter": "disabled",
            "locked_set_review_enabled": legacy_package is not None,
            "loop9_review_enabled": loop9_package is not None,
        }

    @app.get("/api/v1/session")
    def create_local_session(request: Request) -> JSONResponse:
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        fetch_site = request.headers.get("sec-fetch-site")
        same_origin_page = (
            origin == canonical_origin
            or (
                origin is None
                and referer is not None
                and referer.startswith(f"{canonical_origin}/")
            )
            or (origin is None and fetch_site in {"same-origin", "none"})
        )
        if not same_origin_page:
            raise ApiError(
                403,
                "invalid_local_origin",
                "请从大禾本地操作台打开此页面",
            )
        response = JSONResponse(
            {
                "csrf_token": csrf_token,
                "application_version": __version__,
                "api_version": API_VERSION,
                "locked_set_review_enabled": legacy_package is not None,
                "loop9_review_enabled": loop9_package is not None,
            }
        )
        response.set_cookie(
            SESSION_COOKIE,
            session_secret,
            httponly=True,
            samesite="strict",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/v1/jobs")
    def get_empty_jobs(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        return {
            "jobs": [],
            "event_cursor": 0,
            "resources": [],
            "start_actions": {},
        }

    @app.get("/api/v1/resources")
    def get_empty_resources(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        return {"resources": []}

    @app.get("/api/v1/events")
    async def stream_review_keepalive(
        request: Request,
        _: None = Depends(require_session),
    ) -> StreamingResponse:
        async def generate() -> AsyncIterator[str]:
            while not await request.is_disconnected():
                yield ": locked-set-review\n\n"
                await asyncio.sleep(15)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    if legacy_package is not None:
        app.include_router(
            build_locked_set_review_router(
                package=legacy_package,
                repository=review_repository,
                require_session=require_session,
                require_write=require_write,
            )
        )
    else:
        assert loop9_package is not None
        app.state.loop9_review_workspace = Loop9ReviewWorkspace(
            package=loop9_package,
            repository=review_repository,
            output_root=(data_root / "review-exports").resolve(),
        )
        app.include_router(
            build_loop9_review_router(
                workspace=app.state.loop9_review_workspace,
                require_session=require_session,
                require_write=require_write,
            )
        )

    if resolved_static_dir is not None:
        app.mount(
            "/",
            StaticFiles(
                directory=resolved_static_dir,
                html=True,
                check_dir=True,
            ),
            name="operator-console",
        )

    return app


def create_app(
    data_root: Path,
    project_root: Path,
    instance_id: str,
    auto_run_jobs: bool,
    stage_delay_seconds: float,
    previous_instance_id: str | None = None,
    static_dir: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8877,
    enable_test_fixtures: bool = False,
    ocr_execution_backend: AsyncOcrExecutionBackend | None = None,
    ocr_execution_backend_factory: (Callable[[], AsyncOcrExecutionBackend] | None) = None,
    developer_access_code: str | None = None,
    accepted_template_development_manifest_sha256: str | None = None,
    accepted_template_runtime_fingerprint: str | None = None,
    enable_locked_set_review: bool = False,
    runtime_log_store: RuntimeLogStore | None = None,
    enable_chengfeng_shadow: bool = False,
    production_read_only: bool = False,
    enable_loop9_scheduler_probe: bool = False,
    platform_build_sha256: str | None = None,
    browser_runtime: BrowserRuntime | None = None,
    browser_lifecycle: BrowserRuntimeLifecycle | None = None,
    platform_contract_validator: LiveContractValidationPort | None = None,
    daily_execution_backend: AsyncDailyExecutionBackend | None = None,
    settlement_capture_execution_backend: (AsyncSettlementCaptureExecutionBackend | None) = None,
    chengfeng_shadow_job_source: ChengfengShadowJobSource | None = None,
    loop9_review_package_path: Path | None = None,
    platform_credential_vault: PlatformCredentialVault | None = None,
    update_service: UpdateService | None = None,
    release_identity: ReleaseIdentity | None = None,
) -> FastAPI:
    platform_access_enabled = enable_chengfeng_shadow or production_read_only
    if stage_delay_seconds < 0:
        raise ValueError("stage_delay_seconds cannot be negative")
    if host != "127.0.0.1":
        raise ValueError("host must be the IPv4 loopback address")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if ocr_execution_backend is not None and ocr_execution_backend_factory is not None:
        raise ValueError("provide an OCR backend or a factory, not both")
    if enable_locked_set_review and (
        ocr_execution_backend is not None or ocr_execution_backend_factory is not None
    ):
        raise ValueError("locked-set review mode cannot use an OCR backend")
    if enable_locked_set_review and (
        enable_test_fixtures
        or developer_access_code is not None
        or accepted_template_development_manifest_sha256 is not None
        or accepted_template_runtime_fingerprint is not None
    ):
        raise ValueError("locked-set review mode must run alone without tuning or test modes")
    if platform_access_enabled and enable_locked_set_review:
        raise ValueError("Chengfeng shadow mode cannot run in locked-set review mode")
    if loop9_review_package_path is not None and (
        platform_access_enabled
        or enable_locked_set_review
        or enable_test_fixtures
        or developer_access_code is not None
        or accepted_template_development_manifest_sha256 is not None
        or accepted_template_runtime_fingerprint is not None
        or ocr_execution_backend is not None
        or ocr_execution_backend_factory is not None
        or daily_execution_backend is not None
        or settlement_capture_execution_backend is not None
        or browser_runtime is not None
        or browser_lifecycle is not None
        or platform_contract_validator is not None
        or chengfeng_shadow_job_source is not None
    ):
        raise ValueError("Loop 9 review mode must run alone without Chengfeng or runtime modes")
    if loop9_review_package_path is not None and not loop9_review_package_path.is_absolute():
        raise ValueError("Loop 9 review package path must be absolute")
    if enable_loop9_scheduler_probe and not enable_chengfeng_shadow:
        raise ValueError("Loop 9 scheduler probe requires Chengfeng shadow mode")
    if enable_loop9_scheduler_probe and enable_test_fixtures:
        raise ValueError("Loop 9 scheduler probe cannot enable generic test fixtures")
    if platform_access_enabled and enable_test_fixtures:
        raise ValueError("Chengfeng shadow mode cannot enable generic test fixtures")
    if platform_access_enabled and (
        platform_build_sha256 is None
        or len(platform_build_sha256) != 64
        or any(character not in "0123456789abcdef" for character in platform_build_sha256)
    ):
        raise ValueError("Chengfeng shadow mode requires a lowercase build SHA-256")
    if enable_locked_set_review or loop9_review_package_path is not None:
        return _create_locked_set_review_app(
            data_root=data_root,
            project_root=project_root,
            instance_id=instance_id,
            previous_instance_id=previous_instance_id,
            static_dir=static_dir,
            host=host,
            port=port,
            loop9_review_package_path=loop9_review_package_path,
        )
    canonical_host = f"{host}:{port}"
    canonical_origin = f"http://{host}:{port}"
    release_identity = release_identity or load_release_identity(
        project_root,
        fallback_resource_sha256=platform_build_sha256 or ("0" * 64),
    )
    breadcrumb_store = BreadcrumbStore(
        data_root.resolve() / "diagnostics" / "breadcrumbs.jsonl"
    )

    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=instance_id,
    )
    runtime_log_store = runtime_log_store or RuntimeLogStore(data_root / "logs")
    factory_created_backend = False
    factory_created_daily_backend = False
    factory_created_settlement_backend = False
    factory_created_browser_runtime = False
    daily_live_executor: DailyLiveStageExecutor | None = None
    settlement_live_executor: SettlementCaptureLiveStageExecutor | None = None
    settlement_capture_store: SqliteSettlementCaptureStore | None = None
    verify_settlement_capture_prerequisites: (
        Callable[[ShadowBatchTargetKind], Loop9VerifiedExclusionSnapshot] | None
    ) = None
    try:
        if ocr_execution_backend_factory is not None:
            ocr_execution_backend = ocr_execution_backend_factory()
            factory_created_backend = True
        detected_template_runtime_fingerprint: str | None = None
        if ocr_execution_backend is not None:
            runtime_identities: list[dict[str, str]] = []
            for runtime_kind in ("cpu", "gpu"):
                if not ocr_execution_backend.has_runtime(runtime_kind):
                    continue
                identity = ocr_execution_backend.identity_for(runtime_kind)
                runtime_identities.append(
                    {
                        "profile_id": identity.profile_id,
                        "runtime_fingerprint": identity.runtime_fingerprint,
                        "runtime_kind": identity.runtime_kind,
                    }
                )
            detected_template_runtime_fingerprint = current_template_ocr_runtime_set_fingerprint(
                runtime_identities
            )
        if (
            accepted_template_runtime_fingerprint is not None
            and detected_template_runtime_fingerprint is not None
            and accepted_template_runtime_fingerprint != detected_template_runtime_fingerprint
        ):
            raise ValueError("configured template OCR runtime does not match qualified runtimes")
        template_runtime_fingerprint = (
            accepted_template_runtime_fingerprint or detected_template_runtime_fingerprint
        )
        template_repository = SqliteTemplateRepository(
            runtime=runtime,
            accepted_build_fingerprint=(
                current_template_pipeline_build_fingerprint(
                    application_version=__version__,
                )
            ),
            accepted_runtime_fingerprint=template_runtime_fingerprint,
            accepted_development_manifest_sha256=(accepted_template_development_manifest_sha256),
            accepted_matcher_fingerprint=development_matcher_fingerprint(),
            accepted_policy_fingerprint=development_policy_fingerprint(),
        )
        platform_access_repository = SqlitePlatformAccessRepository(runtime)
        business_session_store = SqliteBusinessConnectionSessionStore(runtime)
        platform_credential_service = PlatformCredentialService(
            vault=platform_credential_vault or WindowsCredentialVault(),
            store=SqlitePlatformCredentialConfigStore(runtime),
        )
        platform_connection_mode_store = ChengfengConnectionModeStore()
        browser_control_store = BrowserControlStore(
            runtime.engine,
            runtime.commit_gate,
        )
        platform_session_id = "chengfeng-shadow-v1"
        browser_control_store.initialize(
            session_id=platform_session_id,
            now=datetime.now(UTC),
        )
        if browser_runtime is None:
            def browser_output_sink(
                worker_id: str,
                stream: str,
                output: str,
                protocol_stdout: bool,
            ) -> None:
                runtime_log_store.append_process_output(
                    source=worker_id,
                    stream=stream,
                    text=output,
                    protocol_stdout=protocol_stdout,
                )

            def browser_event_sink(event_code: str, message: str) -> None:
                runtime_log_store.append(
                    level=(
                        "info"
                        if event_code == "browser_read_freshness_verified"
                        else "warning"
                    ),
                    source="chengfeng-browser-worker",
                    event_code=event_code,
                    stream="system",
                    message=message,
                )

            browser_runtime = IsolatedBrowserRuntime(
                project_root=project_root,
                data_root=data_root,
                runtime_root=default_browser_runtime_root(),
                below_normal_priority=production_read_only,
                output_sink=browser_output_sink,
                event_sink=browser_event_sink,
            )
            factory_created_browser_runtime = True
        browser_lifecycle = browser_lifecycle or BrowserRuntimeLifecycleGuard()
        live_connector: VerifiedChengfengConnector | None = None
        selected_contract: SelectedLiveReadContract | None = None
        identity_authority: Loop9IdentityAuthority | None = None
        navigation_authorizer: SqliteBrowserNavigationAuthorizer | None = None
        active_contract_selection = (
            data_root.resolve() / "platform-read-contract" / "active-candidate.json"
        )
        platform_request_audit_store = PlatformReadAuditEvidenceStore(data_root.resolve())
        if (
            platform_access_enabled
            and active_contract_selection.is_file()
            and platform_build_sha256 is not None
        ):
            selected_contract = load_selected_live_read_contract(data_root.resolve())
            identity_authority = load_or_create_loop9_identity_authority(data_root.resolve())
            navigation_authorizer = SqliteBrowserNavigationAuthorizer(
                browser_control_store,
                access_repository=platform_access_repository,
                build_sha256=platform_build_sha256,
                clock=lambda: datetime.now(UTC),
            )
            live_runtime = LiveConnectorRuntime(
                browser=browser_runtime,
                manifest=selected_contract.manifest,
                data_root=data_root.resolve(),
                authorizer=navigation_authorizer,
                build_sha256=platform_build_sha256,
                contract_selection_sha256=(selected_contract.selection_sha256),
                clock=lambda: datetime.now(UTC),
                runtime_log_store=runtime_log_store,
                request_audit_store=platform_request_audit_store,
            )
            live_connector = VerifiedChengfengConnector(
                runtime=live_runtime,
                data_root=data_root.resolve(),
                authorizer=navigation_authorizer,
            )
        discovery_evidence_store = DiscoveryEvidenceStore(data_root)
        evidence_store = ContentAddressedEvidenceStore(data_root / "evidence")
        chengfeng_capture_store = SqliteChengfengCaptureStore(
            runtime=runtime,
            evidence_store=evidence_store,
        )
        settlement_capture_store = SqliteSettlementCaptureStore(runtime)
        transient_business_progress_store = TransientBusinessProgressStore()
        shadow_batch_store = ShadowBatchManifestStore(data_root / "chengfeng-shadow-batches")
        formal_selection_store = (
            FormalShadowSelectionStore(data_root.resolve()) if platform_access_enabled else None
        )
        if (
            chengfeng_shadow_job_source is None
            and enable_chengfeng_shadow
            and selected_contract is not None
            and platform_build_sha256 is not None
            and formal_selection_store is not None
        ):
            shadow_image_reader = ContentAddressedShadowImageReader(evidence_store)
            chengfeng_shadow_job_source = ChengfengShadowJobSourceResolver(
                manifest_store=shadow_batch_store,
                selection_reader=formal_selection_store,
                capture_reader=chengfeng_capture_store,
                access_reader=platform_access_repository,
                image_reader=shadow_image_reader,
                authority=ShadowJobExecutionAuthority(
                    build_sha256=platform_build_sha256,
                    contract_canonical_sha256=(selected_contract.manifest.canonical_sha256),
                    contract_file_sha256=(selected_contract.contract_file_sha256),
                    contract_selection_sha256=(selected_contract.selection_sha256),
                ),
            )
        daily_invocation_store = SqliteDailyInvocationStore(runtime)
        daily_store = SqliteDailyStore(runtime)
        daily_item_repository = SqliteDailyItemRepository(runtime, daily_store)

        def update_ocr_idle_timeout(settings: PerformanceSettingsRecord) -> None:
            if ocr_execution_backend is None:
                return
            setter = getattr(ocr_execution_backend, "set_idle_timeout_seconds", None)
            if callable(setter):
                setter(None if settings.keep_gpu_ready else settings.gpu_idle_minutes * 60)
            thread_setter = getattr(
                ocr_execution_backend,
                "set_cpu_thread_limit",
                None,
            )
            if callable(thread_setter):
                thread_setter(settings.cpu_ocr_threads)

        performance_settings_repository = PerformanceSettingsRepository(
            runtime,
            on_change=update_ocr_idle_timeout,
        )
        update_ocr_idle_timeout(performance_settings_repository.get())

        def capture_concurrency() -> tuple[int, int]:
            settings = performance_settings_repository.get()
            return settings.detail_concurrency, settings.image_concurrency

        def capture_batch_size() -> int:
            return performance_settings_repository.get().network_batch_size

        daily_operational_ocr_store = SqliteDailyOperationalOcrStore(runtime)
        selected_daily_contract: SelectedDailyReadContract | None = None
        active_daily_contract_selection = (
            data_root.resolve() / "daily-platform-read-contract" / "active-candidate.json"
        )
        if platform_access_enabled and active_daily_contract_selection.is_file():
            selected_daily_contract = load_selected_daily_read_contract(data_root.resolve())
        if (
            platform_contract_validator is None
            and live_connector is not None
            and selected_contract is not None
            and identity_authority is not None
        ):
            daily_validation_source = (
                None
                if (selected_daily_contract is None or navigation_authorizer is None)
                else ChengfengDailyContractValidationSource(
                    browser=browser_runtime,
                    selected=selected_daily_contract,
                    authorizer=navigation_authorizer,
                    clock=lambda: datetime.now(UTC),
                    request_audit_store=platform_request_audit_store,
                    build_sha256=platform_build_sha256,
                )
            )
            platform_contract_validator = LiveContractValidationRunner(
                connector=live_connector,
                selected=selected_contract,
                data_root=data_root.resolve(),
                clock=lambda: datetime.now(UTC),
                identity_salt=identity_authority.salt,
                identity_namespace=identity_authority.namespace,
                daily_source=daily_validation_source,
            )
        if (
            platform_access_enabled
            and selected_contract is not None
            and live_connector is not None
            and identity_authority is not None
            and navigation_authorizer is not None
            and platform_build_sha256 is not None
            and formal_selection_store is not None
        ):

            def verify_capture_prerequisites(
                target_kind: ShadowBatchTargetKind,
            ) -> Loop9VerifiedExclusionSnapshot:
                if selected_daily_contract is None:
                    raise SettlementCaptureContractError(
                        "formal daily read authority is unavailable"
                    )
                if target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
                    formal_selection_store.require_current_locked_gate(
                        expected_current_build_sha256=(platform_build_sha256),
                        expected_settlement_contract_sha256=(
                            selected_contract.manifest.canonical_sha256
                        ),
                    )
                return load_verified_loop9_exclusion_snapshot_from_persisted_authority(
                    data_root=data_root.resolve(),
                    expected_current_build_sha256=platform_build_sha256,
                    expected_settlement_contract_sha256=(
                        selected_contract.manifest.canonical_sha256
                    ),
                    expected_daily_contract_sha256=(
                        selected_daily_contract.manifest.canonical_sha256
                    ),
                    expected_settlement_selection_sha256=(selected_contract.selection_sha256),
                    expected_daily_selection_sha256=(selected_daily_contract.selection_sha256),
                )

            verify_settlement_capture_prerequisites = verify_capture_prerequisites
            if settlement_capture_execution_backend is None:

                def validate_capture_authority(
                    invocation: SettlementCaptureInvocationView,
                    authority: BrowserCommandAuthority,
                    now: datetime,
                ) -> None:
                    if (
                        authority.job_id != invocation.job_id
                        or authority.session_id != platform_session_id
                        or invocation.source_build_sha256 != platform_build_sha256
                        or invocation.contract_canonical_sha256
                        != selected_contract.manifest.canonical_sha256
                        or invocation.contract_file_sha256 != selected_contract.contract_file_sha256
                        or invocation.contract_selection_sha256
                        != selected_contract.selection_sha256
                        or invocation.identity_context_sha256 != identity_authority.context_sha256
                    ):
                        raise SettlementCaptureContractError("settlement capture authority changed")
                    target_kind = settlement_capture_store.target_kind(invocation.invocation_id)
                    purpose = (
                        AccessPurpose.FORMAL_LOCKED_SET
                        if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50
                        else AccessPurpose.PRODUCTION_SHADOW
                    )
                    platform_access_repository.authorize(
                        access_window_id=invocation.access_window_id,
                        purpose=purpose,
                        job_id=invocation.job_id,
                        session_id=platform_session_id,
                        build_sha256=platform_build_sha256,
                        now=now,
                    )

                def load_capture_exclusions(
                    capture: SettlementCaptureManifest,
                ) -> Loop9VerifiedExclusionSnapshot:
                    if (
                        capture.source_build_sha256 != platform_build_sha256
                        or capture.contract_canonical_sha256
                        != selected_contract.manifest.canonical_sha256
                        or capture.contract_file_sha256 != selected_contract.contract_file_sha256
                        or capture.contract_selection_sha256 != selected_contract.selection_sha256
                        or capture.identity_context_sha256 != identity_authority.context_sha256
                    ):
                        raise SettlementCaptureContractError(
                            "settlement capture evidence authority changed"
                        )
                    return verify_capture_prerequisites(
                        settlement_capture_store.target_kind(
                            settlement_capture_store.get_by_job(capture.source_job_id).invocation_id
                        )
                    )

                def validate_capture_target(
                    target_kind: ShadowBatchTargetKind,
                ) -> None:
                    verify_capture_prerequisites(target_kind)

                durable_coordinator = DurableChengfengCaptureCoordinator(
                    adapter=live_connector,
                    navigation_authorizer=navigation_authorizer,
                    checkpoint_store=chengfeng_capture_store,
                    interleave_images=True,
                )
                paginated_coordinator = PaginatedSettlementCaptureCoordinator(
                    durable_coordinator=durable_coordinator,
                    checkpoint_store=chengfeng_capture_store,
                    invocation_store=cast(
                        SettlementCaptureInvocationPort,
                        settlement_capture_store,
                    ),
                    outward_store=SettlementCaptureManifestStore(data_root.resolve()),
                    image_reader=ContentAddressedShadowImageReader(evidence_store),
                    identity_salt=identity_authority.salt,
                    identity_namespace=identity_authority.namespace,
                    validate_authority=validate_capture_authority,
                    clock=lambda: datetime.now(UTC),
                    request_audit_store=(platform_request_audit_store),
                )
                operational_coordinator = OperationalSettlementCaptureCoordinator(
                    durable_coordinator=durable_coordinator,
                    checkpoint_store=chengfeng_capture_store,
                )
                fast_operational_coordinator = FastOperationalSettlementCaptureCoordinator(
                    adapter=live_connector,
                    navigation_authorizer=navigation_authorizer,
                    batch_store=chengfeng_capture_store,
                    concurrency_provider=capture_concurrency,
                    batch_size_provider=capture_batch_size,
                    progress_sink=transient_business_progress_store.publish,
                )

                def materialize_operational_audit(
                    capture_job_id: str,
                ) -> None:
                    invocation = settlement_capture_store.get_by_job(capture_job_id)
                    if (
                        settlement_capture_store.target_kind(invocation.invocation_id)
                        is not ShadowBatchTargetKind.OPERATIONAL_COMPAT
                    ):
                        return

                    def create_audit_job(
                        spec: ScheduledJobSpec,
                        *,
                        source_identity: str,
                    ) -> None:
                        request_payload = {
                            "capture_job_id": capture_job_id,
                            "source_identity": source_identity,
                            "fixture_id": spec.fixture_id,
                        }
                        request_hash = hashlib.sha256(
                            json.dumps(
                                request_payload,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()
                        idempotency_key = (
                            f"operational-materialize:{source_identity}"
                        )
                        active, expected_version = repository.fixture_start_state(
                            spec.conflict_key
                        )
                        reused_existing = active
                        try:
                            if active:
                                audit_job, _created = (
                                    repository.link_active_scheduled_job(
                                        conflict_key=spec.conflict_key,
                                        idempotency_key=idempotency_key,
                                        request_hash=request_hash,
                                    )
                                )
                            else:
                                audit_job, _created = (
                                    repository.create_scheduled_job(
                                        fixture=spec,
                                        scope_label=spec.scope_label,
                                        idempotency_key=idempotency_key,
                                        request_hash=request_hash,
                                        expected_record_version=(
                                            expected_version
                                        ),
                                    )
                                )
                        except ActiveScopeConflictError:
                            reused_existing = True
                            audit_job, _created = (
                                repository.link_active_scheduled_job(
                                    conflict_key=spec.conflict_key,
                                    idempotency_key=idempotency_key,
                                    request_hash=request_hash,
                                )
                            )
                        runtime_log_store.append(
                            level="info",
                            source="platform",
                            event_code=(
                                "operational_audit_reused"
                                if reused_existing or not _created
                                else "operational_audit_materialized"
                            ),
                            stream="application",
                            message=(
                                "Business read evidence linked an audit "
                                f"job with {len(spec.items)} waybill(s)."
                            ),
                            job_id=audit_job.job_id,
                        )

                    batch_run = chengfeng_capture_store.load_operational_run(job_id=capture_job_id)
                    pipeline_fingerprint = current_template_pipeline_build_fingerprint(
                        application_version=__version__
                    )
                    if batch_run is not None:
                        for batch_number in range(
                            1,
                            batch_run.committed_batch_count + 1,
                        ):
                            checkpoint = chengfeng_capture_store.load(
                                job_id=capture_job_id,
                                scope=batch_run.scope,
                                page_number=batch_number,
                                page_size=batch_run.batch_size,
                            )
                            if checkpoint is None:
                                raise RuntimeError("committed operational batch is missing")
                            if not checkpoint.details:
                                continue
                            spec = scheduled_job_from_operational_batch(
                                checkpoint=checkpoint,
                                pipeline_fingerprint=(pipeline_fingerprint),
                            )
                            create_audit_job(
                                spec,
                                source_identity=(
                                    f"{capture_job_id}:batch:"
                                    f"{batch_number}:"
                                    f"{spec.fixture_id.rsplit(':', 1)[-1]}"
                                ),
                            )
                        if batch_run.status == "complete" and batch_run.total == 0:
                            runtime_log_store.append(
                                level="info",
                                source="platform",
                                event_code="operational_capture_empty",
                                stream="application",
                                message=(
                                    "Business connection completed with zero pending waybills."
                                ),
                                job_id=capture_job_id,
                            )
                        return
                    if (
                        invocation.status != "operational_ready"
                        or invocation.manifest_sha256 is None
                    ):
                        return
                    checkpoints = load_complete_operational_checkpoints(
                        checkpoint_store=chengfeng_capture_store,
                        job_id=capture_job_id,
                        scope=invocation.scope,
                        page_size=invocation.page_size,
                    )
                    first = checkpoints[0]
                    assert first.page is not None
                    if first.page.total == 0:
                        runtime_log_store.append(
                            level="info",
                            source="platform",
                            event_code="operational_capture_empty",
                            stream="application",
                            message=("Business connection completed with zero pending waybills."),
                            job_id=capture_job_id,
                        )
                        return
                    spec = scheduled_job_from_operational_checkpoints(
                        checkpoints=checkpoints,
                        pipeline_fingerprint=pipeline_fingerprint,
                    )
                    create_audit_job(
                        spec,
                        source_identity=invocation.manifest_sha256,
                    )

                settlement_live_executor = SettlementCaptureLiveStageExecutor(
                    invocation_store=settlement_capture_store,
                    coordinator=paginated_coordinator,
                    selection_store=formal_selection_store,
                    batch_store=shadow_batch_store,
                    request_audit_store=platform_request_audit_store,
                    access_repository=platform_access_repository,
                    browser_control=browser_control_store,
                    browser_runtime=browser_runtime,
                    browser_lifecycle=browser_lifecycle,
                    instance_id=instance_id,
                    session_id=platform_session_id,
                    build_sha256=platform_build_sha256,
                    pipeline_fingerprint=(
                        current_template_pipeline_build_fingerprint(application_version=__version__)
                    ),
                    exclusion_snapshot_loader=load_capture_exclusions,
                    target_prerequisite_validator=(validate_capture_target),
                    validation_authority_gate=(
                        lambda: (
                            platform_contract_validator is not None
                            and platform_contract_validator.has_successful_validation(
                                platform_build_sha256
                            )
                        )
                    ),
                    operational_coordinator=(operational_coordinator),
                    fast_operational_coordinator=(fast_operational_coordinator),
                    operational_materializer=(materialize_operational_audit),
                )
                settlement_capture_execution_backend = AsyncSettlementCaptureExecutionBackend(
                    execute=settlement_live_executor,
                    reconcile_terminal=(settlement_live_executor.close_terminal_job),
                )
                factory_created_settlement_backend = True
        if (
            daily_execution_backend is None
            and selected_daily_contract is not None
            and selected_contract is not None
            and live_connector is not None
            and navigation_authorizer is not None
        ):

            def materialize_daily_operational_ocr(
                daily_job_id: str,
            ) -> None:
                source_job = repository.get_job(daily_job_id)
                if source_job.scope_fixture_id.startswith(
                    "daily-operational-network-only-v1:"
                ):
                    runtime_log_store.append(
                        level="info",
                        source="platform",
                        event_code="daily_network_measurement_complete",
                        stream="application",
                        message=(
                            "Daily network measurement completed without "
                            "starting local OCR."
                        ),
                        job_id=daily_job_id,
                    )
                    return
                run = chengfeng_capture_store.load_operational_run(job_id=daily_job_id)
                if run is None or not run.scope.startswith("daily:"):
                    return
                pipeline_fingerprint = current_template_pipeline_build_fingerprint(
                    application_version=__version__
                )
                for batch_number in range(
                    1,
                    run.committed_batch_count + 1,
                ):
                    if (
                        daily_operational_ocr_store.get_batch(
                            daily_job_id=daily_job_id,
                            batch_number=batch_number,
                        )
                        is not None
                    ):
                        continue
                    checkpoint = chengfeng_capture_store.load(
                        job_id=daily_job_id,
                        scope=run.scope,
                        page_number=batch_number,
                        page_size=run.batch_size,
                    )
                    if checkpoint is None or not checkpoint.details:
                        continue
                    base = scheduled_job_from_operational_batch(
                        checkpoint=checkpoint,
                        pipeline_fingerprint=pipeline_fingerprint,
                    )
                    eligible = tuple(
                        item
                        for item in base.items
                        if item.loading_image_relative_path is not None
                        and item.unloading_image_relative_path is not None
                    )
                    missing_count = len(base.items) - len(eligible)
                    ocr_job_id: str | None = None
                    if eligible:
                        capture_identity = base.fixture_id.rsplit(":", 1)[-1]
                        spec = replace(
                            base,
                            fixture_id=(
                                "daily-observation:"
                                f"{daily_job_id[:12]}:{batch_number}:"
                                f"{capture_identity[:16]}"
                            ),
                            job_kind="observation",
                            scope_label=(
                                "装卸车识别 "
                                f"{run.scope.removeprefix('daily:')} "
                                f"第 {batch_number} 批"
                            ),
                            conflict_key=(
                                f"daily-ocr:{daily_job_id}:{batch_number}:{capture_identity}"
                            ),
                            items=eligible,
                        )
                        _active, expected_version = repository.fixture_start_state(
                            spec.conflict_key
                        )
                        request_hash = hashlib.sha256(
                            json.dumps(
                                {
                                    "batch": batch_number,
                                    "daily_job_id": daily_job_id,
                                    "fixture_id": spec.fixture_id,
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()
                        ocr_job, _created = repository.create_scheduled_job(
                            fixture=spec,
                            scope_label=spec.scope_label,
                            idempotency_key=(
                                f"daily-operational-ocr:{daily_job_id}:{batch_number}"
                            ),
                            request_hash=request_hash,
                            expected_record_version=(expected_version),
                        )
                        ocr_job_id = ocr_job.job_id
                    daily_operational_ocr_store.register_batch(
                        daily_job_id=daily_job_id,
                        batch_number=batch_number,
                        ocr_job_id=ocr_job_id,
                        eligible_item_count=len(eligible),
                        missing_ticket_count=missing_count,
                    )
                    runtime_log_store.append(
                        level="info",
                        source="platform",
                        event_code="daily_operational_batch_materialized",
                        stream="application",
                        message=("Daily evidence batch was committed and queued for local OCR."),
                        job_id=daily_job_id,
                    )

            def observe_daily_unexpected_error(
                daily_job_id: str,
                failure_step: str,
                exception_type: str,
            ) -> None:
                runtime_log_store.append(
                    level="error",
                    source="platform",
                    event_code="daily_operational_stage_unexpected_error",
                    stream="application",
                    message=(
                        f"Daily operational stage stopped at {failure_step} ({exception_type})."
                    ),
                    diagnostic_code="DAILY-STAGE-EXECUTION-FAILED",
                    job_id=daily_job_id,
                )

            daily_live_executor = DailyLiveStageExecutor(
                invocation_store=daily_invocation_store,
                access_repository=platform_access_repository,
                browser_control=browser_control_store,
                browser_runtime=browser_runtime,
                browser_lifecycle=browser_lifecycle,
                manifest=selected_daily_contract.manifest,
                connector=live_connector,
                evidence_store=evidence_store,
                request_audit_store=platform_request_audit_store,
                daily_store=daily_store,
                instance_id=instance_id,
                session_id=platform_session_id,
                build_sha256=platform_build_sha256 or ("0" * 64),
                settlement_contract_sha256=(selected_contract.manifest.canonical_sha256),
                settlement_contract_selection_sha256=(selected_contract.selection_sha256),
                daily_contract_selection_sha256=(selected_daily_contract.selection_sha256),
                settlement_validation_gate=(
                    lambda: (
                        platform_contract_validator is not None
                        and platform_contract_validator.has_successful_validation(
                            platform_build_sha256 or ("0" * 64)
                        )
                    )
                ),
                operational_coordinator=(
                    FastOperationalDailyCaptureCoordinator(
                        detail_adapter=live_connector,
                        navigation_authorizer=navigation_authorizer,
                        batch_store=chengfeng_capture_store,
                        daily_store=daily_store,
                        clock=lambda: datetime.now(UTC),
                        concurrency_provider=capture_concurrency,
                        batch_size_provider=capture_batch_size,
                        progress_sink=transient_business_progress_store.publish,
                    )
                ),
                operational_materializer=(
                    materialize_daily_operational_ocr if ocr_execution_backend is not None else None
                ),
                unexpected_error_observer=observe_daily_unexpected_error,
            )
            daily_execution_backend = AsyncDailyExecutionBackend(
                execute=daily_live_executor,
                reconcile_terminal=(daily_live_executor.close_terminal_job),
            )
            factory_created_daily_backend = True
        local_audit_evaluator = None
        if ocr_execution_backend is not None:
            shadow_templates = template_repository.list_current_eligible_shadow_versions()
            operational_template_bundle = data_root / "operational-template-bundle.json"
            if not shadow_templates and operational_template_bundle.is_file():
                try:
                    shadow_templates = load_operational_template_bundle(
                        operational_template_bundle.resolve(strict=True),
                        expected_matcher_fingerprint=(development_matcher_fingerprint()),
                        expected_policy_fingerprint=(development_policy_fingerprint()),
                    )
                except OperationalTemplateBundleError as exc:
                    raise ValueError("operational template bundle is invalid") from exc
            if shadow_templates:
                local_audit_evaluator = LocalOcrAuditEvaluator(
                    templates=shadow_templates,
                    role_policy=default_development_policy(),
                )
        production_guard = ProductionReadOnlyGuardStore(runtime) if production_read_only else None
        audit_workflow_repository = SqliteAuditWorkflowRepository(
            runtime,
            local_observation_projector=local_audit_evaluator,
            production_guard=production_guard,
        )
        repository = SqliteJobRepository(
            runtime,
            scheduler_instance_id=instance_id,
            ocr_execution_backend=ocr_execution_backend,
            daily_execution_backend=daily_execution_backend,
            settlement_capture_execution_backend=(settlement_capture_execution_backend),
            local_audit_evaluator=local_audit_evaluator,
        )
        offline_manifest_path = data_root / "offline-audit" / "loop8-offline-v1.json"
        default_audit_spec = (
            load_loop8_offline_batch(offline_manifest_path)
            if offline_manifest_path.is_file()
            else NORMAL_AUDIT_JOB_SPEC
        )
    except BaseException:
        cleanup_actions: list[Callable[[], None]] = []
        if factory_created_backend and ocr_execution_backend is not None:
            cleanup_actions.append(ocr_execution_backend.close)
        if factory_created_daily_backend and daily_execution_backend is not None:
            cleanup_actions.append(daily_execution_backend.close)
        if factory_created_settlement_backend and settlement_capture_execution_backend is not None:
            cleanup_actions.append(settlement_capture_execution_backend.close)
        if factory_created_browser_runtime and browser_runtime is not None:
            cleanup_actions.append(browser_runtime.close)
        cleanup_actions.append(runtime.close)
        for cleanup in cleanup_actions:
            try:
                cleanup()
            except BaseException:
                continue
        raise
    recovery_store = PersistentRecoveryStore(
        runtime.engine,
        runtime.commit_gate,
    )
    instance_lifecycle = ApplicationInstanceLifecycle(
        recovery_store,
        instance_id=instance_id,
        data_root=data_root,
        application_version=__version__,
        port=port,
    )
    scheduler = CooperativeScheduler(repository)
    scheduler_runner = CooperativeSchedulerRunner(
        scheduler,
        tick_interval_seconds=stage_delay_seconds,
    )
    platform_access_expiry_reconciler = (
        PlatformAccessExpiryReconciler(
            access_repository=platform_access_repository,
            browser_control=browser_control_store,
            browser_runtime=browser_runtime,
            browser_lifecycle=browser_lifecycle,
            runtime_log_store=runtime_log_store,
            session_id=platform_session_id,
            build_sha256=platform_build_sha256,
        )
        if platform_access_enabled and platform_build_sha256 is not None
        else None
    )
    session_secret = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        lifecycle_started = False
        process_supervisor: OwnedProcessSupervisor | None = None
        outbox_log_bridge: RuntimeOutboxLogBridge | None = None
        visible_browser_start_task: asyncio.Task[object] | None = None
        try:
            runtime_log_store.append(
                level="info",
                source="application",
                event_code="application_starting",
                stream="application",
                message="Local application startup began.",
            )
            instance_lifecycle.start()
            lifecycle_started = True
            if previous_instance_id is not None:
                recovery_store.mark_instance_crashed(
                    instance_id=previous_instance_id,
                    replacement_instance_id=instance_id,
                    data_root_identity=instance_lifecycle.data_root_identity,
                    single_instance_proof=True,
                    now=datetime.now(UTC),
                )
            recovery_store.mark_other_instances_crashed(
                replacement_instance_id=instance_id,
                data_root_identity=instance_lifecycle.data_root_identity,
                single_instance_proof=True,
                now=datetime.now(UTC),
            )
            repository.recover_abandoned_attempts(recovering_instance_id=instance_id)
            if settlement_capture_store is not None:
                reconciled_settlement_jobs = (
                    settlement_capture_store.reconcile_terminal_or_expired_access(
                        now=datetime.now(UTC)
                    )
                )
                if reconciled_settlement_jobs:
                    runtime_log_store.append(
                        level="info",
                        source="platform",
                        event_code=("settlement_capture_terminal_reconciled"),
                        stream="application",
                        message=(
                            "Recovered terminal settlement capture "
                            f"authority for "
                            f"{len(reconciled_settlement_jobs)} job(s)."
                        ),
                    )
                if settlement_capture_execution_backend is not None:
                    latest_complete_job_id = (
                        chengfeng_capture_store.latest_completed_operational_job_id(
                            scope="current"
                        )
                    )
                    if latest_complete_job_id is not None:
                        settlement_capture_execution_backend.reconcile_terminal(
                            latest_complete_job_id
                        )
            if daily_live_executor is not None:
                orphaned_daily_starts = set(daily_invocation_store.orphaned_start_job_ids())
                reconciled_jobs = daily_live_executor.reconcile_terminal_or_expired()
                for orphaned_job_id in sorted(orphaned_daily_starts):
                    orphaned_job = repository.get_job(orphaned_job_id)
                    if not orphaned_job.status.is_terminal:
                        repository.fail_job(
                            orphaned_job_id,
                            "DAILY-START-INTERRUPTED",
                        )
                if reconciled_jobs:
                    runtime_log_store.append(
                        level="info",
                        source="platform",
                        event_code="daily_terminal_reconciled",
                        stream="application",
                        message=(
                            "Recovered terminal daily browser authority "
                            f"for {len(reconciled_jobs)} job(s)."
                        ),
                    )
            if platform_access_expiry_reconciler is not None:
                platform_access_expiry_reconciler.start()
            outbox_log_bridge = RuntimeOutboxLogBridge(
                events_after=repository.events_after,
                store=runtime_log_store,
            )
            outbox_log_bridge.start()
            template_repository.expire_staged_reference_uploads(
                older_than=datetime.now(UTC) - timedelta(hours=24),
            )
            process_supervisor = OwnedProcessSupervisor(
                instance_id=instance_id,
                runtime_dir=data_root / "runtime" / "workers",
            )
            application.state.process_supervisor = process_supervisor
            if auto_run_jobs:
                scheduler_runner.start()
                scheduler_runner.notify()
            if production_read_only and platform_access_enabled:
                async def start_visible_browser() -> None:
                    try:
                        await asyncio.to_thread(
                            reconcile_operational_browser_readiness,
                            browser_control=browser_control_store,
                            browser_runtime=browser_runtime,
                            browser_lifecycle=browser_lifecycle,
                            session_id=platform_session_id,
                            now=datetime.now(UTC),
                        )
                        runtime_log_store.append(
                            level="info",
                            source="platform",
                            event_code="visible_browser_ready",
                            stream="application",
                            message="Visible Chengfeng browser is ready.",
                        )
                    except Exception as exc:
                        runtime_log_store.append(
                            level="warning",
                            source="platform",
                            event_code="visible_browser_start_failed",
                            stream="application",
                            message=(
                                "Visible Chengfeng browser did not start "
                                f"({type(exc).__name__})."
                            ),
                            diagnostic_code="CF-VISIBLE-BROWSER-START-FAILED",
                        )

                visible_browser_start_task = asyncio.create_task(start_visible_browser())
            runtime_log_store.append(
                level="info",
                source="application",
                event_code="application_started",
                stream="application",
                message="Local application startup completed.",
            )
            if update_service is not None:
                update_service.start_periodic_checks()
            yield
        finally:
            # No attempt may be requeued while an owned worker could still
            # submit a late result. Stop lifecycle housekeeping, then stop
            # scheduling, terminate and join only this instance's workers, and
            # only then abandon the remaining uncommitted attempts.
            first_shutdown_failure: BaseException | None = None

            def attempt_shutdown(step: Callable[[], object]) -> None:
                nonlocal first_shutdown_failure
                try:
                    step()
                except BaseException as exc:
                    if first_shutdown_failure is None:
                        first_shutdown_failure = exc

            if platform_access_expiry_reconciler is not None:
                attempt_shutdown(platform_access_expiry_reconciler.close)
            if update_service is not None:
                attempt_shutdown(update_service.stop_periodic_checks)
            if visible_browser_start_task is not None:
                visible_browser_start_task.cancel()
            attempt_shutdown(scheduler_runner.close)
            if outbox_log_bridge is not None:
                attempt_shutdown(outbox_log_bridge.close)
            attempt_shutdown(repository.stop_ocr_execution)
            if process_supervisor is not None:
                attempt_shutdown(process_supervisor.close)
            attempt_shutdown(lambda: repository.abandon_instance_attempts(instance_id=instance_id))

            def close_business_connection_on_shutdown() -> None:
                business_session = business_session_store.latest(
                    platform_session_id=platform_session_id
                )
                if business_session is None or business_session.status != "active":
                    return
                browser_runtime.close()
                browser = browser_control_store.get(platform_session_id)
                if (
                    browser.browser_lifecycle == "ready"
                    and browser.browser_control_mode in {"human_login", "human_handoff"}
                    and browser.holder_id is not None
                ):
                    with contextlib.suppress(BrowserControlError):
                        browser_control_store.mark_human_session_closed(
                            session_id=platform_session_id,
                            human_session_id=browser.holder_id,
                            expected_record_version=browser.record_version,
                            now=datetime.now(UTC),
                        )
                login_window, login_window_version = platform_access_repository.get_with_version(
                    business_session.login_access_window_id
                )
                if login_window.consumed_at is None:
                    platform_access_repository.retire(
                        access_window_id=(business_session.login_access_window_id),
                        expected_record_version=login_window_version,
                        now=datetime.now(UTC),
                    )
                request_hash = hashlib.sha256(
                    (f"{business_session.business_session_id}:shutdown").encode()
                ).hexdigest()
                business_session_store.close(
                    business_session_id=(business_session.business_session_id),
                    expected_record_version=(business_session.record_version),
                    reason="shutdown",
                    idempotency_key=(f"business-shutdown:{request_hash}"),
                    request_hash=request_hash,
                    now=datetime.now(UTC),
                )

            attempt_shutdown(close_business_connection_on_shutdown)
            if lifecycle_started:
                attempt_shutdown(instance_lifecycle.close)
            attempt_shutdown(repository.close)
            attempt_shutdown(
                lambda: runtime_log_store.append(
                    level="info",
                    source="application",
                    event_code="application_stopped",
                    stream="application",
                    message="Local application stopped.",
                )
            )

            def close_browser_runtime() -> None:
                with browser_lifecycle.hold():
                    browser_runtime.close()

            attempt_shutdown(close_browser_runtime)
            if first_shutdown_failure is not None:
                raise first_shutdown_failure

    app = FastAPI(
        title="DaHe Logistics Local API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.state.repository = repository
    app.state.sqlite_runtime = runtime
    app.state.template_repository = template_repository
    app.state.audit_workflow_repository = audit_workflow_repository
    app.state.platform_access_repository = platform_access_repository
    app.state.business_session_store = business_session_store
    app.state.browser_control_store = browser_control_store
    app.state.browser_runtime = browser_runtime
    app.state.platform_access_expiry_reconciler = platform_access_expiry_reconciler
    app.state.daily_invocation_store = daily_invocation_store
    app.state.daily_operational_ocr_store = daily_operational_ocr_store
    app.state.transient_business_progress_store = (
        transient_business_progress_store
    )
    app.state.selected_daily_contract = selected_daily_contract
    app.state.settlement_capture_store = settlement_capture_store
    app.state.selected_settlement_contract = selected_contract
    app.state.settlement_capture_execution_available = (
        settlement_capture_execution_backend is not None
    )
    app.state.runtime_log_store = runtime_log_store
    app.state.scheduler = scheduler
    app.state.instance_lifecycle = instance_lifecycle
    app.state.request_shutdown = None
    app.state.update_service = update_service

    @app.exception_handler(ApiError)
    async def handle_api_error(_: Request, exc: ApiError) -> JSONResponse:
        runtime_log_store.append(
            level="error" if exc.status_code >= 500 else "warning",
            source="api",
            event_code="api_request_rejected",
            stream="application",
            message=f"Local API request rejected ({exc.code}).",
            diagnostic_code=exc.code,
        )
        return _error(exc.status_code, exc.code, exc.message)

    @app.middleware("http")
    async def protect_local_boundary(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_host = request.headers.get("host")
        if request_host != canonical_host:
            return _error(400, "invalid_local_host", "本地访问地址无效")
        if request.url.path.startswith("/api/"):
            client_version = request.headers.get("x-dahe-client-version")
            readiness_request = request.url.path == "/api/v1/system/readiness"
            versioned_query_path = (
                request.url.path == "/api/v1/events"
                or request.url.path == "/api/v1/diagnostics/logs/stream"
                or (
                    request.url.path.startswith("/api/v1/platform/business-reads/")
                    and request.url.path.endswith("/progress/stream")
                )
                or (
                    request.method == "GET"
                    and request.url.path.startswith("/api/v1/template-studio/reference-images/")
                    and request.url.path.endswith("/content")
                )
                or (
                    request.method == "GET"
                    and request.url.path.startswith("/api/v1/locked-set-review/images/")
                )
                or (request.method == "GET" and request.url.path.startswith("/api/v1/evidence/"))
            )
            if versioned_query_path and client_version is None:
                client_version = request.query_params.get("client_version")
            if not readiness_request and client_version != __version__:
                return _error(
                    409,
                    "client_version_mismatch",
                    "页面版本已过期。请刷新后重试",
                )
            origin = request.headers.get("origin")
            if origin is not None and origin != canonical_origin:
                return _error(403, "invalid_local_origin", "本地页面来源无效")
        response = await call_next(request)
        if request.url.path.startswith("/api/") and request.method != "GET":
            route = request.scope.get("route")
            route_name = str(getattr(route, "name", "local_action"))
            path = request.url.path
            page = (
                "daily"
                if "daily" in path
                else "history"
                if "history" in path
                else "settlement"
                if any(token in path for token in ("audit", "settlement", "platform"))
                else "system"
            )
            job_id = next(
                (
                    part
                    for part in path.split("/")
                    if len(part) == 32
                    and all(character in "0123456789abcdef" for character in part)
                ),
                None,
            )
            breadcrumb_store.append(
                page=page,
                action_type=route_name,
                job_id=job_id,
                result=(
                    "succeeded"
                    if response.status_code < 400
                    else "rejected"
                    if response.status_code < 500
                    else "failed"
                ),
                error_code=(
                    None
                    if response.status_code < 400
                    else f"http_{response.status_code}"
                ),
            )
        if response.status_code >= 500:
            runtime_log_store.append(
                level="error",
                source="api",
                event_code="api_server_error",
                stream="application",
                message="Local API request returned a server error.",
            )
        response.headers["X-DaHe-Application-Version"] = __version__
        response.headers["X-DaHe-API-Version"] = API_VERSION
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data: blob:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    def require_session(request: Request) -> None:
        supplied = request.cookies.get(SESSION_COOKIE)
        if supplied is None or not secrets.compare_digest(supplied, session_secret):
            raise ApiError(
                403,
                "local_session_required",
                "本地会话已失效。请刷新页面",
            )

    def require_write(
        request: Request,
        x_csrf_token: str | None = Header(default=None),
        x_idempotency_key: str | None = Header(default=None),
        standard_idempotency_key: str | None = Header(
            default=None,
            alias="Idempotency-Key",
        ),
    ) -> str:
        supplied_session = request.cookies.get(SESSION_COOKIE)
        session_ok = supplied_session is not None and secrets.compare_digest(
            supplied_session,
            session_secret,
        )
        csrf_ok = x_csrf_token is not None and secrets.compare_digest(
            x_csrf_token,
            csrf_token,
        )
        origin_ok = request.headers.get("origin") == canonical_origin
        normalized_x_key = None if x_idempotency_key is None else x_idempotency_key.strip()
        normalized_standard_key = (
            None if standard_idempotency_key is None else standard_idempotency_key.strip()
        )
        idempotency_keys_agree = (
            normalized_x_key is None
            or normalized_standard_key is None
            or normalized_x_key == normalized_standard_key
        )
        selected_idempotency_key = normalized_standard_key or normalized_x_key
        idempotency_ok = (
            selected_idempotency_key is not None
            and bool(selected_idempotency_key)
            and len(selected_idempotency_key) <= 200
            and idempotency_keys_agree
        )
        if not (session_ok and csrf_ok and origin_ok and idempotency_ok):
            raise ApiError(
                403,
                "local_write_protection_failed",
                "本地操作验证失败。请刷新页面后重试",
            )
        assert selected_idempotency_key is not None
        return selected_idempotency_key

    @app.get("/api/v1/meta")
    def get_meta() -> dict[str, object]:
        return {
            "application_id": "DaHeLogistics",
            "application_version": __version__,
            "api_version": API_VERSION,
            "run_mode": "operational" if production_read_only else "shadow",
            "real_platform_access": platform_access_enabled,
            "platform_adapter": ("chengfeng_read_only" if platform_access_enabled else "fake"),
            "ocr_adapter": ("local" if ocr_execution_backend is not None else "fake"),
            "locked_set_review_enabled": False,
            "production_read_only": production_read_only,
        }

    @app.get("/api/v1/session")
    def create_local_session(request: Request) -> JSONResponse:
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        fetch_site = request.headers.get("sec-fetch-site")
        same_origin_page = (
            origin == canonical_origin
            or (
                origin is None
                and referer is not None
                and referer.startswith(f"{canonical_origin}/")
            )
            or (origin is None and fetch_site in {"same-origin", "none"})
        )
        if not same_origin_page:
            raise ApiError(
                403,
                "invalid_local_origin",
                "请从大禾本地操作台打开此页面",
            )
        response = JSONResponse(
            {
                "csrf_token": csrf_token,
                "application_version": __version__,
                "api_version": API_VERSION,
                "locked_set_review_enabled": False,
                "production_read_only": production_read_only,
            }
        )
        response.set_cookie(
            SESSION_COOKIE,
            session_secret,
            httponly=True,
            samesite="strict",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    shutdown_request_lock = threading.Lock()
    shutdown_request_keys: set[str] = set()

    def _environment_snapshot() -> dict[str, object]:
        browser_value = os.environ.get("DAHE_BROWSER_RUNTIME_ROOT")
        browser_root = (
            Path(browser_value)
            if browser_value is not None
            else default_browser_runtime_root()
        )
        ocr_value = os.environ.get("DAHE_OCR_RUNTIME_ROOT")
        ocr_root = Path(ocr_value) if ocr_value is not None else project_root / ".runtime"
        return environment_snapshot(
            data_root=data_root.resolve(),
            identity=release_identity,
            schema_revision=runtime.current_revision(),
            browser_runtime_root=browser_root,
            ocr_runtime_root=ocr_root,
        )

    @app.get("/api/v1/diagnostics/environment")
    def get_environment_snapshot(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        return _environment_snapshot()

    @app.get("/api/v1/diagnostics/support-bundle")
    def export_support_bundle(
        _: None = Depends(require_session),
    ) -> Response:
        content = build_support_bundle(
            data_root=data_root.resolve(),
            snapshot=_environment_snapshot(),
            breadcrumbs=breadcrumb_store,
        )
        return Response(
            content=content,
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    'attachment; filename="dahe-diagnostic-package.zip"'
                ),
                "Cache-Control": "no-store",
            },
        )

    @app.post("/api/v1/diagnostics/open-directory")
    def open_diagnostics_directory(
        _: str = Depends(require_write),
    ) -> dict[str, object]:
        diagnostics_root = data_root.resolve() / "diagnostics"
        diagnostics_root.mkdir(parents=True, exist_ok=True)
        open_path = getattr(os, "startfile", None)
        if open_path is None:
            raise ApiError(
                409,
                "diagnostics_directory_unavailable",
                "当前系统无法打开诊断目录。",
            )
        open_path(diagnostics_root)
        return {"opened": True}

    @app.post("/api/v1/diagnostics/breadcrumbs", status_code=202)
    def record_breadcrumb(
        payload: BreadcrumbRequest,
        _: str = Depends(require_write),
    ) -> dict[str, object]:
        breadcrumb_store.append(
            page=payload.page,
            action_type=payload.action_type,
            job_id=None,
            result="succeeded",
            error_code=None,
        )
        return {"accepted": True}

    @app.get("/api/v1/system/readiness")
    def system_readiness() -> dict[str, object]:
        return {
            "ready": True,
            "application_version": release_identity.application_version,
            "build_git_commit": release_identity.build_git_commit,
            "resource_sha256": release_identity.resource_sha256,
            "schema_revision": runtime.current_revision(),
        }

    @app.get("/api/v1/system/update-status")
    def get_update_status(
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        if update_service is None:
            return {
                "state": "unavailable",
                "current_version": __version__,
                "available_version": None,
                "update_available": False,
                "checked_at": None,
                "error_code": "update_program_unavailable",
            }
        return update_service.status().to_payload()

    @app.post("/api/v1/system/updates/check")
    def check_for_updates(
        _: str = Depends(require_write),
    ) -> dict[str, object]:
        if update_service is None:
            raise ApiError(
                409,
                "update_program_unavailable",
                "当前安装不支持软件更新。",
            )
        return update_service.check().to_payload()

    @app.post("/api/v1/system/updates/install", status_code=202)
    def install_update(
        _: str = Depends(require_write),
    ) -> dict[str, object]:
        if update_service is None:
            raise ApiError(
                409,
                "update_program_unavailable",
                "当前安装不支持软件更新。",
            )
        callback = app.state.request_shutdown
        if callback is None:
            raise ApiError(
                409,
                "application_shutdown_unavailable",
                "当前运行方式不能安全退出并安装更新。",
            )
        active_job_count = _count_update_blocking_jobs(
            repository.list_jobs()
        )
        try:
            status = update_service.install(
                active_job_count=active_job_count,
                process_id=os.getpid(),
            )
        except UpdateInstallBlocked as exc:
            raise ApiError(
                409,
                "software_update_blocked",
                "请先结束、取消或恢复当前任务，再安装更新。",  # noqa: RUF001
            ) from exc
        timer = threading.Timer(0.25, callback)
        timer.name = "dahe-update-shutdown"
        timer.daemon = True
        timer.start()
        return status.to_payload()

    @app.post("/api/v1/system/shutdown", status_code=202)
    def request_application_shutdown(
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        callback = app.state.request_shutdown
        if callback is None:
            raise ApiError(
                409,
                "application_shutdown_unavailable",
                "当前运行方式不支持从操作台退出程序。",
            )
        with shutdown_request_lock:
            replay = idempotency_key in shutdown_request_keys
            shutdown_request_keys.add(idempotency_key)
        if not replay:
            runtime_log_store.append(
                level="info",
                source="application",
                event_code="application_shutdown_requested",
                stream="application",
                message="Local application shutdown was requested.",
            )
            timer = threading.Timer(0.15, callback)
            timer.name = "dahe-console-shutdown"
            timer.daemon = True
            timer.start()
        return {
            "accepted": True,
            "idempotent_replay": replay,
        }

    @app.post("/api/v1/jobs")
    def create_job(
        payload: CreateJobRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        try:
            if payload.input_source == "chengfeng_shadow":
                source = payload.chengfeng_shadow
                assert source is not None
                if not enable_chengfeng_shadow:
                    raise ApiError(
                        403,
                        "chengfeng_shadow_disabled",
                        "当前未启用成丰只读影子任务。",
                    )
                if chengfeng_shadow_job_source is None:
                    raise ApiError(
                        409,
                        "chengfeng_shadow_source_unavailable",
                        "当前构建尚未具备可重放的成丰只读批次。",
                    )
                if payload.task_type != "audit" or payload.job_kind != "business":
                    raise ApiError(
                        400,
                        "chengfeng_shadow_contract_mismatch",
                        "成丰只读批次只支持业务审核任务。",
                    )
                if payload.expected_record_version is None:
                    raise ApiError(
                        400,
                        "expected_record_version_required",
                        "请刷新任务状态后重试。",
                    )
                try:
                    scheduled = chengfeng_shadow_job_source.resolve(
                        target_kind=ShadowBatchTargetKind(source.target_kind),
                        manifest_sha256=source.manifest_sha256,
                    )
                except (ChengfengShadowJobSourceError, ValueError) as exc:
                    raise ApiError(
                        409,
                        "chengfeng_shadow_source_invalid",
                        "成丰只读批次与当前构建或已封存证据不一致。",
                    ) from exc
                job, created = repository.create_scheduled_job(
                    fixture=scheduled,
                    scope_label=scheduled.scope_label,
                    idempotency_key=idempotency_key,
                    request_hash=_request_hash(payload),
                    expected_record_version=payload.expected_record_version,
                )
            else:
                scope = payload.scope
                assert scope is not None
                if scope.fixture_id in LOOP3_FIXTURES:
                    fixture_is_enabled = enable_test_fixtures or (
                        enable_loop9_scheduler_probe and scope.fixture_id == "loading-probe-001"
                    )
                    if not fixture_is_enabled:
                        raise ApiError(
                            403,
                            "test_fixture_disabled",
                            "当前入口未启用隔离调度测试夹具",
                        )
                    fixture = get_loop3_fixture(scope.fixture_id)
                    if payload.expected_record_version is None:
                        raise ApiError(
                            400,
                            "expected_record_version_required",
                            "请刷新任务状态后重试",
                        )
                    if (
                        payload.task_type != fixture.task_type
                        or payload.job_kind != fixture.job_kind
                    ):
                        raise ApiError(
                            400,
                            "fixture_contract_mismatch",
                            "任务类型与冻结测试夹具不一致",
                        )
                    job, created = repository.create_scheduled_job(
                        fixture=fixture,
                        scope_label=scope.label,
                        idempotency_key=idempotency_key,
                        request_hash=_request_hash(payload),
                        expected_record_version=(payload.expected_record_version),
                    )
                else:
                    if enable_loop9_scheduler_probe:
                        raise ApiError(
                            403,
                            "loop9_scheduler_probe_only",
                            "当前入口只允许隔离的装卸车调度探针",
                        )
                    if payload.task_type != "audit" or payload.job_kind != "business":
                        raise ApiError(
                            400,
                            "fixture_contract_mismatch",
                            "单条审核夹具只支持业务影子任务",
                        )
                    if payload.expected_record_version is None:
                        raise ApiError(
                            400,
                            "expected_record_version_required",
                            "请刷新任务状态后重试",
                        )
                    job, created = repository.create_scheduled_job(
                        fixture=default_audit_spec,
                        scope_label=(
                            default_audit_spec.scope_label
                            if default_audit_spec is not NORMAL_AUDIT_JOB_SPEC
                            else scope.label
                        ),
                        idempotency_key=idempotency_key,
                        request_hash=_request_hash(payload),
                        expected_record_version=(payload.expected_record_version),
                    )
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "该操作编号已经用于其他请求。请刷新后重试",
            ) from exc
        except ActiveScopeConflictError as exc:
            raise ApiError(
                409,
                "active_scope_conflict",
                "相同范围的审核任务正在运行",
            ) from exc
        except RecordVersionConflictError as exc:
            raise ApiError(
                409,
                "record_version_conflict",
                "任务入口状态已更新。请刷新后重试",
            ) from exc
        items = repository.list_items(job.job_id)
        projection = project_job(
            job,
            items,
            repository.runtime_projection(job.job_id),
            expose_internal_codes=not production_read_only,
        )
        if created and auto_run_jobs:
            scheduler_runner.notify()
        return {"created": created, "job": projection}

    @app.get("/api/v1/jobs")
    def list_jobs(_: None = Depends(require_session)) -> dict[str, object]:
        bundles, cursor = repository.snapshot()
        normal_active, normal_version = repository.fixture_start_state(
            default_audit_spec.conflict_key
        )
        start_actions = (
            {}
            if enable_loop9_scheduler_probe
            else build_start_action_matrix(
                has_active_scope_conflict=normal_active,
                expected_record_version=normal_version,
            )
        )
        if enable_test_fixtures or enable_loop9_scheduler_probe:
            protected_facts: dict[str, ProtectedStartActionFacts] = {}
            fixture_actions = (
                {
                    "start_audit_long": (
                        "audit-batch-long-001",
                        "启动长批次审核演练",
                    ),
                    "start_audit_short": (
                        "audit-batch-short-002",
                        "启动短批次审核演练",
                    ),
                    "start_loading_probe": (
                        "loading-probe-001",
                        "启动装卸车调度探针",
                    ),
                }
                if enable_test_fixtures
                else {
                    "start_loading_probe": (
                        "loading-probe-001",
                        "启动装卸车调度探针",
                    )
                }
            )
            for action_id, (fixture_id, label) in fixture_actions.items():
                fixture = get_loop3_fixture(fixture_id)
                active, version = repository.fixture_start_state(fixture.conflict_key)
                protected_facts[action_id] = ProtectedStartActionFacts(
                    label=label,
                    active_conflict=active,
                    expected_record_version=version,
                )
            start_actions.update(build_protected_start_action_matrix(protected_facts))
        return {
            "jobs": [
                project_job(
                    job,
                    items,
                    repository.runtime_projection(job.job_id),
                    expose_internal_codes=not production_read_only,
                )
                for job, items in bundles
            ],
            "event_cursor": cursor,
            "resources": project_resources(repository.resources_projection()),
            "start_actions": serialize_actions(start_actions),
        }

    @app.get("/api/v1/jobs/{job_id}")
    def get_job(
        job_id: str,
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        try:
            job = repository.get_job(job_id)
            items = repository.list_items(job_id)
        except JobNotFoundError as exc:
            raise ApiError(404, "job_not_found", "没有找到该任务") from exc
        return project_job(
            job,
            items,
            repository.runtime_projection(job_id),
            expose_internal_codes=not production_read_only,
        )

    @app.get("/api/v1/jobs/{job_id}/items")
    def get_job_items(
        job_id: str,
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        try:
            items = repository.list_items(job_id)
        except JobNotFoundError as exc:
            raise ApiError(404, "job_not_found", "没有找到该任务") from exc
        job = repository.get_job(job_id)
        return {
            "items": [
                project_item(
                    item,
                    include_runtime=job.scope_fixture_id != FIXTURE_ID,
                )
                for item in items
            ]
        }

    def control_job(
        *,
        job_id: str,
        action: str,
        payload: ControlJobRequest,
        idempotency_key: str,
    ) -> dict[str, object]:
        try:
            job, replay = repository.request_job_control(
                job_id=job_id,
                action=action,
                expected_record_version=payload.expected_record_version,
                idempotency_key=idempotency_key,
                request_hash=_control_request_hash(job_id, action, payload),
            )
        except JobNotFoundError as exc:
            raise ApiError(404, "job_not_found", "没有找到该任务") from exc
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "该操作编号已经用于其他请求",
            ) from exc
        except RecordVersionConflictError as exc:
            raise ApiError(
                409,
                "record_version_conflict",
                "任务状态已更新。请刷新后重试",
            ) from exc
        except JobControlError as exc:
            raise ApiError(409, "job_control_not_allowed", str(exc)) from exc
        if action == "cancel" and platform_access_enabled:
            try:
                browser_runtime.abort_active_operation(job_id)
            except Exception as exc:
                runtime_log_store.append(
                    level="warning",
                    source="platform",
                    event_code="business_read_abort_failed",
                    stream="application",
                    message=(
                        "Business read abort acknowledgement was not received "
                        f"({type(exc).__name__})."
                    ),
                    diagnostic_code="CF-BUSINESS-READ-ABORT-FAILED",
                    job_id=job_id,
                )
        items = repository.list_items(job_id)
        if auto_run_jobs:
            scheduler_runner.notify()
        return {
            "idempotent_replay": replay,
            "job": project_job(
                job,
                items,
                repository.runtime_projection(job_id),
                expose_internal_codes=not production_read_only,
            ),
        }

    @app.post("/api/v1/jobs/{job_id}/pause")
    def pause_job(
        job_id: str,
        payload: ControlJobRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        return control_job(
            job_id=job_id,
            action="pause",
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/api/v1/jobs/{job_id}/resume")
    def resume_job(
        job_id: str,
        payload: ControlJobRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        return control_job(
            job_id=job_id,
            action="resume",
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.post("/api/v1/jobs/{job_id}/cancel")
    def cancel_job(
        job_id: str,
        payload: ControlJobRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        return control_job(
            job_id=job_id,
            action="cancel",
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @app.get("/api/v1/resources")
    def get_resources(_: None = Depends(require_session)) -> dict[str, object]:
        return {"resources": project_resources(repository.resources_projection())}

    @app.get("/api/v1/events")
    async def stream_events(
        request: Request,
        _: None = Depends(require_session),
        after: int = 0,
    ) -> StreamingResponse:
        last_event_id = request.headers.get("last-event-id")
        cursor = after
        if last_event_id is not None:
            try:
                cursor = max(cursor, int(last_event_id))
            except ValueError as exc:
                raise ApiError(
                    400,
                    "invalid_event_cursor",
                    "事件续传位置无效",
                ) from exc
        if cursor < 0:
            raise ApiError(400, "invalid_event_cursor", "事件续传位置无效")

        async def generate() -> AsyncIterator[str]:
            current = cursor
            idle_cycles = 0
            while True:
                if await request.is_disconnected():
                    return
                events = await asyncio.to_thread(repository.events_after, current)
                if events:
                    idle_cycles = 0
                    for event in events:
                        current = int(str(event["event_id"]))
                        yield format_sse_message(event)
                else:
                    idle_cycles += 1
                    if idle_cycles >= 150:
                        idle_cycles = 0
                        yield ": keepalive\n\n"
                await asyncio.sleep(0.1)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    app.include_router(
        build_platform_router(
            enabled=platform_access_enabled,
            build_sha256=platform_build_sha256 or ("0" * 64),
            data_root=data_root.resolve(),
            access_repository=platform_access_repository,
            business_session_store=business_session_store,
            credential_service=platform_credential_service,
            connection_mode_store=platform_connection_mode_store,
            browser_control=browser_control_store,
            browser_runtime=browser_runtime,
            browser_lifecycle=browser_lifecycle,
            discovery_evidence=discovery_evidence_store,
            contract_validator=platform_contract_validator,
            job_repository=repository,
            daily_invocation_store=daily_invocation_store,
            daily_operational_ocr_store=daily_operational_ocr_store,
            transient_progress_store=transient_business_progress_store,
            selected_daily_contract=selected_daily_contract,
            daily_execution_available=(daily_execution_backend is not None),
            settlement_capture_store=settlement_capture_store,
            selected_settlement_contract=selected_contract,
            settlement_identity_context_sha256=(
                None if identity_authority is None else identity_authority.context_sha256
            ),
            settlement_capture_execution_available=(
                settlement_capture_execution_backend is not None
            ),
            verify_settlement_capture_prerequisites=(verify_settlement_capture_prerequisites),
            notify_scheduler=scheduler_runner.notify,
            runtime_log_store=runtime_log_store,
            instance_id=instance_id,
            session_id=platform_session_id,
            require_session=require_session,
            require_write=require_write,
            load_settlement_ready_waybill_numbers=(
                audit_workflow_repository.list_latest_settlement_ready_waybill_numbers
            ),
            expose_internal_codes=not production_read_only,
        )
    )
    app.include_router(
        build_audit_workflow_router(
            repository=audit_workflow_repository,
            evidence_store=evidence_store,
            require_session=require_session,
            require_write=require_write,
            after_action=scheduler.tick,
            load_resources=repository.resources_projection,
            runtime_log_store=runtime_log_store,
            production_guard=production_guard,
        )
    )
    daily_report_repository = SqliteDailyReportRepository(
        runtime=runtime,
        daily_store=daily_store,
        daily_items=daily_item_repository,
        default_output_directory=(
            (resolve_desktop_directory() / "成丰装卸车明细")
            if production_read_only
            else (data_root.resolve() / "reports")
        ).resolve(),
    )
    app.include_router(
        build_performance_settings_router(
            repository=performance_settings_repository,
            require_session=require_session,
            require_write=require_write,
        )
    )
    app.include_router(
        build_daily_item_router(
            enabled=production_read_only,
            repository=daily_item_repository,
            require_session=require_session,
            require_write=require_write,
        )
    )
    app.include_router(
        build_daily_report_router(
            enabled=production_read_only,
            repository=daily_report_repository,
            require_session=require_session,
            require_write=require_write,
        )
    )
    app.include_router(
        build_template_studio_router(
            repository=template_repository,
            require_session=require_session,
            require_write=require_write,
            developer_access_code=developer_access_code,
            enable_test_fixtures=enable_test_fixtures,
        )
    )
    if static_dir is not None:
        resolved_static_dir = static_dir.resolve(strict=True)
        if not resolved_static_dir.is_dir():
            raise ValueError("static_dir must be a directory")
        app.mount(
            "/",
            StaticFiles(directory=resolved_static_dir, html=True, check_dir=True),
            name="operator-console",
        )

    return app
