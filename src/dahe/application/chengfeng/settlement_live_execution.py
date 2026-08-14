from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import OperationalError

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeError,
    BrowserRuntimeLifecycle,
)
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditError,
    PlatformReadAuditEvidenceStore,
)
from dahe.adapters.files.shadow_batch_manifest import (
    ShadowBatchManifestStore,
    ShadowBatchManifestStoreError,
    ShadowBatchManifestTransientStoreError,
)
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
    FormalShadowSelectionStoreError,
    FormalShadowSelectionTransientStoreError,
)
from dahe.adapters.sqlite.browser_control import (
    BrowserControlError,
    BrowserControlRecord,
    BrowserControlStore,
)
from dahe.adapters.sqlite.platform_access import (
    PlatformAccessConflictError,
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.settlement_capture import (
    SettlementCaptureInvocationRecord,
    SettlementCaptureStoreConflictError,
    SqliteSettlementCaptureStore,
)
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowError,
)
from dahe.application.chengfeng.browser_readiness import (
    reconcile_operational_browser_readiness,
)
from dahe.application.chengfeng.operational_capture import (
    FastOperationalSettlementCaptureCoordinator,
    OperationalCaptureContractError,
    OperationalSettlementCaptureCoordinator,
)
from dahe.application.chengfeng.settlement_capture import (
    PaginatedSettlementCaptureCoordinator,
    SettlementCaptureContractError,
    SettlementCaptureManifest,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalSelectionExclusionSnapshot,
)
from dahe.jobs.settlement_capture_execution import (
    SETTLEMENT_CAPTURE_STAGE,
    SettlementCaptureStageExecution,
    SettlementCaptureStageWork,
)
from dahe.ports.chengfeng import (
    CURRENT_PENDING_SETTLEMENT_SCOPE,
    HISTORICAL_SETTLED_SCOPE,
    BrowserCommandAuthority,
    BrowserContextClosedError,
    ChengfengReadError,
    LoginRequiredError,
)
from dahe.verification.loop9_dataset_isolation import (
    Loop9DatasetIsolationError,
)
from dahe.verification.loop9_exclusion_authority import (
    Loop9VerifiedExclusionSnapshot,
)

# One batch may use three successively reduced-concurrency worker attempts.
# Keep the fencing authority valid until that bounded retry budget and browser
# preparation have both completed.
_CONTROL_TTL = timedelta(minutes=30)
_MAX_TRANSIENT_SELECTION_RETRIES = 2
_MAX_OPERATIONAL_BROWSER_RECOVERY_RETRIES = 1
_BLOCKED_SELECTION_DIAGNOSTICS = {
    "sealed capture has insufficient eligible waybills": (
        "SETTLEMENT-SELECTION-INSUFFICIENT"
    ),
    "locked selection authority is unavailable": (
        "SETTLEMENT-LOCKED-AUTHORITY-REQUIRED"
    ),
    "current locked gate authority is unavailable": (
        "SETTLEMENT-LOCKED-GATE-REQUIRED"
    ),
    "current locked gate build or selection binding changed": (
        "SETTLEMENT-LOCKED-GATE-AUTHORITY-MISMATCH"
    ),
    "real shadow selection locked gate binding changed": (
        "SETTLEMENT-LOCKED-GATE-AUTHORITY-MISMATCH"
    ),
    "prior selection authority does not match the capture": (
        "SETTLEMENT-SELECTION-AUTHORITY-MISMATCH"
    ),
    "formal selection target belongs to another capture": (
        "SETTLEMENT-SELECTION-AUTHORITY-MISMATCH"
    ),
    "full-history exclusion authority does not match the capture": (
        "SETTLEMENT-SELECTION-EXCLUSIONS-MISMATCH"
    ),
    "sealed capture overlaps an excluded discovery scope": (
        "SETTLEMENT-SELECTION-DISCOVERY-OVERLAP"
    ),
}

_BROWSER_RUNTIME_DIAGNOSTICS = {
    "browser_saved_credential_missing": "CF-CREDENTIAL-REQUIRED",
    "browser_saved_login_captcha_required": "CF-LOGIN-INTERVENTION-REQUIRED",
    "browser_saved_login_failed": "CF-LOGIN-INTERVENTION-REQUIRED",
    "browser_saved_login_structure_changed": "CF-LOGIN-INTERVENTION-REQUIRED",
    "browser_context_closed": "CF-SETTLEMENT-BROWSER-CLOSED",
    "browser_worker_unavailable": "CF-SETTLEMENT-BROWSER-UNAVAILABLE",
    "browser_worker_timeout": "CF-SETTLEMENT-BROWSER-TIMEOUT",
    "browser_contract_subject_control_unavailable": (
        "CF-SETTLEMENT-SUBJECT-CONTROL-UNAVAILABLE"
    ),
    "browser_contract_subject_option_unavailable": (
        "CF-SETTLEMENT-SUBJECT-OPTION-UNAVAILABLE"
    ),
    "browser_contract_subject_switch_failed": (
        "CF-SETTLEMENT-SUBJECT-SWITCH-FAILED"
    ),
    "browser_contract_subject_confirmation_failed": (
        "CF-SETTLEMENT-SUBJECT-CONFIRMATION-FAILED"
    ),
    "browser_session_settlement_scope_control_unavailable": (
        "CF-SETTLEMENT-SCOPE-CONTROL-UNAVAILABLE"
    ),
    "browser_session_fixed_values_rejected": (
        "CF-SETTLEMENT-FIXED-VALUES-REJECTED"
    ),
    "browser_session_waybill_control_unavailable": (
        "CF-SETTLEMENT-WAYBILL-CONTROL-UNAVAILABLE"
    ),
    "browser_session_query_control_unavailable": (
        "CF-SETTLEMENT-QUERY-CONTROL-UNAVAILABLE"
    ),
    "browser_session_automation_unfreeze_failed": (
        "CF-SETTLEMENT-BROWSER-UNFREEZE-FAILED"
    ),
    "browser_operational_query_failed": (
        "CF-SETTLEMENT-OPERATIONAL-QUERY-FAILED"
    ),
    "browser_operational_query_contract_changed": (
        "CF-SETTLEMENT-OPERATIONAL-CONTRACT-CHANGED"
    ),
    "browser_operational_query_not_completed": (
        "CF-SETTLEMENT-OPERATIONAL-QUERY-INCOMPLETE"
    ),
    "browser_operational_cache_refresh_failed": (
        "CF-SETTLEMENT-CACHE-REFRESH-FAILED"
    ),
    "browser_operational_prepare_fields_invalid": (
        "CF-SETTLEMENT-PREPARE-FIELDS-INVALID"
    ),
    "browser_operational_prepare_metrics_invalid": (
        "CF-SETTLEMENT-PREPARE-METRICS-INVALID"
    ),
    "browser_operational_prepare_values_invalid": (
        "CF-SETTLEMENT-PREPARE-VALUES-INVALID"
    ),
    "browser_operational_trace_fields_invalid": (
        "CF-SETTLEMENT-TRACE-FIELDS-INVALID"
    ),
    "browser_operational_trace_values_invalid": (
        "CF-SETTLEMENT-TRACE-VALUES-INVALID"
    ),
    "browser_operational_response_contract_failed": (
        "CF-SETTLEMENT-RESPONSE-CONTRACT-FAILED"
    ),
    "browser_operational_unexpected_failed": (
        "CF-SETTLEMENT-OPERATIONAL-UNEXPECTED-FAILED"
    ),
}

_BROWSER_RUNTIME_TRACE_DIAGNOSTICS = {
    "approved_request_count": "APPROVED-REQUEST-COUNT",
    "blocked_request_count": "BLOCKED-REQUEST-COUNT",
    "cache_refresh_count": "CACHE-REFRESH-COUNT",
    "duration_ms": "DURATION",
    "observed_request_count": "OBSERVED-REQUEST-COUNT",
    "page_count": "PAGE-COUNT",
    "query_attempt_count": "QUERY-ATTEMPT-COUNT",
    "query_attempt_id": "QUERY-ATTEMPT-ID",
    "request_method": "REQUEST-METHOD",
    "request_path": "REQUEST-PATH",
    "request_reconciliation": "REQUEST-RECONCILIATION",
    "resource_type": "RESOURCE-TYPE",
    "response_byte_size": "RESPONSE-BYTE-SIZE",
    "response_status": "RESPONSE-STATUS",
    "response_structure_sha256": "RESPONSE-STRUCTURE",
    "schema_version": "SCHEMA-VERSION",
    "zero_retry_performed": "ZERO-RETRY",
}


def _browser_runtime_diagnostic(error: BrowserRuntimeError) -> str:
    """Map only reviewed worker codes into durable, non-sensitive diagnostics."""

    prefix = "browser_operational_trace_"
    suffix = "_invalid"
    if error.code.startswith(prefix) and error.code.endswith(suffix):
        field_name = error.code[len(prefix) : -len(suffix)]
        diagnostic_field = _BROWSER_RUNTIME_TRACE_DIAGNOSTICS.get(field_name)
        if diagnostic_field is not None:
            return f"CF-SETTLEMENT-TRACE-{diagnostic_field}-INVALID"
    return _BROWSER_RUNTIME_DIAGNOSTICS.get(
        error.code,
        "CF-SETTLEMENT-BROWSER-RUNTIME-FAILED",
    )


class SettlementCaptureLiveStageExecutor:
    """Advance one live read or finish its local selection without rereading."""

    def __init__(
        self,
        *,
        invocation_store: SqliteSettlementCaptureStore,
        coordinator: PaginatedSettlementCaptureCoordinator,
        selection_store: FormalShadowSelectionStore,
        batch_store: ShadowBatchManifestStore,
        request_audit_store: PlatformReadAuditEvidenceStore,
        access_repository: SqlitePlatformAccessRepository,
        browser_control: BrowserControlStore,
        browser_runtime: BrowserRuntime,
        browser_lifecycle: BrowserRuntimeLifecycle,
        instance_id: str,
        session_id: str,
        build_sha256: str,
        pipeline_fingerprint: str,
        exclusion_snapshot_loader: Callable[
            [SettlementCaptureManifest],
            Loop9VerifiedExclusionSnapshot,
        ],
        target_prerequisite_validator: Callable[
            [ShadowBatchTargetKind],
            None,
        ],
        validation_authority_gate: Callable[[], bool],
        operational_coordinator: (
            OperationalSettlementCaptureCoordinator | None
        ) = None,
        fast_operational_coordinator: (
            FastOperationalSettlementCaptureCoordinator | None
        ) = None,
        operational_materializer: Callable[[str], None] | None = None,
        contract_subject_for_job: Callable[[str], str] = (
            lambda _job_id: "shanxi_guienbo"
        ),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._invocations = invocation_store
        self._coordinator = coordinator
        self._selections = selection_store
        self._batches = batch_store
        self._request_audit_store = request_audit_store
        self._access = access_repository
        self._browser_control = browser_control
        self._browser_runtime = browser_runtime
        self._browser_lifecycle = browser_lifecycle
        self._instance_id = instance_id
        self._session_id = session_id
        self._build_sha256 = build_sha256
        self._pipeline_fingerprint = pipeline_fingerprint
        self._exclusion_snapshot_loader = exclusion_snapshot_loader
        self._target_prerequisite_validator = (
            target_prerequisite_validator
        )
        self._validation_authority_gate = validation_authority_gate
        self._operational_coordinator = operational_coordinator
        self._fast_operational_coordinator = (
            fast_operational_coordinator
        )
        self._operational_materializer = operational_materializer
        self._contract_subject_for_job = contract_subject_for_job
        self._materialized_operational_jobs: set[str] = set()
        self._pending_operational_handoffs: set[str] = set()
        self._operational_browser_recovery_counts: dict[str, int] = {}
        self._clock = clock

    def _ensure_operational_browser_prepared(self, job_id: str) -> None:
        """Confirm the current browser generation owns settlement authority."""

        # The job survives a controlled browser restart.  Preparation caching
        # belongs to the runtime generation; this set only records that the
        # terminal job still requires its configured handoff or close action.
        self._browser_runtime.prepare_operational_compat(
            getattr(
                self,
                "_contract_subject_for_job",
                lambda _job_id: "shanxi_guienbo",
            )(job_id)
        )
        self._pending_operational_handoffs.add(job_id)

    def __call__(
        self,
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        invocation: SettlementCaptureInvocationRecord | None = None
        acquired: BrowserControlRecord | None = None
        is_operational = False
        rebuild_operational_browser = False
        worker_id = f"settlement-capture-{work.stage_attempt_id}"
        try:
            invocation = self._invocations.get_by_job(work.job_id)
            target_kind = self._invocations.target_kind(
                invocation.invocation_id
            )
            if invocation.status == "operational_ready":
                return self._operational_execution(work, invocation)
            if invocation.status == "selected":
                if target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
                    self._target_prerequisite_validator(target_kind)
                return self._selected_execution(work, invocation)
            if invocation.status in {"selection_blocked", "failed"}:
                return self._failed_execution(
                    work,
                    diagnostic_code=(
                        invocation.diagnostic_code
                        or "SETTLEMENT-CAPTURE-TERMINAL"
                    ),
                )
            if invocation.status == "sealed":
                if target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
                    self._target_prerequisite_validator(target_kind)
                return self._finalize_selection(
                    work,
                    invocation=invocation,
                    platform_read_performed=False,
                    checkpoint_revision=None,
                )
            if invocation.status != "collecting":
                raise SettlementCaptureStoreConflictError(
                    "settlement capture invocation is unavailable"
                )

            is_operational = (
                target_kind
                is ShadowBatchTargetKind.OPERATIONAL_COMPAT
            )
            if not is_operational:
                try:
                    validation_authority_ready = (
                        self._validation_authority_gate()
                    )
                except Exception:
                    validation_authority_ready = False
                if not validation_authority_ready:
                    return self._failed_execution(
                        work,
                        diagnostic_code=(
                            "SETTLEMENT-VALIDATION-GATE-REQUIRED"
                        ),
                    )
                self._target_prerequisite_validator(target_kind)
            elif (
                self._operational_coordinator is None
                and self._fast_operational_coordinator is None
            ):
                return self._failed_execution(
                    work,
                    diagnostic_code=(
                        "CF-OPERATIONAL-CAPTURE-UNAVAILABLE"
                    ),
                )
            purpose = self._purpose_for_target(target_kind)
            authorization_time = self._clock()
            grant = self._access.authorize(
                access_window_id=invocation.access_window_id,
                purpose=purpose,
                job_id=work.job_id,
                session_id=self._session_id,
                build_sha256=self._build_sha256,
                now=authorization_time,
            )
            control_ttl = min(
                _CONTROL_TTL,
                grant.expires_at - authorization_time,
            )
            if control_ttl <= timedelta(0):
                raise AccessWindowError("access window is expired")
            control = self._browser_control.get(self._session_id)
            if is_operational:
                control = reconcile_operational_browser_readiness(
                    browser_control=self._browser_control,
                    browser_runtime=self._browser_runtime,
                    browser_lifecycle=self._browser_lifecycle,
                    session_id=self._session_id,
                    now=self._clock(),
                )
                if control.browser_lifecycle == "ready":
                    self._pending_operational_handoffs.discard(work.job_id)
            if (
                control.browser_lifecycle != "ready"
                or control.browser_control_mode != "idle"
                or not self._browser_runtime.running
            ):
                return self._retry_execution(
                    work,
                    diagnostic_code="CF-SETTLEMENT-BROWSER-NOT-READY",
                )
            acquired = self._browser_control.acquire_automated(
                session_id=self._session_id,
                instance_id=self._instance_id,
                worker_id=worker_id,
                job_id=work.job_id,
                expected_record_version=control.record_version,
                now=authorization_time,
                ttl=control_ttl,
            )
            if acquired.fencing_token is None:
                raise BrowserControlError(
                    "settlement browser authority has no fencing token"
                )
            authority = BrowserCommandAuthority(
                session_id=self._session_id,
                instance_id=self._instance_id,
                worker_id=worker_id,
                job_id=work.job_id,
                control_epoch=acquired.control_epoch,
                fencing_token=acquired.fencing_token,
            )
            if is_operational:
                self._ensure_operational_browser_prepared(work.job_id)
            else:
                self._browser_runtime.prepare_automated(
                    scope=self._scope_for_target(
                        target_kind,
                        invocation.scope,
                    ),
                )
            if is_operational:
                strategy_loader = getattr(
                    self._invocations,
                    "capture_strategy",
                    None,
                )
                strategy = (
                    str(strategy_loader(invocation.job_id))
                    if callable(strategy_loader)
                    else "legacy"
                )
                if strategy in {"batch_v1", "whole_run_v1"}:
                    if self._fast_operational_coordinator is None:
                        raise OperationalCaptureContractError(
                            "fast operational capture is unavailable"
                        )
                    operational_step = (
                        self._fast_operational_coordinator.advance(
                            invocation=invocation,
                            authority=authority,
                        )
                    )
                else:
                    if self._operational_coordinator is None:
                        raise OperationalCaptureContractError(
                            "legacy operational capture is unavailable"
                        )
                    operational_step = (
                        self._operational_coordinator.advance(
                            invocation=invocation,
                            authority=authority,
                        )
                    )
                self._operational_browser_recovery_counts.pop(
                    work.job_id,
                    None,
                )
                self._release(
                    work=work,
                    invocation=invocation,
                    acquired=acquired,
                    worker_id=worker_id,
                )
                acquired = None
                if operational_step.has_more:
                    return SettlementCaptureStageExecution(
                        stage_attempt_id=work.stage_attempt_id,
                        outcome="succeeded",
                        completed_stage=SETTLEMENT_CAPTURE_STAGE,
                        next_stage=SETTLEMENT_CAPTURE_STAGE,
                        platform_read_performed=(
                            operational_step.platform_read_performed
                        ),
                        checkpoint_revision=(
                            operational_step.checkpoint_revision
                        ),
                        manifest_sha256=None,
                        diagnostic_code=None,
                    )
                if operational_step.capture_sha256 is None:
                    raise OperationalCaptureContractError(
                        "complete operational capture has no identity"
                    )
                checkpoints = operational_step.checkpoints
                if not checkpoints or checkpoints[0].page is None:
                    raise OperationalCaptureContractError(
                        "complete operational capture has no audit lineage"
                    )
                total = checkpoints[0].page.total
                list_read_count = (
                    max(1, (total + 49) // 50)
                    if strategy in {"batch_v1", "whole_run_v1"}
                    else len(checkpoints)
                )
                self._request_audit_store.seal(
                    job_id=work.job_id,
                    authority=PlatformReadAuditAuthority(
                        build_sha256=self._build_sha256,
                        settlement_contract_sha256=(
                            invocation.contract_canonical_sha256
                        ),
                        settlement_contract_selection_sha256=(
                            invocation.contract_selection_sha256
                        ),
                    ),
                    purpose="operational_settlement",
                    expected_succeeded_operations={
                        "list_waybills": list_read_count,
                        "get_waybill_detail": sum(
                            len(checkpoint.details)
                            for checkpoint in checkpoints
                        ),
                        "download_ticket_image": sum(
                            len(checkpoint.ticket_images)
                            for checkpoint in checkpoints
                        ),
                    },
                )
                ready = self._invocations.mark_operational_ready(
                    invocation_id=invocation.invocation_id,
                    expected_record_version=invocation.record_version,
                    capture_sha256=(
                        operational_step.capture_sha256
                    ),
                    now=self._clock(),
                )
                return self._operational_execution(
                    work,
                    ready,
                    platform_read_performed=(
                        operational_step.platform_read_performed
                    ),
                    checkpoint_revision=(
                        operational_step.checkpoint_revision
                    ),
                )
            step = self._coordinator.advance(
                invocation_id=invocation.invocation_id,
                authority=authority,
            )
            self._release(
                work=work,
                invocation=invocation,
                acquired=acquired,
                worker_id=worker_id,
            )
            acquired = None
            if step.has_more:
                return SettlementCaptureStageExecution(
                    stage_attempt_id=work.stage_attempt_id,
                    outcome="succeeded",
                    completed_stage=SETTLEMENT_CAPTURE_STAGE,
                    next_stage=SETTLEMENT_CAPTURE_STAGE,
                    platform_read_performed=(
                        step.platform_read_performed
                    ),
                    checkpoint_revision=step.checkpoint_revision,
                    manifest_sha256=None,
                    diagnostic_code=None,
                )
            sealed = self._invocations.get(invocation.invocation_id)
            if sealed.status != "sealed":
                raise SettlementCaptureStoreConflictError(
                    "complete settlement capture was not sealed"
                )
            return self._finalize_selection(
                work,
                invocation=sealed,
                platform_read_performed=step.platform_read_performed,
                checkpoint_revision=step.checkpoint_revision,
            )
        except ChengfengReadError as exc:
            if isinstance(exc, LoginRequiredError):
                return self._waiting_external_execution(
                    work,
                    diagnostic_code=exc.diagnostic_code,
                )
            if is_operational and isinstance(
                exc,
                BrowserContextClosedError,
            ):
                return self._operational_browser_recovery_execution(
                    work,
                    diagnostic_code=exc.diagnostic_code,
                )
            if is_operational and exc.retryable:
                return self._waiting_external_execution(
                    work,
                    diagnostic_code=exc.diagnostic_code,
                )
            if exc.retryable:
                return self._retry_execution(
                    work,
                    diagnostic_code=exc.diagnostic_code,
                )
            return self._failed_execution(
                work,
                diagnostic_code=exc.diagnostic_code,
            )
        except BrowserControlError:
            return self._retry_execution(
                work,
                diagnostic_code="CF-SETTLEMENT-BROWSER-CONTROL-FAILED",
            )
        except BrowserRuntimeError as exc:
            if exc.code in {
                "browser_saved_credential_missing",
                "browser_saved_login_captcha_required",
                "browser_saved_login_failed",
                "browser_saved_login_structure_changed",
                "browser_read_login_required",
            }:
                return self._waiting_external_execution(
                    work,
                    diagnostic_code=_browser_runtime_diagnostic(exc),
                )
            if is_operational and exc.code in {
                "browser_context_closed",
                "browser_session_settlement_route_unavailable",
                "browser_worker_unavailable",
            }:
                rebuild_operational_browser = True
                return self._operational_browser_recovery_execution(
                    work,
                    diagnostic_code=_browser_runtime_diagnostic(exc),
                )
            if is_operational and exc.code in {
                "browser_read_network_failed",
                "browser_read_http_failed",
                "browser_read_rate_limited",
                "browser_read_server_transient",
                "browser_worker_timeout",
            }:
                return self._waiting_external_execution(
                    work,
                    diagnostic_code=_browser_runtime_diagnostic(exc),
                )
            if is_operational:
                return self._failed_execution(
                    work,
                    diagnostic_code=_browser_runtime_diagnostic(exc),
                )
            return self._retry_execution(
                work,
                diagnostic_code=_browser_runtime_diagnostic(exc),
            )
        except AccessWindowError:
            return self._waiting_external_execution(
                work,
                diagnostic_code=(
                    "CF-SETTLEMENT-ACCESS-WINDOW-EXPIRED"
                ),
            )
        except PlatformAccessConflictError:
            return self._failed_execution(
                work,
                diagnostic_code="CF-SETTLEMENT-ACCESS-WINDOW-INVALID",
            )
        except FormalShadowSelectionStoreError:
            return self._failed_execution(
                work,
                diagnostic_code="SETTLEMENT-LOCKED-GATE-REQUIRED",
            )
        except (
            SettlementCaptureContractError,
            OperationalCaptureContractError,
            PlatformReadAuditError,
            SettlementCaptureStoreConflictError,
            ValueError,
        ):
            return self._failed_execution(
                work,
                diagnostic_code="SETTLEMENT-CAPTURE-CONTRACT-FAILED",
            )
        except Exception:
            return self._failed_execution(
                work,
                diagnostic_code="SETTLEMENT-CAPTURE-EXECUTION-FAILED",
            )
        finally:
            if acquired is not None:
                self._release_after_failed_execution(
                    work=work,
                    invocation=invocation,
                    acquired=acquired,
                    worker_id=worker_id,
                    is_operational=is_operational,
                )
            if rebuild_operational_browser:
                self._pending_operational_handoffs.discard(work.job_id)
                with contextlib.suppress(
                    BrowserRuntimeError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ):
                    self._browser_runtime.close()

    @staticmethod
    def _purpose_for_target(
        target_kind: ShadowBatchTargetKind,
    ) -> AccessPurpose:
        if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
            return AccessPurpose.FORMAL_LOCKED_SET
        if target_kind is ShadowBatchTargetKind.OPERATIONAL_COMPAT:
            return AccessPurpose.PRODUCTION_SHADOW
        return AccessPurpose.PRODUCTION_SHADOW

    @staticmethod
    def _scope_for_target(
        target_kind: ShadowBatchTargetKind,
        source_scope: str,
    ) -> str:
        if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
            if source_scope in {
                CURRENT_PENDING_SETTLEMENT_SCOPE,
                HISTORICAL_SETTLED_SCOPE,
            }:
                return source_scope
            raise ValueError("locked-set source scope is invalid")
        if source_scope != CURRENT_PENDING_SETTLEMENT_SCOPE:
            raise ValueError("settlement source scope must remain current")
        return source_scope

    def _finalize_selection(
        self,
        work: SettlementCaptureStageWork,
        *,
        invocation: SettlementCaptureInvocationRecord,
        platform_read_performed: bool,
        checkpoint_revision: int | None,
    ) -> SettlementCaptureStageExecution:
        try:
            capture = self._invocations.load_manifest(
                invocation.invocation_id
            )
            target_kind = self._invocations.target_kind(
                invocation.invocation_id
            )
            verified_exclusions = self._exclusion_snapshot_loader(
                capture
            )
            exclusion_snapshot = FormalSelectionExclusionSnapshot(
                authority_sha256=verified_exclusions.authority_sha256,
                child_index_head_sha256=(
                    verified_exclusions.child_index_head_sha256
                ),
                source_boundary_sha256=(
                    verified_exclusions.source_boundary_sha256
                ),
                source_inventory_high_watermark=(
                    verified_exclusions.source_inventory_high_watermark
                ),
                identity_context_sha256=(
                    verified_exclusions.identity_context_sha256
                ),
                expected_current_build_sha256=(
                    verified_exclusions.expected_current_build_sha256
                ),
                expected_settlement_contract_sha256=(
                    verified_exclusions
                    .expected_settlement_contract_sha256
                ),
                expected_settlement_selection_sha256=(
                    verified_exclusions
                    .expected_settlement_selection_sha256
                ),
                excluded_platform_identity_sha256s=(
                    verified_exclusions
                    .excluded_platform_identity_sha256s
                ),
                excluded_image_sha256s=(
                    verified_exclusions.excluded_image_sha256s
                ),
                excluded_scope_exclusion_tokens=(
                    verified_exclusions
                    .excluded_scope_exclusion_tokens
                ),
                excluded_perceptual_fingerprints=(
                    verified_exclusions
                    .excluded_perceptual_fingerprints
                ),
            )
            selection = self._selections.select(
                capture=capture,
                target_kind=target_kind,
                pipeline_fingerprint=self._pipeline_fingerprint,
                exclusion_snapshot=exclusion_snapshot,
                expected_current_build_sha256=(
                    self._build_sha256
                    if target_kind
                    is ShadowBatchTargetKind.REAL_SHADOW_30
                    else None
                ),
                expected_settlement_contract_sha256=(
                    capture.contract_canonical_sha256
                    if target_kind
                    is ShadowBatchTargetKind.REAL_SHADOW_30
                    else None
                ),
            )
            sealed_batch = self._batches.seal(
                selection.batch_manifest
            )
            verified_selection = self._selections.load(target_kind)
            verified_batch = self._batches.load(
                sealed_batch.canonical_sha256
            )
            if (
                verified_selection.canonical_sha256
                != selection.canonical_sha256
                or verified_selection.source_capture_sha256
                != capture.canonical_sha256
                or verified_batch.canonical_sha256
                != selection.batch_manifest.canonical_sha256
                or verified_selection.batch_manifest.canonical_sha256
                != verified_batch.canonical_sha256
            ):
                raise FormalShadowSelectionStoreError(
                    "formal selection content-addressed verification failed"
                )
            selected = self._invocations.mark_selected(
                invocation_id=invocation.invocation_id,
                expected_record_version=invocation.record_version,
                selection_manifest_sha256=(
                    verified_selection.canonical_sha256
                ),
                batch_manifest_sha256=verified_batch.canonical_sha256,
                now=self._clock(),
            )
            return self._selected_execution(
                work,
                selected,
                platform_read_performed=platform_read_performed,
                checkpoint_revision=checkpoint_revision,
            )
        except (
            FormalShadowSelectionTransientStoreError,
            ShadowBatchManifestTransientStoreError,
            OSError,
            OperationalError,
        ):
            return self._retry_selection_or_block(
                work,
                invocation=invocation,
            )
        except FormalShadowSelectionStoreError as exc:
            return self._block_selection_execution(
                work,
                invocation=invocation,
                diagnostic_code=(
                    _BLOCKED_SELECTION_DIAGNOSTICS.get(str(exc))
                    or "SETTLEMENT-SELECTION-DETERMINISTIC-BLOCKED"
                ),
            )
        except Loop9DatasetIsolationError:
            return self._block_selection_execution(
                work,
                invocation=invocation,
                diagnostic_code=(
                    "SETTLEMENT-SELECTION-EXCLUSIONS-UNAVAILABLE"
                ),
            )
        except ShadowBatchManifestStoreError:
            return self._block_selection_execution(
                work,
                invocation=invocation,
                diagnostic_code=(
                    "SETTLEMENT-BATCH-DETERMINISTIC-BLOCKED"
                ),
            )
        except SettlementCaptureStoreConflictError:
            current = self._invocations.get(invocation.invocation_id)
            if current.status == "selected":
                return self._selected_execution(
                    work,
                    current,
                    platform_read_performed=platform_read_performed,
                    checkpoint_revision=checkpoint_revision,
                )
            return self._block_selection_execution(
                work,
                invocation=invocation,
                diagnostic_code=(
                    "SETTLEMENT-SELECTION-COMMIT-CONFLICT"
                ),
            )
        except Exception:
            return self._block_selection_execution(
                work,
                invocation=invocation,
                diagnostic_code=(
                    "SETTLEMENT-SELECTION-DETERMINISTIC-BLOCKED"
                ),
            )

    def _retry_selection_or_block(
        self,
        work: SettlementCaptureStageWork,
        *,
        invocation: SettlementCaptureInvocationRecord,
    ) -> SettlementCaptureStageExecution:
        if work.attempt_count < _MAX_TRANSIENT_SELECTION_RETRIES:
            return self._retry_execution(
                work,
                diagnostic_code=(
                    "SETTLEMENT-SELECTION-TRANSIENT-IO-RETRY"
                ),
            )
        return self._block_selection_execution(
            work,
            invocation=invocation,
            diagnostic_code=(
                "SETTLEMENT-SELECTION-TRANSIENT-RETRY-EXHAUSTED"
            ),
        )

    def _block_selection_execution(
        self,
        work: SettlementCaptureStageWork,
        *,
        invocation: SettlementCaptureInvocationRecord,
        diagnostic_code: str,
    ) -> SettlementCaptureStageExecution:
        blocked = self._invocations.block_selection(
            invocation_id=invocation.invocation_id,
            expected_record_version=invocation.record_version,
            diagnostic_code=diagnostic_code,
            now=self._clock(),
        )
        return self._failed_execution(
            work,
            diagnostic_code=(
                blocked.diagnostic_code or diagnostic_code
            ),
        )

    def _selected_execution(
        self,
        work: SettlementCaptureStageWork,
        invocation: SettlementCaptureInvocationRecord,
        *,
        platform_read_performed: bool = False,
        checkpoint_revision: int | None = None,
    ) -> SettlementCaptureStageExecution:
        if (
            invocation.status != "selected"
            or invocation.manifest_sha256 is None
            or invocation.selection_manifest_sha256 is None
            or invocation.batch_manifest_sha256 is None
        ):
            raise SettlementCaptureStoreConflictError(
                "selected settlement capture is incomplete"
            )
        target_kind = self._invocations.target_kind(
            invocation.invocation_id
        )
        selection = self._selections.load(target_kind)
        batch = self._batches.load(invocation.batch_manifest_sha256)
        if (
            selection.canonical_sha256
            != invocation.selection_manifest_sha256
            or selection.source_capture_sha256
            != invocation.manifest_sha256
            or batch.canonical_sha256
            != invocation.batch_manifest_sha256
            or selection.batch_manifest.canonical_sha256
            != batch.canonical_sha256
        ):
            raise SettlementCaptureStoreConflictError(
                "selected settlement capture authority changed"
            )
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="succeeded",
            completed_stage=SETTLEMENT_CAPTURE_STAGE,
            next_stage=None,
            platform_read_performed=platform_read_performed,
            checkpoint_revision=checkpoint_revision,
            manifest_sha256=invocation.manifest_sha256,
            selection_manifest_sha256=(
                invocation.selection_manifest_sha256
            ),
            batch_manifest_sha256=invocation.batch_manifest_sha256,
            diagnostic_code=None,
        )

    @staticmethod
    def _operational_execution(
        work: SettlementCaptureStageWork,
        invocation: SettlementCaptureInvocationRecord,
        *,
        platform_read_performed: bool = False,
        checkpoint_revision: int | None = None,
    ) -> SettlementCaptureStageExecution:
        if (
            invocation.status != "operational_ready"
            or invocation.manifest_sha256 is None
            or invocation.selection_manifest_sha256 is not None
            or invocation.batch_manifest_sha256 is not None
        ):
            raise SettlementCaptureStoreConflictError(
                "operational settlement capture is incomplete"
            )
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="succeeded",
            completed_stage=SETTLEMENT_CAPTURE_STAGE,
            next_stage=None,
            platform_read_performed=platform_read_performed,
            checkpoint_revision=checkpoint_revision,
            manifest_sha256=None,
            selection_manifest_sha256=None,
            batch_manifest_sha256=None,
            operational_capture_sha256=(
                invocation.manifest_sha256
            ),
            diagnostic_code=None,
        )

    @staticmethod
    def _retry_execution(
        work: SettlementCaptureStageWork,
        *,
        diagnostic_code: str,
    ) -> SettlementCaptureStageExecution:
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="retry",
            completed_stage=SETTLEMENT_CAPTURE_STAGE,
            next_stage=SETTLEMENT_CAPTURE_STAGE,
            platform_read_performed=False,
            checkpoint_revision=None,
            manifest_sha256=None,
            diagnostic_code=diagnostic_code,
        )

    @staticmethod
    def _failed_execution(
        work: SettlementCaptureStageWork,
        *,
        diagnostic_code: str,
    ) -> SettlementCaptureStageExecution:
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="failed",
            completed_stage=SETTLEMENT_CAPTURE_STAGE,
            next_stage=None,
            platform_read_performed=False,
            checkpoint_revision=None,
            manifest_sha256=None,
            diagnostic_code=diagnostic_code,
        )

    def _operational_browser_recovery_execution(
        self,
        work: SettlementCaptureStageWork,
        *,
        diagnostic_code: str,
    ) -> SettlementCaptureStageExecution:
        recovery_counts = getattr(
            self,
            "_operational_browser_recovery_counts",
            None,
        )
        if recovery_counts is None:
            recovery_counts = {}
            self._operational_browser_recovery_counts = recovery_counts
        count = recovery_counts.get(work.job_id, 0) + 1
        recovery_counts[work.job_id] = count
        if count <= _MAX_OPERATIONAL_BROWSER_RECOVERY_RETRIES:
            return self._retry_execution(
                work,
                diagnostic_code=diagnostic_code,
            )
        recovery_counts.pop(work.job_id, None)
        return self._failed_execution(
            work,
            diagnostic_code=diagnostic_code,
        )

    @staticmethod
    def _waiting_external_execution(
        work: SettlementCaptureStageWork,
        *,
        diagnostic_code: str,
    ) -> SettlementCaptureStageExecution:
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="waiting_external",
            completed_stage=SETTLEMENT_CAPTURE_STAGE,
            next_stage=SETTLEMENT_CAPTURE_STAGE,
            platform_read_performed=False,
            checkpoint_revision=None,
            manifest_sha256=None,
            diagnostic_code=diagnostic_code,
        )

    def _release(
        self,
        *,
        work: SettlementCaptureStageWork,
        invocation: SettlementCaptureInvocationRecord,
        acquired: BrowserControlRecord,
        worker_id: str,
    ) -> None:
        if acquired.fencing_token is None:
            raise BrowserControlError(
                "settlement browser authority has no fencing token"
            )
        self._browser_control.release_automated(
            session_id=self._session_id,
            instance_id=self._instance_id,
            worker_id=worker_id,
            job_id=work.job_id,
            control_epoch=acquired.control_epoch,
            fencing_token=acquired.fencing_token,
            now=self._clock(),
        )

    def _release_after_failed_execution(
        self,
        *,
        work: SettlementCaptureStageWork,
        invocation: SettlementCaptureInvocationRecord | None,
        acquired: BrowserControlRecord,
        worker_id: str,
        is_operational: bool,
    ) -> None:
        """Preserve a visible operational page when authority can be released."""

        if is_operational and invocation is not None:
            try:
                self._release(
                    work=work,
                    invocation=invocation,
                    acquired=acquired,
                    worker_id=worker_id,
                )
                return
            except BrowserControlError:
                pass
        self._recover_failed_release(
            work=work,
            invocation=invocation,
            acquired=acquired,
            worker_id=worker_id,
        )

    def _recover_failed_release(
        self,
        *,
        work: SettlementCaptureStageWork,
        invocation: SettlementCaptureInvocationRecord | None,
        acquired: BrowserControlRecord,
        worker_id: str,
    ) -> None:
        with (
            self._browser_lifecycle.hold(),
            contextlib.suppress(BrowserControlError),
        ):
            recovering = (
                self._browser_control.begin_automatic_recovery(
                    session_id=self._session_id,
                    instance_id=self._instance_id,
                    worker_id=worker_id,
                    job_id=work.job_id,
                    expected_control_epoch=acquired.control_epoch,
                    reason="settlement_capture_release_failed",
                    now=self._clock(),
                )
            )
            with contextlib.suppress(
                BrowserRuntimeError,
                OSError,
                RuntimeError,
                ValueError,
            ):
                self._browser_runtime.close()
            access_window_id = (
                invocation.access_window_id
                if invocation is not None
                else "unbound-settlement-capture"
            )
            request_hash = hashlib.sha256(
                (
                    f"{work.stage_attempt_id}:"
                    f"{recovering.control_epoch}"
                ).encode()
            ).hexdigest()
            self._browser_control.mark_stopped(
                session_id=self._session_id,
                access_window_id=access_window_id,
                expected_record_version=recovering.record_version,
                idempotency_key=(
                    f"settlement-release:{work.stage_attempt_id}"
                ),
                request_hash=request_hash,
                now=self._clock(),
            )

    def close_terminal_job(self, job_id: str) -> None:
        """Retire one terminal window and reconcile its exact browser."""

        invocation = self._invocations.get_by_job(job_id)
        target_kind = self._invocations.target_kind(
            invocation.invocation_id
        )
        self._invocations.retire_terminal_access(
            job_id=job_id,
            now=self._clock(),
        )
        if target_kind is ShadowBatchTargetKind.OPERATIONAL_COMPAT:
            self._recover_missing_operational_runtime(
                job_id=job_id,
                access_window_id=invocation.access_window_id,
            )
            if job_id in self._pending_operational_handoffs:
                binding_probe = getattr(
                    self._invocations,
                    "has_business_session_binding",
                    None,
                )
                has_human_handoff = (
                    bool(binding_probe(job_id))
                    if callable(binding_probe)
                    else True
                )
                if has_human_handoff:
                    self._handoff_operational_browser(
                        job_id=job_id,
                        access_window_id=invocation.access_window_id,
                    )
                else:
                    with self._browser_lifecycle.hold():
                        control = self._browser_control.get(
                            self._session_id
                        )
                        if (
                            control.browser_control_mode == "idle"
                            and control.browser_lifecycle == "ready"
                        ):
                            self._browser_runtime.park_operational_session()
                self._pending_operational_handoffs.discard(job_id)
            if (
                invocation.status == "operational_ready"
                and self._operational_materializer is not None
                and job_id not in self._materialized_operational_jobs
            ):
                self._operational_materializer(job_id)
                self._materialized_operational_jobs.add(job_id)
            return
        failures: list[Exception] = []
        with self._browser_lifecycle.hold():
            control = self._browser_control.get(self._session_id)
            if (
                control.browser_control_mode == "automated"
                and control.job_id == job_id
            ):
                try:
                    if (
                        control.instance_id is None
                        or control.worker_id is None
                    ):
                        raise BrowserControlError(
                            "settlement automated browser holder is incomplete"
                        )
                    control = (
                        self._browser_control.begin_automatic_recovery(
                            session_id=self._session_id,
                            instance_id=control.instance_id,
                            worker_id=control.worker_id,
                            job_id=job_id,
                            expected_control_epoch=control.control_epoch,
                            reason="settlement_terminal_reconciliation",
                            now=self._clock(),
                        )
                    )
                except BrowserControlError as exc:
                    failures.append(exc)
            if (
                control.browser_control_mode.startswith("human_")
                and control.holder_kind == "human_session"
                and control.holder_id == invocation.access_window_id
            ):
                try:
                    self._browser_runtime.close()
                    self._browser_control.mark_human_session_closed(
                        session_id=self._session_id,
                        human_session_id=invocation.access_window_id,
                        expected_record_version=control.record_version,
                        now=self._clock(),
                    )
                except (
                    BrowserControlError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as exc:
                    failures.append(exc)
            elif (
                control.browser_control_mode == "idle"
                and control.browser_lifecycle in {"ready", "recovering"}
            ):
                try:
                    self._browser_runtime.close()
                    self._stop_browser(
                        access_window_id=invocation.access_window_id,
                        job_id=job_id,
                        expected_record_version=control.record_version,
                    )
                except (
                    BrowserControlError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as exc:
                    failures.append(exc)
            elif (
                control.browser_lifecycle == "stopped"
                and self._browser_runtime.running
            ):
                try:
                    self._browser_runtime.close()
                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as exc:
                    failures.append(exc)
            elif (
                control.browser_control_mode != "idle"
                or control.browser_lifecycle != "stopped"
            ):
                failures.append(
                    BrowserControlError(
                        "another browser authority is active"
                    )
                )
        if failures:
            raise RuntimeError(
                "settlement terminal cleanup did not complete"
            ) from failures[0]

    def _recover_missing_operational_runtime(
        self,
        *,
        job_id: str,
        access_window_id: str,
    ) -> bool:
        """Release a terminal durable holder whose owned process is gone."""

        with self._browser_lifecycle.hold():
            control = self._browser_control.get(self._session_id)
            if (
                control.browser_control_mode != "automated"
                or control.job_id != job_id
                or self._browser_runtime.running
            ):
                return False
            if control.instance_id is None or control.worker_id is None:
                raise BrowserControlError(
                    "settlement automated browser holder is incomplete"
                )
            recovering = self._browser_control.begin_automatic_recovery(
                session_id=self._session_id,
                instance_id=control.instance_id,
                worker_id=control.worker_id,
                job_id=job_id,
                expected_control_epoch=control.control_epoch,
                reason="operational_runtime_missing_after_terminal",
                now=self._clock(),
            )
            with contextlib.suppress(
                BrowserRuntimeError,
                OSError,
                RuntimeError,
                ValueError,
            ):
                self._browser_runtime.close()
            self._stop_browser(
                access_window_id=access_window_id,
                job_id=job_id,
                expected_record_version=recovering.record_version,
            )
            return True

    def _handoff_operational_browser(
        self,
        *,
        job_id: str,
        access_window_id: str,
    ) -> None:
        """Keep the owned window open only after private authority is erased."""

        failures: list[Exception] = []
        with self._browser_lifecycle.hold():
            control = self._browser_control.get(self._session_id)
            if (
                control.browser_control_mode == "human_handoff"
                and control.holder_kind == "human_session"
                and control.holder_id == access_window_id
                and self._browser_runtime.running
            ):
                return
            if (
                control.browser_control_mode == "automated"
                and control.job_id == job_id
            ):
                try:
                    if (
                        control.instance_id is None
                        or control.worker_id is None
                    ):
                        raise BrowserControlError(
                            "settlement automated browser holder is incomplete"
                        )
                    control = self._browser_control.begin_automatic_recovery(
                        session_id=self._session_id,
                        instance_id=control.instance_id,
                        worker_id=control.worker_id,
                        job_id=job_id,
                        expected_control_epoch=control.control_epoch,
                        reason="operational_handoff_reconciliation",
                        now=self._clock(),
                    )
                except BrowserControlError as exc:
                    failures.append(exc)
            if (
                not failures
                and control.browser_lifecycle == "ready"
                and control.browser_control_mode == "idle"
                and self._browser_runtime.running
            ):
                request = {
                    "access_window_id": access_window_id,
                    "job_id": job_id,
                    "operation": "operational_handoff",
                    "session_id": self._session_id,
                }
                request_hash = hashlib.sha256(
                    json.dumps(
                        request,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                try:
                    self._browser_runtime.handoff_operational_session()
                    self._browser_control.acquire_human_session_control(
                        session_id=self._session_id,
                        control_mode="human_handoff",
                        human_session_id=access_window_id,
                        expected_record_version=control.record_version,
                        idempotency_key=f"operational-handoff:{job_id}",
                        request_hash=request_hash,
                        now=self._clock(),
                    )
                    return
                except (
                    BrowserControlError,
                    BrowserRuntimeError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as exc:
                    failures.append(exc)
            elif not failures:
                failures.append(
                    BrowserControlError(
                        "operational browser is not ready for human handoff"
                    )
                )

            with contextlib.suppress(
                BrowserRuntimeError,
                OSError,
                RuntimeError,
                ValueError,
            ):
                self._browser_runtime.close()
            stopped = self._browser_control.get(self._session_id)
            if (
                stopped.browser_control_mode == "idle"
                and stopped.browser_lifecycle in {"ready", "recovering"}
            ):
                with contextlib.suppress(
                    BrowserControlError,
                    RuntimeError,
                    ValueError,
                ):
                    self._stop_browser(
                        access_window_id=access_window_id,
                        job_id=job_id,
                        expected_record_version=stopped.record_version,
                    )
        raise RuntimeError(
            "operational browser handoff did not complete"
        ) from failures[0]

    def _stop_browser(
        self,
        *,
        access_window_id: str,
        job_id: str,
        expected_record_version: int,
    ) -> None:
        request = {
            "access_window_id": access_window_id,
            "job_id": job_id,
            "operation": "settlement_terminal_close",
            "session_id": self._session_id,
        }
        request_hash = hashlib.sha256(
            json.dumps(
                request,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self._browser_control.mark_stopped(
            session_id=self._session_id,
            access_window_id=access_window_id,
            expected_record_version=expected_record_version,
            idempotency_key=f"settlement-terminal:{job_id}",
            request_hash=request_hash,
            now=self._clock(),
        )
