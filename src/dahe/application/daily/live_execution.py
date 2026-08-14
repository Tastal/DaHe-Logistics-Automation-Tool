from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from dahe.adapters.chengfeng.browser_gate import (
    SqliteBrowserNavigationAuthorizer,
)
from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeError,
    BrowserRuntimeLifecycle,
)
from dahe.adapters.chengfeng.daily_live_adapter import (
    ChengfengDailyDetailEvidenceAdapter,
    ChengfengDailyListAdapter,
)
from dahe.adapters.chengfeng.daily_manifest import DailyReadContractManifest
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditError,
    PlatformReadAuditEvidenceStore,
)
from dahe.adapters.sqlite.browser_control import (
    BrowserControlError,
    BrowserControlStore,
)
from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationConflictError,
    DailyInvocationRecord,
    SqliteDailyInvocationStore,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.platform_access import (
    PlatformAccessConflictError,
    SqlitePlatformAccessRepository,
)
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowError,
    AccessWindowGrant,
)
from dahe.application.chengfeng.browser_readiness import (
    reconcile_operational_browser_readiness,
)
from dahe.application.chengfeng.operational_capture import (
    OperationalCaptureContractError,
)
from dahe.application.daily.capture import (
    DailyCaptureError,
    DailyCaptureService,
    DailyCaptureStage,
)
from dahe.application.daily.operational_capture import (
    FastOperationalDailyCaptureCoordinator,
)
from dahe.jobs.daily_execution import (
    DailyStageExecution,
    DailyStageWork,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserContextClosedError,
    ChengfengReadError,
    ChengfengReadPort,
    LoginRequiredError,
)

# One batch may use three successively reduced-concurrency worker attempts.
# Keep the fencing authority valid until that bounded retry budget and browser
# preparation have both completed.
_CONTROL_TTL = timedelta(minutes=30)
_MAX_OPERATIONAL_BROWSER_START_RECOVERY_RETRIES = 1


class DailyLiveStageExecutor:
    """Execute one persisted daily stage under a short browser authority."""

    def __init__(
        self,
        *,
        invocation_store: SqliteDailyInvocationStore,
        access_repository: SqlitePlatformAccessRepository,
        browser_control: BrowserControlStore,
        browser_runtime: BrowserRuntime,
        browser_lifecycle: BrowserRuntimeLifecycle,
        manifest: DailyReadContractManifest,
        connector: ChengfengReadPort,
        evidence_store: ContentAddressedEvidenceStore,
        request_audit_store: PlatformReadAuditEvidenceStore,
        daily_store: SqliteDailyStore,
        instance_id: str,
        session_id: str,
        build_sha256: str,
        settlement_contract_sha256: str,
        settlement_contract_selection_sha256: str,
        daily_contract_selection_sha256: str,
        settlement_validation_gate: Callable[[], bool],
        operational_coordinator: (
            FastOperationalDailyCaptureCoordinator | None
        ) = None,
        operational_materializer: Callable[[str], None] | None = None,
        contract_subject_for_job: Callable[[str], str] = (
            lambda _job_id: "shanxi_guienbo"
        ),
        unexpected_error_observer: (
            Callable[[str, str, str], None] | None
        ) = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._invocations = invocation_store
        self._access = access_repository
        self._browser_control = browser_control
        self._browser_runtime = browser_runtime
        self._browser_lifecycle = browser_lifecycle
        self._manifest = manifest
        self._connector = connector
        self._evidence_store = evidence_store
        self._request_audit_store = request_audit_store
        self._daily_store = daily_store
        self._instance_id = instance_id
        self._session_id = session_id
        self._build_sha256 = build_sha256
        self._settlement_contract_sha256 = (
            settlement_contract_sha256
        )
        self._settlement_contract_selection_sha256 = (
            settlement_contract_selection_sha256
        )
        self._daily_contract_selection_sha256 = (
            daily_contract_selection_sha256
        )
        self._settlement_validation_gate = (
            settlement_validation_gate
        )
        self._operational_coordinator = operational_coordinator
        self._operational_materializer = operational_materializer
        self._contract_subject_for_job = contract_subject_for_job
        self._prepared_operational_jobs: set[str] = set()
        self._operational_browser_recovery_counts: dict[str, int] = {}
        self._unexpected_error_observer = unexpected_error_observer
        self._clock = clock
        self._authorizer = SqliteBrowserNavigationAuthorizer(
            browser_control,
            access_repository=access_repository,
            build_sha256=build_sha256,
            clock=clock,
        )

    def _ensure_operational_browser_prepared(self, job_id: str) -> None:
        """Confirm the current browser generation owns daily read authority."""

        # A live job can outlast its owned browser process.  The runtime keeps
        # the cheap same-process preparation cache and rebuilds authority when
        # its worker generation changes, so a job-level shortcut is unsafe.
        self._browser_runtime.prepare_operational_daily(
            self._contract_subject_for_job(job_id)
        )
        self._prepared_operational_jobs.add(job_id)

    def __call__(self, work: DailyStageWork) -> DailyStageExecution:
        return self._execute(work)

    def _execute(self, work: DailyStageWork) -> DailyStageExecution:
        invocation: DailyInvocationRecord | None = None
        acquired = None
        is_operational = False
        rebuild_operational_browser = False
        failure_step = "load_invocation"
        try:
            invocation = self._invocations.get_by_job(work.job_id)
            is_operational = (
                self._invocations.job_run_mode(work.job_id)
                == "operational"
            )
            if (
                invocation.status not in {"ready", "running"}
                or invocation.next_stage is None
                or invocation.next_stage.value != work.stage
            ):
                raise DailyInvocationConflictError(
                    "daily scheduler stage does not match its invocation"
                )
            try:
                settlement_validation_passed = (
                    is_operational
                    or self._settlement_validation_gate()
                )
            except Exception:
                settlement_validation_passed = is_operational
            if not settlement_validation_passed:
                return self._failure(
                    work,
                    invocation,
                    diagnostic_code=(
                        "CF-DAILY-SETTLEMENT-VALIDATION-REQUIRED"
                    ),
                    retryable=False,
                )
            authorization_time = self._clock()
            access_window = self._access.authorize(
                access_window_id=invocation.access_window_id,
                purpose=AccessPurpose.PRODUCTION_SHADOW,
                job_id=work.job_id,
                session_id=self._session_id,
                build_sha256=self._build_sha256,
                now=authorization_time,
            )
            control_ttl = min(
                _CONTROL_TTL,
                access_window.expires_at - authorization_time,
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
            if (
                control.browser_lifecycle != "ready"
                or control.browser_control_mode != "idle"
                or not self._browser_runtime.running
            ):
                return self._retry(
                    work,
                    invocation,
                    diagnostic_code="CF-DAILY-BROWSER-NOT-READY",
                )
            worker_id = f"daily-stage-{work.stage_attempt_id}"
            acquired = self._browser_control.acquire_automated(
                session_id=self._session_id,
                instance_id=self._instance_id,
                worker_id=worker_id,
                job_id=work.job_id,
                expected_record_version=control.record_version,
                now=authorization_time,
                ttl=control_ttl,
            )
            fencing_token = acquired.fencing_token
            if fencing_token is None:
                raise BrowserControlError(
                    "daily browser authority has no fencing token"
                )
            authority = BrowserCommandAuthority(
                session_id=self._session_id,
                instance_id=self._instance_id,
                worker_id=worker_id,
                job_id=work.job_id,
                control_epoch=acquired.control_epoch,
                fencing_token=fencing_token,
            )
            capture_strategy = (
                self._invocations.capture_strategy(work.job_id)
                if is_operational
                else "legacy"
            )
            if is_operational and capture_strategy in {"batch_v1", "whole_run_v1"}:
                # Reuse live private authority when the worker survived, or
                # rebuild it through the page-owned settlement transition
                # after a process restart. Never resume through the legacy
                # APIRequestContext path, which the platform WAF can reject.
                self._ensure_operational_browser_prepared(work.job_id)
            elif is_operational and invocation.checkpoint is None:
                self._browser_runtime.prepare_daily()
            if is_operational and capture_strategy in {"batch_v1", "whole_run_v1"}:
                if self._operational_coordinator is None:
                    raise DailyCaptureError(
                        "fast operational daily capture is unavailable"
                    )
                failure_step = "capture_batch"
                operational_step = self._operational_coordinator.advance(
                    invocation=invocation,
                    authority=authority,
                    list_port=ChengfengDailyListAdapter(
                        browser=self._browser_runtime,
                        manifest=self._manifest,
                        authority=authority,
                        authorizer=self._authorizer,
                        request_audit_store=self._request_audit_store,
                        build_sha256=self._build_sha256,
                        contract_selection_sha256=(
                            self._daily_contract_selection_sha256
                        ),
                    ),
                )
                self._operational_browser_recovery_counts.pop(
                    work.job_id,
                    None,
                )
                failure_step = "release_browser_control"
                self._browser_control.release_automated(
                    session_id=self._session_id,
                    instance_id=self._instance_id,
                    worker_id=worker_id,
                    job_id=work.job_id,
                    control_epoch=acquired.control_epoch,
                    fencing_token=fencing_token,
                    now=self._clock(),
                )
                acquired = None
                if not operational_step.has_more:
                    if operational_step.request_audit_counts is None:
                        raise DailyCaptureError(
                            "terminal operational daily capture has no audit lineage"
                        )
                    self._request_audit_store.seal(
                        job_id=work.job_id,
                        authority=PlatformReadAuditAuthority(
                            build_sha256=self._build_sha256,
                            settlement_contract_sha256=(
                                self._settlement_contract_sha256
                            ),
                            settlement_contract_selection_sha256=(
                                self._settlement_contract_selection_sha256
                            ),
                            daily_contract_sha256=(
                                self._manifest.canonical_sha256
                            ),
                            daily_contract_selection_sha256=(
                                self._daily_contract_selection_sha256
                            ),
                        ),
                        purpose="operational_daily",
                        expected_succeeded_operations=(
                            operational_step.request_audit_counts
                        ),
                    )
                failure_step = "commit_invocation_checkpoint"
                committed = self._invocations.commit_checkpoint(
                    job_id=work.job_id,
                    expected_record_version=invocation.record_version,
                    checkpoint=operational_step.checkpoint,
                    next_stage=(
                        DailyCaptureStage.LIST_PAGE
                        if operational_step.has_more
                        else None
                    ),
                    completed=not operational_step.has_more,
                    now=self._clock(),
                )
                return DailyStageExecution(
                    stage_attempt_id=work.stage_attempt_id,
                    outcome="succeeded",
                    completed_stage=work.stage,
                    next_stage=(
                        None
                        if committed.next_stage is None
                        else committed.next_stage.value
                    ),
                    checkpoint_revision=(
                        operational_step.checkpoint.revision
                    ),
                    diagnostic_code=None,
                )
            service = DailyCaptureService(
                platform=ChengfengDailyListAdapter(
                    browser=self._browser_runtime,
                    manifest=self._manifest,
                    authority=authority,
                    authorizer=self._authorizer,
                    request_audit_store=(
                        None
                        if is_operational
                        else self._request_audit_store
                    ),
                    build_sha256=(
                        None if is_operational else self._build_sha256
                    ),
                    contract_selection_sha256=(
                        None
                        if is_operational
                        else self._daily_contract_selection_sha256
                    ),
                ),
                detail_evidence=ChengfengDailyDetailEvidenceAdapter(
                    connector=self._connector,
                    authority=authority,
                    evidence_store=self._evidence_store,
                    access_window_id=(
                        invocation.access_window_id
                    ),
                ),
                store=self._daily_store,
                access_window_id=invocation.access_window_id,
                clock=self._clock,
            )
            step = service.advance(
                request=invocation.request,
                checkpoint=invocation.checkpoint,
            )
            returned = self._browser_control.release_automated(
                session_id=self._session_id,
                instance_id=self._instance_id,
                worker_id=worker_id,
                job_id=work.job_id,
                control_epoch=acquired.control_epoch,
                fencing_token=fencing_token,
                now=self._clock(),
            )
            del returned
            acquired = None
            if not step.has_more and not is_operational:
                snapshot = step.checkpoint.snapshot
                if snapshot is None:
                    raise DailyCaptureError(
                        "terminal daily checkpoint has no snapshot"
                    )
                captures = step.checkpoint.completed_detail_captures
                if len(captures) != len(snapshot.candidates):
                    raise DailyCaptureError(
                        "terminal daily checkpoint has no exact read lineage"
                    )
                image_count = sum(
                    capture.image_read_count for capture in captures
                )
                detail_count = sum(
                    capture.detail_read_count for capture in captures
                )
                self._request_audit_store.seal(
                    job_id=work.job_id,
                    authority=PlatformReadAuditAuthority(
                        build_sha256=self._build_sha256,
                        settlement_contract_sha256=(
                            self._settlement_contract_sha256
                        ),
                        settlement_contract_selection_sha256=(
                            self._settlement_contract_selection_sha256
                        ),
                        daily_contract_sha256=(
                            self._manifest.canonical_sha256
                        ),
                        daily_contract_selection_sha256=(
                            self._daily_contract_selection_sha256
                        ),
                    ),
                    purpose="daily_snapshot",
                    expected_succeeded_operations={
                        "list_daily_waybills": (
                            len(step.checkpoint.pages)
                            + len(step.checkpoint.verification_pages)
                        ),
                        "get_waybill_detail": detail_count,
                        "download_ticket_image": image_count,
                    },
                )
            committed = self._invocations.commit_checkpoint(
                job_id=work.job_id,
                expected_record_version=invocation.record_version,
                checkpoint=step.checkpoint,
                next_stage=step.next_stage,
                completed=not step.has_more,
                now=self._clock(),
            )
            return DailyStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="succeeded",
                completed_stage=work.stage,
                next_stage=(
                    None
                    if committed.next_stage is None
                    else committed.next_stage.value
                ),
                checkpoint_revision=step.checkpoint.revision,
                diagnostic_code=None,
            )
        except ChengfengReadError as exc:
            if isinstance(exc, LoginRequiredError):
                return self._waiting_external(
                    work,
                    invocation,
                    diagnostic_code=exc.diagnostic_code,
                )
            if is_operational and isinstance(
                exc,
                BrowserContextClosedError,
            ):
                rebuild_operational_browser = True
                return self._operational_browser_recovery(
                    work,
                    invocation,
                )
            if is_operational and exc.retryable:
                return self._waiting_external(
                    work,
                    invocation,
                    diagnostic_code=exc.diagnostic_code,
                )
            return self._failure(
                work,
                invocation,
                diagnostic_code=exc.diagnostic_code,
                retryable=exc.retryable,
            )
        except BrowserRuntimeError as exc:
            if self._unexpected_error_observer is not None:
                self._unexpected_error_observer(
                    work.job_id,
                    failure_step,
                    f"BrowserRuntimeError:{exc.code}",
                )
            if exc.code in {
                "browser_saved_credential_missing",
                "browser_saved_login_captcha_required",
                "browser_saved_login_failed",
                "browser_saved_login_structure_changed",
                "browser_read_login_required",
            }:
                return self._waiting_external(
                    work,
                    invocation,
                    diagnostic_code="CF-DAILY-LOGIN-REQUIRED",
                )
            if is_operational and exc.code in {
                "browser_context_closed",
                "browser_daily_route_unavailable",
                "browser_worker_unavailable",
            }:
                rebuild_operational_browser = True
                return self._operational_browser_recovery(
                    work,
                    invocation,
                )
            if is_operational and exc.code in {
                "browser_read_network_failed",
                "browser_read_http_failed",
                "browser_read_rate_limited",
                "browser_read_server_transient",
                "browser_worker_timeout",
            }:
                return self._waiting_external(
                    work,
                    invocation,
                    diagnostic_code="CF-NETWORK-TRANSIENT",
                )
            return self._failure(
                work,
                invocation,
                diagnostic_code="CF-DAILY-BROWSER-RUNTIME-FAILED",
                retryable=(not is_operational),
            )
        except BrowserControlError:
            return self._failure(
                work,
                invocation,
                diagnostic_code="CF-DAILY-BROWSER-CONTROL-FAILED",
                retryable=True,
            )
        except (
            AccessWindowError,
            PlatformAccessConflictError,
        ):
            return self._waiting_external(
                work,
                invocation,
                diagnostic_code="CF-DAILY-ACCESS-WINDOW-INVALID",
            )
        except (
            DailyCaptureError,
            DailyInvocationConflictError,
            OperationalCaptureContractError,
            PlatformReadAuditError,
            ValueError,
        ) as exc:
            if self._unexpected_error_observer is not None:
                self._unexpected_error_observer(
                    work.job_id,
                    failure_step,
                    type(exc).__name__,
                )
            return self._failure(
                work,
                invocation,
                diagnostic_code="DAILY-CAPTURE-CONTRACT-FAILED",
                retryable=False,
            )
        except Exception as exc:
            if self._unexpected_error_observer is not None:
                self._unexpected_error_observer(
                    work.job_id,
                    failure_step,
                    type(exc).__name__,
                )
            return self._failure(
                work,
                invocation,
                diagnostic_code="DAILY-STAGE-EXECUTION-FAILED",
                retryable=False,
            )
        finally:
            if acquired is not None and acquired.fencing_token is not None:
                try:
                    self._browser_control.release_automated(
                        session_id=self._session_id,
                        instance_id=self._instance_id,
                        worker_id=f"daily-stage-{work.stage_attempt_id}",
                        job_id=work.job_id,
                        control_epoch=acquired.control_epoch,
                        fencing_token=acquired.fencing_token,
                        now=self._clock(),
                    )
                except BrowserControlError:
                    with self._browser_lifecycle.hold():
                        try:
                            recovering = (
                                self._browser_control.begin_automatic_recovery(
                                    session_id=self._session_id,
                                    instance_id=self._instance_id,
                                    worker_id=(
                                        f"daily-stage-"
                                        f"{work.stage_attempt_id}"
                                    ),
                                    job_id=work.job_id,
                                    expected_control_epoch=(
                                        acquired.control_epoch
                                    ),
                                    reason="daily_stage_release_failed",
                                    now=self._clock(),
                                )
                            )
                            self._prepared_operational_jobs.discard(
                                work.job_id
                            )
                            self._browser_runtime.close()
                            self._stop_browser(
                                access_window_id=(
                                    invocation.access_window_id
                                    if invocation is not None
                                    else "unbound-daily-stage"
                                ),
                                job_id=work.job_id,
                                expected_record_version=(
                                    recovering.record_version
                                ),
                            )
                        except (
                            BrowserControlError,
                            OSError,
                            RuntimeError,
                            ValueError,
                        ):
                            with contextlib.suppress(
                                OSError,
                                RuntimeError,
                                ValueError,
                            ):
                                self._prepared_operational_jobs.discard(
                                    work.job_id
                                )
                                self._browser_runtime.close()
            if rebuild_operational_browser:
                self._prepared_operational_jobs.discard(work.job_id)
                with contextlib.suppress(
                    BrowserRuntimeError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ):
                    self._browser_runtime.close()

    def _operational_browser_recovery(
        self,
        work: DailyStageWork,
        invocation: DailyInvocationRecord | None,
    ) -> DailyStageExecution:
        recovery_count = (
            self._operational_browser_recovery_counts.get(work.job_id, 0)
            + 1
        )
        self._operational_browser_recovery_counts[work.job_id] = recovery_count
        if (
            invocation is not None
            and recovery_count <= _MAX_OPERATIONAL_BROWSER_START_RECOVERY_RETRIES
        ):
            return self._retry(
                work,
                invocation,
                diagnostic_code="CF-DAILY-BROWSER-RESTARTING",
            )
        self._operational_browser_recovery_counts.pop(work.job_id, None)
        return self._failure(
            work,
            invocation,
            diagnostic_code="CF-DAILY-BROWSER-RUNTIME-FAILED",
            retryable=False,
        )

    def _failure(
        self,
        work: DailyStageWork,
        invocation: DailyInvocationRecord | None,
        *,
        diagnostic_code: str,
        retryable: bool,
    ) -> DailyStageExecution:
        if retryable and invocation is not None:
            return self._retry(
                work,
                invocation,
                diagnostic_code=diagnostic_code,
            )
        if (
            invocation is not None
            and invocation.status not in {"failed", "succeeded"}
        ):
            try:
                self._invocations.fail(
                    job_id=work.job_id,
                    expected_record_version=invocation.record_version,
                    diagnostic_code=diagnostic_code,
                    now=self._clock(),
                )
            except DailyInvocationConflictError:
                diagnostic_code = "DAILY-INVOCATION-COMMIT-FAILED"
        return DailyStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="failed",
            completed_stage=work.stage,
            next_stage=None,
            checkpoint_revision=(
                None
                if invocation is None or invocation.checkpoint is None
                else invocation.checkpoint.revision
            ),
            diagnostic_code=diagnostic_code,
        )

    @staticmethod
    def _waiting_external(
        work: DailyStageWork,
        invocation: DailyInvocationRecord | None,
        *,
        diagnostic_code: str,
    ) -> DailyStageExecution:
        return DailyStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="waiting_external",
            completed_stage=work.stage,
            next_stage=work.stage,
            checkpoint_revision=(
                None
                if invocation is None or invocation.checkpoint is None
                else invocation.checkpoint.revision
            ),
            diagnostic_code=diagnostic_code,
        )

    def _cleanup_terminal(self, job_id: str) -> None:
        self._prepared_operational_jobs.discard(job_id)
        try:
            keep_warm = (
                self._invocations.job_run_mode(job_id) == "operational"
                and self._invocations.capture_strategy(job_id)
                in {"batch_v1", "whole_run_v1"}
            )
        except DailyInvocationConflictError:
            keep_warm = False
        for grant, access_version in (
            self._access.production_shadow_windows_for_job(job_id)
        ):
            self._cleanup_binding(
                job_id=job_id,
                grant=grant,
                access_version=access_version,
                keep_warm=keep_warm,
            )

    def _cleanup_binding(
        self,
        *,
        job_id: str,
        grant: AccessWindowGrant,
        access_version: int,
        keep_warm: bool,
    ) -> None:
        access_window_id = grant.access_window_id
        failures: list[Exception] = []
        window_was_active = grant.consumed_at is None
        if window_was_active:
            try:
                self._access.retire(
                    access_window_id=access_window_id,
                    expected_record_version=access_version,
                    now=self._clock(),
                )
            except PlatformAccessConflictError as exc:
                failures.append(exc)
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
                            "daily automated browser holder is incomplete"
                        )
                    control = self._browser_control.begin_automatic_recovery(
                        session_id=self._session_id,
                        instance_id=control.instance_id,
                        worker_id=control.worker_id,
                        job_id=job_id,
                        expected_control_epoch=control.control_epoch,
                        reason="daily_terminal_reconciliation",
                        now=self._clock(),
                    )
                except BrowserControlError as exc:
                    failures.append(exc)
            if (
                control.browser_control_mode.startswith("human_")
                and control.holder_kind == "human_session"
                and control.holder_id == access_window_id
            ):
                try:
                    control = (
                        self._browser_control.mark_human_session_closed(
                            session_id=self._session_id,
                            human_session_id=access_window_id,
                            expected_record_version=control.record_version,
                            now=self._clock(),
                        )
                    )
                    self._browser_runtime.close()
                except (
                    BrowserControlError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as exc:
                    failures.append(exc)
            elif (
                control.browser_control_mode == "idle"
                and (
                    window_was_active
                    or (
                        control.browser_lifecycle == "recovering"
                        and control.job_id == job_id
                    )
                )
                and (
                    control.browser_lifecycle == "ready"
                    or (
                        control.browser_lifecycle == "recovering"
                        and control.job_id == job_id
                    )
                )
            ):
                try:
                    if keep_warm and self._browser_runtime.running:
                        self._browser_runtime.park_operational_session()
                    else:
                        self._browser_runtime.close()
                        self._stop_browser(
                            access_window_id=access_window_id,
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
                window_was_active
                and control.browser_lifecycle == "stopped"
                and self._browser_runtime.running
            ):
                try:
                    self._browser_runtime.close()
                except (OSError, RuntimeError, ValueError) as exc:
                    failures.append(exc)
        if failures:
            raise RuntimeError(
                "daily terminal cleanup did not complete"
            ) from failures[0]

    def close_terminal_job(self, job_id: str) -> None:
        """Idempotently retire one terminal or expired daily browser session."""

        eligible_jobs = set(
            self._access.terminal_or_expired_daily_job_ids(
                now=self._clock()
            )
        )
        orphaned_starts = set(
            self._invocations.orphaned_start_job_ids()
        )
        if (
            job_id not in eligible_jobs
            and job_id not in orphaned_starts
            and not self._invocations.is_cleanup_candidate(
                job_id,
                now=self._clock(),
            )
        ):
            raise DailyInvocationConflictError(
                "daily job is not eligible for terminal cleanup"
            )
        try:
            terminal_invocation = self._invocations.get_by_job(job_id)
        except DailyInvocationConflictError:
            terminal_invocation = None
        if (
            self._operational_materializer is not None
            and not self._invocations.is_network_only_measurement(job_id)
            and terminal_invocation is not None
            and terminal_invocation.status == "succeeded"
        ):
            # The final capture checkpoint is committed before the scheduler
            # marks the parent job terminal. Create the last local OCR child
            # only after that terminal commit, so child scheduling never races
            # the parent transition. The callback is idempotent and terminal
            # cleanup remains pending when it fails, allowing a safe retry.
            self._operational_materializer(job_id)
        self._cleanup_terminal(job_id)

    def reconcile_terminal_or_expired(self) -> tuple[str, ...]:
        """Close every durable daily authority left terminal after a crash."""

        reconciled: list[str] = []
        failures: list[Exception] = []
        job_ids = {
            invocation.job_id
            for invocation in self._invocations.cleanup_candidates(
                now=self._clock()
            )
        }
        job_ids.update(
            self._access.terminal_or_expired_daily_job_ids(
                now=self._clock()
            )
        )
        job_ids.update(self._invocations.orphaned_start_job_ids())
        for job_id in sorted(job_ids):
            try:
                self.close_terminal_job(job_id)
                reconciled.append(job_id)
            except (
                BrowserControlError,
                DailyInvocationConflictError,
                PlatformAccessConflictError,
                OSError,
                RuntimeError,
                ValueError,
            ) as exc:
                failures.append(exc)
        if failures:
            raise RuntimeError(
                "one or more daily terminal authorities remain unreconciled"
            ) from failures[0]
        return tuple(reconciled)

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
            "operation": "daily_terminal_close",
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
            idempotency_key=(
                f"daily-terminal:{job_id}:{access_window_id}"
            ),
            request_hash=request_hash,
            now=self._clock(),
        )

    @staticmethod
    def _retry(
        work: DailyStageWork,
        invocation: DailyInvocationRecord,
        *,
        diagnostic_code: str,
    ) -> DailyStageExecution:
        return DailyStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="retry",
            completed_stage=work.stage,
            next_stage=work.stage,
            checkpoint_revision=(
                None
                if invocation.checkpoint is None
                else invocation.checkpoint.revision
            ),
            diagnostic_code=diagnostic_code,
        )
