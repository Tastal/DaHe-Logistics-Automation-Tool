from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeLifecycle,
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
from dahe.application.chengfeng.access_window import AccessWindowGrant
from dahe.diagnostics.runtime_log import RuntimeLogStore

ReconciliationOutcome = Literal[
    "noop",
    "reconciled",
    "deferred",
    "failed",
]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DEFERRED_DIAGNOSTIC = "CF-BROWSER-EXPIRY-STATE-UNMATCHED"
_FAILURE_DIAGNOSTIC = "CF-BROWSER-EXPIRY-RECONCILIATION-FAILED"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("expiry reconciliation clock must be timezone-aware")
    return value.astimezone(UTC)


class PlatformAccessExpiryReconciler:
    """Retire expired real-read authority without owning business scheduling."""

    def __init__(
        self,
        *,
        access_repository: SqlitePlatformAccessRepository,
        browser_control: BrowserControlStore,
        browser_runtime: BrowserRuntime,
        browser_lifecycle: BrowserRuntimeLifecycle,
        runtime_log_store: RuntimeLogStore,
        session_id: str,
        build_sha256: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        interval_seconds: float = 1.0,
    ) -> None:
        if not session_id:
            raise ValueError("platform session identity is required")
        if _SHA256.fullmatch(build_sha256) is None:
            raise ValueError("platform build identity must be lowercase SHA-256")
        if interval_seconds <= 0:
            raise ValueError("expiry reconciliation interval must be positive")
        self._access = access_repository
        self._browser_control = browser_control
        self._browser_runtime = browser_runtime
        self._browser_lifecycle = browser_lifecycle
        self._runtime_log_store = runtime_log_store
        self._session_id = session_id
        self._build_sha256 = build_sha256
        self._clock = clock
        self._interval_seconds = interval_seconds
        self._thread_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._closed = threading.Event()
        self._diagnostic_lock = threading.Lock()
        self._last_diagnostic_key: tuple[str, int, str] | None = None

    @property
    def running(self) -> bool:
        with self._thread_lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start one best-effort housekeeping thread for this application."""

        with self._thread_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._closed = threading.Event()
            thread = threading.Thread(
                target=self._run,
                name="dahe-platform-access-expiry",
                daemon=True,
            )
            self._thread = thread
            thread.start()

    def close(self) -> None:
        """Stop polling and wait for the current fenced transition to finish."""

        with self._thread_lock:
            thread = self._thread
            self._closed.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        with self._thread_lock:
            if self._thread is thread:
                self._thread = None

    def _run(self) -> None:
        while not self._closed.is_set():
            self.reconcile_once()
            self._closed.wait(self._interval_seconds)

    def reconcile_once(self) -> ReconciliationOutcome:
        """Recheck and retire only the exact latest expired window."""

        candidate: tuple[AccessWindowGrant, int] | None = None
        try:
            initial_now = _utc(self._clock())
            candidate = self._access.latest_for_session(self._session_id)
            if not self._is_expired_candidate(candidate, now=initial_now):
                self._clear_diagnostic()
                return "noop"
            assert candidate is not None
            initial_grant, initial_version = candidate
            with self._browser_lifecycle.hold():
                locked_now = _utc(self._clock())
                current = self._access.latest_for_session(self._session_id)
                if (
                    current is None
                    or current[0].access_window_id
                    != initial_grant.access_window_id
                    or current[1] != initial_version
                    or not self._is_expired_candidate(
                        current,
                        now=locked_now,
                    )
                ):
                    return "noop"
                grant, access_version = current
                control = self._browser_control.get(self._session_id)
                if (
                    grant.consumed_at is not None
                    and control.browser_lifecycle == "stopped"
                    and control.browser_control_mode == "idle"
                    and not self._browser_runtime.running
                ):
                    self._clear_diagnostic()
                    return "noop"
                if not self._control_matches(
                    grant=grant,
                    control=control,
                ):
                    self._log_deferred(
                        grant=grant,
                        access_version=access_version,
                        control=control,
                    )
                    return "deferred"
                self._close_matching_runtime(
                    grant=grant,
                    control=control,
                    now=locked_now,
                )
                if grant.consumed_at is None:
                    self._access.retire(
                        access_window_id=grant.access_window_id,
                        expected_record_version=access_version,
                        now=locked_now,
                    )
            self._clear_diagnostic()
            self._runtime_log_store.append(
                level="info",
                source="chengfeng-browser",
                event_code="platform_access_expiry_reconciled",
                stream="application",
                message=(
                    "Expired read-only browser authority was closed and "
                    "retired."
                ),
                job_id=initial_grant.job_id,
            )
            return "reconciled"
        except (
            BrowserControlError,
            PlatformAccessConflictError,
            OSError,
            RuntimeError,
            ValueError,
        ):
            self._log_failure(candidate)
            return "failed"

    def _is_expired_candidate(
        self,
        candidate: tuple[AccessWindowGrant, int] | None,
        *,
        now: datetime,
    ) -> bool:
        if candidate is None:
            return False
        grant, _ = candidate
        return bool(
            grant.session_id == self._session_id
            and grant.build_sha256 == self._build_sha256
            and grant.expires_at <= now
        )

    def _control_matches(
        self,
        *,
        grant: AccessWindowGrant,
        control: BrowserControlRecord,
    ) -> bool:
        if control.session_id != self._session_id:
            return False
        if control.browser_control_mode in {
            "human_login",
            "human_handoff",
        }:
            return bool(
                control.browser_lifecycle == "ready"
                and control.holder_kind == "human_session"
                and control.holder_id == grant.access_window_id
            )
        if control.browser_control_mode == "automated":
            return bool(
                control.browser_lifecycle == "ready"
                and control.job_id == grant.job_id
                and control.instance_id is not None
                and control.worker_id is not None
            )
        if control.browser_control_mode != "idle":
            return False
        if control.browser_lifecycle == "ready":
            return bool(
                control.holder_kind is None
                and control.holder_id is None
                and control.job_id is None
            )
        if control.browser_lifecycle == "recovering":
            return bool(
                control.holder_kind is None
                and control.holder_id is None
                and control.job_id == grant.job_id
            )
        if control.browser_lifecycle == "stopped":
            return not self._browser_runtime.running
        return False

    def _close_matching_runtime(
        self,
        *,
        grant: AccessWindowGrant,
        control: BrowserControlRecord,
        now: datetime,
    ) -> None:
        if control.browser_control_mode in {
            "human_login",
            "human_handoff",
        }:
            if self._browser_runtime.running:
                self._browser_runtime.close()
            self._browser_control.mark_human_session_closed(
                session_id=self._session_id,
                human_session_id=grant.access_window_id,
                expected_record_version=control.record_version,
                now=now,
            )
            return

        if control.browser_control_mode == "automated":
            assert control.instance_id is not None
            assert control.worker_id is not None
            control = self._browser_control.begin_automatic_recovery(
                session_id=self._session_id,
                instance_id=control.instance_id,
                worker_id=control.worker_id,
                job_id=grant.job_id,
                expected_control_epoch=control.control_epoch,
                reason="platform_access_expired",
                now=now,
            )

        if control.browser_lifecycle == "stopped":
            return
        if self._browser_runtime.running:
            self._browser_runtime.close()
        self._mark_stopped(
            grant=grant,
            expected_record_version=control.record_version,
            now=now,
        )

    def _mark_stopped(
        self,
        *,
        grant: AccessWindowGrant,
        expected_record_version: int,
        now: datetime,
    ) -> None:
        request = {
            "access_window_id": grant.access_window_id,
            "job_id": grant.job_id,
            "operation": "platform_access_expiry_close",
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
            access_window_id=grant.access_window_id,
            expected_record_version=expected_record_version,
            idempotency_key=(
                f"platform-access-expiry:{grant.access_window_id}"
            ),
            request_hash=request_hash,
            now=now,
        )

    def _log_deferred(
        self,
        *,
        grant: AccessWindowGrant,
        access_version: int,
        control: BrowserControlRecord,
    ) -> None:
        key = (
            grant.access_window_id,
            access_version,
            f"deferred:{control.control_epoch}:{control.record_version}",
        )
        if not self._take_diagnostic_key(key):
            return
        self._runtime_log_store.append(
            level="warning",
            source="chengfeng-browser",
            event_code="platform_access_expiry_deferred",
            stream="application",
            message=(
                "Expired read-only authority was not closed because the "
                "browser ownership did not match."
            ),
            diagnostic_code=_DEFERRED_DIAGNOSTIC,
            job_id=grant.job_id,
        )

    def _log_failure(
        self,
        candidate: tuple[AccessWindowGrant, int] | None,
    ) -> None:
        if candidate is None:
            key = ("unknown", 0, "failed")
            job_id = None
        else:
            grant, version = candidate
            key = (grant.access_window_id, version, "failed")
            job_id = grant.job_id
        if not self._take_diagnostic_key(key):
            return
        self._runtime_log_store.append(
            level="error",
            source="chengfeng-browser",
            event_code="platform_access_expiry_failed",
            stream="application",
            message=(
                "Expired read-only browser authority could not be "
                "reconciled; it will be retried."
            ),
            diagnostic_code=_FAILURE_DIAGNOSTIC,
            job_id=job_id,
        )

    def _take_diagnostic_key(
        self,
        key: tuple[str, int, str],
    ) -> bool:
        with self._diagnostic_lock:
            if self._last_diagnostic_key == key:
                return False
            self._last_diagnostic_key = key
            return True

    def _clear_diagnostic(self) -> None:
        with self._diagnostic_lock:
            self._last_diagnostic_key = None
