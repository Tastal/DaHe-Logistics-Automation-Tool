from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeError,
    BrowserRuntimeLifecycle,
)
from dahe.adapters.sqlite.browser_control import (
    BrowserControlRecord,
    BrowserControlStore,
)


def reconcile_operational_browser_readiness(
    *,
    browser_control: BrowserControlStore,
    browser_runtime: BrowserRuntime,
    browser_lifecycle: BrowserRuntimeLifecycle,
    session_id: str,
    now: datetime,
) -> BrowserControlRecord:
    """Align durable control state with the owned operational browser runtime."""

    with browser_lifecycle.hold():
        control = browser_control.get(session_id)
        if control.browser_control_mode != "idle":
            return control
        if control.browser_lifecycle not in {"stopped", "ready"}:
            return control
        if not browser_runtime.running:
            try:
                browser_runtime.start_operational()
            except BrowserRuntimeError:
                # Initialization can leave an owned worker half-open. Rebuild
                # it once inside the same business task so the operator never
                # needs a second Start click.
                browser_runtime.close()
                browser_runtime.start_operational()
        if control.browser_lifecycle == "ready":
            return control
        return browser_control.mark_ready(
            session_id=session_id,
            expected_record_version=control.record_version,
            now=now,
        )


def reconcile_terminal_automated_browser_holder(
    *,
    browser_control: BrowserControlStore,
    browser_runtime: BrowserRuntime,
    session_id: str,
    load_job_state: Callable[[str], tuple[str, bool]],
    reconcile_settlement: Callable[[str], None],
    reconcile_daily: Callable[[str], None],
) -> str | None:
    """Recover the exact terminal job still fencing a missing runtime."""

    control = browser_control.get(session_id)
    if (
        control.browser_control_mode != "automated"
        or control.job_id is None
        or browser_runtime.running
    ):
        return None
    task_type, is_terminal = load_job_state(control.job_id)
    if not is_terminal:
        return None
    if task_type == "settlement_capture":
        reconcile_settlement(control.job_id)
    elif task_type == "daily":
        reconcile_daily(control.job_id)
    else:
        return None
    return control.job_id
