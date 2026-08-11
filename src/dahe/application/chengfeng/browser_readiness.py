from __future__ import annotations

from datetime import datetime

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
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
        if (
            control.browser_control_mode != "idle"
            or control.browser_lifecycle != "stopped"
        ):
            return control
        if not browser_runtime.running:
            browser_runtime.start_operational()
        return browser_control.mark_ready(
            session_id=session_id,
            expected_record_version=control.record_version,
            now=now,
        )
