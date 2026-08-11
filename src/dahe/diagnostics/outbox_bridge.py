from __future__ import annotations

import threading
from collections.abc import Callable

from dahe.diagnostics.runtime_log import RuntimeLogStore


class RuntimeOutboxLogBridge:
    """Mirror committed scheduler events without copying their payloads."""

    def __init__(
        self,
        *,
        events_after: Callable[[int, int], list[dict[str, object]]],
        store: RuntimeLogStore,
        poll_seconds: float = 0.2,
    ) -> None:
        self._events_after = events_after
        self._store = store
        self._poll_seconds = poll_seconds
        self._cursor = 0
        while True:
            existing = events_after(self._cursor, 1000)
            if not existing:
                break
            self._cursor = int(str(existing[-1]["event_id"]))
            if len(existing) < 1000:
                break
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="dahe-runtime-log-bridge",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self._poll_seconds):
            for event in self._events_after(self._cursor, 100):
                self._cursor = int(str(event["event_id"]))
                event_type = str(event["event_type"])
                aggregate_type = str(event["aggregate_type"])
                aggregate_id = str(event["aggregate_id"])
                self._store.append(
                    level=(
                        "error"
                        if event_type.endswith(".failed")
                        else "warning"
                        if "cancel" in event_type or "pause" in event_type
                        else "info"
                    ),
                    source=aggregate_type,
                    event_code=event_type,
                    stream="application",
                    message=self._message(event_type, aggregate_type),
                    job_id=aggregate_id if aggregate_type == "job" else None,
                    work_item_id=(
                        aggregate_id if aggregate_type == "work_item" else None
                    ),
                )

    @staticmethod
    def _message(event_type: str, aggregate_type: str) -> str:
        labels = {
            "job.queued": "任务已进入队列。",
            "job.changed": "任务状态已更新。",
            "job.succeeded": "任务已完成。",
            "job.failed": "任务发生技术失败。",
            "work_item.changed": "运单处理阶段已更新。",
            "resource.changed": "本地资源租约已更新。",
        }
        return labels.get(
            event_type,
            f"{aggregate_type} runtime state changed ({event_type}).",
        )
