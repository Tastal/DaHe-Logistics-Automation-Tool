from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class TransientBusinessProgress:
    revision: int
    job_id: str
    phase: str
    completed: int
    total: int
    updated_at: datetime


class TransientBusinessProgressStore:
    """Publish non-durable item progress without changing batch checkpoints."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._revision = 0
        self._records: dict[str, TransientBusinessProgress] = {}

    def publish(self, job_id: str, phase: str, completed: int, total: int) -> None:
        if not job_id.strip() or completed < 0 or total < 0 or completed > total:
            raise ValueError("transient business progress is invalid")
        with self._condition:
            self._revision += 1
            self._records[job_id] = TransientBusinessProgress(
                revision=self._revision,
                job_id=job_id,
                phase=phase,
                completed=completed,
                total=total,
                updated_at=datetime.now(UTC),
            )
            self._condition.notify_all()

    def get(self, job_id: str) -> TransientBusinessProgress | None:
        with self._condition:
            return self._records.get(job_id)

    def wait_after(
        self, job_id: str, revision: int, timeout: float
    ) -> TransientBusinessProgress | None:
        with self._condition:
            current = self._records.get(job_id)
            if current is None or current.revision <= revision:
                self._condition.wait(timeout=timeout)
                current = self._records.get(job_id)
            if current is None or current.revision <= revision:
                return None
            return current

    def clear(self, job_id: str) -> None:
        with self._condition:
            self._records.pop(job_id, None)

