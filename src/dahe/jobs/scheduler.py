from __future__ import annotations

import threading
from collections.abc import MutableSet
from typing import Protocol


def choose_candidate(
    candidates: list[dict[str, object]],
    *,
    last_granted_job_id: str | None,
    sequence: int,
) -> dict[str, object] | None:
    """Select one candidate using category priority, aging, and fair rotation."""
    if not candidates:
        return None

    def base_priority(candidate: dict[str, object]) -> int:
        return 20 if candidate["job_kind"] == "business" else 10

    highest_base = max(base_priority(candidate) for candidate in candidates)
    eligible = [
        candidate
        for candidate in candidates
        if base_priority(candidate) == highest_base
        or sequence - int(str(candidate["ready_sequence"]))
        >= highest_base - base_priority(candidate)
    ]

    # A single persistent OCR worker should finish the other image for the
    # same truck before rotating to another job. The preference lasts for one
    # image only; normal cross-job fairness resumes after the pair completes.
    paired = [
        candidate
        for candidate in eligible
        if bool(candidate.get("pair_continuation", False))
    ]
    if paired:
        eligible = paired

    def priority(candidate: dict[str, object]) -> tuple[int, int, str, int]:
        last_grant = int(str(candidate.get("last_granted_sequence", 0)))
        if "last_granted_sequence" not in candidate:
            last_grant = (
                sequence if candidate["job_id"] == last_granted_job_id else 0
            )
        return (
            last_grant,
            int(str(candidate["ready_sequence"])),
            str(candidate["job_id"]),
            int(str(candidate["item_index"])),
        )

    return sorted(eligible, key=priority)[0]


class SchedulerRepository(Protocol):
    def scheduler_tick(self, failure_image_hashes: set[str]) -> bool: ...

    def has_automatic_work(self) -> bool: ...

    def automatic_poll_interval_seconds(self) -> float: ...

    def maintain_automatic_work(self) -> bool: ...


class CooperativeScheduler:
    """Drive the single cooperative scheduler over persistent atomic stages."""

    def __init__(self, repository: SchedulerRepository) -> None:
        self._repository = repository
        self._failure_image_hashes: MutableSet[str] = set()

    def tick(self) -> bool:
        return self._repository.scheduler_tick(set(self._failure_image_hashes))

    def has_automatic_work(self) -> bool:
        return self._repository.has_automatic_work()

    def automatic_poll_interval_seconds(self) -> float:
        interval = self._repository.automatic_poll_interval_seconds()
        if interval < 0:
            raise ValueError("automatic poll interval cannot be negative")
        return interval

    def maintain_automatic_work(self) -> bool:
        maintain = getattr(self._repository, "maintain_automatic_work", None)
        if maintain is None:
            return True
        return bool(maintain())

    def run_until_quiescent(self, *, max_ticks: int) -> int:
        if max_ticks <= 0:
            raise ValueError("max_ticks must be positive")
        for tick_count in range(1, max_ticks + 1):
            self.tick()
            if not self.has_automatic_work():
                return tick_count
        raise RuntimeError("scheduler did not become quiescent")

    def inject_ocr_failure(self, image_sha256: str) -> None:
        self._failure_image_hashes.add(image_sha256)


class CooperativeSchedulerRunner:
    """Wake a cooperative scheduler without owning its persistent state."""

    def __init__(
        self,
        scheduler: CooperativeScheduler,
        *,
        tick_interval_seconds: float = 0,
    ) -> None:
        if tick_interval_seconds < 0:
            raise ValueError("tick_interval_seconds cannot be negative")
        self._scheduler = scheduler
        self._tick_interval_seconds = tick_interval_seconds
        self._wake = threading.Event()
        self._closed = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="dahe-loop3-scheduler",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def notify(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        while not self._closed.is_set():
            self._wake.wait(timeout=0.1)
            self._wake.clear()
            while (
                not self._closed.is_set()
                and self._scheduler.has_automatic_work()
            ):
                self._scheduler.tick()
                while (
                    not self._closed.is_set()
                    and self._scheduler.has_automatic_work()
                ):
                    # Browser futures can run for minutes, while OCR futures
                    # finish at image boundaries. Let the repository perform a
                    # lightweight lease heartbeat until the external future is
                    # complete, while an API control action still wakes the full
                    # scheduler immediately.
                    cadence = getattr(
                        self._scheduler,
                        "automatic_poll_interval_seconds",
                        lambda: 0.25,
                    )()
                    interval = max(
                        self._tick_interval_seconds,
                        float(cadence),
                        0.25,
                    )
                    notified = self._wake.wait(interval)
                    self._wake.clear()
                    if notified:
                        break
                    maintain = getattr(
                        self._scheduler,
                        "maintain_automatic_work",
                        lambda: True,
                    )
                    if maintain():
                        break

    def close(self) -> None:
        self._closed.set()
        self._wake.set()
        if self._thread.is_alive():
            # A committed checkpoint or an abandoned-attempt transition may only
            # happen after the current atomic scheduler quantum has returned.
            # Closing the database while this thread is still inside a tick
            # would turn an orderly shutdown into an unsafe concurrent write.
            self._thread.join()
