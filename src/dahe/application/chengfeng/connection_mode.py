from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from threading import RLock


class ChengfengConnectionMode(StrEnum):
    OPERATIONAL_COMPAT = "operational_compat"
    STRICT_SHADOW = "strict_shadow"


class ChengfengConnectionModeConflictError(RuntimeError):
    """Raised when a connection mode change is stale or unsafe."""


@dataclass(frozen=True, slots=True)
class ChengfengConnectionModeState:
    mode: ChengfengConnectionMode
    record_version: int


class ChengfengConnectionModeStore:
    """Keep one process-local mode; every restart defaults to business use."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._state = ChengfengConnectionModeState(
            mode=ChengfengConnectionMode.OPERATIONAL_COMPAT,
            record_version=1,
        )
        self._idempotency: dict[
            str,
            tuple[str, ChengfengConnectionModeState],
        ] = {}

    def get(self) -> ChengfengConnectionModeState:
        with self._lock:
            return self._state

    def switch(
        self,
        *,
        mode: ChengfengConnectionMode,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
        switching_allowed: bool,
    ) -> ChengfengConnectionModeState:
        with self._lock:
            replay = self._idempotency.get(idempotency_key)
            if replay is not None:
                prior_hash, prior_state = replay
                if prior_hash != request_hash:
                    raise ChengfengConnectionModeConflictError(
                        "connection mode idempotency key was reused"
                    )
                return prior_state
            if not switching_allowed:
                raise ChengfengConnectionModeConflictError(
                    "connection mode cannot change while work owns the browser"
                )
            if self._state.record_version != expected_record_version:
                raise ChengfengConnectionModeConflictError(
                    "connection mode record version is stale"
                )
            if self._state.mode is mode:
                next_state = self._state
            else:
                next_state = ChengfengConnectionModeState(
                    mode=mode,
                    record_version=self._state.record_version + 1,
                )
                self._state = next_state
            self._idempotency[idempotency_key] = (
                request_hash,
                next_state,
            )
            return next_state
