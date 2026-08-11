from __future__ import annotations

import json
import re
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_.:-]{1,100}$")
_JOB_ID = re.compile(r"^[0-9a-f]{32}$")
_PAGES = frozenset({"settlement", "daily", "history", "system", "application"})
_RESULTS = frozenset({"succeeded", "rejected", "failed"})


class BreadcrumbStore:
    """Bounded local user-action metadata with no business payload fields."""

    def __init__(
        self,
        path: Path,
        *,
        retention: timedelta = timedelta(days=7),
        maximum_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self.path = path.resolve()
        self.retention = retention
        self.maximum_bytes = maximum_bytes
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        page: str,
        action_type: str,
        job_id: str | None,
        result: str,
        error_code: str | None,
        occurred_at: datetime | None = None,
    ) -> None:
        safe_page = page if page in _PAGES else "application"
        safe_action = (
            action_type
            if _IDENTIFIER.fullmatch(action_type) is not None
            else "local_action"
        )
        safe_job_id = job_id if job_id and _JOB_ID.fullmatch(job_id) else None
        safe_result = result if result in _RESULTS else "failed"
        safe_error = (
            error_code
            if error_code and _IDENTIFIER.fullmatch(error_code) is not None
            else None
        )
        event = {
            "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
            "page": safe_page,
            "action_type": safe_action,
            "job_id": safe_job_id,
            "result": safe_result,
            "error_code": safe_error,
        }
        encoded = (
            json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with self._lock:
            with self.path.open("ab") as handle:
                handle.write(encoded)
            self._prune()

    def _prune(self) -> None:
        if not self.path.is_file():
            return
        cutoff = datetime.now(UTC) - self.retention
        try:
            lines = self.path.read_bytes().splitlines(keepends=True)
        except OSError:
            return
        retained: list[bytes] = []
        for line in lines:
            try:
                payload = json.loads(line)
                occurred_at = datetime.fromisoformat(str(payload["occurred_at"]))
            except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                continue
            if occurred_at >= cutoff:
                retained.append(line)
        while retained and sum(map(len, retained)) > self.maximum_bytes:
            retained.pop(0)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_bytes(b"".join(retained))
        temporary.replace(self.path)

    def export(self, *, maximum_bytes: int) -> bytes:
        with self._lock:
            self._prune()
            content = self.path.read_bytes() if self.path.is_file() else b""
        lines = content.splitlines(keepends=True)
        selected: list[bytes] = []
        size = 0
        for line in reversed(lines):
            if size + len(line) > maximum_bytes:
                break
            selected.append(line)
            size += len(line)
        return b"".join(reversed(selected))
