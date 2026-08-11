from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict, cast


class RuntimeLogEvent(TypedDict):
    event_id: str
    created_at: str
    level: str
    source: str
    event_code: str
    stream: str
    message: str
    diagnostic_code: str | None
    job_id: str | None
    work_item_id: str | None


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|cookie|authorization|token|secret|access[_ -]?code"
    r"|raw[_ -]?ocr|ocr[_ -]?text|recognized[_ -]?text)"
    r"\s*[:=]\s*.*$"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_URL = re.compile(r"https?://[^\s<>'\"]+")
_WINDOWS_PATH = re.compile(
    r"(?i)(?:[A-Z]:[\\/]|\\\\)[^<>:\"|?*\r\n,;]+"
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_SAFE_LEVELS = {"debug", "info", "warning", "error"}
_SAFE_STREAMS = {"application", "stdout", "stderr"}
_SAFE_FIELD = re.compile(r"[^a-zA-Z0-9_.:-]")


def redact_runtime_text(value: str) -> str:
    """Return single-line diagnostic text without operational secrets."""

    cleaned = _CONTROL_CHARACTERS.sub("", value).replace("\r", " ").replace("\n", " ")
    cleaned = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", cleaned)
    cleaned = _BEARER.sub("Bearer [REDACTED]", cleaned)

    def redact_url(match: re.Match[str]) -> str:
        url = match.group(0)
        return url.split("?", 1)[0].split("#", 1)[0] + "[QUERY_REDACTED]"

    cleaned = _URL.sub(redact_url, cleaned)
    cleaned = _WINDOWS_PATH.sub("[PATH_REDACTED]", cleaned)
    cleaned = _EMAIL.sub("[CONTACT_REDACTED]", cleaned)
    cleaned = _PHONE.sub("[CONTACT_REDACTED]", cleaned)
    return cleaned[:2000]


class RuntimeLogStore:
    """Best-effort JSONL log store that can never block business processing."""

    def __init__(
        self,
        root: Path,
        *,
        segment_bytes: int = 5 * 1024 * 1024,
        total_bytes: int = 50 * 1024 * 1024,
        retention: timedelta = timedelta(days=7),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._root = root
        self._segment_bytes = segment_bytes
        self._total_bytes = total_bytes
        self._retention = retention
        self._now = now or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._last_event_id = 0
        self._write_error: str | None = None
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            self._last_event_id = self._scan_last_event_id()
            self.prune()
        except OSError as exc:
            self._write_error = type(exc).__name__

    def append(
        self,
        *,
        level: str,
        source: str,
        event_code: str,
        stream: str,
        message: str,
        diagnostic_code: str | None = None,
        job_id: str | None = None,
        work_item_id: str | None = None,
    ) -> RuntimeLogEvent | None:
        try:
            with self._condition:
                if self._write_error is not None and not self._root.is_dir():
                    return None
                created_at = self._utc_now()
                self._last_event_id = max(
                    self._last_event_id + 1,
                    time.time_ns(),
                )
                event: RuntimeLogEvent = {
                    "event_id": str(self._last_event_id),
                    "created_at": created_at.isoformat(),
                    "level": level if level in _SAFE_LEVELS else "info",
                    "source": self._safe_identifier(source, "application"),
                    "event_code": self._safe_identifier(event_code, "runtime_event"),
                    "stream": stream if stream in _SAFE_STREAMS else "application",
                    "message": redact_runtime_text(message),
                    "diagnostic_code": self._optional_identifier(diagnostic_code),
                    "job_id": self._optional_identifier(job_id),
                    "work_item_id": self._optional_identifier(work_item_id),
                }
                encoded = (
                    json.dumps(
                        event,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                path = self._active_segment(created_at, len(encoded))
                with path.open("ab") as handle:
                    handle.write(encoded)
                    handle.flush()
                self._write_error = None
                self._prune_locked(created_at)
                self._condition.notify_all()
                return event
        except OSError as exc:
            self._write_error = type(exc).__name__
            return None

    def append_process_output(
        self,
        *,
        source: str,
        stream: str,
        text: str,
        protocol_stdout: bool = False,
        diagnostic_code: str | None = None,
    ) -> RuntimeLogEvent | None:
        source_kind = source.casefold()
        content_must_be_excluded = (
            protocol_stdout
            or "ocr" in source_kind
            or "browser" in source_kind
        )
        if content_must_be_excluded:
            byte_count = len(text.encode("utf-8", errors="replace"))
            return self.append(
                level=(
                    "debug"
                    if protocol_stdout
                    else "error"
                    if stream == "stderr"
                    else "info"
                ),
                source=source,
                event_code=(
                    "protocol_output"
                    if protocol_stdout
                    else f"process_{stream}"
                ),
                stream=stream,
                message=(
                    f"Protocol stdout received ({byte_count} bytes); "
                    "content excluded."
                    if protocol_stdout
                    else (
                        f"Controlled process {stream} received "
                        f"({byte_count} bytes); content excluded."
                    )
                ),
                diagnostic_code=diagnostic_code,
            )
        return self.append(
            level="error" if stream == "stderr" else "info",
            source=source,
            event_code=f"process_{stream}",
            stream=stream,
            message=text,
            diagnostic_code=diagnostic_code,
        )

    def query(
        self,
        *,
        before: int | None = None,
        after: int | None = None,
        limit: int = 200,
        level: str | None = None,
        source: str | None = None,
        text: str | None = None,
    ) -> dict[str, object]:
        safe_limit = max(1, min(limit, 1000))
        needle = (text or "").casefold()
        with self._lock:
            events = self._read_events_locked()
        filtered = [
            event
            for event in events
            if (before is None or int(event["event_id"]) < before)
            and (after is None or int(event["event_id"]) > after)
            and (level is None or event["level"] == level)
            and (source is None or event["source"] == source)
            and (
                not needle
                or needle in event["message"].casefold()
                or needle in event["event_code"].casefold()
                or (
                    event["diagnostic_code"] is not None
                    and needle in event["diagnostic_code"].casefold()
                )
            )
        ]
        page = filtered[-safe_limit:]
        all_ids = [int(event["event_id"]) for event in events]
        return {
            "events": page,
            "earliest_cursor": str(min(all_ids)) if all_ids else None,
            "latest_cursor": str(max(all_ids)) if all_ids else None,
            "has_more_older": len(filtered) > len(page),
        }

    def export_text(self) -> bytes:
        with self._lock:
            events = self._read_events_locked()
        lines = [
            (
                f"{event['created_at']} {str(event['level']).upper():7} "
                f"{event['source']} {event['event_code']} {event['message']}"
            )
            for event in events
        ]
        return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")

    def wait_for_newer(self, cursor: int, timeout: float) -> bool:
        with self._condition:
            if self._last_event_id > cursor:
                return True
            self._condition.wait(timeout)
            return self._last_event_id > cursor

    def health_status(self) -> dict[str, str]:
        if self._write_error is None:
            return {
                "id": "runtime_logs",
                "label": "运行日志",
                "status": "normal",
                "summary": "日志记录正常",
            }
        return {
            "id": "runtime_logs",
            "label": "运行日志",
            "status": "attention",
            "summary": "日志暂时无法写入, 不影响业务处理",
        }

    def prune(self) -> None:
        try:
            with self._lock:
                self._prune_locked(self._utc_now())
        except OSError as exc:
            self._write_error = type(exc).__name__

    def _utc_now(self) -> datetime:
        current = self._now()
        return current if current.tzinfo is not None else current.replace(tzinfo=UTC)

    def _scan_last_event_id(self) -> int:
        events = self._read_events_locked()
        return max((int(event["event_id"]) for event in events), default=0)

    def _read_events_locked(self) -> list[RuntimeLogEvent]:
        events: list[RuntimeLogEvent] = []
        if not self._root.is_dir():
            return events
        for path in sorted(self._root.glob("runtime-*.jsonl")):
            try:
                with path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        try:
                            value = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(value, dict) or not isinstance(
                            value.get("event_id"),
                            str,
                        ):
                            continue
                        try:
                            event_id = str(int(value["event_id"]))
                        except (TypeError, ValueError):
                            continue
                        created_at = _CONTROL_CHARACTERS.sub(
                            "",
                            str(value.get("created_at", "")),
                        )[:80]
                        level = str(value.get("level", "info"))
                        stream = str(value.get("stream", "application"))
                        events.append(
                            cast(
                                RuntimeLogEvent,
                                {
                                    "event_id": event_id,
                                    "created_at": created_at,
                                    "level": (
                                        level
                                        if level in _SAFE_LEVELS
                                        else "info"
                                    ),
                                    "source": self._safe_identifier(
                                        str(value.get("source", "")),
                                        "application",
                                    ),
                                    "event_code": self._safe_identifier(
                                        str(value.get("event_code", "")),
                                        "runtime_event",
                                    ),
                                    "stream": (
                                        stream
                                        if stream in _SAFE_STREAMS
                                        else "application"
                                    ),
                                    "message": redact_runtime_text(
                                        str(value.get("message", ""))
                                    ),
                                    "diagnostic_code": self._optional_identifier(
                                        None
                                        if value.get("diagnostic_code") is None
                                        else str(
                                            value["diagnostic_code"]
                                        )
                                    ),
                                    "job_id": self._optional_identifier(
                                        None
                                        if value.get("job_id") is None
                                        else str(value["job_id"])
                                    ),
                                    "work_item_id": self._optional_identifier(
                                        None
                                        if value.get("work_item_id") is None
                                        else str(value["work_item_id"])
                                    ),
                                },
                            )
                        )
            except OSError:
                continue
        events.sort(key=lambda event: int(event["event_id"]))
        return events

    def _active_segment(self, created_at: datetime, incoming: int) -> Path:
        prefix = f"runtime-{created_at:%Y%m%d}-"
        candidates = sorted(self._root.glob(f"{prefix}*.jsonl"))
        if candidates and candidates[-1].stat().st_size + incoming <= self._segment_bytes:
            return candidates[-1]
        sequence = 1
        if candidates:
            sequence = int(candidates[-1].stem.rsplit("-", 1)[1]) + 1
        return self._root / f"{prefix}{sequence:04d}.jsonl"

    def _prune_locked(self, current: datetime) -> None:
        if not self._root.is_dir():
            return
        cutoff = current - self._retention
        files = sorted(self._root.glob("runtime-*.jsonl"))
        for path in files:
            try:
                day = datetime.strptime(path.name[8:16], "%Y%m%d").replace(
                    tzinfo=UTC
                )
            except ValueError:
                continue
            if day + timedelta(days=1) <= cutoff:
                path.unlink(missing_ok=True)
        files = sorted(
            self._root.glob("runtime-*.jsonl"),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
        )
        total = sum(path.stat().st_size for path in files)
        while files and total > self._total_bytes:
            oldest = files.pop(0)
            total -= oldest.stat().st_size
            oldest.unlink(missing_ok=True)

    @staticmethod
    def _safe_identifier(value: str, fallback: str) -> str:
        cleaned = _SAFE_FIELD.sub("_", value)[:80]
        return cleaned or fallback

    @classmethod
    def _optional_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return cls._safe_identifier(value, "unknown")
