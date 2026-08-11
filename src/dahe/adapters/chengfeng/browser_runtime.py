from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from threading import Event, RLock
from typing import Protocol
from uuid import uuid4

from pydantic import ValidationError

from dahe.adapters.chengfeng.contract_freezer import LIST_PATH
from dahe.adapters.chengfeng.daily_manifest import (
    DAILY_LIST_OPERATION,
    DAILY_LIST_PATH,
    DAILY_ORIGIN,
)
from dahe.adapters.chengfeng.daily_request_builder import DailyAuthorizedRequest
from dahe.adapters.chengfeng.discovery import DiscoveryObservation
from dahe.adapters.chengfeng.live_manifest import (
    LiveAuthorizedImageRequest,
    LiveAuthorizedRequest,
)
from dahe.ports.chengfeng import WaybillReuseCandidate
from dahe.system.supervision import (
    SupervisedLineProcess,
    SupervisedLineProcessError,
    SupervisedLineProcessTimeout,
)

HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS = 75
FREEZE_HUMAN_SESSION_WORKER_TIMEOUT_SECONDS = 80
PREPARE_AUTOMATED_WORKER_TIMEOUT_SECONDS = 80
PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS = 150
PREPARE_DAILY_WORKER_TIMEOUT_SECONDS = 80
OPERATIONAL_BATCH_WORKER_TIMEOUT_SECONDS = 480
BROWSER_PROTOCOL_VERSION = 6
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_QUERY_ATTEMPT_ID = re.compile(r"^[0-9a-f]{32}$")
_READ_MEDIA_TYPES = {
    "application/json",
    "image/bmp",
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/webp",
}
_READ_RESULT_FIELDS = {
    "relative_path",
    "sha256",
    "byte_size",
    "media_type",
    "status_code",
}
_LIST_BODY_STRUCTURE_MISMATCH_CODES = {
    "browser_daily_response_contract_changed",
    "browser_session_native_probe_contract_changed",
    "browser_session_native_probe_page_number_mismatch",
    "browser_session_native_probe_page_number_ahead_one",
    "browser_session_native_probe_page_number_is_total_pages",
    "browser_session_native_probe_page_number_is_total_count",
    "browser_session_native_probe_page_number_is_page_size",
    "browser_session_native_probe_page_number_ahead_many",
    "browser_session_native_probe_page_number_behind_many",
    "browser_session_native_probe_list_exceeds_requested_page_size",
    "browser_session_native_probe_list_exceeds_response_page_size",
    "browser_session_native_probe_total_below_list_length",
    "browser_session_native_probe_page_size_mismatch",
    "browser_session_list_body_field_set_mismatch",
    "browser_session_list_body_fields_added",
    "browser_session_list_body_fields_removed",
    "browser_session_list_body_fields_changed",
}


class BrowserRuntimeError(RuntimeError):
    """Raised when the isolated browser worker cannot be trusted or controlled."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "browser_runtime_failed",
        safe_discovery: tuple[dict[str, object], ...] = (),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.safe_discovery = safe_discovery


def _validated_error_discovery(
    value: object,
    *,
    error_code: object,
) -> tuple[dict[str, object], ...]:
    if value is None:
        return ()
    if (
        error_code not in _LIST_BODY_STRUCTURE_MISMATCH_CODES
        or not isinstance(value, list)
        or len(value) != 1
        or not isinstance(value[0], dict)
    ):
        raise BrowserRuntimeError("browser worker returned unsafe diagnostics")
    try:
        observation = DiscoveryObservation.model_validate(value[0])
    except ValidationError as exc:
        raise BrowserRuntimeError(
            "browser worker returned unsafe diagnostics"
        ) from exc
    return (observation.model_dump(mode="json"),)


@dataclass(frozen=True, slots=True)
class BrowserReadPayload:
    content: bytes
    sha256: str
    media_type: str
    byte_size: int
    status_code: int
    validator_sha256: str | None = None
    reused_from_cache: bool = False


@dataclass(frozen=True, slots=True)
class BrowserOperationalBatchItem:
    platform_waybill_id: str
    source_revision_sha256: str
    detail: BrowserReadPayload
    images: tuple[tuple[str, BrowserReadPayload], ...]


@dataclass(frozen=True, slots=True)
class SettlementQueryFlightRecord:
    """Value-free diagnostics for one atomic page-native list query."""

    query_attempt_id: str
    observed_request_count: int
    approved_request_count: int
    blocked_request_count: int
    query_attempt_count: int
    zero_retry_performed: bool
    cache_refresh_count: int
    page_count: int
    request_method: str
    request_path: str
    resource_type: str
    response_status: int
    response_byte_size: int
    response_structure_sha256: str
    duration_ms: int

    def __post_init__(self) -> None:
        if _QUERY_ATTEMPT_ID.fullmatch(self.query_attempt_id) is None:
            raise ValueError("settlement query attempt identity is invalid")
        if (
            type(self.observed_request_count) is not int
            or not 1 <= self.observed_request_count <= 10_000
            or type(self.approved_request_count) is not int
            or type(self.query_attempt_count) is not int
            or self.query_attempt_count not in {1, 2}
            or self.approved_request_count != self.query_attempt_count
            or type(self.blocked_request_count) is not int
            or self.blocked_request_count < 0
            or self.observed_request_count
            != self.approved_request_count + self.blocked_request_count
            or type(self.zero_retry_performed) is not bool
            or self.zero_retry_performed
            != (self.query_attempt_count == 2)
            or type(self.cache_refresh_count) is not int
            or self.cache_refresh_count != self.query_attempt_count
            or type(self.page_count) is not int
            or self.page_count != 1
            or self.request_method != "POST"
            or self.request_path != LIST_PATH
            or self.resource_type not in {"fetch", "xhr"}
            or self.response_status != 200
            or type(self.response_byte_size) is not int
            or not 1 <= self.response_byte_size <= 2 * 1024 * 1024
            or _SHA256.fullmatch(self.response_structure_sha256) is None
            or type(self.duration_ms) is not int
            or not 0 <= self.duration_ms <= 120_000
        ):
            raise ValueError("settlement query flight record is invalid")

    @classmethod
    def from_worker_payload(
        cls,
        value: object,
    ) -> SettlementQueryFlightRecord:
        expected = {
            "schema_version",
            "query_attempt_id",
            "observed_request_count",
            "approved_request_count",
            "blocked_request_count",
            "query_attempt_count",
            "zero_retry_performed",
            "cache_refresh_count",
            "page_count",
            "request_method",
            "request_path",
            "resource_type",
            "response_status",
            "response_byte_size",
            "response_structure_sha256",
            "duration_ms",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or value.get("schema_version") != 1
        ):
            raise ValueError("settlement query flight record fields are invalid")
        return cls(
            query_attempt_id=value["query_attempt_id"],
            observed_request_count=value["observed_request_count"],
            approved_request_count=value["approved_request_count"],
            blocked_request_count=value["blocked_request_count"],
            query_attempt_count=value["query_attempt_count"],
            zero_retry_performed=value["zero_retry_performed"],
            cache_refresh_count=value["cache_refresh_count"],
            page_count=value["page_count"],
            request_method=value["request_method"],
            request_path=value["request_path"],
            resource_type=value["resource_type"],
            response_status=value["response_status"],
            response_byte_size=value["response_byte_size"],
            response_structure_sha256=value["response_structure_sha256"],
            duration_ms=value["duration_ms"],
        )


@dataclass(frozen=True, slots=True)
class DailyPreparationEvidence:
    """Value-free proof that the daily page was freshly prepared."""

    cache_refresh_count: int
    page_count: int
    route: str

    @classmethod
    def from_worker_payload(cls, value: object) -> DailyPreparationEvidence:
        expected = {
            "schema_version",
            "evidence_kind",
            "cache_disabled_during_reload",
            "ignore_cache_reload",
            "cache_refresh_count",
            "fresh_query_response_observed",
            "page_count",
            "route",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("daily freshness evidence fields are invalid")
        cache_refresh_count = value.get("cache_refresh_count")
        if (
            value.get("schema_version") != 1
            or value.get("evidence_kind") != "chengfeng_daily_freshness"
            or value.get("cache_disabled_during_reload") is not True
            or value.get("ignore_cache_reload") is not True
            or type(cache_refresh_count) is not int
            or not 1 <= cache_refresh_count <= 2
            or value.get("fresh_query_response_observed") is not True
            or value.get("page_count") != 1
            or value.get("route") != "/wayBill"
        ):
            raise ValueError("daily freshness evidence is invalid")
        return cls(
            cache_refresh_count=cache_refresh_count,
            page_count=1,
            route="/wayBill",
        )


@dataclass(frozen=True, slots=True)
class SettlementListProbe:
    """Bounded page-native list metadata with no platform business values."""

    total_count: int
    list_length: int
    page_number: int
    page_size: int
    response_structure_sha256: str
    query_trace: SettlementQueryFlightRecord | None = None

    def __post_init__(self) -> None:
        integer_values = (
            self.total_count,
            self.list_length,
            self.page_number,
            self.page_size,
        )
        if any(type(value) is not int for value in integer_values):
            raise ValueError("settlement list probe metrics must be integers")
        if not 0 <= self.total_count <= 10_000_000:
            raise ValueError("settlement list probe total is outside its bound")
        if not 0 <= self.list_length <= 100:
            raise ValueError("settlement list probe length is outside its bound")
        if not 0 <= self.page_number <= 10_000:
            raise ValueError("settlement list probe page is outside its bound")
        if not 1 <= self.page_size <= 100:
            raise ValueError("settlement list probe page size is outside its bound")
        if (
            self.list_length > self.page_size
            or self.total_count < self.list_length
            or (self.total_count == 0 and self.list_length != 0)
        ):
            raise ValueError("settlement list probe metrics are inconsistent")
        if _SHA256.fullmatch(self.response_structure_sha256) is None:
            raise ValueError("settlement list probe structure identity is invalid")

    @classmethod
    def from_worker_payload(
        cls,
        value: object,
        *,
        require_query_trace: bool = False,
    ) -> SettlementListProbe:
        required = {
            "schema_version",
            "probe_kind",
            "operation",
            "metrics",
            "response_structure_sha256",
        }
        expected = required | ({"query_trace"} if require_query_trace else set())
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("settlement list probe fields are invalid")
        metrics = value.get("metrics")
        if (
            value.get("schema_version") != 1
            or value.get("probe_kind") != "chengfeng_settlement_list"
            or value.get("operation") != "list_waybills"
            or not isinstance(metrics, dict)
            or set(metrics)
            != {
                "total_count",
                "list_length",
                "page_number",
                "page_size",
            }
        ):
            raise ValueError("settlement list probe contract is invalid")
        trace = (
            SettlementQueryFlightRecord.from_worker_payload(
                value["query_trace"]
            )
            if require_query_trace
            else None
        )
        if (
            trace is not None
            and trace.response_structure_sha256
            != value["response_structure_sha256"]
        ):
            raise ValueError("settlement query trace identity is inconsistent")
        return cls(
            total_count=metrics["total_count"],
            list_length=metrics["list_length"],
            page_number=metrics["page_number"],
            page_size=metrics["page_size"],
            response_structure_sha256=value["response_structure_sha256"],
            query_trace=trace,
        )


@dataclass(frozen=True, slots=True)
class SettlementViewProbe:
    """Value-free counts from the two official pending-settlement tabs."""

    settlement_total_count: int
    settlement_list_length: int
    credit_total_count: int
    credit_list_length: int
    page_number: int
    page_size: int
    settlement_response_structure_sha256: str
    credit_response_structure_sha256: str

    def __post_init__(self) -> None:
        for total, length in (
            (self.settlement_total_count, self.settlement_list_length),
            (self.credit_total_count, self.credit_list_length),
        ):
            if (
                type(total) is not int
                or not 0 <= total <= 10_000_000
                or type(length) is not int
                or not 0 <= length <= 100
                or total < length
                or (total == 0 and length != 0)
            ):
                raise ValueError("settlement view metrics are invalid")
        if (
            type(self.page_number) is not int
            or not 0 <= self.page_number <= 10_000
            or type(self.page_size) is not int
            or not 1 <= self.page_size <= 100
            or self.settlement_list_length > self.page_size
            or self.credit_list_length > self.page_size
            or _SHA256.fullmatch(
                self.settlement_response_structure_sha256
            )
            is None
            or _SHA256.fullmatch(
                self.credit_response_structure_sha256
            )
            is None
        ):
            raise ValueError("settlement view metadata is invalid")

    @classmethod
    def from_worker_payload(cls, value: object) -> SettlementViewProbe:
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "probe_kind",
                "operation",
                "views",
            }
            or value.get("schema_version") != 1
            or value.get("probe_kind") != "chengfeng_settlement_views"
            or value.get("operation") != "list_waybills"
        ):
            raise ValueError("settlement view probe fields are invalid")
        raw_views = value.get("views")
        if not isinstance(raw_views, list) or len(raw_views) != 2:
            raise ValueError("settlement view probe views are invalid")
        normalized: dict[str, dict[str, object]] = {}
        for expected_view, raw_view in zip(
            ("settlement", "credit"),
            raw_views,
            strict=True,
        ):
            if (
                not isinstance(raw_view, dict)
                or set(raw_view)
                != {
                    "view",
                    "metrics",
                    "response_structure_sha256",
                }
                or raw_view.get("view") != expected_view
                or not isinstance(raw_view.get("metrics"), dict)
                or set(raw_view["metrics"])
                != {
                    "total_count",
                    "list_length",
                    "page_number",
                    "page_size",
                }
            ):
                raise ValueError("settlement view probe contract is invalid")
            normalized[expected_view] = raw_view
        settlement = normalized["settlement"]
        credit = normalized["credit"]
        settlement_metrics = settlement["metrics"]
        credit_metrics = credit["metrics"]
        assert isinstance(settlement_metrics, dict)
        assert isinstance(credit_metrics, dict)
        settlement_digest = settlement["response_structure_sha256"]
        credit_digest = credit["response_structure_sha256"]
        if (
            settlement_metrics["page_number"]
            != credit_metrics["page_number"]
            or settlement_metrics["page_size"]
            != credit_metrics["page_size"]
            or not isinstance(settlement_digest, str)
            or not isinstance(credit_digest, str)
        ):
            raise ValueError("settlement view paging is inconsistent")
        return cls(
            settlement_total_count=settlement_metrics["total_count"],
            settlement_list_length=settlement_metrics["list_length"],
            credit_total_count=credit_metrics["total_count"],
            credit_list_length=credit_metrics["list_length"],
            page_number=settlement_metrics["page_number"],
            page_size=settlement_metrics["page_size"],
            settlement_response_structure_sha256=settlement_digest,
            credit_response_structure_sha256=credit_digest,
        )


def default_browser_runtime_root() -> Path:
    explicit = os.environ.get("DAHE_BROWSER_RUNTIME_ROOT")
    if explicit:
        root = Path(explicit)
        if not root.is_absolute():
            raise BrowserRuntimeError("browser runtime root is not absolute")
        return root.resolve()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data is None:
        raise BrowserRuntimeError("LOCALAPPDATA is unavailable")
    root = Path(local_app_data) / "DaHeLogistics" / "runtimes" / "browser"
    if not root.is_absolute():
        raise BrowserRuntimeError("browser runtime root is not absolute")
    return root.resolve()


class BrowserRuntimeLifecycle(Protocol):
    """Serialize physical browser lifecycle changes with durable control state."""

    def hold(self) -> contextlib.AbstractContextManager[None]: ...


class BrowserRuntimeLifecycleGuard:
    """Process-local fence spanning browser state and runtime transitions."""

    def __init__(self) -> None:
        self._lock = RLock()

    @contextlib.contextmanager
    def hold(self) -> Iterator[None]:
        with self._lock:
            yield


class BrowserRuntime(Protocol):
    @property
    def available(self) -> bool: ...

    @property
    def running(self) -> bool: ...

    @property
    def selected_browser(self) -> str | None: ...

    @property
    def discovery_capturing(self) -> bool: ...

    @property
    def capability_generation_id(self) -> str | None: ...

    def start_human_login(self) -> str: ...

    def start_operational(self) -> str: ...

    def freeze_human_session(self) -> None: ...

    def probe_settlement_views(self) -> SettlementViewProbe: ...

    def start_discovery_capture(self) -> None: ...

    def stop_discovery_capture(self) -> list[dict[str, object]]: ...

    def prepare_automated(
        self,
        *,
        scope: str = "current",
    ) -> SettlementListProbe: ...

    def prepare_operational_compat(self) -> SettlementListProbe: ...

    def prepare_settlement_filter_handoff(
        self,
        waybill_numbers: tuple[str, ...],
    ) -> dict[str, int]: ...

    def handoff_operational_session(self) -> None: ...

    def park_operational_session(self) -> None: ...

    def prepare_daily(self) -> dict[str, object]: ...

    def prepare_daily_from_automated(self) -> dict[str, object]: ...

    def prepare_operational_daily(self) -> dict[str, object]: ...

    def read_daily(self, request: DailyAuthorizedRequest) -> BrowserReadPayload: ...

    def read(
        self,
        request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
    ) -> BrowserReadPayload: ...

    def read_operational_batch(
        self,
        requests: tuple[tuple[str, LiveAuthorizedRequest], ...],
        *,
        detail_concurrency: int,
        image_concurrency: int,
        reuse_candidates: tuple[WaybillReuseCandidate, ...] = (),
        active_job_id: str | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> tuple[BrowserOperationalBatchItem, ...]: ...

    def abort_active_operation(self, job_id: str) -> bool: ...

    def close(self) -> None: ...


class IsolatedBrowserRuntime:
    """Own one isolated NDJSON worker without importing Playwright."""

    def __init__(
        self,
        *,
        project_root: Path,
        data_root: Path,
        runtime_root: Path,
        browser: str = "auto",
        below_normal_priority: bool = False,
        output_sink: Callable[[str, str, str, bool], None] | None = None,
        event_sink: Callable[[str, str], None] | None = None,
    ) -> None:
        self._project_root = project_root.resolve()
        self._data_root = data_root.resolve()
        self._runtime_root = runtime_root.resolve()
        self._browser = browser
        self._below_normal_priority = below_normal_priority
        self._output_sink = output_sink
        self._event_sink = event_sink
        if browser not in {"auto", "chromium", "msedge"}:
            raise ValueError("browser preference is invalid")
        self._process: SupervisedLineProcess | None = None
        self._selected_browser: str | None = None
        self._headless = False
        self._active_read_scope: str | None = None
        self._operational_probe: SettlementListProbe | None = None
        self._daily_preparation: dict[str, object] | None = None
        self._discovery_capturing = False
        self._capability_generation_id: str | None = None
        self._lock = RLock()
        self._active_batch_request_id: str | None = None
        self._active_batch_job_id: str | None = None
        self._active_batch_abort_ack = Event()
        self._active_batch_finished = Event()

    def _emit_event(self, event_code: str, message: str) -> None:
        if self._event_sink is not None:
            self._event_sink(event_code, message)

    @staticmethod
    def _worker_state(process: SupervisedLineProcess | None) -> str:
        if process is None:
            return "worker=missing"
        exit_code = getattr(process, "exit_code", None)
        stderr_digest = getattr(process, "stderr_digest", None)
        return (
            f"worker_alive={str(process.is_alive).lower()} "
            f"exit_code={exit_code} "
            f"stderr_digest={stderr_digest or 'none'}"
        )

    @property
    def _python(self) -> Path:
        portable = self._runtime_root / "python" / "python.exe"
        if portable.is_file():
            return portable
        return self._runtime_root / "python" / "Scripts" / "python.exe"

    @property
    def _manifest(self) -> Path:
        return self._runtime_root / "runtime-installation.json"

    @property
    def available(self) -> bool:
        try:
            self._validate_installation()
        except BrowserRuntimeError:
            return False
        return True

    @property
    def running(self) -> bool:
        with self._lock:
            process = self._process
            if process is None or not process.is_alive:
                return False
            frozen_settlement_authority = (
                self._active_read_scope == "settlement"
                and self._operational_probe is not None
            )
            frozen_daily_authority = (
                self._active_read_scope == "daily"
                and self._daily_preparation is not None
            )
            if frozen_settlement_authority or frozen_daily_authority:
                # A frozen operational session may be busy serving a long batch
                # and cannot answer an unrelated status command synchronously.
                # Process supervision is the liveness authority until the next
                # bounded business command completes or fails explicitly.
                return True
            try:
                response = self._exchange(
                    {
                        "schema_version": BROWSER_PROTOCOL_VERSION,
                        "command": "status",
                        "request_id": uuid4().hex,
                    },
                    timeout=2,
                )
            except BrowserRuntimeError:
                self._terminate_owned()
                return False
            if (
                response.get("read_result") is None
                and response.get("browser_open") is True
            ):
                return True
            self._terminate_owned()
            return False

    @property
    def selected_browser(self) -> str | None:
        return self._selected_browser

    @property
    def discovery_capturing(self) -> bool:
        return self._discovery_capturing

    @property
    def capability_generation_id(self) -> str | None:
        with self._lock:
            if self._process is None or not self._process.is_alive:
                return None
            return self._capability_generation_id

    def _validate_installation(self) -> None:
        if (
            not self._python.is_file()
            or not self._manifest.is_file()
            or self._python.is_symlink()
            or self._manifest.is_symlink()
        ):
            raise BrowserRuntimeError("isolated browser runtime is not installed")
        try:
            raw = json.loads(self._manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BrowserRuntimeError("browser runtime manifest is unreadable") from exc
        lock = self._project_root / "browser-runtime" / "requirements.lock"
        source_root = self._project_root / "browser-runtime" / "src" / "dahe_browser_worker"
        source_digest = hashlib.sha256()
        for path in sorted(source_root.rglob("*.py")):
            source_digest.update(path.relative_to(source_root).as_posix().encode("utf-8"))
            source_digest.update(b"\0")
            source_digest.update(path.read_bytes())
            source_digest.update(b"\0")
        if (
            raw.get("schema_version") != 1
            or raw.get("runtime_kind") != "browser"
            or raw.get("dependency_lock") != "browser-runtime/requirements.lock"
            or raw.get("dependency_lock_sha256") != hashlib.sha256(lock.read_bytes()).hexdigest()
            or raw.get("worker_source_sha256") != source_digest.hexdigest()
            or raw.get("smoke_selected_browser") not in {"chromium", "msedge"}
        ):
            raise BrowserRuntimeError("browser runtime manifest does not match this build")
        packages = raw.get("packages")
        if not isinstance(packages, list) or "playwright==1.61.0" not in {
            str(item).casefold() for item in packages
        }:
            raise BrowserRuntimeError("browser runtime package inventory is invalid")

    def _profile_root(self) -> Path:
        root = self._data_root / "browser-profile" / "chengfeng-shadow"
        resolved = root.resolve()
        if resolved == self._data_root or self._data_root not in resolved.parents:
            raise BrowserRuntimeError("browser profile is outside the application data root")
        if root.is_symlink():
            raise BrowserRuntimeError("browser profile cannot be a symbolic link")
        root.mkdir(parents=True, exist_ok=True)
        return resolved

    def _staging_root(self) -> Path:
        root = self._data_root / "runtime" / "browser-worker" / "read-results"
        resolved = root.resolve()
        if resolved == self._data_root or self._data_root not in resolved.parents:
            raise BrowserRuntimeError("browser read staging is outside application data")
        if root.is_symlink():
            raise BrowserRuntimeError("browser read staging cannot be a symbolic link")
        root.mkdir(parents=True, exist_ok=True)
        return resolved

    def _exchange(self, payload: dict[str, object], *, timeout: float) -> dict[str, object]:
        process = self._process
        if process is None or not process.is_alive:
            raise BrowserRuntimeError("browser worker is not running")
        try:
            line = process.request_line(
                json.dumps(
                    payload,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                timeout_seconds=timeout,
            )
        except SupervisedLineProcessTimeout as exc:
            raise BrowserRuntimeError(
                "受控浏览器等待页面响应超时，窗口已安全关闭。请重新打开成丰登录页。",  # noqa: RUF001
                code="browser_worker_timeout",
            ) from exc
        except SupervisedLineProcessError as exc:
            self._emit_event(
                "browser_worker_unavailable",
                self._worker_state(process),
            )
            raise BrowserRuntimeError(
                "受控浏览器进程意外中断，窗口已安全关闭。请重新打开成丰登录页。",  # noqa: RUF001
                code="browser_worker_unavailable",
            ) from exc
        return self._validate_final_response(payload, line)

    def _validate_final_response(
        self,
        payload: dict[str, object],
        line: str,
    ) -> dict[str, object]:
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BrowserRuntimeError("browser worker returned invalid NDJSON") from exc
        expected_response_fields = {
            "batch_result",
            "browser_open",
            "discovery",
            "error_code",
            "ok",
            "prepare_result",
            "read_result",
            "request_id",
            "schema_version",
            "selected_browser",
        }
        if (
            not isinstance(response, dict)
            or set(response) != expected_response_fields
            or response.get("schema_version") != BROWSER_PROTOCOL_VERSION
            or response.get("request_id") != payload["request_id"]
        ):
            raise BrowserRuntimeError("browser worker rejected the command")
        command = payload.get("command")
        prepare_result = response.get("prepare_result")
        batch_result = response.get("batch_result")
        if command in {
            "prepare_automated",
            "prepare_operational_compat",
            "prepare_settlement_filter_handoff",
            "prepare_daily_from_automated",
        }:
            if response.get("ok") is True and prepare_result is None:
                raise BrowserRuntimeError(
                    "browser worker returned no settlement list probe"
                )
        elif prepare_result is not None:
            raise BrowserRuntimeError(
                "browser worker returned a probe for the wrong command"
            )
        if command == "read_operational_batch":
            if response.get("ok") is True and not isinstance(
                batch_result,
                list,
            ):
                raise BrowserRuntimeError(
                    "browser worker returned no operational batch"
                )
        elif batch_result is not None:
            raise BrowserRuntimeError(
                "browser worker returned a batch for the wrong command"
            )
        if response.get("ok") is not True:
            error_code = response.get("error_code")
            safe_discovery = _validated_error_discovery(
                response.get("discovery"),
                error_code=error_code,
            )
            self._raise_worker_error(
                error_code,
                safe_discovery=safe_discovery,
            )
        return response

    def _exchange_streaming_batch(
        self,
        payload: dict[str, object],
        *,
        timeout: float,
        progress_callback: Callable[[str, int, int], None] | None,
    ) -> dict[str, object]:
        process = self._process
        if process is None or not process.is_alive:
            raise BrowserRuntimeError("browser worker is not running")
        request_id = payload["request_id"]

        def parse_frame(line: str) -> dict[str, object]:
            try:
                frame = json.loads(line)
            except json.JSONDecodeError as exc:
                raise BrowserRuntimeError(
                    "browser worker returned invalid NDJSON"
                ) from exc
            if not isinstance(frame, dict):
                raise BrowserRuntimeError("browser worker returned an invalid frame")
            return frame

        def on_line(line: str) -> None:
            frame = parse_frame(line)
            frame_kind = frame.get("frame_kind")
            if frame_kind == "progress":
                completed = frame.get("completed")
                total = frame.get("total")
                if (
                    set(frame)
                    != {
                        "schema_version",
                        "frame_kind",
                        "request_id",
                        "phase",
                        "completed",
                        "total",
                    }
                    or frame.get("schema_version") != BROWSER_PROTOCOL_VERSION
                    or frame.get("request_id") != request_id
                    or frame.get("phase") not in {"detail", "image"}
                    or type(completed) is not int
                    or type(total) is not int
                    or not 0 <= completed <= total
                ):
                    raise BrowserRuntimeError(
                        "browser worker returned an invalid progress frame"
                    )
                if progress_callback is not None:
                    progress_callback(
                        str(frame["phase"]),
                        completed,
                        total,
                    )
                return
            if frame_kind == "abort_ack":
                if (
                    set(frame)
                    != {
                        "schema_version",
                        "frame_kind",
                        "request_id",
                        "target_request_id",
                        "accepted",
                    }
                    or frame.get("schema_version") != BROWSER_PROTOCOL_VERSION
                    or frame.get("target_request_id") != request_id
                    or type(frame.get("accepted")) is not bool
                ):
                    raise BrowserRuntimeError(
                        "browser worker returned an invalid abort acknowledgement"
                    )
                if frame["accepted"] is True:
                    self._active_batch_abort_ack.set()
                return
            if frame_kind is not None:
                raise BrowserRuntimeError("browser worker returned an unknown frame")

        def is_final(line: str) -> bool:
            frame = parse_frame(line)
            return frame.get("frame_kind") is None and frame.get("request_id") == request_id

        try:
            line = process.request_lines(
                json.dumps(
                    payload,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                timeout_seconds=timeout,
                is_final=is_final,
                on_line=on_line,
            )
        except SupervisedLineProcessTimeout as exc:
            raise BrowserRuntimeError(
                "受控浏览器等待页面响应超时，本批数据未提交。",  # noqa: RUF001
                code="browser_worker_timeout",
            ) from exc
        except SupervisedLineProcessError as exc:
            self._emit_event("browser_worker_unavailable", self._worker_state(process))
            raise BrowserRuntimeError(
                "受控浏览器进程意外中断，本批数据未提交。",  # noqa: RUF001
                code="browser_worker_unavailable",
            ) from exc
        return self._validate_final_response(payload, line)

    @staticmethod
    def _raise_worker_error(
        error_code: object,
        *,
        safe_discovery: tuple[dict[str, object], ...] = (),
    ) -> None:
        if error_code == "browser_login_entry_failed":
            raise BrowserRuntimeError(
                "成丰登录页未能打开，受控浏览器已安全关闭。请检查当前网络后重试。",  # noqa: RUF001
                code=error_code,
            )
        if error_code == "browser_initialize_failed":
            raise BrowserRuntimeError(
                "受控浏览器未能启动，未留下可继续使用的窗口。",  # noqa: RUF001
                code=error_code,
            )
        if error_code == "browser_saved_credential_missing":
            raise BrowserRuntimeError(
                "尚未保存成丰登录信息,请先在系统参数中配置,或打开登录窗口。",
                code=error_code,
            )
        if error_code in {
            "browser_saved_login_captcha_required",
            "browser_saved_login_failed",
            "browser_saved_login_structure_changed",
        }:
            raise BrowserRuntimeError(
                "后台登录未完成,请打开登录窗口后继续。",
                code=str(error_code),
            )
        if error_code in {
            "browser_read_login_required",
            "browser_session_waybill_control_unavailable",
            "browser_session_settlement_scope_control_unavailable",
            "browser_session_query_control_unavailable",
            "browser_session_trigger_failed",
            "browser_session_headers_rejected",
            "browser_session_fixed_values_rejected",
            "browser_session_fixed_values_unavailable",
            "browser_session_cache_query_rejected",
            "browser_session_cache_query_unavailable",
            "browser_session_list_body_rejected",
            "browser_session_list_body_unavailable",
            "browser_session_request_not_constructed",
            "browser_session_native_probe_not_constructed",
            "browser_session_native_probe_failed",
            "browser_session_list_path_variant",
            "browser_session_query_present",
            "browser_session_other_api_constructed",
            "browser_session_non_api_constructed",
            "browser_session_resource_mismatch",
            "browser_session_method_mismatch",
            "browser_session_origin_mismatch",
            "browser_session_url_invalid",
            "browser_connection_mode_change_rejected",
            "browser_operational_query_not_completed",
            "browser_operational_cache_refresh_failed",
            "browser_session_automation_unfreeze_failed",
        }:
            raise BrowserRuntimeError(
                "成丰登录状态已失效，请重新打开登录窗口。",  # noqa: RUF001
                code=str(error_code),
            )
        if error_code in {
            "browser_settlement_filter_handoff_failed",
            "browser_settlement_filter_values_invalid",
        }:
            raise BrowserRuntimeError(
                "成丰批量筛选未完成, 平台没有执行结算操作。",
                code=str(error_code),
            )
        if error_code in {
            "browser_read_network_failed",
            "browser_read_http_failed",
            "browser_session_native_probe_network_failed",
            "browser_session_native_probe_http_failed",
            "browser_operational_query_network_failed",
            "browser_operational_query_http_failed",
            "browser_read_rate_limited",
            "browser_read_server_transient",
        }:
            raise BrowserRuntimeError(
                "成丰只读请求暂时失败，未保存不完整结果。",  # noqa: RUF001
                code=str(error_code),
            )
        if error_code in {
            "browser_daily_response_contract_changed",
            "browser_read_contract_changed",
            "browser_image_contract_changed",
            "browser_read_size_invalid",
            "browser_session_list_body_mismatch",
            "browser_session_list_body_field_set_mismatch",
            "browser_session_list_body_fields_added",
            "browser_session_list_body_fields_removed",
            "browser_session_list_body_fields_changed",
            "browser_session_list_body_filter_mismatch",
            "browser_session_list_body_hash_mismatch",
            "browser_session_native_probe_contract_changed",
            "browser_session_native_probe_page_number_mismatch",
            "browser_session_native_probe_page_number_ahead_one",
            "browser_session_native_probe_page_number_is_total_pages",
            "browser_session_native_probe_page_number_is_total_count",
            "browser_session_native_probe_page_number_is_page_size",
            "browser_session_native_probe_page_number_ahead_many",
            "browser_session_native_probe_page_number_behind_many",
            "browser_session_native_probe_list_exceeds_requested_page_size",
            "browser_session_native_probe_list_exceeds_response_page_size",
            "browser_session_native_probe_total_below_list_length",
            "browser_session_native_probe_page_size_mismatch",
            "browser_operational_query_contract_changed",
            "browser_operational_query_body_changed",
        }:
            raise BrowserRuntimeError(
                "成丰返回内容与已批准的只读合同不一致。",
                code=str(error_code),
                safe_discovery=safe_discovery,
            )
        if error_code == "browser_context_closed":
            raise BrowserRuntimeError(
                "受控浏览器已经关闭，本次只读请求未执行。",  # noqa: RUF001
                code=error_code,
            )
        if error_code == "browser_read_cancelled":
            raise BrowserRuntimeError(
                "本次读取已取消，未完成批次没有保存。",  # noqa: RUF001
                code=error_code,
            )
        raise BrowserRuntimeError(
            "独立浏览器运行环境拒绝了本次操作。",
            code=(
                str(error_code)
                if isinstance(error_code, str)
                else "browser_worker_rejected"
            ),
        )

    def start_human_login(self) -> str:
        with self._lock:
            running = self.running
            if running and self._headless:
                self._terminate_owned()
                running = False
            if running:
                if self._selected_browser is None:
                    raise BrowserRuntimeError("browser runtime state is incomplete")
                try:
                    response = self._exchange(
                        {
                            "schema_version": BROWSER_PROTOCOL_VERSION,
                            "command": "resume_human_session",
                            "request_id": uuid4().hex,
                        },
                        timeout=HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS,
                    )
                except BrowserRuntimeError:
                    self._terminate_owned()
                    raise
                if (
                    response.get("browser_open") is not True
                    or response.get("selected_browser")
                    != self._selected_browser
                    or response.get("discovery") is not None
                    or response.get("prepare_result") is not None
                    or response.get("read_result") is not None
                ):
                    self._terminate_owned()
                    raise BrowserRuntimeError(
                        "controlled browser could not resume human control",
                        code="browser_human_session_resume_failed",
                    )
                return self._selected_browser
            self._validate_installation()
            self._process = SupervisedLineProcess(
                worker_id="chengfeng-browser-worker",
                argv=[
                    os.fspath(self._python),
                    "-I",
                    "-B",
                    "-m",
                    "dahe_browser_worker",
                ],
                runtime_dir=self._data_root / "runtime" / "browser-worker",
                max_request_bytes=16 * 1024,
                max_response_bytes=512 * 1024,
                below_normal_priority=self._below_normal_priority,
                output_sink=self._output_sink,
            )
            try:
                response = self._exchange(
                    {
                        "schema_version": BROWSER_PROTOCOL_VERSION,
                        "command": "initialize",
                        "request_id": uuid4().hex,
                        "browser": self._browser,
                        "profile_root": os.fspath(self._profile_root()),
                        "staging_root": os.fspath(self._staging_root()),
                    },
                    timeout=HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS,
                )
                selected = response.get("selected_browser")
                if (
                    selected not in {"chromium", "msedge"}
                    or response.get("browser_open") is not True
                    or response.get("read_result") is not None
                ):
                    raise BrowserRuntimeError("worker selected an invalid browser")
                self._selected_browser = str(selected)
                self._headless = False
                self._capability_generation_id = uuid4().hex
                return self._selected_browser
            except BaseException:
                self._terminate_owned()
                raise

    def start_operational(self) -> str:
        """Start one owned visible context and consume credentials in-worker."""

        with self._lock:
            running = self.running
            if running:
                if self._selected_browser is None:
                    raise BrowserRuntimeError(
                        "browser runtime state is incomplete"
                    )
                return self._selected_browser
            self._validate_installation()
            self._process = SupervisedLineProcess(
                worker_id="chengfeng-browser-worker",
                argv=[
                    os.fspath(self._python),
                    "-I",
                    "-B",
                    "-m",
                    "dahe_browser_worker",
                ],
                runtime_dir=(
                    self._data_root / "runtime" / "browser-worker"
                ),
                max_request_bytes=16 * 1024,
                max_response_bytes=512 * 1024,
                below_normal_priority=self._below_normal_priority,
                output_sink=self._output_sink,
            )
            try:
                response = self._exchange(
                    {
                        "schema_version": BROWSER_PROTOCOL_VERSION,
                        "command": "initialize",
                        "request_id": uuid4().hex,
                        "browser": self._browser,
                        "profile_root": os.fspath(self._profile_root()),
                        "staging_root": os.fspath(self._staging_root()),
                    },
                    timeout=HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS,
                )
                selected = response.get("selected_browser")
                if (
                    selected not in {"chromium", "msedge"}
                    or response.get("browser_open") is not True
                    or response.get("read_result") is not None
                ):
                    raise BrowserRuntimeError(
                        "worker selected an invalid browser"
                    )
                self._selected_browser = str(selected)
                self._headless = False
                self._capability_generation_id = uuid4().hex
                return self._selected_browser
            except BaseException:
                self._terminate_owned()
                raise

    def prepare_settlement_filter_handoff(
        self,
        waybill_numbers: tuple[str, ...],
    ) -> dict[str, int]:
        """Open the official read-only batch filter in a visible owned window."""

        if (
            not waybill_numbers
            or len(waybill_numbers) > 2000
            or len(set(waybill_numbers)) != len(waybill_numbers)
            or any(
                re.fullmatch(r"[A-Za-z0-9_-]{1,40}", value) is None
                for value in waybill_numbers
            )
        ):
            raise ValueError("waybill numbers are invalid")
        with self._lock:
            self.start_human_login()
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "prepare_settlement_filter_handoff",
                    "request_id": uuid4().hex,
                    "waybill_numbers": list(waybill_numbers),
                },
                timeout=HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS,
            )
            prepare_result = response.get("prepare_result")
            if (
                response.get("browser_open") is not True
                or response.get("discovery") is not None
                or response.get("read_result") is not None
                or response.get("batch_result") is not None
                or not isinstance(prepare_result, dict)
            ):
                raise BrowserRuntimeError(
                    "成丰批量筛选窗口未能安全建立。",
                    code="browser_settlement_filter_handoff_failed",
                )
            expected = {
                "schema_version",
                "requested_count",
                "matched_count",
                "missing_count",
            }
            if set(prepare_result) != expected:
                raise BrowserRuntimeError(
                    "成丰批量筛选结果无法核对。",
                    code="browser_settlement_filter_result_invalid",
                )
            requested_count = prepare_result.get("requested_count")
            matched_count = prepare_result.get("matched_count")
            missing_count = prepare_result.get("missing_count")
            if (
                prepare_result.get("schema_version") != 1
                or requested_count != len(waybill_numbers)
                or type(matched_count) is not int
                or type(missing_count) is not int
                or matched_count + missing_count != requested_count
            ):
                raise BrowserRuntimeError(
                    "成丰批量筛选结果无法核对。",
                    code="browser_settlement_filter_result_invalid",
                )
            return {
                "requested_count": requested_count,
                "matched_count": matched_count,
                "missing_count": missing_count,
            }

    def start_discovery_capture(self) -> None:
        with self._lock:
            if not self.running or self._selected_browser is None:
                raise BrowserRuntimeError("browser must be running before discovery capture")
            if self._discovery_capturing:
                return
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "capture_start",
                    "request_id": uuid4().hex,
                },
                timeout=10,
            )
            if response.get("discovery") is not None or response.get("read_result") is not None:
                raise BrowserRuntimeError("capture start returned unexpected evidence")
            if response.get("browser_open") is not True:
                raise BrowserRuntimeError("browser closed while capture was starting")
            self._discovery_capturing = True

    def freeze_human_session(self) -> None:
        """Block all page traffic before durable human control is returned."""

        with self._lock:
            if self._process is None or not self._process.is_alive:
                self._emit_event(
                    "browser_batch_worker_missing",
                    self._worker_state(self._process),
                )
                raise BrowserRuntimeError(
                    "controlled browser is not running",
                    code="browser_context_closed",
                )
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "freeze_human_session",
                    "request_id": uuid4().hex,
                },
                timeout=FREEZE_HUMAN_SESSION_WORKER_TIMEOUT_SECONDS,
            )
            if (
                response.get("browser_open") is not True
                or response.get("discovery") is not None
                or response.get("read_result") is not None
                or response.get("prepare_result") is not None
            ):
                self._terminate_owned()
                raise BrowserRuntimeError(
                    "browser session could not be frozen safely",
                    code="browser_session_freeze_failed",
                )

    def probe_settlement_views(self) -> SettlementViewProbe:
        """Probe both official pending-settlement tabs without business values."""

        with self._lock:
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "controlled browser is not running",
                    code="browser_context_closed",
                )
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "probe_settlement_views",
                    "request_id": uuid4().hex,
                },
                timeout=PREPARE_AUTOMATED_WORKER_TIMEOUT_SECONDS,
            )
            discovery = response.get("discovery")
            if (
                response.get("browser_open") is not True
                or response.get("prepare_result") is not None
                or response.get("read_result") is not None
                or not isinstance(discovery, list)
                or len(discovery) != 1
            ):
                raise BrowserRuntimeError(
                    "browser worker returned no settlement view probe"
                )
            try:
                return SettlementViewProbe.from_worker_payload(discovery[0])
            except (TypeError, ValueError) as exc:
                raise BrowserRuntimeError(
                    "browser worker returned an unsafe settlement view probe"
                ) from exc

    def stop_discovery_capture(self) -> list[dict[str, object]]:
        with self._lock:
            if not self.running or not self._discovery_capturing:
                raise BrowserRuntimeError("discovery capture is not active")
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "capture_stop",
                    "request_id": uuid4().hex,
                },
                timeout=20,
            )
            observations = response.get("discovery")
            if (
                not isinstance(observations, list)
                or len(observations) > 200
                or any(not isinstance(item, dict) for item in observations)
                or response.get("browser_open") is not True
                or response.get("read_result") is not None
            ):
                raise BrowserRuntimeError("browser worker returned unsafe discovery evidence")
            self._discovery_capturing = False
            return [dict(item) for item in observations]

    def read(
        self,
        request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
    ) -> BrowserReadPayload:
        with self._lock:
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "受控浏览器没有运行，本次只读请求未执行。",  # noqa: RUF001
                    code="browser_context_closed",
                )
            raw_request = request.request
            is_image = isinstance(request, LiveAuthorizedImageRequest)
            if is_image:
                if raw_request.operation != "download_ticket_image":
                    raise BrowserRuntimeError("authorized image request is invalid")
                command_name = "read_image"
                timeout = 70
            else:
                if raw_request.operation not in {
                    "list_waybills",
                    "get_waybill_detail",
                }:
                    raise BrowserRuntimeError("authorized JSON request is invalid")
                expected_location = (
                    "json"
                    if raw_request.operation == "list_waybills"
                    else "form"
                )
                if raw_request.parameters_location != expected_location:
                    raise BrowserRuntimeError(
                        "authorized JSON request encoding is invalid"
                    )
                command_name = "read_json"
                timeout = 40
            request_id = f"read-{uuid4().hex}"
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": command_name,
                    "request_id": request_id,
                    "operation": raw_request.operation,
                    "method": raw_request.method,
                    "url": raw_request.url,
                    "parameters": {
                        key: list(value) if isinstance(value, tuple) else value
                        for key, value in raw_request.parameters.items()
                    },
                },
                timeout=timeout,
            )
            result = response.get("read_result")
            if (
                response.get("browser_open") is not True
                or response.get("discovery") is not None
                or not isinstance(result, dict)
            ):
                raise BrowserRuntimeError("browser worker returned no read result")
            return self._verify_staged_read(
                request_id=request_id,
                result=result,
                image=is_image,
            )

    def read_operational_batch(
        self,
        requests: tuple[tuple[str, LiveAuthorizedRequest], ...],
        *,
        detail_concurrency: int,
        image_concurrency: int,
        reuse_candidates: tuple[WaybillReuseCandidate, ...] = (),
        active_job_id: str | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> tuple[BrowserOperationalBatchItem, ...]:
        """Execute one sanitized frozen-size batch inside the owned worker."""

        if (
            not requests
            or len(requests) > 100
            or type(detail_concurrency) is not int
            or not 1 <= detail_concurrency <= 4
            or type(image_concurrency) is not int
            or not 1 <= image_concurrency <= 6
        ):
            raise BrowserRuntimeError(
                "operational batch request limits are invalid"
            )
        reuse_by_id = {
            candidate.platform_waybill_id: candidate
            for candidate in reuse_candidates
        }
        if (
            len(reuse_by_id) != len(reuse_candidates)
            or not set(reuse_by_id).issubset(
                {identity for identity, _request in requests}
            )
        ):
            raise BrowserRuntimeError(
                "operational reuse candidates are invalid"
            )
        with self._lock:
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "受控浏览器没有运行，本批只读请求未执行。",  # noqa: RUF001
                    code="browser_context_closed",
                )
            details: list[dict[str, object]] = []
            identities: set[str] = set()
            for platform_waybill_id, request in requests:
                raw = request.request
                if (
                    not platform_waybill_id
                    or platform_waybill_id in identities
                    or raw.operation != "get_waybill_detail"
                    or raw.method != "POST"
                    or raw.parameters_location != "form"
                    or raw.parameters != {"id": platform_waybill_id}
                ):
                    raise BrowserRuntimeError(
                        "operational batch detail request is invalid"
                    )
                identities.add(platform_waybill_id)
                details.append(
                    {
                        "platform_waybill_id": platform_waybill_id,
                        "url": raw.url,
                        "parameters": dict(raw.parameters),
                        "reuse": (
                            {
                                "source_revision_sha256": (
                                    reuse_by_id[
                                        platform_waybill_id
                                    ].source_revision_sha256
                                ),
                                "images": [
                                    {
                                        "slot": image.slot,
                                        "sha256": image.sha256,
                                        "media_type": image.media_type,
                                        "validator_sha256": (
                                            image.validator_sha256
                                        ),
                                    }
                                    for image in reuse_by_id[
                                        platform_waybill_id
                                    ].images
                                ],
                            }
                            if platform_waybill_id in reuse_by_id
                            else None
                        ),
                    }
                )
            request_id = f"batch-{uuid4().hex}"
            if active_job_id is not None and not active_job_id.strip():
                raise BrowserRuntimeError("active job id is invalid")
            self._active_batch_request_id = request_id
            self._active_batch_job_id = active_job_id
            self._active_batch_abort_ack.clear()
            self._active_batch_finished.clear()
            try:
                response = self._exchange_streaming_batch(
                    {
                        "schema_version": BROWSER_PROTOCOL_VERSION,
                        "command": "read_operational_batch",
                        "request_id": request_id,
                        "details": details,
                        "detail_concurrency": detail_concurrency,
                        "image_concurrency": image_concurrency,
                    },
                    timeout=OPERATIONAL_BATCH_WORKER_TIMEOUT_SECONDS,
                    progress_callback=progress_callback,
                )
            finally:
                self._active_batch_finished.set()
                self._active_batch_request_id = None
                self._active_batch_job_id = None
            raw_batch = response.get("batch_result")
            if (
                response.get("discovery") is not None
                or response.get("prepare_result") is not None
                or response.get("read_result") is not None
                or not isinstance(raw_batch, list)
                or len(raw_batch) != len(requests)
            ):
                raise BrowserRuntimeError(
                    "browser worker returned no operational batch"
                )
            results: list[BrowserOperationalBatchItem] = []
            for expected_id, raw_item in zip(
                (identity for identity, _request in requests),
                raw_batch,
                strict=True,
            ):
                if (
                    not isinstance(raw_item, dict)
                    or set(raw_item) != {
                        "platform_waybill_id",
                        "source_revision_sha256",
                        "detail",
                        "images",
                    }
                    or raw_item["platform_waybill_id"] != expected_id
                    or not isinstance(
                        raw_item["source_revision_sha256"], str
                    )
                    or _SHA256.fullmatch(
                        raw_item["source_revision_sha256"]
                    ) is None
                    or not isinstance(raw_item["detail"], dict)
                    or not isinstance(raw_item["images"], list)
                ):
                    raise BrowserRuntimeError(
                        "browser operational batch metadata is invalid"
                    )
                detail_metadata = raw_item["detail"]
                detail_relative = detail_metadata.get("relative_path")
                if not isinstance(detail_relative, str):
                    raise BrowserRuntimeError(
                        "browser operational batch path is invalid"
                    )
                detail_request_id = PurePosixPath(
                    detail_relative
                ).parts[0]
                detail = self._verify_staged_read(
                    request_id=detail_request_id,
                    result=detail_metadata,
                    image=False,
                )
                images: list[tuple[str, BrowserReadPayload]] = []
                slots: set[str] = set()
                for raw_image in raw_item["images"]:
                    if (
                        not isinstance(raw_image, dict)
                        or set(raw_image)
                        not in (
                            {"slot", "payload", "validator_sha256"},
                            {"slot", "reused"},
                        )
                        or raw_image["slot"]
                        not in {"loading", "unloading"}
                        or raw_image["slot"] in slots
                    ):
                        raise BrowserRuntimeError(
                            "browser operational batch image is invalid"
                        )
                    slot = str(raw_image["slot"])
                    slots.add(slot)
                    if "reused" in raw_image:
                        reused = raw_image["reused"]
                        if (
                            not isinstance(reused, dict)
                            or set(reused) != {
                                "sha256",
                                "media_type",
                                "validator_sha256",
                            }
                            or not isinstance(reused["sha256"], str)
                            or _SHA256.fullmatch(reused["sha256"])
                            is None
                            or reused["media_type"]
                            not in _READ_MEDIA_TYPES - {"application/json"}
                            or not isinstance(
                                reused["validator_sha256"], str
                            )
                            or _SHA256.fullmatch(
                                reused["validator_sha256"]
                            )
                            is None
                        ):
                            raise BrowserRuntimeError(
                                "browser operational reuse result is invalid"
                            )
                        images.append(
                            (
                                slot,
                                BrowserReadPayload(
                                    content=b"",
                                    sha256=reused["sha256"],
                                    media_type=reused["media_type"],
                                    byte_size=0,
                                    status_code=304,
                                    validator_sha256=(
                                        reused["validator_sha256"]
                                    ),
                                    reused_from_cache=True,
                                ),
                            )
                        )
                        continue
                    payload_metadata = raw_image.get("payload")
                    validator_sha256 = raw_image.get(
                        "validator_sha256"
                    )
                    if (
                        not isinstance(payload_metadata, dict)
                        or not isinstance(validator_sha256, (str, type(None)))
                        or (
                            isinstance(validator_sha256, str)
                            and _SHA256.fullmatch(validator_sha256) is None
                        )
                    ):
                        raise BrowserRuntimeError(
                            "browser operational batch image is invalid"
                        )
                    relative = payload_metadata.get("relative_path")
                    if not isinstance(relative, str):
                        raise BrowserRuntimeError(
                            "browser operational batch path is invalid"
                        )
                    image_request_id = PurePosixPath(relative).parts[0]
                    images.append(
                        (
                            slot,
                            replace(
                                self._verify_staged_read(
                                    request_id=image_request_id,
                                    result=payload_metadata,
                                    image=True,
                                ),
                                validator_sha256=validator_sha256,
                            ),
                        )
                    )
                results.append(
                    BrowserOperationalBatchItem(
                        platform_waybill_id=expected_id,
                        source_revision_sha256=raw_item[
                            "source_revision_sha256"
                        ],
                        detail=detail,
                        images=tuple(images),
                    )
                )
            return tuple(results)

    def abort_active_operation(self, job_id: str) -> bool:
        """Abort only the active owned browser batch for ``job_id``."""

        if not job_id.strip():
            raise ValueError("job_id cannot be empty")
        process = self._process
        request_id = self._active_batch_request_id
        if (
            process is None
            or not process.is_alive
            or request_id is None
            or self._active_batch_job_id != job_id
        ):
            return False
        abort_id = f"abort-{uuid4().hex}"
        try:
            process.send_line(
                json.dumps(
                    {
                        "schema_version": BROWSER_PROTOCOL_VERSION,
                        "command": "abort",
                        "request_id": abort_id,
                        "target_request_id": request_id,
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        except SupervisedLineProcessError:
            if process.is_alive:
                process.terminate()
            return True
        if self._active_batch_finished.wait(timeout=2):
            return True
        process.terminate()
        self._active_read_scope = None
        self._operational_probe = None
        self._daily_preparation = None
        # The process is owned by this runtime. Restore the visible platform
        # window after the hard abort so people are not left without access.
        with contextlib.suppress(BrowserRuntimeError):
            self.start_operational()
        return True

    def prepare_automated(
        self,
        *,
        scope: str = "current",
    ) -> SettlementListProbe:
        if scope not in {"current", "settled_history"}:
            raise BrowserRuntimeError(
                "settlement scope is invalid",
                code="browser_settlement_scope_invalid",
            )
        with self._lock:
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "受控浏览器没有运行，无法进入自动只读模式。",  # noqa: RUF001
                    code="browser_context_closed",
                )
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "prepare_automated",
                    "request_id": uuid4().hex,
                    "scope": scope,
                },
                timeout=PREPARE_AUTOMATED_WORKER_TIMEOUT_SECONDS,
            )
            if (
                response.get("browser_open") is not True
                or response.get("discovery") is not None
                or response.get("read_result") is not None
            ):
                raise BrowserRuntimeError("browser automated preparation failed")
            try:
                probe = SettlementListProbe.from_worker_payload(
                    response.get("prepare_result")
                )
            except (TypeError, ValueError) as exc:
                raise BrowserRuntimeError(
                    "browser worker returned an unsafe settlement list probe"
                ) from exc
            self._active_read_scope = "strict_settlement"
            self._operational_probe = None
            self._daily_preparation = None
            return probe

    def prepare_operational_compat(self) -> SettlementListProbe:
        """Prepare the page-authoritative current settlement read."""

        with self._lock:
            if self._process is None or not self._process.is_alive:
                self._active_read_scope = None
                self._operational_probe = None
                self._daily_preparation = None
                raise BrowserRuntimeError(
                    "controlled browser worker is unavailable",
                    code="browser_worker_unavailable",
                )
            if (
                self._active_read_scope == "settlement"
                and self._operational_probe is not None
            ):
                return self._operational_probe
            if self._active_read_scope is not None:
                self.park_operational_session()
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "controlled browser is not running",
                    code="browser_context_closed",
                )
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "prepare_operational_compat",
                    "request_id": uuid4().hex,
                },
                timeout=PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS,
            )
            if (
                response.get("browser_open") is not True
                or response.get("discovery") is not None
                or response.get("read_result") is not None
            ):
                raise BrowserRuntimeError(
                    "browser operational preparation failed"
                )
            try:
                probe = SettlementListProbe.from_worker_payload(
                    response.get("prepare_result"),
                    require_query_trace=True,
                )
            except (TypeError, ValueError) as exc:
                raise BrowserRuntimeError(
                    "browser worker returned an unsafe settlement list probe"
                ) from exc
            assert probe.query_trace is not None
            self._emit_event(
                "browser_read_freshness_verified",
                (
                    "scope=settlement "
                    f"cache_refresh_count={probe.query_trace.cache_refresh_count} "
                    f"query_attempt_count={probe.query_trace.query_attempt_count} "
                    f"page_count={probe.query_trace.page_count} "
                    "route=/billablewaybill"
                ),
            )
            self._active_read_scope = "settlement"
            self._operational_probe = probe
            self._daily_preparation = None
            return probe

    def handoff_operational_session(self) -> None:
        """Return the fixed platform entry after erasing read authority."""

        with self._lock:
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "controlled browser is not running",
                    code="browser_context_closed",
                )
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "handoff_operational_session",
                    "request_id": uuid4().hex,
                },
                timeout=HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS,
            )
            if (
                response.get("browser_open") is not True
                or response.get("selected_browser")
                != self._selected_browser
                or response.get("discovery") is not None
                or response.get("prepare_result") is not None
                or response.get("read_result") is not None
            ):
                self._terminate_owned()
                raise BrowserRuntimeError(
                    "controlled browser could not enter human handoff",
                    code="browser_operational_handoff_failed",
                )
            self._active_read_scope = None
            self._operational_probe = None
            self._daily_preparation = None

    def park_operational_session(self) -> None:
        """Clear one job's private authority without closing its profile."""

        with self._lock:
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "controlled browser is not running",
                    code="browser_context_closed",
                )
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "park_operational_session",
                    "request_id": uuid4().hex,
                },
                timeout=HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS,
            )
            if (
                response.get("browser_open") is not True
                or response.get("selected_browser") != self._selected_browser
                or response.get("discovery") is not None
                or response.get("prepare_result") is not None
                or response.get("read_result") is not None
            ):
                self._terminate_owned()
                raise BrowserRuntimeError(
                    "controlled browser could not park safely",
                    code="browser_operational_park_failed",
                )
            self._active_read_scope = None
            self._operational_probe = None
            self._daily_preparation = None

    def prepare_daily(self) -> dict[str, object]:
        """Prepare the fixed daily page and return one sanitized request shape."""

        return self._prepare_daily_command("prepare_daily")

    def prepare_daily_from_automated(self) -> dict[str, object]:
        """Switch an automated session to the fixed daily read without navigation."""

        return self._prepare_daily_command(
            "prepare_daily_from_automated"
        )

    def prepare_operational_daily(self) -> dict[str, object]:
        """Reuse or rebuild the page-owned operational daily authority."""

        with self._lock:
            if (
                self._active_read_scope == "daily"
                and self._daily_preparation is not None
            ):
                return dict(self._daily_preparation)
            if self._active_read_scope is not None:
                self.park_operational_session()
            self.prepare_operational_compat()
            return self.prepare_daily_from_automated()

    def _prepare_daily_command(
        self,
        command: str,
    ) -> dict[str, object]:
        with self._lock:
            if (
                command == "prepare_daily"
                and self._active_read_scope == "daily"
                and self._daily_preparation is not None
            ):
                return dict(self._daily_preparation)
            if command == "prepare_daily" and self._active_read_scope is not None:
                self.park_operational_session()
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "controlled browser is not running for daily preparation",
                    code="browser_context_closed",
                )
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": command,
                    "request_id": uuid4().hex,
                },
                timeout=PREPARE_DAILY_WORKER_TIMEOUT_SECONDS,
            )
            observations = response.get("discovery")
            prepare_result = response.get("prepare_result")
            if (
                response.get("browser_open") is not True
                or response.get("read_result") is not None
                or (command == "prepare_daily" and prepare_result is not None)
                or (
                    command == "prepare_daily_from_automated"
                    and prepare_result is None
                )
                or not isinstance(observations, list)
                or len(observations) != 1
            ):
                raise BrowserRuntimeError(
                    "browser worker returned no safe daily request structure"
                )
            try:
                observation = DiscoveryObservation.model_validate(
                    observations[0]
                )
            except ValidationError as exc:
                raise BrowserRuntimeError(
                    "browser worker returned an unsafe daily request structure"
                ) from exc
            freshness: DailyPreparationEvidence | None = None
            if command == "prepare_daily_from_automated":
                try:
                    freshness = DailyPreparationEvidence.from_worker_payload(
                        prepare_result
                    )
                except ValueError as exc:
                    raise BrowserRuntimeError(
                        "browser worker returned unsafe daily freshness evidence"
                    ) from exc
            if (
                observation.resource_kind != "json_api"
                or observation.origin != DAILY_ORIGIN
                or observation.path != DAILY_LIST_PATH
                or observation.method != "POST"
                or observation.path_sha256 is not None
                or observation.content_kind != "json"
                or observation.response_status != 200
            ):
                raise BrowserRuntimeError(
                    "browser worker returned a different daily request structure"
                )
            prepared = observation.model_dump(mode="json")
            if freshness is not None:
                self._emit_event(
                    "browser_read_freshness_verified",
                    (
                        "scope=daily "
                        f"cache_refresh_count={freshness.cache_refresh_count} "
                        f"page_count={freshness.page_count} "
                        f"route={freshness.route}"
                    ),
                )
            self._active_read_scope = "daily"
            self._operational_probe = None
            self._daily_preparation = dict(prepared)
            return prepared

    def read_daily(
        self,
        request: DailyAuthorizedRequest,
    ) -> BrowserReadPayload:
        """Execute one exact daily-list read through the isolated worker."""

        with self._lock:
            if self._process is None or not self._process.is_alive:
                raise BrowserRuntimeError(
                    "controlled browser is not running for a daily read",
                    code="browser_context_closed",
                )
            if (
                request.operation != DAILY_LIST_OPERATION
                or request.method != "POST"
                or request.url != f"{DAILY_ORIGIN}{DAILY_LIST_PATH}"
                or request.parameters_location != "json"
            ):
                raise BrowserRuntimeError("authorized daily request is invalid")
            request_id = f"daily-{uuid4().hex}"
            response = self._exchange(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "read_daily_json",
                    "request_id": request_id,
                    "operation": request.operation,
                    "method": request.method,
                    "url": request.url,
                    "parameters": {
                        key: list(value) if isinstance(value, tuple) else value
                        for key, value in request.parameters.items()
                    },
                },
                timeout=40,
            )
            result = response.get("read_result")
            if (
                response.get("browser_open") is not True
                or response.get("discovery") is not None
                or response.get("prepare_result") is not None
                or not isinstance(result, dict)
            ):
                raise BrowserRuntimeError("browser worker returned no daily read result")
            return self._verify_staged_read(
                request_id=request_id,
                result=result,
                image=False,
            )

    def _verify_staged_read(
        self,
        *,
        request_id: str,
        result: dict[object, object],
        image: bool,
    ) -> BrowserReadPayload:
        if set(result) != _READ_RESULT_FIELDS:
            raise BrowserRuntimeError("browser read result fields are invalid")
        relative_value = result.get("relative_path")
        digest = result.get("sha256")
        byte_size = result.get("byte_size")
        media_type = result.get("media_type")
        status_code = result.get("status_code")
        if (
            not isinstance(relative_value, str)
            or "\\" in relative_value
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or type(byte_size) is not int
            or byte_size <= 0
            or type(status_code) is not int
            or status_code != 200
            or not isinstance(media_type, str)
            or media_type not in _READ_MEDIA_TYPES
            or (image and not media_type.startswith("image/"))
            or (not image and media_type != "application/json")
        ):
            raise BrowserRuntimeError("browser read result metadata is invalid")
        relative = PurePosixPath(relative_value)
        if (
            relative.is_absolute()
            or len(relative.parts) != 2
            or relative.parts[0] != request_id
            or not relative.parts[1].startswith("payload.")
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise BrowserRuntimeError("browser read result path is invalid")
        staging_root = self._staging_root()
        target = staging_root.joinpath(*relative.parts)
        resolved = target.resolve()
        if (
            staging_root not in resolved.parents
            or target.is_symlink()
            or target.parent.is_symlink()
            or not target.is_file()
        ):
            raise BrowserRuntimeError("browser read payload path is unsafe")
        maximum = 25 * 1024 * 1024 if image else 2 * 1024 * 1024
        try:
            content = target.read_bytes()
            if (
                len(content) != byte_size
                or byte_size > maximum
                or hashlib.sha256(content).hexdigest() != digest
            ):
                raise BrowserRuntimeError("browser read payload integrity failed")
            return BrowserReadPayload(
                content=content,
                sha256=digest,
                media_type=media_type,
                byte_size=byte_size,
                status_code=status_code,
            )
        finally:
            try:
                target.unlink(missing_ok=True)
                target.parent.rmdir()
            except OSError as exc:
                raise BrowserRuntimeError(
                    "browser read payload cleanup failed",
                    code="browser_read_staging_failed",
                ) from exc

    def _terminate_owned(self) -> None:
        process = self._process
        self._emit_event(
            "browser_runtime_terminate_owned",
            (
                f"scope={self._active_read_scope or 'none'} "
                f"headless={str(self._headless).lower()} "
                f"{self._worker_state(process)}"
            ),
        )
        self._process = None
        self._selected_browser = None
        self._headless = False
        self._active_read_scope = None
        self._operational_probe = None
        self._daily_preparation = None
        self._discovery_capturing = False
        self._capability_generation_id = None
        if process is None:
            return
        with contextlib.suppress(SupervisedLineProcessError):
            process.close()

    def close(self) -> None:
        with self._lock:
            if not self.running:
                self._terminate_owned()
                return
            try:
                self._exchange(
                    {
                        "schema_version": BROWSER_PROTOCOL_VERSION,
                        "command": "close",
                        "request_id": uuid4().hex,
                    },
                    timeout=10,
                )
            except BrowserRuntimeError:
                self._terminate_owned()
            finally:
                if self._process is not None:
                    self._process.close()
                self._process = None
                self._selected_browser = None
                self._headless = False
                self._active_read_scope = None
                self._operational_probe = None
                self._daily_preparation = None
