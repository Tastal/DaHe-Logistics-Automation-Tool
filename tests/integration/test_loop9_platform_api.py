from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Protocol, cast
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from dahe import __version__
from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntime,
    BrowserRuntimeError,
    BrowserRuntimeLifecycle,
    SettlementListProbe,
    SettlementViewProbe,
)
from dahe.adapters.chengfeng.contract_freezer import DETAIL_PATH, LIST_PATH
from dahe.adapters.chengfeng.daily_contract_freezer import (
    freeze_daily_read_contract,
)
from dahe.adapters.chengfeng.daily_contract_selection import (
    DailyContractSelectionError,
    load_selected_daily_read_contract,
    select_daily_read_contract,
)
from dahe.adapters.chengfeng.discovery import DiscoveryEvidenceStore
from dahe.adapters.chengfeng.live_contract_selection import (
    select_live_read_contract,
)
from dahe.adapters.chengfeng.live_contract_validation import (
    LiveContractValidationError,
    LiveContractValidationResult,
)
from dahe.adapters.chengfeng.live_manifest import LiveReadContractManifest
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditError,
)
from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationAuthority,
)
from dahe.api import platform as platform_api
from dahe.api.app import create_app
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowGrant,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.application.daily.capture import DailyCaptureRequest
from dahe.domain.daily.calendar import SHANGHAI
from dahe.jobs.daily_execution import (
    AsyncDailyExecutionBackend,
    DailyStageExecution,
    DailyStageWork,
)
from dahe.jobs.settlement_capture_execution import (
    AsyncSettlementCaptureExecutionBackend,
    SettlementCaptureStageExecution,
    SettlementCaptureStageWork,
)
from dahe.ports.chengfeng import BrowserCommandAuthority

PROJECT_ROOT = Path(__file__).parents[2]
ORIGIN = "http://127.0.0.1:8877"
BUILD_SHA256 = hashlib.sha256(b"loop9-api-build").hexdigest()


def _daily_observation() -> dict[str, object]:
    return {
        "method": "POST",
        "origin": "https://pc.chengfengkuaiyun.com",
        "path": "/api/hz/orderItem/queryOrderItemListPC",
        "path_sha256": None,
        "query_keys": [],
        "request_fields": [
            {"path": "$.carNumber", "type": "string"},
            {"path": "$.filterParamList", "type": "empty_array"},
            {"path": "$.loadEndTime", "type": "string"},
            {"path": "$.loadStartTime", "type": "string"},
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.pageSize", "type": "integer"},
            {"path": "$.receivePlace", "type": "string"},
            {"path": "$.remarks", "type": "null"},
        ],
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [
            {"path": "$.data.list[].carNumber", "type": "string"},
            {"path": "$.data.list[].id", "type": "string"},
            {"path": "$.data.list[].sn", "type": "string"},
            {"path": "$.data.list[].loadPunchDate", "type": "string"},
            {"path": "$.data.total", "type": "integer"},
        ],
    }


class FakeBrowserRuntime:
    def __init__(
        self,
        *,
        available: bool = True,
        prepare_error_code: str | None = None,
    ) -> None:
        self._available = available
        self._prepare_error_code = prepare_error_code
        self._running = False
        self._selected_browser: str | None = None
        self._discovery_capturing = False
        self.discovery_start_count = 0
        self.freeze_count = 0
        self.frozen = False
        self.prepare_automated_count = 0
        self.prepare_automated_scopes: list[str] = []
        self.prepare_daily_count = 0
        self.settlement_view_probe_count = 0
        self.operational_handoff_count = 0
        self.human_login_start_count = 0
        self.operational_start_count = 0

    @property
    def available(self) -> bool:
        return self._available

    @property
    def running(self) -> bool:
        return self._running

    @property
    def selected_browser(self) -> str | None:
        return self._selected_browser

    @property
    def discovery_capturing(self) -> bool:
        return self._discovery_capturing

    def start_human_login(self) -> str:
        if not self._available:
            raise BrowserRuntimeError("unavailable")
        self.human_login_start_count += 1
        self._running = True
        self._selected_browser = "chromium"
        return "chromium"

    def start_operational(self) -> str:
        if not self._available:
            raise BrowserRuntimeError("unavailable")
        self.operational_start_count += 1
        self._running = True
        self._selected_browser = "chromium"
        return "chromium"

    def start_discovery_capture(self) -> None:
        if not self._running:
            raise BrowserRuntimeError("browser is not running")
        self.discovery_start_count += 1
        self._discovery_capturing = True

    def freeze_human_session(self) -> None:
        if not self._running:
            raise BrowserRuntimeError("browser is not running")
        self.freeze_count += 1
        self.frozen = True

    def stop_discovery_capture(self) -> list[dict[str, object]]:
        if not self._discovery_capturing:
            raise BrowserRuntimeError("capture is not active")
        self._discovery_capturing = False
        return [
            {
                "method": "GET",
                "origin": "https://platform.example.invalid",
                "path": "/api/waybills/list",
                "path_sha256": None,
                "query_keys": ["page"],
                "request_fields": [],
                "resource_kind": "json_api",
                "response_status": 200,
                "content_kind": "json",
                "response_fields": [
                    {"path": "$.data.rows[].id", "type": "string"},
                ],
            },
            {
                "method": "GET",
                "origin": "https://images.example.invalid",
                "path": None,
                "path_sha256": "b" * 64,
                "query_keys": ["signature"],
                "request_fields": [],
                "resource_kind": "image",
                "response_status": 200,
                "content_kind": "image",
                "response_fields": [],
            },
        ]

    def prepare_automated(
        self,
        *,
        scope: str = "current",
    ) -> SettlementListProbe:
        if not self._running:
            raise BrowserRuntimeError("browser is not running")
        self.prepare_automated_count += 1
        self.prepare_automated_scopes.append(scope)
        if self._prepare_error_code is not None:
            raise BrowserRuntimeError(
                "sensitive runtime detail must not be logged",
                code=self._prepare_error_code,
            )
        return SettlementListProbe(
            total_count=20,
            list_length=20,
            page_number=1,
            page_size=30,
            response_structure_sha256="f" * 64,
        )

    def probe_settlement_views(self) -> SettlementViewProbe:
        if not self._running:
            raise BrowserRuntimeError("browser is not running")
        self.settlement_view_probe_count += 1
        return SettlementViewProbe(
            settlement_total_count=0,
            settlement_list_length=0,
            credit_total_count=137,
            credit_list_length=20,
            page_number=1,
            page_size=20,
            settlement_response_structure_sha256="a" * 64,
            credit_response_structure_sha256="b" * 64,
        )

    def prepare_daily(self) -> dict[str, object]:
        if not self._running:
            raise BrowserRuntimeError("browser is not running")
        self.prepare_daily_count += 1
        return _daily_observation()

    def handoff_operational_session(self) -> None:
        if not self._running:
            raise BrowserRuntimeError("browser is not running")
        self.operational_handoff_count += 1

    def close(self) -> None:
        self._discovery_capturing = False
        self._running = False
        self._selected_browser = None


class _ObservedLifecycle:
    def __init__(self) -> None:
        self._lock = Lock()
        self.waiter_observed = Event()

    @contextmanager
    def hold(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            self.waiter_observed.set()
            self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()


class _StatusResponse(Protocol):
    status_code: int


class FakeContractValidator:
    selection_sha256 = "d" * 64

    def __init__(
        self,
        data_root: Path,
        *,
        fail: bool = False,
        successful_builds: set[str] | None = None,
    ) -> None:
        self._data_root = data_root
        self._fail = fail
        self._results: dict[str, LiveContractValidationResult] = {}
        self._successful_builds = set(successful_builds or ())
        self.calls: list[BrowserCommandAuthority] = []

    def has_successful_validation(self, build_sha256: str) -> bool:
        return build_sha256 in self._successful_builds

    def existing_for_access_window(
        self,
        access_window_id: str,
    ) -> LiveContractValidationResult | None:
        return self._results.get(access_window_id)

    def validate(
        self,
        *,
        authority: BrowserCommandAuthority,
        access_window_id: str,
        build_sha256: str,
        settlement_probe: SettlementListProbe | None = None,
    ) -> LiveContractValidationResult:
        assert build_sha256 == BUILD_SHA256
        assert settlement_probe is not None
        assert settlement_probe.total_count == 20
        self.calls.append(authority)
        if self._fail:
            raise LiveContractValidationError("forced validation failure")
        result = LiveContractValidationResult(
            evidence_id="e" * 64,
            canonical_sha256="e" * 64,
            selection_sha256=self.selection_sha256,
            list_item_count=20,
            detail_attempt_count=1,
            image_count=2,
            evidence_path=self._data_root / "validation.json",
        )
        self._results[access_window_id] = result
        self._successful_builds.add(build_sha256)
        return result


def _headers(*, csrf: str | None = None, key: str | None = None) -> dict[str, str]:
    values = {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }
    if csrf is not None:
        values["X-CSRF-Token"] = csrf
    if key is not None:
        values["Idempotency-Key"] = key
    return values


def _app(
    tmp_path: Path,
    *,
    enabled: bool,
    browser_runtime: FakeBrowserRuntime | None = None,
    data_root: Path | None = None,
    build_sha256: str = BUILD_SHA256,
    contract_validator: FakeContractValidator | None = None,
    daily_execution_backend: AsyncDailyExecutionBackend | None = None,
    settlement_capture_execution_backend: (
        AsyncSettlementCaptureExecutionBackend | None
    ) = None,
    browser_lifecycle: BrowserRuntimeLifecycle | None = None,
    auto_run_jobs: bool = False,
) -> FastAPI:
    resolved_data_root = data_root or (tmp_path / uuid4().hex)
    if (
        daily_execution_backend is not None
        and contract_validator is None
    ):
        contract_validator = FakeContractValidator(
            resolved_data_root,
            successful_builds={build_sha256},
        )
    return create_app(
        data_root=resolved_data_root,
        project_root=PROJECT_ROOT,
        instance_id=uuid4().hex,
        auto_run_jobs=auto_run_jobs,
        stage_delay_seconds=0,
        enable_chengfeng_shadow=enabled,
        platform_build_sha256=build_sha256 if enabled else None,
        browser_runtime=cast(BrowserRuntime | None, browser_runtime),
        browser_lifecycle=browser_lifecycle,
        platform_contract_validator=contract_validator,
        daily_execution_backend=daily_execution_backend,
        settlement_capture_execution_backend=(
            settlement_capture_execution_backend
        ),
    )


def _prepare_daily_selection(data_root: Path) -> str:
    data_root.mkdir(parents=True, exist_ok=True)
    evidence = DiscoveryEvidenceStore(data_root).seal(
        observations=[_daily_observation()],
        build_sha256=BUILD_SHA256,
        access_window_id="daily-api-contract",
        captured_at=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
    )
    frozen = freeze_daily_read_contract(
        discovery_evidence_path=evidence.path,
        data_root=data_root,
    )
    return select_daily_read_contract(
        data_root=data_root,
        frozen=frozen,
    ).manifest.canonical_sha256


def _prepare_settlement_selection(data_root: Path) -> str:
    contract_root = data_root / "platform-read-contract"
    contract_root.mkdir(parents=True, exist_ok=True)
    fixture_source = (
        PROJECT_ROOT
        / "fixtures"
        / "chengfeng"
        / "loop9-read-only.invalid.json"
    ).read_bytes()
    fixture_payload = json.loads(fixture_source)
    for request in fixture_payload["requests"]:
        if request["operation"] == "list_waybills":
            request["path"] = LIST_PATH
        elif request["operation"] == "get_waybill_detail":
            request["path"] = DETAIL_PATH
    source = json.dumps(
        fixture_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest = LiveReadContractManifest.model_validate_json(
        source,
        strict=True,
    )
    contract_path = contract_root / f"{manifest.canonical_sha256}.json"
    contract_path.write_bytes(source)
    contract_file_sha256 = hashlib.sha256(source).hexdigest()
    freeze_body = {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_freeze",
        "classification": "development_only",
        "source_discovery_sha256": manifest.source_discovery_sha256,
        "source_observation_count": manifest.source_observation_count,
        "contract_canonical_sha256": manifest.canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "selected_observation_count": 3,
        "excluded_observation_count": 0,
        "potentially_mutating_observation_count": 0,
        "potentially_mutating_path_sha256s": [],
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    freeze_encoded = json.dumps(
        freeze_body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    freeze_sha256 = hashlib.sha256(freeze_encoded).hexdigest()
    (
        contract_root
        / f"{manifest.canonical_sha256}.freeze-evidence.json"
    ).write_bytes(
        json.dumps(
            {**freeze_body, "canonical_sha256": freeze_sha256},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    return select_live_read_contract(
        data_root=data_root,
        contract_canonical_sha256=manifest.canonical_sha256,
        contract_file_sha256=contract_file_sha256,
        freeze_evidence_sha256=freeze_sha256,
    ).manifest.canonical_sha256


def _idle_daily_backend() -> AsyncDailyExecutionBackend:
    def execute(work: DailyStageWork) -> DailyStageExecution:
        return DailyStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="failed",
            completed_stage=work.stage,
            next_stage=None,
            checkpoint_revision=None,
            diagnostic_code="TEST-BACKEND-MUST-NOT-RUN",
        )

    return AsyncDailyExecutionBackend(execute=execute)


def _idle_settlement_backend() -> AsyncSettlementCaptureExecutionBackend:
    def execute(
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        raise AssertionError(
            f"Gate-blocked capture must not execute: {work.job_id}"
        )

    return AsyncSettlementCaptureExecutionBackend(execute=execute)


def test_contract_subject_selection_is_local_versioned_and_does_not_open_browser(
    tmp_path: Path,
) -> None:
    browser_runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=browser_runtime,
    )

    with TestClient(app) as client:
        csrf = client.get(
            "/api/v1/session",
            headers=_headers(),
        ).json()["csrf_token"]
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        )
        assert initial.status_code == 200, initial.text
        subject = initial.json()["contract_subject"]
        assert subject["current_subject_code"] == "shanxi_guienbo"
        assert subject["available_subjects"] == [
            {"code": "shanxi_guienbo", "label": "山西贵恩博"},
            {"code": "shanghai_jinyisheng", "label": "上海晋亿晟"},
        ]

        changed = client.put(
            "/api/v1/platform/contract-subject",
            headers=_headers(csrf=csrf, key="select-shanghai"),
            json={
                "subject_code": "shanghai_jinyisheng",
                "expected_record_version": subject["record_version"],
            },
        )
        assert changed.status_code == 200, changed.text
        changed_subject = changed.json()
        assert changed_subject["current_subject_code"] == "shanghai_jinyisheng"
        assert changed_subject["record_version"] == subject["record_version"] + 1
        assert browser_runtime.operational_start_count == 0
        assert browser_runtime.human_login_start_count == 0

        stale = client.put(
            "/api/v1/platform/contract-subject",
            headers=_headers(csrf=csrf, key="stale-select-shanxi"),
            json={
                "subject_code": "shanxi_guienbo",
                "expected_record_version": subject["record_version"],
            },
        )
        assert stale.status_code == 409, stale.text
        assert stale.json()["error"]["code"] == "record_version_conflict"

        invalid = client.put(
            "/api/v1/platform/contract-subject",
            headers=_headers(csrf=csrf, key="select-unknown"),
            json={
                "subject_code": "unknown_subject",
                "expected_record_version": changed_subject["record_version"],
            },
        )
        assert invalid.status_code == 422, invalid.text
        assert "detail" in invalid.json()

        current = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()["contract_subject"]
        assert current["current_subject_code"] == "shanghai_jinyisheng"
        assert current["record_version"] == changed_subject["record_version"]


def test_business_reads_start_without_daily_confirmation_and_attach_duplicates(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "fast-business-reads").resolve()
    _prepare_settlement_selection(data_root)
    _prepare_daily_selection(data_root)
    browser_runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=browser_runtime,
        daily_execution_backend=_idle_daily_backend(),
        settlement_capture_execution_backend=(
            _idle_settlement_backend()
        ),
    )
    with TestClient(app) as client:
        csrf = client.get(
            "/api/v1/session",
            headers=_headers(),
        ).json()["csrf_token"]
        settlement = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="fast-settlement"),
            json={
                "business_scope": "settlement",
                "contract_subject_code": "shanxi_guienbo",
                "expected_record_version": 0,
            },
        )
        assert settlement.status_code == 200, settlement.text
        assert settlement.json()["created"] is True
        assert settlement.json()["attached"] is False
        assert settlement.json()["job"]["run_mode"] == "operational"

        attached = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="fast-settlement-repeat"),
            json={
                "business_scope": "settlement",
                "contract_subject_code": "shanxi_guienbo",
                "expected_record_version": 0,
            },
        )
        assert attached.status_code == 200, attached.text
        assert attached.json()["created"] is False
        assert attached.json()["attached"] is True
        assert (
            attached.json()["job"]["job_id"]
            == settlement.json()["job"]["job_id"]
        )

        daily = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="fast-daily"),
            json={
                "business_scope": "daily",
                "contract_subject_code": "shanxi_guienbo",
                "business_date": "2026-08-01",
                "expected_record_version": 0,
            },
        )
        assert daily.status_code == 200, daily.text
        assert daily.json()["created"] is True
        assert daily.json()["job"]["run_mode"] == "operational"

        unknown = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="fast-unknown"),
            json={
                "business_scope": "unknown",
                "contract_subject_code": "shanxi_guienbo",
                "expected_record_version": 0,
            },
        )
        assert unknown.status_code == 422

        platform = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert (
            platform["access_window"]["job_id"]
            == daily.json()["job"]["job_id"]
        )
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="fast-daily-login"),
            json={
                "access_window_id": platform["access_window"][
                    "access_window_id"
                ],
                "expected_record_version": platform["record_version"],
            },
        )
        assert started.status_code == 200, started.text
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="fast-daily-return"),
            json={
                "access_window_id": platform["access_window"][
                    "access_window_id"
                ],
                "expected_record_version": started.json()[
                    "platform_session"
                ]["record_version"],
            },
        )
        assert returned.status_code == 200, returned.text
        assert (
            returned.json()["platform_session"]["browser_lifecycle"]
            == "ready"
        )
        assert returned.json()["platform_session"]["runtime_running"] is True

        network_only = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="fast-daily-network-only"),
            json={
                "business_scope": "daily",
                "contract_subject_code": "shanxi_guienbo",
                "business_date": "2026-08-02",
                "network_only_measurement": True,
                "expected_record_version": 0,
            },
        )
        assert network_only.status_code == 200, network_only.text
        assert network_only.json()["job"]["scope"]["fixture_id"] == (
            "daily-operational-network-only-v1:2026-08-02"
        )

        invalid_network_only = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="fast-settlement-network-only"),
            json={
                "business_scope": "settlement",
                "contract_subject_code": "shanxi_guienbo",
                "network_only_measurement": True,
                "expected_record_version": 0,
            },
        )
        assert invalid_network_only.status_code == 422


def test_business_read_start_queues_a_missing_runtime_for_the_owner_task(
    tmp_path: Path,
) -> None:
    for business_scope in ("settlement", "daily"):
        data_root = (tmp_path / f"failed-browser-{business_scope}").resolve()
        _prepare_settlement_selection(data_root)
        _prepare_daily_selection(data_root)
        app = _app(
            tmp_path,
            enabled=True,
            data_root=data_root,
            browser_runtime=FakeBrowserRuntime(available=False),
            daily_execution_backend=_idle_daily_backend(),
            settlement_capture_execution_backend=_idle_settlement_backend(),
        )
        with TestClient(app) as client:
            csrf = client.get(
                "/api/v1/session",
                headers=_headers(),
            ).json()["csrf_token"]
            payload: dict[str, object] = {
                "business_scope": business_scope,
                "contract_subject_code": "shanxi_guienbo",
                "expected_record_version": 0,
            }
            if business_scope == "daily":
                payload["business_date"] = "2026-08-01"
            started = client.post(
                "/api/v1/platform/business-reads",
                headers=_headers(
                    csrf=csrf,
                    key=f"failed-browser-{business_scope}",
                ),
                json=payload,
            )

            assert started.status_code == 200, started.text
            body = started.json()
            assert body["created"] is True
            job_id = body["job"]["job_id"]
            progress = client.get(
                f"/api/v1/platform/business-reads/{job_id}/progress",
                headers=_headers(),
            ).json()
            job = client.get(
                f"/api/v1/jobs/{job_id}",
                headers=_headers(),
            ).json()
            assert job["job_status"] == "queued"
            assert job["diagnostic_code"] is None
            assert progress["is_terminal"] is False
            assert progress["phase"] == "opening_browser"
            assert progress["capture_mode"] == "whole_run_v1"
            if business_scope == "daily":
                active, version = app.state.repository.fixture_start_state(
                    "daily:shanxi_guienbo:2026-08-01"
                )
                assert active is True
                assert version == job["record_version"]


def test_business_read_start_leaves_browser_start_to_the_owner_task(
    tmp_path: Path,
) -> None:
    class BlockingBrowserRuntime(FakeBrowserRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.start_entered = Event()
            self.allow_start = Event()

        def start_operational(self) -> str:
            self.start_entered.set()
            if not self.allow_start.wait(timeout=5):
                raise BrowserRuntimeError("test browser start timed out")
            return super().start_operational()

    data_root = (tmp_path / "nonblocking-browser-start").resolve()
    _prepare_settlement_selection(data_root)
    runtime = BlockingBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=runtime,
        settlement_capture_execution_backend=_idle_settlement_backend(),
    )
    try:
        with TestClient(app) as client:
            csrf = client.get(
                "/api/v1/session",
                headers=_headers(),
            ).json()["csrf_token"]
            started_at = time.monotonic()
            response = client.post(
                "/api/v1/platform/business-reads",
                headers=_headers(csrf=csrf, key="nonblocking-browser-start"),
                json={
                    "business_scope": "settlement",
                    "contract_subject_code": "shanxi_guienbo",
                    "expected_record_version": 0,
                },
            )
            elapsed = time.monotonic() - started_at

            assert response.status_code == 200, response.text
            assert response.json()["created"] is True
            assert elapsed < 1
            assert not runtime.start_entered.wait(timeout=0.2)
            assert runtime.running is False
    finally:
        runtime.allow_start.set()


def test_future_daily_business_window_is_rejected_before_any_state_is_created(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "future-daily-business-read").resolve()
    _prepare_settlement_selection(data_root)
    _prepare_daily_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=FakeBrowserRuntime(),
        daily_execution_backend=_idle_daily_backend(),
        settlement_capture_execution_backend=(
            _idle_settlement_backend()
        ),
    )
    monkeypatch.setattr(
        platform_api,
        "_daily_now",
        lambda: datetime(2026, 8, 11, 10, 0, tzinfo=SHANGHAI),
    )

    with TestClient(app) as client:
        csrf = client.get(
            "/api/v1/session",
            headers=_headers(),
        ).json()["csrf_token"]
        response = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="future-daily"),
            json={
                "business_scope": "daily",
                "contract_subject_code": "shanxi_guienbo",
                "business_date": "2026-08-11",
                "expected_record_version": 0,
            },
        )

        assert response.status_code == 422
        assert response.json()["error"]["code"] == (
            "daily_business_date_unavailable"
        )
        assert app.state.repository.list_jobs() == ()
        assert app.state.daily_invocation_store.orphaned_start_job_ids() == ()
        assert (
            app.state.platform_access_repository.latest_for_session(
                "chengfeng-shadow-v1"
            )
            is None
        )


def test_whole_run_is_picked_up_after_visible_browser_is_started(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "fast-business-read-scheduler").resolve()
    _prepare_settlement_selection(data_root)
    browser_runtime = FakeBrowserRuntime()
    executed = Event()

    def execute(
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        executed.set()
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="failed",
            completed_stage=work.stage,
            next_stage=None,
            platform_read_performed=False,
            checkpoint_revision=None,
            manifest_sha256=None,
            diagnostic_code="TEST-CAPTURE-STOP",
        )

    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=browser_runtime,
        settlement_capture_execution_backend=(
            AsyncSettlementCaptureExecutionBackend(execute=execute)
        ),
        auto_run_jobs=True,
    )
    with TestClient(app) as client:
        csrf = client.get(
            "/api/v1/session",
            headers=_headers(),
        ).json()["csrf_token"]
        response = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="fast-scheduler-start"),
            json={
                "business_scope": "settlement",
                "contract_subject_code": "shanxi_guienbo",
                "expected_record_version": 0,
            },
        )
        assert response.status_code == 200, response.text
        job_id = response.json()["job"]["job_id"]
        assert executed.wait(timeout=1), (
            "whole-run business read was not scheduled"
        )
        job = client.get(
            f"/api/v1/jobs/{job_id}",
            headers=_headers(),
        ).json()
        assert job["job_status"] in {"running", "failed"}


@pytest.mark.parametrize(
    "recoverable_diagnostic",
    ["CF-CREDENTIAL-REQUIRED", "CF-BROWSER-CLOSED"],
)
def test_operational_login_recovery_opens_one_window_and_resumes_once(
    tmp_path: Path,
    recoverable_diagnostic: str,
) -> None:
    data_root = (
        tmp_path / f"automatic-login-recovery-{recoverable_diagnostic}"
    ).resolve()
    _prepare_settlement_selection(data_root)
    browser_runtime = FakeBrowserRuntime()
    resumed = Event()
    call_lock = Lock()
    call_count = 0

    def execute(
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        nonlocal call_count
        with call_lock:
            call_count += 1
            current_call = call_count
        if current_call == 1:
            return SettlementCaptureStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="waiting_external",
                completed_stage=work.stage,
                next_stage=work.stage,
                platform_read_performed=False,
                checkpoint_revision=None,
                manifest_sha256=None,
                diagnostic_code=recoverable_diagnostic,
            )
        resumed.set()
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="failed",
            completed_stage=work.stage,
            next_stage=None,
            platform_read_performed=False,
            checkpoint_revision=None,
            manifest_sha256=None,
            diagnostic_code="TEST-CAPTURE-STOP",
        )

    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=browser_runtime,
        settlement_capture_execution_backend=(
            AsyncSettlementCaptureExecutionBackend(execute=execute)
        ),
        auto_run_jobs=True,
    )
    with TestClient(app) as client:
        csrf = client.get(
            "/api/v1/session",
            headers=_headers(),
        ).json()["csrf_token"]
        response = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="automatic-login-start"),
            json={
                "business_scope": "settlement",
                "contract_subject_code": "shanxi_guienbo",
                "expected_record_version": 0,
            },
        )
        assert response.status_code == 200, response.text
        did_resume = resumed.wait(timeout=5)
        if not did_resume:
            job_id = response.json()["job"]["job_id"]
            job_state = client.get(
                f"/api/v1/jobs/{job_id}",
                headers=_headers(),
            ).json()
            platform_state = client.get(
                "/api/v1/platform/session",
                headers=_headers(),
            ).json()
            pytest.fail(
                "login recovery did not resume the capture: "
                f"job={job_state!r}, platform={platform_state!r}, "
                f"starts={browser_runtime.human_login_start_count}, "
                f"freezes={browser_runtime.freeze_count}"
            )
        assert browser_runtime.human_login_start_count == 1
        assert browser_runtime.freeze_count == 1

        client.get("/api/v1/settlement/workspace", headers=_headers())
        Event().wait(1.1)
        assert browser_runtime.human_login_start_count == 1
        assert browser_runtime.freeze_count == 1


def test_operational_login_recovery_retries_a_transient_browser_start(
    tmp_path: Path,
) -> None:
    class ClosingBrowserRuntime(FakeBrowserRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.start_attempt_count = 0

        def start_human_login(self) -> str:
            self.start_attempt_count += 1
            if self.start_attempt_count == 1:
                raise BrowserRuntimeError(
                    "prior browser process is still closing",
                    code="browser_worker_start_failed",
                )
            return super().start_human_login()

    data_root = (tmp_path / "automatic-login-transient-start").resolve()
    _prepare_settlement_selection(data_root)
    browser_runtime = ClosingBrowserRuntime()
    resumed = Event()
    call_count = 0

    def execute(
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return SettlementCaptureStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="waiting_external",
                completed_stage=work.stage,
                next_stage=work.stage,
                platform_read_performed=False,
                checkpoint_revision=None,
                manifest_sha256=None,
                diagnostic_code="CF-LOGIN-REQUIRED",
            )
        resumed.set()
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="failed",
            completed_stage=work.stage,
            next_stage=None,
            platform_read_performed=False,
            checkpoint_revision=None,
            manifest_sha256=None,
            diagnostic_code="TEST-CAPTURE-STOP",
        )

    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=browser_runtime,
        settlement_capture_execution_backend=(
            AsyncSettlementCaptureExecutionBackend(execute=execute)
        ),
        auto_run_jobs=True,
    )
    with TestClient(app) as client:
        csrf = client.get(
            "/api/v1/session",
            headers=_headers(),
        ).json()["csrf_token"]
        response = client.post(
            "/api/v1/platform/business-reads",
            headers=_headers(csrf=csrf, key="automatic-login-transient"),
            json={
                "business_scope": "settlement",
                "contract_subject_code": "shanxi_guienbo",
                "expected_record_version": 0,
            },
        )
        assert response.status_code == 200, response.text
        assert resumed.wait(timeout=7)
        assert browser_runtime.start_attempt_count == 2
        assert browser_runtime.human_login_start_count == 1
        assert browser_runtime.freeze_count == 1


def _daily_job_and_returned_window(
    client: TestClient,
    *,
    csrf: str,
    initial_record_version: int,
    key_prefix: str,
    scope: str = "current",
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    created = client.post(
        "/api/v1/platform/daily-jobs",
        headers=_headers(csrf=csrf, key=f"{key_prefix}-job"),
        json={"expected_record_version": 0, "scope": scope},
    )
    assert created.status_code == 200
    job = created.json()["job"]
    window_response = client.post(
        "/api/v1/platform/access-windows",
        headers=_headers(csrf=csrf, key=f"{key_prefix}-window"),
        json={
            "purpose": "production_shadow",
            "job_id": job["job_id"],
            "duration_minutes": 60,
            "legacy_idle_confirmed": True,
            "no_settlement_or_payment_confirmed": True,
            "same_account_session_risk_accepted": True,
            "expected_record_version": 0,
        },
    )
    assert window_response.status_code == 200
    window = window_response.json()["access_window"]
    started_response = client.post(
        "/api/v1/platform/session/human-login/start",
        headers=_headers(csrf=csrf, key=f"{key_prefix}-login"),
        json={
            "access_window_id": window["access_window_id"],
            "expected_record_version": initial_record_version,
        },
    )
    assert started_response.status_code == 200
    started = started_response.json()["platform_session"]
    returned_response = client.post(
        "/api/v1/platform/session/human-login/return",
        headers=_headers(csrf=csrf, key=f"{key_prefix}-return"),
        json={
            "access_window_id": window["access_window_id"],
            "expected_record_version": started["record_version"],
        },
    )
    assert returned_response.status_code == 200
    return job, window, returned_response.json()["platform_session"]


def test_default_application_exposes_only_disabled_platform_state(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path, enabled=False)
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        assert session.status_code == 200
        state = client.get("/api/v1/platform/session", headers=_headers())
        assert state.status_code == 200
        assert state.json()["enabled"] is False
        assert state.json()["contract_candidate_selected"] is False
        assert (
            state.json()["available_actions"]["validate_read_contract"]["enabled"]
            is False
        )
        assert state.json()["available_actions"]["create_access_window"]["enabled"] is False
        assert (
            app.openapi()["paths"]
            .keys()
            .isdisjoint(
                {
                    "/api/v1/settlement/confirm",
                    "/api/v1/settlement/pay",
                    "/api/v1/platform/request",
                }
            )
        )


def test_operational_capture_starts_without_formal_daily_gate(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "operational-capture-api").resolve()
    _prepare_settlement_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=FakeBrowserRuntime(),
        contract_validator=FakeContractValidator(data_root),
        settlement_capture_execution_backend=_idle_settlement_backend(),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert initial["connection_mode"] == "operational_compat"
        assert (
            initial["available_actions"]["start_operational_capture"][
                "enabled"
            ]
            is True
        )

        response = client.post(
            "/api/v1/platform/settlement-captures",
            headers=_headers(
                csrf=csrf,
                key="operational-capture-without-formal-daily",
            ),
            json={
                "target_kind": "operational_compat",
                "duration_minutes": 720,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["capture"]["target_kind"] == "operational_compat"
        assert body["capture"]["status"] == "collecting"
        assert body["job"]["run_mode"] == "operational"
        assert body["job"]["job_status"] == "queued"
        assert body["access_window"]["purpose"] == "production_shadow"
        assert body["business_session"]["status"] == "active"
        assert body["business_session"]["record_version"] == 2
        assert (
            app.state.business_session_store.active_read_job_id(
                business_session_id=body["business_session"][
                    "business_session_id"
                ]
            )
            == body["job"]["job_id"]
        )
        assert (
            datetime.fromisoformat(body["access_window"]["expires_at"])
            - datetime.fromisoformat(body["access_window"]["issued_at"])
            == timedelta(hours=12)
        )
        assert app.state.selected_daily_contract is None


def test_business_session_confirms_once_then_starts_an_atomic_read(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "business-session-api").resolve()
    _prepare_settlement_selection(data_root)
    browser_runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=browser_runtime,
        contract_validator=FakeContractValidator(data_root),
        settlement_capture_execution_backend=_idle_settlement_backend(),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert initial["available_actions"]["start_business_session"][
            "enabled"
        ] is True

        started = client.post(
            "/api/v1/platform/business-session/start",
            headers=_headers(csrf=csrf, key="business-session-start"),
            json={
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )
        assert started.status_code == 200
        started_body = started.json()
        business_session = started_body["business_session"]
        access_window = started_body["access_window"]
        assert business_session["record_version"] == 1
        assert access_window["purpose"] == "production_shadow"

        login = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="business-login"),
            json={
                "access_window_id": access_window["access_window_id"],
                "expected_record_version": started_body[
                    "platform_session"
                ]["record_version"],
            },
        )
        assert login.status_code == 200
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="business-login-return"),
            json={
                "access_window_id": access_window["access_window_id"],
                "expected_record_version": login.json()[
                    "platform_session"
                ]["record_version"],
            },
        )
        assert returned.status_code == 200
        returned_browser = returned.json()["platform_session"]

        read = client.post(
            "/api/v1/platform/business-session/read",
            headers=_headers(csrf=csrf, key="business-read-one"),
            json={
                "business_session_id": business_session[
                    "business_session_id"
                ],
                "expected_record_version": 1,
                "expected_browser_record_version": returned_browser[
                    "record_version"
                ],
            },
        )

        assert read.status_code == 200, read.text
        read_body = read.json()
        assert read_body["created"] is True
        assert read_body["business_session"]["record_version"] == 2
        assert read_body["job"]["run_mode"] == "operational"
        assert read_body["job"]["job_status"] == "queued"
        assert "legacy_idle_confirmed" not in read.request.content.decode()

        replay = client.post(
            "/api/v1/platform/business-session/read",
            headers=_headers(csrf=csrf, key="business-read-one"),
            json={
                "business_session_id": business_session[
                    "business_session_id"
                ],
                "expected_record_version": 1,
                "expected_browser_record_version": returned_browser[
                    "record_version"
                ],
            },
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["created"] is False
        assert replay.json()["job"]["job_id"] == read_body["job"][
            "job_id"
        ]


def test_business_session_close_is_idempotent_after_state_advances(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "business-session-close-replay").resolve()
    _prepare_settlement_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=FakeBrowserRuntime(),
        contract_validator=FakeContractValidator(data_root),
        settlement_capture_execution_backend=_idle_settlement_backend(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        started = client.post(
            "/api/v1/platform/business-session/start",
            headers=_headers(csrf=csrf, key="close-replay-start"),
            json={
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()
        payload = {
            "business_session_id": started["business_session"][
                "business_session_id"
            ],
            "expected_record_version": 1,
            "expected_browser_record_version": started[
                "platform_session"
            ]["record_version"],
        }
        first = client.post(
            "/api/v1/platform/business-session/close",
            headers=_headers(csrf=csrf, key="close-replay"),
            json=payload,
        )
        replay = client.post(
            "/api/v1/platform/business-session/close",
            headers=_headers(csrf=csrf, key="close-replay"),
            json=payload,
        )

        assert first.status_code == 200, first.text
        assert replay.status_code == 200, replay.text
        assert replay.json()["business_session"][
            "idempotent_replay"
        ] is True
        assert replay.json()["business_session"]["status"] == "closed"


def test_closing_the_human_browser_recovers_the_business_session(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "business-session-browser-close").resolve()
    _prepare_settlement_selection(data_root)
    browser_runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=browser_runtime,
        contract_validator=FakeContractValidator(data_root),
        settlement_capture_execution_backend=_idle_settlement_backend(),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        started = client.post(
            "/api/v1/platform/business-session/start",
            headers=_headers(csrf=csrf, key="browser-close-session"),
            json={
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()
        login = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="browser-close-login"),
            json={
                "access_window_id": started["access_window"][
                    "access_window_id"
                ],
                "expected_record_version": started["platform_session"][
                    "record_version"
                ],
            },
        )
        assert login.status_code == 200
        browser_runtime._running = False

        recovered = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        )

        assert recovered.status_code == 200
        body = recovered.json()
        assert body["browser_lifecycle"] == "stopped"
        assert body["browser_control_mode"] == "idle"
        assert body["business_session"]["status"] == "closed"
        assert body["available_actions"]["start_business_session"][
            "enabled"
        ] is True


def test_application_shutdown_closes_its_business_session_and_browser(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "business-session-shutdown").resolve()
    _prepare_settlement_selection(data_root)
    browser_runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=browser_runtime,
        contract_validator=FakeContractValidator(data_root),
        settlement_capture_execution_backend=_idle_settlement_backend(),
    )
    business_session_id = ""
    login_access_window_id = ""

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        started = client.post(
            "/api/v1/platform/business-session/start",
            headers=_headers(csrf=csrf, key="shutdown-session"),
            json={
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()
        business_session_id = started["business_session"][
            "business_session_id"
        ]
        login_access_window_id = started["access_window"][
            "access_window_id"
        ]
        login = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="shutdown-login"),
            json={
                "access_window_id": login_access_window_id,
                "expected_record_version": started["platform_session"][
                    "record_version"
                ],
            },
        )
        assert login.status_code == 200
        assert browser_runtime.running is True

    closed = app.state.business_session_store.get(business_session_id)
    retired = app.state.platform_access_repository.get(
        login_access_window_id
    )
    assert closed.status == "closed"
    assert closed.close_reason == "shutdown"
    assert retired.consumed_at is not None
    assert browser_runtime.running is False


def test_real_shadow_capture_is_rejected_before_job_creation_without_gate(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "real-shadow-gate-api").resolve()
    _prepare_settlement_selection(data_root)
    _prepare_daily_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        contract_validator=FakeContractValidator(
            data_root,
            successful_builds={BUILD_SHA256},
        ),
        settlement_capture_execution_backend=(
            _idle_settlement_backend()
        ),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        response = client.post(
            "/api/v1/platform/settlement-captures",
            headers=_headers(
                csrf=csrf,
                key="real-shadow-without-current-gate",
            ),
            json={
                "target_kind": "real_shadow_30",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )

        assert response.status_code == 409
        assert response.json()["error"]["code"] == (
            "settlement_capture_prerequisites_failed"
        )
        assert app.state.repository.list_jobs() == ()


def test_locked_capture_requires_current_validation_before_job_creation(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "locked-validation-gate-api").resolve()
    _prepare_settlement_selection(data_root)
    _prepare_daily_selection(data_root)
    validator = FakeContractValidator(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        contract_validator=validator,
        settlement_capture_execution_backend=(
            _idle_settlement_backend()
        ),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        response = client.post(
            "/api/v1/platform/settlement-captures",
            headers=_headers(
                csrf=csrf,
                key="locked-without-contract-validation",
            ),
            json={
                "target_kind": "current_locked_50",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )

        assert response.status_code == 409
        assert response.json()["error"]["code"] == (
            "settlement_validation_gate_required"
        )
        assert app.state.repository.list_jobs() == ()


@pytest.mark.parametrize(
    "target_kind",
    ["real_shadow_30", "operational_compat"],
)
def test_only_locked_capture_accepts_settled_history_source(
    tmp_path: Path,
    target_kind: str,
) -> None:
    data_root = (tmp_path / f"history-source-{target_kind}").resolve()
    _prepare_settlement_selection(data_root)
    _prepare_daily_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        settlement_capture_execution_backend=(
            _idle_settlement_backend()
        ),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        response = client.post(
            "/api/v1/platform/settlement-captures",
            headers=_headers(
                csrf=csrf,
                key=f"reject-history-{target_kind}",
            ),
            json={
                "target_kind": target_kind,
                "source_scope": "settled_history",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )

        assert response.status_code == 409
        assert response.json()["error"]["code"] == (
            "settlement_capture_scope_mismatch"
        )
        assert app.state.repository.list_jobs() == ()


def test_paused_capture_access_window_can_be_rebound_locally(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "capture-rollover-api").resolve()
    _prepare_settlement_selection(data_root)
    _prepare_daily_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        contract_validator=FakeContractValidator(
            data_root,
            successful_builds={BUILD_SHA256},
        ),
        settlement_capture_execution_backend=(
            _idle_settlement_backend()
        ),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        selected = app.state.selected_settlement_contract
        assert selected is not None
        now = datetime.now(UTC)
        started = app.state.settlement_capture_store.create_start(
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            session_id="chengfeng-shadow-v1",
            source_build_sha256=BUILD_SHA256,
            contract_canonical_sha256=(
                selected.manifest.canonical_sha256
            ),
            contract_file_sha256=selected.contract_file_sha256,
            contract_selection_sha256=selected.selection_sha256,
            identity_context_sha256="e" * 64,
            duration_minutes=60,
            legacy_idle_confirmed=True,
            no_settlement_or_payment_confirmed=True,
            same_account_session_risk_accepted=True,
            idempotency_key="capture-rollover-api-start",
            request_hash=hashlib.sha256(
                b"capture-rollover-api-start"
            ).hexdigest(),
            now=now - timedelta(hours=2),
        )
        requested, replayed = app.state.repository.request_job_control(
            job_id=started.job_id,
            action="pause",
            expected_record_version=1,
            idempotency_key="capture-rollover-api-pause",
            request_hash=hashlib.sha256(
                b"capture-rollover-api-pause"
            ).hexdigest(),
        )
        assert replayed is False
        assert requested.status.value == "pause_requested"
        assert app.state.scheduler.tick() is True
        assert (
            app.state.repository.get_job(started.job_id).status.value
            == "paused"
        )
        app.state.settlement_capture_store.reconcile_terminal_or_expired_access(
            now=now
        )
        replacement, replayed = (
            app.state.platform_access_repository.issue(
                purpose=AccessPurpose.FORMAL_LOCKED_SET,
                job_id=started.job_id,
                session_id="chengfeng-shadow-v1",
                build_sha256=BUILD_SHA256,
                duration_minutes=60,
                legacy_idle_confirmed=True,
                no_settlement_or_payment_confirmed=True,
                same_account_session_risk_accepted=True,
                run_mode="shadow",
                idempotency_key="capture-rollover-api-window",
                request_hash=hashlib.sha256(
                    b"capture-rollover-api-window"
                ).hexdigest(),
                now=now,
            )
        )
        assert replayed is False
        payload = {
            "access_window_id": replacement.access_window_id,
            "expected_record_version": (
                started.invocation.record_version
            ),
        }
        rebound = client.post(
            (
                "/api/v1/platform/settlement-captures/"
                f"{started.job_id}/access-window"
            ),
            headers=_headers(
                csrf=csrf,
                key="capture-rollover-api-rebind",
            ),
            json=payload,
        )

        assert rebound.status_code == 200
        body = rebound.json()
        assert body["idempotent_replay"] is False
        assert body["capture"] == {
            "access_window_id": replacement.access_window_id,
            "record_version": started.invocation.record_version + 1,
            "status": "collecting",
        }
        assert body["job"]["job_id"] == started.job_id
        assert body["job"]["job_status"] == "paused"

        exact_replay = client.post(
            (
                "/api/v1/platform/settlement-captures/"
                f"{started.job_id}/access-window"
            ),
            headers=_headers(
                csrf=csrf,
                key="capture-rollover-api-rebind",
            ),
            json=payload,
        )
        assert exact_replay.status_code == 200
        assert exact_replay.json()["idempotent_replay"] is True

        rejected_unknown_field = client.post(
            (
                "/api/v1/platform/settlement-captures/"
                f"{started.job_id}/access-window"
            ),
            headers=_headers(
                csrf=csrf,
                key="capture-rollover-api-unknown",
            ),
            json={**payload, "platform_url": "https://example.invalid"},
        )
        assert rejected_unknown_field.status_code == 422


def test_rollover_fences_human_login_authorized_by_the_old_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "capture-rollover-race").resolve()
    _prepare_settlement_selection(data_root)
    _prepare_daily_selection(data_root)
    runtime = FakeBrowserRuntime()
    lifecycle = _ObservedLifecycle()
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        browser_runtime=runtime,
        browser_lifecycle=lifecycle,
        contract_validator=FakeContractValidator(
            data_root,
            successful_builds={BUILD_SHA256},
        ),
        settlement_capture_execution_backend=_idle_settlement_backend(),
    )

    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        selected = app.state.selected_settlement_contract
        assert selected is not None
        now = datetime.now(UTC)
        started = app.state.settlement_capture_store.create_start(
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            session_id="chengfeng-shadow-v1",
            source_build_sha256=BUILD_SHA256,
            contract_canonical_sha256=(
                selected.manifest.canonical_sha256
            ),
            contract_file_sha256=selected.contract_file_sha256,
            contract_selection_sha256=selected.selection_sha256,
            identity_context_sha256="e" * 64,
            duration_minutes=60,
            legacy_idle_confirmed=True,
            no_settlement_or_payment_confirmed=True,
            same_account_session_risk_accepted=True,
            idempotency_key="capture-rollover-race-start",
            request_hash=hashlib.sha256(
                b"capture-rollover-race-start"
            ).hexdigest(),
            now=now,
        )
        requested, replayed = app.state.repository.request_job_control(
            job_id=started.job_id,
            action="pause",
            expected_record_version=1,
            idempotency_key="capture-rollover-race-pause",
            request_hash=hashlib.sha256(
                b"capture-rollover-race-pause"
            ).hexdigest(),
        )
        assert replayed is False
        assert requested.status.value == "pause_requested"
        assert app.state.scheduler.tick() is True

        authorize_entered = Event()
        allow_authorize_return = Event()
        original_authorize = (
            app.state.platform_access_repository.authorize
        )

        def blocking_authorize(
            *,
            access_window_id: str,
            purpose: AccessPurpose,
            job_id: str,
            session_id: str,
            build_sha256: str,
            now: datetime,
        ) -> AccessWindowGrant:
            grant = original_authorize(
                access_window_id=access_window_id,
                purpose=purpose,
                job_id=job_id,
                session_id=session_id,
                build_sha256=build_sha256,
                now=now,
            )
            if access_window_id == started.access_window.access_window_id:
                authorize_entered.set()
                if not allow_authorize_return.wait(timeout=5):
                    raise AssertionError(
                        "test did not release the old authorization"
                    )
            return grant

        monkeypatch.setattr(
            app.state.platform_access_repository,
            "authorize",
            blocking_authorize,
        )
        old_responses: list[tuple[int, dict[str, object]]] = []
        old_errors: list[BaseException] = []

        def start_old_window() -> None:
            try:
                response = client.post(
                    "/api/v1/platform/session/human-login/start",
                    headers=_headers(
                        csrf=csrf,
                        key="capture-rollover-race-old-login",
                    ),
                    json={
                        "access_window_id": (
                            started.access_window.access_window_id
                        ),
                        "expected_record_version": 1,
                    },
                )
                old_responses.append(
                    (response.status_code, response.json())
                )
            except BaseException as exc:  # pragma: no cover
                old_errors.append(exc)

        old_thread = Thread(target=start_old_window)
        old_thread.start()
        assert authorize_entered.wait(timeout=5)

        app.state.platform_access_repository.consume(
            access_window_id=started.access_window.access_window_id,
            expected_record_version=1,
            now=now + timedelta(minutes=1),
        )
        replacement, replayed = (
            app.state.platform_access_repository.issue(
                purpose=AccessPurpose.FORMAL_LOCKED_SET,
                job_id=started.job_id,
                session_id="chengfeng-shadow-v1",
                build_sha256=BUILD_SHA256,
                duration_minutes=60,
                legacy_idle_confirmed=True,
                no_settlement_or_payment_confirmed=True,
                same_account_session_risk_accepted=True,
                run_mode="shadow",
                idempotency_key="capture-rollover-race-replacement",
                request_hash=hashlib.sha256(
                    b"capture-rollover-race-replacement"
                ).hexdigest(),
                now=now + timedelta(minutes=2),
            )
        )
        assert replayed is False
        rebound = client.post(
            (
                "/api/v1/platform/settlement-captures/"
                f"{started.job_id}/access-window"
            ),
            headers=_headers(
                csrf=csrf,
                key="capture-rollover-race-rebind",
            ),
            json={
                "access_window_id": replacement.access_window_id,
                "expected_record_version": (
                    started.invocation.record_version
                ),
            },
        )
        assert rebound.status_code == 200
        fenced = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert fenced["browser_control_mode"] == "idle"
        assert fenced["control_epoch"] == 1
        assert fenced["record_version"] == 2

        allow_authorize_return.set()
        old_thread.join(timeout=5)
        assert not old_thread.is_alive()
        assert old_errors == []
        assert len(old_responses) == 1
        assert old_responses[0][0] == 409
        assert old_responses[0][1]["error"]["code"] == (
            "access_window_invalid"
        )
        assert runtime.running is False
        final = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert final["browser_control_mode"] == "idle"
        assert final["record_version"] == 2


def test_access_window_requires_all_current_confirmations_and_is_idempotent(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path, enabled=True)
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        payload = {
            "purpose": "contract_discovery",
            "job_id": "loop9-discovery-job",
            "duration_minutes": 60,
            "legacy_idle_confirmed": True,
            "no_settlement_or_payment_confirmed": True,
            "same_account_session_risk_accepted": False,
            "expected_record_version": 0,
        }
        rejected = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="window-1"),
            json=payload,
        )
        assert rejected.status_code == 409

        payload["same_account_session_risk_accepted"] = True
        created = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="window-2"),
            json=payload,
        )
        assert created.status_code == 200
        assert created.json()["access_window"]["record_version"] == 1
        assert "token" not in created.text.casefold()
        replay = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="window-2"),
            json=payload,
        )
        assert replay.status_code == 200
        assert replay.json()["access_window"]["idempotent_replay"] is True


def test_human_login_control_is_versioned_idempotent_and_closable(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    app = _app(tmp_path, enabled=True, browser_runtime=runtime)
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="window-control"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        control = {
            "access_window_id": window["access_window_id"],
            "expected_record_version": 1,
        }
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="login-start"),
            json=control,
        )
        assert started.status_code == 200
        assert started.json()["platform_session"]["browser_control_mode"] == "human_login"
        started_version = started.json()["platform_session"]["record_version"]

        replay = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="login-start"),
            json=control,
        )
        assert replay.status_code == 200
        assert replay.json()["platform_session"]["idempotent_replay"] is True

        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="login-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started_version,
            },
        )
        assert returned.status_code == 200
        assert returned.json()["platform_session"]["browser_control_mode"] == "idle"
        assert runtime.freeze_count == 1
        assert runtime.frozen is True
        returned_version = returned.json()["platform_session"]["record_version"]

        closed = client.post(
            "/api/v1/platform/session/close",
            headers=_headers(csrf=csrf, key="session-close"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned_version,
            },
        )
        assert closed.status_code == 200
        assert closed.json()["platform_session"]["browser_lifecycle"] == "stopped"
        assert runtime.running is False


def test_human_login_return_fails_closed_when_runtime_cannot_freeze(
    tmp_path: Path,
) -> None:
    class FreezeFailureRuntime(FakeBrowserRuntime):
        def freeze_human_session(self) -> None:
            raise BrowserRuntimeError(
                "Authorization=secret C:\\private\\profile",
                code="browser_session_existing_page_freeze_failed",
            )

    runtime = FreezeFailureRuntime()
    app = _app(tmp_path, enabled=True, browser_runtime=runtime)
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="freeze-failure-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-freeze-failure",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="freeze-failure-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]

        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="freeze-failure-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        )

        assert returned.status_code == 409
        assert returned.json()["error"]["code"] == "browser_session_freeze_failed"
        assert "Authorization" not in returned.text
        assert "private" not in returned.text
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["browser_lifecycle"] == "stopped"
        assert state["browser_control_mode"] == "idle"
        assert runtime.running is False
        logs = client.get(
            "/api/v1/diagnostics/logs?limit=100",
            headers=_headers(),
        ).json()["events"]
        freeze_failures = [
            event
            for event in logs
            if event["event_code"] == "human_login_freeze_failed"
        ]
        assert len(freeze_failures) == 1
        assert (
            freeze_failures[0]["diagnostic_code"]
            == "CF-BROWSER-EXISTING-PAGE-FREEZE-FAILED"
        )
        assert "Authorization" not in freeze_failures[0]["message"]
        assert "private" not in freeze_failures[0]["message"]


def test_session_close_fences_a_concurrent_new_human_login(
    tmp_path: Path,
) -> None:
    class BlockingCloseRuntime(FakeBrowserRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.close_entered = Event()
            self.allow_close = Event()

        def close(self) -> None:
            self.close_entered.set()
            if not self.allow_close.wait(timeout=5):
                raise AssertionError("test did not release browser close")
            super().close()

    runtime = BlockingCloseRuntime()
    lifecycle = _ObservedLifecycle()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        browser_lifecycle=lifecycle,
    )
    with TestClient(app) as client:
        csrf = str(
            client.get(
                "/api/v1/session",
                headers=_headers(),
            ).json()["csrf_token"]
        )

        def issue_window(key: str, job_id: str) -> dict[str, object]:
            response = client.post(
                "/api/v1/platform/access-windows",
                headers=_headers(csrf=csrf, key=key),
                json={
                    "purpose": "contract_discovery",
                    "job_id": job_id,
                    "duration_minutes": 60,
                    "legacy_idle_confirmed": True,
                    "no_settlement_or_payment_confirmed": True,
                    "same_account_session_risk_accepted": True,
                    "expected_record_version": 0,
                },
            )
            assert response.status_code == 200
            return response.json()["access_window"]  # type: ignore[no-any-return]

        old_window = issue_window("old-close-window", "old-close-job")
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="start-old-window"),
            json={
                "access_window_id": old_window["access_window_id"],
                "expected_record_version": 1,
            },
        )
        assert started.status_code == 200
        started_version = started.json()["platform_session"]["record_version"]

        close_responses: list[_StatusResponse] = []
        replacement_responses: list[_StatusResponse] = []
        close_errors: list[BaseException] = []
        replacement_errors: list[BaseException] = []
        replacement_attempted = Event()

        def close_old_window() -> None:
            try:
                close_responses.append(
                    client.post(
                        "/api/v1/platform/session/close",
                        headers=_headers(csrf=csrf, key="close-old-window"),
                        json={
                            "access_window_id": old_window[
                                "access_window_id"
                            ],
                            "expected_record_version": started_version,
                        },
                    )
                )
            except BaseException as exc:  # pragma: no cover - assertion reports it
                close_errors.append(exc)

        close_thread = Thread(target=close_old_window)
        close_thread.start()
        assert runtime.close_entered.wait(timeout=5)
        between = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert between["browser_control_mode"] == "idle"

        def issue_replacement_window() -> None:
            try:
                replacement_attempted.set()
                replacement_responses.append(
                    client.post(
                        "/api/v1/platform/access-windows",
                        headers=_headers(csrf=csrf, key="new-login-window"),
                        json={
                            "purpose": "contract_discovery",
                            "job_id": "new-login-job",
                            "duration_minutes": 60,
                            "legacy_idle_confirmed": True,
                            "no_settlement_or_payment_confirmed": True,
                            "same_account_session_risk_accepted": True,
                            "expected_record_version": 0,
                        },
                    )
                )
            except BaseException as exc:  # pragma: no cover - assertion reports it
                replacement_errors.append(exc)

        replacement_thread = Thread(target=issue_replacement_window)
        replacement_thread.start()
        assert replacement_attempted.wait(timeout=5)
        replacement_waited = lifecycle.waiter_observed.wait(timeout=1)
        runtime.allow_close.set()
        close_thread.join(timeout=5)
        replacement_thread.join(timeout=5)

        assert replacement_waited
        assert close_errors == []
        assert replacement_errors == []
        assert len(close_responses) == 1
        assert len(replacement_responses) == 1
        closed_response = close_responses[0]
        replacement_response = replacement_responses[0]
        assert closed_response.status_code == 200
        assert replacement_response.status_code == 200
        new_window = replacement_response.json()["access_window"]

        stopped = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert stopped["browser_lifecycle"] == "stopped"
        assert runtime.running is False
        reopened = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="retry-new-window"),
            json={
                "access_window_id": new_window["access_window_id"],
                "expected_record_version": stopped["record_version"],
            },
        )
        assert reopened.status_code == 200
        assert (
            reopened.json()["platform_session"]["browser_control_mode"]
            == "human_login"
        )
        assert runtime.running is True


def test_human_login_landing_failure_closes_runtime_and_preserves_safe_retry(
    tmp_path: Path,
) -> None:
    class FailingBrowserRuntime(FakeBrowserRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.close_count = 0

        def start_human_login(self) -> str:
            self._running = True
            raise BrowserRuntimeError(
                "成丰登录页未能打开，受控浏览器已安全关闭。请检查当前网络后重试。",  # noqa: RUF001
                code="browser_login_entry_failed",
            )

        def close(self) -> None:
            self.close_count += 1
            super().close()

    runtime = FailingBrowserRuntime()
    app = _app(tmp_path, enabled=True, browser_runtime=runtime)
    with TestClient(app) as client:
        csrf = str(client.get("/api/v1/session", headers=_headers()).json()["csrf_token"])
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="failed-login-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]

        failed = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="failed-login-start"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": 1,
            },
        )

        assert failed.status_code == 409
        assert failed.json()["error"] == {
            "code": "browser_start_failed",
            "message": (
                "成丰登录页未能打开，受控浏览器已安全关闭。"  # noqa: RUF001
                "请检查当前网络后重试。"
            ),
        }
        assert runtime.close_count == 1
        assert runtime.running is False
        state = client.get("/api/v1/platform/session", headers=_headers()).json()
        assert state["browser_lifecycle"] == "stopped"
        assert state["browser_control_mode"] == "idle"
        assert state["access_window"]["consumed_at"] is None
        assert state["available_actions"]["start_human_login"]["enabled"] is True


def test_prior_build_window_is_not_actionable_and_fresh_window_can_replace_it(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "shared-data"
    prior_build = hashlib.sha256(b"prior-loop9-build").hexdigest()
    current_build = hashlib.sha256(b"current-loop9-build").hexdigest()
    prior_app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        build_sha256=prior_build,
    )
    with TestClient(prior_app) as client:
        csrf = str(client.get("/api/v1/session", headers=_headers()).json()["csrf_token"])
        prior = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="prior-build-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )
        assert prior.status_code == 200

    current_app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        build_sha256=current_build,
    )
    with TestClient(current_app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        state = client.get("/api/v1/platform/session", headers=_headers()).json()

        assert state["access_window"] is None
        assert state["waiting_reason"] == "access_window_required"
        assert state["available_actions"]["start_human_login"]["enabled"] is False
        assert state["available_actions"]["close_session"]["enabled"] is False

        replacement = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="current-build-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )

        assert replacement.status_code == 200
        assert replacement.json()["access_window"]["build_sha256"] == current_build


def test_closed_human_browser_is_reconciled_without_consuming_access_window(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    app = _app(tmp_path, enabled=True, browser_runtime=runtime)
    with TestClient(app) as client:
        csrf = str(client.get("/api/v1/session", headers=_headers()).json()["csrf_token"])
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="closed-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="closed-window-start"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": 1,
            },
        )
        assert started.status_code == 200

        runtime.close()
        state = client.get("/api/v1/platform/session", headers=_headers()).json()

        assert state["browser_lifecycle"] == "stopped"
        assert state["browser_control_mode"] == "idle"
        assert state["runtime_running"] is False
        assert state["access_window"]["consumed_at"] is None
        assert state["available_actions"]["start_human_login"]["enabled"] is True


def test_return_after_user_closed_browser_fails_closed_and_can_reopen(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    app = _app(tmp_path, enabled=True, browser_runtime=runtime)
    with TestClient(app) as client:
        csrf = str(client.get("/api/v1/session", headers=_headers()).json()["csrf_token"])
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="return-closed-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="return-closed-start"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": 1,
            },
        ).json()["platform_session"]

        runtime.close()
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="return-after-close"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        )

        assert returned.status_code == 409
        assert returned.json()["error"]["code"] == "browser_window_closed"
        state = client.get("/api/v1/platform/session", headers=_headers()).json()
        assert state["browser_lifecycle"] == "stopped"
        reopened = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="reopen-after-close"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": state["record_version"],
            },
        )
        assert reopened.status_code == 200
        assert reopened.json()["platform_session"]["browser_control_mode"] == "human_login"


def test_unused_access_window_can_be_closed_without_starting_browser(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    app = _app(tmp_path, enabled=True, browser_runtime=runtime)
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="unused-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        state = client.get("/api/v1/platform/session", headers=_headers()).json()
        assert state["available_actions"]["close_session"]["enabled"] is True

        closed = client.post(
            "/api/v1/platform/session/close",
            headers=_headers(csrf=csrf, key="close-unused"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": state["record_version"],
            },
        )

        assert closed.status_code == 200
        assert runtime.running is False
        final = client.get("/api/v1/platform/session", headers=_headers()).json()
        assert final["access_window"]["consumed_at"] is not None
        assert final["available_actions"]["start_human_login"]["enabled"] is False


def test_contract_discovery_starts_only_after_login_return_and_seals_shapes(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    data_root = tmp_path / "discovery-data"
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
    )
    with TestClient(app) as client:
        csrf = str(client.get("/api/v1/session", headers=_headers()).json()["csrf_token"])
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="discovery-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-discovery-job",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        access_window_id = window["access_window_id"]
        premature = client.post(
            "/api/v1/platform/discovery/start",
            headers=_headers(csrf=csrf, key="capture-too-early"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": 1,
            },
        )
        assert premature.status_code == 409

        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="capture-login"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": 1,
            },
        ).json()["platform_session"]
        during_login = client.post(
            "/api/v1/platform/discovery/start",
            headers=_headers(csrf=csrf, key="capture-during-login"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": started["record_version"],
            },
        )
        assert during_login.status_code == 409
        assert runtime.discovery_start_count == 0
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="capture-login-return"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]
        capture = client.post(
            "/api/v1/platform/discovery/start",
            headers=_headers(csrf=csrf, key="capture-start"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": returned["record_version"],
            },
        )
        assert capture.status_code == 200
        captured_session = capture.json()["platform_session"]
        assert captured_session["browser_control_mode"] == "human_handoff"
        assert captured_session["discovery_capturing"] is True
        assert runtime.discovery_start_count == 1

        stopped = client.post(
            "/api/v1/platform/discovery/stop",
            headers=_headers(csrf=csrf, key="capture-stop"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": captured_session["record_version"],
            },
        )
        assert stopped.status_code == 200
        result = stopped.json()
        assert result["platform_session"]["browser_lifecycle"] == "stopped"
        assert result["discovery_evidence"]["observation_count"] == 2
        evidence_path = (
            data_root
            / "platform-contract-discovery"
            / f"{result['discovery_evidence']['canonical_sha256']}.json"
        )
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        assert evidence["classification"] == "development_only"
        image_observation = next(
            item for item in evidence["observations"] if item["resource_kind"] == "image"
        )
        assert image_observation["path"] is None

        replay = client.post(
            "/api/v1/platform/discovery/stop",
            headers=_headers(csrf=csrf, key="capture-stop"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": captured_session["record_version"],
            },
        )
        assert replay.status_code == 200
        assert replay.json()["discovery_evidence"]["idempotent_replay"] is True


@pytest.mark.parametrize(
    ("scope", "instant", "expected_date"),
    [
        (
            "current",
            datetime(2026, 7, 29, 13, 59, tzinfo=SHANGHAI),
            date(2026, 7, 28),
        ),
        (
            "last_completed",
            datetime(2026, 7, 29, 14, 29, tzinfo=SHANGHAI),
            date(2026, 7, 27),
        ),
        (
            "last_completed",
            datetime(2026, 7, 29, 14, 30, tzinfo=SHANGHAI),
            date(2026, 7, 28),
        ),
    ],
)
def test_daily_job_scope_freezes_exactly_one_business_date_item(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    instant: datetime,
    expected_date: date,
) -> None:
    data_root = (tmp_path / "daily-scope-api").resolve()
    _prepare_daily_selection(data_root)
    monkeypatch.setattr(
        platform_api,
        "_daily_now",
        lambda: instant,
        raising=False,
    )
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        daily_execution_backend=_idle_daily_backend(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        created = client.post(
            "/api/v1/platform/daily-jobs",
            headers=_headers(csrf=csrf, key=f"daily-scope-{scope}"),
            json={"expected_record_version": 0, "scope": scope},
        )

        assert created.status_code == 200
        body = created.json()
        assert body["daily_scope"]["business_date"] == expected_date.isoformat()
        items = app.state.repository.list_items(body["job"]["job_id"])
        assert len(items) == 1
        assert items[0].waybill_number == f"daily:{expected_date.isoformat()}"


def test_daily_job_rejects_arbitrary_or_unknown_date_scope(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "daily-scope-rejections").resolve()
    _prepare_daily_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        daily_execution_backend=_idle_daily_backend(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        arbitrary = client.post(
            "/api/v1/platform/daily-jobs",
            headers=_headers(csrf=csrf, key="daily-arbitrary-date"),
            json={
                "expected_record_version": 0,
                "scope": "current",
                "business_date": "2026-01-01",
            },
        )
        unknown = client.post(
            "/api/v1/platform/daily-jobs",
            headers=_headers(csrf=csrf, key="daily-unknown-scope"),
            json={
                "expected_record_version": 0,
                "scope": "arbitrary",
            },
        )

        assert arbitrary.status_code == 422
        assert unknown.status_code == 422


def test_daily_job_requires_current_build_settlement_validation(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "daily-settlement-gate").resolve()
    _prepare_daily_selection(data_root)
    validator = FakeContractValidator(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        contract_validator=validator,
        daily_execution_backend=_idle_daily_backend(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert (
            state["available_actions"]["create_daily_job"]["enabled"]
            is False
        )

        rejected = client.post(
            "/api/v1/platform/daily-jobs",
            headers=_headers(
                csrf=csrf,
                key="daily-without-settlement-validation",
            ),
            json={"expected_record_version": 0, "scope": "current"},
        )

        assert rejected.status_code == 409
        assert (
            rejected.json()["error"]["code"]
            == "daily_settlement_gate_required"
        )
        assert app.state.repository.list_jobs() == ()


def test_daily_job_then_bound_shadow_window_creates_one_fixed_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "daily-capture-api").resolve()
    selected_sha256 = _prepare_daily_selection(data_root)
    _prepare_settlement_selection(data_root)
    runtime = FakeBrowserRuntime()
    backend = _idle_daily_backend()
    daily_now = {
        "value": datetime(
            2026,
            7,
            29,
            14,
            29,
            tzinfo=SHANGHAI,
        )
    }
    monkeypatch.setattr(
        platform_api,
        "_daily_now",
        lambda: daily_now["value"],
        raising=False,
    )
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        daily_execution_backend=backend,
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        created_job = client.post(
            "/api/v1/platform/daily-jobs",
            headers=_headers(csrf=csrf, key="daily-job-create"),
            json={
                "expected_record_version": 0,
                "scope": "last_completed",
            },
        )
        assert created_job.status_code == 200
        created_body = created_job.json()
        job = created_body["job"]
        assert job["task_type"] == "daily"
        assert job["current_stage"] == "daily.list_page"
        assert len(job["job_id"]) == 32
        assert created_body["daily_scope"]["business_date"] == "2026-07-27"

        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="daily-capture-window"),
            json={
                "purpose": "production_shadow",
                "job_id": job["job_id"],
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="daily-capture-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="daily-capture-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]
        daily_now["value"] = datetime(
            2026,
            7,
            29,
            14,
            31,
            tzinfo=SHANGHAI,
        )

        capture = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(csrf=csrf, key="daily-capture-start"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert capture.status_code == 200
        result = capture.json()
        assert result["created"] is True
        assert result["job_id"] == job["job_id"]
        assert result["invocation_id"] == job["job_id"]
        assert result["next_stage"] == "daily.list_page"
        assert runtime.prepare_daily_count == 1
        invocation = app.state.daily_invocation_store.get_by_job(
            job["job_id"]
        )
        assert invocation.job_id == job["job_id"]
        assert invocation.invocation_id == job["job_id"]
        assert invocation.access_window_id == window["access_window_id"]
        assert invocation.request.receive_place == "榆林"
        assert invocation.request.business_date == date(2026, 7, 27)
        assert (
            invocation.request.source_contract_sha256
            == selected_sha256
        )
        # The first formal page must exactly reuse the bounded browser probe.
        # A different page size would discard the probe and fail closed before
        # any durable daily snapshot can be created.
        assert invocation.request.page_size == 5

        replay = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(csrf=csrf, key="daily-capture-start"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )
        assert replay.status_code == 200
        assert replay.json()["idempotent_replay"] is True
        assert runtime.prepare_daily_count == 1

        changed_replay = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(csrf=csrf, key="daily-capture-start"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": (
                    returned["record_version"] + 1
                ),
            },
        )
        assert changed_replay.status_code == 409
        assert (
            changed_replay.json()["error"]["code"]
            == "idempotency_key_reused"
        )
        assert runtime.prepare_daily_count == 1

        forbidden_input = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(csrf=csrf, key="daily-capture-forbidden"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
                "url": "https://example.invalid/",
                "account": "forbidden",
                "receive_place": "arbitrary",
            },
        )
        assert forbidden_input.status_code == 422
    assert backend.closed is True


def test_daily_access_window_rollover_api_preserves_paused_invocation(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "daily-rollover-api").resolve()
    _prepare_daily_selection(data_root)
    _prepare_settlement_selection(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        data_root=data_root,
        daily_execution_backend=_idle_daily_backend(),
    )
    now = datetime.now(UTC)
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        created = client.post(
            "/api/v1/platform/daily-jobs",
            headers=_headers(
                csrf=csrf,
                key="daily-rollover-api-job",
            ),
            json={
                "expected_record_version": 0,
                "scope": "current",
            },
        )
        assert created.status_code == 200
        job_id = str(created.json()["job"]["job_id"])
        job_item = app.state.repository.list_items(job_id)[0]
        business_date = date.fromisoformat(
            job_item.waybill_number.removeprefix("daily:")
        )
        old_window, replayed = (
            app.state.platform_access_repository.issue(
                purpose=AccessPurpose.PRODUCTION_SHADOW,
                job_id=job_id,
                session_id="chengfeng-shadow-v1",
                build_sha256=BUILD_SHA256,
                duration_minutes=60,
                legacy_idle_confirmed=True,
                no_settlement_or_payment_confirmed=True,
                same_account_session_risk_accepted=True,
                run_mode="shadow",
                idempotency_key="daily-rollover-api-old",
                request_hash=hashlib.sha256(
                    b"daily-rollover-api-old"
                ).hexdigest(),
                now=now - timedelta(hours=2),
            )
        )
        assert replayed is False
        selected_daily = app.state.selected_daily_contract
        selected_settlement = app.state.selected_settlement_contract
        assert selected_daily is not None
        assert selected_settlement is not None
        invocation = app.state.daily_invocation_store.create(
            job_id=job_id,
            access_window_id=old_window.access_window_id,
            authority=DailyInvocationAuthority(
                source_build_sha256=BUILD_SHA256,
                daily_contract_sha256=(
                    selected_daily.manifest.canonical_sha256
                ),
                daily_contract_file_sha256=(
                    selected_daily.contract_file_sha256
                ),
                daily_contract_selection_sha256=(
                    selected_daily.selection_sha256
                ),
                settlement_contract_sha256=(
                    selected_settlement.manifest.canonical_sha256
                ),
                settlement_contract_selection_sha256=(
                    selected_settlement.selection_sha256
                ),
            ),
            request=DailyCaptureRequest(
                invocation_id=job_id,
                business_date=business_date,
                receive_place="姒嗘灄",
                now=datetime.now(SHANGHAI),
                source_contract_sha256=(
                    selected_daily.manifest.canonical_sha256
                ),
            ),
            now=now - timedelta(hours=2),
        )
        with app.state.sqlite_runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = 'paused',
                        record_version = record_version + 1
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
            connection.execute(
                text(
                    """
                    UPDATE work_items
                    SET status = 'waiting_external',
                        waiting_reason_kind = 'external',
                        waiting_reason = 'access_window_expired',
                        diagnostic_code =
                            'CF-DAILY-ACCESS-WINDOW-INVALID',
                        record_version = record_version + 1
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": job_id},
            )
        _old_grant, old_record_version = (
            app.state.platform_access_repository.get_with_version(
                old_window.access_window_id
            )
        )
        app.state.platform_access_repository.retire(
            access_window_id=old_window.access_window_id,
            expected_record_version=old_record_version,
            now=now,
        )
        replacement, replayed = (
            app.state.platform_access_repository.issue(
                purpose=AccessPurpose.PRODUCTION_SHADOW,
                job_id=job_id,
                session_id="chengfeng-shadow-v1",
                build_sha256=BUILD_SHA256,
                duration_minutes=60,
                legacy_idle_confirmed=True,
                no_settlement_or_payment_confirmed=True,
                same_account_session_risk_accepted=True,
                run_mode="shadow",
                idempotency_key="daily-rollover-api-new",
                request_hash=hashlib.sha256(
                    b"daily-rollover-api-new"
                ).hexdigest(),
                now=now,
            )
        )
        assert replayed is False
        payload = {
            "access_window_id": replacement.access_window_id,
            "expected_record_version": invocation.record_version,
        }

        rebound = client.post(
            f"/api/v1/platform/daily-captures/{job_id}/access-window",
            headers=_headers(
                csrf=csrf,
                key="daily-rollover-api-rebind",
            ),
            json=payload,
        )

        assert rebound.status_code == 200
        body = rebound.json()
        assert body["idempotent_replay"] is False
        assert body["job"]["job_status"] == "paused"
        assert body["capture"] == {
            "access_window_id": replacement.access_window_id,
            "record_version": invocation.record_version + 1,
            "status": "ready",
        }
        assert (
            app.state.daily_invocation_store.access_window_lineage(
                job_id
            ).access_window_ids
            == (
                old_window.access_window_id,
                replacement.access_window_id,
            )
        )

        exact_replay = client.post(
            f"/api/v1/platform/daily-captures/{job_id}/access-window",
            headers=_headers(
                csrf=csrf,
                key="daily-rollover-api-rebind",
            ),
            json=payload,
        )
        assert exact_replay.status_code == 200
        assert exact_replay.json()["idempotent_replay"] is True

        forbidden = client.post(
            f"/api/v1/platform/daily-captures/{job_id}/access-window",
            headers=_headers(
                csrf=csrf,
                key="daily-rollover-api-forbidden",
            ),
            json={
                **payload,
                "platform_url": "https://example.invalid",
            },
        )
        assert forbidden.status_code == 422


@pytest.mark.parametrize(
    "invalid_items",
    ["missing", "duplicate", "malformed"],
)
def test_daily_capture_fails_closed_for_invalid_frozen_target_items(
    tmp_path: Path,
    invalid_items: str,
) -> None:
    data_root = (tmp_path / f"daily-invalid-item-{invalid_items}").resolve()
    _prepare_daily_selection(data_root)
    runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        daily_execution_backend=_idle_daily_backend(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        job, window, returned = _daily_job_and_returned_window(
            client,
            csrf=csrf,
            initial_record_version=int(initial["record_version"]),
            key_prefix=f"daily-invalid-{invalid_items}",
        )
        job_id = str(job["job_id"])
        with app.state.sqlite_runtime.engine.begin() as connection:
            if invalid_items == "missing":
                connection.execute(
                    text("DELETE FROM work_items WHERE job_id = :job_id"),
                    {"job_id": job_id},
                )
            elif invalid_items == "malformed":
                connection.execute(
                    text(
                        "UPDATE work_items "
                        "SET waybill_number = 'daily:2026-7-29' "
                        "WHERE job_id = :job_id"
                    ),
                    {"job_id": job_id},
                )
            else:
                connection.execute(
                    text(
                        """
                        INSERT INTO work_items (
                            work_item_id, job_id, record_version,
                            waybill_number, vehicle_number, status,
                            current_stage, item_index, attempt_count,
                            download_complete, loading_ocr_complete,
                            unloading_ocr_complete, ready_sequence
                        )
                        SELECT
                            'duplicate-daily-work-item-001', job_id,
                            record_version, waybill_number, vehicle_number,
                            status, current_stage, item_index + 1,
                            attempt_count, download_complete,
                            loading_ocr_complete, unloading_ocr_complete,
                            ready_sequence
                        FROM work_items
                        WHERE job_id = :job_id
                        """
                    ),
                    {"job_id": job_id},
                )

        capture = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(
                csrf=csrf,
                key=f"daily-invalid-{invalid_items}-capture",
            ),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert capture.status_code == 409
        assert capture.json()["error"]["code"] == "daily_capture_job_invalid"
        assert runtime.prepare_daily_count == 0


@pytest.mark.parametrize(
    "job_status",
    [
        "created",
        "running",
        "waiting_resource",
        "waiting_user",
        "waiting_external",
        "retry_wait",
        "pause_requested",
        "paused",
        "cancel_requested",
        "cancelled",
        "succeeded",
        "failed",
    ],
)
def test_daily_capture_rejects_non_startable_job_before_browser_call(
    tmp_path: Path,
    job_status: str,
) -> None:
    data_root = (tmp_path / f"daily-job-state-{job_status}").resolve()
    _prepare_daily_selection(data_root)
    runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        daily_execution_backend=_idle_daily_backend(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        job, window, returned = _daily_job_and_returned_window(
            client,
            csrf=csrf,
            initial_record_version=int(initial["record_version"]),
            key_prefix=f"daily-job-state-{job_status}",
        )
        with app.state.sqlite_runtime.engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE jobs SET status = :status "
                    "WHERE job_id = :job_id"
                ),
                {"status": job_status, "job_id": job["job_id"]},
            )

        session_state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert (
            session_state["available_actions"]["start_daily_capture"][
                "enabled"
            ]
            is False
        )
        capture = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(
                csrf=csrf,
                key=f"daily-job-state-{job_status}-capture",
            ),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert capture.status_code == 409
        assert capture.json()["error"]["code"] == "daily_capture_job_invalid"
        assert runtime.prepare_daily_count == 0


@pytest.mark.parametrize(
    ("target", "column", "value"),
    [
        ("job", "current_stage", "daily.detail"),
        ("item", "status", "running"),
        ("item", "status", "waiting_resource"),
        ("item", "status", "waiting_user"),
        ("item", "status", "waiting_external"),
        ("item", "status", "retry_wait"),
        ("item", "status", "cancelled"),
        ("item", "status", "succeeded"),
        ("item", "status", "failed"),
        ("item", "current_stage", "daily.detail"),
    ],
)
def test_daily_capture_rejects_non_startable_item_before_browser_call(
    tmp_path: Path,
    target: str,
    column: str,
    value: str,
) -> None:
    case_id = f"{target}-{column}-{value}".replace(".", "-")
    data_root = (tmp_path / f"daily-item-state-{case_id}").resolve()
    _prepare_daily_selection(data_root)
    runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        daily_execution_backend=_idle_daily_backend(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        job, window, returned = _daily_job_and_returned_window(
            client,
            csrf=csrf,
            initial_record_version=int(initial["record_version"]),
            key_prefix=f"daily-item-state-{case_id}",
        )
        table = "jobs" if target == "job" else "work_items"
        with app.state.sqlite_runtime.engine.begin() as connection:
            if table == "jobs":
                connection.execute(
                    text(
                        "UPDATE jobs SET current_stage = :value "
                        "WHERE job_id = :job_id"
                    ),
                    {"value": value, "job_id": job["job_id"]},
                )
            elif column == "status":
                connection.execute(
                    text(
                        "UPDATE work_items SET status = :value "
                        "WHERE job_id = :job_id"
                    ),
                    {"value": value, "job_id": job["job_id"]},
                )
            else:
                connection.execute(
                    text(
                        "UPDATE work_items SET current_stage = :value "
                        "WHERE job_id = :job_id"
                    ),
                    {"value": value, "job_id": job["job_id"]},
                )

        session_state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert (
            session_state["available_actions"]["start_daily_capture"][
                "enabled"
            ]
            is False
        )
        capture = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(
                csrf=csrf,
                key=f"daily-item-state-{case_id}-capture",
            ),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert capture.status_code == 409
        assert capture.json()["error"]["code"] == "daily_capture_job_invalid"
        assert runtime.prepare_daily_count == 0


def test_daily_preflight_failure_does_not_create_invocation_or_review_item(
    tmp_path: Path,
) -> None:
    class FailingDailyPreflight(FakeBrowserRuntime):
        def prepare_daily(self) -> dict[str, object]:
            self.prepare_daily_count += 1
            raise BrowserRuntimeError(
                "Authorization=secret C:\\private\\browser-profile",
                code="browser_daily_response_contract_changed",
            )

    data_root = (tmp_path / "failed-daily-capture-api").resolve()
    _prepare_daily_selection(data_root)
    runtime = FailingDailyPreflight()
    backend = _idle_daily_backend()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        daily_execution_backend=backend,
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        job = client.post(
            "/api/v1/platform/daily-jobs",
            headers=_headers(csrf=csrf, key="failed-daily-job"),
            json={"expected_record_version": 0},
        ).json()["job"]
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="failed-daily-window"),
            json={
                "purpose": "production_shadow",
                "job_id": job["job_id"],
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="failed-daily-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="failed-daily-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]
        failed = client.post(
            "/api/v1/platform/daily-captures",
            headers=_headers(csrf=csrf, key="failed-daily-start"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )
        assert failed.status_code == 409
        assert failed.json()["error"]["code"] == "daily_capture_preflight_failed"
        assert "Authorization" not in failed.text
        with pytest.raises(Exception, match="does not exist"):
            app.state.daily_invocation_store.get_by_job(job["job_id"])
        item = client.get(
            f"/api/v1/jobs/{job['job_id']}/items",
            headers=_headers(),
        ).json()["items"][0]
        assert item["status"] == "queued"
        assert item["business_outcome"] is None
        assert item["review_reason"] is None
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["browser_control_mode"] == "idle"
        assert state["browser_lifecycle"] == "ready"
        assert runtime.running is True
    assert backend.closed is True


def test_daily_contract_discovery_freezes_selects_and_replays_without_browser(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    data_root = (tmp_path / "daily-contract-data").resolve()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="daily-contract-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-daily-contract-discovery",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="daily-contract-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="daily-contract-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]
        ready_state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert (
            ready_state["available_actions"]["discover_daily_contract"][
                "enabled"
            ]
            is True
        )

        discovered = client.post(
            "/api/v1/platform/daily-contract-discovery",
            headers=_headers(csrf=csrf, key="daily-contract-run"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert discovered.status_code == 200
        result = discovered.json()
        assert result["platform_session"]["browser_lifecycle"] == "stopped"
        assert result["daily_contract"]["discovery_observation_count"] == 1
        assert result["daily_contract"]["idempotent_replay"] is False
        assert runtime.prepare_daily_count == 1
        assert runtime.running is False
        assert set(result["daily_contract"]) == {
            "discovery_evidence_sha256",
            "discovery_observation_count",
            "contract_canonical_sha256",
            "contract_file_sha256",
            "freeze_evidence_sha256",
            "selection_sha256",
            "idempotent_replay",
        }
        assert (
            data_root
            / "daily-platform-read-contract"
            / "active-candidate.json"
        ).is_file()
        discovery_path = (
            data_root
            / "platform-contract-discovery"
            / (
                result["daily_contract"]["discovery_evidence_sha256"]
                + ".json"
            )
        )
        evidence = json.loads(discovery_path.read_text(encoding="utf-8"))
        assert evidence["observation_count"] == 1
        assert evidence["excluded_data"] == [
            "credential_material",
            "request_header_values",
            "response_header_values",
            "session_material",
            "request_values",
            "response_values",
            "signed_image_paths",
            "raw_responses",
        ]
        serialized = json.dumps(result, sort_keys=True)
        assert "queryOrderItemListPC" not in serialized
        assert "loadStartTime" not in serialized

        replay = client.post(
            "/api/v1/platform/daily-contract-discovery",
            headers=_headers(csrf=csrf, key="daily-contract-run"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )
        assert replay.status_code == 200
        assert replay.json()["daily_contract"]["idempotent_replay"] is True
        assert runtime.prepare_daily_count == 1
        assert runtime.running is False


def test_daily_contract_discovery_rejects_wrong_window_and_unknown_input(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=(tmp_path / "daily-contract-rejections").resolve(),
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        formal = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="daily-wrong-window"),
            json={
                "purpose": "formal_locked_set",
                "job_id": "loop9-not-daily-discovery",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        wrong_window = client.post(
            "/api/v1/platform/daily-contract-discovery",
            headers=_headers(csrf=csrf, key="daily-wrong-purpose"),
            json={
                "access_window_id": formal["access_window_id"],
                "expected_record_version": 1,
            },
        )
        assert wrong_window.status_code == 409
        assert runtime.prepare_daily_count == 0

        unknown_input = client.post(
            "/api/v1/platform/daily-contract-discovery",
            headers=_headers(csrf=csrf, key="daily-unknown-input"),
            json={
                "access_window_id": formal["access_window_id"],
                "expected_record_version": 1,
                "url": "https://example.invalid/",
                "receive_place": "must-not-be-accepted",
            },
        )
        assert unknown_input.status_code == 422
        assert runtime.prepare_daily_count == 0


def test_failed_daily_contract_discovery_closes_and_consumes_without_leaking(
    tmp_path: Path,
) -> None:
    class FailingDailyRuntime(FakeBrowserRuntime):
        def prepare_daily(self) -> dict[str, object]:
            self.prepare_daily_count += 1
            changed = _daily_observation()
            changed["response_fields"] = [
                {
                    "path": "$.data.records[].waybillId",
                    "type": "integer",
                },
                {"path": "$.data.total", "type": "integer"},
            ]
            raise BrowserRuntimeError(
                "Authorization=secret and C:\\private\\profile must not leak",
                code="browser_daily_response_contract_changed",
                safe_discovery=(changed,),
            )

    runtime = FailingDailyRuntime()
    data_root = (tmp_path / "failed-daily-contract").resolve()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="failed-daily-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-failed-daily-discovery",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="failed-daily-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="failed-daily-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]

        failed = client.post(
            "/api/v1/platform/daily-contract-discovery",
            headers=_headers(csrf=csrf, key="failed-daily-run"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert failed.status_code == 409
        assert failed.json()["error"]["code"] == "daily_contract_discovery_failed"
        assert "Authorization" not in failed.text
        assert "private" not in failed.text
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["browser_lifecycle"] == "stopped"
        assert state["access_window"]["consumed_at"] is not None
        assert runtime.running is False
        assert runtime.prepare_daily_count == 1
        logs = client.get(
            "/api/v1/diagnostics/logs?limit=100",
            headers=_headers(),
        ).json()["events"]
        failure_logs = [
            event
            for event in logs
            if event["event_code"] == "daily_contract_discovery_failed"
        ]
        assert len(failure_logs) == 1
        assert (
            failure_logs[0]["diagnostic_code"]
            == "browser_daily_response_contract_changed"
        )
        assert "Authorization" not in json.dumps(failure_logs)
        assert "private" not in json.dumps(failure_logs)
        evidence_paths = list(
            (data_root / "platform-contract-discovery").glob("*.json")
        )
        assert len(evidence_paths) == 1
        evidence_text = evidence_paths[0].read_text(encoding="utf-8")
        assert "$.data.records[].waybillId" in evidence_text
        assert "Authorization" not in evidence_text
        assert "private" not in evidence_text


def test_unexpected_daily_discovery_exception_still_closes_and_consumes(
    tmp_path: Path,
) -> None:
    class UnexpectedDailyRuntime(FakeBrowserRuntime):
        def prepare_daily(self) -> dict[str, object]:
            self.prepare_daily_count += 1
            raise ValueError("unexpected private implementation defect")

    runtime = UnexpectedDailyRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=(tmp_path / "unexpected-daily-contract").resolve(),
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="unexpected-daily-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-unexpected-daily",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="unexpected-daily-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="unexpected-daily-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]

        failed = client.post(
            "/api/v1/platform/daily-contract-discovery",
            headers=_headers(csrf=csrf, key="unexpected-daily-run"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert failed.status_code == 500
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["browser_lifecycle"] == "stopped"
        assert state["access_window"]["consumed_at"] is not None
        assert runtime.running is False
        assert runtime.prepare_daily_count == 1


def test_daily_contract_discovery_does_not_publish_before_cleanup_succeeds(
    tmp_path: Path,
) -> None:
    class FailingCleanupRuntime(FakeBrowserRuntime):
        fail_next_close = True

        def close(self) -> None:
            super().close()
            if self.fail_next_close:
                self.fail_next_close = False
                raise BrowserRuntimeError(
                    "Authorization=secret C:\\private\\browser-profile",
                    code="browser_close_failed",
                )

    runtime = FailingCleanupRuntime()
    data_root = (tmp_path / "daily-cleanup-publication").resolve()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="cleanup-publication-window"),
            json={
                "purpose": "contract_discovery",
                "job_id": "loop9-cleanup-publication",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="cleanup-publication-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="cleanup-publication-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]

        failed = client.post(
            "/api/v1/platform/daily-contract-discovery",
            headers=_headers(csrf=csrf, key="cleanup-publication-run"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert failed.status_code == 409
        assert (
            failed.json()["error"]["code"]
            == "daily_contract_discovery_cleanup_failed"
        )
        assert "Authorization" not in failed.text
        assert "private" not in failed.text
        assert runtime.prepare_daily_count == 1
        assert runtime.running is False
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["access_window"]["consumed_at"] is not None
        assert not (
            data_root
            / "daily-platform-read-contract"
            / "active-candidate.json"
        ).exists()
        assert any(
            (data_root / "platform-contract-discovery").glob("*.json")
        )
        assert any(
            (data_root / "daily-platform-read-contract").glob("*.json")
        )
        with pytest.raises(
            DailyContractSelectionError,
            match="selection is unavailable",
        ):
            load_selected_daily_read_contract(data_root)


def test_selected_contract_validation_uses_automated_control_and_consumes_window(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "validation-data").resolve()
    runtime = FakeBrowserRuntime()
    validator = FakeContractValidator(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        contract_validator=validator,
    )
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert initial["contract_candidate_selected"] is True
        created = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="validation-window"),
            json={
                "purpose": "formal_locked_set",
                "job_id": "loop9-read-contract-validation",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        )
        assert created.status_code == 200
        access_window_id = created.json()["access_window"]["access_window_id"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="validation-login"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="validation-return"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]
        assert returned["browser_control_mode"] == "idle"

        validated = client.post(
            "/api/v1/platform/contract-validation",
            headers=_headers(csrf=csrf, key="validation-run"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": returned["record_version"],
            },
        )
        assert validated.status_code == 200
        result = validated.json()
        assert result["platform_session"]["browser_lifecycle"] == "stopped"
        assert result["contract_validation"]["image_count"] == 2
        assert result["contract_validation"]["idempotent_replay"] is False
        assert runtime.prepare_automated_count == 1
        assert runtime.running is False
        assert len(validator.calls) == 1

        replay = client.post(
            "/api/v1/platform/contract-validation",
            headers=_headers(csrf=csrf, key="validation-run"),
            json={
                "access_window_id": access_window_id,
                "expected_record_version": returned["record_version"],
            },
        )
        assert replay.status_code == 200
        assert replay.json()["contract_validation"]["idempotent_replay"] is True
        assert len(validator.calls) == 1


def test_settlement_view_probe_uses_returned_control_and_keeps_window_open(
    tmp_path: Path,
) -> None:
    runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
    )
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        created = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="view-probe-window"),
            json={
                "purpose": "formal_locked_set",
                "job_id": "loop9-settlement-view-probe",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="view-probe-login"),
            json={
                "access_window_id": created["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="view-probe-return"),
            json={
                "access_window_id": created["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]

        response = client.post(
            "/api/v1/platform/diagnostics/settlement-views",
            headers=_headers(csrf=csrf, key="view-probe-run"),
            json={
                "access_window_id": created["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert response.status_code == 200
        result = response.json()
        assert result["settlement_views"] == {
            "settlement": {
                "total_count": 0,
                "list_length": 0,
            },
            "credit": {
                "total_count": 137,
                "list_length": 20,
            },
            "page_number": 1,
            "page_size": 20,
            "response_structure_sha256": {
                "settlement": "a" * 64,
                "credit": "b" * 64,
            },
        }
        assert result["platform_session"]["browser_control_mode"] == "idle"
        assert result["platform_session"]["runtime_running"] is True
        current = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert current["access_window"]["consumed_at"] is None
        assert runtime.settlement_view_probe_count == 1


def test_unexpected_contract_validation_exception_still_closes_and_consumes(
    tmp_path: Path,
) -> None:
    class UnexpectedValidator(FakeContractValidator):
        def validate(
            self,
            *,
            authority: BrowserCommandAuthority,
            access_window_id: str,
            build_sha256: str,
            settlement_probe: SettlementListProbe | None = None,
        ) -> LiveContractValidationResult:
            del authority, access_window_id, build_sha256, settlement_probe
            raise ValueError("unexpected private implementation defect")

    data_root = (tmp_path / "unexpected-validation").resolve()
    runtime = FakeBrowserRuntime()
    validator = UnexpectedValidator(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        contract_validator=validator,
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="unexpected-validation-window"),
            json={
                "purpose": "formal_locked_set",
                "job_id": "loop9-unexpected-validation",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="unexpected-validation-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="unexpected-validation-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]

        failed = client.post(
            "/api/v1/platform/contract-validation",
            headers=_headers(csrf=csrf, key="unexpected-validation-run"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert failed.status_code == 500
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["browser_lifecycle"] == "stopped"
        assert state["access_window"]["consumed_at"] is not None
        assert runtime.running is False
        assert runtime.prepare_automated_count == 1


def test_request_audit_validation_error_is_safe_409_and_closes(
    tmp_path: Path,
) -> None:
    class AuditErrorValidator(FakeContractValidator):
        def validate(
            self,
            *,
            authority: BrowserCommandAuthority,
            access_window_id: str,
            build_sha256: str,
            settlement_probe: SettlementListProbe | None = None,
        ) -> LiveContractValidationResult:
            del authority, access_window_id, build_sha256, settlement_probe
            raise PlatformReadAuditError(
                "private audit chain detail"
            )

    data_root = (tmp_path / "audit-error-validation").resolve()
    runtime = FakeBrowserRuntime()
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        contract_validator=AuditErrorValidator(data_root),
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        window = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="audit-error-window"),
            json={
                "purpose": "formal_locked_set",
                "job_id": "loop9-audit-error-validation",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="audit-error-login"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="audit-error-return"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]

        failed = client.post(
            "/api/v1/platform/contract-validation",
            headers=_headers(csrf=csrf, key="audit-error-run"),
            json={
                "access_window_id": window["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )

        assert failed.status_code == 409
        assert (
            failed.json()["error"]["code"]
            == "read_contract_validation_failed"
        )
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["browser_lifecycle"] == "stopped"
        assert state["access_window"]["consumed_at"] is not None
        assert runtime.running is False
        logs = client.get(
            "/api/v1/diagnostics/logs?limit=100",
            headers=_headers(),
        ).json()["events"]
        audit_events = [
            event
            for event in logs
            if event["event_code"] == "formal_read_audit_invalid"
        ]
        assert len(audit_events) == 1
        serialized = json.dumps(audit_events, sort_keys=True)
        assert "private audit chain detail" not in serialized


@pytest.mark.parametrize(
    ("prepare_error_code", "expected_diagnostic_code"),
    [
        (
            "browser_read_login_required",
            "CF-BROWSER-SESSION-CONTINUITY-MISSING",
        ),
        (
            "browser_session_fixed_values_rejected",
            "CF-BROWSER-SESSION-FIXED-VALUES-REJECTED",
        ),
        (
            "browser_session_fixed_values_unavailable",
            "CF-BROWSER-SESSION-FIXED-VALUES-UNAVAILABLE",
        ),
        (
            "browser_session_cache_query_rejected",
            "CF-BROWSER-SESSION-CACHE-QUERY-REJECTED",
        ),
        (
            "browser_session_cache_query_unavailable",
            "CF-BROWSER-SESSION-CACHE-QUERY-UNAVAILABLE",
        ),
        (
            "browser_session_list_body_rejected",
            "CF-BROWSER-SESSION-LIST-BODY-REJECTED",
        ),
        (
            "browser_session_list_body_unavailable",
            "CF-BROWSER-SESSION-LIST-BODY-UNAVAILABLE",
        ),
        (
            "browser_session_list_body_mismatch",
            "CF-BROWSER-SESSION-LIST-BODY-MISMATCH",
        ),
        (
            "browser_prepare_automated_failed",
            "CF-BROWSER-AUTOMATED-ISOLATION-FAILED",
        ),
        (
            "browser_session_settlement_route_unavailable",
            "CF-BROWSER-SETTLEMENT-ROUTE-UNAVAILABLE",
        ),
    ],
)
def test_failed_contract_validation_closes_browser_and_consumes_window(
    tmp_path: Path,
    prepare_error_code: str,
    expected_diagnostic_code: str,
) -> None:
    data_root = (tmp_path / "failed-validation-data").resolve()
    runtime = FakeBrowserRuntime(
        prepare_error_code=prepare_error_code,
    )
    validator = FakeContractValidator(data_root)
    app = _app(
        tmp_path,
        enabled=True,
        browser_runtime=runtime,
        data_root=data_root,
        contract_validator=validator,
    )
    with TestClient(app) as client:
        csrf = str(
            client.get("/api/v1/session", headers=_headers()).json()[
                "csrf_token"
            ]
        )
        initial = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        created = client.post(
            "/api/v1/platform/access-windows",
            headers=_headers(csrf=csrf, key="failed-window"),
            json={
                "purpose": "formal_locked_set",
                "job_id": "loop9-read-contract-validation",
                "duration_minutes": 60,
                "legacy_idle_confirmed": True,
                "no_settlement_or_payment_confirmed": True,
                "same_account_session_risk_accepted": True,
                "expected_record_version": 0,
            },
        ).json()["access_window"]
        started = client.post(
            "/api/v1/platform/session/human-login/start",
            headers=_headers(csrf=csrf, key="failed-login"),
            json={
                "access_window_id": created["access_window_id"],
                "expected_record_version": initial["record_version"],
            },
        ).json()["platform_session"]
        returned = client.post(
            "/api/v1/platform/session/human-login/return",
            headers=_headers(csrf=csrf, key="failed-return"),
            json={
                "access_window_id": created["access_window_id"],
                "expected_record_version": started["record_version"],
            },
        ).json()["platform_session"]

        failed = client.post(
            "/api/v1/platform/contract-validation",
            headers=_headers(csrf=csrf, key="failed-run"),
            json={
                "access_window_id": created["access_window_id"],
                "expected_record_version": returned["record_version"],
            },
        )
        assert failed.status_code == 409
        assert failed.json()["error"]["code"] == "read_contract_validation_failed"
        state = client.get(
            "/api/v1/platform/session",
            headers=_headers(),
        ).json()
        assert state["browser_lifecycle"] == "stopped"
        assert state["access_window"]["consumed_at"] is not None
        assert runtime.running is False
        assert runtime.prepare_automated_count == 1
        logs = client.get(
            "/api/v1/diagnostics/logs?limit=100",
            headers=_headers(),
        ).json()["events"]
        browser_failures = [
            event
            for event in logs
            if event["event_code"] == "formal_read_browser_failed"
        ]
        assert len(browser_failures) == 1
        assert browser_failures[0]["diagnostic_code"] == expected_diagnostic_code
        serialized = json.dumps(browser_failures, sort_keys=True)
        assert "sensitive runtime detail" not in serialized


def test_platform_api_rejects_unknown_fields_and_has_no_credential_surface(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path, enabled=True)
    schema = app.openapi()
    platform_path = schema["paths"]["/api/v1/platform/access-windows"]["post"]
    request_schema_name = platform_path["requestBody"]["content"]["application/json"]["schema"][
        "$ref"
    ].rsplit("/", 1)[-1]
    serialized = str(schema["components"]["schemas"][request_schema_name]).casefold()
    for forbidden in ("password", "cookie", "authorization", "username", "arbitrary_url"):
        assert forbidden not in serialized
