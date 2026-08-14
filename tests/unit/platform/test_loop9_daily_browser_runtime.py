from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.adapters.chengfeng.browser_runtime import (
    PREPARE_DAILY_WORKER_TIMEOUT_SECONDS,
    PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS,
    BrowserReadPayload,
    BrowserRuntimeError,
    IsolatedBrowserRuntime,
)
from dahe.adapters.chengfeng.daily_request_builder import (
    ChengfengDailyRequestBuilder,
)
from dahe.domain.daily.calendar import candidate_query_window
from tests.unit.platform.test_loop9_daily_manifest import daily_manifest


class _FakeProcess:
    is_alive = True

    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.requests: list[dict[str, object]] = []
        self.raw_requests: list[str] = []
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self.is_alive = False

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        del timeout_seconds
        self.raw_requests.append(line)
        request = json.loads(line)
        self.requests.append(request)
        response = dict(self.response)
        response["request_id"] = request["request_id"]
        return json.dumps(response)


class _TimeoutRecordingProcess(_FakeProcess):
    def __init__(self, response: dict[str, object]) -> None:
        super().__init__(response)
        self.timeouts: list[float] = []

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        self.timeouts.append(timeout_seconds)
        return super().request_line(line, timeout_seconds=timeout_seconds)


class _SequenceProcess(_FakeProcess):
    def __init__(self, responses: list[dict[str, object]]) -> None:
        if not responses:
            raise ValueError("at least one response is required")
        super().__init__(responses[0])
        self._responses = [dict(response) for response in responses]

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        del timeout_seconds
        self.raw_requests.append(line)
        request = json.loads(line)
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("unexpected browser worker request")
        response = self._responses.pop(0)
        response["request_id"] = request["request_id"]
        return json.dumps(response)


def _response(
    *,
    discovery: object = None,
    read_result: object = None,
    prepare_result: object = None,
) -> dict[str, object]:
    return {
        "schema_version": 9,
        "request_id": "replaced",
        "ok": True,
        "selected_browser": "msedge",
        "error_code": None,
        "discovery": discovery,
        "browser_open": True,
        "batch_result": None,
        "read_result": read_result,
        "prepare_result": prepare_result,
    }


def _runtime(
    tmp_path: Path,
    process: _FakeProcess,
    *,
    event_sink: Callable[[str, str], None] | None = None,
) -> IsolatedBrowserRuntime:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "runtime",
        event_sink=event_sink,
    )
    runtime._process = process  # type: ignore[assignment]
    runtime._selected_browser = "msedge"
    return runtime


def _daily_observation() -> dict[str, object]:
    return {
        "method": "POST",
        "origin": "https://pc.chengfengkuaiyun.com",
        "path": "/api/hz/orderItem/queryOrderItemListPC",
        "path_sha256": None,
        "query_keys": ["t"],
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
            {"path": "$.data.list[].id", "type": "integer"},
            {"path": "$.data.list[].sn", "type": "string"},
            {"path": "$.data.total", "type": "integer"},
        ],
    }


def _daily_freshness_evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "evidence_kind": "chengfeng_daily_freshness",
        "cache_disabled_during_reload": True,
        "ignore_cache_reload": True,
        "cache_refresh_count": 1,
        "fresh_query_response_observed": True,
        "page_count": 1,
        "route": "/wayBill",
        "contract_subject_code": "shanxi_guienbo",
        "contract_subject_confirmed": True,
    }


def _operational_probe() -> dict[str, object]:
    trace = {
        "schema_version": 1,
        "query_attempt_id": "1" * 32,
        "observed_request_count": 3,
        "approved_request_count": 1,
        "blocked_request_count": 2,
        "query_attempt_count": 1,
        "zero_retry_performed": False,
        "cache_refresh_count": 1,
        "page_count": 1,
        "request_method": "POST",
        "request_path": (
            "/api/order-center-server/app/clientOrderItem/"
            "queryWaitSettlementOrderItemListPC"
        ),
        "resource_type": "fetch",
        "response_status": 200,
        "response_byte_size": 128,
        "response_structure_sha256": "a" * 64,
        "duration_ms": 25,
    }
    return {
        "schema_version": 1,
        "probe_kind": "chengfeng_settlement_list",
        "operation": "list_waybills",
        "metrics": {
            "total_count": 2,
            "list_length": 2,
            "page_number": 1,
            "page_size": 30,
        },
        "response_structure_sha256": "a" * 64,
        "query_trace": trace,
    }


def test_parent_accepts_only_one_exact_sanitized_daily_structure(
    tmp_path: Path,
) -> None:
    process = _FakeProcess(_response(discovery=[_daily_observation()]))
    runtime = _runtime(tmp_path, process)

    observation = runtime.prepare_daily()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert observation["request_fields"][0] == {
        "path": "$.carNumber",
        "type": "string",
    }
    assert process.requests[0]["command"] == "prepare_daily"


def test_parent_reuses_one_daily_preparation_for_all_batches(
    tmp_path: Path,
) -> None:
    process = _FakeProcess(_response(discovery=[_daily_observation()]))
    runtime = _runtime(tmp_path, process)

    first = runtime.prepare_daily()
    second = runtime.prepare_daily()

    assert second == first
    assert [request["command"] for request in process.requests] == [
        "prepare_daily"
    ]


def test_parent_uses_dedicated_automated_daily_transition(
    tmp_path: Path,
) -> None:
    process = _FakeProcess(
        _response(
            discovery=[_daily_observation()],
            prepare_result={
                key: value
                for key, value in _daily_freshness_evidence().items()
                if key
                not in {
                    "contract_subject_code",
                    "contract_subject_confirmed",
                }
            },
        )
    )
    events: list[tuple[str, str]] = []
    runtime = _runtime(
        tmp_path,
        process,
        event_sink=lambda code, message: events.append((code, message)),
    )

    observation = runtime.prepare_daily_from_automated()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert (
        process.requests[0]["command"]
        == "prepare_daily_from_automated"
    )
    assert events[0][0] == "browser_read_freshness_verified"
    assert events[0][1].startswith(
        "scope=daily cache_refresh_count=1 page_count=1 route=/wayBill "
    )
    assert "settlement_prepare_count=0" in events[0][1]
    assert "settlement_list_request_count=0" in events[0][1]


def test_parent_reuses_cached_operational_daily_authority(
    tmp_path: Path,
) -> None:
    process = _FakeProcess(_response())
    runtime = _runtime(tmp_path, process)
    prepared = _daily_observation()
    runtime._active_read_scope = "daily"
    runtime._daily_preparation = dict(prepared)

    result = runtime.prepare_operational_daily()

    assert result == prepared
    assert result is not prepared
    assert process.requests == []


def test_parent_keeps_frozen_daily_worker_alive_after_page_closes(
    tmp_path: Path,
) -> None:
    response = _response()
    response["browser_open"] = False
    process = _FakeProcess(response)
    runtime = _runtime(tmp_path, process)
    runtime._active_read_scope = "daily"
    runtime._daily_preparation = _daily_observation()

    assert runtime.running is True
    assert process.closed is False
    assert [request["command"] for request in process.requests] == []


def test_parent_builds_operational_daily_authority_through_page_transition(
    tmp_path: Path,
) -> None:
    process = _FakeProcess(
        _response(
            discovery=[_daily_observation()],
            prepare_result=_daily_freshness_evidence(),
        )
    )
    runtime = _runtime(tmp_path, process)

    observation = runtime.prepare_operational_daily()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert [request["command"] for request in process.requests] == [
        "prepare_operational_daily",
    ]
    assert runtime._active_read_scope == "daily"


def test_operational_daily_budget_matches_subject_switch_preparation(
    tmp_path: Path,
) -> None:
    process = _TimeoutRecordingProcess(
        _response(
            discovery=[_daily_observation()],
            prepare_result=_daily_freshness_evidence(),
        )
    )
    runtime = _runtime(tmp_path, process)

    runtime.prepare_operational_daily()

    assert PREPARE_DAILY_WORKER_TIMEOUT_SECONDS == (
        PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS
    )
    assert process.timeouts == [PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS]


@pytest.mark.parametrize(
    "observation",
    [
        {**_daily_observation(), "path": "/api/hz/orderItem/delete"},
        {**_daily_observation(), "method": "GET"},
        {**_daily_observation(), "origin": "https://example.invalid"},
        {**_daily_observation(), "response_status": 302},
        {**_daily_observation(), "raw_response": {"private": "value"}},
    ],
)
def test_parent_rejects_unsafe_daily_structure(
    tmp_path: Path,
    observation: dict[str, object],
) -> None:
    runtime = _runtime(
        tmp_path,
        _FakeProcess(_response(discovery=[observation])),
    )

    with pytest.raises(BrowserRuntimeError, match="daily request structure"):
        runtime.prepare_daily()


def test_parent_preserves_only_sanitized_daily_change_structure(
    tmp_path: Path,
) -> None:
    observation = _daily_observation()
    observation["response_fields"] = [
        {"path": "$.data.records[].waybillId", "type": "integer"},
        {"path": "$.data.total", "type": "integer"},
    ]
    response = _response(discovery=[observation])
    response["ok"] = False
    response["error_code"] = "browser_daily_response_contract_changed"
    runtime = _runtime(tmp_path, _FakeProcess(response))

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime.prepare_daily()

    assert raised.value.code == "browser_daily_response_contract_changed"
    assert raised.value.safe_discovery == (observation,)


def test_parent_preserves_sanitized_daily_read_change_structure(
    tmp_path: Path,
) -> None:
    observation = _daily_observation()
    observation["response_fields"] = [
        *observation["response_fields"],
        {"path": "$.data.list[].optionalStatus", "type": "integer"},
    ]
    response = _response(discovery=[observation])
    response["ok"] = False
    response["error_code"] = "browser_daily_response_contract_changed"
    runtime = _runtime(tmp_path, _FakeProcess(response))
    request = ChengfengDailyRequestBuilder(daily_manifest()).list_waybills(
        query_window=candidate_query_window(
            date(2026, 7, 29),
            now=datetime.fromisoformat("2026-07-29T18:00:00+08:00"),
        ),
        receive_place="榆林",
        page_number=1,
        page_size=20,
    )

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime.read_daily(request)

    assert raised.value.code == "browser_daily_response_contract_changed"
    assert raised.value.safe_discovery == (observation,)


def test_parent_stages_and_reverifies_daily_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "dahe.adapters.chengfeng.browser_runtime.uuid4",
        lambda: SimpleNamespace(hex="daily1"),
    )
    content = b'{"code":200,"data":{"total":0,"list":[]}}'
    target = (
        tmp_path
        / "data"
        / "runtime"
        / "browser-worker"
        / "read-results"
        / "daily-daily1"
        / "payload.json"
    )
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    process = _FakeProcess(
        _response(
            read_result={
                "relative_path": "daily-daily1/payload.json",
                "sha256": hashlib.sha256(content).hexdigest(),
                "byte_size": len(content),
                "media_type": "application/json",
                "status_code": 200,
            }
        )
    )
    runtime = _runtime(tmp_path, process)
    request = ChengfengDailyRequestBuilder(daily_manifest()).list_waybills(
        query_window=candidate_query_window(
            date(2026, 7, 29),
            now=datetime.fromisoformat("2026-07-29T15:00:00+08:00"),
        ),
        receive_place="榆林",
        page_number=1,
        page_size=100,
    )

    result = runtime.read_daily(request)

    assert result == BrowserReadPayload(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        media_type="application/json",
        byte_size=len(content),
        status_code=200,
    )
    assert process.requests[0]["command"] == "read_daily_json"
    assert process.requests[0]["operation"] == "list_daily_waybills"
    assert "\\u6986\\u6797" in process.raw_requests[0]
    assert all(ord(character) < 128 for character in process.raw_requests[0])
    assert not target.exists()
