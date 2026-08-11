from __future__ import annotations

import json
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.browser_runtime import (
    PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS,
    BrowserRuntimeError,
    IsolatedBrowserRuntime,
    SettlementListProbe,
    SettlementQueryFlightRecord,
)


class _FakeProcess:
    is_alive = True

    def __init__(self, prepare_result: object) -> None:
        self.prepare_result = prepare_result
        self.requests: list[dict[str, object]] = []
        self.timeouts: list[float] = []

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        self.timeouts.append(timeout_seconds)
        request = json.loads(line)
        self.requests.append(request)
        return json.dumps(
            {
                "schema_version": 6,
                "request_id": request["request_id"],
                "ok": True,
                "selected_browser": "msedge",
                "error_code": None,
                "discovery": None,
                "browser_open": True,
                "batch_result": None,
                "read_result": None,
                "prepare_result": self.prepare_result,
            }
        )


class _StoppedFakeProcess(_FakeProcess):
    is_alive = False


def _runtime(tmp_path: Path, prepare_result: object) -> IsolatedBrowserRuntime:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "runtime",
    )
    runtime._process = _FakeProcess(prepare_result)  # type: ignore[assignment]
    runtime._selected_browser = "msedge"
    return runtime


def _probe() -> dict[str, object]:
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
    }


def _operational_probe() -> dict[str, object]:
    return {
        **_probe(),
        "query_trace": {
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
        },
    }


def test_parent_accepts_only_the_bounded_settlement_list_probe(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, _probe())

    result = runtime.prepare_automated()

    assert result == SettlementListProbe(
        total_count=2,
        list_length=2,
        page_number=1,
        page_size=30,
        response_structure_sha256="a" * 64,
    )
    process = runtime._process
    assert isinstance(process, _FakeProcess)
    assert process.requests[-1]["scope"] == "current"


def test_parent_requests_the_historical_settled_baseline_explicitly(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, _probe())

    runtime.prepare_automated(scope="settled_history")

    process = runtime._process
    assert isinstance(process, _FakeProcess)
    assert process.requests[-1]["scope"] == "settled_history"


def test_parent_requests_operational_compat_without_contract_values(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, _operational_probe())

    result = runtime.prepare_operational_compat()

    assert result.total_count == 2
    assert result.query_trace == SettlementQueryFlightRecord(
        query_attempt_id="1" * 32,
        observed_request_count=3,
        approved_request_count=1,
        blocked_request_count=2,
        query_attempt_count=1,
        zero_retry_performed=False,
        cache_refresh_count=1,
        page_count=1,
        request_method="POST",
        request_path=(
            "/api/order-center-server/app/clientOrderItem/"
            "queryWaitSettlementOrderItemListPC"
        ),
        resource_type="fetch",
        response_status=200,
        response_byte_size=128,
        response_structure_sha256="a" * 64,
        duration_ms=25,
    )
    process = runtime._process
    assert isinstance(process, _FakeProcess)
    assert process.requests[-1] == {
        "schema_version": 6,
        "command": "prepare_operational_compat",
        "request_id": process.requests[-1]["request_id"],
    }
    assert process.timeouts[-1] == PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS


def test_parent_reuses_one_operational_preparation_for_all_batches(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, _operational_probe())

    first = runtime.prepare_operational_compat()
    second = runtime.prepare_operational_compat()

    assert second is first
    process = runtime._process
    assert isinstance(process, _FakeProcess)
    assert [request["command"] for request in process.requests] == [
        "prepare_operational_compat"
    ]


def test_parent_never_reuses_operational_authority_after_worker_exit(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, _operational_probe())
    runtime._active_read_scope = "settlement"
    runtime._operational_probe = SettlementListProbe.from_worker_payload(
        _operational_probe(),
        require_query_trace=True,
    )
    runtime._process = _StoppedFakeProcess(  # type: ignore[assignment]
        _operational_probe()
    )

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime.prepare_operational_compat()

    assert raised.value.code == "browser_worker_unavailable"
    assert runtime._operational_probe is None
    assert runtime._active_read_scope is None


@pytest.mark.parametrize(
    "prepare_result",
    [
        None,
        {**_probe(), "raw_response": {"private": "value"}},
        {
            **_probe(),
            "metrics": {
                "total_count": 0,
                "list_length": 1,
                "page_number": 1,
                "page_size": 30,
            },
        },
        {
            **_probe(),
            "metrics": {
                "total_count": 2,
                "list_length": 2,
                "page_number": 1,
                "page_size": 1,
            },
        },
        {
            **_probe(),
            "metrics": {
                "total_count": True,
                "list_length": 1,
                "page_number": 1,
                "page_size": 30,
            },
        },
        {**_probe(), "response_structure_sha256": "A" * 64},
    ],
)
def test_parent_rejects_missing_or_unsafe_prepare_probe(
    tmp_path: Path,
    prepare_result: object,
) -> None:
    runtime = _runtime(tmp_path, prepare_result)

    with pytest.raises(BrowserRuntimeError, match="probe"):
        runtime.prepare_automated()


@pytest.mark.parametrize(
    "trace_patch",
    [
        {"query_attempt_id": "../private"},
        {"approved_request_count": 2},
        {"query_attempt_count": 2},
        {"zero_retry_performed": True},
        {"cache_refresh_count": 2},
        {"blocked_request_count": -1},
        {"request_method": "GET"},
        {"request_path": "/api/private"},
        {"response_structure_sha256": "b" * 64},
        {"request_body": {"private": True}},
    ],
)
def test_parent_rejects_unsafe_operational_query_trace(
    tmp_path: Path,
    trace_patch: dict[str, object],
) -> None:
    probe = _operational_probe()
    trace = probe["query_trace"]
    assert isinstance(trace, dict)
    probe["query_trace"] = {**trace, **trace_patch}
    runtime = _runtime(tmp_path, probe)

    with pytest.raises(BrowserRuntimeError, match="probe"):
        runtime.prepare_operational_compat()


def test_parent_rejects_prepare_probe_on_non_prepare_response(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, _probe())

    with pytest.raises(BrowserRuntimeError, match="command"):
        runtime._exchange(
            {
                "schema_version": 6,
                "command": "status",
                "request_id": "status-with-probe",
            },
            timeout=1,
        )
