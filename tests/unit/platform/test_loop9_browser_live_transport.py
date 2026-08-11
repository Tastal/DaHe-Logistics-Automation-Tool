from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from dahe.adapters.chengfeng.browser_runtime import (
    OPERATIONAL_BATCH_WORKER_TIMEOUT_SECONDS,
    BrowserReadPayload,
    BrowserRuntimeError,
    IsolatedBrowserRuntime,
)
from dahe.adapters.chengfeng.live_manifest import (
    LiveAuthorizedImageRequest,
    LiveAuthorizedRequest,
)
from dahe.adapters.chengfeng.policy import ReadRequest

PROJECT_ROOT = Path(__file__).parents[3]
BROWSER_SOURCE = PROJECT_ROOT / "browser-runtime" / "src"


def test_operational_batch_timeout_fits_one_browser_control_lease() -> None:
    assert OPERATIONAL_BATCH_WORKER_TIMEOUT_SECONDS == 480


def _load_worker_modules(monkeypatch: pytest.MonkeyPatch) -> tuple[object, object]:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    for name in (
        "dahe_browser_worker.engine",
        "dahe_browser_worker.protocol",
    ):
        sys.modules.pop(name, None)
    import dahe_browser_worker.engine as engine
    import dahe_browser_worker.protocol as protocol

    return engine, protocol


def test_browser_worker_protocol_accepts_only_typed_read_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    parse_command = protocol.parse_command

    command = parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "read_json",
                "request_id": "read-json-1",
                "operation": "list_waybills",
                "method": "POST",
                "url": "https://platform.example.invalid/api/list",
                "parameters": {"pageNumber": 1, "sns": []},
            }
        )
    )
    assert command.operation == "list_waybills"
    assert command.parameters == {"pageNumber": 1, "sns": ()}
    prepared = parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "prepare_automated",
                "request_id": "prepare-1",
                "scope": "current",
            }
        )
    )
    assert prepared.request_id == "prepare-1"
    assert prepared.scope == "current"
    operational = parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "prepare_operational_compat",
                "request_id": "prepare-operational-1",
            }
        )
    )
    assert operational.request_id == "prepare-operational-1"
    handoff = parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "prepare_settlement_filter_handoff",
                "request_id": "filter-handoff-1",
                "waybill_numbers": ["SXYD202608080001", "YD202608080002"],
            }
        )
    )
    assert handoff.waybill_numbers == (
        "SXYD202608080001",
        "YD202608080002",
    )
    frozen = parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "freeze_human_session",
                "request_id": "freeze-1",
            }
        )
    )
    assert frozen.request_id == "freeze-1"
    resumed = parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "resume_human_session",
                "request_id": "resume-1",
            }
        )
    )
    assert resumed.request_id == "resume-1"
    settlement_views = parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "probe_settlement_views",
                "request_id": "probe-settlement-views-1",
            }
        )
    )
    assert settlement_views.request_id == "probe-settlement-views-1"

    invalid_payloads = (
        {
            "schema_version": 6,
            "command": "read_json",
            "request_id": "read-json-2",
            "operation": "confirm_settlement",
            "method": "POST",
            "url": "https://platform.example.invalid/api/confirm",
            "parameters": {"id": "one"},
        },
        {
            "schema_version": 6,
            "command": "read_json",
            "request_id": "read-json-3",
            "operation": "list_waybills",
            "method": "GET",
            "url": "https://platform.example.invalid/api/list",
            "parameters": {},
        },
        {
            "schema_version": 6,
            "command": "read_image",
            "request_id": "../escape",
            "operation": "download_ticket_image",
            "method": "GET",
            "url": "https://images.example.invalid/ticket.jpg?signature=secret",
            "parameters": {},
        },
        {
            "schema_version": 6,
            "command": "read_image",
            "request_id": "read-image-1",
            "operation": "download_ticket_image",
            "method": "GET",
            "url": "http://images.example.invalid/ticket.jpg",
            "parameters": {},
        },
        {
            "schema_version": 6,
            "command": "prepare_automated",
            "request_id": "prepare-invalid-scope",
            "scope": "all_history",
        },
        {
            "schema_version": 6,
            "command": "prepare_automated",
            "request_id": "prepare-missing-scope",
        },
        {
            "schema_version": 6,
            "command": "prepare_operational_compat",
            "request_id": "prepare-operational-extra",
            "scope": "current",
        },
        {
            "schema_version": 6,
            "command": "prepare_settlement_filter_handoff",
            "request_id": "filter-handoff-duplicate",
            "waybill_numbers": ["YD1", "YD1"],
        },
        {
            "schema_version": 6,
            "command": "prepare_settlement_filter_handoff",
            "request_id": "filter-handoff-unsafe",
            "waybill_numbers": ["YD1\n结算"],
        },
    )
    for payload in invalid_payloads:
        with pytest.raises(protocol.ProtocolError):
            parse_command(json.dumps(payload))


def test_browser_worker_protocol_rejects_image_outside_fixed_chengfeng_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)

    accepted = protocol.parse_command(
        json.dumps(
            {
                "schema_version": 6,
                "command": "read_image",
                "request_id": "read-image-chengfeng-origin",
                "operation": "download_ticket_image",
                "method": "GET",
                "url": (
                    "https://cfhy-file-data.obs.cn-north-4."
                    "myhuaweicloud.com/ticket.jpg?signature=private"
                ),
                "parameters": {},
            }
        )
    )
    assert accepted.operation == "download_ticket_image"

    with pytest.raises(protocol.ProtocolError):
        protocol.parse_command(
            json.dumps(
                {
                    "schema_version": 6,
                    "command": "read_image",
                    "request_id": "read-image-arbitrary-origin",
                    "operation": "download_ticket_image",
                    "method": "GET",
                    "url": (
                        "https://arbitrary.example.invalid/"
                        "internal-resource.jpg"
                    ),
                    "parameters": {},
                }
            )
        )


def test_browser_worker_protocol_emits_only_bounded_prepare_probe_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    command = protocol.PrepareAutomatedCommand(
        request_id="prepare-safe-probe",
        scope="current",
    )
    probe = {
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

    output = json.loads(
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=None,
            browser_open=True,
            read_result=None,
            prepare_result=probe,
        )
    )

    assert output["prepare_result"] == probe
    assert set(output["prepare_result"]) == {
        "schema_version",
        "probe_kind",
        "operation",
        "metrics",
        "response_structure_sha256",
    }

    unsafe = {
        **probe,
        "raw_response": {"data": {"list": [{"orderItemSn": "private"}]}},
    }
    with pytest.raises(protocol.ProtocolError):
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=None,
            browser_open=True,
            read_result=None,
            prepare_result=unsafe,
        )


def test_browser_worker_protocol_emits_value_free_operational_query_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    command = protocol.PrepareOperationalCompatCommand(
        request_id="prepare-operational-trace",
    )
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
    probe = {
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

    output = json.loads(
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=None,
            browser_open=True,
            read_result=None,
            prepare_result=probe,
        )
    )

    assert output["prepare_result"]["query_trace"] == trace
    serialized = json.dumps(output, sort_keys=True)
    for private_value in (
        "authorization",
        "cookie",
        "orderItemSn",
        "pageNumber",
        "signature",
    ):
        assert private_value not in serialized

    with pytest.raises(protocol.ProtocolError):
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            browser_open=True,
            prepare_result={
                **probe,
                "query_trace": {**trace, "request_body": {"private": True}},
            },
        )


def test_browser_worker_captures_only_bounded_private_session_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
        )
        post_data = '{"password":"must-never-be-read"}'

        def all_headers(self) -> dict[str, str]:
            return {
                "Authorization": "Bearer worker-memory-only",
                "X-Company-Id": "company-session",
                "Cookie": "session=must-not-be-copied",
                "Host": "pc.chengfengkuaiyun.com",
                "Content-Length": "123",
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip",
                "Sec-Fetch-Site": "same-origin",
            }

    headers = engine_module._session_headers_from_request(ApprovedRequest())

    assert headers == {
        "authorization": "Bearer worker-memory-only",
        "x-company-id": "company-session",
    }
    assert "must-never-be-read" not in json.dumps(headers)


def test_browser_worker_accepts_aborted_list_query_only_for_session_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class ApprovedAbortedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            "?page-origin=official-ui"
        )

        def all_headers(self) -> dict[str, str]:
            return {"Authorization": "Bearer worker-memory-only"}

    headers = engine_module._session_headers_from_request(
        ApprovedAbortedRequest()
    )

    assert headers == {"authorization": "Bearer worker-memory-only"}


def test_browser_worker_keeps_only_bounded_list_cache_query_in_private_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            "?t=1785300000123"
        )

    assert engine_module._private_list_cache_query_from_request(
        ApprovedRequest()
    ) == "t=1785300000123"


@pytest.mark.parametrize("dept_code", ["", "370800"])
def test_browser_worker_accepts_only_the_exact_historical_list_request_shape(
    monkeypatch: pytest.MonkeyPatch,
    dept_code: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com"
            f"{engine_module.CHENGFENG_HISTORICAL_LIST_PATH}"
            "?t=1785300000123"
        )
        post_data_json: ClassVar[dict[str, object]] = {
            "deptCode": dept_code,
            "pageNumber": 1,
            "pageSize": 100,
            "sortParams": [],
        }

    request = ApprovedRequest()

    assert engine_module._historical_list_fixed_values_from_request(request) == {
        "deptCode": dept_code,
    }
    assert engine_module._private_list_cache_query_from_request(
        request,
        expected_path=engine_module.CHENGFENG_HISTORICAL_LIST_PATH,
    ) == "t=1785300000123"
    assert engine_module._private_list_body_from_request(
        request,
        scope="settled_history",
    ) == ApprovedRequest.post_data_json
    assert engine_module._approved_json_read_url(
        "https://pc.chengfengkuaiyun.com"
        f"{engine_module.CHENGFENG_HISTORICAL_LIST_PATH}"
    )
    assert not engine_module._approved_json_read_url(
        "https://pc.chengfengkuaiyun.com"
        f"{engine_module.CHENGFENG_HISTORICAL_LIST_PATH}/other"
    )


@pytest.mark.parametrize(
    "post_data",
    [
        {
            "deptCode": "not numeric",
            "pageNumber": 1,
            "pageSize": 100,
            "sortParams": [],
        },
        {
            "deptCode": "370800",
            "pageNumber": 1,
            "pageSize": 100,
            "sortParams": ["unsafe"],
        },
        {
            "deptCode": "370800",
            "pageNumber": 1,
            "pageSize": 100,
            "sortParams": [],
            "unexpected": "",
        },
    ],
)
def test_browser_worker_rejects_unsafe_historical_list_baselines(
    monkeypatch: pytest.MonkeyPatch,
    post_data: dict[str, object],
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class Request:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com"
            f"{engine_module.CHENGFENG_HISTORICAL_LIST_PATH}"
            "?t=1785300000123"
        )
        post_data_json = post_data

    request = Request()
    assert engine_module._historical_list_fixed_values_from_request(request) is None
    assert (
        engine_module._private_list_body_from_request(
            request,
            scope="settled_history",
        )
        is None
    )


@pytest.mark.parametrize(
    "query",
    [
        "",
        "other=1785300000123",
        "t=not-a-number",
        "t=123",
        "t=1785300000123&other=1",
        "t=1785300000123&t=1785300000456",
    ],
)
def test_browser_worker_rejects_unapproved_list_cache_query(
    monkeypatch: pytest.MonkeyPatch,
    query: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class Request:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            + (f"?{query}" if query else "")
        )

    assert engine_module._private_list_cache_query_from_request(Request()) is None


def test_browser_worker_keeps_only_safe_list_fixed_values_in_private_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC?t=cache-buster"
        )
        post_data_json: ClassVar[dict[str, object]] = {
            "order": "asc",
            "queryType": "2",
            "settleQueryType": 2,
            "pageNumber": 1,
            "pageSize": 30,
            "driverName": "must-not-be-retained",
            "sns": ["must-not-be-retained"],
        }

    fixed_values = engine_module._private_list_fixed_values_from_request(
        ApprovedRequest()
    )

    assert fixed_values == {
        "order": "asc",
        "queryType": "2",
        "settleQueryType": 2,
    }
    assert "must-not-be-retained" not in json.dumps(fixed_values)


def test_browser_worker_private_list_body_hash_ignores_only_paging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    first = {
        "driverName": "",
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 30,
        "queryType": "2",
        "settleQueryType": 1,
        "sns": [],
    }
    another_page = {
        **first,
        "pageNumber": 9,
        "pageSize": 100,
    }
    changed_filter = {
        **first,
        "driverName": "must-change-the-hash",
    }

    assert engine_module._normalized_private_list_body_sha256(
        first
    ) == engine_module._normalized_private_list_body_sha256(another_page)
    assert engine_module._normalized_private_list_body_sha256(
        first
    ) != engine_module._normalized_private_list_body_sha256(changed_filter)


@pytest.mark.parametrize(
    "body",
    [
        {"pageNumber": True, "pageSize": 30},
        {"pageNumber": 1, "pageSize": 30, "nested": {"unsafe": "value"}},
        {"pageNumber": 1, "pageSize": 30, "sns": ["unsafe"]},
        {
            "pageNumber": 1,
            "pageSize": 30,
            "accessToken": "must-never-be-cached",
        },
    ],
)
def test_browser_worker_rejects_unbounded_private_list_body_hash_input(
    monkeypatch: pytest.MonkeyPatch,
    body: dict[str, object],
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    assert engine_module._normalized_private_list_body_sha256(body) is None


@pytest.mark.parametrize(
    "post_data",
    [
        {"order": "newest", "queryType": "2", "settleQueryType": 1},
        {"order": "desc", "queryType": "2", "settleQueryType": True},
        {"order": "desc", "queryType": "2", "settleQueryType": -1},
        {"order": "desc", "queryType": "2", "settleQueryType": 100},
        {"order": "desc", "queryType": "all", "settleQueryType": 1},
        {"order": "desc", "settleQueryType": 1},
    ],
)
def test_browser_worker_rejects_unsafe_private_list_fixed_values(
    monkeypatch: pytest.MonkeyPatch,
    post_data: dict[str, object],
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
        )
        post_data_json = post_data

    assert (
        engine_module._private_list_fixed_values_from_request(ApprovedRequest())
        is None
    )


@pytest.mark.parametrize(
    ("query_type", "settle_query_type"),
    [
        ("", 1),
        ("0", 1),
        ("9", 9),
    ],
)
def test_browser_worker_accepts_bounded_private_list_enums(
    monkeypatch: pytest.MonkeyPatch,
    query_type: str,
    settle_query_type: int,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC?t=1785300000123"
        )
        post_data_json: ClassVar[dict[str, object]] = {
            "order": "desc",
            "queryType": query_type,
            "settleQueryType": settle_query_type,
        }

    assert engine_module._private_list_fixed_values_from_request(
        ApprovedRequest()
    ) == {
        "order": "desc",
        "queryType": query_type,
        "settleQueryType": settle_query_type,
    }


@pytest.mark.parametrize(
    ("method", "resource_type", "url"),
    [
        (
            "GET",
            "xhr",
            (
                "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            ),
        ),
        (
            "POST",
            "document",
            (
                "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            ),
        ),
        (
            "POST",
            "xhr",
            (
                "https://other.invalid/api/order-center-server/"
                "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            ),
        ),
        (
            "POST",
            "xhr",
            "https://pc.chengfengkuaiyun.com/api/login",
        ),
        (
            "POST",
            "xhr",
            (
                "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                "app/clientOrderItem/getOrderItemDetailsByIdPC"
            ),
        ),
    ],
)
def test_browser_worker_ignores_non_list_session_header_sources(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    resource_type: str,
    url: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class Request:
        def all_headers(self) -> dict[str, str]:
            raise AssertionError("headers must not be read from an unapproved request")

    request = Request()
    request.method = method
    request.resource_type = resource_type
    request.url = url

    assert engine_module._session_headers_from_request(request) is None


def test_browser_engine_stages_json_without_page_navigation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    fetch_calls: list[tuple[str, dict[str, object]]] = []
    body = b'{"data":{"list":[],"pageNo":1,"pageSize":30,"total":0}}'

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {
            "content-type": "application/json; charset=utf-8"
        }

        def body(self) -> bytes:
            return body

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            fetch_calls.append((url, options))
            return Response()

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {
        "authorization": "Bearer worker-memory-only",
        "x-company-id": "company-session",
    }
    worker._session_list_fixed_values = {
        "order": "asc",
        "queryType": "2",
        "settleQueryType": 2,
    }
    worker._session_list_cache_query = "t=1785300000123"
    worker._session_list_body = {
        "order": "asc",
        "pageNumber": 7,
        "pageSize": 100,
        "queryType": "2",
        "settleQueryType": 2,
        "taxPublishFlag": "1",
    }
    worker._session_list_body_sha256 = (
        engine_module._normalized_private_list_body_sha256(
            worker._session_list_body
        )
    )
    command = protocol.ReadJsonCommand(
        request_id="read-json-1",
        operation="list_waybills",
        method="POST",
        url=(
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
        ),
        parameters={
            "order": "",
            "pageNumber": 1,
            "pageSize": 30,
            "queryType": "",
            "settleQueryType": 0,
            "taxPublishFlag": "",
        },
    )

    result = worker.read(command)

    assert fetch_calls == [
        (
                (
                    "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                    "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
                    "?t=1785300000123"
                ),
            {
                "method": "POST",
                "data": {
                    "order": "asc",
                    "pageNumber": 1,
                    "pageSize": 30,
                    "queryType": "2",
                    "settleQueryType": 2,
                    "taxPublishFlag": "1",
                },
                "fail_on_status_code": False,
                "headers": {
                    "authorization": "Bearer worker-memory-only",
                    "x-company-id": "company-session",
                },
                "max_redirects": 0,
                "timeout": 30_000,
            },
        )
    ]
    assert result["sha256"] == hashlib.sha256(body).hexdigest()
    assert result["media_type"] == "application/json"
    serialized_result = json.dumps(result, sort_keys=True)
    assert "worker-memory-only" not in serialized_result
    assert "company-session" not in serialized_result
    assert (
        worker._staging_root / str(result["relative_path"])
    ).read_bytes() == body


def test_browser_engine_rejects_nonempty_filter_from_private_list_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)

    class RequestContext:
        def fetch(self, url: str, **options: object) -> object:
            raise AssertionError("mismatched body must fail before network")

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "worker-memory-only"}
    worker._session_list_fixed_values = {
        "order": "desc",
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_cache_query = "t=1785300000123"
    worker._session_list_body = {
        "driverName": "",
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 30,
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_body_sha256 = (
        engine_module._normalized_private_list_body_sha256(
            worker._session_list_body
        )
    )
    command = protocol.ReadJsonCommand(
        request_id="read-json-body-mismatch",
        operation="list_waybills",
        method="POST",
        url=(
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
        ),
        parameters={
            "driverName": "unexpected-filter",
            "order": "",
            "pageNumber": 1,
            "pageSize": 30,
            "queryType": "",
            "settleQueryType": 1,
        },
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.read(command)

    assert raised.value.code == "browser_session_list_body_filter_mismatch"


def test_browser_engine_rejects_list_body_field_set_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)

    class RequestContext:
        def fetch(self, url: str, **options: object) -> object:
            raise AssertionError("mismatched field set must fail before network")

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "worker-memory-only"}
    worker._session_list_fixed_values = {
        "order": "desc",
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_cache_query = "t=1785300000123"
    worker._session_list_body = {
        "driverName": "",
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 30,
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_body_sha256 = (
        engine_module._normalized_private_list_body_sha256(
            worker._session_list_body
        )
    )
    command = protocol.ReadJsonCommand(
        request_id="read-json-field-set-mismatch",
        operation="list_waybills",
        method="POST",
        url=(
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
        ),
        parameters={
            "order": "",
            "pageNumber": 1,
            "pageSize": 30,
            "queryType": "",
            "settleQueryType": 1,
        },
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.read(command)

    assert (
        raised.value.code
        == "browser_session_list_body_fields_added"
    )
    assert raised.value.safe_discovery == [
        {
            "method": "POST",
            "origin": "https://pc.chengfengkuaiyun.com",
            "path": (
                "/api/order-center-server/app/clientOrderItem/"
                "queryWaitSettlementOrderItemListPC"
            ),
            "path_sha256": None,
            "query_keys": ["t"],
            "request_fields": [
                {"path": "$.driverName", "type": "string"},
                {"path": "$.order", "type": "string"},
                {"path": "$.pageNumber", "type": "integer"},
                {"path": "$.pageSize", "type": "integer"},
                {"path": "$.queryType", "type": "string"},
                {"path": "$.settleQueryType", "type": "integer"},
            ],
            "resource_kind": "json_api",
            "response_status": None,
            "content_kind": None,
            "response_fields": [],
        }
    ]


def test_browser_engine_rejects_list_body_hash_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)

    class RequestContext:
        def fetch(self, url: str, **options: object) -> object:
            raise AssertionError("mismatched body hash must fail before network")

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "worker-memory-only"}
    worker._session_list_fixed_values = {
        "order": "desc",
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_cache_query = "t=1785300000123"
    worker._session_list_body = {
        "driverName": "",
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 30,
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_body_sha256 = "a" * 64
    command = protocol.ReadJsonCommand(
        request_id="read-json-hash-mismatch",
        operation="list_waybills",
        method="POST",
        url=(
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
        ),
        parameters={
            "driverName": "",
            "order": "",
            "pageNumber": 1,
            "pageSize": 30,
            "queryType": "",
            "settleQueryType": 1,
        },
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.read(command)

    assert raised.value.code == "browser_session_list_body_hash_mismatch"


def test_browser_engine_never_attaches_chengfeng_session_headers_to_images(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    fetch_calls: list[tuple[str, dict[str, object]]] = []
    body = b"\x89PNG\r\n\x1a\nprivate-image"

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {"content-type": "image/png"}

        def body(self) -> bytes:
            return body

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            fetch_calls.append((url, options))
            return Response()

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "Bearer worker-memory-only"}
    command = protocol.ReadImageCommand(
        request_id="read-image-private",
        operation="download_ticket_image",
        method="GET",
        url=(
            "https://cfhy-file-data.obs.cn-north-4.myhuaweicloud.com/"
            "ticket.png?signature=private"
        ),
        parameters={},
    )
    worker._detail_image_grants[command.url] = (
        worker._monotonic()
        + engine_module.DETAIL_IMAGE_GRANT_TTL_SECONDS
    )

    result = worker.read(command)

    assert fetch_calls[0][1] == {
        "method": "GET",
        "fail_on_status_code": False,
        "max_redirects": 0,
        "timeout": 60_000,
    }
    assert "headers" not in fetch_calls[0][1]
    assert result["media_type"] == "image/png"


def test_browser_engine_requires_exact_response_derived_image_url_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    loading_url = (
        "https://cfhy-file-data.obs.cn-north-4.myhuaweicloud.com/"
        "ticket/loading.png?signature=private-loading"
    )
    unloading_url = (
        "https://cfky.oss-cn-zhangjiakou.aliyuncs.com/"
        "ticket/unloading.png?signature=private-unloading"
    )
    fetch_calls: list[str] = []

    class Response:
        def __init__(
            self,
            *,
            body: bytes,
            content_type: str,
        ) -> None:
            self.status = 200
            self.headers = {"content-type": content_type}
            self._body = body

        def body(self) -> bytes:
            return self._body

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            del options
            fetch_calls.append(url)
            if "getOrderItemDetailsByIdPC" in url:
                return Response(
                    body=json.dumps(
                        {
                            "data": [
                                {
                                    "id": "900000001",
                                    "originalTonImageUrl": loading_url,
                                    "image": unloading_url,
                                }
                            ]
                        }
                    ).encode(),
                    content_type="application/json",
                )
            return Response(
                body=b"\x89PNG\r\n\x1a\nprivate-image",
                content_type="image/png",
            )

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "worker-memory-only"}
    image_command = protocol.ReadImageCommand(
        request_id="image-before-detail",
        operation="download_ticket_image",
        method="GET",
        url=loading_url,
        parameters={},
    )

    with pytest.raises(engine_module.BrowserReadError) as unseen:
        worker.read(image_command)

    assert unseen.value.code == "browser_image_not_registered"
    assert fetch_calls == []

    worker.read(
        protocol.ReadJsonCommand(
            request_id="detail-register-images",
            operation="get_waybill_detail",
            method="POST",
            url=(
                "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                "app/clientOrderItem/getOrderItemDetailsByIdPC"
            ),
            parameters={"id": "900000001"},
        )
    )

    first = worker.read(
        protocol.ReadImageCommand(
            request_id="image-loading",
            operation="download_ticket_image",
            method="GET",
            url=loading_url,
            parameters={},
        )
    )
    second = worker.read(
        protocol.ReadImageCommand(
            request_id="image-unloading",
            operation="download_ticket_image",
            method="GET",
            url=unloading_url,
            parameters={},
        )
    )
    retried = worker.read(
        protocol.ReadImageCommand(
            request_id="image-loading-retry",
            operation="download_ticket_image",
            method="GET",
            url=loading_url,
            parameters={},
        )
    )

    assert first["sha256"] == retried["sha256"]
    assert second["media_type"] == "image/png"
    assert fetch_calls == [
        (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/getOrderItemDetailsByIdPC"
        ),
        loading_url,
        unloading_url,
        loading_url,
    ]


def test_browser_engine_submits_detail_identity_as_form_data(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    fetch_options: list[dict[str, object]] = []

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {
            "content-type": "application/json"
        }

        def body(self) -> bytes:
            return json.dumps(
                {
                    "data": [
                        {
                            "id": "900000001",
                            "originalTonImageUrl": "https://cfhy-file-data.obs.cn-north-4.myhuaweicloud.com/loading.png",
                            "image": "https://cfky.oss-cn-zhangjiakou.aliyuncs.com/unloading.png",
                        }
                    ]
                }
            ).encode()

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            del url
            fetch_options.append(options)
            return Response()

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "worker-memory-only"}

    worker.read(
        protocol.ReadJsonCommand(
            request_id="detail-form",
            operation="get_waybill_detail",
            method="POST",
            url=(
                "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                "app/clientOrderItem/getOrderItemDetailsByIdPC"
            ),
            parameters={"id": "900000001"},
        )
    )

    assert fetch_options[0]["form"] == {"id": "900000001"}
    assert "data" not in fetch_options[0]


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    (
        ({"data": None}, "browser_detail_data_null_missing"),
        (
            {"code": 200, "data": None},
            "browser_detail_data_null_success",
        ),
        ({"data": {"id": "900000001"}}, "browser_detail_data_object"),
        ({"data": []}, "browser_detail_cardinality_changed"),
        ({"data": ["invalid"]}, "browser_detail_item_contract_changed"),
        (
            {"data": [{"id": "different"}]},
            "browser_detail_identity_mismatch",
        ),
    ),
)
def test_browser_engine_classifies_detail_contract_failures_without_values(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    expected_code: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    with pytest.raises(engine_module.BrowserReadError) as raised:
        engine_module._validated_detail_image_urls(
            payload,
            expected_platform_waybill_id="900000001",
    )

    assert raised.value.code == expected_code
    assert raised.value.safe_discovery is None


@pytest.mark.parametrize(
    "unsafe_url",
    (
        (
            "https://cfhy-file-data.obs.cn-north-4.myhuaweicloud.com/"
            "ticket/loading.png?signature=changed"
        ),
        "https://pc.chengfengkuaiyun.com/logout",
        "https://pc.chengfengkuaiyun.com/%6c%6f%67%6f%75%74",
        "https://pc.chengfengkuaiyun.com/api/unknown",
    ),
)
def test_browser_engine_rejects_unseen_same_origin_image_url_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    unsafe_url: str,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    fetch_calls: list[str] = []

    class RequestContext:
        def fetch(self, url: str, **options: object) -> object:
            del options
            fetch_calls.append(url)
            raise AssertionError("unseen image URL reached the network")

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.read(
            protocol.ReadImageCommand(
                request_id="unseen-same-origin-image",
                operation="download_ticket_image",
                method="GET",
                url=unsafe_url,
                parameters={},
            )
        )

    assert raised.value.code == "browser_image_not_registered"
    assert fetch_calls == []


def test_browser_engine_expires_response_derived_image_url_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    image_url = (
        "https://cfhy-file-data.obs.cn-north-4.myhuaweicloud.com/"
        "ticket/loading.png?signature=private"
    )
    monotonic_now = [100.0]
    fetch_calls: list[str] = []

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {
            "content-type": "application/json"
        }

        def body(self) -> bytes:
            return json.dumps(
                {
                    "data": [
                        {
                            "id": "900000001",
                            "originalTonImageUrl": image_url,
                            "image": image_url,
                        }
                    ]
                }
            ).encode()

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            del options
            fetch_calls.append(url)
            return Response()

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "worker-memory-only"}
    worker._monotonic = lambda: monotonic_now[0]
    worker.read(
        protocol.ReadJsonCommand(
            request_id="detail-short-lived-images",
            operation="get_waybill_detail",
            method="POST",
            url=(
                "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                "app/clientOrderItem/getOrderItemDetailsByIdPC"
            ),
            parameters={"id": "900000001"},
        )
    )
    monotonic_now[0] += 301.0

    with pytest.raises(engine_module.BrowserReadError) as expired:
        worker.read(
            protocol.ReadImageCommand(
                request_id="expired-image",
                operation="download_ticket_image",
                method="GET",
                url=image_url,
                parameters={},
            )
        )

    assert expired.value.code == "browser_image_not_registered"
    assert len(fetch_calls) == 1


def test_browser_engine_rejects_arbitrary_image_origin_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    fetch_calls: list[str] = []

    class RequestContext:
        def fetch(self, url: str, **options: object) -> object:
            del options
            fetch_calls.append(url)
            raise AssertionError("arbitrary image origin reached the network")

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.read(
            protocol.ReadImageCommand(
                request_id="read-image-arbitrary-origin",
                operation="download_ticket_image",
                method="GET",
                url=(
                    "https://arbitrary.example.invalid/"
                    "internal-resource.jpg"
                ),
                parameters={},
            )
        )

    assert raised.value.code == "browser_image_origin_denied"
    assert fetch_calls == []


def test_browser_engine_rejects_redirect_without_staging_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)

    class Response:
        status = 302
        headers: ClassVar[dict[str, str]] = {
            "content-type": "text/html",
            "location": "https://other.invalid",
        }

        def body(self) -> bytes:
            return b"redirect"

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            return Response()

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "Bearer worker-memory-only"}
    worker._session_list_fixed_values = {
        "order": "desc",
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_cache_query = "t=1785300000123"
    worker._session_list_body = {
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 30,
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_body_sha256 = (
        engine_module._normalized_private_list_body_sha256(
            worker._session_list_body
        )
    )
    command = protocol.ReadJsonCommand(
        request_id="read-json-redirect",
        operation="list_waybills",
        method="POST",
        url=(
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
        ),
        parameters={
            "order": "",
            "pageNumber": 1,
            "pageSize": 30,
            "queryType": "",
            "settleQueryType": 1,
        },
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.read(command)

    assert raised.value.code == "browser_read_redirect_rejected"
    assert not tuple(worker._staging_root.iterdir())


def test_operational_read_reuses_hidden_page_body_and_only_changes_paging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    page_calls: list[tuple[str, dict[str, object]]] = []

    class RequestContext:
        def fetch(self, _url: str, **_options: object) -> object:
            raise AssertionError(
                "operational paging must stay inside the browser page"
            )

    class Page:
        def is_closed(self) -> bool:
            return False

        def evaluate(
            self,
            script: str,
            arguments: dict[str, object],
        ) -> dict[str, object]:
            page_calls.append((script, arguments))
            worker._operational_batch_list_seen = True
            return {
                "status": 200,
                "redirected": False,
                "contentType": "application/json",
                "body": json.dumps(
                    {
                        "data": {
                            "list": [],
                            "pageNo": 2,
                            "pageSize": 50,
                            "total": 137,
                        }
                    }
                ),
            }

    class Context:
        request = RequestContext()
        pages: ClassVar[list[object]] = []

    baseline = {
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 20,
        "queryType": "2",
        "settleQueryType": 1,
        "futureEmptyFilter": "",
        "futureArrayFilter": [],
        "futureNullFilter": None,
        "futureBooleanFilter": False,
        "futureObjectFilter": {},
        "futureVersion": "business-view-v2",
    }
    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path / "read-staging"
    worker._staging_root.mkdir()
    worker._session_headers = {"authorization": "private"}
    worker._session_list_fixed_values = None
    worker._session_list_cache_query = "t=1785300000123"
    worker._session_list_body = baseline
    worker._session_list_body_sha256 = (
        engine_module._normalized_private_list_body_sha256(baseline)
    )
    worker._automated_prepared = True
    worker._automated_scope = "current"
    worker._operational_compat_prepared = True
    worker._operational_batch_page = Page()
    worker._operational_batch_route_handler = object()

    result = worker.read(
        protocol.ReadJsonCommand(
            request_id="operational-hidden-fields",
            operation="list_waybills",
            method="POST",
            url=(
                "https://pc.chengfengkuaiyun.com"
                f"{engine_module.CHENGFENG_LIST_PATH}"
            ),
            parameters={
                "order": "desc",
                "pageNumber": 2,
                "pageSize": 50,
                "queryType": "2",
                "settleQueryType": 1,
            },
        )
    )

    assert result["status_code"] == 200
    assert len(page_calls) == 1
    script, arguments = page_calls[0]
    assert script == engine_module._OPERATIONAL_LIST_FETCH_SCRIPT
    url = arguments["url"]
    assert isinstance(url, str)
    assert url.endswith(
        f"{engine_module.CHENGFENG_LIST_PATH}?t=1785300000123"
    )
    assert arguments["body"] == {
        **baseline,
        "pageNumber": 2,
        "pageSize": 50,
    }


def test_operational_page_list_route_requires_exact_body_and_cache_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    expected_body = {
        "order": "desc",
        "pageNumber": 2,
        "pageSize": 50,
        "queryType": "2",
        "settleQueryType": 1,
    }

    class Request:
        method = "POST"
        resource_type = "fetch"
        url = (
            "https://pc.chengfengkuaiyun.com"
            f"{engine_module.CHENGFENG_LIST_PATH}?t=1785300000123"
        )
        post_data_json = expected_body

    assert engine_module._operational_list_request_matches(
        Request(),
        expected_body=expected_body,
        expected_cache_query="t=1785300000123",
    )

    changed = Request()
    changed.post_data_json = {**expected_body, "pageNumber": 3}
    assert not engine_module._operational_list_request_matches(
        changed,
        expected_body=expected_body,
        expected_cache_query="t=1785300000123",
    )
    assert not engine_module._operational_list_request_matches(
        Request(),
        expected_body=expected_body,
        expected_cache_query="t=1785300000999",
    )


def test_browser_engine_requires_session_headers_before_closing_human_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class HumanPage:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def wait_for_timeout(self, timeout_ms: int) -> None:
            assert timeout_ms == 100

        def close(self) -> None:
            raise AssertionError("human page must remain open when session continuity is absent")

    class Context:
        pages: ClassVar[list[object]] = [HumanPage()]

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    monkeypatch.setattr(engine_module, "SESSION_HEADER_CAPTURE_WAIT_STEPS", 1)
    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_automated()

    assert (
        raised.value.code
        == "browser_session_settlement_scope_control_unavailable"
    )


def test_discovery_capture_blocks_unknown_requests_before_send_and_accounts_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []

    class Request:
        def __init__(self, method: str, url: str, resource_type: str = "xhr") -> None:
            self.method = method
            self.url = url
            self.resource_type = resource_type
            self.post_data_json = {"pageNumber": 1}

    class Route:
        def __init__(self, request: Request) -> None:
            self.request = request

        def abort(self) -> None:
            events.append(f"abort:{self.request.method}")

        def continue_(self) -> None:
            events.append(f"continue:{self.request.method}")

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def __init__(self) -> None:
            self.route_handler: object | None = None
            self.listeners: dict[str, object] = {}

        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert callable(handler)
            events.append("route-installed")
            self.route_handler = handler

        def unroute(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert handler is self.route_handler
            events.append("route-removed")
            self.route_handler = None

        def on(self, event: str, handler: object) -> None:
            events.append(f"listener:{event}")
            self.listeners[event] = handler

        def remove_listener(self, event: str, handler: object) -> None:
            assert self.listeners[event] is handler

        def wait_for_timeout(self, timeout_ms: int) -> None:
            assert timeout_ms == 250

    page = Page()

    class Context:
        pages: ClassVar[list[object]] = [page]

        def __init__(self) -> None:
            self.page_handler: object | None = None

        def on(self, event: str, handler: object) -> None:
            assert event == "page"
            self.page_handler = handler

        def remove_listener(self, event: str, handler: object) -> None:
            assert event == "page"
            assert self.page_handler is handler

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    worker.start_capture()

    assert events[:3] == [
        "route-installed",
        "listener:request",
        "listener:response",
    ]
    assert callable(page.route_handler)
    route_handler = page.route_handler
    for method in ("PUT", "PATCH", "DELETE"):
        route_handler(Route(Request(method, "https://pc.chengfengkuaiyun.com/api/save")))
    route_handler(
        Route(
            Request(
                "POST",
                (
                    "https://pc.chengfengkuaiyun.com"
                    f"{engine_module.CHENGFENG_LIST_PATH}"
                ),
            )
        )
    )
    route_handler(
        Route(
            Request(
                "POST",
                "https://pc.chengfengkuaiyun.com/api/unknown",
            )
        )
    )
    route_handler(
        Route(
            Request(
                "GET",
                "https://attacker.invalid/tracking.png?credential=secret",
                resource_type="image",
            )
        )
    )
    route_handler(
        Route(
            Request(
                "GET",
                "https://cfky.oss-cn-zhangjiakou.aliyuncs.com/"
                "approved-ticket.png?Expires=1&OSSAccessKeyId=2&Signature=3",
                resource_type="image",
            )
        )
    )

    assert events[-7:] == [
        "abort:PUT",
        "abort:PATCH",
        "abort:DELETE",
        "continue:POST",
        "abort:POST",
        "abort:GET",
        "continue:GET",
    ]
    assert worker._discovery_blocked_method_counts == {
        "DELETE": 1,
        "GET": 1,
        "PATCH": 1,
        "POST": 1,
        "PUT": 1,
    }

    assert worker.stop_capture() == []
    assert "route-removed" in events


def test_freeze_human_session_blocks_existing_and_future_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []

    class Route:
        def abort(self) -> None:
            events.append("aborted-before-send")

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def __init__(self, name: str) -> None:
            self.name = name
            self.route_handler: object | None = None

        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert callable(handler)
            events.append(f"frozen:{self.name}")
            self.route_handler = handler

    existing = Page("existing")

    class Context:
        pages: ClassVar[list[object]] = [existing]

        def __init__(self) -> None:
            self.page_handler: object | None = None

        def on(self, event: str, handler: object) -> None:
            assert event == "page"
            self.page_handler = handler

    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context

    worker.freeze_human_session()
    worker.freeze_human_session()

    assert events == ["frozen:existing"]
    assert callable(existing.route_handler)
    existing.route_handler(Route())
    future = Page("future")
    assert callable(context.page_handler)
    context.page_handler(future)
    assert callable(future.route_handler)
    future.route_handler(Route())

    assert events == [
        "frozen:existing",
        "aborted-before-send",
        "frozen:future",
        "aborted-before-send",
    ]


def test_resume_human_session_removes_freeze_and_revalidates_on_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def __init__(self) -> None:
            self.route_handler: object | None = None

        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            self.route_handler = handler
            events.append("page-frozen")

        def unroute(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert handler is self.route_handler
            self.route_handler = None
            events.append("page-unfrozen")

        def bring_to_front(self) -> None:
            events.append("page-focused")

        def goto(
            self,
            url: str,
            *,
            wait_until: str,
            timeout: int,
        ) -> object:
            assert url == (
                "https://pc.chengfengkuaiyun.com/billablewaybill"
            )
            assert wait_until == "commit"
            assert timeout == engine_module.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS
            events.append("page-reloaded")
            return type("Response", (), {"status": 200})()

    page = Page()

    class Context:
        pages: ClassVar[list[object]] = [page]

        def __init__(self) -> None:
            self.page_handler: object | None = None

        def on(self, event: str, handler: object) -> None:
            assert event == "page"
            self.page_handler = handler
            events.append("future-pages-frozen")

        def remove_listener(self, event: str, handler: object) -> None:
            assert event == "page"
            assert handler is self.page_handler
            self.page_handler = None
            events.append("future-pages-unfrozen")

    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context

    worker.freeze_human_session()
    worker.resume_human_session()
    assert worker._human_freeze_handlers == {}
    assert worker._human_freeze_context_page_handler is None
    assert page.route_handler is None

    worker.freeze_human_session()
    page.url = "https://pc.chengfengkuaiyun.com/"
    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.freeze_human_session()

    assert raised.value.code == "browser_session_settlement_route_unavailable"
    assert events == [
        "page-frozen",
        "future-pages-frozen",
        "future-pages-unfrozen",
        "page-unfrozen",
        "page-reloaded",
        "page-focused",
        "page-frozen",
        "future-pages-frozen",
    ]


def test_freeze_human_session_blocks_traffic_before_controls_are_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    route_calls: list[str] = []

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def route(self, pattern: str, handler: object) -> None:
            del pattern, handler
            route_calls.append("frozen")

    class Context:
        pages: ClassVar[list[object]] = [Page()]

        def on(self, event: str, handler: object) -> None:
            assert event == "page"
            assert callable(handler)
            route_calls.append("future-pages-frozen")

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    worker.freeze_human_session()

    assert route_calls == ["frozen", "future-pages-frozen"]


def test_freeze_human_session_ignores_a_page_that_closed_during_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    route_calls: list[str] = []

    class Page:
        def __init__(
            self,
            *,
            url: str,
            closed: bool,
            close_during_route: bool = False,
        ) -> None:
            self.url = url
            self.closed = closed
            self.close_during_route = close_during_route

        def is_closed(self) -> bool:
            return self.closed

        def route(self, pattern: str, handler: object) -> None:
            del pattern, handler
            if self.close_during_route:
                self.closed = True
                raise RuntimeError("page closed while installing routes")
            if self.closed:
                raise RuntimeError("a closed page cannot install routes")
            route_calls.append("frozen")

    active = Page(
        url="https://pc.chengfengkuaiyun.com/billablewaybill",
        closed=False,
    )
    closing = Page(url="about:blank", closed=True)
    racing = Page(
        url="about:blank",
        closed=False,
        close_during_route=True,
    )

    class Context:
        pages: ClassVar[list[object]] = [active, closing, racing]

        def on(self, event: str, handler: object) -> None:
            assert event == "page"
            assert callable(handler)
            route_calls.append("future-pages-frozen")

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    worker.freeze_human_session()

    assert route_calls == ["frozen", "future-pages-frozen"]
    assert set(worker._human_freeze_handlers) == {id(active)}


@pytest.mark.parametrize(
    ("fail_stage", "expected_code"),
    [
        ("existing_page", "browser_session_existing_page_freeze_failed"),
        ("future_pages", "browser_session_future_page_freeze_failed"),
    ],
)
def test_freeze_human_session_reports_the_safe_failing_stage(
    monkeypatch: pytest.MonkeyPatch,
    fail_stage: str,
    expected_code: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class Control:
        def filter(self, *, visible: bool) -> Control:
            assert visible is True
            return self

        @property
        def first(self) -> Control:
            return self

        def wait_for(self, *, state: str, timeout: int) -> None:
            del state, timeout

        def is_visible(self) -> bool:
            return False

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def locator(self, selector: str) -> Control:
            del selector
            return Control()

        def get_by_text(self, text: str, *, exact: bool) -> Control:
            del text, exact
            return Control()

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Control:
            del role, name, exact
            return Control()

        def route(self, pattern: str, handler: object) -> None:
            del pattern, handler
            if fail_stage == "existing_page":
                raise RuntimeError("safe synthetic existing-page failure")

    class Context:
        pages: ClassVar[list[object]] = [Page()]

        def on(self, event: str, handler: object) -> None:
            del event, handler
            if fail_stage == "future_pages":
                raise RuntimeError("safe synthetic future-page failure")

        def close(self) -> None:
            return

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.freeze_human_session()

    assert raised.value.code == expected_code


def test_browser_engine_classifies_visible_login_page_before_control_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class LoginPage:
        url = "https://pc.chengfengkuaiyun.com/login"

        def get_by_text(self, text: str, *, exact: bool) -> object:
            raise AssertionError("login controls must be classified first")

    class Context:
        pages: ClassVar[list[object]] = [LoginPage()]

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_automated()

    assert raised.value.code == "browser_read_login_required"


def test_browser_engine_rejects_an_unexpected_page_before_control_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class OtherPage:
        url = "https://pc.chengfengkuaiyun.com/"

        def get_by_text(self, text: str, *, exact: bool) -> object:
            raise AssertionError("unexpected routes must be classified first")

    class Context:
        pages: ClassVar[list[object]] = [OtherPage()]

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_automated()

    assert (
        raised.value.code
        == "browser_session_settlement_route_unavailable"
    )


def test_browser_engine_detects_login_form_on_the_settlement_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class VisibleControl:
        @property
        def first(self) -> VisibleControl:
            return self

        def is_visible(self) -> bool:
            return True

    class LoginFormPage:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def locator(self, selector: str) -> VisibleControl:
            assert selector == "input[type='password']"
            return VisibleControl()

        def get_by_text(self, text: str, *, exact: bool) -> object:
            raise AssertionError("login form must be classified first")

    class Context:
        pages: ClassVar[list[object]] = [LoginFormPage()]

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_automated()

    assert raised.value.code == "browser_read_login_required"


def test_browser_engine_builds_current_replay_baseline_from_one_native_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []
    native_body = json.dumps(
        {
            "data": {
                "list": [
                    {"id": 101, "orderItemSn": "must-not-leave-probe"},
                    {"id": 102, "orderItemSn": "also-private"},
                ],
                "pageNo": 1,
                "pageSize": 30,
                "total": 2,
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            "?t=1785300000123"
        )
        post_data_json: ClassVar[dict[str, object]] = {
            "order": "asc",
            "queryType": "2",
            "settleQueryType": 2,
            "pageNumber": 1,
            "pageSize": 30,
            "driverName": "",
            "sns": [],
        }

        def all_headers(self) -> dict[str, str]:
            return {
                "Authorization": "Bearer worker-memory-only",
                "Cookie": "must-not-be-copied",
            }

    class Route:
        request = ApprovedRequest()

        class Response:
            status = 200

            def body(self) -> bytes:
                events.append("native-body-read")
                return native_body

            def dispose(self) -> None:
                events.append("native-response-disposed")

        def fetch(self, **options: object) -> Response:
            assert options == {
                "max_redirects": 0,
                "timeout": engine_module.JSON_READ_TIMEOUT_MS,
            }
            events.append("native-request-fetched")
            return self.Response()

        def abort(self) -> None:
            events.append("request-aborted")

    class Trigger:
        def __init__(
            self,
            page: HumanPage,
            *,
            name: str,
            visible_match_selected: bool = False,
        ) -> None:
            self._page = page
            self._name = name
            self._visible_match_selected = visible_match_selected

        def filter(self, *, visible: bool) -> Trigger:
            assert visible is True
            return Trigger(
                self._page,
                name=self._name,
                visible_match_selected=True,
            )

        @property
        def first(self) -> Trigger:
            assert self._visible_match_selected is True
            return self

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert self._visible_match_selected is True
            assert state == "visible"
            assert timeout == engine_module.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS
            events.append(f"{self._name}-visible")

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000
            assert self._page.route_handler is not None
            events.append(f"{self._name}-clicked")
            if self._name == "waybill-tab":
                self._page.waybill_view_active = True
            elif self._name == "reset":
                # Chengfeng redraws the list after reset and may drop the
                # selected display mode. The Worker must activate it again
                # before issuing the native read-only query.
                self._page.waybill_view_active = False
            if self._name == "query":
                assert self._page.waybill_view_active is True
                self._page.route_handler(Route())

    class HumanPage:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def __init__(self) -> None:
            self.route_handler: object | None = None
            self.requested_texts: list[str] = []
            self.waybill_view_active = False

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Trigger:
            assert role == "button"
            assert exact is True
            if name == "查询":
                return Trigger(self, name="query")
            if name == "重置":
                return Trigger(self, name="reset")
            raise AssertionError(f"unexpected button: {name}")

        def get_by_text(self, text: str, *, exact: bool) -> Trigger:
            assert exact is True
            self.requested_texts.append(text)
            controls = {
                "可结算": "settle-ready",
                "已结算": "settle-ready",
                "结算": "settlement-tab",
                "按运单显示": "waybill-tab",
            }
            if text not in controls:
                raise AssertionError(f"unexpected text control: {text}")
            return Trigger(self, name=controls[text])

        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert callable(handler)
            self.route_handler = handler
            events.append("abort-route-installed")

        def unroute(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert handler is self.route_handler
            self.route_handler = None
            events.append("abort-route-removed")

        def wait_for_timeout(self, timeout_ms: int) -> None:
            assert timeout_ms in {100, 300}

        def close(self) -> None:
            events.append("human-closed")

    class BlankPage:
        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert callable(handler)
            events.append("blank-route-installed")

        def goto(self, url: str) -> None:
            assert url == "about:blank"
            events.append("blank-opened")

    class BackgroundPage:
        url = "about:blank"

        def close(self) -> None:
            events.append("background-closed")

    human = HumanPage()
    blank = BlankPage()
    background = BackgroundPage()

    class Context:
        pages: ClassVar[list[object]] = [background, human]

        def new_page(self) -> BlankPage:
            self.pages.append(blank)
            return blank

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    safe_probe = worker.prepare_automated(scope="current")
    assert worker.prepare_automated(scope="current") == safe_probe
    assert human.requested_texts[0] == "可结算"

    assert worker._session_headers == {
        "authorization": "Bearer worker-memory-only",
    }
    assert worker._session_list_fixed_values == {
        "order": "asc",
        "queryType": "2",
        "settleQueryType": 2,
    }
    assert worker._session_list_cache_query == "t=1785300000123"
    assert worker._session_list_body == ApprovedRequest.post_data_json
    assert isinstance(worker._session_list_body_sha256, str)
    assert len(worker._session_list_body_sha256) == 64
    assert safe_probe == {
        "schema_version": 1,
        "probe_kind": "chengfeng_settlement_list",
        "operation": "list_waybills",
        "metrics": {
            "total_count": 2,
            "list_length": 2,
            "page_number": 1,
            "page_size": 30,
        },
        "response_structure_sha256": engine_module._response_structure_sha256(
            json.loads(native_body)
        ),
    }
    serialized_probe = json.dumps(safe_probe, sort_keys=True)
    assert "must-not-leave-probe" not in serialized_probe
    assert "also-private" not in serialized_probe
    assert not hasattr(worker, "_session_native_response")
    assert events == [
        "settle-ready-visible",
        "settlement-tab-visible",
        "waybill-tab-visible",
        "reset-visible",
        "query-visible",
        "abort-route-installed",
        "settle-ready-clicked",
        "settlement-tab-clicked",
        "waybill-tab-clicked",
        "reset-clicked",
        "waybill-tab-clicked",
        "query-clicked",
        "native-request-fetched",
        "native-body-read",
        "native-response-disposed",
        "request-aborted",
        "abort-route-removed",
        "blank-route-installed",
        "blank-opened",
        "background-closed",
        "human-closed",
    ]


def test_browser_engine_probes_both_official_settlement_views_without_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []

    class Request:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com/api/order-center-server/"
            "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            "?t=1785300000123"
        )

        def __init__(self, settle_query_type: int) -> None:
            self.post_data_json = {
                "order": "asc",
                "queryType": "",
                "settleQueryType": settle_query_type,
                "pageNumber": 1,
                "pageSize": 20,
                "driverName": "",
                "sns": [],
            }

        def all_headers(self) -> dict[str, str]:
            return {"Authorization": "Bearer worker-memory-only"}

    class Route:
        def __init__(self, settle_query_type: int) -> None:
            self.request = Request(settle_query_type)

        class Response:
            status = 200

            def __init__(self, settle_query_type: int) -> None:
                self._settle_query_type = settle_query_type

            def body(self) -> bytes:
                total = 0 if self._settle_query_type == 1 else 137
                items = (
                    []
                    if total == 0
                    else [{"id": "private-id", "orderItemSn": "private-sn"}]
                )
                return json.dumps(
                    {
                        "data": {
                            "list": items,
                            "pageNo": 1,
                            "pageSize": 20,
                            "total": total,
                        }
                    },
                    separators=(",", ":"),
                ).encode("utf-8")

            def dispose(self) -> None:
                events.append("response-disposed")

        def fetch(self, **options: object) -> Response:
            assert options == {
                "max_redirects": 0,
                "timeout": engine_module.JSON_READ_TIMEOUT_MS,
            }
            events.append("request-fetched")
            return self.Response(self.request.post_data_json["settleQueryType"])

        def abort(self) -> None:
            events.append("request-aborted")

    class Trigger:
        def __init__(self, page: HumanPage, name: str) -> None:
            self._page = page
            self._name = name

        def filter(self, *, visible: bool) -> Trigger:
            assert visible is True
            return self

        @property
        def first(self) -> Trigger:
            return self

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert state == "visible"
            assert timeout == engine_module.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000
            events.append(f"{self._name}-clicked")
            if self._name == "settlement":
                self._page.settle_query_type = 1
            elif self._name == "credit":
                self._page.settle_query_type = 2
            elif self._name == "query":
                assert self._page.route_handlers
                self._page.route_handlers[0](
                    Route(self._page.settle_query_type)
                )

    class HumanPage:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def __init__(self) -> None:
            self.route_handlers: list[object] = []
            self.settle_query_type = 1

        def get_by_text(self, text: str, *, exact: bool) -> Trigger:
            assert exact is True
            controls = {
                "\u53ef\u7ed3\u7b97": "settle-ready",
                "\u7ed3\u7b97": "settlement",
                "\u4fe1\u7528": "credit",
                "\u6309\u8fd0\u5355\u663e\u793a": "waybill",
            }
            return Trigger(self, controls[text])

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Trigger:
            assert role == "button"
            assert exact is True
            controls = {
                "\u91cd\u7f6e": "reset",
                "\u67e5\u8be2": "query",
            }
            return Trigger(self, controls[name])

        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert callable(handler)
            self.route_handlers.append(handler)

        def unroute(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            self.route_handlers.remove(handler)

        def wait_for_timeout(self, timeout_ms: int) -> None:
            assert timeout_ms in {100, 300}

    human = HumanPage()

    class Context:
        pages: ClassVar[list[object]] = [human]

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._freeze_page(human)
    frozen_handler = human.route_handlers[0]

    result = worker.probe_settlement_views()

    assert result["schema_version"] == 1
    assert result["probe_kind"] == "chengfeng_settlement_views"
    assert result["operation"] == "list_waybills"
    assert result["views"] == [
        {
            "view": "settlement",
            "metrics": {
                "total_count": 0,
                "list_length": 0,
                "page_number": 1,
                "page_size": 20,
            },
            "response_structure_sha256": result["views"][0][
                "response_structure_sha256"
            ],
        },
        {
            "view": "credit",
            "metrics": {
                "total_count": 137,
                "list_length": 1,
                "page_number": 1,
                "page_size": 20,
            },
            "response_structure_sha256": result["views"][1][
                "response_structure_sha256"
            ],
        },
    ]
    serialized = json.dumps(result, sort_keys=True)
    assert "private-id" not in serialized
    assert "private-sn" not in serialized
    assert "worker-memory-only" not in serialized
    assert events.count("request-fetched") == 2
    assert events.count("response-disposed") == 2
    assert events.count("request-aborted") == 2
    assert "reset-clicked" not in events
    assert human.route_handlers == [frozen_handler]


def test_browser_engine_navigates_directly_to_the_historical_read_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []

    class ApprovedRequest:
        method = "POST"
        resource_type = "xhr"
        url = (
            "https://pc.chengfengkuaiyun.com"
            f"{engine_module.CHENGFENG_HISTORICAL_LIST_PATH}"
            "?t=1785300000123"
        )
        post_data_json: ClassVar[dict[str, object]] = {
            "deptCode": "370800",
            "pageNumber": 1,
            "pageSize": 100,
            "sortParams": [],
        }

        def all_headers(self) -> dict[str, str]:
            return {
                "Authorization": "Bearer worker-memory-only",
                "Cookie": "must-not-be-copied",
            }

    class Route:
        request = ApprovedRequest()

        class Response:
            status = 200

            def body(self) -> bytes:
                return json.dumps(
                    {
                        "data": {
                            "list": [
                                {
                                    "orderItemId": "private-id",
                                    "orderItemSn": "private-number",
                                    "carNumber": "private-vehicle",
                                }
                            ],
                            "total": "1",
                        }
                    }
                ).encode("utf-8")

            def dispose(self) -> None:
                events.append("native-response-disposed")

        def fetch(self, **options: object) -> Response:
            assert options == {
                "max_redirects": 0,
                "timeout": engine_module.JSON_READ_TIMEOUT_MS,
            }
            events.append("native-request-fetched")
            return self.Response()

        def abort(self) -> None:
            events.append("request-aborted")

    class Trigger:
        def __init__(
            self,
            page: HumanPage,
            name: str,
            *,
            filtered: bool = False,
        ) -> None:
            self.page = page
            self.name = name
            self.filtered = filtered

        def filter(self, *, visible: bool) -> Trigger:
            assert visible is True
            return Trigger(self.page, self.name, filtered=True)

        @property
        def first(self) -> Trigger:
            assert self.filtered
            return self

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert state == "visible"
            assert timeout == engine_module.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS
            events.append(f"{self.name}-visible")

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000
            events.append(f"{self.name}-clicked")
            if self.name == "query":
                assert self.page.route_handler is not None
                self.page.route_handler(Route())

    class HumanPage:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def __init__(self) -> None:
            self.route_handler: object | None = None

        def goto(
            self,
            url: str,
            *,
            wait_until: str,
            timeout: int,
        ) -> object:
            assert url == engine_module.CHENGFENG_HISTORICAL_ENTRY
            assert wait_until == "commit"
            assert timeout == engine_module.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS
            self.url = url
            events.append("historical-route-opened")
            return type("Response", (), {"status": 200})()

        def locator(self, selector: str) -> object:
            assert selector == "input[type='password']"
            return type(
                "Locator",
                (),
                {
                    "first": type(
                        "First",
                        (),
                        {"is_visible": lambda self: False},
                    )()
                },
            )()

        def get_by_text(self, text: str, *, exact: bool) -> Trigger:
            assert exact is True
            assert text == "按运单显示"
            return Trigger(self, "waybill-tab")

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Trigger:
            assert role == "button"
            assert exact is True
            if name == "登录":
                raise RuntimeError("not a login page")
            if name == "重置":
                return Trigger(self, "reset")
            if name == "查询":
                return Trigger(self, "query")
            raise AssertionError(name)

        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            self.route_handler = handler
            events.append("abort-route-installed")

        def unroute(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert handler is self.route_handler
            self.route_handler = None
            events.append("abort-route-removed")

        def wait_for_timeout(self, timeout_ms: int) -> None:
            assert timeout_ms in {100, 300}

        def close(self) -> None:
            events.append("human-closed")

    class BlankPage:
        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"

        def goto(self, url: str) -> None:
            assert url == "about:blank"

    human = HumanPage()

    class Context:
        pages: ClassVar[list[object]] = [human]

        def new_page(self) -> BlankPage:
            return BlankPage()

    worker = engine_module.BrowserEngine()
    worker._context = Context()

    probe = worker.prepare_automated(scope="settled_history")

    assert probe["metrics"] == {
        "total_count": 1,
        "list_length": 1,
        "page_number": 1,
        "page_size": 100,
    }
    assert worker._session_list_fixed_values == {"deptCode": "370800"}
    assert worker._session_list_body == ApprovedRequest.post_data_json
    assert events[:5] == [
        "historical-route-opened",
        "waybill-tab-visible",
        "reset-visible",
        "query-visible",
        "abort-route-installed",
    ]
    assert "settlement-tab-clicked" not in events
    assert "settle-ready-clicked" not in events


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [
        (
            {"data": {"list": [], "pageNo": 1, "pageSize": 30}},
            "browser_session_native_probe_contract_changed",
        ),
        (
            {"data": {"list": "not-a-list", "pageNo": 1, "pageSize": 30, "total": 0}},
            "browser_session_native_probe_contract_changed",
        ),
        (
            {"data": {"list": [], "pageNo": True, "pageSize": 30, "total": 0}},
            "browser_session_native_probe_contract_changed",
        ),
        (
            {"data": {"list": [], "pageNo": 1, "pageSize": 101, "total": 0}},
            "browser_session_native_probe_contract_changed",
        ),
        (
            {"data": {"list": [{}, {}], "pageNo": 1, "pageSize": 1, "total": 2}},
            "browser_session_native_probe_list_exceeds_response_page_size",
        ),
        (
            {"data": {"list": [{}], "pageNo": 1, "pageSize": 30, "total": 0}},
            "browser_session_native_probe_total_below_list_length",
        ),
    ],
)
def test_browser_worker_rejects_unsafe_native_list_probe_payload(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    expected_code: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    with pytest.raises(engine_module.BrowserReadError) as raised:
        engine_module._safe_native_list_probe(payload)

    assert raised.value.code == expected_code


def test_browser_worker_native_probe_normalizes_zero_page_size_without_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    first = {
        "data": {
            "list": [{"id": 101, "orderItemSn": "private-first"}],
            "pageNo": 0,
            "pageSize": 0,
            "total": 1,
        }
    }
    same_shape = {
        "data": {
            "list": [{"id": 999, "orderItemSn": "private-second"}],
            "pageNo": 0,
            "pageSize": 0,
            "total": 1,
        }
    }

    first_probe = engine_module._safe_native_list_probe(first)
    second_probe = engine_module._safe_native_list_probe(same_shape)

    assert first_probe["metrics"] == {
        "total_count": 1,
        "list_length": 1,
        "page_number": 1,
        "page_size": 30,
    }
    assert (
        first_probe["response_structure_sha256"]
        == second_probe["response_structure_sha256"]
    )
    serialized = json.dumps(first_probe, sort_keys=True)
    assert "private-first" not in serialized
    assert "private-second" not in serialized


def test_browser_worker_historical_probe_accepts_only_string_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    payload = {
        "data": {
            "list": [
                {
                    "orderItemId": "private",
                    "orderItemSn": "must-not-leave-probe",
                    "carNumber": "private",
                }
            ],
            "total": "1",
        }
    }

    probe = engine_module._safe_native_list_probe(
        payload,
        scope="settled_history",
        requested_page_number=1,
        requested_page_size=100,
    )

    assert probe["metrics"] == {
        "total_count": 1,
        "list_length": 1,
        "page_number": 1,
        "page_size": 100,
    }
    serialized = json.dumps(probe, sort_keys=True)
    assert "must-not-leave-probe" not in serialized


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        (
            "pageNo",
            7,
            "browser_session_native_probe_page_number_ahead_many",
        ),
        (
            "pageSize",
            50,
            "browser_session_native_probe_page_size_mismatch",
        ),
    ],
)
def test_browser_worker_classifies_safe_native_page_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
    expected_code: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    data = {"list": [], "pageNo": 1, "pageSize": 30, "total": 0}
    data[field] = value

    with pytest.raises(engine_module.BrowserReadError) as raised:
        engine_module._safe_native_list_probe({"data": data})

    assert raised.value.code == expected_code


@pytest.mark.parametrize(
    ("data", "expected_code"),
    [
        (
            {"list": [], "pageNo": 2, "pageSize": 30, "total": 0},
            "browser_session_native_probe_page_number_ahead_one",
        ),
        (
            {
                "list": [],
                "pageNo": 4,
                "pageSize": 30,
                "total": 0,
                "totalPage": 4,
            },
            "browser_session_native_probe_page_number_is_total_pages",
        ),
        (
            {
                "list": [],
                "pageNo": 30,
                "pageSize": 30,
                "total": 31,
                "totalPage": 2,
            },
            "browser_session_native_probe_page_number_is_page_size",
        ),
        (
            {
                "list": [],
                "pageNo": 9,
                "pageSize": 30,
                "total": 9,
                "totalPage": 1,
            },
            "browser_session_native_probe_page_number_is_total_count",
        ),
        (
            {
                "list": [],
                "pageNo": 8,
                "pageSize": 30,
                "total": 9,
                "totalPage": 1,
            },
            "browser_session_native_probe_page_number_ahead_many",
        ),
    ],
)
def test_browser_worker_reports_only_page_number_relationship(
    monkeypatch: pytest.MonkeyPatch,
    data: dict[str, object],
    expected_code: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    with pytest.raises(engine_module.BrowserReadError) as raised:
        engine_module._safe_native_list_probe({"data": data})

    assert raised.value.code == expected_code


def test_browser_worker_normalizes_platform_reversed_request_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    probe = engine_module._safe_native_list_probe(
        {
            "data": {
                "list": [{}, {}, {}, {}],
                "pageNo": 30,
                "pageSize": 1,
                "total": 9,
                "totalPage": 3,
            }
        },
        requested_page_number=1,
        requested_page_size=30,
    )

    assert probe["metrics"] == {
        "total_count": 9,
        "list_length": 4,
        "page_number": 1,
        "page_size": 30,
    }


def test_browser_worker_normalizes_reversed_partial_last_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    probe = engine_module._safe_native_list_probe(
        {
            "data": {
                "list": [{} for _ in range(15)],
                "pageNo": 50,
                "pageSize": 7,
                "total": 315,
                "totalPage": 7,
            }
        },
        requested_page_number=7,
        requested_page_size=50,
    )

    assert probe["metrics"] == {
        "total_count": 315,
        "list_length": 15,
        "page_number": 7,
        "page_size": 50,
    }


def test_browser_worker_rejects_unpaired_reversed_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    with pytest.raises(engine_module.BrowserReadError):
        engine_module._safe_native_list_probe(
            {
                "data": {
                    "list": [{}, {}, {}, {}],
                    "pageNo": 4,
                    "pageSize": 30,
                    "total": 9,
                }
            },
            requested_page_number=1,
            requested_page_size=30,
        )
    with pytest.raises(engine_module.BrowserReadError):
        engine_module._safe_native_list_probe(
            {
                "data": {
                    "list": [{}, {}, {}, {}],
                    "pageNo": 4,
                    "pageSize": 1,
                    "total": 9,
                }
            },
            requested_page_number=1,
            requested_page_size=30,
        )
    with pytest.raises(engine_module.BrowserReadError):
        engine_module._safe_native_list_probe(
            {"data": {"list": [], "total": 0}},
            scope="settled_history",
            requested_page_number=1,
            requested_page_size=100,
        )


def test_browser_worker_disposes_rejected_native_probe_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []

    class Response:
        status = 200

        def body(self) -> bytes:
            events.append("body-read")
            return b'{"data":{"list":"unsafe","pageNo":1,"pageSize":30,"total":0}}'

        def dispose(self) -> None:
            events.append("disposed")

    class Route:
        def fetch(self, **options: object) -> Response:
            assert options == {"max_redirects": 0, "timeout": 30_000}
            events.append("fetched")
            return Response()

    with pytest.raises(engine_module.BrowserReadError) as raised:
        engine_module._fetch_native_list_probe(
            Route(),
            request_body={
                "pageNumber": 1,
                "pageSize": 30,
            },
        )

    assert raised.value.code == "browser_session_native_probe_contract_changed"
    assert events == ["fetched", "body-read", "disposed"]


def test_operational_native_response_reports_only_rejected_field_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class Response:
        status = 200

        def body(self) -> bytes:
            return (
                b'{"data":{"list":[{"orderItemSn":"private-waybill"}],'
                b'"pageNo":"1","pageSize":30,"total":1}}'
            )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        engine_module._native_list_response(
            Response(),
            request_body={"pageNumber": 1, "pageSize": 30},
        )

    assert raised.value.code == "browser_session_native_probe_contract_changed"
    assert raised.value.safe_discovery is not None
    observation = raised.value.safe_discovery[0]
    assert observation["response_status"] == 200
    assert observation["content_kind"] == "json"
    assert {field["path"] for field in observation["response_fields"]} == {
        "$.data.list[].orderItemSn",
        "$.data.pageNo",
        "$.data.pageSize",
        "$.data.total",
    }
    assert "private-waybill" not in json.dumps(observation, sort_keys=True)


def test_browser_engine_removes_human_pages_before_automated_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    events: list[str] = []

    class HumanPage:
        def close(self) -> None:
            events.append("human-closed")

    class BlankPage:
        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*"
            assert callable(handler)
            events.append("route-installed")

        def goto(self, url: str) -> None:
            assert url == "about:blank"
            events.append("blank-opened")

        def close(self) -> None:
            events.append("blank-closed")

    human = HumanPage()
    blank = BlankPage()

    class Context:
        pages: ClassVar[list[object]] = [human]

        def new_page(self) -> BlankPage:
            events.append("blank-created")
            self.pages.append(blank)
            return blank

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._session_headers = {"authorization": "Bearer worker-memory-only"}
    worker._session_list_fixed_values = {
        "order": "desc",
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_cache_query = "t=1785300000123"
    monkeypatch.setattr(
        worker,
        "_wait_for_session_headers",
        lambda pages, *, scope: None,
    )

    worker.prepare_automated()

    assert events == [
        "blank-created",
        "route-installed",
        "blank-opened",
        "human-closed",
    ]


def test_browser_engine_close_clears_worker_private_session_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class Context:
        def close(self) -> None:
            return None

        def remove_listener(self, event: str, handler: object) -> None:
            assert event == "request"
            assert callable(handler)

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._session_request_handler = lambda request: request
    worker._session_headers = {"authorization": "Bearer worker-memory-only"}
    worker._session_list_fixed_values = {
        "order": "desc",
        "queryType": "2",
        "settleQueryType": 1,
    }
    worker._session_list_cache_query = "t=1785300000123"
    worker._session_list_body = {"order": "desc"}
    worker._session_list_body_sha256 = "a" * 64
    worker._session_native_probe = {
        "schema_version": 1,
        "probe_kind": "chengfeng_settlement_list",
    }

    worker.close()

    assert worker._session_headers is None
    assert worker._session_list_fixed_values is None
    assert worker._session_list_cache_query is None
    assert worker._session_list_body is None
    assert worker._session_list_body_sha256 is None
    assert worker._session_native_probe is None
    assert worker._session_request_handler is None


class _FakeProcess:
    is_alive = True

    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.requests: list[dict[str, object]] = []

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        del timeout_seconds
        request = json.loads(line)
        self.requests.append(request)
        response = dict(self.response)
        response["request_id"] = request["request_id"]
        return json.dumps(response)


def _runtime(
    tmp_path: Path,
    *,
    process: _FakeProcess,
) -> IsolatedBrowserRuntime:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    runtime._process = process  # type: ignore[assignment]
    runtime._selected_browser = "msedge"
    return runtime


def _worker_response(
    *,
    read_result: dict[str, object] | None,
    ok: bool = True,
    error_code: str | None = None,
    discovery: list[dict[str, object]] | None = None,
    prepare_result: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 6,
        "request_id": "replaced",
        "ok": ok,
        "selected_browser": "msedge",
        "error_code": error_code,
        "discovery": discovery,
        "browser_open": True,
        "read_result": read_result,
        "prepare_result": prepare_result,
        "batch_result": None,
    }


def test_parent_reverifies_and_removes_staged_read_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "dahe.adapters.chengfeng.browser_runtime.uuid4",
        lambda: SimpleNamespace(hex="json1"),
    )
    content = b'{"data":{"list":[]}}'
    runtime_root = tmp_path / "data" / "runtime" / "browser-worker" / "read-results"
    target = runtime_root / "read-json1" / "payload.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    process = _FakeProcess(
        _worker_response(
            read_result={
                "relative_path": "read-json1/payload.json",
                "sha256": hashlib.sha256(content).hexdigest(),
                "byte_size": len(content),
                "media_type": "application/json",
                "status_code": 200,
            }
        )
    )
    runtime = _runtime(tmp_path, process=process)
    authorized = LiveAuthorizedRequest(
        ReadRequest(
            operation="list_waybills",
            method="POST",
            url="https://platform.example.invalid/api/list",
            parameters_location="json",
            parameters={"pageNumber": 1, "sns": ()},
        ),
        SimpleNamespace(),
    )

    payload = runtime.read(authorized)

    assert payload == BrowserReadPayload(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        media_type="application/json",
        byte_size=len(content),
        status_code=200,
    )
    assert not target.exists()
    assert process.requests[0]["parameters"] == {"pageNumber": 1, "sns": []}


def test_parent_rejects_tampered_read_payload_and_removes_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "dahe.adapters.chengfeng.browser_runtime.uuid4",
        lambda: SimpleNamespace(hex="json2"),
    )
    content = b"tampered"
    runtime_root = tmp_path / "data" / "runtime" / "browser-worker" / "read-results"
    target = runtime_root / "read-json2" / "payload.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    process = _FakeProcess(
        _worker_response(
            read_result={
                "relative_path": "read-json2/payload.json",
                "sha256": "0" * 64,
                "byte_size": len(content),
                "media_type": "application/json",
                "status_code": 200,
            }
        )
    )
    runtime = _runtime(tmp_path, process=process)
    authorized = LiveAuthorizedRequest(
        ReadRequest(
            operation="list_waybills",
            method="POST",
            url="https://platform.example.invalid/api/list",
            parameters_location="json",
            parameters={},
        ),
        SimpleNamespace(),
    )

    with pytest.raises(BrowserRuntimeError, match="payload"):
        runtime.read(authorized)

    assert not target.exists()


def test_parent_maps_read_failure_without_echoing_signed_url(tmp_path: Path) -> None:
    process = _FakeProcess(
        _worker_response(
            read_result=None,
            ok=False,
            error_code="browser_read_network_failed",
        )
    )
    runtime = _runtime(tmp_path, process=process)
    signed_url = "https://images.example.invalid/ticket.jpg?signature=secret"
    authorized = LiveAuthorizedImageRequest(
        request=ReadRequest(
            operation="download_ticket_image",
            method="GET",
            url=signed_url,
            parameters_location="query",
            parameters={},
        ),
        url_sha256=hashlib.sha256(signed_url.encode("utf-8")).hexdigest(),
    )

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime.read(authorized)

    assert raised.value.code == "browser_read_network_failed"
    assert signed_url not in str(raised.value)
    assert "secret" not in str(raised.value)


def test_parent_preserves_validated_reset_structure_on_field_set_mismatch(
    tmp_path: Path,
) -> None:
    observation = {
        "method": "POST",
        "origin": "https://pc.chengfengkuaiyun.com",
        "path": (
            "/api/order-center-server/app/clientOrderItem/"
            "queryWaitSettlementOrderItemListPC"
        ),
        "path_sha256": None,
        "query_keys": ["t"],
        "request_fields": [
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.pageSize", "type": "integer"},
        ],
        "resource_kind": "json_api",
        "response_status": None,
        "content_kind": None,
        "response_fields": [],
    }
    process = _FakeProcess(
        _worker_response(
            read_result=None,
            ok=False,
            error_code="browser_session_list_body_fields_changed",
            discovery=[observation],
        )
    )
    runtime = _runtime(tmp_path, process=process)
    authorized = LiveAuthorizedRequest(
        ReadRequest(
            operation="list_waybills",
            method="POST",
            url=(
                "https://pc.chengfengkuaiyun.com/api/order-center-server/"
                "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
            ),
            parameters_location="json",
            parameters={"pageNumber": 1, "pageSize": 30},
        ),
        SimpleNamespace(),
    )

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime.read(authorized)

    assert raised.value.code == "browser_session_list_body_fields_changed"
    assert raised.value.safe_discovery == (observation,)


def test_parent_preserves_validated_native_response_shape_diagnostics(
    tmp_path: Path,
) -> None:
    observation = {
        "method": "POST",
        "origin": "https://pc.chengfengkuaiyun.com",
        "path": (
            "/api/order-center-server/app/clientOrderItem/"
            "queryWaitSettlementOrderItemListPC"
        ),
        "path_sha256": None,
        "query_keys": ["t"],
        "request_fields": [
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.pageSize", "type": "integer"},
        ],
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [
            {"path": "$.data.pageNo", "type": "string"},
            {"path": "$.data.total", "type": "integer"},
        ],
    }
    process = _FakeProcess(
        _worker_response(
            read_result=None,
            ok=False,
            error_code="browser_session_native_probe_contract_changed",
            discovery=[observation],
        )
    )
    runtime = _runtime(tmp_path, process=process)

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime.prepare_operational_compat()

    assert raised.value.code == "browser_session_native_probe_contract_changed"
    assert raised.value.safe_discovery == (observation,)
