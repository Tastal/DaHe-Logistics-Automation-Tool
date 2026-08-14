from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest

PROJECT_ROOT = Path(__file__).parents[3]
BROWSER_SOURCE = PROJECT_ROOT / "browser-runtime" / "src"
DAILY_ENTRY = "https://pc.chengfengkuaiyun.com/wayBill"
DAILY_URL = "https://pc.chengfengkuaiyun.com/api/hz/orderItem/queryOrderItemListPC"


def _load_worker_modules(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any]:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    for name in (
        "dahe_browser_worker.engine",
        "dahe_browser_worker.protocol",
    ):
        sys.modules.pop(name, None)
    import dahe_browser_worker.engine as engine
    import dahe_browser_worker.protocol as protocol

    return engine, protocol


def _daily_parameters() -> dict[str, object]:
    return {
        "carNumber": "",
        "filterParamList": [],
        "loadEndTime": "2026-07-28 20:15:00",
        "loadStartTime": "2026-07-28 14:00:00",
        "pageNumber": 1,
        "pageSize": 100,
        "receivePlace": "榆林",
        "remarks": None,
    }


def _dynamic_daily_parameters() -> dict[str, object]:
    return {
        "deptCode": "",
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 20,
        "sortParams": [],
    }


def _daily_payload() -> dict[str, object]:
    return {
        "code": 200,
        "success": True,
        "data": {
            "total": 1,
            "list": [
                {
                    "id": 900000001,
                    "sn": "YD-MUST-NOT-LEAK",
                    "carNumber": "陕K-MUST-NOT-LEAK",
                    "loadPunchDate": "2026-07-28 15:00:00",
                    "receivePlace": "榆林-MUST-NOT-LEAK",
                    "driverPhone": "13800000000",
                    "token": "must-not-leak",
                }
            ],
        },
    }


def test_daily_scope_hash_excludes_pagination_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    first_page = _daily_parameters()
    second_page = {
        **first_page,
        "pageNumber": 2,
        "pageSize": 50,
    }

    assert engine_module._daily_scope_sha256(first_page) == (
        engine_module._daily_scope_sha256(second_page)
    )

    changed_range = {
        **first_page,
        "loadEndTime": "2026-07-29 14:30:00",
    }
    assert engine_module._daily_scope_sha256(first_page) != (
        engine_module._daily_scope_sha256(changed_range)
    )


@pytest.mark.parametrize(
    ("now", "expected_start", "expected_end"),
    [
        (
            datetime(2026, 7, 30, 13, 0),
            "2026-07-28 14:00:00",
            "2026-07-29 14:30:00",
        ),
        (
            datetime(2026, 7, 30, 14, 30),
            "2026-07-29 14:00:00",
            "2026-07-30 14:30:00",
        ),
    ],
)
def test_daily_discovery_uses_only_a_completed_business_window(
    monkeypatch: pytest.MonkeyPatch,
    now: datetime,
    expected_start: str,
    expected_end: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    body = engine_module._daily_discovery_body(now)

    assert body == {
        "loadEndTime": expected_end,
        "loadStartTime": expected_start,
        "pageNumber": 1,
        "pageSize": 5,
        "receivePlace": "榆林",
    }


def test_daily_protocol_accepts_only_fixed_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)

    prepared = protocol.parse_command(
        json.dumps(
            {
                "schema_version": 9,
                "command": "prepare_daily",
                "request_id": "prepare-daily-1",
            }
        )
    )
    assert isinstance(prepared, protocol.PrepareDailyCommand)

    automated_transition = protocol.parse_command(
        json.dumps(
            {
                "schema_version": 9,
                "command": "prepare_daily_from_automated",
                "request_id": "prepare-daily-automated-1",
            }
        )
    )
    assert isinstance(
        automated_transition,
        protocol.PrepareDailyFromAutomatedCommand,
    )

    operational_daily = protocol.parse_command(
        json.dumps(
            {
                "schema_version": 9,
                "command": "prepare_operational_daily",
                    "contract_subject_code": "shanxi_guienbo",
                "request_id": "prepare-operational-daily-1",
            }
        )
    )
    assert isinstance(
        operational_daily,
        protocol.PrepareOperationalDailyCommand,
    )

    read = protocol.parse_command(
        json.dumps(
            {
                "schema_version": 9,
                "command": "read_daily_json",
                "request_id": "read-daily-1",
                "operation": "list_daily_waybills",
                "method": "POST",
                "url": DAILY_URL,
                "parameters": _daily_parameters(),
            }
        )
    )
    assert isinstance(read, protocol.ReadDailyJsonCommand)
    assert read.url == DAILY_URL
    assert read.parameters["remarks"] is None
    assert read.parameters["filterParamList"] == ()

    unsafe = (
        {
            "schema_version": 9,
            "command": "prepare_daily",
            "request_id": "prepare-daily-url",
            "url": "https://example.invalid",
        },
        {
            "schema_version": 9,
            "command": "read_daily_json",
            "request_id": "read-daily-url",
            "operation": "list_daily_waybills",
            "method": "POST",
            "url": "https://example.invalid/api/list",
            "parameters": _daily_parameters(),
        },
        {
            "schema_version": 9,
            "command": "read_daily_json",
            "request_id": "read-daily-method",
            "operation": "list_daily_waybills",
            "method": "GET",
            "url": DAILY_URL,
            "parameters": _daily_parameters(),
        },
        {
            "schema_version": 9,
            "command": "read_json",
            "request_id": "read-daily-via-settlement",
            "operation": "list_daily_waybills",
            "method": "POST",
            "url": DAILY_URL,
            "parameters": _daily_parameters(),
        },
    )
    for payload in unsafe:
        with pytest.raises(protocol.ProtocolError):
            protocol.parse_command(json.dumps(payload))


def _daily_protocol_observation() -> dict[str, object]:
    return {
        "method": "POST",
        "origin": "https://pc.chengfengkuaiyun.com",
        "path": "/api/hz/orderItem/queryOrderItemListPC",
        "path_sha256": None,
        "query_keys": ["t"],
        "request_fields": [
            {"path": "$.loadEndTime", "type": "string"},
            {"path": "$.loadStartTime", "type": "string"},
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.pageSize", "type": "integer"},
            {"path": "$.receivePlace", "type": "string"},
        ],
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [
            {"path": "$.data.list[].carNumber", "type": "string"},
            {"path": "$.data.list[].id", "type": "integer"},
            {"path": "$.data.list[].sn", "type": "string"},
            {"path": "$.data.list[].loadPunchDate", "type": "string"},
            {"path": "$.data.total", "type": "integer"},
        ],
    }


def test_prepare_daily_response_contains_exactly_one_sanitized_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    command = protocol.PrepareDailyCommand(request_id="prepare-daily-safe")
    observation = _daily_protocol_observation()

    output = json.loads(
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=[observation],
            browser_open=True,
            read_result=None,
            prepare_result=None,
        )
    )

    assert output["discovery"] == [observation]
    assert set(output) == {
        "batch_result",
        "schema_version",
        "request_id",
        "ok",
        "selected_browser",
        "error_code",
        "discovery",
        "browser_open",
        "read_result",
        "prepare_result",
    }
    assert output["prepare_result"] is None
    assert output["read_result"] is None
    assert output["batch_result"] is None

    with pytest.raises(protocol.ProtocolError):
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=[
                {
                    **observation,
                    "raw_response": {"sn": "must-not-leak"},
                }
            ],
            browser_open=True,
            read_result=None,
            prepare_result=None,
        )


def test_automated_daily_response_contains_freshness_and_single_tab_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    command = protocol.PrepareDailyFromAutomatedCommand(
        request_id="prepare-daily-fresh"
    )
    evidence = {
        "schema_version": 1,
        "evidence_kind": "chengfeng_daily_freshness",
        "cache_disabled_during_reload": True,
        "ignore_cache_reload": True,
        "cache_refresh_count": 1,
        "fresh_query_response_observed": True,
        "page_count": 1,
        "route": "/wayBill",
    }

    output = json.loads(
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=[_daily_protocol_observation()],
            browser_open=True,
            read_result=None,
            prepare_result=evidence,
        )
    )

    assert output["prepare_result"] == evidence
    with pytest.raises(protocol.ProtocolError):
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=[_daily_protocol_observation()],
            browser_open=True,
            read_result=None,
            prepare_result={**evidence, "page_count": 2},
        )


def test_direct_operational_daily_response_uses_the_same_safe_evidence_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    command = protocol.PrepareOperationalDailyCommand(
        request_id="prepare-operational-daily-fresh"
    )
    evidence = {
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

    output = json.loads(
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            discovery=[_daily_protocol_observation()],
            browser_open=True,
            read_result=None,
            prepare_result=evidence,
        )
    )

    assert output["discovery"] == [_daily_protocol_observation()]
    assert output["prepare_result"] == evidence


class _NativeResponse:
    def __init__(
        self,
        *,
        payload: dict[str, object],
        status: int = 200,
        content_type: str = "application/json",
        events: list[str],
        request: _Request | None = None,
    ) -> None:
        self.status = status
        self.headers = {"content-type": content_type}
        self._payload = payload
        self._events = events
        self.request = request

    def body(self) -> bytes:
        self._events.append("native-body-read")
        return json.dumps(self._payload, ensure_ascii=False).encode("utf-8")

    def dispose(self) -> None:
        self._events.append("native-response-disposed")


class _DailyRequestContext:
    def __init__(
        self,
        *,
        payload: dict[str, object],
        status: int,
        events: list[str],
        allowed_page_sizes: tuple[int, ...] = (5,),
    ) -> None:
        self._payload = payload
        self._status = status
        self._events = events
        self._allowed_page_sizes = allowed_page_sizes
        self.calls: list[tuple[str, dict[str, object]]] = []

    def fetch(self, url: str, **options: object) -> _NativeResponse:
        self.calls.append((url, dict(options)))
        self._events.append("daily-native-fetch")
        assert url == DAILY_URL
        assert options["method"] == "POST"
        assert options["fail_on_status_code"] is False
        assert options["max_redirects"] == 0
        assert options["timeout"] == 30_000
        assert options["headers"] == {
            "authorization": "Bearer worker-memory-only"
        }
        body = options["data"]
        assert isinstance(body, dict)
        assert set(body) == {
            "loadEndTime",
            "loadStartTime",
            "pageNumber",
            "pageSize",
            "receivePlace",
        }
        assert body["pageNumber"] == 1
        assert body["pageSize"] in self._allowed_page_sizes
        assert body["receivePlace"] == "榆林"
        return _NativeResponse(
            payload=self._payload,
            status=self._status,
            events=self._events,
        )


class _Request:
    def __init__(
        self,
        *,
        method: str,
        resource_type: str,
        url: str,
        post_data: dict[str, object] | None = None,
    ) -> None:
        self.method = method
        self.resource_type = resource_type
        self.url = url
        self.post_data_json = post_data

    def all_headers(self) -> dict[str, str]:
        return {
            "authorization": "Bearer worker-memory-only",
            "cookie": "must-not-copy",
        }


class _Route:
    def __init__(
        self,
        *,
        request: _Request,
        response: _NativeResponse | None,
        events: list[str],
    ) -> None:
        self.request = request
        self._response = response
        self._events = events

    def fetch(self, **options: object) -> _NativeResponse:
        assert options == {"max_redirects": 0, "timeout": 30_000}
        self._events.append("native-fetch")
        assert self._response is not None
        return self._response

    def abort(self) -> None:
        self._events.append(f"abort:{self.request.method}:{self.request.url}")

    def continue_(self, **options: object) -> None:
        post_data = options.pop("post_data", None)
        assert not options
        if post_data is not None:
            assert isinstance(post_data, str)
            self.request.post_data_json = json.loads(post_data)
        self._events.append(f"continue:{self.request.method}:{self.request.url}")


class _NavigationResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class _DailyPage:
    def __init__(
        self,
        *,
        payload: dict[str, object],
        events: list[str],
        status: int = 200,
        final_url: str = DAILY_ENTRY,
        extra_post: bool = False,
    ) -> None:
        self._payload = payload
        self._events = events
        self._status = status
        self._final_url = final_url
        self._extra_post = extra_post
        self._handler: Any = None
        self.url = "about:blank"

    def route(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        self._handler = handler
        self._events.append("route-installed")

    def unroute(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        assert handler is self._handler
        self._handler = None
        self._events.append("route-removed")

    def goto(self, url: str, **options: object) -> _NavigationResponse:
        assert url == DAILY_ENTRY
        assert options == {"wait_until": "commit", "timeout": 60_000}
        document = _Request(
            method="GET",
            resource_type="document",
            url=DAILY_ENTRY,
        )
        self._handler(_Route(request=document, response=None, events=self._events))
        self.url = self._final_url
        return _NavigationResponse(self._status)

    def get_by_role(
        self,
        role: str,
        *,
        name: str,
        exact: bool,
    ) -> _DailyQueryButton:
        assert role == "button"
        assert name == "查询"
        assert exact is True
        return _DailyQueryButton(page=self)

    def _click_query(self) -> None:
        self._events.append("query-clicked")
        daily_request = _Request(
            method="POST",
            resource_type="xhr",
            url=f"{DAILY_URL}?t=1785300000123",
            post_data=_daily_parameters(),
        )
        native = _NativeResponse(
            payload=self._payload,
            status=self._status,
            events=self._events,
        )
        self._handler(
            _Route(
                request=daily_request,
                response=native,
                events=self._events,
            )
        )
        if self._extra_post:
            unexpected = _Request(
                method="POST",
                resource_type="xhr",
                url="https://pc.chengfengkuaiyun.com/api/unsafe/write",
                post_data={"id": 1},
            )
            self._handler(
                _Route(
                    request=unexpected,
                    response=None,
                    events=self._events,
                )
            )

    def wait_for_timeout(self, timeout_ms: int) -> None:
        assert timeout_ms in {100, 300}

    def close(self) -> None:
        self._events.append("daily-page-closed")


class _DailyQueryButton:
    def __init__(self, *, page: _DailyPage) -> None:
        self._page = page

    @property
    def first(self) -> _DailyQueryButton:
        return self

    def wait_for(self, *, state: str, timeout: int) -> None:
        assert state == "visible"
        assert timeout == 60_000
        self._page._events.append("query-visible")

    def click(self) -> None:
        self._page._click_query()


class _PageOwnedDailyPage:
    def __init__(
        self,
        *,
        payload: dict[str, object],
        events: list[str],
        navigation_body: dict[str, object] | None = None,
        scope_matches: bool = True,
        emit_navigation_request: bool = True,
    ) -> None:
        self._payload = payload
        self._events = events
        self._navigation_body = (
            dict(navigation_body)
            if navigation_body is not None
            else _daily_parameters()
        )
        self._scope_matches = scope_matches
        self._emit_navigation_request = emit_navigation_request
        self._handler: Any = None
        self._expected_response: _PageOwnedExpectedResponse | None = None
        self.url = "https://pc.chengfengkuaiyun.com/billablewaybill"
        self.closed = False

    def route(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        self._handler = handler
        self._events.append("page-route-installed")

    def unroute(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        assert handler is self._handler
        self._handler = None
        self._events.append("page-route-removed")

    def goto(self, url: str, **options: object) -> _NavigationResponse:
        assert url == DAILY_ENTRY
        assert options == {"wait_until": "domcontentloaded", "timeout": 60_000}
        if self._handler is None:
            self.url = DAILY_ENTRY
            self._events.append("human-daily-navigation")
            return _NavigationResponse(200)
        assert self._handler is not None
        self._handler(
            _Route(
                request=_Request(
                    method="GET",
                    resource_type="document",
                    url=DAILY_ENTRY,
                ),
                response=None,
                events=self._events,
            )
        )
        self.url = DAILY_ENTRY
        self._handler(
            _Route(
                request=_Request(
                    method="POST",
                    resource_type="xhr",
                    url=(
                        "https://pc.chengfengkuaiyun.com/api/"
                        "order-center-server/app/order/"
                        "getPublicOrderConfig?t=1785300000001"
                    ),
                    post_data={"pageNumber": 1},
                ),
                response=None,
                events=self._events,
            )
        )
        if self._emit_navigation_request:
            self._handler(
                _Route(
                    request=_Request(
                        method="POST",
                        resource_type="xhr",
                        url=f"{DAILY_URL}?t=1785300000123",
                        post_data=self._navigation_body,
                    ),
                    response=_NativeResponse(
                        payload=self._payload,
                        events=self._events,
                    ),
                    events=self._events,
                )
            )
        return _NavigationResponse(200)

    def reload(self, **options: object) -> _NavigationResponse:
        assert options == {"wait_until": "domcontentloaded", "timeout": 60_000}
        self._events.append("daily-page-cache-refreshed")
        return self.goto(
            DAILY_ENTRY,
            wait_until="domcontentloaded",
            timeout=60_000,
        )

    def bring_to_front(self) -> None:
        self._events.append("daily-human-page-selected")

    def wait_for_timeout(self, timeout_ms: int) -> None:
        assert timeout_ms == 100

    def wait_for_load_state(self, state: str, *, timeout: int) -> None:
        assert state == "domcontentloaded"
        assert timeout == 60_000

    def wait_for_function(self, _script: str, *, timeout: int) -> None:
        assert timeout == 15_000

    def get_by_text(self, text: str, *, exact: bool) -> _PageOwnedControl:
        assert text == "运单管理"
        assert exact is True
        return _PageOwnedControl(page=self, name=text)

    def get_by_role(
        self,
        role: str,
        *,
        name: str,
        exact: bool,
    ) -> _PageOwnedControl:
        assert role == "button"
        assert name in {"重置", "查询"}
        assert exact is True
        return _PageOwnedControl(page=self, name=name)

    def expect_response(
        self,
        predicate: Any,
        *,
        timeout: int,
    ) -> _PageOwnedExpectedResponse:
        assert timeout == 60_000
        expected = _PageOwnedExpectedResponse(page=self, predicate=predicate)
        self._expected_response = expected
        return expected

    def locator(self, selector: str) -> _PageOwnedPaginationLocator:
        assert "pagination" in selector
        return _PageOwnedPaginationLocator(total=int(self._payload["data"]["total"]))

    def _click_control(self, name: str) -> None:
        if name == "重置":
            self._events.append("daily-reset-clicked")
            return
        assert name == "查询"
        self._events.append("daily-query-clicked")
        request = _Request(
            method="POST",
            resource_type="xhr",
            url=f"{DAILY_URL}?t=1785300000789",
            post_data=dict(self._navigation_body),
        )
        response = _NativeResponse(
            payload=self._payload,
            events=self._events,
            request=request,
        )
        assert self._handler is not None
        self._handler(
            _Route(
                request=request,
                response=response,
                events=self._events,
            )
        )
        expected = self._expected_response
        if expected is not None and expected.predicate(response):
            expected.value = response

    def is_closed(self) -> bool:
        return self.closed

    def evaluate(
        self,
        script: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        assert "fetch" in script
        assert self._handler is not None
        body = payload["body"]
        assert isinstance(body, dict)
        expected_fields = (
            set(self._navigation_body)
            | {"loadEndTime", "loadStartTime", "receivePlace"}
            if self._emit_navigation_request
            else {
                "loadEndTime",
                "loadStartTime",
                "pageNumber",
                "pageSize",
                "receivePlace",
            }
        )
        assert set(body) == expected_fields
        start = datetime.strptime(
            str(body["loadStartTime"]),
            "%Y-%m-%d %H:%M:%S",
        )
        end = datetime.strptime(
            str(body["loadEndTime"]),
            "%Y-%m-%d %H:%M:%S",
        )
        assert (start.hour, start.minute, start.second) == (14, 0, 0)
        assert (end - start).total_seconds() == (24 * 60 + 30) * 60
        assert body["receivePlace"] == "榆林"
        for name in ("deptCode", "order", "sortParams"):
            if name in self._navigation_body:
                assert body[name] == self._navigation_body[name]
        response_payload = json.loads(
            json.dumps(self._payload, ensure_ascii=False)
        )
        if self._scope_matches:
            for item in response_payload["data"]["list"]:
                item["loadPunchDate"] = (
                    start.replace(hour=15, minute=0, second=0)
                ).strftime("%Y-%m-%d %H:%M:%S")
                item["receivePlace"] = "榆林-MUST-NOT-LEAK"
        self._handler(
            _Route(
                request=_Request(
                    method="POST",
                    resource_type="fetch",
                    url=f"{DAILY_URL}?t=1785300000456",
                    post_data=body,
                ),
                response=_NativeResponse(
                    payload=response_payload,
                    events=self._events,
                ),
                events=self._events,
            )
        )
        self._events.append("page-evaluate-fetch")
        return {
            "status": 200,
            "redirected": False,
            "contentType": "application/json",
            "body": json.dumps(response_payload, ensure_ascii=False),
        }

    def close(self) -> None:
        self.closed = True
        self._events.append("page-owned-daily-page-closed")


class _PageOwnedControl:
    def __init__(self, *, page: _PageOwnedDailyPage, name: str) -> None:
        self._page = page
        self._name = name

    @property
    def first(self) -> _PageOwnedControl:
        return self

    def filter(self, *, visible: bool) -> _PageOwnedControl:
        assert visible is True
        return self

    def is_visible(self) -> bool:
        return True

    def wait_for(self, *, state: str, timeout: int) -> None:
        assert state == "visible"
        assert timeout == 60_000

    def click(self, *, timeout: int) -> None:
        assert timeout == 60_000
        self._page._click_control(self._name)


class _PageOwnedExpectedResponse:
    def __init__(self, *, page: _PageOwnedDailyPage, predicate: Any) -> None:
        self._page = page
        self.predicate = predicate
        self.value: _NativeResponse | None = None

    def __enter__(self) -> _PageOwnedExpectedResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self._page._expected_response = None


class _PageOwnedPaginationLocator:
    def __init__(self, *, total: int) -> None:
        self._total = total

    def count(self) -> int:
        return 1

    def nth(self, index: int) -> _PageOwnedPaginationLocator:
        assert index == 0
        return self

    def inner_text(self, *, timeout: int) -> str:
        assert timeout == 1_000
        return f"共 {self._total} 条"


class _HumanPage:
    def __init__(
        self,
        *,
        name: str,
        events: list[str],
        fail_on_close: bool = False,
    ) -> None:
        self._name = name
        self._events = events
        self._fail_on_close = fail_on_close
        self._handler: Any = None
        self.closed = False

    def route(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        self._handler = handler
        self._events.append(f"human-route-installed:{self._name}")

    def unroute(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        assert handler is self._handler
        self._handler = None
        self._events.append(f"human-route-removed:{self._name}")

    def is_closed(self) -> bool:
        return self.closed

    def assert_network_is_blocked(self) -> None:
        assert self._handler is not None

        class Route:
            request = None

            def abort(inner_self) -> None:
                self._events.append(
                    f"human-request-aborted:{self._name}"
                )

        self._handler(Route())

    def close(self) -> None:
        if self._fail_on_close:
            self._events.append(f"human-page-close-failed:{self._name}")
            raise RuntimeError("simulated page close failure")
        self.closed = True
        self._events.append(f"human-page-closed:{self._name}")


class _BlockedBlankPage:
    def __init__(self, *, events: list[str]) -> None:
        self._events = events
        self._handler: Any = None
        self.url = ""
        self.closed = False

    def route(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        self._handler = handler
        self._events.append("blank-route-installed")

    def goto(self, url: str) -> None:
        assert url == "about:blank"
        self.url = url
        self._events.append("blank-opened")

    def assert_network_is_blocked(self) -> None:
        assert self._handler is not None

        class Route:
            def abort(inner_self) -> None:
                self._events.append("blank-request-aborted")

        self._handler(Route())

    def close(self) -> None:
        self.closed = True
        self._events.append("blank-page-closed")


def _prepared_daily_engine(
    engine_module: Any,
    *,
    payload: dict[str, object],
    status: int = 200,
    final_url: str = DAILY_ENTRY,
    extra_post: bool = False,
    human_close_fails: bool = False,
    allowed_page_sizes: tuple[int, ...] = (5,),
) -> tuple[Any, list[str], Any]:
    events: list[str] = []
    request_context = _DailyRequestContext(
        payload=payload,
        status=status,
        events=events,
        allowed_page_sizes=allowed_page_sizes,
    )
    human_pages = [
        _HumanPage(name="first", events=events),
        _HumanPage(
            name="second",
            events=events,
            fail_on_close=human_close_fails,
        ),
    ]

    class Context:
        def __init__(self) -> None:
            self.pages: list[object] = [*human_pages]
            self.request = request_context
            self.blank_page: _BlockedBlankPage | None = None
            self._new_page_count = 0

        def new_page(self) -> _BlockedBlankPage:
            self._new_page_count += 1
            assert self._new_page_count == 1
            self.blank_page = _BlockedBlankPage(events=events)
            self.pages.append(self.blank_page)
            return self.blank_page

    worker = engine_module.BrowserEngine()
    worker._install_single_chengfeng_page_guard = lambda: None
    context = Context()
    worker._context = context
    worker._wait_for_session_headers = lambda pages: (
        events.append("settlement-session-probed"),
        setattr(
            worker,
            "_session_headers",
            {"authorization": "Bearer worker-memory-only"},
        ),
        {"probe": "safe"},
    )[-1]
    return worker, events, context


def _prepared_page_owned_daily_engine(
    engine_module: Any,
    *,
    payload: dict[str, object],
    navigation_body: dict[str, object] | None = None,
    scope_matches: bool = True,
    emit_navigation_request: bool = True,
) -> tuple[Any, list[str], Any]:
    engine_module._ensure_contract_subject = (
        lambda _page, *, contract_subject_code, login_page: {
            "contract_subject_code": contract_subject_code,
            "contract_subject_switch_performed": False,
        }
    )
    events: list[str] = []
    page = _PageOwnedDailyPage(
        payload=payload,
        events=events,
        navigation_body=navigation_body,
        scope_matches=scope_matches,
        emit_navigation_request=emit_navigation_request,
    )

    class FailingRequestContext:
        def fetch(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("APIRequestContext must not issue the daily query")

    class Context:
        request = FailingRequestContext()

        def __init__(self) -> None:
            self.pages: list[object] = [page]

        def new_page(self) -> _PageOwnedDailyPage:
            controlled = _PageOwnedDailyPage(
                payload=payload,
                events=events,
                navigation_body=navigation_body,
                scope_matches=scope_matches,
                emit_navigation_request=emit_navigation_request,
            )
            self.pages.append(controlled)
            return controlled

        def new_cdp_session(self, target: object) -> object:
            assert isinstance(target, _PageOwnedDailyPage)

            class CdpSession:
                def send(
                    self,
                    command: str,
                    parameters: object | None = None,
                ) -> object:
                    events.append(f"cdp:{command}")
                    if command == "Browser.getWindowForTarget":
                        assert parameters is None
                        return {"windowId": 9}
                    if command == "Browser.getWindowBounds":
                        assert parameters == {"windowId": 9}
                        return {"bounds": {"windowState": "minimized"}}
                    if command == "Browser.setWindowBounds":
                        assert parameters == {
                            "windowId": 9,
                            "bounds": {"windowState": "normal"},
                        }
                        return None
                    if command == "Network.setCacheDisabled":
                        assert parameters in (
                            {"cacheDisabled": True},
                            {"cacheDisabled": False},
                        )
                        return None
                    if command == "Page.reload":
                        assert parameters == {"ignoreCache": True}
                        target.reload(
                            wait_until="domcontentloaded",
                            timeout=engine_module.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
                        )
                        return None
                    assert parameters is None
                    assert command in {
                        "Network.enable",
                        "Network.clearBrowserCache",
                    }
                    return None

                def detach(self) -> None:
                    events.append("cdp:detached")

            return CdpSession()

    context = Context()
    worker = engine_module.BrowserEngine()
    worker._install_single_chengfeng_page_guard = lambda: None
    worker._context = context
    worker._automated_prepared = True
    worker._operational_compat_prepared = True
    worker._session_headers = {
        "authorization": "Bearer worker-memory-only",
    }
    worker._install_operational_batch_page(page)
    return worker, events, context


def test_prepare_daily_executes_fixed_read_and_emits_no_business_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, context = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )

    observation = worker.prepare_daily()

    assert observation["origin"] == "https://pc.chengfengkuaiyun.com"
    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert observation["method"] == "POST"
    assert observation["query_keys"] == []
    assert observation["response_status"] == 200
    assert observation["content_kind"] == "json"
    serialized = json.dumps(observation, ensure_ascii=False, sort_keys=True)
    for private_value in (
        "YD-MUST-NOT-LEAK",
        "陕K-MUST-NOT-LEAK",
        "13800000000",
        "must-not-leak",
        "Bearer worker-memory-only",
    ):
        assert private_value not in serialized
    assert worker._daily_session_headers == {
        "authorization": "Bearer worker-memory-only",
    }
    assert worker._daily_body is not None
    assert worker._daily_body["loadStartTime"] == ""
    assert worker._daily_body["loadEndTime"] == ""
    assert worker._daily_body["receivePlace"] == ""
    assert worker._daily_body["pageNumber"] == 1
    assert worker._daily_body["pageSize"] == 1
    assert worker._session_headers is None
    assert context.blank_page is None
    retained_page = context.pages[0]
    assert isinstance(retained_page, _HumanPage)
    retained_page.assert_network_is_blocked()
    assert events == [
        "settlement-session-probed",
        "daily-native-fetch",
        "native-body-read",
        "native-response-disposed",
        "human-route-installed:first",
        "human-page-closed:second",
        "human-request-aborted:first",
    ]


def test_prepare_daily_executes_only_the_exact_direct_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, context = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
        extra_post=True,
    )

    observation = worker.prepare_daily()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert events.count("daily-native-fetch") == 1
    assert not any("/api/unsafe/write" in event for event in events)
    assert context.blank_page is None
    retained_page = context.pages[0]
    assert isinstance(retained_page, _HumanPage)
    retained_page.assert_network_is_blocked()


def test_prepare_daily_reuses_its_normalized_probe_for_the_exact_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker._staging_root = tmp_path

    worker.prepare_daily()
    assert worker._daily_probe_body is not None
    command = protocol.ReadDailyJsonCommand(
        request_id="daily-probe-reuse",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=dict(worker._daily_probe_body),
    )
    result = worker.read(command)

    assert events.count("daily-native-fetch") == 1
    staged = tmp_path.joinpath(
        *str(result["relative_path"]).split("/")
    )
    normalized = json.loads(staged.read_bytes())
    assert normalized["data"]["total"] == 1
    assert set(normalized["data"]["list"][0]) == {
        "carNumber",
        "id",
        "orderItemSn",
        "originalDate",
    }
    assert worker._daily_probe_body is None
    assert worker._daily_probe_content is None


def test_first_daily_read_refetches_same_scope_when_only_pagination_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
        allowed_page_sizes=(5, 100),
    )
    worker._staging_root = tmp_path

    worker.prepare_daily()
    assert worker._daily_probe_body is not None
    requested = dict(worker._daily_probe_body)
    requested["pageSize"] = 100
    command = protocol.ReadDailyJsonCommand(
        request_id="daily-probe-pagination-refetch",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=requested,
    )

    result = worker.read(command)

    assert result["media_type"] == "application/json"
    assert events.count("daily-native-fetch") == 2
    assert worker._daily_probe_read_pending is False
    assert worker._daily_probe_body is None
    assert worker._daily_probe_content is None


def test_prepare_daily_from_automated_captures_daily_page_headers_privately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, context = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker._session_list_fixed_values = {"queryType": 1}
    worker._session_list_cache_query = "t=private"
    worker._session_list_body = {"pageNumber": 1}
    worker._session_list_body_sha256 = "a" * 64
    worker._session_native_probe = {"total_count": 0}

    observation = worker.prepare_daily_from_automated()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert observation["query_keys"] == ["t"]
    assert events.count("daily-query-clicked") == 2
    assert events.count("daily-page-cache-refreshed") == 1
    assert events.count("cdp:Network.clearBrowserCache") == 1
    assert "human-daily-navigation" in events
    assert "cdp:Browser.setWindowBounds" in events
    assert len([page for page in context.pages if not page.is_closed()]) == 1
    assert worker._operational_batch_page is worker._human_page
    assert worker._human_page.url == DAILY_ENTRY
    assert "page-evaluate-fetch" not in events
    assert worker._automated_prepared is False
    assert worker._session_headers is None
    assert worker._session_list_fixed_values is None
    assert worker._session_list_cache_query is None
    assert worker._session_list_body is None
    assert worker._session_list_body_sha256 is None
    assert worker._session_native_probe is None
    assert worker._daily_session_headers == {
        "authorization": "Bearer worker-memory-only",
    }

    worker.park_operational_session()

    assert len([page for page in context.pages if not page.is_closed()]) == 1
    assert worker._human_page.url == DAILY_ENTRY


def test_prepare_operational_daily_does_not_require_settlement_preparation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, context = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker._automated_prepared = False
    worker._operational_compat_prepared = False
    worker._session_headers = None

    observation = worker.prepare_operational_daily()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert events.count("daily-query-clicked") == 2
    assert events.count("daily-page-cache-refreshed") == 1
    assert not any("billablewaybill" in event.lower() for event in events)
    assert len([page for page in context.pages if not page.is_closed()]) == 1
    assert worker._human_page.url == DAILY_ENTRY


def test_prepare_operational_daily_accepts_zero_after_fresh_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    empty = _daily_payload()
    empty["data"] = {"total": 0, "list": []}
    worker, events, context = _prepared_page_owned_daily_engine(
        engine_module,
        payload=empty,
    )

    observation = worker.prepare_operational_daily()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert worker._daily_cache_refresh_count == 2
    assert events.count("daily-page-cache-refreshed") == 2
    assert events.count("daily-query-clicked") == 3
    assert len([page for page in context.pages if not page.is_closed()]) == 1
    assert worker._daily_probe_content is not None
    normalized = json.loads(worker._daily_probe_content)
    assert normalized == {
        "_dahe_scope": {
            "platform_display_total": 0,
            "query_scope_sha256": worker._daily_authority_scope_sha256,
            "response_page_count": 1,
            "response_total": 0,
            "scope_complete": True,
            "scope_diagnostic_code": None,
        },
        "data": {"list": [], "total": 0},
    }


def test_prepare_daily_from_automated_uses_the_authenticated_page_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )

    observation = worker.prepare_daily_from_automated()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert observation["query_keys"] == ["t"]
    assert worker._daily_session_headers == {
        "authorization": "Bearer worker-memory-only",
    }
    assert worker._daily_body == {
        "loadEndTime": "",
        "loadStartTime": "",
        "pageNumber": 1,
        "pageSize": 1,
        "receivePlace": "",
    }
    assert events.count("daily-query-clicked") == 2
    assert "page-evaluate-fetch" not in events
    assert not any(event.startswith("abort:POST") for event in events)


def test_page_authoritative_daily_zero_refreshes_once_before_accepting_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker.prepare_daily_from_automated()
    page = worker._operational_batch_page
    assert isinstance(page, _PageOwnedDailyPage)
    page._payload = {"data": {"total": 0, "list": []}}
    body = _daily_parameters()
    private_body = dict(worker._daily_private_body)
    for name in engine_module._DAILY_CONTROLLED_FIELDS:
        private_body[name] = body[name]

    content, _ = worker._read_page_authoritative_daily_list(
        body=body,
        private_body=private_body,
        require_nonempty=False,
    )

    normalized = json.loads(content)
    assert normalized["data"] == {"list": [], "total": 0}
    assert normalized["_dahe_scope"]["platform_display_total"] == 0
    assert normalized["_dahe_scope"]["scope_complete"] is True
    assert events.count("daily-page-cache-refreshed") == 2
    assert events.count("cdp:Network.clearBrowserCache") == 2
    assert worker._daily_cache_refresh_count == 2


def test_page_authoritative_daily_ignores_unscoped_display_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, _, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker.prepare_daily_from_automated()
    monkeypatch.setattr(
        engine_module,
        "_daily_platform_display_total",
        lambda _page: 25_378,
    )
    body = _daily_parameters()
    private_body = dict(worker._daily_private_body)
    for name in engine_module._DAILY_CONTROLLED_FIELDS:
        private_body[name] = body[name]

    content, _ = worker._read_page_authoritative_daily_list(
        body=body,
        private_body=private_body,
        require_nonempty=False,
        retry_after_refresh=True,
    )

    scope = json.loads(content)["_dahe_scope"]
    assert scope["platform_display_total"] is None
    assert scope["response_total"] == 1
    assert scope["scope_complete"] is True
    assert scope["scope_diagnostic_code"] is None


def test_prepare_daily_from_automated_uses_frozen_contract_when_page_is_idle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
        emit_navigation_request=False,
    )

    observation = worker.prepare_daily_from_automated()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert worker._daily_session_headers == {
        "authorization": "Bearer worker-memory-only",
    }
    assert worker._daily_private_body == {
        "carNumber": "",
        "filterParamList": [],
        "loadEndTime": "",
        "loadStartTime": "",
        "pageNumber": 1,
        "pageSize": 1,
        "receivePlace": "",
        "remarks": None,
    }
    assert events.count("daily-query-clicked") == 2
    assert "page-evaluate-fetch" not in events


def test_prepare_daily_from_automated_accepts_the_dynamic_page_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
        navigation_body=_dynamic_daily_parameters(),
    )

    observation = worker.prepare_daily_from_automated()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert {item["path"] for item in observation["request_fields"]} == {
        "$.loadEndTime",
        "$.loadStartTime",
        "$.pageNumber",
        "$.pageSize",
        "$.receivePlace",
    }
    assert worker._daily_private_body == {
        "deptCode": "",
        "order": "desc",
        "pageNumber": 1,
        "pageSize": 1,
        "sortParams": [],
    }
    assert events.count("daily-query-clicked") == 2
    assert "page-evaluate-fetch" not in events


def test_prepare_daily_from_automated_accepts_broader_dynamic_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
        navigation_body=_dynamic_daily_parameters(),
        scope_matches=False,
    )

    observation = worker.prepare_daily_from_automated()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert events.count("daily-query-clicked") == 2
    assert "page-evaluate-fetch" not in events


def test_prepare_daily_from_automated_preserves_page_owned_nonempty_filters_privately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    page_owned = _daily_parameters()
    page_owned.update(
        {
            "businessType": "daily",
            "filterParamList": [{"field": "status", "values": [1, 2]}],
            "includeChildDepartments": True,
        }
    )
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
        navigation_body=page_owned,
    )

    observation = worker.prepare_daily_from_automated()

    assert observation["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert worker._daily_private_body is not None
    assert worker._daily_private_body["businessType"] == "daily"
    assert worker._daily_private_body["filterParamList"] == [
        {"field": "status", "values": [1, 2]}
    ]
    assert worker._daily_private_body["includeChildDepartments"] is True
    assert "daily-reset-clicked" not in events
    serialized = json.dumps(observation, ensure_ascii=False)
    assert "daily" not in serialized
    assert '"field"' not in serialized
    assert '"values"' not in serialized


def test_prepare_daily_from_automated_does_not_reset_page_owned_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )

    worker.prepare_daily_from_automated()

    assert "daily-reset-clicked" not in events


def test_page_owned_daily_scope_accepts_platform_date_level_filtering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    request_body = {
        "loadStartTime": "2026-07-28 14:00:00",
        "loadEndTime": "2026-07-29 14:30:00",
        "receivePlace": "榆林",
    }
    payload = {
        "data": {
            "list": [
                {
                    "loadPunchDate": "2026-07-28 08:00:00",
                    "receivePlace": "榆林象道物流园",
                },
                {
                    "loadPunchDate": "2026-07-29 20:00:00",
                    "receivePlace": "榆林象道物流园",
                },
            ]
        }
    }

    engine_module._validate_page_owned_daily_scope(
        payload,
        request_body=request_body,
    )


def test_page_owned_daily_scope_does_not_require_location_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    engine_module._validate_page_owned_daily_scope(
        {
            "data": {
                "list": [
                    {
                        "loadPunchDate": "2026-07-28 15:00:00",
                    },
                    {
                        "loadPunchDate": "2026-07-29 09:00:00",
                        "receivePlace": "platform display label changed",
                    },
                ]
            }
        },
        request_body={
            "loadStartTime": "2026-07-28 14:00:00",
            "loadEndTime": "2026-07-29 14:30:00",
            "receivePlace": "榆林",
        },
    )


def test_page_owned_daily_scope_allows_missing_loading_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    engine_module._validate_page_owned_daily_scope(
        {
            "data": {
                "list": [
                    {
                        "loadPunchDate": None,
                    },
                    {
                        "loadPunchDate": "",
                    },
                    {
                        "loadPunchDate": "2026-08-10 15:00:00",
                    },
                ]
            }
        },
        request_body={
            "loadStartTime": "2026-08-10 14:00:00",
            "loadEndTime": "2026-08-11 14:30:00",
            "receivePlace": "榆林",
        },
    )


def test_page_owned_daily_scope_accepts_null_list_for_zero_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    engine_module._validate_page_owned_daily_scope(
        {
            "data": {
                "list": None,
                "total": 0,
            }
        },
        request_body={
            "loadStartTime": "2026-08-10 14:00:00",
            "loadEndTime": "2026-08-11 14:30:00",
            "receivePlace": "榆林",
        },
    )


def test_page_owned_daily_scope_allows_broader_candidate_dates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    engine_module._validate_page_owned_daily_scope(
        {
            "data": {
                "list": [
                    {
                        "loadPunchDate": "2026-07-30 00:00:00",
                        "receivePlace": "榆林象道物流园",
                    }
                ]
            }
        },
        request_body={
            "loadStartTime": "2026-07-28 14:00:00",
            "loadEndTime": "2026-07-29 14:30:00",
            "receivePlace": "榆林",
        },
    )


def test_prepare_daily_from_automated_reuses_its_exact_probe_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_page_owned_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker._staging_root = tmp_path

    worker.prepare_daily_from_automated()
    assert worker._daily_probe_body is not None
    command = protocol.ReadDailyJsonCommand(
        request_id="automated-daily-probe-reuse",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=dict(worker._daily_probe_body),
    )

    result = worker.read(command)

    assert events.count("daily-query-clicked") == 2
    assert "page-evaluate-fetch" not in events
    staged = tmp_path.joinpath(
        *str(result["relative_path"]).split("/")
    )
    normalized = json.loads(staged.read_bytes())
    assert normalized["data"]["total"] == 1
    assert len(normalized["data"]["list"]) == 1
    assert worker._daily_probe_read_pending is False
    assert worker._daily_probe_body is None
    assert worker._daily_probe_content is None


def test_first_daily_read_allows_a_different_valid_business_day(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    worker, events, _ = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker._staging_root = tmp_path
    worker.prepare_daily()
    assert worker._daily_probe_body is not None
    mismatched = dict(worker._daily_probe_body)
    mismatched["loadStartTime"] = "2026-07-27 14:00:00"
    mismatched["loadEndTime"] = "2026-07-28 14:30:00"
    command = protocol.ReadDailyJsonCommand(
        request_id="daily-probe-scope-mismatch",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=mismatched,
    )

    result = worker.read(command)

    assert result["media_type"] == "application/json"
    assert events.count("daily-native-fetch") == 2
    assert worker._daily_probe_read_pending is False
    assert worker._daily_probe_read_pending is False
    assert worker._daily_probe_body is None
    assert worker._daily_probe_content is None


def test_prepare_daily_from_automated_rejects_unprepared_state_without_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, context = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
    )
    worker._session_headers = {
        "authorization": "Bearer worker-memory-only",
    }

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_daily_from_automated()

    assert raised.value.code == "browser_daily_automated_transition_required"
    assert events == []
    assert context.blank_page is None


@pytest.mark.parametrize(
    ("status", "final_url", "expected"),
    [
        (401, DAILY_ENTRY, "browser_read_login_required"),
        (
            302,
            "https://pc.chengfengkuaiyun.com/login",
            "browser_daily_redirect_rejected",
        ),
    ],
)
def test_prepare_daily_rejects_session_expiry_or_redirect(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    final_url: str,
    expected: str,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, _, _ = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
        status=status,
        final_url=final_url,
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_daily()

    assert raised.value.code == expected


def test_prepare_daily_rejects_response_contract_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    changed = _daily_payload()
    changed["data"] = {
        "total": 1,
        "list": [{"id": 1, "carNumber": None, "loadPunchDate": None}],
    }
    worker, events, context = _prepared_daily_engine(
        engine_module,
        payload=changed,
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_daily()

    assert raised.value.code == "browser_daily_response_contract_changed"
    assert len(raised.value.safe_discovery) == 1
    diagnostic = raised.value.safe_discovery[0]
    assert diagnostic["path"] == "/api/hz/orderItem/queryOrderItemListPC"
    assert {
        field["path"]
        for field in diagnostic["response_fields"]
    } == {
        "$.code",
        "$.data.list[].carNumber",
        "$.data.list[].id",
        "$.data.list[].loadPunchDate",
        "$.data.total",
        "$.success",
    }
    serialized = json.dumps(
        raised.value.safe_discovery,
        ensure_ascii=False,
        sort_keys=True,
    )
    assert "YD-MUST-NOT-LEAK" not in serialized
    assert "13800000000" not in serialized
    assert worker._daily_session_headers is None
    assert worker._daily_body is None
    assert worker._daily_response_fields is None
    assert context.blank_page is None
    assert "blank-opened" not in events
    assert not any(event.startswith("human-page-closed:") for event in events)


def test_failed_daily_response_can_emit_only_sanitized_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    command = protocol.PrepareDailyCommand(request_id="prepare-daily-changed")
    observation = {
        "method": "POST",
        "origin": "https://pc.chengfengkuaiyun.com",
        "path": "/api/hz/orderItem/queryOrderItemListPC",
        "path_sha256": None,
        "query_keys": [],
        "request_fields": [
            {"path": "$.loadEndTime", "type": "string"},
            {"path": "$.loadStartTime", "type": "string"},
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.pageSize", "type": "integer"},
            {"path": "$.receivePlace", "type": "string"},
        ],
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [
            {"path": "$.data.records[].waybillId", "type": "integer"},
            {"path": "$.data.total", "type": "integer"},
        ],
    }

    output = json.loads(
        protocol.response(
            command,
            ok=False,
            selected_browser="msedge",
            error_code="browser_daily_response_contract_changed",
            discovery=[observation],
            browser_open=True,
            read_result=None,
            prepare_result=None,
        )
    )

    assert output["ok"] is False
    assert output["error_code"] == "browser_daily_response_contract_changed"
    assert output["discovery"] == [observation]


def test_prepare_daily_reports_an_empty_completed_window_separately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    empty = _daily_payload()
    empty["data"] = {"total": 0, "list": []}
    worker, events, context = _prepared_daily_engine(
        engine_module,
        payload=empty,
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_daily()

    assert raised.value.code == "browser_daily_list_empty"
    assert worker._daily_session_headers is None
    assert worker._daily_body is None
    assert worker._daily_response_fields is None
    assert context.blank_page is None
    assert "blank-opened" not in events
    assert not any(event.startswith("human-page-closed:") for event in events)


def test_daily_empty_null_list_is_normalized_without_weakening_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    empty = _daily_payload()
    empty["data"] = {"total": 0, "list": None}

    assert engine_module._daily_response_fields(
        empty,
        require_nonempty=False,
    ) == [{"path": "$.data.total", "type": "integer"}]
    assert json.loads(
        engine_module._normalized_daily_read_bytes(empty)
    ) == {"data": {"list": [], "total": 0}}
    with pytest.raises(engine_module.BrowserReadError) as raised:
        engine_module._daily_response_fields(
            empty,
            require_nonempty=True,
        )
    assert raised.value.code == "browser_daily_list_empty"


def test_daily_minimal_contract_ignores_unrelated_response_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    payload = _daily_payload()
    data = payload["data"]
    assert isinstance(data, dict)
    items = data["list"]
    assert isinstance(items, list)
    item = items[0]
    assert isinstance(item, dict)
    item["futureOptionalField"] = {"nested": "not part of the contract"}

    fields = engine_module._daily_response_fields(
        payload,
        require_nonempty=True,
    )

    assert {field["path"] for field in fields} == {
        "$.data.list[].carNumber",
        "$.data.list[].id",
        "$.data.list[].loadPunchDate",
        "$.data.list[].sn",
        "$.data.total",
    }
    assert not any(
        "futureOptionalField" in field["path"]
        for field in fields
    )


def test_prepare_daily_does_not_publish_state_when_page_isolation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    worker, events, context = _prepared_daily_engine(
        engine_module,
        payload=_daily_payload(),
        human_close_fails=True,
    )

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.prepare_daily()

    assert raised.value.code == "browser_daily_prepare_failed"
    assert worker._daily_session_headers is None
    assert worker._daily_body is None
    assert worker._daily_response_fields is None
    assert context.blank_page is None
    first_page = context.pages[0]
    assert isinstance(first_page, _HumanPage)
    assert first_page.closed is True
    assert "human-route-removed:first" in events
    assert "human-page-close-failed:second" in events


def test_daily_only_session_supports_detail_and_image_not_settlement_list(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    detail_url = (
        "https://pc.chengfengkuaiyun.com/api/order-center-server/"
        "app/clientOrderItem/getOrderItemDetailsByIdPC"
    )
    image_url = "https://pc.chengfengkuaiyun.com/images/ticket-1.jpg"
    settlement_url = (
        "https://pc.chengfengkuaiyun.com/api/order-center-server/"
        "app/clientOrderItem/queryWaitSettlementOrderItemListPC"
    )
    calls: list[tuple[str, dict[str, object]]] = []

    class Response:
        status = 200

        def __init__(self, *, body: bytes, content_type: str) -> None:
            self._body = body
            self.headers = {"content-type": content_type}

        def body(self) -> bytes:
            return self._body

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            calls.append((url, options))
            if url == detail_url:
                return Response(
                    body=(
                        b'{"data":[{"id":"900000001",'
                        b'"originalTonImageUrl":'
                        b'"https://pc.chengfengkuaiyun.com/'
                        b'images/ticket-1.jpg"}]}'
                    ),
                    content_type="application/json",
                )
            assert url == image_url
            return Response(body=b"safe-image-bytes", content_type="image/jpeg")

    class Context:
        request = RequestContext()

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path
    worker._daily_session_headers = {"authorization": "Bearer daily-private"}
    worker._session_headers = None

    detail = worker.read(
        protocol.ReadJsonCommand(
            request_id="daily-detail",
            operation="get_waybill_detail",
            method="POST",
            url=detail_url,
            parameters={"id": "900000001"},
        )
    )
    image = worker.read(
        protocol.ReadImageCommand(
            request_id="daily-image",
            operation="download_ticket_image",
            method="GET",
            url=image_url,
            parameters={},
        )
    )

    assert detail["media_type"] == "application/json"
    assert image["media_type"] == "image/jpeg"
    assert calls == [
        (
            detail_url,
            {
                "method": "POST",
                "fail_on_status_code": False,
                "max_redirects": 0,
                "timeout": 30_000,
                "form": {"id": "900000001"},
                "headers": {"authorization": "Bearer daily-private"},
            },
        ),
        (
            image_url,
            {
                "method": "GET",
                "fail_on_status_code": False,
                "max_redirects": 0,
                "timeout": 60_000,
            },
        ),
    ]

    with pytest.raises(engine_module.BrowserReadError) as raised:
        worker.read(
            protocol.ReadJsonCommand(
                request_id="settlement-list-with-daily-session",
                operation="list_waybills",
                method="POST",
                url=settlement_url,
                parameters={},
            )
        )
    assert raised.value.code == "browser_read_login_required"


def test_read_daily_json_uses_private_baseline_and_zero_redirects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    calls: list[tuple[str, dict[str, object]]] = []
    response_events: list[str] = []
    content = json.dumps(_daily_payload(), ensure_ascii=False).encode("utf-8")

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

        def body(self) -> bytes:
            return content

        def dispose(self) -> None:
            response_events.append("disposed")

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            calls.append((url, options))
            return Response()

    class Context:
        request = RequestContext()

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path
    worker._daily_session_headers = {"authorization": "Bearer private"}
    worker._daily_body = {
        **_daily_parameters(),
        "loadStartTime": "",
        "loadEndTime": "",
        "receivePlace": "",
        "pageNumber": 1,
        "pageSize": 1,
    }
    worker._daily_response_fields = engine_module._json_fields(_daily_payload())
    command = protocol.ReadDailyJsonCommand(
        request_id="read-daily-safe",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=_daily_parameters(),
    )

    result = worker.read(command)

    assert result["media_type"] == "application/json"
    staged_path = tmp_path.joinpath(*str(result["relative_path"]).split("/"))
    staged_content = staged_path.read_bytes()
    source_data = _daily_payload()["data"]
    assert isinstance(source_data, dict)
    source_items = source_data["list"]
    assert isinstance(source_items, list)
    source_item = source_items[0]
    assert isinstance(source_item, dict)
    assert json.loads(staged_content) == {
        "data": {
            "list": [
                {
                    "carNumber": source_item["carNumber"],
                    "id": source_item["id"],
                    "orderItemSn": source_item["sn"],
                    "originalDate": source_item["loadPunchDate"],
                }
            ],
            "total": 1,
        }
    }
    assert b"driverPhone" not in staged_content
    assert b"token" not in staged_content
    assert result["sha256"] == engine_module.hashlib.sha256(staged_content).hexdigest()
    assert result["sha256"] != engine_module.hashlib.sha256(content).hexdigest()
    assert result["byte_size"] == len(staged_content)
    assert response_events == ["disposed"]
    assert calls == [
        (
            DAILY_URL,
            {
                "method": "POST",
                "fail_on_status_code": False,
                "max_redirects": 0,
                "timeout": 30_000,
                "data": _daily_parameters(),
                "headers": {"authorization": "Bearer private"},
            },
        )
    ]


def test_read_staging_recovery_removes_only_owned_known_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    staging_root = tmp_path / "read-results"
    completed = staging_root / f"daily-{'a' * 32}"
    interrupted = staging_root / f"read-{'b' * 32}"
    unrelated_directory = staging_root / "manual-investigation"
    completed.mkdir(parents=True)
    interrupted.mkdir()
    unrelated_directory.mkdir()
    (completed / "payload.json").write_bytes(
        b'{"token":"orphan-must-be-removed"}'
    )
    (interrupted / ".payload.part").write_bytes(b"partial-private-response")
    unrelated_file = staging_root / "operator-note.txt"
    unrelated_file.write_text("keep", encoding="utf-8")
    unrelated_child = unrelated_directory / "keep.txt"
    unrelated_child.write_text("keep", encoding="utf-8")

    removed = engine_module.recover_read_result_staging(staging_root)

    assert removed == 2
    assert not completed.exists()
    assert not interrupted.exists()
    assert unrelated_file.read_text(encoding="utf-8") == "keep"
    assert unrelated_child.read_text(encoding="utf-8") == "keep"


def test_read_staging_recovery_rejects_owned_symlink_without_touching_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    staging_root = tmp_path / "read-results"
    owned = staging_root / f"daily-{'c' * 32}"
    outside = tmp_path / "outside.json"
    owned.mkdir(parents=True)
    outside.write_text("keep", encoding="utf-8")
    try:
        (owned / "payload.json").symlink_to(outside)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(RuntimeError, match=r"symbolic link|reparse"):
        engine_module.recover_read_result_staging(staging_root)

    assert outside.read_text(encoding="utf-8") == "keep"
    assert owned.exists()


def test_read_staging_recovery_rejects_unknown_owned_content_without_deleting_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    staging_root = tmp_path / "read-results"
    owned = staging_root / f"daily-{'f' * 32}"
    unknown = owned / "raw-response.json"
    owned.mkdir(parents=True)
    unknown.write_text('{"secret":"keep-for-safe-failure"}', encoding="utf-8")

    with pytest.raises(RuntimeError, match="unknown entry"):
        engine_module.recover_read_result_staging(staging_root)

    assert unknown.read_text(encoding="utf-8") == (
        '{"secret":"keep-for-safe-failure"}'
    )


def test_read_staging_recovery_rejects_reparse_guard_before_unlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)
    staging_root = tmp_path / "read-results"
    owned = staging_root / f"daily-{'1' * 32}"
    payload = owned / "payload.json"
    owned.mkdir(parents=True)
    payload.write_text("keep", encoding="utf-8")
    payload_identity = payload.lstat().st_ino
    original = engine_module._is_link_or_reparse

    def simulated_reparse(metadata: Any) -> bool:
        return (
            getattr(metadata, "st_ino", None) == payload_identity
            or original(metadata)
        )

    monkeypatch.setattr(
        engine_module,
        "_is_link_or_reparse",
        simulated_reparse,
    )

    with pytest.raises(RuntimeError, match=r"symbolic link|reparse"):
        engine_module.recover_read_result_staging(staging_root)

    assert payload.read_text(encoding="utf-8") == "keep"


def test_daily_read_rejects_end_before_start_or_after_safety_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)

    class Context:
        request = object()

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path
    worker._daily_session_headers = {"authorization": "Bearer private"}
    worker._daily_body = {
        **_daily_parameters(),
        "loadStartTime": "",
        "loadEndTime": "",
        "receivePlace": "",
        "pageNumber": 1,
        "pageSize": 1,
    }
    worker._daily_response_fields = engine_module._json_fields(_daily_payload())

    for end_time in (
        "2026-07-28 13:59:59",
        "2026-07-29 14:30:01",
    ):
        parameters = {**_daily_parameters(), "loadEndTime": end_time}
        command = protocol.ReadDailyJsonCommand(
            request_id=f"read-daily-invalid-{end_time[-2:]}",
            operation="list_daily_waybills",
            method="POST",
            url=DAILY_URL,
            parameters=parameters,
        )
        with pytest.raises(engine_module.BrowserReadError) as raised:
            worker.read(command)
        assert raised.value.code == "browser_daily_business_parameters_invalid"


def test_read_daily_json_rejects_arbitrary_url_and_changed_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

        def body(self) -> bytes:
            return b'{"data":{"total":1,"list":[{"id":1}]}}'

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            del url, options
            return Response()

    class Context:
        request = RequestContext()

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path
    worker._daily_session_headers = {"authorization": "Bearer private"}
    worker._daily_body = {
        **_daily_parameters(),
        "loadStartTime": "",
        "loadEndTime": "",
        "receivePlace": "",
        "pageNumber": 1,
        "pageSize": 1,
    }
    worker._daily_response_fields = engine_module._json_fields(_daily_payload())

    arbitrary = protocol.ReadDailyJsonCommand(
        request_id="read-daily-arbitrary",
        operation="list_daily_waybills",
        method="POST",
        url="https://example.invalid/api/list",
        parameters=_daily_parameters(),
    )
    with pytest.raises(engine_module.BrowserReadError) as arbitrary_error:
        worker.read(arbitrary)
    assert arbitrary_error.value.code == "browser_read_contract_changed"

    changed = protocol.ReadDailyJsonCommand(
        request_id="read-daily-changed",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=_daily_parameters(),
    )
    with pytest.raises(engine_module.BrowserReadError) as shape_error:
        worker.read(changed)
    assert shape_error.value.code == "browser_daily_response_contract_changed"
    assert len(shape_error.value.safe_discovery) == 1
    assert shape_error.value.safe_discovery[0]["response_fields"] == [
        {"path": "$.data.list[].id", "type": "integer"},
        {"path": "$.data.total", "type": "integer"},
    ]


def test_read_daily_ignores_unrelated_optional_field(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    changed_payload = _daily_payload()
    data = changed_payload["data"]
    assert isinstance(data, dict)
    items = data["list"]
    assert isinstance(items, list)
    item = items[0]
    assert isinstance(item, dict)
    item["optionalStatus"] = 7
    content = json.dumps(changed_payload, ensure_ascii=False).encode("utf-8")

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {
            "content-type": "application/json"
        }

        def body(self) -> bytes:
            return content

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            del url, options
            return Response()

    class Context:
        request = RequestContext()

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path
    worker._daily_session_headers = {"authorization": "Bearer private"}
    worker._daily_body = {
        **_daily_parameters(),
        "loadStartTime": "",
        "loadEndTime": "",
        "receivePlace": "",
        "pageNumber": 1,
        "pageSize": 1,
    }
    worker._daily_response_fields = engine_module._json_fields(
        _daily_payload()
    )
    command = protocol.ReadDailyJsonCommand(
        request_id="read-daily-safe-change",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=_daily_parameters(),
    )

    result = worker.read(command)

    staged = tmp_path.joinpath(
        *str(result["relative_path"]).split("/")
    )
    normalized = json.loads(staged.read_bytes())
    assert "optionalStatus" not in normalized["data"]["list"][0]


def test_read_daily_json_rejects_required_field_type_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _load_worker_modules(monkeypatch)
    changed_payload = _daily_payload()
    data = changed_payload["data"]
    assert isinstance(data, dict)
    items = data["list"]
    assert isinstance(items, list)
    item = items[0]
    assert isinstance(item, dict)
    item["sn"] = 900000001
    content = json.dumps(changed_payload).encode("utf-8")

    class Response:
        status = 200
        headers: ClassVar[dict[str, str]] = {
            "content-type": "application/json"
        }

        def body(self) -> bytes:
            return content

    class RequestContext:
        def fetch(self, url: str, **options: object) -> Response:
            del url, options
            return Response()

    class Context:
        request = RequestContext()

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path
    worker._daily_session_headers = {"authorization": "Bearer private"}
    worker._daily_body = {
        **_daily_parameters(),
        "loadStartTime": "",
        "loadEndTime": "",
        "receivePlace": "",
        "pageNumber": 1,
        "pageSize": 1,
    }
    worker._daily_response_fields = engine_module._json_fields(
        _daily_payload()
    )
    command = protocol.ReadDailyJsonCommand(
        request_id="read-daily-type-drift",
        operation="list_daily_waybills",
        method="POST",
        url=DAILY_URL,
        parameters=_daily_parameters(),
    )

    with pytest.raises(engine_module.BrowserReadError) as drift_error:
        worker.read(command)

    assert (
        drift_error.value.code
        == "browser_daily_response_contract_changed"
    )
    assert list(tmp_path.iterdir()) == []


def test_close_clears_daily_private_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _ = _load_worker_modules(monkeypatch)

    class Context:
        pages: ClassVar[list[object]] = []

        def close(self) -> None:
            return None

        def remove_listener(self, event: str, handler: object) -> None:
            del event, handler

    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._daily_session_headers = {"authorization": "private"}
    worker._daily_body = _daily_parameters()
    worker._daily_response_fields = [{"path": "$.data.total", "type": "integer"}]

    worker.close()

    assert worker._daily_session_headers is None
    assert worker._daily_body is None
    assert worker._daily_response_fields is None
