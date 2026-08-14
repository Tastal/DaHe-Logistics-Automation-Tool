from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import ClassVar

import pytest

PROJECT_ROOT = Path(__file__).parents[3]
BROWSER_SOURCE = PROJECT_ROOT / "browser-runtime" / "src"


def _load_engine(monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    for name in (
        "dahe_browser_worker.engine",
        "dahe_browser_worker.protocol",
    ):
        sys.modules.pop(name, None)
    import dahe_browser_worker.engine as engine

    return engine


def test_operational_query_preserves_landing_scope_and_uses_atomic_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _load_engine(monkeypatch)
    events: list[str] = []
    private_body = {
        "order": "desc",
        "queryType": "2",
        "settleQueryType": 1,
        "pageNumber": 1,
        "pageSize": 30,
        "futureHiddenAccountScope": "must-stay-in-worker-memory",
        "futureEmptyFilter": "",
        "futureArrayFilter": [],
    }

    class Request:
        method = "POST"
        resource_type = "fetch"
        url = (
            "https://pc.chengfengkuaiyun.com"
            f"{engine.CHENGFENG_LIST_PATH}?t=1785500000000"
        )
        post_data_json: ClassVar[dict[str, object]] = private_body

        def all_headers(self) -> dict[str, str]:
            return {
                "Authorization": "Bearer must-stay-in-worker-memory",
                "Cookie": "must-not-be-copied",
            }

    class NoiseRequest:
        method = "POST"
        resource_type = "xhr"
        url = "https://pc.chengfengkuaiyun.com/api/unapproved/background"

    def response_body(*, primed: bool) -> bytes:
        return json.dumps(
            {
                "data": {
                    "list": (
                        [
                            {
                                "id": "private-id",
                                "orderItemSn": "private-waybill",
                            }
                        ]
                        if primed
                        else []
                    ),
                    "pageNo": 1,
                    "pageSize": 30,
                    "total": 1 if primed else 0,
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")

    class Response:
        status = 200
        request = Request()

        def __init__(self, page: Page) -> None:
            self._page = page

        def body(self) -> bytes:
            events.append("response-body-read")
            self._page.authoritative_response_count += 1
            return response_body(
                primed=(
                    self._page.authoritative_response_count % 2 == 0
                    and self._page.priming_read_count % 6 == 0
                )
            )

    class ResponseInfo:
        def __init__(self, page: Page) -> None:
            self._page = page

        def __enter__(self) -> ResponseInfo:
            events.append("expect-response-armed")
            return self

        def __exit__(self, *args: object) -> None:
            events.append("expect-response-released")
            self._page.response_predicate = None

        @property
        def value(self) -> Response:
            assert self._page.response is not None
            return self._page.response

    class Route:
        def __init__(self, page: Page, request: object) -> None:
            self.request = request
            self._page = page

        def abort(self) -> None:
            events.append("request-aborted")

        def continue_(self) -> None:
            events.append("approved-request-continued")
            predicate = self._page.response_predicate
            if predicate is None:
                self._page.priming_read_count += 1
                return
            response = Response(self._page)
            assert predicate is not None and predicate(response)
            self._page.response = response

    class Trigger:
        def __init__(self, page: Page, name: str) -> None:
            self._page = page
            self._name = name
            self._generation = page.control_generation

        def filter(self, *, visible: bool) -> Trigger:
            assert visible is True
            return self

        @property
        def first(self) -> Trigger:
            return self

        def count(self) -> int:
            return 1

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert state == "visible"
            assert timeout == engine.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS
            if (
                self._name == "waybill-tab"
                and self._page.fail_waybill_wait_once
            ):
                self._page.fail_waybill_wait_once = False
                events.append("waybill-tab-transiently-unavailable")
                raise TimeoutError("transient SPA control delay")
            events.append(f"{self._name}-visible")

        def is_visible(self) -> bool:
            return (
                self._name == "waybill-tab"
                and self._page.url == engine.CHENGFENG_HUMAN_LOGIN_ENTRY
            )

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000
            assert self._generation == self._page.control_generation
            events.append(f"{self._name}-clicked")
            if self._name == "settle-ready":
                self._page.settlement_scope_selected = True
            if self._name == "settlement-tab":
                assert self._page.settlement_scope_selected
                self._page.settlement_tab_selected = True
            if self._name != "query":
                assert self._page.route_handler is not None
                self._page.route_handler(Route(self._page, Request()))
                if self._name == "reset":
                    self._page.control_generation += 1
                return
            assert self._page.route_handler is not None
            self._page.route_handler(Route(self._page, NoiseRequest()))
            self._page.route_handler(Route(self._page, Request()))
            self._page.route_handler(Route(self._page, Request()))

    class Locator:
        first: ClassVar[Locator]

        def is_visible(self) -> bool:
            return False

    Locator.first = Locator()

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def __init__(self) -> None:
            self.route_handler: object | None = None
            self.route_handlers: list[object] = []
            self.response_predicate: object | None = None
            self.response: Response | None = None
            self.priming_read_count = 0
            self.authoritative_response_count = 0
            self.settlement_scope_selected = False
            self.settlement_tab_selected = False
            self.control_generation = 0
            self.idle_wait_count = 0
            self.navigation_count = 0
            self.closed = False
            self.fail_waybill_wait_once = False

        def is_closed(self) -> bool:
            return self.closed

        def locator(self, selector: str) -> Locator:
            if selector == "[role='search']:visible, form:visible, .el-form:visible":
                page = self

                class QueryRegions:
                    def count(self) -> int:
                        return 1

                    def nth(self, index: int) -> QueryRegions:
                        assert index == 0
                        return self

                    def is_visible(self) -> bool:
                        return True

                    def get_by_role(
                        self,
                        role: str,
                        *,
                        name: str,
                        exact: bool,
                    ) -> Trigger:
                        return page.get_by_role(role, name=name, exact=exact)

                return QueryRegions()  # type: ignore[return-value]
            assert selector == "input[type='password']"
            return Locator()

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
            assert exact is True
            if role == "tab":
                assert name == "按运单显示"
                return Trigger(self, "waybill-tab")
            assert role == "button"
            if name == "登录":
                return Trigger(self, "login")
            return Trigger(self, {"重置": "reset", "查询": "query"}[name])

        def route(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*" and callable(handler)
            self.route_handlers.append(handler)
            self.route_handler = handler
            events.append(f"human-route-installed-{len(self.route_handlers)}")

        def unroute(self, pattern: str, handler: object) -> None:
            assert pattern == "**/*" and handler in self.route_handlers
            self.route_handlers.remove(handler)
            self.route_handler = (
                self.route_handlers[-1] if self.route_handlers else None
            )

        def expect_response(
            self,
            predicate: object,
            *,
            timeout: int,
        ) -> ResponseInfo:
            assert callable(predicate)
            assert timeout == engine.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS
            self.response_predicate = predicate
            return ResponseInfo(self)

        def wait_for_timeout(self, timeout_ms: int) -> None:
            assert timeout_ms in {250, 300}

        def goto(
            self,
            url: str,
            *,
            wait_until: str | None = None,
            timeout: int | None = None,
        ) -> object | None:
            if url == "about:blank":
                assert wait_until is None
                assert timeout is None
                self.url = url
                self.navigation_count += 1
                events.append("operational-session-parked")
                return
            assert url == engine.CHENGFENG_HUMAN_LOGIN_ENTRY
            assert wait_until == "domcontentloaded"
            assert timeout == engine.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS
            self.url = url
            self.navigation_count += 1
            self.control_generation += 1
            return type("NavigationResponse", (), {"status": 200})()

        def bring_to_front(self) -> None:
            events.append("entry-brought-to-front")

        def reload(
            self,
            *,
            wait_until: str,
            timeout: int,
        ) -> None:
            assert wait_until == "domcontentloaded"
            assert timeout == engine.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS
            self.navigation_count += 1
            self.control_generation += 1
            events.append("page-cache-refreshed")

        def wait_for_function(self, expression: str, *, timeout: int) -> None:
            assert "loading-mask" in expression
            assert timeout == engine.OPERATIONAL_UI_IDLE_TIMEOUT_MS
            self.idle_wait_count += 1

        def wait_for_load_state(self, state: str, *, timeout: int) -> None:
            assert state == "domcontentloaded"
            assert timeout == engine.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS

        def close(self) -> None:
            self.closed = True
            events.append("controlled-page-closed")

    page = Page()

    class Context:
        def __init__(self) -> None:
            self.pages: list[Page] = [page]
            self.page_handler: object | None = None

        def new_page(self) -> Page:
            controlled = Page()
            self.pages.append(controlled)
            return controlled

        def new_cdp_session(self, target: object) -> object:
            assert isinstance(target, Page)

            class CdpSession:
                def send(
                    self,
                    command: str,
                    parameters: object | None = None,
                ) -> object:
                    if command == "Browser.getWindowForTarget":
                        assert parameters is None
                        events.append(f"cdp:{command}")
                        return {"windowId": 7}
                    if command == "Browser.getWindowBounds":
                        assert parameters == {"windowId": 7}
                        events.append(f"cdp:{command}")
                        return {"bounds": {"windowState": "normal"}}
                    if command == "Network.setCacheDisabled":
                        assert parameters in (
                            {"cacheDisabled": True},
                            {"cacheDisabled": False},
                        )
                    elif command == "Page.reload":
                        assert parameters == {"ignoreCache": True}
                        target.reload(
                            wait_until="domcontentloaded",
                            timeout=engine.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
                        )
                    else:
                        assert parameters is None
                        assert command in {
                            "Network.enable",
                            "Network.clearBrowserCache",
                        }
                    events.append(f"cdp:{command}")
                    return None

                def detach(self) -> None:
                    events.append("cdp:detached")

            return CdpSession()

        def on(self, event: str, handler: object) -> None:
            assert event == "page"
            self.page_handler = handler

        def remove_listener(self, event: str, handler: object) -> None:
            assert event == "page"
            assert handler is self.page_handler
            self.page_handler = None

    engine._ensure_contract_subject = (
        lambda _page, *, contract_subject_code, login_page: {
            "contract_subject_code": contract_subject_code,
            "contract_subject_switch_performed": False,
        }
    )
    worker = engine.BrowserEngine()
    worker._context = Context()
    worker._human_page = page
    worker.freeze_human_session()

    result = worker.prepare_operational_compat()

    assert result["metrics"] == {
        "total_count": 1,
        "list_length": 1,
        "page_number": 1,
        "page_size": 30,
    }
    trace = result["query_trace"]
    assert isinstance(trace, dict)
    assert trace["observed_request_count"] == 6
    assert trace["approved_request_count"] == 2
    assert trace["blocked_request_count"] == 4
    assert trace["query_attempt_count"] == 2
    assert trace["zero_retry_performed"] is True
    assert trace["cache_refresh_count"] == 2
    assert trace["request_method"] == "POST"
    assert trace["request_path"] == engine.CHENGFENG_LIST_PATH
    assert trace["resource_type"] == "fetch"
    assert trace["response_status"] == 200
    assert trace["response_byte_size"] == len(response_body(primed=True))
    assert trace["response_structure_sha256"] == result[
        "response_structure_sha256"
    ]
    assert "expect-response-armed" in events
    assert events.index("expect-response-armed") < events.index("query-clicked")
    assert "response-body-read" in events
    controlled_page = worker._operational_batch_page
    assert isinstance(controlled_page, Page)
    assert controlled_page is page
    assert len([candidate for candidate in worker._context.pages if not candidate.is_closed()]) == 1
    assert controlled_page.priming_read_count == 6
    assert controlled_page.authoritative_response_count == 2
    assert controlled_page.idle_wait_count >= 8
    assert controlled_page.navigation_count == 2
    assert controlled_page.settlement_scope_selected is False
    assert controlled_page.settlement_tab_selected is False
    assert worker._human_freeze_handlers == {}
    assert worker._human_freeze_context_page_handler is None
    assert "settle-ready-clicked" not in events
    assert "settlement-tab-clicked" not in events
    assert events.count("page-cache-refreshed") == 2
    assert events.count("cdp:Network.clearBrowserCache") == 2
    assert "cdp:Browser.getWindowForTarget" in events
    controlled_route_index = max(
        index
        for index, event in enumerate(events)
        if event == "human-route-installed-1"
    )
    assert events.index("waybill-tab-visible") < controlled_route_index
    serialized = json.dumps(result, sort_keys=True)
    for private_value in (
        "must-stay-in-worker-memory",
        "private-id",
        "private-waybill",
        "authorization",
        "cookie",
        "pageNumber",
    ):
        assert private_value not in serialized

    human_navigation_count = page.navigation_count
    worker.park_operational_session()

    assert page.navigation_count == human_navigation_count
    assert page.url == engine.CHENGFENG_HUMAN_LOGIN_ENTRY
    assert "controlled-page-closed" not in events
    assert "entry-brought-to-front" in events
    assert worker._context is not None
    assert worker._session_list_body is None
    assert worker._session_headers is None

    page.fail_waybill_wait_once = True
    second_result = worker.prepare_operational_compat()

    assert second_result["metrics"]["total_count"] == 1
    assert page.url == engine.CHENGFENG_HUMAN_LOGIN_ENTRY
    second_controlled_page = worker._operational_batch_page
    assert isinstance(second_controlled_page, Page)
    assert second_controlled_page is controlled_page
    assert len([candidate for candidate in worker._context.pages if not candidate.is_closed()]) == 1
    assert second_controlled_page.navigation_count == 4
    assert events.count("waybill-tab-transiently-unavailable") == 1
    assert events.count("page-cache-refreshed") == 4
