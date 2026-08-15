from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parents[3]
BROWSER_SOURCE = PROJECT_ROOT / "browser-runtime" / "src"


def _load_worker_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[object, object]:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    for name in (
        "dahe_browser_worker.engine",
        "dahe_browser_worker.protocol",
    ):
        sys.modules.pop(name, None)
    import dahe_browser_worker.engine as engine
    import dahe_browser_worker.protocol as protocol

    return engine, protocol


def _load_worker_main(monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    for name in (
        "dahe_browser_worker.__main__",
        "dahe_browser_worker.engine",
        "dahe_browser_worker.protocol",
    ):
        sys.modules.pop(name, None)
    import dahe_browser_worker.__main__ as worker_main

    return worker_main


def test_operational_protocol_failure_uses_value_free_specific_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_main = _load_worker_main(monkeypatch)
    command = worker_main.parse_command(
        json.dumps(
            {
                "schema_version": worker_main.PROTOCOL_VERSION,
                "command": "prepare_operational_compat",
                "contract_subject_code": "shanxi_guienbo",
                "request_id": "prepare-operational-diagnostic",
            }
        )
    )

    assert (
        worker_main._safe_worker_failure_code(
            command,
            worker_main.ProtocolError("operational query trace page_count is invalid"),
        )
        == "browser_operational_trace_page_count_invalid"
    )
    assert (
        worker_main._safe_worker_failure_code(
            command,
            RuntimeError("private detail must not be exposed"),
        )
        == "browser_operational_unexpected_failed"
    )

    daily_command = worker_main.parse_command(
        json.dumps(
            {
                "schema_version": worker_main.PROTOCOL_VERSION,
                "command": "prepare_operational_daily",
                "contract_subject_code": "shanxi_guienbo",
                "request_id": "prepare-operational-daily-diagnostic",
            }
        )
    )
    assert (
        worker_main._safe_worker_failure_code(
            daily_command,
            RuntimeError("private detail must not be exposed"),
        )
        == "browser_daily_direct_prepare_unexpected_runtimeerror"
    )


def test_headless_initialize_protocol_contains_no_credential_material(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    profile = (tmp_path / "browser-profile" / "chengfeng-shadow").resolve()
    staging = (tmp_path / "runtime" / "browser-worker" / "read-results").resolve()
    raw = {
        "schema_version": 9,
        "command": "initialize_headless",
        "request_id": "headless-1",
        "browser": "auto",
        "profile_root": str(profile),
        "staging_root": str(staging),
    }

    parsed = protocol.parse_command(json.dumps(raw))

    assert isinstance(parsed, protocol.InitializeHeadlessCommand)
    serialized = json.dumps(raw).casefold()
    assert "username" not in serialized
    assert "password" not in serialized
    assert "credential_reference" not in serialized


def test_saved_login_stops_before_reading_credentials_when_captcha_is_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    monkeypatch.setattr(engine, "_visible_captcha", lambda _page: True)
    monkeypatch.setattr(
        engine,
        "read_saved_credential",
        lambda: (_ for _ in ()).throw(AssertionError("credentials must not be read")),
    )

    with pytest.raises(engine.BrowserReadError) as raised:
        engine._login_with_saved_credential(object())

    assert raised.value.code == "browser_saved_login_captcha_required"


def test_contract_subject_reads_element_ui_input_value_not_nested_popup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)

    class Input:
        @property
        def first(self) -> Input:
            return self

        def count(self) -> int:
            return 1

        def input_value(self) -> str:
            return "上海晋亿晟信息科技有限公司"

    class Control:
        def locator(self, selector: str) -> Input:
            assert selector == "input"
            return Input()

    class Page:
        def locator(self, selector: str) -> object:
            raise AssertionError(f"the selected popup item is outside the control: {selector}")

    monkeypatch.setattr(
        engine,
        "_contract_subject_control",
        lambda _page, *, login_page: Control(),
    )

    assert engine._selected_contract_subject_code(Page(), login_page=False) == "shanghai_jinyisheng"


def test_contract_subject_waits_for_delayed_element_ui_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    waits = 0
    option_clicked = False
    response_handler: object | None = None

    class Input:
        @property
        def first(self) -> Input:
            return self

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000

    class Control:
        def locator(self, selector: str) -> Input:
            assert selector == "input"
            return Input()

    class Option:
        def inner_text(self) -> str:
            return "上海晋亿晟信息科技有限公司"

        def click(self, *, timeout: int) -> None:
            nonlocal option_clicked
            assert timeout == 10_000
            option_clicked = True
            assert callable(response_handler)
            response_handler(
                SimpleNamespace(
                    url="https://pc.chengfengkuaiyun.com/api/user-center-server/business/user/getUserInfoAndFlag",
                    status=200,
                    request=SimpleNamespace(resource_type="xhr"),
                )
            )

    class Options:
        @property
        def first(self) -> Option:
            return Option()

        def count(self) -> int:
            return 1 if waits else 0

        def nth(self, index: int) -> Option:
            assert index == 0
            return Option()

    class Page:
        def locator(self, selector: str) -> Options:
            assert selector == ".el-select-dropdown:visible .el-select-dropdown__item"
            return Options()

        def wait_for_timeout(self, milliseconds: int) -> None:
            nonlocal waits
            assert milliseconds == 250
            waits += 1

        def on(self, event: str, handler: object) -> None:
            nonlocal response_handler
            assert event == "response"
            response_handler = handler

        def remove_listener(self, event: str, handler: object) -> None:
            nonlocal response_handler
            assert event == "response"
            assert handler is response_handler
            response_handler = None

    monkeypatch.setattr(
        engine,
        "_contract_subject_control",
        lambda _page, *, login_page: Control(),
    )
    monkeypatch.setattr(
        engine,
        "_selected_contract_subject_code",
        lambda _page, *, login_page: (
            "shanghai_jinyisheng" if option_clicked else "shanxi_guienbo"
        ),
    )

    result = engine._ensure_contract_subject(
        Page(),
        contract_subject_code="shanghai_jinyisheng",
        login_page=False,
    )

    assert waits == 9
    assert option_clicked is True
    assert response_handler is None
    assert result == {
        "contract_subject_code": "shanghai_jinyisheng",
        "contract_subject_switch_performed": True,
        "contract_subject_switch_response_observed": True,
    }


def test_contract_subject_confirmation_survives_continuous_page_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    option_clicked = False
    response_handler: object | None = None

    class Input:
        @property
        def first(self) -> Input:
            return self

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000

    class Control:
        def locator(self, selector: str) -> Input:
            assert selector == "input"
            return Input()

    class Option:
        def inner_text(self) -> str:
            return "山西贵恩博信息科技有限公司"

        def click(self, *, timeout: int) -> None:
            nonlocal option_clicked
            assert timeout == 10_000
            option_clicked = True

    class Options:
        def count(self) -> int:
            return 1

        def nth(self, index: int) -> Option:
            assert index == 0
            return Option()

    class Page:
        def locator(self, selector: str) -> Options:
            assert selector == ".el-select-dropdown:visible .el-select-dropdown__item"
            return Options()

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 250
            assert callable(response_handler)
            response_handler(
                SimpleNamespace(
                    url="https://pc.chengfengkuaiyun.com/api/user-center-server/message/unread",
                    status=200,
                    request=SimpleNamespace(resource_type="xhr"),
                )
            )

        def on(self, event: str, handler: object) -> None:
            nonlocal response_handler
            assert event == "response"
            response_handler = handler

        def remove_listener(self, event: str, handler: object) -> None:
            nonlocal response_handler
            assert event == "response"
            assert handler is response_handler
            response_handler = None

    monkeypatch.setattr(
        engine,
        "_contract_subject_control",
        lambda _page, *, login_page: Control(),
    )
    monkeypatch.setattr(
        engine,
        "_selected_contract_subject_code",
        lambda _page, *, login_page: (
            "shanxi_guienbo" if option_clicked else "shanghai_jinyisheng"
        ),
    )

    result = engine._ensure_contract_subject(
        Page(),
        contract_subject_code="shanxi_guienbo",
        login_page=False,
    )

    assert result == {
        "contract_subject_code": "shanxi_guienbo",
        "contract_subject_switch_performed": True,
        "contract_subject_switch_response_observed": True,
    }
    assert response_handler is None


def test_contract_subject_uses_stable_selection_when_switch_has_no_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    option_clicked = False

    class Input:
        @property
        def first(self) -> Input:
            return self

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000

    class Control:
        def locator(self, selector: str) -> Input:
            assert selector == "input"
            return Input()

    class Option:
        def inner_text(self) -> str:
            return "上海晋亿晟信息科技有限公司"

        def click(self, *, timeout: int) -> None:
            nonlocal option_clicked
            assert timeout == 10_000
            option_clicked = True

    class Options:
        def count(self) -> int:
            return 1

        def nth(self, index: int) -> Option:
            assert index == 0
            return Option()

    class Page:
        def locator(self, selector: str) -> Options:
            assert selector == ".el-select-dropdown:visible .el-select-dropdown__item"
            return Options()

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 250

        def on(self, event: str, handler: object) -> None:
            assert event == "response"

        def remove_listener(self, event: str, handler: object) -> None:
            assert event == "response"

    monkeypatch.setattr(
        engine,
        "_contract_subject_control",
        lambda _page, *, login_page: Control(),
    )
    monkeypatch.setattr(
        engine,
        "_selected_contract_subject_code",
        lambda _page, *, login_page: (
            "shanghai_jinyisheng" if option_clicked else "shanxi_guienbo"
        ),
    )

    result = engine._ensure_contract_subject(
        Page(),
        contract_subject_code="shanghai_jinyisheng",
        login_page=False,
    )

    assert result == {
        "contract_subject_code": "shanghai_jinyisheng",
        "contract_subject_switch_performed": True,
        "contract_subject_switch_response_observed": False,
    }


def test_contract_subject_hands_full_reload_to_final_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    option_clicked = False
    post_click_selection_reads = 0
    response_handler: object | None = None

    class Input:
        @property
        def first(self) -> Input:
            return self

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000

    class Control:
        def locator(self, selector: str) -> Input:
            assert selector == "input"
            return Input()

    class Option:
        def inner_text(self) -> str:
            return "山西贵恩博信息科技有限公司"

        def click(self, *, timeout: int) -> None:
            nonlocal option_clicked
            assert timeout == 10_000
            option_clicked = True

    class Options:
        def count(self) -> int:
            return 1

        def nth(self, index: int) -> Option:
            assert index == 0
            return Option()

    class Page:
        def locator(self, selector: str) -> Options:
            assert selector == ".el-select-dropdown:visible .el-select-dropdown__item"
            return Options()

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 250
            assert callable(response_handler)
            response_handler(
                SimpleNamespace(
                    url="https://pc.chengfengkuaiyun.com/billablewaybill",
                    status=200,
                    request=SimpleNamespace(resource_type="document"),
                )
            )

        def on(self, event: str, handler: object) -> None:
            nonlocal response_handler
            assert event == "response"
            response_handler = handler

        def remove_listener(self, event: str, handler: object) -> None:
            nonlocal response_handler
            assert event == "response"
            assert handler is response_handler
            response_handler = None

    monkeypatch.setattr(
        engine,
        "_contract_subject_control",
        lambda _page, *, login_page: Control(),
    )

    def selected(_page: object, *, login_page: bool) -> str:
        nonlocal post_click_selection_reads
        if not option_clicked:
            return "shanghai_jinyisheng"
        post_click_selection_reads += 1
        if post_click_selection_reads > 1:
            raise engine.BrowserReadError(
                "browser_contract_subject_control_unavailable"
            )
        return "shanxi_guienbo"

    monkeypatch.setattr(engine, "_selected_contract_subject_code", selected)

    result = engine._ensure_contract_subject(
        Page(),
        contract_subject_code="shanxi_guienbo",
        login_page=False,
    )

    assert result == {
        "contract_subject_code": "shanxi_guienbo",
        "contract_subject_switch_performed": True,
        "contract_subject_switch_response_observed": True,
    }


def test_contract_subject_recovers_one_blank_business_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    waits = 0
    navigations = 0

    class Page:
        url = engine.CHENGFENG_HUMAN_LOGIN_ENTRY

        def wait_for_timeout(self, milliseconds: int) -> None:
            nonlocal waits
            assert milliseconds == 250
            waits += 1

        def goto(
            self,
            url: str,
            *,
            wait_until: str,
            timeout: int,
        ) -> object:
            nonlocal navigations
            assert url == engine.CHENGFENG_HUMAN_LOGIN_ENTRY
            assert wait_until == "domcontentloaded"
            assert timeout == engine.HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS
            navigations += 1
            return SimpleNamespace(status=200)

    monkeypatch.setattr(
        engine,
        "_entry_business_controls_visible",
        lambda _page: navigations == 1,
    )
    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)
    monkeypatch.setattr(
        engine,
        "_selected_contract_subject_code",
        lambda _page, *, login_page: "shanghai_jinyisheng",
    )

    engine._stabilize_contract_subject_business_page(
        Page(),
        contract_subject_code="shanghai_jinyisheng",
        entry=engine.CHENGFENG_HUMAN_LOGIN_ENTRY,
        daily=False,
    )

    assert waits == (
        engine.CONTRACT_SUBJECT_OPTION_TIMEOUT_MS // 250
        + engine.CONTRACT_SUBJECT_STABLE_POLL_COUNT
    )
    assert navigations == 1


def test_headless_entry_waits_for_delayed_login_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    checks = 0
    waits = 0

    class Page:
        def wait_for_timeout(self, milliseconds: int) -> None:
            nonlocal waits
            assert milliseconds == 500
            waits += 1

    def requires_login(_page: object) -> bool:
        nonlocal checks
        checks += 1
        return checks >= 3

    monkeypatch.setattr(engine, "_page_requires_login", requires_login)
    monkeypatch.setattr(
        engine,
        "_entry_business_controls_visible",
        lambda _page: False,
    )

    assert engine._wait_for_entry_login_state(Page()) is True
    assert waits == 2


def test_headless_entry_reuses_ready_authenticated_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)

    class Page:
        def wait_for_timeout(self, _milliseconds: int) -> None:
            raise AssertionError("ready page must not wait")

    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)
    monkeypatch.setattr(
        engine,
        "_entry_business_controls_visible",
        lambda _page: True,
    )

    assert engine._wait_for_entry_login_state(Page()) is False


def test_settlement_control_wait_classifies_a_late_login_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)

    class Page:
        def get_by_text(self, *_args: object, **_kwargs: object) -> object:
            raise RuntimeError("control unavailable")

    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: True)

    with pytest.raises(engine.BrowserReadError) as raised:
        engine.BrowserEngine()._wait_for_settlement_controls(Page())

    assert raised.value.code == "browser_read_login_required"


def test_settlement_controls_use_exact_tab_role_and_one_visible_query_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    calls: list[tuple[str, str]] = []

    class Control:
        def __init__(self, name: str, *, count: int = 1) -> None:
            self.name = name
            self._count = count

        def filter(self, *, visible: bool) -> Control:
            assert visible is True
            return self

        @property
        def first(self) -> Control:
            return self

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert state == "visible"
            assert timeout == engine.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS
            calls.append(("visible", self.name))

        def count(self) -> int:
            return self._count

        def nth(self, index: int) -> Control:
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
        ) -> Control:
            assert role == "button"
            assert exact is True
            assert name in {"重置", "查询"}
            return Control(name)

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def get_by_text(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("the waybill tab must not use a text locator")

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Control:
            assert (role, name, exact) == ("tab", "按运单显示", True)
            return Control("waybill-tab")

        def locator(self, selector: str) -> Control:
            assert selector == "[role='search']:visible, form:visible, .el-form:visible"

            class QueryRegions:
                def count(self) -> int:
                    return 2

                def nth(self, index: int) -> QueryRegions:
                    assert index in {0, 1}
                    self.index = index
                    return self

                def is_visible(self) -> bool:
                    return True

                def get_by_role(
                    self,
                    role: str,
                    *,
                    name: str,
                    exact: bool,
                ) -> Control:
                    if self.index == 0:
                        raise RuntimeError("unrelated visible form")
                    return Control("query-form").get_by_role(
                        role,
                        name=name,
                        exact=exact,
                    )

            return QueryRegions()  # type: ignore[return-value]

    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)

    _, _, waybill, reset, query = engine.BrowserEngine()._wait_for_settlement_controls(
        Page(),
        require_scope_controls=False,
    )

    assert (waybill.name, reset.name, query.name) == (
        "waybill-tab",
        "重置",
        "查询",
    )
    assert calls == [
        ("visible", "waybill-tab"),
        ("visible", "重置"),
        ("visible", "查询"),
    ]


def test_settlement_controls_accept_exact_whitespace_normalized_element_tab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)

    class MissingRole:
        def count(self) -> int:
            return 0

        def filter(self, *, visible: bool) -> MissingRole:
            assert visible is True
            return self

        @property
        def first(self) -> MissingRole:
            return self

        def wait_for(self, *, state: str, timeout: int) -> None:
            raise RuntimeError((state, timeout))

    class Control:
        def __init__(self, name: str) -> None:
            self.name = name

        def filter(self, *, visible: bool) -> Control:
            assert visible is True
            return self

        @property
        def first(self) -> Control:
            return self

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert state == "visible"
            assert timeout == engine.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS

        def is_visible(self) -> bool:
            return True

        def count(self) -> int:
            return 1

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> MissingRole:
            assert (role, name, exact) == ("tab", "按运单显示", True)
            return MissingRole()

        def locator(self, selector: str) -> object:
            if selector == "[role='tab']:visible, .el-tabs__item:visible":
                candidates = (
                    (" 按 订单 显示 ", "order-tab"),
                    ("\n按 运单\t显示\n", "waybill-tab"),
                )

                class TabCandidates:
                    def count(self) -> int:
                        return len(candidates)

                    def nth(self, index: int) -> TabCandidate:
                        text, name = candidates[index]
                        return TabCandidate(text, name)

                class TabCandidate(Control):
                    def __init__(self, text: str, name: str) -> None:
                        super().__init__(name)
                        self._text = text

                    def text_content(self) -> str:
                        return self._text

                return TabCandidates()

            assert selector == "[role='search']:visible, form:visible, .el-form:visible"

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
                ) -> Control:
                    assert role == "button"
                    assert exact is True
                    return Control(name)

            return QueryRegions()

    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)

    _, _, waybill, reset, query = engine.BrowserEngine()._wait_for_settlement_controls(
        Page(),
        require_scope_controls=False,
    )

    assert (waybill.name, reset.name, query.name) == (
        "waybill-tab",
        "重置",
        "查询",
    )


def test_settlement_controls_accept_one_unique_visible_global_button_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)

    class Control:
        def __init__(self, name: str, *, count: int = 1) -> None:
            self.name = name
            self._count = count

        def filter(self, *, visible: bool) -> Control:
            assert visible is True
            return self

        @property
        def first(self) -> Control:
            return self

        def count(self) -> int:
            return self._count

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert state == "visible"
            assert timeout == engine.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS

    class EmptyRegions:
        def count(self) -> int:
            return 0

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Control:
            assert exact is True
            if role == "tab":
                assert name == "按运单显示"
                return Control("waybill-tab")
            assert role == "button"
            assert name in {"重置", "查询"}
            return Control(name)

        def locator(self, selector: str) -> EmptyRegions:
            assert selector == "[role='search']:visible, form:visible, .el-form:visible"
            return EmptyRegions()

    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)

    _, _, waybill, reset, query = engine.BrowserEngine()._wait_for_settlement_controls(
        Page(),
        require_scope_controls=False,
    )

    assert (waybill.name, reset.name, query.name) == (
        "waybill-tab",
        "重置",
        "查询",
    )


def test_settlement_controls_skip_visible_form_without_query_buttons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    waited: list[str] = []

    class Control:
        def __init__(self, name: str, *, count: int = 1) -> None:
            self.name = name
            self._count = count

        def filter(self, *, visible: bool) -> Control:
            assert visible is True
            return self

        @property
        def first(self) -> Control:
            return self

        def count(self) -> int:
            return self._count

        def wait_for(self, *, state: str, timeout: int) -> None:
            assert state == "visible"
            assert timeout == engine.SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS
            waited.append(self.name)

    class HeaderForm:
        def is_visible(self) -> bool:
            return True

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Control:
            assert role == "button"
            assert exact is True
            return Control(f"header-{name}", count=0)

    class QueryRegions:
        def count(self) -> int:
            return 1

        def nth(self, index: int) -> HeaderForm:
            assert index == 0
            return HeaderForm()

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Control:
            assert exact is True
            if role == "tab":
                assert name == "按运单显示"
                return Control("waybill-tab")
            assert role == "button"
            assert name in {"重置", "查询"}
            return Control(name)

        def locator(self, selector: str) -> QueryRegions:
            assert selector == "[role='search']:visible, form:visible, .el-form:visible"
            return QueryRegions()

    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)

    _, _, _, reset, query = engine.BrowserEngine()._wait_for_settlement_controls(
        Page(),
        require_scope_controls=False,
    )

    assert (reset.name, query.name) == ("重置", "查询")
    assert waited == ["waybill-tab", "重置", "查询"]


def test_single_chengfeng_page_keeps_hydrated_login_over_empty_duplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    closed: list[str] = []

    class Page:
        def __init__(self, name: str, *, hydrated: bool) -> None:
            self.name = name
            self.hydrated = hydrated
            self.url = "https://pc.chengfengkuaiyun.com/login"

        def is_closed(self) -> bool:
            return False

        def close(self) -> None:
            closed.append(self.name)

        def evaluate(self, _script: str) -> dict[str, object]:
            return {
                "ready_state": "complete" if self.hydrated else "loading",
                "body_element_count": 500 if self.hydrated else 0,
            }

    empty = Page("empty", hydrated=False)
    hydrated = Page("hydrated", hydrated=True)
    browser = engine.BrowserEngine()
    browser._context = type("Context", (), {"pages": [empty, hydrated]})()
    browser._human_page = empty
    monkeypatch.setattr(
        engine,
        "_page_requires_login",
        lambda page: bool(page.hydrated),
    )
    monkeypatch.setattr(
        engine,
        "_entry_business_controls_visible",
        lambda _page: False,
    )

    assert browser._human_page_or_create() is hydrated
    assert browser._human_page is hydrated
    assert closed == ["empty"]


def test_single_chengfeng_page_does_not_delete_loading_duplicates_blindly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    closed: list[str] = []

    class Page:
        url = "https://pc.chengfengkuaiyun.com/login"

        def __init__(self, name: str) -> None:
            self.name = name

        def is_closed(self) -> bool:
            return False

        def close(self) -> None:
            closed.append(self.name)

        def evaluate(self, _script: str) -> dict[str, object]:
            return {"ready_state": "loading", "body_element_count": 0}

    preferred = Page("preferred")
    other = Page("other")
    browser = engine.BrowserEngine()
    browser._context = type("Context", (), {"pages": [preferred, other]})()
    browser._human_page = preferred
    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)
    monkeypatch.setattr(
        engine,
        "_entry_business_controls_visible",
        lambda _page: False,
    )

    assert browser._human_page_or_create() is preferred
    assert closed == []


def test_single_chengfeng_page_rechecks_a_restored_blank_tab_after_hydration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    closed: list[str] = []

    class Page:
        def __init__(self, name: str, url: str, *, hydrated: bool) -> None:
            self.name = name
            self.url = url
            self.hydrated = hydrated

        def is_closed(self) -> bool:
            return self.name in closed

        def close(self) -> None:
            closed.append(self.name)

        def evaluate(self, _script: str) -> dict[str, object]:
            return {
                "ready_state": "complete" if self.hydrated else "loading",
                "body_element_count": 500 if self.hydrated else 0,
            }

        def wait_for_timeout(self, _milliseconds: int) -> None:
            restored.url = "https://pc.chengfengkuaiyun.com/login"
            restored.hydrated = True

    preferred = Page(
        "preferred",
        "https://pc.chengfengkuaiyun.com/billablewaybill",
        hydrated=True,
    )
    restored = Page("restored", "about:blank", hydrated=False)
    browser = engine.BrowserEngine()
    browser._context = type("Context", (), {"pages": [preferred, restored]})()
    browser._human_page = preferred
    monkeypatch.setattr(
        engine,
        "_page_requires_login",
        lambda page: page.url.endswith("/login") and page.hydrated,
    )
    monkeypatch.setattr(
        engine,
        "_entry_business_controls_visible",
        lambda page: page is preferred,
    )

    assert browser._human_page_or_create(wait_for_hydrated=True) is preferred
    assert closed == ["restored"]


def test_single_chengfeng_page_guard_closes_a_late_restored_platform_tab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    callbacks: dict[str, object] = {}

    class Page:
        def __init__(self, url: str) -> None:
            self.url = url
            self.closed = False

        def close(self) -> None:
            self.closed = True

        def on(self, event: str, callback: object) -> None:
            assert event == "domcontentloaded"
            callbacks[event] = callback

    primary = Page("https://pc.chengfengkuaiyun.com/billablewaybill")

    class Context:
        def on(self, event: str, callback: object) -> None:
            assert event == "page"
            callbacks[event] = callback

    browser = engine.BrowserEngine()
    browser._context = Context()
    browser._human_page = primary
    browser._install_single_chengfeng_page_guard()

    restored = Page("about:blank")
    page_handler = callbacks["page"]
    assert callable(page_handler)
    page_handler(restored)
    restored.url = "https://pc.chengfengkuaiyun.com/login"
    dom_handler = callbacks["domcontentloaded"]
    assert callable(dom_handler)
    dom_handler()

    assert restored.closed is True


def test_saved_login_uses_values_only_inside_the_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    values: list[tuple[str, str]] = []

    class Locator:
        first: Locator

        def __init__(self, name: str) -> None:
            self.name = name
            self.first = self

        def is_visible(self) -> bool:
            return True

        def fill(self, value: str) -> None:
            values.append((self.name, value))

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def locator(self, selector: str) -> Locator:
            if "password" in selector:
                return Locator("password")
            return Locator("username")

        def get_by_role(
            self,
            role: str,
            *,
            name: str,
            exact: bool,
        ) -> Locator:
            assert (role, name, exact) == ("button", "登录", True)
            return Locator("submit")

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 500

    monkeypatch.setattr(engine, "_visible_captcha", lambda _page: False)
    monkeypatch.setattr(engine, "_page_requires_login", lambda _page: False)
    monkeypatch.setattr(
        engine,
        "read_saved_credential",
        lambda: SimpleNamespace(
            username="fixture-user",
            password="fixture-password",
        ),
    )

    assert engine._login_with_saved_credential(Page()) is None
    assert values == [
        ("username", "fixture-user"),
        ("password", "fixture-password"),
    ]


def test_saved_login_allows_the_platform_sixty_seconds_to_finish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _ = _load_worker_modules(monkeypatch)
    login_checks = 0
    wait_count = 0

    class Locator:
        first: Locator

        def __init__(self) -> None:
            self.first = self

        def is_visible(self) -> bool:
            return True

        def fill(self, _value: str) -> None:
            return None

        def click(self, *, timeout: int) -> None:
            assert timeout == 10_000

    class Page:
        url = "https://pc.chengfengkuaiyun.com/billablewaybill"

        def locator(self, _selector: str) -> Locator:
            return Locator()

        def get_by_role(
            self,
            _role: str,
            *,
            name: str,
            exact: bool,
        ) -> Locator:
            assert (name, exact) == ("登录", True)
            return Locator()

        def wait_for_timeout(self, milliseconds: int) -> None:
            nonlocal wait_count
            assert milliseconds == 500
            wait_count += 1

    def requires_login(_page: object) -> bool:
        nonlocal login_checks
        login_checks += 1
        return login_checks <= 40

    monkeypatch.setattr(engine, "_visible_captcha", lambda _page: False)
    monkeypatch.setattr(engine, "_page_requires_login", requires_login)
    monkeypatch.setattr(
        engine,
        "read_saved_credential",
        lambda: SimpleNamespace(username="fixture", password="secret"),
    )

    assert engine._login_with_saved_credential(Page()) is None
    assert wait_count == 41
