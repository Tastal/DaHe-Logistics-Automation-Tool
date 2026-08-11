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


def test_headless_initialize_protocol_contains_no_credential_material(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, protocol = _load_worker_modules(monkeypatch)
    profile = (tmp_path / "browser-profile" / "chengfeng-shadow").resolve()
    staging = (
        tmp_path / "runtime" / "browser-worker" / "read-results"
    ).resolve()
    raw = {
        "schema_version": 6,
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
        lambda: (_ for _ in ()).throw(
            AssertionError("credentials must not be read")
        ),
    )

    with pytest.raises(engine.BrowserReadError) as raised:
        engine._login_with_saved_credential(object())

    assert raised.value.code == "browser_saved_login_captcha_required"


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
