from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
BROWSER_SOURCE = PROJECT_ROOT / "browser-runtime" / "src"


def test_main_runtime_bootstrap_and_worker_protocol_versions_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dahe.adapters.chengfeng.browser_runtime import (
        BROWSER_PROTOCOL_VERSION,
    )

    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.protocol", None)
    from dahe_browser_worker.protocol import PROTOCOL_VERSION

    assert BROWSER_PROTOCOL_VERSION == PROTOCOL_VERSION


def test_login_entry_error_code_survives_the_worker_main_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from dahe.adapters.chengfeng.browser_runtime import (
        BrowserRuntimeError,
        IsolatedBrowserRuntime,
    )

    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.protocol", None)
    from dahe_browser_worker.protocol import InitializeCommand, response

    wire = json.loads(
        response(
            InitializeCommand(
                request_id="login-contract",
                browser="auto",
                profile_root=tmp_path / "profile",
                staging_root=tmp_path / "staging",
            ),
            ok=False,
            selected_browser=None,
            error_code="browser_login_entry_failed",
            browser_open=False,
        )
    )
    assert set(wire) == {
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

    with pytest.raises(BrowserRuntimeError) as raised:
        IsolatedBrowserRuntime._raise_worker_error(wire["error_code"])

    assert raised.value.code == "browser_login_entry_failed"


def test_browser_dependencies_are_exact_and_absent_from_main_project() -> None:
    lock = (
        (PROJECT_ROOT / "browser-runtime" / "requirements.lock")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    requirements = {
        line.split("==", 1)[0].casefold() for line in lock if line and not line.startswith("#")
    }
    assert "playwright" in requirements
    assert all(line.count("==") == 1 for line in lock if line)
    main_project = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "playwright" not in main_project.casefold()


def test_worker_protocol_has_no_arbitrary_url_or_navigation_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.protocol", None)
    from dahe_browser_worker.protocol import (
        PROTOCOL_VERSION,
        ProtocolError,
        parse_command,
    )

    command = parse_command(
        json.dumps(
            {
                "schema_version": PROTOCOL_VERSION,
                "command": "smoke",
                "request_id": "r1",
                "browser": "auto",
                "browser_store": tmp_path.as_posix(),
            }
        )
    )
    assert command.browser == "auto"
    capture = parse_command(
        json.dumps(
            {
                "schema_version": PROTOCOL_VERSION,
                "command": "capture_start",
                "request_id": "capture-1",
            }
        )
    )
    assert capture.request_id == "capture-1"
    status = parse_command(
        json.dumps(
            {
                "schema_version": PROTOCOL_VERSION,
                "command": "status",
                "request_id": "status-1",
            }
        )
    )
    assert status.request_id == "status-1"
    with pytest.raises(ProtocolError):
        parse_command(
            json.dumps(
                {
                    "schema_version": PROTOCOL_VERSION,
                    "command": "navigate",
                    "request_id": "r1",
                    "browser": "auto",
                    "browser_store": tmp_path.as_posix(),
                    "url": "https://example.invalid",
                }
            )
        )
    with pytest.raises(ProtocolError):
        parse_command(
            json.dumps(
                {
                    "schema_version": PROTOCOL_VERSION,
                    "command": "status",
                    "request_id": "status-2",
                    "url": "https://example.invalid",
                }
            )
        )
    with pytest.raises(ProtocolError):
        parse_command(
            json.dumps(
                {
                    "schema_version": PROTOCOL_VERSION,
                    "command": "capture_start",
                    "request_id": "capture-2",
                    "url": "https://example.invalid",
                }
            )
        )


def test_human_login_opens_only_the_fixed_chengfeng_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    sys.modules.pop("dahe_browser_worker.protocol", None)
    from dahe_browser_worker.engine import (
        CHENGFENG_HUMAN_LOGIN_ENTRY,
        HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
        BrowserEngine,
    )
    from dahe_browser_worker.protocol import InitializeCommand

    launch_options: dict[str, object] = {}

    class Response:
        status = 200

    class Page:
        url = CHENGFENG_HUMAN_LOGIN_ENTRY
        wait_for_function_calls = 0

        def goto(self, url: str, **options: object) -> Response:
            assert url == CHENGFENG_HUMAN_LOGIN_ENTRY
            assert options == {
                "wait_until": "commit",
                "timeout": HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
            }
            return Response()

        def wait_for_function(self, expression: str, *, timeout: int) -> None:
            self.wait_for_function_calls += 1

        def bring_to_front(self) -> None:
            return None

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]
            self.request_handler: object | None = None
            self.page_handler: object | None = None

        def on(self, event: str, handler: object) -> None:
            if event == "page":
                self.page_handler = handler
                return
            assert event == "request"
            self.request_handler = handler

        def remove_listener(self, event: str, handler: object) -> None:
            if event == "page":
                assert handler is self.page_handler
                self.page_handler = None
                return
            assert event == "request"
            assert handler is self.request_handler
            self.request_handler = None

        def close(self) -> None:
            return None

    class Chromium:
        def launch_persistent_context(
            self,
            *,
            user_data_dir: Path,
            **options: object,
        ) -> Context:
            assert user_data_dir == (
                tmp_path
                / "data"
                / "browser-profile"
                / "chengfeng-shadow"
                / "chromium"
            )
            launch_options.update(options)
            return Context()

    class Playwright:
        chromium = Chromium()

        def stop(self) -> None:
            return None

    class Manager:
        def start(self) -> Playwright:
            return Playwright()

    sync_api = SimpleNamespace(
        Error=RuntimeError,
        sync_playwright=lambda: Manager(),
    )
    monkeypatch.setitem(sys.modules, "playwright", SimpleNamespace(sync_api=sync_api))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    staging_root = (
        tmp_path / "data" / "runtime" / "browser-worker" / "read-results"
    )
    completed_orphan = staging_root / f"daily-{'d' * 32}"
    interrupted_orphan = staging_root / f"read-{'e' * 32}"
    unrelated = staging_root / "unrelated"
    completed_orphan.mkdir(parents=True)
    interrupted_orphan.mkdir()
    unrelated.mkdir()
    (completed_orphan / "payload.json").write_bytes(
        b'{"token":"must-not-survive-restart"}'
    )
    (interrupted_orphan / ".payload.part").write_bytes(b"private-partial")
    (unrelated / "keep.txt").write_text("keep", encoding="utf-8")

    engine = BrowserEngine()
    selected = engine.initialize(
        InitializeCommand(
            request_id="human-login",
            browser="chromium",
            profile_root=(
                tmp_path / "data" / "browser-profile" / "chengfeng-shadow"
            ),
            staging_root=staging_root,
        )
    )
    try:
        assert selected == "chromium"
        assert not completed_orphan.exists()
        assert not interrupted_orphan.exists()
        assert (unrelated / "keep.txt").read_text(encoding="utf-8") == "keep"
        assert launch_options["headless"] is False
        assert launch_options["chromium_sandbox"] is True
        assert launch_options["no_viewport"] is True
        assert launch_options["service_workers"] == "block"
        assert engine._context.pages[0].wait_for_function_calls == 0
        assert engine._context.request_handler is not None
    finally:
        engine.close()


def test_parent_deadline_exceeds_fixed_entry_navigation_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS

    from dahe.adapters.chengfeng.browser_runtime import (
        HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS,
    )

    assert HUMAN_LOGIN_WORKER_TIMEOUT_SECONDS * 1000 > HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS


def test_parent_deadline_exceeds_session_header_capture_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import (
        SESSION_HEADER_CAPTURE_POLL_MS,
        SESSION_HEADER_CAPTURE_WAIT_STEPS,
        SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
    )

    from dahe.adapters.chengfeng.browser_runtime import (
        PREPARE_AUTOMATED_WORKER_TIMEOUT_SECONDS,
    )

    worker_wait_ms = (
        SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS
        + SESSION_HEADER_CAPTURE_POLL_MS * SESSION_HEADER_CAPTURE_WAIT_STEPS
        + 10_000
    )
    assert worker_wait_ms < PREPARE_AUTOMATED_WORKER_TIMEOUT_SECONDS * 1000


def test_operational_handoff_erases_private_authority_and_preserves_human_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker import engine as engine_module

    events: list[str] = []

    class ControlledPage:
        def close(self) -> None:
            events.append("controlled_closed")

    class HumanPage:
        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def bring_to_front() -> None:
            events.append("human_brought_to_front")

    class Context:
        def __init__(self) -> None:
            self.pages = [HumanPage()]
            self.removed: object | None = None

        def new_page(self) -> object:
            raise AssertionError("handoff must not create another person-owned page")

        def remove_listener(self, event: str, handler: object) -> None:
            assert event == "request"
            self.removed = handler

    browser = engine_module.BrowserEngine()
    context = Context()
    browser._context = context
    browser._human_page = context.pages[0]
    browser._operational_batch_page = ControlledPage()
    browser._automated_prepared = True
    browser._operational_compat_prepared = True
    browser._session_request_handler = object()
    browser._session_headers = {"authorization": "private"}
    browser._session_list_body = {"hidden": "private"}
    browser._session_native_probe = {"metrics": {"total_count": 1}}
    browser._operational_first_list_content = b"private response"
    browser._operational_query_trace = {"private": True}
    browser._detail_image_grants = {"https://private.invalid": 99.0}
    browser.handoff_operational_session()

    assert events == ["controlled_closed", "human_brought_to_front"]
    assert context.removed is not None
    assert browser._automated_prepared is False
    assert browser._operational_compat_prepared is False
    assert browser._session_request_handler is None
    assert browser._session_headers is None
    assert browser._session_list_body is None
    assert browser._session_native_probe is None
    assert browser._operational_first_list_content is None
    assert browser._operational_query_trace is None
    assert browser._detail_image_grants == {}


def test_operational_handoff_does_not_close_the_single_shared_platform_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker import engine as engine_module

    events: list[str] = []

    class PlatformPage:
        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def close() -> None:
            events.append("closed")

        @staticmethod
        def bring_to_front() -> None:
            events.append("front")

    class Context:
        def __init__(self, page: PlatformPage) -> None:
            self.pages = [page]

        @staticmethod
        def new_page() -> object:
            raise AssertionError("handoff must preserve the shared page")

    page = PlatformPage()
    browser = engine_module.BrowserEngine()
    browser._context = Context(page)
    browser._human_page = page
    browser._operational_batch_page = page
    browser._automated_prepared = True
    browser._operational_compat_prepared = True

    browser.handoff_operational_session()

    assert events == ["front"]


def test_single_platform_page_selection_closes_only_chengfeng_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker import engine as engine_module

    class Page:
        def __init__(self, url: str) -> None:
            self.url = url
            self.closed = False

        def is_closed(self) -> bool:
            return self.closed

        def close(self) -> None:
            self.closed = True

        def evaluate(self, _script: str) -> dict[str, object]:
            return {"ready_state": "complete", "body_element_count": 1}

    primary = Page("https://pc.chengfengkuaiyun.com/billablewaybill")
    duplicate = Page("https://pc.chengfengkuaiyun.com/wayBill")
    unrelated = Page("https://example.com/")

    class Context:
        def __init__(self) -> None:
            self.pages = [primary, duplicate, unrelated]

        @staticmethod
        def new_page() -> object:
            raise AssertionError("an existing Chengfeng page must be reused")

    browser = engine_module.BrowserEngine()
    browser._context = Context()
    browser._human_page = primary

    selected = browser._human_page_or_create()

    assert selected is primary
    assert primary.closed is False
    assert duplicate.closed is True
    assert unrelated.closed is False


@pytest.mark.parametrize(
    "url",
    [
        "about:blank",
        "http://pc.chengfengkuaiyun.com/billablewaybill",
        "https://example.invalid/login",
        "https://pc.chengfengkuaiyun.com/wayBill",
        "https://user:password@pc.chengfengkuaiyun.com/login",
    ],
)
def test_human_login_rejects_blank_insecure_or_unapproved_landing(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import LoginEntryError, assert_login_landing

    with pytest.raises(LoginEntryError):
        assert_login_landing(url, response_status=200)


@pytest.mark.parametrize(
    "url",
    [
        "https://pc.chengfengkuaiyun.com/billablewaybill",
        "https://pc.chengfengkuaiyun.com/login",
        "https://pc.chengfengkuaiyun.com/login?redirect=%2Fbillablewaybill",
    ],
)
def test_human_login_accepts_only_expected_same_origin_landings(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import assert_login_landing

    assert_login_landing(url, response_status=200)


def test_human_login_rejects_failed_http_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import LoginEntryError, assert_login_landing

    with pytest.raises(LoginEntryError):
        assert_login_landing(
            "https://pc.chengfengkuaiyun.com/login",
            response_status=503,
        )


def test_worker_source_is_the_only_project_area_that_imports_playwright() -> None:
    imports = []
    for path in PROJECT_ROOT.rglob("*.py"):
        if any(part in {".venv", ".runtime", "build", "__pycache__"} for part in path.parts):
            continue
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "import playwright" in text or "from playwright" in text:
            imports.append(path.relative_to(PROJECT_ROOT).as_posix())
    assert imports == ["browser-runtime/src/dahe_browser_worker/engine.py"]


def test_edge_is_discovered_from_whitelisted_system_install_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import _trusted_edge_executable

    program_files = tmp_path / "Program Files (x86)"
    edge = program_files / "Microsoft" / "Edge" / "Application" / "msedge.exe"
    edge.parent.mkdir(parents=True)
    edge.write_bytes(b"test executable identity")

    discovered = _trusted_edge_executable(
        {
            "PROGRAMFILES(X86)": str(program_files),
            "LOCALAPPDATA": str(tmp_path / "isolated-local-app-data"),
        }
    )

    assert discovered == edge.resolve()


def test_discovery_sanitizer_retains_shapes_without_values_or_signed_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import _request_observation

    class Request:
        method = "POST"
        resource_type = "xhr"
        url = "https://platform.example.invalid/api/waybills/list?page=1&signature=secret-value"

        def __init__(self) -> None:
            self.post_data_json = {
                "pageNumber": 1,
                "filter": {"status": "current"},
                "password": "must-not-survive",
            }

    observation = _request_observation(Request())

    assert observation is not None
    serialized = json.dumps(observation, ensure_ascii=False, sort_keys=True)
    assert observation["origin"] == "https://platform.example.invalid"
    assert observation["path"] == "/api/waybills/list"
    assert observation["query_keys"] == ["page", "signature"]
    assert "pageNumber" in serialized
    assert "filter.status" in serialized
    for forbidden in (
        "secret-value",
        "must-not-survive",
        "https://platform.example.invalid/api",
        '"password"',
    ):
        assert forbidden not in serialized


def test_discovery_sanitizer_hashes_image_paths_and_drops_login_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    sys.modules.pop("dahe_browser_worker.engine", None)
    from dahe_browser_worker.engine import _request_observation

    class ImageRequest:
        method = "GET"
        resource_type = "image"
        url = "https://images.example.invalid/private/one.jpeg?Expires=60&token=secret"
        post_data_json = None

    class LoginRequest:
        method = "POST"
        resource_type = "xhr"
        url = "https://platform.example.invalid/api/login"

        def __init__(self) -> None:
            self.post_data_json = {"account": "secret"}

    image = _request_observation(ImageRequest())

    assert image is not None
    assert image["path"] is None
    assert image["path_sha256"]
    assert "/private/one.jpeg" not in json.dumps(image)
    assert _request_observation(LoginRequest()) is None
