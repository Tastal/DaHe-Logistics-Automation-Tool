from __future__ import annotations

import json
from pathlib import Path

import pytest

import dahe.adapters.chengfeng.browser_runtime as browser_runtime_module
from dahe.adapters.chengfeng.browser_runtime import (
    BROWSER_PROTOCOL_VERSION,
    FREEZE_HUMAN_SESSION_WORKER_TIMEOUT_SECONDS,
    BrowserRuntimeError,
    IsolatedBrowserRuntime,
    SettlementViewProbe,
)
from dahe.system.supervision import (
    SupervisedLineProcessError,
    SupervisedLineProcessTimeout,
)


class _FakeProcess:
    is_alive = True

    def __init__(self, response: dict[str, object]) -> None:
        self._response = response

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        del timeout_seconds
        request = json.loads(line)
        response = dict(self._response)
        response["request_id"] = request["request_id"]
        return json.dumps(response)


class _TimeoutProcess:
    is_alive = True

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        del line, timeout_seconds
        raise SupervisedLineProcessTimeout("the owned worker response timed out")


class _FailedProcess:
    is_alive = True
    exit_code = 7
    stderr_digest = "a" * 64

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        del line, timeout_seconds
        raise SupervisedLineProcessError("worker exited")


class _RecordingProcess:
    is_alive = True

    def __init__(
        self,
        response: dict[str, object],
        *,
        responses_by_command: dict[str, dict[str, object]] | None = None,
    ) -> None:
        self._response = response
        self._responses_by_command = responses_by_command or {}
        self.timeouts: list[float] = []
        self.commands: list[str] = []
        self.closed = False

    def request_line(self, line: str, *, timeout_seconds: float) -> str:
        request = json.loads(line)
        self.commands.append(request["command"])
        self.timeouts.append(timeout_seconds)
        response = dict(
            self._responses_by_command.get(request["command"], self._response)
        )
        response["request_id"] = request["request_id"]
        return json.dumps(response)

    def close(self) -> None:
        self.closed = True
        self.is_alive = False


def _runtime(tmp_path: Path, response: dict[str, object]) -> IsolatedBrowserRuntime:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    runtime._process = _FakeProcess(response)  # type: ignore[assignment]
    return runtime


def _response(**overrides: object) -> dict[str, object]:
    response: dict[str, object] = {
        "schema_version": BROWSER_PROTOCOL_VERSION,
        "request_id": "replaced-by-fake",
        "ok": True,
        "selected_browser": "msedge",
        "error_code": None,
        "discovery": None,
        "browser_open": True,
        "batch_result": None,
        "prepare_result": None,
        "read_result": None,
    }
    response.update(overrides)
    return response


def test_formal_browser_runtime_prefers_root_embed_interpreter(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "browser-runtime"
    portable = runtime_root / "python" / "python.exe"
    portable.parent.mkdir(parents=True)
    portable.write_bytes(b"portable")
    legacy = runtime_root / "python" / "Scripts" / "python.exe"
    legacy.parent.mkdir()
    legacy.write_bytes(b"venv")
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=runtime_root,
    )

    assert runtime._python == portable


def test_worker_response_rejects_unknown_fields(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, _response(raw_page_text="must not pass"))

    with pytest.raises(BrowserRuntimeError, match="rejected the command"):
        runtime._exchange(
            {
                "schema_version": BROWSER_PROTOCOL_VERSION,
                "command": "status",
                "request_id": "status",
            },
            timeout=1,
        )


def test_login_landing_error_is_mapped_without_raw_worker_output(
    tmp_path: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        _response(
            ok=False,
            selected_browser=None,
            error_code="browser_login_entry_failed",
            browser_open=False,
        ),
    )

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime._exchange(
            {
                "schema_version": BROWSER_PROTOCOL_VERSION,
                "command": "initialize",
                "request_id": "initialize",
            },
            timeout=1,
        )

    assert raised.value.code == "browser_login_entry_failed"
    assert str(raised.value) == (
        "成丰登录页未能打开，受控浏览器已安全关闭。请检查当前网络后重试。"  # noqa: RUF001
    )


def test_worker_timeout_is_mapped_to_business_safe_chinese(tmp_path: Path) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    runtime._process = _TimeoutProcess()  # type: ignore[assignment]

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime._exchange(
            {
                "schema_version": BROWSER_PROTOCOL_VERSION,
                "command": "initialize",
                "request_id": "initialize",
            },
            timeout=1,
        )

    assert raised.value.code == "browser_worker_timeout"
    assert str(raised.value) == (
        "受控浏览器等待页面响应超时，窗口已安全关闭。请重新打开成丰登录页。"  # noqa: RUF001
    )


def test_failed_worker_emits_only_bounded_lifecycle_state(
    tmp_path: Path,
) -> None:
    events: list[tuple[str, str]] = []
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
        event_sink=lambda code, message: events.append((code, message)),
    )
    runtime._process = _FailedProcess()  # type: ignore[assignment]

    with pytest.raises(BrowserRuntimeError) as raised:
        runtime._exchange(
            {
                "schema_version": BROWSER_PROTOCOL_VERSION,
                "command": "status",
                "request_id": "status",
            },
            timeout=1,
        )

    assert raised.value.code == "browser_worker_unavailable"
    assert events == [
        (
            "browser_worker_unavailable",
            "worker_alive=true exit_code=7 stderr_digest=" + "a" * 64,
        )
    ]


def test_owned_runtime_termination_emits_sanitized_worker_state(
    tmp_path: Path,
) -> None:
    events: list[tuple[str, str]] = []
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
        event_sink=lambda code, message: events.append((code, message)),
    )
    process = _RecordingProcess(_response())
    runtime._process = process  # type: ignore[assignment]
    runtime._active_read_scope = "daily"
    runtime._headless = True

    runtime._terminate_owned()

    assert process.closed is True
    assert events == [
        (
            "browser_runtime_terminate_owned",
            "scope=daily headless=true worker_alive=true "
            "exit_code=None stderr_digest=none",
        )
    ]


def test_freeze_supervisor_outlives_the_page_readiness_deadline(
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _RecordingProcess(_response())
    runtime._process = process  # type: ignore[assignment]

    runtime.freeze_human_session()

    assert process.timeouts == [
        FREEZE_HUMAN_SESSION_WORKER_TIMEOUT_SECONDS
    ]
    assert FREEZE_HUMAN_SESSION_WORKER_TIMEOUT_SECONDS > 60


def test_reentering_human_login_resumes_the_owned_browser(
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _RecordingProcess(_response())
    runtime._process = process  # type: ignore[assignment]
    runtime._selected_browser = "msedge"

    assert runtime.start_human_login() == "msedge"

    assert process.commands == ["status", "resume_human_session"]


def test_settlement_filter_handoff_uses_one_typed_visible_command(
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _RecordingProcess(
        _response(),
        responses_by_command={
            "prepare_settlement_filter_handoff": _response(
                prepare_result={
                    "schema_version": 1,
                    "requested_count": 1,
                    "matched_count": 1,
                    "missing_count": 0,
                }
            )
        },
    )
    runtime._process = process  # type: ignore[assignment]
    runtime._selected_browser = "msedge"

    result = runtime.prepare_settlement_filter_handoff(("YD202608080001",))

    assert process.commands == [
        "status",
        "resume_human_session",
        "prepare_settlement_filter_handoff",
    ]
    assert result == {
        "requested_count": 1,
        "matched_count": 1,
        "missing_count": 0,
    }


def test_headless_login_failure_rebuilds_a_visible_owned_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    headless = _RecordingProcess(_response())
    runtime._process = headless  # type: ignore[assignment]
    runtime._selected_browser = "msedge"
    runtime._headless = True
    visible = _RecordingProcess(_response())
    monkeypatch.setattr(runtime, "_validate_installation", lambda: None)
    monkeypatch.setattr(
        browser_runtime_module,
        "SupervisedLineProcess",
        lambda **_kwargs: visible,
    )

    assert runtime.start_human_login() == "msedge"

    assert headless.closed is True
    assert visible.commands == ["initialize"]
    assert runtime._headless is False


def test_operational_worker_transport_accepts_whole_run_command_capacity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _RecordingProcess(_response())
    captured: dict[str, object] = {}

    def build_process(**kwargs: object) -> _RecordingProcess:
        captured.update(kwargs)
        return process

    monkeypatch.setattr(runtime, "_validate_installation", lambda: None)
    monkeypatch.setattr(
        browser_runtime_module,
        "SupervisedLineProcess",
        build_process,
    )

    assert runtime.start_operational() == "msedge"

    assert captured["max_request_bytes"] == 4 * 1024 * 1024
    assert captured["max_response_bytes"] == 16 * 1024 * 1024


def test_operational_handoff_uses_the_bounded_worker_command(
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _RecordingProcess(_response())
    runtime._process = process  # type: ignore[assignment]
    runtime._selected_browser = "msedge"

    runtime.handoff_operational_session()

    assert process.commands == ["handoff_operational_session"]


def test_operational_park_keeps_the_worker_and_clears_private_authority(
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _RecordingProcess(_response())
    runtime._process = process  # type: ignore[assignment]
    runtime._selected_browser = "msedge"
    runtime._active_read_scope = "settlement"
    runtime._operational_probe = object()  # type: ignore[assignment]
    runtime._daily_preparation = {"schema_version": 1}

    runtime.park_operational_session()

    assert process.commands == ["park_operational_session"]
    assert process.closed is False
    assert runtime.running is True
    assert runtime._active_read_scope is None
    assert runtime._operational_probe is None
    assert runtime._daily_preparation is None


def test_running_preserves_frozen_settlement_authority_when_spa_page_closes(
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _RecordingProcess(_response(browser_open=False))
    runtime._process = process  # type: ignore[assignment]
    runtime._active_read_scope = "settlement"
    runtime._operational_probe = object()  # type: ignore[assignment]

    assert runtime.running is True
    assert process.closed is False
    assert process.commands == []


def test_running_does_not_probe_a_busy_worker_with_frozen_daily_authority(
    tmp_path: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=tmp_path / "project",
        data_root=tmp_path / "data",
        runtime_root=tmp_path / "browser-runtime",
    )
    process = _TimeoutProcess()
    runtime._process = process  # type: ignore[assignment]
    runtime._active_read_scope = "daily"
    runtime._daily_preparation = {"schema_version": 1}

    assert runtime.running is True
    assert process.is_alive is True


def test_settlement_view_probe_accepts_only_bounded_value_free_metadata(
    tmp_path: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        _response(
            discovery=[
                {
                    "schema_version": 1,
                    "probe_kind": "chengfeng_settlement_views",
                    "operation": "list_waybills",
                    "views": [
                        {
                            "view": "settlement",
                            "metrics": {
                                "total_count": 0,
                                "list_length": 0,
                                "page_number": 1,
                                "page_size": 20,
                            },
                            "response_structure_sha256": "a" * 64,
                        },
                        {
                            "view": "credit",
                            "metrics": {
                                "total_count": 137,
                                "list_length": 20,
                                "page_number": 1,
                                "page_size": 20,
                            },
                            "response_structure_sha256": "b" * 64,
                        },
                    ],
                }
            ],
        ),
    )

    probe = runtime.probe_settlement_views()

    assert probe == SettlementViewProbe(
        settlement_total_count=0,
        settlement_list_length=0,
        credit_total_count=137,
        credit_list_length=20,
        page_number=1,
        page_size=20,
        settlement_response_structure_sha256="a" * 64,
        credit_response_structure_sha256="b" * 64,
    )
