from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import dahe.api.app as app_module
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.jobs.ocr_execution import OcrRuntimeIdentity


class _FailingFactoryOcrBackend:
    def __init__(self, calls: list[str]) -> None:
        self._calls = calls
        self._identity = OcrRuntimeIdentity(
            runtime_kind="cpu",
            profile_id="construction-cleanup",
            runtime_fingerprint="7" * 64,
        )

    def has_runtime(self, runtime_kind: str) -> bool:
        return runtime_kind == "cpu"

    def identity_for(self, runtime_kind: str) -> OcrRuntimeIdentity:
        assert runtime_kind == "cpu"
        return self._identity

    def close(self) -> None:
        self._calls.append("ocr")
        raise RuntimeError("injected OCR construction cleanup failure")


class _CloseRecorder:
    def __init__(self, name: str, calls: list[str]) -> None:
        self._name = name
        self._calls = calls

    def close(self) -> None:
        self._calls.append(self._name)


def test_failed_app_construction_attempts_all_factory_cleanup_and_preserves_cause(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    ocr_backend = _FailingFactoryOcrBackend(calls)
    daily_backend = _CloseRecorder("daily", calls)
    settlement_backend = _CloseRecorder("settlement", calls)
    browser_runtime = _CloseRecorder("browser", calls)

    settlement_manifest = SimpleNamespace(canonical_sha256="1" * 64)
    settlement_contract = SimpleNamespace(
        manifest=settlement_manifest,
        contract_file_sha256="2" * 64,
        selection_sha256="3" * 64,
    )
    daily_contract = SimpleNamespace(
        manifest=SimpleNamespace(canonical_sha256="4" * 64),
        selection_sha256="5" * 64,
    )
    identity_authority = SimpleNamespace(
        salt=b"shutdown-resilience-test",
        namespace="shutdown-resilience",
        context_sha256="6" * 64,
    )

    (tmp_path / "platform-read-contract").mkdir()
    (tmp_path / "platform-read-contract" / "active-candidate.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (tmp_path / "daily-platform-read-contract").mkdir()
    (
        tmp_path
        / "daily-platform-read-contract"
        / "active-candidate.json"
    ).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        app_module,
        "load_selected_live_read_contract",
        lambda _data_root: settlement_contract,
    )
    monkeypatch.setattr(
        app_module,
        "load_selected_daily_read_contract",
        lambda _data_root: daily_contract,
    )
    monkeypatch.setattr(
        app_module,
        "load_or_create_loop9_identity_authority",
        lambda _data_root: identity_authority,
    )
    monkeypatch.setattr(
        app_module,
        "IsolatedBrowserRuntime",
        lambda **_kwargs: browser_runtime,
    )
    monkeypatch.setattr(
        app_module,
        "LiveConnectorRuntime",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        app_module,
        "VerifiedChengfengConnector",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        app_module,
        "SettlementCaptureLiveStageExecutor",
        lambda **_kwargs: SimpleNamespace(
            close_terminal_job=lambda _job_id: None
        ),
    )
    monkeypatch.setattr(
        app_module,
        "DailyLiveStageExecutor",
        lambda **_kwargs: SimpleNamespace(
            close_terminal_job=lambda _job_id: None
        ),
    )
    monkeypatch.setattr(
        app_module,
        "AsyncSettlementCaptureExecutionBackend",
        lambda **_kwargs: settlement_backend,
    )
    monkeypatch.setattr(
        app_module,
        "AsyncDailyExecutionBackend",
        lambda **_kwargs: daily_backend,
    )

    def fail_repository_construction(*_args: object, **_kwargs: object) -> Any:
        raise ValueError("injected repository construction failure")

    monkeypatch.setattr(
        app_module,
        "SqliteJobRepository",
        fail_repository_construction,
    )
    original_runtime_close = SqliteRuntime.close

    def observe_runtime_close(runtime: SqliteRuntime) -> None:
        calls.append("runtime")
        original_runtime_close(runtime)

    monkeypatch.setattr(SqliteRuntime, "close", observe_runtime_close)

    with pytest.raises(
        ValueError,
        match="injected repository construction failure",
    ):
        app_module.create_app(
            data_root=tmp_path,
            project_root=project_root,
            instance_id="construction-cleanup-resilience",
            auto_run_jobs=False,
            stage_delay_seconds=0,
            ocr_execution_backend_factory=lambda: ocr_backend,  # type: ignore[arg-type]
            enable_chengfeng_shadow=True,
            platform_build_sha256="a" * 64,
            platform_contract_validator=object(),  # type: ignore[arg-type]
        )

    assert calls == [
        "ocr",
        "daily",
        "settlement",
        "browser",
        "runtime",
    ]
