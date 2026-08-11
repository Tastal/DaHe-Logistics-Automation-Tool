from __future__ import annotations

from dataclasses import dataclass

import pytest

from dahe.adapters.sqlite.loop3_repository import SqliteLoop3Store
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageExecution,
    OcrImageWork,
    OcrRuntimeIdentity,
)


@dataclass
class _CloseRecorder:
    name: str
    calls: list[str]
    failure: BaseException | None = None

    def close(self) -> None:
        self.calls.append(self.name)
        if self.failure is not None:
            raise self.failure


class _Gateway(_CloseRecorder):
    def __init__(
        self,
        *,
        runtime_kind: str,
        calls: list[str],
        failure: BaseException | None = None,
    ) -> None:
        super().__init__(runtime_kind, calls, failure)
        self._identity = OcrRuntimeIdentity(
            runtime_kind=runtime_kind,  # type: ignore[arg-type]
            profile_id=f"{runtime_kind}-shutdown-test",
            runtime_fingerprint=(
                "1" * 64 if runtime_kind == "gpu" else "2" * 64
            ),
        )

    @property
    def identity(self) -> OcrRuntimeIdentity:
        return self._identity

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        raise AssertionError(
            f"shutdown test must not execute OCR: {image} {pipeline_fingerprint}"
        )


def test_loop3_close_attempts_every_execution_backend_after_failure() -> None:
    calls: list[str] = []
    store = object.__new__(SqliteLoop3Store)
    store._ocr_execution_backend = _CloseRecorder(  # type: ignore[attr-defined]
        "ocr",
        calls,
        RuntimeError("injected OCR close failure"),
    )
    store._daily_execution_backend = _CloseRecorder(  # type: ignore[attr-defined]
        "daily",
        calls,
    )
    store._settlement_capture_execution_backend = _CloseRecorder(  # type: ignore[attr-defined]
        "settlement",
        calls,
    )

    with pytest.raises(RuntimeError, match="injected OCR close failure"):
        store.close()

    assert calls == ["ocr", "daily", "settlement"]


def test_ocr_backend_close_attempts_every_gateway_and_is_repeat_safe() -> None:
    calls: list[str] = []
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={
            "gpu": _Gateway(
                runtime_kind="gpu",
                calls=calls,
                failure=RuntimeError("injected GPU close failure"),
            ),
            "cpu": _Gateway(runtime_kind="cpu", calls=calls),
        },
    )

    with pytest.raises(RuntimeError, match="injected GPU close failure"):
        backend.close()

    backend.close()

    assert calls == ["gpu", "cpu"]
