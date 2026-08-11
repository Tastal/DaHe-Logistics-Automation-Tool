from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.runtime_inventory import (
    RuntimeInventoryError,
    parse_exact_lock,
    query_installed_inventory,
    validate_runtime_inventory,
)


def test_inventory_query_disables_bytecode_writes(tmp_path: Path) -> None:
    python = tmp_path / "python.exe"
    python.write_bytes(b"fake")
    observed: tuple[str, ...] | None = None

    def runner(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal observed
        del kwargs
        observed = command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps({"pip": "25.0.1"}),
            stderr="",
        )

    assert query_installed_inventory(python, runner=runner) == {"pip": "25.0.1"}
    assert observed is not None
    assert observed[1:3] == ("-I", "-B")


def test_exact_lock_and_inventory_must_match_without_stale_packages(
    tmp_path: Path,
) -> None:
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "paddlepaddle==3.3.1\npaddleocr==3.7.0\n",
        encoding="utf-8",
    )
    expected = parse_exact_lock(lock)
    installed = {
        "paddlepaddle": "3.3.1",
        "paddleocr": "3.7.0",
        "dahe-ocr-worker": "0.6.0",
        "pip": "25.0.1",
    }

    validate_runtime_inventory(
        runtime_kind=RuntimeKind.CPU,
        locked=expected,
        installed=installed,
        worker_version="0.6.0",
    )

    installed["stale-package"] = "1.0"
    with pytest.raises(RuntimeInventoryError, match="unexpected"):
        validate_runtime_inventory(
            runtime_kind=RuntimeKind.CPU,
            locked=expected,
            installed=installed,
            worker_version="0.6.0",
        )


def test_cpu_and_gpu_inventory_reject_cross_installed_paddle() -> None:
    with pytest.raises(RuntimeInventoryError, match="GPU"):
        validate_runtime_inventory(
            runtime_kind=RuntimeKind.CPU,
            locked={"paddlepaddle": "3.3.1"},
            installed={
                "paddlepaddle": "3.3.1",
                "paddlepaddle-gpu": "3.3.1",
                "dahe-ocr-worker": "0.6.0",
                "pip": "25.0.1",
            },
            worker_version="0.6.0",
        )

    with pytest.raises(RuntimeInventoryError, match="CPU"):
        validate_runtime_inventory(
            runtime_kind=RuntimeKind.GPU,
            locked={"paddlepaddle-gpu": "3.3.1"},
            installed={
                "paddlepaddle-gpu": "3.3.1",
                "paddlepaddle": "3.3.1",
                "dahe-ocr-worker": "0.6.0",
                "pip": "25.0.1",
            },
            worker_version="0.6.0",
        )
