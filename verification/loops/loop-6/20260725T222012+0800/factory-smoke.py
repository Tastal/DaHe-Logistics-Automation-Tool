from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.config.schema import (
    AppConfig,
    OcrPreference,
    OcrSettings,
    RuntimeProfile,
)


def _owned_worker_count() -> int:
    command = (
        "$workers = Get-CimInstance Win32_Process | Where-Object { "
        "$_.Name -like 'python*.exe' -and $_.CommandLine -and "
        "$_.CommandLine -match '(?i)-m\\s+dahe_ocr_worker' }; "
        "Write-Output @($workers).Count"
    )
    completed = subprocess.run(
        (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    return int(completed.stdout.strip())


def _wait_for_worker_cleanup() -> int:
    for _ in range(20):
        remaining = _owned_worker_count()
        if remaining == 0:
            return 0
        time.sleep(0.1)
    return _owned_worker_count()


def main() -> None:
    repository_root = Path.cwd().resolve()
    results: dict[str, object] = {}
    with TemporaryDirectory(prefix="dahe-loop6-factory-smoke-") as temporary:
        data_root = Path(temporary).resolve()
        auto = build_ocr_execution_backend(
            config=AppConfig(
                runtime_profile=RuntimeProfile.TEST,
                data_root=data_root,
                ocr=OcrSettings(
                    preference=OcrPreference.AUTO,
                    allow_cpu_fallback=True,
                ),
            ),
            repository_root=repository_root,
        )
        try:
            results["auto"] = {
                "primary": auto.primary_runtime_kind,
                "has_cpu": auto.has_runtime("cpu"),
                "has_gpu": auto.has_runtime("gpu"),
                "cpu_profile_id": (
                    auto.identity_for("cpu").profile_id
                    if auto.has_runtime("cpu")
                    else None
                ),
                "gpu_profile_id": (
                    auto.identity_for("gpu").profile_id
                    if auto.has_runtime("gpu")
                    else None
                ),
            }
        finally:
            auto.close()
        results["workers_after_auto_close"] = _wait_for_worker_cleanup()

        cpu_only = build_ocr_execution_backend(
            config=AppConfig(
                runtime_profile=RuntimeProfile.TEST,
                data_root=data_root,
                ocr=OcrSettings(
                    preference=OcrPreference.CPU_ONLY,
                    allow_cpu_fallback=False,
                ),
            ),
            repository_root=repository_root,
        )
        try:
            results["cpu_only"] = {
                "primary": cpu_only.primary_runtime_kind,
                "has_cpu": cpu_only.has_runtime("cpu"),
                "has_gpu": cpu_only.has_runtime("gpu"),
            }
        finally:
            cpu_only.close()
        results["workers_after_cpu_only_close"] = _wait_for_worker_cleanup()

    expected = {
        "auto": {
            "primary": "gpu",
            "has_cpu": True,
            "has_gpu": True,
            "cpu_profile_id": "cpu-portable-fp32-b1-w1",
            "gpu_profile_id": "gpu-c7fe21693329-fp16-b6-w1",
        },
        "workers_after_auto_close": 0,
        "cpu_only": {
            "primary": "cpu",
            "has_cpu": True,
            "has_gpu": False,
        },
        "workers_after_cpu_only_close": 0,
    }
    if results != expected:
        raise SystemExit(
            json.dumps(
                {"expected": expected, "observed": results},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    print(json.dumps(results, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
