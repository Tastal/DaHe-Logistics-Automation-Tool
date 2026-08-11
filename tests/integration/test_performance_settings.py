from __future__ import annotations

from pathlib import Path

import pytest

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.api.performance_settings import (
    PerformanceSettingsRecord,
    PerformanceSettingsRepository,
    SavePerformanceSettingsRequest,
)
from dahe.ports.jobs import RecordVersionConflictError

PROJECT_ROOT = Path(__file__).parents[2]


@pytest.mark.integration
def test_performance_settings_default_to_response_first_and_are_versioned(
    tmp_path: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="performance-settings",
    )
    changed: list[PerformanceSettingsRecord] = []
    try:
        repository = PerformanceSettingsRepository(runtime, on_change=changed.append)
        default = repository.get()
        assert (default.preset, default.detail_concurrency, default.image_concurrency) == (
            "responsive",
            2,
            3,
        )
        assert default.gpu_idle_minutes == 10
        assert default.network_batch_size == 50
        saved = repository.save(
            SavePerformanceSettingsRequest(
                preset="balanced",
                detail_concurrency=3,
                image_concurrency=4,
                cpu_ocr_threads=2,
                gpu_idle_minutes=30,
                keep_gpu_ready=False,
                expected_record_version=0,
            )
        )
        assert repository.get() == saved
        assert changed == [saved]
        with pytest.raises(RecordVersionConflictError):
            repository.save(
                SavePerformanceSettingsRequest(
                    preset="responsive",
                    detail_concurrency=2,
                    image_concurrency=3,
                    cpu_ocr_threads=2,
                    gpu_idle_minutes=10,
                    keep_gpu_ready=False,
                    expected_record_version=0,
                )
            )
    finally:
        runtime.close()
