from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, update

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import PERFORMANCE_SETTINGS
from dahe.api.errors import ApiError
from dahe.ports.jobs import RecordVersionConflictError


@dataclass(frozen=True, slots=True)
class PerformanceSettingsRecord:
    preset: str = "responsive"
    detail_concurrency: int = 2
    image_concurrency: int = 3
    cpu_ocr_threads: int = 4
    gpu_idle_minutes: int = 10
    keep_gpu_ready: bool = False
    network_batch_size: int = 50
    record_version: int = 0


class SavePerformanceSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preset: str = Field(pattern="^(responsive|balanced|speed)$")
    detail_concurrency: int = Field(ge=1, le=4)
    image_concurrency: int = Field(ge=1, le=6)
    cpu_ocr_threads: int = Field(ge=1, le=max(1, min(8, (os.cpu_count() or 4) - 2)))
    gpu_idle_minutes: int = Field(ge=0, le=60)
    keep_gpu_ready: bool
    network_batch_size: int = Field(default=50)
    expected_record_version: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_idle_policy(self) -> Self:
        if not self.keep_gpu_ready and self.gpu_idle_minutes < 1:
            raise ValueError("GPU 空闲释放时间必须为 1 到 60 分钟")
        if self.network_batch_size not in {20, 50, 100}:
            raise ValueError("每批保存数量必须为 20、50 或 100")
        return self


class PerformanceSettingsRepository:
    def __init__(
        self,
        runtime: SqliteRuntime,
        *,
        on_change: Callable[[PerformanceSettingsRecord], None] | None = None,
    ) -> None:
        self._runtime = runtime
        self._on_change = on_change

    def get(self) -> PerformanceSettingsRecord:
        with self._runtime.engine.connect() as connection:
            row = connection.execute(
                select(PERFORMANCE_SETTINGS).where(
                    PERFORMANCE_SETTINGS.c.settings_id == "primary"
                )
            ).mappings().one_or_none()
        if row is None:
            return PerformanceSettingsRecord(
                cpu_ocr_threads=max(1, min(4, (os.cpu_count() or 4) - 2))
            )
        return PerformanceSettingsRecord(
            preset=str(row["preset"]),
            detail_concurrency=int(row["detail_concurrency"]),
            image_concurrency=int(row["image_concurrency"]),
            cpu_ocr_threads=int(row["cpu_ocr_threads"]),
            gpu_idle_minutes=int(row["gpu_idle_minutes"]),
            keep_gpu_ready=bool(row["keep_gpu_ready"]),
            network_batch_size=int(row["network_batch_size"]),
            record_version=int(row["record_version"]),
        )

    def save(self, payload: SavePerformanceSettingsRequest) -> PerformanceSettingsRecord:
        candidate = PerformanceSettingsRecord(
            preset=payload.preset,
            detail_concurrency=payload.detail_concurrency,
            image_concurrency=payload.image_concurrency,
            cpu_ocr_threads=payload.cpu_ocr_threads,
            gpu_idle_minutes=0 if payload.keep_gpu_ready else payload.gpu_idle_minutes,
            keep_gpu_ready=payload.keep_gpu_ready,
            network_batch_size=payload.network_batch_size,
            record_version=payload.expected_record_version + 1,
        )
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            existing = connection.execute(
                select(PERFORMANCE_SETTINGS).where(
                    PERFORMANCE_SETTINGS.c.settings_id == "primary"
                )
            ).mappings().one_or_none()
            actual = 0 if existing is None else int(existing["record_version"])
            if actual != payload.expected_record_version:
                raise RecordVersionConflictError("performance settings changed")
            values = {
                "preset": candidate.preset,
                "detail_concurrency": candidate.detail_concurrency,
                "image_concurrency": candidate.image_concurrency,
                "cpu_ocr_threads": candidate.cpu_ocr_threads,
                "gpu_idle_minutes": candidate.gpu_idle_minutes,
                "keep_gpu_ready": int(candidate.keep_gpu_ready),
                "network_batch_size": candidate.network_batch_size,
                "record_version": candidate.record_version,
                "updated_at": datetime.now(UTC).isoformat(),
            }
            if existing is None:
                connection.execute(
                    PERFORMANCE_SETTINGS.insert().values(
                        settings_id="primary", **values
                    )
                )
            else:
                connection.execute(
                    update(PERFORMANCE_SETTINGS)
                    .where(PERFORMANCE_SETTINGS.c.settings_id == "primary")
                    .values(**values)
                )
        if self._on_change is not None:
            self._on_change(candidate)
        return candidate


def _payload(record: PerformanceSettingsRecord) -> dict[str, object]:
    return {
        "preset": record.preset,
        "detail_concurrency": record.detail_concurrency,
        "image_concurrency": record.image_concurrency,
        "cpu_ocr_threads": record.cpu_ocr_threads,
        "gpu_idle_minutes": record.gpu_idle_minutes,
        "keep_gpu_ready": record.keep_gpu_ready,
        "network_batch_size": record.network_batch_size,
        "record_version": record.record_version,
    }


def build_performance_settings_router(
    *,
    repository: PerformanceSettingsRepository,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/settings/performance")

    @router.get("")
    def get_settings(_: None = Depends(require_session)) -> dict[str, object]:
        return _payload(repository.get())

    @router.put("")
    def save_settings(
        payload: SavePerformanceSettingsRequest,
        _: str = Depends(require_write),
    ) -> dict[str, object]:
        try:
            return _payload(repository.save(payload))
        except RecordVersionConflictError as exc:
            raise ApiError(409, "record_version_conflict", "设置已更新。请刷新后重试。") from exc

    return router
