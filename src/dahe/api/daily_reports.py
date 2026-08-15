# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from datetime import date, time
from pathlib import Path
from typing import TypeVar

from fastapi import APIRouter, Depends
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
)

from dahe.adapters.sqlite.daily_reports import (
    DailyReportConflictError,
    DailyReportRecord,
    SqliteDailyReportRepository,
)
from dahe.api.errors import ApiError
from dahe.application.chengfeng.contract_subject import (
    SHANXI_GUIENBO,
    require_contract_subject_code,
)
from dahe.application.daily.report_workbook import (
    DailyReportSettings,
    validate_report_output_directory,
    validate_report_text,
)
from dahe.ports.jobs import IdempotencyConflictError, RecordVersionConflictError

T = TypeVar("T")


class SaveDailyReportSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shipping_mine: str = Field(min_length=1, max_length=200)
    coal_type: str = Field(min_length=1, max_length=200)
    unloading_place: str = Field(min_length=1, max_length=200)
    query_place_keyword: str = Field(min_length=1, max_length=200)
    output_directory: Path
    confirmed: bool
    expected_record_version: int = Field(ge=0)
    capture_start_time: time = time(14, 0)
    capture_end_mode: str = Field(
        default="system_current_time",
        pattern="^(system_current_time|fixed_time)$",
    )
    capture_fixed_end_day_offset: int = Field(default=1, ge=0, le=1)
    capture_fixed_end_time: time = time(14, 30)

    @field_validator(
        "shipping_mine",
        "coal_type",
        "unloading_place",
        "query_place_keyword",
    )
    @classmethod
    def reject_invalid_text_encoding(
        cls,
        value: str,
        info: ValidationInfo,
    ) -> str:
        validate_report_text(
            value,
            field=info.field_name or "report_text",
        )
        return value

    @field_validator("output_directory")
    @classmethod
    def require_absolute_output_directory(cls, value: Path) -> Path:
        validate_report_output_directory(value)
        return value


class CreateDailyReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    business_date: date
    contract_subject_code: str = SHANXI_GUIENBO
    expected_settings_version: int = Field(ge=1)


class VersionedDailyReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=1)
    contract_subject_code: str = SHANXI_GUIENBO


def _hash(operation: str, payload: BaseModel) -> str:
    encoded = json.dumps(
        {
            "operation": operation,
            "payload": payload.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _settings_payload(settings: DailyReportSettings) -> dict[str, object]:
    return {
        "coal_type": settings.coal_type,
        "capture_start_time": settings.capture_start_time.isoformat(),
        "capture_end_mode": settings.capture_end_mode,
        "capture_fixed_end_day_offset": settings.capture_fixed_end_day_offset,
        "capture_fixed_end_time": settings.capture_fixed_end_time.isoformat(),
        "capture_range_covers_report_window": (
            settings.report_window_is_fully_covered()
        ),
        "confirmed": settings.confirmed,
        "output_directory": str(settings.output_directory),
        "query_place_keyword": settings.query_place_keyword,
        "record_version": settings.record_version,
        "shipping_mine": settings.shipping_mine,
        "unloading_place": settings.unloading_place,
    }


def _report_payload(report: DailyReportRecord) -> dict[str, object]:
    return report.to_payload()


def build_daily_report_router(
    *,
    enabled: bool,
    repository: SqliteDailyReportRepository,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
    open_directory: Callable[[Path], None] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/daily")
    directory_opener = open_directory or (lambda path: os.startfile(str(path)))

    def require_enabled() -> None:
        if not enabled:
            raise ApiError(
                403,
                "daily_reports_disabled",
                "当前运行模式未启用正式装卸车报表。",
            )

    def handle(action: Callable[[], T]) -> T:
        try:
            return action()
        except RecordVersionConflictError as exc:
            raise ApiError(
                409,
                "record_version_conflict",
                "记录已更新，请刷新后重试。",
            ) from exc
        except IdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "该操作编号已用于其他请求，请刷新后重试。",
            ) from exc
        except DailyReportConflictError as exc:
            raise ApiError(409, "daily_report_conflict", str(exc)) from exc

    @router.get("/report-settings")
    def get_settings(_: None = Depends(require_session)) -> dict[str, object]:
        require_enabled()
        return _settings_payload(repository.get_settings())

    @router.put("/report-settings")
    def save_settings(
        payload: SaveDailyReportSettingsRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        require_enabled()
        result = handle(
            lambda: repository.save_settings(
                shipping_mine=payload.shipping_mine,
                coal_type=payload.coal_type,
                unloading_place=payload.unloading_place,
                query_place_keyword=payload.query_place_keyword,
                output_directory=payload.output_directory,
                confirmed=payload.confirmed,
                expected_record_version=payload.expected_record_version,
                capture_start_time=payload.capture_start_time,
                capture_end_mode=payload.capture_end_mode,
                capture_fixed_end_day_offset=payload.capture_fixed_end_day_offset,
                capture_fixed_end_time=payload.capture_fixed_end_time,
                idempotency_key=idempotency_key,
                request_hash=_hash("save_settings", payload),
            )
        )
        assert isinstance(result, DailyReportSettings)
        return _settings_payload(result)

    @router.post("/reports")
    def create_report(
        payload: CreateDailyReportRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(
            payload.contract_subject_code
        )
        result = handle(
            lambda: repository.create_report(
                business_date=payload.business_date,
                expected_settings_version=payload.expected_settings_version,
                idempotency_key=idempotency_key,
                request_hash=_hash("create_report", payload),
                contract_subject_code=subject_code,
            )
        )
        report, replayed = result
        return {"idempotent_replay": replayed, "report": _report_payload(report)}

    @router.get("/reports")
    def find_report(
        business_date: date,
        contract_subject_code: str = SHANXI_GUIENBO,
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(contract_subject_code)
        report = repository.find_report_for_business_date(
            business_date,
            contract_subject_code=subject_code,
        )
        return {"report": None if report is None else _report_payload(report)}

    @router.get("/reports/{report_id}")
    def get_report(
        report_id: str,
        contract_subject_code: str = SHANXI_GUIENBO,
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(contract_subject_code)
        result = handle(
            lambda: repository.get_report(
                report_id,
                contract_subject_code=subject_code,
            )
        )
        assert isinstance(result, DailyReportRecord)
        return _report_payload(result)

    @router.post("/reports/{report_id}/confirm")
    def confirm_report(
        report_id: str,
        payload: VersionedDailyReportRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(
            payload.contract_subject_code
        )
        result = handle(
            lambda: repository.confirm_report(
                report_id=report_id,
                expected_record_version=payload.expected_record_version,
                idempotency_key=idempotency_key,
                request_hash=_hash(f"confirm:{report_id}", payload),
                contract_subject_code=subject_code,
            )
        )
        report, replayed = result
        return {"idempotent_replay": replayed, "report": _report_payload(report)}

    @router.post("/reports/{report_id}/save-new-copy")
    def save_new_copy(
        report_id: str,
        payload: VersionedDailyReportRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(
            payload.contract_subject_code
        )
        result = handle(
            lambda: repository.save_new_copy(
                report_id=report_id,
                expected_record_version=payload.expected_record_version,
                idempotency_key=idempotency_key,
                request_hash=_hash(f"save_new_copy:{report_id}", payload),
                contract_subject_code=subject_code,
            )
        )
        report, replayed = result
        return {"idempotent_replay": replayed, "report": _report_payload(report)}

    @router.post("/reports/{report_id}/open-folder")
    def open_report_folder(
        report_id: str,
        payload: VersionedDailyReportRequest,
        _: str = Depends(require_write),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(
            payload.contract_subject_code
        )
        report = handle(
            lambda: repository.get_report(
                report_id,
                contract_subject_code=subject_code,
            )
        )
        assert isinstance(report, DailyReportRecord)
        if report.record_version != payload.expected_record_version:
            raise ApiError(409, "record_version_conflict", "报表已更新，请刷新后重试。")
        output_directory = report.output_directory.resolve()
        if not output_directory.is_dir():
            raise ApiError(409, "report_directory_missing", "报表所在文件夹已不存在。")
        try:
            directory_opener(output_directory)
        except OSError as exc:
            raise ApiError(500, "report_directory_open_failed", "无法打开报表所在文件夹。") from exc
        return {"opened": True}

    return router
