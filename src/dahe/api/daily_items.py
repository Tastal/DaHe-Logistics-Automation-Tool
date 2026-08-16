from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Literal, cast

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator

from dahe.adapters.sqlite.daily_items import (
    EDITABLE_FIELDS,
    DailyItemConflictError,
    DailyItemView,
    SqliteDailyItemRepository,
)
from dahe.api.errors import ApiError
from dahe.application.chengfeng.contract_subject import (
    SHANXI_GUIENBO,
    require_contract_subject_code,
)
from dahe.domain.daily.calendar import SHANGHAI
from dahe.domain.daily.models import DailyObservationFields
from dahe.ports.jobs import IdempotencyConflictError, RecordVersionConflictError


class DailyItemChanges(BaseModel):
    model_config = ConfigDict(extra="forbid")

    loading_net_tonnes: str | None = None
    loading_time: str | None = None
    unloading_net_tonnes: str | None = None
    unloading_time: str | None = None

    @field_validator("loading_net_tonnes", "unloading_net_tonnes")
    @classmethod
    def validate_weight(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = Decimal(value)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("重量必须是有效数字") from exc
        if not parsed.is_finite() or parsed < 0:
            raise ValueError("重量必须是非负有限数字")
        exponent = parsed.as_tuple().exponent
        if not isinstance(exponent, int) or exponent < -2:
            raise ValueError("重量最多保留两位小数")
        return format(parsed.quantize(Decimal("0.01")), "f")

    @field_validator("loading_time", "unloading_time")
    @classmethod
    def validate_time(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("时间格式无效") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("时间必须包含时区")
        return parsed.astimezone(SHANGHAI).isoformat()


class SaveDailyItemRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    business_date: date
    contract_subject_code: str = SHANXI_GUIENBO
    expected_record_version: int = Field(ge=1)
    changes: DailyItemChanges


def _fields_payload(fields: DailyObservationFields) -> dict[str, object]:
    payload = fields.to_payload()
    return {field: payload[field] for field in sorted(EDITABLE_FIELDS)}


def _date_value(value: object) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value)).date().isoformat()
    except ValueError:
        return None


def _item_payload(item: DailyItemView, *, business_date: date) -> dict[str, object]:
    machine = _fields_payload(item.machine.fields)
    effective = _fields_payload(item.effective_fields)
    resolved = {
        field: effective[field] is not None or item.field_sources[field] == "manual"
        for field in sorted(EDITABLE_FIELDS)
    }
    issues = {
        field: {
            "has_issue": not resolved[field],
            "message": "该字段尚未确认" if not resolved[field] else None,
        }
        for field in sorted(EDITABLE_FIELDS)
    }
    review_state = "reviewed" if all(resolved.values()) else "needs_review"
    loading_date = (
        _date_value(effective["loading_time"])
        or _date_value(machine["loading_time"])
        or business_date.isoformat()
    )
    unloading_date = (
        _date_value(effective["unloading_time"])
        or _date_value(effective["loading_time"])
        or _date_value(machine["loading_time"])
        or business_date.isoformat()
    )
    return {
        "platform_waybill_id": item.machine.platform_waybill_id,
        "waybill_number": item.machine.waybill_number,
        "vehicle_number": item.effective_fields.vehicle_number,
        "loading_ticket": (
            None
            if item.machine.loading_ticket_sha256 is None
            else {
                "sha256": item.machine.loading_ticket_sha256,
                "url": f"/api/v1/evidence/{item.machine.loading_ticket_sha256}",
            }
        ),
        "unloading_ticket": (
            None
            if item.machine.unloading_ticket_sha256 is None
            else {
                "sha256": item.machine.unloading_ticket_sha256,
                "url": f"/api/v1/evidence/{item.machine.unloading_ticket_sha256}",
            }
        ),
        "machine_fields": machine,
        "effective_fields": effective,
        "field_sources": item.field_sources,
        "field_issues": issues,
        "review_state": review_state,
        "materialized_at": item.materialized_at,
        "time_prefill": {
            "loading_date": loading_date,
            "unloading_date": unloading_date,
        },
        "record_version": item.record_version,
        "updated_at": item.updated_at,
    }


def _counts_payload(
    repository: SqliteDailyItemRepository,
    *,
    business_date: date,
    contract_subject_code: str = "shanxi_guienbo",
) -> dict[str, int]:
    items = repository.list_items(
        business_date,
        contract_subject_code=contract_subject_code,
    )
    reviewed = sum(
        _item_payload(item, business_date=business_date)["review_state"] == "reviewed"
        for item in items
    )
    return {
        "all": len(items),
        "needs_review": len(items) - reviewed,
        "reviewed": reviewed,
        "complete": reviewed,
    }


def build_daily_item_router(
    *,
    enabled: bool,
    repository: SqliteDailyItemRepository,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/daily")

    def require_enabled() -> None:
        if not enabled:
            raise ApiError(403, "daily_items_disabled", "当前运行模式未启用装卸车明细。")

    @router.get("/items")
    def list_items(
        business_date: date,
        contract_subject_code: str = "shanxi_guienbo",
        view: Literal["all", "reviewed", "needs_review", "complete"] = "all",
        _: None = Depends(require_session),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(contract_subject_code)
        items = repository.list_items(
            business_date,
            contract_subject_code=subject_code,
        )
        source = repository.latest_source_context(
            business_date,
            contract_subject_code=subject_code,
        )
        payloads = tuple(_item_payload(item, business_date=business_date) for item in items)
        selected_view = "reviewed" if view == "complete" else view
        selected = (
            payloads
            if selected_view == "all"
            else tuple(item for item in payloads if item["review_state"] == selected_view)
        )
        return {
            "business_date": business_date.isoformat(),
            "items": selected,
            "contract_subject_code": subject_code,
            "counts": _counts_payload(
                repository,
                business_date=business_date,
                contract_subject_code=subject_code,
            ),
            "source_job_id": None if source is None else source.source_job_id,
            "source_record_version": 0 if source is None else source.source_record_version,
            "capture_mode": "batch_v1" if source is None else source.capture_mode,
            "visible_prefix_count": len(payloads),
            "online_capture_complete": (
                False if source is None else source.online_capture_complete
            ),
            "active_job": None,
            "progress": None,
        }

    @router.post("/items/{platform_waybill_id}/revisions")
    def save_revision(
        platform_waybill_id: str,
        payload: SaveDailyItemRevisionRequest,
        idempotency_key: str = Depends(require_write),
    ) -> dict[str, object]:
        require_enabled()
        subject_code = require_contract_subject_code(
            payload.contract_subject_code
        )
        try:
            current = repository.get_item_for_business_date(
                platform_waybill_id,
                business_date=payload.business_date,
                contract_subject_code=subject_code,
            )
            actual_business_date = repository.business_date_for(current.machine)
        except DailyItemConflictError as exc:
            try:
                historical = repository.get_item(
                    platform_waybill_id,
                    contract_subject_code=subject_code,
                )
                historical_business_date = repository.business_date_for(
                    historical.machine
                )
            except DailyItemConflictError:
                raise ApiError(409, "daily_item_conflict", str(exc)) from exc
            if historical_business_date != payload.business_date:
                raise ApiError(
                    409,
                    "daily_item_business_date_conflict",
                    "记录不属于当前业务日。请刷新后重试。",
                ) from exc
            raise ApiError(409, "daily_item_conflict", str(exc)) from exc
        if actual_business_date != payload.business_date:
            raise ApiError(
                409,
                "daily_item_business_date_conflict",
                "记录不属于当前业务日。请刷新后重试。",
            )
        changes = {
            field: getattr(payload.changes, field)
            for field in payload.changes.model_fields_set
        }
        current_payload = _item_payload(current, business_date=actual_business_date)
        field_issues = cast(
            dict[str, dict[str, object]],
            current_payload["field_issues"],
        )
        unresolved_fields = {
            field
            for field, issue in field_issues.items()
            if issue["has_issue"]
        }
        if not unresolved_fields.issubset(changes):
            raise ApiError(
                422,
                "daily_item_review_fields_incomplete",
                "请一次确认当前记录的全部待核对字段。",
            )
        if "unloading_time" in changes and changes["unloading_time"] is not None:
            parsed = datetime.fromisoformat(str(changes["unloading_time"]))
            changes["unloading_time"] = parsed.replace(microsecond=0).isoformat()
        if "loading_time" in changes and changes["loading_time"] is not None:
            parsed = datetime.fromisoformat(str(changes["loading_time"]))
            changes["loading_time"] = parsed.replace(microsecond=0).isoformat()
        try:
            item, replayed = repository.append_revision(
                platform_waybill_id=platform_waybill_id,
                business_date=payload.business_date,
                expected_record_version=payload.expected_record_version,
                changes=changes,
                idempotency_key=idempotency_key,
                contract_subject_code=subject_code,
            )
        except RecordVersionConflictError as exc:
            raise ApiError(409, "record_version_conflict", "记录已更新。请刷新后重试。") from exc
        except IdempotencyConflictError as exc:
            raise ApiError(409, "idempotency_key_reused", "该操作编号已用于其他请求。") from exc
        except DailyItemConflictError as exc:
            raise ApiError(409, "daily_item_conflict", str(exc)) from exc
        business_date = repository.business_date_for(item.machine)
        return {
            "idempotent_replay": replayed,
            "business_date": business_date.isoformat(),
            "contract_subject_code": subject_code,
            "item": _item_payload(item, business_date=business_date),
            "counts": _counts_payload(
                repository,
                business_date=business_date,
                contract_subject_code=subject_code,
            ),
        }

    return router
