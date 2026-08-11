from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Annotated, Literal
from urllib.parse import quote, unquote

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from starlette.responses import JSONResponse, Response

from dahe import __version__
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
    EvidenceIntegrityError,
)
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateAuthorizationError,
    TemplateEvaluationGateError,
    TemplateEvaluationRecord,
    TemplateFamilyConflictError,
    TemplateFamilyCurrent,
    TemplateFamilySummary,
    TemplateIdempotencyConflictError,
    TemplateLifecycleTransitionError,
    TemplateNotFoundError,
    TemplatePersistenceError,
    TemplateRecordVersionConflictError,
    TemplateReferenceUploadError,
)
from dahe.api.errors import ApiError
from dahe.application.template_studio.reference_images import (
    MAX_REFERENCE_BYTES,
    TemplateReferenceImageError,
    build_template_reference_mask,
    normalize_template_reference_image,
    template_reference_alignment_fingerprint,
)
from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TicketField,
)

DEVELOPER_COOKIE = "dahe_template_maintenance"
MAINTENANCE_SECONDS = 15 * 60
TEMPORARY_ANCHOR_TEXT = "请替换为票面固定文字"


class NormalizedRectPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    x: Decimal = Field(ge=0, le=1)
    y: Decimal = Field(ge=0, le=1)
    width: Decimal = Field(gt=0, le=1)
    height: Decimal = Field(gt=0, le=1)

    def to_domain(self) -> NormalizedRect:
        return NormalizedRect(
            x=self.x,
            y=self.y,
            width=self.width,
            height=self.height,
        )


class TemplateAnchorPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anchor_id: str = Field(min_length=1, max_length=100)
    expected_text: str = Field(min_length=1, max_length=512)
    match_kind: AnchorMatchKind = AnchorMatchKind.LITERAL
    box: NormalizedRectPayload
    required: bool
    weight: Decimal = Field(gt=0)
    max_edit_distance: Decimal = Field(ge=0, le=1)
    loading_evidence: Decimal = Field(ge=-1, le=1)
    unloading_evidence: Decimal = Field(ge=-1, le=1)

    def to_domain(self) -> TemplateAnchor:
        return TemplateAnchor(
            anchor_id=self.anchor_id,
            expected_text=self.expected_text,
            match_kind=self.match_kind,
            box=self.box.to_domain(),
            required=self.required,
            weight=self.weight,
            max_edit_distance=self.max_edit_distance,
            loading_evidence=self.loading_evidence,
            unloading_evidence=self.unloading_evidence,
        )


class RecognitionRegionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region_id: str = Field(min_length=1, max_length=100)
    field: TicketField
    box: NormalizedRectPayload
    relative_to_anchor_id: str | None = Field(default=None, max_length=100)
    unit: str | None = Field(default=None, max_length=20)
    format_pattern: str = Field(min_length=1, max_length=512)
    required: bool
    layout_scope: str = Field(min_length=1, max_length=100)

    def to_domain(self) -> RecognitionRegion:
        return RecognitionRegion(
            region_id=self.region_id,
            field=self.field,
            box=self.box.to_domain(),
            relative_to_anchor_id=self.relative_to_anchor_id,
            unit=self.unit,
            format_pattern=self.format_pattern,
            required=self.required,
            layout_scope=self.layout_scope,
        )


class TemplateDefinitionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    role: Literal["loading", "unloading"]
    anchors: tuple[TemplateAnchorPayload, ...] = Field(min_length=1, max_length=100)
    regions: tuple[RecognitionRegionPayload, ...] = Field(max_length=100)

    def to_domain(self) -> TemplateDefinition:
        return TemplateDefinition(
            family_id=self.family_id,
            name=self.name,
            role=TicketRole(self.role),
            anchors=tuple(anchor.to_domain() for anchor in self.anchors),
            regions=tuple(region.to_domain() for region in self.regions),
        )


class CreateTemplatePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    definition: TemplateDefinitionPayload
    reference_image_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference_mask_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    alignment_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkbenchAnchorPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anchor_id: str = Field(min_length=1, max_length=100)
    expected_text: str = Field(min_length=1, max_length=512)
    match_mode: Literal["exact", "contains", "pattern"]
    required: bool
    role_evidence: Literal["loading", "unloading", "position_only"]
    importance: Literal["primary", "supporting"]
    bounds: NormalizedRectPayload


class WorkbenchRegionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region_id: str = Field(min_length=1, max_length=100)
    field: Literal[
        "ordinary_net_weight",
        "factory_net_weight",
        "gross_weight",
        "tare_weight",
        "loading_weigh_time",
        "unloading_tare_time",
        "print_time",
    ]
    value_type: Literal["weight", "time", "text"]
    unit: Literal["ton", "kilogram", "printed"]
    required: bool
    anchor_id: str = Field(min_length=1, max_length=100)
    bounds: NormalizedRectPayload


class WorkbenchDraftPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anchors: tuple[WorkbenchAnchorPayload, ...] = Field(min_length=1, max_length=100)
    regions: tuple[WorkbenchRegionPayload, ...] = Field(max_length=100)


class SaveWorkbenchDraftPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=1)
    draft: WorkbenchDraftPayload


class CreateWorkbenchTemplatePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    staged_reference_id: str = Field(min_length=1, max_length=32)
    expected_record_version: int = Field(ge=1)
    family_name: str = Field(min_length=1, max_length=200)
    role: Literal["loading", "unloading"]
    draft: WorkbenchDraftPayload


class AbandonReferenceUploadPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=1)


class LifecyclePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    expected_record_version: int = Field(ge=1)
    evaluation_id: str = Field(min_length=1, max_length=100)


class RollbackPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_version_id: str = Field(min_length=1, max_length=32)
    expected_record_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=200)


class DeveloperRevalidationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    access_code: str = Field(min_length=1, max_length=200)
    action: Literal[
        "template.maintenance_session",
        "template.publish_shadow",
        "template.rollback_shadow",
    ]
    resource_id: str = Field(min_length=1, max_length=200)


@dataclass(slots=True)
class _SessionGrant:
    expires_at: float


@dataclass(slots=True)
class _ActionGrant:
    action: str
    resource_id: str
    expires_at: float
    idempotency_key: str | None = None


class DeveloperAuthorizationManager:
    """Hold short-lived local grants without persisting the access code."""

    def __init__(self, access_code: str | None) -> None:
        if access_code is not None and not access_code.strip():
            raise ValueError("developer access code cannot be blank")
        self._access_code = access_code
        self._sessions: dict[str, _SessionGrant] = {}
        self._actions: dict[str, _ActionGrant] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _identity(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _check_code(self, supplied: str) -> None:
        if self._access_code is None:
            raise ApiError(
                403,
                "developer_access_not_configured",
                "当前启动方式未启用模板维护",
            )
        if not secrets.compare_digest(supplied, self._access_code):
            raise ApiError(
                403,
                "developer_revalidation_failed",
                "维护验证码不正确",
            )

    def revalidate(
        self,
        *,
        access_code: str,
        action: str,
        resource_id: str,
    ) -> tuple[str, str | None]:
        self._check_code(access_code)
        now = time.monotonic()
        session_token = secrets.token_urlsafe(32)
        session_identity = self._identity(session_token)
        action_token: str | None = None
        with self._lock:
            self._sessions[session_identity] = _SessionGrant(
                expires_at=now + MAINTENANCE_SECONDS
            )
            if action != "template.maintenance_session":
                action_token = secrets.token_urlsafe(32)
                self._actions[self._identity(action_token)] = _ActionGrant(
                    action=action,
                    resource_id=resource_id,
                    expires_at=now + MAINTENANCE_SECONDS,
                )
            self._discard_expired(now)
        return session_token, action_token

    def _discard_expired(self, now: float) -> None:
        self._sessions = {
            identity: grant
            for identity, grant in self._sessions.items()
            if grant.expires_at >= now
        }
        self._actions = {
            identity: grant
            for identity, grant in self._actions.items()
            if grant.expires_at >= now
        }

    def session_identity(self, request: Request) -> str:
        token = request.cookies.get(DEVELOPER_COOKIE)
        if token is None:
            raise ApiError(
                403,
                "developer_revalidation_required",
                "请先进入模板维护模式",
            )
        identity = self._identity(token)
        now = time.monotonic()
        with self._lock:
            self._discard_expired(now)
            if identity not in self._sessions:
                raise ApiError(
                    403,
                    "developer_revalidation_required",
                    "模板维护授权已过期。请重新验证",
                )
        return identity

    def is_authorized(self, request: Request) -> bool:
        try:
            self.session_identity(request)
        except ApiError:
            return False
        return True

    def action_identity(
        self,
        *,
        token: str | None,
        action: str,
        resource_id: str,
        idempotency_key: str,
    ) -> str:
        if token is None:
            raise ApiError(
                403,
                "developer_action_revalidation_required",
                "该操作需要重新输入维护验证码",
            )
        identity = self._identity(token)
        now = time.monotonic()
        with self._lock:
            self._discard_expired(now)
            grant = self._actions.get(identity)
            if (
                grant is None
                or grant.action != action
                or grant.resource_id != resource_id
                or (
                    grant.idempotency_key is not None
                    and grant.idempotency_key != idempotency_key
                )
            ):
                raise ApiError(
                    403,
                    "developer_action_revalidation_required",
                    "维护授权与当前操作不匹配。请重新验证",
                )
            grant.idempotency_key = idempotency_key
        return identity


def _lifecycle_label(lifecycle: TemplateLifecycle) -> str:
    return {
        TemplateLifecycle.DRAFT: "草稿",
        TemplateLifecycle.DEVELOPMENT_TESTED: "开发样本已通过",
        TemplateLifecycle.SHADOW: "影子测试中",
        TemplateLifecycle.ACTIVE: "不可用",
        TemplateLifecycle.RETIRED: "不可用",
    }[lifecycle]


def _purpose_label(role: TicketRole) -> str:
    return "装货磅单" if role is TicketRole.LOADING else "卸货磅单"


def _action(
    label: str,
    record_version: int,
    *,
    visible: bool,
    enabled: bool,
    reason: str | None = None,
    evaluation_id: str | None = None,
) -> dict[str, object]:
    return {
        "visible": visible,
        "enabled": enabled,
        "reason": reason,
        "label": label,
        "expected_record_version": record_version,
        "evaluation_id": evaluation_id,
    }


def _actions(
    current: TemplateFamilyCurrent,
    evaluation: TemplateEvaluationRecord | None,
    *,
    rollback_target_count: int = 0,
    shadow_pointer_record_version: int | None = None,
) -> dict[str, dict[str, object]]:
    lifecycle = current.version.lifecycle
    version = current.version.record_version
    evaluation_passed = evaluation is not None and evaluation.gate_passed
    return {
        "save_draft": _action(
            (
                "保存草稿"
                if lifecycle is TemplateLifecycle.DRAFT
                else "以此版本另存为新草稿"
            ),
            version,
            visible=True,
            enabled=True,
        ),
        "run_development_check": _action(
            "确认开发样本检查",
            version,
            visible=lifecycle is TemplateLifecycle.DRAFT,
            enabled=(
                lifecycle is TemplateLifecycle.DRAFT
                and evaluation_passed
            ),
            reason=(
                None
                if evaluation_passed
                else (
                    "开发样本检查未通过"
                    if evaluation is not None
                    else "尚未完成开发样本检查"
                )
            ),
            evaluation_id=(
                None if evaluation is None else evaluation.evaluation_id
            ),
        ),
        "start_shadow": _action(
            "开始影子测试",
            version,
            visible=lifecycle is TemplateLifecycle.DEVELOPMENT_TESTED,
            enabled=(
                lifecycle is TemplateLifecycle.DEVELOPMENT_TESTED
                and evaluation_passed
            ),
            reason=(
                None
                if evaluation_passed
                else (
                    "开发样本检查已失效"
                    if lifecycle is TemplateLifecycle.DEVELOPMENT_TESTED
                    else None
                )
            ),
            evaluation_id=(
                None if evaluation is None else evaluation.evaluation_id
            ),
        ),
        "restore_shadow": _action(
            "恢复上一影子版本",
            shadow_pointer_record_version or version,
            visible=shadow_pointer_record_version is not None,
            enabled=(
                shadow_pointer_record_version is not None
                and rollback_target_count > 0
            ),
            reason=(
                None
                if rollback_target_count > 0
                else "没有可恢复的较早影子版本"
            ),
        ),
    }


def _family_summary(summary: TemplateFamilySummary) -> dict[str, object]:
    lifecycle = _lifecycle_label(summary.lifecycle)
    return {
        "family_id": summary.family_id,
        "name": summary.name,
        "purpose_label": _purpose_label(summary.role),
        "current_version_label": f"{lifecycle} {summary.latest_version_number}",
        "lifecycle_label": lifecycle,
    }


def _field_wire(field: TicketField) -> str:
    return {
        TicketField.ORDINARY_NET: "ordinary_net_weight",
        TicketField.FACTORY_NET: "factory_net_weight",
        TicketField.GROSS: "gross_weight",
        TicketField.TARE: "tare_weight",
        TicketField.LOADING_WEIGH_TIME: "loading_weigh_time",
        TicketField.UNLOADING_TARE_TIME: "unloading_tare_time",
        TicketField.PRINT_TIME: "print_time",
    }[field]


def _field_label(field: TicketField) -> str:
    return {
        TicketField.ORDINARY_NET: "普通净重",
        TicketField.FACTORY_NET: "工厂净重",
        TicketField.GROSS: "毛重",
        TicketField.TARE: "皮重",
        TicketField.LOADING_WEIGH_TIME: "装货过磅时间",
        TicketField.UNLOADING_TARE_TIME: "卸货皮重时间",
        TicketField.PRINT_TIME: "打印时间",
    }[field]


def _rect_wire(rectangle: NormalizedRect) -> dict[str, float]:
    return {
        "x": float(rectangle.x),
        "y": float(rectangle.y),
        "width": float(rectangle.width),
        "height": float(rectangle.height),
    }


_REPORT_METRICS = (
    ("geometry_match_rate", "版式位置匹配"),
    ("anchor_pass_rate", "固定内容通过"),
    ("field_reliability", "字段读取可靠"),
    ("direct_completion_rate", "模板直接完成"),
    ("fallback_rate", "需要整页处理"),
    ("wrong_template_rate", "错模板"),
    ("role_conflict_rate", "票据角色冲突"),
    ("unknown_layout_rate", "未知版式"),
    ("p50_elapsed_ms", "一半图片耗时"),
    ("p95_elapsed_ms", "较慢图片耗时"),
)


def _metric_value_label(metric_id: str, measurement: Mapping[str, object]) -> str:
    if measurement.get("status") != "measured":
        return "尚未测量"
    value = measurement.get("value")
    if metric_id.endswith("_rate") and isinstance(value, str):
        try:
            return f"{Decimal(value) * Decimal(100):.1f}%"
        except ArithmeticError:
            return "数据无效"
    if metric_id.endswith("_elapsed_ms") and isinstance(value, str):
        try:
            return f"{Decimal(value):.2f} 毫秒"
        except ArithmeticError:
            return "数据无效"
    return str(value)


def _check_report(
    evaluation: TemplateEvaluationRecord | None,
) -> dict[str, object] | None:
    if evaluation is None:
        return None
    raw_metrics = evaluation.metrics.get("development_metrics")
    if not isinstance(raw_metrics, Mapping):
        return None
    metrics: list[dict[str, str]] = []
    for metric_id, label in _REPORT_METRICS:
        measurement = raw_metrics.get(metric_id)
        if not isinstance(measurement, Mapping):
            continue
        metrics.append(
            {
                "metric_id": metric_id,
                "label": label,
                "value_label": _metric_value_label(metric_id, measurement),
            }
        )
    raw_scope = raw_metrics.get("development_sample_scope")
    scope_value = (
        raw_scope.get("value")
        if isinstance(raw_scope, Mapping)
        else None
    )
    synthetic_scope = (
        isinstance(scope_value, Mapping)
        and scope_value.get("dataset_kind") == "generated_synthetic"
    )
    raw_sample_count = raw_metrics.get("sample_count")
    sample_count_value = (
        raw_sample_count.get("value")
        if isinstance(raw_sample_count, Mapping)
        else None
    )
    scope_label = "开发样本检查"
    if isinstance(sample_count_value, Mapping):
        scope_label = (
            f"{sample_count_value.get('observation_cases', 0)} 个开发样本 / "
            f"{sample_count_value.get('observation_runs', 0)} 次方向检查 / "
            f"{sample_count_value.get('pair_cases', 0)} 对票据"
        )
    warning = "开发检查不代表 50 条独立锁定集已经通过。"
    if isinstance(scope_value, Mapping):
        raw_warning = scope_value.get("warning")
        if isinstance(raw_warning, str) and raw_warning.strip():
            warning = (
                "这是小规模合成开发检查。它不代表 50 条独立锁定集"
                "或真实影子验收已经通过。"
            )
    return {
        "evaluation_id": evaluation.evaluation_id,
        "summary_label": (
            (
                "合成开发检查通过"
                if synthetic_scope
                else "开发样本检查通过"
            )
            if evaluation.gate_passed
            else "开发样本检查未通过"
        ),
        "scope_label": scope_label,
        "warning": warning,
        "metrics": metrics,
    }


def _detail(
    current: TemplateFamilyCurrent,
    evaluation: TemplateEvaluationRecord | None,
    *,
    rollback_target_count: int = 0,
    shadow_pointer_record_version: int | None = None,
) -> dict[str, object]:
    definition = current.version.definition
    reference_width, reference_height = (
        (
            current.reference_image_width,
            current.reference_image_height,
        )
        if (
            current.reference_image_width is not None
            and current.reference_image_height is not None
        )
        else (800, 500)
    )
    anchors = [
        {
            "anchor_id": anchor.anchor_id,
            "label": anchor.expected_text,
            "expected_text": anchor.expected_text,
            "match_mode": {
                AnchorMatchKind.LITERAL: "exact",
                AnchorMatchKind.CONTAINS: "contains",
                AnchorMatchKind.REGEX: "pattern",
            }[anchor.match_kind],
            "required": anchor.required,
            "role_evidence": (
                "loading"
                if anchor.loading_evidence > anchor.unloading_evidence
                else (
                    "unloading"
                    if anchor.unloading_evidence > anchor.loading_evidence
                    else "position_only"
                )
            ),
            "importance": "primary" if anchor.weight >= 1 else "supporting",
            "bounds": _rect_wire(anchor.box),
        }
        for anchor in definition.anchors
    ]
    regions = [
        {
            "region_id": region.region_id,
            "label": _field_label(region.field),
            "field": _field_wire(region.field),
            "value_type": (
                "time"
                if region.field
                in {
                    TicketField.LOADING_WEIGH_TIME,
                    TicketField.UNLOADING_TARE_TIME,
                    TicketField.PRINT_TIME,
                }
                else "weight"
            ),
            "unit": (
                "kilogram"
                if region.unit == "kg"
                else ("printed" if region.unit is None else "ton")
            ),
            "required": region.required,
            "anchor_id": region.relative_to_anchor_id or definition.anchors[0].anchor_id,
            "bounds": _rect_wire(region.box),
        }
        for region in definition.regions
    ]
    return {
        "version_id": current.version.version_id,
        "record_version": current.version.record_version,
        "family_id": definition.family_id,
        "family_name": definition.name,
        "purpose": definition.role.value,
        "purpose_label": _purpose_label(definition.role),
        "lifecycle": current.version.lifecycle.value,
        "lifecycle_label": _lifecycle_label(current.version.lifecycle),
        "reference_image": {
            "image_id": current.reference_image_sha256,
            "content_url": _reference_content_url(
                current.reference_image_sha256
            ),
            "alt": f"{definition.name}参考图",
            "width": reference_width,
            "height": reference_height,
            "rotation": 0,
        },
        "draft": {"anchors": anchors, "regions": regions},
        "actions": _actions(
            current,
            evaluation,
            rollback_target_count=rollback_target_count,
            shadow_pointer_record_version=shadow_pointer_record_version,
        ),
        "check_report": _check_report(evaluation),
    }


def _definition_from_draft(
    *,
    family_id: str,
    family_name: str,
    role: TicketRole,
    draft: WorkbenchDraftPayload,
) -> TemplateDefinition:
    if any(
        item.expected_text.strip() == TEMPORARY_ANCHOR_TEXT
        for item in draft.anchors
    ):
        raise DomainContractError(
            "template anchor placeholder must be replaced"
        )
    anchors: list[TemplateAnchor] = []
    for item in draft.anchors:
        if item.role_evidence == "loading":
            loading_evidence, unloading_evidence = Decimal("0.8"), Decimal("-0.2")
        elif item.role_evidence == "unloading":
            loading_evidence, unloading_evidence = Decimal("-0.2"), Decimal("0.8")
        else:
            loading_evidence = unloading_evidence = Decimal("0.1")
        anchors.append(
            TemplateAnchor(
                anchor_id=item.anchor_id,
                expected_text=item.expected_text,
                match_kind={
                    "exact": AnchorMatchKind.LITERAL,
                    "contains": AnchorMatchKind.CONTAINS,
                    "pattern": AnchorMatchKind.REGEX,
                }[item.match_mode],
                box=item.bounds.to_domain(),
                required=item.required,
                weight=Decimal(1) if item.importance == "primary" else Decimal("0.5"),
                max_edit_distance=(
                    Decimal("0.10") if item.match_mode == "exact" else Decimal("0.25")
                ),
                loading_evidence=loading_evidence,
                unloading_evidence=unloading_evidence,
            )
        )
    field_map = {
        "ordinary_net_weight": TicketField.ORDINARY_NET,
        "factory_net_weight": TicketField.FACTORY_NET,
        "gross_weight": TicketField.GROSS,
        "tare_weight": TicketField.TARE,
        "loading_weigh_time": TicketField.LOADING_WEIGH_TIME,
        "unloading_tare_time": TicketField.UNLOADING_TARE_TIME,
        "print_time": TicketField.PRINT_TIME,
    }
    regions = tuple(
        RecognitionRegion(
            region_id=item.region_id,
            field=field_map[item.field],
            box=item.bounds.to_domain(),
            relative_to_anchor_id=item.anchor_id,
            unit={"ton": "t", "kilogram": "kg", "printed": None}[item.unit],
            format_pattern=(
                r"^\d{1,4}(?:\.\d{1,3})?$"
                if item.value_type == "weight"
                else r"^\d{4}-\d{2}-\d{2}"
            ),
            required=item.required,
            layout_scope="ticket",
        )
        for item in draft.regions
    )
    return TemplateDefinition(
        family_id=family_id,
        name=family_name,
        role=role,
        anchors=tuple(anchors),
        regions=regions,
    )


def _definition_from_workbench(
    current: TemplateFamilyCurrent,
    draft: WorkbenchDraftPayload,
) -> TemplateDefinition:
    definition = current.version.definition
    return _definition_from_draft(
        family_id=definition.family_id,
        family_name=definition.name,
        role=definition.role,
        draft=draft,
    )


def _translate_persistence_error(exc: TemplatePersistenceError) -> ApiError:
    if isinstance(exc, TemplateNotFoundError):
        return ApiError(404, "template_not_found", "没有找到该票据模板")
    if isinstance(exc, TemplateIdempotencyConflictError):
        return ApiError(409, "idempotency_key_reused", "该操作编号已经用于其他模板请求")
    if isinstance(exc, TemplateRecordVersionConflictError):
        return ApiError(409, "record_version_conflict", "模板已被更新。请刷新后重试")
    if isinstance(exc, TemplateReferenceUploadError):
        return ApiError(
            409,
            "template_reference_upload_conflict",
            "参考图暂存状态已经变化。请重新选择图片",
        )
    if isinstance(exc, TemplateEvaluationGateError):
        return ApiError(
            409,
            "template_evaluation_gate_failed",
            "没有找到可用于当前模板的已通过开发样本检查",
        )
    if isinstance(
        exc,
        (
            TemplateFamilyConflictError,
            TemplateLifecycleTransitionError,
        ),
    ):
        return ApiError(409, "template_operation_conflict", "当前模板状态不允许该操作")
    if isinstance(exc, TemplateAuthorizationError):
        return ApiError(403, "developer_revalidation_required", "该模板操作需要维护授权")
    return ApiError(500, "template_storage_failure", "模板数据保存失败。请查看诊断信息")


def _safe_reference_alt(raw_header: str | None) -> str:
    if raw_header is None:
        return "票据参考图"
    decoded = unquote(raw_header).replace("\\", "/").rsplit("/", 1)[-1]
    printable = "".join(
        character
        for character in decoded
        if character.isprintable() and character not in "\r\n"
    ).strip()
    if not printable:
        return "票据参考图"
    return printable[:120]


def _reference_content_url(image_sha256: str) -> str:
    return (
        "/api/v1/template-studio/reference-images/"
        f"{quote(image_sha256, safe='')}/content"
        f"?client_version={quote(__version__, safe='')}"
    )


def build_template_studio_router(
    *,
    repository: SqliteTemplateRepository,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
    developer_access_code: str | None,
    enable_test_fixtures: bool,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/template-studio", tags=["template-studio"])
    authorization = DeveloperAuthorizationManager(developer_access_code)
    evidence_store = ContentAddressedEvidenceStore(repository.runtime.data_root / "evidence")

    session_dependency = require_session
    write_dependency = require_write

    def require_developer_read(
        request: Request,
        _: None = Depends(session_dependency),
    ) -> str:
        return authorization.session_identity(request)

    def require_developer_write(
        request: Request,
        idempotency_key: str = Depends(write_dependency),
    ) -> str:
        authorization.session_identity(request)
        return idempotency_key

    def family_index(
        request: Request,
        *,
        authorized_override: bool | None = None,
    ) -> dict[str, object]:
        authorized = (
            authorization.is_authorized(request)
            if authorized_override is None
            else authorized_override
        )
        return {
            "maintenance": {
                "authorized": authorized,
                "status_label": (
                    "维护模式已开启" if authorized else "未进入维护模式"
                ),
                "expires_at_label": (
                    "15 分钟后自动退出" if authorized else None
                ),
            },
            "families": [
                _family_summary(summary) for summary in repository.list_families()
            ],
            "actions": {
                "create_template": {
                    "visible": True,
                    "enabled": authorized,
                    "reason": (
                        None
                        if authorized
                        else "进入维护模式后才能添加票据模板"
                    ),
                    "label": "添加票据模板",
                    "expected_record_version": None,
                    "evaluation_id": None,
                }
            },
            "acceptance_set": {
                "waybill_count": 0,
                "target_waybill_count": 50,
                "status_label": "独立验收样本尚未建立",
            },
        }

    def project_detail(current: TemplateFamilyCurrent) -> dict[str, object]:
        evaluation = repository.get_latest_valid_development_evaluation(
            current.version.version_id
        )
        rollback = project_rollback_options(
            current.version.definition.family_id
        )
        current_shadow = rollback["current_shadow"]
        versions_value = rollback["versions"]
        versions: list[object] = (
            versions_value if isinstance(versions_value, list) else []
        )
        return _detail(
            current,
            evaluation,
            rollback_target_count=sum(
                1
                for version in versions
                if isinstance(version, Mapping)
                and version.get("can_rollback") is True
            ),
            shadow_pointer_record_version=(
                int(current_shadow["record_version"])
                if isinstance(current_shadow, Mapping)
                and isinstance(current_shadow.get("record_version"), int)
                else None
            ),
        )

    def project_rollback_options(family_id: str) -> dict[str, object]:
        versions = repository.list_family_versions(family_id)
        try:
            pointer = repository.get_shadow_pointer(family_id)
        except (TemplateNotFoundError, TemplateEvaluationGateError):
            pointer = None
        projected_versions: list[dict[str, object]] = []
        for version in versions:
            evaluation = (
                repository.get_latest_valid_development_evaluation(
                    version.version_id
                )
                if version.lifecycle is TemplateLifecycle.SHADOW
                else None
            )
            is_current = (
                pointer is not None
                and pointer.version_id == version.version_id
            )
            can_rollback = (
                pointer is not None
                and not is_current
                and version.lifecycle is TemplateLifecycle.SHADOW
                and evaluation is not None
                and evaluation.gate_passed
            )
            projected_versions.append(
                {
                    "version_id": version.version_id,
                    "version_number": version.version_number,
                    "lifecycle_label": _lifecycle_label(version.lifecycle),
                    "is_current_shadow": is_current,
                    "can_rollback": can_rollback,
                    "label": (
                        (
                            f"影子版本 {version.version_number}"
                            if version.lifecycle is TemplateLifecycle.SHADOW
                            else (
                                f"{_lifecycle_label(version.lifecycle)} "
                                f"{version.version_number}"
                            )
                        )
                        + (" (当前)" if is_current else "")
                    ),
                }
            )
        return {
            "family_id": family_id,
            "current_shadow": (
                None
                if pointer is None
                else {
                    "version_id": pointer.version_id,
                    "record_version": pointer.record_version,
                }
            ),
            "versions": projected_versions,
        }

    @router.get("/families")
    def list_template_families(
        request: Request,
        _: None = Depends(session_dependency),
    ) -> dict[str, object]:
        return family_index(request)

    @router.post("/developer/revalidate")
    def revalidate_developer(
        payload: DeveloperRevalidationPayload,
        request: Request,
        _: str = Depends(write_dependency),
    ) -> JSONResponse:
        session_token, action_token = authorization.revalidate(
            access_code=payload.access_code,
            action=payload.action,
            resource_id=payload.resource_id,
        )
        body = family_index(request, authorized_override=True)
        if action_token is not None:
            body["authorization_token"] = action_token
        response = JSONResponse(body)
        response.set_cookie(
            DEVELOPER_COOKIE,
            session_token,
            httponly=True,
            samesite="strict",
            max_age=MAINTENANCE_SECONDS,
            path="/api/v1/template-studio",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.get("/families/{family_id}")
    def get_template_family(
        family_id: str,
        _: str = Depends(require_developer_read),
    ) -> dict[str, object]:
        try:
            return project_detail(repository.get_family_current(family_id))
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc

    @router.get("/families/{family_id}/versions")
    def list_template_family_versions(
        family_id: str,
        _: str = Depends(require_developer_read),
    ) -> dict[str, object]:
        try:
            return project_rollback_options(family_id)
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc

    @router.post("/reference-images")
    async def stage_reference_image(
        request: Request,
        idempotency_key: str = Depends(require_developer_write),
        x_dahe_file_name: Annotated[
            str | None,
            Header(alias="X-DaHe-File-Name"),
        ] = None,
    ) -> dict[str, object]:
        raw_length = request.headers.get("content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length)
            except ValueError as exc:
                raise ApiError(
                    400,
                    "invalid_reference_image_length",
                    "参考图片大小信息无效",
                ) from exc
            if content_length < 0:
                raise ApiError(
                    400,
                    "invalid_reference_image_length",
                    "参考图片大小信息无效",
                )
            if content_length > MAX_REFERENCE_BYTES:
                raise ApiError(
                    413,
                    "reference_image_too_large",
                    "参考图片不能超过 15 MB",
                )
        declared_media_type = (
            request.headers.get("content-type", "")
            .split(";", 1)[0]
            .strip()
            .lower()
        )
        chunks: list[bytes] = []
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > MAX_REFERENCE_BYTES:
                raise ApiError(
                    413,
                    "reference_image_too_large",
                    "参考图片不能超过 15 MB",
                )
            chunks.append(chunk)
        content = b"".join(chunks)
        try:
            normalized = normalize_template_reference_image(
                content,
                declared_media_type=declared_media_type,
            )
        except TemplateReferenceImageError as exc:
            raise ApiError(
                400,
                "invalid_template_reference_image",
                "请选择清晰、完整的 PNG 或 JPEG 磅单图片",
            ) from exc
        stored = evidence_store.put_bytes(
            normalized.content,
            media_type=normalized.media_type,
        )
        try:
            upload, _ = repository.stage_reference_upload(
                image_sha256=stored.sha256,
                relative_path=stored.relative_path,
                byte_size=stored.byte_size,
                media_type=stored.media_type,
                width=normalized.width,
                height=normalized.height,
                actor_id=authorization.session_identity(request),
                idempotency_key=idempotency_key,
            )
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc
        return {
            "upload": {
                "staged_reference_id": upload.staged_reference_id,
                "image_id": upload.image_sha256,
                "content_url": _reference_content_url(upload.image_sha256),
                "alt": _safe_reference_alt(x_dahe_file_name),
                "width": upload.width,
                "height": upload.height,
                "record_version": upload.record_version,
            }
        }

    @router.post("/reference-images/{staged_reference_id}/abandon")
    def abandon_reference_image(
        staged_reference_id: str,
        payload: AbandonReferenceUploadPayload,
        request: Request,
        idempotency_key: str = Depends(require_developer_write),
    ) -> dict[str, object]:
        try:
            upload, abandoned = repository.abandon_reference_upload(
                staged_reference_id=staged_reference_id,
                expected_record_version=payload.expected_record_version,
                actor_id=authorization.session_identity(request),
                idempotency_key=idempotency_key,
            )
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc
        return {
            "abandoned": abandoned,
            "record_version": upload.record_version,
            "state": upload.state,
        }

    @router.post("/templates/from-staged-reference")
    def create_template_from_staged_reference(
        payload: CreateWorkbenchTemplatePayload,
        request: Request,
        idempotency_key: str = Depends(require_developer_write),
    ) -> dict[str, object]:
        actor_id = authorization.session_identity(request)
        try:
            upload = repository.get_reference_upload(
                payload.staged_reference_id
            )
            role = TicketRole(payload.role)
            family_id = (
                "ticket-"
                + hashlib.sha256(
                    (
                        f"{payload.staged_reference_id}:"
                        f"{idempotency_key}"
                    ).encode()
                ).hexdigest()[:24]
            )
            definition = _definition_from_draft(
                family_id=family_id,
                family_name=payload.family_name,
                role=role,
                draft=payload.draft,
            )
            mask_content = build_template_reference_mask(
                width=upload.width,
                height=upload.height,
                anchors=tuple(
                    anchor.box
                    for anchor in definition.anchors
                ),
            )
            stored_mask = evidence_store.put_bytes(
                mask_content,
                media_type="image/png",
            )
            repository.register_derived_template_mask(
                sha256=stored_mask.sha256,
                relative_path=stored_mask.relative_path,
                byte_size=stored_mask.byte_size,
                actor_id=actor_id,
                idempotency_key=hashlib.sha256(
                    f"template-mask:{idempotency_key}".encode()
                ).hexdigest(),
            )
            version, created = repository.create_draft(
                definition=definition,
                reference_image_sha256=upload.image_sha256,
                reference_mask_sha256=stored_mask.sha256,
                alignment_fingerprint=(
                    template_reference_alignment_fingerprint(
                        image_sha256=upload.image_sha256,
                        width=upload.width,
                        height=upload.height,
                    )
                ),
                actor_id=actor_id,
                idempotency_key=idempotency_key,
                staged_reference_id=upload.staged_reference_id,
                expected_staged_reference_record_version=(
                    payload.expected_record_version
                ),
            )
            current = repository.get_family_current(
                version.definition.family_id
            )
        except TemplateReferenceImageError as exc:
            raise ApiError(
                400,
                "invalid_template_reference_mask",
                "固定内容框选无法生成参考遮罩",
            ) from exc
        except DomainContractError as exc:
            raise ApiError(
                400,
                "invalid_template_definition",
                "请先正确填写模板名称并标出至少一处固定内容",
            ) from exc
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc
        return {"created": created, "template": project_detail(current)}

    if enable_test_fixtures:

        @router.post("/test-fixtures/templates")
        def create_template_test_fixture(
            payload: CreateTemplatePayload,
            request: Request,
            idempotency_key: str = Depends(require_developer_write),
        ) -> dict[str, object]:
            """Seed immutable evidence only in an explicit isolated test app."""

            try:
                version, created = repository.create_draft(
                    definition=payload.definition.to_domain(),
                    reference_image_sha256=payload.reference_image_sha256,
                    reference_mask_sha256=payload.reference_mask_sha256,
                    alignment_fingerprint=payload.alignment_fingerprint,
                    actor_id=authorization.session_identity(request),
                    idempotency_key=idempotency_key,
                )
                current = repository.get_family_current(
                    version.definition.family_id
                )
            except DomainContractError as exc:
                raise ApiError(
                    400,
                    "invalid_template_definition",
                    "模板框选内容无效",
                ) from exc
            except TemplatePersistenceError as exc:
                raise _translate_persistence_error(exc) from exc
            return {"created": created, "template": project_detail(current)}

    @router.put("/templates/{version_id}/draft")
    def save_template_draft(
        version_id: str,
        payload: SaveWorkbenchDraftPayload,
        request: Request,
        idempotency_key: str = Depends(require_developer_write),
    ) -> dict[str, object]:
        try:
            actor_id = authorization.session_identity(request)
            current_version = repository.get_version(version_id)
            if current_version.record_version != payload.expected_record_version:
                raise TemplateRecordVersionConflictError("template screen is stale")
            current = repository.get_family_current(current_version.definition.family_id)
            if (
                current.reference_image_width is None
                or current.reference_image_height is None
            ):
                raise TemplateReferenceImageError(
                    "template reference dimensions are unavailable"
                )
            definition = _definition_from_workbench(current, payload.draft)
            mask_content = build_template_reference_mask(
                width=current.reference_image_width,
                height=current.reference_image_height,
                anchors=tuple(anchor.box for anchor in definition.anchors),
            )
            stored_mask = evidence_store.put_bytes(
                mask_content,
                media_type="image/png",
            )
            repository.register_derived_template_mask(
                sha256=stored_mask.sha256,
                relative_path=stored_mask.relative_path,
                byte_size=stored_mask.byte_size,
                actor_id=actor_id,
                idempotency_key=hashlib.sha256(
                    f"template-mask:{idempotency_key}".encode()
                ).hexdigest(),
            )
            revised, _ = repository.revise_draft(
                source_version_id=version_id,
                definition=definition,
                reference_image_sha256=current.reference_image_sha256,
                reference_mask_sha256=stored_mask.sha256,
                alignment_fingerprint=current.alignment_fingerprint,
                expected_record_version=payload.expected_record_version,
                actor_id=actor_id,
                idempotency_key=idempotency_key,
            )
            return project_detail(
                repository.get_family_current(revised.definition.family_id)
            )
        except TemplateReferenceImageError as exc:
            raise ApiError(
                409,
                "template_reference_dimensions_unavailable",
                "参考图尺寸无法确认, 请重新上传参考图后再保存.",
            ) from exc
        except DomainContractError as exc:
            raise ApiError(400, "invalid_template_definition", "模板框选内容无效") from exc
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc

    @router.post("/templates/{version_id}/development-tested")
    def mark_development_tested(
        version_id: str,
        payload: LifecyclePayload,
        request: Request,
        idempotency_key: str = Depends(require_developer_write),
    ) -> dict[str, object]:
        try:
            version, _ = repository.mark_development_tested(
                version_id=version_id,
                expected_record_version=payload.expected_record_version,
                evaluation_id=payload.evaluation_id,
                developer_authorization_id=authorization.session_identity(request),
                actor_id=authorization.session_identity(request),
                idempotency_key=idempotency_key,
            )
            return project_detail(
                repository.get_family_current(version.definition.family_id)
            )
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc

    @router.post("/templates/{version_id}/shadow")
    def publish_shadow(
        version_id: str,
        payload: LifecyclePayload,
        idempotency_key: str = Depends(require_developer_write),
        x_developer_authorization: Annotated[
            str | None,
            Header(alias="X-DaHe-Developer-Authorization"),
        ] = None,
    ) -> dict[str, object]:
        action_identity = authorization.action_identity(
            token=x_developer_authorization,
            action="template.publish_shadow",
            resource_id=version_id,
            idempotency_key=idempotency_key,
        )
        try:
            version, _ = repository.publish_shadow(
                version_id=version_id,
                expected_record_version=payload.expected_record_version,
                evaluation_id=payload.evaluation_id,
                developer_authorization_id=action_identity,
                actor_id=action_identity,
                idempotency_key=idempotency_key,
            )
            return project_detail(
                repository.get_family_current(version.definition.family_id)
            )
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc

    @router.post("/families/{family_id}/rollback")
    def rollback_shadow(
        family_id: str,
        payload: RollbackPayload,
        idempotency_key: str = Depends(require_developer_write),
        x_developer_authorization: Annotated[
            str | None,
            Header(alias="X-DaHe-Developer-Authorization"),
        ] = None,
    ) -> dict[str, object]:
        action_identity = authorization.action_identity(
            token=x_developer_authorization,
            action="template.rollback_shadow",
            resource_id=family_id,
            idempotency_key=idempotency_key,
        )
        try:
            pointer, applied = repository.rollback_shadow(
                family_id=family_id,
                target_version_id=payload.target_version_id,
                expected_record_version=payload.expected_record_version,
                reason=payload.reason,
                developer_authorization_id=action_identity,
                actor_id=action_identity,
                idempotency_key=idempotency_key,
            )
            return {
                "applied": applied,
                "shadow_pointer": {
                    "family_id": pointer.family_id,
                    "version_id": pointer.version_id,
                    "record_version": pointer.record_version,
                },
            }
        except TemplatePersistenceError as exc:
            raise _translate_persistence_error(exc) from exc

    @router.get("/reference-images/{image_id}/content")
    def get_reference_image(
        image_id: str,
        _: str = Depends(require_developer_read),
    ) -> Response:
        with repository.runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT media_type FROM evidence_blobs "
                        "WHERE sha256 = :sha256 AND storage_state = 'available'"
                    ),
                    {"sha256": image_id},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise ApiError(404, "template_reference_not_found", "模板参考图不可用")
        try:
            content = evidence_store.read_bytes(image_id)
        except EvidenceIntegrityError as exc:
            raise ApiError(
                500,
                "template_reference_integrity_failure",
                "模板参考图校验失败。请查看诊断信息",
            ) from exc
        return Response(
            content=content,
            media_type=str(row["media_type"]),
            headers={"Cache-Control": "private, no-store"},
        )

    return router
