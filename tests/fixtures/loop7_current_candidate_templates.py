from __future__ import annotations

from decimal import Decimal

from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
    TicketField,
)


def current_candidate_versions() -> tuple[TemplateVersion, ...]:
    """Return deterministic candidates aligned with all formal seed contracts."""

    loading = TemplateVersion(
        version_id="test-current-loading-v1",
        definition=TemplateDefinition(
            family_id="loop7-real-loading-minimal",
            name="Loop 7 minimal loading ticket",
            role=TicketRole.LOADING,
            anchors=(
                TemplateAnchor(
                    anchor_id="loading-customer-name",
                    expected_text="客户名称",
                    box=NormalizedRect(
                        x=Decimal("0.199"),
                        y=Decimal("0.572666667"),
                        width=Decimal("0.1105"),
                        height=Decimal("0.046666666"),
                    ),
                    required=True,
                    weight=Decimal("1"),
                    max_edit_distance=Decimal("0.1"),
                    loading_evidence=Decimal("1"),
                    unloading_evidence=Decimal("-0.4"),
                    match_kind=AnchorMatchKind.LITERAL,
                ),
            ),
            regions=(
                RecognitionRegion(
                    region_id="loading-ordinary-net",
                    field=TicketField.ORDINARY_NET,
                    box=NormalizedRect(
                        x=Decimal("0.675"),
                        y=Decimal("0.55"),
                        width=Decimal("0.15"),
                        height=Decimal("0.12"),
                    ),
                    relative_to_anchor_id=None,
                    unit="t",
                    format_pattern=r"^[0-9]+(?:\.[0-9]{1,3})?$",
                    required=True,
                    layout_scope="ticket",
                ),
            ),
        ),
        lifecycle=TemplateLifecycle.DRAFT,
        parent_version_id=None,
        record_version=1,
    )
    loading_success = TemplateVersion(
        version_id="test-current-loading-success-v1",
        definition=TemplateDefinition(
            family_id="loop7-real-loading-success",
            name="装货磅单（保存成功参考字段）",  # noqa: RUF001
            role=TicketRole.LOADING,
            anchors=(
                TemplateAnchor(
                    anchor_id="loading-save-success",
                    expected_text="保存成功",
                    box=NormalizedRect(
                        x=Decimal("0.106481481"),
                        y=Decimal("0.646875"),
                        width=Decimal("0.195370371"),
                        height=Decimal("0.036458333"),
                    ),
                    required=True,
                    weight=Decimal("1"),
                    max_edit_distance=Decimal("0.1"),
                    loading_evidence=Decimal("1"),
                    unloading_evidence=Decimal("-0.4"),
                    match_kind=AnchorMatchKind.CONTAINS,
                ),
            ),
            regions=(
                RecognitionRegion(
                    region_id="loading-success-ordinary-net",
                    field=TicketField.ORDINARY_NET,
                    box=NormalizedRect(
                        x=Decimal("0.70"),
                        y=Decimal("0.50"),
                        width=Decimal("0.24"),
                        height=Decimal("0.12"),
                    ),
                    relative_to_anchor_id=None,
                    unit="t",
                    format_pattern=r"^[0-9]+(?:\.[0-9]{1,3})?$",
                    required=True,
                    layout_scope="ticket",
                ),
            ),
        ),
        lifecycle=TemplateLifecycle.DRAFT,
        parent_version_id=None,
        record_version=1,
    )
    loading_prompt = TemplateVersion(
        version_id="test-current-loading-prompt-v1",
        definition=TemplateDefinition(
            family_id="loop7-real-loading-prompt",
            name="装货磅单（提示信息参考字段）",  # noqa: RUF001
            role=TicketRole.LOADING,
            anchors=(
                TemplateAnchor(
                    anchor_id="loading-prompt-information",
                    expected_text="提示信息",
                    box=NormalizedRect(
                        x=Decimal("0"),
                        y=Decimal("0.564"),
                        width=Decimal("0.141906874"),
                        height=Decimal("0.026"),
                    ),
                    required=True,
                    weight=Decimal("1"),
                    max_edit_distance=Decimal("0.1"),
                    loading_evidence=Decimal("1"),
                    unloading_evidence=Decimal("-0.4"),
                    match_kind=AnchorMatchKind.LITERAL,
                ),
            ),
            regions=(
                RecognitionRegion(
                    region_id="loading-prompt-ordinary-net",
                    field=TicketField.ORDINARY_NET,
                    box=NormalizedRect(
                        x=Decimal("0.58"),
                        y=Decimal("0.47"),
                        width=Decimal("0.20"),
                        height=Decimal("0.09"),
                    ),
                    relative_to_anchor_id=None,
                    unit="t",
                    format_pattern=r"^[0-9]+(?:\.[0-9]{1,3})?$",
                    required=True,
                    layout_scope="ticket",
                ),
            ),
        ),
        lifecycle=TemplateLifecycle.DRAFT,
        parent_version_id=None,
        record_version=1,
    )
    unloading = TemplateVersion(
        version_id="test-current-unloading-v1",
        definition=TemplateDefinition(
            family_id="loop7-real-unloading-minimal",
            name="Loop 7 minimal unloading ticket",
            role=TicketRole.UNLOADING,
            anchors=(
                TemplateAnchor(
                    anchor_id="unloading-factory-net",
                    expected_text="工厂净重",
                    box=NormalizedRect(
                        x=Decimal("0.486"),
                        y=Decimal("0.548666667"),
                        width=Decimal("0.063"),
                        height=Decimal("0.024"),
                    ),
                    required=True,
                    weight=Decimal("1"),
                    max_edit_distance=Decimal("0.1"),
                    loading_evidence=Decimal("-0.4"),
                    unloading_evidence=Decimal("1"),
                    match_kind=AnchorMatchKind.LITERAL,
                ),
            ),
            regions=(
                RecognitionRegion(
                    region_id="unloading-ordinary-net",
                    field=TicketField.ORDINARY_NET,
                    box=NormalizedRect(
                        x=Decimal("0.62"),
                        y=Decimal("0.49"),
                        width=Decimal("0.12"),
                        height=Decimal("0.08"),
                    ),
                    relative_to_anchor_id=None,
                    unit="t",
                    format_pattern=r"^[0-9]+(?:\.[0-9]{1,3})?$",
                    required=True,
                    layout_scope="ticket",
                ),
            ),
        ),
        lifecycle=TemplateLifecycle.DRAFT,
        parent_version_id=None,
        record_version=1,
    )
    return loading, loading_success, loading_prompt, unloading
