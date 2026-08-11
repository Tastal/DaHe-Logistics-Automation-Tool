from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dahe.adapters.ocr.protocol import (
    NormalizedBox,
    OcrFieldValue,
    OcrResult,
    OcrResultStatus,
    OcrRoleObservation,
    OcrTextLine,
)
from dahe.adapters.ocr.template_role_input import template_role_input_from_ocr_v1
from dahe.application.template_studio import matcher as matcher_module
from dahe.application.template_studio.matcher import (
    MATCHER_VERSION,
    ObservedTextLine,
    TemplateRoleInput,
    build_development_evaluation_template_set,
    build_template_set_fingerprint,
    match_ticket_role,
    match_ticket_role_for_development_evaluation,
)
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.role_assessment import RoleAssessmentPolicy
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
)


def _rect(x: str, y: str, width: str, height: str) -> NormalizedRect:
    return NormalizedRect(
        x=Decimal(x),
        y=Decimal(y),
        width=Decimal(width),
        height=Decimal(height),
    )


def _rotate(rectangle: NormalizedRect, degrees: int) -> NormalizedRect:
    if degrees == 0:
        return rectangle
    if degrees == 90:
        return _rect(
            str(1 - rectangle.y - rectangle.height),
            str(rectangle.x),
            str(rectangle.height),
            str(rectangle.width),
        )
    if degrees == 180:
        return _rect(
            str(1 - rectangle.x - rectangle.width),
            str(1 - rectangle.y - rectangle.height),
            str(rectangle.width),
            str(rectangle.height),
        )
    return _rect(
        str(rectangle.y),
        str(1 - rectangle.x - rectangle.width),
        str(rectangle.height),
        str(rectangle.width),
    )


def _anchor(
    anchor_id: str,
    text: str,
    box: NormalizedRect,
    role: TicketRole,
) -> TemplateAnchor:
    return TemplateAnchor(
        anchor_id=anchor_id,
        expected_text=text,
        box=box,
        required=True,
        weight=Decimal("1"),
        max_edit_distance=Decimal("0.10"),
        loading_evidence=Decimal("0.9") if role is TicketRole.LOADING else Decimal("-0.4"),
        unloading_evidence=(
            Decimal("0.9") if role is TicketRole.UNLOADING else Decimal("-0.4")
        ),
    )


def _version(role: TicketRole, marker: str) -> TemplateVersion:
    title = "装货磅单" if role is TicketRole.LOADING else "卸货磅单"
    return TemplateVersion(
        version_id=f"{marker}-v1",
        definition=TemplateDefinition(
            family_id=f"{marker}-family",
            name=f"{marker} ticket",
            role=role,
            anchors=(
                _anchor(
                    f"{marker}-title",
                    title,
                    _rect("0.10", "0.08", "0.30", "0.08"),
                    role,
                ),
                _anchor(
                    f"{marker}-net",
                    "净重",
                    _rect("0.10", "0.62", "0.14", "0.07"),
                    role,
                ),
            ),
            regions=(),
        ),
        lifecycle=TemplateLifecycle.SHADOW,
        parent_version_id=None,
        record_version=3,
    )


def _policy() -> RoleAssessmentPolicy:
    return RoleAssessmentPolicy(
        minimum_score=Decimal("0.60"),
        minimum_margin=Decimal("0.25"),
        minimum_sources=2,
        minimum_ticket_likelihood=Decimal("0.60"),
        high_confidence_score=Decimal("0.85"),
        version="loop7-matcher-policy-v1",
    )


def _input(role: TicketRole, orientation: int = 0) -> TemplateRoleInput:
    title = "装货磅单" if role is TicketRole.LOADING else "卸货磅单"
    fixed = "装货" if role is TicketRole.LOADING else "卸货"
    return TemplateRoleInput(
        image_sha256=("1" if role is TicketRole.LOADING else "2") * 64,
        text_lines=(
            ObservedTextLine(
                text=title,
                confidence=Decimal("0.98"),
                box=_rotate(_rect("0.10", "0.08", "0.30", "0.08"), orientation),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.96"),
                box=_rotate(_rect("0.10", "0.62", "0.14", "0.07"), orientation),
            ),
        ),
        fixed_text=(fixed, "磅单", "净重"),
    )


def _ocr_authorized_role_input(
    role_input: TemplateRoleInput,
    *,
    ordinary_net_reliable: bool,
) -> TemplateRoleInput:
    result = OcrResult(
        command_id="matcher-authoritative-input",
        status=OcrResultStatus.OK,
        worker_identity="matcher-test-worker",
        runtime_fingerprint="9" * 64,
        verified_image_sha256=role_input.image_sha256,
        elapsed_ms=1,
        text_lines=tuple(
            OcrTextLine(
                text=line.text,
                confidence=line.confidence,
                box=NormalizedBox(
                    x=line.box.x,
                    y=line.box.y,
                    width=line.box.width,
                    height=line.box.height,
                ),
            )
            for line in role_input.text_lines
        ),
        fields=(
            {
                "ordinary_net": OcrFieldValue(
                    raw_text="31.25",
                    amount="31.25",
                    unit="t",
                    confidence=Decimal("0.97"),
                )
            }
            if ordinary_net_reliable
            else {}
        ),
        role_observation=OcrRoleObservation(
            fixed_text=role_input.fixed_text,
            layout_fingerprint="matcher-authoritative-layout",
            orientation_degrees=0,
        ),
        error=None,
    )
    return template_role_input_from_ocr_v1(result)


@pytest.mark.parametrize("orientation", [0, 90, 180, 270])
def test_matcher_compares_both_role_families_and_recovers_orientation(
    orientation: int,
) -> None:
    templates = (
        _version(TicketRole.LOADING, "loading"),
        _version(TicketRole.UNLOADING, "unloading"),
    )

    loading = match_ticket_role(_input(TicketRole.LOADING, orientation), templates, _policy())
    unloading = match_ticket_role(
        _input(TicketRole.UNLOADING, orientation),
        tuple(reversed(templates)),
        _policy(),
    )

    assert loading.assessment.role is TicketRole.LOADING
    assert loading.observation.orientation_degrees == orientation
    assert unloading.assessment.role is TicketRole.UNLOADING
    assert unloading.observation.orientation_degrees == orientation
    assert loading.template_set_fingerprint == unloading.template_set_fingerprint


def test_fixed_term_from_the_template_ocr_line_is_not_an_independent_source() -> None:
    templates = (
        _version(TicketRole.LOADING, "loading"),
        _version(TicketRole.UNLOADING, "unloading"),
    )
    role_input = _input(TicketRole.LOADING)
    role_input = replace(
        role_input,
        text_lines=(
            replace(role_input.text_lines[0], text="装 货 磅 单"),
            role_input.text_lines[1],
        ),
    )

    result = match_ticket_role(role_input, templates, _policy())
    fixed_text = result.observation.evidence[0]

    assert fixed_text.loading_score == 0
    assert "loading:装货" not in fixed_text.matched_ids
    assert result.observation.evidence[1].loading_score >= Decimal("0.85")
    assert result.observation.evidence[2].loading_score >= Decimal("0.85")
    assert result.assessment.role is TicketRole.LOADING


def test_matcher_returns_unknown_for_conflicting_or_non_ticket_text() -> None:
    templates = (
        _version(TicketRole.LOADING, "loading"),
        _version(TicketRole.UNLOADING, "unloading"),
    )
    conflicting = TemplateRoleInput(
        image_sha256="3" * 64,
        text_lines=(
            ObservedTextLine(
                text="装货磅单",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="卸货磅单",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.96"),
                box=_rect("0.10", "0.62", "0.14", "0.07"),
            ),
        ),
        fixed_text=("装货", "卸货", "磅单", "净重"),
    )
    non_ticket = TemplateRoleInput(
        image_sha256="4" * 64,
        text_lines=(
            ObservedTextLine(
                text="普通发票",
                confidence=Decimal("0.99"),
                box=_rect("0.20", "0.10", "0.30", "0.08"),
            ),
        ),
        fixed_text=(),
    )

    assert (
        match_ticket_role(conflicting, templates, _policy()).assessment.role
        is TicketRole.UNKNOWN
    )
    assert (
        match_ticket_role(non_ticket, templates, _policy()).assessment.role
        is TicketRole.UNKNOWN
    )


def test_unloading_party_labels_do_not_conflict_with_factory_weight_evidence() -> None:
    templates = (
        _version(TicketRole.LOADING, "loading"),
        _version(TicketRole.UNLOADING, "unloading"),
    )
    unloading = replace(
        _input(TicketRole.UNLOADING),
        fixed_text=(
            "发货单位",
            "收货单位",
            "工厂净重",
            "称重来源",
            "磅单",
            "净重",
        ),
    )

    result = match_ticket_role(unloading, templates, _policy())
    fixed_text = result.observation.evidence[0]

    assert fixed_text.loading_score == Decimal(0)
    assert fixed_text.unloading_score == Decimal(1)
    assert "loading:发货" not in fixed_text.matched_ids
    assert "unloading:收货" not in fixed_text.matched_ids
    assert "unloading:工厂净重" in fixed_text.matched_ids
    assert result.assessment.role is TicketRole.UNLOADING


@pytest.mark.parametrize("unloading_term", ["收货单位", "进货", "到达站"])
def test_unloading_business_terms_are_independent_fixed_evidence(
    unloading_term: str,
) -> None:
    role_input = TemplateRoleInput(
        image_sha256="4" * 64,
        text_lines=(
            ObservedTextLine(
                text=unloading_term,
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.20", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.97"),
                box=_rect("0.10", "0.50", "0.14", "0.07"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.30", "0.50", "0.14", "0.07"),
            ),
        ),
        fixed_text=(unloading_term, "磅单", "净重"),
    )

    result = match_ticket_role(
        role_input,
        (
            _version(TicketRole.LOADING, "loading"),
            _version(TicketRole.UNLOADING, "unloading"),
        ),
        _policy(),
    )
    fixed_text = result.observation.evidence[0]

    assert fixed_text.loading_score == 0
    assert fixed_text.unloading_score == 1
    assert f"unloading:{unloading_term}" in fixed_text.matched_ids


@pytest.mark.parametrize("single_term", ["全程禁止下车", "服务热线"])
def test_loading_kiosk_term_alone_is_not_fixed_evidence(single_term: str) -> None:
    role_input = TemplateRoleInput(
        image_sha256="3" * 64,
        text_lines=(
            ObservedTextLine(
                text=single_term,
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.20", "0.40", "0.08"),
            ),
        ),
        fixed_text=(single_term,),
    )

    result = match_ticket_role(
        role_input,
        (
            _version(TicketRole.LOADING, "loading"),
            _version(TicketRole.UNLOADING, "unloading"),
        ),
        _policy(),
    )

    assert result.observation.evidence[0].loading_score == 0
    assert "loading:kiosk-safety-hotline" not in (
        result.observation.evidence[0].matched_ids
    )


def test_loading_kiosk_terms_form_one_composite_fixed_evidence() -> None:
    role_input = TemplateRoleInput(
        image_sha256="0" * 64,
        text_lines=(
            ObservedTextLine(
                text="全程禁止下车",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.20", "0.40", "0.08"),
            ),
            ObservedTextLine(
                text="服务热线",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.32", "0.30", "0.08"),
            ),
        ),
        fixed_text=("全程禁止下车", "服务热线"),
    )

    result = match_ticket_role(
        role_input,
        (
            _version(TicketRole.LOADING, "loading"),
            _version(TicketRole.UNLOADING, "unloading"),
        ),
        _policy(),
    )
    fixed_text = result.observation.evidence[0]

    assert fixed_text.loading_score == 1
    assert fixed_text.matched_ids == ("loading:kiosk-safety-hotline",)


def test_loading_kiosk_composite_counts_once_when_terms_share_an_ocr_line() -> None:
    combined_text = "全程禁止下车 服务热线"
    role_input = TemplateRoleInput(
        image_sha256="1" * 64,
        text_lines=(
            ObservedTextLine(
                text=combined_text,
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.20", "0.60", "0.08"),
            ),
        ),
        fixed_text=(combined_text,),
    )

    result = match_ticket_role(
        role_input,
        (
            _version(TicketRole.LOADING, "loading"),
            _version(TicketRole.UNLOADING, "unloading"),
        ),
        _policy(),
    )
    fixed_text = result.observation.evidence[0]

    assert fixed_text.loading_score == 1
    assert fixed_text.matched_ids == ("loading:kiosk-safety-hotline",)


def test_loading_kiosk_composite_does_not_reuse_a_template_line() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="全程禁止下车",
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="8" * 64,
        text_lines=(
            ObservedTextLine(
                text="全程禁止下车",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="服务热线",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.32", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.97"),
                box=_rect("0.10", "0.50", "0.14", "0.07"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.30", "0.50", "0.14", "0.07"),
            ),
        ),
        fixed_text=("全程禁止下车", "服务热线", "磅单", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.evidence[0].loading_score == 0
    assert "loading:kiosk-safety-hotline" not in (
        result.observation.evidence[0].matched_ids
    )
    assert result.assessment.role is TicketRole.LOADING


@pytest.mark.parametrize("loading_marker", ["客户名称", "提示信息", "保存成功"])
def test_loading_specific_ui_markers_provide_fixed_text_evidence(
    loading_marker: str,
) -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text=loading_marker,
                ),
                loading_template.definition.anchors[1],
            ),
        ),
    )
    templates = (
        loading_template,
        _version(TicketRole.UNLOADING, "unloading"),
    )
    role_input = TemplateRoleInput(
        image_sha256="5" * 64,
        text_lines=(
            ObservedTextLine(
                text=loading_marker,
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.96"),
                box=_rect("0.10", "0.62", "0.14", "0.07"),
            ),
        ),
        fixed_text=(loading_marker, "磅单", "净重"),
    )

    result = match_ticket_role(role_input, templates, _policy())
    fixed_text = result.observation.evidence[0]

    assert fixed_text.loading_score == Decimal(0)
    assert fixed_text.unloading_score == Decimal(0)
    assert f"loading:{loading_marker}" not in fixed_text.matched_ids
    assert result.assessment.role is TicketRole.LOADING


@pytest.mark.parametrize("loading_marker", ["客户名称", "提示信息", "保存成功"])
def test_loading_ui_marker_alone_does_not_turn_a_non_ticket_into_a_ticket(
    loading_marker: str,
) -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text=loading_marker,
                    match_kind=AnchorMatchKind.CONTAINS,
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="a" * 64,
        text_lines=(
            ObservedTextLine(
                text=loading_marker,
                confidence=Decimal("0.99"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
        ),
        fixed_text=(loading_marker,),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.ticket_likelihood == 0
    assert result.observation.evidence[0].loading_score == 0
    assert result.assessment.role is TicketRole.UNKNOWN


@pytest.mark.parametrize(
    ("ordinary_net_reliable", "expected_likelihood", "expected_role"),
    [
        (False, Decimal(0), TicketRole.UNKNOWN),
        (True, Decimal(1), TicketRole.LOADING),
    ],
)
def test_only_authoritative_ordinary_net_can_establish_ticket_eligibility(
    ordinary_net_reliable: bool,
    expected_likelihood: Decimal,
    expected_role: TicketRole,
) -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="客户名称",
                ),
            ),
        ),
    )
    untrusted = TemplateRoleInput(
        image_sha256="7" * 64,
        text_lines=(
            ObservedTextLine(
                text="客户名称",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
        ),
        fixed_text=("客户名称",),
    )
    role_input = _ocr_authorized_role_input(
        untrusted,
        ordinary_net_reliable=ordinary_net_reliable,
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.ticket_likelihood == expected_likelihood
    assert result.observation.evidence[0].loading_score == 0
    assert result.assessment.role is expected_role


def test_reference_text_survives_crop_translation_with_an_independent_role_line() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="客户名称",
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="6" * 64,
        text_lines=(
            ObservedTextLine(
                text="客户名称",
                confidence=Decimal("0.98"),
                box=_rect("0.62", "0.72", "0.18", "0.06"),
            ),
            ObservedTextLine(
                text="装货",
                confidence=Decimal("0.96"),
                box=_rect("0.05", "0.90", "0.10", "0.04"),
            ),
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.97"),
                box=_rect("0.70", "0.80", "0.10", "0.04"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.74", "0.86", "0.10", "0.04"),
            ),
        ),
        fixed_text=("客户名称", "装货", "磅单", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    fixed_text = result.observation.evidence[0]
    assert fixed_text.loading_score == Decimal(1)
    assert "loading:客户名称" not in fixed_text.matched_ids
    assert "loading:装货" in fixed_text.matched_ids
    assert result.observation.evidence[1].loading_score >= Decimal("0.85")
    assert result.assessment.role is TicketRole.LOADING


def test_translated_reference_text_cannot_duplicate_the_fixed_text_source() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="客户名称",
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="b" * 64,
        text_lines=(
            ObservedTextLine(
                text="客户名称",
                confidence=Decimal("0.98"),
                box=_rect("0.62", "0.72", "0.18", "0.06"),
            ),
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.97"),
                box=_rect("0.70", "0.80", "0.10", "0.04"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.74", "0.86", "0.10", "0.04"),
            ),
        ),
        fixed_text=("客户名称", "磅单", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.evidence[0].loading_score == 0
    assert result.observation.evidence[1].loading_score >= Decimal("0.85")
    assert result.observation.evidence[2].loading_score == 0
    assert result.assessment.role is TicketRole.UNKNOWN


def test_translated_reference_text_below_confidence_gate_remains_unknown() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="客户名称",
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="7" * 64,
        text_lines=(
            ObservedTextLine(
                text="客户名称",
                confidence=Decimal("0.50"),
                box=_rect("0.62", "0.72", "0.18", "0.06"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.74", "0.86", "0.10", "0.04"),
            ),
        ),
        fixed_text=("客户名称", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.evidence[1].loading_score < Decimal("0.60")
    assert result.assessment.role is TicketRole.UNKNOWN


def test_negated_save_success_does_not_match_the_positive_contains_anchor() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="保存成功",
                    match_kind=AnchorMatchKind.CONTAINS,
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="c" * 64,
        text_lines=(
            ObservedTextLine(
                text="未保存成功",
                confidence=Decimal("0.99"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.97"),
                box=_rect("0.10", "0.62", "0.14", "0.07"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.25", "0.62", "0.14", "0.07"),
            ),
        ),
        fixed_text=("未保存成功", "磅单", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.evidence[0].loading_score == 0
    assert result.observation.evidence[1].loading_score == 0
    assert result.assessment.role is TicketRole.UNKNOWN


def test_loading_term_does_not_match_inside_unloading() -> None:
    unloading_template = _version(TicketRole.UNLOADING, "unloading")
    unloading_template = replace(
        unloading_template,
        definition=replace(
            unloading_template.definition,
            anchors=(
                replace(
                    unloading_template.definition.anchors[0],
                    expected_text="unloading",
                    match_kind=AnchorMatchKind.CONTAINS,
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="d" * 64,
        text_lines=(
            ObservedTextLine(
                text="unloading",
                confidence=Decimal("0.99"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="ticket",
                confidence=Decimal("0.98"),
                box=_rect("0.10", "0.62", "0.14", "0.07"),
            ),
            ObservedTextLine(
                text="net",
                confidence=Decimal("0.98"),
                box=_rect("0.25", "0.62", "0.14", "0.07"),
            ),
        ),
        fixed_text=("unloading", "ticket", "net"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(unloading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )
    fixed_text = result.observation.evidence[0]

    assert fixed_text.loading_score == 0
    assert "loading:loading" not in fixed_text.matched_ids
    assert result.assessment.role is TicketRole.UNLOADING


def test_orientation_alignment_uses_only_the_line_matching_the_anchor_text() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="客户名称",
                ),
            ),
        ),
    )
    rotated = _rotate(_rect("0.10", "0.08", "0.30", "0.08"), 90)
    translated_rotated = _rect(
        str(rotated.x + Decimal("0.04")),
        str(rotated.y + Decimal("0.03")),
        str(rotated.width),
        str(rotated.height),
    )
    role_input = TemplateRoleInput(
        image_sha256="e" * 64,
        text_lines=(
            ObservedTextLine(
                text="客户名称",
                confidence=Decimal("0.98"),
                box=translated_rotated,
            ),
            ObservedTextLine(
                text="无关文字",
                confidence=Decimal("0.99"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.97"),
                box=_rect("0.60", "0.72", "0.10", "0.04"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.72", "0.72", "0.10", "0.04"),
            ),
        ),
        fixed_text=("客户名称", "无关文字", "磅单", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.orientation_degrees == 90
    assert result.observation.evidence[2].loading_score > Decimal("0.60")
    assert result.assessment.role is TicketRole.LOADING


def test_far_translated_anchor_is_unknown_despite_unrelated_text_at_the_old_position() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="客户名称",
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="f" * 64,
        text_lines=(
            ObservedTextLine(
                text="客户名称",
                confidence=Decimal("0.98"),
                box=_rect("0.62", "0.72", "0.18", "0.06"),
            ),
            ObservedTextLine(
                text="无关文字",
                confidence=Decimal("0.99"),
                box=_rect("0.10", "0.08", "0.30", "0.08"),
            ),
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.97"),
                box=_rect("0.70", "0.80", "0.10", "0.04"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.74", "0.86", "0.10", "0.04"),
            ),
        ),
        fixed_text=("客户名称", "无关文字", "磅单", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.evidence[0].loading_score == 0
    assert result.observation.evidence[2].loading_score == 0
    assert result.assessment.role is TicketRole.UNKNOWN


def test_layout_cannot_conflict_without_its_template_reference_text() -> None:
    loading_template = _version(TicketRole.LOADING, "loading")
    loading_template = replace(
        loading_template,
        definition=replace(
            loading_template.definition,
            anchors=(
                replace(
                    loading_template.definition.anchors[0],
                    expected_text="客户名称",
                ),
            ),
        ),
    )
    unloading_template = _version(TicketRole.UNLOADING, "unloading")
    unloading_template = replace(
        unloading_template,
        definition=replace(
            unloading_template.definition,
            anchors=(
                replace(
                    unloading_template.definition.anchors[0],
                    expected_text="工厂净重",
                    box=_rect("0.62", "0.72", "0.18", "0.06"),
                ),
            ),
        ),
    )
    role_input = TemplateRoleInput(
        image_sha256="8" * 64,
        text_lines=(
            ObservedTextLine(
                text="客户名称",
                confidence=Decimal("0.98"),
                box=_rect("0.62", "0.72", "0.18", "0.06"),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=_rect("0.74", "0.86", "0.10", "0.04"),
            ),
        ),
        fixed_text=("客户名称", "净重"),
    )

    result = match_ticket_role_for_development_evaluation(
        role_input,
        candidates=(
            replace(loading_template, lifecycle=TemplateLifecycle.DRAFT),
            replace(unloading_template, lifecycle=TemplateLifecycle.DRAFT),
        ),
        current_shadow=(),
        policy=_policy(),
    )

    assert result.observation.evidence[2].unloading_score == 0
    assert result.assessment.role is TicketRole.UNKNOWN


def test_template_source_with_bidirectional_anchor_evidence_fails_safe() -> None:
    loading = _version(TicketRole.LOADING, "loading")
    conflicting = replace(
        loading,
        definition=replace(
            loading.definition,
            anchors=tuple(
                replace(
                    anchor,
                    loading_evidence=Decimal("0.9"),
                    unloading_evidence=Decimal("0.9"),
                )
                for anchor in loading.definition.anchors
            ),
        ),
    )

    result = match_ticket_role(
        _input(TicketRole.LOADING),
        (conflicting,),
        _policy(),
    )

    assert result.observation.evidence[1].loading_score >= Decimal("0.8")
    assert result.observation.evidence[1].unloading_score >= Decimal("0.8")
    assert result.assessment.role is TicketRole.UNKNOWN
    assert result.assessment.high_confidence is False


def test_anchor_direction_and_weight_override_family_role_bucket() -> None:
    unloading_family = _version(TicketRole.UNLOADING, "weighted")
    loading_title = replace(
        unloading_family.definition.anchors[0],
        expected_text="装货磅单",
        weight=Decimal("1"),
        loading_evidence=Decimal("0.9"),
        unloading_evidence=Decimal("-0.9"),
    )
    weak_unloading_net = replace(
        unloading_family.definition.anchors[1],
        expected_text="净重",
        weight=Decimal("0.1"),
        loading_evidence=Decimal("-0.9"),
        unloading_evidence=Decimal("0.9"),
    )
    weighted = replace(
        unloading_family,
        definition=replace(
            unloading_family.definition,
            anchors=(loading_title, weak_unloading_net),
        ),
    )

    result = match_ticket_role(
        _input(TicketRole.LOADING),
        (weighted,),
        _policy(),
    )
    template_evidence = result.observation.evidence[1]

    assert weighted.definition.role is TicketRole.UNLOADING
    assert template_evidence.loading_score >= Decimal("0.7")
    assert template_evidence.unloading_score < Decimal("0.2")
    assert result.assessment.role is TicketRole.LOADING


def test_template_set_fingerprint_is_order_independent_and_rejects_non_shadow() -> None:
    loading = _version(TicketRole.LOADING, "loading")
    unloading = _version(TicketRole.UNLOADING, "unloading")

    first = build_template_set_fingerprint((loading, unloading))
    second = build_template_set_fingerprint((unloading, loading))

    assert first == second
    assert len(first) == 64
    with pytest.raises(ValueError, match="shadow"):
        build_template_set_fingerprint(
            (
                TemplateVersion(
                    version_id=loading.version_id,
                    definition=loading.definition,
                    lifecycle=TemplateLifecycle.DRAFT,
                    parent_version_id=None,
                    record_version=1,
                ),
            )
        )
    duplicate_family = replace(
        loading,
        version_id="loading-v2",
        version_number=2,
    )
    with pytest.raises(ValueError, match="unique family"):
        build_template_set_fingerprint((loading, duplicate_family))
    with pytest.raises(ValueError, match="unique family"):
        match_ticket_role(
            _input(TicketRole.LOADING),
            (loading, duplicate_family),
            _policy(),
        )


def test_matcher_v5_invalidates_v4_template_set_fingerprints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    versions = (
        _version(TicketRole.LOADING, "loading"),
        _version(TicketRole.UNLOADING, "unloading"),
    )
    current = build_template_set_fingerprint(versions)

    assert MATCHER_VERSION == "loop7-template-matcher-v5"
    monkeypatch.setattr(
        matcher_module,
        "MATCHER_VERSION",
        "loop7-template-matcher-v4",
    )
    assert build_template_set_fingerprint(versions) != current


def test_development_evaluation_accepts_candidates_without_weakening_shadow_matching() -> None:
    loading_shadow = _version(TicketRole.LOADING, "loading")
    unloading_shadow = _version(TicketRole.UNLOADING, "unloading")
    loading_candidate = replace(
        loading_shadow,
        version_id="loading-candidate-v2",
        lifecycle=TemplateLifecycle.DRAFT,
        parent_version_id=loading_shadow.version_id,
        record_version=1,
        version_number=2,
    )

    with pytest.raises(ValueError, match="shadow"):
        match_ticket_role(
            _input(TicketRole.LOADING),
            (loading_candidate, unloading_shadow),
            _policy(),
        )

    evaluation = match_ticket_role_for_development_evaluation(
        _input(TicketRole.LOADING),
        candidates=(loading_candidate,),
        current_shadow=(loading_shadow, unloading_shadow),
        policy=_policy(),
    )
    selected = build_development_evaluation_template_set(
        candidates=(loading_candidate,),
        current_shadow=(loading_shadow, unloading_shadow),
    )

    assert evaluation.assessment.role is TicketRole.LOADING
    assert evaluation.template_set_fingerprint == selected.fingerprint
    assert tuple(version.version_id for version in selected.versions) == (
        "loading-candidate-v2",
        "unloading-v1",
    )
    assert selected.fingerprint != build_template_set_fingerprint(
        (loading_shadow, unloading_shadow)
    )


def test_development_evaluation_fingerprint_captures_lifecycle_and_rejects_bad_sets() -> None:
    loading_shadow = _version(TicketRole.LOADING, "loading")
    loading_draft = replace(
        loading_shadow,
        version_id="loading-candidate-v2",
        lifecycle=TemplateLifecycle.DRAFT,
        record_version=1,
        version_number=2,
    )
    loading_tested = replace(
        loading_draft,
        lifecycle=TemplateLifecycle.DEVELOPMENT_TESTED,
        record_version=2,
    )

    draft_set = build_development_evaluation_template_set(
        candidates=(loading_draft,),
        current_shadow=(),
    )
    tested_set = build_development_evaluation_template_set(
        candidates=(loading_tested,),
        current_shadow=(),
    )

    assert draft_set.fingerprint != tested_set.fingerprint
    with pytest.raises(ValueError, match="candidate"):
        build_development_evaluation_template_set(
            candidates=(loading_shadow,),
            current_shadow=(),
        )
    with pytest.raises(ValueError, match="unique family"):
        build_development_evaluation_template_set(
            candidates=(loading_draft, loading_tested),
            current_shadow=(),
        )
    with pytest.raises(ValueError, match="shadow"):
        build_development_evaluation_template_set(
            candidates=(loading_draft,),
            current_shadow=(loading_draft,),
        )
