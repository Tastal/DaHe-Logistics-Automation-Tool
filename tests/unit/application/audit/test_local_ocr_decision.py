from __future__ import annotations

import json
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
from dahe.application.audit.local_ocr_decision import LocalOcrAuditEvaluator
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.role_assessment import RoleAssessmentPolicy
from dahe.domain.ticket.templates import (
    NormalizedRect,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
)
from dahe.jobs.audit_execution import (
    LocalAuditEvaluationInput,
    LocalAuditTechnicalError,
)

LOADING_SHA = "1" * 64
UNLOADING_SHA = "2" * 64
RUNTIME_SHA = "3" * 64
PIPELINE_SHA = "4" * 64


def _rect(x: str, y: str, width: str, height: str) -> NormalizedRect:
    return NormalizedRect(
        x=Decimal(x),
        y=Decimal(y),
        width=Decimal(width),
        height=Decimal(height),
    )


def _title(role: TicketRole) -> str:
    return (
        "alpha coal inbound loading slip"
        if role is TicketRole.LOADING
        else "zulu quarry unloading scale receipt"
    )


def _template(role: TicketRole) -> TemplateVersion:
    marker = role.value
    title = _title(role)
    return TemplateVersion(
        version_id=f"{marker}-v1",
        definition=TemplateDefinition(
            family_id=f"{marker}-family",
            name=title,
            role=role,
            anchors=(
                TemplateAnchor(
                    anchor_id=f"{marker}-title",
                    expected_text=title,
                    box=_rect("0.10", "0.08", "0.30", "0.08"),
                    required=True,
                    weight=Decimal("1"),
                    max_edit_distance=Decimal("0.10"),
                    loading_evidence=(
                        Decimal("0.9")
                        if role is TicketRole.LOADING
                        else Decimal("-0.4")
                    ),
                    unloading_evidence=(
                        Decimal("0.9")
                        if role is TicketRole.UNLOADING
                        else Decimal("-0.4")
                    ),
                ),
            ),
            regions=(),
        ),
        lifecycle=TemplateLifecycle.SHADOW,
        parent_version_id=None,
        record_version=3,
    )


def _result(
    *,
    image_sha256: str,
    role: TicketRole,
    amount: str,
) -> str:
    title = _title(role)
    result = OcrResult(
        command_id=f"{role.value}-command",
        status=OcrResultStatus.OK,
        worker_identity="local-audit-test-worker",
        runtime_fingerprint=RUNTIME_SHA,
        verified_image_sha256=image_sha256,
        elapsed_ms=1,
        text_lines=(
            OcrTextLine(
                text=title,
                confidence=Decimal("0.99"),
                box=NormalizedBox(
                    x=Decimal("0.10"),
                    y=Decimal("0.08"),
                    width=Decimal("0.30"),
                    height=Decimal("0.08"),
                ),
            ),
            OcrTextLine(
                text=role.value,
                confidence=Decimal("0.99"),
                box=NormalizedBox(
                    x=Decimal("0.60"),
                    y=Decimal("0.60"),
                    width=Decimal("0.20"),
                    height=Decimal("0.08"),
                ),
            ),
        ),
        fields={
            "ordinary_net": OcrFieldValue(
                raw_text=f"{amount} t",
                amount=amount,
                unit="t",
                confidence=Decimal("0.99"),
            )
        },
        role_observation=OcrRoleObservation(
            fixed_text=(role.value, "ticket", "net"),
            layout_fingerprint=f"{role.value}-layout",
            orientation_degrees=0,
        ),
        error=None,
    )
    return result.model_dump_json()


def _input(
    *,
    loading_amount: str = "30.10",
    unloading_amount: str = "29.90",
    loading_output_json: str | None = None,
) -> LocalAuditEvaluationInput:
    return LocalAuditEvaluationInput(
        work_item_id="work-item-001",
        snapshot_id="snapshot-001",
        loading_image_sha256=LOADING_SHA,
        unloading_image_sha256=UNLOADING_SHA,
        platform_loading_net="30.10",
        platform_unloading_net="29.90",
        pipeline_fingerprint=PIPELINE_SHA,
        runtime_fingerprint=RUNTIME_SHA,
        loading_output_json=loading_output_json
        or _result(
            image_sha256=LOADING_SHA,
            role=TicketRole.LOADING,
            amount=loading_amount,
        ),
        unloading_output_json=_result(
            image_sha256=UNLOADING_SHA,
            role=TicketRole.UNLOADING,
            amount=unloading_amount,
        ),
    )


def _evaluator() -> LocalOcrAuditEvaluator:
    return LocalOcrAuditEvaluator(
        templates=(
            _template(TicketRole.LOADING),
            _template(TicketRole.UNLOADING),
        ),
        role_policy=RoleAssessmentPolicy(
            minimum_score=Decimal("0.60"),
            minimum_margin=Decimal("0.25"),
            minimum_sources=2,
            minimum_ticket_likelihood=Decimal("0.60"),
            high_confidence_score=Decimal("0.85"),
            version="local-audit-test-policy-v1",
        ),
    )


def test_local_ocr_evaluator_uses_existing_domain_contract_for_pass() -> None:
    result = _evaluator().evaluate(_input())

    assert result.business_outcome == "normal_ready"
    assert result.decision == "pass"
    assert result.review_reason is None
    assert result.ticket_loading_net == "30.10"
    assert result.ticket_unloading_net == "29.90"


def test_local_ocr_evaluator_projects_bounded_machine_role_evidence() -> None:
    projection = _evaluator().project_observation(
        output_json=_result(
            image_sha256=LOADING_SHA,
            role=TicketRole.LOADING,
            amount="30.10",
        ),
        expected_image_sha256=LOADING_SHA,
        expected_runtime_fingerprint=RUNTIME_SHA,
    )

    assert projection.ticket_role == "loading"
    assert projection.role_quality == "reliable"
    assert projection.role_high_confidence is True
    assert projection.ordinary_net_amount == "30.10"
    assert projection.ordinary_net_unit == "t"
    assert projection.ordinary_net_reliable is True
    assert len(projection.role_fingerprint) == 64
    assert len(projection.template_set_fingerprint) == 64


def test_local_ocr_evaluator_keeps_suspicious_four_digit_value_for_review() -> None:
    result = _evaluator().evaluate(_input(loading_amount="3270"))

    assert result.business_outcome == "awaiting_review"
    assert result.decision == "review"
    assert result.review_reason == "ticket_weight_format_suspicious"
    assert result.ticket_loading_net == "3270"


def test_local_ocr_evaluator_treats_protocol_corruption_as_technical_failure() -> None:
    invalid = json.dumps({"status": "ok"})

    with pytest.raises(
        LocalAuditTechnicalError,
        match="OCR result",
    ) as failure:
        _evaluator().evaluate(_input(loading_output_json=invalid))

    assert failure.value.diagnostic_code == "AUDIT-OCR-EVIDENCE-INVALID"
