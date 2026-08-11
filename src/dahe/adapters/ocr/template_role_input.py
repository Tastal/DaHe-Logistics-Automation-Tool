from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from dahe.adapters.ocr.protocol import OcrResult, OcrResultStatus
from dahe.application.template_studio.matcher import (
    ObservedTextLine,
    TemplateRoleInput,
)
from dahe.domain.ticket.templates import NormalizedRect


class OcrRoleInputError(ValueError):
    """Raised when an OCR v1 result cannot safely become role-matcher input."""


def ordinary_net_review_reason_from_ocr_v1(
    result: OcrResult,
) -> str | None:
    """Return a review reason without repairing the OCR amount."""

    field = result.fields.get("ordinary_net")
    if (
        field is not None
        and field.amount is not None
        and field.unit is not None
        and field.unit.strip().lower() == "t"
        and re.fullmatch(r"[0-9]{4,}", field.amount.strip()) is not None
    ):
        return "ticket_weight_format_suspicious"
    return None


def _ordinary_net_is_reliable(result: OcrResult) -> bool:
    field = result.fields.get("ordinary_net")
    if field is None or field.amount is None or field.unit is None:
        return False
    try:
        amount = Decimal(field.amount)
    except InvalidOperation:
        return False
    if (
        not amount.is_finite()
        or amount <= 0
        or field.unit.strip().lower() != "t"
        or ordinary_net_review_reason_from_ocr_v1(result) is not None
    ):
        return False
    try:
        return amount == amount.quantize(Decimal("0.01"))
    except InvalidOperation:
        return False


def template_role_input_from_ocr_v1(
    result: OcrResult,
) -> TemplateRoleInput:
    """Translate accepted independent image OCR evidence without business context."""

    if not isinstance(result, OcrResult):
        raise OcrRoleInputError("role matching requires an accepted OCR v1 result")
    if result.status is not OcrResultStatus.OK:
        raise OcrRoleInputError("role matching requires a successful OCR v1 result")
    if result.protocol_version != 1:
        raise OcrRoleInputError("role matching supports OCR protocol version 1")
    if result.verified_image_sha256 is None:
        raise OcrRoleInputError("role matching requires verified image identity")

    lines = tuple(
        ObservedTextLine(
            text=line.text,
            confidence=line.confidence,
            box=NormalizedRect(
                x=line.box.x,
                y=line.box.y,
                width=line.box.width,
                height=line.box.height,
            ),
        )
        for line in result.text_lines
    )
    fixed_text = (
        ()
        if result.role_observation is None
        else tuple(result.role_observation.fixed_text)
    )
    return TemplateRoleInput(
        image_sha256=result.verified_image_sha256,
        text_lines=lines,
        fixed_text=fixed_text,
    )._with_authoritative_ordinary_net(
        reliable=_ordinary_net_is_reliable(result),
    )
