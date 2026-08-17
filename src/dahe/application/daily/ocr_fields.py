from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from pydantic import ValidationError

from dahe.adapters.ocr.protocol import OcrResult, OcrResultStatus, OcrTextLine
from dahe.adapters.ocr.template_role_input import (
    ordinary_net_review_reason_from_ocr_v1,
)

_TONNE_QUANTUM = Decimal("0.01")
_MAX_PLAUSIBLE_TONNES = Decimal("100.00")


def extract_ordinary_net_tonnes(
    output_json: str | None,
    *,
    expected_image_sha256: str | None,
) -> Decimal | None:
    """Project a bounded OCR ordinary-net value for the current ticket image."""

    if not output_json or expected_image_sha256 is None:
        return None
    try:
        result = OcrResult.model_validate_json(output_json)
    except (ValidationError, ValueError):
        return None
    if (
        result.status is not OcrResultStatus.OK
        or result.verified_image_sha256 != expected_image_sha256
    ):
        return None

    spatial_ordinary = _standard_unloading_ordinary_net(result)
    if spatial_ordinary is not None:
        return spatial_ordinary

    ordinary = _qualified_tonnes(result, "ordinary_net")
    if ordinary_net_review_reason_from_ocr_v1(result) is not None:
        ordinary = None
    gross = _qualified_tonnes(result, "gross")
    tare = _qualified_tonnes(result, "tare")
    derived = _derived_net_tonnes(gross=gross, tare=tare)

    if ordinary is None:
        return derived
    if derived is None or derived == ordinary:
        return ordinary

    # Some unloading templates expose the factory net in the ordinary-net slot.
    # Gross minus tare is independent evidence and may replace that duplicated
    # template value.  Any other disagreement remains a human-review item.
    factory = _qualified_tonnes(result, "factory_net")
    if factory == ordinary:
        return derived
    if factory is not None:
        return ordinary
    return None


def _qualified_tonnes(result: OcrResult, field_name: str) -> Decimal | None:
    field = result.fields.get(field_name)
    if field is None or field.amount is None or field.unit is None:
        return None
    if field.unit.strip().lower() != "t":
        return None
    try:
        amount = Decimal(field.amount)
    except InvalidOperation:
        return None
    if (
        not amount.is_finite()
        or amount <= 0
        or amount > _MAX_PLAUSIBLE_TONNES
    ):
        return None
    try:
        if amount != amount.quantize(_TONNE_QUANTUM):
            return None
    except InvalidOperation:
        return None
    return amount


def _derived_net_tonnes(
    *,
    gross: Decimal | None,
    tare: Decimal | None,
) -> Decimal | None:
    if gross is None or tare is None or gross <= tare:
        return None
    try:
        derived = (gross - tare).quantize(_TONNE_QUANTUM)
    except InvalidOperation:
        return None
    return derived if derived > 0 else None


_STANDARD_UNLOADING_LABELS = ("毛重", "皮重", "净重", "工厂净重")
_DECIMAL_LINE = re.compile(r"^\s*(\d{1,2}\.\d{1,2})\s*(?:t|吨)?\s*$", re.IGNORECASE)


def _standard_unloading_ordinary_net(result: OcrResult) -> Decimal | None:
    """Read the right value column of a complete standard unloading table.

    This is intentionally stricter than the general field mapper: all four
    labels must be present, the four values must form one right-hand column,
    and gross minus tare must exactly equal the ordinary net.  That prevents a
    visually unrelated number on a non-standard ticket from becoming a
    business weight.
    """

    labels: dict[str, OcrTextLine] = {}
    for line in result.text_lines:
        normalized = _normalize_label(line.text)
        if normalized in _STANDARD_UNLOADING_LABELS:
            if normalized in labels:
                return None
            labels[normalized] = line
    if set(labels) != set(_STANDARD_UNLOADING_LABELS):
        return None

    label_lines = [labels[label] for label in _STANDARD_UNLOADING_LABELS]
    label_right = max(line.box.x + line.box.width for line in label_lines)
    min_y = min(line.box.y for line in label_lines) - Decimal("0.08")
    max_y = max(line.box.y + line.box.height for line in label_lines) + Decimal("0.08")

    values: list[tuple[Decimal, Decimal]] = []
    for line in result.text_lines:
        match = _DECIMAL_LINE.fullmatch(line.text)
        if match is None or line.box.x <= label_right + Decimal("0.03"):
            continue
        if line.box.y < min_y or line.box.y > max_y:
            continue
        try:
            amount = Decimal(match.group(1))
        except InvalidOperation:
            return None
        if amount <= 0 or amount > _MAX_PLAUSIBLE_TONNES:
            return None
        values.append((line.box.y, amount))

    if len(values) != 4:
        return None
    values.sort(key=lambda item: item[0])
    gross, tare, ordinary, factory = (amount for _, amount in values)
    if len({y for y, _ in values}) != 4:
        return None
    derived = _derived_net_tonnes(gross=gross, tare=tare)
    if derived is None or derived != ordinary:
        return None
    if factory >= gross:
        return None
    return ordinary


def _normalize_label(text: str) -> str:
    return re.sub(r"[\s:\uFF1A]", "", text)
