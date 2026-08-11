from __future__ import annotations

import inspect
from decimal import Decimal

import pytest

from dahe.adapters.ocr.protocol import (
    NormalizedBox,
    OcrFieldValue,
    OcrResult,
    OcrResultStatus,
    OcrRoleObservation,
    OcrTextLine,
    OcrWorkerError,
)
from dahe.adapters.ocr.template_role_input import (
    OcrRoleInputError,
    ordinary_net_review_reason_from_ocr_v1,
    template_role_input_from_ocr_v1,
)
from dahe.application.template_studio.matcher import TemplateRoleInput

IMAGE_SHA256 = "1" * 64
RUNTIME_SHA256 = "2" * 64


def _successful_result(
    *,
    image_sha256: str | None = IMAGE_SHA256,
    field_amount: str = "30.00",
    role_observation: OcrRoleObservation | None = None,
) -> OcrResult:
    return OcrResult(
        protocol_version=1,
        command_id="accepted-ocr-v1",
        status=OcrResultStatus.OK,
        worker_identity="synthetic-worker",
        runtime_fingerprint=RUNTIME_SHA256,
        verified_image_sha256=image_sha256,
        elapsed_ms=12.5,
        text_lines=(
            OcrTextLine(
                text="装货磅单",
                confidence=Decimal("0.98"),
                box=NormalizedBox(
                    x=Decimal("0.10"),
                    y=Decimal("0.08"),
                    width=Decimal("0.30"),
                    height=Decimal("0.08"),
                ),
            ),
            OcrTextLine(
                text="净重 30.00 t",
                confidence=Decimal("0.96"),
                box=NormalizedBox(
                    x=Decimal("0.10"),
                    y=Decimal("0.62"),
                    width=Decimal("0.30"),
                    height=Decimal("0.08"),
                ),
            ),
        ),
        fields={
            "ordinary_net": OcrFieldValue(
                raw_text=f"净重 {field_amount} t",
                amount=field_amount,
                unit="t",
                confidence=Decimal("0.96"),
            )
        },
        role_observation=role_observation
        or OcrRoleObservation(
            fixed_text=("装货", "磅单", "净重"),
            layout_fingerprint="synthetic-layout-v1",
            orientation_degrees=0,
        ),
        error=None,
    )


def test_bridge_accepts_only_an_independent_ocr_result() -> None:
    assert set(inspect.signature(template_role_input_from_ocr_v1).parameters) == {
        "result"
    }


def test_bridge_preserves_image_text_confidence_boxes_and_fixed_text() -> None:
    role_input = template_role_input_from_ocr_v1(_successful_result())

    assert role_input.image_sha256 == IMAGE_SHA256
    assert role_input.ordinary_net_reliable is True
    assert role_input.fixed_text == ("装货", "磅单", "净重")
    assert tuple(line.text for line in role_input.text_lines) == (
        "装货磅单",
        "净重 30.00 t",
    )
    assert role_input.text_lines[0].confidence == Decimal("0.98")
    assert role_input.text_lines[0].box.x == Decimal("0.10")
    assert role_input.text_lines[0].box.y == Decimal("0.08")
    assert role_input.text_lines[0].box.width == Decimal("0.30")
    assert role_input.text_lines[0].box.height == Decimal("0.08")


def test_bridge_uses_only_the_reliability_of_extracted_weight_fields_for_role_input() -> None:
    first = template_role_input_from_ocr_v1(
        _successful_result(field_amount="30.00")
    )
    changed_weight = template_role_input_from_ocr_v1(
        _successful_result(field_amount="999.99")
    )

    assert first == changed_weight
    assert first.ordinary_net_reliable is True


@pytest.mark.parametrize(
    ("amount", "expected_reliable", "expected_reason"),
    [
        ("3270", False, "ticket_weight_format_suspicious"),
        ("12345", False, "ticket_weight_format_suspicious"),
        ("32.70", True, None),
        ("9.8", True, None),
        ("100.0", True, None),
    ],
)
def test_bridge_blocks_only_unseparated_four_digit_tonne_amounts(
    amount: str,
    expected_reliable: bool,
    expected_reason: str | None,
) -> None:
    result = _successful_result(field_amount=amount)

    role_input = template_role_input_from_ocr_v1(result)

    assert role_input.ordinary_net_reliable is expected_reliable
    assert ordinary_net_review_reason_from_ocr_v1(result) == expected_reason


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {
            "ordinary_net": OcrFieldValue(
                raw_text="净重 31250 kg",
                amount="31250",
                unit="kg",
                confidence=Decimal("0.99"),
            )
        },
        {
            "ordinary_net": OcrFieldValue(
                raw_text="净重",
                amount=None,
                unit="t",
                confidence=Decimal("0.99"),
            )
        },
        {
            "ordinary_net": OcrFieldValue(
                raw_text="净重 0.00 t",
                amount="0.00",
                unit="t",
                confidence=Decimal("0.99"),
            )
        },
        {
            "ordinary_net": OcrFieldValue(
                raw_text="净重 invalid t",
                amount="invalid",
                unit="t",
                confidence=Decimal("0.99"),
            )
        },
        {
            "ordinary_net": OcrFieldValue(
                raw_text="净重 31.251 t",
                amount="31.251",
                unit="t",
                confidence=Decimal("0.99"),
            )
        },
    ],
)
def test_bridge_rejects_unreliable_ordinary_net_business_fields(
    fields: dict[str, OcrFieldValue],
) -> None:
    result = _successful_result().model_copy(update={"fields": fields})

    role_input = template_role_input_from_ocr_v1(result)

    assert role_input.ordinary_net_reliable is False


def test_direct_role_input_callers_cannot_claim_reliable_ordinary_net() -> None:
    accepted = template_role_input_from_ocr_v1(_successful_result())
    constructor_values = {
        "fixed_text": accepted.fixed_text,
        "image_sha256": accepted.image_sha256,
        "text_lines": accepted.text_lines,
    }

    assert "ordinary_net_reliable" not in inspect.signature(TemplateRoleInput).parameters
    assert TemplateRoleInput(**constructor_values).ordinary_net_reliable is False
    with pytest.raises(TypeError, match="ordinary_net_reliable"):
        TemplateRoleInput(
            **constructor_values,
            ordinary_net_reliable=True,
        )


def test_bridge_allows_missing_role_observation_without_guessing_fixed_text() -> None:
    result = _successful_result().model_copy(
        update={"role_observation": None}
    )

    role_input = template_role_input_from_ocr_v1(result)

    assert role_input.fixed_text == ()


def test_bridge_rejects_a_success_result_without_verified_image_identity() -> None:
    with pytest.raises(OcrRoleInputError, match="image"):
        template_role_input_from_ocr_v1(
            _successful_result(image_sha256=None)
        )


def test_bridge_rejects_a_failed_ocr_result() -> None:
    failed = OcrResult(
        protocol_version=1,
        command_id="failed-ocr-v1",
        status=OcrResultStatus.ERROR,
        worker_identity="synthetic-worker",
        runtime_fingerprint=RUNTIME_SHA256,
        verified_image_sha256=IMAGE_SHA256,
        elapsed_ms=5,
        text_lines=(),
        fields={},
        role_observation=None,
        error=OcrWorkerError(
            kind="worker_crashed",
            message="Synthetic failure",
            diagnostic_code="OCR-SYNTHETIC",
        ),
    )

    with pytest.raises(OcrRoleInputError, match="successful"):
        template_role_input_from_ocr_v1(failed)
