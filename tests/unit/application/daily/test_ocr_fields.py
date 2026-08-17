from __future__ import annotations

import hashlib
import json
from decimal import Decimal

import pytest

from dahe.application.daily.ocr_fields import extract_ordinary_net_tonnes

IMAGE_SHA256 = hashlib.sha256(b"daily-ocr-field-image").hexdigest()
RUNTIME_SHA256 = hashlib.sha256(b"daily-ocr-field-runtime").hexdigest()


def _result(
    *,
    amount: str = "33.36",
    unit: str = "t",
    image_sha256: str = IMAGE_SHA256,
    gross: str | None = None,
    tare: str | None = None,
    factory_net: str | None = None,
    text_lines: list[dict[str, object]] | None = None,
) -> str:
    fields = {
        "ordinary_net": {
            "raw_text": f"净重 {amount} {unit}",
            "amount": amount,
            "unit": unit,
            "confidence": "0.99",
        }
    }
    for name, value in (
        ("gross", gross),
        ("tare", tare),
        ("factory_net", factory_net),
    ):
        if value is not None:
            fields[name] = {
                "raw_text": value,
                "amount": value,
                "unit": unit,
                "confidence": "0.99",
            }
    return json.dumps(
        {
            "protocol_version": 1,
            "command_id": "daily-ocr-field",
            "status": "ok",
            "worker_identity": "daily-test-worker",
            "runtime_fingerprint": RUNTIME_SHA256,
            "verified_image_sha256": image_sha256,
            "elapsed_ms": 1.0,
            "text_lines": text_lines or [],
            "fields": fields,
            "role_observation": None,
            "error": None,
        },
        ensure_ascii=False,
    )


def test_extracts_qualified_ordinary_net_for_the_current_image() -> None:
    assert extract_ordinary_net_tonnes(
        _result(),
        expected_image_sha256=IMAGE_SHA256,
    ) == Decimal("33.36")


def test_derives_net_from_independent_gross_and_tare_when_net_is_missing() -> None:
    payload = json.loads(_result(gross="48.70", tare="15.92"))
    del payload["fields"]["ordinary_net"]
    assert extract_ordinary_net_tonnes(
        json.dumps(payload, ensure_ascii=False),
        expected_image_sha256=IMAGE_SHA256,
    ) == Decimal("32.78")


def test_rejects_an_unexplained_weight_conflict() -> None:
    assert (
        extract_ordinary_net_tonnes(
            _result(amount="33.38", gross="48.68", tare="15.18"),
            expected_image_sha256=IMAGE_SHA256,
        )
        is None
    )


def test_replaces_factory_net_contamination_with_gross_minus_tare() -> None:
    assert extract_ordinary_net_tonnes(
        _result(
            amount="33.38",
            gross="48.68",
            tare="15.18",
            factory_net="33.38",
        ),
        expected_image_sha256=IMAGE_SHA256,
    ) == Decimal("33.50")


def test_keeps_a_distinct_ordinary_net_when_factory_net_confirms_separate_roles() -> None:
    assert extract_ordinary_net_tonnes(
        _result(
            amount="32.48",
            gross="43.68",
            tare="16.20",
            factory_net="32.38",
        ),
        expected_image_sha256=IMAGE_SHA256,
    ) == Decimal("32.48")


def test_ignores_an_out_of_range_gross_value_instead_of_rejecting_net() -> None:
    assert extract_ordinary_net_tonnes(
        _result(amount="33.64", gross="560", tare="15.06"),
        expected_image_sha256=IMAGE_SHA256,
    ) == Decimal("33.64")


def test_uses_gross_minus_tare_when_the_net_text_is_malformed() -> None:
    assert extract_ordinary_net_tonnes(
        _result(amount="3298", gross="48.62", tare="15.64"),
        expected_image_sha256=IMAGE_SHA256,
    ) == Decimal("32.98")


def test_recovers_standard_unloading_weights_from_the_right_value_column() -> None:
    def line(text: str, *, x: str, y: str) -> dict[str, object]:
        return {
            "text": text,
            "confidence": "0.99",
            "box": {
                "x": x,
                "y": y,
                "width": "0.05",
                "height": "0.03",
            },
        }

    lines = [
        line("毛重", x="0.40", y="0.30"),
        line("48.68", x="0.65", y="0.31"),
        line("皮重", x="0.40", y="0.35"),
        line("15.18", x="0.65", y="0.36"),
        line("净重", x="0.40", y="0.40"),
        line("33.50", x="0.65", y="0.41"),
        line("工厂净重", x="0.40", y="0.45"),
        line("33.38", x="0.65", y="0.46"),
    ]
    assert extract_ordinary_net_tonnes(
        _result(
            amount="33.38",
            gross="15.18",
            factory_net="33.38",
            text_lines=lines,
        ),
        expected_image_sha256=IMAGE_SHA256,
    ) == Decimal("33.50")


@pytest.mark.parametrize(
    "lines",
    [
        [
            ("毛重", "0.40", "0.30"),
            ("48.68", "0.65", "0.31"),
            ("皮重", "0.40", "0.35"),
            ("15.18", "0.65", "0.36"),
            ("净重", "0.40", "0.40"),
            ("33.40", "0.65", "0.41"),
            ("工厂净重", "0.40", "0.45"),
            ("33.38", "0.65", "0.46"),
        ],
        [
            ("毛重", "0.40", "0.30"),
            ("48.68", "0.65", "0.31"),
            ("皮重", "0.40", "0.35"),
            ("15.18", "0.65", "0.36"),
            ("净重", "0.40", "0.40"),
            ("33.50", "0.65", "0.41"),
        ],
    ],
)
def test_rejects_an_incomplete_or_inconsistent_standard_weight_column(
    lines: list[tuple[str, str, str]],
) -> None:
    text_lines = [
        {
            "text": text,
            "confidence": "0.99",
            "box": {"x": x, "y": y, "width": "0.05", "height": "0.03"},
        }
        for text, x, y in lines
    ]
    assert (
        extract_ordinary_net_tonnes(
            _result(
                amount="33.38",
                gross="15.18",
                factory_net="33.38",
                text_lines=text_lines,
            ),
            expected_image_sha256=IMAGE_SHA256,
        )
        == Decimal("33.38")
    )


@pytest.mark.parametrize(
    ("output", "expected_sha256"),
    [
        (_result(image_sha256=hashlib.sha256(b"old").hexdigest()), IMAGE_SHA256),
        (_result(amount="3336"), IMAGE_SHA256),
        (_result(amount="33.361"), IMAGE_SHA256),
        (_result(unit="kg"), IMAGE_SHA256),
        (None, IMAGE_SHA256),
        (_result(), None),
    ],
)
def test_rejects_unqualified_or_stale_ordinary_net(
    output: str | None,
    expected_sha256: str | None,
) -> None:
    assert extract_ordinary_net_tonnes(
        output,
        expected_image_sha256=expected_sha256,
    ) is None
