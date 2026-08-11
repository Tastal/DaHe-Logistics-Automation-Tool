from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.weights import (
    WeightComparisonPolicy,
    WeightReading,
    WeightUnit,
    compare_weights,
    normalize_weight,
)


def policy() -> WeightComparisonPolicy:
    return WeightComparisonPolicy(
        decimal_places=2,
        rule_version="exact-two-decimal-tonnes-v1",
    )


def reading(amount: str, unit: WeightUnit = WeightUnit.TONNE) -> WeightReading:
    return WeightReading(amount=Decimal(amount), unit=unit, raw_text=f"{amount} {unit.value}")


def test_weight_reading_rejects_float_input() -> None:
    with pytest.raises(DomainContractError, match="Decimal"):
        WeightReading(amount=12.34, unit=WeightUnit.TONNE, raw_text="12.34")  # type: ignore[arg-type]


@pytest.mark.parametrize("amount", [Decimal("-0.01"), Decimal("NaN"), Decimal("Infinity")])
def test_weight_reading_rejects_invalid_amounts(amount: Decimal) -> None:
    with pytest.raises(DomainContractError):
        WeightReading(amount=amount, unit=WeightUnit.TONNE, raw_text=str(amount))


def test_weight_reading_requires_original_text() -> None:
    with pytest.raises(DomainContractError, match="raw_text"):
        WeightReading(amount=Decimal("12.34"), unit=WeightUnit.TONNE, raw_text=" ")


@given(kilograms=st.integers(min_value=0, max_value=200_000))
def test_kilograms_convert_to_exact_tonnes(kilograms: int) -> None:
    source = WeightReading(
        amount=Decimal(kilograms),
        unit=WeightUnit.KILOGRAM,
        raw_text=f"{kilograms} kg",
    )

    normalized = normalize_weight(source, policy())

    assert normalized.exact_tonnes == Decimal(kilograms) / Decimal(1000)
    assert normalized.comparison_tonnes is None
    assert normalized.source is source


def test_tonnes_are_not_scaled_during_normalization() -> None:
    normalized = normalize_weight(reading("31.256"), policy())

    assert normalized.exact_tonnes == Decimal("31.256")
    assert normalized.comparison_tonnes is None


def test_values_requiring_rounding_have_no_automatic_comparison_value() -> None:
    tonnes = normalize_weight(reading("12.345"), policy())
    kilograms = normalize_weight(
        reading("12345", WeightUnit.KILOGRAM),
        policy(),
    )

    assert tonnes.exact_tonnes == Decimal("12.345")
    assert tonnes.comparison_tonnes is None
    assert kilograms.exact_tonnes == Decimal("12.345")
    assert kilograms.comparison_tonnes is None

    huge_kilograms = normalize_weight(
        reading(
            "123456789012345678901234567891",
            WeightUnit.KILOGRAM,
        ),
        policy(),
    )
    assert (
        huge_kilograms.exact_tonnes
        == Decimal("123456789012345678901234567.891")
    )
    assert huge_kilograms.comparison_tonnes is None


def test_weight_policy_is_fixed_to_two_decimal_places() -> None:
    with pytest.raises(DomainContractError, match="two decimal"):
        WeightComparisonPolicy(
            decimal_places=3,
            rule_version="invalid-v1",
        )


def test_comparison_uses_normalized_two_decimal_values() -> None:
    result = compare_weights(
        platform=reading("12.340"),
        ticket=reading("12.34"),
        policy=policy(),
    )

    assert result.matches is True
    assert result.platform.comparison_tonnes == Decimal("12.34")
    assert result.ticket.comparison_tonnes == Decimal("12.34")
    assert result.difference_tonnes == Decimal("0.00")

    with pytest.raises(DomainContractError, match="tonne"):
        compare_weights(
            platform=reading("12.34"),
            ticket=reading("12340", WeightUnit.KILOGRAM),
            policy=policy(),
        )


def test_comparison_has_no_business_tolerance() -> None:
    result = compare_weights(
        platform=reading("12.34"),
        ticket=reading("12.35"),
        policy=policy(),
    )

    assert result.matches is False
    assert result.difference_tonnes == Decimal("0.01")

    large_result = compare_weights(
        platform=reading("123456789012345678901234567890.12"),
        ticket=reading("123456789012345678901234567890.13"),
        policy=policy(),
    )
    assert large_result.matches is False
    assert large_result.difference_tonnes == Decimal("0.01")
