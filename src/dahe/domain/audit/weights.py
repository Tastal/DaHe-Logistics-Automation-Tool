from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from enum import StrEnum

from dahe.domain.audit.errors import DomainContractError


class WeightUnit(StrEnum):
    TONNE = "t"
    KILOGRAM = "kg"


@dataclass(frozen=True, slots=True)
class WeightComparisonPolicy:
    decimal_places: int
    rule_version: str

    def __post_init__(self) -> None:
        if self.decimal_places != 2:
            raise DomainContractError("weight comparison must use two decimal places")
        if not self.rule_version.strip():
            raise DomainContractError("rule_version is required")

    @property
    def quantum(self) -> Decimal:
        return Decimal("0.01")

@dataclass(frozen=True, slots=True)
class WeightReading:
    amount: Decimal
    unit: WeightUnit
    raw_text: str

    def __post_init__(self) -> None:
        if not isinstance(self.amount, Decimal):
            raise DomainContractError("weight amount must be a Decimal")
        if not self.amount.is_finite() or self.amount < 0:
            raise DomainContractError("weight amount must be finite and non-negative")
        if not isinstance(self.unit, WeightUnit):
            raise DomainContractError("weight unit is invalid")
        if not self.raw_text.strip():
            raise DomainContractError("weight raw_text is required")


@dataclass(frozen=True, slots=True)
class NormalizedWeight:
    source: WeightReading
    exact_tonnes: Decimal
    comparison_tonnes: Decimal | None
    policy_version: str


@dataclass(frozen=True, slots=True)
class WeightComparison:
    platform: NormalizedWeight
    ticket: NormalizedWeight
    matches: bool
    difference_tonnes: Decimal


def _shift_decimal_exponent(value: Decimal, places: int) -> Decimal:
    parts = value.as_tuple()
    exponent = parts.exponent
    if not isinstance(exponent, int):
        raise DomainContractError("weight amount must have a finite exponent")
    return Decimal((parts.sign, parts.digits, exponent + places))


def _exact_two_decimal_value(value: Decimal) -> Decimal | None:
    if value.is_zero():
        return Decimal((value.as_tuple().sign, (0,), -2))

    parts = value.as_tuple()
    digits = parts.digits
    exponent = parts.exponent
    if not isinstance(exponent, int):
        raise DomainContractError("weight amount must have a finite exponent")
    if exponent < -2:
        extra_places = -2 - exponent
        if extra_places >= len(digits):
            return None
        if any(digit != 0 for digit in digits[-extra_places:]):
            return None
        digits = digits[:-extra_places]
    elif exponent > -2:
        digits = digits + ((0,) * (exponent + 2))
    return Decimal((parts.sign, digits or (0,), -2))


def _exact_difference(left: Decimal, right: Decimal) -> Decimal:
    left_parts = left.as_tuple()
    right_parts = right.as_tuple()
    if left_parts.exponent != -2 or right_parts.exponent != -2:
        raise DomainContractError("comparison values must have two-decimal exponents")
    with localcontext() as context:
        context.prec = max(len(left_parts.digits), len(right_parts.digits)) + 1
        return (left - right).copy_abs()


def normalize_weight(
    reading: WeightReading,
    policy: WeightComparisonPolicy,
) -> NormalizedWeight:
    exact_tonnes = (
        _shift_decimal_exponent(reading.amount, -3)
        if reading.unit is WeightUnit.KILOGRAM
        else reading.amount
    )
    comparison_tonnes = (
        None
        if reading.unit is WeightUnit.KILOGRAM
        else _exact_two_decimal_value(exact_tonnes)
    )
    return NormalizedWeight(
        source=reading,
        exact_tonnes=exact_tonnes,
        comparison_tonnes=comparison_tonnes,
        policy_version=policy.rule_version,
    )


def compare_weights(
    *,
    platform: WeightReading,
    ticket: WeightReading,
    policy: WeightComparisonPolicy,
) -> WeightComparison:
    if (
        platform.unit is not WeightUnit.TONNE
        or ticket.unit is not WeightUnit.TONNE
    ):
        raise DomainContractError(
            "automatic comparison requires platform and ticket weights in tonne"
        )
    platform_weight = normalize_weight(platform, policy)
    ticket_weight = normalize_weight(ticket, policy)
    if (
        platform_weight.comparison_tonnes is None
        or ticket_weight.comparison_tonnes is None
    ):
        raise DomainContractError(
            "automatic comparison requires values exactly representable "
            "to two decimal places"
        )
    difference = _exact_difference(
        platform_weight.comparison_tonnes,
        ticket_weight.comparison_tonnes,
    )
    return WeightComparison(
        platform=platform_weight,
        ticket=ticket_weight,
        matches=platform_weight.comparison_tonnes == ticket_weight.comparison_tonnes,
        difference_tonnes=difference,
    )
