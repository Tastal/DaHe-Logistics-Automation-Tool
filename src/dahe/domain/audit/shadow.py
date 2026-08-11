from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from dahe.domain.audit.decisions import BusinessOutcome
from dahe.domain.audit.errors import DomainContractError


class ShadowDisposition(StrEnum):
    NORMAL_SAMPLE = "normal_sample"
    REVIEW_PENDING = "review_pending"
    EXCLUDED_PROBLEM = "excluded_problem"


class RealSettlementEffect(StrEnum):
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ShadowProjection:
    business_outcome: BusinessOutcome
    disposition: ShadowDisposition
    real_settlement_effect: RealSettlementEffect
    platform_actions: tuple[()]

    def __post_init__(self) -> None:
        expected_disposition = {
            BusinessOutcome.NORMAL_READY: ShadowDisposition.NORMAL_SAMPLE,
            BusinessOutcome.AWAITING_REVIEW: ShadowDisposition.REVIEW_PENDING,
            BusinessOutcome.CONFIRMED_PROBLEM: ShadowDisposition.EXCLUDED_PROBLEM,
        }
        if not isinstance(self.business_outcome, BusinessOutcome):
            raise DomainContractError("shadow business outcome is invalid")
        if self.disposition is not expected_disposition[self.business_outcome]:
            raise DomainContractError("shadow disposition does not match the outcome")
        if self.real_settlement_effect is not RealSettlementEffect.NONE:
            raise DomainContractError("shadow mode cannot affect real settlement")
        if not isinstance(self.platform_actions, tuple) or self.platform_actions != ():
            raise DomainContractError("shadow mode cannot contain platform actions")


def project_shadow_outcome(outcome: BusinessOutcome) -> ShadowProjection:
    if outcome is BusinessOutcome.NORMAL_READY:
        disposition = ShadowDisposition.NORMAL_SAMPLE
    elif outcome is BusinessOutcome.CONFIRMED_PROBLEM:
        disposition = ShadowDisposition.EXCLUDED_PROBLEM
    else:
        disposition = ShadowDisposition.REVIEW_PENDING
    return ShadowProjection(
        business_outcome=outcome,
        disposition=disposition,
        real_settlement_effect=RealSettlementEffect.NONE,
        platform_actions=(),
    )
