from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from dahe.domain.audit.decisions import (
    AuditDecision,
    AuditDecisionKind,
    BusinessOutcome,
    evaluate_audit,
)
from dahe.domain.audit.errors import DomainContractError, StaleEvidenceError
from dahe.domain.audit.evidence import AuditEvidence, build_evidence_identity
from dahe.domain.audit.weights import WeightComparisonPolicy

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ProblemReason(StrEnum):
    SWAPPED_TICKETS = "swapped_tickets"
    WRONG_TICKET = "wrong_ticket"
    MISSING_TICKET = "missing_ticket"
    CONFIRMED_WEIGHT_MISMATCH = "confirmed_weight_mismatch"
    KEY_CONTENT_UNCONFIRMED = "key_content_unconfirmed"
    OTHER_BUSINESS_PROBLEM = "other_business_problem"


class InvalidationReason(StrEnum):
    KEY_EVIDENCE_CHANGED = "key_evidence_changed"


def _require_text(value: str, field: str) -> None:
    if not value.strip():
        raise DomainContractError(f"{field} is required")


def _validate_common_action(
    action_id: str,
    evidence_fingerprint: str,
) -> None:
    _require_text(action_id, "action_id")
    if not SHA256_PATTERN.fullmatch(evidence_fingerprint):
        raise DomainContractError("evidence_fingerprint must be a SHA-256")


@dataclass(frozen=True, slots=True)
class ProblemConfirmationAction:
    action_id: str
    evidence_fingerprint: str
    reason: ProblemReason

    def __post_init__(self) -> None:
        _validate_common_action(
            self.action_id,
            self.evidence_fingerprint,
        )
        if not isinstance(self.reason, ProblemReason):
            raise DomainContractError("problem reason must be a preset reason")


@dataclass(frozen=True, slots=True)
class ConfirmNormalAction:
    action_id: str
    evidence_fingerprint: str

    def __post_init__(self) -> None:
        _validate_common_action(
            self.action_id,
            self.evidence_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class ActionRevocation:
    action_id: str
    original_action_id: str
    evidence_fingerprint: str
    reason: str

    def __post_init__(self) -> None:
        _validate_common_action(
            self.action_id,
            self.evidence_fingerprint,
        )
        _require_text(self.original_action_id, "original_action_id")
        _require_text(self.reason, "reason")


ManualAction = ProblemConfirmationAction | ConfirmNormalAction


@dataclass(frozen=True, slots=True)
class ProblemConfirmationResult:
    action: ProblemConfirmationAction
    source_evidence: AuditEvidence
    business_outcome: BusinessOutcome


@dataclass(frozen=True, slots=True)
class NormalConfirmationResult:
    action: ConfirmNormalAction
    source_evidence: AuditEvidence
    business_outcome: BusinessOutcome


@dataclass(frozen=True, slots=True)
class RevokedAction:
    original_action: ManualAction
    revocation: ActionRevocation
    reevaluated_decision: AuditDecision


@dataclass(frozen=True, slots=True)
class InvalidatedAction:
    original_action: ManualAction
    previous_evidence_fingerprint: str
    current_evidence_fingerprint: str
    reason: InvalidationReason
    requires_revalidation: bool


def _assert_current_evidence(
    evidence: AuditEvidence,
    evidence_fingerprint: str,
    policy: WeightComparisonPolicy,
) -> None:
    current = build_evidence_identity(evidence, policy.rule_version)
    if current.fingerprint != evidence_fingerprint:
        raise StaleEvidenceError("the manual action targets stale evidence")


def confirm_problem(
    evidence: AuditEvidence,
    machine_decision: AuditDecision,
    action: ProblemConfirmationAction,
    policy: WeightComparisonPolicy,
) -> ProblemConfirmationResult:
    _assert_current_evidence(evidence, action.evidence_fingerprint, policy)
    current_decision = evaluate_audit(evidence, policy)
    if current_decision != machine_decision:
        raise StaleEvidenceError("the machine decision no longer matches the evidence")
    if current_decision.kind is AuditDecisionKind.PASS:
        raise DomainContractError(
            "an automatic pass needs new evidence before it can become a problem"
        )
    return ProblemConfirmationResult(
        action=action,
        source_evidence=evidence,
        business_outcome=BusinessOutcome.CONFIRMED_PROBLEM,
    )


def confirm_normal(
    evidence: AuditEvidence,
    machine_decision: AuditDecision,
    action: ConfirmNormalAction,
    policy: WeightComparisonPolicy,
) -> NormalConfirmationResult:
    _assert_current_evidence(evidence, action.evidence_fingerprint, policy)
    if evaluate_audit(evidence, policy) != machine_decision:
        raise StaleEvidenceError("the machine decision no longer matches the evidence")
    if machine_decision.kind is AuditDecisionKind.PASS:
        raise DomainContractError("the machine decision already passed")
    return NormalConfirmationResult(
        action=action,
        source_evidence=evidence,
        business_outcome=BusinessOutcome.NORMAL_READY,
    )


def revoke_action(
    source_evidence: AuditEvidence,
    original_action: ManualAction,
    revocation: ActionRevocation,
    policy: WeightComparisonPolicy,
) -> RevokedAction:
    _assert_current_evidence(
        source_evidence,
        original_action.evidence_fingerprint,
        policy,
    )
    _assert_current_evidence(
        source_evidence,
        revocation.evidence_fingerprint,
        policy,
    )
    if revocation.original_action_id != original_action.action_id:
        raise DomainContractError("revocation does not reference the original action")
    return RevokedAction(
        original_action=original_action,
        revocation=revocation,
        reevaluated_decision=evaluate_audit(source_evidence, policy),
    )


def invalidate_action_for_changed_evidence(
    current_source_evidence: AuditEvidence,
    original_action: ManualAction,
    policy: WeightComparisonPolicy,
) -> InvalidatedAction:
    """Invalidate an action only when immutable source evidence has changed."""
    current_identity = build_evidence_identity(
        current_source_evidence,
        policy.rule_version,
    )
    if current_identity.fingerprint == original_action.evidence_fingerprint:
        raise DomainContractError("the evidence has not changed")
    return InvalidatedAction(
        original_action=original_action,
        previous_evidence_fingerprint=original_action.evidence_fingerprint,
        current_evidence_fingerprint=current_identity.fingerprint,
        reason=InvalidationReason.KEY_EVIDENCE_CHANGED,
        requires_revalidation=True,
    )
