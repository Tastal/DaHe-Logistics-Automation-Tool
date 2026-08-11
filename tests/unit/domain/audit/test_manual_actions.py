from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dahe.domain.audit.decisions import (
    AuditDecisionKind,
    BusinessOutcome,
    evaluate_audit,
)
from dahe.domain.audit.errors import DomainContractError, StaleEvidenceError
from dahe.domain.audit.evidence import (
    AuditEvidence,
    EvidenceIdentity,
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightFieldEvidence,
    build_evidence_identity,
)
from dahe.domain.audit.manual_actions import (
    ActionRevocation,
    ConfirmNormalAction,
    InvalidationReason,
    ProblemConfirmationAction,
    ProblemReason,
    confirm_normal,
    confirm_problem,
    invalidate_action_for_changed_evidence,
    revoke_action,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.domain.audit.weights import (
    WeightComparisonPolicy,
    WeightReading,
    WeightUnit,
)


def weight(amount: str) -> WeightReading:
    return WeightReading(Decimal(amount), WeightUnit.TONNE, f"{amount} t")


def reliable(amount: str) -> WeightFieldEvidence:
    return WeightFieldEvidence(weight(amount), EvidenceQuality.RELIABLE)


def missing() -> WeightFieldEvidence:
    return WeightFieldEvidence(None, EvidenceQuality.MISSING)


def ticket(slot: TicketSlot, amount: str) -> TicketEvidence:
    role = TicketRole.LOADING if slot is TicketSlot.LOADING else TicketRole.UNLOADING
    marker = "a" if slot is TicketSlot.LOADING else "b"
    return TicketEvidence(
        slot=slot,
        image_sha256=marker * 64,
        machine_role=role,
        role_quality=EvidenceQuality.RELIABLE,
        weights=TicketWeightEvidence(
            ordinary_net=reliable(amount),
            factory_net=reliable("88.88"),
            gross=missing(),
            tare=missing(),
        ),
        extraction_fingerprint=f"extract-{marker}",
        role_fingerprint=f"role-{marker}",
    )


def audit_evidence(loading: str = "30.01") -> AuditEvidence:
    return AuditEvidence(
        snapshot_id="snapshot-001",
        platform_loading_net=reliable("30.00"),
        platform_unloading_net=reliable("30.00"),
        loading_ticket_quality=EvidenceQuality.RELIABLE,
        unloading_ticket_quality=EvidenceQuality.RELIABLE,
        loading_ticket=ticket(TicketSlot.LOADING, loading),
        unloading_ticket=ticket(TicketSlot.UNLOADING, "30.00"),
    )


def policy() -> WeightComparisonPolicy:
    return WeightComparisonPolicy(2, "exact-two-decimal-tonnes-v1")


def identity(source: AuditEvidence | None = None) -> EvidenceIdentity:
    return build_evidence_identity(source or audit_evidence(), policy().rule_version)


def test_manual_decisions_have_no_weight_note_or_identity_fields() -> None:
    problem = ProblemConfirmationAction(
        action_id="problem-001",
        evidence_fingerprint=identity().fingerprint,
        reason=ProblemReason.CONFIRMED_WEIGHT_MISMATCH,
    )
    normal = ConfirmNormalAction(
        action_id="normal-001",
        evidence_fingerprint=identity().fingerprint,
    )
    for action in (problem, normal):
        assert not hasattr(action, "operator")
        assert not hasattr(action, "correct_weight")
        assert not hasattr(action, "note")


def test_problem_confirmation_uses_preset_reason_and_keeps_evidence() -> None:
    source = audit_evidence()
    machine = evaluate_audit(source, policy())
    action = ProblemConfirmationAction(
        action_id="problem-001",
        evidence_fingerprint=identity(source).fingerprint,
        reason=ProblemReason.CONFIRMED_WEIGHT_MISMATCH,
    )

    result = confirm_problem(source, machine, action, policy())

    assert result.business_outcome is BusinessOutcome.CONFIRMED_PROBLEM
    assert result.source_evidence is source
    with pytest.raises(DomainContractError, match="reason"):
        replace(action, reason="free text")  # type: ignore[arg-type]


def test_confirm_normal_is_an_append_only_override_without_weight_change() -> None:
    source = audit_evidence()
    machine = evaluate_audit(source, policy())
    assert machine.kind is AuditDecisionKind.WEIGHT_MISMATCH
    action = ConfirmNormalAction(
        action_id="normal-001",
        evidence_fingerprint=identity(source).fingerprint,
    )

    result = confirm_normal(source, machine, action, policy())

    assert result.business_outcome is BusinessOutcome.NORMAL_READY
    assert result.source_evidence is source
    assert source.loading_ticket is not None
    assert source.loading_ticket.weights.ordinary_net.reading == weight("30.01")


def test_manual_decisions_reject_pass_and_stale_evidence() -> None:
    passed = audit_evidence(loading="30.00")
    passed_machine = evaluate_audit(passed, policy())
    normal = ConfirmNormalAction(
        action_id="normal-001",
        evidence_fingerprint=identity(passed).fingerprint,
    )
    with pytest.raises(DomainContractError, match="already passed"):
        confirm_normal(passed, passed_machine, normal, policy())

    changed = replace(audit_evidence(), snapshot_id="snapshot-002")
    problem = ProblemConfirmationAction(
        action_id="problem-001",
        evidence_fingerprint=identity().fingerprint,
        reason=ProblemReason.CONFIRMED_WEIGHT_MISMATCH,
    )
    with pytest.raises(StaleEvidenceError):
        confirm_problem(changed, evaluate_audit(changed, policy()), problem, policy())


def test_revocation_and_invalidation_remain_append_only() -> None:
    source = audit_evidence()
    action = ProblemConfirmationAction(
        action_id="problem-001",
        evidence_fingerprint=identity(source).fingerprint,
        reason=ProblemReason.CONFIRMED_WEIGHT_MISMATCH,
    )
    revocation = ActionRevocation(
        action_id="revocation-001",
        original_action_id=action.action_id,
        evidence_fingerprint=identity(source).fingerprint,
        reason="decision entered in error",
    )

    revoked = revoke_action(source, action, revocation, policy())
    assert revoked.reevaluated_decision.kind is AuditDecisionKind.WEIGHT_MISMATCH

    changed = replace(source, snapshot_id="snapshot-002")
    invalidated = invalidate_action_for_changed_evidence(changed, action, policy())
    assert invalidated.reason is InvalidationReason.KEY_EVIDENCE_CHANGED
    assert invalidated.requires_revalidation is True
