from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dahe.domain.audit.decisions import (
    AuditDecision,
    AuditDecisionKind,
    BusinessOutcome,
    DecisionReason,
    evaluate_audit,
)
from dahe.domain.audit.errors import DomainContractError, SystemEvidenceError
from dahe.domain.audit.evidence import (
    AuditEvidence,
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightEvidenceIssue,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import (
    RoleIssue,
    TicketRole,
    TicketSlot,
    assess_ticket_roles,
)
from dahe.domain.audit.weights import (
    WeightComparisonPolicy,
    WeightReading,
    WeightUnit,
)

LOADING_HASH = "1" * 64
UNLOADING_HASH = "2" * 64


def weight(amount: str) -> WeightReading:
    return WeightReading(Decimal(amount), WeightUnit.TONNE, f"{amount} t")


def field(
    amount: str | None,
    quality: EvidenceQuality = EvidenceQuality.RELIABLE,
    unit: WeightUnit = WeightUnit.TONNE,
) -> WeightFieldEvidence:
    return WeightFieldEvidence(
        reading=(
            WeightReading(Decimal(amount), unit, f"{amount} {unit.value}")
            if amount is not None
            else None
        ),
        quality=quality,
    )


def ticket(
    slot: TicketSlot,
    role: TicketRole,
    amount: str = "30.00",
    *,
    image_hash: str | None = None,
    role_quality: EvidenceQuality = EvidenceQuality.RELIABLE,
    net_quality: EvidenceQuality = EvidenceQuality.RELIABLE,
    factory_amount: str = "99.99",
    net_unit: WeightUnit = WeightUnit.TONNE,
) -> TicketEvidence:
    actual_hash = image_hash or (LOADING_HASH if slot is TicketSlot.LOADING else UNLOADING_HASH)
    return TicketEvidence(
        slot=slot,
        image_sha256=actual_hash,
        machine_role=role,
        role_quality=role_quality,
        weights=TicketWeightEvidence(
            ordinary_net=field(
                amount if net_quality is EvidenceQuality.RELIABLE else None,
                net_quality,
                net_unit,
            ),
            factory_net=field(factory_amount),
            gross=field(None, EvidenceQuality.MISSING),
            tare=field(None, EvidenceQuality.MISSING),
        ),
        extraction_fingerprint=f"extract-{slot.value}-v1",
        role_fingerprint=f"role-{slot.value}-v1",
    )


def evidence(
    *,
    loading: TicketEvidence | None = None,
    unloading: TicketEvidence | None = None,
    platform_loading: WeightFieldEvidence | None = None,
    platform_unloading: WeightFieldEvidence | None = None,
) -> AuditEvidence:
    return AuditEvidence(
        snapshot_id="snapshot-001",
        platform_loading_net=platform_loading or field("30.00"),
        platform_unloading_net=platform_unloading or field("30.00"),
        loading_ticket_quality=EvidenceQuality.RELIABLE,
        unloading_ticket_quality=EvidenceQuality.RELIABLE,
        loading_ticket=loading
        or ticket(TicketSlot.LOADING, TicketRole.LOADING, amount="30.00"),
        unloading_ticket=unloading
        or ticket(TicketSlot.UNLOADING, TicketRole.UNLOADING, amount="30.00"),
    )


def comparison_policy() -> WeightComparisonPolicy:
    return WeightComparisonPolicy(2, "exact-two-decimal-tonnes-v1")


@pytest.mark.parametrize(
    ("issue", "expected_reason"),
    [
        (
            WeightEvidenceIssue.FORMAT_SUSPICIOUS,
            DecisionReason.TICKET_WEIGHT_FORMAT_SUSPICIOUS,
        ),
        (
            WeightEvidenceIssue.RUNTIME_DISAGREEMENT,
            DecisionReason.OCR_WEIGHT_DISAGREEMENT,
        ),
    ],
)
def test_weight_evidence_issue_routes_to_specific_human_review(
    issue: WeightEvidenceIssue,
    expected_reason: DecisionReason,
) -> None:
    loading = ticket(TicketSlot.LOADING, TicketRole.LOADING)
    suspicious = WeightFieldEvidence(
        reading=weight("3270"),
        quality=EvidenceQuality.UNCERTAIN,
        issue=issue,
    )
    loading = replace(
        loading,
        weights=replace(loading.weights, ordinary_net=suspicious),
    )

    decision = evaluate_audit(
        evidence(loading=loading),
        comparison_policy(),
    )

    assert decision.kind is AuditDecisionKind.REVIEW
    assert decision.business_outcome is BusinessOutcome.AWAITING_REVIEW
    assert decision.reasons == (expected_reason,)


def test_expected_ticket_roles_are_accepted() -> None:
    assessment = assess_ticket_roles(
        ticket(TicketSlot.LOADING, TicketRole.LOADING),
        ticket(TicketSlot.UNLOADING, TicketRole.UNLOADING),
    )

    assert assessment.issue is None
    assert assessment.roles_valid is True


@pytest.mark.parametrize(
    ("loading_role", "unloading_role", "expected_issue"),
    [
        (TicketRole.UNLOADING, TicketRole.LOADING, RoleIssue.SUSPECTED_SWAPPED),
        (TicketRole.LOADING, TicketRole.LOADING, RoleIssue.BOTH_LOADING),
        (TicketRole.UNLOADING, TicketRole.UNLOADING, RoleIssue.BOTH_UNLOADING),
        (TicketRole.UNKNOWN, TicketRole.UNLOADING, RoleIssue.ROLE_UNKNOWN),
    ],
)
def test_role_conflicts_have_stable_classification(
    loading_role: TicketRole,
    unloading_role: TicketRole,
    expected_issue: RoleIssue,
) -> None:
    loading_quality = (
        EvidenceQuality.UNCERTAIN
        if loading_role is TicketRole.UNKNOWN
        else EvidenceQuality.RELIABLE
    )
    assessment = assess_ticket_roles(
        ticket(TicketSlot.LOADING, loading_role, role_quality=loading_quality),
        ticket(TicketSlot.UNLOADING, unloading_role),
    )

    assert assessment.issue is expected_issue
    assert assessment.roles_valid is False


def test_duplicate_image_takes_priority_over_role_conflict() -> None:
    assessment = assess_ticket_roles(
        ticket(TicketSlot.LOADING, TicketRole.UNLOADING, image_hash=LOADING_HASH),
        ticket(TicketSlot.UNLOADING, TicketRole.LOADING, image_hash=LOADING_HASH),
    )

    assert assessment.issue is RoleIssue.DUPLICATE_IMAGE


def test_missing_ticket_is_not_inferred_from_the_upload_slot() -> None:
    assessment = assess_ticket_roles(
        ticket(TicketSlot.LOADING, TicketRole.LOADING),
        None,
    )

    assert assessment.issue is RoleIssue.MISSING_EVIDENCE
    source = evidence()
    missing_source = replace(
        source,
        unloading_ticket_quality=EvidenceQuality.MISSING,
        unloading_ticket=None,
    )
    decision = evaluate_audit(missing_source, comparison_policy())
    assert decision.kind is AuditDecisionKind.REVIEW
    assert decision.reasons == (DecisionReason.MISSING_TICKET,)


def test_uncertain_role_is_not_forced_to_a_binary_role() -> None:
    loading = ticket(
        TicketSlot.LOADING,
        TicketRole.LOADING,
        role_quality=EvidenceQuality.UNCERTAIN,
    )

    assert assess_ticket_roles(loading, ticket(
        TicketSlot.UNLOADING, TicketRole.UNLOADING
    )).issue is RoleIssue.ROLE_UNRELIABLE


def test_ticket_position_mismatch_is_a_contract_error() -> None:
    with pytest.raises(DomainContractError, match="slot"):
        assess_ticket_roles(
            ticket(TicketSlot.UNLOADING, TicketRole.UNLOADING),
            ticket(TicketSlot.LOADING, TicketRole.LOADING),
        )


def test_normal_audit_passes_only_when_both_ordinary_nets_match() -> None:
    result = evaluate_audit(evidence(), comparison_policy())

    assert result.kind is AuditDecisionKind.PASS
    assert result.business_outcome is BusinessOutcome.NORMAL_READY
    assert result.reasons == ()
    assert result.loading_comparison is not None
    assert result.unloading_comparison is not None

    with pytest.raises(DomainContractError, match="internally inconsistent"):
        AuditDecision(
            kind=AuditDecisionKind.PASS,
            business_outcome=BusinessOutcome.AWAITING_REVIEW,
            reasons=(),
            loading_comparison=result.loading_comparison,
            unloading_comparison=result.unloading_comparison,
        )

    extra_precision = evaluate_audit(
        evidence(platform_loading=field("30.005")),
        comparison_policy(),
    )
    assert extra_precision.kind is AuditDecisionKind.REVIEW
    assert (
        DecisionReason.PLATFORM_WEIGHT_PRECISION_REQUIRES_REVIEW
        in extra_precision.reasons
    )


@pytest.mark.parametrize(
    ("loading_amount", "unloading_amount"),
    [("30.01", "30.00"), ("30.00", "29.99"), ("30.01", "29.99")],
)
def test_any_reliable_weight_mismatch_requires_a_recorded_resolution(
    loading_amount: str,
    unloading_amount: str,
) -> None:
    result = evaluate_audit(
        evidence(
            loading=ticket(
                TicketSlot.LOADING,
                TicketRole.LOADING,
                amount=loading_amount,
            ),
            unloading=ticket(
                TicketSlot.UNLOADING,
                TicketRole.UNLOADING,
                amount=unloading_amount,
            ),
        ),
        comparison_policy(),
    )

    assert result.kind is AuditDecisionKind.WEIGHT_MISMATCH
    assert result.business_outcome is BusinessOutcome.AWAITING_REVIEW
    assert DecisionReason.WEIGHT_MISMATCH in result.reasons


@pytest.mark.parametrize(
    ("changed", "expected_reason"),
    [
        (
            {"platform_loading": field(None, EvidenceQuality.MISSING)},
            DecisionReason.PLATFORM_WEIGHT_MISSING,
        ),
        (
            {
                "loading": ticket(
                    TicketSlot.LOADING,
                    TicketRole.LOADING,
                    net_quality=EvidenceQuality.MISSING,
                )
            },
            DecisionReason.TICKET_NET_MISSING,
        ),
        (
            {
                "unloading": ticket(
                    TicketSlot.UNLOADING,
                    TicketRole.UNLOADING,
                    amount="30.005",
                )
            },
            DecisionReason.TICKET_WEIGHT_PRECISION_REQUIRES_REVIEW,
        ),
        (
            {
                "loading": ticket(
                    TicketSlot.LOADING,
                    TicketRole.LOADING,
                    amount="30000",
                    net_unit=WeightUnit.KILOGRAM,
                )
            },
            DecisionReason.TICKET_WEIGHT_UNIT_REQUIRES_REVIEW,
        ),
    ],
)
def test_ineligible_weight_evidence_never_auto_passes(
    changed: dict[str, object],
    expected_reason: DecisionReason,
) -> None:
    result = evaluate_audit(evidence(**changed), comparison_policy())  # type: ignore[arg-type]

    assert result.kind is AuditDecisionKind.REVIEW
    assert result.business_outcome is BusinessOutcome.AWAITING_REVIEW
    assert expected_reason in result.reasons


def test_role_swap_is_suspected_but_never_automatically_exchanged() -> None:
    original = evidence(
        loading=ticket(TicketSlot.LOADING, TicketRole.UNLOADING, amount="30.00"),
        unloading=ticket(TicketSlot.UNLOADING, TicketRole.LOADING, amount="30.00"),
    )

    result = evaluate_audit(original, comparison_policy())

    assert result.kind is AuditDecisionKind.SUSPECTED_PROBLEM
    assert result.reasons == (DecisionReason.SUSPECTED_SWAPPED,)
    assert original.loading_ticket is not None
    assert original.loading_ticket.weights.ordinary_net.reading == weight("30.00")


@pytest.mark.parametrize(
    ("loading", "unloading", "expected_kind"),
    [
        (
            ticket(
                TicketSlot.LOADING,
                TicketRole.LOADING,
                image_hash=LOADING_HASH,
            ),
            ticket(
                TicketSlot.UNLOADING,
                TicketRole.UNLOADING,
                image_hash=LOADING_HASH,
            ),
            AuditDecisionKind.SUSPECTED_PROBLEM,
        ),
        (
            ticket(TicketSlot.LOADING, TicketRole.LOADING),
            ticket(TicketSlot.UNLOADING, TicketRole.LOADING),
            AuditDecisionKind.SUSPECTED_PROBLEM,
        ),
        (
            ticket(TicketSlot.LOADING, TicketRole.UNLOADING),
            ticket(TicketSlot.UNLOADING, TicketRole.UNLOADING),
            AuditDecisionKind.SUSPECTED_PROBLEM,
        ),
    ],
)
def test_role_pair_issues_block_automatic_pass(
    loading: TicketEvidence,
    unloading: TicketEvidence,
    expected_kind: AuditDecisionKind,
) -> None:
    result = evaluate_audit(
        evidence(loading=loading, unloading=unloading),
        comparison_policy(),
    )

    assert result.kind is expected_kind
    assert result.business_outcome is BusinessOutcome.AWAITING_REVIEW


def test_factory_net_never_changes_audit_result() -> None:
    base = evidence()
    assert base.loading_ticket is not None
    changed_loading = replace(
        base.loading_ticket,
        weights=replace(base.loading_ticket.weights, factory_net=field("1.00")),
    )

    original_result = evaluate_audit(base, comparison_policy())
    changed_result = evaluate_audit(
        replace(base, loading_ticket=changed_loading),
        comparison_policy(),
    )

    assert original_result.kind is AuditDecisionKind.PASS
    assert changed_result.kind is AuditDecisionKind.PASS

    factory_matches_but_ordinary_differs = replace(
        changed_loading,
        weights=replace(
            changed_loading.weights,
            ordinary_net=field("30.01"),
            factory_net=field("30.00"),
        ),
    )
    mismatch = evaluate_audit(
        replace(base, loading_ticket=factory_matches_but_ordinary_differs),
        comparison_policy(),
    )
    assert mismatch.kind is AuditDecisionKind.WEIGHT_MISMATCH


def test_uncertain_evidence_takes_precedence_over_a_known_mismatch() -> None:
    result = evaluate_audit(
        evidence(
            loading=ticket(TicketSlot.LOADING, TicketRole.LOADING, amount="30.01"),
            unloading=ticket(
                TicketSlot.UNLOADING,
                TicketRole.UNLOADING,
                net_quality=EvidenceQuality.UNCERTAIN,
            ),
        ),
        comparison_policy(),
    )

    assert result.kind is AuditDecisionKind.REVIEW
    assert result.loading_comparison is None
    assert result.unloading_comparison is None
    assert DecisionReason.TICKET_NET_UNRELIABLE in result.reasons


def test_system_failures_are_raised_instead_of_becoming_finance_review() -> None:
    failed_platform_field = field(None, EvidenceQuality.SYSTEM_FAILURE)

    with pytest.raises(SystemEvidenceError, match="platform"):
        evaluate_audit(
            evidence(platform_loading=failed_platform_field),
            comparison_policy(),
        )

    source = evidence()
    failed_ticket_download = replace(
        source,
        loading_ticket_quality=EvidenceQuality.SYSTEM_FAILURE,
        loading_ticket=None,
    )
    with pytest.raises(SystemEvidenceError, match="ticket acquisition"):
        evaluate_audit(failed_ticket_download, comparison_policy())
