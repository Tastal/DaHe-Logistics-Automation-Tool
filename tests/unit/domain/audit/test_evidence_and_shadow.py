from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dahe.domain.audit.decisions import BusinessOutcome
from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.evidence import (
    AuditEvidence,
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightEvidenceIssue,
    WeightFieldEvidence,
    build_evidence_identity,
)
from dahe.domain.audit.shadow import (
    RealSettlementEffect,
    ShadowDisposition,
    ShadowProjection,
    project_shadow_outcome,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.domain.audit.weights import WeightReading, WeightUnit


def field(amount: str | None, quality: EvidenceQuality) -> WeightFieldEvidence:
    reading = (
        WeightReading(Decimal(amount), WeightUnit.TONNE, f"{amount} t")
        if amount is not None
        else None
    )
    return WeightFieldEvidence(reading, quality)


def ticket(slot: TicketSlot, marker: str) -> TicketEvidence:
    role = TicketRole.LOADING if slot is TicketSlot.LOADING else TicketRole.UNLOADING
    return TicketEvidence(
        slot=slot,
        image_sha256=marker * 64,
        machine_role=role,
        role_quality=EvidenceQuality.RELIABLE,
        weights=TicketWeightEvidence(
            ordinary_net=field("30.00", EvidenceQuality.RELIABLE),
            factory_net=field("31.00", EvidenceQuality.RELIABLE),
            gross=field(None, EvidenceQuality.MISSING),
            tare=field(None, EvidenceQuality.MISSING),
        ),
        extraction_fingerprint=f"extract-{marker}",
        role_fingerprint=f"role-{marker}",
    )


def audit_evidence() -> AuditEvidence:
    return AuditEvidence(
        snapshot_id="snapshot-001",
        platform_loading_net=field("30.00", EvidenceQuality.RELIABLE),
        platform_unloading_net=field("30.00", EvidenceQuality.RELIABLE),
        loading_ticket_quality=EvidenceQuality.RELIABLE,
        unloading_ticket_quality=EvidenceQuality.RELIABLE,
        loading_ticket=ticket(TicketSlot.LOADING, "a"),
        unloading_ticket=ticket(TicketSlot.UNLOADING, "b"),
    )


def test_evidence_fingerprint_is_deterministic_and_rule_versioned() -> None:
    source = audit_evidence()

    first = build_evidence_identity(source, "comparison-v1")
    second = build_evidence_identity(source, "comparison-v1")
    changed_rule = build_evidence_identity(source, "comparison-v2")

    assert first.fingerprint == second.fingerprint
    assert first.fingerprint != changed_rule.fingerprint


def test_key_evidence_changes_invalidate_the_identity() -> None:
    source = audit_evidence()
    baseline = build_evidence_identity(source, "comparison-v1")
    assert source.loading_ticket is not None

    variants = [
        replace(source, snapshot_id="snapshot-002"),
        replace(
            source,
            loading_ticket=replace(source.loading_ticket, image_sha256="c" * 64),
        ),
        replace(
            source,
            platform_loading_net=field("30.01", EvidenceQuality.RELIABLE),
        ),
        replace(
            source,
            loading_ticket=replace(
                source.loading_ticket,
                extraction_fingerprint="extract-new",
            ),
        ),
        replace(
            source,
            platform_loading_net=WeightFieldEvidence(
                reading=source.platform_loading_net.reading,
                quality=EvidenceQuality.UNCERTAIN,
                issue=WeightEvidenceIssue.FORMAT_SUSPICIOUS,
            ),
        ),
    ]

    assert all(
        build_evidence_identity(item, "comparison-v1").fingerprint != baseline.fingerprint
        for item in variants
    )


def test_shadow_problem_is_only_excluded_from_the_shadow_normal_sample() -> None:
    projection = project_shadow_outcome(BusinessOutcome.CONFIRMED_PROBLEM)

    assert projection.disposition is ShadowDisposition.EXCLUDED_PROBLEM
    assert projection.real_settlement_effect is RealSettlementEffect.NONE
    assert projection.platform_actions == ()


def test_every_shadow_outcome_has_no_real_platform_effect() -> None:
    projections = [project_shadow_outcome(outcome) for outcome in BusinessOutcome]

    assert all(
        item.real_settlement_effect is RealSettlementEffect.NONE
        for item in projections
    )
    assert all(item.platform_actions == () for item in projections)

    with pytest.raises(DomainContractError, match="platform actions"):
        ShadowProjection(
            business_outcome=BusinessOutcome.CONFIRMED_PROBLEM,
            disposition=ShadowDisposition.EXCLUDED_PROBLEM,
            real_settlement_effect=RealSettlementEffect.NONE,
            platform_actions=("receipt_cancel",),  # type: ignore[arg-type]
        )
    with pytest.raises(DomainContractError, match="platform actions"):
        ShadowProjection(
            business_outcome=BusinessOutcome.CONFIRMED_PROBLEM,
            disposition=ShadowDisposition.EXCLUDED_PROBLEM,
            real_settlement_effect=RealSettlementEffect.NONE,
            platform_actions=[],  # type: ignore[arg-type]
        )
