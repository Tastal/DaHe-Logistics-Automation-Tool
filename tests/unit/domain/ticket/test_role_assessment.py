from __future__ import annotations

import inspect
from dataclasses import fields
from decimal import Decimal

import pytest

from dahe.domain.audit.evidence import (
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import (
    RoleIssue,
    TicketRole,
    TicketSlot,
    assess_ticket_roles,
)
from dahe.domain.ticket.role_assessment import (
    LabeledRoleResult,
    RoleAssessmentPolicy,
    RoleEvidence,
    RoleEvidenceSource,
    RoleObservation,
    assess_ticket_role,
    summarize_role_metrics,
)

LOADING_HASH = "1" * 64
UNLOADING_HASH = "2" * 64


def _evidence(
    source: RoleEvidenceSource,
    *,
    loading: str,
    unloading: str,
    marker: str,
) -> RoleEvidence:
    return RoleEvidence(
        source=source,
        loading_score=Decimal(loading),
        unloading_score=Decimal(unloading),
        matched_ids=(marker,),
        evidence_fingerprint=(marker * 64)[:64],
    )


def _strong_loading() -> tuple[RoleEvidence, ...]:
    return (
        _evidence(
            RoleEvidenceSource.FIXED_TEXT,
            loading="0.95",
            unloading="0.05",
            marker="a",
        ),
        _evidence(
            RoleEvidenceSource.TEMPLATE,
            loading="0.90",
            unloading="0.10",
            marker="b",
        ),
        _evidence(
            RoleEvidenceSource.LAYOUT,
            loading="0.80",
            unloading="0.15",
            marker="c",
        ),
    )


def _strong_unloading() -> tuple[RoleEvidence, ...]:
    return (
        _evidence(
            RoleEvidenceSource.FIXED_TEXT,
            loading="0.05",
            unloading="0.95",
            marker="d",
        ),
        _evidence(
            RoleEvidenceSource.TEMPLATE,
            loading="0.10",
            unloading="0.90",
            marker="e",
        ),
        _evidence(
            RoleEvidenceSource.LAYOUT,
            loading="0.15",
            unloading="0.80",
            marker="f",
        ),
    )


def _policy() -> RoleAssessmentPolicy:
    return RoleAssessmentPolicy(
        minimum_score=Decimal("0.65"),
        minimum_margin=Decimal("0.30"),
        minimum_sources=2,
        minimum_ticket_likelihood=Decimal("0.60"),
        high_confidence_score=Decimal("0.85"),
        version="loop7-role-policy-v1",
    )


def _observation(
    evidence: tuple[RoleEvidence, ...],
    *,
    image_sha256: str = LOADING_HASH,
    orientation: int = 0,
    ticket_likelihood: str = "0.95",
) -> RoleObservation:
    return RoleObservation(
        image_sha256=image_sha256,
        orientation_degrees=orientation,
        ticket_likelihood=Decimal(ticket_likelihood),
        evidence=evidence,
    )


def _missing_weights() -> TicketWeightEvidence:
    missing = WeightFieldEvidence(
        reading=None,
        quality=EvidenceQuality.MISSING,
    )
    return TicketWeightEvidence(
        ordinary_net=missing,
        factory_net=missing,
        gross=missing,
        tare=missing,
    )


def _ticket(
    slot: TicketSlot,
    image_sha256: str,
    observation: RoleObservation,
) -> TicketEvidence:
    assessment = assess_ticket_role(observation, _policy())
    return TicketEvidence(
        slot=slot,
        image_sha256=image_sha256,
        machine_role=assessment.role,
        role_quality=assessment.quality,
        weights=_missing_weights(),
        extraction_fingerprint="synthetic-extraction-v1",
        role_fingerprint=assessment.fingerprint,
    )


def test_role_contract_has_no_upload_slot_or_webpage_weight_input() -> None:
    forbidden_fragments = {"slot", "platform", "web", "expected_weight"}
    observation_fields = {field.name for field in fields(RoleObservation)}
    evidence_fields = {field.name for field in fields(RoleEvidence)}
    scorer_parameters = set(inspect.signature(assess_ticket_role).parameters)

    assert not any(
        fragment in name
        for fragment in forbidden_fragments
        for name in observation_fields | evidence_fields | scorer_parameters
    )
    assert scorer_parameters == {"observation", "policy"}


@pytest.mark.parametrize("orientation", [0, 90, 180, 270])
def test_strong_independent_evidence_has_no_orientation_bias(
    orientation: int,
) -> None:
    loading = assess_ticket_role(
        _observation(_strong_loading(), orientation=orientation),
        _policy(),
    )
    unloading = assess_ticket_role(
        _observation(
            _strong_unloading(),
            image_sha256=UNLOADING_HASH,
            orientation=orientation,
        ),
        _policy(),
    )

    assert loading.role is TicketRole.LOADING
    assert loading.quality is EvidenceQuality.RELIABLE
    assert unloading.role is TicketRole.UNLOADING
    assert unloading.quality is EvidenceQuality.RELIABLE


@pytest.mark.parametrize("orientation", [0, 90, 180, 270])
def test_insufficient_rotated_evidence_fails_safe_to_unknown(
    orientation: int,
) -> None:
    result = assess_ticket_role(
        _observation(
            (
                _evidence(
                    RoleEvidenceSource.FIXED_TEXT,
                    loading="0.90",
                    unloading="0.05",
                    marker="a",
                ),
            ),
            orientation=orientation,
        ),
        _policy(),
    )

    assert result.role is TicketRole.UNKNOWN
    assert result.quality is EvidenceQuality.UNCERTAIN
    assert result.high_confidence is False


def test_conflicting_sources_fail_safe_to_unknown() -> None:
    result = assess_ticket_role(
        _observation(
            (
                _evidence(
                    RoleEvidenceSource.FIXED_TEXT,
                    loading="0.95",
                    unloading="0.05",
                    marker="a",
                ),
                _evidence(
                    RoleEvidenceSource.TEMPLATE,
                    loading="0.05",
                    unloading="0.70",
                    marker="b",
                ),
                _evidence(
                    RoleEvidenceSource.LAYOUT,
                    loading="0.95",
                    unloading="0.05",
                    marker="c",
                ),
            )
        ),
        _policy(),
    )

    assert result.role is TicketRole.UNKNOWN
    assert result.quality is EvidenceQuality.UNCERTAIN


def test_internally_conflicting_source_fails_safe_even_with_consensus_elsewhere() -> None:
    result = assess_ticket_role(
        _observation(
            (
                _evidence(
                    RoleEvidenceSource.FIXED_TEXT,
                    loading="0.95",
                    unloading="0.05",
                    marker="a",
                ),
                _evidence(
                    RoleEvidenceSource.TEMPLATE,
                    loading="0.95",
                    unloading="0.90",
                    marker="b",
                ),
                _evidence(
                    RoleEvidenceSource.LAYOUT,
                    loading="0.90",
                    unloading="0.05",
                    marker="c",
                ),
            )
        ),
        _policy(),
    )

    assert result.role is TicketRole.UNKNOWN
    assert result.quality is EvidenceQuality.UNCERTAIN
    assert result.high_confidence is False


def test_zero_evidence_sources_do_not_satisfy_minimum_sources() -> None:
    result = assess_ticket_role(
        _observation(
            (
                _evidence(
                    RoleEvidenceSource.FIXED_TEXT,
                    loading="0.95",
                    unloading="0.05",
                    marker="a",
                ),
                _evidence(
                    RoleEvidenceSource.TEMPLATE,
                    loading="0",
                    unloading="0",
                    marker="b",
                ),
                _evidence(
                    RoleEvidenceSource.LAYOUT,
                    loading="0",
                    unloading="0",
                    marker="c",
                ),
            )
        ),
        _policy(),
    )

    assert result.role is TicketRole.UNKNOWN
    assert result.quality is EvidenceQuality.UNCERTAIN


def test_non_ticket_likelihood_blocks_a_confident_role() -> None:
    result = assess_ticket_role(
        _observation(_strong_loading(), ticket_likelihood="0.20"),
        _policy(),
    )

    assert result.role is TicketRole.UNKNOWN
    assert result.quality is EvidenceQuality.UNCERTAIN


def test_role_fingerprint_is_deterministic_and_evidence_order_independent() -> None:
    first = assess_ticket_role(_observation(_strong_loading()), _policy())
    reordered = assess_ticket_role(
        _observation(tuple(reversed(_strong_loading()))),
        _policy(),
    )

    assert first.fingerprint == reordered.fingerprint
    assert len(first.fingerprint) == 64


def test_existing_pair_assessment_detects_swapped_roles() -> None:
    loading_slot = _ticket(
        TicketSlot.LOADING,
        LOADING_HASH,
        _observation(
            _strong_unloading(),
            image_sha256=LOADING_HASH,
        ),
    )
    unloading_slot = _ticket(
        TicketSlot.UNLOADING,
        UNLOADING_HASH,
        _observation(
            _strong_loading(),
            image_sha256=UNLOADING_HASH,
        ),
    )

    result = assess_ticket_roles(loading_slot, unloading_slot)

    assert result.issue is RoleIssue.SUSPECTED_SWAPPED
    assert result.roles_valid is False


def test_existing_pair_assessment_keeps_duplicate_image_priority() -> None:
    loading_slot = _ticket(
        TicketSlot.LOADING,
        LOADING_HASH,
        _observation(_strong_loading(), image_sha256=LOADING_HASH),
    )
    unloading_slot = _ticket(
        TicketSlot.UNLOADING,
        LOADING_HASH,
        _observation(_strong_unloading(), image_sha256=LOADING_HASH),
    )

    result = assess_ticket_roles(loading_slot, unloading_slot)

    assert result.issue is RoleIssue.DUPLICATE_IMAGE


def test_existing_pair_assessment_detects_two_loading_tickets() -> None:
    loading_slot = _ticket(
        TicketSlot.LOADING,
        LOADING_HASH,
        _observation(_strong_loading(), image_sha256=LOADING_HASH),
    )
    unloading_slot = _ticket(
        TicketSlot.UNLOADING,
        UNLOADING_HASH,
        _observation(_strong_loading(), image_sha256=UNLOADING_HASH),
    )

    result = assess_ticket_roles(loading_slot, unloading_slot)

    assert result.issue is RoleIssue.BOTH_LOADING


def test_development_metrics_report_confusion_unknown_and_nearest_rank_latency() -> None:
    loading = assess_ticket_role(_observation(_strong_loading()), _policy())
    unloading = assess_ticket_role(
        _observation(_strong_unloading(), image_sha256=UNLOADING_HASH),
        _policy(),
    )
    unknown = assess_ticket_role(
        _observation((), image_sha256="3" * 64),
        _policy(),
    )
    results = (
        LabeledRoleResult("sample-1", TicketRole.LOADING, loading, Decimal("1")),
        LabeledRoleResult("sample-2", TicketRole.UNLOADING, unloading, Decimal("2")),
        LabeledRoleResult("sample-3", TicketRole.LOADING, loading, Decimal("3")),
        LabeledRoleResult("sample-4", TicketRole.UNLOADING, unloading, Decimal("4")),
        LabeledRoleResult("sample-5", TicketRole.LOADING, unknown, Decimal("100")),
    )

    metrics = summarize_role_metrics(results)

    assert metrics.sample_count == 5
    assert metrics.confusion_matrix["loading"]["loading"] == 2
    assert metrics.confusion_matrix["loading"]["unknown"] == 1
    assert metrics.confusion_matrix["unloading"]["unloading"] == 2
    assert metrics.unknown_rate == Decimal("0.2")
    assert metrics.high_confidence_error_count == 0
    assert metrics.p50_elapsed_ms == Decimal("3")
    assert metrics.p95_elapsed_ms == Decimal("100")


def test_development_metrics_count_high_confidence_role_errors() -> None:
    wrong = assess_ticket_role(_observation(_strong_loading()), _policy())

    metrics = summarize_role_metrics(
        (
            LabeledRoleResult(
                "wrong-high-confidence",
                TicketRole.UNLOADING,
                wrong,
                Decimal("5"),
            ),
        )
    )

    assert wrong.high_confidence is True
    assert metrics.high_confidence_error_count == 1
