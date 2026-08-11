from __future__ import annotations

import hashlib
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from dahe.domain.audit.evidence import EvidenceQuality
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.verification.controlled_non_ticket_challenge import (
    ControlledNonTicketChallenge,
)
from dahe.verification.controlled_non_ticket_gate import (
    ControlledNonTicketGateError,
    evaluate_controlled_non_ticket_gate,
)
from dahe.verification.locked_set_runner import (
    LockedOcrRuntimeComparison,
    LockedOcrRuntimeOutput,
    LockedRolePrediction,
)


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _challenge(tmp_path: Path) -> ControlledNonTicketChallenge:
    digest = _sha256("redacted")
    return ControlledNonTicketChallenge(
        manifest_path=tmp_path / "manifest.json",
        redacted_image_path=tmp_path / "redacted.png",
        payload={
            "canonical_sha256": _sha256("artifact"),
            "redacted_sha256": digest,
        },
    )


def _output(
    *,
    runtime_kind: str,
    role: TicketRole = TicketRole.UNKNOWN,
    ordinary_net_reliable: bool = False,
) -> LockedOcrRuntimeOutput:
    known = role is not TicketRole.UNKNOWN
    return LockedOcrRuntimeOutput(
        image_sha256=_sha256("redacted"),
        runtime_kind=runtime_kind,
        runtime_fingerprint=_sha256(f"{runtime_kind}-runtime"),
        output_fingerprint=_sha256(f"{runtime_kind}-output"),
        worker_elapsed_ms=Decimal("2"),
        wall_elapsed_ms=Decimal("3"),
        ordinary_net_amount=(
            Decimal("30.00") if ordinary_net_reliable else None
        ),
        ordinary_net_unit="t" if ordinary_net_reliable else None,
        ordinary_net_confidence=(
            Decimal("0.99") if ordinary_net_reliable else None
        ),
        ordinary_net_reliable=ordinary_net_reliable,
        role=role,
        role_quality=(
            EvidenceQuality.RELIABLE
            if known
            else EvidenceQuality.UNCERTAIN
        ),
        role_confidence=Decimal("0.95") if known else Decimal("0.20"),
        role_high_confidence=known,
        safety_route=(
            "eligible_for_downstream_comparison"
            if known and ordinary_net_reliable
            else "non_automatic"
        ),
        assessment_fingerprint=_sha256(f"{runtime_kind}-assessment"),
    )


def _prediction(
    *,
    role: TicketRole = TicketRole.UNKNOWN,
    ordinary_net_reliable: bool = False,
) -> LockedRolePrediction:
    outputs = tuple(
        _output(
            runtime_kind=runtime_kind,
            role=role,
            ordinary_net_reliable=ordinary_net_reliable,
        )
        for runtime_kind in ("cpu", "gpu")
    )
    comparison = LockedOcrRuntimeComparison(
        status="dual_consistent",
        source="local_ocr_locked_evaluator",
        reason=None,
        selected_runtime_kind="gpu",
        critical_fields_match=True,
        differences=(),
        outputs=outputs,
        failures=(),
    )
    selected = outputs[1]
    return LockedRolePrediction(
        image_sha256=selected.image_sha256,
        role=selected.role,
        quality=selected.role_quality,
        confidence=selected.role_confidence,
        high_confidence=selected.role_high_confidence,
        assessment_fingerprint=selected.assessment_fingerprint,
        incremental_elapsed_ms=Decimal("8"),
        runtime_comparison=comparison,
    )


def _evaluate(
    tmp_path: Path,
    prediction: LockedRolePrediction,
):
    return evaluate_controlled_non_ticket_gate(
        challenge=_challenge(tmp_path),
        prediction=prediction,
        source_authority_sha256=_sha256("source-authority"),
        execution_authority_sha256=_sha256("execution-authority"),
        development_authority_rollover_sha256=_sha256("rollover"),
    )


def test_non_ticket_requires_dual_unknown_and_both_slots_route_to_review(
    tmp_path: Path,
) -> None:
    result = _evaluate(tmp_path, _prediction())

    assert result.passed is True
    assert result.payload["metrics_exclusion"] == {
        "accuracy": True,
        "confusion_matrix": True,
        "historical_prevalence": True,
        "latency": True,
        "layout_distribution": True,
        "natural_sample_count": True,
        "unknown_rate": True,
    }
    assert result.payload["slot_scenarios"] == [
        {
            "automatic_outcome": "awaiting_review",
            "challenge_slot": "loading",
            "role_issue": "role_unknown",
            "roles_valid": False,
        },
        {
            "automatic_outcome": "awaiting_review",
            "challenge_slot": "unloading",
            "role_issue": "role_unknown",
            "roles_valid": False,
        },
    ]


def test_non_ticket_rejects_known_role_or_single_runtime(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ControlledNonTicketGateError,
        match="did not pass",
    ):
        _evaluate(
            tmp_path,
            _prediction(
                role=TicketRole.LOADING,
                ordinary_net_reliable=True,
            ),
        )

    single = replace(
        _prediction(),
        runtime_comparison=LockedOcrRuntimeComparison(
            status="single_cpu",
            source="local_ocr_locked_evaluator",
            reason="single_qualified_cpu",
            selected_runtime_kind="cpu",
            critical_fields_match=None,
            differences=(),
            outputs=(_output(runtime_kind="cpu"),),
            failures=(),
        ),
        assessment_fingerprint=_output(
            runtime_kind="cpu"
        ).assessment_fingerprint,
    )
    with pytest.raises(
        ControlledNonTicketGateError,
        match="did not pass",
    ):
        _evaluate(tmp_path, single)
