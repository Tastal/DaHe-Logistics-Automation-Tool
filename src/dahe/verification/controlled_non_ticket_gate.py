from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

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
from dahe.verification.controlled_non_ticket_challenge import (
    ControlledNonTicketChallenge,
)
from dahe.verification.locked_set_runner import LockedRolePrediction

SCHEMA_VERSION = 1
KIND = "loop7_controlled_non_ticket_gate"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ControlledNonTicketGateError(ValueError):
    """Raised when the controlled non-ticket image is not safely rejected."""


@dataclass(frozen=True, slots=True)
class ControlledNonTicketGateResult:
    payload: dict[str, object]
    result_sha256: str
    passed: bool


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ControlledNonTicketGateError(
            "controlled challenge result is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ControlledNonTicketGateError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


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
    *,
    slot: TicketSlot,
    image_sha256: str,
    role: TicketRole,
    quality: EvidenceQuality,
    fingerprint: str,
) -> TicketEvidence:
    return TicketEvidence(
        slot=slot,
        image_sha256=image_sha256,
        machine_role=role,
        role_quality=quality,
        weights=_missing_weights(),
        extraction_fingerprint=fingerprint,
        role_fingerprint=fingerprint,
    )


def _slot_scenarios(
    prediction: LockedRolePrediction,
) -> list[dict[str, object]]:
    counterpart_sha256 = _canonical_sha256(
        {
            "kind": "controlled_non_ticket_counterpart",
            "schema_version": 1,
        }
    )
    counterpart_fingerprint = _canonical_sha256(
        {
            "kind": "controlled_non_ticket_counterpart_role",
            "schema_version": 1,
        }
    )
    scenarios: list[dict[str, object]] = []
    for challenge_slot in (TicketSlot.LOADING, TicketSlot.UNLOADING):
        counterpart_slot = (
            TicketSlot.UNLOADING
            if challenge_slot is TicketSlot.LOADING
            else TicketSlot.LOADING
        )
        counterpart_role = (
            TicketRole.UNLOADING
            if counterpart_slot is TicketSlot.UNLOADING
            else TicketRole.LOADING
        )
        challenge = _ticket(
            slot=challenge_slot,
            image_sha256=prediction.image_sha256,
            role=prediction.role,
            quality=prediction.quality,
            fingerprint=prediction.assessment_fingerprint,
        )
        counterpart = _ticket(
            slot=counterpart_slot,
            image_sha256=counterpart_sha256,
            role=counterpart_role,
            quality=EvidenceQuality.RELIABLE,
            fingerprint=counterpart_fingerprint,
        )
        loading = (
            challenge
            if challenge_slot is TicketSlot.LOADING
            else counterpart
        )
        unloading = (
            challenge
            if challenge_slot is TicketSlot.UNLOADING
            else counterpart
        )
        assessment = assess_ticket_roles(loading, unloading)
        scenarios.append(
            {
                "automatic_outcome": "awaiting_review",
                "challenge_slot": challenge_slot.value,
                "role_issue": (
                    None
                    if assessment.issue is None
                    else assessment.issue.value
                ),
                "roles_valid": assessment.roles_valid,
            }
        )
    return scenarios


def evaluate_controlled_non_ticket_gate(
    *,
    challenge: ControlledNonTicketChallenge,
    prediction: LockedRolePrediction,
    source_authority_sha256: str,
    execution_authority_sha256: str,
    development_authority_rollover_sha256: str,
) -> ControlledNonTicketGateResult:
    """Require both qualified runtimes and both upload slots to reject safely."""

    if not isinstance(challenge, ControlledNonTicketChallenge):
        raise ControlledNonTicketGateError(
            "controlled challenge artifact is required"
        )
    if not isinstance(prediction, LockedRolePrediction):
        raise ControlledNonTicketGateError(
            "locked role prediction is required"
        )
    redacted_sha256 = _sha256(
        challenge.payload.get("redacted_sha256"),
        label="redacted image SHA-256",
    )
    if prediction.image_sha256 != redacted_sha256:
        raise ControlledNonTicketGateError(
            "prediction does not match the redacted challenge"
        )
    comparison = prediction.runtime_comparison
    output_kinds = {output.runtime_kind for output in comparison.outputs}
    outputs_safe = (
        comparison.status == "dual_consistent"
        and comparison.critical_fields_match is True
        and output_kinds == {"cpu", "gpu"}
        and not comparison.failures
        and all(
            output.role is TicketRole.UNKNOWN
            and output.role_quality is not EvidenceQuality.RELIABLE
            and output.role_high_confidence is False
            and output.ordinary_net_reliable is False
            and output.safety_route == "non_automatic"
            for output in comparison.outputs
        )
    )
    prediction_safe = (
        prediction.role is TicketRole.UNKNOWN
        and prediction.quality is not EvidenceQuality.RELIABLE
        and prediction.high_confidence is False
    )
    scenarios = _slot_scenarios(prediction)
    scenarios_safe = all(
        item["automatic_outcome"] == "awaiting_review"
        and item["role_issue"] == RoleIssue.ROLE_UNKNOWN.value
        and item["roles_valid"] is False
        for item in scenarios
    )
    passed = outputs_safe and prediction_safe and scenarios_safe
    payload: dict[str, object] = {
        "challenge_artifact_sha256": _sha256(
            challenge.payload.get("canonical_sha256"),
            label="challenge artifact SHA-256",
        ),
        "development_authority_rollover_sha256": _sha256(
            development_authority_rollover_sha256,
            label="development authority rollover SHA-256",
        ),
        "execution_authority_sha256": _sha256(
            execution_authority_sha256,
            label="execution authority SHA-256",
        ),
        "kind": KIND,
        "metrics_exclusion": {
            "accuracy": True,
            "confusion_matrix": True,
            "historical_prevalence": True,
            "latency": True,
            "layout_distribution": True,
            "natural_sample_count": True,
            "unknown_rate": True,
        },
        "passed": passed,
        "prediction": {
            "assessment_fingerprint": prediction.assessment_fingerprint,
            "confidence": str(prediction.confidence),
            "high_confidence": prediction.high_confidence,
            "incremental_elapsed_ms": str(
                prediction.incremental_elapsed_ms
            ),
            "quality": prediction.quality.value,
            "role": prediction.role.value,
            "runtime_comparison": comparison.to_payload(),
        },
        "redacted_sha256": redacted_sha256,
        "schema_version": SCHEMA_VERSION,
        "slot_scenarios": scenarios,
        "source_authority_sha256": _sha256(
            source_authority_sha256,
            label="source authority SHA-256",
        ),
    }
    payload["result_sha256"] = _canonical_sha256(payload)
    if not passed:
        raise ControlledNonTicketGateError(
            "controlled non-ticket challenge did not pass"
        )
    return parse_controlled_non_ticket_gate_result(payload)


def parse_controlled_non_ticket_gate_result(
    value: Mapping[str, object],
) -> ControlledNonTicketGateResult:
    payload = json.loads(_canonical_json(dict(value)))
    expected_fields = {
        "challenge_artifact_sha256",
        "development_authority_rollover_sha256",
        "execution_authority_sha256",
        "kind",
        "metrics_exclusion",
        "passed",
        "prediction",
        "redacted_sha256",
        "result_sha256",
        "schema_version",
        "slot_scenarios",
        "source_authority_sha256",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_fields
        or payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("kind") != KIND
        or payload.get("passed") is not True
    ):
        raise ControlledNonTicketGateError(
            "controlled non-ticket gate contract is unsupported"
        )
    result_sha256 = _sha256(
        payload.get("result_sha256"),
        label="controlled challenge result SHA-256",
    )
    without_hash = dict(payload)
    without_hash.pop("result_sha256")
    if _canonical_sha256(without_hash) != result_sha256:
        raise ControlledNonTicketGateError(
            "controlled challenge result SHA-256 does not match"
        )
    return ControlledNonTicketGateResult(
        payload=payload,
        result_sha256=result_sha256,
        passed=True,
    )


def write_controlled_non_ticket_gate_result(
    path: Path,
    result: ControlledNonTicketGateResult,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> Path:
    output = path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        existing = load_controlled_non_ticket_gate_result(
            output,
            expected_sha256=result.result_sha256,
        )
        if existing != result:
            raise ControlledNonTicketGateError(
                "controlled challenge result output conflicts"
            )
        return output
    content = (_canonical_json(result.payload) + "\n").encode("utf-8")
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if failpoint is not None:
            failpoint("after_challenge_result_staged_fsync")
        try:
            os.link(staged, output)
        except FileExistsError:
            existing = load_controlled_non_ticket_gate_result(
                output,
                expected_sha256=result.result_sha256,
            )
            if existing != result:
                raise ControlledNonTicketGateError(
                    "controlled challenge result output conflicts"
                ) from None
        except OSError as exc:
            raise ControlledNonTicketGateError(
                "controlled challenge result could not be published atomically"
            ) from exc
        return output
    finally:
        staged.unlink(missing_ok=True)


def load_controlled_non_ticket_gate_result(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> ControlledNonTicketGateResult:
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
        payload = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControlledNonTicketGateError(
            "controlled challenge result is not readable"
        ) from exc
    if (
        not resolved.is_file()
        or resolved.is_symlink()
        or not isinstance(payload, dict)
        or content != (_canonical_json(payload) + "\n").encode("utf-8")
    ):
        raise ControlledNonTicketGateError(
            "controlled challenge result file is invalid"
        )
    result = parse_controlled_non_ticket_gate_result(payload)
    if (
        expected_sha256 is not None
        and result.result_sha256 != expected_sha256
    ):
        raise ControlledNonTicketGateError(
            "controlled challenge result does not match the expected SHA-256"
        )
    return result
