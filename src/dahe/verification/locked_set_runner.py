from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import PurePosixPath

from dahe.domain.audit.evidence import (
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import (
    TicketRole,
    TicketSlot,
    assess_ticket_roles,
)
from dahe.verification.application_build import ApplicationBuildManifest
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedSetReleaseAttestation,
)
from dahe.verification.locked_set_acceptance import (
    DERIVED_ADVERSARIAL_GENERATOR_VERSION,
    LOCAL_OCR_RUNTIME_SOURCE,
    NOT_MEASURED_RUNTIME_REASON,
    RUNTIME_COMPARISON_EVIDENCE_VERSION,
    build_locked_set_derived_adversarial_suite,
    evaluate_locked_set_release,
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RUNNER_VERSION = "dahe.loop7.locked-role-runner.v5"
_RUNTIME_KINDS = frozenset({"cpu", "gpu"})
_RUNTIME_COMPARISON_STATUSES = frozenset(
    {
        "not_measured",
        "single_cpu",
        "dual_consistent",
        "dual_different",
        "gpu_failed_cpu_fallback",
    }
)
_SAFETY_ROUTES = frozenset(
    {
        "eligible_for_downstream_comparison",
        "non_automatic",
    }
)
_AUTOMATIC_REVIEW_REASONS = frozenset(
    {
        "ocr_weight_disagreement",
        "ticket_weight_format_suspicious",
    }
)


class LockedSetRunnerError(RuntimeError):
    """Raised when technical or contract evidence prevents a formal run."""


@dataclass(frozen=True, slots=True)
class IndependentLockedImage:
    """The only locked-set data an OCR or role evaluator may receive."""

    image_sha256: str
    relative_path: str

    def __post_init__(self) -> None:
        if SHA256_PATTERN.fullmatch(self.image_sha256) is None:
            raise LockedSetRunnerError("independent image identity must be a lowercase SHA-256")
        if not self.relative_path or "\\" in self.relative_path or ":" in self.relative_path:
            raise LockedSetRunnerError("independent image relative path is invalid")
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            raise LockedSetRunnerError("independent image relative path is invalid")


def _is_probability(value: object) -> bool:
    return isinstance(value, Decimal) and value.is_finite() and Decimal(0) <= value <= Decimal(1)


def _is_elapsed(value: object) -> bool:
    return isinstance(value, Decimal) and value.is_finite() and value >= Decimal(0)


def _decimal_payload(value: Decimal | None) -> str | None:
    if value is None:
        return None
    normalized = value.normalize()
    return "0" if normalized == 0 else format(normalized, "f")


@dataclass(frozen=True, slots=True)
class LockedOcrRuntimeOutput:
    """One successful runtime's image-bound critical output and latency."""

    image_sha256: str
    runtime_kind: str
    runtime_fingerprint: str
    output_fingerprint: str
    worker_elapsed_ms: Decimal
    wall_elapsed_ms: Decimal
    ordinary_net_amount: Decimal | None
    ordinary_net_unit: str | None
    ordinary_net_confidence: Decimal | None
    ordinary_net_reliable: bool
    role: TicketRole
    role_quality: EvidenceQuality
    role_confidence: Decimal
    role_high_confidence: bool
    safety_route: str
    assessment_fingerprint: str
    weight_review_reason: str | None = None
    # Historical Loop 7 evidence did not persist this timing. New formal Loop 9
    # evidence requires it, while the optional field preserves read compatibility.
    role_elapsed_ms: Decimal | None = None

    def __post_init__(self) -> None:
        if (
            SHA256_PATTERN.fullmatch(self.image_sha256) is None
            or self.runtime_kind not in _RUNTIME_KINDS
            or SHA256_PATTERN.fullmatch(self.runtime_fingerprint) is None
            or SHA256_PATTERN.fullmatch(self.output_fingerprint) is None
            or SHA256_PATTERN.fullmatch(self.assessment_fingerprint) is None
            or not _is_elapsed(self.worker_elapsed_ms)
            or not _is_elapsed(self.wall_elapsed_ms)
            or (
                self.role_elapsed_ms is not None
                and not _is_elapsed(self.role_elapsed_ms)
            )
        ):
            raise LockedSetRunnerError("runtime output evidence is invalid")
        if self.ordinary_net_amount is not None and (
            not isinstance(self.ordinary_net_amount, Decimal)
            or not self.ordinary_net_amount.is_finite()
            or self.ordinary_net_amount <= 0
        ):
            raise LockedSetRunnerError("runtime ordinary-net evidence is invalid")
        if self.ordinary_net_unit is not None and (
            not isinstance(self.ordinary_net_unit, str)
            or not self.ordinary_net_unit.strip()
            or len(self.ordinary_net_unit) > 16
        ):
            raise LockedSetRunnerError("runtime ordinary-net evidence is invalid")
        if self.ordinary_net_confidence is not None and not _is_probability(
            self.ordinary_net_confidence
        ):
            raise LockedSetRunnerError("runtime ordinary-net evidence is invalid")
        if not isinstance(self.ordinary_net_reliable, bool):
            raise LockedSetRunnerError("runtime ordinary-net evidence is invalid")
        if (
            self.weight_review_reason is not None
            and self.weight_review_reason not in _AUTOMATIC_REVIEW_REASONS
        ):
            raise LockedSetRunnerError("runtime weight-review evidence is invalid")
        if self.weight_review_reason is not None and self.ordinary_net_reliable:
            raise LockedSetRunnerError("review-required weight cannot be reliable")
        if self.ordinary_net_reliable and (
            self.ordinary_net_amount is None
            or self.ordinary_net_unit != "t"
            or self.ordinary_net_confidence is None
            or self.ordinary_net_amount != self.ordinary_net_amount.quantize(Decimal("0.01"))
        ):
            raise LockedSetRunnerError("reliable ordinary-net evidence is invalid")
        if (
            not isinstance(self.role, TicketRole)
            or not isinstance(self.role_quality, EvidenceQuality)
            or not _is_probability(self.role_confidence)
            or not isinstance(self.role_high_confidence, bool)
        ):
            raise LockedSetRunnerError("runtime role evidence is invalid")
        if self.role is TicketRole.UNKNOWN and (
            self.role_quality is EvidenceQuality.RELIABLE or self.role_high_confidence
        ):
            raise LockedSetRunnerError("runtime role evidence is invalid")
        if (
            self.role is not TicketRole.UNKNOWN
            and self.role_quality is not EvidenceQuality.RELIABLE
        ):
            raise LockedSetRunnerError("runtime role evidence is invalid")
        expected_route = (
            "eligible_for_downstream_comparison"
            if (
                self.role is not TicketRole.UNKNOWN
                and self.role_quality is EvidenceQuality.RELIABLE
                and self.ordinary_net_reliable
            )
            else "non_automatic"
        )
        if self.safety_route not in _SAFETY_ROUTES or self.safety_route != expected_route:
            raise LockedSetRunnerError("runtime safety-route evidence is invalid")

    def critical_payload(self) -> dict[str, object]:
        return {
            "ordinary_net_amount": _decimal_payload(self.ordinary_net_amount),
            "ordinary_net_unit": self.ordinary_net_unit,
            "ordinary_net_reliable": self.ordinary_net_reliable,
            "weight_review_reason": self.weight_review_reason,
            "role": self.role.value,
            "role_quality": self.role_quality.value,
            "role_high_confidence": self.role_high_confidence,
            "safety_route": self.safety_route,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            "assessment_fingerprint": self.assessment_fingerprint,
            "critical_output": self.critical_payload(),
            "image_sha256": self.image_sha256,
            "ordinary_net_confidence": _decimal_payload(self.ordinary_net_confidence),
            "output_fingerprint": self.output_fingerprint,
            "role_confidence": _decimal_payload(self.role_confidence),
            "runtime_fingerprint": self.runtime_fingerprint,
            "runtime_kind": self.runtime_kind,
            "wall_elapsed_ms": _decimal_text(self.wall_elapsed_ms),
            "worker_elapsed_ms": _decimal_text(self.worker_elapsed_ms),
        }


@dataclass(frozen=True, slots=True)
class LockedOcrRuntimeFailure:
    """One failed runtime attempt without fabricated business output."""

    image_sha256: str
    runtime_kind: str
    runtime_fingerprint: str
    wall_elapsed_ms: Decimal
    error_kind: str
    diagnostic_code: str

    def __post_init__(self) -> None:
        if (
            SHA256_PATTERN.fullmatch(self.image_sha256) is None
            or self.runtime_kind not in _RUNTIME_KINDS
            or SHA256_PATTERN.fullmatch(self.runtime_fingerprint) is None
            or not _is_elapsed(self.wall_elapsed_ms)
            or not isinstance(self.error_kind, str)
            or not self.error_kind.strip()
            or len(self.error_kind) > 64
            or not isinstance(self.diagnostic_code, str)
            or not self.diagnostic_code.strip()
            or len(self.diagnostic_code) > 128
        ):
            raise LockedSetRunnerError("runtime failure evidence is invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "diagnostic_code": self.diagnostic_code,
            "error_kind": self.error_kind,
            "image_sha256": self.image_sha256,
            "runtime_fingerprint": self.runtime_fingerprint,
            "runtime_kind": self.runtime_kind,
            "wall_elapsed_ms": _decimal_text(self.wall_elapsed_ms),
        }


@dataclass(frozen=True, slots=True)
class LockedOcrRuntimeComparison:
    """Per-image CPU/GPU parity evidence with explicit non-measurement states."""

    status: str
    source: str | None
    reason: str | None
    selected_runtime_kind: str | None
    critical_fields_match: bool | None
    differences: tuple[str, ...]
    outputs: tuple[LockedOcrRuntimeOutput, ...]
    failures: tuple[LockedOcrRuntimeFailure, ...]

    def __post_init__(self) -> None:
        if (
            self.status not in _RUNTIME_COMPARISON_STATUSES
            or (
                self.source is not None
                and (
                    not isinstance(self.source, str)
                    or not self.source.strip()
                    or len(self.source) > 64
                )
            )
            or (
                self.reason is not None
                and (
                    not isinstance(self.reason, str)
                    or not self.reason.strip()
                    or len(self.reason) > 128
                )
            )
            or (
                self.selected_runtime_kind is not None
                and self.selected_runtime_kind not in _RUNTIME_KINDS
            )
            or self.critical_fields_match not in {True, False, None}
            or any(not isinstance(value, str) or not value for value in self.differences)
            or len(set(self.differences)) != len(self.differences)
            or any(not isinstance(value, LockedOcrRuntimeOutput) for value in self.outputs)
            or any(not isinstance(value, LockedOcrRuntimeFailure) for value in self.failures)
        ):
            raise LockedSetRunnerError("runtime comparison evidence is invalid")
        output_kinds = tuple(value.runtime_kind for value in self.outputs)
        failure_kinds = tuple(value.runtime_kind for value in self.failures)
        if (
            len(set(output_kinds)) != len(output_kinds)
            or len(set(failure_kinds)) != len(failure_kinds)
            or set(output_kinds).intersection(failure_kinds)
        ):
            raise LockedSetRunnerError("runtime comparison evidence is invalid")
        if self.status == "not_measured":
            valid = (
                self.source is None
                and self.reason == NOT_MEASURED_RUNTIME_REASON
                and self.selected_runtime_kind is None
                and self.critical_fields_match is None
                and not self.differences
                and not self.outputs
                and not self.failures
            )
        elif self.status == "single_cpu":
            valid = (
                self.source == LOCAL_OCR_RUNTIME_SOURCE
                and self.reason == "single_qualified_cpu"
                and self.selected_runtime_kind == "cpu"
                and self.critical_fields_match is None
                and not self.differences
                and set(output_kinds) == {"cpu"}
                and not self.failures
            )
        elif self.status == "dual_consistent":
            critical_payloads = [
                value.critical_payload()
                for value in sorted(
                    self.outputs,
                    key=lambda item: item.runtime_kind,
                )
            ]
            valid = (
                self.source == LOCAL_OCR_RUNTIME_SOURCE
                and self.reason is None
                and self.selected_runtime_kind in {"cpu", "gpu"}
                and self.critical_fields_match is True
                and not self.differences
                and set(output_kinds) == {"cpu", "gpu"}
                and not self.failures
                and len(critical_payloads) == 2
                and critical_payloads[0] == critical_payloads[1]
            )
        elif self.status == "dual_different":
            ordered_outputs = sorted(
                self.outputs,
                key=lambda item: item.runtime_kind,
            )
            actual_differences = (
                tuple(
                    field
                    for field in sorted(ordered_outputs[0].critical_payload())
                    if ordered_outputs[0].critical_payload()[field]
                    != ordered_outputs[1].critical_payload()[field]
                )
                if tuple(item.runtime_kind for item in ordered_outputs)
                == ("cpu", "gpu")
                else ()
            )
            valid = (
                self.source == LOCAL_OCR_RUNTIME_SOURCE
                and self.reason == "critical_outputs_differ"
                and self.selected_runtime_kind == "cpu"
                and self.critical_fields_match is False
                and set(self.differences) == set(actual_differences)
                and bool(actual_differences)
                and set(output_kinds) == {"cpu", "gpu"}
                and not self.failures
            )
        else:
            valid = (
                self.source == LOCAL_OCR_RUNTIME_SOURCE
                and self.reason == "gpu_runtime_failed"
                and self.selected_runtime_kind == "cpu"
                and self.critical_fields_match is None
                and not self.differences
                and set(output_kinds) == {"cpu"}
                and set(failure_kinds) == {"gpu"}
            )
        if not valid:
            raise LockedSetRunnerError("runtime comparison status is inconsistent")

    @classmethod
    def not_measured(cls) -> LockedOcrRuntimeComparison:
        return cls(
            status="not_measured",
            source=None,
            reason=NOT_MEASURED_RUNTIME_REASON,
            selected_runtime_kind=None,
            critical_fields_match=None,
            differences=(),
            outputs=(),
            failures=(),
        )

    def _payload_without_hash(self) -> dict[str, object]:
        return {
            "critical_fields_match": self.critical_fields_match,
            "differences": list(self.differences),
            "failures": [
                value.to_payload()
                for value in sorted(
                    self.failures,
                    key=lambda item: item.runtime_kind,
                )
            ],
            "outputs": [
                value.to_payload()
                for value in sorted(
                    self.outputs,
                    key=lambda item: item.runtime_kind,
                )
            ],
            "reason": self.reason,
            "schema_version": RUNTIME_COMPARISON_EVIDENCE_VERSION,
            "selected_runtime_kind": self.selected_runtime_kind,
            "source": self.source,
            "status": self.status,
        }

    @property
    def comparison_sha256(self) -> str:
        return _canonical_sha256(self._payload_without_hash())

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_hash()
        payload["comparison_sha256"] = self.comparison_sha256
        return payload


@dataclass(frozen=True, slots=True)
class LockedRolePrediction:
    image_sha256: str
    role: TicketRole
    quality: EvidenceQuality
    confidence: Decimal
    high_confidence: bool
    assessment_fingerprint: str
    incremental_elapsed_ms: Decimal
    runtime_comparison: LockedOcrRuntimeComparison = field(
        default_factory=LockedOcrRuntimeComparison.not_measured
    )
    automatic_review_reason: str | None = None

    def __post_init__(self) -> None:
        if SHA256_PATTERN.fullmatch(self.image_sha256) is None:
            raise LockedSetRunnerError("prediction image identity is invalid")
        if not isinstance(self.role, TicketRole) or not isinstance(
            self.quality,
            EvidenceQuality,
        ):
            raise LockedSetRunnerError("prediction contract is invalid")
        if (
            not isinstance(self.confidence, Decimal)
            or not self.confidence.is_finite()
            or not 0 <= self.confidence <= 1
        ):
            raise LockedSetRunnerError("prediction contract is invalid")
        if not isinstance(self.high_confidence, bool):
            raise LockedSetRunnerError("prediction contract is invalid")
        if self.role is TicketRole.UNKNOWN and (
            self.quality is EvidenceQuality.RELIABLE or self.high_confidence
        ):
            raise LockedSetRunnerError("prediction contract is invalid")
        if self.role is not TicketRole.UNKNOWN and self.quality is not EvidenceQuality.RELIABLE:
            raise LockedSetRunnerError("prediction contract is invalid")
        if SHA256_PATTERN.fullmatch(self.assessment_fingerprint) is None:
            raise LockedSetRunnerError("prediction contract is invalid")
        if (
            not isinstance(self.incremental_elapsed_ms, Decimal)
            or not self.incremental_elapsed_ms.is_finite()
            or self.incremental_elapsed_ms < 0
        ):
            raise LockedSetRunnerError("prediction contract is invalid")
        if not isinstance(self.runtime_comparison, LockedOcrRuntimeComparison):
            raise LockedSetRunnerError("prediction runtime comparison is invalid")
        if (
            self.automatic_review_reason is not None
            and self.automatic_review_reason
            not in _AUTOMATIC_REVIEW_REASONS
        ):
            raise LockedSetRunnerError("prediction review reason is invalid")
        evidence_images = {value.image_sha256 for value in self.runtime_comparison.outputs}.union(
            value.image_sha256 for value in self.runtime_comparison.failures
        )
        if evidence_images and evidence_images != {self.image_sha256}:
            raise LockedSetRunnerError("prediction runtime comparison image changed")
        if self.runtime_comparison.selected_runtime_kind is not None:
            selected_output: LockedOcrRuntimeOutput | None = next(
                (
                    value
                    for value in self.runtime_comparison.outputs
                    if value.runtime_kind == self.runtime_comparison.selected_runtime_kind
                ),
                None,
            )
            if selected_output is None or (
                selected_output.role is not self.role
                or selected_output.role_quality is not self.quality
                or selected_output.role_confidence != self.confidence
                or selected_output.role_high_confidence is not self.high_confidence
                or selected_output.assessment_fingerprint != self.assessment_fingerprint
            ):
                raise LockedSetRunnerError("prediction differs from selected runtime evidence")


LockedImageEvaluator = Callable[[IndependentLockedImage], LockedRolePrediction]


@dataclass(frozen=True, slots=True)
class LockedSetRunContext:
    application_build_sha256: str
    application_build_manifest: ApplicationBuildManifest
    runtime_set_sha256: str
    ocr_composition_evidence_sha256: str
    template_set_sha256: str
    matcher_sha256: str
    policy_sha256: str
    expected_runtime_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.application_build_manifest, ApplicationBuildManifest)
            or self.application_build_manifest.canonical_sha256
            != self.application_build_sha256
        ):
            raise LockedSetRunnerError(
                "locked-set application build evidence is inconsistent"
            )
        for value in (
            self.application_build_sha256,
            self.runtime_set_sha256,
            self.ocr_composition_evidence_sha256,
            self.template_set_sha256,
            self.matcher_sha256,
            self.policy_sha256,
        ):
            if SHA256_PATTERN.fullmatch(value) is None:
                raise LockedSetRunnerError("locked-set run context fingerprints are invalid")
        if self.expected_runtime_kinds not in {
            ("cpu",),
            ("cpu", "gpu"),
        }:
            raise LockedSetRunnerError("locked-set expected runtime kinds are invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "application_build_manifest": self.application_build_manifest.to_payload(),
            "application_build_sha256": self.application_build_sha256,
            "expected_runtime_kinds": list(self.expected_runtime_kinds),
            "matcher_sha256": self.matcher_sha256,
            "ocr_composition_evidence_sha256": (self.ocr_composition_evidence_sha256),
            "policy_sha256": self.policy_sha256,
            "runtime_set_sha256": self.runtime_set_sha256,
            "template_set_sha256": self.template_set_sha256,
        }


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decimal_text(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.001")), ".3f")


def content_addressed_evidence_relative_path(image_sha256: str) -> str:
    """Return the only path shape exposed to a locked-set evaluator."""

    if SHA256_PATTERN.fullmatch(image_sha256) is None:
        raise LockedSetRunnerError("locked image identity is invalid")
    return f"evidence/sha256/{image_sha256[:2]}/{image_sha256[2:4]}/{image_sha256}.blob"


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


def _pair_ticket(
    *,
    slot: TicketSlot,
    prediction: LockedRolePrediction,
) -> TicketEvidence:
    return TicketEvidence(
        slot=slot,
        image_sha256=prediction.image_sha256,
        machine_role=prediction.role,
        role_quality=prediction.quality,
        weights=_missing_weights(),
        extraction_fingerprint=_canonical_sha256(
            {
                "image_sha256": prediction.image_sha256,
                "purpose": "locked_role_pair_without_weight_decision",
                "runner_version": RUNNER_VERSION,
            }
        ),
        role_fingerprint=prediction.assessment_fingerprint,
    )


def _truth_manifest_payload(
    manifest: LockedSetManifest,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "waybill_count": manifest.waybill_count,
        "image_count": manifest.image_count,
        "pairs": [
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "truth_role": image.role.value,
                    }
                    for image in waybill.images
                ],
                "submitted_slots": {
                    image.slot.value: image.image_sha256 for image in waybill.images
                },
            }
            for waybill in manifest.waybills
        ],
    }


def _attestation_payload(
    attestation: LockedSetReleaseAttestation,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": attestation.dataset_id,
        "manifest_sha256": attestation.manifest_sha256,
        "attestation_sha256": attestation.attestation_sha256,
        "exclusion_snapshot_sha256": (attestation.exclusion_snapshot_sha256),
        "waybill_count": attestation.waybill_count,
        "image_count": attestation.image_count,
    }


def run_locked_set_role_evaluation(
    *,
    manifest: LockedSetManifest,
    preflight_attestation: LockedSetReleaseAttestation,
    evaluator: LockedImageEvaluator,
    run_context: LockedSetRunContext,
    quality_coverage: object,
    near_duplicate_scan: object,
    near_duplicate_decisions: object,
    eligibility_history: object,
    candidate_review_source_authority: object,
) -> dict[str, object]:
    """Run the sealed role gate without exposing truth or platform context."""

    if not isinstance(manifest, LockedSetManifest):
        raise LockedSetRunnerError("locked-set manifest is invalid")
    if (
        manifest.dataset_kind != "locked"
        or manifest.tuning_prohibited is not True
        or manifest.waybill_count != 50
        or manifest.image_count != 100
    ):
        raise LockedSetRunnerError("locked-set manifest is not release eligible")
    if not isinstance(preflight_attestation, LockedSetReleaseAttestation):
        raise LockedSetRunnerError("locked-set preflight attestation is invalid")
    if (
        preflight_attestation.dataset_id != manifest.dataset_id
        or preflight_attestation.manifest_sha256 != manifest.canonical_sha256
        or preflight_attestation.waybill_count != manifest.waybill_count
        or preflight_attestation.image_count != manifest.image_count
    ):
        raise LockedSetRunnerError("locked-set preflight attestation does not match the manifest")
    if not callable(evaluator):
        raise LockedSetRunnerError("locked image evaluator is required")
    if not isinstance(run_context, LockedSetRunContext):
        raise LockedSetRunnerError("locked-set run context is required")
    evaluator_context = getattr(evaluator, "run_context", None)
    if not isinstance(evaluator_context, LockedSetRunContext):
        raise LockedSetRunnerError("authoritative evaluator run context is required")
    if evaluator_context != run_context:
        raise LockedSetRunnerError("locked-set run context is not bound to the evaluator")
    if run_context.expected_runtime_kinds != ("cpu", "gpu"):
        raise LockedSetRunnerError("formal locked-set evaluation requires exactly CPU plus GPU")

    predictions: dict[str, LockedRolePrediction] = {}
    image_results: list[dict[str, object]] = []
    image_membership = {
        image.image_sha256: waybill.sample_id
        for waybill in manifest.waybills
        for image in waybill.images
    }
    for image_sha256 in sorted(image_membership):
        independent = IndependentLockedImage(
            image_sha256=image_sha256,
            relative_path=content_addressed_evidence_relative_path(image_sha256),
        )
        try:
            prediction = evaluator(independent)
        except LockedSetRunnerError:
            raise
        except Exception as exc:
            raise LockedSetRunnerError("locked image evaluator had a technical failure") from exc
        if not isinstance(prediction, LockedRolePrediction):
            raise LockedSetRunnerError("prediction contract is invalid")
        if prediction.image_sha256 != independent.image_sha256:
            raise LockedSetRunnerError("prediction image identity does not match locked evidence")
        if prediction.image_sha256 in predictions:
            raise LockedSetRunnerError("locked image was evaluated twice")
        predictions[prediction.image_sha256] = prediction
        runtime_comparison = prediction.runtime_comparison.to_payload()
        image_results.append(
            {
                "result_id": _canonical_sha256(
                    {
                        "assessment_fingerprint": (prediction.assessment_fingerprint),
                        "image_sha256": prediction.image_sha256,
                        "runner_version": RUNNER_VERSION,
                        "runtime_comparison_sha256": (runtime_comparison["comparison_sha256"]),
                    }
                ),
                "sample_id": image_membership[image_sha256],
                "image_sha256": prediction.image_sha256,
                "predicted_role": prediction.role.value,
                "high_confidence": prediction.high_confidence,
                "automatic_review_reason": prediction.automatic_review_reason,
                "incremental_elapsed_ms": _decimal_text(prediction.incremental_elapsed_ms),
                "runtime_comparison": runtime_comparison,
            }
        )
    if len(predictions) != 100:
        raise LockedSetRunnerError("locked image evaluation count did not reconcile")

    pair_results: list[dict[str, object]] = []
    for waybill in manifest.waybills:
        by_slot = {image.slot: image for image in waybill.images}
        if set(by_slot) != {TicketSlot.LOADING, TicketSlot.UNLOADING}:
            raise LockedSetRunnerError("locked waybill submitted slots do not reconcile")
        loading = by_slot[TicketSlot.LOADING]
        unloading = by_slot[TicketSlot.UNLOADING]
        assessment = assess_ticket_roles(
            _pair_ticket(
                slot=TicketSlot.LOADING,
                prediction=predictions[loading.image_sha256],
            ),
            _pair_ticket(
                slot=TicketSlot.UNLOADING,
                prediction=predictions[unloading.image_sha256],
            ),
        )
        issue = None if assessment.issue is None else assessment.issue.value
        review_reasons = {
            reason
            for reason in (
                predictions[loading.image_sha256].automatic_review_reason,
                predictions[unloading.image_sha256].automatic_review_reason,
            )
            if reason is not None
        }
        review_reason = (
            "ocr_weight_disagreement"
            if "ocr_weight_disagreement" in review_reasons
            else (
                "ticket_weight_format_suspicious"
                if "ticket_weight_format_suspicious" in review_reasons
                else None
            )
        )
        pair_results.append(
            {
                "result_id": _canonical_sha256(
                    {
                        "loading_image_sha256": loading.image_sha256,
                        "runner_version": RUNNER_VERSION,
                        "sample_id": waybill.sample_id,
                        "unloading_image_sha256": unloading.image_sha256,
                    }
                ),
                "sample_id": waybill.sample_id,
                "loading_slot_image_sha256": loading.image_sha256,
                "unloading_slot_image_sha256": unloading.image_sha256,
                "automatic_outcome": (
                    "normal_ready"
                    if assessment.roles_valid and review_reason is None
                    else "awaiting_review"
                ),
                "role_issue": issue,
                "review_reason": review_reason,
            }
        )

    truth_manifest = _truth_manifest_payload(manifest)
    raw_suite = build_locked_set_derived_adversarial_suite(
        truth_manifest,
    )
    raw_scenarios = raw_suite.get("scenarios")
    if raw_suite.get(
        "generator_version"
    ) != DERIVED_ADVERSARIAL_GENERATOR_VERSION or not isinstance(raw_scenarios, list):
        raise LockedSetRunnerError("derived adversarial suite is invalid")
    if len(raw_scenarios) != 4:
        raise LockedSetRunnerError("derived adversarial suite is invalid")
    derived_results: list[dict[str, object]] = []
    for raw_scenario in raw_scenarios:
        if not isinstance(raw_scenario, dict):
            raise LockedSetRunnerError("derived adversarial suite is invalid")
        scenario_id = raw_scenario.get("scenario_id")
        loading_hash = raw_scenario.get("loading_slot_image_sha256")
        unloading_hash = raw_scenario.get("unloading_slot_image_sha256")
        if (
            not isinstance(scenario_id, str)
            or not isinstance(loading_hash, str)
            or not isinstance(unloading_hash, str)
            or loading_hash not in predictions
            or unloading_hash not in predictions
        ):
            raise LockedSetRunnerError("derived adversarial suite is invalid")
        assessment = assess_ticket_roles(
            _pair_ticket(
                slot=TicketSlot.LOADING,
                prediction=predictions[loading_hash],
            ),
            _pair_ticket(
                slot=TicketSlot.UNLOADING,
                prediction=predictions[unloading_hash],
            ),
        )
        derived_review_reasons = {
            reason
            for reason in (
                predictions[loading_hash].automatic_review_reason,
                predictions[unloading_hash].automatic_review_reason,
            )
            if reason is not None
        }
        derived_review_reason = (
            "ocr_weight_disagreement"
            if "ocr_weight_disagreement" in derived_review_reasons
            else (
                "ticket_weight_format_suspicious"
                if "ticket_weight_format_suspicious"
                in derived_review_reasons
                else None
            )
        )
        derived_results.append(
            {
                "scenario_id": scenario_id,
                "loading_slot_image_sha256": loading_hash,
                "unloading_slot_image_sha256": unloading_hash,
                "automatic_outcome": (
                    "normal_ready"
                    if assessment.roles_valid
                    and derived_review_reason is None
                    else "awaiting_review"
                ),
                "role_issue": (None if assessment.issue is None else assessment.issue.value),
                "review_reason": derived_review_reason,
            }
        )

    report = evaluate_locked_set_release(
        preflight_attestation=_attestation_payload(preflight_attestation),
        truth_manifest=truth_manifest,
        image_results=image_results,
        pair_results=pair_results,
        quality_coverage=quality_coverage,
        near_duplicate_scan=near_duplicate_scan,
        near_duplicate_decisions=near_duplicate_decisions,
        eligibility_history=eligibility_history,
        candidate_review_source_authority=(
            candidate_review_source_authority
        ),
        expected_runtime_kinds=run_context.expected_runtime_kinds,
    )
    reported_derived = report.get("derived_adversarial_results")
    if not isinstance(reported_derived, dict) or reported_derived.get("results") != derived_results:
        raise LockedSetRunnerError(
            "derived adversarial routing differs from the production role policy"
        )
    report["runner_version"] = RUNNER_VERSION
    report["run_context"] = run_context.to_payload()
    report["image_results"] = image_results
    report["pair_results"] = pair_results
    report["runner_report_sha256"] = _canonical_sha256(report)
    return report
