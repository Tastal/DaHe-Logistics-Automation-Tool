from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, localcontext
from enum import StrEnum
from pathlib import Path
from typing import cast

from dahe.application.template_studio.matcher import (
    MATCHER_VERSION,
    DevelopmentEvaluationTemplateSet,
    ObservedTextLine,
    TemplateRoleInput,
    TemplateRoleRun,
    build_development_evaluation_template_set,
    match_ticket_role_for_development_evaluation,
)
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
    TicketRoleAssessment,
    summarize_role_metrics,
)
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
    TicketField,
)

RUNNER_VERSION = "loop7-frozen-development-evaluation-v2"
EVALUATION_PURPOSE = "development_evaluation"
SHA256_HEX_LENGTH = 64
WILSON_95_Z = Decimal("1.959963984540054")
RATE_QUANTUM = Decimal("0.000001")
AUTHORIZING_TRUTH_SOURCE = "code_authored_synthetic"


class FrozenDevelopmentFixtureError(ValueError):
    """Raised when a frozen development fixture violates the local contract."""


class MeasurementStatus(StrEnum):
    MEASURED = "measured"
    NOT_MEASURED = "not_measured"


@dataclass(frozen=True, slots=True)
class Measurement:
    status: MeasurementStatus
    value: object | None
    definition: str

    def to_payload(self) -> dict[str, object]:
        return {
            "definition": self.definition,
            "status": self.status.value,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentEvaluationMetrics:
    sample_count: Measurement
    quality_tag_distribution: Measurement
    development_sample_scope: Measurement
    expected_result_reconciliation: Measurement
    pair_reconciliation: Measurement
    confusion_matrix: Measurement
    unknown_rate: Measurement
    unknown_rate_wilson_95_ci: Measurement
    high_confidence_errors: Measurement
    p50_elapsed_ms: Measurement
    p95_elapsed_ms: Measurement
    geometry_match_rate: Measurement
    anchor_pass_rate: Measurement
    direct_completion_rate: Measurement
    fallback_rate: Measurement
    wrong_template_rate: Measurement
    wrong_template_rate_wilson_95_ci: Measurement
    synthetic_swapped_pair_recall: Measurement
    synthetic_swapped_pair_recall_wilson_95_ci: Measurement
    normal_pair_false_positive_rate: Measurement
    normal_pair_false_positive_rate_wilson_95_ci: Measurement
    role_conflict_rate: Measurement
    unknown_layout_rate: Measurement
    field_reliability: Measurement

    def to_payload(self) -> dict[str, object]:
        return {
            "anchor_pass_rate": self.anchor_pass_rate.to_payload(),
            "confusion_matrix": self.confusion_matrix.to_payload(),
            "development_sample_scope": self.development_sample_scope.to_payload(),
            "direct_completion_rate": self.direct_completion_rate.to_payload(),
            "expected_result_reconciliation": (
                self.expected_result_reconciliation.to_payload()
            ),
            "fallback_rate": self.fallback_rate.to_payload(),
            "field_reliability": self.field_reliability.to_payload(),
            "geometry_match_rate": self.geometry_match_rate.to_payload(),
            "high_confidence_errors": self.high_confidence_errors.to_payload(),
            "normal_pair_false_positive_rate": (
                self.normal_pair_false_positive_rate.to_payload()
            ),
            "normal_pair_false_positive_rate_wilson_95_ci": (
                self.normal_pair_false_positive_rate_wilson_95_ci.to_payload()
            ),
            "p50_elapsed_ms": self.p50_elapsed_ms.to_payload(),
            "p95_elapsed_ms": self.p95_elapsed_ms.to_payload(),
            "pair_reconciliation": self.pair_reconciliation.to_payload(),
            "quality_tag_distribution": self.quality_tag_distribution.to_payload(),
            "role_conflict_rate": self.role_conflict_rate.to_payload(),
            "sample_count": self.sample_count.to_payload(),
            "synthetic_swapped_pair_recall": (
                self.synthetic_swapped_pair_recall.to_payload()
            ),
            "synthetic_swapped_pair_recall_wilson_95_ci": (
                self.synthetic_swapped_pair_recall_wilson_95_ci.to_payload()
            ),
            "unknown_layout_rate": self.unknown_layout_rate.to_payload(),
            "unknown_rate": self.unknown_rate.to_payload(),
            "unknown_rate_wilson_95_ci": (
                self.unknown_rate_wilson_95_ci.to_payload()
            ),
            "wrong_template_rate": self.wrong_template_rate.to_payload(),
            "wrong_template_rate_wilson_95_ci": (
                self.wrong_template_rate_wilson_95_ci.to_payload()
            ),
        }

    def to_repository_metrics(self, *, sample_count: int) -> dict[str, object]:
        """Return the complete metrics object stored with an evaluation record."""

        return {
            "confusion_matrix": self.confusion_matrix.value,
            "development_metrics": self.to_payload(),
            "high_confidence_error_count": self.high_confidence_errors.value,
            "p50_elapsed_ms": self.p50_elapsed_ms.value,
            "p95_elapsed_ms": self.p95_elapsed_ms.value,
            "sample_count": sample_count,
            "unknown_rate": self.unknown_rate.value,
        }


@dataclass(frozen=True, slots=True)
class FrozenObservationCase:
    case_id: str
    base_role: str
    rotations: tuple[int, ...]
    quality_tags: tuple[str, ...]
    expected_role: TicketRole
    confidence_multiplier: Decimal
    omit_anchors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FrozenPairCase:
    case_id: str
    loading_case: str
    unloading_case: str
    same_image: bool
    expected_issue: str | None


@dataclass(frozen=True, slots=True)
class FrozenDevelopmentFixture:
    fixture_id: str
    manifest_sha256: str
    candidates: tuple[TemplateVersion, ...]
    observation_cases: tuple[FrozenObservationCase, ...]
    pair_cases: tuple[FrozenPairCase, ...]


@dataclass(frozen=True, slots=True)
class AuthorizingObservationSample:
    sample_id: str
    orientation_degrees: int
    role_input: TemplateRoleInput


@dataclass(frozen=True, slots=True)
class AuthorizingObservationCase:
    case_id: str
    truth_role: TicketRole
    truth_source: str
    quality_tags: tuple[str, ...]
    rotations: tuple[AuthorizingObservationSample, ...]


@dataclass(frozen=True, slots=True)
class AuthorizingPairCase:
    case_id: str
    loading_sample_id: str
    unloading_sample_id: str
    expected_issue: str | None


@dataclass(frozen=True, slots=True)
class AuthorizingDevelopmentDataset:
    dataset_id: str
    manifest_sha256: str
    observation_cases: tuple[AuthorizingObservationCase, ...]
    pair_cases: tuple[AuthorizingPairCase, ...]


@dataclass(frozen=True, slots=True)
class EvaluationEvidenceItem:
    source: str
    loading_score: Decimal
    unloading_score: Decimal
    matched_ids: tuple[str, ...]
    evidence_fingerprint: str

    @classmethod
    def from_domain(cls, evidence: RoleEvidence) -> EvaluationEvidenceItem:
        return cls(
            source=evidence.source.value,
            loading_score=evidence.loading_score,
            unloading_score=evidence.unloading_score,
            matched_ids=evidence.matched_ids,
            evidence_fingerprint=evidence.evidence_fingerprint,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "evidence_fingerprint": self.evidence_fingerprint,
            "loading_score": _decimal_text(self.loading_score),
            "matched_ids": list(self.matched_ids),
            "source": self.source,
            "unloading_score": _decimal_text(self.unloading_score),
        }


@dataclass(frozen=True, slots=True)
class DevelopmentEvaluationItem:
    sample_id: str
    case_id: str
    image_sha256: str
    expected_role: TicketRole
    result_role: TicketRole
    orientation_degrees: int
    detected_orientation_degrees: int
    quality_tags: tuple[str, ...]
    truth_source: str
    identity_kind: str
    confidence: Decimal
    high_confidence: bool
    evidence_quality: EvidenceQuality
    assessment_fingerprint: str
    elapsed_ms: Decimal
    evidence: tuple[EvaluationEvidenceItem, ...]
    expected_matches_result: bool
    geometry_matched: bool
    anchors_passed: bool
    direct_completion: bool
    fallback_required: bool
    wrong_template: bool
    role_conflict: bool
    unknown_layout: bool

    def to_repository_item_payload(self, fixture_id: str) -> dict[str, object]:
        return {
            "assessment_fingerprint": self.assessment_fingerprint,
            "confidence": _decimal_text(self.confidence),
            "elapsed_ms": _decimal_text(self.elapsed_ms),
            "evidence": {
                "detected_orientation_degrees": self.detected_orientation_degrees,
                "identity_kind": self.identity_kind,
                "quality_tags": list(self.quality_tags),
                "routing": {
                    "anchors_passed": self.anchors_passed,
                    "direct_completion": self.direct_completion,
                    "fallback_required": self.fallback_required,
                    "geometry_matched": self.geometry_matched,
                    "role_conflict": self.role_conflict,
                    "unknown_layout": self.unknown_layout,
                    "wrong_template": self.wrong_template,
                },
                "sources": [item.to_payload() for item in self.evidence],
                "truth_source": self.truth_source,
            },
            "high_confidence": self.high_confidence,
            "image_sha256": self.image_sha256,
            "identity_kind": self.identity_kind,
            "orientation_degrees": self.detected_orientation_degrees,
            "pair_issue": None,
            "prediction": self.result_role.value,
            "sample_id": self.sample_id,
            "truth": self.expected_role.value,
            "unknown_reason": (
                "insufficient_role_evidence"
                if self.result_role is TicketRole.UNKNOWN
                else None
            ),
            "waybill_id": f"{fixture_id}:{self.case_id}",
        }

    def to_stable_payload(self) -> dict[str, object]:
        """Exclude wall-clock timing while retaining deterministic outcomes."""

        return {
            "anchors_passed": self.anchors_passed,
            "assessment_fingerprint": self.assessment_fingerprint,
            "case_id": self.case_id,
            "detected_orientation_degrees": self.detected_orientation_degrees,
            "direct_completion": self.direct_completion,
            "expected_role": self.expected_role.value,
            "fallback_required": self.fallback_required,
            "geometry_matched": self.geometry_matched,
            "image_sha256": self.image_sha256,
            "orientation_degrees": self.orientation_degrees,
            "result_role": self.result_role.value,
            "role_conflict": self.role_conflict,
            "sample_id": self.sample_id,
            "unknown_layout": self.unknown_layout,
            "wrong_template": self.wrong_template,
            "truth_source": self.truth_source,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentPairItem:
    case_id: str
    expected_issue: str | None
    result_issue: str | None
    expected_matches_result: bool

    def to_payload(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "expected_issue": self.expected_issue,
            "expected_matches_result": self.expected_matches_result,
            "result_issue": self.result_issue,
        }


@dataclass(frozen=True, slots=True)
class EvaluationCandidateIdentity:
    version_id: str
    family_id: str
    lifecycle: TemplateLifecycle
    content_sha256: str

    @classmethod
    def from_version(cls, version: TemplateVersion) -> EvaluationCandidateIdentity:
        return cls(
            version_id=version.version_id,
            family_id=version.definition.family_id,
            lifecycle=version.lifecycle,
            content_sha256=version.content_sha256,
        )

    def to_repository_payload(self) -> dict[str, object]:
        return {
            "content_sha256": self.content_sha256,
            "version_id": self.version_id,
        }

    def to_stable_payload(self) -> dict[str, object]:
        return {
            "content_sha256": self.content_sha256,
            "family_id": self.family_id,
            "lifecycle": self.lifecycle.value,
            "version_id": self.version_id,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentEvaluationReport:
    fixture_id: str
    dataset_kind: str
    dataset_manifest_sha256: str
    template_set_fingerprint: str
    matcher_fingerprint: str
    policy_fingerprint: str
    evaluation_fingerprint: str
    stable_outcome_sha256: str
    candidates: tuple[EvaluationCandidateIdentity, ...]
    items: tuple[DevelopmentEvaluationItem, ...]
    pair_items: tuple[DevelopmentPairItem, ...]
    expected_count: int
    result_count: int
    metrics: DevelopmentEvaluationMetrics
    gate_passed: bool

    def to_repository_metrics(self) -> dict[str, object]:
        metrics = self.metrics.to_repository_metrics(
            sample_count=self.result_count,
        )
        metrics["pair_results"] = [
            item.to_payload() for item in self.pair_items
        ]
        metrics["stable_outcome_sha256"] = self.stable_outcome_sha256
        return metrics

    def to_record_evaluation_payload(
        self,
        *,
        build_fingerprint: str,
        runtime_fingerprint: str,
        actor_id: str = "loop7-development-evaluator",
    ) -> dict[str, object]:
        """Return JSON-only input for the SQLite evaluation-record boundary."""

        _require_sha256(build_fingerprint, "build_fingerprint")
        _require_sha256(runtime_fingerprint, "runtime_fingerprint")
        metrics = self.to_repository_metrics()
        attempt_fingerprint = _canonical_sha256(
            {
                "build_fingerprint": build_fingerprint,
                "evaluation_fingerprint": self.evaluation_fingerprint,
                "runtime_fingerprint": runtime_fingerprint,
                "stable_outcome_sha256": self.stable_outcome_sha256,
            }
        )
        return {
            "actor_id": actor_id,
            "build_fingerprint": build_fingerprint,
            "candidates": [
                candidate.to_repository_payload()
                for candidate in self.candidates
            ],
            "dataset_id": self.fixture_id,
            "dataset_kind": "development",
            "dataset_manifest_sha256": self.dataset_manifest_sha256,
            "evaluation_id": f"dev-{attempt_fingerprint[:28]}",
            "expected_count": self.expected_count,
            "gate_passed": self.gate_passed,
            "items": [
                item.to_repository_item_payload(self.fixture_id)
                for item in self.items
            ],
            "matcher_fingerprint": self.matcher_fingerprint,
            "metrics": metrics,
            "metrics_sha256": _canonical_sha256(metrics),
            "policy_fingerprint": self.policy_fingerprint,
            "result_count": self.result_count,
            "runtime_fingerprint": runtime_fingerprint,
            "template_set_fingerprint": self.template_set_fingerprint,
        }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


def authorizing_observation_sha256(
    *,
    case_id: str,
    sample_id: str,
    orientation_degrees: int,
    text_lines: tuple[ObservedTextLine, ...],
) -> str:
    """Return the canonical identity of one code-authored OCR observation."""

    return _canonical_sha256(
        {
            "case_id": case_id,
            "ocr_lines": [
                {
                    "box": {
                        "height": _decimal_text(line.box.height),
                        "width": _decimal_text(line.box.width),
                        "x": _decimal_text(line.box.x),
                        "y": _decimal_text(line.box.y),
                    },
                    "confidence": _decimal_text(line.confidence),
                    "text": line.text,
                }
                for line in text_lines
            ],
            "orientation_degrees": orientation_degrees,
            "sample_id": sample_id,
        }
    )


def _require_sha256(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FrozenDevelopmentFixtureError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise FrozenDevelopmentFixtureError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FrozenDevelopmentFixtureError(f"{label} must be non-empty text")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _required_string(value, label)


def _required_boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise FrozenDevelopmentFixtureError(f"{label} must be boolean")
    return value


def _require_exact_keys(
    payload: Mapping[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    label: str,
) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise FrozenDevelopmentFixtureError(
            f"{label} contains unsupported keys: {', '.join(unknown)}"
        )
    missing = sorted(required - set(payload))
    if missing:
        raise FrozenDevelopmentFixtureError(
            f"{label} is missing required keys: {', '.join(missing)}"
        )


def _decimal(value: object, label: str) -> Decimal:
    if not isinstance(value, str):
        raise FrozenDevelopmentFixtureError(f"{label} must be decimal text")
    try:
        result = Decimal(value)
    except ArithmeticError as exc:
        raise FrozenDevelopmentFixtureError(f"{label} is not a decimal") from exc
    if not result.is_finite():
        raise FrozenDevelopmentFixtureError(f"{label} must be finite")
    return result


def _rectangle(value: object, label: str) -> NormalizedRect:
    payload = _mapping(value, label)
    return NormalizedRect(
        x=_decimal(payload.get("x"), f"{label}.x"),
        y=_decimal(payload.get("y"), f"{label}.y"),
        width=_decimal(payload.get("width"), f"{label}.width"),
        height=_decimal(payload.get("height"), f"{label}.height"),
    )


def normalize_manifest_role_evidence(raw: Decimal) -> Decimal:
    """Normalize synthetic raw evidence to [-1, 1] with signed saturation.

    The frozen manifest separates anchor weight from directional role
    evidence. Values whose magnitude exceeds one are therefore divided by
    their own magnitude; values already inside the domain remain unchanged.
    """

    if not raw.is_finite():
        raise FrozenDevelopmentFixtureError("role evidence must be finite")
    denominator = max(Decimal(1), abs(raw))
    return raw / denominator


def _parse_anchor(value: object, family_key: str) -> TemplateAnchor:
    payload = _mapping(value, f"{family_key}.anchor")
    role_evidence = _mapping(
        payload.get("role_evidence"),
        f"{family_key}.anchor.role_evidence",
    )
    try:
        match_kind = AnchorMatchKind(
            _required_string(
                payload.get("match_kind"),
                f"{family_key}.anchor.match_kind",
            )
        )
    except ValueError as exc:
        raise FrozenDevelopmentFixtureError(
            f"{family_key}.anchor.match_kind is unsupported"
        ) from exc
    return TemplateAnchor(
        anchor_id=_required_string(
            payload.get("anchor_key"),
            f"{family_key}.anchor.anchor_key",
        ),
        expected_text=_required_string(
            payload.get("expected_text"),
            f"{family_key}.anchor.expected_text",
        ),
        match_kind=match_kind,
        box=_rectangle(payload.get("box"), f"{family_key}.anchor.box"),
        required=_required_boolean(
            payload.get("required"),
            f"{family_key}.anchor.required",
        ),
        weight=_decimal(payload.get("weight"), f"{family_key}.anchor.weight"),
        max_edit_distance=_decimal(
            payload.get("max_text_distance"),
            f"{family_key}.anchor.max_text_distance",
        ),
        loading_evidence=normalize_manifest_role_evidence(
            _decimal(
                role_evidence.get("loading"),
                f"{family_key}.anchor.role_evidence.loading",
            )
        ),
        unloading_evidence=normalize_manifest_role_evidence(
            _decimal(
                role_evidence.get("unloading"),
                f"{family_key}.anchor.role_evidence.unloading",
            )
        ),
    )


def _parse_region(value: object, family_key: str) -> RecognitionRegion:
    payload = _mapping(value, f"{family_key}.region")
    tolerance = _decimal(
        payload.get("layout_tolerance"),
        f"{family_key}.region.layout_tolerance",
    )
    try:
        field = TicketField(
            _required_string(
                payload.get("field"),
                f"{family_key}.region.field",
            )
        )
    except ValueError as exc:
        raise FrozenDevelopmentFixtureError(
            f"{family_key}.region.field is unsupported"
        ) from exc
    return RecognitionRegion(
        region_id=_required_string(
            payload.get("region_key"),
            f"{family_key}.region.region_key",
        ),
        field=field,
        box=_rectangle(payload.get("box"), f"{family_key}.region.box"),
        relative_to_anchor_id=_optional_string(
            payload.get("relative_to_anchor"),
            f"{family_key}.region.relative_to_anchor",
        ),
        unit=_optional_string(
            payload.get("unit"),
            f"{family_key}.region.unit",
        ),
        format_pattern=_required_string(
            payload.get("format_pattern"),
            f"{family_key}.region.format_pattern",
        ),
        required=_required_boolean(
            payload.get("required"),
            f"{family_key}.region.required",
        ),
        layout_scope=f"synthetic:tolerance={_decimal_text(tolerance)}",
    )


def _version_id(family_key: str) -> str:
    return f"dev-{hashlib.sha256(family_key.encode('utf-8')).hexdigest()[:24]}"


def _parse_family(
    value: object,
    *,
    lifecycle: TemplateLifecycle,
) -> TemplateVersion:
    payload = _mapping(value, "template family")
    family_key = _required_string(payload.get("family_key"), "family_key")
    reference_hash = _required_string(
        payload.get("reference_image_sha256"),
        f"{family_key}.reference_image_sha256",
    )
    _require_sha256(reference_hash, f"{family_key}.reference_image_sha256")
    try:
        role = TicketRole(
            _required_string(payload.get("role"), f"{family_key}.role")
        )
    except ValueError as exc:
        raise FrozenDevelopmentFixtureError(
            f"{family_key}.role is unsupported"
        ) from exc
    if role is TicketRole.UNKNOWN:
        raise FrozenDevelopmentFixtureError(
            f"{family_key}.role cannot be unknown"
        )
    return TemplateVersion(
        version_id=_version_id(family_key),
        definition=TemplateDefinition(
            family_id=family_key,
            name=_required_string(payload.get("name"), f"{family_key}.name"),
            role=role,
            anchors=tuple(
                _parse_anchor(anchor, family_key)
                for anchor in _sequence(
                    payload.get("anchors"),
                    f"{family_key}.anchors",
                )
            ),
            regions=tuple(
                _parse_region(region, family_key)
                for region in _sequence(
                    payload.get("recognition_regions"),
                    f"{family_key}.recognition_regions",
                )
            ),
        ),
        lifecycle=lifecycle,
        parent_version_id=None,
        record_version=1,
        version_number=1,
    )


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    return tuple(
        _required_string(item, label)
        for item in _sequence(value, label)
    )


def _parse_observation_case(value: object) -> FrozenObservationCase:
    payload = _mapping(value, "observation case")
    case_id = _required_string(payload.get("case_id"), "observation case_id")
    rotations: list[int] = []
    for rotation in _sequence(payload.get("rotations"), f"{case_id}.rotations"):
        if not isinstance(rotation, int) or rotation not in {0, 90, 180, 270}:
            raise FrozenDevelopmentFixtureError(
                f"{case_id}.rotations contains an unsupported orientation"
            )
        rotations.append(rotation)
    if not rotations or len(rotations) != len(set(rotations)):
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.rotations must be non-empty and unique"
        )
    base_role = _required_string(payload.get("base_role"), f"{case_id}.base_role")
    if base_role not in {"loading", "unloading", "mixed", "unknown", "non_ticket"}:
        raise FrozenDevelopmentFixtureError(f"{case_id}.base_role is unsupported")
    try:
        expected_role = TicketRole(
            _required_string(
                payload.get("expected_role"),
                f"{case_id}.expected_role",
            )
        )
    except ValueError as exc:
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.expected_role is unsupported"
        ) from exc
    multiplier_value = payload.get("confidence_multiplier", "1")
    confidence_multiplier = _decimal(
        multiplier_value,
        f"{case_id}.confidence_multiplier",
    )
    if not 0 <= confidence_multiplier <= 1:
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.confidence_multiplier must be between zero and one"
        )
    return FrozenObservationCase(
        case_id=case_id,
        base_role=base_role,
        rotations=tuple(rotations),
        quality_tags=_string_tuple(
            payload.get("quality_tags"),
            f"{case_id}.quality_tags",
        ),
        expected_role=expected_role,
        confidence_multiplier=confidence_multiplier,
        omit_anchors=_string_tuple(
            payload.get("omit_anchors", []),
            f"{case_id}.omit_anchors",
        ),
    )


def _parse_pair_case(value: object) -> FrozenPairCase:
    payload = _mapping(value, "pair case")
    case_id = _required_string(payload.get("case_id"), "pair case_id")
    expected_issue = _optional_string(
        payload.get("expected_issue"),
        f"{case_id}.expected_issue",
    )
    if expected_issue is not None and expected_issue not in {
        issue.value for issue in RoleIssue
    }:
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.expected_issue is unsupported"
        )
    return FrozenPairCase(
        case_id=case_id,
        loading_case=_required_string(
            payload.get("loading_case"),
            f"{case_id}.loading_case",
        ),
        unloading_case=_required_string(
            payload.get("unloading_case"),
            f"{case_id}.unloading_case",
        ),
        same_image=_required_boolean(
            payload.get("same_image", False),
            f"{case_id}.same_image",
        ),
        expected_issue=expected_issue,
    )


def load_frozen_development_fixture(
    manifest_path: Path,
    *,
    candidate_lifecycle: TemplateLifecycle = TemplateLifecycle.DRAFT,
) -> FrozenDevelopmentFixture:
    """Read a local synthetic manifest without changing it or using external data."""

    if candidate_lifecycle not in {
        TemplateLifecycle.DRAFT,
        TemplateLifecycle.DEVELOPMENT_TESTED,
    }:
        raise FrozenDevelopmentFixtureError(
            "development candidates must be draft or development_tested"
        )
    raw_bytes = manifest_path.read_bytes()
    try:
        decoded: object = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrozenDevelopmentFixtureError(
            "fixture manifest must be valid UTF-8 JSON"
        ) from exc
    payload = _mapping(decoded, "fixture manifest")
    if payload.get("schema_version") != 1:
        raise FrozenDevelopmentFixtureError(
            "fixture manifest schema_version must be 1"
        )
    if payload.get("kind") != "generated_synthetic":
        raise FrozenDevelopmentFixtureError(
            "development fixture must be generated_synthetic"
        )
    for flag in (
        "production_data",
        "contains_credentials",
        "contains_personal_data",
    ):
        if _required_boolean(payload.get(flag), flag):
            raise FrozenDevelopmentFixtureError(
                f"development fixture safety flag {flag} must be false"
            )

    candidates = tuple(
        _parse_family(family, lifecycle=candidate_lifecycle)
        for family in _sequence(
            payload.get("template_families"),
            "template_families",
        )
    )
    observation_cases = tuple(
        _parse_observation_case(case)
        for case in _sequence(
            payload.get("observation_cases"),
            "observation_cases",
        )
    )
    pair_cases = tuple(
        _parse_pair_case(case)
        for case in _sequence(payload.get("pair_cases"), "pair_cases")
    )
    observation_ids = tuple(case.case_id for case in observation_cases)
    if len(observation_ids) != len(set(observation_ids)):
        raise FrozenDevelopmentFixtureError(
            "observation case identifiers must be unique"
        )
    pair_ids = tuple(case.case_id for case in pair_cases)
    if len(pair_ids) != len(set(pair_ids)):
        raise FrozenDevelopmentFixtureError(
            "pair case identifiers must be unique"
        )
    known_cases = set(observation_ids)
    if any(
        pair.loading_case not in known_cases
        or pair.unloading_case not in known_cases
        for pair in pair_cases
    ):
        raise FrozenDevelopmentFixtureError(
            "pair case references an unknown observation case"
        )
    return FrozenDevelopmentFixture(
        fixture_id=_required_string(payload.get("fixture_id"), "fixture_id"),
        manifest_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        candidates=candidates,
        observation_cases=observation_cases,
        pair_cases=pair_cases,
    )


def _parse_authorizing_line(
    value: object,
    *,
    sample_id: str,
) -> ObservedTextLine:
    payload = _mapping(value, f"{sample_id}.ocr_line")
    _require_exact_keys(
        payload,
        allowed=frozenset({"box", "confidence", "text"}),
        required=frozenset({"box", "confidence", "text"}),
        label=f"{sample_id}.ocr_line",
    )
    confidence = _decimal(
        payload.get("confidence"),
        f"{sample_id}.ocr_line.confidence",
    )
    if not 0 <= confidence <= 1:
        raise FrozenDevelopmentFixtureError(
            f"{sample_id}.ocr_line.confidence must be between zero and one"
        )
    return ObservedTextLine(
        text=_required_string(
            payload.get("text"),
            f"{sample_id}.ocr_line.text",
        ),
        confidence=confidence,
        box=_rectangle(
            payload.get("box"),
            f"{sample_id}.ocr_line.box",
        ),
    )


def _parse_authorizing_sample(
    value: object,
    *,
    case_id: str,
) -> AuthorizingObservationSample:
    payload = _mapping(value, f"{case_id}.rotation")
    _require_exact_keys(
        payload,
        allowed=frozenset(
            {
                "observation_sha256",
                "ocr_lines",
                "orientation_degrees",
                "sample_id",
            }
        ),
        required=frozenset(
            {
                "observation_sha256",
                "ocr_lines",
                "orientation_degrees",
                "sample_id",
            }
        ),
        label=f"{case_id}.rotation",
    )
    sample_id = _required_string(
        payload.get("sample_id"),
        f"{case_id}.rotation.sample_id",
    )
    orientation = payload.get("orientation_degrees")
    if not isinstance(orientation, int) or orientation not in {0, 90, 180, 270}:
        raise FrozenDevelopmentFixtureError(
            f"{sample_id}.orientation_degrees is unsupported"
        )
    observation_sha256 = _required_string(
        payload.get("observation_sha256"),
        f"{sample_id}.observation_sha256",
    )
    try:
        _require_sha256(
            observation_sha256,
            f"{sample_id}.observation_sha256",
        )
    except ValueError as exc:
        raise FrozenDevelopmentFixtureError(str(exc)) from exc
    text_lines = tuple(
        _parse_authorizing_line(line, sample_id=sample_id)
        for line in _sequence(
            payload.get("ocr_lines"),
            f"{sample_id}.ocr_lines",
        )
    )
    expected_identity = authorizing_observation_sha256(
        case_id=case_id,
        sample_id=sample_id,
        orientation_degrees=orientation,
        text_lines=text_lines,
    )
    if observation_sha256 != expected_identity:
        raise FrozenDevelopmentFixtureError(
            f"{sample_id}.observation_sha256 does not match canonical OCR "
            "observation"
        )
    return AuthorizingObservationSample(
        sample_id=sample_id,
        orientation_degrees=orientation,
        role_input=TemplateRoleInput(
            image_sha256=observation_sha256,
            text_lines=text_lines,
            fixed_text=tuple(line.text for line in text_lines),
        ),
    )


def _parse_authorizing_case(value: object) -> AuthorizingObservationCase:
    payload = _mapping(value, "authorizing observation")
    _require_exact_keys(
        payload,
        allowed=frozenset(
            {
                "case_id",
                "quality_tags",
                "rotations",
                "truth_role",
                "truth_source",
            }
        ),
        required=frozenset(
            {
                "case_id",
                "quality_tags",
                "rotations",
                "truth_role",
                "truth_source",
            }
        ),
        label="authorizing observation",
    )
    case_id = _required_string(
        payload.get("case_id"),
        "authorizing observation.case_id",
    )
    try:
        truth_role = TicketRole(
            _required_string(
                payload.get("truth_role"),
                f"{case_id}.truth_role",
            )
        )
    except ValueError as exc:
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.truth_role is unsupported"
        ) from exc
    truth_source = _required_string(
        payload.get("truth_source"),
        f"{case_id}.truth_source",
    )
    if truth_source != AUTHORIZING_TRUTH_SOURCE:
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.truth_source must be {AUTHORIZING_TRUTH_SOURCE}"
        )
    rotations = tuple(
        _parse_authorizing_sample(rotation, case_id=case_id)
        for rotation in _sequence(
            payload.get("rotations"),
            f"{case_id}.rotations",
        )
    )
    if not rotations:
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.rotations must not be empty"
        )
    orientations = tuple(sample.orientation_degrees for sample in rotations)
    if len(orientations) != len(set(orientations)):
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.rotations must use unique orientations"
        )
    return AuthorizingObservationCase(
        case_id=case_id,
        truth_role=truth_role,
        truth_source=truth_source,
        quality_tags=_string_tuple(
            payload.get("quality_tags"),
            f"{case_id}.quality_tags",
        ),
        rotations=rotations,
    )


def _parse_authorizing_pair(value: object) -> AuthorizingPairCase:
    payload = _mapping(value, "authorizing pair case")
    _require_exact_keys(
        payload,
        allowed=frozenset(
            {
                "case_id",
                "expected_issue",
                "loading_sample_id",
                "unloading_sample_id",
            }
        ),
        required=frozenset(
            {
                "case_id",
                "expected_issue",
                "loading_sample_id",
                "unloading_sample_id",
            }
        ),
        label="authorizing pair case",
    )
    case_id = _required_string(payload.get("case_id"), "pair case_id")
    expected_issue = _optional_string(
        payload.get("expected_issue"),
        f"{case_id}.expected_issue",
    )
    if expected_issue is not None and expected_issue not in {
        issue.value for issue in RoleIssue
    }:
        raise FrozenDevelopmentFixtureError(
            f"{case_id}.expected_issue is unsupported"
        )
    return AuthorizingPairCase(
        case_id=case_id,
        loading_sample_id=_required_string(
            payload.get("loading_sample_id"),
            f"{case_id}.loading_sample_id",
        ),
        unloading_sample_id=_required_string(
            payload.get("unloading_sample_id"),
            f"{case_id}.unloading_sample_id",
        ),
        expected_issue=expected_issue,
    )


def load_authorizing_development_dataset(
    manifest_path: Path,
) -> AuthorizingDevelopmentDataset:
    """Load explicit code-authored OCR observations without template definitions."""

    raw_bytes = manifest_path.read_bytes()
    try:
        decoded: object = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrozenDevelopmentFixtureError(
            "authorizing dataset must be valid UTF-8 JSON"
        ) from exc
    payload = _mapping(decoded, "authorizing dataset")
    if payload.get("kind") != "authorizing_observation_dataset":
        raise FrozenDevelopmentFixtureError(
            "persistent development evidence requires "
            "authorizing_observation_dataset"
        )
    _require_exact_keys(
        payload,
        allowed=frozenset(
            {
                "contains_credentials",
                "contains_personal_data",
                "dataset_id",
                "description",
                "kind",
                "observations",
                "pair_cases",
                "production_data",
                "schema_version",
            }
        ),
        required=frozenset(
            {
                "contains_credentials",
                "contains_personal_data",
                "dataset_id",
                "kind",
                "observations",
                "pair_cases",
                "production_data",
                "schema_version",
            }
        ),
        label="authorizing dataset",
    )
    if payload.get("schema_version") != 1:
        raise FrozenDevelopmentFixtureError(
            "authorizing dataset schema_version must be 1"
        )
    for flag in (
        "production_data",
        "contains_credentials",
        "contains_personal_data",
    ):
        if _required_boolean(payload.get(flag), flag):
            raise FrozenDevelopmentFixtureError(
                f"authorizing dataset safety flag {flag} must be false"
            )
    if "description" in payload:
        _required_string(
            payload.get("description"),
            "authorizing dataset.description",
        )

    observation_cases = tuple(
        _parse_authorizing_case(case)
        for case in _sequence(
            payload.get("observations"),
            "authorizing dataset.observations",
        )
    )
    if not observation_cases:
        raise FrozenDevelopmentFixtureError(
            "authorizing dataset observations must not be empty"
        )
    pair_cases = tuple(
        _parse_authorizing_pair(case)
        for case in _sequence(
            payload.get("pair_cases"),
            "authorizing dataset.pair_cases",
        )
    )
    if not pair_cases:
        raise FrozenDevelopmentFixtureError(
            "authorizing dataset pair_cases must not be empty"
        )

    case_ids = tuple(case.case_id for case in observation_cases)
    if len(case_ids) != len(set(case_ids)):
        raise FrozenDevelopmentFixtureError(
            "authorizing observation case identifiers must be unique"
        )
    pair_ids = tuple(case.case_id for case in pair_cases)
    if len(pair_ids) != len(set(pair_ids)):
        raise FrozenDevelopmentFixtureError(
            "authorizing pair case identifiers must be unique"
        )
    samples = tuple(
        sample
        for case in observation_cases
        for sample in case.rotations
    )
    sample_ids = tuple(sample.sample_id for sample in samples)
    if len(sample_ids) != len(set(sample_ids)):
        raise FrozenDevelopmentFixtureError(
            "authorizing sample identifiers must be unique"
        )
    known_sample_ids = set(sample_ids)
    if any(
        pair.loading_sample_id not in known_sample_ids
        or pair.unloading_sample_id not in known_sample_ids
        for pair in pair_cases
    ):
        raise FrozenDevelopmentFixtureError(
            "authorizing pair case references an unknown sample"
        )

    image_observations: dict[
        str,
        tuple[int, tuple[ObservedTextLine, ...]],
    ] = {}
    for sample in samples:
        prior = image_observations.setdefault(
            sample.role_input.image_sha256,
            (
                sample.orientation_degrees,
                sample.role_input.text_lines,
            ),
        )
        if prior != (
            sample.orientation_degrees,
            sample.role_input.text_lines,
        ):
            raise FrozenDevelopmentFixtureError(
                "one image identity cannot contain conflicting OCR observations"
            )
    return AuthorizingDevelopmentDataset(
        dataset_id=_required_string(
            payload.get("dataset_id"),
            "authorizing dataset.dataset_id",
        ),
        manifest_sha256=_canonical_sha256(decoded),
        observation_cases=observation_cases,
        pair_cases=pair_cases,
    )


def _rotate(rectangle: NormalizedRect, degrees: int) -> NormalizedRect:
    if degrees == 0:
        return rectangle
    if degrees == 90:
        return NormalizedRect(
            x=Decimal(1) - rectangle.y - rectangle.height,
            y=rectangle.x,
            width=rectangle.height,
            height=rectangle.width,
        )
    if degrees == 180:
        return NormalizedRect(
            x=Decimal(1) - rectangle.x - rectangle.width,
            y=Decimal(1) - rectangle.y - rectangle.height,
            width=rectangle.width,
            height=rectangle.height,
        )
    return NormalizedRect(
        x=rectangle.y,
        y=Decimal(1) - rectangle.x - rectangle.width,
        width=rectangle.height,
        height=rectangle.width,
    )


def _synthetic_role_input(
    fixture: FrozenDevelopmentFixture,
    case: FrozenObservationCase,
    orientation: int,
) -> TemplateRoleInput:
    definitions = tuple(candidate.definition for candidate in fixture.candidates)
    if case.base_role in {"loading", "unloading"}:
        role = TicketRole(case.base_role)
        selected_definitions = tuple(
            definition
            for definition in definitions
            if definition.role is role
        )
    elif case.base_role == "mixed":
        selected_definitions = definitions
    else:
        selected_definitions = ()

    confidence = (Decimal("0.98") * case.confidence_multiplier).quantize(
        Decimal("0.000001")
    )
    lines: list[ObservedTextLine] = []
    for definition in selected_definitions:
        for anchor in definition.anchors:
            if anchor.anchor_id in case.omit_anchors:
                continue
            lines.append(
                ObservedTextLine(
                    text=anchor.expected_text,
                    confidence=confidence,
                    box=_rotate(anchor.box, orientation),
                )
            )

    if case.base_role == "unknown":
        lines = [
            ObservedTextLine(
                text="磅单",
                confidence=Decimal("0.95"),
                box=_rotate(
                    NormalizedRect(
                        x=Decimal("0.62"),
                        y=Decimal("0.34"),
                        width=Decimal("0.16"),
                        height=Decimal("0.05"),
                    ),
                    orientation,
                ),
            ),
            ObservedTextLine(
                text="净重",
                confidence=Decimal("0.95"),
                box=_rotate(
                    NormalizedRect(
                        x=Decimal("0.66"),
                        y=Decimal("0.48"),
                        width=Decimal("0.12"),
                        height=Decimal("0.05"),
                    ),
                    orientation,
                ),
            ),
        ]
    elif case.base_role == "non_ticket":
        lines = [
            ObservedTextLine(
                text="普通发票",
                confidence=Decimal("0.99"),
                box=NormalizedRect(
                    x=Decimal("0.62"),
                    y=Decimal("0.36"),
                    width=Decimal("0.22"),
                    height=Decimal("0.06"),
                ),
            )
        ]

    return TemplateRoleInput(
        image_sha256=_canonical_sha256(
            {
                "case_id": case.case_id,
                "fixture_id": fixture.fixture_id,
                "orientation": orientation,
            }
        ),
        text_lines=tuple(lines),
        fixed_text=tuple(line.text for line in lines),
    )


def default_development_policy() -> RoleAssessmentPolicy:
    """Return the one policy allowed to authorize the Loop 7 lifecycle."""

    return RoleAssessmentPolicy(
        minimum_score=Decimal("0.85"),
        minimum_margin=Decimal("0.25"),
        minimum_sources=2,
        minimum_ticket_likelihood=Decimal("0.60"),
        high_confidence_score=Decimal("0.90"),
        version="loop7-frozen-development-policy-v1",
    )


def development_policy_fingerprint(
    policy: RoleAssessmentPolicy | None = None,
) -> str:
    """Fingerprint an explicit policy or the authoritative default policy."""

    selected = default_development_policy() if policy is None else policy
    return _canonical_sha256(
        {
            "high_confidence_score": _decimal_text(selected.high_confidence_score),
            "minimum_margin": _decimal_text(selected.minimum_margin),
            "minimum_score": _decimal_text(selected.minimum_score),
            "minimum_sources": selected.minimum_sources,
            "minimum_ticket_likelihood": _decimal_text(
                selected.minimum_ticket_likelihood
            ),
            "version": selected.version,
        }
    )


def development_matcher_fingerprint() -> str:
    """Fingerprint the code-owned matcher/runner contract."""

    return _canonical_sha256(
        {
            "matcher_version": MATCHER_VERSION,
            "runner_version": RUNNER_VERSION,
        }
    )


def _source(run: TemplateRoleRun, source: RoleEvidenceSource) -> RoleEvidence:
    return next(
        evidence
        for evidence in run.observation.evidence
        if evidence.source is source
    )


def _evaluation_item(
    *,
    case_id: str,
    expected_role: TicketRole,
    quality_tags: tuple[str, ...],
    truth_source: str,
    identity_kind: str,
    sample_id: str,
    orientation: int,
    run: TemplateRoleRun,
) -> DevelopmentEvaluationItem:
    fixed = _source(run, RoleEvidenceSource.FIXED_TEXT)
    template = _source(run, RoleEvidenceSource.TEMPLATE)
    layout = _source(run, RoleEvidenceSource.LAYOUT)
    role_conflict = (
        fixed.loading_score > 0
        and fixed.unloading_score > 0
    ) or (
        template.loading_score > 0
        and template.unloading_score > 0
    )
    result_role = run.assessment.role
    direct_completion = result_role is not TicketRole.UNKNOWN
    return DevelopmentEvaluationItem(
        sample_id=sample_id,
        case_id=case_id,
        image_sha256=run.observation.image_sha256,
        expected_role=expected_role,
        result_role=result_role,
        orientation_degrees=orientation,
        detected_orientation_degrees=run.observation.orientation_degrees,
        quality_tags=quality_tags,
        truth_source=truth_source,
        identity_kind=identity_kind,
        confidence=run.assessment.confidence,
        high_confidence=run.assessment.high_confidence,
        evidence_quality=run.assessment.quality,
        assessment_fingerprint=run.assessment.fingerprint,
        elapsed_ms=run.elapsed_ms,
        evidence=tuple(
            EvaluationEvidenceItem.from_domain(evidence)
            for evidence in run.observation.evidence
        ),
        expected_matches_result=result_role is expected_role,
        geometry_matched=max(layout.loading_score, layout.unloading_score) > 0,
        anchors_passed=max(template.loading_score, template.unloading_score) > 0,
        direct_completion=direct_completion,
        fallback_required=not direct_completion,
        wrong_template=(
            expected_role is not TicketRole.UNKNOWN
            and result_role is not TicketRole.UNKNOWN
            and result_role is not expected_role
        ),
        role_conflict=role_conflict,
        unknown_layout=max(layout.loading_score, layout.unloading_score) == 0,
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


def _pair_ticket(
    *,
    item: DevelopmentEvaluationItem,
    image_sha256: str,
    position: TicketSlot,
) -> TicketEvidence:
    return TicketEvidence(
        slot=position,
        image_sha256=image_sha256,
        machine_role=item.result_role,
        role_quality=item.evidence_quality,
        weights=_missing_weights(),
        extraction_fingerprint=_canonical_sha256(
            {
                "purpose": "development_role_pair_without_field_extraction",
                "sample_id": item.sample_id,
            }
        ),
        role_fingerprint=item.assessment_fingerprint,
    )


def _evaluate_pairs(
    fixture: FrozenDevelopmentFixture,
    items: tuple[DevelopmentEvaluationItem, ...],
) -> tuple[DevelopmentPairItem, ...]:
    by_case = {
        item.case_id: item
        for item in items
        if item.orientation_degrees == 0
    }
    results: list[DevelopmentPairItem] = []
    for pair in fixture.pair_cases:
        loading_item = by_case[pair.loading_case]
        unloading_item = by_case[pair.unloading_case]
        shared_hash = _canonical_sha256(
            {
                "case_id": pair.case_id,
                "fixture_id": fixture.fixture_id,
                "same_image": True,
            }
        )
        loading_hash = (
            shared_hash
            if pair.same_image
            else _canonical_sha256(
                {
                    "case_id": pair.case_id,
                    "fixture_id": fixture.fixture_id,
                    "position": "loading",
                }
            )
        )
        unloading_hash = (
            shared_hash
            if pair.same_image
            else _canonical_sha256(
                {
                    "case_id": pair.case_id,
                    "fixture_id": fixture.fixture_id,
                    "position": "unloading",
                }
            )
        )
        assessment = assess_ticket_roles(
            _pair_ticket(
                item=loading_item,
                image_sha256=loading_hash,
                position=TicketSlot.LOADING,
            ),
            _pair_ticket(
                item=unloading_item,
                image_sha256=unloading_hash,
                position=TicketSlot.UNLOADING,
            ),
        )
        result_issue = None if assessment.issue is None else assessment.issue.value
        results.append(
            DevelopmentPairItem(
                case_id=pair.case_id,
                expected_issue=pair.expected_issue,
                result_issue=result_issue,
                expected_matches_result=result_issue == pair.expected_issue,
            )
        )
    return tuple(results)


def _evaluate_authorizing_pairs(
    dataset: AuthorizingDevelopmentDataset,
    items: tuple[DevelopmentEvaluationItem, ...],
) -> tuple[DevelopmentPairItem, ...]:
    by_sample = {item.sample_id: item for item in items}
    results: list[DevelopmentPairItem] = []
    for pair in dataset.pair_cases:
        loading_item = by_sample[pair.loading_sample_id]
        unloading_item = by_sample[pair.unloading_sample_id]
        assessment = assess_ticket_roles(
            _pair_ticket(
                item=loading_item,
                image_sha256=loading_item.image_sha256,
                position=TicketSlot.LOADING,
            ),
            _pair_ticket(
                item=unloading_item,
                image_sha256=unloading_item.image_sha256,
                position=TicketSlot.UNLOADING,
            ),
        )
        result_issue = None if assessment.issue is None else assessment.issue.value
        results.append(
            DevelopmentPairItem(
                case_id=pair.case_id,
                expected_issue=pair.expected_issue,
                result_issue=result_issue,
                expected_matches_result=result_issue == pair.expected_issue,
            )
        )
    return tuple(results)


def _rate(items: tuple[DevelopmentEvaluationItem, ...], attribute: str) -> str:
    count = sum(bool(getattr(item, attribute)) for item in items)
    return _decimal_text(Decimal(count) / Decimal(len(items)))


def _reconciliation(
    *,
    expected_count: int,
    result_count: int,
    matched_count: int,
) -> dict[str, int]:
    return {
        "expected_count": expected_count,
        "matched_count": matched_count,
        "mismatch_count": result_count - matched_count,
        "result_count": result_count,
    }


def _sample_count_value(
    items: tuple[DevelopmentEvaluationItem, ...],
    pair_items: tuple[DevelopmentPairItem, ...],
) -> dict[str, int]:
    return {
        "observation_cases": len({item.case_id for item in items}),
        "observation_runs": len(items),
        "pair_cases": len(pair_items),
    }


def _quality_tag_distribution(
    items: tuple[DevelopmentEvaluationItem, ...],
) -> dict[str, dict[str, int]]:
    run_counts: Counter[str] = Counter()
    case_tags: dict[str, tuple[str, ...]] = {}
    for item in items:
        run_counts.update(item.quality_tags)
        existing = case_tags.setdefault(item.case_id, item.quality_tags)
        if existing != item.quality_tags:
            raise FrozenDevelopmentFixtureError(
                f"quality tags changed across rotations for {item.case_id}"
            )
    case_counts: Counter[str] = Counter(
        tag
        for tags in case_tags.values()
        for tag in tags
    )
    return {
        "observation_cases": dict(sorted(case_counts.items())),
        "observation_runs": dict(sorted(run_counts.items())),
    }


def _ratio(success_count: int, sample_count: int) -> str | None:
    if sample_count == 0:
        return None
    return _decimal_text(Decimal(success_count) / Decimal(sample_count))


def _wilson_95_interval(
    success_count: int,
    sample_count: int,
) -> dict[str, object] | None:
    """Return a deterministic six-decimal Wilson score interval."""

    if sample_count == 0:
        return None
    if (
        success_count < 0
        or sample_count < 0
        or success_count > sample_count
    ):
        raise ValueError("Wilson interval counts are invalid")
    with localcontext() as context:
        context.prec = 50
        successes = Decimal(success_count)
        samples = Decimal(sample_count)
        proportion = successes / samples
        z_squared = WILSON_95_Z * WILSON_95_Z
        denominator = Decimal(1) + z_squared / samples
        center = (
            proportion + z_squared / (Decimal(2) * samples)
        ) / denominator
        margin = (
            WILSON_95_Z
            * (
                proportion * (Decimal(1) - proportion) / samples
                + z_squared / (Decimal(4) * samples * samples)
            ).sqrt()
            / denominator
        )
        lower = max(Decimal(0), center - margin).quantize(
            RATE_QUANTUM,
            rounding=ROUND_HALF_UP,
        )
        upper = min(Decimal(1), center + margin).quantize(
            RATE_QUANTUM,
            rounding=ROUND_HALF_UP,
        )
    return {
        "confidence_level": "0.95",
        "lower": _decimal_text(lower),
        "method": "wilson_score",
        "sample_count": sample_count,
        "success_count": success_count,
        "upper": _decimal_text(upper),
    }


def _pair_metric_status(sample_count: int) -> MeasurementStatus:
    return (
        MeasurementStatus.MEASURED
        if sample_count > 0
        else MeasurementStatus.NOT_MEASURED
    )


def _metrics(
    items: tuple[DevelopmentEvaluationItem, ...],
    pair_items: tuple[DevelopmentPairItem, ...],
    assessments: Mapping[str, TicketRoleAssessment],
    *,
    dataset_kind: str = "generated_synthetic",
) -> DevelopmentEvaluationMetrics:
    is_synthetic = dataset_kind == "generated_synthetic"
    sample_scope = (
        {
            "dataset_kind": "generated_synthetic",
            "formal_acceptance_eligible": False,
            "production_data": False,
            "warning": (
                "Small synthetic development sample; do not use as a formal "
                "locked-set or production-shadow gate."
            ),
        }
        if is_synthetic
        else {
            "dataset_kind": "authorizing_observation_dataset",
            "formal_acceptance_eligible": False,
            "production_data": False,
            "warning": (
                "Code-authored synthetic development evidence only; it cannot "
                "prove real-image accuracy or replace the independent locked-set "
                "and production-shadow gates."
            ),
        }
    )
    role_metrics = summarize_role_metrics(
        tuple(
            LabeledRoleResult(
                sample_id=item.sample_id,
                truth=item.expected_role,
                assessment=assessments[item.sample_id],
                elapsed_ms=item.elapsed_ms,
            )
            for item in items
        )
    )
    item_matches = sum(item.expected_matches_result for item in items)
    pair_matches = sum(item.expected_matches_result for item in pair_items)
    unknown_count = sum(
        item.result_role is TicketRole.UNKNOWN
        for item in items
    )
    wrong_template_count = sum(item.wrong_template for item in items)
    swapped_pairs = tuple(
        item
        for item in pair_items
        if item.expected_issue == RoleIssue.SUSPECTED_SWAPPED.value
    )
    swapped_detected = sum(
        item.result_issue == RoleIssue.SUSPECTED_SWAPPED.value
        for item in swapped_pairs
    )
    normal_pairs = tuple(
        item
        for item in pair_items
        if item.expected_issue is None
    )
    normal_false_positives = sum(
        item.result_issue is not None
        for item in normal_pairs
    )
    return DevelopmentEvaluationMetrics(
        sample_count=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_sample_count_value(items, pair_items),
            definition=(
                "Development observation cases, explicit rotations, and pair "
                "cases; these are not formal acceptance sample counts."
            ),
        ),
        quality_tag_distribution=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_quality_tag_distribution(items),
            definition=(
                "Quality-tag counts by unique case and expanded "
                "observation run; multi-tag cases may contribute to multiple bins."
            ),
        ),
        development_sample_scope=Measurement(
            status=MeasurementStatus.MEASURED,
            value=sample_scope,
            definition=(
                "Scope warning persisted with every development metric payload."
            ),
        ),
        expected_result_reconciliation=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_reconciliation(
                expected_count=len(items),
                result_count=len(items),
                matched_count=item_matches,
            ),
            definition="Exact expected-role versus matcher-result reconciliation.",
        ),
        pair_reconciliation=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_reconciliation(
                expected_count=len(pair_items),
                result_count=len(pair_items),
                matched_count=pair_matches,
            ),
            definition="Exact expected-issue versus pair-contract reconciliation.",
        ),
        confusion_matrix=Measurement(
            status=MeasurementStatus.MEASURED,
            value=role_metrics.confusion_matrix,
            definition="Rows are expected roles and columns are matcher results.",
        ),
        unknown_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_decimal_text(role_metrics.unknown_rate),
            definition="Unknown matcher results divided by all observation runs.",
        ),
        unknown_rate_wilson_95_ci=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_wilson_95_interval(unknown_count, len(items)),
            definition=(
                "Wilson 95% interval for unknown results in this small development "
                "sample; not a formal acceptance bound."
            ),
        ),
        high_confidence_errors=Measurement(
            status=MeasurementStatus.MEASURED,
            value=role_metrics.high_confidence_error_count,
            definition="High-confidence known roles that disagree with expected role.",
        ),
        p50_elapsed_ms=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_decimal_text(role_metrics.p50_elapsed_ms),
            definition="Nearest-rank P50 matcher wall-clock milliseconds.",
        ),
        p95_elapsed_ms=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_decimal_text(role_metrics.p95_elapsed_ms),
            definition="Nearest-rank P95 matcher wall-clock milliseconds.",
        ),
        geometry_match_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_rate(items, "geometry_matched"),
            definition="Runs with positive selected-orientation layout evidence.",
        ),
        anchor_pass_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_rate(items, "anchors_passed"),
            definition="Runs with a template whose required anchors passed.",
        ),
        direct_completion_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_rate(items, "direct_completion"),
            definition="Runs producing a reliable known role without fallback.",
        ),
        fallback_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_rate(items, "fallback_required"),
            definition=(
                "Runs routed to fallback or unknown handling because direct "
                "completion was unsafe; no fallback OCR is executed here."
            ),
        ),
        wrong_template_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_rate(items, "wrong_template"),
            definition="Known-role results selecting the opposite expected role.",
        ),
        wrong_template_rate_wilson_95_ci=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_wilson_95_interval(wrong_template_count, len(items)),
            definition=(
                "Wilson 95% interval for wrong-template results in this small "
                "development sample; not a formal acceptance bound."
            ),
        ),
        synthetic_swapped_pair_recall=Measurement(
            status=_pair_metric_status(len(swapped_pairs)),
            value=_ratio(swapped_detected, len(swapped_pairs)),
            definition=(
                (
                    "Recall on explicitly synthetic swapped pair cases. "
                    if is_synthetic
                    else "Recall on explicitly code-authored swapped pair cases. "
                )
                + "The sample is small and cannot establish a formal "
                "swapped-ticket threshold."
            ),
        ),
        synthetic_swapped_pair_recall_wilson_95_ci=Measurement(
            status=_pair_metric_status(len(swapped_pairs)),
            value=_wilson_95_interval(swapped_detected, len(swapped_pairs)),
            definition=(
                "Wilson 95% interval for "
                + ("synthetic " if is_synthetic else "")
                + "swapped-pair recall; the small development sample is not a "
                "formal acceptance bound."
            ),
        ),
        normal_pair_false_positive_rate=Measurement(
            status=_pair_metric_status(len(normal_pairs)),
            value=_ratio(normal_false_positives, len(normal_pairs)),
            definition=(
                "False-positive issue rate on labeled normal pairs. The sample "
                "is small and cannot establish a formal production threshold."
            ),
        ),
        normal_pair_false_positive_rate_wilson_95_ci=Measurement(
            status=_pair_metric_status(len(normal_pairs)),
            value=_wilson_95_interval(
                normal_false_positives,
                len(normal_pairs),
            ),
            definition=(
                "Wilson 95% interval for normal-pair false positives; the small "
                "development sample is not a formal acceptance bound."
            ),
        ),
        role_conflict_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_rate(items, "role_conflict"),
            definition="Runs where fixed-text or template evidence supports both roles.",
        ),
        unknown_layout_rate=Measurement(
            status=MeasurementStatus.MEASURED,
            value=_rate(items, "unknown_layout"),
            definition="Runs with no positive loading or unloading layout evidence.",
        ),
        field_reliability=Measurement(
            status=MeasurementStatus.NOT_MEASURED,
            value=None,
            definition=(
                "Not measured: this frozen runner evaluates ticket role and "
                "template routing only; field extraction is not executed."
            ),
        ),
    )


def _validated_template_set(
    fixture: FrozenDevelopmentFixture,
    *,
    candidates: tuple[TemplateVersion, ...],
    current_shadow: tuple[TemplateVersion, ...],
) -> DevelopmentEvaluationTemplateSet:
    template_set = build_development_evaluation_template_set(
        candidates=candidates,
        current_shadow=current_shadow,
    )
    expected_by_family = {
        version.definition.family_id: version
        for version in fixture.candidates
    }
    selected_by_family = {
        version.definition.family_id: version
        for version in template_set.versions
    }
    if set(selected_by_family) != set(expected_by_family):
        raise FrozenDevelopmentFixtureError(
            "evaluation template families do not match the frozen manifest"
        )
    for family_id, selected in selected_by_family.items():
        expected = expected_by_family[family_id]
        if (
            selected.definition.role is not expected.definition.role
            or selected.content_sha256 != expected.content_sha256
        ):
            raise FrozenDevelopmentFixtureError(
                f"template family {family_id} content does not match the frozen manifest"
            )
    return template_set


def _build_development_report(
    *,
    dataset_id: str,
    dataset_kind: str,
    dataset_manifest_sha256: str,
    candidates: tuple[TemplateVersion, ...],
    template_set: DevelopmentEvaluationTemplateSet,
    selected_policy: RoleAssessmentPolicy,
    items: tuple[DevelopmentEvaluationItem, ...],
    pair_items: tuple[DevelopmentPairItem, ...],
    assessments: Mapping[str, TicketRoleAssessment],
    expected_count: int,
) -> DevelopmentEvaluationReport:
    metrics = _metrics(
        items,
        pair_items,
        assessments,
        dataset_kind=dataset_kind,
    )
    matcher_fingerprint = development_matcher_fingerprint()
    policy_fingerprint = development_policy_fingerprint(selected_policy)
    evaluation_fingerprint = _canonical_sha256(
        {
            "dataset_manifest_sha256": dataset_manifest_sha256,
            "matcher_fingerprint": matcher_fingerprint,
            "policy_fingerprint": policy_fingerprint,
            "purpose": EVALUATION_PURPOSE,
            "template_set_fingerprint": template_set.fingerprint,
        }
    )
    candidate_identities = tuple(
        EvaluationCandidateIdentity.from_version(candidate)
        for candidate in sorted(
            candidates,
            key=lambda version: (
                version.definition.family_id,
                version.version_id,
            ),
        )
    )
    stable_outcome_sha256 = _canonical_sha256(
        {
            "candidates": [
                candidate.to_stable_payload()
                for candidate in candidate_identities
            ],
            "evaluation_fingerprint": evaluation_fingerprint,
            "items": [item.to_stable_payload() for item in items],
            "pair_items": [item.to_payload() for item in pair_items],
            "schema_version": 1,
        }
    )
    gate_passed = (
        len(items) == expected_count
        and all(item.expected_matches_result for item in items)
        and all(item.expected_matches_result for item in pair_items)
        and (
            dataset_kind == "generated_synthetic"
            or all(
                item.detected_orientation_degrees == item.orientation_degrees
                for item in items
            )
        )
        and metrics.high_confidence_errors.value == 0
    )
    return DevelopmentEvaluationReport(
        fixture_id=dataset_id,
        dataset_kind=dataset_kind,
        dataset_manifest_sha256=dataset_manifest_sha256,
        template_set_fingerprint=template_set.fingerprint,
        matcher_fingerprint=matcher_fingerprint,
        policy_fingerprint=policy_fingerprint,
        evaluation_fingerprint=evaluation_fingerprint,
        stable_outcome_sha256=stable_outcome_sha256,
        candidates=candidate_identities,
        items=items,
        pair_items=pair_items,
        expected_count=expected_count,
        result_count=len(items),
        metrics=metrics,
        gate_passed=gate_passed,
    )


def run_development_evaluation(
    fixture: FrozenDevelopmentFixture,
    *,
    candidates: tuple[TemplateVersion, ...],
    current_shadow: tuple[TemplateVersion, ...] = (),
    policy: RoleAssessmentPolicy | None = None,
) -> DevelopmentEvaluationReport:
    """Evaluate repository-backed candidates against one frozen fixture.

    Candidate identities and content hashes in the report are taken from the
    supplied versions. Their selected definitions must exactly match the
    frozen fixture, preventing a repository lifecycle decision from being
    attached to a different template body.
    """

    selected_policy = default_development_policy() if policy is None else policy
    template_set = _validated_template_set(
        fixture,
        candidates=candidates,
        current_shadow=current_shadow,
    )
    runs: list[tuple[FrozenObservationCase, int, TemplateRoleRun]] = []
    for case in fixture.observation_cases:
        for orientation in case.rotations:
            role_input = _synthetic_role_input(fixture, case, orientation)
            run = match_ticket_role_for_development_evaluation(
                role_input,
                candidates=candidates,
                current_shadow=current_shadow,
                policy=selected_policy,
            )
            runs.append((case, orientation, run))
    items = tuple(
        _evaluation_item(
            case_id=case.case_id,
            expected_role=case.expected_role,
            quality_tags=case.quality_tags,
            truth_source="generated_synthetic",
            identity_kind="synthetic_observation_sha256",
            sample_id=f"{case.case_id}@{orientation}",
            orientation=orientation,
            run=run,
        )
        for case, orientation, run in runs
    )
    assessments = {
        item.sample_id: run.assessment
        for item, (_, _, run) in zip(items, runs, strict=True)
    }
    pair_items = _evaluate_pairs(fixture, items)
    return _build_development_report(
        dataset_id=fixture.fixture_id,
        dataset_kind="generated_synthetic",
        dataset_manifest_sha256=fixture.manifest_sha256,
        candidates=candidates,
        template_set=template_set,
        selected_policy=selected_policy,
        items=items,
        pair_items=pair_items,
        expected_count=sum(
            len(case.rotations)
            for case in fixture.observation_cases
        ),
        assessments=assessments,
    )


def run_authorizing_development_evaluation(
    dataset: AuthorizingDevelopmentDataset,
    *,
    candidates: tuple[TemplateVersion, ...],
    current_shadow: tuple[TemplateVersion, ...] = (),
    policy: RoleAssessmentPolicy | None = None,
) -> DevelopmentEvaluationReport:
    """Evaluate SQLite-selected templates against code-approved synthetic rows."""

    selected_policy = default_development_policy() if policy is None else policy
    template_set = build_development_evaluation_template_set(
        candidates=candidates,
        current_shadow=current_shadow,
    )
    runs: list[
        tuple[
            AuthorizingObservationCase,
            AuthorizingObservationSample,
            TemplateRoleRun,
        ]
    ] = []
    for case in dataset.observation_cases:
        for sample in case.rotations:
            run = match_ticket_role_for_development_evaluation(
                sample.role_input,
                candidates=candidates,
                current_shadow=current_shadow,
                policy=selected_policy,
            )
            runs.append((case, sample, run))

    covered_candidate_ids = {
        matched_id
        for _, _, run in runs
        for evidence in run.observation.evidence
        if evidence.source is RoleEvidenceSource.TEMPLATE
        for matched_id in evidence.matched_ids
    }
    missing_coverage = sorted(
        candidate.version_id
        for candidate in candidates
        if candidate.version_id not in covered_candidate_ids
    )
    if missing_coverage:
        raise FrozenDevelopmentFixtureError(
            "candidate versions are not covered by authorizing observations: "
            + ", ".join(missing_coverage)
        )

    items = tuple(
        _evaluation_item(
            case_id=case.case_id,
            expected_role=case.truth_role,
            quality_tags=case.quality_tags,
            truth_source=case.truth_source,
            identity_kind="synthetic_observation_sha256",
            sample_id=sample.sample_id,
            orientation=sample.orientation_degrees,
            run=run,
        )
        for case, sample, run in runs
    )
    assessments = {
        item.sample_id: run.assessment
        for item, (_, _, run) in zip(items, runs, strict=True)
    }
    pair_items = _evaluate_authorizing_pairs(dataset, items)
    return _build_development_report(
        dataset_id=dataset.dataset_id,
        dataset_kind="authorizing_observation_dataset",
        dataset_manifest_sha256=dataset.manifest_sha256,
        candidates=candidates,
        template_set=template_set,
        selected_policy=selected_policy,
        items=items,
        pair_items=pair_items,
        assessments=assessments,
        expected_count=sum(
            len(case.rotations)
            for case in dataset.observation_cases
        ),
    )


def run_frozen_development_evaluation(
    manifest_path: Path,
    *,
    candidate_lifecycle: TemplateLifecycle = TemplateLifecycle.DRAFT,
    current_shadow: tuple[TemplateVersion, ...] = (),
    policy: RoleAssessmentPolicy | None = None,
) -> DevelopmentEvaluationReport:
    """Run the frozen fixture using deterministic local candidate identities."""

    fixture = load_frozen_development_fixture(
        manifest_path,
        candidate_lifecycle=candidate_lifecycle,
    )
    return run_development_evaluation(
        fixture,
        candidates=fixture.candidates,
        current_shadow=current_shadow,
        policy=policy,
    )
