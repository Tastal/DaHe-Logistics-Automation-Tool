from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation, localcontext
from typing import cast

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

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SUPPORTED_QUALITY_CONDITIONS = frozenset(
    {
        "blur",
        "crop",
        "glare",
        "non_ticket",
        "printed",
        "rotation_0",
        "rotation_90",
        "rotation_180",
        "rotation_270",
        "screen",
        "unknown_layout",
    }
)
REQUIRED_NATURAL_QUALITY_CONDITIONS = frozenset(
    SUPPORTED_QUALITY_CONDITIONS - {"non_ticket"}
)
ROTATION_QUALITY_CONDITIONS = frozenset(
    {"rotation_0", "rotation_90", "rotation_180", "rotation_270"}
)
UNKNOWN_TRUTH_QUALITY_CONDITIONS = frozenset({"unknown_layout"})
KNOWN_ROLES = ("loading", "unloading", "unknown")
TRUTH_ROLES = KNOWN_ROLES
AUTOMATIC_OUTCOMES = {
    "normal_ready",
    "awaiting_review",
}
DERIVED_ADVERSARIAL_GENERATOR_VERSION = "dahe.loop7.derived-role-adversarial.v1"
WILSON_95_Z = Decimal("1.959963984540054")
RATE_QUANTUM = Decimal("0.000001")
RUNTIME_COMPARISON_EVIDENCE_VERSION = 1
RUNTIME_EXECUTION_GATE_VERSION = 1
NOT_MEASURED_RUNTIME_REASON = "runtime_evidence_not_provided"
LOCAL_OCR_RUNTIME_SOURCE = "local_ocr_locked_evaluator"
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
_RUNTIME_CRITICAL_FIELDS = frozenset(
    {
        "ordinary_net_amount",
        "ordinary_net_unit",
        "ordinary_net_reliable",
        "weight_review_reason",
        "role",
        "role_quality",
        "role_high_confidence",
        "safety_route",
    }
)
_AUTOMATIC_REVIEW_REASONS = frozenset(
    {
        "ocr_weight_disagreement",
        "ticket_weight_format_suspicious",
    }
)
_CANDIDATE_REVIEW_SOURCE_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "seal_sha256",
        "package_sha256",
        "record_set_sha256",
        "review_history_authority_sha256",
        "source_authority_sha256",
    }
)


class LockedSetAcceptanceError(ValueError):
    """Raised when formal locked-set release evidence is incomplete or stale."""


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise LockedSetAcceptanceError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise LockedSetAcceptanceError(f"{label} must be a list")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LockedSetAcceptanceError(f"{label} is required")
    return value.strip()


def _sha256(value: object, label: str) -> str:
    digest = _text(value, label)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise LockedSetAcceptanceError(f"{label} must be a lowercase SHA-256")
    return digest


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise LockedSetAcceptanceError(f"{label} is invalid")
    return value


def _require_schema_version(
    value: object,
    label: str,
    *,
    expected: int,
) -> None:
    if type(value) is not int or value != expected:
        raise LockedSetAcceptanceError(f"{label} schema version is unsupported")


def _decimal(value: object, label: str) -> Decimal:
    if not isinstance(value, str):
        raise LockedSetAcceptanceError(f"{label} must be a decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise LockedSetAcceptanceError(f"{label} is invalid") from exc
    if not result.is_finite() or result < 0:
        raise LockedSetAcceptanceError(f"{label} is invalid")
    return result


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_candidate_review_source_authority_binding(
    value: object,
) -> dict[str, object]:
    """Return the canonical immutable source binding for a formal report."""

    binding = _mapping(
        value,
        "candidate-review source authority",
    )
    if set(binding) != _CANDIDATE_REVIEW_SOURCE_AUTHORITY_FIELDS:
        raise LockedSetAcceptanceError(
            "candidate-review source authority fields are invalid"
        )
    _require_schema_version(
        binding.get("schema_version"),
        "candidate-review source authority",
        expected=1,
    )
    return {
        "schema_version": 1,
        "seal_sha256": _sha256(
            binding.get("seal_sha256"),
            "candidate-review source authority seal SHA-256",
        ),
        "package_sha256": _sha256(
            binding.get("package_sha256"),
            "candidate-review source authority package SHA-256",
        ),
        "record_set_sha256": _sha256(
            binding.get("record_set_sha256"),
            "candidate-review source authority record-set SHA-256",
        ),
        "review_history_authority_sha256": _sha256(
            binding.get("review_history_authority_sha256"),
            "candidate-review source authority history SHA-256",
        ),
        "source_authority_sha256": _sha256(
            binding.get("source_authority_sha256"),
            "candidate-review source authority SHA-256",
        ),
    }


def candidate_review_source_authority_binding_sha256(
    value: object,
) -> str:
    """Hash a fully validated candidate-review source binding."""

    return _canonical_sha256(
        validate_candidate_review_source_authority_binding(value)
    )


def not_measured_runtime_comparison_payload() -> dict[str, object]:
    """Return the only explicit contract for an evaluator without runtime evidence."""

    payload: dict[str, object] = {
        "critical_fields_match": None,
        "differences": [],
        "failures": [],
        "outputs": [],
        "reason": NOT_MEASURED_RUNTIME_REASON,
        "schema_version": RUNTIME_COMPARISON_EVIDENCE_VERSION,
        "selected_runtime_kind": None,
        "source": None,
        "status": "not_measured",
    }
    payload["comparison_sha256"] = _canonical_sha256(payload)
    return payload


def quality_review_evidence_sha256(
    *,
    dataset_id: str,
    manifest_sha256: str,
    entry: Mapping[str, object],
) -> str:
    """Bind one human quality attestation to its exact reviewed subject."""

    identity = _text(dataset_id, "quality review dataset ID")
    manifest_identity = _sha256(
        manifest_sha256,
        "quality review manifest SHA-256",
    )
    condition = _text(
        entry.get("condition"),
        "quality coverage condition",
    )
    if condition not in REQUIRED_NATURAL_QUALITY_CONDITIONS:
        raise LockedSetAcceptanceError("quality coverage condition is invalid")
    reviewer_id = _text(
        entry.get("reviewer_id"),
        "quality coverage reviewer",
    )
    reviewed_at = _text(
        entry.get("reviewed_at"),
        "quality coverage review time",
    )
    try:
        parsed_time = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LockedSetAcceptanceError("quality coverage review time must be ISO-8601") from exc
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise LockedSetAcceptanceError("quality coverage review time must include a timezone")
    payload: dict[str, object] = {
        "condition": condition,
        "dataset_id": identity,
        "manifest_sha256": manifest_identity,
        "reviewed_at": reviewed_at,
        "reviewer_id": reviewer_id,
        "schema_version": 1,
    }
    allowed_fields = {
        "condition",
        "review_evidence_sha256",
        "reviewed_at",
        "reviewer_id",
    }
    payload["subject"] = {
        "image_sha256": _sha256(
            entry.get("image_sha256"),
            "quality coverage image SHA-256",
        )
    }
    allowed_fields.add("image_sha256")
    notes = entry.get("notes")
    if notes is not None:
        payload["notes"] = _text(notes, "quality coverage notes")
        allowed_fields.add("notes")
    if set(entry).difference(allowed_fields):
        raise LockedSetAcceptanceError("quality coverage entry contains unsupported fields")
    return _canonical_sha256(payload)


def locked_set_quality_coverage_sha256(
    value: Mapping[str, object],
) -> str:
    """Hash the complete quality declaration except its self-hash field."""

    payload = dict(value)
    payload.pop("quality_coverage_sha256", None)
    return _canonical_sha256(payload)


def _without_integrity_field(
    value: dict[str, object],
    field: str,
) -> dict[str, object]:
    return {key: item for key, item in value.items() if key != field}


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    return "0" if normalized == 0 else format(normalized, "f")


def _millisecond_text(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.001")), ".3f")


def _wilson_95_interval(
    success_count: int,
    sample_count: int,
) -> dict[str, object]:
    if sample_count <= 0 or success_count < 0 or success_count > sample_count:
        raise ValueError("Wilson interval counts are invalid")
    with localcontext() as context:
        context.prec = 50
        successes = Decimal(success_count)
        samples = Decimal(sample_count)
        proportion = successes / samples
        z_squared = WILSON_95_Z * WILSON_95_Z
        denominator = Decimal(1) + z_squared / samples
        center = (proportion + z_squared / (Decimal(2) * samples)) / denominator
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


def _require_binding(
    payload: dict[str, object],
    *,
    label: str,
    dataset_id: str,
    manifest_sha256: str,
) -> None:
    if _text(payload.get("dataset_id"), f"{label} dataset_id") != dataset_id:
        raise LockedSetAcceptanceError(f"{label} dataset binding is invalid")
    if (
        _sha256(
            payload.get("manifest_sha256"),
            f"{label} manifest_sha256",
        )
        != manifest_sha256
    ):
        raise LockedSetAcceptanceError(f"{label} manifest binding is invalid")


def _manifest_contract(
    truth_manifest: object,
) -> tuple[
    str,
    str,
    dict[str, tuple[str, str]],
    dict[str, tuple[str, str]],
]:
    manifest = _mapping(truth_manifest, "truth manifest")
    _require_schema_version(
        manifest.get("schema_version"),
        "truth manifest",
        expected=1,
    )
    dataset_id = _text(manifest.get("dataset_id"), "truth manifest dataset_id")
    manifest_sha256 = _sha256(
        manifest.get("manifest_sha256"),
        "truth manifest manifest_sha256",
    )
    if (
        _integer(manifest.get("waybill_count"), "truth manifest waybill_count") != 50
        or _integer(manifest.get("image_count"), "truth manifest image_count") != 100
    ):
        raise LockedSetAcceptanceError("truth manifest requires exactly 50 waybills and 100 images")
    pairs = _sequence(manifest.get("pairs"), "truth manifest pairs")
    if len(pairs) != 50:
        raise LockedSetAcceptanceError("truth manifest requires exactly 50 pairs")

    image_truth: dict[str, tuple[str, str]] = {}
    pair_slots: dict[str, tuple[str, str]] = {}
    waybill_identities: set[str] = set()
    for raw_pair in pairs:
        pair = _mapping(raw_pair, "truth manifest pair")
        sample_id = _text(pair.get("sample_id"), "truth manifest sample_id")
        if sample_id in pair_slots:
            raise LockedSetAcceptanceError("truth manifest sample IDs must be unique")
        waybill_identity = _sha256(
            pair.get("waybill_identity_sha256"),
            "truth manifest waybill identity",
        )
        if waybill_identity in waybill_identities:
            raise LockedSetAcceptanceError("truth manifest waybill identities must be unique")
        waybill_identities.add(waybill_identity)
        if (
            pair.get("human_confirmed") is not True
            or pair.get("label_source") != "direct_image_review"
        ):
            raise LockedSetAcceptanceError(
                "truth manifest labels require direct human image review"
            )
        images = _sequence(pair.get("images"), "truth manifest pair images")
        if len(images) != 2:
            raise LockedSetAcceptanceError("truth manifest pair requires exactly two images")
        pair_image_hashes: set[str] = set()
        for raw_image in images:
            image = _mapping(raw_image, "truth manifest image")
            image_sha256 = _sha256(
                image.get("image_sha256"),
                "truth manifest image SHA-256",
            )
            truth_role = _text(
                image.get("truth_role"),
                "truth manifest image role",
            )
            if truth_role not in TRUTH_ROLES:
                raise LockedSetAcceptanceError("truth manifest image role is invalid")
            if image_sha256 in image_truth:
                raise LockedSetAcceptanceError("truth manifest image identities must be unique")
            image_truth[image_sha256] = (sample_id, truth_role)
            pair_image_hashes.add(image_sha256)
        if len(pair_image_hashes) != 2:
            raise LockedSetAcceptanceError("truth manifest pair images must be distinct")
        slots = _mapping(pair.get("submitted_slots"), "truth manifest submitted slots")
        loading_slot = _sha256(
            slots.get("loading"),
            "truth manifest loading slot",
        )
        unloading_slot = _sha256(
            slots.get("unloading"),
            "truth manifest unloading slot",
        )
        if {loading_slot, unloading_slot} != pair_image_hashes:
            raise LockedSetAcceptanceError(
                "truth manifest submitted slots do not match pair images"
            )
        pair_slots[sample_id] = (loading_slot, unloading_slot)
    if len(image_truth) != 100:
        raise LockedSetAcceptanceError("truth manifest image identities do not reconcile")
    return dataset_id, manifest_sha256, image_truth, pair_slots


def _validate_preflight(
    value: object,
    *,
    dataset_id: str,
    manifest_sha256: str,
) -> tuple[str, str]:
    attestation = _mapping(value, "preflight attestation")
    _require_schema_version(
        attestation.get("schema_version"),
        "preflight attestation",
        expected=1,
    )
    _require_binding(
        attestation,
        label="preflight attestation",
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
    )
    if (
        _integer(attestation.get("waybill_count"), "preflight waybill_count") != 50
        or _integer(attestation.get("image_count"), "preflight image_count") != 100
    ):
        raise LockedSetAcceptanceError("preflight attestation counts do not reconcile")
    return (
        _sha256(
            attestation.get("attestation_sha256"),
            "preflight attestation SHA-256",
        ),
        _sha256(
            attestation.get("exclusion_snapshot_sha256"),
            "preflight exclusion snapshot SHA-256",
        ),
    )


def _validate_history(
    value: object,
    *,
    dataset_id: str,
    manifest_sha256: str,
) -> dict[str, object]:
    history = _mapping(value, "eligibility history")
    _require_schema_version(
        history.get("schema_version"),
        "eligibility history",
        expected=1,
    )
    _require_binding(
        history,
        label="eligibility history",
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
    )
    status = _text(history.get("status"), "eligibility history status")
    if status not in {"eligible", "permanently_invalidated"}:
        raise LockedSetAcceptanceError("eligibility history status is invalid")
    events = _sequence(history.get("events"), "eligibility history events")
    if not events:
        raise LockedSetAcceptanceError("eligibility history requires an event")
    event_ids: set[str] = set()
    permanently_invalidated = False
    for raw_event in events:
        event = _mapping(raw_event, "eligibility event")
        event_id = _text(event.get("event_id"), "eligibility event ID")
        if event_id in event_ids:
            raise LockedSetAcceptanceError("eligibility history event IDs must be unique")
        event_ids.add(event_id)
        event_type = _text(event.get("event_type"), "eligibility event type")
        _text(event.get("recorded_at"), "eligibility event time")
        _text(event.get("actor_id"), "eligibility event actor")
        event_sha256 = _sha256(
            event.get("event_sha256"),
            "eligibility event SHA-256",
        )
        if event_sha256 != _canonical_sha256(_without_integrity_field(event, "event_sha256")):
            raise LockedSetAcceptanceError("eligibility history event integrity is invalid")
        if event_type == "executable_influence":
            permanently_invalidated = True
    if permanently_invalidated or status == "permanently_invalidated":
        raise LockedSetAcceptanceError(
            "locked set is permanently invalidated by its eligibility history"
        )
    history_sha256 = _sha256(
        history.get("history_sha256"),
        "eligibility history SHA-256",
    )
    if history_sha256 != _canonical_sha256(_without_integrity_field(history, "history_sha256")):
        raise LockedSetAcceptanceError("eligibility history integrity is invalid")
    return history


def _optional_probability(
    value: object,
    label: str,
) -> Decimal | None:
    if value is None:
        return None
    probability = _decimal(value, label)
    if probability > 1:
        raise LockedSetAcceptanceError(f"{label} is invalid")
    return probability


def _runtime_output_contract(
    value: object,
    *,
    image_sha256: str,
) -> dict[str, object]:
    output = _mapping(value, "runtime output")
    expected_fields = {
        "assessment_fingerprint",
        "critical_output",
        "image_sha256",
        "ordinary_net_confidence",
        "output_fingerprint",
        "role_confidence",
        "runtime_fingerprint",
        "runtime_kind",
        "wall_elapsed_ms",
        "worker_elapsed_ms",
    }
    if set(output) != expected_fields:
        raise LockedSetAcceptanceError("runtime output schema is invalid")
    if _sha256(output.get("image_sha256"), "runtime output image") != image_sha256:
        raise LockedSetAcceptanceError("runtime output image identity changed")
    runtime_kind = _text(output.get("runtime_kind"), "runtime kind")
    if runtime_kind not in _RUNTIME_KINDS:
        raise LockedSetAcceptanceError("runtime kind is invalid")
    _sha256(output.get("runtime_fingerprint"), "runtime fingerprint")
    _sha256(output.get("output_fingerprint"), "runtime output fingerprint")
    _sha256(output.get("assessment_fingerprint"), "runtime assessment fingerprint")
    _decimal(output.get("wall_elapsed_ms"), "runtime wall latency")
    _decimal(output.get("worker_elapsed_ms"), "runtime worker latency")
    ordinary_confidence = _optional_probability(
        output.get("ordinary_net_confidence"),
        "runtime ordinary-net confidence",
    )
    role_confidence = _optional_probability(
        output.get("role_confidence"),
        "runtime role confidence",
    )
    if role_confidence is None:
        raise LockedSetAcceptanceError("runtime role confidence is required")

    critical = _mapping(output.get("critical_output"), "runtime critical output")
    if set(critical) != _RUNTIME_CRITICAL_FIELDS:
        raise LockedSetAcceptanceError("runtime critical output schema is invalid")
    raw_amount = critical.get("ordinary_net_amount")
    ordinary_amount = (
        None if raw_amount is None else _decimal(raw_amount, "runtime ordinary-net amount")
    )
    if ordinary_amount is not None and ordinary_amount <= 0:
        raise LockedSetAcceptanceError("runtime ordinary-net amount is invalid")
    raw_unit = critical.get("ordinary_net_unit")
    ordinary_unit = None if raw_unit is None else _text(raw_unit, "runtime ordinary-net unit")
    ordinary_reliable = critical.get("ordinary_net_reliable")
    if not isinstance(ordinary_reliable, bool):
        raise LockedSetAcceptanceError("runtime ordinary-net reliability is invalid")
    weight_review_reason = critical.get("weight_review_reason")
    if (
        weight_review_reason is not None
        and weight_review_reason not in _AUTOMATIC_REVIEW_REASONS
    ):
        raise LockedSetAcceptanceError(
            "runtime weight-review reason is invalid"
        )
    if ordinary_reliable and weight_review_reason is not None:
        raise LockedSetAcceptanceError(
            "runtime reliable ordinary-net evidence cannot require review"
        )
    if ordinary_reliable:
        exact_cents = False
        if ordinary_amount is not None:
            try:
                exact_cents = ordinary_amount == ordinary_amount.quantize(Decimal("0.01"))
            except InvalidOperation:
                exact_cents = False
        if ordinary_unit != "t" or ordinary_confidence is None or not exact_cents:
            raise LockedSetAcceptanceError("runtime reliable ordinary-net evidence is invalid")
    role = _text(critical.get("role"), "runtime role")
    role_quality = _text(critical.get("role_quality"), "runtime role quality")
    role_high_confidence = critical.get("role_high_confidence")
    if (
        role not in KNOWN_ROLES
        or role_quality not in {"reliable", "uncertain"}
        or not isinstance(role_high_confidence, bool)
        or (role == "unknown" and (role_quality == "reliable" or role_high_confidence))
        or (role != "unknown" and role_quality != "reliable")
    ):
        raise LockedSetAcceptanceError("runtime role evidence is invalid")
    safety_route = _text(critical.get("safety_route"), "runtime safety route")
    expected_route = (
        "eligible_for_downstream_comparison"
        if (role != "unknown" and role_quality == "reliable" and ordinary_reliable)
        else "non_automatic"
    )
    if safety_route != expected_route:
        raise LockedSetAcceptanceError("runtime safety route is inconsistent")
    return output


def _runtime_failure_contract(
    value: object,
    *,
    image_sha256: str,
) -> dict[str, object]:
    failure = _mapping(value, "runtime failure")
    if set(failure) != {
        "diagnostic_code",
        "error_kind",
        "image_sha256",
        "runtime_fingerprint",
        "runtime_kind",
        "wall_elapsed_ms",
    }:
        raise LockedSetAcceptanceError("runtime failure schema is invalid")
    if _sha256(failure.get("image_sha256"), "runtime failure image") != image_sha256:
        raise LockedSetAcceptanceError("runtime failure image identity changed")
    runtime_kind = _text(failure.get("runtime_kind"), "runtime failure kind")
    if runtime_kind not in _RUNTIME_KINDS:
        raise LockedSetAcceptanceError("runtime failure kind is invalid")
    _sha256(failure.get("runtime_fingerprint"), "runtime failure fingerprint")
    _decimal(failure.get("wall_elapsed_ms"), "runtime failure latency")
    _text(failure.get("error_kind"), "runtime error kind")
    _text(failure.get("diagnostic_code"), "runtime diagnostic code")
    return failure


def _runtime_comparison_contract(
    value: object,
    *,
    image_sha256: str,
    predicted_role: str,
    high_confidence: bool,
) -> str:
    comparison = _mapping(value, "runtime comparison")
    expected_fields = {
        "comparison_sha256",
        "critical_fields_match",
        "differences",
        "failures",
        "outputs",
        "reason",
        "schema_version",
        "selected_runtime_kind",
        "source",
        "status",
    }
    if set(comparison) != expected_fields:
        raise LockedSetAcceptanceError("runtime comparison schema is invalid")
    _require_schema_version(
        comparison.get("schema_version"),
        "runtime comparison",
        expected=RUNTIME_COMPARISON_EVIDENCE_VERSION,
    )
    comparison_sha256 = _sha256(
        comparison.get("comparison_sha256"),
        "runtime comparison SHA-256",
    )
    if comparison_sha256 != _canonical_sha256(
        {field: item for field, item in comparison.items() if field != "comparison_sha256"}
    ):
        raise LockedSetAcceptanceError("runtime comparison integrity is invalid")
    status = _text(comparison.get("status"), "runtime comparison status")
    if status not in _RUNTIME_COMPARISON_STATUSES:
        raise LockedSetAcceptanceError("runtime comparison status is invalid")
    source = comparison.get("source")
    reason = comparison.get("reason")
    selected_runtime_kind = comparison.get("selected_runtime_kind")
    critical_fields_match = comparison.get("critical_fields_match")
    raw_differences = _sequence(
        comparison.get("differences"),
        "runtime differences",
    )
    if any(
        not isinstance(item, str) or item not in _RUNTIME_CRITICAL_FIELDS
        for item in raw_differences
    ) or len(set(raw_differences)) != len(raw_differences):
        raise LockedSetAcceptanceError("runtime differences are invalid")
    outputs = tuple(
        _runtime_output_contract(item, image_sha256=image_sha256)
        for item in _sequence(comparison.get("outputs"), "runtime outputs")
    )
    failures = tuple(
        _runtime_failure_contract(item, image_sha256=image_sha256)
        for item in _sequence(comparison.get("failures"), "runtime failures")
    )
    output_kinds = tuple(cast(str, item["runtime_kind"]) for item in outputs)
    failure_kinds = tuple(cast(str, item["runtime_kind"]) for item in failures)
    if (
        output_kinds != tuple(sorted(output_kinds))
        or failure_kinds != tuple(sorted(failure_kinds))
        or len(set(output_kinds)) != len(output_kinds)
        or len(set(failure_kinds)) != len(failure_kinds)
        or set(output_kinds).intersection(failure_kinds)
    ):
        raise LockedSetAcceptanceError("runtime comparison members are invalid")

    if status == "not_measured":
        valid = (
            source is None
            and reason == NOT_MEASURED_RUNTIME_REASON
            and selected_runtime_kind is None
            and critical_fields_match is None
            and not raw_differences
            and not outputs
            and not failures
        )
    elif status == "single_cpu":
        valid = (
            source == LOCAL_OCR_RUNTIME_SOURCE
            and reason == "single_qualified_cpu"
            and selected_runtime_kind == "cpu"
            and critical_fields_match is None
            and not raw_differences
            and output_kinds == ("cpu",)
            and not failures
        )
    elif status == "dual_consistent":
        valid = (
            source == LOCAL_OCR_RUNTIME_SOURCE
            and reason is None
            and selected_runtime_kind in _RUNTIME_KINDS
            and critical_fields_match is True
            and not raw_differences
            and output_kinds == ("cpu", "gpu")
            and not failures
            and outputs[0]["critical_output"] == outputs[1]["critical_output"]
        )
    elif status == "dual_different":
        cpu_critical = (
            cast(dict[str, object], outputs[0]["critical_output"])
            if output_kinds == ("cpu", "gpu")
            else {}
        )
        gpu_critical = (
            cast(dict[str, object], outputs[1]["critical_output"])
            if output_kinds == ("cpu", "gpu")
            else {}
        )
        actual_differences = (
            {
                field
                for field in _RUNTIME_CRITICAL_FIELDS
                if cpu_critical[field] != gpu_critical[field]
            }
            if output_kinds == ("cpu", "gpu")
            else set()
        )
        valid = (
            source == LOCAL_OCR_RUNTIME_SOURCE
            and reason == "critical_outputs_differ"
            and selected_runtime_kind == "cpu"
            and critical_fields_match is False
            and set(raw_differences) == actual_differences
            and bool(actual_differences)
            and output_kinds == ("cpu", "gpu")
            and not failures
        )
    else:
        valid = (
            source == LOCAL_OCR_RUNTIME_SOURCE
            and reason == "gpu_runtime_failed"
            and selected_runtime_kind == "cpu"
            and critical_fields_match is None
            and not raw_differences
            and output_kinds == ("cpu",)
            and failure_kinds == ("gpu",)
        )
    if not valid:
        raise LockedSetAcceptanceError("runtime comparison status is inconsistent")
    if selected_runtime_kind is not None:
        selected = next(item for item in outputs if item["runtime_kind"] == selected_runtime_kind)
        selected_critical = cast(
            dict[str, object],
            selected["critical_output"],
        )
        if (
            selected_critical["role"] != predicted_role
            or selected_critical["role_high_confidence"] is not high_confidence
        ):
            raise LockedSetAcceptanceError("image result differs from selected runtime output")
    return comparison_sha256


def _runtime_comparison_evidence_sha256(
    comparisons: Mapping[str, str],
) -> str:
    return _canonical_sha256(
        {
            "items": [
                {
                    "comparison_sha256": comparisons[image_sha256],
                    "image_sha256": image_sha256,
                }
                for image_sha256 in sorted(comparisons)
            ],
            "schema_version": RUNTIME_COMPARISON_EVIDENCE_VERSION,
        }
    )


def _expected_runtime_kinds_contract(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or any(not isinstance(item, str) for item in value)
    ):
        raise LockedSetAcceptanceError("expected runtime kinds are invalid")
    expected = tuple(value)
    if expected != ("cpu", "gpu"):
        raise LockedSetAcceptanceError("formal expected runtime kinds must be exactly CPU plus GPU")
    return expected


def _runtime_latency_summary(values: list[Decimal]) -> dict[str, object]:
    if not values:
        return {
            "sample_count": 0,
            "p50": None,
            "p95": None,
        }
    ordered = sorted(values)
    sample_count = len(ordered)
    return {
        "sample_count": sample_count,
        "p50": _millisecond_text(ordered[math.ceil(sample_count * 0.50) - 1]),
        "p95": _millisecond_text(ordered[math.ceil(sample_count * 0.95) - 1]),
    }


def _runtime_execution_gate(
    *,
    image_results: Mapping[str, dict[str, object]],
    expected_runtime_kinds: object,
) -> dict[str, object]:
    expected = _expected_runtime_kinds_contract(expected_runtime_kinds)
    expected_status = "dual_consistent"
    status_counts = {
        status: 0
        for status in sorted(_RUNTIME_COMPARISON_STATUSES)
    }
    runtime_evidence: dict[str, dict[str, object]] = {
        runtime_kind: {
            "success_count": 0,
            "failure_count": 0,
            "wall_elapsed_ms": [],
            "worker_elapsed_ms": [],
        }
        for runtime_kind in expected
    }
    evidence_items: list[dict[str, str]] = []
    failed_image_count = 0
    for image_sha256 in sorted(image_results):
        result = image_results[image_sha256]
        comparison = cast(
            dict[str, object],
            result["runtime_comparison"],
        )
        status = cast(str, comparison["status"])
        if status == "not_measured":
            raise LockedSetAcceptanceError(
                "formal runtime evidence must not use not_measured"
            )
        status_counts[status] += 1
        if status != expected_status:
            failed_image_count += 1
        evidence_items.append(
            {
                "comparison_sha256": cast(
                    str,
                    comparison["comparison_sha256"],
                ),
                "image_sha256": image_sha256,
            }
        )
        for raw_output in cast(list[object], comparison["outputs"]):
            output = cast(dict[str, object], raw_output)
            runtime_kind = cast(str, output["runtime_kind"])
            if runtime_kind not in runtime_evidence:
                continue
            summary = runtime_evidence[runtime_kind]
            summary["success_count"] = cast(int, summary["success_count"]) + 1
            cast(list[Decimal], summary["wall_elapsed_ms"]).append(
                _decimal(output["wall_elapsed_ms"], "runtime wall latency")
            )
            cast(list[Decimal], summary["worker_elapsed_ms"]).append(
                _decimal(output["worker_elapsed_ms"], "runtime worker latency")
            )
        for raw_failure in cast(list[object], comparison["failures"]):
            failure = cast(dict[str, object], raw_failure)
            runtime_kind = cast(str, failure["runtime_kind"])
            if runtime_kind not in runtime_evidence:
                continue
            summary = runtime_evidence[runtime_kind]
            summary["failure_count"] = cast(int, summary["failure_count"]) + 1

    runtime_summaries: dict[str, object] = {}
    for runtime_kind in expected:
        raw_summary = runtime_evidence[runtime_kind]
        runtime_summaries[runtime_kind] = {
            "success_count": raw_summary["success_count"],
            "failure_count": raw_summary["failure_count"],
            "wall_elapsed_ms": _runtime_latency_summary(
                cast(list[Decimal], raw_summary["wall_elapsed_ms"])
            ),
            "worker_elapsed_ms": _runtime_latency_summary(
                cast(list[Decimal], raw_summary["worker_elapsed_ms"])
            ),
        }
    evidence_payload = {
        "expected_runtime_kinds": list(expected),
        "items": evidence_items,
        "schema_version": RUNTIME_EXECUTION_GATE_VERSION,
    }
    passed = (
        len(image_results) == 100
        and status_counts["dual_consistent"] == 100
        and status_counts["dual_different"] == 0
        and status_counts["gpu_failed_cpu_fallback"] == 0
        and status_counts["single_cpu"] == 0
        and status_counts["not_measured"] == 0
        and failed_image_count == 0
    )
    return {
        "schema_version": RUNTIME_EXECUTION_GATE_VERSION,
        "expected_runtime_kinds": list(expected),
        "image_count": len(image_results),
        "status_counts": status_counts,
        "failed_image_count": failed_image_count,
        "runtime_summaries": runtime_summaries,
        "evidence_sha256": _canonical_sha256(evidence_payload),
        "passed": passed,
    }


def _image_result_contract(
    value: object,
    *,
    image_truth: dict[str, tuple[str, str]],
) -> tuple[
    list[dict[str, object]],
    dict[str, dict[str, object]],
    dict[str, list[str]],
    str,
]:
    results = _sequence(value, "image results")
    normalized_results: list[dict[str, object]] = []
    by_hash: dict[str, dict[str, object]] = {}
    result_ids: set[str] = set()
    unexpected: list[str] = []
    duplicate: list[str] = []
    runtime_comparisons: dict[str, str] = {}
    for raw_result in results:
        result = _mapping(raw_result, "image result")
        normalized_results.append(result)
        result_id = _text(result.get("result_id"), "image result ID")
        if result_id in result_ids:
            duplicate.append(result_id)
        result_ids.add(result_id)
        image_sha256 = _sha256(
            result.get("image_sha256"),
            "image result SHA-256",
        )
        if image_sha256 not in image_truth:
            unexpected.append(image_sha256)
            continue
        if image_sha256 in by_hash:
            duplicate.append(image_sha256)
            continue
        expected_sample, _ = image_truth[image_sha256]
        if _text(result.get("sample_id"), "image result sample_id") != expected_sample:
            raise LockedSetAcceptanceError(
                "image result reconciliation failed: sample membership changed"
            )
        predicted_role = _text(
            result.get("predicted_role"),
            "image result predicted role",
        )
        if predicted_role not in KNOWN_ROLES:
            raise LockedSetAcceptanceError("image result predicted role is invalid")
        if not isinstance(result.get("high_confidence"), bool):
            raise LockedSetAcceptanceError("image result high-confidence flag is invalid")
        automatic_review_reason = result.get(
            "automatic_review_reason"
        )
        if (
            automatic_review_reason is not None
            and automatic_review_reason
            not in _AUTOMATIC_REVIEW_REASONS
        ):
            raise LockedSetAcceptanceError(
                "image result automatic review reason is invalid"
            )
        _decimal(
            result.get("incremental_elapsed_ms"),
            "image result incremental latency",
        )
        runtime_comparisons[image_sha256] = _runtime_comparison_contract(
            result.get("runtime_comparison"),
            image_sha256=image_sha256,
            predicted_role=predicted_role,
            high_confidence=cast(bool, result["high_confidence"]),
        )
        by_hash[image_sha256] = result
    missing = sorted(set(image_truth).difference(by_hash))
    if missing or unexpected or duplicate or len(results) != 100:
        raise LockedSetAcceptanceError("image result reconciliation failed")
    reconciliation = {
        "missing_image_results": missing,
        "unexpected_image_results": sorted(unexpected),
        "duplicate_image_results": sorted(set(duplicate)),
    }
    return (
        normalized_results,
        by_hash,
        reconciliation,
        _runtime_comparison_evidence_sha256(runtime_comparisons),
    )


def _pair_result_contract(
    value: object,
    *,
    pair_slots: dict[str, tuple[str, str]],
    image_results: Mapping[str, dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, dict[str, object]], dict[str, list[str]]]:
    results = _sequence(value, "pair results")
    normalized_results: list[dict[str, object]] = []
    by_sample: dict[str, dict[str, object]] = {}
    result_ids: set[str] = set()
    duplicate: list[str] = []
    unexpected: list[str] = []
    for raw_result in results:
        result = _mapping(raw_result, "pair result")
        normalized_results.append(result)
        result_id = _text(result.get("result_id"), "pair result ID")
        sample_id = _text(result.get("sample_id"), "pair result sample_id")
        if result_id in result_ids or sample_id in by_sample:
            duplicate.append(sample_id)
            continue
        result_ids.add(result_id)
        if sample_id not in pair_slots:
            unexpected.append(sample_id)
            continue
        expected_loading, expected_unloading = pair_slots[sample_id]
        if (
            _sha256(
                result.get("loading_slot_image_sha256"),
                "pair result loading slot",
            )
            != expected_loading
            or _sha256(
                result.get("unloading_slot_image_sha256"),
                "pair result unloading slot",
            )
            != expected_unloading
        ):
            raise LockedSetAcceptanceError(
                "pair result reconciliation failed: slot membership changed"
            )
        outcome = _text(
            result.get("automatic_outcome"),
            "pair result automatic outcome",
        )
        if outcome not in AUTOMATIC_OUTCOMES:
            raise LockedSetAcceptanceError("pair result automatic outcome is invalid")
        if "role_issue" not in result or "review_reason" not in result:
            raise LockedSetAcceptanceError(
                "pair result review fields are required"
            )
        role_issue = result["role_issue"]
        review_reason = result["review_reason"]
        if (
            review_reason is not None
            and review_reason not in _AUTOMATIC_REVIEW_REASONS
        ):
            raise LockedSetAcceptanceError(
                "pair result review reason is invalid"
            )
        if outcome == "normal_ready":
            if role_issue is not None or review_reason is not None:
                raise LockedSetAcceptanceError(
                    "pair result review fields must be null for normal_ready"
                )
        elif (
            (not isinstance(role_issue, str) or not role_issue.strip())
            and review_reason is None
        ):
            raise LockedSetAcceptanceError(
                "pair result awaiting_review requires a reason"
            )
        expected_outcome, expected_issue, expected_review_reason = (
            _predicted_role_route(
            loading_image_sha256=expected_loading,
            unloading_image_sha256=expected_unloading,
            image_results=image_results,
            )
        )
        if (
            outcome != expected_outcome
            or role_issue != expected_issue
            or review_reason != expected_review_reason
        ):
            raise LockedSetAcceptanceError(
                "pair result differs from the production role assessment"
            )
        by_sample[sample_id] = result
    missing = sorted(set(pair_slots).difference(by_sample))
    if missing or unexpected or duplicate or len(results) != 50:
        raise LockedSetAcceptanceError("pair result reconciliation failed")
    return (
        normalized_results,
        by_sample,
        {
            "missing_pair_results": missing,
            "unexpected_pair_results": sorted(unexpected),
            "duplicate_pair_results": sorted(set(duplicate)),
        },
    )


def _quality_contract(
    value: object,
    *,
    dataset_id: str,
    manifest_sha256: str,
    image_truth: Mapping[str, tuple[str, str]],
    pair_slots: Mapping[str, tuple[str, str]],
) -> dict[str, object]:
    coverage = _mapping(value, "quality coverage")
    allowed_root_fields = {
        "schema_version",
        "dataset_id",
        "manifest_sha256",
        "required_conditions",
        "entries",
        "derived_adversarial_suite",
        "quality_coverage_sha256",
    }
    if set(coverage) != allowed_root_fields:
        raise LockedSetAcceptanceError("quality coverage fields are invalid")
    _require_schema_version(
        coverage.get("schema_version"),
        "quality coverage",
        expected=2,
    )
    _require_binding(
        coverage,
        label="quality coverage",
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
    )
    quality_coverage_sha256 = _sha256(
        coverage.get("quality_coverage_sha256"),
        "quality coverage SHA-256",
    )
    if quality_coverage_sha256 != locked_set_quality_coverage_sha256(coverage):
        raise LockedSetAcceptanceError("quality coverage integrity is invalid")
    declared_suite = _mapping(
        coverage.get("derived_adversarial_suite"),
        "quality coverage derived adversarial suite",
    )
    _require_schema_version(
        declared_suite.get("schema_version"),
        "quality coverage derived adversarial suite",
        expected=1,
    )
    expected_suite = _derived_adversarial_suite(
        image_truth=image_truth,
        pair_slots=pair_slots,
    )
    if declared_suite != expected_suite:
        raise LockedSetAcceptanceError("quality coverage derived adversarial suite is invalid")
    raw_required = _sequence(
        coverage.get("required_conditions"),
        "quality coverage required conditions",
    )
    required = {_text(item, "quality coverage condition") for item in raw_required}
    if required != REQUIRED_NATURAL_QUALITY_CONDITIONS or len(raw_required) != len(
        REQUIRED_NATURAL_QUALITY_CONDITIONS
    ):
        raise LockedSetAcceptanceError("quality coverage required conditions are incomplete")
    entries = _sequence(coverage.get("entries"), "quality coverage entries")
    if len(entries) != len(REQUIRED_NATURAL_QUALITY_CONDITIONS):
        raise LockedSetAcceptanceError("quality coverage entries are incomplete")
    covered: set[str] = set()
    image_entries = 0
    rotation_images: set[str] = set()
    display_medium_images: dict[str, str] = {}
    for raw_entry in entries:
        entry = _mapping(raw_entry, "quality coverage entry")
        condition = _text(entry.get("condition"), "quality coverage condition")
        if condition not in REQUIRED_NATURAL_QUALITY_CONDITIONS or condition in covered:
            raise LockedSetAcceptanceError(
                "quality coverage conditions must be complete and unique"
            )
        covered.add(condition)
        evidence_sha256 = _sha256(
            entry.get("review_evidence_sha256"),
            "quality coverage evidence SHA-256",
        )
        if evidence_sha256 != quality_review_evidence_sha256(
            dataset_id=dataset_id,
            manifest_sha256=manifest_sha256,
            entry=entry,
        ):
            raise LockedSetAcceptanceError("quality coverage evidence hash is invalid")
        image_entries += 1
        image_sha256 = _sha256(
            entry.get("image_sha256"),
            "quality coverage image SHA-256",
        )
        truth = image_truth.get(image_sha256)
        if truth is None:
            raise LockedSetAcceptanceError("quality coverage references an unknown locked image")
        if condition in UNKNOWN_TRUTH_QUALITY_CONDITIONS and truth[1] != "unknown":
            raise LockedSetAcceptanceError(
                "quality coverage unknown or non-ticket evidence does not match human truth"
            )
        if condition in ROTATION_QUALITY_CONDITIONS:
            rotation_images.add(image_sha256)
        if condition in {"printed", "screen"}:
            display_medium_images[condition] = image_sha256
    if covered != REQUIRED_NATURAL_QUALITY_CONDITIONS:
        raise LockedSetAcceptanceError("quality coverage is incomplete")
    if len(rotation_images) != len(ROTATION_QUALITY_CONDITIONS):
        raise LockedSetAcceptanceError("quality coverage rotations require four distinct images")
    if display_medium_images.get("printed") == display_medium_images.get("screen"):
        raise LockedSetAcceptanceError(
            "quality coverage printed and screen evidence must be distinct"
        )
    return {
        "covered_conditions": sorted(covered),
        "entry_count": len(entries),
        "image_entry_count": image_entries,
        "pair_entry_count": 0,
        "derived_adversarial_suite_sha256": expected_suite["suite_sha256"],
        "quality_coverage_sha256": quality_coverage_sha256,
        "passed": True,
    }


def validate_locked_set_quality_coverage(
    value: object,
    *,
    dataset_id: str,
    manifest_sha256: str,
    image_truth: Mapping[str, tuple[str, str]],
    pair_slots: Mapping[str, tuple[str, str]],
) -> dict[str, object]:
    """Validate human quality coverage before starting expensive OCR work."""

    return _quality_contract(
        value,
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
        image_truth=image_truth,
        pair_slots=pair_slots,
    )


def _near_duplicate_contract(
    scan_value: object,
    decisions_value: object,
    *,
    dataset_id: str,
    manifest_sha256: str,
    exclusion_snapshot_sha256: str,
    image_hashes: set[str],
) -> dict[str, object]:
    scan = _mapping(scan_value, "near-duplicate scan")
    _require_schema_version(
        scan.get("schema_version"),
        "near-duplicate scan",
        expected=1,
    )
    _require_binding(
        scan,
        label="near-duplicate scan",
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
    )
    if (
        _sha256(
            scan.get("exclusion_snapshot_sha256"),
            "near-duplicate exclusion snapshot SHA-256",
        )
        != exclusion_snapshot_sha256
    ):
        raise LockedSetAcceptanceError("near-duplicate scan used a stale exclusion snapshot")
    if (
        scan.get("completed") is not True
        or _integer(
            scan.get("locked_image_count"),
            "near-duplicate locked image count",
        )
        != 100
    ):
        raise LockedSetAcceptanceError("near-duplicate scan did not cover every locked image")
    _integer(
        scan.get("excluded_image_count"),
        "near-duplicate excluded image count",
    )
    scan_fingerprint = _sha256(
        scan.get("scan_fingerprint"),
        "near-duplicate scan fingerprint",
    )
    if scan_fingerprint != _canonical_sha256(_without_integrity_field(scan, "scan_fingerprint")):
        raise LockedSetAcceptanceError("near-duplicate scan integrity is invalid")
    _sha256(
        scan.get("detector_fingerprint"),
        "near-duplicate detector fingerprint",
    )
    raw_candidates = _sequence(
        scan.get("candidates"),
        "near-duplicate candidates",
    )
    candidates: dict[str, dict[str, object]] = {}
    for raw_candidate in raw_candidates:
        candidate = _mapping(raw_candidate, "near-duplicate candidate")
        if "schema_version" in candidate:
            _require_schema_version(
                candidate.get("schema_version"),
                "near-duplicate candidate",
                expected=1,
            )
        candidate_id = _text(
            candidate.get("candidate_id"),
            "near-duplicate candidate ID",
        )
        if candidate_id in candidates:
            raise LockedSetAcceptanceError("near-duplicate candidate IDs must be unique")
        if (
            _sha256(
                candidate.get("locked_image_sha256"),
                "near-duplicate locked image SHA-256",
            )
            not in image_hashes
        ):
            raise LockedSetAcceptanceError(
                "near-duplicate candidate references an unknown locked image"
            )
        _sha256(
            candidate.get("excluded_image_sha256"),
            "near-duplicate excluded image SHA-256",
        )
        _text(candidate.get("detector"), "near-duplicate detector")
        similarity = _decimal(
            candidate.get("similarity"),
            "near-duplicate similarity",
        )
        if similarity > 1:
            raise LockedSetAcceptanceError("near-duplicate similarity must be between zero and one")
        candidates[candidate_id] = candidate

    decisions = _sequence(decisions_value, "near-duplicate decisions")
    reviewed: dict[str, str] = {}
    for raw_decision in decisions:
        decision = _mapping(raw_decision, "near-duplicate decision")
        if "schema_version" in decision:
            _require_schema_version(
                decision.get("schema_version"),
                "near-duplicate decision",
                expected=1,
            )
        candidate_id = _text(
            decision.get("candidate_id"),
            "near-duplicate decision candidate ID",
        )
        if candidate_id in reviewed or candidate_id not in candidates:
            raise LockedSetAcceptanceError("near-duplicate decisions do not match scan candidates")
        if (
            _sha256(
                decision.get("scan_fingerprint"),
                "near-duplicate decision scan fingerprint",
            )
            != scan_fingerprint
        ):
            raise LockedSetAcceptanceError("near-duplicate decision belongs to a stale scan")
        verdict = _text(
            decision.get("verdict"),
            "near-duplicate decision verdict",
        )
        if verdict not in {"distinct", "duplicate"}:
            raise LockedSetAcceptanceError("near-duplicate decision verdict is invalid")
        _text(decision.get("reviewer_id"), "near-duplicate decision reviewer")
        _text(decision.get("decided_at"), "near-duplicate decision time")
        _text(decision.get("reason"), "near-duplicate decision reason")
        _sha256(
            decision.get("decision_evidence_sha256"),
            "near-duplicate decision evidence SHA-256",
        )
        reviewed[candidate_id] = verdict
    if set(reviewed) != set(candidates):
        raise LockedSetAcceptanceError(
            "near-duplicate candidates require complete bound manual decisions"
        )
    counts = Counter(reviewed.values())
    duplicate_count = counts["duplicate"]
    distinct_count = counts["distinct"]
    return {
        "candidate_count": len(candidates),
        "distinct_count": distinct_count,
        "duplicate_count": duplicate_count,
        "undecided_count": len(candidates) - distinct_count - duplicate_count,
        "passed": duplicate_count == 0,
    }


def _pair_truth_issue(
    slots: tuple[str, str],
    image_truth: dict[str, tuple[str, str]],
) -> str | None:
    loading_role = image_truth[slots[0]][1]
    unloading_role = image_truth[slots[1]][1]
    if loading_role == "unloading" and unloading_role == "loading":
        return "suspected_swapped"
    if loading_role == "loading" and unloading_role == "loading":
        return "both_loading"
    if loading_role == "unloading" and unloading_role == "unloading":
        return "both_unloading"
    if loading_role == "loading" and unloading_role == "unloading":
        return None
    return "unknown_or_non_ticket"


def _derived_adversarial_suite(
    *,
    image_truth: Mapping[str, tuple[str, str]],
    pair_slots: Mapping[str, tuple[str, str]],
) -> dict[str, object]:
    candidates_by_role = {
        role: sorted(
            (sample_id, image_sha256)
            for image_sha256, (sample_id, truth_role) in image_truth.items()
            if truth_role == role
        )
        for role in ("loading", "unloading")
    }

    selected_by_role: dict[str, list[tuple[str, str]]] = {}
    for role, candidates in candidates_by_role.items():
        selected: list[tuple[str, str]] = []
        selected_sample_ids: set[str] = set()
        for sample_id, image_sha256 in candidates:
            if sample_id in selected_sample_ids:
                continue
            selected.append((sample_id, image_sha256))
            selected_sample_ids.add(sample_id)
            if len(selected) == 2:
                break
        selected_by_role[role] = selected
    if any(len(selected_by_role[role]) < 2 for role in ("loading", "unloading")):
        raise LockedSetAcceptanceError(
            "derived adversarial suite requires two human-confirmed images "
            "from different waybills for each known role"
        )

    normal_pairs = sorted(
        (sample_id, slots[0], slots[1])
        for sample_id, slots in pair_slots.items()
        if (
            image_truth[slots[0]][1],
            image_truth[slots[1]][1],
        )
        == ("loading", "unloading")
    )
    if not normal_pairs:
        raise LockedSetAcceptanceError(
            "derived adversarial suite requires a human-confirmed normal pair"
        )
    normal_sample_id, normal_loading, normal_unloading = normal_pairs[0]
    (
        (first_loading_sample, first_loading),
        (
            second_loading_sample,
            second_loading,
        ),
    ) = selected_by_role["loading"]
    (
        (first_unloading_sample, first_unloading),
        (
            second_unloading_sample,
            second_unloading,
        ),
    ) = selected_by_role["unloading"]
    scenarios = [
        {
            "scenario_id": "swapped_slots",
            "source_sample_ids": [normal_sample_id],
            "loading_slot_image_sha256": normal_unloading,
            "unloading_slot_image_sha256": normal_loading,
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "suspected_swapped",
        },
        {
            "scenario_id": "both_loading",
            "source_sample_ids": [
                first_loading_sample,
                second_loading_sample,
            ],
            "loading_slot_image_sha256": first_loading,
            "unloading_slot_image_sha256": second_loading,
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "both_loading",
        },
        {
            "scenario_id": "both_unloading",
            "source_sample_ids": [
                first_unloading_sample,
                second_unloading_sample,
            ],
            "loading_slot_image_sha256": first_unloading,
            "unloading_slot_image_sha256": second_unloading,
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "both_unloading",
        },
        {
            "scenario_id": "exact_duplicate_image",
            "source_sample_ids": [normal_sample_id],
            "loading_slot_image_sha256": normal_loading,
            "unloading_slot_image_sha256": normal_loading,
            "expected_automatic_outcome": "awaiting_review",
            "expected_role_issue": "duplicate_image",
        },
    ]
    source_truth_sha256 = _canonical_sha256(
        {
            "images": [
                {
                    "image_sha256": image_sha256,
                    "sample_id": sample_id,
                    "truth_role": truth_role,
                }
                for image_sha256, (sample_id, truth_role) in sorted(image_truth.items())
            ],
            "pairs": [
                {
                    "loading_slot_image_sha256": slots[0],
                    "sample_id": sample_id,
                    "unloading_slot_image_sha256": slots[1],
                }
                for sample_id, slots in sorted(pair_slots.items())
            ],
        }
    )
    suite: dict[str, object] = {
        "schema_version": 1,
        "generator_version": DERIVED_ADVERSARIAL_GENERATOR_VERSION,
        "source_truth_sha256": source_truth_sha256,
        "scenarios": scenarios,
    }
    suite["suite_sha256"] = _canonical_sha256(suite)
    return suite


def build_locked_set_derived_adversarial_suite(
    truth_manifest: object,
) -> dict[str, object]:
    """Build the order-independent suite declaration from human truth only."""

    _, _, image_truth, pair_slots = _manifest_contract(truth_manifest)
    return _derived_adversarial_suite(
        image_truth=image_truth,
        pair_slots=pair_slots,
    )


def _predicted_role_route(
    *,
    loading_image_sha256: str,
    unloading_image_sha256: str,
    image_results: Mapping[str, dict[str, object]],
) -> tuple[str, str | None, str | None]:
    missing_weight = WeightFieldEvidence(
        reading=None,
        quality=EvidenceQuality.MISSING,
    )
    missing_weights = TicketWeightEvidence(
        ordinary_net=missing_weight,
        factory_net=missing_weight,
        gross=missing_weight,
        tare=missing_weight,
    )

    def ticket(slot: TicketSlot, image_sha256: str) -> TicketEvidence:
        role = TicketRole(cast(str, image_results[image_sha256]["predicted_role"]))
        quality = (
            EvidenceQuality.UNCERTAIN if role is TicketRole.UNKNOWN else EvidenceQuality.RELIABLE
        )
        fingerprint = _canonical_sha256(
            {
                "image_sha256": image_sha256,
                "purpose": "derived_adversarial_role_routing",
                "slot": slot.value,
            }
        )
        return TicketEvidence(
            slot=slot,
            image_sha256=image_sha256,
            machine_role=role,
            role_quality=quality,
            weights=missing_weights,
            extraction_fingerprint=fingerprint,
            role_fingerprint=fingerprint,
        )

    assessment = assess_ticket_roles(
        ticket(TicketSlot.LOADING, loading_image_sha256),
        ticket(TicketSlot.UNLOADING, unloading_image_sha256),
    )
    review_reasons = {
        cast(str, reason)
        for reason in (
            image_results[loading_image_sha256].get(
                "automatic_review_reason"
            ),
            image_results[unloading_image_sha256].get(
                "automatic_review_reason"
            ),
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
    return (
        "normal_ready"
        if assessment.roles_valid and review_reason is None
        else "awaiting_review",
        None if assessment.issue is None else assessment.issue.value,
        review_reason,
    )


def _derived_adversarial_contract(
    *,
    image_truth: Mapping[str, tuple[str, str]],
    pair_slots: Mapping[str, tuple[str, str]],
    image_results: Mapping[str, dict[str, object]],
) -> tuple[
    dict[str, object],
    dict[str, object],
    str,
    dict[str, object],
]:
    suite = _derived_adversarial_suite(
        image_truth=image_truth,
        pair_slots=pair_slots,
    )
    scenarios = cast(list[dict[str, object]], suite["scenarios"])
    computed_results: list[dict[str, object]] = []
    for scenario in scenarios:
        loading_hash = cast(str, scenario["loading_slot_image_sha256"])
        unloading_hash = cast(str, scenario["unloading_slot_image_sha256"])
        outcome, issue, review_reason = _predicted_role_route(
            loading_image_sha256=loading_hash,
            unloading_image_sha256=unloading_hash,
            image_results=image_results,
        )
        computed_results.append(
            {
                "scenario_id": scenario["scenario_id"],
                "loading_slot_image_sha256": loading_hash,
                "unloading_slot_image_sha256": unloading_hash,
                "automatic_outcome": outcome,
                "role_issue": issue,
                "review_reason": review_reason,
            }
        )

    failed_scenarios = [
        cast(str, scenario["scenario_id"])
        for scenario, result in zip(scenarios, computed_results, strict=True)
        if (
            result["automatic_outcome"] != scenario["expected_automatic_outcome"]
            or result["role_issue"] != scenario["expected_role_issue"]
        )
    ]
    results: dict[str, object] = {
        "schema_version": 1,
        "generator_version": DERIVED_ADVERSARIAL_GENERATOR_VERSION,
        "suite_sha256": suite["suite_sha256"],
        "results": computed_results,
    }
    results["results_sha256"] = _canonical_sha256(results)
    fingerprint = _canonical_sha256(
        {
            "generator_version": DERIVED_ADVERSARIAL_GENERATOR_VERSION,
            "results_sha256": results["results_sha256"],
            "suite_sha256": suite["suite_sha256"],
        }
    )
    gate = {
        "scenario_count": len(scenarios),
        "passed_count": len(scenarios) - len(failed_scenarios),
        "failed_scenarios": failed_scenarios,
        "passed": not failed_scenarios,
    }
    return suite, results, fingerprint, gate


def _metrics(
    *,
    image_truth: dict[str, tuple[str, str]],
    image_results: dict[str, dict[str, object]],
    pair_slots: dict[str, tuple[str, str]],
    pair_results: dict[str, dict[str, object]],
) -> dict[str, object]:
    confusion = {truth: {prediction: 0 for prediction in KNOWN_ROLES} for truth in TRUTH_ROLES}
    latencies: list[Decimal] = []
    unknown_count = 0
    high_confidence_errors = 0
    wrong_prediction_hashes: set[str] = set()
    for image_sha256, (_, truth) in image_truth.items():
        result = image_results[image_sha256]
        prediction = cast(str, result["predicted_role"])
        confusion[truth][prediction] += 1
        unknown_count += prediction == "unknown"
        if prediction != truth:
            wrong_prediction_hashes.add(image_sha256)
            if result["high_confidence"] is True:
                high_confidence_errors += 1
        latencies.append(
            _decimal(
                result["incremental_elapsed_ms"],
                "image result incremental latency",
            )
        )
    ordered_latency = sorted(latencies)

    wrong_auto_pass_count = 0
    truth_pair_issue_counts: Counter[str] = Counter()
    normal_pair_count = 0
    normal_pair_false_positive_count = 0
    real_swapped_count = 0
    real_swapped_detected_count = 0
    for sample_id, slots in pair_slots.items():
        result = pair_results[sample_id]
        truth_issue = _pair_truth_issue(slots, image_truth)
        truth_issue_label = truth_issue or "normal_pair"
        truth_pair_issue_counts[truth_issue_label] += 1
        if truth_issue is None:
            normal_pair_count += 1
            if result["automatic_outcome"] != "normal_ready":
                normal_pair_false_positive_count += 1
        elif truth_issue == "suspected_swapped":
            real_swapped_count += 1
            if (
                result["automatic_outcome"] == "awaiting_review"
                and result["role_issue"] == "suspected_swapped"
            ):
                real_swapped_detected_count += 1
        predicted_wrong = bool({slots[0], slots[1]}.intersection(wrong_prediction_hashes))
        if result["automatic_outcome"] == "normal_ready" and (
            truth_issue is not None or predicted_wrong
        ):
            wrong_auto_pass_count += 1

    image_sample_count = len(image_truth)
    pair_sample_count = len(pair_slots)
    truth_role_counts = Counter(truth for _, truth in image_truth.values())
    if normal_pair_count == 0:
        normal_pair_false_positive: dict[str, object] = {
            "status": "not_measured",
            "sample_count": 0,
            "reason": ("The formal locked set contains no naturally occurring normal pair."),
        }
    else:
        normal_pair_false_positive = {
            "status": "measured",
            "sample_count": normal_pair_count,
            "false_positive_count": normal_pair_false_positive_count,
            "rate": _decimal_text(
                Decimal(normal_pair_false_positive_count) / Decimal(normal_pair_count)
            ),
            "wilson_95": _wilson_95_interval(
                normal_pair_false_positive_count,
                normal_pair_count,
            ),
        }
    if real_swapped_count == 0:
        real_swapped_recall: dict[str, object] = {
            "status": "not_measured",
            "sample_count": 0,
            "reason": (
                "The formal locked set contains no naturally occurring suspected-swapped pair."
            ),
        }
    else:
        real_swapped_recall = {
            "status": "measured",
            "sample_count": real_swapped_count,
            "detected_count": real_swapped_detected_count,
            "rate": _decimal_text(
                Decimal(real_swapped_detected_count) / Decimal(real_swapped_count)
            ),
            "wilson_95": _wilson_95_interval(
                real_swapped_detected_count,
                real_swapped_count,
            ),
        }
    return {
        "confusion_matrix": confusion,
        "real_image_sample_count": image_sample_count,
        "real_pair_sample_count": pair_sample_count,
        "truth_role_distribution": {role: truth_role_counts[role] for role in TRUTH_ROLES},
        "truth_pair_issue_distribution": {
            issue: truth_pair_issue_counts[issue]
            for issue in (
                "both_loading",
                "both_unloading",
                "normal_pair",
                "suspected_swapped",
                "unknown_or_non_ticket",
            )
        },
        "unknown_count": unknown_count,
        "unknown_rate": _decimal_text(Decimal(unknown_count) / Decimal(image_sample_count)),
        "unknown_rate_wilson_95": _wilson_95_interval(
            unknown_count,
            image_sample_count,
        ),
        "normal_pair_false_positive": normal_pair_false_positive,
        "real_swapped_recall": real_swapped_recall,
        "layout_distribution": {
            "status": "not_measured",
            "reason": ("The formal truth manifest has no exhaustive per-image layout labels."),
        },
        "quality_distribution": {
            "status": "not_measured",
            "reason": ("The formal truth manifest has no exhaustive per-image quality labels."),
        },
        "p50_incremental_elapsed_ms": _millisecond_text(
            ordered_latency[math.ceil(image_sample_count * 0.50) - 1]
        ),
        "p95_incremental_elapsed_ms": _millisecond_text(
            ordered_latency[math.ceil(image_sample_count * 0.95) - 1]
        ),
        "wrong_auto_pass_count": wrong_auto_pass_count,
        "high_confidence_role_error_count": high_confidence_errors,
    }


def evaluate_locked_set_release(
    *,
    preflight_attestation: object,
    truth_manifest: object,
    image_results: object,
    pair_results: object,
    quality_coverage: object,
    near_duplicate_scan: object,
    near_duplicate_decisions: object,
    eligibility_history: object,
    candidate_review_source_authority: object,
    expected_runtime_kinds: object,
) -> dict[str, object]:
    """Build the formal fail-closed release report from independently sealed inputs."""

    (
        dataset_id,
        manifest_sha256,
        image_truth,
        pair_slots,
    ) = _manifest_contract(truth_manifest)
    attestation_sha256, exclusion_snapshot_sha256 = _validate_preflight(
        preflight_attestation,
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
    )
    _validate_history(
        eligibility_history,
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
    )
    source_authority = (
        validate_candidate_review_source_authority_binding(
            candidate_review_source_authority
        )
    )
    source_authority_sha256 = (
        candidate_review_source_authority_binding_sha256(
            source_authority
        )
    )
    (
        raw_image_results,
        image_result_map,
        image_reconciliation,
        runtime_comparison_evidence_sha256,
    ) = _image_result_contract(
        image_results,
        image_truth=image_truth,
    )
    runtime_execution_gate = _runtime_execution_gate(
        image_results=image_result_map,
        expected_runtime_kinds=expected_runtime_kinds,
    )
    raw_pair_results, pair_result_map, pair_reconciliation = _pair_result_contract(
        pair_results,
        pair_slots=pair_slots,
        image_results=image_result_map,
    )
    quality_gate = _quality_contract(
        quality_coverage,
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
        image_truth=image_truth,
        pair_slots=pair_slots,
    )
    near_duplicate_gate = _near_duplicate_contract(
        near_duplicate_scan,
        near_duplicate_decisions,
        dataset_id=dataset_id,
        manifest_sha256=manifest_sha256,
        exclusion_snapshot_sha256=exclusion_snapshot_sha256,
        image_hashes=set(image_truth),
    )
    metrics = _metrics(
        image_truth=image_truth,
        image_results=image_result_map,
        pair_slots=pair_slots,
        pair_results=pair_result_map,
    )
    (
        derived_adversarial_suite,
        normalized_derived_results,
        derived_adversarial_fingerprint,
        derived_adversarial_gate,
    ) = _derived_adversarial_contract(
        image_truth=image_truth,
        pair_slots=pair_slots,
        image_results=image_result_map,
    )
    zero_error_gates = {
        "wrong_auto_pass_zero": {
            "error_count": metrics["wrong_auto_pass_count"],
            "passed": metrics["wrong_auto_pass_count"] == 0,
        },
        "high_confidence_role_error_zero": {
            "error_count": metrics["high_confidence_role_error_count"],
            "passed": metrics["high_confidence_role_error_count"] == 0,
        },
    }
    reconciliation = {
        "expected_image_count": 100,
        "result_image_count": len(raw_image_results),
        "expected_pair_count": 50,
        "result_pair_count": len(raw_pair_results),
        **image_reconciliation,
        **pair_reconciliation,
    }
    observed_zero_error_gates_passed = all(
        cast(bool, gate["passed"]) for gate in zero_error_gates.values()
    )
    observed_locked_set_gate = {
        "zero_error_gates_passed": observed_zero_error_gates_passed,
        "quality_coverage_passed": cast(bool, quality_gate["passed"]),
        "near_duplicate_passed": cast(bool, near_duplicate_gate["passed"]),
        "passed": (
            observed_zero_error_gates_passed
            and cast(bool, quality_gate["passed"])
            and cast(bool, near_duplicate_gate["passed"])
        ),
    }
    gate_passed = (
        observed_locked_set_gate["passed"]
        and cast(bool, derived_adversarial_gate["passed"])
        and cast(bool, runtime_execution_gate["passed"])
    )
    report: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": dataset_id,
        "manifest_sha256": manifest_sha256,
        "candidate_review_source_authority": source_authority,
        "candidate_review_source_authority_sha256": (
            source_authority_sha256
        ),
        "preflight_attestation_sha256": attestation_sha256,
        "exclusion_snapshot_sha256": exclusion_snapshot_sha256,
        "reconciliation": reconciliation,
        "metrics": metrics,
        "zero_error_gates": zero_error_gates,
        "quality_coverage_gate": quality_gate,
        "quality_coverage_sha256": quality_gate["quality_coverage_sha256"],
        "runtime_comparison_evidence_sha256": (runtime_comparison_evidence_sha256),
        "runtime_execution_gate": runtime_execution_gate,
        "near_duplicate_gate": near_duplicate_gate,
        "observed_locked_set_gate": observed_locked_set_gate,
        "derived_adversarial_suite": derived_adversarial_suite,
        "derived_adversarial_results": normalized_derived_results,
        "derived_adversarial_fingerprint": derived_adversarial_fingerprint,
        "derived_adversarial_gate": derived_adversarial_gate,
        "claim_scope": {
            "real_locked_set_image_count": 100,
            "real_locked_set_pair_count": 50,
            "derived_adversarial_scenario_count": 4,
            "derived_adversarial_in_reconciliation": False,
            "derived_adversarial_in_confusion_matrix": False,
            "derived_adversarial_in_accuracy_metrics": False,
            "derived_adversarial_in_latency_metrics": False,
            "derived_adversarial_role_routing_only": True,
        },
        "formal_accuracy_claim_scope": "none_uncommitted",
        "eligible_accuracy_scope": "observed_real_locked_set_only",
        "derived_scenario_accuracy_claim": False,
        "derived_prevalence_claim": False,
        "gate_passed": gate_passed,
        "formal_report": False,
        # This pure contract has no authority over SQLite state or evaluator
        # composition. Only the supported persistence boundary may promote a
        # passing report to a formal accuracy claim.
        "formal_accuracy_claim": False,
        "claim_status": "uncommitted",
    }
    report["report_sha256"] = _canonical_sha256(report)
    return report


def record_locked_set_result_use(
    *,
    eligibility_history: object,
    use_event: object,
) -> dict[str, object]:
    """Append how a locked result was used; executable influence is irreversible."""

    history = copy.deepcopy(_mapping(eligibility_history, "eligibility history"))
    dataset_id = _text(history.get("dataset_id"), "eligibility history dataset_id")
    manifest_sha256 = _sha256(
        history.get("manifest_sha256"),
        "eligibility history manifest_sha256",
    )
    try:
        _validate_history(
            history,
            dataset_id=dataset_id,
            manifest_sha256=manifest_sha256,
        )
    except LockedSetAcceptanceError as exc:
        if "permanently invalidated" in str(exc):
            raise
        raise LockedSetAcceptanceError("eligibility history is invalid") from exc

    event = _mapping(use_event, "locked result use event")
    event_id = _text(event.get("event_id"), "locked result use event ID")
    events = _sequence(history.get("events"), "eligibility history events")
    if any(
        _mapping(existing, "eligibility event").get("event_id") == event_id for existing in events
    ):
        raise LockedSetAcceptanceError("locked result use event ID already exists")
    influenced = event.get("influenced_executable_system")
    if not isinstance(influenced, bool):
        raise LockedSetAcceptanceError("locked result executable-influence flag is invalid")
    appended = {
        "event_id": event_id,
        "event_type": ("executable_influence" if influenced else "acceptance_report_recorded"),
        "result_fingerprint": _sha256(
            event.get("result_fingerprint"),
            "locked result fingerprint",
        ),
        "influenced_executable_system": influenced,
        "artifact_kind": _text(
            event.get("artifact_kind"),
            "locked result artifact kind",
        ),
        "artifact_sha256": _sha256(
            event.get("artifact_sha256"),
            "locked result artifact SHA-256",
        ),
        "actor_id": _text(event.get("actor_id"), "locked result actor"),
        "recorded_at": _text(event.get("recorded_at"), "locked result event time"),
        "reason": _text(event.get("reason"), "locked result use reason"),
    }
    appended["event_sha256"] = _canonical_sha256(appended)
    events.append(appended)
    history["status"] = "permanently_invalidated" if influenced else "eligible"
    history["history_sha256"] = _canonical_sha256(
        {key: value for key, value in history.items() if key != "history_sha256"}
    )
    return history
