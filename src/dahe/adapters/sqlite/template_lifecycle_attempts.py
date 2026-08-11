from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import cast

from dahe.adapters.sqlite.candidate_development_ocr import (
    CandidateDevelopmentOcrRunAuthorityRecord,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATUSES = frozenset(
    {"succeeded", "business_failed", "technical_failed"}
)


class TemplateLifecycleAttemptError(RuntimeError):
    """Raised when a lifecycle terminal attempt is not trustworthy."""


@dataclass(frozen=True, slots=True)
class CompositeLifecycleAttemptScope:
    ocr_evidence_sha256: str
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    reviewer_id: str
    ocr_capture_build_sha256: str
    role_evaluator_build_sha256: str
    composition_evidence_sha256: str
    runtime_set_sha256: str
    pipeline_contract_sha256: str
    dataset_manifest_sha256: str
    candidate_set_sha256: str
    matcher_fingerprint: str
    policy_fingerprint: str
    template_set_fingerprint: str
    composite_policy_sha256: str
    scope_sha256: str

    def with_recomputed_identity(self) -> CompositeLifecycleAttemptScope:
        without_identity = replace(self, scope_sha256="0" * 64)
        return replace(
            without_identity,
            scope_sha256=_canonical_sha256(
                _scope_payload(without_identity)
            ),
        )


@dataclass(frozen=True, slots=True)
class CompositeLifecycleAttemptRecord:
    attempt_sequence: int
    attempt_id: str
    scope_sha256: str
    terminal_status: str
    evaluation_id: str | None
    failure_code: str | None
    ocr_evidence_sha256: str
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    reviewer_id: str
    ocr_capture_build_sha256: str
    role_evaluator_build_sha256: str
    composition_evidence_sha256: str
    runtime_set_sha256: str
    pipeline_contract_sha256: str
    dataset_manifest_sha256: str
    candidate_set_sha256: str
    matcher_fingerprint: str
    policy_fingerprint: str
    template_set_fingerprint: str
    composite_policy_sha256: str
    attempt_payload_json: str
    attempt_sha256: str
    actor_id: str
    created_at: str


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise TemplateLifecycleAttemptError(
            "template lifecycle attempt is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        _canonical_json(value).encode("utf-8")
    ).hexdigest()


def _required_text(value: object, *, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > maximum
    ):
        raise TemplateLifecycleAttemptError(f"{label} is invalid")
    return value


def _sha256(value: object, *, label: str) -> str:
    text = _required_text(value, label=label, maximum=64)
    if _SHA256_PATTERN.fullmatch(text) is None:
        raise TemplateLifecycleAttemptError(
            f"{label} must be a lowercase SHA-256"
        )
    return text


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TemplateLifecycleAttemptError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _scope_payload(
    scope: CompositeLifecycleAttemptScope,
) -> dict[str, object]:
    return {
        field: getattr(scope, field)
        for field in CompositeLifecycleAttemptScope.__dataclass_fields__
        if field not in {"ocr_evidence_sha256", "scope_sha256"}
    } | {
        "kind": "template_lifecycle_attempt_scope",
        "schema_version": 1,
    }


def validate_composite_lifecycle_attempt_scope(
    scope: CompositeLifecycleAttemptScope,
) -> CompositeLifecycleAttemptScope:
    if not isinstance(scope, CompositeLifecycleAttemptScope):
        raise TemplateLifecycleAttemptError(
            "template lifecycle attempt scope is invalid"
        )
    for field in CompositeLifecycleAttemptScope.__dataclass_fields__:
        if field == "reviewer_id":
            _required_text(
                getattr(scope, field),
                label="reviewer ID",
                maximum=200,
            )
        else:
            _sha256(getattr(scope, field), label=field)
    expected = _canonical_sha256(_scope_payload(scope))
    if scope.scope_sha256 != expected:
        raise TemplateLifecycleAttemptError(
            "template lifecycle attempt scope identity does not reconcile"
        )
    return scope


def make_composite_lifecycle_attempt_scope(
    *,
    ocr_evidence_sha256: str,
    package_sha256: str,
    review_history_authority_sha256: str,
    source_authority_sha256: str,
    reviewer_id: str,
    ocr_capture_build_sha256: str,
    role_evaluator_build_sha256: str,
    composition_evidence_sha256: str,
    runtime_set_sha256: str,
    pipeline_contract_sha256: str,
    dataset_manifest_sha256: str,
    candidate_set_sha256: str,
    matcher_fingerprint: str,
    policy_fingerprint: str,
    template_set_fingerprint: str,
    composite_policy_sha256: str,
) -> CompositeLifecycleAttemptScope:
    provisional = CompositeLifecycleAttemptScope(
        ocr_evidence_sha256=_sha256(
            ocr_evidence_sha256,
            label="OCR evidence SHA-256",
        ),
        package_sha256=_sha256(
            package_sha256,
            label="package SHA-256",
        ),
        review_history_authority_sha256=_sha256(
            review_history_authority_sha256,
            label="review-history authority SHA-256",
        ),
        source_authority_sha256=_sha256(
            source_authority_sha256,
            label="source authority SHA-256",
        ),
        reviewer_id=_required_text(
            reviewer_id,
            label="reviewer ID",
            maximum=200,
        ),
        ocr_capture_build_sha256=_sha256(
            ocr_capture_build_sha256,
            label="OCR capture build SHA-256",
        ),
        role_evaluator_build_sha256=_sha256(
            role_evaluator_build_sha256,
            label="role evaluator build SHA-256",
        ),
        composition_evidence_sha256=_sha256(
            composition_evidence_sha256,
            label="composition evidence SHA-256",
        ),
        runtime_set_sha256=_sha256(
            runtime_set_sha256,
            label="runtime-set SHA-256",
        ),
        pipeline_contract_sha256=_sha256(
            pipeline_contract_sha256,
            label="pipeline contract SHA-256",
        ),
        dataset_manifest_sha256=_sha256(
            dataset_manifest_sha256,
            label="dataset manifest SHA-256",
        ),
        candidate_set_sha256=_sha256(
            candidate_set_sha256,
            label="candidate-set SHA-256",
        ),
        matcher_fingerprint=_sha256(
            matcher_fingerprint,
            label="matcher fingerprint",
        ),
        policy_fingerprint=_sha256(
            policy_fingerprint,
            label="policy fingerprint",
        ),
        template_set_fingerprint=_sha256(
            template_set_fingerprint,
            label="template-set fingerprint",
        ),
        composite_policy_sha256=_sha256(
            composite_policy_sha256,
            label="composite policy SHA-256",
        ),
        scope_sha256="0" * 64,
    )
    return validate_composite_lifecycle_attempt_scope(
        provisional.with_recomputed_identity()
    )


def build_composite_lifecycle_attempt_scope(
    *,
    metrics: dict[str, object],
    dataset_manifest_sha256: str,
    template_set_fingerprint: str,
    matcher_fingerprint: str,
    policy_fingerprint: str,
    role_evaluator_build_sha256: str,
    runtime_set_sha256: str,
    ocr_authority: CandidateDevelopmentOcrRunAuthorityRecord,
) -> CompositeLifecycleAttemptScope:
    parent = _mapping(
        metrics.get("composite_lifecycle"),
        label="composite lifecycle parent",
    )
    bindings = _mapping(
        parent.get("bindings"),
        label="composite lifecycle bindings",
    )
    components = _mapping(
        metrics.get("composite_lifecycle_components"),
        label="composite lifecycle components",
    )
    real = _mapping(
        components.get("real_candidate_roles"),
        label="real candidate component",
    )
    source = _mapping(
        real.get("source"),
        label="real candidate source",
    )
    candidate_set_sha256 = _sha256(
        bindings.get("candidate_set_sha256"),
        label="candidate-set SHA-256",
    )
    composite_policy_sha256 = _sha256(
        bindings.get("composite_gate_policy_sha256"),
        label="composite policy SHA-256",
    )
    expected_bindings = {
        "ocr_evidence_sha256": ocr_authority.evidence_sha256,
        "package_sha256": ocr_authority.package_sha256,
        "review_history_authority_sha256": (
            ocr_authority.review_history_authority_sha256
        ),
        "reviewer_id_sha256": _canonical_sha256(
            ocr_authority.reviewer_id
        ),
        "source_authority_sha256": ocr_authority.source_authority_sha256,
        "ocr_capture_build_sha256": (
            ocr_authority.application_build_sha256
        ),
        "composition_evidence_sha256": (
            ocr_authority.composition_evidence_sha256
        ),
        "runtime_set_sha256": ocr_authority.runtime_set_sha256,
        "ocr_pipeline_contract_sha256": (
            ocr_authority.pipeline_contract_sha256
        ),
    }
    mismatches = [
        field
        for field, expected in expected_bindings.items()
        if source.get(field) != expected
    ]
    if (
        bindings.get("role_evaluator_build_sha256")
        != role_evaluator_build_sha256
        or bindings.get("runtime_set_sha256") != runtime_set_sha256
        or bindings.get("matcher_fingerprint") != matcher_fingerprint
        or bindings.get("policy_fingerprint") != policy_fingerprint
        or bindings.get("template_set_fingerprint")
        != template_set_fingerprint
        or ocr_authority.runtime_set_sha256 != runtime_set_sha256
        or parent.get("dataset_manifest_sha256")
        != dataset_manifest_sha256
    ):
        mismatches.append("repository_contract")
    if mismatches:
        raise TemplateLifecycleAttemptError(
            "template lifecycle attempt scope bindings changed: "
            + ", ".join(sorted(set(mismatches)))
        )
    return make_composite_lifecycle_attempt_scope(
        ocr_evidence_sha256=ocr_authority.evidence_sha256,
        package_sha256=ocr_authority.package_sha256,
        review_history_authority_sha256=(
            ocr_authority.review_history_authority_sha256
        ),
        source_authority_sha256=ocr_authority.source_authority_sha256,
        reviewer_id=ocr_authority.reviewer_id,
        ocr_capture_build_sha256=(
            ocr_authority.application_build_sha256
        ),
        role_evaluator_build_sha256=role_evaluator_build_sha256,
        composition_evidence_sha256=(
            ocr_authority.composition_evidence_sha256
        ),
        runtime_set_sha256=runtime_set_sha256,
        pipeline_contract_sha256=(
            ocr_authority.pipeline_contract_sha256
        ),
        dataset_manifest_sha256=_sha256(
            bindings.get("frozen_synthetic_dataset_sha256"),
            label="frozen synthetic dataset SHA-256",
        ),
        candidate_set_sha256=candidate_set_sha256,
        matcher_fingerprint=matcher_fingerprint,
        policy_fingerprint=policy_fingerprint,
        template_set_fingerprint=template_set_fingerprint,
        composite_policy_sha256=composite_policy_sha256,
    )


def lifecycle_attempt_payload(
    *,
    scope: CompositeLifecycleAttemptScope,
    terminal_status: str,
    evaluation_id: str | None,
    failure_code: str | None,
) -> dict[str, object]:
    validated = validate_composite_lifecycle_attempt_scope(scope)
    if terminal_status not in _TERMINAL_STATUSES:
        raise TemplateLifecycleAttemptError(
            "template lifecycle terminal status is invalid"
        )
    if terminal_status == "succeeded":
        _required_text(
            evaluation_id,
            label="evaluation ID",
            maximum=100,
        )
        if failure_code is not None:
            raise TemplateLifecycleAttemptError(
                "successful lifecycle attempt cannot have a failure code"
            )
    else:
        if evaluation_id is not None:
            raise TemplateLifecycleAttemptError(
                "failed lifecycle attempt cannot bind an evaluation"
            )
        _required_text(
            failure_code,
            label="failure code",
            maximum=100,
        )
    return {
        "evaluation_id": evaluation_id,
        "failure_code": failure_code,
        "kind": "template_lifecycle_terminal_attempt",
        "ocr_evidence_sha256": validated.ocr_evidence_sha256,
        "schema_version": 1,
        "scope": _scope_payload(validated),
        "scope_sha256": validated.scope_sha256,
        "terminal_status": terminal_status,
    }


def lifecycle_attempt_record_from_mapping(
    value: dict[str, object],
) -> CompositeLifecycleAttemptRecord:
    scope_fields = {
        field: value[field]
        for field in CompositeLifecycleAttemptScope.__dataclass_fields__
    }
    scope = validate_composite_lifecycle_attempt_scope(
        CompositeLifecycleAttemptScope(
            **cast(dict[str, str], scope_fields)
        )
    )
    terminal_status = _required_text(
        value["terminal_status"],
        label="terminal status",
        maximum=30,
    )
    evaluation_id = (
        None
        if value["evaluation_id"] is None
        else str(value["evaluation_id"])
    )
    failure_code = (
        None if value["failure_code"] is None else str(value["failure_code"])
    )
    payload = lifecycle_attempt_payload(
        scope=scope,
        terminal_status=terminal_status,
        evaluation_id=evaluation_id,
        failure_code=failure_code,
    )
    record = CompositeLifecycleAttemptRecord(
        attempt_sequence=cast(int, value["attempt_sequence"]),
        attempt_id=str(value["attempt_id"]),
        terminal_status=terminal_status,
        evaluation_id=evaluation_id,
        failure_code=failure_code,
        **asdict(scope),
        attempt_payload_json=str(value["attempt_payload_json"]),
        attempt_sha256=str(value["attempt_sha256"]),
        actor_id=str(value["actor_id"]),
        created_at=str(value["created_at"]),
    )
    if (
        isinstance(record.attempt_sequence, bool)
        or record.attempt_sequence <= 0
        or len(record.attempt_id) != 32
        or record.attempt_payload_json != _canonical_json(payload)
        or record.attempt_sha256 != _canonical_sha256(payload)
    ):
        raise TemplateLifecycleAttemptError(
            "template lifecycle terminal attempt does not reconcile"
        )
    _required_text(record.actor_id, label="actor ID", maximum=200)
    created_at = _required_text(
        record.created_at,
        label="attempt creation time",
        maximum=40,
    )
    try:
        parsed = datetime.fromisoformat(created_at)
    except ValueError as exc:
        raise TemplateLifecycleAttemptError(
            "attempt creation time is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise TemplateLifecycleAttemptError(
            "attempt creation time must include a timezone"
        )
    return record


def lifecycle_attempt_row(
    *,
    scope: CompositeLifecycleAttemptScope,
    terminal_status: str,
    evaluation_id: str | None,
    failure_code: str | None,
    attempt_id: str,
    actor_id: str,
    created_at: str,
) -> dict[str, object]:
    payload = lifecycle_attempt_payload(
        scope=scope,
        terminal_status=terminal_status,
        evaluation_id=evaluation_id,
        failure_code=failure_code,
    )
    return {
        **asdict(scope),
        "actor_id": _required_text(
            actor_id,
            label="actor ID",
            maximum=200,
        ),
        "attempt_id": _required_text(
            attempt_id,
            label="attempt ID",
            maximum=32,
        ),
        "attempt_payload_json": _canonical_json(payload),
        "attempt_sha256": _canonical_sha256(payload),
        "created_at": created_at,
        "evaluation_id": evaluation_id,
        "failure_code": failure_code,
        "terminal_status": terminal_status,
    }
