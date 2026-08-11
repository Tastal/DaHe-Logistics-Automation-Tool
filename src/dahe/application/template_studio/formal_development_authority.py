from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe import __version__
from dahe.adapters.sqlite.locked_set import (
    LockedSetPersistenceError,
    PersistedExclusionSnapshot,
    PersistedPerceptualFingerprint,
    SqliteLockedSetRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_lifecycle_attempts import (
    CompositeLifecycleAttemptScope,
    TemplateLifecycleAttemptError,
    lifecycle_attempt_record_from_mapping,
    make_composite_lifecycle_attempt_scope,
)
from dahe.adapters.sqlite.template_studio import (
    ShadowTemplatePublicationAuthority,
    SqliteTemplateRepository,
    TemplateEligibilityContract,
    deserialize_template_definition,
    serialize_template_definition,
)
from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_fingerprint,
)
from dahe.application.template_studio.matcher import (
    build_template_set_fingerprint,
)
from dahe.domain.ticket.templates import (
    TemplateLifecycle,
    TemplateVersion,
    canonical_template_hash,
)
from dahe.verification.locked_set import LockedSetExclusionSnapshot

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CATEGORY_FIELDS = (
    "template_reference_image_hashes",
    "development_image_hashes",
    "calibration_image_hashes",
    "shadow_image_hashes",
    "prior_locked_image_hashes",
    "prior_waybill_identity_hashes",
)


class FormalDevelopmentAuthorityError(ValueError):
    """Raised when a formal bootstrap authority is incomplete or changed."""


@dataclass(frozen=True, slots=True)
class FormalDevelopmentAuthority:
    authority_sha256: str
    payload: dict[str, object]
    exclusion_snapshot: LockedSetExclusionSnapshot
    inventory_high_watermark: int
    perceptual_fingerprints: tuple[PersistedPerceptualFingerprint, ...]
    shadow_templates: tuple[TemplateVersion, ...]
    eligibility_contract: TemplateEligibilityContract

    @property
    def image_sha256s(self) -> frozenset[str]:
        snapshot = self.exclusion_snapshot
        return frozenset(
            snapshot.template_reference_image_hashes
            | snapshot.development_image_hashes
            | snapshot.calibration_image_hashes
            | snapshot.shadow_image_hashes
            | snapshot.prior_locked_image_hashes
        )

    @property
    def waybill_identity_sha256s(self) -> frozenset[str]:
        return self.exclusion_snapshot.prior_waybill_identity_hashes


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
        raise FormalDevelopmentAuthorityError(
            "development authority is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise FormalDevelopmentAuthorityError(f"{label} must be a lowercase SHA-256")
    return value


def _positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise FormalDevelopmentAuthorityError(f"{label} must be a positive integer")
    return value


def _hash_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise FormalDevelopmentAuthorityError(f"{label} must be an array")
    values = tuple(_sha256(item, label=label) for item in value)
    if values != tuple(sorted(set(values))):
        raise FormalDevelopmentAuthorityError(f"{label} must be sorted and unique")
    return values


def _evaluation_payload(
    authority: ShadowTemplatePublicationAuthority,
) -> dict[str, object]:
    evaluation = authority.publication_evaluation
    return {
        "evaluation_id": evaluation.evaluation_id,
        "dataset_kind": evaluation.dataset_kind,
        "dataset_id": evaluation.dataset_id,
        "dataset_manifest_sha256": evaluation.dataset_manifest_sha256,
        "template_set_fingerprint": evaluation.template_set_fingerprint,
        "matcher_fingerprint": evaluation.matcher_fingerprint,
        "policy_fingerprint": evaluation.policy_fingerprint,
        "build_fingerprint": evaluation.build_fingerprint,
        "runtime_fingerprint": evaluation.runtime_fingerprint,
        "verification_source": evaluation.verification_source,
        "stable_outcome_sha256": evaluation.stable_outcome_sha256,
        "expected_count": evaluation.expected_count,
        "result_count": evaluation.result_count,
        "metrics": dict(evaluation.metrics),
        "metrics_sha256": evaluation.metrics_sha256,
        "gate_passed": evaluation.gate_passed,
        "actor_id": evaluation.actor_id,
        "completed_at": evaluation.completed_at,
    }


def _publication_payload(
    authority: ShadowTemplatePublicationAuthority,
) -> dict[str, object]:
    version = authority.version
    return {
        "family_id": version.definition.family_id,
        "version_id": version.version_id,
        "version_number": version.version_number,
        "parent_version_id": version.parent_version_id,
        "record_version": version.record_version,
        "pointer_record_version": authority.pointer_record_version,
        "publication_event_id": authority.publication_event_id,
        "publication_event_record_version": (
            authority.publication_event_record_version
        ),
        "lifecycle": version.lifecycle.value,
        "content_sha256": version.content_sha256,
        "definition": serialize_template_definition(version.definition),
        "publication_evaluation": _evaluation_payload(authority),
        "lifecycle_attempt": asdict(authority.lifecycle_attempt),
    }


def _attempt_matches_scope(
    attempt: object,
    scope: CompositeLifecycleAttemptScope,
) -> bool:
    return all(
        getattr(attempt, field) == getattr(scope, field)
        for field in CompositeLifecycleAttemptScope.__dataclass_fields__
    )


def _scope_matches_publication_contract(
    scope: CompositeLifecycleAttemptScope,
    *,
    eligibility_contract: TemplateEligibilityContract,
    template_set_fingerprint: object,
) -> bool:
    return (
        scope.role_evaluator_build_sha256
        == eligibility_contract.build_fingerprint
        and scope.runtime_set_sha256
        == eligibility_contract.runtime_fingerprint
        and scope.matcher_fingerprint
        == eligibility_contract.matcher_fingerprint
        and scope.policy_fingerprint
        == eligibility_contract.policy_fingerprint
        and scope.template_set_fingerprint
        == template_set_fingerprint
    )


def build_formal_development_authority(
    *,
    exclusion_snapshot: PersistedExclusionSnapshot,
    eligibility_contract: TemplateEligibilityContract,
    shadow_publications: Sequence[ShadowTemplatePublicationAuthority],
) -> FormalDevelopmentAuthority:
    if not shadow_publications:
        raise FormalDevelopmentAuthorityError(
            "development authority requires a shadow template set"
        )
    snapshot = exclusion_snapshot.snapshot
    image_hashes = frozenset(
        snapshot.template_reference_image_hashes
        | snapshot.development_image_hashes
        | snapshot.calibration_image_hashes
        | snapshot.shadow_image_hashes
        | snapshot.prior_locked_image_hashes
    )
    if not image_hashes or not snapshot.prior_waybill_identity_hashes:
        raise FormalDevelopmentAuthorityError("development authority exclusions must be non-empty")
    fingerprints = tuple(
        sorted(
            exclusion_snapshot.perceptual_fingerprints,
            key=lambda item: item.content_sha256,
        )
    )
    if (
        exclusion_snapshot.missing_fingerprint_count != 0
        or exclusion_snapshot.inventory_image_count != len(image_hashes)
        or exclusion_snapshot.fingerprinted_image_count != len(image_hashes)
        or {item.content_sha256 for item in fingerprints} != image_hashes
    ):
        raise FormalDevelopmentAuthorityError(
            "development authority requires complete perceptual fingerprints"
        )
    templates = tuple(
        item.version
        for item in sorted(
            shadow_publications,
            key=lambda item: item.version.definition.family_id,
        )
    )
    if len({item.definition.family_id for item in templates}) != len(templates):
        raise FormalDevelopmentAuthorityError(
            "development authority shadow families must be unique"
        )
    contract_payload = {
        "dataset_manifest_sha256": (eligibility_contract.dataset_manifest_sha256),
        "matcher_fingerprint": eligibility_contract.matcher_fingerprint,
        "policy_fingerprint": eligibility_contract.policy_fingerprint,
        "build_fingerprint": eligibility_contract.build_fingerprint,
        "runtime_fingerprint": eligibility_contract.runtime_fingerprint,
    }
    publications = [
        _publication_payload(item)
        for item in sorted(
            shadow_publications,
            key=lambda item: item.version.definition.family_id,
        )
    ]
    for publication in publications:
        evaluation = cast(
            dict[str, object],
            publication["publication_evaluation"],
        )
        if (
            publication["lifecycle"] != TemplateLifecycle.SHADOW.value
            or evaluation["gate_passed"] is not True
            or evaluation["verification_source"] != "frozen_runner"
            or evaluation["expected_count"] != evaluation["result_count"]
            or evaluation["stable_outcome_sha256"] is None
            or any(evaluation[field] != expected for field, expected in contract_payload.items())
            or _canonical_sha256(evaluation["metrics"]) != evaluation["metrics_sha256"]
        ):
            raise FormalDevelopmentAuthorityError(
                "shadow publication evidence is not authoritative"
            )
        metrics = evaluation.get("metrics")
        lifecycle_attempt = publication.get("lifecycle_attempt")
        if not isinstance(metrics, Mapping) or not isinstance(
            lifecycle_attempt,
            Mapping,
        ) or not isinstance(lifecycle_attempt.get("reviewer_id"), str):
            raise FormalDevelopmentAuthorityError(
                "shadow publication evidence is not authoritative"
            )
        expected_scope = (
            _composite_lifecycle_scope_from_metrics(
                metrics,
                composite_manifest_sha256=(
                    eligibility_contract.dataset_manifest_sha256
                ),
                reviewer_id=cast(
                    str,
                    lifecycle_attempt["reviewer_id"],
                ),
            )
        )
        try:
            attempt_record = lifecycle_attempt_record_from_mapping(
                dict(lifecycle_attempt)
            )
        except (
            KeyError,
            TemplateLifecycleAttemptError,
            TypeError,
            ValueError,
        ) as exc:
            raise FormalDevelopmentAuthorityError(
                "shadow publication lifecycle attempt changed"
            ) from exc
        if (
            attempt_record.terminal_status != "succeeded"
            or attempt_record.evaluation_id
            != evaluation.get("evaluation_id")
            or not _attempt_matches_scope(
                attempt_record,
                expected_scope,
            )
            or not _scope_matches_publication_contract(
                expected_scope,
                eligibility_contract=eligibility_contract,
                template_set_fingerprint=evaluation.get(
                    "template_set_fingerprint"
                ),
            )
        ):
            raise FormalDevelopmentAuthorityError(
                "shadow publication lifecycle attempt changed"
            )
    categories = {
        field: sorted(cast(frozenset[str], getattr(snapshot, field))) for field in _CATEGORY_FIELDS
    }
    fingerprint_payloads = [
        {
            "algorithm_version": item.algorithm_version,
            "content_sha256": item.content_sha256,
            "fingerprint_sha256": item.fingerprint_sha256,
            "perceptual_fingerprint_json": (item.perceptual_fingerprint_json),
        }
        for item in fingerprints
    ]
    without_hash: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop7_formal_development_authority",
        "source_exclusion_snapshot_sha256": snapshot.canonical_sha256,
        "source_exclusion_snapshot_id": exclusion_snapshot.snapshot_id,
        "source_exclusion_snapshot_source_id": snapshot.source_id,
        "source_inventory_high_watermark": (exclusion_snapshot.inventory_high_watermark),
        "exclusion_categories": categories,
        "image_identity_count": len(image_hashes),
        "waybill_identity_count": len(snapshot.prior_waybill_identity_hashes),
        "fingerprint_algorithm_versions": list(exclusion_snapshot.fingerprint_algorithm_versions),
        "perceptual_fingerprints": fingerprint_payloads,
        "eligibility_contract": contract_payload,
        "shadow_template_set_fingerprint": (build_template_set_fingerprint(templates)),
        "shadow_publications": publications,
    }
    payload = {
        **without_hash,
        "authority_sha256": _canonical_sha256(without_hash),
    }
    return parse_formal_development_authority(payload)


def _composite_lifecycle_scope_from_metrics(
    metrics: Mapping[str, object],
    *,
    composite_manifest_sha256: str,
    reviewer_id: str,
) -> CompositeLifecycleAttemptScope:
    """Re-derive both composite and terminal-attempt identities."""

    composite = metrics.get("composite_lifecycle")
    component_evidence = metrics.get("composite_lifecycle_components")
    if (
        metrics.get("lifecycle_authorization_schema_version") != 2
        or not isinstance(composite, Mapping)
        or not isinstance(component_evidence, Mapping)
        or composite.get("kind") != "composite_template_lifecycle_evaluation"
        or composite.get("schema_version") != 1
        or composite.get("authorization_scope") != "ticket_role_evidence"
        or composite.get("authorizing_lifecycle_evidence") is not True
        or composite.get("dataset_manifest_sha256")
        != composite_manifest_sha256
    ):
        raise FormalDevelopmentAuthorityError(
            "shadow publication is not bound to the approved development dataset"
        )
    bindings = composite.get("bindings")
    components = composite.get("components")
    if not isinstance(bindings, Mapping) or not isinstance(
        components,
        Mapping,
    ):
        raise FormalDevelopmentAuthorityError(
            "shadow publication is not bound to the approved development dataset"
        )
    frozen_component = components.get("frozen_synthetic")
    persisted_frozen_component = component_evidence.get(
        "frozen_synthetic"
    )
    persisted_real_component = component_evidence.get(
        "real_candidate_roles"
    )
    if (
        not isinstance(frozen_component, Mapping)
        or not isinstance(persisted_frozen_component, Mapping)
        or not isinstance(persisted_real_component, Mapping)
    ):
        raise FormalDevelopmentAuthorityError(
            "shadow publication is not bound to the approved development dataset"
        )
    approved_manifest_sha256 = _sha256(
        bindings.get("frozen_synthetic_dataset_sha256"),
        label="approved development manifest SHA-256",
    )
    if (
        frozen_component.get("dataset_manifest_sha256")
        != approved_manifest_sha256
        or persisted_frozen_component.get("dataset_manifest_sha256")
        != approved_manifest_sha256
    ):
        raise FormalDevelopmentAuthorityError(
            "shadow publication is not bound to the approved development dataset"
        )
    persisted_real_source = persisted_real_component.get("source")
    if not isinstance(persisted_real_source, Mapping):
        raise FormalDevelopmentAuthorityError(
            "shadow publication is not bound to the approved development dataset"
        )
    if persisted_real_source.get(
        "reviewer_id_sha256"
    ) != _canonical_sha256(reviewer_id):
        raise FormalDevelopmentAuthorityError(
            "shadow publication reviewer authority changed"
        )
    expected_composite_manifest = _canonical_sha256(
        {
            "authorization_scope": "ticket_role_evidence",
            "candidate_set_sha256": _sha256(
                bindings.get("candidate_set_sha256"),
                label="candidate-set SHA-256",
            ),
            "frozen_synthetic_dataset_sha256": (
                approved_manifest_sha256
            ),
            "ocr_evidence_sha256": _sha256(
                persisted_real_source.get("ocr_evidence_sha256"),
                label="OCR evidence SHA-256",
            ),
            "real_source_authority_sha256": _sha256(
                persisted_real_source.get("source_authority_sha256"),
                label="source authority SHA-256",
            ),
            "schema_version": 1,
        }
    )
    if composite_manifest_sha256 != expected_composite_manifest:
        raise FormalDevelopmentAuthorityError(
            "shadow publication composite dataset identity is invalid"
        )
    try:
        return make_composite_lifecycle_attempt_scope(
            ocr_evidence_sha256=_sha256(
                persisted_real_source.get("ocr_evidence_sha256"),
                label="OCR evidence SHA-256",
            ),
            package_sha256=_sha256(
                persisted_real_source.get("package_sha256"),
                label="review package SHA-256",
            ),
            review_history_authority_sha256=_sha256(
                persisted_real_source.get(
                    "review_history_authority_sha256"
                ),
                label="review history authority SHA-256",
            ),
            source_authority_sha256=_sha256(
                persisted_real_source.get("source_authority_sha256"),
                label="source authority SHA-256",
            ),
            reviewer_id=reviewer_id,
            ocr_capture_build_sha256=_sha256(
                persisted_real_source.get("ocr_capture_build_sha256"),
                label="OCR capture build SHA-256",
            ),
            role_evaluator_build_sha256=_sha256(
                bindings.get("role_evaluator_build_sha256"),
                label="role evaluator build SHA-256",
            ),
            composition_evidence_sha256=_sha256(
                persisted_real_source.get(
                    "composition_evidence_sha256"
                ),
                label="composition evidence SHA-256",
            ),
            runtime_set_sha256=_sha256(
                bindings.get("runtime_set_sha256"),
                label="runtime-set SHA-256",
            ),
            pipeline_contract_sha256=_sha256(
                persisted_real_source.get(
                    "ocr_pipeline_contract_sha256"
                ),
                label="OCR pipeline contract SHA-256",
            ),
            dataset_manifest_sha256=approved_manifest_sha256,
            candidate_set_sha256=_sha256(
                bindings.get("candidate_set_sha256"),
                label="candidate-set SHA-256",
            ),
            matcher_fingerprint=_sha256(
                bindings.get("matcher_fingerprint"),
                label="matcher fingerprint",
            ),
            policy_fingerprint=_sha256(
                bindings.get("policy_fingerprint"),
                label="policy fingerprint",
            ),
            template_set_fingerprint=_sha256(
                bindings.get("template_set_fingerprint"),
                label="template-set fingerprint",
            ),
            composite_policy_sha256=_sha256(
                bindings.get("composite_gate_policy_sha256"),
                label="composite policy SHA-256",
            ),
        )
    except (TemplateLifecycleAttemptError, TypeError, ValueError) as exc:
        raise FormalDevelopmentAuthorityError(
            "shadow publication lifecycle scope is invalid"
        ) from exc


def require_approved_development_dataset_binding(
    authority: FormalDevelopmentAuthority,
    *,
    approved_manifest_sha256: str,
) -> None:
    """Recheck the approved synthetic input carried by every publication."""

    approved_manifest = _sha256(
        approved_manifest_sha256,
        label="approved development manifest SHA-256",
    )
    raw_publications = authority.payload.get("shadow_publications")
    if not isinstance(raw_publications, list) or not raw_publications:
        raise FormalDevelopmentAuthorityError(
            "development authority shadow publications are incomplete"
        )
    for publication in raw_publications:
        if not isinstance(publication, Mapping):
            raise FormalDevelopmentAuthorityError(
                "development authority shadow publication is invalid"
            )
        evaluation = publication.get("publication_evaluation")
        if not isinstance(evaluation, Mapping):
            raise FormalDevelopmentAuthorityError(
                "development authority publication evaluation is invalid"
            )
        composite_manifest = evaluation.get(
            "dataset_manifest_sha256"
        )
        metrics = evaluation.get("metrics")
        lifecycle_attempt = publication.get("lifecycle_attempt")
        if (
            composite_manifest
            != authority.eligibility_contract.dataset_manifest_sha256
            or not isinstance(metrics, Mapping)
            or not isinstance(lifecycle_attempt, Mapping)
            or not isinstance(
                lifecycle_attempt.get("reviewer_id"),
                str,
            )
        ):
            raise FormalDevelopmentAuthorityError(
                "shadow publication is not bound to the approved development dataset"
            )
        bound_scope = _composite_lifecycle_scope_from_metrics(
            metrics,
            composite_manifest_sha256=authority.eligibility_contract.dataset_manifest_sha256,
            reviewer_id=cast(
                str,
                lifecycle_attempt["reviewer_id"],
            ),
        )
        if bound_scope.dataset_manifest_sha256 != approved_manifest:
            raise FormalDevelopmentAuthorityError(
                "shadow publication is not bound to the approved development dataset"
            )


def build_current_formal_development_authority(
    runtime: SqliteRuntime,
    *,
    frozen_exclusion_snapshot_sha256: str | None = None,
) -> FormalDevelopmentAuthority:
    """Revalidate the live development root and freeze its current authority."""

    contract = SqliteTemplateRepository.current_shadow_eligibility_contract(runtime)
    approved = load_approved_authorizing_development_dataset(
        approved_authorizing_development_dataset_path()
    )
    expected_contract = {
        "matcher_fingerprint": development_matcher_fingerprint(),
        "policy_fingerprint": development_policy_fingerprint(),
        "build_fingerprint": current_template_pipeline_build_fingerprint(
            application_version=__version__,
        ),
    }
    if any(getattr(contract, field) != expected for field, expected in expected_contract.items()):
        raise FormalDevelopmentAuthorityError("current shadow eligibility contract is stale")
    template_repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint=contract.build_fingerprint,
        accepted_runtime_fingerprint=contract.runtime_fingerprint,
        accepted_development_manifest_sha256=(contract.dataset_manifest_sha256),
        accepted_matcher_fingerprint=contract.matcher_fingerprint,
        accepted_policy_fingerprint=contract.policy_fingerprint,
    )
    shadow_publications = (
        template_repository.list_current_shadow_publication_authorities()
    )
    for publication in shadow_publications:
        bound_scope = _composite_lifecycle_scope_from_metrics(
            publication.publication_evaluation.metrics,
            composite_manifest_sha256=contract.dataset_manifest_sha256,
            reviewer_id=publication.lifecycle_attempt.reviewer_id,
        )
        if bound_scope.dataset_manifest_sha256 != approved.manifest_sha256:
            raise FormalDevelopmentAuthorityError(
                "shadow publication is not bound to the approved development dataset"
            )
    locked_repository = SqliteLockedSetRepository(runtime=runtime)
    live_snapshot = locked_repository.build_exclusion_snapshot()
    authority_snapshot = live_snapshot
    if frozen_exclusion_snapshot_sha256 is not None:
        authority_snapshot = locked_repository.get_exclusion_snapshot(
            frozen_exclusion_snapshot_sha256
        )
        if (
            live_snapshot.snapshot.template_reference_image_hashes
            != authority_snapshot.snapshot.template_reference_image_hashes
            or live_snapshot.snapshot.development_image_hashes
            != authority_snapshot.snapshot.development_image_hashes
            or live_snapshot.snapshot.calibration_image_hashes
            != authority_snapshot.snapshot.calibration_image_hashes
            or live_snapshot.snapshot.shadow_image_hashes
            != authority_snapshot.snapshot.shadow_image_hashes
            or live_snapshot.snapshot.prior_locked_image_hashes
            != authority_snapshot.snapshot.prior_locked_image_hashes
            or live_snapshot.snapshot.prior_waybill_identity_hashes
            != authority_snapshot.snapshot.prior_waybill_identity_hashes
            or live_snapshot.inventory_image_count
            != authority_snapshot.inventory_image_count
            or live_snapshot.fingerprinted_image_count
            != authority_snapshot.fingerprinted_image_count
            or live_snapshot.missing_fingerprint_count
            != authority_snapshot.missing_fingerprint_count
            or live_snapshot.fingerprint_algorithm_versions
            != authority_snapshot.fingerprint_algorithm_versions
            or live_snapshot.perceptual_fingerprints
            != authority_snapshot.perceptual_fingerprints
        ):
            raise FormalDevelopmentAuthorityError(
                "live development exclusion identities changed after the frozen authority"
            )
    return build_formal_development_authority(
        exclusion_snapshot=authority_snapshot,
        eligibility_contract=contract,
        shadow_publications=shadow_publications,
    )


def parse_formal_development_authority(
    value: Mapping[str, object],
) -> FormalDevelopmentAuthority:
    payload = json.loads(_canonical_json(dict(value)))
    if not isinstance(payload, dict):
        raise FormalDevelopmentAuthorityError("development authority must be an object")
    expected_fields = {
        "schema_version",
        "kind",
        "source_exclusion_snapshot_sha256",
        "source_exclusion_snapshot_id",
        "source_exclusion_snapshot_source_id",
        "source_inventory_high_watermark",
        "exclusion_categories",
        "image_identity_count",
        "waybill_identity_count",
        "fingerprint_algorithm_versions",
        "perceptual_fingerprints",
        "eligibility_contract",
        "shadow_template_set_fingerprint",
        "shadow_publications",
        "authority_sha256",
    }
    if (
        set(payload) != expected_fields
        or payload.get("schema_version") != 1
        or payload.get("kind") != "loop7_formal_development_authority"
    ):
        raise FormalDevelopmentAuthorityError("development authority contract is unsupported")
    authority_sha256 = _sha256(
        payload.get("authority_sha256"),
        label="development authority SHA-256",
    )
    without_hash = dict(payload)
    without_hash.pop("authority_sha256")
    if _canonical_sha256(without_hash) != authority_sha256:
        raise FormalDevelopmentAuthorityError("development authority SHA-256 does not match")
    categories_value = payload.get("exclusion_categories")
    if not isinstance(categories_value, dict) or set(categories_value) != set(_CATEGORY_FIELDS):
        raise FormalDevelopmentAuthorityError(
            "development authority exclusion categories are invalid"
        )
    categories = {
        field: frozenset(_hash_list(categories_value[field], label=field))
        for field in _CATEGORY_FIELDS
    }
    source_id = payload.get("source_exclusion_snapshot_source_id")
    if not isinstance(source_id, str) or not source_id.strip():
        raise FormalDevelopmentAuthorityError("development authority exclusion source is invalid")
    snapshot = LockedSetExclusionSnapshot.create(
        source_id=source_id,
        template_reference_image_hashes=set(categories["template_reference_image_hashes"]),
        development_image_hashes=set(categories["development_image_hashes"]),
        calibration_image_hashes=set(categories["calibration_image_hashes"]),
        shadow_image_hashes=set(categories["shadow_image_hashes"]),
        prior_locked_image_hashes=set(categories["prior_locked_image_hashes"]),
        prior_waybill_identity_hashes=set(categories["prior_waybill_identity_hashes"]),
    )
    if snapshot.canonical_sha256 != _sha256(
        payload.get("source_exclusion_snapshot_sha256"),
        label="source exclusion snapshot SHA-256",
    ):
        raise FormalDevelopmentAuthorityError("development authority exclusion snapshot changed")
    image_hashes = frozenset(
        snapshot.template_reference_image_hashes
        | snapshot.development_image_hashes
        | snapshot.calibration_image_hashes
        | snapshot.shadow_image_hashes
        | snapshot.prior_locked_image_hashes
    )
    if (
        not image_hashes
        or not snapshot.prior_waybill_identity_hashes
        or payload.get("image_identity_count") != len(image_hashes)
        or payload.get("waybill_identity_count") != len(snapshot.prior_waybill_identity_hashes)
    ):
        raise FormalDevelopmentAuthorityError(
            "development authority exclusion membership is incomplete"
        )
    raw_fingerprints = payload.get("perceptual_fingerprints")
    if not isinstance(raw_fingerprints, list):
        raise FormalDevelopmentAuthorityError("development authority fingerprints must be an array")
    fingerprints: list[PersistedPerceptualFingerprint] = []
    for raw in raw_fingerprints:
        if not isinstance(raw, dict) or set(raw) != {
            "algorithm_version",
            "content_sha256",
            "fingerprint_sha256",
            "perceptual_fingerprint_json",
        }:
            raise FormalDevelopmentAuthorityError("development authority fingerprint is invalid")
        fingerprint = PersistedPerceptualFingerprint(
            content_sha256=_sha256(
                raw.get("content_sha256"),
                label="fingerprint content SHA-256",
            ),
            perceptual_fingerprint_json=cast(
                str,
                raw.get("perceptual_fingerprint_json"),
            ),
            fingerprint_sha256=_sha256(
                raw.get("fingerprint_sha256"),
                label="fingerprint SHA-256",
            ),
            algorithm_version=cast(
                str,
                raw.get("algorithm_version"),
            ),
        )
        try:
            fingerprint.to_image_fingerprint()
        except (LockedSetPersistenceError, TypeError, ValueError) as exc:
            raise FormalDevelopmentAuthorityError(
                "development authority fingerprint integrity is invalid"
            ) from exc
        fingerprints.append(fingerprint)
    if tuple(item.content_sha256 for item in fingerprints) != tuple(sorted(image_hashes)) or len(
        fingerprints
    ) != len(image_hashes):
        raise FormalDevelopmentAuthorityError("development authority fingerprints are incomplete")
    raw_contract = payload.get("eligibility_contract")
    if not isinstance(raw_contract, dict) or set(raw_contract) != {
        "dataset_manifest_sha256",
        "matcher_fingerprint",
        "policy_fingerprint",
        "build_fingerprint",
        "runtime_fingerprint",
    }:
        raise FormalDevelopmentAuthorityError(
            "development authority eligibility contract is invalid"
        )
    contract = TemplateEligibilityContract(
        dataset_manifest_sha256=_sha256(
            raw_contract.get("dataset_manifest_sha256"),
            label="development manifest SHA-256",
        ),
        matcher_fingerprint=_sha256(
            raw_contract.get("matcher_fingerprint"),
            label="matcher fingerprint",
        ),
        policy_fingerprint=_sha256(
            raw_contract.get("policy_fingerprint"),
            label="policy fingerprint",
        ),
        build_fingerprint=_sha256(
            raw_contract.get("build_fingerprint"),
            label="build fingerprint",
        ),
        runtime_fingerprint=_sha256(
            raw_contract.get("runtime_fingerprint"),
            label="runtime fingerprint",
        ),
    )
    raw_publications = payload.get("shadow_publications")
    if not isinstance(raw_publications, list) or not raw_publications:
        raise FormalDevelopmentAuthorityError(
            "development authority shadow publications are incomplete"
        )
    templates: list[TemplateVersion] = []
    seen_families: set[str] = set()
    for raw in raw_publications:
        if not isinstance(raw, dict) or set(raw) != {
            "family_id",
            "version_id",
            "version_number",
            "parent_version_id",
            "record_version",
            "pointer_record_version",
            "publication_event_id",
            "publication_event_record_version",
            "lifecycle",
            "content_sha256",
            "definition",
            "publication_evaluation",
            "lifecycle_attempt",
        }:
            raise FormalDevelopmentAuthorityError(
                "development authority shadow publication is invalid"
            )
        definition_value = raw.get("definition")
        if not isinstance(definition_value, dict):
            raise FormalDevelopmentAuthorityError(
                "development authority template definition is invalid"
            )
        definition = deserialize_template_definition(definition_value)
        family_id = raw.get("family_id")
        if (
            family_id != definition.family_id
            or not isinstance(family_id, str)
            or family_id in seen_families
            or raw.get("lifecycle") != TemplateLifecycle.SHADOW.value
        ):
            raise FormalDevelopmentAuthorityError("development authority shadow family is invalid")
        seen_families.add(family_id)
        version_number = _positive_int(
            raw.get("version_number"),
            label="template version number",
        )
        record_version = _positive_int(
            raw.get("record_version"),
            label="template record version",
        )
        _positive_int(
            raw.get("pointer_record_version"),
            label="shadow pointer record version",
        )
        publication_event_id = raw.get("publication_event_id")
        publication_event_record_version = _positive_int(
            raw.get("publication_event_record_version"),
            label="publication event record version",
        )
        version_id = raw.get("version_id")
        parent_version_id = raw.get("parent_version_id")
        if (
            not isinstance(version_id, str)
            or not version_id.strip()
            or not isinstance(publication_event_id, str)
            or not publication_event_id.strip()
            or publication_event_record_version != record_version
            or (
                parent_version_id is not None
                and (not isinstance(parent_version_id, str) or not parent_version_id.strip())
            )
        ):
            raise FormalDevelopmentAuthorityError(
                "development authority template identity is invalid"
            )
        version = TemplateVersion(
            version_id=version_id,
            version_number=version_number,
            definition=definition,
            lifecycle=TemplateLifecycle.SHADOW,
            parent_version_id=parent_version_id,
            record_version=record_version,
        )
        if (
            version.content_sha256
            != _sha256(
                raw.get("content_sha256"),
                label="template content SHA-256",
            )
            or canonical_template_hash(definition) != version.content_sha256
        ):
            raise FormalDevelopmentAuthorityError("development authority template content changed")
        evaluation = raw.get("publication_evaluation")
        if not isinstance(evaluation, dict):
            raise FormalDevelopmentAuthorityError(
                "development authority publication evaluation is invalid"
            )
        required_evaluation_fields = {
            "evaluation_id",
            "dataset_kind",
            "dataset_id",
            "dataset_manifest_sha256",
            "template_set_fingerprint",
            "matcher_fingerprint",
            "policy_fingerprint",
            "build_fingerprint",
            "runtime_fingerprint",
            "verification_source",
            "stable_outcome_sha256",
            "expected_count",
            "result_count",
            "metrics",
            "metrics_sha256",
            "gate_passed",
            "actor_id",
            "completed_at",
        }
        if (
            set(evaluation) != required_evaluation_fields
            or evaluation.get("gate_passed") is not True
            or evaluation.get("verification_source") != "frozen_runner"
            or evaluation.get("expected_count") != evaluation.get("result_count")
            or evaluation.get("stable_outcome_sha256") is None
            or any(
                evaluation.get(field) != getattr(contract, field)
                for field in (
                    "dataset_manifest_sha256",
                    "matcher_fingerprint",
                    "policy_fingerprint",
                    "build_fingerprint",
                    "runtime_fingerprint",
                )
            )
            or _canonical_sha256(evaluation.get("metrics")) != evaluation.get("metrics_sha256")
        ):
            raise FormalDevelopmentAuthorityError(
                "development authority publication evaluation changed"
            )
        metrics = evaluation.get("metrics")
        if not isinstance(metrics, Mapping):
            raise FormalDevelopmentAuthorityError(
                "development authority publication evaluation changed"
            )
        lifecycle_attempt_value = raw.get("lifecycle_attempt")
        if not isinstance(lifecycle_attempt_value, dict):
            raise FormalDevelopmentAuthorityError(
                "development authority lifecycle attempt is invalid"
            )
        try:
            lifecycle_attempt = lifecycle_attempt_record_from_mapping(
                lifecycle_attempt_value
            )
        except (
            KeyError,
            TemplateLifecycleAttemptError,
            TypeError,
            ValueError,
        ) as exc:
            raise FormalDevelopmentAuthorityError(
                "development authority lifecycle attempt is invalid"
            ) from exc
        expected_scope = (
            _composite_lifecycle_scope_from_metrics(
                metrics,
                composite_manifest_sha256=(
                    contract.dataset_manifest_sha256
                ),
                reviewer_id=lifecycle_attempt.reviewer_id,
            )
        )
        if (
            lifecycle_attempt.terminal_status != "succeeded"
            or lifecycle_attempt.evaluation_id != evaluation.get("evaluation_id")
            or not _attempt_matches_scope(
                lifecycle_attempt,
                expected_scope,
            )
            or not _scope_matches_publication_contract(
                expected_scope,
                eligibility_contract=contract,
                template_set_fingerprint=evaluation.get(
                    "template_set_fingerprint"
                ),
            )
        ):
            raise FormalDevelopmentAuthorityError(
                "development authority lifecycle attempt changed"
            )
        templates.append(version)
    ordered_templates = tuple(
        sorted(
            templates,
            key=lambda item: item.definition.family_id,
        )
    )
    if build_template_set_fingerprint(ordered_templates) != _sha256(
        payload.get("shadow_template_set_fingerprint"),
        label="shadow template-set fingerprint",
    ):
        raise FormalDevelopmentAuthorityError("development authority template set changed")
    return FormalDevelopmentAuthority(
        authority_sha256=authority_sha256,
        payload=cast(dict[str, object], payload),
        exclusion_snapshot=snapshot,
        inventory_high_watermark=_positive_int(
            payload.get("source_inventory_high_watermark"),
            label="source inventory high watermark",
        ),
        perceptual_fingerprints=tuple(fingerprints),
        shadow_templates=ordered_templates,
        eligibility_contract=contract,
    )


def load_formal_development_authority(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> FormalDevelopmentAuthority:
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
        payload = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FormalDevelopmentAuthorityError(
            "development authority is not a readable JSON file"
        ) from exc
    if not resolved.is_file() or not isinstance(payload, dict):
        raise FormalDevelopmentAuthorityError("development authority must be a JSON object")
    expected_content = (_canonical_json(payload) + "\n").encode("utf-8")
    if content != expected_content:
        raise FormalDevelopmentAuthorityError("development authority file is not canonical")
    authority = parse_formal_development_authority(payload)
    if expected_sha256 is not None and authority.authority_sha256 != expected_sha256:
        raise FormalDevelopmentAuthorityError(
            "development authority does not match the expected SHA-256"
        )
    return authority


def write_formal_development_authority(
    path: Path,
    authority: FormalDevelopmentAuthority,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> Path:
    output = path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    stale_pattern = f".{output.name}.*.tmp"
    for stale in output.parent.glob(stale_pattern):
        if stale.is_file():
            try:
                stale.unlink()
            except OSError as exc:
                raise FormalDevelopmentAuthorityError(
                    "stale development authority staging file cannot be removed"
                ) from exc
    if output.exists():
        existing = load_formal_development_authority(
            output,
            expected_sha256=authority.authority_sha256,
        )
        if existing != authority:
            raise FormalDevelopmentAuthorityError(
                "development authority output conflicts"
            )
        return output
    content = (_canonical_json(authority.payload) + "\n").encode("utf-8")
    staged = output.with_name(
        f".{output.name}.{uuid4().hex}.tmp"
    )
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if failpoint is not None:
            failpoint("after_authority_staged_fsync")
        try:
            os.link(staged, output)
        except FileExistsError:
            existing = load_formal_development_authority(
                output,
                expected_sha256=authority.authority_sha256,
            )
            if existing != authority:
                raise FormalDevelopmentAuthorityError(
                    "development authority output conflicts"
                ) from None
        except OSError as exc:
            raise FormalDevelopmentAuthorityError(
                "development authority could not be published atomically"
            ) from exc
        if failpoint is not None:
            failpoint("after_authority_atomic_publish")
        return output
    finally:
        staged.unlink(missing_ok=True)


def persist_formal_development_authority(
    data_root: Path,
    authority: FormalDevelopmentAuthority,
) -> Path:
    """Store one content-addressed authority without replacing prior evidence."""

    root = data_root.resolve(strict=True)
    if not root.is_dir():
        raise FormalDevelopmentAuthorityError(
            "formal data root is unavailable"
        )
    authority_root = root / "formal-development-authorities"
    authority_root.mkdir(exist_ok=True)
    output = authority_root / f"{authority.authority_sha256}.json"
    if output.exists():
        existing = load_formal_development_authority(
            output,
            expected_sha256=authority.authority_sha256,
        )
        if existing != authority:
            raise FormalDevelopmentAuthorityError(
                "persisted development authority conflicts"
            )
        return output
    return write_formal_development_authority(output, authority)


def load_persisted_formal_development_authority(
    data_root: Path,
    *,
    authority_sha256: str,
) -> FormalDevelopmentAuthority:
    root = data_root.resolve(strict=True)
    return load_formal_development_authority(
        root
        / "formal-development-authorities"
        / f"{authority_sha256}.json",
        expected_sha256=authority_sha256,
    )
