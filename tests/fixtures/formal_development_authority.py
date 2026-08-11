from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from io import BytesIO

from PIL import Image

from dahe.adapters.sqlite.locked_set import (
    PersistedExclusionSnapshot,
    PersistedPerceptualFingerprint,
)
from dahe.adapters.sqlite.template_lifecycle_attempts import (
    lifecycle_attempt_record_from_mapping,
    lifecycle_attempt_row,
    make_composite_lifecycle_attempt_scope,
)
from dahe.adapters.sqlite.template_studio import (
    ShadowTemplatePublicationAuthority,
    TemplateEligibilityContract,
    TemplateEvaluationRecord,
)
from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
    build_formal_development_authority,
)
from dahe.domain.ticket.templates import TemplateLifecycle
from dahe.verification.image_similarity import build_image_fingerprint
from dahe.verification.locked_set import LockedSetExclusionSnapshot
from tests.fixtures.loop7_current_candidate_templates import (
    current_candidate_versions,
)


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def formal_development_authority(
    *,
    build_fingerprint: str | None = None,
    runtime_fingerprint: str | None = None,
    matcher_fingerprint: str | None = None,
    policy_fingerprint: str | None = None,
    development_manifest: str | None = None,
) -> FormalDevelopmentAuthority:
    """Build one small but fully parsed authority for boundary tests."""

    image_buffer = BytesIO()
    Image.new("RGB", (24, 18), (45, 90, 135)).save(
        image_buffer,
        format="PNG",
    )
    image_bytes = image_buffer.getvalue()
    fingerprint = build_image_fingerprint(image_bytes)
    fingerprint_json = _canonical_json(fingerprint.to_record())
    persisted_fingerprint = PersistedPerceptualFingerprint(
        content_sha256=fingerprint.content_sha256,
        perceptual_fingerprint_json=fingerprint_json,
        fingerprint_sha256=hashlib.sha256(
            fingerprint_json.encode("utf-8")
        ).hexdigest(),
        algorithm_version=fingerprint.algorithm_version,
    )
    snapshot = LockedSetExclusionSnapshot.create(
        source_id="loop7-test-development-authority",
        template_reference_image_hashes=set(),
        development_image_hashes={fingerprint.content_sha256},
        calibration_image_hashes=set(),
        shadow_image_hashes=set(),
        prior_locked_image_hashes=set(),
        prior_waybill_identity_hashes={
            _sha256("loop7-test-prior-waybill")
        },
    )
    persisted_snapshot = PersistedExclusionSnapshot(
        snapshot_id=snapshot.canonical_sha256,
        inventory_high_watermark=2,
        snapshot=snapshot,
        inventory_image_count=1,
        fingerprinted_image_count=1,
        missing_fingerprint_count=0,
        fingerprint_algorithm_versions=(
            fingerprint.algorithm_version,
        ),
        perceptual_fingerprints=(persisted_fingerprint,),
        created_at="2026-07-26T00:00:00+00:00",
    )

    build_fingerprint = (
        build_fingerprint or _sha256("loop7-test-build")
    )
    runtime_fingerprint = (
        runtime_fingerprint or _sha256("loop7-test-runtime")
    )
    matcher_fingerprint = (
        matcher_fingerprint or _sha256("loop7-test-matcher")
    )
    policy_fingerprint = (
        policy_fingerprint or _sha256("loop7-test-policy")
    )
    approved_development_manifest = (
        development_manifest
        or _sha256("loop7-test-development-manifest")
    )
    candidate_set_sha256 = _sha256("loop7-test-candidate-set")
    ocr_evidence_sha256 = _sha256("loop7-test-ocr-evidence")
    source_authority_sha256 = _sha256(
        "loop7-test-source-authority"
    )
    composite_manifest = hashlib.sha256(
        _canonical_json(
            {
                "authorization_scope": "ticket_role_evidence",
                "candidate_set_sha256": candidate_set_sha256,
                "frozen_synthetic_dataset_sha256": (
                    approved_development_manifest
                ),
                "ocr_evidence_sha256": ocr_evidence_sha256,
                "real_source_authority_sha256": (
                    source_authority_sha256
                ),
                "schema_version": 1,
            }
        ).encode("utf-8")
    ).hexdigest()
    evaluation_template_set = _sha256(
        "loop7-test-development-evaluation-template-set"
    )
    contract = TemplateEligibilityContract(
        dataset_manifest_sha256=composite_manifest,
        matcher_fingerprint=matcher_fingerprint,
        policy_fingerprint=policy_fingerprint,
        build_fingerprint=build_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
    )
    template = replace(
        current_candidate_versions()[0],
        lifecycle=TemplateLifecycle.SHADOW,
        record_version=3,
    )
    metrics: dict[str, object] = {
        "lifecycle_authorization_schema_version": 2,
        "composite_lifecycle": {
            "authorization_scope": "ticket_role_evidence",
            "authorizing_lifecycle_evidence": True,
            "bindings": {
                "candidate_set_sha256": candidate_set_sha256,
                "composite_gate_policy_sha256": _sha256(
                    "loop7-test-composite-policy"
                ),
                "frozen_synthetic_dataset_sha256": (
                    approved_development_manifest
                ),
                "matcher_fingerprint": matcher_fingerprint,
                "policy_fingerprint": policy_fingerprint,
                "role_evaluator_build_sha256": build_fingerprint,
                "runtime_set_sha256": runtime_fingerprint,
                "template_set_fingerprint": (
                    evaluation_template_set
                ),
            },
            "components": {
                "frozen_synthetic": {
                    "dataset_manifest_sha256": (
                        approved_development_manifest
                    ),
                },
            },
            "dataset_manifest_sha256": composite_manifest,
            "kind": "composite_template_lifecycle_evaluation",
            "schema_version": 1,
        },
        "composite_lifecycle_components": {
            "frozen_synthetic": {
                "dataset_manifest_sha256": (
                    approved_development_manifest
                ),
            },
            "real_candidate_roles": {
                "source": {
                    "composition_evidence_sha256": _sha256(
                        "loop7-test-composition"
                    ),
                    "ocr_evidence_sha256": ocr_evidence_sha256,
                    "ocr_capture_build_sha256": _sha256(
                        "loop7-test-ocr-build"
                    ),
                    "ocr_pipeline_contract_sha256": _sha256(
                        "loop7-test-pipeline"
                    ),
                    "package_sha256": _sha256(
                        "loop7-test-package"
                    ),
                    "review_history_authority_sha256": _sha256(
                        "loop7-test-review-history"
                    ),
                    "reviewer_id_sha256": hashlib.sha256(
                        _canonical_json(
                            "loop7-test-reviewer"
                        ).encode("utf-8")
                    ).hexdigest(),
                    "runtime_set_sha256": runtime_fingerprint,
                    "source_authority_sha256": (
                        source_authority_sha256
                    ),
                },
            },
        },
    }
    evaluation = TemplateEvaluationRecord(
        evaluation_id="loop7-test-development-evaluation",
        dataset_kind="development",
        dataset_id="loop7-test-development-dataset",
        dataset_manifest_sha256=composite_manifest,
        template_set_fingerprint=evaluation_template_set,
        matcher_fingerprint=matcher_fingerprint,
        policy_fingerprint=policy_fingerprint,
        build_fingerprint=build_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
        verification_source="frozen_runner",
        stable_outcome_sha256=_sha256("loop7-test-stable-outcome"),
        expected_count=1,
        result_count=1,
        metrics=metrics,
        metrics_sha256=hashlib.sha256(
            _canonical_json(metrics).encode("utf-8")
        ).hexdigest(),
        gate_passed=True,
        actor_id="loop7-test-actor",
        completed_at="2026-07-26T00:00:00+00:00",
    )
    scope = make_composite_lifecycle_attempt_scope(
        ocr_evidence_sha256=ocr_evidence_sha256,
        package_sha256=_sha256("loop7-test-package"),
        review_history_authority_sha256=_sha256(
            "loop7-test-review-history"
        ),
        source_authority_sha256=source_authority_sha256,
        reviewer_id="loop7-test-reviewer",
        ocr_capture_build_sha256=_sha256("loop7-test-ocr-build"),
        role_evaluator_build_sha256=build_fingerprint,
        composition_evidence_sha256=_sha256(
            "loop7-test-composition"
        ),
        runtime_set_sha256=runtime_fingerprint,
        pipeline_contract_sha256=_sha256("loop7-test-pipeline"),
        dataset_manifest_sha256=approved_development_manifest,
        candidate_set_sha256=candidate_set_sha256,
        matcher_fingerprint=matcher_fingerprint,
        policy_fingerprint=policy_fingerprint,
        template_set_fingerprint=evaluation_template_set,
        composite_policy_sha256=_sha256("loop7-test-composite-policy"),
    )
    attempt_row = lifecycle_attempt_row(
        scope=scope,
        terminal_status="succeeded",
        evaluation_id=evaluation.evaluation_id,
        failure_code=None,
        attempt_id="a" * 32,
        actor_id="loop7-test-actor",
        created_at="2026-07-26T00:00:00+00:00",
    )
    attempt_row["attempt_sequence"] = 1
    attempt = lifecycle_attempt_record_from_mapping(attempt_row)
    publication = ShadowTemplatePublicationAuthority(
        version=template,
        pointer_record_version=1,
        publication_event_id="b" * 32,
        publication_event_record_version=template.record_version,
        publication_evaluation=evaluation,
        lifecycle_attempt=attempt,
    )
    return build_formal_development_authority(
        exclusion_snapshot=persisted_snapshot,
        eligibility_contract=contract,
        shadow_publications=(publication,),
    )


def external_exclusion_snapshot(
    authority: FormalDevelopmentAuthority,
) -> dict[str, object]:
    image_sha256s = sorted(authority.image_sha256s)
    waybill_sha256s = sorted(authority.waybill_identity_sha256s)
    canonical = {
        "image_sha256s": image_sha256s,
        "schema_version": 1,
        "source_file_sha256s": [],
        "waybill_identity_sha256s": waybill_sha256s,
    }
    return {
        "schema_version": 1,
        "image_identity_count": len(image_sha256s),
        "waybill_identity_count": len(waybill_sha256s),
        "source_file_sha256s": [],
        "canonical_sha256": hashlib.sha256(
            _canonical_json(canonical).encode("utf-8")
        ).hexdigest(),
        "image_sha256s": image_sha256s,
        "waybill_identity_sha256s": waybill_sha256s,
    }
