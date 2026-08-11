from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dahe.application.template_studio.candidate_role_metrics import (
    _RUNTIME_KINDS,
    _EvaluatedImage,
    _role_consistency,
    _runtime_payload,
)
from dahe.application.template_studio.candidate_role_ocr_evidence import (
    _validate_evidence,
)
from dahe.application.template_studio.candidate_role_ocr_evidence import (
    load_protected_candidate_development_ocr_evidence as _load_protected_evidence,
)
from dahe.application.template_studio.candidate_role_source_authority import (
    CandidateRoleEvaluationError as CandidateRoleEvaluationError,
)
from dahe.application.template_studio.candidate_role_source_authority import (
    _canonical_sha256,
    _mapping,
)
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.matcher import (
    build_development_evaluation_template_set,
)
from dahe.domain.audit.errors import DomainContractError
from dahe.domain.ticket.templates import TemplateVersion

EVALUATOR_VERSION = "dahe.loop7.candidate-role-evaluation.v3"


@dataclass(frozen=True, slots=True)
class CandidateDevelopmentRoleEvaluation:
    payload: dict[str, object]
    evaluation_sha256: str


def _role_evaluator_build_sha256(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CandidateRoleEvaluationError(
            "role evaluator build must be a lowercase SHA-256"
        )
    return value


def evaluate_candidate_development_roles(
    evidence: Mapping[str, object],
    *,
    candidates: tuple[TemplateVersion, ...],
    role_evaluator_build_sha256: str,
    current_shadow: tuple[TemplateVersion, ...] = (),
) -> CandidateDevelopmentRoleEvaluation:
    """Evaluate reviewed development OCR without creating gate authority."""

    evaluator_build_sha256 = _role_evaluator_build_sha256(
        role_evaluator_build_sha256
    )
    validated = _validate_evidence(evidence)
    try:
        template_set = build_development_evaluation_template_set(
            candidates=candidates,
            current_shadow=current_shadow,
        )
    except (DomainContractError, ValueError) as exc:
        raise CandidateRoleEvaluationError(
            "candidate templates are not valid for development evaluation"
        ) from exc
    runtime_payloads: dict[str, object] = {}
    runtime_results: dict[
        str,
        dict[str, _EvaluatedImage],
    ] = {}
    for runtime_kind in _RUNTIME_KINDS:
        runtime_payload, results = _runtime_payload(
            runtime_kind,
            validated=validated,
            candidates=candidates,
            current_shadow=current_shadow,
        )
        runtime_payloads[runtime_kind] = runtime_payload
        runtime_results[runtime_kind] = results
    source_authority = _mapping(
        validated.source["source_authority_payload"],
        label="candidate source authority",
    )
    payload: dict[str, object] = {
        "attempt_contract": {
            "completed_attempt_count": len(validated.attempts),
            "expected_attempt_count": 200,
            "technical_failure_count": 0,
        },
        "authorizing_lifecycle_evidence": False,
        "cpu_gpu_role_consistency": _role_consistency(
            cpu=runtime_results["cpu"],
            gpu=runtime_results["gpu"],
        ),
        "development_only": True,
        "evaluator_version": EVALUATOR_VERSION,
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "kind": ("candidate_review_development_role_template_evaluation"),
        "runtimes": runtime_payloads,
        "schema_version": 2,
        "source": {
            "composition_evidence_sha256": (validated.composition_evidence_sha256),
            "manifest_sha256": validated.source["manifest_sha256"],
            "ocr_capture_build_sha256": (
                validated.application_build_sha256
            ),
            "ocr_evidence_sha256": (validated.evidence_sha256),
            "ocr_pipeline_contract_sha256": (validated.pipeline_contract_sha256),
            "package_sha256": validated.source["package_sha256"],
            "quality_coverage_sha256": validated.source["quality_coverage_sha256"],
            "record_set_sha256": validated.source["record_set_sha256"],
            "review_history_authority_sha256": (
                validated.source["review_history_authority_sha256"]
            ),
            "reviewer_id_sha256": _canonical_sha256(
                source_authority["configured_reviewer_id"]
            ),
            "runtime_set_sha256": (validated.runtime_set_sha256),
            "role_evaluator_build_sha256": (
                evaluator_build_sha256
            ),
            "source_authority_sha256": (validated.source["source_authority_sha256"]),
        },
        "status": "completed",
        "template_contract": {
            "candidate_count": len(candidates),
            "candidates": [
                {
                    "content_sha256": candidate.content_sha256,
                    "family_id_sha256": _canonical_sha256(candidate.definition.family_id),
                    "lifecycle": candidate.lifecycle.value,
                    "role": candidate.definition.role.value,
                    "version_id": candidate.version_id,
                }
                for candidate in sorted(
                    candidates,
                    key=lambda item: item.version_id,
                )
            ],
            "current_shadow_count": len(current_shadow),
            "dataset_id_sha256": _canonical_sha256(source_authority["dataset_id"]),
            "matcher_fingerprint": (development_matcher_fingerprint()),
            "policy_fingerprint": (development_policy_fingerprint()),
            "selected_template_count": len(template_set.versions),
            "template_set_fingerprint": (template_set.fingerprint),
        },
    }
    evaluation_sha256 = _canonical_sha256(payload)
    payload["evaluation_sha256"] = evaluation_sha256
    return CandidateDevelopmentRoleEvaluation(
        payload=payload,
        evaluation_sha256=evaluation_sha256,
    )


def load_protected_candidate_development_ocr_evidence(
    path: Path,
    *,
    data_root: Path,
) -> dict[str, object]:
    """Load one immutable, content-addressed protected OCR record."""

    return _load_protected_evidence(
        path,
        data_root=data_root,
    )


def evaluate_candidate_development_roles_from_path(
    path: Path,
    *,
    data_root: Path,
    candidates: tuple[TemplateVersion, ...],
    role_evaluator_build_sha256: str,
    current_shadow: tuple[TemplateVersion, ...] = (),
) -> CandidateDevelopmentRoleEvaluation:
    evidence = load_protected_candidate_development_ocr_evidence(
        path,
        data_root=data_root,
    )
    return evaluate_candidate_development_roles(
        evidence,
        candidates=candidates,
        role_evaluator_build_sha256=role_evaluator_build_sha256,
        current_shadow=current_shadow,
    )
