from __future__ import annotations

from pathlib import Path

from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.candidate_template_seed import (
    load_template_definition,
)
from dahe.application.template_studio.development_evaluation import (
    run_authorizing_development_evaluation,
)
from dahe.domain.ticket.role_assessment import RoleEvidenceSource
from dahe.domain.ticket.templates import TemplateLifecycle, TemplateVersion

PROJECT_ROOT = Path(__file__).resolve().parents[4]
TEMPLATE_DEFINITIONS = (
    ("candidate-loading-customer", "development-loading-template-v1.json"),
    ("candidate-loading-success", "development-loading-success-template-v1.json"),
    ("candidate-loading-prompt", "development-loading-prompt-template-v1.json"),
    ("candidate-unloading-factory", "development-unloading-template-v1.json"),
)


def _formally_seeded_candidate_contract() -> tuple[TemplateVersion, ...]:
    return tuple(
        TemplateVersion(
            version_id=version_id,
            definition=load_template_definition(
                (PROJECT_ROOT / "verification" / "loops" / "loop-7" / definition_name).resolve(
                    strict=True
                )
            ),
            lifecycle=TemplateLifecycle.DRAFT,
            parent_version_id=None,
            record_version=1,
        )
        for version_id, definition_name in TEMPLATE_DEFINITIONS
    )


def test_approved_authorizing_observations_cover_all_formal_seed_candidates() -> None:
    manifest = approved_authorizing_development_dataset_path()
    dataset = load_approved_authorizing_development_dataset(manifest)
    candidates = _formally_seeded_candidate_contract()

    report = run_authorizing_development_evaluation(
        dataset,
        candidates=candidates,
    )

    covered_candidate_ids = {
        matched_id
        for item in report.items
        for evidence in item.evidence
        if evidence.source == RoleEvidenceSource.TEMPLATE.value
        for matched_id in evidence.matched_ids
    }
    assert manifest.name == "authorizing-development-dataset-v4.json"
    assert covered_candidate_ids == {candidate.version_id for candidate in candidates}
    assert report.gate_passed is True
