from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateEvaluationContractError,
    TemplateEvaluationGateError,
)
from dahe.application.template_studio.matcher import (
    build_development_evaluation_template_set,
)
from tests.integration.test_loop7_template_persistence import (
    _create_draft,
    _definition,
    _publish_version_as_shadow,
    _record_evaluation,
    _repository,
    _runtime,
    _seed_reference_image,
)


def _repository_with_build(runtime: Any, build_fingerprint: str) -> SqliteTemplateRepository:
    return SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint=build_fingerprint,
        accepted_runtime_fingerprint="9" * 64,
        accepted_development_manifest_sha256="4" * 64,
        accepted_matcher_fingerprint="6" * 64,
        accepted_policy_fingerprint="7" * 64,
    )


def _create_family_draft(
    repository: SqliteTemplateRepository,
    *,
    family_id: str,
    image_sha256: str,
    mask_sha256: str,
    idempotency_key: str,
) -> Any:
    draft, created = repository.create_draft(
        definition=_definition(family_id=family_id),
        reference_image_sha256=image_sha256,
        reference_mask_sha256=mask_sha256,
        alignment_fingerprint="c" * 64,
        actor_id="developer-test",
        idempotency_key=idempotency_key,
    )
    assert created is True
    return draft


def _revise_candidate(
    repository: SqliteTemplateRepository,
    source: Any,
    *,
    image_sha256: str,
    mask_sha256: str,
    idempotency_key: str,
) -> Any:
    candidate, created = repository.revise_draft(
        source_version_id=source.version_id,
        definition=_definition(
            family_id=source.definition.family_id,
            left="0.20",
        ),
        reference_image_sha256=image_sha256,
        reference_mask_sha256=mask_sha256,
        alignment_fingerprint="f" * 64,
        expected_record_version=source.record_version,
        actor_id="developer-test",
        idempotency_key=idempotency_key,
    )
    assert created is True
    return candidate


def _invalidate_without_pointer_cleanup(
    runtime: Any,
    *,
    evaluation_id: str,
    invalidation_id: str,
) -> None:
    """Inject an interrupted cleanup state to test commit-time revalidation."""

    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            text(
                """
                INSERT INTO template_evaluation_invalidations (
                    invalidation_id, evaluation_id, reason, actor_id, created_at
                ) VALUES (
                    :invalidation_id, :evaluation_id, :reason, :actor_id, :created_at
                )
                """
            ),
            {
                "invalidation_id": invalidation_id,
                "evaluation_id": evaluation_id,
                "reason": "Injected stale publication evidence",
                "actor_id": "test-fault-injector",
                "created_at": "2026-07-26T12:00:00+00:00",
            },
        )


def test_candidate_can_replace_same_family_shadow_with_stale_build(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-candidate-replace-build")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    try:
        draft, _ = _create_draft(repository, key="candidate-replace-build-v1")
        _evaluation, shadow, pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="candidate-replace-build-v1",
        )
        candidate = _revise_candidate(
            repository,
            shadow,
            image_sha256="d" * 64,
            mask_sha256="e" * 64,
            idempotency_key="candidate-replace-build-v2",
        )
        changed_build_repository = _repository_with_build(runtime, "f" * 64)

        with pytest.raises(TemplateEvaluationGateError):
            changed_build_repository.list_current_eligible_shadow_versions()

        current_shadow = (
            changed_build_repository.list_current_shadow_versions_for_development_evaluation(
                candidates=(candidate,),
            )
        )
        template_set = build_development_evaluation_template_set(
            candidates=(candidate,),
            current_shadow=current_shadow,
        )

        assert current_shadow == (shadow,)
        assert tuple(version.version_id for version in template_set.versions) == (
            candidate.version_id,
        )
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT version_id FROM template_shadow_pointers "
                        "WHERE family_id = :family_id"
                    ),
                    {"family_id": shadow.definition.family_id},
                ).scalar_one()
                == pointer.version_id
            )
    finally:
        runtime.close()


def test_candidate_replacement_retains_unrelated_valid_shadow(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-candidate-retain-shadow")
    _seed_reference_image(
        runtime,
        "a" * 64,
        "b" * 64,
        "d" * 64,
        "e" * 64,
        "1" * 64,
        "2" * 64,
    )
    repository = _repository(runtime)
    try:
        alpha_draft, _ = _create_draft(repository, key="candidate-retain-alpha-v1")
        alpha_evaluation, alpha_shadow, _pointer = _publish_version_as_shadow(
            repository,
            alpha_draft,
            suffix="candidate-retain-alpha-v1",
        )
        beta_draft = _create_family_draft(
            repository,
            family_id="scale-slip-beta",
            image_sha256="1" * 64,
            mask_sha256="2" * 64,
            idempotency_key="candidate-retain-beta-v1",
        )
        _beta_evaluation, beta_shadow, _beta_pointer = _publish_version_as_shadow(
            repository,
            beta_draft,
            suffix="candidate-retain-beta-v1",
        )
        candidate = _revise_candidate(
            repository,
            alpha_shadow,
            image_sha256="d" * 64,
            mask_sha256="e" * 64,
            idempotency_key="candidate-retain-alpha-v2",
        )
        _invalidate_without_pointer_cleanup(
            runtime,
            evaluation_id=alpha_evaluation.evaluation_id,
            invalidation_id="candidate-retain-alpha-stale",
        )

        current_shadow = (
            repository.list_current_shadow_versions_for_development_evaluation(
                candidates=(candidate,),
            )
        )
        template_set = build_development_evaluation_template_set(
            candidates=(candidate,),
            current_shadow=current_shadow,
        )

        assert {version.version_id for version in current_shadow} == {
            alpha_shadow.version_id,
            beta_shadow.version_id,
        }
        assert {version.version_id for version in template_set.versions} == {
            candidate.version_id,
            beta_shadow.version_id,
        }
    finally:
        runtime.close()


def test_candidate_replacement_rejects_unrelated_stale_shadow(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-candidate-stale-shadow")
    _seed_reference_image(
        runtime,
        "a" * 64,
        "b" * 64,
        "d" * 64,
        "e" * 64,
        "1" * 64,
        "2" * 64,
    )
    repository = _repository(runtime)
    try:
        alpha_draft, _ = _create_draft(repository, key="candidate-stale-alpha-v1")
        _alpha_evaluation, alpha_shadow, _alpha_pointer = _publish_version_as_shadow(
            repository,
            alpha_draft,
            suffix="candidate-stale-alpha-v1",
        )
        beta_draft = _create_family_draft(
            repository,
            family_id="scale-slip-beta",
            image_sha256="1" * 64,
            mask_sha256="2" * 64,
            idempotency_key="candidate-stale-beta-v1",
        )
        beta_evaluation, _beta_shadow, _beta_pointer = _publish_version_as_shadow(
            repository,
            beta_draft,
            suffix="candidate-stale-beta-v1",
        )
        candidate = _revise_candidate(
            repository,
            alpha_shadow,
            image_sha256="d" * 64,
            mask_sha256="e" * 64,
            idempotency_key="candidate-stale-alpha-v2",
        )
        _invalidate_without_pointer_cleanup(
            runtime,
            evaluation_id=beta_evaluation.evaluation_id,
            invalidation_id="candidate-stale-beta-stale",
        )

        with pytest.raises(
            TemplateEvaluationGateError,
            match="stale, incomplete, or invalidated",
        ):
            repository.list_current_shadow_versions_for_development_evaluation(
                candidates=(candidate,),
            )
    finally:
        runtime.close()


def test_candidate_replacement_does_not_bypass_pointer_structure_checks(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-candidate-structure")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    try:
        draft, _ = _create_draft(repository, key="candidate-structure-v1")
        _evaluation, shadow, _pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="candidate-structure-v1",
        )
        candidate = _revise_candidate(
            repository,
            shadow,
            image_sha256="d" * 64,
            mask_sha256="e" * 64,
            idempotency_key="candidate-structure-v2",
        )
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                text(
                    """
                    UPDATE template_version_states
                    SET lifecycle = 'development_tested'
                    WHERE version_id = :version_id
                    """
                ),
                {"version_id": shadow.version_id},
            )

        with pytest.raises(
            TemplateEvaluationGateError,
            match="does not reference a shadow version",
        ):
            repository.list_current_shadow_versions_for_development_evaluation(
                candidates=(candidate,),
            )
    finally:
        runtime.close()


def test_candidate_replacement_rejects_invalid_candidates_before_exemption(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-candidate-invalid")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    try:
        draft, _ = _create_draft(repository, key="candidate-invalid-v1")
        _evaluation, shadow, _pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="candidate-invalid-v1",
        )
        candidate = _revise_candidate(
            repository,
            shadow,
            image_sha256="d" * 64,
            mask_sha256="e" * 64,
            idempotency_key="candidate-invalid-v2",
        )

        with pytest.raises(
            TemplateEvaluationContractError,
            match="one version per family",
        ):
            repository.list_current_shadow_versions_for_development_evaluation(
                candidates=(candidate, candidate),
            )
        with pytest.raises(
            TemplateEvaluationContractError,
            match="draft or development_tested",
        ):
            repository.list_current_shadow_versions_for_development_evaluation(
                candidates=(shadow,),
            )
    finally:
        runtime.close()


@dataclass
class _InvalidateBeforePersistRepository:
    repository: SqliteTemplateRepository
    candidate: Any
    unrelated_evaluation_id: str

    @property
    def runtime(self) -> Any:
        return self.repository.runtime

    def get_version(self, version_id: str) -> Any:
        return self.repository.get_version(version_id)

    def list_current_eligible_shadow_versions(self) -> tuple[Any, ...]:
        return self.repository.list_current_shadow_versions_for_development_evaluation(
            candidates=(self.candidate,),
        )

    def _record_frozen_development_evaluation(self, **kwargs: Any) -> Any:
        _invalidate_without_pointer_cleanup(
            self.runtime,
            evaluation_id=self.unrelated_evaluation_id,
            invalidation_id="candidate-post-prepare-stale",
        )
        return self.repository._record_frozen_development_evaluation(**kwargs)


def test_persistence_revalidates_unrelated_shadow_after_preparation(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-candidate-commit-recheck")
    _seed_reference_image(
        runtime,
        "a" * 64,
        "b" * 64,
        "d" * 64,
        "e" * 64,
        "1" * 64,
        "2" * 64,
    )
    repository = _repository(runtime)
    try:
        alpha_draft, _ = _create_draft(repository, key="candidate-recheck-alpha-v1")
        _alpha_evaluation, alpha_shadow, _alpha_pointer = _publish_version_as_shadow(
            repository,
            alpha_draft,
            suffix="candidate-recheck-alpha-v1",
        )
        beta_draft = _create_family_draft(
            repository,
            family_id="scale-slip-beta",
            image_sha256="1" * 64,
            mask_sha256="2" * 64,
            idempotency_key="candidate-recheck-beta-v1",
        )
        beta_evaluation, _beta_shadow, _beta_pointer = _publish_version_as_shadow(
            repository,
            beta_draft,
            suffix="candidate-recheck-beta-v1",
        )
        candidate = _revise_candidate(
            repository,
            alpha_shadow,
            image_sha256="d" * 64,
            mask_sha256="e" * 64,
            idempotency_key="candidate-recheck-alpha-v2",
        )
        proxy = _InvalidateBeforePersistRepository(
            repository=repository,
            candidate=candidate,
            unrelated_evaluation_id=beta_evaluation.evaluation_id,
        )

        with pytest.raises(
            TemplateEvaluationContractError,
            match="current shadow set",
        ):
            _record_evaluation(
                proxy,
                candidate,
                evaluation_id="development-candidate-commit-recheck",
            )

        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_evaluations "
                        "WHERE evaluation_id = 'development-candidate-commit-recheck'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        runtime.close()
