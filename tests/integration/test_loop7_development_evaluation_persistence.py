from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text

from dahe.adapters.sqlite.candidate_development_ocr import (
    CandidateDevelopmentOcrRunAuthorityInput,
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_evaluation import (
    _PREPARED_COMPOSITE_SEAL,
    PreparedCompositeLifecycleEvaluation,
    _persist_code_owned_development_evaluation,
    persist_composite_lifecycle_evaluation,
    run_and_persist_frozen_development_evaluation,
)
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateEvaluationGateError,
)
from dahe.application.template_studio import authorizing_registry
from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
)
from dahe.application.template_studio.candidate_template_seed import (
    load_template_definition,
)
from dahe.application.template_studio.composite_lifecycle_evaluation import (
    build_composite_lifecycle_evaluation,
)
from dahe.application.template_studio.development_evaluation import (
    FrozenDevelopmentFixtureError,
    development_matcher_fingerprint,
    development_policy_fingerprint,
    load_authorizing_development_dataset,
    load_frozen_development_fixture,
    run_authorizing_development_evaluation,
    run_frozen_development_evaluation,
)
from dahe.domain.ticket.templates import TemplateLifecycle, TemplateVersion
from tests.fixtures.loop7_current_candidate_templates import (
    current_candidate_versions,
)
from tests.unit.application.template_studio.test_composite_lifecycle_evaluation import (
    _real_component,
)

FROZEN_MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "verification"
    / "loops"
    / "loop-7"
    / "20260725T232143+0800"
    / "fixture-manifest.json"
)
APPROVED_MANIFEST = approved_authorizing_development_dataset_path()


def test_code_approved_dataset_uses_current_real_anchor_contract() -> None:
    dataset = load_authorizing_development_dataset(APPROVED_MANIFEST)
    samples = {
        sample.sample_id: sample
        for case in dataset.observation_cases
        for sample in case.rotations
    }

    assert APPROVED_MANIFEST.name == "authorizing-development-dataset-v4.json"
    loading_anchor = samples["loading-clear@0"].role_input.text_lines[0]
    success_anchor = samples[
        "loading-save-success@0"
    ].role_input.text_lines[0]
    prompt_anchor = samples[
        "loading-prompt-information@0"
    ].role_input.text_lines[0]
    unloading_anchor = samples["unloading-clear@0"].role_input.text_lines[0]
    assert loading_anchor.text == "客户名称"
    assert loading_anchor.box.x == Decimal("0.199")
    assert loading_anchor.box.y == Decimal("0.572666667")
    assert success_anchor.text == "保存成功"
    assert success_anchor.box.x == Decimal("0.106481481")
    assert success_anchor.box.y == Decimal("0.646875")
    assert prompt_anchor.text == "提示信息"
    assert prompt_anchor.box.x == Decimal("0")
    assert prompt_anchor.box.y == Decimal("0.564")
    assert unloading_anchor.text == "工厂净重"
    assert unloading_anchor.box.x == Decimal("0.486")
    assert unloading_anchor.box.y == Decimal("0.548666667")


def test_code_approved_dataset_matches_versioned_development_templates(
    project_root: Path,
) -> None:
    template_root = project_root / "verification" / "loops" / "loop-7"
    candidate_contracts = (
        ("loading-customer", "development-loading-template-v1.json"),
        (
            "loading-success",
            "development-loading-success-template-v1.json",
        ),
        (
            "loading-prompt",
            "development-loading-prompt-template-v1.json",
        ),
        ("unloading-factory", "development-unloading-template-v1.json"),
    )
    candidates = tuple(
        TemplateVersion(
            version_id=f"test-{candidate_name}-candidate-v1",
            definition=load_template_definition(
                (template_root / definition_name).resolve(strict=True)
            ),
            lifecycle=TemplateLifecycle.DRAFT,
            parent_version_id=None,
            record_version=1,
        )
        for candidate_name, definition_name in candidate_contracts
    )
    report = run_authorizing_development_evaluation(
        load_authorizing_development_dataset(APPROVED_MANIFEST),
        candidates=candidates,
    )

    assert report.gate_passed is True
    assert report.expected_count == report.result_count == 19
    assert {
        (item.sample_id, item.result_role.value)
        for item in report.items
    }.issuperset(
        {
            ("loading-clear@0", "loading"),
            ("loading-save-success@0", "loading"),
            ("loading-prompt-information@0", "loading"),
            ("unloading-clear@0", "unloading"),
            ("unknown-layout@0", "unknown"),
            ("non-ticket@0", "unknown"),
            ("mixed-conflict@0", "unknown"),
        }
    )
    assert all(item.expected_matches_result for item in report.items)
    assert all(item.expected_matches_result for item in report.pair_items)


def _seed_reference(runtime: SqliteRuntime, sha256: str) -> None:
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            text(
                """
                INSERT INTO evidence_blobs (
                    sha256, relative_path, byte_size, media_type,
                    storage_state, record_version, created_at, verified_at
                ) VALUES (
                    :sha256, :relative_path, 1, 'image/png',
                    'available', 1, :created_at, :verified_at
                )
                """
            ),
            {
                "sha256": sha256,
                "relative_path": f"loop7/{sha256}.png",
                "created_at": "2026-07-25T12:00:00+00:00",
                "verified_at": "2026-07-25T12:00:00+00:00",
            },
        )


def test_frozen_synthetic_evaluation_is_persisted_as_non_authorizing_diagnostic(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop7-development-evaluation",
    )
    source_candidates = tuple(
        replace(
            candidate,
            version_id=f"ui-version-{uuid4().hex}",
            definition=replace(
                candidate.definition,
                family_id=f"ui-family-{uuid4().hex}",
            ),
        )
        for candidate in current_candidate_versions()
    )
    dataset = load_authorizing_development_dataset(APPROVED_MANIFEST)
    repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="a" * 64,
        accepted_runtime_fingerprint="b" * 64,
        accepted_development_manifest_sha256=dataset.manifest_sha256,
        accepted_matcher_fingerprint=development_matcher_fingerprint(),
        accepted_policy_fingerprint=development_policy_fingerprint(),
    )
    try:
        persisted_candidates = []
        for index, candidate in enumerate(source_candidates, start=1):
            reference_sha256 = str(index) * 64
            mask_sha256 = chr(ord("a") + index - 1) * 64
            _seed_reference(runtime, reference_sha256)
            _seed_reference(runtime, mask_sha256)
            version, created = repository.create_draft(
                definition=candidate.definition,
                reference_image_sha256=reference_sha256,
                reference_mask_sha256=mask_sha256,
                alignment_fingerprint=str(index + 4) * 64,
                actor_id="loop7-evaluator",
                idempotency_key=f"create-evaluation-candidate-{index}",
            )
            assert created is True
            persisted_candidates.append(version)

        report, evaluation = run_and_persist_frozen_development_evaluation(
            repository,
            manifest_path=APPROVED_MANIFEST,
            candidate_version_ids=tuple(
                version.version_id for version in persisted_candidates
            ),
            actor_id="loop7-evaluator",
        )

        assert report.gate_passed is True
        assert evaluation.gate_passed is True
        assert evaluation.verification_source == "frozen_runner"
        assert (
            evaluation.stable_outcome_sha256
            == report.stable_outcome_sha256
        )
        assert evaluation.expected_count == evaluation.result_count == 19
        assert evaluation.metrics["sample_count"] == 19
        assert {
            item.sample_id for item in report.items
        } == {
            "loading-clear@0",
            "loading-clear@90",
            "loading-clear@180",
            "loading-clear@270",
            "loading-save-success@0",
            "loading-save-success@90",
            "loading-save-success@180",
            "loading-save-success@270",
            "loading-prompt-information@0",
            "loading-prompt-information@90",
            "loading-prompt-information@180",
            "loading-prompt-information@270",
            "unloading-clear@0",
            "unloading-clear@90",
            "unloading-clear@180",
            "unloading-clear@270",
            "unknown-layout@0",
            "non-ticket@0",
            "mixed-conflict@0",
        }
        assert all(
            item.truth_source == "code_authored_synthetic"
            and item.identity_kind == "synthetic_observation_sha256"
            for item in report.items
        )
        assert {
            (pair.case_id, pair.expected_issue, pair.result_issue)
            for pair in report.pair_items
        } == {
            ("normal-pair", None, None),
            ("swapped-pair", "suspected_swapped", "suspected_swapped"),
        }

        for draft in persisted_candidates:
            latest = repository.get_latest_valid_development_evaluation(draft.version_id)
            assert latest is None

        restarted_repository = SqliteTemplateRepository(
            runtime=runtime,
            accepted_build_fingerprint="a" * 64,
            accepted_runtime_fingerprint="b" * 64,
            accepted_matcher_fingerprint=development_matcher_fingerprint(),
            accepted_policy_fingerprint=development_policy_fingerprint(),
        )
        assert (
            restarted_repository.accepted_development_manifest_sha256
            == dataset.manifest_sha256
        )
        for draft in persisted_candidates:
            restarted = (
                restarted_repository.get_latest_valid_development_evaluation(
                    draft.version_id
                )
            )
            assert restarted is None
    finally:
        runtime.close()


def test_legacy_synthetic_only_record_cannot_authorize_lifecycle(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop7-legacy-synthetic-rejection",
    )
    dataset = load_authorizing_development_dataset(APPROVED_MANIFEST)
    repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="a" * 64,
        accepted_runtime_fingerprint="b" * 64,
        accepted_development_manifest_sha256=dataset.manifest_sha256,
        accepted_matcher_fingerprint=development_matcher_fingerprint(),
        accepted_policy_fingerprint=development_policy_fingerprint(),
    )
    try:
        candidates = []
        for index, candidate in enumerate(
            current_candidate_versions(),
            start=1,
        ):
            reference_sha256 = str(index) * 64
            mask_sha256 = chr(ord("a") + index - 1) * 64
            _seed_reference(runtime, reference_sha256)
            _seed_reference(runtime, mask_sha256)
            version, _ = repository.create_draft(
                definition=candidate.definition,
                reference_image_sha256=reference_sha256,
                reference_mask_sha256=mask_sha256,
                alignment_fingerprint=str(index + 4) * 64,
                actor_id="loop7-evaluator",
                idempotency_key=f"legacy-candidate-{index}",
            )
            candidates.append(version)
        _, evaluation = run_and_persist_frozen_development_evaluation(
            repository,
            manifest_path=APPROVED_MANIFEST,
            candidate_version_ids=tuple(
                candidate.version_id for candidate in candidates
            ),
            actor_id="loop7-evaluator",
        )

        assert (
            repository.get_latest_valid_development_evaluation(
                candidates[0].version_id
            )
            is None
        )
        with pytest.raises(
            TemplateEvaluationGateError,
            match=r"unverified|invalidated",
        ):
            repository.mark_development_tested(
                version_id=candidates[0].version_id,
                expected_record_version=1,
                evaluation_id=evaluation.evaluation_id,
                developer_authorization_id="loop7-test-authorization",
                actor_id="loop7-evaluator",
                idempotency_key="legacy-cannot-promote",
            )
    finally:
        runtime.close()


def test_composite_parent_is_the_only_authorizing_evaluation_identity(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop7-composite-parent",
    )
    base_repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="a" * 64,
    )
    try:
        candidates = []
        for index, candidate in enumerate(
            current_candidate_versions(),
            start=1,
        ):
            reference_sha256 = str(index) * 64
            mask_sha256 = chr(ord("a") + index - 1) * 64
            _seed_reference(runtime, reference_sha256)
            _seed_reference(runtime, mask_sha256)
            version, _ = base_repository.create_draft(
                definition=candidate.definition,
                reference_image_sha256=reference_sha256,
                reference_mask_sha256=mask_sha256,
                alignment_fingerprint=str(index + 4) * 64,
                actor_id="loop7-evaluator",
                idempotency_key=f"composite-candidate-{index}",
            )
            candidates.append(version)
        dataset = load_authorizing_development_dataset(APPROVED_MANIFEST)
        synthetic = run_authorizing_development_evaluation(
            dataset,
            candidates=tuple(candidates),
        )
        real = _real_component(synthetic)
        build_sha256 = str(
            real.payload["source"]["role_evaluator_build_sha256"]
        )
        runtime_sha256 = str(
            real.payload["source"]["runtime_set_sha256"]
        )
        composite = build_composite_lifecycle_evaluation(
            real_component=real,
            synthetic_component=synthetic,
            expected_role_evaluator_build_sha256=build_sha256,
            expected_runtime_set_sha256=runtime_sha256,
        )
        authorizing_repository = SqliteTemplateRepository(
            runtime=runtime,
            accepted_build_fingerprint=build_sha256,
            accepted_runtime_fingerprint=runtime_sha256,
            accepted_development_manifest_sha256=(
                composite.dataset_manifest_sha256
            ),
            accepted_matcher_fingerprint=synthetic.matcher_fingerprint,
            accepted_policy_fingerprint=synthetic.policy_fingerprint,
        )
        prepared = PreparedCompositeLifecycleEvaluation(
            real_component=real,
            synthetic_component=synthetic,
            composite=composite,
            _seal=_PREPARED_COMPOSITE_SEAL,
        )
        real_source = real.payload["source"]
        evidence_sha256 = str(
            real_source["ocr_evidence_sha256"]
        )
        SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        ).record_completed_run(
            CandidateDevelopmentOcrRunAuthorityInput(
                evidence_sha256=evidence_sha256,
                evidence_blob_sha256="f" * 64,
                evidence_relative_path=(
                    "development/protected-candidate-review-ocr/"
                    f"records/sha256/{evidence_sha256[:2]}/"
                    f"{evidence_sha256[2:4]}/{evidence_sha256}.json"
                ),
                evidence_byte_size=4096,
                package_sha256=str(
                    real_source["package_sha256"]
                ),
                review_history_authority_sha256=str(
                    real_source[
                        "review_history_authority_sha256"
                    ]
                ),
                source_authority_sha256=str(
                    real_source["source_authority_sha256"]
                ),
                reviewer_id="reviewer-sensitive",
                application_build_sha256=str(
                    real_source["ocr_capture_build_sha256"]
                ),
                composition_evidence_sha256=str(
                    real_source["composition_evidence_sha256"]
                ),
                runtime_set_sha256=str(
                    real_source["runtime_set_sha256"]
                ),
                pipeline_contract_sha256=str(
                    real_source[
                        "ocr_pipeline_contract_sha256"
                    ]
                ),
                completion_status="completed",
                completed_at="2026-07-26T12:00:00+00:00",
            )
        )

        evaluation = persist_composite_lifecycle_evaluation(
            authorizing_repository,
            prepared,
            actor_id="loop7-evaluator",
        )

        assert evaluation.evaluation_id == composite.evaluation_id
        assert evaluation.evaluation_id != real.evaluation_sha256
        assert evaluation.evaluation_id != synthetic.stable_outcome_sha256
        latest = (
            authorizing_repository.get_latest_valid_development_evaluation(
                candidates[0].version_id
            )
        )
        assert latest is not None
        assert latest.evaluation_id == composite.evaluation_id
    finally:
        runtime.close()


def test_generated_synthetic_fixture_cannot_persist_authorizing_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop7-generated-regression-rejection",
    )
    regression_fixture = load_frozen_development_fixture(FROZEN_MANIFEST)
    repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="a" * 64,
        accepted_runtime_fingerprint="b" * 64,
        accepted_development_manifest_sha256=regression_fixture.manifest_sha256,
        accepted_matcher_fingerprint=development_matcher_fingerprint(),
        accepted_policy_fingerprint=development_policy_fingerprint(),
    )
    try:
        with pytest.raises(
            FrozenDevelopmentFixtureError,
            match="code-approved",
        ):
            run_and_persist_frozen_development_evaluation(
                repository,
                manifest_path=FROZEN_MANIFEST,
                candidate_version_ids=("does-not-matter",),
                actor_id="loop7-evaluator",
            )
        with runtime.engine.connect() as connection:
            count = connection.execute(
                text("SELECT COUNT(*) FROM template_evaluations")
            ).scalar_one()
        assert count == 0
    finally:
        runtime.close()


def test_generated_report_cannot_cross_private_frozen_persistence_boundary(
    tmp_path: Path,
    project_root: Path,
) -> None:
    report = run_frozen_development_evaluation(FROZEN_MANIFEST)
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop7-generated-report-rejection",
    )
    repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="a" * 64,
        accepted_runtime_fingerprint="b" * 64,
        accepted_development_manifest_sha256=report.dataset_manifest_sha256,
        accepted_matcher_fingerprint=development_matcher_fingerprint(),
        accepted_policy_fingerprint=development_policy_fingerprint(),
    )
    try:
        with pytest.raises(
            FrozenDevelopmentFixtureError,
            match="only an authorizing_observation_dataset",
        ):
            _persist_code_owned_development_evaluation(
                repository,
                report,
                actor_id="loop7-evaluator",
            )
        with runtime.engine.connect() as connection:
            count = connection.execute(
                text("SELECT COUNT(*) FROM template_evaluations")
            ).scalar_one()
        assert count == 0
    finally:
        runtime.close()


def test_external_copy_of_approved_dataset_cannot_persist_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    copied_manifest = tmp_path / "copied-authorizing-dataset.json"
    shutil.copyfile(APPROVED_MANIFEST, copied_manifest)
    dataset = load_authorizing_development_dataset(APPROVED_MANIFEST)
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="loop7-external-authorizing-rejection",
    )
    repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="a" * 64,
        accepted_runtime_fingerprint="b" * 64,
        accepted_development_manifest_sha256=dataset.manifest_sha256,
        accepted_matcher_fingerprint=development_matcher_fingerprint(),
        accepted_policy_fingerprint=development_policy_fingerprint(),
    )
    try:
        with pytest.raises(
            FrozenDevelopmentFixtureError,
            match="code-approved",
        ):
            run_and_persist_frozen_development_evaluation(
                repository,
                manifest_path=copied_manifest,
                candidate_version_ids=("does-not-matter",),
                actor_id="loop7-evaluator",
            )
        with runtime.engine.connect() as connection:
            count = connection.execute(
                text("SELECT COUNT(*) FROM template_evaluations")
            ).scalar_one()
        assert count == 0
    finally:
        runtime.close()


def test_tampered_registered_dataset_cannot_persist_evidence(
    tmp_path: Path,
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_project_root = tmp_path / "code-root"
    tampered_manifest = (
        fake_project_root
        / "verification"
        / "loops"
        / "loop-7"
        / APPROVED_MANIFEST.name
    )
    tampered_manifest.parent.mkdir(parents=True)
    shutil.copyfile(APPROVED_MANIFEST, tampered_manifest)
    tampered_manifest.write_bytes(
        tampered_manifest.read_bytes().replace(
            b"Code-authored synthetic OCR observations",
            b"Tampered synthetic OCR observations",
        )
    )
    monkeypatch.setattr(
        authorizing_registry,
        "_PROJECT_ROOT",
        fake_project_root,
    )

    dataset = load_authorizing_development_dataset(APPROVED_MANIFEST)
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="loop7-tampered-authorizing-rejection",
    )
    repository = SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="a" * 64,
        accepted_runtime_fingerprint="b" * 64,
        accepted_development_manifest_sha256=dataset.manifest_sha256,
        accepted_matcher_fingerprint=development_matcher_fingerprint(),
        accepted_policy_fingerprint=development_policy_fingerprint(),
    )
    try:
        with pytest.raises(
            FrozenDevelopmentFixtureError,
            match="SHA-256",
        ):
            run_and_persist_frozen_development_evaluation(
                repository,
                manifest_path=tampered_manifest,
                candidate_version_ids=("does-not-matter",),
                actor_id="loop7-evaluator",
            )
        with runtime.engine.connect() as connection:
            count = connection.execute(
                text("SELECT COUNT(*) FROM template_evaluations")
            ).scalar_one()
        assert count == 0
    finally:
        runtime.close()


def test_persist_cli_rejects_external_manifest_before_creating_data_root(
    tmp_path: Path,
    project_root: Path,
) -> None:
    external_manifest = tmp_path / "external-authorizing-dataset.json"
    shutil.copyfile(APPROVED_MANIFEST, external_manifest)
    data_root = tmp_path / "must-not-be-created"
    output = tmp_path / "must-not-be-written.json"

    result = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "loop7_development_evaluation.py"),
            "--persist",
            "--manifest",
            str(external_manifest),
            "--output",
            str(output),
            "--data-root",
            str(data_root),
            "--candidate-version",
            "not-loaded-before-registry-check",
        ],
        cwd=project_root,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode != 0
    assert "code-approved" in f"{result.stdout}\n{result.stderr}"
    assert data_root.exists() is False
    assert output.exists() is False
