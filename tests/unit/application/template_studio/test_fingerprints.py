from __future__ import annotations

from pathlib import Path

import pytest

from dahe.application.template_studio import fingerprints as fingerprint_module
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
    current_template_pipeline_build_fingerprint,
)
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildManifestError,
)

FORMAL_PIPELINE_CRITICAL_SOURCES = (
    "__init__.py",
    "adapters/files/content_addressed.py",
    "adapters/ocr/devices.py",
    "adapters/ocr/errors.py",
    "adapters/ocr/fingerprints.py",
    "adapters/ocr/locked_set_evaluator.py",
    "adapters/ocr/model_manifest.py",
    "adapters/ocr/profile_registry.py",
    "adapters/ocr/profiles.py",
    "adapters/ocr/protocol.py",
    "adapters/ocr/runtime_factory.py",
    "adapters/ocr/runtime_inventory.py",
    "adapters/ocr/runtime_layout.py",
    "adapters/ocr/runtime_paths.py",
    "adapters/ocr/scheduled_gateway.py",
    "adapters/ocr/source_fingerprint.py",
    "adapters/ocr/template_role_input.py",
    "adapters/ocr/worker_session.py",
    "adapters/sqlite/audit_workflow.py",
    "adapters/sqlite/candidate_development_ocr.py",
    "adapters/sqlite/locked_set.py",
    "adapters/sqlite/locked_set_review.py",
    "adapters/sqlite/loop3_schema.py",
    "adapters/sqlite/migrations/env.py",
    "adapters/sqlite/migrations/versions/0001_loop4_data_foundation.py",
    "adapters/sqlite/migrations/versions/0002_retry_requests_and_lease_fk.py",
    "adapters/sqlite/migrations/versions/0003_loop6_ocr_runs.py",
    "adapters/sqlite/migrations/versions/0004_loop6_image_quanta.py",
    "adapters/sqlite/migrations/versions/0005_loop7_template_studio.py",
    "adapters/sqlite/migrations/versions/0006_loop7_locked_set_authority.py",
    "adapters/sqlite/migrations/versions/0007_loop7_locked_set_review.py",
    "adapters/sqlite/migrations/versions/0008_loop7_review_authority.py",
    "adapters/sqlite/migrations/versions/0009_loop7_template_reference_origin.py",
    "adapters/sqlite/migrations/versions/0010_loop7_candidate_development_ocr_runs.py",
    "adapters/sqlite/migrations/versions/0011_loop7_terminal_attempt_ledgers.py",
    "adapters/sqlite/migrations/versions/0012_loop7_development_authority.py",
    "adapters/sqlite/migrations/versions/0013_loop7_authority_insert_guards.py",
    "adapters/sqlite/migrations/versions/0014_loop8_offline_audit.py",
    "adapters/sqlite/runtime.py",
    "adapters/sqlite/schema.py",
    "adapters/sqlite/template_evaluation.py",
    "adapters/sqlite/template_lifecycle_attempts.py",
    "adapters/sqlite/template_studio.py",
    "alembic.ini",
    "application/audit/layered_records.py",
    "application/audit/offline_batch.py",
    "application/template_studio/authorizing_registry.py",
    "application/template_studio/candidate_development_ocr.py",
    "application/template_studio/candidate_development_ocr_run_authority.py",
    "application/template_studio/candidate_review_export.py",
    "application/template_studio/candidate_review_seal.py",
    "application/template_studio/candidate_review_semantics.py",
    "application/template_studio/candidate_role_evaluation.py",
    "application/template_studio/candidate_role_metrics.py",
    "application/template_studio/candidate_role_ocr_evidence.py",
    "application/template_studio/candidate_role_source_authority.py",
    "application/template_studio/candidate_template_seed.py",
    "application/template_studio/composite_lifecycle_evaluation.py",
    "application/template_studio/development_authority_rollover.py",
    "application/template_studio/development_evaluation.py",
    "application/template_studio/fingerprints.py",
    "application/template_studio/formal_development_authority.py",
    "application/template_studio/formal_locked_set_release.py",
    "application/template_studio/locked_set_evidence.py",
    "application/template_studio/locked_set_release.py",
    "application/template_studio/matcher.py",
    "application/template_studio/reference_images.py",
    "bootstrap.py",
    "config/paths.py",
    "config/schema.py",
    "domain/audit/errors.py",
    "domain/audit/evidence.py",
    "domain/audit/ticket_roles.py",
    "domain/audit/weights.py",
    "domain/ticket/role_assessment.py",
    "domain/ticket/templates.py",
    "jobs/ocr_errors.py",
    "jobs/ocr_execution.py",
    "ocr-runtime/model-spec.json",
    "ocr-runtime/src/dahe_ocr_worker/engine.py",
    "ocr-runtime/src/dahe_ocr_worker/model_manifest.py",
    "ocr-runtime/src/dahe_ocr_worker/protocol.py",
    "system/environment.py",
    "system/instance_lock.py",
    "system/port_guard.py",
    "system/supervision.py",
    "system/versioning.py",
    "tools/loop7_controlled_non_ticket_challenge.py",
    "tools/loop7_locked_set_release.py",
    "tools/loop7_shadow_authority_rollover.py",
    "verification/application_build.py",
    "verification/controlled_non_ticket_challenge.py",
    "verification/controlled_non_ticket_gate.py",
    "verification/image_similarity.py",
    "verification/locked_set.py",
    "verification/locked_set_acceptance.py",
    "verification/locked_set_review_package.py",
    "verification/locked_set_runner.py",
    "verification/locked_set_similarity_scan.py",
)


def test_template_runtime_set_fingerprint_is_order_independent_and_bound() -> None:
    cpu = {
        "profile_id": "cpu-portable",
        "runtime_fingerprint": "1" * 64,
        "runtime_kind": "cpu",
    }
    gpu = {
        "profile_id": "gpu-qualified",
        "runtime_fingerprint": "2" * 64,
        "runtime_kind": "gpu",
    }

    expected = current_template_ocr_runtime_set_fingerprint((cpu, gpu))

    assert current_template_ocr_runtime_set_fingerprint((gpu, cpu)) == expected
    assert (
        current_template_ocr_runtime_set_fingerprint(
            (
                cpu,
                {
                    **gpu,
                    "runtime_fingerprint": "3" * 64,
                },
            )
        )
        != expected
    )


def test_template_runtime_set_requires_qualified_sha256_identity() -> None:
    with pytest.raises(ValueError, match="at least one"):
        current_template_ocr_runtime_set_fingerprint(())
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        current_template_ocr_runtime_set_fingerprint(
            (
                {
                    "profile_id": "cpu-portable",
                    "runtime_fingerprint": "not-a-runtime-hash",
                    "runtime_kind": "cpu",
                },
            )
        )


def test_template_pipeline_build_includes_installed_role_and_ocr_sources() -> None:
    fingerprint = current_template_pipeline_build_fingerprint(
        application_version="test-build",
    )
    source_names = {logical_path for logical_path, _path in fingerprint_module._pipeline_sources()}

    assert len(fingerprint) == 64
    assert fingerprint == fingerprint.lower()
    assert {
        "adapters/ocr/fingerprints.py",
        "adapters/ocr/locked_set_evaluator.py",
        "adapters/ocr/scheduled_gateway.py",
        "adapters/sqlite/candidate_development_ocr.py",
        "adapters/sqlite/locked_set.py",
        "adapters/sqlite/locked_set_review.py",
        "adapters/sqlite/schema.py",
        "adapters/sqlite/template_evaluation.py",
        "adapters/sqlite/template_lifecycle_attempts.py",
        "adapters/sqlite/template_studio.py",
        "application/template_studio/candidate_development_ocr.py",
        "application/template_studio/candidate_development_ocr_run_authority.py",
        "application/template_studio/candidate_review_export.py",
        "application/template_studio/candidate_review_seal.py",
        "application/template_studio/candidate_review_semantics.py",
        "application/template_studio/candidate_role_evaluation.py",
        "application/template_studio/candidate_role_metrics.py",
        "application/template_studio/candidate_role_ocr_evidence.py",
        "application/template_studio/candidate_role_source_authority.py",
        "application/template_studio/candidate_template_seed.py",
        "application/template_studio/composite_lifecycle_evaluation.py",
        "application/template_studio/formal_locked_set_release.py",
        "verification/image_similarity.py",
        "verification/locked_set_acceptance.py",
        "verification/locked_set_runner.py",
        "verification/locked_set_similarity_scan.py",
    } <= source_names


def test_release_installed_module_locates_the_release_source_root(
    tmp_path: Path,
) -> None:
    release_root = tmp_path / "release"
    module_path = (
        release_root
        / ".venv"
        / "Lib"
        / "site-packages"
        / "dahe"
        / "application"
        / "template_studio"
        / "fingerprints.py"
    )
    module_path.parent.mkdir(parents=True)
    module_path.write_text("# installed module\n", encoding="utf-8")
    (release_root / "src" / "dahe").mkdir(parents=True)
    (release_root / "src" / "dahe" / "__init__.py").write_text(
        "",
        encoding="utf-8",
    )
    (release_root / "ocr-runtime").mkdir()
    (release_root / "ocr-runtime" / "model-spec.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (release_root / "alembic.ini").write_text("[alembic]\n", encoding="utf-8")

    assert fingerprint_module._locate_project_root(module_path) == release_root


def test_frozen_pipeline_locates_sources_beside_the_application_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_root = tmp_path / "release"
    executable = release_root / "DaHeApp.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"frozen")
    (release_root / "src" / "dahe").mkdir(parents=True)
    (release_root / "src" / "dahe" / "__init__.py").write_text(
        "",
        encoding="utf-8",
    )
    (release_root / "ocr-runtime").mkdir()
    (release_root / "ocr-runtime" / "model-spec.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (release_root / "alembic.ini").write_text("[alembic]\n", encoding="utf-8")
    monkeypatch.setattr(fingerprint_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(fingerprint_module.sys, "executable", str(executable))

    assert (
        fingerprint_module._locate_project_root(
            fingerprint_module._runtime_project_location()
        )
        == release_root
    )


def test_formal_pipeline_build_manifest_is_explicit_and_complete() -> None:
    source_names = tuple(
        logical_path for logical_path, _path in fingerprint_module._pipeline_sources()
    )

    assert source_names == FORMAL_PIPELINE_CRITICAL_SOURCES


@pytest.mark.parametrize("logical_path", FORMAL_PIPELINE_CRITICAL_SOURCES)
def test_each_formal_pipeline_source_byte_changes_the_build_fingerprint(
    logical_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = dict(fingerprint_module._pipeline_sources())
    target = sources[logical_path]
    baseline = current_template_pipeline_build_fingerprint(
        application_version="test-build",
    )
    original_read_bytes = Path.read_bytes

    def mutated_read_bytes(path: Path) -> bytes:
        content = original_read_bytes(path)
        if path.resolve() == target.resolve():
            return content + b"\x00"
        return content

    monkeypatch.setattr(Path, "read_bytes", mutated_read_bytes)

    assert (
        current_template_pipeline_build_fingerprint(
            application_version="test-build",
        )
        != baseline
    )


def test_formal_pipeline_manifest_payload_is_visible_and_hash_bound() -> None:
    builder = getattr(
        fingerprint_module,
        "current_template_pipeline_build_manifest",
        None,
    )

    assert callable(builder)
    manifest = builder(application_version="test-build")
    payload = manifest.to_payload()

    assert payload["schema_version"] == 1
    assert payload["application_version"] == "test-build"
    assert tuple(source["path"] for source in payload["sources"]) == (
        FORMAL_PIPELINE_CRITICAL_SOURCES
    )
    assert manifest.canonical_sha256 == current_template_pipeline_build_fingerprint(
        application_version="test-build",
    )


def test_formal_pipeline_manifest_rejects_boolean_schema_version() -> None:
    manifest = fingerprint_module.current_template_pipeline_build_manifest(
        application_version="test-build",
    )
    payload = manifest.to_payload()
    payload["schema_version"] = True

    with pytest.raises(ApplicationBuildManifestError, match="version"):
        ApplicationBuildManifest.from_payload(payload)


def test_missing_explicit_formal_source_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        fingerprint_module,
        "TEMPLATE_PIPELINE_SOURCE_MANIFEST",
        ("verification/missing-formal-source.py",),
    )

    with pytest.raises(
        fingerprint_module.TemplatePipelineBuildError,
        match="unavailable",
    ):
        current_template_pipeline_build_fingerprint(
            application_version="test-build",
        )
