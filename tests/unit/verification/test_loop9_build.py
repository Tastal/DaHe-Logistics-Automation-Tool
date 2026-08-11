from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import dahe.verification.loop9_build as loop9_build
from dahe import __version__
from dahe.verification.loop9_build import (
    LOOP9_SOURCE_MANIFEST,
    Loop9BuildError,
    current_loop9_build_manifest,
    current_loop9_build_sha256,
    runtime_loop9_build_sha256,
)

PROJECT_ROOT = Path(__file__).parents[3]


def test_runtime_build_identity_uses_and_verifies_a_sealed_release_manifest(
    tmp_path: Path,
) -> None:
    release = (tmp_path / "release").resolve()
    release.mkdir()
    payload = release / "payload.txt"
    payload.write_bytes(b"sealed payload")
    source_build_sha256 = "b" * 64
    (release / "runtime-manifest.json").write_text(
        json.dumps(
            {
                "application_version": __version__,
                "build_git_commit": "a" * 40,
                "files": {
                    "payload.txt": hashlib.sha256(payload.read_bytes()).hexdigest()
                },
                "kind": "dahe_local_production_read_only_release",
                "module_modes": {
                    "audit": "operational",
                    "daily": "operational",
                    "dispatch": "disabled",
                    "settlement": "disabled",
                },
                "schema_version": 1,
                "source_build_sha256": source_build_sha256,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    assert runtime_loop9_build_sha256(release) == source_build_sha256

    payload.write_bytes(b"tampered payload")
    with pytest.raises(Loop9BuildError, match="payload changed"):
        runtime_loop9_build_sha256(release)

CRITICAL_LOOP9_RUNTIME_SOURCES = (
    "alembic.ini",
    "pyproject.toml",
    "requirements.lock",
    "version-manifest.json",
    "frontend/index.html",
    "frontend/package-lock.json",
    "frontend/package.json",
    "frontend/src/main.tsx",
    "src/dahe/__main__.py",
    "src/dahe/__init__.py",
    "src/dahe/adapters/fake/audit.py",
    "src/dahe/adapters/fake/loop3.py",
    "src/dahe/adapters/files/content_addressed.py",
    "src/dahe/adapters/files/settlement_capture_manifest.py",
    "src/dahe/adapters/files/shadow_batch_manifest.py",
    "src/dahe/adapters/files/shadow_selection_manifest.py",
    "src/dahe/adapters/sqlite/settlement_capture.py",
    "src/dahe/adapters/sqlite/loop4_recovery_store.py",
    "src/dahe/adapters/sqlite/migrations/env.py",
    "src/dahe/adapters/sqlite/recovery.py",
    "src/dahe/api/loop9_review.py",
    "src/dahe/api/locked_set_review.py",
    "src/dahe/adapters/sqlite/runtime.py",
    "src/dahe/application/chengfeng/identity_authority.py",
    "src/dahe/application/chengfeng/settlement_capture.py",
    "src/dahe/application/chengfeng/settlement_live_execution.py",
    "src/dahe/application/chengfeng/shadow_selection.py",
    "src/dahe/application/chengfeng/shadow_selection_lifecycle.py",
    "src/dahe/bootstrap.py",
    "src/dahe/cli.py",
    "src/dahe/config/paths.py",
    "src/dahe/diagnostics/outbox_bridge.py",
    "src/dahe/domain/ticket/role_assessment.py",
    "src/dahe/domain/ticket/templates.py",
    "src/dahe/ports/jobs.py",
    "src/dahe/server.py",
    "src/dahe/system/environment.py",
    "src/dahe/system/instance_lock.py",
    "src/dahe/system/instance_lifecycle.py",
    "src/dahe/system/port_guard.py",
    "src/dahe/system/test_fixture_root.py",
    "src/dahe/system/versioning.py",
)
CRITICAL_LOOP9_MIGRATION_SOURCES = (
    "src/dahe/adapters/sqlite/migrations/versions/0018_loop9_daily_window_fks.py",
    "src/dahe/adapters/sqlite/migrations/versions/0019_loop9_settlement_capture.py",
    "src/dahe/adapters/sqlite/migrations/versions/0020_loop9_exclusion_authority_anchor.py",
    "src/dahe/adapters/sqlite/migrations/versions/0021_loop9_settlement_selection_state.py",
    "src/dahe/adapters/sqlite/migrations/versions/0022_loop9_selection_lifecycle.py",
    "src/dahe/adapters/sqlite/migrations/versions/0023_loop9_daily_access_rollover.py",
    "src/dahe/adapters/sqlite/migrations/versions/0024_loop9_historical_settlement_scope.py",
    "src/dahe/adapters/sqlite/migrations/versions/0025_operational_compat_capture.py",
    "src/dahe/adapters/sqlite/migrations/versions/0026_business_connection_session.py",
    "src/dahe/adapters/sqlite/migrations/versions/0027_platform_credentials.py",
    "src/dahe/adapters/sqlite/migrations/versions/0028_operational_batch_capture.py",
    "src/dahe/adapters/sqlite/migrations/versions/0029_daily_operational_ocr_batches.py",
    "src/dahe/adapters/sqlite/migrations/versions/0030_credential_idempotency_results.py",
    "src/dahe/adapters/sqlite/migrations/versions/0031_loop9_authority_contexts.py",
    "src/dahe/adapters/sqlite/migrations/versions/0032_production_daily_reports.py",
    "src/dahe/adapters/sqlite/migrations/versions/0033_production_read_only_guard.py",
)
CRITICAL_LOOP9_FAST_BUSINESS_SOURCES = (
    "docs/adr/ADR-043-headless-batch-business-reads.md",
    "docs/adr/ADR-044-build-scoped-exclusion-anchor-chains.md",
    "src/dahe/adapters/sqlite/daily_operational_ocr.py",
    "src/dahe/adapters/sqlite/platform_credentials.py",
    "src/dahe/adapters/windows/__init__.py",
    "src/dahe/adapters/windows/credential_manager.py",
    "src/dahe/application/chengfeng/credential_service.py",
    "src/dahe/application/daily/operational_capture.py",
    "src/dahe/ports/platform_credentials.py",
)
CRITICAL_LOOP9_VERIFICATION_SOURCES = (
    "docs/adr/ADR-030-loop9-daily-read-contract.md",
    "docs/adr/ADR-031-loop9-generation-bound-formal-gates.md",
    "docs/adr/ADR-032-loop9-atomic-shadow-acceptance.md",
    "docs/adr/ADR-033-access-window-rollover-lineage.md",
    "docs/adr/ADR-034-exact-image-capability-request-audit.md",
    "docs/adr/ADR-035-chengfeng-detail-form-encoding-rollover.md",
    "docs/adr/ADR-036-bounded-historical-locked-set-source.md",
    "docs/adr/ADR-037-operational-compat-read-connector.md",
    "src/dahe/verification/application_build.py",
    "src/dahe/verification/daily_snapshot_validation.py",
    "src/dahe/verification/ledger.py",
    "src/dahe/verification/image_similarity.py",
    "src/dahe/verification/locked_set.py",
    "src/dahe/verification/locked_set_acceptance.py",
    "src/dahe/verification/locked_set_review_package.py",
    "src/dahe/verification/locked_set_runner.py",
    "src/dahe/verification/locked_set_similarity_scan.py",
    "src/dahe/verification/loop9_dataset_artifacts.py",
    "src/dahe/verification/loop9_dataset_isolation.py",
    "src/dahe/verification/loop9_draft_suggestions.py",
    "src/dahe/verification/loop9_exclusion_authority.py",
    "src/dahe/verification/loop9_fault_injection.py",
    "src/dahe/verification/loop9_final_acceptance.py",
    "src/dahe/verification/loop9_human_review.py",
    "src/dahe/verification/loop9_locked_gate.py",
    "src/dahe/verification/loop9_locked_selection_rollover.py",
    "src/dahe/verification/loop9_operational_evidence.py",
    "src/dahe/verification/loop9_request_audit.py",
    "src/dahe/adapters/files/platform_request_audit.py",
    "tools/loop7_locked_set_release.py",
    "tools/loop7_shadow_authority_rollover.py",
    "tools/loop9_build_dataset_artifacts.py",
    "tools/loop9_build_exclusion_authority.py",
    "tools/loop9_build_operational_evidence.py",
    "tools/loop9_final_acceptance.py",
    "tools/loop9_run_fault_injections.py",
    "tools/loop9_draft_suggestions.py",
    "tools/loop9_human_review.py",
    "tools/loop9_invalidate_locked_selection.py",
    "tools/loop9_register_discovery_exclusion.py",
    "tools/loop9_replay_dataset_isolation.py",
    "tools/loop9_validate_daily_snapshots.py",
    "tools/loop9_validate_dataset_isolation.py",
    "verification/loop-ledger.schema.json",
)
CRITICAL_LOOP9_AUDIT_CONTRACT_SOURCES = (
    "frontend/src/api/auditContracts.ts",
    "frontend/src/app/App.tsx",
    "frontend/src/features/audit/AuditResults.tsx",
    "frontend/src/features/audit/AuditReviewQueue.tsx",
    "frontend/src/features/audit/WaybillHistory.tsx",
    "src/dahe/adapters/sqlite/audit_workflow.py",
    "src/dahe/adapters/sqlite/migrations/versions/0014_loop8_offline_audit.py",
    "src/dahe/api/audit_workflow.py",
    "src/dahe/ports/audit.py",
)
CRITICAL_LOOP9_OCR_RUNTIME_SOURCES = (
    "ocr-runtime/model-spec.json",
    "ocr-runtime/pyproject.toml",
    "ocr-runtime/requirements-cpu.lock",
    "ocr-runtime/requirements-gpu.lock",
    "src/dahe/ports/ocr.py",
)
CRITICAL_LOOP9_TEMPLATE_PERSISTENCE_SOURCES = (
    "src/dahe/adapters/sqlite/candidate_development_ocr.py",
    "src/dahe/adapters/sqlite/locked_set.py",
    "src/dahe/adapters/sqlite/locked_set_review.py",
    "src/dahe/adapters/sqlite/migrations/versions/0005_loop7_template_studio.py",
    "src/dahe/adapters/sqlite/migrations/versions/0006_loop7_locked_set_authority.py",
    "src/dahe/adapters/sqlite/migrations/versions/0007_loop7_locked_set_review.py",
    "src/dahe/adapters/sqlite/migrations/versions/0008_loop7_review_authority.py",
    "src/dahe/adapters/sqlite/migrations/versions/0009_loop7_template_reference_origin.py",
    "src/dahe/adapters/sqlite/migrations/versions/0010_loop7_candidate_development_ocr_runs.py",
    "src/dahe/adapters/sqlite/migrations/versions/0011_loop7_terminal_attempt_ledgers.py",
    "src/dahe/adapters/sqlite/migrations/versions/0012_loop7_development_authority.py",
    "src/dahe/adapters/sqlite/migrations/versions/0013_loop7_authority_insert_guards.py",
    "src/dahe/adapters/sqlite/template_evaluation.py",
    "src/dahe/adapters/sqlite/template_lifecycle_attempts.py",
    "src/dahe/adapters/sqlite/template_studio.py",
    "src/dahe/api/template_studio.py",
)
LOOP9_AUDIT_PIPELINE_GLOBS = (
    "frontend/dist/**/*",
    "frontend/src/**/*.css",
    "frontend/src/**/*.ts",
    "frontend/src/**/*.tsx",
    "ocr-runtime/src/dahe_ocr_worker/*.py",
    "src/dahe/adapters/ocr/*.py",
    "src/dahe/application/audit/*.py",
    "src/dahe/application/template_studio/*.py",
    "src/dahe/domain/audit/*.py",
)


def _loop9_required_sources() -> set[str]:
    sources: set[str] = set()
    for pattern in (
        "browser-runtime/src/dahe_browser_worker/*.py",
        "src/dahe/adapters/chengfeng/*.py",
        "src/dahe/application/chengfeng/*.py",
        "src/dahe/application/daily/*.py",
        "src/dahe/domain/daily/*.py",
        "src/dahe/jobs/*.py",
        "src/dahe/adapters/sqlite/loop3_*.py",
        "src/dahe/adapters/sqlite/migrations/versions/*.py",
        *LOOP9_AUDIT_PIPELINE_GLOBS,
    ):
        sources.update(
            path.relative_to(PROJECT_ROOT).as_posix()
            for path in PROJECT_ROOT.glob(pattern)
            if (
                path.is_file()
                and not path.is_symlink()
                and "/test/" not in path.relative_to(PROJECT_ROOT).as_posix()
                and ".test." not in path.name
                and ".spec." not in path.name
            )
        )
    sources.update(
        {
            *CRITICAL_LOOP9_RUNTIME_SOURCES,
            *CRITICAL_LOOP9_MIGRATION_SOURCES,
            *CRITICAL_LOOP9_FAST_BUSINESS_SOURCES,
            *CRITICAL_LOOP9_VERIFICATION_SOURCES,
            *CRITICAL_LOOP9_AUDIT_CONTRACT_SOURCES,
            *CRITICAL_LOOP9_OCR_RUNTIME_SOURCES,
            *CRITICAL_LOOP9_TEMPLATE_PERSISTENCE_SOURCES,
            "src/dahe/adapters/sqlite/browser_control.py",
            "src/dahe/adapters/sqlite/chengfeng_capture.py",
            "src/dahe/adapters/sqlite/daily_invocation_store.py",
            "src/dahe/adapters/sqlite/daily_store.py",
            "src/dahe/adapters/sqlite/loop3_repository.py",
            "src/dahe/adapters/sqlite/loop3_resource_store.py",
            "src/dahe/adapters/sqlite/migrations/versions/0015_loop9_platform_access.py",
            "src/dahe/adapters/sqlite/migrations/versions/0016_loop9_daily_read_model.py",
            "src/dahe/adapters/sqlite/migrations/versions/0017_loop9_daily_start_idempotency.py",
            "src/dahe/adapters/sqlite/migrations/versions/0021_loop9_settlement_selection_state.py",
            "src/dahe/adapters/sqlite/migrations/versions/0022_loop9_selection_lifecycle.py",
            "src/dahe/adapters/sqlite/platform_access.py",
            "src/dahe/adapters/sqlite/repository.py",
            "src/dahe/adapters/sqlite/schema.py",
            "src/dahe/adapters/sqlite/settlement_capture.py",
            "src/dahe/api/app.py",
            "src/dahe/api/errors.py",
            "src/dahe/api/loop9_review.py",
            "src/dahe/api/platform.py",
            "src/dahe/config/schema.py",
            "src/dahe/diagnostics/runtime_log.py",
            "src/dahe/ports/chengfeng.py",
            "src/dahe/ports/daily.py",
            "src/dahe/system/supervision.py",
            "src/dahe/verification/loop9_build.py",
        }
    )
    return sources


def test_loop9_manifest_covers_daily_and_settlement_runtime_sources() -> None:
    required = _loop9_required_sources()
    manifest = set(LOOP9_SOURCE_MANIFEST)

    assert required <= manifest, sorted(required - manifest)
    assert tuple(sorted(LOOP9_SOURCE_MANIFEST)) == LOOP9_SOURCE_MANIFEST
    assert len(LOOP9_SOURCE_MANIFEST) == len(manifest)


def test_loop9_build_is_explicit_complete_and_stable() -> None:
    first = current_loop9_build_manifest(PROJECT_ROOT)
    second = current_loop9_build_manifest(PROJECT_ROOT)
    assert first == second
    sources = first["sources"]
    assert isinstance(sources, list)
    assert tuple(source["path"] for source in sources) == LOOP9_SOURCE_MANIFEST
    fingerprint = current_loop9_build_sha256(PROJECT_ROOT)
    assert len(fingerprint) == 64
    assert fingerprint == current_loop9_build_sha256(PROJECT_ROOT)


def test_loop9_build_rejects_omitted_duplicate_or_unsorted_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required_source = "src/dahe/ports/daily.py"
    without_required = tuple(path for path in LOOP9_SOURCE_MANIFEST if path != required_source)
    monkeypatch.setattr(
        loop9_build,
        "LOOP9_SOURCE_MANIFEST",
        without_required,
    )
    with pytest.raises(Loop9BuildError, match="omits"):
        current_loop9_build_manifest(PROJECT_ROOT)

    monkeypatch.setattr(
        loop9_build,
        "LOOP9_SOURCE_MANIFEST",
        (*LOOP9_SOURCE_MANIFEST, LOOP9_SOURCE_MANIFEST[-1]),
    )
    with pytest.raises(Loop9BuildError, match="sorted and unique"):
        current_loop9_build_manifest(PROJECT_ROOT)

    monkeypatch.setattr(
        loop9_build,
        "LOOP9_SOURCE_MANIFEST",
        tuple(reversed(LOOP9_SOURCE_MANIFEST)),
    )
    with pytest.raises(Loop9BuildError, match="sorted and unique"):
        current_loop9_build_manifest(PROJECT_ROOT)


@pytest.mark.parametrize(
    "logical_path",
    (
        *CRITICAL_LOOP9_RUNTIME_SOURCES,
        *CRITICAL_LOOP9_MIGRATION_SOURCES,
        *CRITICAL_LOOP9_FAST_BUSINESS_SOURCES,
        *CRITICAL_LOOP9_VERIFICATION_SOURCES,
        *CRITICAL_LOOP9_AUDIT_CONTRACT_SOURCES,
        *CRITICAL_LOOP9_OCR_RUNTIME_SOURCES,
        *CRITICAL_LOOP9_TEMPLATE_PERSISTENCE_SOURCES,
    ),
)
def test_loop9_build_rejects_omitted_critical_source(
    monkeypatch: pytest.MonkeyPatch,
    logical_path: str,
) -> None:
    monkeypatch.setattr(
        loop9_build,
        "LOOP9_SOURCE_MANIFEST",
        tuple(path for path in LOOP9_SOURCE_MANIFEST if path != logical_path),
    )

    with pytest.raises(Loop9BuildError, match="omits"):
        current_loop9_build_manifest(PROJECT_ROOT)


def test_loop9_fingerprint_changes_for_each_protected_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index, logical_path in enumerate(sorted(_loop9_required_sources())):
        project = tmp_path / f"project-{index}"
        changed = project / logical_path
        changed.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROJECT_ROOT / logical_path, changed)
        monkeypatch.setattr(loop9_build, "LOOP9_SOURCE_MANIFEST", (logical_path,))
        monkeypatch.setattr(
            loop9_build,
            "_required_loop9_sources",
            lambda _root, path=logical_path: {path},
        )
        first = current_loop9_build_sha256(project)
        original = changed.read_bytes()
        changed.write_bytes(original + b"\n")
        assert current_loop9_build_sha256(project) != first, logical_path
        changed.write_bytes(original)
        assert current_loop9_build_sha256(project) == first


def test_loop9_build_rejects_each_missing_protected_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index, logical_path in enumerate(sorted(_loop9_required_sources())):
        project = tmp_path / f"project-{index}"
        target = project / logical_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROJECT_ROOT / logical_path, target)
        monkeypatch.setattr(loop9_build, "LOOP9_SOURCE_MANIFEST", (logical_path,))
        monkeypatch.setattr(
            loop9_build,
            "_required_loop9_sources",
            lambda _root, path=logical_path: {path},
        )
        target.unlink()
        with pytest.raises(Loop9BuildError, match="unavailable"):
            current_loop9_build_manifest(project)
