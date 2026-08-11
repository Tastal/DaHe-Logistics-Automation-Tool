from __future__ import annotations

import hashlib
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from dahe.jobs.ocr_execution import qualified_runtime_set_sha256
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildSource,
)

TEMPLATE_PIPELINE_SOURCE_MANIFEST = (
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


class TemplatePipelineBuildError(RuntimeError):
    """Raised when the explicit formal pipeline build cannot be fingerprinted."""


def _runtime_project_location() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    return Path(__file__)


def _locate_project_root(module_path: Path) -> Path:
    try:
        resolved_module = module_path.resolve(strict=True)
    except OSError as exc:
        raise TemplatePipelineBuildError(
            "formal pipeline module location is unavailable"
        ) from exc
    for candidate in resolved_module.parents:
        if (
            (candidate / "src" / "dahe" / "__init__.py").is_file()
            and (candidate / "ocr-runtime" / "model-spec.json").is_file()
            and (candidate / "alembic.ini").is_file()
        ):
            return candidate
    raise TemplatePipelineBuildError("formal pipeline project root is unavailable")


def _pipeline_sources() -> tuple[tuple[str, Path], ...]:
    project_root = _locate_project_root(_runtime_project_location())
    dahe_root = project_root / "src" / "dahe"
    if (
        tuple(sorted(TEMPLATE_PIPELINE_SOURCE_MANIFEST))
        != TEMPLATE_PIPELINE_SOURCE_MANIFEST
        or len(set(TEMPLATE_PIPELINE_SOURCE_MANIFEST))
        != len(TEMPLATE_PIPELINE_SOURCE_MANIFEST)
    ):
        raise TemplatePipelineBuildError(
            "formal pipeline source manifest must be unique and sorted"
        )
    sources: list[tuple[str, Path]] = []
    for logical_path in TEMPLATE_PIPELINE_SOURCE_MANIFEST:
        project_relative = (
            logical_path == "alembic.ini"
            or logical_path.startswith("tools/")
            or logical_path.startswith("ocr-runtime/")
        )
        path = (
            project_root / logical_path
            if project_relative
            else dahe_root / logical_path
        )
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(project_root)
        except (OSError, ValueError) as exc:
            raise TemplatePipelineBuildError(
                f"formal pipeline source is unavailable: {logical_path}"
            ) from exc
        if path.is_symlink() or not resolved.is_file():
            raise TemplatePipelineBuildError(
                f"formal pipeline source is not a regular project file: {logical_path}"
            )
        sources.append((logical_path, resolved))
    return tuple(sources)


def current_template_pipeline_build_manifest(
    *,
    application_version: str,
) -> ApplicationBuildManifest:
    """Build auditable evidence for the exact formal role and OCR pipeline."""

    sources: list[ApplicationBuildSource] = []
    for logical_path, path in _pipeline_sources():
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise TemplatePipelineBuildError(
                f"formal pipeline source cannot be read: {logical_path}"
            ) from exc
        sources.append(
            ApplicationBuildSource(
                path=logical_path,
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    return ApplicationBuildManifest(
        application_version=application_version,
        sources=tuple(sources),
    )


def current_template_pipeline_build_fingerprint(
    *,
    application_version: str,
) -> str:
    """Hash the installed role-pipeline sources without a machine-specific path."""

    return current_template_pipeline_build_manifest(
        application_version=application_version,
    ).canonical_sha256


def current_template_ocr_runtime_set_fingerprint(
    identities: Sequence[Mapping[str, str]],
) -> str:
    """Bind template evidence to the complete qualified OCR runtime set."""

    return qualified_runtime_set_sha256(identities)
