from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from dahe import __version__

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_LOOP9_BASE_SOURCE_MANIFEST = (
    "alembic.ini",
    "frontend/index.html",
    "frontend/package-lock.json",
    "frontend/package.json",
    "browser-runtime/pyproject.toml",
    "browser-runtime/requirements.lock",
    "browser-runtime/src/dahe_browser_worker/__init__.py",
    "browser-runtime/src/dahe_browser_worker/__main__.py",
    "browser-runtime/src/dahe_browser_worker/engine.py",
    "browser-runtime/src/dahe_browser_worker/protocol.py",
    "docs/adr/ADR-030-loop9-daily-read-contract.md",
    "docs/adr/ADR-031-loop9-generation-bound-formal-gates.md",
    "docs/adr/ADR-032-loop9-atomic-shadow-acceptance.md",
    "docs/adr/ADR-033-access-window-rollover-lineage.md",
    "docs/adr/ADR-034-exact-image-capability-request-audit.md",
    "docs/adr/ADR-035-chengfeng-detail-form-encoding-rollover.md",
    "docs/adr/ADR-036-bounded-historical-locked-set-source.md",
    "docs/adr/ADR-037-operational-compat-read-connector.md",
    "fixtures/chengfeng/loop9-read-only.invalid.json",
    "frontend/src/api/client.ts",
    "frontend/src/app/contracts.ts",
    "frontend/src/features/system/PlatformSessionPanel.tsx",
    "frontend/src/features/system/SystemWorkspace.tsx",
    "frontend/src/styles/app.css",
    "pyproject.toml",
    "requirements.lock",
    "requirements-production.lock",
    "version-manifest.json",
    "src/dahe/__init__.py",
    "src/dahe/__main__.py",
    "src/dahe/adapters/fake/audit.py",
    "src/dahe/adapters/fake/loop3.py",
    "src/dahe/adapters/chengfeng/__init__.py",
    "src/dahe/adapters/chengfeng/browser_gate.py",
    "src/dahe/adapters/chengfeng/browser_runtime.py",
    "src/dahe/adapters/chengfeng/connector_runtime.py",
    "src/dahe/adapters/chengfeng/connector_staging.py",
    "src/dahe/adapters/chengfeng/contract_freezer.py",
    "src/dahe/adapters/chengfeng/daily_contract_freezer.py",
    "src/dahe/adapters/chengfeng/daily_contract_selection.py",
    "src/dahe/adapters/chengfeng/daily_live_adapter.py",
    "src/dahe/adapters/chengfeng/daily_manifest.py",
    "src/dahe/adapters/chengfeng/daily_payload.py",
    "src/dahe/adapters/chengfeng/daily_request_builder.py",
    "src/dahe/adapters/chengfeng/discovery.py",
    "src/dahe/adapters/chengfeng/frozen.py",
    "src/dahe/adapters/chengfeng/live_connector_runtime.py",
    "src/dahe/adapters/chengfeng/live_contract_selection.py",
    "src/dahe/adapters/chengfeng/live_contract_validation.py",
    "src/dahe/adapters/chengfeng/live_manifest.py",
    "src/dahe/adapters/chengfeng/live_payload.py",
    "src/dahe/adapters/chengfeng/vehicle_number.py",
    "src/dahe/adapters/chengfeng/live_request_builder.py",
    "src/dahe/adapters/chengfeng/manifest.py",
    "src/dahe/adapters/chengfeng/payload_codec.py",
    "src/dahe/adapters/chengfeng/policy.py",
    "src/dahe/adapters/chengfeng/protocol.py",
    "src/dahe/adapters/chengfeng/redaction.py",
    "src/dahe/adapters/chengfeng/result_verifier.py",
    "src/dahe/adapters/chengfeng/verified_connector.py",
    "src/dahe/adapters/files/content_addressed.py",
    "src/dahe/adapters/files/platform_request_audit.py",
    "src/dahe/adapters/files/settlement_capture_manifest.py",
    "src/dahe/adapters/files/shadow_batch_manifest.py",
    "src/dahe/adapters/files/shadow_selection_lifecycle.py",
    "src/dahe/adapters/files/shadow_selection_manifest.py",
    "src/dahe/adapters/sqlite/browser_control.py",
    "src/dahe/adapters/sqlite/chengfeng_capture.py",
    "src/dahe/adapters/sqlite/daily_invocation_store.py",
    "src/dahe/adapters/sqlite/daily_store.py",
    "src/dahe/adapters/sqlite/loop3_job_store.py",
    "src/dahe/adapters/sqlite/loop3_query_store.py",
    "src/dahe/adapters/sqlite/loop3_repository.py",
    "src/dahe/adapters/sqlite/loop3_resource_store.py",
    "src/dahe/adapters/sqlite/loop3_scheduler_store.py",
    "src/dahe/adapters/sqlite/loop3_schema.py",
    "src/dahe/adapters/sqlite/loop3_support.py",
    "src/dahe/adapters/sqlite/loop4_recovery_store.py",
    "src/dahe/adapters/sqlite/migrations/env.py",
    "src/dahe/adapters/sqlite/migrations/versions/0015_loop9_platform_access.py",
    "src/dahe/adapters/sqlite/migrations/versions/0016_loop9_daily_read_model.py",
    "src/dahe/adapters/sqlite/migrations/versions/0017_loop9_daily_start_idempotency.py",
    "src/dahe/adapters/sqlite/migrations/versions/0018_loop9_daily_window_fks.py",
    "src/dahe/adapters/sqlite/migrations/versions/0019_loop9_settlement_capture.py",
    "src/dahe/adapters/sqlite/migrations/versions/0020_loop9_exclusion_authority_anchor.py",
    "src/dahe/adapters/sqlite/migrations/versions/0021_loop9_settlement_selection_state.py",
    "src/dahe/adapters/sqlite/migrations/versions/0022_loop9_selection_lifecycle.py",
    "src/dahe/adapters/sqlite/migrations/versions/0023_loop9_daily_access_rollover.py",
    "src/dahe/adapters/sqlite/migrations/versions/0024_loop9_historical_settlement_scope.py",
    "src/dahe/adapters/sqlite/migrations/versions/0025_operational_compat_capture.py",
    "src/dahe/adapters/sqlite/migrations/versions/0026_business_connection_session.py",
    "src/dahe/adapters/sqlite/business_connection.py",
    "src/dahe/adapters/sqlite/platform_access.py",
    "src/dahe/adapters/sqlite/repository.py",
    "src/dahe/adapters/sqlite/recovery.py",
    "src/dahe/adapters/sqlite/runtime.py",
    "src/dahe/adapters/sqlite/schema.py",
    "src/dahe/adapters/sqlite/settlement_capture.py",
    "src/dahe/api/app.py",
    "src/dahe/api/errors.py",
    "src/dahe/api/locked_set_review.py",
    "src/dahe/api/loop9_review.py",
    "src/dahe/api/platform.py",
    "src/dahe/application/chengfeng/__init__.py",
    "src/dahe/application/chengfeng/access_window.py",
    "src/dahe/application/chengfeng/business_session.py",
    "src/dahe/application/chengfeng/connection_mode.py",
    "src/dahe/application/chengfeng/durable_capture.py",
    "src/dahe/application/chengfeng/expiry_reconciler.py",
    "src/dahe/application/chengfeng/identity_authority.py",
    "src/dahe/application/chengfeng/operational_capture.py",
    "src/dahe/application/chengfeng/settlement_capture.py",
    "src/dahe/application/chengfeng/settlement_live_execution.py",
    "src/dahe/application/chengfeng/shadow_batch.py",
    "src/dahe/application/chengfeng/shadow_job_source.py",
    "src/dahe/application/chengfeng/shadow_selection.py",
    "src/dahe/application/chengfeng/shadow_selection_lifecycle.py",
    "src/dahe/application/daily/__init__.py",
    "src/dahe/application/daily/capture.py",
    "src/dahe/application/daily/live_execution.py",
    "src/dahe/cli.py",
    "src/dahe/bootstrap.py",
    "src/dahe/config/paths.py",
    "src/dahe/config/schema.py",
    "src/dahe/diagnostics/outbox_bridge.py",
    "src/dahe/diagnostics/runtime_log.py",
    "src/dahe/domain/ticket/role_assessment.py",
    "src/dahe/domain/ticket/templates.py",
    "src/dahe/domain/daily/__init__.py",
    "src/dahe/domain/daily/calendar.py",
    "src/dahe/domain/daily/models.py",
    "src/dahe/jobs/__init__.py",
    "src/dahe/jobs/actions.py",
    "src/dahe/jobs/audit_execution.py",
    "src/dahe/jobs/daily_execution.py",
    "src/dahe/jobs/models.py",
    "src/dahe/jobs/ocr_errors.py",
    "src/dahe/jobs/ocr_execution.py",
    "src/dahe/jobs/scheduler.py",
    "src/dahe/jobs/settlement_capture_execution.py",
    "src/dahe/jobs/shared_evidence.py",
    "src/dahe/jobs/specs.py",
    "src/dahe/ports/chengfeng.py",
    "src/dahe/ports/daily.py",
    "src/dahe/ports/jobs.py",
    "src/dahe/server.py",
    "src/dahe/system/environment.py",
    "src/dahe/system/instance_lock.py",
    "src/dahe/system/instance_lifecycle.py",
    "src/dahe/system/port_guard.py",
    "src/dahe/system/supervision.py",
    "src/dahe/system/test_fixture_root.py",
    "src/dahe/system/versioning.py",
    "src/dahe/verification/daily_snapshot_validation.py",
    "src/dahe/verification/ledger.py",
    "src/dahe/verification/loop9_build.py",
    "src/dahe/verification/loop9_dataset_artifacts.py",
    "src/dahe/verification/loop9_dataset_isolation.py",
    "src/dahe/verification/loop9_exclusion_authority.py",
    "src/dahe/verification/loop9_fault_injection.py",
    "src/dahe/verification/loop9_final_acceptance.py",
    "src/dahe/verification/loop9_locked_gate.py",
    "src/dahe/verification/loop9_locked_selection_rollover.py",
    "src/dahe/verification/loop9_machine_results.py",
    "src/dahe/verification/loop9_operational_evidence.py",
    "src/dahe/verification/operational_fast_capture.py",
    "src/dahe/verification/loop9_request_audit.py",
    "tools/bootstrap_browser.py",
    "tools/loop9_build_dataset_artifacts.py",
    "tools/loop9_build_exclusion_authority.py",
    "tools/loop9_build_operational_evidence.py",
    "tools/loop9_final_acceptance.py",
    "tools/loop9_freeze_read_contract.py",
    "tools/loop9_invalidate_locked_selection.py",
    "tools/install_operational_read_contracts.py",
    "tools/install_operational_template_bundle.py",
    "tools/verify_operational_fast_capture.py",
    "tools/loop9_machine_results.py",
    "tools/loop9_run_fault_injections.py",
    "tools/loop9_operational_read_only_acceptance.py",
    "tools/loop9_register_discovery_exclusion.py",
    "tools/loop9_replay_dataset_isolation.py",
    "tools/loop9_rollover_list_contract.py",
    "tools/loop9_select_read_contract.py",
    "tools/loop9_validate_daily_snapshots.py",
    "tools/loop9_validate_dataset_isolation.py",
    "verification/loop-ledger.schema.json",
)

_LOOP9_AUDIT_PIPELINE_SOURCE_MANIFEST = (
    "frontend/src/api/auditContracts.ts",
    "frontend/src/app/App.tsx",
    "frontend/src/features/audit/AuditResults.tsx",
    "frontend/src/features/audit/AuditReviewQueue.tsx",
    "frontend/src/features/audit/WaybillHistory.tsx",
    "ocr-runtime/model-spec.json",
    "ocr-runtime/pyproject.toml",
    "ocr-runtime/requirements-cpu.lock",
    "ocr-runtime/requirements-gpu.lock",
    "ocr-runtime/src/dahe_ocr_worker/__init__.py",
    "ocr-runtime/src/dahe_ocr_worker/__main__.py",
    "ocr-runtime/src/dahe_ocr_worker/engine.py",
    "ocr-runtime/src/dahe_ocr_worker/model_manifest.py",
    "ocr-runtime/src/dahe_ocr_worker/network_guard.py",
    "ocr-runtime/src/dahe_ocr_worker/protocol.py",
    "ocr-runtime/src/dahe_ocr_worker/protocol_stdout.py",
    "src/dahe/adapters/ocr/__init__.py",
    "src/dahe/adapters/ocr/coordinator.py",
    "src/dahe/adapters/ocr/devices.py",
    "src/dahe/adapters/ocr/diff_report.py",
    "src/dahe/adapters/ocr/errors.py",
    "src/dahe/adapters/ocr/fingerprints.py",
    "src/dahe/adapters/ocr/locked_set_evaluator.py",
    "src/dahe/adapters/ocr/model_manifest.py",
    "src/dahe/adapters/ocr/profile_registry.py",
    "src/dahe/adapters/ocr/profiles.py",
    "src/dahe/adapters/ocr/protocol.py",
    "src/dahe/adapters/ocr/runtime_factory.py",
    "src/dahe/adapters/ocr/runtime_inventory.py",
    "src/dahe/adapters/ocr/runtime_layout.py",
    "src/dahe/adapters/ocr/runtime_paths.py",
    "src/dahe/adapters/ocr/scheduled_gateway.py",
    "src/dahe/adapters/ocr/source_fingerprint.py",
    "src/dahe/adapters/ocr/template_role_input.py",
    "src/dahe/adapters/ocr/worker_session.py",
    "src/dahe/adapters/sqlite/audit_workflow.py",
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
    "src/dahe/adapters/sqlite/migrations/versions/0014_loop8_offline_audit.py",
    "src/dahe/adapters/sqlite/template_evaluation.py",
    "src/dahe/adapters/sqlite/template_lifecycle_attempts.py",
    "src/dahe/adapters/sqlite/template_studio.py",
    "src/dahe/api/audit_workflow.py",
    "src/dahe/api/template_studio.py",
    "src/dahe/application/audit/__init__.py",
    "src/dahe/application/audit/layered_records.py",
    "src/dahe/application/audit/local_ocr_decision.py",
    "src/dahe/application/audit/offline_batch.py",
    "src/dahe/application/audit/projections.py",
    "src/dahe/application/audit/service.py",
    "src/dahe/application/template_studio/__init__.py",
    "src/dahe/application/template_studio/authorizing_registry.py",
    "src/dahe/application/template_studio/operational_bundle.py",
    "src/dahe/application/template_studio/candidate_development_ocr.py",
    "src/dahe/application/template_studio/candidate_development_ocr_run_authority.py",
    "src/dahe/application/template_studio/candidate_review_export.py",
    "src/dahe/application/template_studio/candidate_review_seal.py",
    "src/dahe/application/template_studio/candidate_review_semantics.py",
    "src/dahe/application/template_studio/candidate_role_evaluation.py",
    "src/dahe/application/template_studio/candidate_role_metrics.py",
    "src/dahe/application/template_studio/candidate_role_ocr_evidence.py",
    "src/dahe/application/template_studio/candidate_role_source_authority.py",
    "src/dahe/application/template_studio/candidate_template_seed.py",
    "src/dahe/application/template_studio/composite_lifecycle_evaluation.py",
    "src/dahe/application/template_studio/development_authority_rollover.py",
    "src/dahe/application/template_studio/development_evaluation.py",
    "src/dahe/application/template_studio/fingerprints.py",
    "src/dahe/application/template_studio/formal_development_authority.py",
    "src/dahe/application/template_studio/formal_locked_set_release.py",
    "src/dahe/application/template_studio/locked_set_evidence.py",
    "src/dahe/application/template_studio/locked_set_release.py",
    "src/dahe/application/template_studio/matcher.py",
    "src/dahe/application/template_studio/reference_images.py",
    "src/dahe/domain/audit/__init__.py",
    "src/dahe/domain/audit/decisions.py",
    "src/dahe/domain/audit/errors.py",
    "src/dahe/domain/audit/evidence.py",
    "src/dahe/domain/audit/manual_actions.py",
    "src/dahe/domain/audit/shadow.py",
    "src/dahe/domain/audit/ticket_roles.py",
    "src/dahe/domain/audit/weights.py",
    "src/dahe/ports/audit.py",
    "src/dahe/ports/ocr.py",
    "src/dahe/verification/application_build.py",
    "src/dahe/verification/image_similarity.py",
    "src/dahe/verification/locked_set.py",
    "src/dahe/verification/locked_set_acceptance.py",
    "src/dahe/verification/locked_set_review_package.py",
    "src/dahe/verification/locked_set_runner.py",
    "src/dahe/verification/locked_set_similarity_scan.py",
    "src/dahe/verification/loop9_draft_suggestions.py",
    "src/dahe/verification/loop9_human_review.py",
    "tools/loop7_locked_set_release.py",
    "tools/loop7_shadow_authority_rollover.py",
    "tools/loop9_draft_suggestions.py",
    "tools/loop9_human_review.py",
    "tools/loop9_register_discovery_exclusion.py",
)

_LOOP9_REQUIRED_SOURCE_GLOBS = (
    "browser-runtime/src/dahe_browser_worker/*.py",
    "frontend/dist/**/*",
    "frontend/src/**/*.css",
    "frontend/src/**/*.ts",
    "frontend/src/**/*.tsx",
    "ocr-runtime/src/dahe_ocr_worker/*.py",
    "src/dahe/adapters/chengfeng/*.py",
    "src/dahe/adapters/ocr/*.py",
    "src/dahe/application/audit/*.py",
    "src/dahe/application/chengfeng/*.py",
    "src/dahe/application/daily/*.py",
    "src/dahe/application/template_studio/*.py",
    "src/dahe/domain/audit/*.py",
    "src/dahe/domain/daily/*.py",
    "src/dahe/jobs/*.py",
    "src/dahe/adapters/sqlite/loop3_*.py",
    "src/dahe/adapters/sqlite/migrations/versions/*.py",
)
_LOOP9_REQUIRED_SOURCE_FILES = (
    "alembic.ini",
    "DESIGN.md",
    "DEVELOPMENT_GUIDE.md",
    "PRODUCT.md",
    "docs/adr/ADR-030-loop9-daily-read-contract.md",
    "docs/adr/ADR-031-loop9-generation-bound-formal-gates.md",
    "docs/adr/ADR-032-loop9-atomic-shadow-acceptance.md",
    "docs/adr/ADR-033-access-window-rollover-lineage.md",
    "docs/adr/ADR-034-exact-image-capability-request-audit.md",
    "docs/adr/ADR-035-chengfeng-detail-form-encoding-rollover.md",
    "docs/adr/ADR-036-bounded-historical-locked-set-source.md",
    "docs/adr/ADR-037-operational-compat-read-connector.md",
    "docs/adr/ADR-042-business-session-human-handoff.md",
    "docs/adr/ADR-043-headless-batch-business-reads.md",
    "docs/adr/ADR-044-build-scoped-exclusion-anchor-chains.md",
    "docs/adr/ADR-047-guarded-read-only-production-cutover.md",
    "docs/adr/ADR-050-remove-mandatory-first-batch-guard.md",
    "frontend/index.html",
    "frontend/package-lock.json",
    "frontend/package.json",
    "frontend/src/main.tsx",
    "frontend/tsconfig.app.json",
    "frontend/tsconfig.json",
    "frontend/tsconfig.node.json",
    "frontend/vite.config.ts",
    "pyproject.toml",
    "requirements.lock",
    "version-manifest.json",
    "src/dahe/__init__.py",
    "src/dahe/__main__.py",
    "src/dahe/adapters/fake/audit.py",
    "src/dahe/adapters/fake/loop3.py",
    "src/dahe/adapters/files/content_addressed.py",
    "src/dahe/adapters/files/platform_request_audit.py",
    "src/dahe/adapters/files/settlement_capture_manifest.py",
    "src/dahe/adapters/files/shadow_batch_manifest.py",
    "src/dahe/adapters/files/shadow_selection_lifecycle.py",
    "src/dahe/adapters/files/shadow_selection_manifest.py",
    "src/dahe/adapters/sqlite/browser_control.py",
    "src/dahe/adapters/sqlite/chengfeng_capture.py",
    "src/dahe/adapters/sqlite/daily_invocation_store.py",
    "src/dahe/adapters/sqlite/daily_operational_ocr.py",
    "src/dahe/adapters/sqlite/daily_reports.py",
    "src/dahe/adapters/sqlite/daily_store.py",
    "src/dahe/adapters/sqlite/loop3_repository.py",
    "src/dahe/adapters/sqlite/loop3_resource_store.py",
    "src/dahe/adapters/sqlite/loop4_recovery_store.py",
    "src/dahe/adapters/sqlite/migrations/env.py",
    "src/dahe/adapters/sqlite/migrations/versions/0015_loop9_platform_access.py",
    "src/dahe/adapters/sqlite/migrations/versions/0016_loop9_daily_read_model.py",
    "src/dahe/adapters/sqlite/migrations/versions/0017_loop9_daily_start_idempotency.py",
    "src/dahe/adapters/sqlite/migrations/versions/0018_loop9_daily_window_fks.py",
    "src/dahe/adapters/sqlite/migrations/versions/0019_loop9_settlement_capture.py",
    "src/dahe/adapters/sqlite/migrations/versions/0020_loop9_exclusion_authority_anchor.py",
    "src/dahe/adapters/sqlite/migrations/versions/0021_loop9_settlement_selection_state.py",
    "src/dahe/adapters/sqlite/migrations/versions/0022_loop9_selection_lifecycle.py",
    "src/dahe/adapters/sqlite/platform_access.py",
    "src/dahe/adapters/sqlite/platform_credentials.py",
    "src/dahe/adapters/sqlite/production_guard.py",
    "src/dahe/adapters/sqlite/repository.py",
    "src/dahe/adapters/sqlite/recovery.py",
    "src/dahe/adapters/sqlite/runtime.py",
    "src/dahe/adapters/sqlite/schema.py",
    "src/dahe/adapters/sqlite/settlement_capture.py",
    "src/dahe/adapters/windows/__init__.py",
    "src/dahe/adapters/windows/credential_manager.py",
    "src/dahe/api/app.py",
    "src/dahe/api/daily_reports.py",
    "src/dahe/api/errors.py",
    "src/dahe/api/locked_set_review.py",
    "src/dahe/api/loop9_review.py",
    "src/dahe/api/platform.py",
    "src/dahe/application/chengfeng/identity_authority.py",
    "src/dahe/application/chengfeng/credential_service.py",
    "src/dahe/application/chengfeng/settlement_capture.py",
    "src/dahe/application/chengfeng/settlement_live_execution.py",
    "src/dahe/application/chengfeng/shadow_selection.py",
    "src/dahe/application/chengfeng/shadow_selection_lifecycle.py",
    "src/dahe/application/daily/operational_capture.py",
    "src/dahe/bootstrap.py",
    "src/dahe/cli.py",
    "src/dahe/config/paths.py",
    "src/dahe/config/schema.py",
    "src/dahe/diagnostics/outbox_bridge.py",
    "src/dahe/diagnostics/runtime_log.py",
    "src/dahe/domain/ticket/role_assessment.py",
    "src/dahe/domain/ticket/templates.py",
    "src/dahe/ports/chengfeng.py",
    "src/dahe/ports/daily.py",
    "src/dahe/ports/jobs.py",
    "src/dahe/ports/platform_credentials.py",
    "src/dahe/release/__init__.py",
    "src/dahe/release/local_release.py",
    "src/dahe/server.py",
    "src/dahe/system/environment.py",
    "src/dahe/system/instance_lock.py",
    "src/dahe/system/instance_lifecycle.py",
    "src/dahe/system/port_guard.py",
    "src/dahe/system/supervision.py",
    "src/dahe/system/test_fixture_root.py",
    "src/dahe/system/versioning.py",
    "src/dahe/verification/daily_snapshot_validation.py",
    "src/dahe/verification/ledger.py",
    "src/dahe/verification/loop9_build.py",
    "src/dahe/verification/loop9_dataset_artifacts.py",
    "src/dahe/verification/loop9_dataset_isolation.py",
    "src/dahe/verification/loop9_exclusion_authority.py",
    "src/dahe/verification/loop9_fault_injection.py",
    "src/dahe/verification/loop9_final_acceptance.py",
    "src/dahe/verification/loop9_locked_gate.py",
    "src/dahe/verification/loop9_locked_selection_rollover.py",
    "src/dahe/verification/loop9_machine_results.py",
    "src/dahe/verification/loop9_operational_evidence.py",
    "src/dahe/verification/loop9_request_audit.py",
    "src/dahe/verification/operational_fast_capture.py",
    "src/dahe/verification/operational_read_only_acceptance.py",
    "src/dahe/verification/production_backup_restore.py",
    "tools/loop9_build_dataset_artifacts.py",
    "tools/loop9_build_exclusion_authority.py",
    "tools/loop9_build_operational_evidence.py",
    "tools/loop9_final_acceptance.py",
    "tools/loop9_invalidate_locked_selection.py",
    "tools/loop9_machine_results.py",
    "tools/loop9_run_fault_injections.py",
    "tools/loop9_replay_dataset_isolation.py",
    "tools/loop9_validate_daily_snapshots.py",
    "tools/loop9_validate_dataset_isolation.py",
    "tools/build_local_production_release.py",
    "tools/verify_production_backup_restore.py",
    "verification/loop-ledger.schema.json",
    *_LOOP9_AUDIT_PIPELINE_SOURCE_MANIFEST,
)


def _is_runtime_build_input(path: Path, project_root: Path) -> bool:
    logical = path.relative_to(project_root).as_posix()
    return "/node_modules/" not in f"/{logical}" and not any(
        marker in logical
        for marker in (
            "/test/",
            ".test.ts",
            ".test.tsx",
            ".spec.ts",
            ".spec.tsx",
        )
    )


def _required_loop9_sources(project_root: Path) -> set[str]:
    required = set(_LOOP9_REQUIRED_SOURCE_FILES)
    for pattern in _LOOP9_REQUIRED_SOURCE_GLOBS:
        for path in project_root.glob(pattern):
            if (
                path.is_file()
                and not path.is_symlink()
                and _is_runtime_build_input(path, project_root)
            ):
                required.add(path.relative_to(project_root).as_posix())
    return required


LOOP9_SOURCE_MANIFEST = tuple(
    sorted(
        {
            *_LOOP9_BASE_SOURCE_MANIFEST,
            *_LOOP9_AUDIT_PIPELINE_SOURCE_MANIFEST,
            *_required_loop9_sources(_PROJECT_ROOT),
        }
    )
)


class Loop9BuildError(RuntimeError):
    """Raised when the explicit Loop 9 build cannot be fingerprinted."""


def current_loop9_build_manifest(project_root: Path) -> dict[str, object]:
    root = project_root.resolve()
    if tuple(sorted(LOOP9_SOURCE_MANIFEST)) != LOOP9_SOURCE_MANIFEST or len(
        set(LOOP9_SOURCE_MANIFEST)
    ) != len(LOOP9_SOURCE_MANIFEST):
        raise Loop9BuildError("Loop 9 source manifest must be sorted and unique")
    omitted = _required_loop9_sources(root) - set(LOOP9_SOURCE_MANIFEST)
    if omitted:
        raise Loop9BuildError(
            "Loop 9 source manifest omits required runtime sources: " + ",".join(sorted(omitted))
        )
    sources: list[dict[str, str]] = []
    for logical_path in LOOP9_SOURCE_MANIFEST:
        candidate = root / logical_path
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise Loop9BuildError(f"Loop 9 source is unavailable: {logical_path}") from exc
        if candidate.is_symlink() or not resolved.is_file():
            raise Loop9BuildError(f"Loop 9 source is not a regular project file: {logical_path}")
        sources.append(
            {
                "path": logical_path,
                "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
            }
        )
    return {
        "schema_version": 1,
        "application_version": __version__,
        "sources": sources,
    }


def current_loop9_build_sha256(project_root: Path) -> str:
    payload = json.dumps(
        current_loop9_build_manifest(project_root),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def runtime_loop9_build_sha256(project_root: Path) -> str:
    """Resolve a source checkout or sealed local release build identity."""
    root = project_root.resolve(strict=True)
    manifest_path = root / "runtime-manifest.json"
    if not manifest_path.exists():
        return current_loop9_build_sha256(root)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise Loop9BuildError("runtime release manifest is unsafe")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9BuildError("runtime release manifest is invalid") from exc
    expected_modes = {
        "audit": "operational",
        "daily": "operational",
        "dispatch": "disabled",
        "settlement": "disabled",
    }
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or document.get("kind") != "dahe_local_production_read_only_release"
        or document.get("application_version") != __version__
        or document.get("module_modes") != expected_modes
    ):
        raise Loop9BuildError("runtime release manifest identity is invalid")
    source_build_sha256 = document.get("source_build_sha256")
    commit = document.get("build_git_commit")
    files = document.get("files")
    if (
        not isinstance(source_build_sha256, str)
        or len(source_build_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_build_sha256)
        or not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
        or not isinstance(files, dict)
        or not files
    ):
        raise Loop9BuildError("runtime release manifest provenance is invalid")
    for logical_path, expected_sha256 in files.items():
        if not isinstance(logical_path, str) or not isinstance(expected_sha256, str):
            raise Loop9BuildError("runtime release file identity is invalid")
        pure_path = PurePosixPath(logical_path)
        if (
            pure_path.is_absolute()
            or not pure_path.parts
            or any(part in {"", ".", ".."} for part in pure_path.parts)
            or "\\" in logical_path
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise Loop9BuildError("runtime release file identity is invalid")
        candidate = root.joinpath(*pure_path.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise Loop9BuildError("runtime release payload is incomplete") from exc
        if candidate.is_symlink() or not resolved.is_file():
            raise Loop9BuildError("runtime release payload is unsafe")
        actual_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise Loop9BuildError("runtime release payload changed after build")
    return source_build_sha256
