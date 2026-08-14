from __future__ import annotations

import copy
import hashlib
import importlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError

from tests.fixtures.loop7_composite_lifecycle import (
    add_composite_lifecycle_authority,
)

EXPECTED_REVISION = "0041_contract_subject_scope"
TEMPLATE_TABLES = {
    "template_families",
    "template_reference_origins",
    "template_reference_uploads",
    "template_versions",
    "template_evaluations",
    "template_evaluation_candidates",
    "template_evaluation_items",
    "template_evaluation_pairs",
    "template_development_contract_state",
    "template_evaluation_invalidations",
    "template_lifecycle_events",
    "template_shadow_pointers",
    "template_idempotency_records",
    "template_audit_events",
    "template_unknown_samples",
    "template_lifecycle_attempts",
    "candidate_development_ocr_attempts",
    "locked_set_exclusion_inventory",
    "locked_set_exclusion_snapshots",
    "locked_set_datasets",
    "locked_set_preflight_attestations",
    "locked_set_similarity_scans",
    "locked_set_formal_evaluations",
    "locked_set_development_authority",
    "locked_set_invalidations",
}


class InjectedTemplateFailure(RuntimeError):
    pass


def _module(name: str) -> ModuleType:
    return importlib.import_module(name)


def _runtime(tmp_path: Path, project_root: Path, *, instance_id: str) -> Any:
    runtime_module = _module("dahe.adapters.sqlite.runtime")
    return runtime_module.SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id=instance_id,
    )


def _repository(
    runtime: Any,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> Any:
    repository_module = _module("dahe.adapters.sqlite.template_studio")
    return repository_module.SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="8" * 64,
        accepted_runtime_fingerprint="9" * 64,
        accepted_development_manifest_sha256="4" * 64,
        accepted_matcher_fingerprint="6" * 64,
        accepted_policy_fingerprint="7" * 64,
        failpoint=failpoint,
    )


def _migration_config(project_root: Path, database_path: Path) -> Config:
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(project_root / "src" / "dahe" / "adapters" / "sqlite" / "migrations"),
    )
    url = URL.create("sqlite+pysqlite", database=str(database_path))
    config.set_main_option(
        "sqlalchemy.url",
        url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    return config


def _definition(
    *,
    family_id: str = "scale-slip-alpha",
    left: str = "0.10",
    match_kind: str = "literal",
    unit: str | None = "t",
) -> Any:
    templates = _module("dahe.domain.ticket.templates")
    roles = _module("dahe.domain.audit.ticket_roles")
    return templates.TemplateDefinition(
        family_id=family_id,
        name="Alpha loading scale slip",
        role=roles.TicketRole.LOADING,
        anchors=(
            templates.TemplateAnchor(
                anchor_id="loading-title",
                expected_text="装货磅单",
                box=templates.NormalizedRect(
                    x=Decimal("0.10"),
                    y=Decimal("0.05"),
                    width=Decimal("0.35"),
                    height=Decimal("0.10"),
                ),
                required=True,
                weight=Decimal("1.00"),
                max_edit_distance=Decimal("0.15"),
                loading_evidence=Decimal("0.80"),
                unloading_evidence=Decimal("-0.20"),
                match_kind=templates.AnchorMatchKind(match_kind),
            ),
        ),
        regions=(
            templates.RecognitionRegion(
                region_id="net-weight",
                field=templates.TicketField.ORDINARY_NET,
                box=templates.NormalizedRect(
                    x=Decimal(left),
                    y=Decimal("0.55"),
                    width=Decimal("0.35"),
                    height=Decimal("0.12"),
                ),
                relative_to_anchor_id=None,
                unit=unit,
                format_pattern=r"^\d{1,3}(?:\.\d{1,2})?$",
                required=True,
                layout_scope="full_ticket",
            ),
        ),
    )


def _create_draft(repository: Any, *, key: str, left: str = "0.10") -> tuple[Any, bool]:
    return cast(
        tuple[Any, bool],
        repository.create_draft(
            definition=_definition(left=left),
            reference_image_sha256="a" * 64,
            reference_mask_sha256="b" * 64,
            alignment_fingerprint="c" * 64,
            actor_id="developer-test",
            idempotency_key=key,
        ),
    )


def _seed_reference_image(runtime: Any, *sha256s: str) -> None:
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        for sha256 in sha256s:
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


def _template_hold(
    runtime: Any,
    version_id: str,
    *,
    hold_kind: str = "template_reference",
) -> dict[str, object]:
    with runtime.engine.connect() as connection:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        sha256, hold_kind, owner_id, reason,
                        record_version, released_at
                    FROM evidence_holds
                    WHERE hold_kind = :hold_kind
                      AND owner_id = :version_id
                    """
                ),
                {
                    "hold_kind": hold_kind,
                    "version_id": version_id,
                },
            )
            .mappings()
            .one()
        )
    return dict(row)


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _evaluation_item(
    *,
    sample_id: str = "development-image-001",
    image_sha256: str = "1" * 64,
    waybill_identity_sha256: str = "e" * 64,
    unknown: bool = False,
) -> Any:
    persistence = _module("dahe.adapters.sqlite.template_studio")
    roles = _module("dahe.domain.audit.ticket_roles")
    prediction = roles.TicketRole.UNKNOWN if unknown else roles.TicketRole.LOADING
    return persistence.TemplateEvaluationItemInput(
        sample_id=sample_id,
        waybill_id="development-waybill-001",
        waybill_identity_sha256=waybill_identity_sha256,
        image_sha256=image_sha256,
        truth=roles.TicketRole.LOADING,
        prediction=prediction,
        confidence=Decimal("0.00" if unknown else "0.96"),
        high_confidence=not unknown,
        orientation_degrees=0,
        evidence={"sources": ["fixed_text", "template"]},
        assessment_fingerprint=("2" if unknown else "3") * 64,
        elapsed_ms=Decimal("1.25"),
        pair_issue="role_unknown" if unknown else None,
        unknown_reason="insufficient_role_evidence" if unknown else None,
    )


def _record_evaluation(
    repository: Any,
    version: Any,
    *,
    evaluation_id: str,
    dataset_kind: str = "development",
    gate_passed: bool = True,
    metrics_sha256: str | None = None,
    candidates: tuple[Any, ...] | None = None,
    items: tuple[Any, ...] | None = None,
    expected_count: int | None = None,
    result_count: int | None = None,
    trusted: bool = True,
    record_ocr_run_authority: bool = True,
) -> Any:
    persistence = _module("dahe.adapters.sqlite.template_studio")
    evaluation_items = items or (_evaluation_item(unknown=not gate_passed),)
    evaluation_candidates = candidates or (
        persistence.TemplateEvaluationCandidateInput(
            version_id=version.version_id,
            content_sha256=version.content_sha256,
        ),
    )
    role_values = ("loading", "unloading", "unknown")
    confusion_matrix = {
        truth: {prediction: 0 for prediction in role_values} for truth in role_values
    }
    for item in evaluation_items:
        confusion_matrix[item.truth.value][item.prediction.value] += 1
    unknown_count = sum(item.prediction.value == "unknown" for item in evaluation_items)
    high_confidence_errors = sum(
        item.high_confidence and item.truth is not item.prediction for item in evaluation_items
    )
    elapsed = sorted(item.elapsed_ms for item in evaluation_items)
    p50_index = max(0, ((50 * len(elapsed) + 99) // 100) - 1)
    p95_index = max(0, ((95 * len(elapsed) + 99) // 100) - 1)
    metrics = {
        "confusion_matrix": confusion_matrix,
        "high_confidence_error_count": high_confidence_errors,
        "p50_elapsed_ms": format(elapsed[p50_index].normalize(), "f"),
        "p95_elapsed_ms": format(elapsed[p95_index].normalize(), "f"),
        "pair_results": [
            {
                "case_id": "normal-pair-001",
                "expected_issue": None,
                "expected_matches_result": True,
                "result_issue": None,
            }
        ],
        "sample_count": len(evaluation_items),
        "unknown_rate": format(
            (Decimal(unknown_count) / Decimal(len(evaluation_items))).normalize(),
            "f",
        ),
    }
    if dataset_kind != "development" or not trusted:
        return repository.record_completed_evaluation(
            evaluation_id=evaluation_id,
            dataset_kind=dataset_kind,
            dataset_id=f"{dataset_kind}-dataset-001",
            dataset_manifest_sha256="4" * 64,
            template_set_fingerprint="5" * 64,
            matcher_fingerprint="6" * 64,
            policy_fingerprint="7" * 64,
            build_fingerprint="8" * 64,
            runtime_fingerprint="9" * 64,
            expected_count=(len(evaluation_items) if expected_count is None else expected_count),
            result_count=(len(evaluation_items) if result_count is None else result_count),
            metrics=metrics,
            metrics_sha256=metrics_sha256 or _canonical_sha256(metrics),
            gate_passed=gate_passed,
            candidates=evaluation_candidates,
            items=evaluation_items,
            actor_id="developer-tastal",
        )
    candidate_versions = tuple(
        repository.get_version(candidate.version_id) for candidate in evaluation_candidates
    )
    matcher = _module("dahe.application.template_studio.matcher")
    try:
        template_set_fingerprint = matcher.build_development_evaluation_template_set(
            candidates=candidate_versions,
            current_shadow=repository.list_current_eligible_shadow_versions(),
        ).fingerprint
    except ValueError:
        template_set_fingerprint = "5" * 64
    stable_outcome_sha256 = _canonical_sha256(
        {
            "evaluation_id": evaluation_id,
            "items": [
                {
                    "image_sha256": item.image_sha256,
                    "prediction": item.prediction.value,
                    "sample_id": item.sample_id,
                    "truth": item.truth.value,
                }
                for item in evaluation_items
            ],
            "template_set_fingerprint": template_set_fingerprint,
        }
    )
    if gate_passed:
        metrics, stable_outcome_sha256 = (
            add_composite_lifecycle_authority(
                metrics,
                evaluation_id=evaluation_id,
                dataset_id=f"{dataset_kind}-dataset-001",
                dataset_manifest_sha256="4" * 64,
                template_set_fingerprint=(
                    template_set_fingerprint
                ),
                matcher_fingerprint="6" * 64,
                policy_fingerprint="7" * 64,
                build_fingerprint="8" * 64,
                runtime_fingerprint="9" * 64,
                candidates=tuple(
                    (
                        candidate.version_id,
                        candidate.content_sha256,
                    )
                    for candidate in evaluation_candidates
                ),
            )
        )
        if record_ocr_run_authority:
            component = metrics["composite_lifecycle_components"][
                "real_candidate_roles"
            ]
            source = component["source"]
            run_module = _module(
                "dahe.adapters.sqlite.candidate_development_ocr"
            )
            evidence_sha256 = str(source["ocr_evidence_sha256"])
            run_module.SqliteCandidateDevelopmentOcrRunRepository(
                runtime=repository.runtime
            ).record_completed_run(
                run_module.CandidateDevelopmentOcrRunAuthorityInput(
                    evidence_sha256=evidence_sha256,
                    evidence_blob_sha256=_canonical_sha256(
                        {"evaluation_id": evaluation_id}
                    ),
                    evidence_relative_path=(
                        "development/protected-candidate-review-ocr/"
                        f"records/sha256/{evidence_sha256[:2]}/"
                        f"{evidence_sha256[2:4]}/{evidence_sha256}.json"
                    ),
                    evidence_byte_size=4096,
                    package_sha256=str(source["package_sha256"]),
                    review_history_authority_sha256=str(
                        source["review_history_authority_sha256"]
                    ),
                    source_authority_sha256=str(
                        source["source_authority_sha256"]
                    ),
                    reviewer_id="developer-tastal",
                    application_build_sha256=str(
                        source["ocr_capture_build_sha256"]
                    ),
                    composition_evidence_sha256=str(
                        source["composition_evidence_sha256"]
                    ),
                    runtime_set_sha256=str(
                        source["runtime_set_sha256"]
                    ),
                    pipeline_contract_sha256=str(
                        source["ocr_pipeline_contract_sha256"]
                    ),
                    completion_status="completed",
                    completed_at="2026-07-26T12:00:00+00:00",
                )
            )
    pair_inputs = tuple(
        persistence.TemplateEvaluationPairInput(
            case_id=str(pair["case_id"]),
            expected_issue=cast(str | None, pair["expected_issue"]),
            result_issue=cast(str | None, pair["result_issue"]),
            expected_matches_result=bool(pair["expected_matches_result"]),
        )
        for pair in metrics["pair_results"]
    )
    return repository._record_frozen_development_evaluation(
        evaluation_id=evaluation_id,
        dataset_id=f"{dataset_kind}-dataset-001",
        dataset_manifest_sha256="4" * 64,
        template_set_fingerprint=template_set_fingerprint,
        matcher_fingerprint="6" * 64,
        policy_fingerprint="7" * 64,
        build_fingerprint="8" * 64,
        runtime_fingerprint="9" * 64,
        expected_count=(len(evaluation_items) if expected_count is None else expected_count),
        result_count=len(evaluation_items) if result_count is None else result_count,
        metrics=metrics,
        metrics_sha256=metrics_sha256 or _canonical_sha256(metrics),
        gate_passed=gate_passed,
        candidates=evaluation_candidates,
        items=evaluation_items,
        pairs=pair_inputs,
        stable_outcome_sha256=stable_outcome_sha256,
        actor_id="developer-tastal",
    )


def _publish_version_as_shadow(
    repository: Any,
    version: Any,
    *,
    suffix: str,
) -> tuple[Any, Any, Any]:
    evaluation = _record_evaluation(
        repository,
        version,
        evaluation_id=f"development-{suffix}",
    )
    tested, _ = repository.mark_development_tested(
        version_id=version.version_id,
        expected_record_version=version.record_version,
        evaluation_id=evaluation.evaluation_id,
        developer_authorization_id=f"authorization-test-{suffix}",
        actor_id="developer-tastal",
        idempotency_key=f"mark-tested-{suffix}",
    )
    shadow, _ = repository.publish_shadow(
        version_id=version.version_id,
        expected_record_version=tested.record_version,
        evaluation_id=evaluation.evaluation_id,
        developer_authorization_id=f"authorization-publish-{suffix}",
        actor_id="developer-tastal",
        idempotency_key=f"publish-{suffix}",
    )
    pointer = repository.get_shadow_pointer(version.definition.family_id)
    return evaluation, shadow, pointer


def test_current_shadow_publication_authority_revalidates_full_terminal_chain(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-shadow-publication-authority",
    )
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    try:
        draft, _ = _create_draft(
            repository,
            key="shadow-publication-authority",
        )
        evaluation, shadow, pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="shadow-publication-authority",
        )

        contract = repository.current_shadow_eligibility_contract(
            runtime
        )
        publications = (
            repository.list_current_shadow_publication_authorities()
        )

        assert contract.dataset_manifest_sha256 == "4" * 64
        assert contract.matcher_fingerprint == "6" * 64
        assert contract.policy_fingerprint == "7" * 64
        assert contract.build_fingerprint == "8" * 64
        assert contract.runtime_fingerprint == "9" * 64
        assert len(publications) == 1
        publication = publications[0]
        assert publication.version == shadow
        assert publication.pointer_record_version == (
            pointer.record_version
        )
        assert publication.publication_evaluation == evaluation
        assert publication.lifecycle_attempt.terminal_status == "succeeded"
        assert publication.lifecycle_attempt.evaluation_id == (
            evaluation.evaluation_id
        )
        assert publication.publication_event_record_version == (
            shadow.record_version
        )
    finally:
        runtime.close()


def test_shadow_publication_uses_the_metrics_derived_terminal_scope(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-shadow-publication-exact-scope",
    )
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    try:
        draft, _ = _create_draft(
            repository,
            key="shadow-publication-exact-scope",
        )
        evaluation, _shadow, _pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="shadow-publication-exact-scope",
        )
        expected_scope = (
            repository.get_composite_lifecycle_attempt_scope(
                evaluation.evaluation_id
            )
        )
        unrelated_scope = replace(
            expected_scope,
            package_sha256="c" * 64,
        ).with_recomputed_identity()
        with runtime.commit_gate.transaction(
            runtime.engine
        ) as connection:
            repository._insert_composite_lifecycle_attempt(
                connection,
                scope=unrelated_scope,
                terminal_status="succeeded",
                evaluation_id=evaluation.evaluation_id,
                failure_code=None,
                actor_id="loop7-unrelated-scope",
                now="2026-07-26T00:01:00+00:00",
            )

        publication = (
            repository.list_current_shadow_publication_authorities()
        )[0]

        assert publication.lifecycle_attempt.scope_sha256 == (
            expected_scope.scope_sha256
        )
    finally:
        runtime.close()


def test_shadow_publication_rejects_latest_attempt_with_changed_ocr_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-shadow-publication-ocr-evidence",
    )
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    try:
        draft, _ = _create_draft(
            repository,
            key="shadow-publication-ocr-evidence",
        )
        evaluation, _shadow, _pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="shadow-publication-ocr-evidence",
        )
        expected_scope = (
            repository.get_composite_lifecycle_attempt_scope(
                evaluation.evaluation_id
            )
        )
        changed_evidence_scope = replace(
            expected_scope,
            ocr_evidence_sha256="c" * 64,
        ).with_recomputed_identity()
        assert changed_evidence_scope.scope_sha256 == (
            expected_scope.scope_sha256
        )
        with runtime.commit_gate.transaction(
            runtime.engine
        ) as connection:
            repository._insert_composite_lifecycle_attempt(
                connection,
                scope=changed_evidence_scope,
                terminal_status="succeeded",
                evaluation_id=evaluation.evaluation_id,
                failure_code=None,
                actor_id="loop7-changed-ocr-evidence",
                now="2026-07-26T00:01:00+00:00",
            )

        with pytest.raises(
            Exception,
            match="stale, incomplete, or invalidated",
        ):
            repository.list_current_shadow_publication_authorities()
    finally:
        runtime.close()


def test_fresh_runtime_applies_current_loop7_template_schema(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-fresh")
    try:
        assert runtime.current_revision() == EXPECTED_REVISION
        assert runtime.head_revision == EXPECTED_REVISION
        with runtime.engine.connect() as connection:
            tables = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            development_authority_triggers = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'trigger'
                      AND tbl_name =
                          'locked_set_development_authority'
                    """
                )
            }
            template_foreign_keys = {
                (str(row[2]), str(row[3]), str(row[4]), str(row[6]))
                for row in connection.exec_driver_sql(
                    "PRAGMA foreign_key_list('template_versions')"
                )
            }
            lifecycle_foreign_keys = {
                (str(row[2]), str(row[3]), str(row[4]), str(row[6]))
                for row in connection.exec_driver_sql(
                    "PRAGMA foreign_key_list('template_lifecycle_events')"
                )
            }
            upload_foreign_keys = {
                (str(row[2]), str(row[3]), str(row[4]), str(row[6]))
                for row in connection.exec_driver_sql(
                    "PRAGMA foreign_key_list('template_reference_uploads')"
                )
            }
        assert tables >= TEMPLATE_TABLES
        assert development_authority_triggers == {
            "locked_set_development_authority_immutable_insert",
            "locked_set_development_authority_immutable_update",
            "locked_set_development_authority_immutable_delete",
        }
        assert (
            "evidence_blobs",
            "reference_image_sha256",
            "sha256",
            "RESTRICT",
        ) in template_foreign_keys
        assert (
            "evidence_blobs",
            "reference_mask_sha256",
            "sha256",
            "RESTRICT",
        ) in template_foreign_keys
        assert (
            "evidence_blobs",
            "image_sha256",
            "sha256",
            "RESTRICT",
        ) in upload_foreign_keys
        assert (
            "template_evaluations",
            "evaluation_id",
            "evaluation_id",
            "RESTRICT",
        ) in lifecycle_foreign_keys
    finally:
        runtime.close()


def test_runtime_upgrades_0004_with_backup_and_preserves_existing_data(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "upgrade-from-0004"
    database_path = data_root / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    command.upgrade(_migration_config(project_root, database_path), "0004_loop6_image_quanta")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO system_meta (key, value) VALUES (?, ?)",
            ("loop7-upgrade-fixture", "preserve-me"),
        )
        connection.commit()

    runtime = _runtime(data_root, project_root, instance_id="loop7-upgrade")
    try:
        assert runtime.current_revision() == EXPECTED_REVISION
        assert runtime.pre_migration_backup_path is not None
        manifest_path = runtime.pre_migration_backup_path / "manifest.json"
        backup_path = runtime.pre_migration_backup_path / "dahe.sqlite3"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["from_revision"] == "0004_loop6_image_quanta"
        assert manifest["to_revision"] == EXPECTED_REVISION
        assert manifest["database_sha256"] == hashlib.sha256(backup_path.read_bytes()).hexdigest()
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT value FROM system_meta WHERE key = 'loop7-upgrade-fixture'")
                ).scalar_one()
                == "preserve-me"
            )
    finally:
        runtime.close()


def test_runtime_upgrades_0005_and_backfills_authoritative_exclusion_inventory(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "upgrade-from-0005"
    database_path = data_root / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    command.upgrade(
        _migration_config(project_root, database_path),
        "0005_loop7_template_studio",
    )
    created_at = "2026-07-26T00:00:00+00:00"
    with sqlite3.connect(database_path) as connection:
        for sha256 in (
            "a" * 64,
            "b" * 64,
            "d" * 64,
            "7" * 64,
            "e" * 64,
        ):
            connection.execute(
                """
                INSERT INTO evidence_blobs (
                    sha256, relative_path, byte_size, media_type,
                    storage_state, record_version, created_at, verified_at
                ) VALUES (?, ?, 1, 'image/png', 'available', 1, ?, ?)
                """,
                (sha256, f"loop7/{sha256}.png", created_at, created_at),
            )
        connection.execute(
            """
            INSERT INTO template_families (
                family_id, name, role, created_by, created_at
            ) VALUES (
                'legacy-family', 'Legacy family', 'loading',
                'developer-test', ?
            )
            """,
            (created_at,),
        )
        connection.execute(
            """
            INSERT INTO template_versions (
                version_id, family_id, version_number, parent_version_id,
                definition_json, content_sha256, reference_image_sha256,
                reference_mask_sha256, alignment_fingerprint, created_by,
                created_at
            ) VALUES (
                'legacy-version', 'legacy-family', 1, NULL, '{}',
                ?, ?, ?, ?, 'developer-test', ?
            )
            """,
            ("c" * 64, "a" * 64, "b" * 64, "f" * 64, created_at),
        )
        connection.execute(
            """
            INSERT INTO template_evaluations (
                evaluation_id, dataset_kind, dataset_id,
                dataset_manifest_sha256, template_set_fingerprint,
                matcher_fingerprint, policy_fingerprint,
                build_fingerprint, runtime_fingerprint,
                verification_source, stable_outcome_sha256,
                expected_count, result_count, metrics_json,
                metrics_sha256, gate_passed, actor_id, completed_at
            ) VALUES (
                'legacy-development-evaluation', 'development',
                'legacy-development-dataset', ?, ?, ?, ?, ?, ?,
                'untrusted_record', NULL, 1, 1, '{}', ?, 1,
                'developer-test', ?
            )
            """,
            (
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                "5" * 64,
                "6" * 64,
                hashlib.sha256(b"{}").hexdigest(),
                created_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO template_evaluation_items (
                item_id, evaluation_id, sample_id, waybill_id,
                image_sha256, truth, prediction, confidence,
                high_confidence, orientation_degrees, evidence_json,
                assessment_fingerprint, elapsed_ms, pair_issue,
                unknown_reason
            ) VALUES (
                'legacy-item', 'legacy-development-evaluation',
                'legacy-sample', 'legacy-waybill', ?, 'loading',
                'loading', '0.95', 1, 0, '{}', ?, '1.0', NULL, NULL
            )
            """,
            ("7" * 64, "8" * 64),
        )
        connection.execute(
            """
            INSERT INTO template_evaluation_items (
                item_id, evaluation_id, sample_id, waybill_id,
                image_sha256, truth, prediction, confidence,
                high_confidence, orientation_degrees, evidence_json,
                assessment_fingerprint, elapsed_ms, pair_issue,
                unknown_reason
            ) VALUES (
                'legacy-synthetic-item',
                'legacy-development-evaluation',
                'legacy-synthetic-sample',
                'legacy-synthetic-waybill', ?, 'loading',
                'loading', '0.95', 1, 0, '{}', ?, '1.0', NULL, NULL
            )
            """,
            ("0" * 64, "f" * 64),
        )
        connection.execute(
            """
            INSERT INTO template_evaluations (
                evaluation_id, dataset_kind, dataset_id,
                dataset_manifest_sha256, template_set_fingerprint,
                matcher_fingerprint, policy_fingerprint,
                build_fingerprint, runtime_fingerprint,
                verification_source, stable_outcome_sha256,
                expected_count, result_count, metrics_json,
                metrics_sha256, gate_passed, actor_id, completed_at
            ) VALUES (
                'legacy-locked-evaluation', 'locked',
                'legacy-locked-dataset', ?, ?, ?, ?, ?, ?,
                'untrusted_record', NULL, 1, 1, '{}', ?, 1,
                'developer-test', ?
            )
            """,
            (
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                "5" * 64,
                "6" * 64,
                hashlib.sha256(b"{}").hexdigest(),
                created_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO template_evaluation_items (
                item_id, evaluation_id, sample_id, waybill_id,
                image_sha256, truth, prediction, confidence,
                high_confidence, orientation_degrees, evidence_json,
                assessment_fingerprint, elapsed_ms, pair_issue,
                unknown_reason
            ) VALUES (
                'legacy-locked-item', 'legacy-locked-evaluation',
                'legacy-locked-sample', 'legacy-locked-waybill', ?,
                'loading', 'loading', '0.95', 1, 0, '{}', ?,
                '1.0', NULL, NULL
            )
            """,
            ("e" * 64, "a" * 64),
        )
        connection.execute(
            """
            INSERT INTO template_unknown_samples (
                sample_id, image_sha256, source_kind,
                source_evaluation_id, unknown_reason, actor_id,
                idempotency_key, request_hash, created_at
            ) VALUES (
                'legacy-calibration', ?, 'calibration', NULL,
                'Legacy calibration unknown', 'developer-test',
                'legacy-calibration-key', ?, ?
            )
            """,
            ("d" * 64, "9" * 64, created_at),
        )
        connection.commit()

    runtime = _runtime(
        data_root,
        project_root,
        instance_id="loop7-upgrade-0005",
    )
    try:
        legacy_waybill_identity = hashlib.sha256(
            b"dahe:persisted-waybill-identity:v1\0legacy-waybill"
        ).hexdigest()
        with runtime.engine.connect() as connection:
            rows = {
                (str(row["category"]), str(row["identity_sha256"]))
                for row in connection.execute(
                    text(
                        """
                        SELECT category, identity_sha256
                        FROM locked_set_exclusion_inventory
                        """
                    )
                ).mappings()
            }
        assert ("template_reference_image", "a" * 64) in rows
        assert ("development_image", "7" * 64) in rows
        assert ("development_image", "0" * 64) not in rows
        assert ("prior_locked_image", "e" * 64) in rows
        assert ("calibration_image", "d" * 64) in rows
        assert ("prior_waybill_identity", legacy_waybill_identity) in rows
    finally:
        runtime.close()


def test_completed_evaluation_is_atomic_reconciled_and_append_only(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-evaluation")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "1" * 64)
    repository = _repository(runtime)
    try:
        version, _ = _create_draft(repository, key="evaluation-draft")
        evaluation = _record_evaluation(
            repository,
            version,
            evaluation_id="development-evaluation-001",
        )

        assert evaluation.evaluation_id == "development-evaluation-001"
        assert evaluation.dataset_kind == "development"
        assert evaluation.expected_count == 1
        assert evaluation.result_count == 1
        assert evaluation.gate_passed is True
        assert evaluation.completed_at
        assert evaluation.metrics["sample_count"] == 1
        assert evaluation.metrics["high_confidence_error_count"] == 0
        with runtime.engine.connect() as connection:
            candidate = (
                connection.execute(
                    text(
                        """
                        SELECT family_id, version_id, content_sha256
                        FROM template_evaluation_candidates
                        WHERE evaluation_id = :evaluation_id
                        """
                    ),
                    {"evaluation_id": evaluation.evaluation_id},
                )
                .mappings()
                .one()
            )
            item = (
                connection.execute(
                    text(
                        """
                        SELECT sample_id, image_sha256, prediction, unknown_reason
                        FROM template_evaluation_items
                        WHERE evaluation_id = :evaluation_id
                        """
                    ),
                    {"evaluation_id": evaluation.evaluation_id},
                )
                .mappings()
                .one()
            )
        assert dict(candidate) == {
            "family_id": version.definition.family_id,
            "version_id": version.version_id,
            "content_sha256": version.content_sha256,
        }
        assert dict(item) == {
            "sample_id": "development-image-001",
            "image_sha256": "1" * 64,
            "prediction": "loading",
            "unknown_reason": None,
        }

        for statement in (
            "UPDATE template_evaluations SET gate_passed = 0",
            "UPDATE template_evaluation_candidates SET content_sha256 = '" + ("0" * 64) + "'",
            "UPDATE template_evaluation_items SET prediction = 'unknown'",
            "DELETE FROM template_evaluation_items",
        ):
            with (
                pytest.raises(IntegrityError),
                runtime.commit_gate.transaction(runtime.engine) as connection,
            ):
                connection.execute(text(statement))
    finally:
        runtime.close()


def test_latest_development_report_is_repository_validated_and_skips_invalidations(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-evaluation-report")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "1" * 64)
    repository = _repository(runtime)
    try:
        version, _ = _create_draft(repository, key="evaluation-report-draft")
        assert repository.get_latest_valid_development_evaluation(version.version_id) is None

        _record_evaluation(
            repository,
            version,
            evaluation_id="development-report-001",
            gate_passed=False,
        )
        locked = _record_evaluation(
            repository,
            version,
            evaluation_id="locked-report-ignored",
            dataset_kind="locked",
        )
        second = _record_evaluation(
            repository,
            version,
            evaluation_id="development-report-002",
        )

        latest = repository.get_latest_valid_development_evaluation(version.version_id)
        assert latest is not None
        assert latest.evaluation_id == second.evaluation_id
        assert latest.metrics["sample_count"] == 1
        assert latest.evaluation_id != locked.evaluation_id
        with runtime.engine.connect() as connection:
            prior_locked_count = connection.execute(
                text(
                    """
                    SELECT count(*)
                    FROM locked_set_exclusion_inventory
                    WHERE category = 'prior_locked_image'
                      AND identity_sha256 = :image_sha256
                    """
                ),
                {"image_sha256": "1" * 64},
            ).scalar_one()
        assert prior_locked_count == 1

        repository.invalidate_evaluation(
            evaluation_id=second.evaluation_id,
            reason="The report informed a template change",
            actor_id="developer-tastal",
        )
        assert repository.get_latest_valid_development_evaluation(version.version_id) is None
    finally:
        runtime.close()


def test_completed_evaluation_rejects_bad_hash_counts_and_candidate_identity(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-evaluation-contract")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    try:
        version, _ = _create_draft(repository, key="evaluation-contract-draft")
        revised, _ = repository.revise_draft(
            source_version_id=version.version_id,
            definition=_definition(left="0.20"),
            reference_image_sha256="d" * 64,
            reference_mask_sha256="e" * 64,
            alignment_fingerprint="f" * 64,
            expected_record_version=version.record_version,
            actor_id="developer-tastal",
            idempotency_key="evaluation-contract-revision",
        )

        with pytest.raises(
            persistence.TemplateEvaluationContractError,
            match="metrics",
        ):
            _record_evaluation(
                repository,
                version,
                evaluation_id="bad-metrics-hash",
                metrics_sha256="0" * 64,
            )
        with pytest.raises(
            persistence.TemplateEvaluationContractError,
            match="counts",
        ):
            _record_evaluation(
                repository,
                version,
                evaluation_id="bad-result-count",
                expected_count=2,
                result_count=1,
            )
        with pytest.raises(
            persistence.TemplateEvaluationContractError,
            match="content",
        ):
            _record_evaluation(
                repository,
                version,
                evaluation_id="bad-candidate-content",
                candidates=(
                    persistence.TemplateEvaluationCandidateInput(
                        version_id=version.version_id,
                        content_sha256="0" * 64,
                    ),
                ),
            )
        with pytest.raises(
            persistence.TemplateEvaluationContractError,
            match="family",
        ):
            _record_evaluation(
                repository,
                version,
                evaluation_id="duplicate-candidate-family",
                candidates=(
                    persistence.TemplateEvaluationCandidateInput(
                        version_id=version.version_id,
                        content_sha256=version.content_sha256,
                    ),
                    persistence.TemplateEvaluationCandidateInput(
                        version_id=revised.version_id,
                        content_sha256=revised.content_sha256,
                    ),
                ),
            )

        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM template_evaluations
                        WHERE evaluation_id IN (
                            'bad-metrics-hash',
                            'bad-result-count',
                            'bad-candidate-content',
                            'duplicate-candidate-family'
                        )
                        """
                    )
                ).scalar_one()
                == 0
            )
    finally:
        runtime.close()


def test_lifecycle_rejects_untrusted_or_invalidated_evaluations(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-evaluation-gate")
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    errors = _module("dahe.adapters.sqlite.template_studio")
    try:
        version, _ = _create_draft(repository, key="evaluation-gate-draft")
        failed = _record_evaluation(
            repository,
            version,
            evaluation_id="development-gate-failed",
            gate_passed=False,
        )
        locked = _record_evaluation(
            repository,
            version,
            evaluation_id="locked-gate-passed",
            dataset_kind="locked",
        )
        invalidated = _record_evaluation(
            repository,
            version,
            evaluation_id="development-gate-invalidated",
        )
        repository.invalidate_evaluation(
            evaluation_id=invalidated.evaluation_id,
            reason="The result informed a matcher threshold change",
            actor_id="developer-tastal",
        )

        for evaluation_id in (
            "missing-evaluation",
            failed.evaluation_id,
            locked.evaluation_id,
            invalidated.evaluation_id,
        ):
            with pytest.raises(errors.TemplateEvaluationGateError):
                repository.mark_development_tested(
                    version_id=version.version_id,
                    expected_record_version=version.record_version,
                    evaluation_id=evaluation_id,
                    developer_authorization_id="authorization-test-gate",
                    actor_id="developer-tastal",
                    idempotency_key=f"rejected-{evaluation_id}",
                )
        assert repository.get_version(version.version_id) == version
    finally:
        runtime.close()


def test_caller_assembled_development_record_never_authorizes_lifecycle(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-untrusted-development-record",
    )
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    try:
        version, _ = _create_draft(
            repository,
            key="untrusted-development-draft",
        )
        untrusted = _record_evaluation(
            repository,
            version,
            evaluation_id="caller-assembled-development",
            trusted=False,
        )
        assert untrusted.verification_source == "untrusted_record"
        assert untrusted.stable_outcome_sha256 is None
        assert repository.get_latest_valid_development_evaluation(version.version_id) is None
        with pytest.raises(
            persistence.TemplateEvaluationGateError,
            match="unverified",
        ):
            repository.mark_development_tested(
                version_id=version.version_id,
                expected_record_version=version.record_version,
                evaluation_id=untrusted.evaluation_id,
                developer_authorization_id="untrusted-test-authorization",
                actor_id="developer-tastal",
                idempotency_key="untrusted-development-transition",
            )
    finally:
        runtime.close()


def test_lifecycle_rejects_evaluation_after_another_shadow_family_changes(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-shadow-set-change",
    )
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    try:
        beta, _ = repository.create_draft(
            definition=_definition(family_id="scale-slip-beta"),
            reference_image_sha256="a" * 64,
            reference_mask_sha256="b" * 64,
            alignment_fingerprint="c" * 64,
            actor_id="developer-tastal",
            idempotency_key="shadow-set-beta-v1",
        )
        _, beta_shadow, _ = _publish_version_as_shadow(
            repository,
            beta,
            suffix="shadow-set-beta-v1",
        )
        alpha, _ = _create_draft(
            repository,
            key="shadow-set-alpha-v1",
        )
        alpha_evaluation = _record_evaluation(
            repository,
            alpha,
            evaluation_id="shadow-set-alpha-evaluation",
        )
        assert repository.get_latest_valid_development_evaluation(alpha.version_id) is not None

        beta_v2, _ = repository.revise_draft(
            source_version_id=beta_shadow.version_id,
            definition=_definition(
                family_id="scale-slip-beta",
                left="0.20",
            ),
            reference_image_sha256="a" * 64,
            reference_mask_sha256="b" * 64,
            alignment_fingerprint="c" * 64,
            expected_record_version=beta_shadow.record_version,
            actor_id="developer-tastal",
            idempotency_key="shadow-set-beta-v2",
        )
        _publish_version_as_shadow(
            repository,
            beta_v2,
            suffix="shadow-set-beta-v2",
        )

        assert repository.get_latest_valid_development_evaluation(alpha.version_id) is None
        with pytest.raises(
            persistence.TemplateEvaluationGateError,
            match="stale",
        ):
            repository.mark_development_tested(
                version_id=alpha.version_id,
                expected_record_version=alpha.record_version,
                evaluation_id=alpha_evaluation.evaluation_id,
                developer_authorization_id="shadow-set-authorization",
                actor_id="developer-tastal",
                idempotency_key="shadow-set-alpha-mark-tested",
            )
    finally:
        runtime.close()


def test_unknown_samples_accept_only_tuning_sources_and_hold_available_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-unknown-sample")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    errors = _module("dahe.adapters.sqlite.template_studio")
    try:
        sample, created = repository.add_unknown_sample(
            image_sha256="a" * 64,
            source_kind="development",
            source_evaluation_id=None,
            unknown_reason="No template family matched this layout",
            actor_id="developer-tastal",
            idempotency_key="unknown-development-001",
        )
        replay, replay_created = repository.add_unknown_sample(
            image_sha256="a" * 64,
            source_kind="development",
            source_evaluation_id=None,
            unknown_reason="No template family matched this layout",
            actor_id="developer-tastal",
            idempotency_key="unknown-development-001",
        )

        assert created is True
        assert replay_created is False
        assert replay == sample
        with runtime.engine.connect() as connection:
            hold = (
                connection.execute(
                    text(
                        """
                        SELECT sha256, hold_kind, owner_id, released_at
                        FROM evidence_holds
                        WHERE owner_id = :owner_id
                        """
                    ),
                    {"owner_id": sample.sample_id},
                )
                .mappings()
                .one()
            )
            assert dict(hold) == {
                "sha256": "a" * 64,
                "hold_kind": "template_unknown_sample",
                "owner_id": sample.sample_id,
                "released_at": None,
            }
            assert (
                connection.execute(
                    text("SELECT record_version FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": "a" * 64},
                ).scalar_one()
                == 2
            )

        for source_kind in ("locked", "shadow"):
            with pytest.raises(errors.TemplateUnknownSampleError):
                repository.add_unknown_sample(
                    image_sha256="d" * 64,
                    source_kind=source_kind,
                    source_evaluation_id=None,
                    unknown_reason="Gate data must not become tuning input",
                    actor_id="developer-tastal",
                    idempotency_key=f"unknown-{source_kind}",
                )

        def failpoint(name: str) -> None:
            if name == "after_unknown_sample_hold":
                raise InjectedTemplateFailure("interrupt unknown sample transaction")

        failing_repository = _repository(runtime, failpoint=failpoint)
        with pytest.raises(InjectedTemplateFailure):
            failing_repository.add_unknown_sample(
                image_sha256="d" * 64,
                source_kind="calibration",
                source_evaluation_id=None,
                unknown_reason="Weak evidence at the calibration threshold",
                actor_id="developer-tastal",
                idempotency_key="unknown-calibration-failed",
            )
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_unknown_samples "
                        "WHERE idempotency_key = 'unknown-calibration-failed'"
                    )
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_holds "
                        "WHERE idempotency_key LIKE 'template-unknown:%'"
                    )
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT record_version FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": "d" * 64},
                ).scalar_one()
                == 1
            )
    finally:
        runtime.close()


def test_template_draft_is_idempotent_and_revision_keeps_prior_version_immutable(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-immutable")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    errors = _module("dahe.adapters.sqlite.template_studio")
    try:
        with pytest.raises(errors.TemplateReferenceEvidenceError):
            repository.create_draft(
                definition=_definition(family_id="scale-slip-missing-mask"),
                reference_image_sha256="a" * 64,
                reference_mask_sha256="0" * 64,
                alignment_fingerprint="c" * 64,
                actor_id="developer-tastal",
                idempotency_key="draft-missing-mask",
            )
        first, first_created = _create_draft(repository, key="draft-001")
        replay, replay_created = _create_draft(repository, key="draft-001")

        assert first_created is True
        assert replay_created is False
        assert replay.version_id == first.version_id
        assert first.version_number == 1
        assert first.record_version == 1
        assert _template_hold(runtime, first.version_id) == {
            "sha256": "a" * 64,
            "hold_kind": "template_reference",
            "owner_id": first.version_id,
            "reason": "Protect immutable template reference image",
            "record_version": 1,
            "released_at": None,
        }
        assert _template_hold(
            runtime,
            first.version_id,
            hold_kind="template_reference_mask",
        ) == {
            "sha256": "b" * 64,
            "hold_kind": "template_reference_mask",
            "owner_id": first.version_id,
            "reason": "Protect immutable template reference mask",
            "record_version": 1,
            "released_at": None,
        }

        with pytest.raises(errors.TemplateReferenceEvidenceError):
            repository.revise_draft(
                source_version_id=first.version_id,
                definition=_definition(left="0.20"),
                reference_image_sha256="d" * 64,
                reference_mask_sha256="0" * 64,
                alignment_fingerprint="f" * 64,
                expected_record_version=first.record_version,
                actor_id="developer-tastal",
                idempotency_key="revision-missing-mask",
            )
        revised, revised_created = repository.revise_draft(
            source_version_id=first.version_id,
            definition=_definition(
                left="0.20",
                match_kind="contains",
                unit=None,
            ),
            reference_image_sha256="d" * 64,
            reference_mask_sha256="e" * 64,
            alignment_fingerprint="f" * 64,
            expected_record_version=first.record_version,
            actor_id="developer-tastal",
            idempotency_key="draft-revision-001",
        )
        assert revised_created is True
        assert revised.version_id != first.version_id
        assert revised.version_number == 2
        assert revised.parent_version_id == first.version_id
        assert repository.get_version(first.version_id) == first
        assert repository.get_version(revised.version_id) == revised
        assert revised.definition.anchors[0].match_kind.value == "contains"
        assert revised.definition.regions[0].unit is None
        assert _template_hold(runtime, revised.version_id) == {
            "sha256": "d" * 64,
            "hold_kind": "template_reference",
            "owner_id": revised.version_id,
            "reason": "Protect immutable template reference image",
            "record_version": 1,
            "released_at": None,
        }
        assert _template_hold(
            runtime,
            revised.version_id,
            hold_kind="template_reference_mask",
        ) == {
            "sha256": "e" * 64,
            "hold_kind": "template_reference_mask",
            "owner_id": revised.version_id,
            "reason": "Protect immutable template reference mask",
            "record_version": 1,
            "released_at": None,
        }

        with pytest.raises(errors.TemplateIdempotencyConflictError):
            _create_draft(repository, key="draft-001", left="0.30")
        with pytest.raises(errors.TemplateRecordVersionConflictError):
            repository.revise_draft(
                source_version_id=first.version_id,
                definition=_definition(left="0.40"),
                reference_image_sha256="1" * 64,
                reference_mask_sha256="2" * 64,
                alignment_fingerprint="3" * 64,
                expected_record_version=first.record_version - 1,
                actor_id="developer-tastal",
                idempotency_key="draft-stale-001",
            )
    finally:
        runtime.close()


def test_lifecycle_and_shadow_rollback_are_ordered_authorized_and_versioned(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-lifecycle")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    templates = _module("dahe.domain.ticket.templates")
    errors = _module("dahe.adapters.sqlite.template_studio")
    try:
        first, _ = _create_draft(repository, key="lifecycle-v1")
        first_evaluation = _record_evaluation(
            repository,
            first,
            evaluation_id="development-evaluation-v1",
        )
        with pytest.raises(errors.TemplateLifecycleTransitionError):
            repository.publish_shadow(
                version_id=first.version_id,
                expected_record_version=first.record_version,
                evaluation_id=first_evaluation.evaluation_id,
                developer_authorization_id="authorization-publish-v1",
                actor_id="developer-tastal",
                idempotency_key="publish-too-early",
            )

        tested, _ = repository.mark_development_tested(
            version_id=first.version_id,
            expected_record_version=first.record_version,
            evaluation_id=first_evaluation.evaluation_id,
            developer_authorization_id="authorization-test-v1",
            actor_id="developer-tastal",
            idempotency_key="development-tested-v1",
        )
        assert tested.lifecycle is templates.TemplateLifecycle.DEVELOPMENT_TESTED
        first_shadow, _ = repository.publish_shadow(
            version_id=first.version_id,
            expected_record_version=tested.record_version,
            evaluation_id=first_evaluation.evaluation_id,
            developer_authorization_id="authorization-publish-v1",
            actor_id="developer-tastal",
            idempotency_key="publish-shadow-v1",  # gitleaks:allow
        )
        assert first_shadow.lifecycle is templates.TemplateLifecycle.SHADOW

        second, _ = repository.revise_draft(
            source_version_id=first.version_id,
            definition=_definition(left="0.20"),
            reference_image_sha256="d" * 64,
            reference_mask_sha256="e" * 64,
            alignment_fingerprint="f" * 64,
            expected_record_version=first_shadow.record_version,
            actor_id="developer-tastal",
            idempotency_key="lifecycle-v2",
        )
        second_evaluation = _record_evaluation(
            repository,
            second,
            evaluation_id="development-evaluation-v2",
        )
        second_tested, _ = repository.mark_development_tested(
            version_id=second.version_id,
            expected_record_version=second.record_version,
            evaluation_id=second_evaluation.evaluation_id,
            developer_authorization_id="authorization-test-v2",
            actor_id="developer-tastal",
            idempotency_key="development-tested-v2",
        )
        repository.publish_shadow(
            version_id=second.version_id,
            expected_record_version=second_tested.record_version,
            evaluation_id=second_evaluation.evaluation_id,
            developer_authorization_id="authorization-publish-v2",
            actor_id="developer-tastal",
            idempotency_key="publish-shadow-v2",  # gitleaks:allow
        )
        current = repository.get_shadow_pointer(first.definition.family_id)
        assert current.version_id == second.version_id

        rolled_back, applied = repository.rollback_shadow(
            family_id=first.definition.family_id,
            target_version_id=first.version_id,
            expected_record_version=current.record_version,
            reason="Shadow regression in development fixtures",
            developer_authorization_id="authorization-rollback-v1",
            actor_id="developer-tastal",
            idempotency_key="rollback-shadow-v1",
        )
        assert applied is True
        assert rolled_back.version_id == first.version_id
        assert rolled_back.record_version == current.record_version + 1
        assert repository.get_version(second.version_id).definition == second.definition

        with pytest.raises(errors.TemplateRecordVersionConflictError):
            repository.rollback_shadow(
                family_id=first.definition.family_id,
                target_version_id=second.version_id,
                expected_record_version=current.record_version,
                reason="Stale operator screen",
                developer_authorization_id="authorization-stale",
                actor_id="developer-tastal",
                idempotency_key="rollback-stale",
            )
    finally:
        runtime.close()


def test_lifecycle_rejects_composite_without_current_db_ocr_run_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-missing-promotion-ocr-authority",
    )
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    try:
        draft, _ = _create_draft(
            repository,
            key="missing-promotion-ocr-authority-draft",
        )
        evaluation = _record_evaluation(
            repository,
            draft,
            evaluation_id=(
                "development-missing-promotion-ocr-authority"
            ),
            record_ocr_run_authority=False,
        )

        with pytest.raises(
            persistence.TemplateEvaluationGateError,
            match="evaluation",
        ):
            repository.mark_development_tested(
                version_id=draft.version_id,
                expected_record_version=draft.record_version,
                evaluation_id=evaluation.evaluation_id,
                developer_authorization_id=(
                    "authorization-missing-ocr-run"
                ),
                actor_id="developer-tastal",
                idempotency_key="mark-tested-missing-ocr-run",
            )
    finally:
        runtime.close()


def test_coordinated_composite_rehash_cannot_bypass_db_ocr_run_binding(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-coordinated-composite-rehash",
    )
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    try:
        draft, _ = _create_draft(
            repository,
            key="coordinated-composite-rehash-draft",
        )
        evaluation = _record_evaluation(
            repository,
            draft,
            evaluation_id="development-coordinated-composite-rehash",
        )
        metrics = copy.deepcopy(dict(evaluation.metrics))
        parent = metrics["composite_lifecycle"]
        full_real = metrics["composite_lifecycle_components"][
            "real_candidate_roles"
        ]
        forged_capture_build = _canonical_sha256(
            {"forged": "capture-build"}
        )
        full_real["source"]["ocr_capture_build_sha256"] = (
            forged_capture_build
        )
        full_real.pop("evaluation_sha256")
        full_real_evaluation_sha256 = _canonical_sha256(full_real)
        full_real["evaluation_sha256"] = full_real_evaluation_sha256
        parent["bindings"]["ocr_capture_build_sha256"] = (
            forged_capture_build
        )
        parent["components"]["real_candidate_roles"][
            "evaluation_sha256"
        ] = full_real_evaluation_sha256
        parent.pop("evaluation_sha256")
        parent["stable_outcome_sha256"] = _canonical_sha256(
            {
                "authorization_scope": parent[
                    "authorization_scope"
                ],
                "bindings": parent["bindings"],
                "components": parent["components"],
                "dataset_manifest_sha256": parent[
                    "dataset_manifest_sha256"
                ],
                "gate_checks": parent["gate"]["checks"],
                "schema_version": parent["schema_version"],
            }
        )
        parent["evaluation_sha256"] = _canonical_sha256(parent)
        metrics_sha256 = _canonical_sha256(metrics)
        with runtime.engine.begin() as connection:
            connection.exec_driver_sql(
                "DROP TRIGGER template_evaluations_immutable_update"
            )
            connection.execute(
                text(
                    """
                    UPDATE template_evaluations
                    SET metrics_json = :metrics_json,
                        metrics_sha256 = :metrics_sha256,
                        stable_outcome_sha256 = :stable_outcome_sha256
                    WHERE evaluation_id = :evaluation_id
                    """
                ),
                {
                    "evaluation_id": evaluation.evaluation_id,
                    "metrics_json": json.dumps(
                        metrics,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "metrics_sha256": metrics_sha256,
                    "stable_outcome_sha256": parent[
                        "stable_outcome_sha256"
                    ],
                },
            )

        assert (
            repository.get_latest_valid_development_evaluation(
                draft.version_id
            )
            is None
        )
    finally:
        runtime.close()


def test_invalidating_current_shadow_evaluation_withdraws_pointer_everywhere(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-shadow-withdraw")
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    try:
        draft, _ = _create_draft(repository, key="shadow-withdraw-draft")
        evaluation, _, pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="shadow-withdraw",
        )
        assert pointer.version_id == draft.version_id

        repository.invalidate_evaluation(
            evaluation_id=evaluation.evaluation_id,
            reason="The current shadow evidence is no longer trusted",
            actor_id="developer-tastal",
        )

        with pytest.raises(persistence.TemplateNotFoundError):
            repository.get_shadow_pointer(draft.definition.family_id)
        assert repository.list_current_eligible_shadow_versions() == ()
        summaries = repository.list_families()
        assert len(summaries) == 1
        assert summaries[0].shadow_version_id is None
        assert (
            repository.get_family_current(draft.definition.family_id).summary.shadow_version_id
            is None
        )
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM template_shadow_pointers")
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_audit_events "
                        "WHERE event_kind = "
                        "'template.shadow_withdrawn_after_evaluation_invalidation'"
                    )
                ).scalar_one()
                == 1
            )
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "terminal_status",
    ("business_failed", "technical_failed"),
)
def test_newer_terminal_composite_failure_blocks_old_success_and_withdraws_shadow(
    tmp_path: Path,
    project_root: Path,
    terminal_status: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id=f"loop7-terminal-{terminal_status}",
    )
    try:
        _seed_reference_image(runtime, "a" * 64, "b" * 64)
        repository = _repository(runtime)
        draft, _ = _create_draft(
            repository,
            key=f"terminal-{terminal_status}-draft",
        )
        evaluation, shadow, pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix=f"terminal-{terminal_status}",
        )
        scope = repository.get_composite_lifecycle_attempt_scope(
            evaluation.evaluation_id
        )
        monkeypatch.setattr(
            _module("dahe.adapters.sqlite.template_studio"),
            "_utc_now",
            lambda: "2000-01-01T00:00:00+00:00",
        )

        failure = repository.record_composite_lifecycle_failure(
            scope=scope,
            terminal_status=terminal_status,
            failure_code=f"LOOP7-{terminal_status.upper()}",
            actor_id="loop7-terminal-test",
        )

        assert failure.attempt_sequence > 0
        assert failure.terminal_status == terminal_status
        assert failure.created_at == "2000-01-01T00:00:00+00:00"
        assert repository.get_latest_valid_development_evaluation(
            shadow.version_id
        ) is None
        with pytest.raises(
            Exception,
            match="no shadow publication",
        ):
            repository.get_shadow_pointer(pointer.family_id)
        with runtime.engine.connect() as connection:
            latest = connection.execute(
                text(
                    "SELECT terminal_status, evaluation_id "
                    "FROM template_lifecycle_attempts "
                    "WHERE scope_sha256 = :scope_sha256 "
                    "ORDER BY attempt_sequence DESC LIMIT 1"
                ),
                {"scope_sha256": scope.scope_sha256},
            ).mappings().one()
        assert dict(latest) == {
            "terminal_status": terminal_status,
            "evaluation_id": None,
        }
    finally:
        runtime.close()


def test_composite_terminal_failure_in_different_scope_does_not_revoke_shadow(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-terminal-scope-isolation",
    )
    try:
        _seed_reference_image(runtime, "a" * 64, "b" * 64)
        repository = _repository(runtime)
        draft, _ = _create_draft(
            repository,
            key="terminal-scope-isolation-draft",
        )
        evaluation, shadow, pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="terminal-scope-isolation",
        )
        scope = repository.get_composite_lifecycle_attempt_scope(
            evaluation.evaluation_id
        )
        other_scope = replace(
            scope,
            runtime_set_sha256="d" * 64,
        ).with_recomputed_identity()

        repository.record_composite_lifecycle_failure(
            scope=other_scope,
            terminal_status="technical_failed",
            failure_code="LOOP7-DIFFERENT-RUNTIME",
            actor_id="loop7-terminal-test",
        )

        latest = repository.get_latest_valid_development_evaluation(
            shadow.version_id
        )
        assert latest is not None
        assert latest.evaluation_id == evaluation.evaluation_id
        assert repository.get_shadow_pointer(pointer.family_id) == pointer
    finally:
        runtime.close()


def test_template_lifecycle_terminal_attempts_are_immutable(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-terminal-attempt-immutable",
    )
    try:
        _seed_reference_image(runtime, "a" * 64, "b" * 64)
        repository = _repository(runtime)
        draft, _ = _create_draft(
            repository,
            key="terminal-attempt-immutable-draft",
        )
        evaluation = _record_evaluation(
            repository,
            draft,
            evaluation_id="terminal-attempt-immutable-evaluation",
        )
        scope = repository.get_composite_lifecycle_attempt_scope(
            evaluation.evaluation_id
        )
        failure = repository.record_composite_lifecycle_failure(
            scope=scope,
            terminal_status="technical_failed",
            failure_code="LOOP7-IMMUTABLE",
            actor_id="loop7-terminal-test",
        )

        with (
            runtime.engine.begin() as connection,
            pytest.raises(IntegrityError, match="append-only"),
        ):
            connection.execute(
                text(
                    "UPDATE template_lifecycle_attempts "
                    "SET terminal_status = 'succeeded' "
                    "WHERE attempt_sequence = :attempt_sequence"
                ),
                {"attempt_sequence": failure.attempt_sequence},
            )
        with (
            runtime.engine.begin() as connection,
            pytest.raises(IntegrityError, match="append-only"),
        ):
            connection.execute(
                text(
                    "DELETE FROM template_lifecycle_attempts "
                    "WHERE attempt_sequence = :attempt_sequence"
                ),
                {"attempt_sequence": failure.attempt_sequence},
            )
    finally:
        runtime.close()


def test_newer_same_scope_ocr_failure_withdraws_dependent_shadow_atomically(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-ocr-failure-shadow-withdrawal",
    )
    try:
        _seed_reference_image(runtime, "a" * 64, "b" * 64)
        repository = _repository(runtime)
        draft, _ = _create_draft(
            repository,
            key="ocr-failure-shadow-withdrawal-draft",
        )
        evaluation, shadow, pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="ocr-failure-shadow-withdrawal",
        )
        scope = repository.get_composite_lifecycle_attempt_scope(
            evaluation.evaluation_id
        )
        run_module = _module(
            "dahe.adapters.sqlite.candidate_development_ocr"
        )
        failed_evidence_sha256 = "f" * 64
        same_scope_failure = (
            run_module.CandidateDevelopmentOcrTerminalAttemptInput(
                evidence_sha256=failed_evidence_sha256,
                evidence_blob_sha256="e" * 64,
                evidence_relative_path=(
                    "development/protected-candidate-review-ocr/"
                    f"records/sha256/{failed_evidence_sha256[:2]}/"
                    f"{failed_evidence_sha256[2:4]}/"
                    f"{failed_evidence_sha256}.json"
                ),
                evidence_byte_size=1024,
                package_sha256=scope.package_sha256,
                review_history_authority_sha256=(
                    scope.review_history_authority_sha256
                ),
                source_authority_sha256=(
                    scope.source_authority_sha256
                ),
                reviewer_id=scope.reviewer_id,
                application_build_sha256=(
                    scope.ocr_capture_build_sha256
                ),
                composition_evidence_sha256=(
                    scope.composition_evidence_sha256
                ),
                runtime_set_sha256=scope.runtime_set_sha256,
                pipeline_contract_sha256=(
                    scope.pipeline_contract_sha256
                ),
                completion_status="failed",
                completed_at="2020-01-01T00:00:00+00:00",
                terminal_status="technical_failed",
            )
        )
        run_repository = (
            run_module.SqliteCandidateDevelopmentOcrRunRepository(
                runtime=runtime
            )
        )
        other_evidence_sha256 = "c" * 64
        run_repository.record_failed_run(
            replace(
                same_scope_failure,
                evidence_sha256=other_evidence_sha256,
                evidence_blob_sha256="d" * 64,
                evidence_relative_path=(
                    "development/protected-candidate-review-ocr/"
                    f"records/sha256/{other_evidence_sha256[:2]}/"
                    f"{other_evidence_sha256[2:4]}/"
                    f"{other_evidence_sha256}.json"
                ),
                runtime_set_sha256="d" * 64,
            )
        )
        assert repository.get_latest_valid_development_evaluation(
            shadow.version_id
        ) is not None
        assert repository.get_shadow_pointer(pointer.family_id) == pointer

        attempt, created = run_repository.record_failed_run(
            same_scope_failure
        )

        assert created is True
        assert attempt.terminal_status == "technical_failed"
        assert repository.get_latest_valid_development_evaluation(
            shadow.version_id
        ) is None
        with pytest.raises(Exception, match="no shadow publication"):
            repository.get_shadow_pointer(pointer.family_id)
    finally:
        runtime.close()


def test_invalidating_noncurrent_shadow_preserves_current_and_blocks_rollback(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-shadow-history")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    try:
        first, _ = _create_draft(repository, key="shadow-history-v1")
        first_evaluation, first_shadow, _ = _publish_version_as_shadow(
            repository,
            first,
            suffix="shadow-history-v1",
        )
        second, _ = repository.revise_draft(
            source_version_id=first.version_id,
            definition=_definition(left="0.20"),
            reference_image_sha256="d" * 64,
            reference_mask_sha256="e" * 64,
            alignment_fingerprint="f" * 64,
            expected_record_version=first_shadow.record_version,
            actor_id="developer-tastal",
            idempotency_key="shadow-history-v2",
        )
        _, _, second_pointer = _publish_version_as_shadow(
            repository,
            second,
            suffix="shadow-history-v2",
        )

        repository.invalidate_evaluation(
            evaluation_id=first_evaluation.evaluation_id,
            reason="Only the historical v1 evaluation is invalid",
            actor_id="developer-tastal",
        )

        assert repository.get_shadow_pointer(first.definition.family_id) == second_pointer
        eligible = repository.list_current_eligible_shadow_versions()
        assert tuple(version.version_id for version in eligible) == (second.version_id,)
        assert repository.list_families()[0].shadow_version_id == second.version_id
        with pytest.raises(persistence.TemplateEvaluationGateError):
            repository.rollback_shadow(
                family_id=first.definition.family_id,
                target_version_id=first.version_id,
                expected_record_version=second_pointer.record_version,
                reason="Invalidated v1 cannot become current again",
                developer_authorization_id="authorization-invalid-rollback",
                actor_id="developer-tastal",
                idempotency_key="rollback-invalidated-v1",
            )
        assert repository.get_shadow_pointer(first.definition.family_id) == second_pointer
    finally:
        runtime.close()


def test_template_authority_writes_register_all_locked_set_exclusion_sources(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-authoritative-exclusion-sources",
    )
    _seed_reference_image(
        runtime,
        "a" * 64,
        "b" * 64,
        "d" * 64,
        "1" * 64,
        "2" * 64,
    )
    repository = _repository(runtime)
    try:
        version, _ = _create_draft(
            repository,
            key="authoritative-exclusion-draft",
        )
        _record_evaluation(
            repository,
            version,
            evaluation_id="authoritative-development-evaluation",
            items=(
                _evaluation_item(
                    image_sha256="1" * 64,
                    waybill_identity_sha256="e" * 64,
                ),
            ),
        )
        _record_evaluation(
            repository,
            version,
            evaluation_id="synthetic-development-evaluation",
            items=(
                _evaluation_item(
                    sample_id="synthetic-observation-001",
                    image_sha256="3" * 64,
                    waybill_identity_sha256="0" * 64,
                ),
            ),
        )
        _record_evaluation(
            repository,
            version,
            evaluation_id="authoritative-shadow-evaluation",
            dataset_kind="shadow",
            items=(
                _evaluation_item(
                    sample_id="shadow-image-001",
                    image_sha256="2" * 64,
                    waybill_identity_sha256="f" * 64,
                ),
            ),
        )
        repository.add_unknown_sample(
            image_sha256="d" * 64,
            source_kind="calibration",
            source_evaluation_id=None,
            unknown_reason="Calibration evidence remained unknown",
            actor_id="developer-tastal",
            idempotency_key="authoritative-calibration-unknown",
        )

        with runtime.engine.connect() as connection:
            rows = {
                (str(row["category"]), str(row["identity_sha256"]))
                for row in connection.execute(
                    text(
                        """
                        SELECT category, identity_sha256
                        FROM locked_set_exclusion_inventory
                        """
                    )
                ).mappings()
            }

        assert ("template_reference_image", "a" * 64) in rows
        assert ("development_image", "1" * 64) in rows
        assert ("shadow_image", "2" * 64) in rows
        assert ("development_image", "3" * 64) not in rows
        assert ("calibration_image", "d" * 64) in rows
        assert ("prior_waybill_identity", "e" * 64) in rows
        assert ("prior_waybill_identity", "f" * 64) in rows
    finally:
        runtime.close()


def test_shadow_reads_fail_closed_when_accepted_build_fingerprint_changes(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-shadow-build")
    _seed_reference_image(runtime, "a" * 64, "b" * 64)
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    try:
        draft, _ = _create_draft(repository, key="shadow-build-draft")
        _, _, pointer = _publish_version_as_shadow(
            repository,
            draft,
            suffix="shadow-build-v1",
        )
        changed_build_repository = persistence.SqliteTemplateRepository(
            runtime=runtime,
            accepted_build_fingerprint="9" * 64,
        )

        with pytest.raises(persistence.TemplateEvaluationGateError):
            changed_build_repository.get_shadow_pointer(draft.definition.family_id)
        with pytest.raises(persistence.TemplateEvaluationGateError):
            changed_build_repository.list_current_eligible_shadow_versions()
        assert changed_build_repository.list_families()[0].shadow_version_id is None
        assert (
            changed_build_repository.get_family_current(
                draft.definition.family_id
            ).summary.shadow_version_id
            is None
        )
        with runtime.engine.connect() as connection:
            stored = connection.execute(
                text(
                    "SELECT version_id FROM template_shadow_pointers WHERE family_id = :family_id"
                ),
                {"family_id": draft.definition.family_id},
            ).scalar_one()
            assert stored == pointer.version_id
    finally:
        runtime.close()


def test_reference_hold_and_template_revision_roll_back_together_on_failure(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-hold-atomicity")
    _seed_reference_image(runtime, "a" * 64, "b" * 64, "d" * 64, "e" * 64)
    repository = _repository(runtime)
    try:
        first, _ = _create_draft(repository, key="hold-atomicity-v1")

        def failpoint(name: str) -> None:
            if name == "after_reference_hold":
                raise InjectedTemplateFailure("interrupt after reference hold")

        failing_repository = _repository(runtime, failpoint=failpoint)
        with pytest.raises(InjectedTemplateFailure):
            failing_repository.revise_draft(
                source_version_id=first.version_id,
                definition=_definition(left="0.20"),
                reference_image_sha256="d" * 64,
                reference_mask_sha256="e" * 64,
                alignment_fingerprint="f" * 64,
                expected_record_version=first.record_version,
                actor_id="developer-tastal",
                idempotency_key="hold-atomicity-v2",
            )

        with runtime.engine.connect() as connection:
            assert (
                connection.execute(text("SELECT count(*) FROM template_versions")).scalar_one() == 1
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_holds WHERE hold_kind = 'template_reference'"
                    )
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT record_version FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": "d" * 64},
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_idempotency_records "
                        "WHERE idempotency_key = 'hold-atomicity-v2'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        runtime.close()


def test_reference_upload_and_derived_mask_are_durable_strict_and_idempotent(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "reference-upload"
    runtime = _runtime(data_root, project_root, instance_id="loop7-reference-upload")
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    image_sha256 = "1" * 64
    mask_sha256 = "2" * 64
    try:
        staged, staged_now = repository.stage_reference_upload(
            image_sha256=image_sha256,
            relative_path=f"sha256/11/11/{image_sha256}.blob",
            byte_size=1234,
            media_type="image/png",
            width=1280,
            height=720,
            actor_id="developer-tastal",
            idempotency_key="stage-reference-001",
        )
        replay, replayed_now = repository.stage_reference_upload(
            image_sha256=image_sha256,
            relative_path=f"sha256/11/11/{image_sha256}.blob",
            byte_size=1234,
            media_type="image/png",
            width=1280,
            height=720,
            actor_id="developer-tastal",
            idempotency_key="stage-reference-001",
        )
        mask, mask_registered = repository.register_derived_template_mask(
            sha256=mask_sha256,
            relative_path=f"sha256/22/22/{mask_sha256}.blob",
            byte_size=321,
            actor_id="developer-tastal",
            idempotency_key="register-mask-001",
        )
        mask_replay, mask_registered_again = repository.register_derived_template_mask(
            sha256=mask_sha256,
            relative_path=f"sha256/22/22/{mask_sha256}.blob",
            byte_size=321,
            actor_id="developer-tastal",
            idempotency_key="register-mask-001",
        )

        assert staged_now is True
        assert replayed_now is False
        assert replay == staged
        assert staged.image_sha256 == image_sha256
        assert staged.state == "staged"
        assert staged.record_version == 1
        assert mask_registered is True
        assert mask_registered_again is False
        assert mask_replay == mask
        assert mask.sha256 == mask_sha256
        assert mask.media_type == "image/png"
        with pytest.raises(persistence.TemplateIdempotencyConflictError):
            repository.stage_reference_upload(
                image_sha256=image_sha256,
                relative_path=f"sha256/11/11/{image_sha256}.blob",
                byte_size=1234,
                media_type="image/png",
                width=1281,
                height=720,
                actor_id="developer-tastal",
                idempotency_key="stage-reference-001",
            )
        with pytest.raises(persistence.TemplateReferenceEvidenceError):
            repository.stage_reference_upload(
                image_sha256=image_sha256,
                relative_path=f"sha256/11/11/{image_sha256}.blob",
                byte_size=9999,
                media_type="image/png",
                width=1280,
                height=720,
                actor_id="developer-tastal",
                idempotency_key="stage-reference-conflict",
            )
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_holds "
                        "WHERE hold_kind = 'template_reference_upload' "
                        "AND released_at IS NULL"
                    )
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM evidence_holds WHERE sha256 = :sha256"),
                    {"sha256": mask_sha256},
                ).scalar_one()
                == 0
            )
    finally:
        runtime.close()

    restarted = _runtime(
        data_root,
        project_root,
        instance_id="loop7-reference-upload-restarted",
    )
    try:
        assert _repository(restarted).get_reference_upload(staged.staged_reference_id) == staged
    finally:
        restarted.close()


def test_stale_reference_upload_expiry_releases_only_its_active_hold(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        project_root,
        instance_id="loop7-reference-expiry",
    )
    repository = _repository(runtime)
    image_sha256 = "1" * 64
    try:
        staged, _ = repository.stage_reference_upload(
            image_sha256=image_sha256,
            relative_path=f"sha256/11/11/{image_sha256}.blob",
            byte_size=1234,
            media_type="image/png",
            width=1280,
            height=720,
            actor_id="developer-tastal",
            idempotency_key="stage-expiring-reference",
        )

        expired_count = repository.expire_staged_reference_uploads(
            older_than=datetime.now(UTC) + timedelta(seconds=1),
        )

        assert expired_count == 1
        expired = repository.get_reference_upload(staged.staged_reference_id)
        assert expired.state == "abandoned"
        assert expired.record_version == 2
        with runtime.engine.connect() as connection:
            hold = (
                connection.execute(
                    text(
                        """
                        SELECT released_at
                        FROM evidence_holds
                        WHERE hold_kind = 'template_reference_upload'
                          AND owner_id = :owner_id
                        """
                    ),
                    {"owner_id": staged.staged_reference_id},
                )
                .mappings()
                .one()
            )
            assert hold["released_at"] is not None
    finally:
        runtime.close()


def test_reference_upload_transaction_rolls_back_on_failure(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-stage-failure")

    def failpoint(name: str) -> None:
        if name == "after_reference_upload_hold":
            raise InjectedTemplateFailure("interrupt staged reference transaction")

    repository = _repository(runtime, failpoint=failpoint)
    image_sha256 = "3" * 64
    try:
        with pytest.raises(InjectedTemplateFailure):
            repository.stage_reference_upload(
                image_sha256=image_sha256,
                relative_path=f"sha256/33/33/{image_sha256}.blob",
                byte_size=1234,
                media_type="image/png",
                width=1280,
                height=720,
                actor_id="developer-tastal",
                idempotency_key="stage-reference-failed",
            )
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM template_reference_uploads")
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_holds "
                        "WHERE hold_kind = 'template_reference_upload'"
                    )
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": image_sha256},
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_idempotency_records "
                        "WHERE idempotency_key = 'stage-reference-failed'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        runtime.close()


def test_create_draft_consumes_staged_reference_and_transfers_evidence_holds(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-consume-reference")
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    image_sha256 = "4" * 64
    mask_sha256 = "5" * 64
    try:
        staged, _ = repository.stage_reference_upload(
            image_sha256=image_sha256,
            relative_path=f"sha256/44/44/{image_sha256}.blob",
            byte_size=1234,
            media_type="image/png",
            width=1280,
            height=720,
            actor_id="developer-tastal",
            idempotency_key="stage-reference-consume",
        )
        repository.register_derived_template_mask(
            sha256=mask_sha256,
            relative_path=f"sha256/55/55/{mask_sha256}.blob",
            byte_size=321,
            actor_id="developer-tastal",
            idempotency_key="register-mask-consume",
        )
        with pytest.raises(persistence.TemplateReferenceUploadError):
            repository.create_draft(
                definition=_definition(family_id="scale-slip-staged"),
                reference_image_sha256=image_sha256,
                reference_mask_sha256=mask_sha256,
                alignment_fingerprint="6" * 64,
                actor_id="developer-tastal",
                idempotency_key="create-unversioned-staged-draft",
                staged_reference_id=staged.staged_reference_id,
            )
        with pytest.raises(persistence.TemplateRecordVersionConflictError):
            repository.create_draft(
                definition=_definition(family_id="scale-slip-staged"),
                reference_image_sha256=image_sha256,
                reference_mask_sha256=mask_sha256,
                alignment_fingerprint="6" * 64,
                actor_id="developer-tastal",
                idempotency_key="create-stale-staged-draft",
                staged_reference_id=staged.staged_reference_id,
                expected_staged_reference_record_version=(staged.record_version + 1),
            )
        with pytest.raises(persistence.TemplateReferenceUploadError):
            repository.create_draft(
                definition=_definition(family_id="scale-slip-staged"),
                reference_image_sha256="0" * 64,
                reference_mask_sha256=mask_sha256,
                alignment_fingerprint="6" * 64,
                actor_id="developer-tastal",
                idempotency_key="create-mismatched-staged-draft",
                staged_reference_id=staged.staged_reference_id,
                expected_staged_reference_record_version=staged.record_version,
            )
        version, created = repository.create_draft(
            definition=_definition(family_id="scale-slip-staged"),
            reference_image_sha256=image_sha256,
            reference_mask_sha256=mask_sha256,
            alignment_fingerprint="6" * 64,
            actor_id="developer-tastal",
            idempotency_key="create-staged-draft",
            staged_reference_id=staged.staged_reference_id,
            expected_staged_reference_record_version=staged.record_version,
        )
        replay, replay_created = repository.create_draft(
            definition=_definition(family_id="scale-slip-staged"),
            reference_image_sha256=image_sha256,
            reference_mask_sha256=mask_sha256,
            alignment_fingerprint="6" * 64,
            actor_id="developer-tastal",
            idempotency_key="create-staged-draft",
            staged_reference_id=staged.staged_reference_id,
            expected_staged_reference_record_version=staged.record_version,
        )

        assert created is True
        assert replay_created is False
        assert replay == version
        consumed = repository.get_reference_upload(staged.staged_reference_id)
        assert consumed.state == "consumed"
        assert consumed.record_version == 2
        with pytest.raises(persistence.TemplateReferenceUploadError):
            repository.abandon_reference_upload(
                staged_reference_id=staged.staged_reference_id,
                expected_record_version=consumed.record_version,
                actor_id="developer-tastal",
                idempotency_key="abandon-consumed-reference",
            )
        with runtime.engine.connect() as connection:
            holds = {
                str(row["hold_kind"]): dict(row)
                for row in connection.execute(
                    text(
                        """
                        SELECT hold_kind, sha256, owner_id, released_at
                        FROM evidence_holds
                        WHERE sha256 IN (:image_sha256, :mask_sha256)
                        ORDER BY hold_kind
                        """
                    ),
                    {
                        "image_sha256": image_sha256,
                        "mask_sha256": mask_sha256,
                    },
                )
                .mappings()
                .all()
            }
            assert holds["template_reference_upload"]["released_at"] is not None
            assert holds["template_reference"]["owner_id"] == version.version_id
            assert holds["template_reference"]["released_at"] is None
            assert holds["template_reference_mask"]["owner_id"] == version.version_id
            assert holds["template_reference_mask"]["released_at"] is None
            versions = dict(
                connection.execute(
                    text(
                        "SELECT sha256, record_version FROM evidence_blobs "
                        "WHERE sha256 IN (:image_sha256, :mask_sha256)"
                    ),
                    {
                        "image_sha256": image_sha256,
                        "mask_sha256": mask_sha256,
                    },
                ).all()
            )
            assert versions == {image_sha256: 4, mask_sha256: 2}
    finally:
        runtime.close()


def test_consuming_reference_is_atomic_and_abandon_never_deletes_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="loop7-reference-finalize")
    repository = _repository(runtime)
    persistence = _module("dahe.adapters.sqlite.template_studio")
    image_sha256 = "7" * 64
    mask_sha256 = "8" * 64
    abandoned_sha256 = "9" * 64
    try:
        staged, _ = repository.stage_reference_upload(
            image_sha256=image_sha256,
            relative_path=f"sha256/77/77/{image_sha256}.blob",
            byte_size=1234,
            media_type="image/png",
            width=1280,
            height=720,
            actor_id="developer-tastal",
            idempotency_key="stage-reference-atomic",
        )
        repository.register_derived_template_mask(
            sha256=mask_sha256,
            relative_path=f"sha256/88/88/{mask_sha256}.blob",
            byte_size=321,
            actor_id="developer-tastal",
            idempotency_key="register-mask-atomic",
        )

        def failpoint(name: str) -> None:
            if name == "after_reference_upload_consumed":
                raise InjectedTemplateFailure("interrupt consumed reference transaction")

        failing_repository = _repository(runtime, failpoint=failpoint)
        with pytest.raises(InjectedTemplateFailure):
            failing_repository.create_draft(
                definition=_definition(family_id="scale-slip-atomic"),
                reference_image_sha256=image_sha256,
                reference_mask_sha256=mask_sha256,
                alignment_fingerprint="a" * 64,
                actor_id="developer-tastal",
                idempotency_key="create-staged-draft-failed",
                staged_reference_id=staged.staged_reference_id,
                expected_staged_reference_record_version=staged.record_version,
            )
        assert repository.get_reference_upload(staged.staged_reference_id) == staged
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_families "
                        "WHERE family_id = 'scale-slip-atomic'"
                    )
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_holds "
                        "WHERE hold_kind IN ('template_reference', "
                        "'template_reference_mask')"
                    )
                ).scalar_one()
                == 0
            )

        abandoned, _ = repository.stage_reference_upload(
            image_sha256=abandoned_sha256,
            relative_path=f"sha256/99/99/{abandoned_sha256}.blob",
            byte_size=456,
            media_type="image/png",
            width=640,
            height=480,
            actor_id="developer-tastal",
            idempotency_key="stage-reference-abandon",
        )
        abandoned_result, abandoned_now = repository.abandon_reference_upload(
            staged_reference_id=abandoned.staged_reference_id,
            expected_record_version=abandoned.record_version,
            actor_id="developer-tastal",
            idempotency_key="abandon-reference-001",
        )
        abandon_replay, abandoned_again = repository.abandon_reference_upload(
            staged_reference_id=abandoned.staged_reference_id,
            expected_record_version=abandoned.record_version,
            actor_id="developer-tastal",
            idempotency_key="abandon-reference-001",
        )
        assert abandoned_now is True
        assert abandoned_again is False
        assert abandon_replay == abandoned_result
        assert abandoned_result.state == "abandoned"
        assert abandoned_result.record_version == 2
        with pytest.raises(persistence.TemplateReferenceUploadError):
            repository.abandon_reference_upload(
                staged_reference_id=abandoned.staged_reference_id,
                expected_record_version=abandoned_result.record_version,
                actor_id="developer-tastal",
                idempotency_key="abandon-reference-again",
            )
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": abandoned_sha256},
                ).scalar_one()
                == 1
            )
            hold = (
                connection.execute(
                    text(
                        "SELECT released_at FROM evidence_holds "
                        "WHERE hold_kind = 'template_reference_upload' "
                        "AND owner_id = :owner_id"
                    ),
                    {"owner_id": abandoned.staged_reference_id},
                )
                .mappings()
                .one()
            )
            assert hold["released_at"] is not None
    finally:
        runtime.close()
