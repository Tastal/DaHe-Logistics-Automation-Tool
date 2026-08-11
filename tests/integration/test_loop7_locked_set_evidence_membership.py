from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.sqlite.locked_set import (
    SqliteLockedSetRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.locked_set_evidence import (
    LockedSetEvidenceInventory,
    stage_locked_set_evidence,
)
from dahe.application.template_studio.locked_set_release import (
    LockedSetReleaseService,
)
from dahe.maintenance.backup import SqliteBackupService


class InjectedEvidenceMembershipFailure(RuntimeError):
    pass


def _runtime(
    data_root: Path,
    project_root: Path,
    *,
    instance_id: str,
) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=instance_id,
    )


def _repository(
    runtime: SqliteRuntime,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> SqliteLockedSetRepository:
    return SqliteLockedSetRepository(
        runtime=runtime,
        failpoint=failpoint,
    )


def _write_fixture(
    root: Path,
    *,
    dataset_id: str,
) -> tuple[Path, Path]:
    dataset_root = root / dataset_id
    waybills: list[dict[str, object]] = []
    for waybill_index in range(50):
        images: list[dict[str, object]] = []
        for slot, ordinary_net in (
            ("loading", "30.00"),
            ("unloading", "29.98"),
        ):
            relative_path = f"images/{waybill_index + 1:03d}-{slot}.png"
            content = (f"locked evidence {dataset_id} {waybill_index + 1:03d} {slot}").encode()
            target = dataset_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            images.append(
                {
                    "image_sha256": hashlib.sha256(content).hexdigest(),
                    "relative_path": relative_path,
                    "submitted_slot": slot,
                    "role": slot,
                    "ordinary_net": ordinary_net,
                }
            )
        waybills.append(
            {
                "sample_id": (f"{dataset_id}-waybill-{waybill_index + 1:03d}"),
                "waybill_identity_sha256": hashlib.sha256(
                    (f"{dataset_id}:waybill:{waybill_index + 1:03d}").encode()
                ).hexdigest(),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": images,
            }
        )
    manifest_path = dataset_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "dataset_id": dataset_id,
                "dataset_kind": "locked",
                "tuning_prohibited": True,
                "waybills": waybills,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest_path, dataset_root


def _preflight_and_stage(
    *,
    repository: SqliteLockedSetRepository,
    store: ContentAddressedEvidenceStore,
    fixture_root: Path,
    dataset_id: str,
) -> tuple[Any, LockedSetEvidenceInventory]:
    manifest_path, dataset_root = _write_fixture(
        fixture_root,
        dataset_id=dataset_id,
    )
    release = LockedSetReleaseService(repository=repository).seal_and_preflight(
        manifest_path=manifest_path,
        dataset_root=dataset_root,
        actor_id="developer-test",
    )
    manifest = repository.get_manifest(dataset_id)
    inventory = stage_locked_set_evidence(
        manifest=manifest,
        dataset_root=dataset_root,
        evidence_store=store,
    )
    return release, inventory


def _count(runtime: SqliteRuntime, statement: str) -> int:
    with runtime.engine.connect() as connection:
        return int(connection.execute(text(statement)).scalar_one())


def test_registration_is_atomic_idempotent_and_holds_survive_invalidation(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="locked-evidence-membership",
    )
    store = ContentAddressedEvidenceStore(data_root / "evidence")
    try:
        repository = _repository(runtime)
        release, inventory = _preflight_and_stage(
            repository=repository,
            store=store,
            fixture_root=tmp_path / "fixture",
            dataset_id="locked-evidence-membership",
        )
        first = repository.register_evidence_membership(
            dataset_id=release.dataset.dataset_id,
            manifest_sha256=release.dataset.manifest_sha256,
            images=inventory.images,
        )
        with runtime.engine.connect() as connection:
            versions_before = tuple(
                connection.execute(
                    text(
                        """
                        SELECT sha256, record_version
                        FROM evidence_blobs
                        ORDER BY sha256
                        """
                    )
                ).all()
            )
        replay = repository.register_evidence_membership(
            dataset_id=release.dataset.dataset_id,
            manifest_sha256=release.dataset.manifest_sha256,
            images=inventory.images,
        )
        with runtime.engine.connect() as connection:
            versions_after = tuple(
                connection.execute(
                    text(
                        """
                        SELECT sha256, record_version
                        FROM evidence_blobs
                        ORDER BY sha256
                        """
                    )
                ).all()
            )

        assert first.applied is True
        assert replay.applied is False
        assert first.image_count == replay.image_count == 100
        assert first.total_bytes == replay.total_bytes > 0
        assert _count(runtime, "SELECT count(*) FROM evidence_blobs") == 100
        assert (
            _count(
                runtime,
                "SELECT count(*) FROM evidence_references "
                "WHERE owner_kind = 'locked_set_dataset' "
                "AND released_at IS NULL",
            )
            == 100
        )
        assert (
            _count(
                runtime,
                "SELECT count(*) FROM evidence_holds "
                "WHERE hold_kind = 'locked_set_member' "
                "AND released_at IS NULL",
            )
            == 100
        )
        assert versions_before == versions_after

        current = repository.get_dataset(release.dataset.dataset_id)
        repository.invalidate_locked_set(
            dataset_id=current.dataset_id,
            expected_record_version=current.record_version,
            influence_kind="code",
            reason="exercise durable locked-set retention",
            actor_id="developer-test",
            idempotency_key="invalidate-locked-evidence-membership",
        )
        assert (
            _count(
                runtime,
                "SELECT count(*) FROM evidence_holds "
                "WHERE hold_kind = 'locked_set_member' "
                "AND released_at IS NULL",
            )
            == 100
        )
    finally:
        runtime.close()


def test_mid_registration_failure_rolls_back_every_database_member(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="locked-evidence-rollback",
    )
    store = ContentAddressedEvidenceStore(data_root / "evidence")
    try:
        repository = _repository(runtime)
        release, inventory = _preflight_and_stage(
            repository=repository,
            store=store,
            fixture_root=tmp_path / "fixture",
            dataset_id="locked-evidence-rollback",
        )
        completed = 0

        def failpoint(name: str) -> None:
            nonlocal completed
            if name != "after_locked_set_evidence_member":
                return
            completed += 1
            if completed == 37:
                raise InjectedEvidenceMembershipFailure(name)

        failing = _repository(runtime, failpoint=failpoint)
        with pytest.raises(InjectedEvidenceMembershipFailure):
            failing.register_evidence_membership(
                dataset_id=release.dataset.dataset_id,
                manifest_sha256=release.dataset.manifest_sha256,
                images=inventory.images,
            )

        assert _count(runtime, "SELECT count(*) FROM evidence_blobs") == 0
        assert _count(runtime, "SELECT count(*) FROM evidence_references") == 0
        assert _count(runtime, "SELECT count(*) FROM evidence_holds") == 0

        retry = repository.register_evidence_membership(
            dataset_id=release.dataset.dataset_id,
            manifest_sha256=release.dataset.manifest_sha256,
            images=inventory.images,
        )
        assert retry.applied is True
        assert _count(runtime, "SELECT count(*) FROM evidence_blobs") == 100
        assert _count(runtime, "SELECT count(*) FROM evidence_references") == 100
        assert _count(runtime, "SELECT count(*) FROM evidence_holds") == 100
    finally:
        runtime.close()


def test_online_backup_contains_all_active_locked_set_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="locked-evidence-backup",
    )
    store = ContentAddressedEvidenceStore(data_root / "evidence")
    try:
        repository = _repository(runtime)
        release, inventory = _preflight_and_stage(
            repository=repository,
            store=store,
            fixture_root=tmp_path / "fixture",
            dataset_id="locked-evidence-backup",
        )
        repository.register_evidence_membership(
            dataset_id=release.dataset.dataset_id,
            manifest_sha256=release.dataset.manifest_sha256,
            images=inventory.images,
        )

        backup = SqliteBackupService(
            runtime=runtime,
            evidence_store=store,
            backup_root=tmp_path / "backups",
        ).create_online_backup()
        manifest = json.loads((backup.path / "manifest.json").read_text(encoding="utf-8"))

        assert len(manifest["evidence"]) == 100
        assert len(tuple((backup.path / "evidence").rglob("*.blob"))) == 100
    finally:
        runtime.close()
