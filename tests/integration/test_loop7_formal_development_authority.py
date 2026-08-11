from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.locked_set import (
    LockedSetConflictError,
    SqliteLockedSetRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.locked_set_release import (
    LockedSetReleaseService,
)
from tests.fixtures.formal_development_authority import (
    formal_development_authority,
)


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


def _write_locked_set(
    root: Path,
    *,
    dataset_id: str,
) -> tuple[Path, Path]:
    dataset_root = root / dataset_id
    waybills: list[dict[str, object]] = []
    for index in range(50):
        images: list[dict[str, object]] = []
        for slot, role in (("loading", "loading"), ("unloading", "unloading")):
            relative_path = f"images/{index + 1:03d}-{slot}.png"
            content = f"{dataset_id}:{index}:{slot}".encode()
            target = dataset_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            images.append(
                {
                    "image_sha256": hashlib.sha256(content).hexdigest(),
                    "relative_path": relative_path,
                    "submitted_slot": slot,
                    "role": role,
                    "ordinary_net": "30.00",
                }
            )
        waybills.append(
            {
                "sample_id": f"L7-{index + 1:03d}",
                "waybill_identity_sha256": hashlib.sha256(
                    f"{dataset_id}:waybill:{index}".encode()
                ).hexdigest(),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": images,
            }
        )
    manifest = {
        "schema_version": 1,
        "dataset_id": dataset_id,
        "dataset_kind": "locked",
        "tuning_prohibited": True,
        "waybills": waybills,
    }
    manifest_path = dataset_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_path, dataset_root


def test_formal_exclusion_import_is_exact_and_idempotent(
    tmp_path: Path,
    project_root: Path,
) -> None:
    authority = formal_development_authority()
    runtime = _runtime(
        tmp_path / "formal-data",
        project_root,
        instance_id="formal-authority-import",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        first = repository.import_formal_development_exclusions(
            authority_sha256=authority.authority_sha256,
            exclusion_snapshot=authority.exclusion_snapshot,
            perceptual_fingerprints=authority.perceptual_fingerprints,
        )
        replay = repository.import_formal_development_exclusions(
            authority_sha256=authority.authority_sha256,
            exclusion_snapshot=authority.exclusion_snapshot,
            perceptual_fingerprints=tuple(
                reversed(authority.perceptual_fingerprints)
            ),
        )

        assert first.snapshot.template_reference_image_hashes == (
            authority.exclusion_snapshot.template_reference_image_hashes
        )
        assert first.snapshot.development_image_hashes == (
            authority.exclusion_snapshot.development_image_hashes
        )
        assert first.snapshot.calibration_image_hashes == (
            authority.exclusion_snapshot.calibration_image_hashes
        )
        assert first.snapshot.shadow_image_hashes == (
            authority.exclusion_snapshot.shadow_image_hashes
        )
        assert first.snapshot.prior_locked_image_hashes == (
            authority.exclusion_snapshot.prior_locked_image_hashes
        )
        assert first.snapshot.prior_waybill_identity_hashes == (
            authority.exclusion_snapshot.prior_waybill_identity_hashes
        )
        assert first.missing_fingerprint_count == 0
        assert replay.snapshot_id == first.snapshot_id
        assert replay.inventory_high_watermark == first.inventory_high_watermark

        with runtime.engine.connect() as connection:
            source_rows = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM locked_set_exclusion_inventory
                        WHERE source_kind =
                              'formal_development_authority'
                          AND source_id = :authority_sha256
                        """
                    ),
                    {"authority_sha256": authority.authority_sha256},
                ).scalar_one()
            )
            fingerprint_rows = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM locked_set_exclusion_inventory
                        WHERE source_kind =
                              'formal_authority_fingerprint'
                        """
                    )
                ).scalar_one()
            )
        assert source_rows == (
            len(authority.image_sha256s)
            + len(authority.waybill_identity_sha256s)
        )
        assert fingerprint_rows == len(authority.image_sha256s)
    finally:
        runtime.close()


def test_formal_exclusion_import_rolls_back_a_partial_batch(
    tmp_path: Path,
    project_root: Path,
) -> None:
    authority = formal_development_authority()

    def failpoint(name: str) -> None:
        if name == "after_formal_authority_exclusion":
            raise RuntimeError("injected formal authority failure")

    runtime = _runtime(
        tmp_path / "formal-data",
        project_root,
        instance_id="formal-authority-rollback",
    )
    try:
        repository = SqliteLockedSetRepository(
            runtime=runtime,
            failpoint=failpoint,
        )
        with pytest.raises(
            RuntimeError,
            match="injected formal authority failure",
        ):
            repository.import_formal_development_exclusions(
                authority_sha256=authority.authority_sha256,
                exclusion_snapshot=authority.exclusion_snapshot,
                perceptual_fingerprints=authority.perceptual_fingerprints,
            )

        with runtime.engine.connect() as connection:
            assert int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM locked_set_exclusion_inventory"
                    )
                ).scalar_one()
            ) == 0
    finally:
        runtime.close()


def test_formal_dataset_binds_one_exact_development_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    authority = formal_development_authority()
    manifest_path, dataset_root = _write_locked_set(
        tmp_path / "fixture",
        dataset_id="loop7-formal-authority",
    )
    runtime = _runtime(
        tmp_path / "formal-data",
        project_root,
        instance_id="formal-authority-binding",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        formal_snapshot = repository.import_formal_development_exclusions(
            authority_sha256=authority.authority_sha256,
            exclusion_snapshot=authority.exclusion_snapshot,
            perceptual_fingerprints=authority.perceptual_fingerprints,
        )
        preflight = LockedSetReleaseService(
            repository=repository
        ).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="loop7-reviewer",
        )
        assert (
            preflight.attestation.exclusion_snapshot_sha256
            == formal_snapshot.snapshot.canonical_sha256
        )
        template_set_sha256 = authority.payload[
            "shadow_template_set_fingerprint"
        ]
        assert isinstance(template_set_sha256, str)
        arguments = {
            "dataset_id": preflight.dataset.dataset_id,
            "manifest_sha256": preflight.attestation.manifest_sha256,
            "authority_sha256": authority.authority_sha256,
            "source_exclusion_snapshot_sha256": (
                authority.exclusion_snapshot.canonical_sha256
            ),
            "formal_exclusion_snapshot_sha256": (
                formal_snapshot.snapshot.canonical_sha256
            ),
            "source_inventory_high_watermark": (
                authority.inventory_high_watermark
            ),
            "shadow_template_set_fingerprint": template_set_sha256,
            "payload": authority.payload,
        }

        created = repository.register_development_authority(**arguments)
        replay = repository.register_development_authority(**arguments)

        assert replay == created
        assert (
            repository.get_development_authority(
                preflight.dataset.dataset_id
            )
            == created
        )
        for statement in (
            """
            UPDATE locked_set_development_authority
            SET authority_sha256 = :changed
            WHERE dataset_id = :dataset_id
            """,
            """
            DELETE FROM locked_set_development_authority
            WHERE dataset_id = :dataset_id
            """,
        ):
            with (
                pytest.raises(IntegrityError),
                runtime.commit_gate.transaction(
                    runtime.engine
                ) as connection,
            ):
                connection.execute(
                    text(statement),
                    {
                        "changed": "e" * 64,
                        "dataset_id": preflight.dataset.dataset_id,
                    },
                )
        with pytest.raises(
            LockedSetConflictError,
            match="manifest does not match",
        ):
            repository.register_development_authority(
                **{
                    **arguments,
                    "manifest_sha256": "f" * 64,
                }
            )
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "insert_prefix",
    ("REPLACE", "INSERT OR REPLACE"),
)
def test_migration_rejects_replace_style_authority_overwrite(
    tmp_path: Path,
    project_root: Path,
    insert_prefix: str,
) -> None:
    authority = formal_development_authority()
    manifest_path, dataset_root = _write_locked_set(
        tmp_path / "fixture",
        dataset_id="loop7-replace-authority",
    )
    runtime = _runtime(
        tmp_path / "formal-data",
        project_root,
        instance_id=f"formal-authority-{insert_prefix.lower().replace(' ', '-')}",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        formal_snapshot = repository.import_formal_development_exclusions(
            authority_sha256=authority.authority_sha256,
            exclusion_snapshot=authority.exclusion_snapshot,
            perceptual_fingerprints=authority.perceptual_fingerprints,
        )
        preflight = LockedSetReleaseService(
            repository=repository
        ).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="loop7-reviewer",
        )
        template_set_sha256 = authority.payload[
            "shadow_template_set_fingerprint"
        ]
        assert isinstance(template_set_sha256, str)
        created = repository.register_development_authority(
            dataset_id=preflight.dataset.dataset_id,
            manifest_sha256=preflight.attestation.manifest_sha256,
            authority_sha256=authority.authority_sha256,
            source_exclusion_snapshot_sha256=(
                authority.exclusion_snapshot.canonical_sha256
            ),
            formal_exclusion_snapshot_sha256=(
                formal_snapshot.snapshot.canonical_sha256
            ),
            source_inventory_high_watermark=(
                authority.inventory_high_watermark
            ),
            shadow_template_set_fingerprint=template_set_sha256,
            payload=authority.payload,
        )

        with runtime.engine.connect() as connection:
            assert int(
                connection.exec_driver_sql(
                    "PRAGMA recursive_triggers"
                ).scalar_one()
            ) == 0
        with (
            pytest.raises(IntegrityError, match="append-only"),
            runtime.commit_gate.transaction(
                runtime.engine
            ) as connection,
        ):
            connection.execute(
                text(
                    f"""
                    {insert_prefix} INTO
                        locked_set_development_authority (
                            dataset_id, manifest_sha256,
                            authority_sha256,
                            source_exclusion_snapshot_sha256,
                            formal_exclusion_snapshot_sha256,
                            source_inventory_high_watermark,
                            shadow_template_set_fingerprint,
                            payload_json, created_at
                        )
                    SELECT
                        dataset_id, manifest_sha256,
                        :changed_authority_sha256,
                        source_exclusion_snapshot_sha256,
                        formal_exclusion_snapshot_sha256,
                        source_inventory_high_watermark,
                        shadow_template_set_fingerprint,
                        payload_json, created_at
                    FROM locked_set_development_authority
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {
                    "changed_authority_sha256": "e" * 64,
                    "dataset_id": preflight.dataset.dataset_id,
                },
            )

        assert (
            repository.get_development_authority(
                preflight.dataset.dataset_id
            )
            == created
        )
    finally:
        runtime.close()
