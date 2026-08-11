from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image
from sqlalchemy import text

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.sqlite.locked_set import (
    DevelopmentExclusionEvidence,
    LockedSetConflictError,
    LockedSetPersistenceError,
    SqliteLockedSetRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.verification.image_similarity import (
    build_image_fingerprint,
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


def _png_bytes(color: tuple[int, int, int]) -> bytes:
    output = BytesIO()
    Image.new("RGB", (24, 18), color).save(output, format="PNG")
    return output.getvalue()


def _staged_images(
    data_root: Path,
) -> tuple[DevelopmentExclusionEvidence, ...]:
    store = ContentAddressedEvidenceStore(data_root / "evidence")
    staged: list[DevelopmentExclusionEvidence] = []
    for content in (
        _png_bytes((10, 20, 30)),
        _png_bytes((210, 120, 30)),
    ):
        stored = store.put_bytes(
            content,
            media_type="image/png",
        )
        staged.append(
            DevelopmentExclusionEvidence(
                image_sha256=stored.sha256,
                storage_relative_path=stored.relative_path,
                byte_size=stored.byte_size,
                media_type=stored.media_type,
                perceptual_fingerprint=build_image_fingerprint(content),
            )
        )
    return tuple(staged)


def _waybill_hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def test_atomic_import_is_idempotent_and_builds_complete_exclusions(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "target-data"
    images = _staged_images(data_root)
    waybills = (
        _waybill_hash("current-waybill"),
        _waybill_hash("prior-waybill"),
    )
    authority_sha256 = hashlib.sha256(b"development-import-authority").hexdigest()
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="development-import-first",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        first = repository.import_development_exclusions(
            source_authority_sha256=authority_sha256,
            images=images,
            waybill_identity_sha256s=waybills,
        )
        replay = repository.import_development_exclusions(
            source_authority_sha256=authority_sha256,
            images=tuple(reversed(images)),
            waybill_identity_sha256s=tuple(reversed(waybills)),
        )

        assert first.applied is True
        assert replay.applied is False
        assert first.source_authority_sha256 == authority_sha256
        assert first.development_image_count == 2
        assert first.prior_waybill_identity_count == 2
        assert replay == type(first)(
            source_authority_sha256=authority_sha256,
            development_image_count=2,
            prior_waybill_identity_count=2,
            applied=False,
        )

        with runtime.engine.connect() as connection:
            blobs = tuple(
                connection.execute(
                    text(
                        """
                        SELECT
                            sha256, relative_path, byte_size,
                            media_type, storage_state
                        FROM evidence_blobs
                        ORDER BY sha256
                        """
                    )
                )
                .mappings()
                .all()
            )
            authority_rows = tuple(
                connection.execute(
                    text(
                        """
                        SELECT category, identity_sha256, source_kind,
                               source_id
                        FROM locked_set_exclusion_inventory
                        WHERE source_kind =
                              'candidate_review_development_import'
                        ORDER BY category, identity_sha256
                        """
                    )
                )
                .mappings()
                .all()
            )
            fingerprint_rows = tuple(
                connection.execute(
                    text(
                        """
                        SELECT identity_sha256,
                               perceptual_fingerprint_json,
                               fingerprint_sha256,
                               algorithm_version
                        FROM locked_set_exclusion_inventory
                        WHERE source_kind =
                              'code_owned_perceptual_fingerprint'
                        ORDER BY identity_sha256
                        """
                    )
                )
                .mappings()
                .all()
            )
            holds = tuple(
                connection.execute(
                    text(
                        """
                        SELECT sha256, hold_kind, owner_id,
                               idempotency_key, released_at
                        FROM evidence_holds
                        WHERE hold_kind =
                              'development_exclusion_import'
                        ORDER BY sha256
                        """
                    )
                )
                .mappings()
                .all()
            )

        assert {str(row["sha256"]) for row in blobs} == {image.image_sha256 for image in images}
        for row in blobs:
            digest = str(row["sha256"])
            assert row["relative_path"] == (f"sha256/{digest[:2]}/{digest[2:4]}/{digest}.blob")
            assert int(row["byte_size"]) > 0
            assert row["media_type"] == "image/png"
            assert row["storage_state"] == "available"
            assert str(tmp_path) not in str(row["relative_path"])

        assert {
            (
                str(row["category"]),
                str(row["identity_sha256"]),
                str(row["source_id"]),
            )
            for row in authority_rows
        } == {("development_image", image.image_sha256, authority_sha256) for image in images} | {
            ("prior_waybill_identity", identity, authority_sha256) for identity in waybills
        }
        assert len(fingerprint_rows) == 2
        assert all(row["perceptual_fingerprint_json"] for row in fingerprint_rows)
        assert all(row["fingerprint_sha256"] for row in fingerprint_rows)
        assert all(
            row["algorithm_version"] == "dahe.ticket-image-similarity.v1"
            for row in fingerprint_rows
        )
        assert {
            (
                str(row["sha256"]),
                str(row["owner_id"]),
                row["released_at"],
            )
            for row in holds
        } == {(image.image_sha256, authority_sha256, None) for image in images}

        snapshot = repository.build_exclusion_snapshot()
        assert snapshot.snapshot.development_image_hashes == {
            image.image_sha256 for image in images
        }
        assert snapshot.snapshot.prior_waybill_identity_hashes == set(waybills)
        assert snapshot.inventory_image_count == 2
        assert snapshot.fingerprinted_image_count == 2
        assert snapshot.missing_fingerprint_count == 0
    finally:
        runtime.close()


def test_partial_authority_rows_fail_closed_without_repairing_them(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "target-data"
    images = _staged_images(data_root)
    authority_sha256 = hashlib.sha256(b"partial-development-import").hexdigest()
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="development-import-partial",
    )
    try:
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO locked_set_exclusion_inventory (
                        category, identity_sha256, source_kind,
                        source_id, perceptual_fingerprint_json,
                        fingerprint_sha256, algorithm_version,
                        created_at
                    ) VALUES (
                        'development_image', :identity,
                        'candidate_review_development_import',
                        :source_id, NULL, NULL, NULL,
                        '2026-07-26T00:00:00+00:00'
                    )
                    """
                ),
                {
                    "identity": images[0].image_sha256,
                    "source_id": authority_sha256,
                },
            )

        repository = SqliteLockedSetRepository(runtime=runtime)
        with pytest.raises(
            LockedSetConflictError,
            match=r"partial|authority",
        ):
            repository.import_development_exclusions(
                source_authority_sha256=authority_sha256,
                images=images,
                waybill_identity_sha256s=(_waybill_hash("waybill"),),
            )

        with runtime.engine.connect() as connection:
            source_count = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM locked_set_exclusion_inventory
                        WHERE source_kind =
                              'candidate_review_development_import'
                          AND source_id = :source_id
                        """
                    ),
                    {"source_id": authority_sha256},
                ).scalar_one()
            )
        assert source_count == 1
    finally:
        runtime.close()


def test_failpoint_rolls_back_all_database_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "target-data"
    images = _staged_images(data_root)
    authority_sha256 = hashlib.sha256(b"rollback-development-import").hexdigest()
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="development-import-rollback",
    )

    def failpoint(name: str) -> None:
        if name == "after_development_exclusion_image":
            raise RuntimeError("injected batch failure")

    try:
        repository = SqliteLockedSetRepository(
            runtime=runtime,
            failpoint=failpoint,
        )
        with pytest.raises(
            RuntimeError,
            match="injected batch failure",
        ):
            repository.import_development_exclusions(
                source_authority_sha256=authority_sha256,
                images=images,
                waybill_identity_sha256s=(_waybill_hash("waybill"),),
            )

        with runtime.engine.connect() as connection:
            assert (
                int(connection.execute(text("SELECT count(*) FROM evidence_blobs")).scalar_one())
                == 0
            )
            assert (
                int(
                    connection.execute(
                        text(
                            """
                            SELECT count(*)
                            FROM locked_set_exclusion_inventory
                            """
                        )
                    ).scalar_one()
                )
                == 0
            )
            assert (
                int(connection.execute(text("SELECT count(*) FROM evidence_holds")).scalar_one())
                == 0
            )
    finally:
        runtime.close()


def test_conflicting_existing_blob_metadata_fails_closed(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "target-data"
    images = _staged_images(data_root)
    authority_sha256 = hashlib.sha256(b"tampered-development-import").hexdigest()
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="development-import-tampered",
    )
    try:
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO evidence_blobs (
                        sha256, relative_path, byte_size,
                        media_type, storage_state,
                        record_version, created_at, verified_at
                    ) VALUES (
                        :sha256, :relative_path, :byte_size,
                        :media_type, 'available',
                        1, :created_at, :verified_at
                    )
                    """
                ),
                {
                    "sha256": images[0].image_sha256,
                    "relative_path": (f"sha256/ff/ff/{images[0].image_sha256}.blob"),
                    "byte_size": images[0].byte_size,
                    "media_type": images[0].media_type,
                    "created_at": "2026-07-26T00:00:00+00:00",
                    "verified_at": "2026-07-26T00:00:00+00:00",
                },
            )

        repository = SqliteLockedSetRepository(runtime=runtime)
        with pytest.raises(
            LockedSetConflictError,
            match="metadata conflicts",
        ):
            repository.import_development_exclusions(
                source_authority_sha256=authority_sha256,
                images=images,
                waybill_identity_sha256s=(_waybill_hash("waybill"),),
            )

        with runtime.engine.connect() as connection:
            exclusion_count = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM locked_set_exclusion_inventory
                        """
                    )
                ).scalar_one()
            )
            hold_count = int(
                connection.execute(text("SELECT count(*) FROM evidence_holds")).scalar_one()
            )
        assert exclusion_count == 0
        assert hold_count == 0
    finally:
        runtime.close()


def test_invalid_or_duplicate_members_are_rejected_before_writes(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "target-data"
    images = _staged_images(data_root)
    authority_sha256 = hashlib.sha256(b"invalid-development-import").hexdigest()
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="development-import-invalid",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        with pytest.raises(
            LockedSetPersistenceError,
            match="duplicate",
        ):
            repository.import_development_exclusions(
                source_authority_sha256=authority_sha256,
                images=(images[0], images[0]),
                waybill_identity_sha256s=(_waybill_hash("waybill"),),
            )
        with pytest.raises(
            LockedSetPersistenceError,
            match="content-addressed",
        ):
            repository.import_development_exclusions(
                source_authority_sha256=authority_sha256,
                images=(
                    DevelopmentExclusionEvidence(
                        image_sha256=images[0].image_sha256,
                        storage_relative_path="legacy/source/image.png",
                        byte_size=images[0].byte_size,
                        media_type=images[0].media_type,
                        perceptual_fingerprint=(images[0].perceptual_fingerprint),
                    ),
                ),
                waybill_identity_sha256s=(_waybill_hash("waybill"),),
            )

        with runtime.engine.connect() as connection:
            assert (
                int(connection.execute(text("SELECT count(*) FROM evidence_blobs")).scalar_one())
                == 0
            )
    finally:
        runtime.close()
