from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, fields, replace
from decimal import Decimal
from pathlib import Path

import pytest

from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.application.template_studio.locked_set_evidence import (
    LockedSetEvidenceStagingError,
    stage_locked_set_evidence,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedTicketImage,
    LockedWaybill,
)
from dahe.verification.locked_set_runner import (
    content_addressed_evidence_relative_path,
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _materialize_manifest(dataset_root: Path) -> LockedSetManifest:
    waybills: list[LockedWaybill] = []
    for index in range(50):
        images: list[LockedTicketImage] = []
        for slot, role in (
            (TicketSlot.LOADING, TicketRole.LOADING),
            (TicketSlot.UNLOADING, TicketRole.UNLOADING),
        ):
            content = f"locked ticket {index:03d} {role.value}".encode()
            relative_path = f"human-truth/{role.value}/waybill-{index:03d}-{slot.value}.png"
            source = dataset_root / relative_path
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(content)
            images.append(
                LockedTicketImage(
                    image_sha256=_sha256(content),
                    relative_path=relative_path,
                    slot=slot,
                    role=role,
                    ordinary_net=Decimal("30.00"),
                )
            )
        waybills.append(
            LockedWaybill(
                sample_id=f"locked-{index:03d}",
                waybill_identity_sha256=_sha256(f"waybill identity {index:03d}".encode()),
                images=(images[0], images[1]),
            )
        )
    return LockedSetManifest(
        dataset_id="locked-set-001",
        dataset_kind="locked",
        tuning_prohibited=True,
        waybills=tuple(waybills),
    )


def _replace_first_image(
    manifest: LockedSetManifest,
    **changes: object,
) -> LockedSetManifest:
    first_waybill = manifest.waybills[0]
    changed_image = replace(first_waybill.images[0], **changes)
    changed_waybill = replace(
        first_waybill,
        images=(changed_image, first_waybill.images[1]),
    )
    return replace(
        manifest,
        waybills=(changed_waybill, *manifest.waybills[1:]),
    )


def test_stages_a_frozen_truth_free_inventory_in_canonical_hash_order(
    tmp_path: Path,
) -> None:
    dataset_root = tmp_path / "locked-source"
    manifest = _materialize_manifest(dataset_root)
    data_root = tmp_path / "application-data"
    store = ContentAddressedEvidenceStore(data_root / "evidence")

    inventory = stage_locked_set_evidence(
        manifest=manifest,
        dataset_root=dataset_root,
        evidence_store=store,
    )

    assert tuple(field.name for field in fields(inventory)) == ("images",)
    assert len(inventory.images) == 100
    assert [item.image_sha256 for item in inventory.images] == sorted(
        image.image_sha256 for waybill in manifest.waybills for image in waybill.images
    )
    for item in inventory.images:
        assert tuple(field.name for field in fields(item)) == (
            "image_sha256",
            "relative_path",
            "storage_relative_path",
            "byte_size",
            "media_type",
        )
        assert item.relative_path == content_addressed_evidence_relative_path(item.image_sha256)
        assert item.storage_relative_path == item.relative_path.removeprefix("evidence/")
        assert item.byte_size > 0
        assert item.media_type == "application/octet-stream"
        assert (data_root / item.relative_path).is_file()
        assert store.read_bytes(item.image_sha256)
        assert "loading" not in item.relative_path
        assert "unloading" not in item.relative_path
        for forbidden_attribute in (
            "ordinary_net",
            "role",
            "sample_id",
            "slot",
            "source_path",
        ):
            assert not hasattr(item, forbidden_attribute)

    with pytest.raises(FrozenInstanceError):
        inventory.images = ()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        inventory.images[0].relative_path = "changed"  # type: ignore[misc]


def test_rejects_a_changed_source_before_writing_any_evidence(
    tmp_path: Path,
) -> None:
    dataset_root = tmp_path / "locked-source"
    manifest = _materialize_manifest(dataset_root)
    first_image = manifest.waybills[0].images[0]
    (dataset_root / first_image.relative_path).write_bytes(b"changed after manifest")
    store = ContentAddressedEvidenceStore(tmp_path / "application-data" / "evidence")

    with pytest.raises(LockedSetEvidenceStagingError, match="SHA-256"):
        stage_locked_set_evidence(
            manifest=manifest,
            dataset_root=dataset_root,
            evidence_store=store,
        )

    assert not tuple(store.objects_root.rglob("*.blob"))


def test_rejects_an_empty_source_before_writing_any_evidence(
    tmp_path: Path,
) -> None:
    dataset_root = tmp_path / "locked-source"
    manifest = _materialize_manifest(dataset_root)
    first_image = manifest.waybills[0].images[0]
    (dataset_root / first_image.relative_path).write_bytes(b"")
    store = ContentAddressedEvidenceStore(tmp_path / "application-data" / "evidence")

    with pytest.raises(LockedSetEvidenceStagingError, match="empty"):
        stage_locked_set_evidence(
            manifest=manifest,
            dataset_root=dataset_root,
            evidence_store=store,
        )

    assert not tuple(store.objects_root.rglob("*.blob"))


def test_rejects_a_source_path_that_escapes_the_dataset_root(
    tmp_path: Path,
) -> None:
    dataset_root = tmp_path / "locked-source"
    manifest = _materialize_manifest(dataset_root)
    escaped_content = b"outside locked source"
    (tmp_path / "outside.png").write_bytes(escaped_content)
    manifest = _replace_first_image(
        manifest,
        image_sha256=_sha256(escaped_content),
        relative_path="../outside.png",
    )
    store = ContentAddressedEvidenceStore(tmp_path / "application-data" / "evidence")

    with pytest.raises(LockedSetEvidenceStagingError, match="escaped"):
        stage_locked_set_evidence(
            manifest=manifest,
            dataset_root=dataset_root,
            evidence_store=store,
        )

    assert not tuple(store.objects_root.rglob("*.blob"))


def test_rejects_a_manifest_that_is_not_the_complete_locked_set(
    tmp_path: Path,
) -> None:
    dataset_root = tmp_path / "locked-source"
    manifest = _materialize_manifest(dataset_root)
    incomplete_manifest = replace(manifest, waybills=manifest.waybills[:-1])
    store = ContentAddressedEvidenceStore(tmp_path / "application-data" / "evidence")

    with pytest.raises(LockedSetEvidenceStagingError, match="100 images"):
        stage_locked_set_evidence(
            manifest=incomplete_manifest,
            dataset_root=dataset_root,
            evidence_store=store,
        )

    assert not tuple(store.objects_root.rglob("*.blob"))
