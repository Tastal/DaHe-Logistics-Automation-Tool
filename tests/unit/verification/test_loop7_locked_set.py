from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dahe.domain.audit.ticket_roles import TicketRole
from dahe.verification.locked_set import (
    LockedSetContractError,
    LockedSetExclusionSnapshot,
    load_locked_set_manifest_for_development,
    preflight_locked_set_release,
)


def _sha256(index: int) -> str:
    return f"{index:064x}"


def _manifest() -> dict[str, object]:
    waybills: list[dict[str, object]] = []
    for index in range(50):
        loading_index = index * 2 + 1
        unloading_index = index * 2 + 2
        waybills.append(
            {
                "sample_id": f"locked-{index + 1:03d}",
                "waybill_identity_sha256": _sha256(10_000 + index),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": _sha256(loading_index),
                        "relative_path": f"images/{loading_index:03d}.png",
                        "submitted_slot": "loading",
                        "role": "loading",
                        "ordinary_net": "30.00",
                    },
                    {
                        "image_sha256": _sha256(unloading_index),
                        "relative_path": f"images/{unloading_index:03d}.png",
                        "submitted_slot": "unloading",
                        "role": "unloading",
                        "ordinary_net": "29.98",
                    },
                ],
            }
        )
    return {
        "schema_version": 1,
        "dataset_id": "unseen-locked-set-001",
        "dataset_kind": "locked",
        "tuning_prohibited": True,
        "waybills": waybills,
    }


def _write_manifest(tmp_path: Path, payload: dict[str, object]) -> Path:
    manifest_path = tmp_path / "locked-set.json"
    manifest_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def _materialize_images(tmp_path: Path, payload: dict[str, object]) -> None:
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    for waybill in waybills:
        images = waybill["images"]
        assert isinstance(images, list)
        for image in images:
            relative_path = image["relative_path"]
            assert isinstance(relative_path, str)
            content = f"synthetic locked image {relative_path}".encode()
            target = tmp_path / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            image["image_sha256"] = hashlib.sha256(content).hexdigest()


def _snapshot(
    *,
    source_id: str = "authoritative-exclusion-export-001",
    template_reference_image_hashes: frozenset[str] = frozenset(),
    development_image_hashes: frozenset[str] = frozenset(),
    calibration_image_hashes: frozenset[str] = frozenset(),
    shadow_image_hashes: frozenset[str] = frozenset(),
    prior_locked_image_hashes: frozenset[str] = frozenset(),
    prior_waybill_identity_hashes: frozenset[str] = frozenset(),
) -> LockedSetExclusionSnapshot:
    return LockedSetExclusionSnapshot.create(
        source_id=source_id,
        template_reference_image_hashes=template_reference_image_hashes,
        development_image_hashes=development_image_hashes,
        calibration_image_hashes=calibration_image_hashes,
        shadow_image_hashes=shadow_image_hashes,
        prior_locked_image_hashes=prior_locked_image_hashes,
        prior_waybill_identity_hashes=prior_waybill_identity_hashes,
    )


def test_locked_set_requires_50_human_confirmed_waybills_and_100_images(
    tmp_path: Path,
) -> None:
    manifest = load_locked_set_manifest_for_development(
        _write_manifest(tmp_path, _manifest()),
        template_reference_hashes=set(),
    )

    assert manifest.waybill_count == 50
    assert manifest.image_count == 100
    assert manifest.dataset_kind == "locked"
    assert manifest.tuning_prohibited is True
    assert manifest.waybills[0].images[0].slot.value == "loading"
    assert manifest.waybills[0].images[1].slot.value == "unloading"


def test_locked_set_allows_human_confirmed_non_ticket_truth_without_weight(
    tmp_path: Path,
) -> None:
    payload = _manifest()
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    images = waybills[0]["images"]
    assert isinstance(images, list)
    images[0]["role"] = "unknown"
    images[0]["ordinary_net"] = None

    manifest = load_locked_set_manifest_for_development(
        _write_manifest(tmp_path, payload),
        template_reference_hashes=set(),
    )

    assert manifest.waybills[0].images[0].role is TicketRole.UNKNOWN
    assert manifest.waybills[0].images[0].ordinary_net is None


def test_locked_set_requires_weight_truth_for_a_real_ticket(
    tmp_path: Path,
) -> None:
    payload = _manifest()
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    images = waybills[0]["images"]
    assert isinstance(images, list)
    images[0]["ordinary_net"] = None

    with pytest.raises(LockedSetContractError, match="ordinary net"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, payload),
            template_reference_hashes=set(),
        )


def test_locked_set_rejects_labels_inherited_from_platform_slots(tmp_path: Path) -> None:
    payload = _manifest()
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    waybills[0]["label_source"] = "platform_slot"

    with pytest.raises(LockedSetContractError, match="direct image review"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, payload),
            template_reference_hashes=set(),
        )


def test_locked_set_keeps_submitted_slot_separate_from_human_role(
    tmp_path: Path,
) -> None:
    payload = _manifest()
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    images = waybills[0]["images"]
    assert isinstance(images, list)
    images[0]["role"], images[1]["role"] = (
        images[1]["role"],
        images[0]["role"],
    )

    manifest = load_locked_set_manifest_for_development(
        _write_manifest(tmp_path, payload),
        template_reference_hashes=set(),
    )

    first = manifest.waybills[0]
    assert first.images[0].slot.value == "loading"
    assert first.images[0].role.value == "unloading"
    assert first.images[1].slot.value == "unloading"
    assert first.images[1].role.value == "loading"


@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_locked_set_requires_one_image_for_each_submitted_slot(
    tmp_path: Path,
    mutation: str,
) -> None:
    payload = _manifest()
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    images = waybills[0]["images"]
    assert isinstance(images, list)
    if mutation == "missing":
        images[0].pop("submitted_slot")
    else:
        images[1]["submitted_slot"] = "loading"

    with pytest.raises(LockedSetContractError, match="submitted slot"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, payload),
            template_reference_hashes=set(),
        )


def test_locked_set_rejects_duplicate_and_reference_image_hashes(tmp_path: Path) -> None:
    payload = _manifest()
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    first_images = waybills[0]["images"]
    second_images = waybills[1]["images"]
    assert isinstance(first_images, list)
    assert isinstance(second_images, list)
    duplicated_hash = first_images[0]["image_sha256"]
    second_images[0]["image_sha256"] = duplicated_hash

    with pytest.raises(LockedSetContractError, match="duplicate image"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, payload),
            template_reference_hashes=set(),
        )

    clean_payload = _manifest()
    with pytest.raises(LockedSetContractError, match="template reference"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, clean_payload),
            template_reference_hashes={_sha256(1)},
        )


def test_locked_set_rejects_wrong_size_or_missing_manual_truth(tmp_path: Path) -> None:
    too_small = _manifest()
    waybills = too_small["waybills"]
    assert isinstance(waybills, list)
    waybills.pop()
    with pytest.raises(LockedSetContractError, match="exactly 50"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, too_small),
            template_reference_hashes=set(),
        )

    missing_truth = _manifest()
    missing_waybills = missing_truth["waybills"]
    assert isinstance(missing_waybills, list)
    images = missing_waybills[0]["images"]
    assert isinstance(images, list)
    images[0]["ordinary_net"] = None
    with pytest.raises(LockedSetContractError, match="ordinary net"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, missing_truth),
            template_reference_hashes=set(),
        )


def test_locked_set_release_preflight_verifies_files_and_returns_attestation(
    tmp_path: Path,
) -> None:
    payload = _manifest()
    _materialize_images(tmp_path, payload)
    manifest_path = _write_manifest(tmp_path, payload)

    attestation = preflight_locked_set_release(
        manifest_path=manifest_path,
        dataset_root=tmp_path,
        exclusion_snapshot=_snapshot(),
    )

    assert attestation.waybill_count == 50
    assert attestation.image_count == 100
    assert attestation.total_bytes > 0
    assert len(attestation.manifest_sha256) == 64
    assert attestation.exclusion_snapshot_sha256 == _snapshot().canonical_sha256
    assert attestation.exclusion_counts == {
        "calibration_images": 0,
        "development_images": 0,
        "prior_locked_images": 0,
        "prior_waybill_identities": 0,
        "shadow_images": 0,
        "template_reference_images": 0,
    }

    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    images = waybills[0]["images"]
    assert isinstance(images, list)
    first_relative_path = images[0]["relative_path"]
    assert isinstance(first_relative_path, str)
    (tmp_path / first_relative_path).write_bytes(b"changed after labeling")
    with pytest.raises(LockedSetContractError, match="content hash"):
        preflight_locked_set_release(
            manifest_path=manifest_path,
            dataset_root=tmp_path,
            exclusion_snapshot=_snapshot(),
        )


@pytest.mark.parametrize(
    "snapshot_field",
    [
        "template_reference_image_hashes",
        "development_image_hashes",
        "calibration_image_hashes",
        "shadow_image_hashes",
        "prior_locked_image_hashes",
    ],
)
def test_locked_set_release_rejects_every_excluded_image_category(
    tmp_path: Path,
    snapshot_field: str,
) -> None:
    payload = _manifest()
    _materialize_images(tmp_path, payload)
    manifest_path = _write_manifest(tmp_path, payload)
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    images = waybills[0]["images"]
    assert isinstance(images, list)
    first_hash = images[0]["image_sha256"]
    assert isinstance(first_hash, str)
    snapshot_arguments = {snapshot_field: frozenset({first_hash})}

    with pytest.raises(LockedSetContractError, match="excluded image"):
        preflight_locked_set_release(
            manifest_path=manifest_path,
            dataset_root=tmp_path,
            exclusion_snapshot=_snapshot(**snapshot_arguments),  # type: ignore[arg-type]
        )


def test_renaming_sample_id_cannot_bypass_stable_waybill_exclusion(
    tmp_path: Path,
) -> None:
    payload = _manifest()
    _materialize_images(tmp_path, payload)
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    stable_identity = waybills[0]["waybill_identity_sha256"]
    assert isinstance(stable_identity, str)
    waybills[0]["sample_id"] = "renamed-after-development-use"

    with pytest.raises(LockedSetContractError, match="waybill identity"):
        preflight_locked_set_release(
            manifest_path=_write_manifest(tmp_path, payload),
            dataset_root=tmp_path,
            exclusion_snapshot=_snapshot(
                prior_waybill_identity_hashes=frozenset({stable_identity}),
            ),
        )


def test_release_preflight_requires_a_sourced_exclusion_snapshot(
    tmp_path: Path,
) -> None:
    payload = _manifest()
    _materialize_images(tmp_path, payload)
    manifest_path = _write_manifest(tmp_path, payload)

    with pytest.raises(TypeError):
        preflight_locked_set_release(  # type: ignore[call-arg]
            manifest_path=manifest_path,
            dataset_root=tmp_path,
        )
    with pytest.raises(LockedSetContractError, match="exclusion snapshot"):
        preflight_locked_set_release(
            manifest_path=manifest_path,
            dataset_root=tmp_path,
            exclusion_snapshot=None,  # type: ignore[arg-type]
        )
    with pytest.raises(LockedSetContractError, match="source"):
        _snapshot(source_id=" ")


def test_locked_manifest_requires_stable_waybill_identity(tmp_path: Path) -> None:
    payload = _manifest()
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    waybills[0].pop("waybill_identity_sha256")

    with pytest.raises(LockedSetContractError, match="waybill identity"):
        load_locked_set_manifest_for_development(
            _write_manifest(tmp_path, payload),
            template_reference_hashes=set(),
        )
