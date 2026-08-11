from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from dahe.adapters.sqlite.locked_set_review import LockedSetReviewRecord
from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewExportError,
    build_candidate_review_formal_export,
)
from dahe.application.template_studio.candidate_review_semantics import (
    candidate_review_waybill_membership_sha256,
    validate_candidate_review_semantic_authority,
)
from dahe.verification.locked_set import (
    load_locked_set_manifest_for_development,
)
from dahe.verification.locked_set_acceptance import (
    REQUIRED_NATURAL_QUALITY_CONDITIONS,
    SUPPORTED_QUALITY_CONDITIONS,
    locked_set_quality_coverage_sha256,
    validate_locked_set_quality_coverage,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImage,
    LockedSetReviewItem,
    LockedSetReviewPackage,
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _image_conditions(sample_index: int, slot: str) -> list[str]:
    if sample_index == 1 and slot == "loading":
        return ["rotation_0", "printed"]
    if sample_index == 1 and slot == "unloading":
        return ["rotation_90", "screen", "unknown_layout"]
    if sample_index == 2 and slot == "loading":
        return ["blur", "rotation_180", "printed"]
    if sample_index == 2 and slot == "unloading":
        return ["crop", "rotation_270", "screen"]
    if sample_index == 3 and slot == "loading":
        return ["glare", "rotation_0", "printed"]
    medium = "printed" if slot == "loading" else "screen"
    return ["rotation_0", medium]


def _fixture_authority(
    tmp_path: Path,
) -> tuple[LockedSetReviewPackage, tuple[LockedSetReviewRecord, ...]]:
    review_root = tmp_path / "locked-set-review"
    image_root = review_root / "images"
    image_root.mkdir(parents=True)
    items: list[LockedSetReviewItem] = []
    records: list[LockedSetReviewRecord] = []
    images_by_sha256: dict[str, LockedSetReviewImage] = {}

    for sample_index in range(1, 51):
        sample_id = f"L7-{sample_index:03d}"
        package_images: list[LockedSetReviewImage] = []
        review_images: list[dict[str, object]] = []
        roles: dict[str, str] = {}
        for slot_index, slot in enumerate(("loading", "unloading")):
            image_index = (sample_index - 1) * 2 + slot_index + 1
            content = f"candidate-review-image-{image_index:03d}".encode()
            digest = hashlib.sha256(content).hexdigest()
            relative_path = f"images/{digest}.jpg"
            path = review_root / relative_path
            path.write_bytes(content)
            image = LockedSetReviewImage(
                submitted_slot=slot,
                image_sha256=digest,
                relative_path=relative_path,
                path=path,
                width=1000,
                height=700,
                media_type="image/jpeg",
                selection_clues=(),
            )
            package_images.append(image)
            images_by_sha256[digest] = image

            role = "unknown" if sample_index == 1 else slot
            roles[slot] = role
            review_images.append(
                {
                    "submitted_slot": slot,
                    "role": role,
                    "ordinary_net": (
                        None if role == "unknown" else ("31.25" if slot == "loading" else "31.20")
                    ),
                    "quality_conditions": _image_conditions(
                        sample_index,
                        slot,
                    ),
                    "notes": (
                        "direct image review" if sample_index == 2 and slot == "unloading" else None
                    ),
                }
            )

        item = LockedSetReviewItem(
            sample_id=sample_id,
            candidate_id=f"candidate-{sample_index:03d}",
            waybill_identity_sha256=hashlib.sha256(
                f"waybill-{sample_index:03d}".encode()
            ).hexdigest(),
            position=sample_index,
            selection_clues=("must_not_become_truth",),
            images=(package_images[0], package_images[1]),
        )
        items.append(item)
        timestamp = f"2026-07-26T00:{sample_index:02d}:00+00:00"
        payload: dict[str, object] = {
            "reviewer_id": "operator-a",
            "decision": "confirmed",
            "images": review_images,
            "pair_conditions": (
                ["pair_unknown"] if "unknown" in roles.values() else ["normal_pair"]
            ),
            "pair_notes": None,
            "replace_reason": None,
        }
        records.append(
            LockedSetReviewRecord(
                sample_id=sample_id,
                review_status="confirmed",
                decision="confirmed",
                review_payload=payload,
                record_version=1,
                created_at=timestamp,
                updated_at=timestamp,
            )
        )

    item_tuple = tuple(items)
    package = LockedSetReviewPackage(
        package_id="loop7-candidate-review-fixture",
        canonical_sha256=_canonical_sha256({"package_id": "loop7-candidate-review-fixture"}),
        review_root=review_root,
        items=item_tuple,
        items_by_sample_id={item.sample_id: item for item in item_tuple},
        images_by_sha256=images_by_sha256,
    )
    return package, tuple(records)


def _build(
    package: LockedSetReviewPackage,
    records: tuple[LockedSetReviewRecord, ...],
):
    return build_candidate_review_formal_export(
        package=package,
        records=records,
        configured_reviewer_id="operator-a",
        dataset_id="loop7-locked-set-001",
    )


def test_builds_deterministic_formal_manifest_source_authority_and_natural_quality_v2(
    tmp_path: Path,
) -> None:
    package, records = _fixture_authority(tmp_path)

    first = _build(package, tuple(reversed(records)))
    second = _build(package, records)
    reordered_items = tuple(
        replace(
            item,
            images=(item.images[1], item.images[0]),
        )
        for item in reversed(package.items)
    )
    reordered_package = replace(
        package,
        items=reordered_items,
        items_by_sample_id={item.sample_id: item for item in reordered_items},
    )
    third = _build(reordered_package, records)

    assert first == second == third
    assert first.manifest_sha256 == first.manifest.canonical_sha256
    assert first.manifest_payload["schema_version"] == 1
    assert first.manifest_payload["dataset_kind"] == "locked"
    assert first.manifest_payload["tuning_prohibited"] is True
    waybills = first.manifest_payload["waybills"]
    assert isinstance(waybills, list)
    assert len(waybills) == 50
    assert sum(len(waybill["images"]) for waybill in waybills) == 100
    assert "candidate_id" not in json.dumps(first.manifest_payload)
    assert "must_not_become_truth" not in json.dumps(first.manifest_payload)

    manifest_path = tmp_path / "formal-manifest.json"
    manifest_path.write_text(
        json.dumps(first.manifest_payload, ensure_ascii=False),
        encoding="utf-8",
    )
    reloaded = load_locked_set_manifest_for_development(
        manifest_path,
        template_reference_hashes=frozenset(),
    )
    assert reloaded.canonical_sha256 == first.manifest_sha256

    source = first.source_authority_payload
    assert source["schema_version"] == 2
    assert source["authority_scope"] == "computed_unsealed_snapshot"
    assert source["persistent_seal"] is False
    assert source["package_sha256"] == package.canonical_sha256
    assert source["record_count"] == 50
    assert source["verified_image_count"] == 100
    assert len(source["records"]) == 50
    assert len(source["verified_images"]) == 100
    assert source["waybill_membership_count"] == 50
    memberships = source["waybill_membership"]
    assert isinstance(memberships, list)
    assert len(memberships) == 50
    assert source["waybill_membership_sha256"] == candidate_review_waybill_membership_sha256(
        package_sha256=package.canonical_sha256,
        waybills=memberships,
    )
    assert (
        validate_candidate_review_semantic_authority(
            manifest_payload=first.manifest_payload,
            source_authority_payload=source,
        )
        == first.manifest_sha256
    )
    assert (
        first.source_authority_sha256
        == source["source_authority_sha256"]
        == _canonical_sha256(
            {key: value for key, value in source.items() if key != "source_authority_sha256"}
        )
    )

    image_truth = {
        image.image_sha256: (waybill.sample_id, image.role.value)
        for waybill in first.manifest.waybills
        for image in waybill.images
    }
    pair_slots = {
        waybill.sample_id: (
            next(image.image_sha256 for image in waybill.images if image.slot.value == "loading"),
            next(image.image_sha256 for image in waybill.images if image.slot.value == "unloading"),
        )
        for waybill in first.manifest.waybills
    }
    quality = first.quality_coverage_payload
    assert quality["schema_version"] == 2
    assert len(quality["entries"]) == 10
    assert set(quality["required_conditions"]) == set(
        REQUIRED_NATURAL_QUALITY_CONDITIONS
    )
    assert "non_ticket" not in quality["required_conditions"]
    assert (
        first.quality_coverage_sha256
        == quality["quality_coverage_sha256"]
        == locked_set_quality_coverage_sha256(quality)
    )
    assert (
        validate_locked_set_quality_coverage(
            quality,
            dataset_id=first.manifest.dataset_id,
            manifest_sha256=first.manifest_sha256,
            image_truth=image_truth,
            pair_slots=pair_slots,
        )["passed"]
        is True
    )


def test_non_ticket_remains_a_supported_review_label_but_not_natural_coverage() -> None:
    assert "non_ticket" in SUPPORTED_QUALITY_CONDITIONS
    assert "non_ticket" not in REQUIRED_NATURAL_QUALITY_CONDITIONS
    assert len(REQUIRED_NATURAL_QUALITY_CONDITIONS) == 10


def test_existing_v2_source_authority_remains_semantically_valid(
    tmp_path: Path,
) -> None:
    package, records = _fixture_authority(tmp_path)
    formal_export = _build(package, records)
    source = json.loads(json.dumps(formal_export.source_authority_payload))
    source.pop("quality_coverage_sha256", None)
    source["schema_version"] = 2
    source_without_hash = {
        key: value for key, value in source.items() if key != "source_authority_sha256"
    }
    source["source_authority_sha256"] = _canonical_sha256(source_without_hash)

    assert (
        validate_candidate_review_semantic_authority(
            manifest_payload=formal_export.manifest_payload,
            source_authority_payload=source,
        )
        == formal_export.manifest_sha256
    )


def test_source_hash_changes_when_record_version_or_payload_changes(
    tmp_path: Path,
) -> None:
    package, records = _fixture_authority(tmp_path)
    baseline = _build(package, records)
    changed_payload = dict(records[0].review_payload)
    changed_payload["pair_notes"] = "review evidence changed"
    changed_records = (
        replace(
            records[0],
            review_payload=changed_payload,
            record_version=2,
            updated_at="2026-07-26T01:00:00+00:00",
        ),
        *records[1:],
    )

    changed = _build(package, changed_records)

    assert changed.record_set_sha256 != baseline.record_set_sha256
    assert changed.source_authority_sha256 != baseline.source_authority_sha256
    assert changed.manifest_sha256 == baseline.manifest_sha256


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda records: records[:-1],
            "exactly match the candidate package",
        ),
        (
            lambda records: (
                replace(
                    records[0],
                    review_status="replace_candidate",
                    decision="replace_candidate",
                ),
                *records[1:],
            ),
            "must be confirmed",
        ),
        (
            lambda records: (
                replace(
                    records[0],
                    review_payload={
                        **records[0].review_payload,
                        "reviewer_id": "another-operator",
                    },
                ),
                *records[1:],
            ),
            "configured reviewer",
        ),
        (
            lambda records: (
                replace(
                    records[0],
                    review_payload={
                        **records[0].review_payload,
                        "unexpected": True,
                    },
                ),
                *records[1:],
            ),
            "unexpected fields",
        ),
    ],
)
def test_rejects_incomplete_nonconfirmed_or_unbound_record_authority(
    tmp_path: Path,
    mutate: Callable[
        [tuple[LockedSetReviewRecord, ...]],
        tuple[LockedSetReviewRecord, ...],
    ],
    expected: str,
) -> None:
    package, records = _fixture_authority(tmp_path)

    with pytest.raises(CandidateReviewExportError, match=expected):
        _build(package, mutate(records))


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("ordinary_net", "31250", "two decimal places"),
        ("quality_conditions", ["printed"], "exactly one rotation"),
        ("submitted_slot", "unloading", "submitted slots"),
    ],
)
def test_revalidates_each_stored_image_contract(
    tmp_path: Path,
    field: str,
    value: object,
    expected: str,
) -> None:
    package, records = _fixture_authority(tmp_path)
    payload = dict(records[1].review_payload)
    images = [dict(image) for image in payload["images"]]
    images[0][field] = value
    payload["images"] = images
    changed = (
        replace(records[1], review_payload=payload),
        *records[:1],
        *records[2:],
    )

    with pytest.raises(CandidateReviewExportError, match=expected):
        _build(package, changed)


def test_rejects_pair_truth_that_disagrees_with_human_roles(
    tmp_path: Path,
) -> None:
    package, records = _fixture_authority(tmp_path)
    payload = dict(records[1].review_payload)
    payload["pair_conditions"] = ["swapped_pair"]
    changed = (
        replace(records[1], review_payload=payload),
        *records[:1],
        *records[2:],
    )

    with pytest.raises(
        CandidateReviewExportError,
        match="pair condition does not match",
    ):
        _build(package, changed)


def test_rehashes_every_image_and_rejects_changed_bytes(
    tmp_path: Path,
) -> None:
    package, records = _fixture_authority(tmp_path)
    final_image = package.items[-1].images[-1]
    final_image.path.write_bytes(b"changed-after-review")

    with pytest.raises(CandidateReviewExportError, match="image changed"):
        _build(package, records)


def test_rejects_a_noncanonical_record_version_or_timestamp(
    tmp_path: Path,
) -> None:
    package, records = _fixture_authority(tmp_path)
    bool_version = (replace(records[0], record_version=True), *records[1:])
    with pytest.raises(CandidateReviewExportError, match="record version"):
        _build(package, bool_version)

    naive_time = (
        replace(records[0], updated_at="2026-07-26T00:00:00"),
        *records[1:],
    )
    with pytest.raises(CandidateReviewExportError, match="timezone"):
        _build(package, naive_time)
