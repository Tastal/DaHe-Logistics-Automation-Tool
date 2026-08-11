from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest
from PIL import Image

from dahe.verification.locked_set_review_package import (
    LockedSetReviewPackageError,
    load_locked_set_review_package,
)
from tests.fixtures.formal_development_authority import (
    formal_development_authority,
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _png_bytes(index: int) -> bytes:
    output = io.BytesIO()
    Image.new(
        "RGB",
        (2, 2),
        color=(index % 251, (index * 17) % 251, (index * 31) % 251),
    ).save(output, format="PNG")
    return output.getvalue()


def _write_package(data_root: Path) -> tuple[Path, dict[str, object]]:
    review_root = data_root / "locked-set-review"
    image_root = review_root / "images"
    image_root.mkdir(parents=True)
    development_authority = formal_development_authority()
    waybills: list[dict[str, object]] = []
    for position in range(1, 51):
        images: list[dict[str, object]] = []
        for slot_offset, slot in enumerate(("loading", "unloading")):
            content = _png_bytes((position - 1) * 2 + slot_offset)
            digest = hashlib.sha256(content).hexdigest()
            relative_path = f"images/{digest}.png"
            (review_root / relative_path).write_bytes(content)
            images.append(
                {
                    "submitted_slot": slot,
                    "image_sha256": digest,
                    "relative_path": relative_path,
                    "width": 2,
                    "height": 2,
                    "selection_clues": ["rotation_0_hint"],
                    "human_review": {
                        "role": None,
                        "ordinary_net": None,
                        "quality_conditions": [],
                        "notes": None,
                    },
                }
            )
        waybills.append(
            {
                "sample_id": f"L7-{position:03d}",
                "candidate_id": f"candidate-{position:03d}",
                "waybill_identity_sha256": hashlib.sha256(
                    f"waybill-{position}".encode()
                ).hexdigest(),
                "selection_clues": [],
                "images": images,
                "pair_review": {"conditions": [], "notes": None},
                "review_status": "pending",
                "record_version": 0,
                "reviewer_id": None,
                "reviewed_at": None,
            }
        )
    external_core = {
        "image_sha256s": sorted(development_authority.image_sha256s),
        "schema_version": 1,
        "source_file_sha256s": [
            development_authority.authority_sha256
        ],
        "waybill_identity_sha256s": sorted(
            development_authority.waybill_identity_sha256s
        ),
    }
    external_snapshot = {
        "schema_version": 1,
        "image_identity_count": len(development_authority.image_sha256s),
        "waybill_identity_count": len(
            development_authority.waybill_identity_sha256s
        ),
        "source_file_sha256s": external_core["source_file_sha256s"],
        "canonical_sha256": _canonical_sha256(external_core),
        "image_sha256s": external_core["image_sha256s"],
        "waybill_identity_sha256s": external_core[
            "waybill_identity_sha256s"
        ],
    }
    (review_root / "external-exclusion-snapshot.json").write_text(
        json.dumps(external_snapshot, ensure_ascii=False),
        encoding="utf-8",
    )
    (review_root / "development-authority.json").write_bytes(
        (
            json.dumps(
                development_authority.payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )
    without_hash: dict[str, object] = {
        "schema_version": 1,
        "kind": "locked_set_candidate_review",
        "package_id": "loop7-review-test",
        "status": "awaiting_human_review",
        "generated_at": "2026-07-26T00:00:00+00:00",
        "tuning_prohibited": True,
        "source_snapshot": {
            "manifest_sha256s": ["a" * 64],
            "candidate_index_sha256": "b" * 64,
            "exclusion_snapshot_sha256": _canonical_sha256(
                {
                    "excluded_image_sha256s": external_core[
                        "image_sha256s"
                    ],
                    "excluded_waybill_identity_sha256s": external_core[
                        "waybill_identity_sha256s"
                    ],
                    "schema_version": 1,
                }
            ),
            "external_exclusion_snapshot_sha256": external_snapshot[
                "canonical_sha256"
            ],
            "external_exclusion_file_sha256": _canonical_sha256(
                external_snapshot
            ),
            "development_authority_sha256": (
                development_authority.authority_sha256
            ),
            "development_authority_file_sha256": _canonical_sha256(
                development_authority.payload
            ),
            "excluded_waybill_count": 0,
            "conflicting_source_waybill_count": 0,
        },
        "waybills": waybills,
    }
    payload = {
        **without_hash,
        "canonical_sha256": _canonical_sha256(without_hash),
    }
    package_path = review_root / "review-package.json"
    package_path.write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
    return package_path, payload


def _rewrite_package(path: Path, payload: dict[str, object]) -> None:
    without_hash = {
        key: value
        for key, value in payload.items()
        if key != "canonical_sha256"
    }
    payload["canonical_sha256"] = _canonical_sha256(without_hash)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_load_review_package_binds_exactly_fifty_pairs_and_verified_images(
    tmp_path: Path,
) -> None:
    _, payload = _write_package(tmp_path)

    package = load_locked_set_review_package(tmp_path)

    assert package.package_id == "loop7-review-test"
    assert package.canonical_sha256 == payload["canonical_sha256"]
    assert len(package.items) == 50
    assert len(package.images_by_sha256) == 100
    assert package.items[0].sample_id == "L7-001"
    assert {image.submitted_slot for image in package.items[0].images} == {
        "loading",
        "unloading",
    }


def test_load_review_package_rejects_path_escape_even_with_a_rebound_hash(
    tmp_path: Path,
) -> None:
    package_path, payload = _write_package(tmp_path)
    outside = tmp_path / "outside.png"
    outside.write_bytes(_png_bytes(200))
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    first = waybills[0]
    assert isinstance(first, dict)
    images = first["images"]
    assert isinstance(images, list)
    first_image = images[0]
    assert isinstance(first_image, dict)
    first_image["relative_path"] = "../outside.png"
    first_image["image_sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    _rewrite_package(package_path, payload)

    with pytest.raises(
        LockedSetReviewPackageError,
        match="inside the review package",
    ):
        load_locked_set_review_package(tmp_path)


def test_load_review_package_rehashes_every_image_at_startup(
    tmp_path: Path,
) -> None:
    _, payload = _write_package(tmp_path)
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    first = waybills[0]
    assert isinstance(first, dict)
    images = first["images"]
    assert isinstance(images, list)
    first_image = images[0]
    assert isinstance(first_image, dict)
    relative_path = first_image["relative_path"]
    assert isinstance(relative_path, str)
    (tmp_path / "locked-set-review" / relative_path).write_bytes(_png_bytes(240))

    with pytest.raises(
        LockedSetReviewPackageError,
        match="SHA-256",
    ):
        load_locked_set_review_package(tmp_path)


def test_load_review_package_rejects_embedded_human_truth(
    tmp_path: Path,
) -> None:
    package_path, payload = _write_package(tmp_path)
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    first = waybills[0]
    assert isinstance(first, dict)
    first["review_status"] = "confirmed"
    first["reviewer_id"] = "legacy-output"
    _rewrite_package(package_path, payload)

    with pytest.raises(
        LockedSetReviewPackageError,
        match="must start pending",
    ):
        load_locked_set_review_package(tmp_path)


def test_load_review_package_rejects_a_changed_external_exclusion_snapshot(
    tmp_path: Path,
) -> None:
    _write_package(tmp_path)
    snapshot_path = (
        tmp_path
        / "locked-set-review"
        / "external-exclusion-snapshot.json"
    )
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["source_file_sha256s"] = ["c" * 64]
    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(
        LockedSetReviewPackageError,
        match="external exclusion",
    ):
        load_locked_set_review_package(tmp_path)


def test_load_review_package_rejects_hidden_truth_and_unknown_clues(
    tmp_path: Path,
) -> None:
    package_path, payload = _write_package(tmp_path)
    payload["ground_truth"] = {"platform_weight": "31.25"}
    _rewrite_package(package_path, payload)

    with pytest.raises(
        LockedSetReviewPackageError,
        match="unexpected fields",
    ):
        load_locked_set_review_package(tmp_path)

    package_path, payload = _write_package(tmp_path / "unknown-clue")
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    first = waybills[0]
    assert isinstance(first, dict)
    first["selection_clues"] = ["preselected_loading_truth"]
    _rewrite_package(package_path, payload)

    with pytest.raises(
        LockedSetReviewPackageError,
        match="selection clue",
    ):
        load_locked_set_review_package(tmp_path / "unknown-clue")
