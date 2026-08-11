from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from PIL import Image

from dahe.verification.legacy_locked_set_candidates import (
    CandidateContractError,
    LegacyCandidateIndex,
    build_candidate_index,
    stage_review_package,
)
from dahe.verification.locked_set import source_waybill_identity_sha256
from dahe.verification.locked_set_review_package import (
    LockedSetReviewPackageError,
    load_locked_set_review_package,
)
from tests.fixtures.formal_development_authority import (
    external_exclusion_snapshot,
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


def _empty_external_exclusion_snapshot() -> dict[str, object]:
    canonical = {
        "image_sha256s": [],
        "schema_version": 1,
        "source_file_sha256s": [],
        "waybill_identity_sha256s": [],
    }
    return {
        "schema_version": 1,
        "image_identity_count": 0,
        "waybill_identity_count": 0,
        "source_file_sha256s": [],
        "canonical_sha256": _canonical_sha256(canonical),
        "image_sha256s": [],
        "waybill_identity_sha256s": [],
    }


def _formal_stage_inputs(
    index: LegacyCandidateIndex,
) -> tuple[
    LegacyCandidateIndex,
    dict[str, object],
    dict[str, object],
]:
    authority = formal_development_authority()
    snapshot = external_exclusion_snapshot(authority)
    exclusion_sha256 = _canonical_sha256(
        {
            "excluded_image_sha256s": snapshot["image_sha256s"],
            "excluded_waybill_identity_sha256s": (
                snapshot["waybill_identity_sha256s"]
            ),
            "schema_version": 1,
        }
    )
    return (
        replace(index, exclusion_snapshot_sha256=exclusion_sha256),
        snapshot,
        authority.payload,
    )


def _write_jpeg(path: Path, *, color: tuple[int, int, int]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (8, 6), color=color).save(path, format="JPEG", quality=90)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_acquisition(
    root: Path,
    *,
    count: int,
    outside_path: Path | None = None,
) -> tuple[Path, list[dict[str, object]]]:
    acquisition_root = root / "daily-reports" / "acquisitions"
    evidence_root = root / "daily-reports" / "evidence"
    acquisition_root.mkdir(parents=True)
    items: list[dict[str, object]] = []
    for index in range(count):
        waybill_no = f"REAL-WAYBILL-{index:03d}"
        pair_root = evidence_root / waybill_no
        loading_path = (
            outside_path
            if index == 0 and outside_path is not None
            else pair_root / "loading.jpg"
        )
        unloading_path = pair_root / "unloading.jpg"
        loading_hash = _write_jpeg(
            loading_path,
            color=((index * 7) % 256, (index * 11) % 256, (index * 13) % 256),
        )
        unloading_hash = _write_jpeg(
            unloading_path,
            color=(
                (index * 17 + 1) % 256,
                (index * 19 + 2) % 256,
                (index * 23 + 3) % 256,
            ),
        )
        items.append(
            {
                "waybill_no": waybill_no,
                "platform_item_id": f"REAL-PLATFORM-{index:03d}",
                "platform_loading_tonnes": "31.25",
                "platform_unloading_tonnes": "31.20",
                "loading_image_path": str(loading_path),
                "loading_image_sha256": loading_hash,
                "unloading_image_path": str(unloading_path),
                "unloading_image_sha256": unloading_hash,
            }
        )
    manifest = acquisition_root / "immutable-export.json"
    manifest.write_text(
        json.dumps({"report_id": "source-report", "items": items}),
        encoding="utf-8",
    )
    return acquisition_root, items


def test_candidate_index_is_deidentified_and_excludes_known_images(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, items = _write_acquisition(legacy_root, count=2)
    excluded_hash = str(items[0]["loading_image_sha256"])

    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes={excluded_hash},
        legacy_result_roots=(),
    )
    assert index.source_waybill_count == 2
    assert index.eligible_waybill_count == 1
    assert index.excluded_waybill_count == 1
    payload = index.to_payload()
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "REAL-WAYBILL" not in encoded
    assert "REAL-PLATFORM" not in encoded
    assert "31.25" not in encoded
    assert "31.20" not in encoded
    assert excluded_hash not in {
        image["image_sha256"]
        for waybill in payload["waybills"]
        for image in waybill["images"]
    }


def test_candidate_index_excludes_a_shared_source_waybill_identity(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=2)
    excluded_identity = source_waybill_identity_sha256(
        source_namespace="chengfeng_waybill_no",
        source_id="REAL-WAYBILL-000",
    )

    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        excluded_waybill_identity_hashes={excluded_identity},
        legacy_result_roots=(),
    )

    assert index.eligible_waybill_count == 1
    assert index.excluded_waybill_count == 1
    assert excluded_identity not in {
        waybill.waybill_identity_sha256 for waybill in index.waybills
    }


def test_chengfeng_waybill_identity_matches_the_persisted_v1_algorithm() -> None:
    source_id = "REAL-WAYBILL-001"

    assert source_waybill_identity_sha256(
        source_namespace="chengfeng_waybill_no",
        source_id=source_id,
    ) == hashlib.sha256(
        b"dahe:persisted-waybill-identity:v1\0"
        + source_id.encode("utf-8")
    ).hexdigest()


def test_candidate_index_excludes_conflicting_duplicate_source_waybills(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, items = _write_acquisition(legacy_root, count=1)
    duplicate_root = (
        legacy_root
        / "daily-reports"
        / "evidence"
        / "conflicting-duplicate"
    )
    loading_path = duplicate_root / "loading.jpg"
    unloading_path = duplicate_root / "unloading.jpg"
    loading_hash = _write_jpeg(loading_path, color=(201, 1, 2))
    unloading_hash = _write_jpeg(unloading_path, color=(3, 202, 4))
    duplicate = {
        **items[0],
        "loading_image_path": str(loading_path),
        "loading_image_sha256": loading_hash,
        "unloading_image_path": str(unloading_path),
        "unloading_image_sha256": unloading_hash,
    }
    (acquisition_root / "second-export.json").write_text(
        json.dumps({"report_id": "second", "items": [duplicate]}),
        encoding="utf-8",
    )

    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )

    assert index.source_waybill_count == 1
    assert index.eligible_waybill_count == 0
    assert index.conflicting_source_waybill_count == 1


def test_candidate_index_rejects_source_paths_outside_legacy_root(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    outside = tmp_path / "outside.jpg"
    acquisition_root, _ = _write_acquisition(
        legacy_root,
        count=1,
        outside_path=outside,
    )

    with pytest.raises(CandidateContractError, match="outside the legacy data root"):
        build_candidate_index(
            legacy_data_root=legacy_root,
            acquisition_root=acquisition_root,
            excluded_image_hashes=set(),
            legacy_result_roots=(),
        )


def test_candidate_index_rejects_declared_image_hash_mismatch(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=1)
    manifest = acquisition_root / "immutable-export.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["items"][0]["loading_image_sha256"] = "0" * 64
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CandidateContractError, match="does not match"):
        build_candidate_index(
            legacy_data_root=legacy_root,
            acquisition_root=acquisition_root,
            excluded_image_hashes=set(),
            legacy_result_roots=(),
        )


def test_stage_review_package_requires_fifty_waybills_and_unique_images(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=50)
    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )
    index, exclusion_snapshot, development_authority = (
        _formal_stage_inputs(index)
    )
    selected = [waybill.candidate_id for waybill in index.waybills]
    output_root = tmp_path / "review"

    package = stage_review_package(
        index=index,
        selected_candidate_ids=selected,
        output_root=output_root,
        package_id="loop7-review-001",
        external_exclusion_snapshot=exclusion_snapshot,
        development_authority=development_authority,
    )

    assert package["status"] == "awaiting_human_review"
    assert len(package["waybills"]) == 50
    images = [
        image
        for waybill in package["waybills"]
        for image in waybill["images"]
    ]
    assert len(images) == 100
    assert len({image["image_sha256"] for image in images}) == 100
    assert all(
        (output_root / image["relative_path"]).is_file()
        for image in images
    )
    encoded = (output_root / "review-package.json").read_text(encoding="utf-8")
    assert "REAL-WAYBILL" not in encoded
    assert "platform_loading_tonnes" not in encoded
    assert (output_root / "external-exclusion-snapshot.json").is_file()
    source_snapshot = package["source_snapshot"]
    assert isinstance(source_snapshot, dict)
    assert (
        source_snapshot["exclusion_snapshot_sha256"]
        == index.exclusion_snapshot_sha256
    )
    assert (
        source_snapshot["external_exclusion_snapshot_sha256"]
        == exclusion_snapshot["canonical_sha256"]
    )

    with pytest.raises(CandidateContractError, match="exactly 50"):
        stage_review_package(
            index=index,
            selected_candidate_ids=selected[:-1],
            output_root=tmp_path / "too-small",
            package_id="loop7-review-too-small",
            external_exclusion_snapshot=exclusion_snapshot,
            development_authority=development_authority,
        )


def test_stage_review_package_never_overwrites_an_existing_output(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=50)
    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )
    index, exclusion_snapshot, development_authority = (
        _formal_stage_inputs(index)
    )
    output_root = tmp_path / "review"
    output_root.mkdir()

    with pytest.raises(CandidateContractError, match="must not already exist"):
        stage_review_package(
            index=index,
            selected_candidate_ids=[
                waybill.candidate_id for waybill in index.waybills
            ],
            output_root=output_root,
            package_id="loop7-review-existing",
            external_exclusion_snapshot=exclusion_snapshot,
            development_authority=development_authority,
        )


def test_stage_review_package_rejects_an_exclusion_snapshot_from_another_index(
    tmp_path: Path,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=50)
    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )
    index, snapshot, development_authority = _formal_stage_inputs(
        index
    )
    snapshot["image_sha256s"] = ["0" * 64]
    snapshot["image_identity_count"] = 1
    canonical = {
        "image_sha256s": ["0" * 64],
        "schema_version": 1,
        "source_file_sha256s": [],
        "waybill_identity_sha256s": (
            snapshot["waybill_identity_sha256s"]
        ),
    }
    snapshot["canonical_sha256"] = _canonical_sha256(canonical)

    with pytest.raises(CandidateContractError, match="candidate index"):
        stage_review_package(
            index=index,
            selected_candidate_ids=[
                waybill.candidate_id for waybill in index.waybills
            ],
            output_root=tmp_path / "review",
            package_id="loop7-review-mismatched-exclusions",
            external_exclusion_snapshot=snapshot,
            development_authority=development_authority,
        )


def test_stage_review_package_rejects_duplicate_source_manifest_hashes_early(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=50)
    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )
    index, exclusion_snapshot, development_authority = (
        _formal_stage_inputs(index)
    )
    repeated_hash = index.source_manifest_sha256s[0]
    unsafe_index = replace(
        index,
        source_manifest_sha256s=(repeated_hash, repeated_hash),
    )

    def unexpected_copy(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("copy must not start before preflight validation")

    monkeypatch.setattr(
        "dahe.verification.legacy_locked_set_candidates.shutil.copyfile",
        unexpected_copy,
    )

    with pytest.raises(CandidateContractError, match="duplicate"):
        stage_review_package(
            index=unsafe_index,
            selected_candidate_ids=[
                waybill.candidate_id for waybill in unsafe_index.waybills
            ],
            output_root=tmp_path / "review",
            package_id="loop7-review-duplicate-manifest",
            external_exclusion_snapshot=exclusion_snapshot,
            development_authority=development_authority,
        )


def test_stage_review_package_rejects_an_overlong_package_id_early(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=50)
    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )
    index, exclusion_snapshot, development_authority = (
        _formal_stage_inputs(index)
    )

    def unexpected_copy(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("copy must not start before preflight validation")

    monkeypatch.setattr(
        "dahe.verification.legacy_locked_set_candidates.shutil.copyfile",
        unexpected_copy,
    )

    with pytest.raises(CandidateContractError, match="too long"):
        stage_review_package(
            index=index,
            selected_candidate_ids=[
                waybill.candidate_id for waybill in index.waybills
            ],
            output_root=tmp_path / "review",
            package_id="x" * 201,
            external_exclusion_snapshot=exclusion_snapshot,
            development_authority=development_authority,
        )


def test_stage_review_package_uses_the_runtime_loader_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=50)
    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )
    index, exclusion_snapshot, development_authority = (
        _formal_stage_inputs(index)
    )
    output_root = tmp_path / "locked-set-review"
    loader_calls: list[Path] = []

    def validating_loader(data_root: Path) -> object:
        assert not output_root.exists()
        loader_calls.append(data_root)
        return load_locked_set_review_package(data_root)

    monkeypatch.setattr(
        "dahe.verification.legacy_locked_set_candidates."
        "load_locked_set_review_package",
        validating_loader,
    )

    package = stage_review_package(
        index=index,
        selected_candidate_ids=[
            waybill.candidate_id for waybill in index.waybills
        ],
        output_root=output_root,
        package_id="loop7-review-runtime-loader",
        external_exclusion_snapshot=exclusion_snapshot,
        development_authority=development_authority,
    )

    assert len(loader_calls) == 1
    assert loader_calls[0].name.startswith(".locked-set-review.staging-")
    assert package["canonical_sha256"] == load_locked_set_review_package(
        tmp_path
    ).canonical_sha256


def test_stage_review_package_does_not_publish_when_runtime_loader_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_root = tmp_path / "legacy"
    acquisition_root, _ = _write_acquisition(legacy_root, count=50)
    index = build_candidate_index(
        legacy_data_root=legacy_root,
        acquisition_root=acquisition_root,
        excluded_image_hashes=set(),
        legacy_result_roots=(),
    )
    index, exclusion_snapshot, development_authority = (
        _formal_stage_inputs(index)
    )
    output_root = tmp_path / "review"

    def rejecting_loader(_data_root: Path) -> object:
        raise LockedSetReviewPackageError("injected formal-loader rejection")

    monkeypatch.setattr(
        "dahe.verification.legacy_locked_set_candidates."
        "load_locked_set_review_package",
        rejecting_loader,
    )

    with pytest.raises(
        CandidateContractError,
        match="formal-loader rejection",
    ):
        stage_review_package(
            index=index,
            selected_candidate_ids=[
                waybill.candidate_id for waybill in index.waybills
            ],
            output_root=output_root,
            package_id="loop7-review-rejected",
            external_exclusion_snapshot=exclusion_snapshot,
            development_authority=development_authority,
        )

    assert not output_root.exists()
    assert not list(tmp_path.glob(".review.staging-*"))
