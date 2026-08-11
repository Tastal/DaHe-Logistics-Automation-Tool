from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
    ShadowBatchImage,
    ShadowBatchItem,
    ShadowBatchSource,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
)
from dahe.verification.loop9_dataset_isolation import ExclusionKind
from dahe.verification.loop9_human_review import Loop9ReviewPackage
from dahe.verification.loop9_locked_selection_rollover import (
    Loop9LockedSelectionRolloverError,
    build_locked_selection_coverage_failure_attestation,
    development_inventory_from_failed_locked_selection,
    load_locked_selection_failure_attestation,
    persist_locked_selection_failure_attestation,
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _fingerprint(image_sha256: str, index: int) -> ImagePerceptualFingerprint:
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=image_sha256,
        width=640,
        height=480,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop,
                average_hash=hashlib.sha256(
                    f"average:{index}:{crop}".encode()
                ).hexdigest(),
                difference_hash=hashlib.sha256(
                    f"difference:{index}:{crop}".encode()
                ).hexdigest(),
            )
            for crop in (1000, 920, 840, 760)
        ),
    )


def _selection() -> FormalShadowSelectionManifest:
    items: list[ShadowBatchItem] = []
    for index in range(50):
        images: list[ShadowBatchImage] = []
        for slot_index, slot in enumerate(("loading", "unloading")):
            image_index = index * 2 + slot_index + 1
            image_sha256 = f"{image_index:064x}"
            images.append(
                ShadowBatchImage(
                    slot=slot,
                    sha256=image_sha256,
                    relative_path=(
                        f"sha256/{image_sha256[:2]}/{image_sha256[2:4]}/"
                        f"{image_sha256}.blob"
                    ),
                    byte_size=1000 + image_index,
                    media_type="image/jpeg",
                    perceptual_fingerprint=_fingerprint(
                        image_sha256,
                        image_index,
                    ),
                )
            )
        items.append(
            ShadowBatchItem(
                platform_waybill_id_digest=f"{1000 + index:064x}",
                waybill_number_digest=f"{2000 + index:064x}",
                vehicle_number_digest=f"{3000 + index:064x}",
                platform_loading_net="32.10",
                platform_unloading_net="31.90",
                images=(images[0], images[1]),
            )
        )
    batch = ChengfengShadowBatchManifest(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        source_build_sha256="a" * 64,
        contract_canonical_sha256="b" * 64,
        contract_file_sha256="c" * 64,
        contract_selection_sha256="d" * 64,
        pipeline_fingerprint="e" * 64,
        identity_context_sha256="f" * 64,
        sources=(
            ShadowBatchSource(
                access_window_id="window-locked-50",
                job_id="job-locked-50",
                capture_id="capture-locked-50",
                scope="current",
                page_number=1,
                page_size=50,
                checkpoint_sha256="1" * 64,
            ),
        ),
        items=tuple(items),
    )
    return FormalShadowSelectionManifest(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        source_capture_sha256="2" * 64,
        full_history_exclusion_authority_sha256="3" * 64,
        exclusion_child_index_head_sha256="4" * 64,
        exclusion_source_boundary_sha256="5" * 64,
        exclusion_source_inventory_high_watermark=7,
        selection_seed_authority_sha256="6" * 64,
        rank_commitment_sha256="7" * 64,
        prior_selection_sha256s=(),
        batch_manifest=batch,
    )


def _package(
    tmp_path: Path,
    selection: FormalShadowSelectionManifest,
) -> Loop9ReviewPackage:
    core: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_human_review_package",
        "review_kind": "current_locked_50",
        "status": "awaiting_human_confirmation",
        "item_count": 50,
        "image_count": 100,
        "binding": {
            "source_batch_sha256": (
                selection.batch_manifest.canonical_sha256
            ),
        },
        "source_files": {},
        "items": [],
        "draft_advisory": {},
    }
    payload = {**core, "canonical_sha256": _canonical_sha256(core)}
    return Loop9ReviewPackage(
        root=tmp_path.resolve(),
        payload=payload,
        source_batch=selection.batch_manifest,
        dataset_manifest=object(),  # type: ignore[arg-type]
        formal_selection=selection,
        auxiliary={},
    )


def _answers(
    package: Loop9ReviewPackage,
    *,
    complete_coverage: bool = False,
) -> dict[str, object]:
    extra_conditions = (
        "blur",
        "crop",
        "glare",
        "printed",
        "rotation_90",
        "rotation_180",
        "rotation_270",
        "screen",
        "unknown_layout",
    )
    reviews: list[dict[str, object]] = []
    image_index = 0
    for item in sorted(
        package.source_batch.items,
        key=lambda value: value.item_identity_sha256,
    ):
        images: list[dict[str, object]] = []
        for image in item.images:
            conditions = ["rotation_0"]
            if complete_coverage and image_index < len(extra_conditions):
                condition = extra_conditions[image_index]
                if condition.startswith("rotation_"):
                    conditions = [condition]
                else:
                    conditions.append(condition)
            role = image.slot
            ordinary_net: str | None = (
                "32.10" if image.slot == "loading" else "31.90"
            )
            if "unknown_layout" in conditions:
                role = "unknown"
                ordinary_net = None
            images.append(
                {
                    "slot": image.slot,
                    "image_sha256": image.sha256,
                    "role": role,
                    "ordinary_net": ordinary_net,
                    "quality_conditions": conditions,
                }
            )
            image_index += 1
        roles = {image["slot"]: image["role"] for image in images}
        pair_condition = (
            "unknown_or_non_ticket"
            if "unknown" in roles.values()
            else "normal_pair"
        )
        reviews.append(
            {
                "item_identity_sha256": item.item_identity_sha256,
                "confirmed_at": "2026-07-30T01:02:03Z",
                "images": images,
                "pair_condition": pair_condition,
                "confirmation": "corrected",
            }
        )
    core: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_human_review_answers",
        "review_kind": "current_locked_50",
        "package_sha256": package.payload["canonical_sha256"],
        "reviews": reviews,
    }
    return {**core, "canonical_sha256": _canonical_sha256(core)}


def test_failure_attestation_binds_complete_failed_50_without_claiming_a_seal(
    tmp_path: Path,
) -> None:
    selection = _selection()
    package = _package(tmp_path, selection)
    answers = _answers(package)

    attestation = build_locked_selection_coverage_failure_attestation(
        selection=selection,
        package=package,
        review_answers=answers,
    )

    assert attestation.gate_passed is False
    assert attestation.failure_reason == "natural_coverage_incomplete"
    assert attestation.selection_sha256 == selection.canonical_sha256
    assert attestation.package_sha256 == package.payload["canonical_sha256"]
    assert attestation.review_answers_sha256 == answers["canonical_sha256"]
    assert attestation.review_count == 50
    assert attestation.image_truth_count == 100
    assert len(attestation.reviews) == 50
    assert attestation.missing_conditions == (
        "blur",
        "crop",
        "glare",
        "printed",
        "rotation_90",
        "rotation_180",
        "rotation_270",
        "screen",
        "unknown_layout",
    )
    payload = attestation.to_payload()
    assert "seal_sha256" not in payload
    assert payload["canonical_sha256"] == attestation.canonical_sha256


def test_failure_attestation_rejects_complete_coverage_and_mismatched_batch(
    tmp_path: Path,
) -> None:
    selection = _selection()
    package = _package(tmp_path, selection)
    with pytest.raises(
        Loop9LockedSelectionRolloverError,
        match=r"coverage.*passed",
    ):
        build_locked_selection_coverage_failure_attestation(
            selection=selection,
            package=package,
            review_answers=_answers(package, complete_coverage=True),
        )

    changed = _selection()
    changed_batch = ChengfengShadowBatchManifest(
        target_kind=changed.batch_manifest.target_kind,
        source_build_sha256=changed.batch_manifest.source_build_sha256,
        contract_canonical_sha256=changed.batch_manifest.contract_canonical_sha256,
        contract_file_sha256=changed.batch_manifest.contract_file_sha256,
        contract_selection_sha256=changed.batch_manifest.contract_selection_sha256,
        pipeline_fingerprint=changed.batch_manifest.pipeline_fingerprint,
        identity_context_sha256=changed.batch_manifest.identity_context_sha256,
        sources=(
            ShadowBatchSource(
                access_window_id="different-window",
                job_id="different-job",
                capture_id="different-capture",
                scope="current",
                page_number=1,
                page_size=50,
                checkpoint_sha256="0" * 64,
            ),
        ),
        items=changed.batch_manifest.items,
    )
    mismatched_package = Loop9ReviewPackage(
        root=tmp_path.resolve(),
        payload=package.payload,
        source_batch=changed_batch,
        dataset_manifest=object(),  # type: ignore[arg-type]
        formal_selection=changed,
        auxiliary={},
    )
    with pytest.raises(
        Loop9LockedSelectionRolloverError,
        match=r"selection.*package",
    ):
        build_locked_selection_coverage_failure_attestation(
            selection=selection,
            package=mismatched_package,
            review_answers=_answers(package),
        )


def test_failed_selection_inventory_excludes_exact_failed_50_only(
    tmp_path: Path,
) -> None:
    selection = _selection()
    package = _package(tmp_path, selection)
    attestation = build_locked_selection_coverage_failure_attestation(
        selection=selection,
        package=package,
        review_answers=_answers(package),
    )

    inventory = development_inventory_from_failed_locked_selection(
        selection=selection,
        failure_attestation=attestation,
    )

    assert inventory.exclusion_kind is ExclusionKind.DEVELOPMENT
    assert len(inventory.platform_identity_sha256s) == 50
    assert len(inventory.image_sha256s) == 100
    assert len(inventory.perceptual_fingerprints) == 100
    assert inventory.scope_exclusion_tokens == ()
    assert inventory.identity_context_sha256 == (
        selection.batch_manifest.identity_context_sha256
    )
    assert set(inventory.platform_identity_sha256s) == {
        item.platform_waybill_id_digest
        for item in selection.batch_manifest.items
    }
    assert set(inventory.image_sha256s) == {
        image.sha256
        for item in selection.batch_manifest.items
        for image in item.images
    }


def test_failure_attestation_store_is_canonical_and_rejects_duplicate_fields(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    selection = _selection()
    package = _package(data_root, selection)
    attestation = build_locked_selection_coverage_failure_attestation(
        selection=selection,
        package=package,
        review_answers=_answers(package),
    )
    path = persist_locked_selection_failure_attestation(
        data_root=data_root,
        attestation=attestation,
    )
    assert (
        load_locked_selection_failure_attestation(path).canonical_sha256
        == attestation.canonical_sha256
    )

    content = path.read_text(encoding="utf-8")
    path.write_text(
        '{"canonical_sha256":"' + ("0" * 64) + '",' + content[1:],
        encoding="utf-8",
    )
    with pytest.raises(
        Loop9LockedSelectionRolloverError,
        match="duplicate",
    ):
        load_locked_selection_failure_attestation(path)
