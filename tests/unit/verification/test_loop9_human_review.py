from __future__ import annotations

import hashlib
import json
from io import BytesIO
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from dahe import __version__
from dahe.api.app import create_app
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
from dahe.verification.image_similarity import build_image_fingerprint
from dahe.verification.loop9_dataset_isolation import (
    DatasetKind,
    Loop9DatasetEntry,
    Loop9DatasetImage,
    Loop9DatasetManifest,
)
from dahe.verification.loop9_human_review import (
    Loop9HumanReviewError,
    load_loop9_review_package,
    prepare_loop9_review_package,
    replay_loop9_review,
    seal_loop9_review,
    write_loop9_review_evidence,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _png_bytes(index: int) -> bytes:
    output = BytesIO()
    Image.new(
        "RGB",
        (12, 12),
        ((index * 29) % 256, (index * 71) % 256, (index * 113) % 256),
    ).save(output, format="PNG", compress_level=0)
    return output.getvalue()


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _with_hash(payload: dict[str, object]) -> dict[str, object]:
    value = dict(payload)
    value["canonical_sha256"] = _canonical_sha256(value)
    return value


def _content_path(digest: str) -> str:
    return f"sha256/{digest[:2]}/{digest[2:4]}/{digest}.blob"


def _source_bundle(
    tmp_path: Path,
    *,
    target: ShadowBatchTargetKind,
) -> tuple[
    Path,
    Path,
    Path,
    ChengfengShadowBatchManifest,
    Loop9DatasetManifest,
]:
    count = target.expected_count
    image_root = (tmp_path / f"{target.value}-images").resolve()
    image_root.mkdir()
    items: list[ShadowBatchItem] = []
    dataset_entries: list[Loop9DatasetEntry] = []
    for item_index in range(count):
        images: list[ShadowBatchImage] = []
        dataset_images: list[Loop9DatasetImage] = []
        for offset, slot in enumerate(("loading", "unloading")):
            content = _png_bytes((item_index * 2) + offset + 1)
            digest = hashlib.sha256(content).hexdigest()
            relative_path = _content_path(digest)
            path = image_root / Path(relative_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            fingerprint = build_image_fingerprint(content)
            images.append(
                ShadowBatchImage(
                    slot=slot,
                    sha256=digest,
                    relative_path=relative_path,
                    byte_size=len(content),
                    media_type="image/png",
                    perceptual_fingerprint=fingerprint,
                )
            )
            dataset_images.append(
                Loop9DatasetImage(
                    image_sha256=digest,
                    perceptual_fingerprint=fingerprint,
                )
            )
        platform_identity = hashlib.sha256(
            f"platform:{target.value}:{item_index}".encode()
        ).hexdigest()
        item = ShadowBatchItem(
            platform_waybill_id_digest=platform_identity,
            waybill_number_digest=hashlib.sha256(
                f"waybill:{target.value}:{item_index}".encode()
            ).hexdigest(),
            vehicle_number_digest=hashlib.sha256(
                f"vehicle:{target.value}:{item_index}".encode()
            ).hexdigest(),
            platform_loading_net=f"{30 + item_index / 100:.2f}",
            platform_unloading_net=f"{29 + item_index / 100:.2f}",
            images=cast(
                tuple[ShadowBatchImage, ShadowBatchImage],
                tuple(images),
            ),
        )
        items.append(item)
        dataset_entries.append(
            Loop9DatasetEntry(
                platform_identity_sha256=platform_identity,
                scope_exclusion_token=None,
                images=tuple(dataset_images),
            )
        )
    source = ShadowBatchSource(
        access_window_id="window-1",
        job_id=f"job-{target.value}",
        capture_id="capture-1",
        scope="current_pending_settlement",
        page_number=1,
        page_size=count,
        checkpoint_sha256=HASH_A,
    )
    batch = ChengfengShadowBatchManifest(
        target_kind=target,
        source_build_sha256=HASH_B,
        contract_canonical_sha256=HASH_C,
        contract_file_sha256=HASH_D,
        contract_selection_sha256=HASH_A,
        pipeline_fingerprint=hashlib.sha256(b"pipeline").hexdigest(),
        identity_context_sha256=hashlib.sha256(b"identity").hexdigest(),
        sources=(source,),
        items=tuple(items),
    )
    selection = _formal_selection(batch)
    dataset = Loop9DatasetManifest(
        dataset_id=f"dataset-{target.value}",
        dataset_kind=DatasetKind(target.value),
        build_sha256=batch.source_build_sha256,
        contract_sha256=batch.contract_canonical_sha256,
        source_job_id=source.job_id,
        source_snapshot_sha256=batch.canonical_sha256,
        entries=tuple(dataset_entries),
        identity_context_sha256=batch.identity_context_sha256,
        formal_selection_sha256=selection.canonical_sha256,
        locked_gate_evidence_sha256=(
            selection.locked_gate_evidence_sha256
        ),
    )
    batch_path = _write_json(
        (tmp_path / f"{target.value}-batch.json").resolve(),
        batch.to_payload(),
    )
    dataset_path = _write_json(
        (tmp_path / f"{target.value}-dataset.json").resolve(),
        dataset.to_payload(),
    )
    return batch_path, dataset_path, image_root, batch, dataset


def _formal_selection(
    batch: ChengfengShadowBatchManifest,
) -> FormalShadowSelectionManifest:
    target = batch.target_kind
    return FormalShadowSelectionManifest(
        target_kind=target,
        source_capture_sha256=hashlib.sha256(
            f"capture:{target.value}".encode()
        ).hexdigest(),
        full_history_exclusion_authority_sha256=hashlib.sha256(
            f"exclusions:{target.value}".encode()
        ).hexdigest(),
        exclusion_child_index_head_sha256=hashlib.sha256(
            f"exclusion-head:{target.value}".encode()
        ).hexdigest(),
        exclusion_source_boundary_sha256=hashlib.sha256(
            f"exclusion-boundary:{target.value}".encode()
        ).hexdigest(),
        exclusion_source_inventory_high_watermark=100,
        selection_seed_authority_sha256=hashlib.sha256(
            f"seed:{target.value}".encode()
        ).hexdigest(),
        rank_commitment_sha256=hashlib.sha256(
            f"rank:{target.value}".encode()
        ).hexdigest(),
        prior_selection_sha256s=(
            ()
            if target is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else (hashlib.sha256(b"locked-selection").hexdigest(),)
        ),
        batch_manifest=batch,
        locked_gate_evidence_sha256=(
            None
            if target is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else hashlib.sha256(b"current-locked-gate").hexdigest()
        ),
    )


def _image_truth(
    *,
    item: ShadowBatchItem,
    item_index: int,
    include_quality_coverage: bool,
) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for image_index, image in enumerate(item.images):
        global_index = (item_index * 2) + image_index
        conditions = [f"rotation_{(global_index % 4) * 90}"]
        if include_quality_coverage:
            extras = {
                0: "blur",
                1: "crop",
                2: "glare",
                3: "printed",
                4: "screen",
                99: "unknown_layout",
            }
            if global_index in extras:
                conditions.append(extras[global_index])
        role = image.slot
        ordinary_net: str | None = (
            item.platform_loading_net
            if image.slot == "loading"
            else item.platform_unloading_net
        )
        if "unknown_layout" in conditions:
            role = "unknown"
            ordinary_net = None
        values.append(
            {
                "slot": image.slot,
                "image_sha256": image.sha256,
                "role": role,
                "ordinary_net": ordinary_net,
                "quality_conditions": conditions,
            }
        )
    return values


def _suggestions(batch: ChengfengShadowBatchManifest) -> dict[str, object]:
    suggestions: list[dict[str, object]] = []
    for index, item in enumerate(batch.items):
        truth = _image_truth(
            item=item,
            item_index=index,
            include_quality_coverage=True,
        )
        suggestions.append(
            {
                "item_identity_sha256": item.item_identity_sha256,
                "truth_status": "unconfirmed_non_truth",
                "images": truth,
                "pair_condition": (
                    "unknown_or_non_ticket"
                    if any(image["role"] == "unknown" for image in truth)
                    else "normal_pair"
                ),
            }
        )
    return _with_hash(
        {
            "schema_version": 1,
            "kind": "loop9_independent_draft_suggestions",
            "target_kind": "current_locked_50",
            "source_batch_sha256": batch.canonical_sha256,
            "source_build_sha256": batch.source_build_sha256,
            "source_contract_sha256": batch.contract_canonical_sha256,
            "origin": "independent_visual_assistance",
            "formal_system_results_accessed": False,
            "suggestions": suggestions,
        }
    )


def _machine_results(
    batch: ChengfengShadowBatchManifest,
    *,
    wrong_auto_pass: bool = False,
    technical_failure: bool = False,
) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for index, item in enumerate(batch.items):
        result_images = [
            {
                "slot": image.slot,
                "image_sha256": image.sha256,
                "predicted_role": image.slot,
                "ordinary_net": (
                    item.platform_loading_net
                    if image.slot == "loading"
                    else item.platform_unloading_net
                ),
                "role_high_confidence": True,
            }
            for image in item.images
        ]
        outcome = "normal_ready"
        issue_code: str | None = None
        diagnostic_code: str | None = None
        if technical_failure and index == 0:
            outcome = "technical_failed"
            issue_code = "ocr_worker_failed"
            diagnostic_code = "OCR-TEST-001"
            result_images = []
        elif wrong_auto_pass and index == 0:
            result_images[0]["predicted_role"] = "unloading"
        core: dict[str, object] = {
            "item_identity_sha256": item.item_identity_sha256,
            "automatic_outcome": outcome,
            "issue_code": issue_code,
            "diagnostic_code": diagnostic_code,
            "images": result_images,
        }
        results.append({**core, "result_sha256": _canonical_sha256(core)})
    return _with_hash(
        {
            "schema_version": 1,
            "kind": "loop9_machine_audit_results",
            "target_kind": "real_shadow_30",
            "source_batch_sha256": batch.canonical_sha256,
            "source_build_sha256": batch.source_build_sha256,
            "source_contract_sha256": batch.contract_canonical_sha256,
            "pipeline_fingerprint": batch.pipeline_fingerprint,
            "results": results,
        }
    )


def _answers(
    *,
    package_payload: dict[str, object],
    batch: ChengfengShadowBatchManifest,
    locked: bool,
) -> dict[str, object]:
    reviews: list[dict[str, object]] = []
    for index, item in enumerate(batch.items):
        images = _image_truth(
            item=item,
            item_index=index,
            include_quality_coverage=locked,
        )
        pair_condition = (
            "unknown_or_non_ticket"
            if any(image["role"] == "unknown" for image in images)
            else "normal_pair"
        )
        review: dict[str, object] = {
            "item_identity_sha256": item.item_identity_sha256,
            "confirmed_at": f"2026-07-30T00:{index:02d}:00Z",
            "images": images,
            "pair_condition": pair_condition,
            "confirmation": "suggestion_confirmed" if locked else "machine_result_confirmed",
        }
        reviews.append(review)
    return _with_hash(
        {
            "schema_version": 1,
            "kind": "loop9_human_review_answers",
            "review_kind": (
                "current_locked_50" if locked else "real_shadow_30"
            ),
            "package_sha256": package_payload["canonical_sha256"],
            "reviews": reviews,
        }
    )


def _isolation_evidence(
    *,
    package_payload: dict[str, object],
) -> dict[str, object]:
    binding = cast(dict[str, object], package_payload["binding"])
    review_binding = {
        "dataset_kind": package_payload["review_kind"],
        "dataset_id": binding["dataset_id"],
        "manifest_sha256": binding["dataset_manifest_sha256"],
        "formal_selection_sha256": binding[
            "formal_selection_sha256"
        ],
        "build_sha256": binding["source_build_sha256"],
        "contract_sha256": binding["contract_canonical_sha256"],
        "source_job_id": binding["source_job_id"],
        "source_snapshot_sha256": binding["source_snapshot_sha256"],
        "locked_gate_evidence_sha256": binding[
            "locked_gate_evidence_sha256"
        ],
        "entry_count": package_payload["item_count"],
        "image_count": package_payload["image_count"],
    }
    other_bindings = [
        {
            "dataset_kind": kind,
            "dataset_id": f"dataset-{kind}",
            "manifest_sha256": hashlib.sha256(kind.encode()).hexdigest(),
            "formal_selection_sha256": (
                hashlib.sha256(f"selection:{kind}".encode()).hexdigest()
                if kind in {"current_locked_50", "real_shadow_30"}
                else None
            ),
            "build_sha256": binding["source_build_sha256"],
            "contract_sha256": binding["contract_canonical_sha256"],
            "source_job_id": f"job-{kind}",
            "source_snapshot_sha256": hashlib.sha256(
                f"snapshot-{kind}".encode()
            ).hexdigest(),
            "locked_gate_evidence_sha256": (
                hashlib.sha256(b"current-locked-gate").hexdigest()
                if kind == "real_shadow_30"
                else None
            ),
            "entry_count": 1,
            "image_count": 1,
        }
        for kind in (
            "discovery_development",
            "current_locked_50",
            "real_shadow_30",
            "daily_validation",
        )
        if kind != package_payload["review_kind"]
    ]
    payload: dict[str, object] = {
        "schema_version": 1,
        "isolation_passed": True,
        "exact_identity_overlap_count": 0,
        "exact_image_overlap_count": 0,
        "perceptual_overlap_count": 0,
        "current_locked_image_count": 100,
        "real_shadow_entry_count": 30,
        "dataset_bindings": [review_binding, *other_bindings],
    }
    return _with_hash(payload)


def _prepare_locked(
    tmp_path: Path,
) -> tuple[
    Path,
    ChengfengShadowBatchManifest,
    dict[str, object],
]:
    batch_path, dataset_path, image_root, batch, _ = _source_bundle(
        tmp_path,
        target=ShadowBatchTargetKind.CURRENT_LOCKED_50,
    )
    suggestion_path = _write_json(
        (tmp_path / "suggestions.json").resolve(),
        _suggestions(batch),
    )
    output_dir = (tmp_path / "review-package").resolve()
    package = prepare_loop9_review_package(
        source_batch_path=batch_path,
        dataset_manifest_path=dataset_path,
        formal_selection=_formal_selection(batch),
        image_root=image_root,
        auxiliary_path=suggestion_path,
        output_dir=output_dir,
    )
    return output_dir, batch, package.payload


def _prepare_shadow(
    tmp_path: Path,
    *,
    wrong_auto_pass: bool = False,
    technical_failure: bool = False,
) -> tuple[
    Path,
    ChengfengShadowBatchManifest,
    dict[str, object],
]:
    batch_path, dataset_path, image_root, batch, _ = _source_bundle(
        tmp_path,
        target=ShadowBatchTargetKind.REAL_SHADOW_30,
    )
    result_path = _write_json(
        (tmp_path / "machine-results.json").resolve(),
        _machine_results(
            batch,
            wrong_auto_pass=wrong_auto_pass,
            technical_failure=technical_failure,
        ),
    )
    output_dir = (tmp_path / "review-package").resolve()
    package = prepare_loop9_review_package(
        source_batch_path=batch_path,
        dataset_manifest_path=dataset_path,
        formal_selection=_formal_selection(batch),
        image_root=image_root,
        auxiliary_path=result_path,
        output_dir=output_dir,
    )
    return output_dir, batch, package.payload


def _review_headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": "http://127.0.0.1:8877",
        "X-DaHe-Client-Version": __version__,
    }


def test_prepare_locked_review_package_is_content_addressed_and_identity_free(
    tmp_path: Path,
) -> None:
    package_dir, batch, payload = _prepare_locked(tmp_path)

    assert payload["review_kind"] == "current_locked_50"
    assert payload["item_count"] == 50
    assert payload["image_count"] == 100
    assert payload["status"] == "awaiting_human_confirmation"
    assert payload["draft_advisory"] == {
        "formal_system_results_accessed": False,
        "message": "辅助建议，尚未成为真值",  # noqa: RUF001
        "truth_status": "unconfirmed_non_truth",
    }
    serialized = json.dumps(payload, ensure_ascii=False).lower()
    for forbidden in (
        "reviewer",
        "operator",
        "actor",
        "employee",
        "staff",
        "username",
        "windows_sid",
    ):
        assert forbidden not in serialized
    for item in cast(list[dict[str, object]], payload["items"]):
        for image in cast(list[dict[str, object]], item["images"]):
            relative = cast(str, image["relative_path"])
            assert relative.startswith("images/sha256/")
            path = package_dir / Path(relative)
            assert path.is_file()
            assert hashlib.sha256(path.read_bytes()).hexdigest() == image["image_sha256"]
    loaded = load_loop9_review_package(package_dir)
    assert loaded.payload == payload
    assert loaded.source_batch.canonical_sha256 == batch.canonical_sha256

    with pytest.raises(Loop9HumanReviewError, match="already exists"):
        prepare_loop9_review_package(
            source_batch_path=package_dir / "source" / "source-batch.json",
            dataset_manifest_path=(
                package_dir / "source" / "dataset-manifest.json"
            ),
            formal_selection=loaded.formal_selection,
            image_root=package_dir / "images",
            auxiliary_path=package_dir / "source" / "review-auxiliary.json",
            output_dir=package_dir,
        )


def test_prepare_rejects_non_independent_suggestions_and_authority_mismatch(
    tmp_path: Path,
) -> None:
    batch_path, dataset_path, image_root, batch, _ = _source_bundle(
        tmp_path,
        target=ShadowBatchTargetKind.CURRENT_LOCKED_50,
    )
    suggestions = _suggestions(batch)
    suggestions["formal_system_results_accessed"] = True
    suggestions["canonical_sha256"] = _canonical_sha256(
        {key: value for key, value in suggestions.items() if key != "canonical_sha256"}
    )
    auxiliary_path = _write_json(
        (tmp_path / "suggestions.json").resolve(),
        suggestions,
    )
    with pytest.raises(Loop9HumanReviewError, match="independent"):
        prepare_loop9_review_package(
            source_batch_path=batch_path,
            dataset_manifest_path=dataset_path,
            formal_selection=_formal_selection(batch),
            image_root=image_root,
            auxiliary_path=auxiliary_path,
            output_dir=(tmp_path / "output").resolve(),
        )

    dataset_payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    dataset_payload["build_sha256"] = HASH_A
    dataset_payload["canonical_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in dataset_payload.items()
            if key != "canonical_sha256"
        }
    )
    _write_json(dataset_path, dataset_payload)
    _write_json(auxiliary_path, _suggestions(batch))
    with pytest.raises(Loop9HumanReviewError, match="build"):
        prepare_loop9_review_package(
            source_batch_path=batch_path,
            dataset_manifest_path=dataset_path,
            formal_selection=_formal_selection(batch),
            image_root=image_root,
            auxiliary_path=auxiliary_path,
            output_dir=(tmp_path / "other-output").resolve(),
        )


def test_locked_review_seal_requires_all_items_and_quality_contract(
    tmp_path: Path,
) -> None:
    package_dir, batch, package_payload = _prepare_locked(tmp_path)
    answers = _answers(
        package_payload=package_payload,
        batch=batch,
        locked=True,
    )
    answers_path = _write_json((tmp_path / "answers.json").resolve(), answers)
    seal_path = (tmp_path / "seal.json").resolve()

    seal = seal_loop9_review(
        package_dir=package_dir,
        review_answers_path=answers_path,
        output_path=seal_path,
    )

    assert seal["status"] == "sealed"
    assert seal["review_count"] == 50
    assert seal["image_truth_count"] == 100
    assert seal["quality_coverage"]["passed"] is True
    assert seal["confirmation_summary"] == {
        "corrected": 0,
        "suggestion_confirmed": 50,
    }
    assert "reviewer" not in json.dumps(seal).lower()
    with pytest.raises(Loop9HumanReviewError, match="already exists"):
        seal_loop9_review(
            package_dir=package_dir,
            review_answers_path=answers_path,
            output_path=seal_path,
        )

    incomplete = dict(answers)
    incomplete["reviews"] = cast(list[object], answers["reviews"])[:-1]
    incomplete["canonical_sha256"] = _canonical_sha256(
        {key: value for key, value in incomplete.items() if key != "canonical_sha256"}
    )
    incomplete_path = _write_json(
        (tmp_path / "incomplete.json").resolve(),
        incomplete,
    )
    with pytest.raises(Loop9HumanReviewError, match="exactly 50"):
        seal_loop9_review(
            package_dir=package_dir,
            review_answers_path=incomplete_path,
            output_path=(tmp_path / "bad-seal.json").resolve(),
        )


def test_locked_review_correction_must_differ_and_forbids_identity_fields(
    tmp_path: Path,
) -> None:
    package_dir, batch, package_payload = _prepare_locked(tmp_path)
    answers = _answers(
        package_payload=package_payload,
        batch=batch,
        locked=True,
    )
    first = cast(list[dict[str, object]], answers["reviews"])[0]
    first["confirmation"] = "corrected"
    answers["canonical_sha256"] = _canonical_sha256(
        {key: value for key, value in answers.items() if key != "canonical_sha256"}
    )
    path = _write_json((tmp_path / "answers.json").resolve(), answers)
    with pytest.raises(Loop9HumanReviewError, match="must change"):
        seal_loop9_review(
            package_dir=package_dir,
            review_answers_path=path,
            output_path=(tmp_path / "seal.json").resolve(),
        )

    first["reviewer_id"] = "not-allowed"
    answers["canonical_sha256"] = _canonical_sha256(
        {key: value for key, value in answers.items() if key != "canonical_sha256"}
    )
    _write_json(path, answers)
    with pytest.raises(Loop9HumanReviewError, match="identity"):
        seal_loop9_review(
            package_dir=package_dir,
            review_answers_path=path,
            output_path=(tmp_path / "identity-seal.json").resolve(),
        )


def test_locked_review_replay_binds_cross_dataset_isolation_and_is_deterministic(
    tmp_path: Path,
) -> None:
    package_dir, batch, package_payload = _prepare_locked(tmp_path)
    answers_path = _write_json(
        (tmp_path / "answers.json").resolve(),
        _answers(
            package_payload=package_payload,
            batch=batch,
            locked=True,
        ),
    )
    seal_path = (tmp_path / "seal.json").resolve()
    seal = seal_loop9_review(
        package_dir=package_dir,
        review_answers_path=answers_path,
        output_path=seal_path,
    )
    isolation_path = _write_json(
        (tmp_path / "isolation.json").resolve(),
        _isolation_evidence(package_payload=package_payload),
    )

    first = replay_loop9_review(
        package_dir=package_dir,
        seal_path=seal_path,
        isolation_evidence_path=isolation_path,
    )
    second = replay_loop9_review(
        package_dir=package_dir,
        seal_path=seal_path,
        isolation_evidence_path=isolation_path,
    )

    assert first == second
    assert first["replay_passed"] is True
    assert first["package_sha256"] == package_payload["canonical_sha256"]
    assert first["seal_sha256"] == seal["canonical_sha256"]
    assert first["cross_dataset_isolation_passed"] is True
    replay_path = (tmp_path / "replay.json").resolve()
    write_loop9_review_evidence(
        output_path=replay_path,
        payload=first,
    )
    assert json.loads(replay_path.read_text(encoding="utf-8")) == first
    with pytest.raises(Loop9HumanReviewError, match="already exists"):
        write_loop9_review_evidence(
            output_path=replay_path,
            payload=first,
        )

    isolation = json.loads(isolation_path.read_text(encoding="utf-8"))
    isolation["dataset_bindings"][0]["manifest_sha256"] = HASH_A
    isolation["canonical_sha256"] = _canonical_sha256(
        {key: value for key, value in isolation.items() if key != "canonical_sha256"}
    )
    _write_json(isolation_path, isolation)
    with pytest.raises(Loop9HumanReviewError, match="isolation"):
        replay_loop9_review(
            package_dir=package_dir,
            seal_path=seal_path,
            isolation_evidence_path=isolation_path,
        )


def test_replay_detects_package_image_and_seal_tampering(
    tmp_path: Path,
) -> None:
    package_dir, batch, package_payload = _prepare_locked(tmp_path)
    answers_path = _write_json(
        (tmp_path / "answers.json").resolve(),
        _answers(
            package_payload=package_payload,
            batch=batch,
            locked=True,
        ),
    )
    seal_path = (tmp_path / "seal.json").resolve()
    seal_loop9_review(
        package_dir=package_dir,
        review_answers_path=answers_path,
        output_path=seal_path,
    )
    isolation_path = _write_json(
        (tmp_path / "isolation.json").resolve(),
        _isolation_evidence(package_payload=package_payload),
    )
    first_item = cast(list[dict[str, object]], package_payload["items"])[0]
    first_image = cast(list[dict[str, object]], first_item["images"])[0]
    (package_dir / Path(cast(str, first_image["relative_path"]))).write_bytes(
        b"changed"
    )
    with pytest.raises(Loop9HumanReviewError, match="image"):
        replay_loop9_review(
            package_dir=package_dir,
            seal_path=seal_path,
            isolation_evidence_path=isolation_path,
        )


def test_package_replay_rejects_unbound_extra_files(
    tmp_path: Path,
) -> None:
    package_dir, _, _ = _prepare_locked(tmp_path)
    (package_dir / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(Loop9HumanReviewError, match="inventory"):
        load_loop9_review_package(package_dir)


def test_package_loader_rejects_duplicate_json_fields(
    tmp_path: Path,
) -> None:
    package_dir, _, _ = _prepare_locked(tmp_path)
    package_path = package_dir / "review-package.json"
    content = package_path.read_text(encoding="utf-8")
    package_path.write_text(
        content.replace(
            '"schema_version": 1,',
            '"schema_version": 1,\n  "schema_version": 1,',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(Loop9HumanReviewError, match="duplicate fields"):
        load_loop9_review_package(package_dir)


def test_shadow_review_records_per_item_differences_and_zero_error_gate(
    tmp_path: Path,
) -> None:
    package_dir, batch, package_payload = _prepare_shadow(tmp_path)
    answers_path = _write_json(
        (tmp_path / "answers.json").resolve(),
        _answers(
            package_payload=package_payload,
            batch=batch,
            locked=False,
        ),
    )
    seal = seal_loop9_review(
        package_dir=package_dir,
        review_answers_path=answers_path,
        output_path=(tmp_path / "seal.json").resolve(),
    )

    comparison = cast(dict[str, object], seal["comparison_summary"])
    assert comparison == {
        "high_confidence_role_error_count": 0,
        "matched_count": 30,
        "reviewed_difference_count": 0,
        "technical_failure_count": 0,
        "unresolved_difference_count": 0,
        "wrong_auto_pass_count": 0,
    }
    assert seal["shadow_gate_passed"] is True
    reviews = cast(list[dict[str, object]], seal["reviews"])
    assert all(review["comparison"]["classification"] == "match" for review in reviews)


def test_shadow_wrong_auto_pass_and_technical_failure_cannot_pass(
    tmp_path: Path,
) -> None:
    wrong_root = (tmp_path / "wrong").resolve()
    wrong_root.mkdir()
    package_dir, batch, package_payload = _prepare_shadow(
        wrong_root,
        wrong_auto_pass=True,
    )
    answers = _answers(
        package_payload=package_payload,
        batch=batch,
        locked=False,
    )
    first = cast(list[dict[str, object]], answers["reviews"])[0]
    first["confirmation"] = "difference_confirmed"
    answers["canonical_sha256"] = _canonical_sha256(
        {key: value for key, value in answers.items() if key != "canonical_sha256"}
    )
    seal = seal_loop9_review(
        package_dir=package_dir,
        review_answers_path=_write_json(
            (wrong_root / "answers.json").resolve(),
            answers,
        ),
        output_path=(wrong_root / "seal.json").resolve(),
    )
    summary = cast(dict[str, object], seal["comparison_summary"])
    assert summary["wrong_auto_pass_count"] == 1
    assert summary["high_confidence_role_error_count"] == 1
    assert seal["shadow_gate_passed"] is False

    technical_root = (tmp_path / "technical").resolve()
    technical_root.mkdir()
    package_dir, batch, package_payload = _prepare_shadow(
        technical_root,
        technical_failure=True,
    )
    answers = _answers(
        package_payload=package_payload,
        batch=batch,
        locked=False,
    )
    first = cast(list[dict[str, object]], answers["reviews"])[0]
    first["confirmation"] = "difference_confirmed"
    answers["canonical_sha256"] = _canonical_sha256(
        {key: value for key, value in answers.items() if key != "canonical_sha256"}
    )
    seal = seal_loop9_review(
        package_dir=package_dir,
        review_answers_path=_write_json(
            (technical_root / "answers.json").resolve(),
            answers,
        ),
        output_path=(technical_root / "seal.json").resolve(),
    )
    summary = cast(dict[str, object], seal["comparison_summary"])
    assert summary["technical_failure_count"] == 1
    assert seal["shadow_gate_passed"] is False


def test_shadow_confirmation_must_match_computed_difference(
    tmp_path: Path,
) -> None:
    package_dir, batch, package_payload = _prepare_shadow(
        tmp_path,
        wrong_auto_pass=True,
    )
    answers = _answers(
        package_payload=package_payload,
        batch=batch,
        locked=False,
    )
    path = _write_json((tmp_path / "answers.json").resolve(), answers)

    with pytest.raises(Loop9HumanReviewError, match="difference"):
        seal_loop9_review(
            package_dir=package_dir,
            review_answers_path=path,
            output_path=(tmp_path / "seal.json").resolve(),
        )


def test_offline_review_app_restores_server_draft_without_mutating_package(
    tmp_path: Path,
    project_root: Path,
) -> None:
    package_dir, _, package_payload = _prepare_locked(tmp_path)
    data_root = (tmp_path / "offline-review-data").resolve()
    package_inventory_before = {
        path.relative_to(package_dir).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in package_dir.rglob("*")
        if path.is_file()
    }
    first = cast(list[dict[str, object]], package_payload["items"])[0]
    identity = cast(str, first["item_identity_sha256"])
    suggestion = cast(dict[str, object], first["draft_suggestion"])
    payload = {
        "expected_record_version": 0,
        "truth": {
            "images": suggestion["images"],
            "pair_condition": suggestion["pair_condition"],
        },
    }

    app = create_app(
        data_root=data_root,
        project_root=project_root,
        instance_id=f"loop9-review-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        loop9_review_package_path=package_dir,
    )
    with TestClient(app) as client:
        session = client.get(
            "/api/v1/session",
            headers=_review_headers(),
        )
        assert session.status_code == 200
        assert session.json()["loop9_review_enabled"] is True
        csrf = session.json()["csrf_token"]
        saved = client.post(
            f"/api/v1/loop9-review/items/{identity}/draft",
            json=payload,
            headers={
                **_review_headers(),
                "X-CSRF-Token": csrf,
                "Idempotency-Key": "save-draft-before-refresh",
            },
        )
        assert saved.status_code == 200, saved.text
        assert saved.json()["item"]["review_status"] == "draft"

    restarted = create_app(
        data_root=data_root,
        project_root=project_root,
        instance_id=f"loop9-review-{uuid4().hex}",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        loop9_review_package_path=package_dir,
    )
    with TestClient(restarted) as client:
        assert client.get(
            "/api/v1/session",
            headers=_review_headers(),
        ).status_code == 200
        restored = client.get(
            f"/api/v1/loop9-review/items/{identity}",
            headers=_review_headers(),
        )
        assert restored.status_code == 200
        assert restored.json()["review_status"] == "draft"
        assert restored.json()["record_version"] == 1
        assert restored.json()["truth"] == payload["truth"]
        image = client.get(
            restored.json()["images"][0]["image_url"],
            headers={"Host": "127.0.0.1:8877"},
        )
        assert image.status_code == 200
        assert hashlib.sha256(image.content).hexdigest() == (
            restored.json()["images"][0]["image_sha256"]
        )

    package_inventory_after = {
        path.relative_to(package_dir).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in package_dir.rglob("*")
        if path.is_file()
    }
    assert package_inventory_after == package_inventory_before


@pytest.mark.parametrize(
    "injected_runtime",
    (
        "daily_execution_backend",
        "browser_runtime",
        "browser_lifecycle",
        "platform_contract_validator",
        "chengfeng_shadow_job_source",
        "settlement_capture_execution_backend",
    ),
)
def test_offline_review_app_rejects_every_active_runtime_injection(
    tmp_path: Path,
    project_root: Path,
    injected_runtime: str,
) -> None:
    package_path = (tmp_path / "offline-review-package").resolve()
    kwargs: dict[str, object] = {
        "data_root": (tmp_path / "offline-review-data").resolve(),
        "project_root": project_root,
        "instance_id": f"loop9-review-{uuid4().hex}",
        "auto_run_jobs": False,
        "stage_delay_seconds": 0,
        "loop9_review_package_path": package_path,
        injected_runtime: object(),
    }

    with pytest.raises(ValueError, match="must run alone"):
        create_app(**kwargs)  # type: ignore[arg-type]
