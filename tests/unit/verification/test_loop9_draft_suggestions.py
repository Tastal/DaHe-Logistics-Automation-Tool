from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from PIL import Image

import dahe.verification.loop9_human_review as human_review
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
from dahe.verification.loop9_draft_suggestions import (
    Loop9DraftSuggestionError,
    build_blank_draft_template,
    load_draft_document,
    persist_new_draft_document,
    seal_independent_draft_suggestions,
    verify_current_locked_source_binding,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _png(index: int) -> bytes:
    output = io.BytesIO()
    Image.new(
        "RGB",
        (2, 2),
        color=(index % 251, (index * 3) % 251, (index * 7) % 251),
    ).save(output, format="PNG")
    return output.getvalue()


def _batch() -> ChengfengShadowBatchManifest:
    items: list[ShadowBatchItem] = []
    for item_index in range(50):
        images: list[ShadowBatchImage] = []
        for offset, slot in enumerate(("loading", "unloading")):
            content = _png((item_index * 2) + offset + 1)
            digest = hashlib.sha256(content).hexdigest()
            images.append(
                ShadowBatchImage(
                    slot=slot,
                    sha256=digest,
                    relative_path=(
                        f"sha256/{digest[:2]}/{digest[2:4]}/{digest}.blob"
                    ),
                    byte_size=len(content),
                    media_type="image/png",
                    perceptual_fingerprint=build_image_fingerprint(content),
                )
            )
        items.append(
            ShadowBatchItem(
                platform_waybill_id_digest=_digest(f"platform:{item_index}"),
                waybill_number_digest=_digest(f"waybill:{item_index}"),
                vehicle_number_digest=_digest(f"vehicle:{item_index}"),
                platform_loading_net=f"{32 + item_index / 100:.2f}",
                platform_unloading_net=f"{31 + item_index / 100:.2f}",
                images=cast(
                    tuple[ShadowBatchImage, ShadowBatchImage],
                    tuple(images),
                ),
            )
        )
    return ChengfengShadowBatchManifest(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        source_build_sha256=_digest("build"),
        contract_canonical_sha256=_digest("contract"),
        contract_file_sha256=_digest("contract-file"),
        contract_selection_sha256=_digest("contract-selection"),
        pipeline_fingerprint=_digest("pipeline"),
        identity_context_sha256=_digest("identity"),
        sources=(
            ShadowBatchSource(
                access_window_id="window-1",
                job_id="job-1",
                capture_id="capture-1",
                scope="current_pending_settlement",
                page_number=1,
                page_size=50,
                checkpoint_sha256=_digest("checkpoint"),
            ),
        ),
        items=tuple(items),
    )


def _selection(
    batch: ChengfengShadowBatchManifest,
) -> FormalShadowSelectionManifest:
    return FormalShadowSelectionManifest(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        source_capture_sha256=_digest("capture"),
        full_history_exclusion_authority_sha256=_digest("exclusions"),
        exclusion_child_index_head_sha256=_digest("exclusion-head"),
        exclusion_source_boundary_sha256=_digest("exclusion-boundary"),
        exclusion_source_inventory_high_watermark=100,
        selection_seed_authority_sha256=_digest("selection-seed"),
        rank_commitment_sha256=_digest("rank"),
        prior_selection_sha256s=(),
        batch_manifest=batch,
    )


def _completed_draft(
    template: dict[str, object],
) -> dict[str, object]:
    result = json.loads(json.dumps(template))
    for suggestion in result["suggestions"]:
        for image in suggestion["images"]:
            image["role"] = image["slot"]
            image["ordinary_net"] = "32.7"
            image["quality_conditions"] = ["rotation_0"]
        suggestion["pair_condition"] = "normal_pair"
    return cast(dict[str, object], result)


def test_blank_template_is_identity_bound_and_contains_no_guessed_truth() -> None:
    batch = _batch()
    selection = _selection(batch)

    template = build_blank_draft_template(
        formal_selection=selection,
        source_batch=batch,
    )

    assert template["kind"] == "loop9_independent_draft_working_template"
    assert template["source_selection_sha256"] == selection.canonical_sha256
    assert template["source_batch_sha256"] == batch.canonical_sha256
    assert template["formal_system_results_accessed"] is False
    suggestions = cast(list[dict[str, object]], template["suggestions"])
    assert len(suggestions) == 50
    assert all(
        suggestion["pair_condition"] == "unknown"
        for suggestion in suggestions
    )
    assert all(
        image["role"] == "unknown"
        and image["ordinary_net"] is None
        and image["quality_conditions"] == []
        for suggestion in suggestions
        for image in cast(list[dict[str, object]], suggestion["images"])
    )
    serialized = json.dumps(template, ensure_ascii=False, sort_keys=True)
    assert batch.items[0].platform_loading_net not in serialized
    assert batch.items[0].platform_unloading_net not in serialized


def test_seal_normalizes_visual_draft_without_claiming_truth() -> None:
    batch = _batch()
    selection = _selection(batch)
    draft = _completed_draft(
        build_blank_draft_template(
            formal_selection=selection,
            source_batch=batch,
        )
    )

    auxiliary = seal_independent_draft_suggestions(
        formal_selection=selection,
        source_batch=batch,
        draft=draft,
    )

    assert auxiliary["kind"] == "loop9_independent_draft_suggestions"
    assert auxiliary["origin"] == "independent_visual_assistance"
    assert auxiliary["formal_system_results_accessed"] is False
    suggestions = cast(list[dict[str, object]], auxiliary["suggestions"])
    assert len(suggestions) == 50
    assert all(
        suggestion["truth_status"] == "unconfirmed_non_truth"
        for suggestion in suggestions
    )
    first_images = cast(list[dict[str, object]], suggestions[0]["images"])
    assert first_images[0]["ordinary_net"] == "32.70"
    parsed = human_review._parse_suggestions(
        auxiliary,
        batch=batch,
    )
    assert len(parsed) == 50


def test_seal_does_not_infer_role_from_upload_slot() -> None:
    batch = _batch()
    selection = _selection(batch)
    draft = build_blank_draft_template(
        formal_selection=selection,
        source_batch=batch,
    )
    for suggestion in cast(list[dict[str, object]], draft["suggestions"]):
        for image in cast(list[dict[str, object]], suggestion["images"]):
            image["quality_conditions"] = ["rotation_0"]
        suggestion["pair_condition"] = "unknown_or_non_ticket"
    auxiliary = seal_independent_draft_suggestions(
        formal_selection=selection,
        source_batch=batch,
        draft=draft,
    )

    for suggestion in cast(
        list[dict[str, object]],
        auxiliary["suggestions"],
    ):
        assert suggestion["pair_condition"] == "unknown_or_non_ticket"
        assert all(
            image["role"] == "unknown"
            for image in cast(
                list[dict[str, object]],
                suggestion["images"],
            )
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda draft: cast(
                list[dict[str, object]],
                draft["suggestions"],
            )[0].update({"pair_condition": "unknown"}),
            "pair condition",
        ),
        (
            lambda draft: cast(
                list[dict[str, object]],
                cast(
                    list[dict[str, object]],
                    draft["suggestions"],
                )[0]["images"],
            )[0].update({"quality_conditions": []}),
            "quality conditions",
        ),
        (
            lambda draft: cast(
                list[dict[str, object]],
                cast(
                    list[dict[str, object]],
                    draft["suggestions"],
                )[0]["images"],
            )[0].update({"image_sha256": "0" * 64}),
            "source binding",
        ),
        (
            lambda draft: cast(
                list[dict[str, object]],
                cast(
                    list[dict[str, object]],
                    draft["suggestions"],
                )[0]["images"],
            )[0].update({"role": "unknown", "ordinary_net": "32.00"}),
            "empty for an unknown role",
        ),
        (
            lambda draft: cast(
                list[dict[str, object]],
                cast(
                    list[dict[str, object]],
                    draft["suggestions"],
                )[0]["images"],
            )[0].update({"reviewer_id": "somebody"}),
            "personnel",
        ),
        (
            lambda draft: draft.update(
                {"formal_system_results_accessed": True}
            ),
            "independently bound",
        ),
    ],
)
def test_seal_rejects_incomplete_tampered_or_identity_bearing_draft(
    mutation: Callable[[dict[str, object]], object],
    message: str,
) -> None:
    batch = _batch()
    selection = _selection(batch)
    draft = _completed_draft(
        build_blank_draft_template(
            formal_selection=selection,
            source_batch=batch,
        )
    )
    mutation(draft)

    with pytest.raises(Loop9DraftSuggestionError, match=message):
        seal_independent_draft_suggestions(
            formal_selection=selection,
            source_batch=batch,
            draft=draft,
        )


def test_source_binding_rejects_another_batch_or_shadow_target() -> None:
    batch = _batch()
    selection = _selection(batch)
    last = batch.items[-1]
    changed = ShadowBatchItem(
        platform_waybill_id_digest=_digest("another-platform"),
        waybill_number_digest=last.waybill_number_digest,
        vehicle_number_digest=last.vehicle_number_digest,
        platform_loading_net=last.platform_loading_net,
        platform_unloading_net=last.platform_unloading_net,
        images=last.images,
    )
    other = ChengfengShadowBatchManifest(
        target_kind=batch.target_kind,
        source_build_sha256=batch.source_build_sha256,
        contract_canonical_sha256=batch.contract_canonical_sha256,
        contract_file_sha256=batch.contract_file_sha256,
        contract_selection_sha256=batch.contract_selection_sha256,
        pipeline_fingerprint=batch.pipeline_fingerprint,
        identity_context_sha256=batch.identity_context_sha256,
        sources=batch.sources,
        items=(*batch.items[:-1], changed),
    )

    with pytest.raises(Loop9DraftSuggestionError, match="formal selection"):
        verify_current_locked_source_binding(
            formal_selection=selection,
            source_batch=other,
        )


def test_persist_is_canonical_atomic_and_refuses_overwrite(
    tmp_path: Path,
) -> None:
    batch = _batch()
    selection = _selection(batch)
    payload = build_blank_draft_template(
        formal_selection=selection,
        source_batch=batch,
    )
    output = (tmp_path / "draft.json").resolve()

    persist_new_draft_document(output=output, payload=payload)

    assert output.read_bytes() == (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(Loop9DraftSuggestionError, match="already exists"):
        persist_new_draft_document(output=output, payload=payload)


def test_draft_loader_rejects_duplicate_fields(tmp_path: Path) -> None:
    source = (tmp_path / "draft.json").resolve()
    source.write_text('{"kind":"first","kind":"second"}', encoding="utf-8")

    with pytest.raises(Loop9DraftSuggestionError, match="duplicate"):
        load_draft_document(source)


def test_draft_loader_rejects_symbolic_link(tmp_path: Path) -> None:
    source = (tmp_path / "source.json").resolve()
    source.write_text("{}", encoding="utf-8")
    link = (tmp_path / "link.json").resolve()
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symbolic links are unavailable on this Windows account")

    with pytest.raises(Loop9DraftSuggestionError, match="unsafe"):
        load_draft_document(link)
