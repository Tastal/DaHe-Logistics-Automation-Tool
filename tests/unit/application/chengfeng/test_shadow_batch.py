from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from io import BytesIO

import pytest
from PIL import Image

from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    PersistedTicketImage,
)
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchContractError,
    ChengfengShadowBatchManifest,
    ShadowBatchTargetKind,
    ShadowCaptureBinding,
    build_chengfeng_shadow_batch,
    chengfeng_shadow_identity_context_sha256,
    chengfeng_shadow_identity_digest,
)
from dahe.ports.chengfeng import (
    ChengfengStage,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)

BUILD_SHA = "a" * 64
CONTRACT_CANONICAL_SHA = "b" * 64
CONTRACT_FILE_SHA = "c" * 64
CONTRACT_SELECTION_SHA = "d" * 64
PIPELINE_SHA = "e" * 64
IDENTITY_SALT = b"loop9-test-identity-salt-32-bytes"
IDENTITY_NAMESPACE = "chengfeng-production-account-v1"


class MemorySafeReader:
    def __init__(self, content_by_path: dict[str, bytes]) -> None:
        self.content_by_path = content_by_path
        self.calls: list[tuple[str, str]] = []

    def read_verified_image(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
    ) -> bytes:
        self.calls.append((relative_path, expected_sha256))
        return self.content_by_path[relative_path]


def _png(seed: int) -> bytes:
    image = Image.new(
        "RGB",
        (8, 8),
        color=(seed % 251, (seed * 7) % 251, (seed * 17) % 251),
    )
    image.putpixel((seed % 8, (seed // 8) % 8), (255, 255, seed % 251))
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _stored_image(
    *,
    ticket_ref: str,
    content: bytes,
) -> PersistedTicketImage:
    sha256 = hashlib.sha256(content).hexdigest()
    return PersistedTicketImage(
        ticket_ref=ticket_ref,
        sha256=sha256,
        relative_path=f"sha256/{sha256[:2]}/{sha256[2:4]}/{sha256}.blob",
        byte_size=len(content),
        media_type="image/png",
    )


def _binding(
    *,
    count: int,
    start: int = 0,
    page_number: int = 1,
    page_size: int | None = None,
    total: int | None = None,
    job_id: str = "source-job-001",
    access_window_id: str = "access-window-001",
    build_sha256: str = BUILD_SHA,
    contract_canonical_sha256: str = CONTRACT_CANONICAL_SHA,
    contract_file_sha256: str = CONTRACT_FILE_SHA,
    contract_selection_sha256: str = CONTRACT_SELECTION_SHA,
) -> tuple[ShadowCaptureBinding, dict[str, bytes]]:
    summaries: list[WaybillSummary] = []
    details: list[WaybillDetail] = []
    images: dict[str, PersistedTicketImage] = {}
    content_by_path: dict[str, bytes] = {}
    for offset in range(count):
        index = start + offset
        platform_id = f"platform-{index:03d}"
        waybill_number = f"CF-{202607290000 + index}"
        vehicle_number = f"陕K{index:05d}"
        summaries.append(
            WaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=vehicle_number,
            )
        )
        tickets: list[TicketReference] = []
        for slot, seed in (("loading", index * 2), ("unloading", index * 2 + 1)):
            ticket_ref = f"ticket-{slot}-{index:03d}"
            content = _png(seed)
            image = _stored_image(ticket_ref=ticket_ref, content=content)
            tickets.append(
                TicketReference(
                    slot=slot,
                    ticket_ref=ticket_ref,
                    media_type="application/octet-stream",
                )
            )
            images[ticket_ref] = image
            content_by_path[image.relative_path] = content
        details.append(
            WaybillDetail(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=vehicle_number,
                loading_net=f"{30 + index % 10}.10",
                unloading_net=f"{29 + index % 10}.90",
                tickets=tuple(tickets),
            )
        )
    effective_page_size = page_size or count
    checkpoint = DurableCaptureCheckpoint(
        capture_id=f"capture-{job_id}-{page_number}",
        job_id=job_id,
        scope="current",
        page_number=page_number,
        page_size=effective_page_size,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        revision=4 + (count * 3),
        completed_list=True,
        completed_detail_ids=tuple(
            detail.platform_waybill_id for detail in details
        ),
        ticket_images=images,
        page=WaybillPage(
            page_number=page_number,
            page_size=effective_page_size,
            total=count if total is None else total,
            items=tuple(summaries),
        ),
        details=tuple(details),
    )
    return (
        ShadowCaptureBinding(
            checkpoint=checkpoint,
            access_window_id=access_window_id,
            source_build_sha256=build_sha256,
            contract_canonical_sha256=contract_canonical_sha256,
            contract_file_sha256=contract_file_sha256,
            contract_selection_sha256=contract_selection_sha256,
        ),
        content_by_path,
    )


def _build(
    *bindings: ShadowCaptureBinding,
    content_by_path: dict[str, bytes],
    target_kind: ShadowBatchTargetKind = ShadowBatchTargetKind.REAL_SHADOW_30,
    identity_salt: bytes = IDENTITY_SALT,
):
    reader = MemorySafeReader(content_by_path)
    result = build_chengfeng_shadow_batch(
        bindings=bindings,
        target_kind=target_kind,
        pipeline_fingerprint=PIPELINE_SHA,
        identity_salt=identity_salt,
        identity_namespace=IDENTITY_NAMESPACE,
        image_reader=reader,
    )
    return result, reader


def test_builds_strict_real_shadow_manifest_and_local_audit_job() -> None:
    binding, content = _binding(count=30)

    result, reader = _build(binding, content_by_path=content)

    manifest = result.manifest
    assert manifest.target_kind is ShadowBatchTargetKind.REAL_SHADOW_30
    assert manifest.source_kind == "chengfeng_shadow"
    assert manifest.source_build_sha256 == BUILD_SHA
    assert manifest.contract_canonical_sha256 == CONTRACT_CANONICAL_SHA
    assert manifest.contract_file_sha256 == CONTRACT_FILE_SHA
    assert manifest.contract_selection_sha256 == CONTRACT_SELECTION_SHA
    assert manifest.pipeline_fingerprint == PIPELINE_SHA
    assert len(manifest.items) == 30
    assert len(reader.calls) == 60
    assert {
        (source.access_window_id, source.job_id, source.capture_id)
        for source in manifest.sources
    } == {("access-window-001", "source-job-001", "capture-source-job-001-1")}
    first = manifest.items[0]
    assert first.platform_loading_net.endswith(".10")
    assert first.platform_unloading_net.endswith(".90")
    assert {image.slot for image in first.images} == {"loading", "unloading"}
    assert all(
        image.perceptual_fingerprint.content_sha256 == image.sha256
        for item in manifest.items
        for image in item.images
    )

    spec = result.scheduled_job
    assert spec.job_kind == "business"
    assert spec.task_type == "audit"
    assert spec.ocr_execution_mode == "local"
    assert spec.pipeline_fingerprint == PIPELINE_SHA
    assert len(spec.items) == 30
    assert all(item.expected_outcome is None for item in spec.items)
    assert all(item.vehicle_number is None for item in spec.items)
    assert {
        item.loading_image_sha256 for item in spec.items
    } == {item.images[0].sha256 for item in manifest.items}
    assert spec.fixture_id.endswith(manifest.canonical_sha256)
    assert spec.conflict_key.endswith(manifest.canonical_sha256)


def test_current_locked_set_requires_exactly_fifty_items() -> None:
    binding, content = _binding(count=50)

    result, _ = _build(
        binding,
        content_by_path=content,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
    )

    assert len(result.manifest.items) == 50
    assert len(result.scheduled_job.items) == 50


def test_manifest_is_canonical_replayable_and_contains_no_raw_identity_or_actor() -> None:
    binding, content = _binding(count=30)
    first, _ = _build(binding, content_by_path=content)
    second, _ = _build(binding, content_by_path=content)

    payload = first.manifest.to_payload()
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert first.manifest.canonical_sha256 == second.manifest.canonical_sha256
    assert (
        ChengfengShadowBatchManifest.from_payload(payload).canonical_sha256
        == first.manifest.canonical_sha256
    )
    for forbidden in (
        "platform-000",
        "CF-202607290000",
        "陕K00000",
        IDENTITY_NAMESPACE,
        "actor",
        "reviewer",
        "operator",
    ):
        assert forbidden not in encoded


def test_identity_salt_changes_identity_and_manifest() -> None:
    binding, content = _binding(count=30)
    first, _ = _build(binding, content_by_path=content)
    second, _ = _build(
        binding,
        content_by_path=content,
        identity_salt=b"a-different-explicit-salt-value",
    )

    assert (
        first.manifest.items[0].platform_waybill_id_digest
        != second.manifest.items[0].platform_waybill_id_digest
    )
    assert first.manifest.canonical_sha256 != second.manifest.canonical_sha256


def test_public_identity_helpers_match_the_sealed_manifest() -> None:
    binding, content = _binding(count=30)
    result, _ = _build(binding, content_by_path=content)

    assert result.manifest.identity_context_sha256 == (
        chengfeng_shadow_identity_context_sha256(
            salt=IDENTITY_SALT,
            namespace=IDENTITY_NAMESPACE,
        )
    )
    assert result.manifest.items[0].platform_waybill_id_digest == (
        chengfeng_shadow_identity_digest(
            salt=IDENTITY_SALT,
            namespace=IDENTITY_NAMESPACE,
            field_name="platform_waybill_id",
            value="platform-000",
        )
    )


def test_manifest_parser_rejects_extra_identity_fields_and_tampering() -> None:
    binding, content = _binding(count=30)
    result, _ = _build(binding, content_by_path=content)
    with_actor = result.manifest.to_payload()
    with_actor["actor_id"] = "not-allowed"
    with pytest.raises(ChengfengShadowBatchContractError, match="contract"):
        ChengfengShadowBatchManifest.from_payload(with_actor)

    changed_weight = result.manifest.to_payload()
    items = changed_weight["items"]
    assert isinstance(items, list)
    first_item = items[0]
    assert isinstance(first_item, dict)
    first_item["platform_loading_net"] = "99.99"
    with pytest.raises(ChengfengShadowBatchContractError, match="integrity"):
        ChengfengShadowBatchManifest.from_payload(changed_weight)


def test_merges_complete_paginated_checkpoints_deterministically() -> None:
    first, first_content = _binding(
        count=15,
        start=0,
        page_number=1,
        page_size=15,
        total=30,
    )
    second, second_content = _binding(
        count=15,
        start=15,
        page_number=2,
        page_size=15,
        total=30,
    )
    content = {**first_content, **second_content}

    ordered, _ = _build(first, second, content_by_path=content)
    reversed_result, _ = _build(second, first, content_by_path=content)

    assert ordered.manifest.canonical_sha256 == reversed_result.manifest.canonical_sha256
    assert ordered.scheduled_job == reversed_result.scheduled_job


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("source_build_sha256", "f" * 64, "build"),
        ("contract_canonical_sha256", "f" * 64, "contract"),
        ("contract_file_sha256", "f" * 64, "contract"),
        ("contract_selection_sha256", "f" * 64, "contract"),
    ],
)
def test_rejects_cross_capture_build_or_contract_mismatch(
    field: str,
    replacement: str,
    message: str,
) -> None:
    first, first_content = _binding(
        count=15,
        start=0,
        page_number=1,
        page_size=15,
        total=30,
    )
    second, second_content = _binding(
        count=15,
        start=15,
        page_number=2,
        page_size=15,
        total=30,
    )
    second = replace(second, **{field: replacement})

    with pytest.raises(ChengfengShadowBatchContractError, match=message):
        _build(
            first,
            second,
            content_by_path={**first_content, **second_content},
        )


@pytest.mark.parametrize(
    ("target_kind", "count"),
    [
        (ShadowBatchTargetKind.REAL_SHADOW_30, 29),
        (ShadowBatchTargetKind.CURRENT_LOCKED_50, 49),
    ],
)
def test_rejects_cross_kind_or_wrong_exact_count(
    target_kind: ShadowBatchTargetKind,
    count: int,
) -> None:
    binding, content = _binding(count=count)

    with pytest.raises(ChengfengShadowBatchContractError, match="exactly"):
        _build(
            binding,
            content_by_path=content,
            target_kind=target_kind,
        )


def test_rejects_partial_page_coverage() -> None:
    binding, content = _binding(
        count=30,
        page_number=1,
        page_size=30,
        total=31,
    )

    with pytest.raises(ChengfengShadowBatchContractError, match="pagination"):
        _build(binding, content_by_path=content)


def test_rejects_checkpoint_that_has_not_reached_complete_image_stage() -> None:
    binding, content = _binding(count=30)
    checkpoint = replace(
        binding.checkpoint,
        stage=ChengfengStage.DETAIL_QUERY,
    )

    with pytest.raises(ChengfengShadowBatchContractError, match="complete image"):
        _build(
            replace(binding, checkpoint=checkpoint),
            content_by_path=content,
        )


def test_rejects_non_settlement_capture_scope() -> None:
    binding, content = _binding(count=30)
    checkpoint = replace(binding.checkpoint, scope="other-scope")

    with pytest.raises(ChengfengShadowBatchContractError, match="scope"):
        _build(
            replace(binding, checkpoint=checkpoint),
            content_by_path=content,
        )


def test_rejects_missing_detail_and_missing_image() -> None:
    binding, content = _binding(count=30)
    checkpoint = binding.checkpoint
    omitted_ticket_refs = {
        ticket.ticket_ref for ticket in checkpoint.details[-1].tickets
    }
    missing_detail = replace(
        checkpoint,
        completed_detail_ids=checkpoint.completed_detail_ids[:-1],
        details=checkpoint.details[:-1],
        ticket_images={
            ticket_ref: image
            for ticket_ref, image in checkpoint.ticket_images.items()
            if ticket_ref not in omitted_ticket_refs
        },
    )
    with pytest.raises(ChengfengShadowBatchContractError, match="one detail"):
        _build(
            replace(binding, checkpoint=missing_detail),
            content_by_path=content,
        )

    missing_image_map = dict(checkpoint.ticket_images)
    missing_image_map.pop(next(iter(missing_image_map)))
    missing_image = replace(checkpoint, ticket_images=missing_image_map)
    with pytest.raises(ChengfengShadowBatchContractError, match="image"):
        _build(
            replace(binding, checkpoint=missing_image),
            content_by_path=content,
        )


def test_rejects_wrong_ticket_slots_and_duplicate_image_sha() -> None:
    binding, content = _binding(count=30)
    checkpoint = binding.checkpoint
    first_detail = checkpoint.details[0]
    wrong_slots = replace(
        first_detail,
        tickets=(
            replace(first_detail.tickets[0], slot="loading"),
            replace(first_detail.tickets[1], slot="loading"),
        ),
    )
    checkpoint_wrong_slots = replace(
        checkpoint,
        details=(wrong_slots, *checkpoint.details[1:]),
    )
    with pytest.raises(ChengfengShadowBatchContractError, match=r"loading.*unloading"):
        _build(
            replace(binding, checkpoint=checkpoint_wrong_slots),
            content_by_path=content,
        )

    image_map = dict(checkpoint.ticket_images)
    refs = tuple(image_map)
    first_image = image_map[refs[0]]
    second_image = image_map[refs[1]]
    image_map[refs[1]] = replace(
        second_image,
        sha256=first_image.sha256,
        relative_path=first_image.relative_path,
        byte_size=first_image.byte_size,
    )
    duplicate_image = replace(checkpoint, ticket_images=image_map)
    duplicate_content = dict(content)
    duplicate_content[first_image.relative_path] = content[first_image.relative_path]
    with pytest.raises(ChengfengShadowBatchContractError, match="duplicate image"):
        _build(
            replace(binding, checkpoint=duplicate_image),
            content_by_path=duplicate_content,
        )


def test_rejects_duplicate_platform_or_waybill_identity_across_captures() -> None:
    first, first_content = _binding(
        count=15,
        start=0,
        page_number=1,
        page_size=15,
        total=15,
        job_id="source-job-a",
        access_window_id="access-a",
    )
    second, second_content = _binding(
        count=15,
        start=0,
        page_number=1,
        page_size=15,
        total=15,
        job_id="source-job-b",
        access_window_id="access-b",
    )

    with pytest.raises(
        ChengfengShadowBatchContractError,
        match=r"duplicate.*identity",
    ):
        _build(
            first,
            second,
            content_by_path={**first_content, **second_content},
        )


@pytest.mark.parametrize("weight", ["", " 30.00", "NaN", "Infinity", "-1", "3e1"])
def test_rejects_malformed_platform_weights(weight: str) -> None:
    binding, content = _binding(count=30)
    checkpoint = binding.checkpoint
    changed = replace(checkpoint.details[0], loading_net=weight)
    malformed = replace(
        checkpoint,
        details=(changed, *checkpoint.details[1:]),
    )

    with pytest.raises(ChengfengShadowBatchContractError, match="weight"):
        _build(
            replace(binding, checkpoint=malformed),
            content_by_path=content,
        )


def test_rejects_malformed_content_addressed_path_even_if_checkpoint_is_tampered() -> None:
    binding, content = _binding(count=30)
    checkpoint = binding.checkpoint
    images = dict(checkpoint.ticket_images)
    ticket_ref = next(iter(images))
    tampered = images[ticket_ref]
    object.__setattr__(tampered, "relative_path", "../outside.png")

    with pytest.raises(ChengfengShadowBatchContractError, match="content-addressed"):
        _build(binding, content_by_path=content)


def test_rejects_safe_reader_bytes_that_do_not_match_persisted_hash() -> None:
    binding, content = _binding(count=30)
    first_path = next(iter(content))
    content[first_path] = _png(9999)

    with pytest.raises(ChengfengShadowBatchContractError, match="hash"):
        _build(binding, content_by_path=content)
