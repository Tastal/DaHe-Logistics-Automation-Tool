from __future__ import annotations

import json
from io import BytesIO

import pytest
from PIL import Image, ImageDraw

from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImageSimilarityContractError,
    NearDuplicateCandidate,
    NearDuplicateDecision,
    ReviewOutcome,
    build_image_fingerprint,
    evaluate_image_similarity_gate,
    find_near_duplicate_candidates,
)


def _ticket_image_bytes(
    *,
    image_format: str = "PNG",
    size: tuple[int, int] = (640, 480),
    quality: int = 90,
) -> bytes:
    image = Image.new("RGB", (640, 480), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((28, 24, 612, 456), outline="black", width=5)
    draw.rectangle((62, 72, 576, 142), fill=(225, 232, 242), outline="black", width=3)
    draw.text((82, 92), "DAHE SCALE TICKET 2026", fill="black")
    draw.line((76, 190, 564, 190), fill="black", width=4)
    draw.line((76, 250, 564, 250), fill="black", width=4)
    draw.line((76, 310, 564, 310), fill="black", width=4)
    draw.rectangle((380, 334, 558, 414), fill=(30, 80, 150))
    draw.text((405, 363), "30.00 t", fill="white")
    if image.size != size:
        image = image.resize(size, Image.Resampling.LANCZOS)
    output = BytesIO()
    save_options: dict[str, object] = {}
    if image_format == "JPEG":
        save_options["quality"] = quality
    image.save(output, format=image_format, **save_options)
    return output.getvalue()


def _center_cropped_ticket_bytes() -> bytes:
    with Image.open(BytesIO(_ticket_image_bytes())) as source:
        width, height = source.size
        left = round(width * 0.12)
        top = round(height * 0.12)
        cropped = source.crop((left, top, width - left, height - top))
        cropped = cropped.resize(source.size, Image.Resampling.LANCZOS)
        output = BytesIO()
        cropped.save(output, format="PNG")
        return output.getvalue()


def _different_image_bytes() -> bytes:
    image = Image.new("RGB", (640, 480), "black")
    draw = ImageDraw.Draw(image)
    for offset in range(0, 640, 32):
        draw.line((offset, 0, 639 - offset, 479), fill="white", width=9)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _distinct_decision(
    candidate: NearDuplicateCandidate,
    *,
    note: str = "人工核对版式和字段后确认不是同一张票",
) -> NearDuplicateDecision:
    return NearDuplicateDecision.create(
        candidate=candidate,
        outcome=ReviewOutcome.DISTINCT,
        operator_id="developer-reviewer",
        note=note,
        decided_at="2026-07-26T09:30:00+08:00",
    )


def test_fingerprint_is_deterministic_versioned_and_content_addressed() -> None:
    content = _ticket_image_bytes()

    first = build_image_fingerprint(content)
    second = build_image_fingerprint(content)

    assert first.algorithm_version == ALGORITHM_VERSION
    assert first.content_sha256 == second.content_sha256
    assert first.canonical_sha256 == second.canonical_sha256
    assert first.view_hashes == second.view_hashes
    assert len(first.canonical_sha256) == 64


def test_fingerprint_record_roundtrip_rejects_payload_or_integrity_tampering() -> None:
    fingerprint = build_image_fingerprint(_ticket_image_bytes())
    record = fingerprint.to_record()

    restored = type(fingerprint).from_record(record)

    assert restored == fingerprint

    changed_payload = json.loads(json.dumps(record))
    changed_payload["width"] = fingerprint.width + 1
    with pytest.raises(ImageSimilarityContractError, match="integrity"):
        type(fingerprint).from_record(changed_payload)

    changed_integrity = dict(record)
    changed_integrity["canonical_sha256"] = "0" * 64
    with pytest.raises(ImageSimilarityContractError, match="integrity"):
        type(fingerprint).from_record(changed_integrity)


def test_reencoded_and_resized_image_produces_a_manual_review_candidate() -> None:
    source = build_image_fingerprint(_ticket_image_bytes())
    probe = build_image_fingerprint(
        _ticket_image_bytes(image_format="JPEG", size=(320, 240), quality=52)
    )

    candidates = find_near_duplicate_candidates(probe=probe, inventory=(source,))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.candidate_id
    assert candidate.algorithm_version == ALGORITHM_VERSION
    assert candidate.probe_image_sha256 == probe.content_sha256
    assert candidate.inventory_image_sha256 == source.content_sha256

    reversed_candidate = find_near_duplicate_candidates(
        probe=source,
        inventory=(probe,),
    )[0]
    assert reversed_candidate.candidate_id == candidate.candidate_id
    assert reversed_candidate.evidence_sha256 == candidate.evidence_sha256


def test_reasonable_center_crop_produces_a_manual_review_candidate() -> None:
    source = build_image_fingerprint(_ticket_image_bytes())
    probe = build_image_fingerprint(_center_cropped_ticket_bytes())

    candidates = find_near_duplicate_candidates(probe=probe, inventory=(source,))

    assert len(candidates) == 1
    assert candidates[0].distance_numerator <= candidates[0].distance_limit


def test_empty_inventory_blocks_instead_of_treating_probe_as_safe() -> None:
    probe = build_image_fingerprint(_ticket_image_bytes())

    result = evaluate_image_similarity_gate(
        probe=probe,
        inventory=(),
        decisions=(),
    )

    assert result.passed is False
    assert result.blocked_reason == "inventory_empty"
    assert result.candidates == ()


def test_unreviewed_candidate_blocks_and_manual_duplicate_stays_blocked() -> None:
    source = build_image_fingerprint(_ticket_image_bytes())
    probe = build_image_fingerprint(_ticket_image_bytes(image_format="JPEG", quality=60))

    unreviewed = evaluate_image_similarity_gate(
        probe=probe,
        inventory=(source,),
        decisions=(),
    )
    assert unreviewed.passed is False
    assert unreviewed.blocked_reason == "unresolved_candidates"

    duplicate = NearDuplicateDecision.create(
        candidate=unreviewed.candidates[0],
        outcome=ReviewOutcome.DUPLICATE,
        operator_id="developer-reviewer",
        note="确认是同一张票的压缩副本",
        decided_at="2026-07-26T09:31:00+08:00",
    )
    reviewed = evaluate_image_similarity_gate(
        probe=probe,
        inventory=(source,),
        decisions=(duplicate,),
    )
    assert reviewed.passed is False
    assert reviewed.blocked_reason == "duplicate_confirmed"
    assert reviewed.decision_set_sha256 is not None


def test_complete_distinct_decision_can_release_candidate_and_is_hashed() -> None:
    source = build_image_fingerprint(_ticket_image_bytes())
    probe = build_image_fingerprint(_ticket_image_bytes(image_format="JPEG", quality=60))
    candidate = find_near_duplicate_candidates(
        probe=probe,
        inventory=(source,),
    )[0]
    decision = _distinct_decision(candidate)

    result = evaluate_image_similarity_gate(
        probe=probe,
        inventory=(source,),
        decisions=(decision,),
    )

    assert result.passed is True
    assert result.blocked_reason is None
    assert result.decision_set_sha256 is not None
    assert decision.canonical_sha256 in result.decision_sha256s

    changed_note = _distinct_decision(candidate, note="另一位人员复核后确认版式不同")
    assert changed_note.canonical_sha256 != decision.canonical_sha256
    changed_result = evaluate_image_similarity_gate(
        probe=probe,
        inventory=(source,),
        decisions=(changed_note,),
    )
    assert changed_result.canonical_sha256 != result.canonical_sha256


@pytest.mark.parametrize(
    ("operator_id", "note", "decided_at", "message"),
    [
        ("", "人工确认不同", "2026-07-26T09:30:00+08:00", "operator"),
        ("developer", "", "2026-07-26T09:30:00+08:00", "note"),
        ("developer", "人工确认不同", "2026-07-26T09:30:00", "timezone"),
    ],
)
def test_distinct_decision_requires_operator_note_and_timezone_aware_time(
    operator_id: str,
    note: str,
    decided_at: str,
    message: str,
) -> None:
    source = build_image_fingerprint(_ticket_image_bytes())
    probe = build_image_fingerprint(_ticket_image_bytes(image_format="JPEG", quality=60))
    candidate = find_near_duplicate_candidates(
        probe=probe,
        inventory=(source,),
    )[0]

    with pytest.raises(ImageSimilarityContractError, match=message):
        NearDuplicateDecision.create(
            candidate=candidate,
            outcome=ReviewOutcome.DISTINCT,
            operator_id=operator_id,
            note=note,
            decided_at=decided_at,
        )


def test_tampered_persisted_decision_fails_closed() -> None:
    source = build_image_fingerprint(_ticket_image_bytes())
    probe = build_image_fingerprint(_ticket_image_bytes(image_format="JPEG", quality=60))
    candidate = find_near_duplicate_candidates(
        probe=probe,
        inventory=(source,),
    )[0]
    decision = _distinct_decision(candidate)
    record = decision.to_record()
    record["note"] = "tampered after review"

    with pytest.raises(ImageSimilarityContractError, match="integrity"):
        NearDuplicateDecision.from_record(record)


def test_unknown_or_stale_decision_cannot_release_current_candidates() -> None:
    source = build_image_fingerprint(_ticket_image_bytes())
    probe = build_image_fingerprint(_ticket_image_bytes(image_format="JPEG", quality=60))
    unrelated = build_image_fingerprint(_center_cropped_ticket_bytes())
    stale_candidate = find_near_duplicate_candidates(
        probe=unrelated,
        inventory=(source,),
    )[0]
    stale_decision = _distinct_decision(stale_candidate)

    with pytest.raises(ImageSimilarityContractError, match="current candidate"):
        evaluate_image_similarity_gate(
            probe=probe,
            inventory=(source,),
            decisions=(stale_decision,),
        )


def test_no_candidate_after_nonempty_inventory_can_pass_without_a_decision() -> None:
    source = build_image_fingerprint(_different_image_bytes())
    probe = build_image_fingerprint(_ticket_image_bytes())

    result = evaluate_image_similarity_gate(
        probe=probe,
        inventory=(source,),
        decisions=(),
    )

    assert result.passed is True
    assert result.blocked_reason is None
    assert result.candidates == ()
    assert result.decision_set_sha256 is not None


def test_corrupt_or_oversized_images_fail_closed() -> None:
    with pytest.raises(ImageSimilarityContractError, match="decode"):
        build_image_fingerprint(b"not an image")

    oversized = _ticket_image_bytes(size=(11, 11))
    with pytest.raises(ImageSimilarityContractError, match="pixel limit"):
        build_image_fingerprint(oversized, max_pixels=100)
