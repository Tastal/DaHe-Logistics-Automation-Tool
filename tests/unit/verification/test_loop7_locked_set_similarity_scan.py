from __future__ import annotations

import hashlib
import json
import random
from copy import deepcopy
from dataclasses import replace
from functools import lru_cache
from io import BytesIO

import pytest
from PIL import Image, ImageDraw

from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
    NearDuplicateDecision,
    ReviewOutcome,
    build_image_fingerprint,
)
from dahe.verification.locked_set_acceptance import _near_duplicate_contract
from dahe.verification.locked_set_similarity_scan import (
    LockedSetSimilarityScanError,
    PersistedFingerprintRecord,
    bind_similarity_decisions,
    recompute_scan_fingerprint,
    scan_locked_set_similarity,
)

DATASET_ID = "unseen-locked-set-001"
MANIFEST_SHA256 = hashlib.sha256(b"locked manifest").hexdigest()
SNAPSHOT_SHA256 = hashlib.sha256(b"authoritative snapshot").hexdigest()


@lru_cache(maxsize=256)
def _noise_fingerprint(seed: int) -> ImagePerceptualFingerprint:
    random_bytes = random.Random(seed).randbytes(64 * 64)
    image = Image.frombytes("L", (64, 64), random_bytes)
    output = BytesIO()
    image.save(output, format="PNG")
    return build_image_fingerprint(output.getvalue())


def _ticket_bytes(
    *,
    image_format: str = "PNG",
    size: tuple[int, int] = (320, 240),
) -> bytes:
    image = Image.new("RGB", (640, 480), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((20, 20, 620, 460), outline="black", width=7)
    draw.rectangle((80, 70, 560, 150), fill=(220, 230, 245), outline="black", width=4)
    draw.text((100, 98), "LOCKED SET TICKET", fill="black")
    draw.line((90, 210, 550, 210), fill="black", width=5)
    draw.line((90, 290, 550, 290), fill="black", width=5)
    draw.rectangle((360, 335, 550, 415), fill=(25, 75, 145))
    if image.size != size:
        image = image.resize(size, Image.Resampling.LANCZOS)
    output = BytesIO()
    options: dict[str, object] = {}
    if image_format == "JPEG":
        options["quality"] = 55
    image.save(output, format=image_format, **options)
    return output.getvalue()


def _probes() -> tuple[ImagePerceptualFingerprint, ...]:
    return tuple(_noise_fingerprint(index) for index in range(100))


def _inventory(
    *fingerprints: ImagePerceptualFingerprint,
) -> tuple[PersistedFingerprintRecord, ...]:
    if fingerprints:
        return tuple(PersistedFingerprintRecord.create(fingerprint) for fingerprint in fingerprints)
    return (
        PersistedFingerprintRecord.create(_noise_fingerprint(1001)),
        PersistedFingerprintRecord.create(_noise_fingerprint(1002)),
    )


def _scan(
    probes: tuple[ImagePerceptualFingerprint, ...],
    inventory: tuple[PersistedFingerprintRecord, ...],
):
    return scan_locked_set_similarity(
        dataset_id=DATASET_ID,
        manifest_sha256=MANIFEST_SHA256,
        exclusion_snapshot_sha256=SNAPSHOT_SHA256,
        probes=probes,
        persisted_inventory=inventory,
    )


def test_scan_is_deterministic_complete_and_acceptance_schema_compatible() -> None:
    probes = _probes()
    inventory = _inventory()

    first = _scan(probes, inventory)
    second = _scan(tuple(reversed(probes)), tuple(reversed(inventory)))
    payload = first.to_payload()

    assert payload == second.to_payload()
    assert payload["schema_version"] == 1
    assert payload["dataset_id"] == DATASET_ID
    assert payload["manifest_sha256"] == MANIFEST_SHA256
    assert payload["exclusion_snapshot_sha256"] == SNAPSHOT_SHA256
    assert payload["detector_fingerprint"]
    assert payload["locked_image_count"] == 100
    assert payload["excluded_image_count"] == 2
    assert payload["completed"] is True
    assert payload["candidates"] == []
    assert recompute_scan_fingerprint(payload) == payload["scan_fingerprint"]
    gate = _near_duplicate_contract(
        payload,
        [],
        dataset_id=DATASET_ID,
        manifest_sha256=MANIFEST_SHA256,
        exclusion_snapshot_sha256=SNAPSHOT_SHA256,
        image_hashes={probe.content_sha256 for probe in probes},
    )
    assert gate["passed"] is True


def test_scan_finds_probe_to_inventory_candidate_without_calling_it_duplicate() -> None:
    source = build_image_fingerprint(_ticket_bytes())
    probe = build_image_fingerprint(_ticket_bytes(image_format="JPEG"))
    probes = (probe, *tuple(_noise_fingerprint(index) for index in range(1, 100)))

    scan = _scan(probes, _inventory(source))
    payload_candidates = scan.to_payload()["candidates"]

    assert isinstance(payload_candidates, list)
    cross_set = [
        candidate
        for candidate in payload_candidates
        if candidate["comparison_scope"] == "probe_to_inventory"
    ]
    assert len(cross_set) == 1
    assert cross_set[0]["locked_image_sha256"] == probe.content_sha256
    assert cross_set[0]["excluded_image_sha256"] == source.content_sha256
    assert cross_set[0]["detector"] == ALGORITHM_VERSION
    assert cross_set[0]["similarity"] <= "1.0000"
    assert scan.review_candidates[0].candidate_id == cross_set[0]["candidate_id"]


def test_scan_also_finds_near_duplicates_inside_the_locked_set() -> None:
    original = build_image_fingerprint(_ticket_bytes())
    reencoded = build_image_fingerprint(_ticket_bytes(image_format="JPEG"))
    probes = (
        original,
        reencoded,
        *tuple(_noise_fingerprint(index) for index in range(2, 100)),
    )

    scan = _scan(probes, _inventory())
    payload_candidates = scan.to_payload()["candidates"]

    assert isinstance(payload_candidates, list)
    internal = [
        candidate
        for candidate in payload_candidates
        if candidate["comparison_scope"] == "probe_to_probe"
    ]
    assert len(internal) == 1
    assert {
        internal[0]["locked_image_sha256"],
        internal[0]["excluded_image_sha256"],
    } == {original.content_sha256, reencoded.content_sha256}


@pytest.mark.parametrize("probe_count", [0, 1, 99, 101])
def test_scan_requires_exactly_100_code_owned_probes(probe_count: int) -> None:
    probes = (
        _probes()[:probe_count] if probe_count <= 100 else (*_probes(), _noise_fingerprint(2001))
    )
    with pytest.raises(LockedSetSimilarityScanError, match="100"):
        _scan(tuple(probes), _inventory())


def test_duplicate_probe_or_inventory_identity_fails_closed() -> None:
    probes = list(_probes())
    probes[-1] = probes[0]
    with pytest.raises(LockedSetSimilarityScanError, match="probe identities"):
        _scan(tuple(probes), _inventory())

    record = PersistedFingerprintRecord.create(_noise_fingerprint(1001))
    with pytest.raises(LockedSetSimilarityScanError, match="inventory identities"):
        _scan(_probes(), (record, record))


def test_proven_empty_inventory_still_scans_all_probes_internally() -> None:
    scan = _scan(_probes(), ())

    assert scan.to_payload()["excluded_image_count"] == 0
    assert scan.to_payload()["locked_image_count"] == 100
    assert scan.to_payload()["completed"] is True


def test_missing_probe_or_inventory_collection_fails_closed() -> None:
    with pytest.raises(LockedSetSimilarityScanError, match="probe collection"):
        scan_locked_set_similarity(
            dataset_id=DATASET_ID,
            manifest_sha256=MANIFEST_SHA256,
            exclusion_snapshot_sha256=SNAPSHOT_SHA256,
            probes=None,  # type: ignore[arg-type]
            persisted_inventory=_inventory(),
        )
    with pytest.raises(LockedSetSimilarityScanError, match="inventory collection"):
        scan_locked_set_similarity(
            dataset_id=DATASET_ID,
            manifest_sha256=MANIFEST_SHA256,
            exclusion_snapshot_sha256=SNAPSHOT_SHA256,
            probes=_probes(),
            persisted_inventory=None,  # type: ignore[arg-type]
        )


def test_algorithm_mismatch_fails_closed() -> None:

    mismatched = deepcopy(_noise_fingerprint(0))
    object.__setattr__(mismatched, "algorithm_version", "other.detector.v1")
    probes = (mismatched, *_probes()[1:])
    with pytest.raises(
        (ImageSimilarityContractError, LockedSetSimilarityScanError),
        match=r"algorithm|integrity",
    ):
        _scan(probes, _inventory())


def test_persisted_fingerprint_json_or_hash_tampering_fails_closed() -> None:
    record = PersistedFingerprintRecord.create(_noise_fingerprint(1001))
    changed_json = record.fingerprint_json.replace(
        '"width":64',
        '"width":65',
    )
    with pytest.raises(LockedSetSimilarityScanError, match="record hash"):
        _scan(
            _probes(),
            (replace(record, fingerprint_json=changed_json),),
        )

    changed_hash = replace(record, fingerprint_json_sha256="0" * 64)
    with pytest.raises(LockedSetSimilarityScanError, match="record hash"):
        _scan(_probes(), (changed_hash,))

    changed_record = json.loads(record.fingerprint_json)
    changed_record["width"] = 65
    changed_json_with_hash = json.dumps(
        changed_record,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    internally_tampered = replace(
        record,
        fingerprint_json=changed_json_with_hash,
        fingerprint_json_sha256=hashlib.sha256(changed_json_with_hash.encode("utf-8")).hexdigest(),
    )
    with pytest.raises(LockedSetSimilarityScanError, match="integrity"):
        _scan(_probes(), (internally_tampered,))


def test_complete_existing_decisions_bind_to_scan_without_creating_candidates() -> None:
    source = build_image_fingerprint(_ticket_bytes())
    probe = build_image_fingerprint(_ticket_bytes(image_format="JPEG"))
    probes = (probe, *tuple(_noise_fingerprint(index) for index in range(1, 100)))
    scan = _scan(probes, _inventory(source))
    assert len(scan.review_candidates) == 1
    decision = NearDuplicateDecision.create(
        candidate=scan.review_candidates[0],
        outcome=ReviewOutcome.DISTINCT,
        operator_id="independent-reviewer",
        note="人工对照原票后确认不是同一业务图片",
        decided_at="2026-07-26T10:30:00+08:00",
    )

    records = bind_similarity_decisions(scan=scan, decisions=(decision,))

    assert records == [
        {
            "candidate_id": decision.candidate_id,
            "scan_fingerprint": scan.scan_fingerprint,
            "verdict": "distinct",
            "reviewer_id": "independent-reviewer",
            "decided_at": "2026-07-26T10:30:00+08:00",
            "reason": "人工对照原票后确认不是同一业务图片",
            "decision_evidence_sha256": decision.canonical_sha256,
        }
    ]
    gate = _near_duplicate_contract(
        scan.to_payload(),
        records,
        dataset_id=DATASET_ID,
        manifest_sha256=MANIFEST_SHA256,
        exclusion_snapshot_sha256=SNAPSHOT_SHA256,
        image_hashes={candidate.content_sha256 for candidate in probes},
    )
    assert gate == {
        "candidate_count": 1,
        "distinct_count": 1,
        "duplicate_count": 0,
        "undecided_count": 0,
        "passed": True,
    }


def test_missing_or_foreign_manual_decision_cannot_release_scan_candidates() -> None:
    source = build_image_fingerprint(_ticket_bytes())
    probe = build_image_fingerprint(_ticket_bytes(image_format="JPEG"))
    probes = (probe, *tuple(_noise_fingerprint(index) for index in range(1, 100)))
    scan = _scan(probes, _inventory(source))

    with pytest.raises(LockedSetSimilarityScanError, match="complete"):
        bind_similarity_decisions(scan=scan, decisions=())

    foreign_scan = _scan(
        (
            build_image_fingerprint(_ticket_bytes(size=(280, 210))),
            *tuple(_noise_fingerprint(index) for index in range(1, 100)),
        ),
        _inventory(source),
    )
    foreign_decision = NearDuplicateDecision.create(
        candidate=foreign_scan.review_candidates[0],
        outcome=ReviewOutcome.DISTINCT,
        operator_id="reviewer",
        note="只属于另一轮扫描",
        decided_at="2026-07-26T10:35:00+08:00",
    )
    with pytest.raises(LockedSetSimilarityScanError, match="current scan"):
        bind_similarity_decisions(scan=scan, decisions=(foreign_decision,))


def test_scan_fingerprint_changes_when_payload_is_tampered() -> None:
    payload = _scan(_probes(), _inventory()).to_payload()
    original = payload["scan_fingerprint"]
    payload["excluded_image_count"] = 99

    assert recompute_scan_fingerprint(payload) != original
