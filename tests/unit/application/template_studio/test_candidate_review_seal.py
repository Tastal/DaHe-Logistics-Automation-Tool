from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from dahe.application.template_studio import candidate_review_seal as seal_module
from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewFormalExport,
)
from dahe.application.template_studio.candidate_review_seal import (
    CandidateReviewSealError,
    create_candidate_review_seal,
    discover_candidate_review_seals,
    is_candidate_review_sealed,
    validate_candidate_review_seal,
)
from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
    FormalDevelopmentAuthorityError,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedTicketImage,
    LockedWaybill,
)
from dahe.verification.locked_set_acceptance import (
    locked_set_quality_coverage_sha256,
)

_TEST_DEVELOPMENT_AUTHORITY_PAYLOAD: dict[str, object] = {
    "schema_version": 1,
    "kind": "candidate_review_seal_test_authority",
    "authority_sha256": "a" * 64,
}


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)[:-1]).hexdigest()


@pytest.fixture(autouse=True)
def _development_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> FormalDevelopmentAuthority:
    payload = dict(_TEST_DEVELOPMENT_AUTHORITY_PAYLOAD)
    authority = FormalDevelopmentAuthority(
        authority_sha256="a" * 64,
        payload=payload,
        exclusion_snapshot=cast(
            Any,
            SimpleNamespace(canonical_sha256="b" * 64),
        ),
        inventory_high_watermark=1,
        perceptual_fingerprints=(),
        shadow_templates=(),
        eligibility_contract=cast(Any, SimpleNamespace()),
    )

    def parse(value: object) -> FormalDevelopmentAuthority:
        if value != payload:
            raise FormalDevelopmentAuthorityError(
                "test development authority changed"
            )
        return authority

    monkeypatch.setattr(
        seal_module,
        "load_formal_development_authority",
        lambda path: authority,
    )
    monkeypatch.setattr(
        seal_module,
        "parse_formal_development_authority",
        parse,
    )
    return authority


def _review_authority_records(
    package_sha256: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    latest_records: list[dict[str, object]] = []
    source_records: list[dict[str, object]] = []
    for position in range(1, 51):
        sample_id = f"L7-{position:03d}"
        record: dict[str, object] = {
            "sample_id": sample_id,
            "record_version": 1,
            "review_status": "confirmed",
            "decision": "confirmed",
            "review_payload": {
                "reviewer_id": "operator-a",
                "decision": "confirmed",
                "images": [
                    {
                        "submitted_slot": "loading",
                        "role": "loading",
                        "ordinary_net": "31.25",
                        "quality_conditions": [
                            "rotation_0",
                            "printed",
                        ],
                        "notes": None,
                    },
                    {
                        "submitted_slot": "unloading",
                        "role": "unloading",
                        "ordinary_net": "31.20",
                        "quality_conditions": [
                            "rotation_0",
                            "screen",
                        ],
                        "notes": None,
                    },
                ],
                "pair_conditions": ["normal_pair"],
                "pair_notes": None,
                "replace_reason": None,
            },
            "created_at": "2026-07-25T08:00:00+00:00",
            "updated_at": "2026-07-25T08:00:00+00:00",
        }
        evidence = {
            "schema_version": 1,
            "package_sha256": package_sha256,
            **record,
        }
        latest_records.append(record)
        source_records.append(
            {
                **record,
                "record_evidence_sha256": _canonical_sha256(evidence),
            }
        )
    return latest_records, source_records


def _fixture_manifest() -> LockedSetManifest:
    return LockedSetManifest(
        dataset_id="loop7-seal-fixture",
        dataset_kind="locked",
        tuning_prohibited=True,
        waybills=tuple(
            LockedWaybill(
                sample_id=f"L7-{position:03d}",
                waybill_identity_sha256=hashlib.sha256(
                    f"waybill:L7-{position:03d}".encode()
                ).hexdigest(),
                images=tuple(
                    LockedTicketImage(
                        image_sha256=hashlib.sha256(
                            f"L7-{position:03d}:{slot.value}".encode()
                        ).hexdigest(),
                        relative_path=(f"images/L7-{position:03d}-{slot.value}.jpg"),
                        slot=slot,
                        role=role,
                        ordinary_net=ordinary_net,
                    )
                    for slot, role, ordinary_net in (
                        (
                            TicketSlot.LOADING,
                            TicketRole.LOADING,
                            Decimal("31.25"),
                        ),
                        (
                            TicketSlot.UNLOADING,
                            TicketRole.UNLOADING,
                            Decimal("31.20"),
                        ),
                    )
                ),  # type: ignore[arg-type]
            )
            for position in range(1, 51)
        ),
    )


def _formal_export() -> CandidateReviewFormalExport:
    manifest = _fixture_manifest()
    manifest_payload: dict[str, object] = {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "dataset_kind": "locked",
        "tuning_prohibited": True,
        "waybills": [
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "relative_path": image.relative_path,
                        "submitted_slot": image.slot.value,
                        "role": image.role.value,
                        "ordinary_net": format(
                            image.ordinary_net,
                            "f",
                        ),
                    }
                    for image in waybill.images
                ],
            }
            for waybill in manifest.waybills
        ],
    }
    manifest_sha256 = manifest.canonical_sha256
    package_sha256 = hashlib.sha256(b"candidate-package").hexdigest()
    _, source_records = _review_authority_records(package_sha256)
    record_set_sha256 = _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package_sha256,
            "configured_reviewer_id": "operator-a",
            "records": [
                {
                    "sample_id": record["sample_id"],
                    "record_version": record["record_version"],
                    "record_evidence_sha256": (record["record_evidence_sha256"]),
                }
                for record in source_records
            ],
        }
    )
    verified_images = [
        {
            "sample_id": f"L7-{position:03d}",
            "submitted_slot": slot,
            "image_sha256": hashlib.sha256(f"L7-{position:03d}:{slot}".encode()).hexdigest(),
            "relative_path": f"images/L7-{position:03d}-{slot}.jpg",
            "width": 1000,
            "height": 800,
            "media_type": "image/jpeg",
            "byte_count": 100,
        }
        for position in range(1, 51)
        for slot in ("loading", "unloading")
    ]
    verified_image_set_sha256 = _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package_sha256,
            "images": verified_images,
        }
    )
    review_by_sample = {
        str(record["sample_id"]): record["review_payload"] for record in source_records
    }
    verified_by_key = {
        (
            str(image["sample_id"]),
            str(image["submitted_slot"]),
        ): image
        for image in verified_images
    }
    waybill_membership = [
        {
            "sample_id": waybill.sample_id,
            "waybill_identity_sha256": (waybill.waybill_identity_sha256),
            "images": [
                {
                    "submitted_slot": image.slot.value,
                    "image_sha256": verified_by_key[(waybill.sample_id, image.slot.value)][
                        "image_sha256"
                    ],
                    "relative_path": verified_by_key[(waybill.sample_id, image.slot.value)][
                        "relative_path"
                    ],
                    "ticket_role": image.role.value,
                    "ordinary_net_kg": str(int(image.ordinary_net * 1000)),
                }
                for image in waybill.images
            ],
        }
        for waybill in manifest.waybills
    ]
    assert len(review_by_sample) == 50
    waybill_membership_sha256 = _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package_sha256,
            "waybills": waybill_membership,
        }
    )
    quality_coverage_payload: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest_sha256,
        "required_conditions": [],
        "entries": [],
        "derived_adversarial_suite": {},
    }
    quality_coverage_sha256 = locked_set_quality_coverage_sha256(quality_coverage_payload)
    quality_coverage_payload["quality_coverage_sha256"] = quality_coverage_sha256
    source_without_hash: dict[str, object] = {
        "schema_version": 2,
        "kind": "candidate_review_formal_source_authority",
        "authority_scope": "computed_unsealed_snapshot",
        "persistent_seal": False,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest_sha256,
        "package_id": "candidate-review-fixture",
        "package_sha256": package_sha256,
        "configured_reviewer_id": "operator-a",
        "record_count": 50,
        "record_set_sha256": record_set_sha256,
        "records": source_records,
        "verified_image_count": 100,
        "verified_image_set_sha256": verified_image_set_sha256,
        "verified_images": verified_images,
        "waybill_membership_count": 50,
        "waybill_membership_sha256": (waybill_membership_sha256),
        "waybill_membership": waybill_membership,
    }
    source_authority_sha256 = _canonical_sha256(source_without_hash)
    source_authority_payload = {
        **source_without_hash,
        "source_authority_sha256": source_authority_sha256,
    }
    return CandidateReviewFormalExport(
        manifest=manifest,
        manifest_payload=manifest_payload,
        manifest_sha256=manifest_sha256,
        source_authority_payload=source_authority_payload,
        source_authority_sha256=source_authority_sha256,
        record_set_sha256=record_set_sha256,
        quality_coverage_payload=quality_coverage_payload,
        quality_coverage_sha256=quality_coverage_sha256,
    )


def _history_authority() -> tuple[dict[str, object], str]:
    package_sha256 = hashlib.sha256(b"candidate-package").hexdigest()
    latest_records, _ = _review_authority_records(package_sha256)
    idempotency_records = [
        {
            "sample_id": record["sample_id"],
            "resulting_record_version": record["record_version"],
            "idempotency_key": f"review-{record['sample_id']}",
            "request_hash": hashlib.sha256(f"request:{record['sample_id']}".encode()).hexdigest(),
            "created_at": record["created_at"],
        }
        for record in latest_records
    ]
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "locked_set_review_authority_snapshot",
        "package_sha256": package_sha256,
        "sample_count": 50,
        "latest_record_count": 50,
        "history_record_count": 50,
        "idempotency_record_count": 50,
        "latest_records": latest_records,
        "history_records": latest_records,
        "idempotency_records": idempotency_records,
    }
    return payload, _canonical_sha256(payload)


def _rehash_source_authority(
    source: dict[str, object],
) -> None:
    membership = source["waybill_membership"]
    source["waybill_membership_sha256"] = _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": source["package_sha256"],
            "waybills": membership,
        }
    )
    source_without_hash = {
        key: value for key, value in source.items() if key != "source_authority_sha256"
    }
    source["source_authority_sha256"] = _canonical_sha256(source_without_hash)


def _mutated_rehashed_export(
    mutation: str,
) -> tuple[CandidateReviewFormalExport, dict[str, object], str]:
    formal_export = _formal_export()
    history, _history_sha256 = _history_authority()
    history = json.loads(json.dumps(history))
    source = json.loads(json.dumps(formal_export.source_authority_payload))
    memberships = source["waybill_membership"]
    assert isinstance(memberships, list)
    first = memberships[0]
    assert isinstance(first, dict)
    images = first["images"]
    assert isinstance(images, list)
    first_image = images[0]
    assert isinstance(first_image, dict)
    changed_record_truth = False
    if mutation == "ticket_role":
        first_image["ticket_role"] = "unloading"
        changed_record_truth = True
    elif mutation == "ordinary_net_kg":
        first_image["ordinary_net_kg"] = "99990"
        changed_record_truth = True
    else:
        first["waybill_identity_sha256"] = hashlib.sha256(b"changed-waybill-identity").hexdigest()
    record_set_sha256 = formal_export.record_set_sha256
    if changed_record_truth:
        source_records = source["records"]
        assert isinstance(source_records, list)
        source_record = source_records[0]
        assert isinstance(source_record, dict)
        review_payload = source_record["review_payload"]
        assert isinstance(review_payload, dict)
        review_images = review_payload["images"]
        assert isinstance(review_images, list)
        review_image = review_images[0]
        assert isinstance(review_image, dict)
        if mutation == "ticket_role":
            review_image["role"] = "unloading"
            review_payload["pair_conditions"] = ["same_role_pair"]
        else:
            review_image["ordinary_net"] = "99.99"
        record_base = {
            key: value for key, value in source_record.items() if key != "record_evidence_sha256"
        }
        source_record["record_evidence_sha256"] = _canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": source["package_sha256"],
                **record_base,
            }
        )
        record_set_sha256 = _canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": source["package_sha256"],
                "configured_reviewer_id": source["configured_reviewer_id"],
                "records": [
                    {
                        "sample_id": record["sample_id"],
                        "record_version": record["record_version"],
                        "record_evidence_sha256": record["record_evidence_sha256"],
                    }
                    for record in source_records
                ],
            }
        )
        source["record_set_sha256"] = record_set_sha256
        latest_records = history["latest_records"]
        history_records = history["history_records"]
        assert isinstance(latest_records, list)
        assert isinstance(history_records, list)
        latest_records[0] = json.loads(json.dumps(record_base))
        history_records[0] = json.loads(json.dumps(record_base))
    _rehash_source_authority(source)
    changed_export = replace(
        formal_export,
        source_authority_payload=source,
        source_authority_sha256=str(source["source_authority_sha256"]),
        record_set_sha256=record_set_sha256,
    )
    return (
        changed_export,
        history,
        _canonical_sha256(history),
    )


def _rewrite_fully_rehashed_seal(
    seal_root: Path,
    *,
    mutation: str,
) -> tuple[Path, str]:
    source = json.loads((seal_root / "source-authority.json").read_text(encoding="utf-8"))
    if mutation == "cross_waybill_image_path":
        memberships = source["waybill_membership"]
        first_images = memberships[0]["images"]
        second_images = memberships[1]["images"]
        verified = source["verified_images"]
        for field in ("image_sha256", "relative_path"):
            first_images[0][field], second_images[0][field] = (
                second_images[0][field],
                first_images[0][field],
            )
            verified[0][field], verified[2][field] = (
                verified[2][field],
                verified[0][field],
            )
        source["verified_image_set_sha256"] = _canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": source["package_sha256"],
                "images": verified,
            }
        )
        _rehash_source_authority(source)
    elif mutation == "sample_slot_association":
        verified = source["verified_images"]
        verified[0]["sample_id"], verified[2]["sample_id"] = (
            verified[2]["sample_id"],
            verified[0]["sample_id"],
        )
        source["verified_image_set_sha256"] = _canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": source["package_sha256"],
                "images": verified,
            }
        )
        _rehash_source_authority(source)
    else:
        verified = source["verified_images"]
        verified[0]["submitted_slot"], verified[1]["submitted_slot"] = (
            verified[1]["submitted_slot"],
            verified[0]["submitted_slot"],
        )
        verified[0], verified[1] = verified[1], verified[0]
        source["verified_image_set_sha256"] = _canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": source["package_sha256"],
                "images": verified,
            }
        )
        _rehash_source_authority(source)
    (seal_root / "source-authority.json").write_bytes(_canonical_bytes(source))

    seal_payload = json.loads((seal_root / "seal.json").read_text(encoding="utf-8"))
    seal_payload["source_authority_sha256"] = source["source_authority_sha256"]
    artifact_sha256s = seal_payload["artifact_sha256s"]
    artifact_sha256s["source-authority.json"] = _canonical_sha256(source)
    seal_without_hash = {key: value for key, value in seal_payload.items() if key != "seal_sha256"}
    changed_sha256 = _canonical_sha256(seal_without_hash)
    seal_payload["seal_sha256"] = changed_sha256
    (seal_root / "seal.json").write_bytes(_canonical_bytes(seal_payload))
    changed_root = seal_root.parent / changed_sha256
    seal_root.replace(changed_root)
    return changed_root, changed_sha256


@pytest.mark.parametrize(
    "mutation",
    (
        "ticket_role",
        "ordinary_net_kg",
        "waybill_identity_sha256",
    ),
)
def test_seal_creation_rejects_rehashed_semantic_authority_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    formal_export, history, history_sha256 = _mutated_rehashed_export(mutation)

    with pytest.raises(
        CandidateReviewSealError,
        match="semantic",
    ):
        create_candidate_review_seal(
            review_data_root=review_data_root,
            formal_export=formal_export,
            review_history_authority_payload=history,
            review_history_authority_sha256=history_sha256,
        )

    assert not (review_data_root / "seals").exists()


def test_seal_validation_rejects_rehashed_quality_not_bound_by_source_authority(
    tmp_path: Path,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    formal_export = _formal_export()
    history, history_sha256 = _history_authority()
    created = create_candidate_review_seal(
        review_data_root=review_data_root,
        formal_export=formal_export,
        review_history_authority_payload=history,
        review_history_authority_sha256=history_sha256,
    )
    changed_quality = json.loads(
        (created.seal_root / "quality-coverage.json").read_text(encoding="utf-8")
    )
    changed_quality["entries"] = [{"condition": "changed-after-source-authority"}]
    changed_quality["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(changed_quality)
    (created.seal_root / "quality-coverage.json").write_bytes(_canonical_bytes(changed_quality))
    seal_payload = json.loads((created.seal_root / "seal.json").read_text(encoding="utf-8"))
    seal_payload["quality_coverage_sha256"] = changed_quality["quality_coverage_sha256"]
    seal_payload["artifact_sha256s"]["quality-coverage.json"] = _canonical_sha256(changed_quality)
    seal_without_hash = {key: value for key, value in seal_payload.items() if key != "seal_sha256"}
    changed_seal_sha256 = _canonical_sha256(seal_without_hash)
    seal_payload["seal_sha256"] = changed_seal_sha256
    (created.seal_root / "seal.json").write_bytes(_canonical_bytes(seal_payload))
    changed_root = created.seal_root.parent / changed_seal_sha256
    created.seal_root.replace(changed_root)

    with pytest.raises(
        CandidateReviewSealError,
        match="existing seal is inconsistent",
    ):
        validate_candidate_review_seal(
            review_data_root=review_data_root,
            seal_sha256=changed_seal_sha256,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "cross_waybill_image_path",
        "sample_slot_association",
        "submitted_slot_association",
    ),
)
def test_seal_validation_rejects_fully_rehashed_semantic_rebinding(
    tmp_path: Path,
    mutation: str,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    history, history_sha256 = _history_authority()
    created = create_candidate_review_seal(
        review_data_root=review_data_root,
        formal_export=_formal_export(),
        review_history_authority_payload=history,
        review_history_authority_sha256=history_sha256,
    )
    _changed_root, changed_sha256 = _rewrite_fully_rehashed_seal(
        created.seal_root,
        mutation=mutation,
    )

    with pytest.raises(
        CandidateReviewSealError,
        match="existing seal is inconsistent",
    ):
        validate_candidate_review_seal(
            review_data_root=review_data_root,
            seal_sha256=changed_sha256,
        )


def test_creates_canonical_immutable_seal_and_discovers_it(
    tmp_path: Path,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    export = _formal_export()
    history, history_sha256 = _history_authority()

    assert is_candidate_review_sealed(review_data_root) is False
    created = create_candidate_review_seal(
        review_data_root=review_data_root,
        formal_export=export,
        review_history_authority_payload=history,
        review_history_authority_sha256=history_sha256,
    )

    assert created.seal_root == (review_data_root / "seals" / created.seal_sha256)
    assert created.seal_root.is_dir()
    assert {path.name for path in created.seal_root.iterdir()} == {
        "development-authority.json",
        "manifest.json",
        "quality-coverage.json",
        "review-history-authority.json",
        "seal.json",
        "source-authority.json",
    }
    expected_payloads = {
        "development-authority.json": (
            _TEST_DEVELOPMENT_AUTHORITY_PAYLOAD
        ),
        "manifest.json": export.manifest_payload,
        "quality-coverage.json": export.quality_coverage_payload,
        "review-history-authority.json": history,
        "seal.json": created.seal_payload,
    }
    for name, payload in expected_payloads.items():
        assert (created.seal_root / name).read_bytes() == _canonical_bytes(payload)
    sealed_source = json.loads(
        (created.seal_root / "source-authority.json").read_text(encoding="utf-8")
    )
    assert sealed_source["schema_version"] == 3
    assert sealed_source["quality_coverage_sha256"] == export.quality_coverage_sha256
    assert sealed_source["source_authority_sha256"] == _canonical_sha256(
        {key: value for key, value in sealed_source.items() if key != "source_authority_sha256"}
    )
    assert created.seal_payload["seal_sha256"] == created.seal_sha256
    assert (
        validate_candidate_review_seal(
            review_data_root=review_data_root,
            seal_sha256=created.seal_sha256,
        )
        == created
    )
    assert discover_candidate_review_seals(review_data_root) == (created,)
    assert is_candidate_review_sealed(review_data_root) is True


def test_identical_seal_creation_is_idempotent_without_rewriting(
    tmp_path: Path,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    export = _formal_export()
    history, history_sha256 = _history_authority()
    first = create_candidate_review_seal(
        review_data_root=review_data_root,
        formal_export=export,
        review_history_authority_payload=history,
        review_history_authority_sha256=history_sha256,
    )
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in first.seal_root.iterdir()
    }

    second = create_candidate_review_seal(
        review_data_root=review_data_root,
        formal_export=export,
        review_history_authority_payload=history,
        review_history_authority_sha256=history_sha256,
    )

    assert second == first
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in second.seal_root.iterdir()
    } == before


@pytest.mark.parametrize(
    "mutation",
    ["changed_file", "extra_file"],
)
def test_existing_inconsistent_seal_is_rejected_without_repair(
    tmp_path: Path,
    mutation: str,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    export = _formal_export()
    history, history_sha256 = _history_authority()
    created = create_candidate_review_seal(
        review_data_root=review_data_root,
        formal_export=export,
        review_history_authority_payload=history,
        review_history_authority_sha256=history_sha256,
    )
    if mutation == "changed_file":
        target = created.seal_root / "manifest.json"
        target.write_text('{"changed":true}\n', encoding="utf-8")
    else:
        target = created.seal_root / "unexpected.json"
        target.write_text("{}\n", encoding="utf-8")
    changed_bytes = target.read_bytes()

    with pytest.raises(
        CandidateReviewSealError,
        match="existing seal is inconsistent",
    ):
        create_candidate_review_seal(
            review_data_root=review_data_root,
            formal_export=export,
            review_history_authority_payload=history,
            review_history_authority_sha256=history_sha256,
        )

    assert target.read_bytes() == changed_bytes


def test_failed_publication_leaves_no_partial_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dahe.application.template_studio import candidate_review_seal

    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    export = _formal_export()
    history, history_sha256 = _history_authority()
    original_write = candidate_review_seal._write_json_exclusive
    call_count = 0

    def fail_on_third_write(path: Path, payload: object) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            raise OSError("injected seal write failure")
        original_write(path, payload)

    monkeypatch.setattr(
        candidate_review_seal,
        "_write_json_exclusive",
        fail_on_third_write,
    )

    with pytest.raises(
        CandidateReviewSealError,
        match="seal publication failed",
    ):
        create_candidate_review_seal(
            review_data_root=review_data_root,
            formal_export=export,
            review_history_authority_payload=history,
            review_history_authority_sha256=history_sha256,
        )

    seals_root = review_data_root / "seals"
    assert not seals_root.exists() or list(seals_root.iterdir()) == []


def test_rejects_noncanonical_hash_or_relative_root_before_writing(
    tmp_path: Path,
) -> None:
    export = _formal_export()
    history, history_sha256 = _history_authority()
    relative_root = Path("relative-review-data")

    with pytest.raises(CandidateReviewSealError, match="absolute"):
        create_candidate_review_seal(
            review_data_root=relative_root,
            formal_export=export,
            review_history_authority_payload=history,
            review_history_authority_sha256=history_sha256,
        )

    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    with pytest.raises(
        CandidateReviewSealError,
        match="history authority SHA-256",
    ):
        create_candidate_review_seal(
            review_data_root=review_data_root,
            formal_export=export,
            review_history_authority_payload=history,
            review_history_authority_sha256="A" * 64,
        )
    assert not (review_data_root / "seals").exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("package", "package"),
        ("latest_record", "latest records"),
        ("history_count", "record counts"),
    ],
)
def test_rejects_unbound_or_incomplete_review_history_authority(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    review_data_root.mkdir()
    export = _formal_export()
    history, _ = _history_authority()
    mutated = json.loads(json.dumps(history))
    assert isinstance(mutated, dict)
    if mutation == "package":
        mutated["package_sha256"] = hashlib.sha256(b"another-package").hexdigest()
    elif mutation == "latest_record":
        latest_records = mutated["latest_records"]
        assert isinstance(latest_records, list)
        latest_record = latest_records[0]
        assert isinstance(latest_record, dict)
        latest_record["updated_at"] = "2026-07-26T08:00:00+00:00"
    else:
        mutated["history_record_count"] = 51

    with pytest.raises(CandidateReviewSealError, match=message):
        create_candidate_review_seal(
            review_data_root=review_data_root,
            formal_export=export,
            review_history_authority_payload=mutated,
            review_history_authority_sha256=_canonical_sha256(mutated),
        )

    assert not (review_data_root / "seals").exists()


def test_discovery_fails_closed_on_an_unknown_entry(
    tmp_path: Path,
) -> None:
    review_data_root = (tmp_path / "review-data").resolve()
    seals_root = review_data_root / "seals"
    seals_root.mkdir(parents=True)
    (seals_root / "unexpected").mkdir()

    with pytest.raises(CandidateReviewSealError, match="seal store is invalid"):
        discover_candidate_review_seals(review_data_root)
    with pytest.raises(CandidateReviewSealError, match="seal store is invalid"):
        is_candidate_review_sealed(review_data_root)
