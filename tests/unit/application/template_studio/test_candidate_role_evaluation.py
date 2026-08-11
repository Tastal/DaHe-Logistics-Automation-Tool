from __future__ import annotations

import copy
import hashlib
import json
from decimal import Decimal
from pathlib import Path, PurePosixPath

import pytest

from dahe.adapters.ocr.fingerprints import build_ocr_output_fingerprint
from dahe.adapters.ocr.protocol import (
    NormalizedBox,
    OcrFieldValue,
    OcrResult,
    OcrResultStatus,
    OcrRoleObservation,
    OcrTextLine,
)
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewAuthoritySnapshot,
    LockedSetReviewIdempotencyRecord,
    LockedSetReviewRecord,
)
from dahe.application.template_studio import matcher as matcher_module
from dahe.application.template_studio.candidate_review_export import (
    build_candidate_review_formal_export,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    CandidateRoleEvaluationError,
    evaluate_candidate_development_roles,
    evaluate_candidate_development_roles_from_path,
)
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    NormalizedRect,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
)
from dahe.jobs.ocr_execution import qualified_runtime_set_sha256
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImage,
    LockedSetReviewItem,
    LockedSetReviewPackage,
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


ROLE_EVALUATOR_BUILD_SHA256 = _sha256("role-evaluator-build")


def _rect(
    x: str,
    y: str,
    width: str,
    height: str,
) -> NormalizedRect:
    return NormalizedRect(
        x=Decimal(x),
        y=Decimal(y),
        width=Decimal(width),
        height=Decimal(height),
    )


def _rotate(
    rectangle: NormalizedRect,
    degrees: int,
) -> NormalizedRect:
    if degrees == 0:
        return rectangle
    if degrees == 90:
        return _rect(
            str(1 - rectangle.y - rectangle.height),
            str(rectangle.x),
            str(rectangle.height),
            str(rectangle.width),
        )
    if degrees == 180:
        return _rect(
            str(1 - rectangle.x - rectangle.width),
            str(1 - rectangle.y - rectangle.height),
            str(rectangle.width),
            str(rectangle.height),
        )
    return _rect(
        str(rectangle.y),
        str(1 - rectangle.x - rectangle.width),
        str(rectangle.height),
        str(rectangle.width),
    )


def _anchor(
    *,
    marker: str,
    text: str,
    box: NormalizedRect,
    role: TicketRole,
) -> TemplateAnchor:
    return TemplateAnchor(
        anchor_id=f"{marker}-{_sha256(text)[:8]}",
        expected_text=text,
        box=box,
        required=True,
        weight=Decimal("1"),
        max_edit_distance=Decimal("0.10"),
        loading_evidence=(Decimal("0.95") if role is TicketRole.LOADING else Decimal("-0.40")),
        unloading_evidence=(Decimal("0.95") if role is TicketRole.UNLOADING else Decimal("-0.40")),
    )


def _candidate(
    role: TicketRole,
    marker: str,
) -> TemplateVersion:
    title = "装货磅单" if role is TicketRole.LOADING else "卸货磅单"
    return TemplateVersion(
        version_id=f"{marker}-candidate",
        definition=TemplateDefinition(
            family_id=f"{marker}-family",
            name=f"{marker} candidate",
            role=role,
            anchors=(
                _anchor(
                    marker=marker,
                    text=title,
                    box=_rect("0.10", "0.08", "0.30", "0.08"),
                    role=role,
                ),
                _anchor(
                    marker=marker,
                    text="净重",
                    box=_rect("0.10", "0.62", "0.14", "0.07"),
                    role=role,
                ),
            ),
            regions=(),
        ),
        lifecycle=TemplateLifecycle.DRAFT,
        parent_version_id=None,
        record_version=1,
    )


def _roles_and_pair(sample_index: int) -> tuple[tuple[str, str], str]:
    if sample_index == 1:
        return ("unloading", "loading"), "swapped_pair"
    if sample_index == 2:
        return ("loading", "loading"), "same_role_pair"
    if sample_index == 3:
        return ("unknown", "unloading"), "pair_unknown"
    return ("loading", "unloading"), "normal_pair"


def _quality_conditions(
    *,
    image_index: int,
    role: str,
    slot: str,
) -> list[str]:
    orientation = (0, 90, 180, 270)[(image_index - 1) % 4]
    conditions: list[str] = []
    if image_index == 7:
        conditions.append("blur")
    if image_index == 8:
        conditions.append("glare")
    if image_index == 9:
        conditions.append("crop")
    conditions.append(f"rotation_{orientation}")
    conditions.append("printed" if slot == "loading" else "screen")
    if role == "unknown":
        conditions.extend(("unknown_layout", "non_ticket"))
    return conditions


def _review_source(
    tmp_path: Path,
) -> tuple[
    LockedSetReviewPackage,
    LockedSetReviewAuthoritySnapshot,
    object,
]:
    review_root = tmp_path / "review-source" / "locked-set-review"
    image_root = review_root / "images"
    image_root.mkdir(parents=True)
    items: list[LockedSetReviewItem] = []
    records: list[LockedSetReviewRecord] = []
    images_by_sha256: dict[str, LockedSetReviewImage] = {}

    for sample_index in range(1, 51):
        sample_id = f"sample-{sample_index:03d}"
        roles, pair_condition = _roles_and_pair(sample_index)
        package_images: list[LockedSetReviewImage] = []
        reviewed_images: list[dict[str, object]] = []
        for slot_index, slot in enumerate(("loading", "unloading")):
            image_index = ((sample_index - 1) * 2) + slot_index + 1
            content = f"candidate-role-image-{image_index:03d}".encode()
            image_sha256 = hashlib.sha256(content).hexdigest()
            image_path = image_root / f"{image_sha256}.jpg"
            image_path.write_bytes(content)
            image = LockedSetReviewImage(
                submitted_slot=slot,
                image_sha256=image_sha256,
                relative_path=f"images/{image_sha256}.jpg",
                path=image_path,
                width=1200,
                height=800,
                media_type="image/jpeg",
                selection_clues=(),
            )
            role = roles[slot_index]
            package_images.append(image)
            images_by_sha256[image_sha256] = image
            reviewed_images.append(
                {
                    "submitted_slot": slot,
                    "role": role,
                    "ordinary_net": (None if role == "unknown" else "31.25"),
                    "quality_conditions": _quality_conditions(
                        image_index=image_index,
                        role=role,
                        slot=slot,
                    ),
                    "notes": (
                        "sensitive reviewer note"
                        if sample_index == 1 and slot == "loading"
                        else None
                    ),
                }
            )
        items.append(
            LockedSetReviewItem(
                sample_id=sample_id,
                candidate_id=f"candidate-{sample_index:03d}",
                waybill_identity_sha256=_sha256(f"waybill-{sample_index:03d}"),
                position=sample_index,
                selection_clues=(),
                images=(package_images[0], package_images[1]),
            )
        )
        timestamp = f"2026-07-26T00:{sample_index:02d}:00+00:00"
        records.append(
            LockedSetReviewRecord(
                sample_id=sample_id,
                review_status="confirmed",
                decision="confirmed",
                review_payload={
                    "reviewer_id": "reviewer-sensitive",
                    "decision": "confirmed",
                    "images": reviewed_images,
                    "pair_conditions": [pair_condition],
                    "pair_notes": ("sensitive pair note" if sample_index == 1 else None),
                    "replace_reason": None,
                },
                record_version=1,
                created_at=timestamp,
                updated_at=timestamp,
            )
        )

    item_tuple = tuple(items)
    package = LockedSetReviewPackage(
        package_id="candidate-role-review-package",
        canonical_sha256=_canonical_sha256({"package": "candidate-role-review-package"}),
        review_root=review_root,
        items=item_tuple,
        items_by_sample_id={item.sample_id: item for item in item_tuple},
        images_by_sha256=images_by_sha256,
    )
    record_tuple = tuple(records)
    idempotency_records = tuple(
        LockedSetReviewIdempotencyRecord(
            idempotency_key=f"review-{index:03d}",
            sample_id=record.sample_id,
            request_hash=_sha256(f"request-{index:03d}"),
            resulting_record_version=1,
            created_at=record.created_at,
        )
        for index, record in enumerate(record_tuple, start=1)
    )
    history_payload = [
        {
            "sample_id": record.sample_id,
            "record_version": record.record_version,
            "review_status": record.review_status,
            "decision": record.decision,
            "review_payload": record.review_payload,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
        for record in record_tuple
    ]
    idempotency_payload = [
        {
            "sample_id": record.sample_id,
            "resulting_record_version": record.resulting_record_version,
            "idempotency_key": record.idempotency_key,
            "request_hash": record.request_hash,
            "created_at": record.created_at,
        }
        for record in idempotency_records
    ]
    authority_payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "locked_set_review_authority_snapshot",
        "package_sha256": package.canonical_sha256,
        "sample_count": 50,
        "latest_record_count": 50,
        "history_record_count": 50,
        "idempotency_record_count": 50,
        "latest_records": history_payload,
        "history_records": history_payload,
        "idempotency_records": idempotency_payload,
    }
    authority = LockedSetReviewAuthoritySnapshot(
        package_sha256=package.canonical_sha256,
        latest_records=record_tuple,
        history_records=record_tuple,
        idempotency_records=idempotency_records,
        payload=authority_payload,
        canonical_sha256=_canonical_sha256(authority_payload),
    )
    review_export = build_candidate_review_formal_export(
        package=package,
        records=authority.latest_records,
        configured_reviewer_id="reviewer-sensitive",
        dataset_id="candidate-role-development-source",
    )
    return package, authority, review_export


def _ocr_result(
    *,
    image_sha256: str,
    role: str,
    orientation: int,
    runtime_kind: str,
    runtime_fingerprint: str,
) -> OcrResult:
    if role == "unknown":
        text_lines = (
            OcrTextLine(
                text="普通发票",
                confidence=Decimal("0.99"),
                box=NormalizedBox(
                    x=Decimal("0.60"),
                    y=Decimal("0.35"),
                    width=Decimal("0.20"),
                    height=Decimal("0.06"),
                ),
            ),
        )
        fixed_text = ("普通发票",)
        fields: dict[str, OcrFieldValue] = {}
    else:
        ticket_role = TicketRole(role)
        title = "装货磅单" if ticket_role is TicketRole.LOADING else "卸货磅单"
        fixed_text = (
            "装货" if ticket_role is TicketRole.LOADING else "卸货",
            "磅单",
            "净重",
        )
        title_box = _rotate(
            _rect("0.10", "0.08", "0.30", "0.08"),
            orientation,
        )
        net_box = _rotate(
            _rect("0.10", "0.62", "0.14", "0.07"),
            orientation,
        )
        text_lines = (
            OcrTextLine(
                text=title,
                confidence=Decimal("0.98"),
                box=NormalizedBox(
                    x=title_box.x,
                    y=title_box.y,
                    width=title_box.width,
                    height=title_box.height,
                ),
            ),
            OcrTextLine(
                text="净重",
                confidence=Decimal("0.97"),
                box=NormalizedBox(
                    x=net_box.x,
                    y=net_box.y,
                    width=net_box.width,
                    height=net_box.height,
                ),
            ),
        )
        fields = {
            "ordinary_net": OcrFieldValue(
                raw_text="31.25",
                amount="31.25",
                unit="t",
                confidence=Decimal("0.97"),
            )
        }
    return OcrResult(
        command_id=f"{runtime_kind}-{image_sha256[:16]}",
        status=OcrResultStatus.OK,
        worker_identity=f"{runtime_kind}-worker",
        runtime_fingerprint=runtime_fingerprint,
        verified_image_sha256=image_sha256,
        elapsed_ms=8.0 if runtime_kind == "cpu" else 2.0,
        text_lines=text_lines,
        fields=fields,
        role_observation=OcrRoleObservation(
            fixed_text=fixed_text,
            layout_fingerprint=f"{runtime_kind}-layout",
            orientation_degrees=orientation,
        ),
        error=None,
    )


def _attempt(
    *,
    result: OcrResult,
    runtime_kind: str,
    profile_id: str,
    pipeline_fingerprint: str,
) -> dict[str, object]:
    result_payload = result.model_dump(mode="json")
    image_sha256 = result.verified_image_sha256
    assert image_sha256 is not None
    business_output = {
        "fields": result_payload["fields"],
        "role_observation": result_payload["role_observation"],
        "text_lines": result_payload["text_lines"],
    }
    raw_output = json.dumps(
        result_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "business_output_sha256": _canonical_sha256(business_output),
        "fields": result_payload["fields"],
        "image_sha256": image_sha256,
        "output_fingerprint": build_ocr_output_fingerprint(
            image_sha256=image_sha256,
            fields=result_payload["fields"],
            role_observation=result_payload["role_observation"],
            text_lines=result_payload["text_lines"],
            verified_image_sha256=image_sha256,
            pipeline_fingerprint=pipeline_fingerprint,
            profile_id=profile_id,
            runtime_fingerprint=result.runtime_fingerprint,
            runtime_kind=runtime_kind,
        ),
        "pipeline_fingerprint": pipeline_fingerprint,
        "profile_id": profile_id,
        "raw_output_sha256": hashlib.sha256(raw_output.encode("utf-8")).hexdigest(),
        "role_input": {
            "fixed_text": (
                [] if result.role_observation is None else list(result.role_observation.fixed_text)
            ),
            "image_sha256": image_sha256,
            "text_lines": result_payload["text_lines"],
        },
        "role_observation": result_payload["role_observation"],
        "runtime_fingerprint": result.runtime_fingerprint,
        "runtime_kind": runtime_kind,
        "status": "succeeded",
        "wall_elapsed_ms": 10.0 if runtime_kind == "cpu" else 3.0,
        "worker_elapsed_ms": result.elapsed_ms,
    }


def _candidate_ocr_evidence(
    tmp_path: Path,
) -> tuple[dict[str, object], tuple[TemplateVersion, ...]]:
    package, authority, review_export = _review_source(tmp_path)
    source_records = review_export.source_authority_payload["records"]
    assert isinstance(source_records, list)
    truth_by_image: dict[str, tuple[str, int]] = {}
    image_by_subject: dict[tuple[str, str], str] = {
        (waybill.sample_id, image.slot.value): image.image_sha256
        for waybill in review_export.manifest.waybills
        for image in waybill.images
    }
    for record in source_records:
        assert isinstance(record, dict)
        review_payload = record["review_payload"]
        assert isinstance(review_payload, dict)
        images = review_payload["images"]
        assert isinstance(images, list)
        for reviewed in images:
            assert isinstance(reviewed, dict)
            conditions = reviewed["quality_conditions"]
            assert isinstance(conditions, list)
            rotation = next(
                int(str(value).split("_")[1])
                for value in conditions
                if str(value).startswith("rotation_")
            )
            key = (
                str(record["sample_id"]),
                str(reviewed["submitted_slot"]),
            )
            truth_by_image[image_by_subject[key]] = (
                str(reviewed["role"]),
                rotation,
            )

    runtime_fingerprints = {
        "cpu": _sha256("cpu-runtime"),
        "gpu": _sha256("gpu-runtime"),
    }
    profiles = {"cpu": "cpu-profile", "gpu": "gpu-profile"}
    composition_sha256 = _sha256("composition")
    runtime_set_sha256 = qualified_runtime_set_sha256(
        tuple(
            {
                "profile_id": profiles[runtime_kind],
                "runtime_fingerprint": runtime_fingerprints[runtime_kind],
                "runtime_kind": runtime_kind,
            }
            for runtime_kind in ("cpu", "gpu")
        )
    )
    application_build_sha256 = _sha256("application-build")
    pipeline_contract_sha256 = _canonical_sha256(
        {
            "application_build_sha256": application_build_sha256,
            "evaluator_version": ("dahe.loop7.candidate-development-ocr.v1"),
            "ocr_composition_evidence_sha256": composition_sha256,
            "ocr_protocol_version": 1,
            "purpose": "candidate_review_development_ocr",
            "runtime_set_sha256": runtime_set_sha256,
        }
    )
    pipelines = {
        runtime_kind: _canonical_sha256(
            {
                "pipeline_contract_fingerprint": pipeline_contract_sha256,
                "profile_id": profiles[runtime_kind],
                "runtime_fingerprint": runtime_fingerprints[runtime_kind],
                "runtime_kind": runtime_kind,
            }
        )
        for runtime_kind in ("cpu", "gpu")
    }
    differing_image = sorted(truth_by_image)[10]
    copied_images: list[dict[str, object]] = []
    attempts: list[dict[str, object]] = []
    comparisons: list[dict[str, object]] = []
    for image_sha256 in sorted(truth_by_image):
        truth_role, orientation = truth_by_image[image_sha256]
        source_image = (
            tmp_path / "review-source" / "locked-set-review" / "images" / f"{image_sha256}.jpg"
        )
        copied_images.append(
            {
                "byte_size": source_image.stat().st_size,
                "image_sha256": image_sha256,
                "media_type": "image/jpeg",
                "relative_path": (
                    "development/protected-candidate-review-ocr/"
                    f"evidence/sha256/{image_sha256[:2]}/"
                    f"{image_sha256[2:4]}/{image_sha256}.blob"
                ),
            }
        )
        by_runtime: dict[str, dict[str, object]] = {}
        for runtime_kind in ("cpu", "gpu"):
            observed_role = (
                "unknown"
                if runtime_kind == "gpu" and image_sha256 == differing_image
                else truth_role
            )
            attempt = _attempt(
                result=_ocr_result(
                    image_sha256=image_sha256,
                    role=observed_role,
                    orientation=orientation,
                    runtime_kind=runtime_kind,
                    runtime_fingerprint=runtime_fingerprints[runtime_kind],
                ),
                runtime_kind=runtime_kind,
                profile_id=profiles[runtime_kind],
                pipeline_fingerprint=pipelines[runtime_kind],
            )
            attempts.append(attempt)
            by_runtime[runtime_kind] = attempt
        differences = [
            section
            for section in ("fields", "role_input", "role_observation")
            if by_runtime["cpu"][section] != by_runtime["gpu"][section]
        ]
        comparisons.append(
            {
                "comparison_status": ("different" if differences else "same"),
                "difference_sections": differences,
                "image_sha256": image_sha256,
                "runtime_output_sha256s": {
                    runtime_kind: by_runtime[runtime_kind]["business_output_sha256"]
                    for runtime_kind in ("cpu", "gpu")
                },
            }
        )

    evidence: dict[str, object] = {
        "application_build_sha256": application_build_sha256,
        "copied_image_set_sha256": _canonical_sha256(copied_images),
        "copied_images": copied_images,
        "development_only": True,
        "evaluator_version": ("dahe.loop7.candidate-development-ocr.v1"),
        "factory_qualification": {
            "composition_evidence_sha256": composition_sha256,
            "runtime_identities": [
                {
                    "profile_id": profiles[runtime_kind],
                    "runtime_fingerprint": (runtime_fingerprints[runtime_kind]),
                    "runtime_kind": runtime_kind,
                }
                for runtime_kind in ("cpu", "gpu")
            ],
            "runtime_set_sha256": runtime_set_sha256,
        },
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "generated_at": "2026-07-26T10:00:00+08:00",
        "kind": "candidate_review_development_ocr_evidence",
        "pipeline_contract_sha256": pipeline_contract_sha256,
        "reviewer_id": "reviewer-sensitive",
        "runtime_attempts": attempts,
        "runtime_comparisons": comparisons,
        "schema_version": 1,
        "source": {
            "manifest_payload": review_export.manifest_payload,
            "manifest_sha256": review_export.manifest_sha256,
            "package_id": package.package_id,
            "package_sha256": package.canonical_sha256,
            "quality_coverage_payload": (review_export.quality_coverage_payload),
            "quality_coverage_sha256": (review_export.quality_coverage_sha256),
            "record_set_sha256": review_export.record_set_sha256,
            "review_history_authority_payload": authority.payload,
            "review_history_authority_sha256": (authority.canonical_sha256),
            "source_authority_payload": (review_export.source_authority_payload),
            "source_authority_sha256": (review_export.source_authority_sha256),
        },
        "status": "completed_with_runtime_differences",
        "technical_failure_count": 0,
    }
    evidence["evidence_sha256"] = _canonical_sha256(evidence)
    return evidence, (
        _candidate(TicketRole.LOADING, "loading"),
        _candidate(TicketRole.UNLOADING, "unloading"),
    )


def _reseal(evidence: dict[str, object]) -> None:
    evidence.pop("evidence_sha256", None)
    evidence["evidence_sha256"] = _canonical_sha256(evidence)


def _write_protected_evidence(
    tmp_path: Path,
    evidence: dict[str, object],
) -> tuple[Path, Path]:
    data_root = (tmp_path / "data").resolve()
    copied_images = evidence["copied_images"]
    assert isinstance(copied_images, list)
    for copied in copied_images:
        assert isinstance(copied, dict)
        image_sha256 = str(copied["image_sha256"])
        source = tmp_path / "review-source" / "locked-set-review" / "images" / f"{image_sha256}.jpg"
        relative_path = PurePosixPath(str(copied["relative_path"]))
        target = data_root.joinpath(*relative_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    evidence_sha256 = str(evidence["evidence_sha256"])
    evidence_path = (
        data_root
        / "development"
        / "protected-candidate-review-ocr"
        / "records"
        / "sha256"
        / evidence_sha256[:2]
        / evidence_sha256[2:4]
        / f"{evidence_sha256}.json"
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(
            evidence,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return data_root, evidence_path


def test_evaluates_both_runtimes_with_human_truth_and_redacted_metrics(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)

    report = evaluate_candidate_development_roles(
        evidence,
        candidates=candidates,
        role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
    )

    payload = report.payload
    assert payload["development_only"] is True
    assert payload["formal_release_eligible"] is False
    assert payload["formal_accuracy_claim"] is False
    assert payload["authorizing_lifecycle_evidence"] is False
    assert payload["status"] == "completed"
    assert payload["schema_version"] == 2
    assert payload["evaluator_version"] == (
        "dahe.loop7.candidate-role-evaluation.v3"
    )
    assert payload["source"]["reviewer_id_sha256"] == (
        _canonical_sha256("reviewer-sensitive")
    )
    assert "gate_passed" not in payload
    assert report.evaluation_sha256 == payload["evaluation_sha256"]
    assert (
        _canonical_sha256(
            {key: value for key, value in payload.items() if key != "evaluation_sha256"}
        )
        == report.evaluation_sha256
    )

    runtimes = payload["runtimes"]
    assert isinstance(runtimes, dict)
    cpu = runtimes["cpu"]
    gpu = runtimes["gpu"]
    assert cpu["sample_count"] == gpu["sample_count"] == 100
    assert cpu["role"]["confusion_matrix"] == {
        "loading": {
            "loading": 50,
            "unknown": 0,
            "unloading": 0,
        },
        "unknown": {
            "loading": 0,
            "unknown": 1,
            "unloading": 0,
        },
        "unloading": {
            "loading": 0,
            "unknown": 0,
            "unloading": 49,
        },
    }
    assert cpu["role"]["unknown_rate"] == "0.01"
    assert cpu["role"]["high_confidence_error_count"] == 0
    assert cpu["role"]["direct_loading_unloading_error_count"] == 0
    assert gpu["role"]["unknown_rate"] == "0.02"
    assert cpu["orientation"]["match_count"] == 100
    assert cpu["orientation"]["sample_count"] == 100
    assert cpu["pair_status"]["expected_counts"] == {
        "duplicate": 0,
        "normal": 47,
        "same_role": 1,
        "swapped": 1,
        "unknown": 1,
    }
    assert cpu["pair_status"]["predicted_counts"] == (cpu["pair_status"]["expected_counts"])
    assert cpu["pair_status"]["mismatch_count"] == 0
    assert cpu["candidate_support"]["support_contract"] == (
        "human_role_correct_and_template_evidence_hit_and_final_role_correct"
    )
    assert cpu["candidate_support"]["supported_candidate_count"] == 2
    assert all(
        row["support_count"] >= 1
        for row in cpu["candidate_support"]["results"]
    )
    cpu_rows_by_subject = {
        row["subject_sha256"]: row
        for row in cpu["role"]["results"]
    }
    assert all(
        support["candidate_version_id"]
        in cpu_rows_by_subject[
            support["supporting_subject_sha256s"][0]
        ]["matched_template_version_ids"]
        for support in cpu["candidate_support"]["results"]
    )
    assert {
        candidate["role"]
        for candidate in payload["template_contract"]["candidates"]
    } == {"loading", "unloading"}
    assert cpu["matcher_latency_ms"]["sample_count"] == 100
    assert cpu["matcher_latency_ms"]["p50"] is not None
    assert cpu["matcher_latency_ms"]["p95"] is not None
    assert cpu["ocr_latency_ms"]["worker"]["sample_count"] == 100
    assert payload["cpu_gpu_role_consistency"] == {
        "agreement_rate": "0.99",
        "match_count": 99,
        "mismatch_count": 1,
        "mismatches": payload["cpu_gpu_role_consistency"]["mismatches"],
        "sample_count": 100,
    }
    assert len(payload["cpu_gpu_role_consistency"]["mismatches"]) == 1
    assert payload["attempt_contract"] == {
        "completed_attempt_count": 200,
        "expected_attempt_count": 200,
        "technical_failure_count": 0,
    }
    assert payload["source"]["ocr_capture_build_sha256"] == (
        evidence["application_build_sha256"]
    )
    assert payload["source"]["role_evaluator_build_sha256"] == (
        ROLE_EVALUATOR_BUILD_SHA256
    )
    assert "application_build_sha256" not in payload["source"]

    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
    )
    for forbidden in (
        "装货磅单",
        "卸货磅单",
        "普通发票",
        "31.25",
        "ordinary_net",
        "relative_path",
        "submitted_slot",
        "reviewer-sensitive",
        "sensitive reviewer note",
        "sensitive pair note",
        "sample-001",
    ):
        assert forbidden not in serialized


def test_candidate_role_evaluation_canonical_payload_is_characterized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)

    tick = -1_000_000

    def deterministic_counter() -> int:
        nonlocal tick
        tick += 1_000_000
        return tick

    monkeypatch.setattr(
        matcher_module,
        "perf_counter_ns",
        deterministic_counter,
    )

    report = evaluate_candidate_development_roles(
        evidence,
        candidates=candidates,
        role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
    )
    canonical_payload = json.dumps(
        report.payload,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert (
        report.evaluation_sha256
        == "62e21b23c463c7b787724d20d0c7505282a4d6359c043578494ed169a0e866fe"
    )
    assert (
        hashlib.sha256(canonical_payload).hexdigest()
        == "1c8b12af9087cc30c3ba44cca5c0deef6a2f47a2fef40df47ab8b80b5be472a3"
    )


def test_human_role_not_upload_slot_is_the_role_truth(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)

    payload = evaluate_candidate_development_roles(
        evidence,
        candidates=candidates,
        role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
    ).payload

    cpu = payload["runtimes"]["cpu"]
    swapped = next(
        pair for pair in cpu["pair_status"]["results"] if pair["expected_status"] == "swapped"
    )
    assert swapped["predicted_status"] == "swapped"
    assert swapped["domain_issue"] == "suspected_swapped"
    assert swapped["matches_truth"] is True


def test_role_evaluator_build_identity_is_required(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)

    with pytest.raises(
        CandidateRoleEvaluationError,
        match="role evaluator build",
    ):
        evaluate_candidate_development_roles(
            evidence,
            candidates=candidates,
            role_evaluator_build_sha256="not-a-sha256",
        )


def test_path_evaluation_requires_every_protected_image_blob(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)
    data_root, evidence_path = _write_protected_evidence(
        tmp_path,
        evidence,
    )

    report = evaluate_candidate_development_roles_from_path(
        evidence_path,
        data_root=data_root,
        candidates=candidates,
        role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
    )
    assert report.payload["status"] == "completed"

    copied_images = evidence["copied_images"]
    assert isinstance(copied_images, list)
    first = copied_images[0]
    assert isinstance(first, dict)
    missing = data_root.joinpath(
        *PurePosixPath(str(first["relative_path"])).parts,
    )
    missing.unlink()

    with pytest.raises(
        CandidateRoleEvaluationError,
        match=r"protected|image|evidence",
    ):
        evaluate_candidate_development_roles_from_path(
            evidence_path,
            data_root=data_root,
            candidates=candidates,
            role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "self_hash",
        "source_authority",
        "source_record_evidence",
        "review_history_authority",
        "technical_failure",
        "missing_runtime_attempt",
        "runtime_set_authority",
        "pipeline_fingerprint",
        "role_input",
    ),
)
def test_tampered_or_incomplete_ocr_evidence_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)
    mutated = copy.deepcopy(evidence)
    attempts = mutated["runtime_attempts"]
    assert isinstance(attempts, list)
    if mutation == "self_hash":
        mutated["evidence_sha256"] = _sha256("forged-evidence")
    elif mutation == "source_authority":
        source = mutated["source"]
        assert isinstance(source, dict)
        source["source_authority_sha256"] = _sha256("forged-source-authority")
        _reseal(mutated)
    elif mutation == "source_record_evidence":
        source = mutated["source"]
        assert isinstance(source, dict)
        source_authority = source["source_authority_payload"]
        assert isinstance(source_authority, dict)
        records = source_authority["records"]
        assert isinstance(records, list)
        first_record = records[0]
        assert isinstance(first_record, dict)
        first_record["record_evidence_sha256"] = _sha256("forged-record-evidence")
        record_set_sha256 = _canonical_sha256(
            {
                "configured_reviewer_id": source_authority["configured_reviewer_id"],
                "package_sha256": source_authority["package_sha256"],
                "records": [
                    {
                        "record_evidence_sha256": record["record_evidence_sha256"],
                        "record_version": record["record_version"],
                        "sample_id": record["sample_id"],
                    }
                    for record in records
                ],
                "schema_version": 1,
            }
        )
        source_authority["record_set_sha256"] = record_set_sha256
        source_authority.pop("source_authority_sha256")
        source_authority_sha256 = _canonical_sha256(source_authority)
        source_authority["source_authority_sha256"] = source_authority_sha256
        source["record_set_sha256"] = record_set_sha256
        source["source_authority_sha256"] = source_authority_sha256
        _reseal(mutated)
    elif mutation == "review_history_authority":
        source = mutated["source"]
        assert isinstance(source, dict)
        source["review_history_authority_payload"] = {
            "fabricated": True,
            "package_sha256": source["package_sha256"],
        }
        source["review_history_authority_sha256"] = _canonical_sha256(
            source["review_history_authority_payload"]
        )
        _reseal(mutated)
    elif mutation == "technical_failure":
        mutated["status"] = "failed"
        mutated["technical_failure_count"] = 1
        _reseal(mutated)
    elif mutation == "missing_runtime_attempt":
        attempts.pop()
        _reseal(mutated)
    elif mutation == "runtime_set_authority":
        factory = mutated["factory_qualification"]
        assert isinstance(factory, dict)
        forged_runtime_set = _sha256("forged-runtime-set")
        factory["runtime_set_sha256"] = forged_runtime_set
        pipeline_contract = _canonical_sha256(
            {
                "application_build_sha256": mutated["application_build_sha256"],
                "evaluator_version": mutated["evaluator_version"],
                "ocr_composition_evidence_sha256": factory["composition_evidence_sha256"],
                "ocr_protocol_version": 1,
                "purpose": "candidate_review_development_ocr",
                "runtime_set_sha256": forged_runtime_set,
            }
        )
        mutated["pipeline_contract_sha256"] = pipeline_contract
        for attempt in attempts:
            assert isinstance(attempt, dict)
            attempt["pipeline_fingerprint"] = _canonical_sha256(
                {
                    "pipeline_contract_fingerprint": pipeline_contract,
                    "profile_id": attempt["profile_id"],
                    "runtime_fingerprint": attempt["runtime_fingerprint"],
                    "runtime_kind": attempt["runtime_kind"],
                }
            )
        _reseal(mutated)
    elif mutation == "pipeline_fingerprint":
        first = attempts[0]
        assert isinstance(first, dict)
        first["pipeline_fingerprint"] = _sha256("forged-pipeline")
        _reseal(mutated)
    else:
        first = attempts[0]
        assert isinstance(first, dict)
        role_input = first["role_input"]
        assert isinstance(role_input, dict)
        role_input["fixed_text"] = ["forged"]
        _reseal(mutated)

    with pytest.raises(
        CandidateRoleEvaluationError,
        match=r"evidence|authority|technical|runtime|role input",
    ):
        evaluate_candidate_development_roles(
            mutated,
            candidates=candidates,
            role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
        )


def test_changed_ocr_business_output_cannot_reuse_old_output_fingerprint(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)
    mutated = copy.deepcopy(evidence)
    attempts = mutated["runtime_attempts"]
    comparisons = mutated["runtime_comparisons"]
    assert isinstance(attempts, list)
    assert isinstance(comparisons, list)
    first = attempts[0]
    assert isinstance(first, dict)
    role_observation = first["role_observation"]
    role_input = first["role_input"]
    assert isinstance(role_observation, dict)
    assert isinstance(role_input, dict)
    role_observation["fixed_text"] = ["forged", "磅单", "净重"]
    role_input["fixed_text"] = ["forged", "磅单", "净重"]
    first["business_output_sha256"] = _canonical_sha256(
        {
            "fields": first["fields"],
            "role_observation": role_observation,
            "text_lines": role_input["text_lines"],
        }
    )
    image_sha256 = first["image_sha256"]
    matching = next(
        comparison
        for comparison in comparisons
        if isinstance(comparison, dict)
        and comparison["image_sha256"] == image_sha256
    )
    runtime_hashes = matching["runtime_output_sha256s"]
    assert isinstance(runtime_hashes, dict)
    runtime_hashes[str(first["runtime_kind"])] = first["business_output_sha256"]
    counterpart = next(
        attempt
        for attempt in attempts
        if isinstance(attempt, dict)
        and attempt["image_sha256"] == image_sha256
        and attempt["runtime_kind"] != first["runtime_kind"]
    )
    matching["difference_sections"] = [
        section
        for section in ("fields", "role_input", "role_observation")
        if first[section] != counterpart[section]
    ]
    matching["comparison_status"] = (
        "different" if matching["difference_sections"] else "same"
    )
    _reseal(mutated)

    with pytest.raises(
        CandidateRoleEvaluationError,
        match="output fingerprint",
    ):
        evaluate_candidate_development_roles(
            mutated,
            candidates=candidates,
            role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
        )


def test_role_input_json_cannot_self_claim_reliable_ordinary_net(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)
    mutated = copy.deepcopy(evidence)
    attempts = mutated["runtime_attempts"]
    assert isinstance(attempts, list)
    no_weight_attempt = next(
        attempt
        for attempt in attempts
        if isinstance(attempt, dict) and attempt["fields"] == {}
    )
    role_input = no_weight_attempt["role_input"]
    assert isinstance(role_input, dict)
    assert "ordinary_net_reliable" not in role_input
    role_input["ordinary_net_reliable"] = True
    _reseal(mutated)

    with pytest.raises(
        CandidateRoleEvaluationError,
        match="role input",
    ):
        evaluate_candidate_development_roles(
            mutated,
            candidates=candidates,
            role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
        )


def test_ocr_latency_rejects_string_encoded_compact_exponents(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)
    mutated = copy.deepcopy(evidence)
    attempts = mutated["runtime_attempts"]
    assert isinstance(attempts, list)
    for attempt in attempts[:12]:
        assert isinstance(attempt, dict)
        attempt["wall_elapsed_ms"] = "1e10000"
    _reseal(mutated)

    with pytest.raises(
        CandidateRoleEvaluationError,
        match="latency",
    ):
        evaluate_candidate_development_roles(
            mutated,
            candidates=candidates,
            role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
        )


def test_candidate_lifecycle_must_use_existing_development_matcher_boundary(
    tmp_path: Path,
) -> None:
    evidence, candidates = _candidate_ocr_evidence(tmp_path)
    shadow_candidate = (
        TemplateVersion(
            version_id=candidates[0].version_id,
            definition=candidates[0].definition,
            lifecycle=TemplateLifecycle.SHADOW,
            parent_version_id=None,
            record_version=1,
        ),
        candidates[1],
    )

    with pytest.raises(
        CandidateRoleEvaluationError,
        match="development",
    ):
        evaluate_candidate_development_roles(
            evidence,
            candidates=shadow_candidate,
            role_evaluator_build_sha256=ROLE_EVALUATOR_BUILD_SHA256,
        )
