from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path

import pytest
from PIL import Image

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewIdempotencyRecord,
    LockedSetReviewRecord,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
)
from dahe.application.template_studio.candidate_development_ocr_run_authority import (
    record_candidate_development_ocr_run_authority,
)
from dahe.application.template_studio.candidate_review_export import (
    build_candidate_review_formal_export,
)
from dahe.application.template_studio.candidate_template_seed import (
    CandidateTemplateSeedError,
    load_candidate_development_template_source,
    load_template_definition,
    seed_candidate_development_template,
)
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TicketField,
)
from dahe.jobs.ocr_execution import qualified_runtime_set_sha256
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImage,
    LockedSetReviewItem,
    LockedSetReviewPackage,
)
from tests.unit.application.template_studio.test_candidate_role_evaluation import (
    _attempt as _candidate_attempt,
)
from tests.unit.application.template_studio.test_candidate_role_evaluation import (
    _ocr_result as _candidate_ocr_result,
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _png(index: int) -> bytes:
    output = io.BytesIO()
    Image.new(
        "RGB",
        (32, 24),
        color=(index % 251, (index * 3) % 251, (index * 7) % 251),
    ).save(output, format="PNG")
    return output.getvalue()


def _quality(sample_index: int, slot: str) -> list[str]:
    explicit = {
        (1, "loading"): ["rotation_0", "printed", "non_ticket"],
        (1, "unloading"): [
            "rotation_90",
            "screen",
            "unknown_layout",
        ],
        (2, "loading"): ["blur", "rotation_180", "printed"],
        (2, "unloading"): ["crop", "rotation_270", "screen"],
        (3, "loading"): ["glare", "rotation_0", "printed"],
    }
    return explicit.get(
        (sample_index, slot),
        ["rotation_0", "printed" if slot == "loading" else "screen"],
    )


def _protected_evidence(
    tmp_path: Path,
) -> tuple[Path, Path, str, dict[tuple[str, str], bytes]]:
    review_root = tmp_path / "review" / "locked-set-review"
    image_root = review_root / "images"
    image_root.mkdir(parents=True)
    items: list[LockedSetReviewItem] = []
    records: list[LockedSetReviewRecord] = []
    idempotency_records: list[LockedSetReviewIdempotencyRecord] = []
    images_by_sha256: dict[str, LockedSetReviewImage] = {}
    content_by_key: dict[tuple[str, str], bytes] = {}
    truth_by_image: dict[str, tuple[str, int]] = {}
    for sample_index in range(1, 51):
        sample_id = f"L7-{sample_index:03d}"
        package_images: list[LockedSetReviewImage] = []
        review_images: list[dict[str, object]] = []
        for slot_index, slot in enumerate(("loading", "unloading")):
            image_index = (sample_index - 1) * 2 + slot_index + 1
            content = _png(image_index)
            digest = hashlib.sha256(content).hexdigest()
            image_path = image_root / f"{digest}.png"
            image_path.write_bytes(content)
            image = LockedSetReviewImage(
                submitted_slot=slot,
                image_sha256=digest,
                relative_path=f"images/{digest}.png",
                path=image_path,
                width=32,
                height=24,
                media_type="image/png",
                selection_clues=(),
            )
            package_images.append(image)
            images_by_sha256[digest] = image
            content_by_key[(sample_id, slot)] = content
            role = "unknown" if sample_index == 1 else slot
            review_images.append(
                {
                    "submitted_slot": slot,
                    "role": role,
                    "ordinary_net": (
                        None
                        if role == "unknown"
                        else "31.25"
                        if slot == "loading"
                        else "31.20"
                    ),
                    "quality_conditions": _quality(sample_index, slot),
                    "notes": None,
                }
            )
            orientation = next(
                int(value.split("_")[1])
                for value in _quality(sample_index, slot)
                if value.startswith("rotation_")
            )
            truth_by_image[digest] = (role, orientation)
        items.append(
            LockedSetReviewItem(
                sample_id=sample_id,
                candidate_id=f"candidate-{sample_index:03d}",
                waybill_identity_sha256=hashlib.sha256(
                    f"waybill-{sample_index}".encode()
                ).hexdigest(),
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
                    "reviewer_id": "operator-a",
                    "decision": "confirmed",
                    "images": review_images,
                    "pair_conditions": (
                        ["pair_unknown"]
                        if sample_index == 1
                        else ["normal_pair"]
                    ),
                    "pair_notes": None,
                    "replace_reason": None,
                },
                record_version=1,
                created_at=timestamp,
                updated_at=timestamp,
            )
        )
        idempotency_records.append(
            LockedSetReviewIdempotencyRecord(
                idempotency_key=f"review-{sample_index:03d}",
                sample_id=sample_id,
                request_hash=hashlib.sha256(
                    f"request-{sample_index:03d}".encode()
                ).hexdigest(),
                resulting_record_version=1,
                created_at=timestamp,
            )
        )
    item_tuple = tuple(items)
    package = LockedSetReviewPackage(
        package_id="candidate-review-fixture",
        canonical_sha256=_canonical_sha256(
            {"package": "candidate-review-fixture"}
        ),
        review_root=review_root,
        items=item_tuple,
        items_by_sample_id={item.sample_id: item for item in item_tuple},
        images_by_sha256=images_by_sha256,
    )
    formal_export = build_candidate_review_formal_export(
        package=package,
        records=tuple(records),
        configured_reviewer_id="operator-a",
        dataset_id="candidate-review-development-source",
    )

    data_root = (tmp_path / "development-data").resolve()
    data_root.mkdir()
    protected_root = (
        data_root
        / "development"
        / "protected-candidate-review-ocr"
    )
    store = ContentAddressedEvidenceStore(protected_root / "evidence")
    copied: list[dict[str, object]] = []
    for image in sorted(
        images_by_sha256.values(),
        key=lambda item: item.image_sha256,
    ):
        stored = store.put_bytes(
            image.path.read_bytes(),
            media_type=image.media_type,
        )
        copied.append(
            {
                "byte_size": stored.byte_size,
                "image_sha256": stored.sha256,
                "media_type": stored.media_type,
                "relative_path": (
                    (protected_root / "evidence" / stored.relative_path)
                    .relative_to(data_root)
                    .as_posix()
                ),
            }
        )
    source_authority = formal_export.source_authority_payload
    history_records = [
        {
            "sample_id": record.sample_id,
            "record_version": record.record_version,
            "review_status": record.review_status,
            "decision": record.decision,
            "review_payload": record.review_payload,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
        for record in records
    ]
    idempotency_payload = [
        {
            "sample_id": record.sample_id,
            "resulting_record_version": (
                record.resulting_record_version
            ),
            "idempotency_key": record.idempotency_key,
            "request_hash": record.request_hash,
            "created_at": record.created_at,
        }
        for record in idempotency_records
    ]
    history_payload = {
        "kind": "locked_set_review_authority_snapshot",
        "package_sha256": package.canonical_sha256,
        "schema_version": 1,
        "sample_count": 50,
        "latest_record_count": 50,
        "history_record_count": 50,
        "idempotency_record_count": 50,
        "latest_records": history_records,
        "history_records": history_records,
        "idempotency_records": idempotency_payload,
    }
    runtime_fingerprints = {
        "cpu": hashlib.sha256(b"cpu-runtime").hexdigest(),
        "gpu": hashlib.sha256(b"gpu-runtime").hexdigest(),
    }
    profiles = {
        "cpu": "cpu-profile",
        "gpu": "gpu-profile",
    }
    runtime_set_sha256 = qualified_runtime_set_sha256(
        tuple(
            {
                "profile_id": profiles[runtime_kind],
                "runtime_fingerprint": (
                    runtime_fingerprints[runtime_kind]
                ),
                "runtime_kind": runtime_kind,
            }
            for runtime_kind in ("cpu", "gpu")
        )
    )
    application_build_sha256 = hashlib.sha256(
        b"application-build"
    ).hexdigest()
    composition_sha256 = hashlib.sha256(
        b"composition"
    ).hexdigest()
    pipeline_contract_sha256 = _canonical_sha256(
        {
            "application_build_sha256": application_build_sha256,
            "evaluator_version": (
                "dahe.loop7.candidate-development-ocr.v1"
            ),
            "ocr_composition_evidence_sha256": composition_sha256,
            "ocr_protocol_version": 1,
            "purpose": "candidate_review_development_ocr",
            "runtime_set_sha256": runtime_set_sha256,
        }
    )
    pipelines = {
        runtime_kind: _canonical_sha256(
            {
                "pipeline_contract_fingerprint": (
                    pipeline_contract_sha256
                ),
                "profile_id": profiles[runtime_kind],
                "runtime_fingerprint": (
                    runtime_fingerprints[runtime_kind]
                ),
                "runtime_kind": runtime_kind,
            }
        )
        for runtime_kind in ("cpu", "gpu")
    }
    attempts: list[dict[str, object]] = []
    comparisons: list[dict[str, object]] = []
    for image in copied:
        image_sha256 = str(image["image_sha256"])
        role, orientation = truth_by_image[image_sha256]
        by_runtime: dict[str, dict[str, object]] = {}
        for runtime_kind in ("cpu", "gpu"):
            attempt = _candidate_attempt(
                result=_candidate_ocr_result(
                    image_sha256=image_sha256,
                    role=role,
                    orientation=orientation,
                    runtime_kind=runtime_kind,
                    runtime_fingerprint=(
                        runtime_fingerprints[runtime_kind]
                    ),
                ),
                runtime_kind=runtime_kind,
                profile_id=profiles[runtime_kind],
                pipeline_fingerprint=pipelines[runtime_kind],
            )
            attempts.append(attempt)
            by_runtime[runtime_kind] = attempt
        differences = [
            section
            for section in (
                "fields",
                "role_input",
                "role_observation",
            )
            if by_runtime["cpu"][section]
            != by_runtime["gpu"][section]
        ]
        comparisons.append(
            {
                "comparison_status": (
                    "different" if differences else "same"
                ),
                "difference_sections": differences,
                "image_sha256": image_sha256,
                "runtime_output_sha256s": {
                    runtime_kind: by_runtime[runtime_kind][
                        "business_output_sha256"
                    ]
                    for runtime_kind in ("cpu", "gpu")
                },
            }
        )
    payload: dict[str, object] = {
        "application_build_sha256": application_build_sha256,
        "copied_image_set_sha256": _canonical_sha256(copied),
        "copied_images": copied,
        "development_only": True,
        "evaluator_version": "dahe.loop7.candidate-development-ocr.v1",
        "factory_qualification": {
            "composition_evidence_sha256": composition_sha256,
            "runtime_identities": [
                {
                    "profile_id": profiles[runtime_kind],
                    "runtime_fingerprint": (
                        runtime_fingerprints[runtime_kind]
                    ),
                    "runtime_kind": runtime_kind,
                }
                for runtime_kind in ("cpu", "gpu")
            ],
            "runtime_set_sha256": runtime_set_sha256,
        },
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "generated_at": "2026-07-26T01:00:00+00:00",
        "kind": "candidate_review_development_ocr_evidence",
        "pipeline_contract_sha256": pipeline_contract_sha256,
        "reviewer_id": "operator-a",
        "runtime_attempts": attempts,
        "runtime_comparisons": comparisons,
        "schema_version": 1,
        "source": {
            "manifest_payload": formal_export.manifest_payload,
            "manifest_sha256": formal_export.manifest_sha256,
            "package_id": package.package_id,
            "package_sha256": package.canonical_sha256,
            "quality_coverage_payload": (
                formal_export.quality_coverage_payload
            ),
            "quality_coverage_sha256": (
                formal_export.quality_coverage_sha256
            ),
            "record_set_sha256": formal_export.record_set_sha256,
            "review_history_authority_payload": history_payload,
            "review_history_authority_sha256": _canonical_sha256(
                history_payload
            ),
            "source_authority_payload": source_authority,
            "source_authority_sha256": (
                formal_export.source_authority_sha256
            ),
        },
        "status": "completed_with_runtime_differences",
        "technical_failure_count": 0,
    }
    evidence_sha256 = _canonical_sha256(payload)
    payload["evidence_sha256"] = evidence_sha256
    evidence_path = (
        protected_root
        / "records"
        / "sha256"
        / evidence_sha256[:2]
        / evidence_sha256[2:4]
        / f"{evidence_sha256}.json"
    )
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return data_root, evidence_path, evidence_sha256, content_by_key


@contextmanager
def _authorized_run_repository(
    *,
    data_root: Path,
    evidence_path: Path,
    project_root: Path,
    instance_id: str,
) -> Iterator[
    tuple[
        SqliteRuntime,
        SqliteCandidateDevelopmentOcrRunRepository,
    ]
]:
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=instance_id,
    )
    try:
        repository = SqliteCandidateDevelopmentOcrRunRepository(
            runtime=runtime
        )
        record_candidate_development_ocr_run_authority(
            repository,
            data_root=data_root,
            evidence_path=evidence_path,
        )
        yield runtime, repository
    finally:
        runtime.close()


def _definition() -> TemplateDefinition:
    return TemplateDefinition(
        family_id="candidate-loading-family",
        name="Candidate loading ticket",
        role=TicketRole.LOADING,
        anchors=(
            TemplateAnchor(
                anchor_id="loading-title",
                expected_text="装货磅单",
                box=NormalizedRect(
                    x=Decimal("0.10"),
                    y=Decimal("0.05"),
                    width=Decimal("0.35"),
                    height=Decimal("0.10"),
                ),
                required=True,
                weight=Decimal("1"),
                max_edit_distance=Decimal("0.15"),
                loading_evidence=Decimal("0.8"),
                unloading_evidence=Decimal("-0.2"),
                match_kind=AnchorMatchKind.LITERAL,
            ),
        ),
        regions=(
            RecognitionRegion(
                region_id="ordinary-net",
                field=TicketField.ORDINARY_NET,
                box=NormalizedRect(
                    x=Decimal("0.55"),
                    y=Decimal("0.55"),
                    width=Decimal("0.30"),
                    height=Decimal("0.12"),
                ),
                relative_to_anchor_id=None,
                unit="t",
                format_pattern=r"^\d{1,3}(?:\.\d{1,2})?$",
                required=True,
                layout_scope="full_ticket",
            ),
        ),
    )


def test_loads_only_a_known_human_confirmed_role_from_protected_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root, evidence_path, evidence_sha256, content_by_key = (
        _protected_evidence(tmp_path)
    )

    with _authorized_run_repository(
        data_root=data_root,
        evidence_path=evidence_path,
        project_root=project_root,
        instance_id="candidate-source-load",
    ) as (_, run_repository):
        source = load_candidate_development_template_source(
            run_repository=run_repository,
            data_root=data_root,
            evidence_path=evidence_path,
            expected_evidence_sha256=evidence_sha256,
            sample_id="L7-002",
            submitted_slot="loading",
            expected_role="loading",
        )

    assert source.sample_id == "L7-002"
    assert source.submitted_slot == "loading"
    assert source.confirmed_role.value == "loading"
    assert source.source_image_content == content_by_key[
        ("L7-002", "loading")
    ]
    assert source.source_image_media_type == "image/png"
    assert len(source.waybill_identity_sha256) == 64
    assert source.candidate_evidence_sha256 == evidence_sha256
    assert source.candidate_record_content == evidence_path.read_bytes()


def test_rejects_completed_evidence_without_persisted_run_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root, evidence_path, evidence_sha256, _ = _protected_evidence(
        tmp_path
    )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="candidate-source-missing-authority",
    )
    try:
        with pytest.raises(
            CandidateTemplateSeedError,
            match="authority does not exist",
        ):
            load_candidate_development_template_source(
                run_repository=(
                    SqliteCandidateDevelopmentOcrRunRepository(
                        runtime=runtime
                    )
                ),
                data_root=data_root,
                evidence_path=evidence_path,
                expected_evidence_sha256=evidence_sha256,
                sample_id="L7-002",
                submitted_slot="loading",
                expected_role="loading",
            )
    finally:
        runtime.close()


def test_rejects_unknown_non_ticket_and_expected_role_mismatch(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root, evidence_path, evidence_sha256, _ = _protected_evidence(
        tmp_path
    )

    with _authorized_run_repository(
        data_root=data_root,
        evidence_path=evidence_path,
        project_root=project_root,
        instance_id="candidate-source-role-rejection",
    ) as (_, run_repository):
        with pytest.raises(
            CandidateTemplateSeedError,
            match="unknown or non-ticket",
        ):
            load_candidate_development_template_source(
                run_repository=run_repository,
                data_root=data_root,
                evidence_path=evidence_path,
                expected_evidence_sha256=evidence_sha256,
                sample_id="L7-001",
                submitted_slot="loading",
                expected_role="loading",
            )
        with pytest.raises(
            CandidateTemplateSeedError,
            match="does not match",
        ):
            load_candidate_development_template_source(
                run_repository=run_repository,
                data_root=data_root,
                evidence_path=evidence_path,
                expected_evidence_sha256=evidence_sha256,
                sample_id="L7-002",
                submitted_slot="loading",
                expected_role="unloading",
            )


def test_rehashes_protected_source_images_and_rejects_tampering(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root, evidence_path, evidence_sha256, _ = _protected_evidence(
        tmp_path
    )
    with _authorized_run_repository(
        data_root=data_root,
        evidence_path=evidence_path,
        project_root=project_root,
        instance_id="candidate-source-tamper",
    ) as (_, run_repository):
        payload = json.loads(
            evidence_path.read_text(encoding="utf-8")
        )
        selected = payload["copied_images"][0]
        selected_path = data_root / selected["relative_path"]
        selected_path.write_bytes(b"changed")

        with pytest.raises(
            CandidateTemplateSeedError,
            match=r"image|evidence",
        ):
            load_candidate_development_template_source(
                run_repository=run_repository,
                data_root=data_root,
                evidence_path=evidence_path,
                expected_evidence_sha256=evidence_sha256,
                sample_id="L7-002",
                submitted_slot="loading",
                expected_role="loading",
            )


def test_normalizes_masks_and_persists_a_candidate_sourced_draft(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root, evidence_path, evidence_sha256, _ = _protected_evidence(
        tmp_path
    )
    with _authorized_run_repository(
        data_root=data_root,
        evidence_path=evidence_path,
        project_root=project_root,
        instance_id="candidate-template-seed",
    ) as (runtime, run_repository):
        source = load_candidate_development_template_source(
            run_repository=run_repository,
            data_root=data_root,
            evidence_path=evidence_path,
            expected_evidence_sha256=evidence_sha256,
            sample_id="L7-002",
            submitted_slot="loading",
            expected_role="loading",
        )
        repository = SqliteTemplateRepository(
            runtime=runtime,
            accepted_build_fingerprint="8" * 64,
            accepted_runtime_fingerprint="9" * 64,
            accepted_development_manifest_sha256="4" * 64,
            accepted_matcher_fingerprint="6" * 64,
            accepted_policy_fingerprint="7" * 64,
        )
        first = seed_candidate_development_template(
            repository,
            definition=_definition(),
            source=source,
            actor_id="developer-a",
            idempotency_key="candidate-template-seed-1",
        )
        replay = seed_candidate_development_template(
            repository,
            definition=_definition(),
            source=source,
            actor_id="developer-a",
            idempotency_key="candidate-template-seed-1",
        )

        assert first.created is True
        assert replay.created is False
        assert replay.version.version_id == first.version.version_id
        assert first.origin.candidate_evidence_sha256 == evidence_sha256
        assert first.origin.source_image_sha256 == (
            source.source_image_sha256
        )
        current = repository.get_family_current(
            first.version.definition.family_id
        )
        assert current.reference_image_width == 32
        assert current.reference_image_height == 24
        assert current.reference_mask_sha256 != (
            current.reference_image_sha256
        )


def test_definition_loader_rejects_noncanonical_or_extra_fields(
    tmp_path: Path,
) -> None:
    from dahe.adapters.sqlite.template_studio import (
        serialize_template_definition,
    )

    definition_path = (tmp_path / "template.json").resolve()
    canonical = serialize_template_definition(_definition())
    definition_path.write_text(
        json.dumps(canonical, ensure_ascii=False),
        encoding="utf-8",
    )
    assert load_template_definition(definition_path) == _definition()

    canonical["unexpected"] = True
    definition_path.write_text(
        json.dumps(canonical, ensure_ascii=False),
        encoding="utf-8",
    )
    with pytest.raises(
        CandidateTemplateSeedError,
        match="contract",
    ):
        load_template_definition(definition_path)
