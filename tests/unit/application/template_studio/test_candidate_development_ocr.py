from __future__ import annotations

import hashlib
import json
import time
from decimal import Decimal
from pathlib import Path

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
from dahe.application.template_studio.candidate_development_ocr import (
    CandidateDevelopmentOcrError,
    _CopiedImage,
    _execute_image,
    run_candidate_development_ocr_evaluation,
)
from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewFormalExport,
    build_candidate_review_formal_export,
)
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrFormalAuthority,
    OcrImageExecution,
    OcrImageExecutionError,
    OcrImageWork,
    OcrRuntimeIdentity,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImage,
    LockedSetReviewItem,
    LockedSetReviewPackage,
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


def _sha256(value: int) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()


def _image_conditions(sample_index: int, slot: str) -> list[str]:
    explicit = {
        (1, "loading"): ["rotation_0", "printed", "non_ticket"],
        (1, "unloading"): ["rotation_90", "screen", "unknown_layout"],
        (2, "loading"): ["blur", "rotation_180", "printed"],
        (2, "unloading"): ["crop", "rotation_270", "screen"],
        (3, "loading"): ["glare", "rotation_0", "printed"],
    }
    return explicit.get(
        (sample_index, slot),
        ["rotation_0", "printed" if slot == "loading" else "screen"],
    )


def _review_authority(
    tmp_path: Path,
) -> tuple[
    LockedSetReviewPackage,
    LockedSetReviewAuthoritySnapshot,
    CandidateReviewFormalExport,
]:
    review_root = tmp_path / "review-data" / "locked-set-review"
    image_root = review_root / "images"
    image_root.mkdir(parents=True)
    items: list[LockedSetReviewItem] = []
    records: list[LockedSetReviewRecord] = []
    images_by_sha256: dict[str, LockedSetReviewImage] = {}

    for sample_index in range(1, 51):
        sample_id = f"L7-{sample_index:03d}"
        package_images: list[LockedSetReviewImage] = []
        review_images: list[dict[str, object]] = []
        for slot_index, slot in enumerate(("loading", "unloading")):
            image_index = (sample_index - 1) * 2 + slot_index + 1
            content = f"candidate-review-image-{image_index:03d}".encode()
            digest = hashlib.sha256(content).hexdigest()
            path = image_root / f"{digest}.jpg"
            path.write_bytes(content)
            image = LockedSetReviewImage(
                submitted_slot=slot,
                image_sha256=digest,
                relative_path=f"images/{digest}.jpg",
                path=path,
                width=1000,
                height=700,
                media_type="image/jpeg",
                selection_clues=(),
            )
            package_images.append(image)
            images_by_sha256[digest] = image
            role = "unknown" if sample_index == 1 else slot
            review_images.append(
                {
                    "submitted_slot": slot,
                    "role": role,
                    "ordinary_net": (
                        None if role == "unknown" else "31.25" if slot == "loading" else "31.20"
                    ),
                    "quality_conditions": _image_conditions(sample_index, slot),
                    "notes": None,
                }
            )
        items.append(
            LockedSetReviewItem(
                sample_id=sample_id,
                candidate_id=f"candidate-{sample_index:03d}",
                waybill_identity_sha256=_sha256(10_000 + sample_index),
                position=sample_index,
                selection_clues=(),
                images=(package_images[0], package_images[1]),
            )
        )
        timestamp = f"2026-07-26T00:{sample_index:02d}:00+00:00"
        payload: dict[str, object] = {
            "reviewer_id": "operator-a",
            "decision": "confirmed",
            "images": review_images,
            "pair_conditions": (["pair_unknown"] if sample_index == 1 else ["normal_pair"]),
            "pair_notes": None,
            "replace_reason": None,
        }
        records.append(
            LockedSetReviewRecord(
                sample_id=sample_id,
                review_status="confirmed",
                decision="confirmed",
                review_payload=payload,
                record_version=1,
                created_at=timestamp,
                updated_at=timestamp,
            )
        )

    item_tuple = tuple(items)
    package = LockedSetReviewPackage(
        package_id="candidate-review-fixture",
        canonical_sha256=_canonical_sha256({"package": "candidate-review-fixture"}),
        review_root=review_root,
        items=item_tuple,
        items_by_sample_id={item.sample_id: item for item in item_tuple},
        images_by_sha256=images_by_sha256,
    )
    record_tuple = tuple(records)
    authority_payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "locked_set_review_authority_snapshot",
        "package_sha256": package.canonical_sha256,
        "sample_count": 50,
        "latest_record_count": 50,
        "history_record_count": 50,
        "idempotency_record_count": 50,
    }
    authority = LockedSetReviewAuthoritySnapshot(
        package_sha256=package.canonical_sha256,
        latest_records=record_tuple,
        history_records=record_tuple,
        idempotency_records=tuple(
            LockedSetReviewIdempotencyRecord(
                idempotency_key=f"review-{index:03d}",
                sample_id=record.sample_id,
                request_hash=_sha256(30_000 + index),
                resulting_record_version=1,
                created_at=record.created_at,
            )
            for index, record in enumerate(record_tuple, start=1)
        ),
        payload=authority_payload,
        canonical_sha256=_canonical_sha256(authority_payload),
    )
    review_export = build_candidate_review_formal_export(
        package=package,
        records=authority.latest_records,
        configured_reviewer_id="operator-a",
        dataset_id="candidate-review-development-source",
    )
    return package, authority, review_export


class _Gateway:
    def __init__(
        self,
        runtime_kind: str,
        *,
        differing_image_sha256: str | None = None,
        failing_image_sha256: str | None = None,
        delay_seconds: float = 0,
    ) -> None:
        self.identity = OcrRuntimeIdentity(
            runtime_kind=runtime_kind,  # type: ignore[arg-type]
            profile_id=f"{runtime_kind}-fixture",
            runtime_fingerprint=_sha256(20_000 if runtime_kind == "cpu" else 20_001),
        )
        self.differing_image_sha256 = differing_image_sha256
        self.failing_image_sha256 = failing_image_sha256
        self.delay_seconds = delay_seconds
        self.calls: list[OcrImageWork] = []

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        self.calls.append(image)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if image.image_sha256 == self.failing_image_sha256:
            raise OcrImageExecutionError(
                "worker_crashed",
                "OCR-DEVELOPMENT-FIXTURE-FAILURE",
                "synthetic runtime failure",
            )
        text = (
            f"{self.identity.runtime_kind}-different"
            if image.image_sha256 == self.differing_image_sha256
            else "装货磅单"
        )
        result = OcrResult(
            command_id=f"{self.identity.runtime_kind}-command",
            status=OcrResultStatus.OK,
            worker_identity=f"{self.identity.runtime_kind}-worker",
            runtime_fingerprint=self.identity.runtime_fingerprint,
            verified_image_sha256=image.image_sha256,
            elapsed_ms=2.5 if self.identity.runtime_kind == "gpu" else 8.5,
            text_lines=(
                OcrTextLine(
                    text=text,
                    confidence=Decimal("0.98"),
                    box=NormalizedBox(
                        x=Decimal("0.1"),
                        y=Decimal("0.1"),
                        width=Decimal("0.3"),
                        height=Decimal("0.1"),
                    ),
                ),
            ),
            fields={
                "ordinary_net": OcrFieldValue(
                    raw_text="31.25",
                    amount="31.25",
                    unit="t",
                    confidence=Decimal("0.97"),
                )
            },
            role_observation=OcrRoleObservation(
                fixed_text=("装货", "磅单"),
                layout_fingerprint="candidate-development-layout",
                orientation_degrees=0,
            ),
            error=None,
        )
        result_payload = result.model_dump(mode="json")
        output_json = json.dumps(
            result_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return OcrImageExecution(
            image_sha256=image.image_sha256,
            output_json=output_json,
            output_fingerprint=build_ocr_output_fingerprint(
                image_sha256=image.image_sha256,
                fields=result_payload["fields"],
                role_observation=result_payload["role_observation"],
                text_lines=result_payload["text_lines"],
                verified_image_sha256=image.image_sha256,
                pipeline_fingerprint=pipeline_fingerprint,
                profile_id=self.identity.profile_id,
                runtime_fingerprint=self.identity.runtime_fingerprint,
                runtime_kind=self.identity.runtime_kind,
            ),
        )

    def close(self) -> None:
        return


def _qualified_backend(
    tmp_path: Path,
    *,
    data_root: Path,
    differing_image_sha256: str | None = None,
    failing_cpu_image_sha256: str | None = None,
    cpu_delay_seconds: float = 0,
    gpu_delay_seconds: float = 0,
) -> tuple[AsyncOcrExecutionBackend, _Gateway, _Gateway]:
    repository_root = tmp_path / "repository"
    repository_root.mkdir(exist_ok=True)
    cpu = _Gateway(
        "cpu",
        differing_image_sha256=differing_image_sha256,
        failing_image_sha256=failing_cpu_image_sha256,
        delay_seconds=cpu_delay_seconds,
    )
    gpu = _Gateway(
        "gpu",
        differing_image_sha256=differing_image_sha256,
        delay_seconds=gpu_delay_seconds,
    )
    identities = tuple(
        sorted(
            (cpu.identity, gpu.identity),
            key=lambda item: item.runtime_kind,
        )
    )
    authority = OcrFormalAuthority._from_verified_composition(
        data_root=data_root.resolve(strict=True),
        repository_root=repository_root.resolve(strict=True),
        runtime_identities=identities,
        composition_evidence_sha256=_sha256(21_000),
    )
    backend = AsyncOcrExecutionBackend._from_verified_composition(
        primary_runtime_kind="gpu",
        gateways={"cpu": cpu, "gpu": gpu},
        formal_authority=authority,
    )
    return backend, cpu, gpu


def test_runtime_wall_latency_is_recorded_when_each_runtime_finishes(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    backend, _, _ = _qualified_backend(
        tmp_path,
        data_root=data_root,
        cpu_delay_seconds=0.08,
        gpu_delay_seconds=0.005,
    )
    try:
        attempts, timed_out = _execute_image(
            backend=backend,
            image=_CopiedImage(
                image_sha256=_sha256(88_001),
                relative_path="development/test-image.blob",
                byte_size=1,
                media_type="image/jpeg",
            ),
            pipeline_fingerprints={
                "cpu": _sha256(88_002),
                "gpu": _sha256(88_003),
            },
            timeout_seconds=1,
        )
    finally:
        backend.close()

    by_runtime = {str(attempt["runtime_kind"]): attempt for attempt in attempts}
    assert timed_out is False
    assert float(by_runtime["gpu"]["wall_elapsed_ms"]) < 40
    assert float(by_runtime["cpu"]["wall_elapsed_ms"]) >= 60


def test_copies_verified_images_and_records_redacted_dual_runtime_development_evidence(
    tmp_path: Path,
) -> None:
    package, authority, review_export = _review_authority(tmp_path)
    target = tmp_path / "development-data"
    target.mkdir()
    differing_hash = sorted(package.images_by_sha256)[0]
    backend, cpu, gpu = _qualified_backend(
        tmp_path,
        data_root=target,
        differing_image_sha256=differing_hash,
    )
    try:
        result = run_candidate_development_ocr_evaluation(
            package=package,
            authority=authority,
            review_export=review_export,
            backend=backend,
            data_root=target.resolve(),
            reviewer_id="operator-a",
            application_build_sha256=_sha256(22_000),
            timeout_seconds=2,
        )
    finally:
        backend.close()

    assert result.status == "completed_with_runtime_differences"
    assert result.technical_failure_count == 0
    assert result.runtime_difference_count == 1
    assert len(cpu.calls) == len(gpu.calls) == 100
    assert {field.name for field in OcrImageWork.__dataclass_fields__.values()} == {
        "image_sha256",
        "relative_path",
    }
    assert all(
        call.relative_path.startswith("development/protected-candidate-review-ocr/evidence/sha256/")
        for call in (*cpu.calls, *gpu.calls)
    )
    assert all("loading" not in call.relative_path for call in (*cpu.calls, *gpu.calls))

    summary = result.summary_payload
    assert summary["development_only"] is True
    assert summary["formal_accuracy_claim"] is False
    assert summary["formal_release_eligible"] is False
    assert summary["image_count"] == 100
    assert summary["runtime_execution_count"] == 200
    assert summary["runtime_difference_count"] == 1
    assert summary["technical_failure_count"] == 0
    summary_text = json.dumps(summary, ensure_ascii=False, sort_keys=True)
    for forbidden in (
        "operator-a",
        "L7-001",
        "ordinary_net",
        "quality_conditions",
        "装货磅单",
        "31.25",
        "relative_path",
    ):
        assert forbidden not in summary_text

    assert result.evidence_path.is_file()
    assert result.evidence_path.is_relative_to(target)
    evidence = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert evidence["development_only"] is True
    assert evidence["formal_accuracy_claim"] is False
    assert evidence["source"]["manifest_payload"]["waybills"][0]["images"][0]["role"] == ("unknown")
    assert len(evidence["copied_images"]) == 100
    assert len(evidence["runtime_attempts"]) == 200
    assert len(evidence["runtime_comparisons"]) == 100
    first_success = next(
        item for item in evidence["runtime_attempts"] if item["status"] == "succeeded"
    )
    assert first_success["fields"]["ordinary_net"]["amount"] == "31.25"
    assert first_success["role_input"]["text_lines"][0]["text"]
    assert first_success["role_input"]["fixed_text"] == ["装货", "磅单"]
    assert "ordinary_net_reliable" not in first_success["role_input"]
    assert first_success["worker_elapsed_ms"] in {2.5, 8.5}
    assert len(first_success["raw_output_sha256"]) == 64
    assert len(first_success["business_output_sha256"]) == 64
    assert evidence["evidence_sha256"] == result.evidence_sha256


def test_runtime_difference_is_recorded_but_technical_failure_fails_the_evaluation(
    tmp_path: Path,
) -> None:
    package, authority, review_export = _review_authority(tmp_path)
    target = tmp_path / "development-data"
    target.mkdir()
    hashes = sorted(package.images_by_sha256)
    backend, _, _ = _qualified_backend(
        tmp_path,
        data_root=target,
        differing_image_sha256=hashes[0],
        failing_cpu_image_sha256=hashes[1],
    )
    try:
        result = run_candidate_development_ocr_evaluation(
            package=package,
            authority=authority,
            review_export=review_export,
            backend=backend,
            data_root=target.resolve(),
            reviewer_id="operator-a",
            application_build_sha256=_sha256(22_001),
            timeout_seconds=2,
        )
    finally:
        backend.close()

    assert result.status == "failed"
    assert result.technical_failure_count == 1
    assert result.runtime_difference_count == 1
    assert result.summary_payload["status"] == "failed"
    assert result.summary_payload["formal_accuracy_claim"] is False
    evidence = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    failures = [item for item in evidence["runtime_attempts"] if item["status"] == "failed"]
    assert len(failures) == 1
    assert failures[0]["diagnostic_code"] == "OCR-DEVELOPMENT-FIXTURE-FAILURE"


def test_rejects_unqualified_or_wrong_root_backend_before_copying_images(
    tmp_path: Path,
) -> None:
    package, authority, review_export = _review_authority(tmp_path)
    target = tmp_path / "development-data"
    target.mkdir()
    cpu = _Gateway("cpu")
    gpu = _Gateway("gpu")
    unqualified = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"cpu": cpu, "gpu": gpu},
    )
    try:
        with pytest.raises(CandidateDevelopmentOcrError, match="factory-qualified"):
            run_candidate_development_ocr_evaluation(
                package=package,
                authority=authority,
                review_export=review_export,
                backend=unqualified,
                data_root=target.resolve(),
                reviewer_id="operator-a",
                application_build_sha256=_sha256(22_002),
                timeout_seconds=2,
            )
    finally:
        unqualified.close()

    assert cpu.calls == gpu.calls == []
    assert not (target / "development").exists()

    other_target = tmp_path / "other-data"
    other_target.mkdir()
    backend, cpu, gpu = _qualified_backend(tmp_path, data_root=other_target)
    try:
        with pytest.raises(CandidateDevelopmentOcrError, match="data root"):
            run_candidate_development_ocr_evaluation(
                package=package,
                authority=authority,
                review_export=review_export,
                backend=backend,
                data_root=target.resolve(),
                reviewer_id="operator-a",
                application_build_sha256=_sha256(22_003),
                timeout_seconds=2,
            )
    finally:
        backend.close()
    assert cpu.calls == gpu.calls == []


def test_revalidates_review_image_bytes_before_any_development_copy(
    tmp_path: Path,
) -> None:
    package, authority, review_export = _review_authority(tmp_path)
    changed = next(iter(package.images_by_sha256.values()))
    changed.path.write_bytes(b"changed-after-review")
    target = tmp_path / "development-data"
    target.mkdir()
    backend, cpu, gpu = _qualified_backend(tmp_path, data_root=target)
    try:
        with pytest.raises(CandidateDevelopmentOcrError, match="image integrity"):
            run_candidate_development_ocr_evaluation(
                package=package,
                authority=authority,
                review_export=review_export,
                backend=backend,
                data_root=target.resolve(),
                reviewer_id="operator-a",
                application_build_sha256=_sha256(22_004),
                timeout_seconds=2,
            )
    finally:
        backend.close()

    assert cpu.calls == gpu.calls == []
    assert not (target / "development").exists()
