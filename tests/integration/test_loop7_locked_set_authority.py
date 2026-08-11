from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from PIL import Image
from sqlalchemy import text

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.sqlite.locked_set import (
    LockedSetConflictError,
    LockedSetIdempotencyConflictError,
    LockedSetInventoryChangedError,
    LockedSetInventoryEvidenceMissingError,
    LockedSetInventoryFingerprintIncompleteError,
    LockedSetPersistenceError,
    LockedSetRecordVersionConflictError,
    LockedSetStateTransitionError,
    SqliteLockedSetRepository,
    register_exclusion_identity,
    require_current_preflight_authority,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.formal_locked_set_release import (
    FormalLockedSetReleaseError,
    complete_existing_exclusion_fingerprints,
)
from dahe.application.template_studio.locked_set_evidence import (
    stage_locked_set_evidence,
)
from dahe.application.template_studio.locked_set_release import (
    LockedSetReleaseService,
)
from dahe.domain.audit.evidence import (
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import TicketRole, assess_ticket_roles
from dahe.maintenance.backup import SqliteBackupService
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildSource,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
)
from dahe.verification.locked_set import LockedSetManifest
from dahe.verification.locked_set_acceptance import (
    build_locked_set_derived_adversarial_suite,
    evaluate_locked_set_release,
    locked_set_quality_coverage_sha256,
    quality_review_evidence_sha256,
)
from dahe.verification.locked_set_runner import RUNNER_VERSION
from tests.fixtures.formal_development_authority import (
    formal_development_authority,
)


class InjectedLockedSetFailure(RuntimeError):
    pass


def _runtime(
    data_root: Path,
    project_root: Path,
    *,
    instance_id: str,
) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=instance_id,
    )


def _repository(
    runtime: SqliteRuntime,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> SqliteLockedSetRepository:
    return SqliteLockedSetRepository(runtime=runtime, failpoint=failpoint)


def _manifest_payload(dataset_id: str) -> dict[str, object]:
    waybills: list[dict[str, object]] = []
    for index in range(50):
        loading_number = index * 2 + 1
        unloading_number = index * 2 + 2
        loading_role = "loading"
        unloading_role = "unloading"
        if index == 0:
            loading_role = "unloading"
            unloading_role = "loading"
        elif index == 1:
            unloading_role = "loading"
        elif index == 2:
            loading_role = "unknown"
            unloading_role = "unknown"
        waybills.append(
            {
                "sample_id": f"{dataset_id}-waybill-{index + 1:03d}",
                "waybill_identity_sha256": hashlib.sha256(
                    f"{dataset_id}:source-waybill:{index + 1}".encode()
                ).hexdigest(),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": f"{loading_number:064x}",
                        "relative_path": f"images/{loading_number:03d}.png",
                        "submitted_slot": "loading",
                        "role": loading_role,
                        "ordinary_net": (None if loading_role == "unknown" else "30.00"),
                    },
                    {
                        "image_sha256": f"{unloading_number:064x}",
                        "relative_path": f"images/{unloading_number:03d}.png",
                        "submitted_slot": "unloading",
                        "role": unloading_role,
                        "ordinary_net": (None if unloading_role == "unknown" else "29.98"),
                    },
                ],
            }
        )
    return {
        "schema_version": 1,
        "dataset_id": dataset_id,
        "dataset_kind": "locked",
        "tuning_prohibited": True,
        "waybills": waybills,
    }


def _write_sealed_fixture(
    root: Path,
    *,
    dataset_id: str,
) -> tuple[Path, Path]:
    dataset_root = root / dataset_id
    payload = _manifest_payload(dataset_id)
    waybills = payload["waybills"]
    assert isinstance(waybills, list)
    for waybill in waybills:
        assert isinstance(waybill, dict)
        images = waybill["images"]
        assert isinstance(images, list)
        for image in images:
            assert isinstance(image, dict)
            relative_path = image["relative_path"]
            assert isinstance(relative_path, str)
            content = f"synthetic contract fixture:{dataset_id}:{relative_path}".encode()
            target = dataset_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            image["image_sha256"] = hashlib.sha256(content).hexdigest()
    manifest_path = dataset_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_path, dataset_root


def _scalar(runtime: SqliteRuntime, statement: str) -> Any:
    with runtime.engine.connect() as connection:
        return connection.execute(text(statement)).scalar_one()


def _fingerprintable_png_bytes(
    *,
    color: tuple[int, int, int] = (30, 90, 150),
) -> bytes:
    output = BytesIO()
    Image.new("RGB", (24, 18), color).save(output, format="PNG")
    return output.getvalue()


def _register_evidence_backed_exclusion(
    runtime: SqliteRuntime,
    *,
    evidence_store: ContentAddressedEvidenceStore,
    source_id: str,
    registered_relative_path: str | None = None,
) -> str:
    stored = evidence_store.put_bytes(
        _fingerprintable_png_bytes(),
        media_type="image/png",
    )
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            text(
                """
                INSERT INTO evidence_blobs (
                    sha256, relative_path, byte_size, media_type,
                    storage_state, record_version, created_at, verified_at
                ) VALUES (
                    :sha256, :relative_path, :byte_size, :media_type,
                    'available', 1, :created_at, :created_at
                )
                """
            ),
            {
                "sha256": stored.sha256,
                "relative_path": (
                    registered_relative_path
                    if registered_relative_path is not None
                    else stored.relative_path
                ),
                "byte_size": stored.byte_size,
                "media_type": stored.media_type,
                "created_at": "2026-07-27T00:00:00+00:00",
            },
        )
        register_exclusion_identity(
            connection,
            category="development_image",
            identity_sha256=stored.sha256,
            source_kind="evidence_fixture",
            source_id=source_id,
            created_at="2026-07-27T00:00:00+00:00",
        )
    return stored.sha256


def _formal_report_payloads(
    runtime: SqliteRuntime,
    dataset_id: str,
) -> tuple[dict[str, object], dict[str, object]]:
    with runtime.engine.connect() as connection:
        row = (
            connection.execute(
                text(
                    """
                    SELECT runner_report_json, committed_report_json
                    FROM locked_set_formal_evaluations
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {"dataset_id": dataset_id},
            )
            .mappings()
            .one()
        )
    runner = json.loads(str(row["runner_report_json"]))
    committed = json.loads(str(row["committed_report_json"]))
    assert isinstance(runner, dict)
    assert isinstance(committed, dict)
    return runner, committed


def _replace_formal_report_payloads(
    runtime: SqliteRuntime,
    dataset_id: str,
    *,
    runner_report: dict[str, object],
    committed_report: dict[str, object],
    gate_passed: bool | None = None,
    formal_accuracy_claim: bool | None = None,
) -> None:
    runner = dict(runner_report)
    committed = dict(committed_report)
    runner["runner_report_sha256"] = _canonical_sha256(
        {field: value for field, value in runner.items() if field != "runner_report_sha256"}
    )
    committed["runner_report_sha256"] = runner["runner_report_sha256"]
    runner_json = _canonical_json(runner)
    committed_json = _canonical_json(committed)
    committed_sha256 = hashlib.sha256(committed_json.encode("utf-8")).hexdigest()
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            text(
                """
                UPDATE locked_set_formal_evaluations
                SET evaluation_id = :evaluation_id,
                    runner_report_json = :runner_report_json,
                    runner_report_sha256 = :runner_report_sha256,
                    committed_report_json = :committed_report_json,
                    committed_report_sha256 = :committed_report_sha256,
                    gate_passed = COALESCE(:gate_passed, gate_passed),
                    formal_accuracy_claim = COALESCE(
                        :formal_accuracy_claim,
                        formal_accuracy_claim
                    )
                WHERE dataset_id = :dataset_id
                """
            ),
            {
                "dataset_id": dataset_id,
                "evaluation_id": committed_sha256,
                "runner_report_json": runner_json,
                "runner_report_sha256": runner["runner_report_sha256"],
                "committed_report_json": committed_json,
                "committed_report_sha256": committed_sha256,
                "gate_passed": (None if gate_passed is None else int(gate_passed)),
                "formal_accuracy_claim": (
                    None if formal_accuracy_claim is None else int(formal_accuracy_claim)
                ),
            },
        )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _application_build_manifest() -> ApplicationBuildManifest:
    return ApplicationBuildManifest(
        application_version="test-build",
        sources=(
            ApplicationBuildSource(
                path="adapters/sqlite/locked_set.py",
                sha256="1" * 64,
            ),
        ),
    )


def _sha256(index: int) -> str:
    return f"{index:064x}"


def _probe_fingerprints(
    manifest: LockedSetManifest,
) -> tuple[ImagePerceptualFingerprint, ...]:
    return tuple(
        _fingerprint_for_hash(image.image_sha256, index=index)
        for index, image in enumerate(
            (image for waybill in manifest.waybills for image in waybill.images),
            start=1,
        )
    )


def _fingerprint_for_hash(
    sha256: str,
    *,
    index: int,
) -> ImagePerceptualFingerprint:
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=sha256,
        width=100 + index,
        height=200 + index,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop_permille,
                average_hash=f"{index + offset:064x}"[-64:],
                difference_hash=f"{index + offset + 1000:064x}"[-64:],
            )
            for offset, crop_permille in enumerate((1000, 920, 840, 760))
        ),
    )


def _similarity_scan(
    *,
    dataset_id: str,
    manifest_sha256: str,
    exclusion_snapshot_sha256: str,
    excluded_image_count: int,
    probes: Sequence[ImagePerceptualFingerprint],
    inventory: Sequence[ImagePerceptualFingerprint] = (),
) -> dict[str, object]:
    scan: dict[str, object] = {
        "schema_version": 1,
        "dataset_id": dataset_id,
        "manifest_sha256": manifest_sha256,
        "exclusion_snapshot_sha256": exclusion_snapshot_sha256,
        "detector_fingerprint": _canonical_sha256(
            {
                "algorithm_version": ALGORITHM_VERSION,
                "comparison_scopes": [
                    "probe_to_inventory",
                    "probe_to_probe",
                ],
                "required_probe_count": 100,
                "scan_schema_version": 1,
            }
        ),
        "probe_set_fingerprint": _fingerprint_set_sha256(probes),
        "inventory_set_fingerprint": _fingerprint_set_sha256(inventory),
        "locked_image_count": 100,
        "excluded_image_count": excluded_image_count,
        "completed": True,
        "candidates": [],
    }
    scan["scan_fingerprint"] = _canonical_sha256(scan)
    return scan


def _fingerprint_set_sha256(
    fingerprints: Sequence[ImagePerceptualFingerprint],
) -> str:
    return _canonical_sha256(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "members": [
                {
                    "content_sha256": fingerprint.content_sha256,
                    "fingerprint_sha256": fingerprint.canonical_sha256,
                }
                for fingerprint in sorted(
                    fingerprints,
                    key=lambda value: value.content_sha256,
                )
            ],
            "schema_version": 1,
        }
    )


def _truth_manifest(manifest: LockedSetManifest) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "waybill_count": manifest.waybill_count,
        "image_count": manifest.image_count,
        "pairs": [
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "truth_role": image.role.value,
                    }
                    for image in waybill.images
                ],
                "submitted_slots": {
                    image.slot.value: image.image_sha256 for image in waybill.images
                },
            }
            for waybill in manifest.waybills
        ],
    }


def _register_candidate_review_source_authority(
    repository: SqliteLockedSetRepository,
    manifest: LockedSetManifest,
) -> dict[str, object]:
    package_sha256 = hashlib.sha256(
        f"{manifest.dataset_id}:candidate-package".encode()
    ).hexdigest()
    record_set_sha256 = hashlib.sha256(
        f"{manifest.dataset_id}:record-set".encode()
    ).hexdigest()
    source_without_hash: dict[str, object] = {
        "schema_version": 2,
        "kind": "candidate_review_formal_source_authority",
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "package_sha256": package_sha256,
        "record_set_sha256": record_set_sha256,
    }
    source_authority_sha256 = _canonical_sha256(
        source_without_hash
    )
    binding: dict[str, object] = {
        "schema_version": 1,
        "seal_sha256": hashlib.sha256(
            f"{manifest.dataset_id}:seal".encode()
        ).hexdigest(),
        "package_sha256": package_sha256,
        "record_set_sha256": record_set_sha256,
        "review_history_authority_sha256": hashlib.sha256(
            f"{manifest.dataset_id}:review-history".encode()
        ).hexdigest(),
        "source_authority_sha256": source_authority_sha256,
    }
    repository.register_candidate_review_source_authority(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        seal_sha256=str(binding["seal_sha256"]),
        package_sha256=package_sha256,
        record_set_sha256=record_set_sha256,
        review_history_authority_sha256=str(
            binding["review_history_authority_sha256"]
        ),
        source_authority_sha256=source_authority_sha256,
        payload={
            **source_without_hash,
            "source_authority_sha256": source_authority_sha256,
        },
    )
    return binding


def _runner_report(
    *,
    manifest: LockedSetManifest,
    attestation_sha256: str,
    exclusion_snapshot_sha256: str,
    scan: Mapping[str, object],
    quality_coverage: Mapping[str, object],
    eligibility_history: Mapping[str, object],
    candidate_review_source_authority: Mapping[str, object],
    gate_passed: bool = True,
    fallback_first_runtime: bool = False,
) -> dict[str, object]:
    image_results: list[dict[str, object]] = []
    for waybill in manifest.waybills:
        for image in waybill.images:
            predicted_role = image.role.value
            if not gate_passed and not image_results:
                predicted_role = (
                    "unloading"
                    if image.role is TicketRole.LOADING
                    else "loading"
                )
            high_confidence = predicted_role != "unknown"
            ordinary_reliable = predicted_role != "unknown"
            critical_output: dict[str, object] = {
                "ordinary_net_amount": "30" if ordinary_reliable else None,
                "ordinary_net_unit": "t" if ordinary_reliable else None,
                "ordinary_net_reliable": ordinary_reliable,
                "weight_review_reason": None,
                "role": predicted_role,
                "role_quality": "reliable" if ordinary_reliable else "uncertain",
                "role_high_confidence": high_confidence,
                "safety_route": (
                    "eligible_for_downstream_comparison"
                    if ordinary_reliable
                    else "non_automatic"
                ),
            }
            outputs = [
                {
                    "assessment_fingerprint": (
                        _sha256(82_001 if runtime_kind == "cpu" else 82_002)
                    ),
                    "critical_output": dict(critical_output),
                    "image_sha256": image.image_sha256,
                    "ordinary_net_confidence": (
                        "0.98" if ordinary_reliable else None
                    ),
                    "output_fingerprint": (
                        _sha256(83_001 if runtime_kind == "cpu" else 83_002)
                    ),
                    "role_confidence": (
                        "0.95" if ordinary_reliable else "0.40"
                    ),
                    "runtime_fingerprint": (
                        _sha256(84_001 if runtime_kind == "cpu" else 84_002)
                    ),
                    "runtime_kind": runtime_kind,
                    "wall_elapsed_ms": (
                        "8.500" if runtime_kind == "cpu" else "2.500"
                    ),
                    "worker_elapsed_ms": (
                        "8.000" if runtime_kind == "cpu" else "2.000"
                    ),
                }
                for runtime_kind in ("cpu", "gpu")
            ]
            if fallback_first_runtime and not image_results:
                comparison = {
                    "critical_fields_match": None,
                    "differences": [],
                    "failures": [
                        {
                            "diagnostic_code": "LOCKED-OCR-GPU-FAILURE",
                            "error_kind": "runtime_failure",
                            "image_sha256": image.image_sha256,
                            "runtime_fingerprint": _sha256(84_002),
                            "runtime_kind": "gpu",
                            "wall_elapsed_ms": "3.000",
                        }
                    ],
                    "outputs": [outputs[0]],
                    "reason": "gpu_runtime_failed",
                    "schema_version": 1,
                    "selected_runtime_kind": "cpu",
                    "source": "local_ocr_locked_evaluator",
                    "status": "gpu_failed_cpu_fallback",
                }
            else:
                comparison = {
                    "critical_fields_match": True,
                    "differences": [],
                    "failures": [],
                    "outputs": outputs,
                    "reason": None,
                    "schema_version": 1,
                    "selected_runtime_kind": "gpu",
                    "source": "local_ocr_locked_evaluator",
                    "status": "dual_consistent",
                }
            comparison["comparison_sha256"] = _canonical_sha256(comparison)
            image_results.append(
                {
                    "result_id": hashlib.sha256(
                        f"result:{image.image_sha256}".encode()
                    ).hexdigest(),
                    "sample_id": waybill.sample_id,
                    "image_sha256": image.image_sha256,
                    "predicted_role": predicted_role,
                    "high_confidence": high_confidence,
                    "incremental_elapsed_ms": "1.000",
                    "runtime_comparison": comparison,
                }
            )
    predicted_roles = {
        str(result["image_sha256"]): str(result["predicted_role"]) for result in image_results
    }
    pair_results: list[dict[str, object]] = []
    missing_weight = WeightFieldEvidence(
        reading=None,
        quality=EvidenceQuality.MISSING,
    )
    missing_weights = TicketWeightEvidence(
        ordinary_net=missing_weight,
        factory_net=missing_weight,
        gross=missing_weight,
        tare=missing_weight,
    )
    for waybill in manifest.waybills:
        by_slot = {image.slot.value: image for image in waybill.images}
        loading = by_slot["loading"]
        unloading = by_slot["unloading"]
        loading_role = TicketRole(predicted_roles[loading.image_sha256])
        unloading_role = TicketRole(predicted_roles[unloading.image_sha256])
        assessment = assess_ticket_roles(
            TicketEvidence(
                slot=loading.slot,
                image_sha256=loading.image_sha256,
                machine_role=loading_role,
                role_quality=(
                    EvidenceQuality.UNCERTAIN
                    if loading_role is TicketRole.UNKNOWN
                    else EvidenceQuality.RELIABLE
                ),
                weights=missing_weights,
                extraction_fingerprint=loading.image_sha256,
                role_fingerprint=loading.image_sha256,
            ),
            TicketEvidence(
                slot=unloading.slot,
                image_sha256=unloading.image_sha256,
                machine_role=unloading_role,
                role_quality=(
                    EvidenceQuality.UNCERTAIN
                    if unloading_role is TicketRole.UNKNOWN
                    else EvidenceQuality.RELIABLE
                ),
                weights=missing_weights,
                extraction_fingerprint=unloading.image_sha256,
                role_fingerprint=unloading.image_sha256,
            ),
        )
        pair_results.append(
            {
                "result_id": hashlib.sha256(f"pair:{waybill.sample_id}".encode()).hexdigest(),
                "sample_id": waybill.sample_id,
                "loading_slot_image_sha256": loading.image_sha256,
                "unloading_slot_image_sha256": unloading.image_sha256,
                "automatic_outcome": (
                    "normal_ready" if assessment.roles_valid else "awaiting_review"
                ),
                "role_issue": (None if assessment.issue is None else assessment.issue.value),
                "review_reason": None,
            }
        )
    truth_manifest = _truth_manifest(manifest)
    report = evaluate_locked_set_release(
        preflight_attestation={
            "schema_version": 1,
            "dataset_id": manifest.dataset_id,
            "manifest_sha256": manifest.canonical_sha256,
            "attestation_sha256": attestation_sha256,
            "exclusion_snapshot_sha256": exclusion_snapshot_sha256,
            "waybill_count": 50,
            "image_count": 100,
        },
        truth_manifest=truth_manifest,
        image_results=image_results,
        pair_results=pair_results,
        quality_coverage=quality_coverage,
        near_duplicate_scan=scan,
        near_duplicate_decisions=[],
        eligibility_history=eligibility_history,
        candidate_review_source_authority=(
            candidate_review_source_authority
        ),
        expected_runtime_kinds=("cpu", "gpu"),
    )
    report["runner_version"] = RUNNER_VERSION
    application_build_manifest = _application_build_manifest()
    report["run_context"] = {
        "application_build_manifest": application_build_manifest.to_payload(),
        "application_build_sha256": application_build_manifest.canonical_sha256,
        "runtime_set_sha256": "2" * 64,
        "ocr_composition_evidence_sha256": "6" * 64,
        "template_set_sha256": "3" * 64,
        "matcher_sha256": "4" * 64,
        "policy_sha256": "5" * 64,
        "expected_runtime_kinds": ["cpu", "gpu"],
    }
    report["image_results"] = image_results
    report["pair_results"] = pair_results
    report["runner_report_sha256"] = _canonical_sha256(report)
    return report


def _quality_coverage(manifest: LockedSetManifest) -> dict[str, object]:
    conditions = (
        "blur",
        "crop",
        "glare",
        "printed",
        "rotation_0",
        "rotation_90",
        "rotation_180",
        "rotation_270",
        "screen",
        "unknown_layout",
    )
    images = [image for waybill in manifest.waybills for image in waybill.images]
    unknown_images = [image.image_sha256 for image in images if image.role.value == "unknown"]
    image_for_condition = {
        "blur": images[8].image_sha256,
        "crop": images[9].image_sha256,
        "glare": images[10].image_sha256,
        "printed": images[11].image_sha256,
        "rotation_0": images[12].image_sha256,
        "rotation_90": images[13].image_sha256,
        "rotation_180": images[14].image_sha256,
        "rotation_270": images[15].image_sha256,
        "screen": images[16].image_sha256,
        "unknown_layout": unknown_images[0],
    }
    entries: list[dict[str, object]] = []
    for condition in conditions:
        entry: dict[str, object] = {
            "condition": condition,
            "reviewer_id": "reviewer-test",
            "reviewed_at": "2026-07-26T00:00:00+00:00",
            "image_sha256": image_for_condition[condition],
        }
        entry["review_evidence_sha256"] = quality_review_evidence_sha256(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            entry=entry,
        )
        entries.append(entry)
    coverage: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "required_conditions": list(conditions),
        "entries": entries,
        "derived_adversarial_suite": (
            build_locked_set_derived_adversarial_suite(_truth_manifest(manifest))
        ),
    }
    coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(coverage)
    return coverage


def _persist_scan(
    repository: SqliteLockedSetRepository,
    result: Any,
) -> tuple[LockedSetManifest, Mapping[str, object]]:
    manifest = repository.get_manifest(result.dataset.dataset_id)
    probes = _probe_fingerprints(manifest)
    scan = _similarity_scan(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256=(result.attestation.exclusion_snapshot_sha256),
        excluded_image_count=result.snapshot.inventory_image_count,
        probes=probes,
    )
    repository.persist_similarity_scan(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256=(result.attestation.exclusion_snapshot_sha256),
        inventory_high_watermark=result.attestation.inventory_high_watermark,
        scan=scan,
        locked_image_fingerprints=probes,
        actor_id="developer-test",
    )
    return manifest, scan


def _persist_formal_evaluation(
    repository: SqliteLockedSetRepository,
    result: Any,
    manifest: LockedSetManifest,
    scan: Mapping[str, object],
    *,
    idempotency_key: str,
    gate_passed: bool = True,
    fallback_first_runtime: bool = False,
) -> Any:
    candidate_review_source_authority = (
        _register_candidate_review_source_authority(
            repository,
            manifest,
        )
    )
    report = _runner_report(
        manifest=manifest,
        attestation_sha256=result.attestation.attestation_sha256,
        exclusion_snapshot_sha256=(result.attestation.exclusion_snapshot_sha256),
        scan=scan,
        quality_coverage=_quality_coverage(manifest),
        eligibility_history=_current_history(repository, result),
        candidate_review_source_authority=(
            candidate_review_source_authority
        ),
        gate_passed=gate_passed,
        fallback_first_runtime=fallback_first_runtime,
    )
    _register_development_authority_for_report(
        repository,
        result,
        manifest,
        report,
    )
    return repository.persist_formal_release_evaluation(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256=(result.attestation.exclusion_snapshot_sha256),
        inventory_high_watermark=result.attestation.inventory_high_watermark,
        scan_fingerprint=str(scan["scan_fingerprint"]),
        runner_report=report,
        quality_coverage=_quality_coverage(manifest),
        near_duplicate_decisions=(),
        actor_id="developer-test",
        idempotency_key=idempotency_key,
    )


def _register_development_authority_for_report(
    repository: SqliteLockedSetRepository,
    result: Any,
    manifest: LockedSetManifest,
    report: dict[str, object],
) -> None:
    run_context = report["run_context"]
    assert isinstance(run_context, dict)
    authority = formal_development_authority(
        build_fingerprint=str(
            run_context["application_build_sha256"]
        ),
        runtime_fingerprint=str(run_context["runtime_set_sha256"]),
        matcher_fingerprint=str(run_context["matcher_sha256"]),
        policy_fingerprint=str(run_context["policy_sha256"]),
    )
    template_set_sha256 = authority.payload[
        "shadow_template_set_fingerprint"
    ]
    assert isinstance(template_set_sha256, str)
    run_context["template_set_sha256"] = template_set_sha256
    report["runner_report_sha256"] = _canonical_sha256(
        {
            field: value
            for field, value in report.items()
            if field != "runner_report_sha256"
        }
    )
    repository.register_development_authority(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        authority_sha256=authority.authority_sha256,
        source_exclusion_snapshot_sha256=(
            authority.exclusion_snapshot.canonical_sha256
        ),
        formal_exclusion_snapshot_sha256=(
            result.attestation.exclusion_snapshot_sha256
        ),
        source_inventory_high_watermark=(
            authority.inventory_high_watermark
        ),
        shadow_template_set_fingerprint=template_set_sha256,
        payload=authority.payload,
    )


def _current_history(
    repository: SqliteLockedSetRepository,
    result: Any,
) -> Mapping[str, object]:
    del repository
    event: dict[str, object] = {
        "actor_id": result.attestation.actor_id,
        "event_id": result.attestation.attestation_id,
        "event_type": "preflight_passed",
        "recorded_at": result.attestation.completed_at,
    }
    event["event_sha256"] = _canonical_sha256(event)
    history: dict[str, object] = {
        "dataset_id": result.dataset.dataset_id,
        "events": [event],
        "manifest_sha256": result.attestation.manifest_sha256,
        "schema_version": 1,
        "status": "eligible",
    }
    history["history_sha256"] = _canonical_sha256(history)
    return history


def test_authoritative_snapshot_is_db_built_and_restart_stable(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(data_root, project_root, instance_id="locked-snapshot-first")
    try:
        fingerprint = _fingerprint_for_hash("a" * 64, index=1)
        fingerprint_json = _canonical_json(fingerprint.to_record())
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            register_exclusion_identity(
                connection,
                category="development_image",
                identity_sha256="a" * 64,
                source_kind="development_evaluation",
                source_id="development-evaluation-001",
                created_at="2026-07-26T00:00:00+00:00",
                perceptual_fingerprint_json=fingerprint_json,
                fingerprint_sha256=hashlib.sha256(fingerprint_json.encode("utf-8")).hexdigest(),
                algorithm_version=ALGORITHM_VERSION,
            )
        first = _repository(runtime).build_exclusion_snapshot()
        replay = _repository(runtime).build_exclusion_snapshot()

        assert replay.snapshot_id == first.snapshot_id
        assert replay.inventory_high_watermark == first.inventory_high_watermark
        assert replay.snapshot.canonical_sha256 == first.snapshot.canonical_sha256
        assert replay.snapshot.development_image_hashes == frozenset({"a" * 64})
        assert replay.inventory_image_count == 1
        assert replay.fingerprinted_image_count == 1
        assert replay.missing_fingerprint_count == 0
        assert replay.fingerprint_algorithm_versions == ("dahe.ticket-image-similarity.v1",)
        persisted_fingerprint = replay.perceptual_fingerprints[0]
        assert persisted_fingerprint.image_sha256 == "a" * 64
        assert persisted_fingerprint.fingerprint_json == fingerprint_json
        assert persisted_fingerprint.to_image_fingerprint() == fingerprint
        assert replay.snapshot.exclusion_counts == {
            "calibration_images": 0,
            "development_images": 1,
            "prior_locked_images": 0,
            "prior_waybill_identities": 0,
            "shadow_images": 0,
            "template_reference_images": 0,
        }
    finally:
        runtime.close()

    restarted = _runtime(
        data_root,
        project_root,
        instance_id="locked-snapshot-restart",
    )
    try:
        after_restart = _repository(restarted).build_exclusion_snapshot()
        assert after_restart.snapshot_id == first.snapshot_id
        assert after_restart.snapshot.canonical_sha256 == first.snapshot.canonical_sha256
    finally:
        restarted.close()


def test_sealed_50_100_manifest_and_preflight_are_durable_without_paths(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-contract-001",
    )
    data_root = tmp_path / "data"
    runtime = _runtime(data_root, project_root, instance_id="locked-preflight")
    try:
        repository = _repository(runtime)
        result = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )

        assert result.dataset.dataset_id == "locked-contract-001"
        assert result.dataset.state == "preflight_passed"
        assert result.dataset.record_version == 2
        assert result.attestation.waybill_count == 50
        assert result.attestation.image_count == 100
        assert result.attestation.exclusion_snapshot_sha256 == (
            result.snapshot.snapshot.canonical_sha256
        )
        assert result.attestation.inventory_high_watermark == (
            result.snapshot.inventory_high_watermark
        )
        assert _scalar(runtime, "SELECT count(*) FROM locked_set_datasets") == 1
        assert _scalar(runtime, "SELECT count(*) FROM locked_set_preflight_attestations") == 1
        persisted_text = _scalar(
            runtime,
            "SELECT manifest_json FROM locked_set_datasets",
        )
        assert str(tmp_path.resolve()) not in str(persisted_text)
        assert str(dataset_root.resolve()) not in str(persisted_text)
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            authority = require_current_preflight_authority(
                connection,
                dataset_id=result.dataset.dataset_id,
                manifest_sha256=result.attestation.manifest_sha256,
                exclusion_snapshot_sha256=(result.attestation.exclusion_snapshot_sha256),
                inventory_high_watermark=(result.attestation.inventory_high_watermark),
            )
            assert authority.dataset.state == "preflight_passed"
            assert authority.attestation == result.attestation
            assert authority.exclusion_snapshot == result.snapshot
            assert authority.eligibility_history["status"] == "eligible"
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            register_exclusion_identity(
                connection,
                category="calibration_image",
                identity_sha256="c" * 64,
                source_kind="calibration_fixture",
                source_id="calibration-after-preflight",
                created_at="2026-07-26T00:00:02+00:00",
            )
        with (
            runtime.commit_gate.transaction(runtime.engine) as connection,
            pytest.raises(
                LockedSetInventoryChangedError,
                match="inventory changed",
            ),
        ):
            require_current_preflight_authority(
                connection,
                dataset_id=result.dataset.dataset_id,
                manifest_sha256=result.attestation.manifest_sha256,
                exclusion_snapshot_sha256=(result.attestation.exclusion_snapshot_sha256),
                inventory_high_watermark=(result.attestation.inventory_high_watermark),
            )
    finally:
        runtime.close()

    restarted = _runtime(
        data_root,
        project_root,
        instance_id="locked-preflight-restart",
    )
    try:
        dataset = _repository(restarted).get_dataset("locked-contract-001")
        assert dataset.state == "preflight_passed"
        assert dataset.record_version == 2
    finally:
        restarted.close()


def test_preflight_attestation_rejects_a_stale_inventory_snapshot(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-stale-snapshot",
    )
    runtime = _runtime(tmp_path / "data", project_root, instance_id="locked-stale")
    try:
        repository = _repository(runtime)
        service = LockedSetReleaseService(repository=repository)
        prepared = service.prepare_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            register_exclusion_identity(
                connection,
                category="shadow_image",
                identity_sha256="b" * 64,
                source_kind="shadow_evaluation",
                source_id="shadow-evaluation-001",
                created_at="2026-07-26T00:00:01+00:00",
            )

        with pytest.raises(
            LockedSetInventoryChangedError,
            match="inventory changed",
        ):
            service.commit_preflight(prepared, actor_id="developer-test")

        assert _scalar(runtime, "SELECT count(*) FROM locked_set_preflight_attestations") == 0
        assert repository.get_dataset("locked-stale-snapshot").state == "sealed"
    finally:
        runtime.close()


def test_formal_authority_rejects_incomplete_inventory_fingerprints(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-incomplete-fingerprints",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-incomplete-fingerprints",
    )
    try:
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            register_exclusion_identity(
                connection,
                category="development_image",
                identity_sha256="d" * 64,
                source_kind="development_fixture",
                source_id="missing-fingerprint",
                created_at="2026-07-26T00:00:00+00:00",
            )
        result = LockedSetReleaseService(repository=_repository(runtime)).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )

        with (
            runtime.commit_gate.transaction(runtime.engine) as connection,
            pytest.raises(
                LockedSetInventoryFingerprintIncompleteError,
                match="fingerprints are incomplete",
            ),
        ):
            require_current_preflight_authority(
                connection,
                dataset_id=result.dataset.dataset_id,
                manifest_sha256=result.attestation.manifest_sha256,
                exclusion_snapshot_sha256=(result.attestation.exclusion_snapshot_sha256),
                inventory_high_watermark=(result.attestation.inventory_high_watermark),
            )
    finally:
        runtime.close()


def test_invalidation_is_cas_idempotent_and_atomic_when_converting_to_development(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-invalidated-001",
    )
    runtime = _runtime(tmp_path / "data", project_root, instance_id="locked-invalidate")
    try:
        repository = _repository(runtime)
        result = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        first = repository.invalidate_locked_set(
            dataset_id=result.dataset.dataset_id,
            expected_record_version=result.dataset.record_version,
            influence_kind="template",
            reason="Locked-set evidence informed a template change",
            actor_id="developer-test",
            idempotency_key="invalidate-locked-001",
        )
        replay = repository.invalidate_locked_set(
            dataset_id=result.dataset.dataset_id,
            expected_record_version=result.dataset.record_version,
            influence_kind="template",
            reason="Locked-set evidence informed a template change",
            actor_id="developer-test",
            idempotency_key="invalidate-locked-001",
        )

        assert first.applied is True
        assert first.dataset.state == "invalidated_to_development"
        assert first.dataset.record_version == 3
        assert replay.applied is False
        assert replay.invalidation == first.invalidation
        assert (
            _scalar(
                runtime,
                "SELECT count(DISTINCT identity_sha256) "
                "FROM locked_set_exclusion_inventory "
                "WHERE category = 'development_image' "
                "AND source_id = 'locked-invalidated-001'",
            )
            == 100
        )
        assert (
            _scalar(
                runtime,
                "SELECT count(DISTINCT identity_sha256) "
                "FROM locked_set_exclusion_inventory "
                "WHERE category = 'prior_waybill_identity' "
                "AND source_id = 'locked-invalidated-001'",
            )
            == 50
        )
        with pytest.raises(LockedSetRecordVersionConflictError):
            repository.invalidate_locked_set(
                dataset_id=result.dataset.dataset_id,
                expected_record_version=2,
                influence_kind="rule",
                reason="A different stale request",
                actor_id="developer-test",
                idempotency_key="invalidate-locked-stale",
            )
    finally:
        runtime.close()


def test_invalidation_failpoint_rolls_back_state_event_and_inventory(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-invalidation-rollback",
    )
    runtime = _runtime(tmp_path / "data", project_root, instance_id="locked-rollback")
    try:
        repository = _repository(runtime)
        result = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )

        def failpoint(name: str) -> None:
            if name == "after_invalidation_inventory":
                raise InjectedLockedSetFailure(name)

        failing = _repository(runtime, failpoint=failpoint)
        with pytest.raises(InjectedLockedSetFailure):
            failing.invalidate_locked_set(
                dataset_id=result.dataset.dataset_id,
                expected_record_version=result.dataset.record_version,
                influence_kind="label",
                reason="A label change was inspired by gate evidence",
                actor_id="developer-test",
                idempotency_key="invalidate-rollback",
            )

        dataset = repository.get_dataset(result.dataset.dataset_id)
        assert dataset.state == "preflight_passed"
        assert dataset.record_version == 2
        assert _scalar(runtime, "SELECT count(*) FROM locked_set_invalidations") == 0
        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_exclusion_inventory "
                "WHERE source_id = 'locked-invalidation-rollback'",
            )
            == 0
        )
    finally:
        runtime.close()


def test_manifest_scan_and_formal_evaluation_are_durable_and_idempotent(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-success",
    )
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="locked-formal-success",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest = repository.get_manifest(preflight.dataset.dataset_id)
        staged = stage_locked_set_evidence(
            manifest=manifest,
            dataset_root=dataset_root,
            evidence_store=ContentAddressedEvidenceStore(data_root / "evidence"),
        )
        repository.register_evidence_membership(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            images=staged.images,
        )
        manifest, scan = _persist_scan(repository, preflight)
        first = _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-success",
        )
        replay = _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-success",
        )

        assert first.applied is True
        assert first.evaluation.formal_report is True
        assert first.evaluation.gate_passed is True
        assert first.evaluation.formal_accuracy_claim is True
        assert first.evaluation.formal_accuracy_claim_scope == "observed_real_locked_set_only"
        assert first.evaluation.derived_scenario_accuracy_claim is False
        assert first.evaluation.derived_prevalence_claim is False
        assert first.dataset.state == "formal_evaluated"
        assert replay.applied is False
        assert replay.evaluation == first.evaluation
        assert json.loads(first.evaluation.quality_coverage_json) == (_quality_coverage(manifest))
        assert json.loads(first.evaluation.decision_set_json) == []
        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM evidence_holds "
                "WHERE hold_kind = 'locked_set_member' "
                "AND released_at IS NULL",
            )
            == 100
        )
        assert (
            _scalar(
                runtime,
                "SELECT count(DISTINCT identity_sha256) "
                "FROM locked_set_exclusion_inventory "
                "WHERE category = 'prior_locked_image' "
                "AND source_id = 'locked-formal-success'",
            )
            == 100
        )
        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_exclusion_inventory "
                "WHERE category = 'prior_locked_image' "
                "AND perceptual_fingerprint_json IS NOT NULL",
            )
            == 100
        )
        assert (
            _scalar(
                runtime,
                "SELECT count(DISTINCT identity_sha256) "
                "FROM locked_set_exclusion_inventory "
                "WHERE category = 'prior_waybill_identity' "
                "AND source_id = 'locked-formal-success'",
            )
            == 50
        )
        later_snapshot = repository.build_exclusion_snapshot()
        assert len(later_snapshot.snapshot.prior_locked_image_hashes) == 100
        assert later_snapshot.inventory_image_count == 100
        assert later_snapshot.fingerprinted_image_count == 100
        assert later_snapshot.missing_fingerprint_count == 0
        backup_service = SqliteBackupService(
            runtime=runtime,
            evidence_store=ContentAddressedEvidenceStore(data_root / "evidence"),
            backup_root=data_root / "backups",
        )
        backup = backup_service.create_online_backup()
        restored_root = tmp_path / "restored"
        restored_root.mkdir()
        backup_service.restore_to_temporary(
            backup.path,
            restored_root,
        )
        restored_runtime = _runtime(
            restored_root,
            project_root,
            instance_id="locked-formal-restored",
        )
        try:
            restored = _repository(restored_runtime).get_formal_release_evaluation(
                manifest.dataset_id
            )
            assert restored.quality_coverage_json == (first.evaluation.quality_coverage_json)
            assert restored.decision_set_json == (first.evaluation.decision_set_json)
        finally:
            restored_runtime.close()
        invalidated = repository.invalidate_locked_set(
            dataset_id=manifest.dataset_id,
            expected_record_version=first.dataset.record_version,
            influence_kind="template",
            reason="Formal evidence influenced a template change.",
            actor_id="developer-test",
            idempotency_key="invalidate-formal-success",
        )
        assert invalidated.dataset.state == "invalidated_to_development"
        with pytest.raises(
            LockedSetStateTransitionError,
            match="cannot replay accuracy",
        ):
            _persist_formal_evaluation(
                repository,
                preflight,
                manifest,
                scan,
                idempotency_key="formal-success",
            )
    finally:
        runtime.close()

    restarted = _runtime(
        data_root,
        project_root,
        instance_id="locked-formal-success-restart",
    )
    try:
        repository = _repository(restarted)
        persisted_scan = repository.get_similarity_scan("locked-formal-success")
        persisted_evaluation = repository.get_formal_release_evaluation("locked-formal-success")
        assert persisted_scan.scan_fingerprint == scan["scan_fingerprint"]
        assert persisted_scan.locked_image_count == 100
        assert len(persisted_scan.locked_image_fingerprints) == 100
        assert persisted_evaluation == first.evaluation
        with restarted.commit_gate.transaction(
            restarted.engine
        ) as connection:
            connection.execute(
                text(
                    "DROP TRIGGER "
                    "locked_set_candidate_review_source_authority_immutable_delete"
                )
            )
            connection.execute(
                text(
                    "DELETE FROM "
                    "locked_set_candidate_review_source_authority "
                    "WHERE dataset_id = :dataset_id"
                ),
                {"dataset_id": manifest.dataset_id},
            )
        with pytest.raises(
            LockedSetConflictError,
            match="candidate-review source authority",
        ):
            repository.get_formal_release_evaluation(
                manifest.dataset_id
            )
    finally:
        restarted.close()


def test_formal_gate_failure_persists_report_without_accuracy_claim(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-gate-failed",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-formal-gate-failed",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)
        outcome = _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-gate-failed",
            gate_passed=False,
        )

        assert outcome.evaluation.formal_report is True
        assert outcome.evaluation.gate_passed is False
        assert outcome.evaluation.formal_accuracy_claim is False
        assert outcome.evaluation.formal_accuracy_claim_scope == "none"
        assert outcome.evaluation.derived_scenario_accuracy_claim is False
        assert outcome.evaluation.derived_prevalence_claim is False
        assert outcome.dataset.state == "formal_evaluated"
    finally:
        runtime.close()


def test_runtime_fallback_is_replayed_but_cannot_receive_a_formal_accuracy_claim(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-runtime-fallback",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-formal-runtime-fallback",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)
        outcome = _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-runtime-fallback",
            fallback_first_runtime=True,
        )

        runner_report = json.loads(outcome.evaluation.runner_report_json)
        runtime_gate = runner_report["runtime_execution_gate"]
        assert runtime_gate["passed"] is False
        assert runtime_gate["failed_image_count"] == 1
        assert runtime_gate["status_counts"]["gpu_failed_cpu_fallback"] == 1
        assert outcome.evaluation.gate_passed is False
        assert outcome.evaluation.formal_accuracy_claim is False
        replay = repository.get_replayable_formal_release_evaluation(
            manifest.dataset_id
        )
        assert replay == outcome.evaluation
    finally:
        runtime.close()


def test_persisted_formal_report_rejects_legacy_and_ambiguous_claim_contracts(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-strict-reload",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-formal-strict-reload",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)
        quality = _quality_coverage(manifest)
        candidate_authority = (
            _register_candidate_review_source_authority(
                repository,
                manifest,
            )
        )
        report = _runner_report(
            manifest=manifest,
            attestation_sha256=preflight.attestation.attestation_sha256,
            exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
            scan=scan,
            quality_coverage=quality,
            eligibility_history=_current_history(repository, preflight),
            candidate_review_source_authority=candidate_authority,
        )
        _register_development_authority_for_report(
            repository,
            preflight,
            manifest,
            report,
        )
        mismatched_authority_report = json.loads(
            _canonical_json(report)
        )
        assert isinstance(mismatched_authority_report, dict)
        mismatched_binding = mismatched_authority_report[
            "candidate_review_source_authority"
        ]
        assert isinstance(mismatched_binding, dict)
        mismatched_binding["seal_sha256"] = "f" * 64
        mismatched_authority_report[
            "candidate_review_source_authority_sha256"
        ] = _canonical_sha256(mismatched_binding)
        mismatched_authority_report["report_sha256"] = (
            _canonical_sha256(
                {
                    field: value
                    for field, value in mismatched_authority_report.items()
                    if field
                    not in {
                        "image_results",
                        "pair_results",
                        "report_sha256",
                        "run_context",
                        "runner_report_sha256",
                        "runner_version",
                    }
                }
            )
        )
        mismatched_authority_report["runner_report_sha256"] = (
            _canonical_sha256(
                {
                    field: value
                    for field, value in mismatched_authority_report.items()
                    if field != "runner_report_sha256"
                }
            )
        )
        with pytest.raises(
            LockedSetConflictError,
            match="candidate-review source authority",
        ):
            repository.persist_formal_release_evaluation(
                dataset_id=manifest.dataset_id,
                manifest_sha256=manifest.canonical_sha256,
                exclusion_snapshot_sha256=(
                    preflight.attestation.exclusion_snapshot_sha256
                ),
                inventory_high_watermark=(
                    preflight.attestation.inventory_high_watermark
                ),
                scan_fingerprint=str(scan["scan_fingerprint"]),
                runner_report=mismatched_authority_report,
                quality_coverage=quality,
                near_duplicate_decisions=(),
                actor_id="developer-test",
                idempotency_key="formal-mismatched-source-authority",
            )
        wrong_scope_report = json.loads(_canonical_json(report))
        assert isinstance(wrong_scope_report, dict)
        wrong_scope_report["formal_accuracy_claim_scope"] = "observed_real_locked_set_only"
        wrong_scope_report["report_sha256"] = _canonical_sha256(
            {
                field: value
                for field, value in wrong_scope_report.items()
                if field
                not in {
                    "image_results",
                    "pair_results",
                    "report_sha256",
                    "run_context",
                    "runner_report_sha256",
                    "runner_version",
                }
            }
        )
        wrong_scope_report["runner_report_sha256"] = _canonical_sha256(
            {
                field: value
                for field, value in wrong_scope_report.items()
                if field != "runner_report_sha256"
            }
        )
        with pytest.raises(
            LockedSetPersistenceError,
            match="uncommitted",
        ):
            repository.persist_formal_release_evaluation(
                dataset_id=manifest.dataset_id,
                manifest_sha256=manifest.canonical_sha256,
                exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
                inventory_high_watermark=(preflight.attestation.inventory_high_watermark),
                scan_fingerprint=str(scan["scan_fingerprint"]),
                runner_report=wrong_scope_report,
                quality_coverage=quality,
                near_duplicate_decisions=(),
                actor_id="developer-test",
                idempotency_key="formal-wrong-uncommitted-scope",
            )

        tampered_quality = json.loads(_canonical_json(quality))
        assert isinstance(tampered_quality, dict)
        tampered_suite = tampered_quality["derived_adversarial_suite"]
        assert isinstance(tampered_suite, dict)
        tampered_suite["source_truth_sha256"] = "f" * 64
        tampered_suite["suite_sha256"] = _canonical_sha256(
            {field: value for field, value in tampered_suite.items() if field != "suite_sha256"}
        )
        tampered_quality["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(
            tampered_quality
        )
        with pytest.raises(
            LockedSetConflictError,
            match="derived adversarial suite",
        ):
            repository.persist_formal_release_evaluation(
                dataset_id=manifest.dataset_id,
                manifest_sha256=manifest.canonical_sha256,
                exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
                inventory_high_watermark=(preflight.attestation.inventory_high_watermark),
                scan_fingerprint=str(scan["scan_fingerprint"]),
                runner_report=report,
                quality_coverage=tampered_quality,
                near_duplicate_decisions=(),
                actor_id="developer-test",
                idempotency_key="formal-tampered-derived-suite",
            )
        _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-strict-reload",
        )
        # Simulate an offline or externally corrupted database. Normal writes
        # cannot reach this state because the authority table is append-only.
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(text("DROP TRIGGER locked_set_formal_evaluations_immutable_update"))
        original_runner, original_committed = _formal_report_payloads(
            runtime,
            manifest.dataset_id,
        )

        def legacy_schema(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner["schema_version"] = 1
            committed["schema_version"] = 1

        def missing_derived_claim(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner.pop("derived_prevalence_claim")
            committed.pop("derived_prevalence_claim")

        def string_boolean_claim(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner["derived_scenario_accuracy_claim"] = "false"
            committed["derived_scenario_accuracy_claim"] = "false"

        def wrong_runner_scope(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner["formal_accuracy_claim_scope"] = "observed_real_locked_set_only"
            committed["formal_accuracy_claim_scope"] = "observed_real_locked_set_only"

        def corrupted_base_report_hash(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner["report_sha256"] = "f" * 64
            committed["report_sha256"] = "f" * 64

        def inconsistent_derived_gate(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner_gate = runner["derived_adversarial_gate"]
            committed_gate = committed["derived_adversarial_gate"]
            assert isinstance(runner_gate, dict)
            assert isinstance(committed_gate, dict)
            runner_gate["passed"] = False
            committed_gate["passed"] = False

        def missing_runtime_comparison_aggregate(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner.pop("runtime_comparison_evidence_sha256")
            committed.pop("runtime_comparison_evidence_sha256")

        def changed_runtime_comparison_aggregate(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner["runtime_comparison_evidence_sha256"] = "f" * 64
            committed["runtime_comparison_evidence_sha256"] = "f" * 64
            pure_runner = {
                field: value
                for field, value in runner.items()
                if field
                not in {
                    "image_results",
                    "pair_results",
                    "report_sha256",
                    "run_context",
                    "runner_report_sha256",
                    "runner_version",
                }
            }
            base_sha256 = _canonical_sha256(pure_runner)
            runner["report_sha256"] = base_sha256
            committed["report_sha256"] = base_sha256

        def missing_candidate_review_source_authority(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner.pop("candidate_review_source_authority")
            committed.pop("candidate_review_source_authority")
            runner.pop("candidate_review_source_authority_sha256")
            committed.pop("candidate_review_source_authority_sha256")

        def changed_candidate_review_source_authority(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner_binding = runner[
                "candidate_review_source_authority"
            ]
            committed_binding = committed[
                "candidate_review_source_authority"
            ]
            assert isinstance(runner_binding, dict)
            assert isinstance(committed_binding, dict)
            runner_binding["seal_sha256"] = "f" * 64
            committed_binding["seal_sha256"] = "f" * 64
            binding_sha256 = _canonical_sha256(runner_binding)
            runner["candidate_review_source_authority_sha256"] = (
                binding_sha256
            )
            committed["candidate_review_source_authority_sha256"] = (
                binding_sha256
            )
            pure_runner = {
                field: value
                for field, value in runner.items()
                if field
                not in {
                    "image_results",
                    "pair_results",
                    "report_sha256",
                    "run_context",
                    "runner_report_sha256",
                    "runner_version",
                }
            }
            base_sha256 = _canonical_sha256(pure_runner)
            runner["report_sha256"] = base_sha256
            committed["report_sha256"] = base_sha256

        def unsupported_runner_version(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner["runner_version"] = "forged-runner-version"
            committed["runner_version"] = "forged-runner-version"

        def incomplete_runner_context(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            runner_context = runner["run_context"]
            committed_context = committed["run_context"]
            assert isinstance(runner_context, dict)
            assert isinstance(committed_context, dict)
            runner_context.pop("policy_sha256")
            committed_context.pop("policy_sha256")

        def changed_runner_context(
            runner: dict[str, object],
            committed: dict[str, object],
        ) -> None:
            for report in (runner, committed):
                context = report["run_context"]
                assert isinstance(context, dict)
                build_manifest = context["application_build_manifest"]
                assert isinstance(build_manifest, dict)
                sources = build_manifest["sources"]
                assert isinstance(sources, list)
                source = sources[0]
                assert isinstance(source, dict)
                source["sha256"] = "f" * 64
                context["application_build_sha256"] = (
                    ApplicationBuildManifest.from_payload(
                        build_manifest
                    ).canonical_sha256
                )

        mutations = (
            legacy_schema,
            missing_derived_claim,
            string_boolean_claim,
            wrong_runner_scope,
            corrupted_base_report_hash,
            inconsistent_derived_gate,
            missing_runtime_comparison_aggregate,
            changed_runtime_comparison_aggregate,
            missing_candidate_review_source_authority,
            changed_candidate_review_source_authority,
        )
        for mutate in mutations:
            runner = json.loads(_canonical_json(original_runner))
            committed = json.loads(_canonical_json(original_committed))
            assert isinstance(runner, dict)
            assert isinstance(committed, dict)
            mutate(runner, committed)
            _replace_formal_report_payloads(
                runtime,
                manifest.dataset_id,
                runner_report=runner,
                committed_report=committed,
            )
            with pytest.raises(LockedSetPersistenceError):
                repository.get_formal_release_evaluation(manifest.dataset_id)
            _replace_formal_report_payloads(
                runtime,
                manifest.dataset_id,
                runner_report=original_runner,
                committed_report=original_committed,
            )

        for mutate, error_pattern in (
            (unsupported_runner_version, "runner version"),
            (incomplete_runner_context, "runner context"),
            (changed_runner_context, "runner context hash"),
        ):
            runner = json.loads(_canonical_json(original_runner))
            committed = json.loads(_canonical_json(original_committed))
            assert isinstance(runner, dict)
            assert isinstance(committed, dict)
            mutate(runner, committed)
            _replace_formal_report_payloads(
                runtime,
                manifest.dataset_id,
                runner_report=runner,
                committed_report=committed,
            )
            with pytest.raises(
                LockedSetPersistenceError,
                match=error_pattern,
            ):
                repository.get_formal_release_evaluation(manifest.dataset_id)
            _replace_formal_report_payloads(
                runtime,
                manifest.dataset_id,
                runner_report=original_runner,
                committed_report=original_committed,
            )

        replay_runner = json.loads(_canonical_json(original_runner))
        replay_committed = json.loads(_canonical_json(original_committed))
        assert isinstance(replay_runner, dict)
        assert isinstance(replay_committed, dict)
        corrupted_base_report_hash(replay_runner, replay_committed)
        _replace_formal_report_payloads(
            runtime,
            manifest.dataset_id,
            runner_report=replay_runner,
            committed_report=replay_committed,
        )
        with pytest.raises(LockedSetPersistenceError):
            _persist_formal_evaluation(
                repository,
                preflight,
                manifest,
                scan,
                idempotency_key="formal-strict-reload",
            )
    finally:
        runtime.close()


def test_reload_recomputes_gate_from_raw_db_authority_after_consistent_forgery(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-forged-reload-pass",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-formal-forged-reload-pass",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)
        original = _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-forged-reload-pass",
            gate_passed=False,
        )
        assert original.evaluation.gate_passed is False
        runner, _ = _formal_report_payloads(runtime, manifest.dataset_id)
        zero_error_gates = runner["zero_error_gates"]
        assert isinstance(zero_error_gates, dict)
        assert any(
            isinstance(gate, dict) and gate.get("passed") is False
            for gate in zero_error_gates.values()
        )

        suite = runner["derived_adversarial_suite"]
        derived_results = runner["derived_adversarial_results"]
        assert isinstance(suite, dict)
        assert isinstance(derived_results, dict)
        scenarios = suite["scenarios"]
        results = derived_results["results"]
        assert isinstance(scenarios, list)
        assert isinstance(results, list)
        scenarios_by_id = {
            scenario["scenario_id"]: scenario
            for scenario in scenarios
            if isinstance(scenario, dict)
        }
        for result in results:
            assert isinstance(result, dict)
            scenario = scenarios_by_id[result["scenario_id"]]
            result["automatic_outcome"] = scenario["expected_automatic_outcome"]
            result["role_issue"] = scenario["expected_role_issue"]
        derived_results["results_sha256"] = _canonical_sha256(
            {field: value for field, value in derived_results.items() if field != "results_sha256"}
        )
        runner["derived_adversarial_fingerprint"] = _canonical_sha256(
            {
                "generator_version": derived_results["generator_version"],
                "results_sha256": derived_results["results_sha256"],
                "suite_sha256": suite["suite_sha256"],
            }
        )
        runner["derived_adversarial_gate"] = {
            "scenario_count": 4,
            "passed_count": 4,
            "failed_scenarios": [],
            "passed": True,
        }
        runner["observed_locked_set_gate"] = {
            "zero_error_gates_passed": True,
            "quality_coverage_passed": True,
            "near_duplicate_passed": True,
            "passed": True,
        }
        runner["gate_passed"] = True
        runner["report_sha256"] = _canonical_sha256(
            {
                field: value
                for field, value in runner.items()
                if field
                not in {
                    "image_results",
                    "pair_results",
                    "report_sha256",
                    "run_context",
                    "runner_report_sha256",
                    "runner_version",
                }
            }
        )
        committed = json.loads(_canonical_json(runner))
        assert isinstance(committed, dict)
        committed["formal_report"] = True
        committed["formal_accuracy_claim"] = True
        committed["formal_accuracy_claim_scope"] = "observed_real_locked_set_only"
        committed["claim_status"] = "formal_accuracy_claim"

        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(text("DROP TRIGGER locked_set_formal_evaluations_immutable_update"))
        _replace_formal_report_payloads(
            runtime,
            manifest.dataset_id,
            runner_report=runner,
            committed_report=committed,
            gate_passed=True,
            formal_accuracy_claim=True,
        )

        with pytest.raises(
            LockedSetPersistenceError,
            match="request hash",
        ):
            repository.get_formal_release_evaluation(manifest.dataset_id)
        with pytest.raises(
            LockedSetPersistenceError,
            match="request hash",
        ):
            _persist_formal_evaluation(
                repository,
                preflight,
                manifest,
                scan,
                idempotency_key="formal-forged-reload-pass",
                gate_passed=False,
            )
    finally:
        runtime.close()


def test_formal_reads_reject_coherent_evaluation_row_result_forgery(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-result-row-forgery",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-formal-result-row-forgery",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)
        original = _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-result-row-forgery",
            gate_passed=False,
        )
        assert original.evaluation.gate_passed is False

        quality = _quality_coverage(manifest)
        candidate_authority = (
            _register_candidate_review_source_authority(
                repository,
                manifest,
            )
        )
        forged_runner = _runner_report(
            manifest=manifest,
            attestation_sha256=(preflight.attestation.attestation_sha256),
            exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
            scan=scan,
            quality_coverage=quality,
            eligibility_history=_current_history(repository, preflight),
            candidate_review_source_authority=candidate_authority,
            gate_passed=True,
        )
        _register_development_authority_for_report(
            repository,
            preflight,
            manifest,
            forged_runner,
        )
        forged_committed = json.loads(_canonical_json(forged_runner))
        assert isinstance(forged_committed, dict)
        forged_committed["formal_report"] = True
        forged_committed["formal_accuracy_claim"] = True
        forged_committed["formal_accuracy_claim_scope"] = "observed_real_locked_set_only"
        forged_committed["claim_status"] = "formal_accuracy_claim"

        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(text("DROP TRIGGER locked_set_formal_evaluations_immutable_update"))
        _replace_formal_report_payloads(
            runtime,
            manifest.dataset_id,
            runner_report=forged_runner,
            committed_report=forged_committed,
            gate_passed=True,
            formal_accuracy_claim=True,
        )

        with pytest.raises(
            LockedSetPersistenceError,
            match="request hash",
        ):
            repository.get_formal_release_evaluation(manifest.dataset_id)
        with pytest.raises(
            LockedSetPersistenceError,
            match="request hash",
        ):
            repository.get_replayable_formal_release_evaluation(manifest.dataset_id)
        with pytest.raises(
            LockedSetPersistenceError,
            match="request hash",
        ):
            _persist_formal_evaluation(
                repository,
                preflight,
                manifest,
                scan,
                idempotency_key="formal-result-row-forgery",
                gate_passed=False,
            )
    finally:
        runtime.close()


def test_similarity_scan_accepts_probe_to_probe_candidate_membership(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-probe-to-probe",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-probe-to-probe",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest = repository.get_manifest(preflight.dataset.dataset_id)
        probes = _probe_fingerprints(manifest)
        scan = _similarity_scan(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
            excluded_image_count=0,
            probes=probes,
        )
        first, second = probes[:2]
        scan["candidates"] = [
            {
                "candidate_id": "probe-to-probe-001",
                "comparison_scope": "probe_to_probe",
                "locked_image_sha256": first.content_sha256,
                "excluded_image_sha256": second.content_sha256,
                "detector": ALGORITHM_VERSION,
                "similarity": "0.9900",
            }
        ]
        scan["scan_fingerprint"] = _canonical_sha256(
            {field: value for field, value in scan.items() if field != "scan_fingerprint"}
        )

        outcome = repository.persist_similarity_scan(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
            inventory_high_watermark=(preflight.attestation.inventory_high_watermark),
            scan=scan,
            locked_image_fingerprints=probes,
            actor_id="developer-test",
        )

        assert outcome.applied is True
        assert outcome.scan.candidate_count == 1
    finally:
        runtime.close()


def test_formal_evaluation_rejects_stale_inventory_and_invalidation(
    tmp_path: Path,
    project_root: Path,
) -> None:
    for suffix, invalidate in (
        ("stale", False),
        ("invalidated", True),
    ):
        manifest_path, dataset_root = _write_sealed_fixture(
            tmp_path / f"fixtures-{suffix}",
            dataset_id=f"locked-formal-{suffix}",
        )
        runtime = _runtime(
            tmp_path / f"data-{suffix}",
            project_root,
            instance_id=f"locked-formal-{suffix}",
        )
        try:
            repository = _repository(runtime)
            preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
                manifest_path=manifest_path,
                dataset_root=dataset_root,
                actor_id="developer-test",
            )
            manifest, scan = _persist_scan(repository, preflight)
            expected_error: type[LockedSetPersistenceError]
            if invalidate:
                repository.invalidate_locked_set(
                    dataset_id=manifest.dataset_id,
                    expected_record_version=preflight.dataset.record_version,
                    influence_kind="template",
                    reason="Formal test invalidation",
                    actor_id="developer-test",
                    idempotency_key=f"invalidate-{suffix}",
                )
                expected_error = LockedSetStateTransitionError
            else:
                with runtime.commit_gate.transaction(runtime.engine) as connection:
                    register_exclusion_identity(
                        connection,
                        category="development_image",
                        identity_sha256="9" * 64,
                        source_kind="evidence_fixture",
                        source_id="changed-after-scan",
                        created_at="2026-07-26T00:00:03+00:00",
                    )
                expected_error = LockedSetInventoryChangedError

            with pytest.raises(expected_error):
                _persist_formal_evaluation(
                    repository,
                    preflight,
                    manifest,
                    scan,
                    idempotency_key=f"formal-{suffix}",
                )
            assert (
                _scalar(
                    runtime,
                    "SELECT count(*) FROM locked_set_formal_evaluations",
                )
                == 0
            )
        finally:
            runtime.close()


def test_formal_evaluation_idempotency_conflict_is_fail_closed(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-idempotency",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-formal-idempotency",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)
        _persist_formal_evaluation(
            repository,
            preflight,
            manifest,
            scan,
            idempotency_key="formal-idempotency",
        )

        with pytest.raises(LockedSetIdempotencyConflictError):
            _persist_formal_evaluation(
                repository,
                preflight,
                manifest,
                scan,
                idempotency_key="formal-idempotency",
                gate_passed=False,
            )
    finally:
        runtime.close()


def test_formal_evaluation_recomputes_gate_from_db_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id="locked-formal-forged-gate",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-formal-forged-gate",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)
        quality = _quality_coverage(manifest)
        candidate_authority = (
            _register_candidate_review_source_authority(
                repository,
                manifest,
            )
        )
        report = _runner_report(
            manifest=manifest,
            attestation_sha256=(preflight.attestation.attestation_sha256),
            exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
            scan=scan,
            quality_coverage=quality,
            eligibility_history=_current_history(
                repository,
                preflight,
            ),
            candidate_review_source_authority=candidate_authority,
        )
        _register_development_authority_for_report(
            repository,
            preflight,
            manifest,
            report,
        )
        metrics = report["metrics"]
        assert isinstance(metrics, dict)
        metrics["unknown_count"] = 99
        report["report_sha256"] = _canonical_sha256(
            {
                field: value
                for field, value in report.items()
                if field
                not in {
                    "image_results",
                    "pair_results",
                    "report_sha256",
                    "run_context",
                    "runner_report_sha256",
                    "runner_version",
                }
            }
        )
        report["runner_report_sha256"] = _canonical_sha256(
            {field: value for field, value in report.items() if field != "runner_report_sha256"}
        )

        with pytest.raises(
            LockedSetConflictError,
            match="independent DB-authority evaluation",
        ):
            repository.persist_formal_release_evaluation(
                dataset_id=manifest.dataset_id,
                manifest_sha256=manifest.canonical_sha256,
                exclusion_snapshot_sha256=(preflight.attestation.exclusion_snapshot_sha256),
                inventory_high_watermark=(preflight.attestation.inventory_high_watermark),
                scan_fingerprint=str(scan["scan_fingerprint"]),
                runner_report=report,
                quality_coverage=quality,
                near_duplicate_decisions=(),
                actor_id="developer-test",
                idempotency_key="formal-forged-gate",
            )
        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_formal_evaluations",
            )
            == 0
        )
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "failpoint_name",
    (
        "after_formal_evaluation_insert",
        "after_prior_locked_image_inventory",
        "after_prior_waybill_inventory",
    ),
)
def test_formal_evaluation_failpoints_roll_back_every_authority_write(
    tmp_path: Path,
    project_root: Path,
    failpoint_name: str,
) -> None:
    manifest_path, dataset_root = _write_sealed_fixture(
        tmp_path / "fixtures",
        dataset_id=f"locked-formal-rollback-{failpoint_name}",
    )
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id=f"locked-formal-rollback-{failpoint_name}",
    )
    try:
        repository = _repository(runtime)
        preflight = LockedSetReleaseService(repository=repository).seal_and_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id="developer-test",
        )
        manifest, scan = _persist_scan(repository, preflight)

        def failpoint(name: str) -> None:
            if name == failpoint_name:
                raise InjectedLockedSetFailure(name)

        failing = _repository(runtime, failpoint=failpoint)
        with pytest.raises(InjectedLockedSetFailure):
            _persist_formal_evaluation(
                failing,
                preflight,
                manifest,
                scan,
                idempotency_key=f"formal-rollback-{failpoint_name}",
            )

        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_formal_evaluations",
            )
            == 0
        )
        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_exclusion_inventory "
                "WHERE source_id = "
                f"'locked-formal-rollback-{failpoint_name}'",
            )
            == 0
        )
        assert repository.get_dataset(manifest.dataset_id).state == ("preflight_passed")
    finally:
        runtime.close()


def test_unfingerprinted_inventory_lists_real_evidence_and_rejects_orphans(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-unfingerprinted",
    )
    try:
        relative_path = "locked-set/evidence.png"
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO evidence_blobs (
                        sha256, relative_path, byte_size, media_type,
                        storage_state, record_version, created_at, verified_at
                    ) VALUES (
                        :sha256, :relative_path, 1, 'image/png',
                        'available', 1, :created_at, :created_at
                    )
                    """
                ),
                {
                    "sha256": "a" * 64,
                    "relative_path": relative_path,
                    "created_at": "2026-07-26T00:00:00+00:00",
                },
            )
            register_exclusion_identity(
                connection,
                category="development_image",
                identity_sha256="a" * 64,
                source_kind="evidence_fixture",
                source_id="real-image",
                created_at="2026-07-26T00:00:00+00:00",
            )
        repository = _repository(runtime)
        pending = repository.list_unfingerprinted_exclusion_images()
        assert [(item.category, item.sha256, item.relative_path) for item in pending] == [
            ("development_image", "a" * 64, relative_path)
        ]
        inserted = repository.register_exclusion_fingerprint(
            category="development_image",
            identity_sha256="a" * 64,
            fingerprint=_fingerprint_for_hash("a" * 64, index=1),
        )
        assert inserted is True
        assert repository.list_unfingerprinted_exclusion_images() == ()

        with runtime.commit_gate.transaction(runtime.engine) as connection:
            register_exclusion_identity(
                connection,
                category="shadow_image",
                identity_sha256="b" * 64,
                source_kind="synthetic_error_fixture",
                source_id="orphan-image",
                created_at="2026-07-26T00:00:01+00:00",
            )
        with pytest.raises(
            LockedSetInventoryEvidenceMissingError,
            match="evidence",
        ):
            repository.list_unfingerprinted_exclusion_images()
    finally:
        runtime.close()


def test_export_fingerprint_completion_appends_once_and_is_idempotent(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="locked-export-fingerprint-completion",
    )
    try:
        repository = _repository(runtime)
        evidence_store = ContentAddressedEvidenceStore(data_root / "evidence")
        identity_sha256 = _register_evidence_backed_exclusion(
            runtime,
            evidence_store=evidence_store,
            source_id="historical-development-image",
        )

        complete_existing_exclusion_fingerprints(
            repository=repository,
            evidence_store=evidence_store,
        )
        with runtime.engine.connect() as connection:
            first_rows = (
                connection.execute(
                    text(
                        """
                        SELECT source_kind, source_id,
                               perceptual_fingerprint_json,
                               fingerprint_sha256
                        FROM locked_set_exclusion_inventory
                        WHERE identity_sha256 = :identity_sha256
                        ORDER BY entry_sequence
                        """
                    ),
                    {"identity_sha256": identity_sha256},
                )
                .mappings()
                .all()
            )

        assert len(first_rows) == 2
        assert first_rows[0]["source_kind"] == "evidence_fixture"
        assert first_rows[0]["source_id"] == "historical-development-image"
        assert first_rows[0]["perceptual_fingerprint_json"] is None
        assert first_rows[0]["fingerprint_sha256"] is None
        assert first_rows[1]["source_kind"] == "code_owned_perceptual_fingerprint"
        assert first_rows[1]["perceptual_fingerprint_json"] is not None
        assert first_rows[1]["fingerprint_sha256"] == first_rows[1]["source_id"]
        assert repository.list_unfingerprinted_exclusion_images() == ()

        complete_existing_exclusion_fingerprints(
            repository=repository,
            evidence_store=evidence_store,
        )
        with runtime.engine.connect() as connection:
            replay_count = int(
                connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM locked_set_exclusion_inventory
                        WHERE identity_sha256 = :identity_sha256
                        """
                    ),
                    {"identity_sha256": identity_sha256},
                ).scalar_one()
            )
        assert replay_count == 2
    finally:
        runtime.close()


def test_export_fingerprint_completion_rejects_missing_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        tmp_path / "data",
        project_root,
        instance_id="locked-export-fingerprint-missing-evidence",
    )
    try:
        identity_sha256 = hashlib.sha256(b"missing-evidence").hexdigest()
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            register_exclusion_identity(
                connection,
                category="development_image",
                identity_sha256=identity_sha256,
                source_kind="evidence_fixture",
                source_id="missing-evidence",
                created_at="2026-07-27T00:00:00+00:00",
            )
        repository = _repository(runtime)

        with pytest.raises(
            LockedSetInventoryEvidenceMissingError,
            match="no available evidence",
        ):
            complete_existing_exclusion_fingerprints(
                repository=repository,
                evidence_store=ContentAddressedEvidenceStore(
                    runtime.data_root / "evidence"
                ),
            )

        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_exclusion_inventory "
                "WHERE perceptual_fingerprint_json IS NOT NULL",
            )
            == 0
        )
    finally:
        runtime.close()


def test_export_fingerprint_completion_rejects_non_addressed_evidence_path(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="locked-export-fingerprint-path-mismatch",
    )
    try:
        repository = _repository(runtime)
        evidence_store = ContentAddressedEvidenceStore(data_root / "evidence")
        _register_evidence_backed_exclusion(
            runtime,
            evidence_store=evidence_store,
            source_id="path-mismatch",
            registered_relative_path="legacy/non-addressed-evidence.blob",
        )

        with pytest.raises(
            FormalLockedSetReleaseError,
            match="path is not content-addressed",
        ):
            complete_existing_exclusion_fingerprints(
                repository=repository,
                evidence_store=evidence_store,
            )

        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_exclusion_inventory "
                "WHERE perceptual_fingerprint_json IS NOT NULL",
            )
            == 0
        )
    finally:
        runtime.close()


def test_export_fingerprint_completion_rejects_content_identity_mismatch(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root,
        project_root,
        instance_id="locked-export-fingerprint-content-mismatch",
    )
    try:
        repository = _repository(runtime)
        evidence_store = ContentAddressedEvidenceStore(data_root / "evidence")
        identity_sha256 = _register_evidence_backed_exclusion(
            runtime,
            evidence_store=evidence_store,
            source_id="content-mismatch",
        )
        evidence_store.path_for(identity_sha256).write_bytes(
            _fingerprintable_png_bytes(color=(150, 60, 30))
        )

        with pytest.raises(
            FormalLockedSetReleaseError,
            match="evidence cannot be fingerprinted",
        ):
            complete_existing_exclusion_fingerprints(
                repository=repository,
                evidence_store=evidence_store,
            )

        assert (
            _scalar(
                runtime,
                "SELECT count(*) FROM locked_set_exclusion_inventory "
                "WHERE perceptual_fingerprint_json IS NOT NULL",
            )
            == 0
        )
    finally:
        runtime.close()
