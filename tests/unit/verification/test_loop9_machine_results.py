from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from dahe.adapters.ocr.protocol import (
    NormalizedBox,
    OcrFieldValue,
    OcrResult,
    OcrResultStatus,
    OcrRoleObservation,
    OcrTextLine,
)
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
from dahe.application.template_studio.matcher import build_template_set_fingerprint
from dahe.domain.audit.evidence import EvidenceQuality
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.role_assessment import RoleAssessmentPolicy
from dahe.domain.ticket.templates import (
    NormalizedRect,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
)
from dahe.jobs.ocr_execution import (
    OcrRuntimeIdentity,
    qualified_runtime_set_sha256,
)
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildSource,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
)
from dahe.verification.locked_set_acceptance import LOCAL_OCR_RUNTIME_SOURCE
from dahe.verification.locked_set_runner import (
    IndependentLockedImage,
    LockedOcrRuntimeComparison,
    LockedOcrRuntimeOutput,
    LockedRolePrediction,
    LockedSetRunContext,
)
from dahe.verification.loop9_machine_results import (
    FormalHumanTruthBinding,
    FormalMachineAuthority,
    Loop9MachineResultError,
    SafeOcrObservationProjector,
    _evaluate_machine_truth,
    _formal_pipeline_contract_sha256,
    _formal_runtime_pipeline_sha256,
    build_formal_machine_result_manifest,
    build_shadow_review_auxiliary,
    load_machine_result_manifest,
    load_machine_truth_evaluation,
    nearest_rank_percentiles,
    persist_machine_result_manifest,
    persist_machine_truth_evaluation,
    project_safe_ocr_observation,
    read_scheduler_batch_projection,
)

IMAGE_SHA256 = "1" * 64
RUNTIME_SHA256 = "2" * 64
PIPELINE_SHA256 = "3" * 64
OUTPUT_SHA256 = "4" * 64


def _rect(x: str, y: str, width: str, height: str) -> NormalizedRect:
    return NormalizedRect(
        x=Decimal(x),
        y=Decimal(y),
        width=Decimal(width),
        height=Decimal(height),
    )


def _template(role: TicketRole) -> TemplateVersion:
    marker = role.value
    title = (
        "alpha coal inbound loading slip"
        if role is TicketRole.LOADING
        else "zulu quarry unloading scale receipt"
    )
    return TemplateVersion(
        version_id=f"{marker}-v1",
        definition=TemplateDefinition(
            family_id=f"{marker}-family",
            name=title,
            role=role,
            anchors=(
                TemplateAnchor(
                    anchor_id=f"{marker}-title",
                    expected_text=title,
                    box=_rect("0.10", "0.08", "0.30", "0.08"),
                    required=True,
                    weight=Decimal("1"),
                    max_edit_distance=Decimal("0.10"),
                    loading_evidence=(
                        Decimal("0.9") if role is TicketRole.LOADING else Decimal("-0.4")
                    ),
                    unloading_evidence=(
                        Decimal("0.9") if role is TicketRole.UNLOADING else Decimal("-0.4")
                    ),
                ),
            ),
            regions=(),
        ),
        lifecycle=TemplateLifecycle.SHADOW,
        parent_version_id=None,
        record_version=3,
    )


def _policy() -> RoleAssessmentPolicy:
    return RoleAssessmentPolicy(
        minimum_score=Decimal("0.60"),
        minimum_margin=Decimal("0.25"),
        minimum_sources=2,
        minimum_ticket_likelihood=Decimal("0.60"),
        high_confidence_score=Decimal("0.85"),
        version="loop9-machine-result-test-policy-v1",
    )


def _ocr_output(
    *,
    ordinary_net_raw_text: str = "32.70 t",
) -> str:
    title = "alpha coal inbound loading slip"
    return OcrResult(
        command_id="safe-projection-command",
        status=OcrResultStatus.OK,
        worker_identity="safe-projection-worker",
        runtime_fingerprint=RUNTIME_SHA256,
        verified_image_sha256=IMAGE_SHA256,
        elapsed_ms=12.5,
        text_lines=(
            OcrTextLine(
                text="sensitive full OCR line that must not be exported",
                confidence=Decimal("0.99"),
                box=NormalizedBox(
                    x=Decimal("0.01"),
                    y=Decimal("0.01"),
                    width=Decimal("0.50"),
                    height=Decimal("0.05"),
                ),
            ),
            OcrTextLine(
                text=title,
                confidence=Decimal("0.99"),
                box=NormalizedBox(
                    x=Decimal("0.10"),
                    y=Decimal("0.08"),
                    width=Decimal("0.30"),
                    height=Decimal("0.08"),
                ),
            ),
        ),
        fields={
            "ordinary_net": OcrFieldValue(
                raw_text=ordinary_net_raw_text,
                amount="32.70",
                unit="t",
                confidence=Decimal("0.98"),
            )
        },
        role_observation=OcrRoleObservation(
            fixed_text=("loading", "ticket", "net"),
            layout_fingerprint="loading-layout",
            orientation_degrees=90,
        ),
        error=None,
    ).model_dump_json()


def test_safe_projection_keeps_business_evidence_and_drops_full_ocr_text() -> None:
    projection = project_safe_ocr_observation(
        output_json=_ocr_output(),
        expected_image_sha256=IMAGE_SHA256,
        expected_runtime_fingerprint=RUNTIME_SHA256,
        runtime_kind="gpu",
        profile_id="qualified-gpu-profile",
        pipeline_fingerprint=PIPELINE_SHA256,
        output_fingerprint=OUTPUT_SHA256,
        templates=(
            _template(TicketRole.LOADING),
            _template(TicketRole.UNLOADING),
        ),
        role_policy=_policy(),
        wall_elapsed_ms=Decimal("14.75"),
    )

    payload = projection.to_payload()
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert payload["runtime_kind"] == "gpu"
    assert payload["profile_id"] == "qualified-gpu-profile"
    assert payload["pipeline_fingerprint"] == PIPELINE_SHA256
    assert payload["ordinary_net"] == {
        "amount": "32.7",
        "confidence": "0.98",
        "reliable": True,
        "review_reason": None,
        "unit": "t",
    }
    assert payload["role"]["predicted"] == "loading"
    assert payload["role"]["orientation_degrees"] == 90
    assert payload["template"]["version_ids"] == [
        "loading-v1",
        "unloading-v1",
    ]
    assert "sensitive full OCR line" not in serialized
    assert "text_lines" not in serialized
    assert len(str(payload["observation_sha256"])) == 64


def test_safe_projection_never_persists_arbitrary_weight_field_text() -> None:
    sensitive = "净重 32.70 联系电话 13800138000 任意正文"
    projection = project_safe_ocr_observation(
        output_json=_ocr_output(ordinary_net_raw_text=sensitive),
        expected_image_sha256=IMAGE_SHA256,
        expected_runtime_fingerprint=RUNTIME_SHA256,
        runtime_kind="gpu",
        profile_id="qualified-gpu-profile",
        pipeline_fingerprint=PIPELINE_SHA256,
        output_fingerprint=OUTPUT_SHA256,
        templates=(
            _template(TicketRole.LOADING),
            _template(TicketRole.UNLOADING),
        ),
        role_policy=_policy(),
        wall_elapsed_ms=Decimal("14.75"),
    )

    serialized = json.dumps(
        projection.to_payload(),
        ensure_ascii=False,
        sort_keys=True,
    )
    assert "13800138000" not in serialized
    assert "任意正文" not in serialized
    assert "raw_text" not in serialized


def test_safe_projector_is_injectable_without_returning_protocol_text() -> None:
    projector = SafeOcrObservationProjector(
        templates=(
            _template(TicketRole.LOADING),
            _template(TicketRole.UNLOADING),
        ),
        role_policy=_policy(),
    )

    payload = projector.project(
        output_json=_ocr_output(),
        expected_image_sha256=IMAGE_SHA256,
        expected_runtime_fingerprint=RUNTIME_SHA256,
        runtime_kind="gpu",
        profile_id="qualified-gpu-profile",
        pipeline_fingerprint=PIPELINE_SHA256,
        output_fingerprint=OUTPUT_SHA256,
        wall_elapsed_ms=Decimal("14.75"),
    ).to_payload()

    assert "text_lines" not in json.dumps(payload, ensure_ascii=False)


def test_safe_projection_rejects_runtime_or_image_identity_drift() -> None:
    with pytest.raises(Loop9MachineResultError, match="identity"):
        project_safe_ocr_observation(
            output_json=_ocr_output(),
            expected_image_sha256="9" * 64,
            expected_runtime_fingerprint=RUNTIME_SHA256,
            runtime_kind="gpu",
            profile_id="qualified-gpu-profile",
            pipeline_fingerprint=PIPELINE_SHA256,
            output_fingerprint=OUTPUT_SHA256,
            templates=(
                _template(TicketRole.LOADING),
                _template(TicketRole.UNLOADING),
            ),
            role_policy=_policy(),
            wall_elapsed_ms=Decimal("14.75"),
        )


def test_nearest_rank_percentiles_are_deterministic_and_report_sample_size() -> None:
    assert nearest_rank_percentiles(
        [Decimal("1"), Decimal("2"), Decimal("3"), Decimal("4")],
    ) == {
        "sample_size": 4,
        "p50_ms": "2",
        "p95_ms": "4",
    }
    assert nearest_rank_percentiles([]) == {
        "sample_size": 0,
        "p50_ms": None,
        "p95_ms": None,
    }


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _rehash_machine_result(payload: dict[str, object]) -> None:
    for result in payload["results"]:
        result["result_sha256"] = _canonical_hash(
            {
                key: value
                for key, value in result.items()
                if key != "result_sha256"
            }
        )
    payload["canonical_sha256"] = _canonical_hash(
        {
            key: value
            for key, value in payload.items()
            if key != "canonical_sha256"
        }
    )


def _fingerprint(image_sha256: str) -> ImagePerceptualFingerprint:
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=image_sha256,
        width=10,
        height=10,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop,
                average_hash="0" * 64,
                difference_hash="f" * 64,
            )
            for crop in (1000, 920, 840, 760)
        ),
    )


def _formal_application_build() -> ApplicationBuildManifest:
    return ApplicationBuildManifest(
        application_version="test",
        sources=(
            ApplicationBuildSource(
                path="source.py",
                sha256="9" * 64,
            ),
        ),
    )


def _shadow_batch(
    target: ShadowBatchTargetKind = ShadowBatchTargetKind.REAL_SHADOW_30,
) -> ChengfengShadowBatchManifest:
    items: list[ShadowBatchItem] = []
    for index in range(target.expected_count):
        images = tuple(
            ShadowBatchImage(
                slot=slot,
                sha256=(digest := _sha(f"{target.value}:{index}:{slot}")),
                relative_path=(f"sha256/{digest[:2]}/{digest[2:4]}/{digest}.blob"),
                byte_size=100 + index,
                media_type="image/png",
                perceptual_fingerprint=_fingerprint(digest),
            )
            for slot in ("loading", "unloading")
        )
        items.append(
            ShadowBatchItem(
                platform_waybill_id_digest=_sha(f"platform:{target.value}:{index}"),
                waybill_number_digest=_sha(f"waybill:{target.value}:{index}"),
                vehicle_number_digest=_sha(f"vehicle:{target.value}:{index}"),
                platform_loading_net="32.70",
                platform_unloading_net="32.70",
                images=images,  # type: ignore[arg-type]
            )
        )
    return ChengfengShadowBatchManifest(
        target_kind=target,
        source_build_sha256="a" * 64,
        contract_canonical_sha256="b" * 64,
        contract_file_sha256="c" * 64,
        contract_selection_sha256="d" * 64,
        pipeline_fingerprint=(
            _formal_application_build().canonical_sha256
        ),
        identity_context_sha256="f" * 64,
        sources=(
            ShadowBatchSource(
                access_window_id="window-001",
                job_id="capture-job-001",
                capture_id="capture-001",
                scope="pending_settlement",
                page_number=1,
                page_size=100,
                checkpoint_sha256="1" * 64,
            ),
        ),
        items=tuple(items),
    )


def _formal_selection(
    batch: ChengfengShadowBatchManifest,
) -> FormalShadowSelectionManifest:
    target = batch.target_kind
    return FormalShadowSelectionManifest(
        target_kind=target,
        source_capture_sha256=_sha(f"capture:{target.value}"),
        full_history_exclusion_authority_sha256=_sha(
            f"exclusions:{target.value}"
        ),
        exclusion_child_index_head_sha256=_sha(
            f"exclusion-head:{target.value}"
        ),
        exclusion_source_boundary_sha256=_sha(
            f"exclusion-boundary:{target.value}"
        ),
        exclusion_source_inventory_high_watermark=100,
        selection_seed_authority_sha256=_sha(
            f"seed:{target.value}"
        ),
        rank_commitment_sha256=_sha(f"rank:{target.value}"),
        prior_selection_sha256s=(
            ()
            if target is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else (_sha("locked-selection"),)
        ),
        batch_manifest=batch,
        locked_gate_evidence_sha256=(
            None
            if target is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else _sha("current-locked-gate")
        ),
    )


def _create_scheduler_database(
    data_root: Path,
    *,
    batch: ChengfengShadowBatchManifest,
    job_id: str = "formal-job-001",
) -> None:
    database_root = data_root / "database"
    database_root.mkdir(parents=True)
    connection = sqlite3.connect(database_root / "dahe.sqlite3")
    try:
        connection.executescript(
            """
            CREATE TABLE jobs (
                job_id TEXT PRIMARY KEY,
                task_type TEXT NOT NULL,
                scope_fixture_id TEXT NOT NULL,
                run_mode TEXT NOT NULL,
                status TEXT NOT NULL,
                job_kind TEXT NOT NULL,
                ocr_execution_mode TEXT NOT NULL,
                record_version INTEGER NOT NULL
            );
            CREATE TABLE work_items (
                work_item_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                record_version INTEGER NOT NULL,
                waybill_number TEXT NOT NULL,
                vehicle_number TEXT NOT NULL,
                status TEXT NOT NULL,
                current_stage TEXT NOT NULL,
                business_outcome TEXT,
                decision TEXT,
                review_reason TEXT,
                diagnostic_code TEXT,
                item_index INTEGER NOT NULL,
                loading_image_sha256 TEXT,
                unloading_image_sha256 TEXT,
                pipeline_fingerprint TEXT,
                fixture_platform_loading_net TEXT,
                fixture_platform_unloading_net TEXT,
                platform_loading_net TEXT,
                platform_unloading_net TEXT,
                ocr_generation_id TEXT
            );
            CREATE TABLE ocr_run_generations (
                generation_id TEXT PRIMARY KEY,
                work_item_id TEXT NOT NULL UNIQUE,
                pipeline_fingerprint TEXT NOT NULL,
                primary_runtime_kind TEXT NOT NULL,
                next_runtime_kind TEXT NOT NULL,
                status TEXT NOT NULL,
                committed_runtime_kind TEXT,
                committed_profile_id TEXT,
                committed_runtime_fingerprint TEXT,
                loading_output_fingerprint TEXT,
                unloading_output_fingerprint TEXT,
                diagnostic_code TEXT,
                record_version INTEGER NOT NULL
            );
            CREATE TABLE stage_attempts (
                stage_attempt_id TEXT PRIMARY KEY,
                consumer_job_id TEXT,
                work_item_id TEXT,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                resource_name TEXT,
                attempt_number INTEGER NOT NULL,
                started_sequence INTEGER NOT NULL,
                finished_sequence INTEGER,
                diagnostic_code TEXT,
                runtime_kind TEXT,
                profile_id TEXT,
                runtime_fingerprint TEXT,
                pipeline_fingerprint TEXT,
                input_fingerprint TEXT,
                output_fingerprint TEXT,
                discarded INTEGER NOT NULL,
                error_kind TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                job_id,
                "audit",
                (f"chengfeng-shadow:{batch.target_kind.value}:{batch.canonical_sha256}"),
                "shadow",
                "succeeded",
                "business",
                "local",
                7,
            ),
        )
        for index, item in enumerate(
            sorted(batch.items, key=lambda value: value.item_identity_sha256)
        ):
            by_slot = {image.slot: image for image in item.images}
            work_item_id = f"work-{index:03d}"
            generation_id = f"generation-{index:03d}"
            connection.execute(
                "INSERT INTO work_items VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    work_item_id,
                    job_id,
                    4,
                    f"CF-{item.item_identity_sha256}",
                    "protected",
                    "succeeded",
                    "audit.compare",
                    "normal_ready",
                    "pass",
                    None,
                    None,
                    index,
                    by_slot["loading"].sha256,
                    by_slot["unloading"].sha256,
                    batch.pipeline_fingerprint,
                    item.platform_loading_net,
                    item.platform_unloading_net,
                    item.platform_loading_net,
                    item.platform_unloading_net,
                    generation_id,
                ),
            )
            connection.execute(
                "INSERT INTO ocr_run_generations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    generation_id,
                    work_item_id,
                    _sha(f"runtime-pipeline:{index}"),
                    "gpu",
                    "gpu",
                    "succeeded",
                    "gpu",
                    "gpu-profile",
                    RUNTIME_SHA256,
                    _sha(f"loading-output:{index}"),
                    _sha(f"unloading-output:{index}"),
                    None,
                    3,
                ),
            )
            connection.execute(
                "INSERT INTO stage_attempts VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"attempt-{index:03d}",
                    job_id,
                    work_item_id,
                    "audit.recognize",
                    "succeeded",
                    "gpu_ocr_slot",
                    1,
                    index * 2,
                    index * 2 + 1,
                    None,
                    "gpu",
                    "gpu-profile",
                    RUNTIME_SHA256,
                    _sha(f"runtime-pipeline:{index}"),
                    _sha(f"input:{index}"),
                    _sha(f"output:{index}"),
                    0,
                    None,
                ),
            )
        connection.commit()
    finally:
        connection.close()


def _runtime_output(
    *,
    image_sha256: str,
    runtime_kind: str,
    role: TicketRole,
) -> LockedOcrRuntimeOutput:
    return LockedOcrRuntimeOutput(
        image_sha256=image_sha256,
        runtime_kind=runtime_kind,
        runtime_fingerprint=_sha(f"{runtime_kind}:runtime"),
        output_fingerprint=_sha(f"{runtime_kind}:{image_sha256}:output"),
        worker_elapsed_ms=Decimal("10") if runtime_kind == "gpu" else Decimal("50"),
        wall_elapsed_ms=Decimal("12") if runtime_kind == "gpu" else Decimal("55"),
        ordinary_net_amount=Decimal("32.70"),
        ordinary_net_unit="t",
        ordinary_net_confidence=Decimal("0.99"),
        ordinary_net_reliable=True,
        role=role,
        role_quality=EvidenceQuality.RELIABLE,
        role_confidence=Decimal("0.99"),
        role_high_confidence=True,
        safety_route="eligible_for_downstream_comparison",
        assessment_fingerprint=_sha(f"{runtime_kind}:{image_sha256}:role"),
        role_elapsed_ms=(
            Decimal("3") if runtime_kind == "gpu" else Decimal("9")
        ),
    )


class _FakeDualEvaluator:
    def __init__(self, batch: ChengfengShadowBatchManifest) -> None:
        self._roles = {
            image.sha256: (TicketRole.LOADING if image.slot == "loading" else TicketRole.UNLOADING)
            for item in batch.items
            for image in item.images
        }

    def __call__(self, image: IndependentLockedImage) -> LockedRolePrediction:
        role = self._roles[image.image_sha256]
        cpu = _runtime_output(
            image_sha256=image.image_sha256,
            runtime_kind="cpu",
            role=role,
        )
        gpu = _runtime_output(
            image_sha256=image.image_sha256,
            runtime_kind="gpu",
            role=role,
        )
        return LockedRolePrediction(
            image_sha256=image.image_sha256,
            role=role,
            quality=EvidenceQuality.RELIABLE,
            confidence=Decimal("0.99"),
            high_confidence=True,
            assessment_fingerprint=gpu.assessment_fingerprint,
            incremental_elapsed_ms=Decimal("70"),
            runtime_comparison=LockedOcrRuntimeComparison(
                status="dual_consistent",
                source=LOCAL_OCR_RUNTIME_SOURCE,
                reason=None,
                selected_runtime_kind="gpu",
                critical_fields_match=True,
                differences=(),
                outputs=(cpu, gpu),
                failures=(),
            ),
        )


class _MissingRoleTimingEvaluator(_FakeDualEvaluator):
    def __call__(self, image: IndependentLockedImage) -> LockedRolePrediction:
        prediction = super().__call__(image)
        comparison = prediction.runtime_comparison
        outputs = tuple(
            replace(output, role_elapsed_ms=None)
            if output.runtime_kind == "gpu"
            else output
            for output in comparison.outputs
        )
        return replace(
            prediction,
            runtime_comparison=replace(
                comparison,
                outputs=outputs,
            ),
        )


def _authority() -> FormalMachineAuthority:
    templates = (
        _template(TicketRole.LOADING),
        _template(TicketRole.UNLOADING),
    )
    application_build = _formal_application_build()
    runtime_identities = (
        OcrRuntimeIdentity(
            runtime_kind="cpu",
            profile_id="cpu-profile",
            runtime_fingerprint=_sha("cpu:runtime"),
        ),
        OcrRuntimeIdentity(
            runtime_kind="gpu",
            profile_id="gpu-profile",
            runtime_fingerprint=_sha("gpu:runtime"),
        ),
    )
    runtime_set_sha256 = qualified_runtime_set_sha256(
        [
            {
                "profile_id": identity.profile_id,
                "runtime_fingerprint": identity.runtime_fingerprint,
                "runtime_kind": identity.runtime_kind,
            }
            for identity in runtime_identities
        ]
    )
    run_context = LockedSetRunContext(
        application_build_sha256=application_build.canonical_sha256,
        application_build_manifest=application_build,
        runtime_set_sha256=runtime_set_sha256,
        ocr_composition_evidence_sha256="7" * 64,
        template_set_sha256=build_template_set_fingerprint(templates),
        matcher_sha256="6" * 64,
        policy_sha256="5" * 64,
        expected_runtime_kinds=("cpu", "gpu"),
    )
    pipeline_contract_sha256 = _formal_pipeline_contract_sha256(
        run_context.to_payload()
    )
    return FormalMachineAuthority(
        current_loop9_build_sha256="a" * 64,
        development_authority_sha256="4" * 64,
        run_context=run_context,
        templates=templates,
        runtime_identities=runtime_identities,
        runtime_pipeline_fingerprints={
            identity.runtime_kind: _formal_runtime_pipeline_sha256(
                pipeline_contract_sha256=pipeline_contract_sha256,
                runtime_kind=identity.runtime_kind,
                profile_id=identity.profile_id,
                runtime_fingerprint=identity.runtime_fingerprint,
            )
            for identity in runtime_identities
        },
    )


def test_scheduler_projection_and_formal_manifest_are_exact_and_replayable(
    tmp_path: Path,
) -> None:
    batch = _shadow_batch()
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    _create_scheduler_database(data_root, batch=batch)

    scheduler = read_scheduler_batch_projection(
        data_root=data_root,
        batch=batch,
        job_id="formal-job-001",
    )
    assert scheduler.job_id == "formal-job-001"
    assert len(scheduler.items) == 30
    assert all(item.generation.status == "succeeded" for item in scheduler.items)

    payload = build_formal_machine_result_manifest(
        batch=batch,
        source_selection=_formal_selection(batch),
        scheduler=scheduler,
        authority=_authority(),
        evaluator=_FakeDualEvaluator(batch),
    )
    assert payload["source"]["formal_selection_sha256"] == (
        _formal_selection(batch).canonical_sha256
    )
    assert payload["source"]["locked_gate_evidence_sha256"] == (
        _formal_selection(batch).locked_gate_evidence_sha256
    )
    assert payload["item_count"] == 30
    assert payload["image_count"] == 60
    assert payload["successful_runtime_observation_count"] == 120
    assert payload["technical_failure_count"] == 0
    assert payload["performance"]["gpu_worker"]["sample_size"] == 60
    assert payload["performance"]["cpu_worker"]["sample_size"] == 60
    assert payload["performance"]["gpu_role"]["sample_size"] == 60
    assert payload["performance"]["cpu_role"]["sample_size"] == 60
    assert all(
        observation["role"]["elapsed_ms"] is not None
        for result in payload["results"]
        for image in result["image_evaluations"]
        for observation in image["runtime_observations"]
    )
    assert all(
        set(result["protected_identity"])
        == {
            "platform_waybill_id_sha256",
            "vehicle_number_sha256",
            "waybill_number_sha256",
        }
        for result in payload["results"]
    )

    persisted = persist_machine_result_manifest(
        data_root=data_root,
        payload=payload,
    )
    assert persisted.name == f"{payload['canonical_sha256']}.json"
    assert load_machine_result_manifest(persisted) == payload
    assert persist_machine_result_manifest(data_root=data_root, payload=payload) == persisted

    auxiliary = build_shadow_review_auxiliary(payload)
    assert auxiliary["kind"] == "loop9_machine_audit_results"
    assert len(auxiliary["results"]) == 30
    assert all(len(result["images"]) == 2 for result in auxiliary["results"])


def test_formal_machine_result_rejects_missing_role_timing(
    tmp_path: Path,
) -> None:
    batch = _shadow_batch()
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    _create_scheduler_database(data_root, batch=batch)
    scheduler = read_scheduler_batch_projection(
        data_root=data_root,
        batch=batch,
        job_id="formal-job-001",
    )

    with pytest.raises(
        Loop9MachineResultError,
        match="role timing is missing",
    ):
        build_formal_machine_result_manifest(
            batch=batch,
            source_selection=_formal_selection(batch),
            scheduler=scheduler,
            authority=_authority(),
            evaluator=_MissingRoleTimingEvaluator(batch),
        )


def test_scheduler_projection_rejects_missing_generation_without_omission(
    tmp_path: Path,
) -> None:
    batch = _shadow_batch()
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    _create_scheduler_database(data_root, batch=batch)
    database = data_root / "database" / "dahe.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "DELETE FROM ocr_run_generations WHERE work_item_id = ?",
            ("work-005",),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(Loop9MachineResultError, match="generation"):
        read_scheduler_batch_projection(
            data_root=data_root,
            batch=batch,
            job_id="formal-job-001",
        )


def _truth_reviews(
    batch: ChengfengShadowBatchManifest,
) -> list[dict[str, object]]:
    return [
        {
            "item_identity_sha256": item.item_identity_sha256,
            "confirmed_at": "2026-07-30T00:00:00Z",
            "confirmation": (
                "machine_result_confirmed"
                if batch.target_kind is ShadowBatchTargetKind.REAL_SHADOW_30
                else "suggestion_confirmed"
            ),
            "images": [
                {
                    "slot": image.slot,
                    "image_sha256": image.sha256,
                    "role": image.slot,
                    "ordinary_net": "32.70",
                    "quality_conditions": ["rotation_0", "clear"],
                }
                for image in item.images
            ],
            "pair_condition": "normal_pair",
        }
        for item in sorted(
            batch.items,
            key=lambda value: value.item_identity_sha256,
        )
    ]


def test_formal_metrics_exist_only_with_confirmed_truth_and_count_both_runtimes(
    tmp_path: Path,
) -> None:
    batch = _shadow_batch()
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    _create_scheduler_database(data_root, batch=batch)
    scheduler = read_scheduler_batch_projection(
        data_root=data_root,
        batch=batch,
        job_id="formal-job-001",
    )
    machine = build_formal_machine_result_manifest(
        batch=batch,
        source_selection=_formal_selection(batch),
        scheduler=scheduler,
        authority=_authority(),
        evaluator=_FakeDualEvaluator(batch),
    )

    evaluation = _evaluate_machine_truth(
        batch=batch,
        source_selection=_formal_selection(batch),
        machine_payload=machine,
        reviews=_truth_reviews(batch),
        package_sha256="8" * 64,
        seal_sha256="9" * 64,
    )

    assert evaluation["gate_passed"] is True
    assert evaluation["wrong_auto_pass_count"] == 0
    assert evaluation["high_confidence_role_error_count"] == 0
    assert evaluation["runtime_observation_count"] == 120

    persisted = persist_machine_truth_evaluation(
        data_root=data_root,
        payload=evaluation,
    )
    assert load_machine_truth_evaluation(persisted) == evaluation

    tampered = json.loads(persisted.read_text(encoding="utf-8"))
    tampered["gate_passed"] = False
    persisted.write_text(
        json.dumps(
            tampered,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        Loop9MachineResultError,
        match=r"canonical|integrity",
    ):
        load_machine_truth_evaluation(persisted)


class _WrongRoleEvaluator(_FakeDualEvaluator):
    def __init__(self, batch: ChengfengShadowBatchManifest) -> None:
        super().__init__(batch)
        first = sorted(
            image.sha256 for item in batch.items for image in item.images if image.slot == "loading"
        )[0]
        self._roles[first] = TicketRole.UNLOADING


def test_high_confidence_runtime_role_error_fails_the_truth_gate(
    tmp_path: Path,
) -> None:
    batch = _shadow_batch()
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    _create_scheduler_database(data_root, batch=batch)
    scheduler = read_scheduler_batch_projection(
        data_root=data_root,
        batch=batch,
        job_id="formal-job-001",
    )
    machine = build_formal_machine_result_manifest(
        batch=batch,
        source_selection=_formal_selection(batch),
        scheduler=scheduler,
        authority=_authority(),
        evaluator=_WrongRoleEvaluator(batch),
    )

    evaluation = _evaluate_machine_truth(
        batch=batch,
        source_selection=_formal_selection(batch),
        machine_payload=machine,
        reviews=_truth_reviews(batch),
        package_sha256="8" * 64,
        seal_sha256="9" * 64,
    )

    assert evaluation["gate_passed"] is False
    assert evaluation["high_confidence_role_error_count"] == 2


def test_current_locked_formal_run_requires_prior_human_truth_seal(
    tmp_path: Path,
) -> None:
    batch = _shadow_batch(ShadowBatchTargetKind.CURRENT_LOCKED_50)
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    _create_scheduler_database(data_root, batch=batch)
    scheduler = read_scheduler_batch_projection(
        data_root=data_root,
        batch=batch,
        job_id="formal-job-001",
    )

    with pytest.raises(Loop9MachineResultError, match="human truth seal"):
        build_formal_machine_result_manifest(
            batch=batch,
            source_selection=_formal_selection(batch),
            scheduler=scheduler,
            authority=_authority(),
            evaluator=_FakeDualEvaluator(batch),
        )

    binding = FormalHumanTruthBinding(
        review_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50.value,
        source_batch_sha256=batch.canonical_sha256,
        source_build_sha256=batch.source_build_sha256,
        package_sha256="7" * 64,
        seal_sha256="8" * 64,
        review_count=50,
        image_truth_count=100,
    )
    payload = build_formal_machine_result_manifest(
        batch=batch,
        source_selection=_formal_selection(batch),
        scheduler=scheduler,
        authority=_authority(),
        evaluator=_FakeDualEvaluator(batch),
        human_truth_binding=binding,
    )

    assert payload["human_truth_binding"]["seal_sha256"] == "8" * 64
    assert payload["human_truth_binding"]["review_count"] == 50


def _current_locked_machine_result(
    tmp_path: Path,
) -> tuple[ChengfengShadowBatchManifest, dict[str, object]]:
    batch = _shadow_batch(ShadowBatchTargetKind.CURRENT_LOCKED_50)
    data_root = (tmp_path / "formal-current-locked").resolve()
    data_root.mkdir()
    _create_scheduler_database(data_root, batch=batch)
    scheduler = read_scheduler_batch_projection(
        data_root=data_root,
        batch=batch,
        job_id="formal-job-001",
    )
    binding = FormalHumanTruthBinding(
        review_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50.value,
        source_batch_sha256=batch.canonical_sha256,
        source_build_sha256=batch.source_build_sha256,
        package_sha256="7" * 64,
        seal_sha256="8" * 64,
        review_count=50,
        image_truth_count=100,
    )
    return (
        batch,
        build_formal_machine_result_manifest(
            batch=batch,
            source_selection=_formal_selection(batch),
            scheduler=scheduler,
            authority=_authority(),
            evaluator=_FakeDualEvaluator(batch),
            human_truth_binding=binding,
        ),
    )


def test_machine_result_rejects_stale_nested_authority_hash(
    tmp_path: Path,
) -> None:
    _batch, machine = _current_locked_machine_result(tmp_path)
    authority = machine["authority"]
    authority["development_authority_sha256"] = "0" * 64
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match="authority",
    ):
        persist_machine_result_manifest(
            data_root=(tmp_path / "formal-current-locked").resolve(),
            payload=machine,
        )


def test_machine_truth_rejects_declared_100_images_backed_by_only_50(
    tmp_path: Path,
) -> None:
    batch, machine = _current_locked_machine_result(tmp_path)
    for result in machine["results"]:
        loading = next(
            image
            for image in result["image_evaluations"]
            if image["slot"] == "loading"
        )
        loading["runtime_observations"] = [
            *loading["runtime_observations"],
            *deepcopy(loading["runtime_observations"]),
        ]
        result["image_evaluations"] = [loading]
        result["automatic_outcome"] = "awaiting_review"
    machine["successful_runtime_observation_count"] = 200
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match=r"image|runtime",
    ):
        _evaluate_machine_truth(
            batch=batch,
            source_selection=_formal_selection(batch),
            machine_payload=machine,
            reviews=_truth_reviews(batch),
            package_sha256="7" * 64,
            seal_sha256="8" * 64,
        )


def test_machine_truth_rejects_rehashed_runtime_pipeline_forgery(
    tmp_path: Path,
) -> None:
    batch, machine = _current_locked_machine_result(tmp_path)
    result = machine["results"][0]
    image = result["image_evaluations"][0]
    observation = image["runtime_observations"][0]
    observation["pipeline_fingerprint"] = "0" * 64
    observation_core = {
        key: value
        for key, value in observation.items()
        if key != "observation_sha256"
    }
    observation["observation_sha256"] = _canonical_hash(
        observation_core
    )
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match="pipeline",
    ):
        _evaluate_machine_truth(
            batch=batch,
            source_selection=_formal_selection(batch),
            machine_payload=machine,
            reviews=_truth_reviews(batch),
            package_sha256="7" * 64,
            seal_sha256="8" * 64,
        )


def test_machine_truth_rejects_batch_image_substitution(
    tmp_path: Path,
) -> None:
    batch, machine = _current_locked_machine_result(tmp_path)
    image = machine["results"][0]["image_evaluations"][0]
    image["image_sha256"] = "0" * 64
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match="image identity",
    ):
        _evaluate_machine_truth(
            batch=batch,
            source_selection=_formal_selection(batch),
            machine_payload=machine,
            reviews=_truth_reviews(batch),
            package_sha256="7" * 64,
            seal_sha256="8" * 64,
        )


def test_machine_truth_rejects_duplicated_cpu_observation(
    tmp_path: Path,
) -> None:
    batch, machine = _current_locked_machine_result(tmp_path)
    image = machine["results"][0]["image_evaluations"][0]
    image["runtime_observations"] = [
        image["runtime_observations"][0],
        deepcopy(image["runtime_observations"][0]),
    ]
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match="CPU and one GPU",
    ):
        _evaluate_machine_truth(
            batch=batch,
            source_selection=_formal_selection(batch),
            machine_payload=machine,
            reviews=_truth_reviews(batch),
            package_sha256="7" * 64,
            seal_sha256="8" * 64,
        )


def test_machine_truth_rejects_stale_runtime_comparison_hash(
    tmp_path: Path,
) -> None:
    batch, machine = _current_locked_machine_result(tmp_path)
    comparison = machine["results"][0]["image_evaluations"][0][
        "runtime_comparison"
    ]
    comparison["comparison_sha256"] = "0" * 64
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match="comparison integrity",
    ):
        _evaluate_machine_truth(
            batch=batch,
            source_selection=_formal_selection(batch),
            machine_payload=machine,
            reviews=_truth_reviews(batch),
            package_sha256="7" * 64,
            seal_sha256="8" * 64,
        )


def test_machine_truth_rejects_invented_automatic_review_reason(
    tmp_path: Path,
) -> None:
    batch, machine = _current_locked_machine_result(tmp_path)
    selected = machine["results"][0]["image_evaluations"][0][
        "selected"
    ]
    selected["automatic_review_reason"] = (
        "ticket_weight_format_suspicious"
    )
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match="review reason",
    ):
        _evaluate_machine_truth(
            batch=batch,
            source_selection=_formal_selection(batch),
            machine_payload=machine,
            reviews=_truth_reviews(batch),
            package_sha256="7" * 64,
            seal_sha256="8" * 64,
        )


def test_machine_truth_rejects_forged_performance_summary(
    tmp_path: Path,
) -> None:
    batch, machine = _current_locked_machine_result(tmp_path)
    machine["performance"]["cpu_worker"]["sample_size"] = 1
    _rehash_machine_result(machine)

    with pytest.raises(
        Loop9MachineResultError,
        match="performance summary",
    ):
        _evaluate_machine_truth(
            batch=batch,
            source_selection=_formal_selection(batch),
            machine_payload=machine,
            reviews=_truth_reviews(batch),
            package_sha256="7" * 64,
            seal_sha256="8" * 64,
        )
