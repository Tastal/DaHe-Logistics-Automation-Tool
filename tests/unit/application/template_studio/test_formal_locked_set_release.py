from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from dahe.adapters.sqlite.locked_set import (
    LockedSetFormalEvaluationRecord,
    LockedSetSimilarityScanRecord,
)
from dahe.application.template_studio import formal_locked_set_release as module
from dahe.application.template_studio.candidate_review_seal import (
    CandidateReviewSeal,
)
from dahe.application.template_studio.candidate_review_semantics import (
    candidate_review_waybill_membership_sha256,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrFormalAuthority,
    OcrImageExecution,
    OcrImageWork,
    OcrRuntimeIdentity,
)
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildSource,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    NearDuplicateCandidate,
)
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedTicketImage,
    LockedWaybill,
)
from dahe.verification.locked_set_similarity_scan import (
    LockedSetSimilarityCandidate,
    LockedSetSimilarityScan,
)


class _Gateway:
    def __init__(self, identity: OcrRuntimeIdentity) -> None:
        self._identity = identity

    @property
    def identity(self) -> OcrRuntimeIdentity:
        return self._identity

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        raise AssertionError(
            f"formal boundary test unexpectedly ran OCR: "
            f"{image.image_sha256} {pipeline_fingerprint}"
        )

    def close(self) -> None:
        return None


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _candidate_review_source_authority() -> dict[str, object]:
    return {
        "schema_version": 1,
        "seal_sha256": "a" * 64,
        "package_sha256": "b" * 64,
        "record_set_sha256": "c" * 64,
        "review_history_authority_sha256": "d" * 64,
        "source_authority_sha256": "e" * 64,
    }


def _development_authority() -> module.FormalDevelopmentAuthority:
    return module.FormalDevelopmentAuthority(
        authority_sha256="f" * 64,
        payload={
            "authority_sha256": "f" * 64,
            "shadow_template_set_fingerprint": "e" * 64,
        },
        exclusion_snapshot=SimpleNamespace(  # type: ignore[arg-type]
            canonical_sha256="d" * 64,
        ),
        inventory_high_watermark=3,
        perceptual_fingerprints=(),
        shadow_templates=(),
        eligibility_contract=SimpleNamespace(),  # type: ignore[arg-type]
    )


def _candidate_manifest(dataset_id: str) -> LockedSetManifest:
    return LockedSetManifest(
        dataset_id=dataset_id,
        dataset_kind="locked",
        tuning_prohibited=True,
        waybills=tuple(
            LockedWaybill(
                sample_id=f"L7-{position:03d}",
                waybill_identity_sha256=hashlib.sha256(
                    f"{dataset_id}:waybill:{position}".encode()
                ).hexdigest(),
                images=tuple(
                    LockedTicketImage(
                        image_sha256=hashlib.sha256(
                            (f"{dataset_id}:{position}:{slot.value}").encode()
                        ).hexdigest(),
                        relative_path=(f"images/{position:03d}-{slot.value}.jpg"),
                        slot=slot,
                        role=role,
                        ordinary_net=net,
                    )
                    for slot, role, net in (
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


def _candidate_quality_coverage(
    *,
    dataset_id: str,
    manifest_sha256: str,
) -> dict[str, object]:
    quality: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": dataset_id,
        "manifest_sha256": manifest_sha256,
        "required_conditions": [],
        "entries": [],
        "derived_adversarial_suite": {},
    }
    quality["quality_coverage_sha256"] = module.locked_set_quality_coverage_sha256(quality)
    return quality


def _candidate_source_payload(
    manifest: LockedSetManifest,
    *,
    package_sha256: str,
    record_set_sha256: str,
    quality_coverage_sha256: str,
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    verified_images: list[dict[str, object]] = []
    waybill_membership: list[dict[str, object]] = []
    for waybill in manifest.waybills:
        review_images: list[dict[str, object]] = []
        member_images: list[dict[str, object]] = []
        for image in waybill.images:
            ordinary_net = format(image.ordinary_net, "f")
            review_images.append(
                {
                    "submitted_slot": image.slot.value,
                    "role": image.role.value,
                    "ordinary_net": ordinary_net,
                    "quality_conditions": [
                        "rotation_0",
                        ("printed" if image.slot is TicketSlot.LOADING else "screen"),
                    ],
                    "notes": None,
                }
            )
            verified_images.append(
                {
                    "sample_id": waybill.sample_id,
                    "submitted_slot": image.slot.value,
                    "image_sha256": image.image_sha256,
                    "relative_path": image.relative_path,
                    "width": 1000,
                    "height": 800,
                    "media_type": "image/jpeg",
                    "byte_count": 100,
                }
            )
            member_images.append(
                {
                    "submitted_slot": image.slot.value,
                    "image_sha256": image.image_sha256,
                    "relative_path": image.relative_path,
                    "ticket_role": image.role.value,
                    "ordinary_net_kg": str(int(image.ordinary_net * 1000)),
                }
            )
        records.append(
            {
                "sample_id": waybill.sample_id,
                "record_version": 1,
                "review_status": "confirmed",
                "decision": "confirmed",
                "review_payload": {
                    "reviewer_id": "operator-a",
                    "decision": "confirmed",
                    "images": review_images,
                    "pair_conditions": ["normal_pair"],
                    "pair_notes": None,
                    "replace_reason": None,
                },
                "created_at": "2026-07-25T08:00:00+00:00",
                "updated_at": "2026-07-25T08:00:00+00:00",
                "record_evidence_sha256": "f" * 64,
            }
        )
        waybill_membership.append(
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "images": member_images,
            }
        )
    verified_set_sha256 = module._canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package_sha256,
            "images": verified_images,
        }
    )
    membership_sha256 = candidate_review_waybill_membership_sha256(
        package_sha256=package_sha256,
        waybills=waybill_membership,
    )
    source_without_hash: dict[str, object] = {
        "schema_version": 3,
        "kind": "candidate_review_formal_source_authority",
        "authority_scope": "computed_unsealed_snapshot",
        "persistent_seal": False,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "quality_coverage_sha256": quality_coverage_sha256,
        "package_id": "candidate-package",
        "package_sha256": package_sha256,
        "configured_reviewer_id": "operator-a",
        "record_count": 50,
        "record_set_sha256": record_set_sha256,
        "records": records,
        "verified_image_count": 100,
        "verified_image_set_sha256": verified_set_sha256,
        "verified_images": verified_images,
        "waybill_membership_count": 50,
        "waybill_membership_sha256": membership_sha256,
        "waybill_membership": waybill_membership,
    }
    return {
        **source_without_hash,
        "source_authority_sha256": module._canonical_sha256(source_without_hash),
    }


def _rehash_candidate_source_payload(
    payload: dict[str, object],
) -> None:
    waybills = payload["waybill_membership"]
    assert isinstance(waybills, list)
    payload["waybill_membership_sha256"] = candidate_review_waybill_membership_sha256(
        package_sha256=str(payload["package_sha256"]),
        waybills=waybills,
    )
    verified_images = payload["verified_images"]
    assert isinstance(verified_images, list)
    payload["verified_image_set_sha256"] = module._canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": payload["package_sha256"],
            "images": verified_images,
        }
    )
    without_hash = {
        key: value for key, value in payload.items() if key != "source_authority_sha256"
    }
    payload["source_authority_sha256"] = module._canonical_sha256(without_hash)


def _authority_backend(
    *,
    data_root: Path,
    repository_root: Path,
) -> AsyncOcrExecutionBackend:
    identity = OcrRuntimeIdentity(
        runtime_kind="cpu",
        profile_id="formal-boundary-test",
        runtime_fingerprint="a" * 64,
    )
    authority = OcrFormalAuthority._from_verified_composition(
        data_root=data_root.resolve(strict=True),
        repository_root=repository_root.resolve(strict=True),
        runtime_identities=(identity,),
        composition_evidence_sha256="b" * 64,
    )
    return AsyncOcrExecutionBackend._from_verified_composition(
        primary_runtime_kind="cpu",
        gateways={"cpu": _Gateway(identity)},
        formal_authority=authority,
    )


def _runtime(
    *,
    data_root: Path,
    repository_root: Path,
) -> SimpleNamespace:
    return SimpleNamespace(
        data_root=data_root.resolve(strict=True),
        project_root=repository_root.resolve(strict=True),
    )


def _records() -> tuple[
    LockedSetFormalEvaluationRecord,
    LockedSetSimilarityScanRecord,
    dict[str, object],
    list[dict[str, object]],
    dict[str, object],
]:
    manifest_sha256 = "1" * 64
    snapshot_sha256 = "2" * 64
    scan_sha256 = "3" * 64
    suite_without_hash: dict[str, object] = {
        "schema_version": 1,
        "generator_version": "dahe.loop7.derived-role-adversarial.v1",
        "source_truth_sha256": "e" * 64,
        "scenarios": [
            {
                "scenario_id": scenario_id,
                "source_sample_ids": ["sample-001"],
                "loading_slot_image_sha256": "f" * 64,
                "unloading_slot_image_sha256": "0" * 64,
                "expected_automatic_outcome": "awaiting_review",
                "expected_role_issue": issue,
            }
            for scenario_id, issue in (
                ("swapped_slots", "suspected_swapped"),
                ("both_loading", "both_loading"),
                ("both_unloading", "both_unloading"),
                ("exact_duplicate_image", "duplicate_image"),
            )
        ],
    }
    suite = dict(suite_without_hash)
    suite["suite_sha256"] = module._canonical_sha256(suite_without_hash)
    quality: dict[str, object] = {
        "dataset_id": "locked-replay",
        "manifest_sha256": manifest_sha256,
        "schema_version": 2,
        "required_conditions": [],
        "entries": [],
        "derived_adversarial_suite": suite,
    }
    quality["quality_coverage_sha256"] = module._canonical_sha256(quality)
    decisions: list[dict[str, object]] = []
    application_build_manifest = ApplicationBuildManifest(
        application_version="test-build",
        sources=(
            ApplicationBuildSource(
                path="application/template_studio/formal_locked_set_release.py",
                sha256="4" * 64,
            ),
        ),
    )
    run_context: dict[str, object] = {
        "application_build_manifest": application_build_manifest.to_payload(),
        "application_build_sha256": application_build_manifest.canonical_sha256,
        "matcher_sha256": "5" * 64,
        "policy_sha256": "6" * 64,
        "runtime_set_sha256": "7" * 64,
        "ocr_composition_evidence_sha256": "9" * 64,
        "template_set_sha256": "8" * 64,
        "expected_runtime_kinds": ["cpu", "gpu"],
    }
    committed_report = {
        "candidate_review_source_authority": (_candidate_review_source_authority()),
        "candidate_review_source_authority_sha256": (
            module._canonical_sha256(_candidate_review_source_authority())
        ),
        "quality_coverage_sha256": quality["quality_coverage_sha256"],
        "derived_adversarial_suite": suite,
        "derived_adversarial_gate": {
            "scenario_count": 4,
            "passed_count": 4,
            "failed_scenarios": [],
            "passed": True,
        },
        "observed_locked_set_gate": {"passed": True},
        "runtime_execution_gate": {
            "passed": True,
            "expected_runtime_kinds": ["cpu", "gpu"],
        },
        "eligible_accuracy_scope": "observed_real_locked_set_only",
        "formal_accuracy_claim_scope": "observed_real_locked_set_only",
        "derived_scenario_accuracy_claim": False,
        "derived_prevalence_claim": False,
        "formal_report": True,
        "formal_accuracy_claim": True,
        "gate_passed": True,
    }
    committed_json = _canonical_json(committed_report)
    evaluation = LockedSetFormalEvaluationRecord(
        evaluation_id="evaluation-001",
        dataset_id="locked-replay",
        manifest_sha256=manifest_sha256,
        exclusion_snapshot_id=snapshot_sha256,
        exclusion_snapshot_sha256=snapshot_sha256,
        inventory_high_watermark=0,
        preflight_attestation_id="9" * 64,
        scan_id=scan_sha256,
        scan_fingerprint=scan_sha256,
        idempotency_key="formal-replay-001",
        request_hash="a" * 64,
        runner_report_json="{}",
        runner_report_sha256="b" * 64,
        committed_report_json=committed_json,
        committed_report_sha256=hashlib.sha256(committed_json.encode("utf-8")).hexdigest(),
        quality_coverage_json=_canonical_json(quality),
        quality_coverage_sha256=module._canonical_sha256(quality),
        decision_set_json=_canonical_json(decisions),
        decision_set_sha256=module._canonical_sha256(decisions),
        run_context_sha256=module._canonical_sha256(run_context),
        gate_passed=True,
        formal_report=True,
        formal_accuracy_claim=True,
        formal_accuracy_claim_scope="observed_real_locked_set_only",
        derived_scenario_accuracy_claim=False,
        derived_prevalence_claim=False,
        actor_id="developer-test",
        completed_at="2026-07-26T00:00:00+00:00",
    )
    scan = LockedSetSimilarityScanRecord(
        scan_id=scan_sha256,
        dataset_id="locked-replay",
        manifest_sha256=manifest_sha256,
        exclusion_snapshot_id=snapshot_sha256,
        exclusion_snapshot_sha256=snapshot_sha256,
        inventory_high_watermark=0,
        scan_json="{}",
        scan_fingerprint=scan_sha256,
        detector_fingerprint="c" * 64,
        locked_image_count=100,
        excluded_image_count=0,
        candidate_count=0,
        locked_image_fingerprints_json="[]",
        locked_image_fingerprints_sha256="d" * 64,
        locked_image_fingerprints=(),
        actor_id="developer-test",
        completed_at="2026-07-26T00:00:00+00:00",
    )
    return evaluation, scan, quality, decisions, run_context


def test_formal_service_owns_template_store_evidence_store_and_source_root() -> None:
    parameters = inspect.signature(module.evaluate_formal_locked_set_release).parameters

    assert "template_repository" not in parameters
    assert "evidence_store" not in parameters
    assert "repository_root" not in parameters
    assert "quality_coverage" not in parameters
    assert "similarity_review" not in parameters
    assert "review_package" in parameters


def test_candidate_review_formal_prepare_revalidates_seal_and_registers_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _candidate_review_source_authority()
    review_root = (tmp_path / "locked-set-review").resolve()
    seal_root = review_root / "seals" / str(binding["seal_sha256"])
    seal_root.mkdir(parents=True)
    (seal_root / "manifest.json").write_text("{}\n", encoding="utf-8")
    sealed_quality = _candidate_quality_coverage(
        dataset_id="locked-seal-prepare",
        manifest_sha256="1" * 64,
    )
    source_without_hash = {
        "schema_version": 3,
        "kind": "candidate_review_formal_source_authority",
        "dataset_id": "locked-seal-prepare",
        "manifest_sha256": "1" * 64,
        "quality_coverage_sha256": sealed_quality["quality_coverage_sha256"],
        "package_sha256": binding["package_sha256"],
        "record_set_sha256": binding["record_set_sha256"],
    }
    source_payload = {
        **source_without_hash,
        "source_authority_sha256": module._canonical_sha256(source_without_hash),
    }
    binding["source_authority_sha256"] = source_payload["source_authority_sha256"]
    (seal_root / "source-authority.json").write_bytes(
        (_canonical_json(source_payload) + "\n").encode("utf-8"),
    )
    (seal_root / "quality-coverage.json").write_bytes(
        (_canonical_json(sealed_quality) + "\n").encode("utf-8"),
    )
    seal_payload = {
        **binding,
        "manifest_sha256": "1" * 64,
        "quality_coverage_sha256": sealed_quality["quality_coverage_sha256"],
        "development_authority_sha256": "f" * 64,
    }
    seal = CandidateReviewSeal(
        seal_sha256=str(binding["seal_sha256"]),
        seal_root=seal_root,
        seal_payload=seal_payload,
    )
    _evaluation, persisted_scan, quality, _decisions, _context = _records()
    prepared = module.PreparedFormalLockedSetReview(
        dataset_id="locked-seal-prepare",
        manifest_sha256="1" * 64,
        exclusion_snapshot_sha256="2" * 64,
        inventory_high_watermark=0,
        scan=SimpleNamespace(),  # type: ignore[arg-type]
        persisted_scan=persisted_scan,
        status="awaiting_human_review",
        dataset_record_version=2,
        quality_coverage=quality,
    )
    validated_calls: list[tuple[Path, str]] = []
    low_level_calls: list[dict[str, object]] = []
    registered: list[dict[str, object]] = []
    registered_development: list[dict[str, object]] = []
    development_authority = _development_authority()
    authority_rollover = module.DevelopmentAuthorityRollover(
        payload={"rollover_sha256": "9" * 64},
        rollover_sha256="9" * 64,
        source_authority_sha256="f" * 64,
        execution_authority_sha256="f" * 64,
    )

    def validate(*, review_data_root: Path, seal_sha256: str) -> CandidateReviewSeal:
        validated_calls.append((review_data_root, seal_sha256))
        return seal

    def low_level(**values: object) -> module.PreparedFormalLockedSetReview:
        low_level_calls.append(values)
        return prepared

    class Repository:
        runtime = SimpleNamespace(
            data_root=(tmp_path / "formal-data").resolve(),
        )

        def import_formal_development_exclusions(
            self,
            **values: object,
        ) -> object:
            assert values == {
                "authority_sha256": "f" * 64,
                "exclusion_snapshot": (
                    development_authority.exclusion_snapshot
                ),
                "perceptual_fingerprints": (),
            }
            return SimpleNamespace(
                snapshot=SimpleNamespace(canonical_sha256="2" * 64),
                inventory_high_watermark=0,
            )

        def register_development_authority(
            self,
            **values: object,
        ) -> object:
            registered_development.append(values)
            return object()

        def register_candidate_review_source_authority(
            self,
            **values: object,
        ) -> object:
            registered.append(values)
            return object()

    repository = Repository()
    repository.runtime.data_root.mkdir()
    monkeypatch.setattr(
        module,
        "validate_candidate_review_seal",
        validate,
    )
    monkeypatch.setattr(
        module,
        "prepare_formal_locked_set_release",
        low_level,
    )
    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda *args, **kwargs: development_authority,
    )
    monkeypatch.setattr(
        module,
        "persist_formal_development_authority",
        lambda *args, **kwargs: (
            repository.runtime.data_root / "authority.json"
        ),
    )
    monkeypatch.setattr(
        module,
        "validate_development_authority_rollover",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        module,
        "persist_development_authority_rollover",
        lambda *args, **kwargs: (
            repository.runtime.data_root / "rollover.json"
        ),
    )

    result = module.prepare_candidate_review_formal_release(
        repository=repository,  # type: ignore[arg-type]
        candidate_review_seal=seal,
        source_development_authority=development_authority,
        live_development_authority=development_authority,
        development_authority_rollover=authority_rollover,
        expected_source_development_authority_sha256="f" * 64,
        expected_execution_development_authority_sha256="f" * 64,
        actor_id="operator-a",
    )

    assert validated_calls == [(review_root, str(binding["seal_sha256"]))]
    assert low_level_calls == [
        {
            "repository": repository,
            "manifest_path": seal_root / "manifest.json",
            "dataset_root": review_root,
            "actor_id": "operator-a",
        }
    ]
    assert registered == [
        {
            "dataset_id": "locked-seal-prepare",
            "manifest_sha256": "1" * 64,
            "seal_sha256": binding["seal_sha256"],
            "package_sha256": binding["package_sha256"],
            "record_set_sha256": binding["record_set_sha256"],
            "review_history_authority_sha256": (binding["review_history_authority_sha256"]),
            "source_authority_sha256": (binding["source_authority_sha256"]),
            "payload": source_payload,
        }
    ]
    assert registered_development == [
        {
            "dataset_id": "locked-seal-prepare",
            "manifest_sha256": "1" * 64,
            "authority_sha256": "f" * 64,
            "source_exclusion_snapshot_sha256": "d" * 64,
            "formal_exclusion_snapshot_sha256": "2" * 64,
            "source_inventory_high_watermark": 3,
            "shadow_template_set_fingerprint": "e" * 64,
            "payload": development_authority.payload,
        }
    ]
    assert result.candidate_review_source_authority == binding
    assert result.development_authority_sha256 == "f" * 64
    assert result.source_development_authority_sha256 == "f" * 64
    assert result.execution_development_authority_sha256 == "f" * 64
    assert result.development_authority_rollover_sha256 == "9" * 64
    assert result.quality_coverage == sealed_quality


def test_review_binding_must_match_persisted_record_and_source_payload() -> None:
    binding = _candidate_review_source_authority()
    manifest = _candidate_manifest("locked-binding")
    quality = _candidate_quality_coverage(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
    )
    source_payload = _candidate_source_payload(
        manifest,
        package_sha256=str(binding["package_sha256"]),
        record_set_sha256=str(binding["record_set_sha256"]),
        quality_coverage_sha256=str(quality["quality_coverage_sha256"]),
    )
    binding["source_authority_sha256"] = source_payload["source_authority_sha256"]
    record = SimpleNamespace(
        dataset_id="locked-binding",
        manifest_sha256=manifest.canonical_sha256,
        seal_sha256=binding["seal_sha256"],
        package_sha256=binding["package_sha256"],
        record_set_sha256=binding["record_set_sha256"],
        review_history_authority_sha256=(binding["review_history_authority_sha256"]),
        source_authority_sha256=binding["source_authority_sha256"],
        payload_json=_canonical_json(source_payload),
    )

    class Repository:
        def get_candidate_review_source_authority(
            self,
            dataset_id: str,
        ) -> object:
            assert dataset_id == "locked-binding"
            return record

    repository = Repository()
    assert (
        module._bind_candidate_review_source_authority(
            repository=repository,  # type: ignore[arg-type]
            manifest=manifest,
            review_package={
                "candidate_review_source_authority": binding,
            },
            quality_coverage=quality,
        )
        == binding
    )

    for review_package in (
        {},
        {
            "candidate_review_source_authority": {
                **binding,
                "seal_sha256": "f" * 64,
            }
        },
    ):
        with pytest.raises(
            module.FormalLockedSetReleaseError,
            match="candidate-review source authority",
        ):
            module._bind_candidate_review_source_authority(
                repository=repository,  # type: ignore[arg-type]
                manifest=manifest,
                review_package=review_package,
                quality_coverage=quality,
            )

    record.payload_json = "{}"
    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="source payload",
    ):
        module._bind_candidate_review_source_authority(
            repository=repository,  # type: ignore[arg-type]
            manifest=manifest,
            review_package={
                "candidate_review_source_authority": binding,
            },
            quality_coverage=quality,
        )

    changed_quality = json.loads(json.dumps(quality))
    changed_quality["entries"] = [{"condition": "changed-after-seal"}]
    changed_quality["quality_coverage_sha256"] = module.locked_set_quality_coverage_sha256(
        changed_quality
    )
    record.payload_json = _canonical_json(source_payload)
    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="quality coverage",
    ):
        module._bind_candidate_review_source_authority(
            repository=repository,  # type: ignore[arg-type]
            manifest=manifest,
            review_package={
                "candidate_review_source_authority": binding,
            },
            quality_coverage=changed_quality,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "waybill_identity",
        "sample_slot_association",
    ),
)
def test_formal_db_binding_replay_rejects_fully_rehashed_semantic_tampering(
    mutation: str,
) -> None:
    manifest = _candidate_manifest("locked-binding-tamper")
    binding = _candidate_review_source_authority()
    quality = _candidate_quality_coverage(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
    )
    source_payload = _candidate_source_payload(
        manifest,
        package_sha256=str(binding["package_sha256"]),
        record_set_sha256=str(binding["record_set_sha256"]),
        quality_coverage_sha256=str(quality["quality_coverage_sha256"]),
    )
    if mutation == "waybill_identity":
        memberships = source_payload["waybill_membership"]
        assert isinstance(memberships, list)
        first = memberships[0]
        assert isinstance(first, dict)
        first["waybill_identity_sha256"] = hashlib.sha256(b"rebound-waybill").hexdigest()
    else:
        memberships = source_payload["waybill_membership"]
        verified_images = source_payload["verified_images"]
        records = source_payload["records"]
        assert isinstance(memberships, list)
        assert isinstance(verified_images, list)
        assert isinstance(records, list)
        first_sample = memberships[0]["sample_id"]
        second_sample = memberships[1]["sample_id"]
        memberships[0]["sample_id"] = second_sample
        memberships[1]["sample_id"] = first_sample
        memberships[0], memberships[1] = (
            memberships[1],
            memberships[0],
        )
        for image in verified_images[:2]:
            image["sample_id"] = second_sample
        for image in verified_images[2:4]:
            image["sample_id"] = first_sample
        verified_images[:4] = verified_images[2:4] + verified_images[:2]
        records[0]["sample_id"] = second_sample
        records[1]["sample_id"] = first_sample
        records[0], records[1] = records[1], records[0]
        for source_record in records[:2]:
            base = {
                key: value
                for key, value in source_record.items()
                if key != "record_evidence_sha256"
            }
            source_record["record_evidence_sha256"] = module._canonical_sha256(
                {
                    "schema_version": 1,
                    "package_sha256": source_payload["package_sha256"],
                    **base,
                }
            )
        source_payload["record_set_sha256"] = module._canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": source_payload["package_sha256"],
                "configured_reviewer_id": source_payload["configured_reviewer_id"],
                "records": [
                    {
                        "sample_id": record["sample_id"],
                        "record_version": record["record_version"],
                        "record_evidence_sha256": record["record_evidence_sha256"],
                    }
                    for record in records
                ],
            }
        )
    _rehash_candidate_source_payload(source_payload)
    binding["record_set_sha256"] = source_payload["record_set_sha256"]
    binding["source_authority_sha256"] = source_payload["source_authority_sha256"]
    record = SimpleNamespace(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        seal_sha256=binding["seal_sha256"],
        package_sha256=binding["package_sha256"],
        record_set_sha256=binding["record_set_sha256"],
        review_history_authority_sha256=(binding["review_history_authority_sha256"]),
        source_authority_sha256=binding["source_authority_sha256"],
        payload_json=_canonical_json(source_payload),
    )

    class Repository:
        def get_candidate_review_source_authority(
            self,
            dataset_id: str,
        ) -> object:
            assert dataset_id == manifest.dataset_id
            return record

    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="semantic bindings",
    ):
        module._bind_candidate_review_source_authority(
            repository=Repository(),  # type: ignore[arg-type]
            manifest=manifest,
            review_package={
                "candidate_review_source_authority": binding,
            },
            quality_coverage=quality,
        )


def test_formal_review_rejects_boolean_root_schema_version() -> None:
    scan = LockedSetSimilarityScan(
        dataset_id="locked-review-schema",
        manifest_sha256="1" * 64,
        exclusion_snapshot_sha256="2" * 64,
        detector_fingerprint="3" * 64,
        probe_set_fingerprint="4" * 64,
        inventory_set_fingerprint="5" * 64,
        locked_image_count=100,
        excluded_image_count=0,
        candidate_entries=(),
    )
    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="current scan",
    ):
        module._parse_review_decisions(
            {
                "schema_version": True,
                "dataset_id": scan.dataset_id,
                "manifest_sha256": scan.manifest_sha256,
                "scan_fingerprint": scan.scan_fingerprint,
                "decisions": [],
            },
            scan=scan,
            expected_reviewer_id="operator-a",
        )


def test_similarity_decision_reviewer_must_match_sealed_reviewer() -> None:
    candidate = NearDuplicateCandidate(
        algorithm_version=ALGORITHM_VERSION,
        probe_image_sha256="1" * 64,
        inventory_image_sha256="2" * 64,
        probe_fingerprint_sha256="3" * 64,
        inventory_fingerprint_sha256="4" * 64,
        probe_crop_permille=1000,
        inventory_crop_permille=1000,
        distance_numerator=1,
        distance_denominator=512,
        distance_limit=80,
    )
    scan = LockedSetSimilarityScan(
        dataset_id="locked-reviewer-authority",
        manifest_sha256="5" * 64,
        exclusion_snapshot_sha256="6" * 64,
        detector_fingerprint="7" * 64,
        probe_set_fingerprint="8" * 64,
        inventory_set_fingerprint="9" * 64,
        locked_image_count=100,
        excluded_image_count=1,
        candidate_entries=(
            LockedSetSimilarityCandidate(
                comparison_scope="probe_to_inventory",
                candidate=candidate,
            ),
        ),
    )

    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="configured reviewer",
    ):
        module._parse_review_decisions(
            {
                "schema_version": 1,
                "dataset_id": scan.dataset_id,
                "manifest_sha256": scan.manifest_sha256,
                "scan_fingerprint": scan.scan_fingerprint,
                "decisions": [
                    {
                        "candidate_id": candidate.candidate_id,
                        "verdict": "distinct",
                        "reviewer_id": "other-reviewer",
                        "decided_at": "2026-07-26T09:00:00+08:00",
                        "reason": "Compared both original images.",
                    }
                ],
            },
            scan=scan,
            expected_reviewer_id="operator-a",
        )


def test_formal_review_binding_rejects_human_confirmed_duplicate_before_quality_or_ocr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _candidate_manifest("locked-duplicate-gate")
    candidate = NearDuplicateCandidate(
        algorithm_version=ALGORITHM_VERSION,
        probe_image_sha256="1" * 64,
        inventory_image_sha256="2" * 64,
        probe_fingerprint_sha256="3" * 64,
        inventory_fingerprint_sha256="4" * 64,
        probe_crop_permille=1000,
        inventory_crop_permille=1000,
        distance_numerator=1,
        distance_denominator=512,
        distance_limit=80,
    )
    scan = LockedSetSimilarityScan(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256="5" * 64,
        detector_fingerprint="6" * 64,
        probe_set_fingerprint="7" * 64,
        inventory_set_fingerprint="8" * 64,
        locked_image_count=100,
        excluded_image_count=1,
        candidate_entries=(
            LockedSetSimilarityCandidate(
                comparison_scope="probe_to_inventory",
                candidate=candidate,
            ),
        ),
    )
    historical_snapshot = SimpleNamespace(
        snapshot_id="snapshot-1",
        snapshot=SimpleNamespace(canonical_sha256=scan.exclusion_snapshot_sha256),
        inventory_high_watermark=4,
    )
    persisted_scan = SimpleNamespace(
        exclusion_snapshot_id="snapshot-1",
        exclusion_snapshot_sha256=scan.exclusion_snapshot_sha256,
        inventory_high_watermark=4,
        scan_json=_canonical_json(scan.to_payload()),
        scan_fingerprint=scan.scan_fingerprint,
        locked_image_fingerprints=(),
    )

    class Repository:
        def get_dataset(self, dataset_id: str) -> SimpleNamespace:
            assert dataset_id == manifest.dataset_id
            return SimpleNamespace(
                state="awaiting_human_review",
                record_version=2,
            )

        def get_manifest(self, dataset_id: str) -> LockedSetManifest:
            assert dataset_id == manifest.dataset_id
            return manifest

        def get_similarity_scan(self, dataset_id: str) -> SimpleNamespace:
            assert dataset_id == manifest.dataset_id
            return persisted_scan

        def get_exclusion_snapshot(self, snapshot_id: str) -> SimpleNamespace:
            assert snapshot_id == "snapshot-1"
            return historical_snapshot

    monkeypatch.setattr(
        module,
        "_authoritative_evidence_store",
        lambda repository: object(),
    )
    monkeypatch.setattr(
        module,
        "_bind_candidate_review_source_authority",
        lambda **_: _candidate_review_source_authority(),
    )
    monkeypatch.setattr(
        module,
        "_bind_development_authority",
        lambda **_: _development_authority(),
    )
    monkeypatch.setattr(
        module,
        "_configured_candidate_reviewer_id",
        lambda **_: "operator-a",
    )
    monkeypatch.setattr(
        module,
        "_scan_from_authority",
        lambda **_: (scan, ()),
    )
    quality = _candidate_quality_coverage(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
    )
    review_package = {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "scan_fingerprint": scan.scan_fingerprint,
        "candidate_review_source_authority": (_candidate_review_source_authority()),
        "decisions": [
            {
                "candidate_id": candidate.candidate_id,
                "verdict": "duplicate",
                "reviewer_id": "operator-a",
                "decided_at": "2026-07-26T09:00:00+08:00",
                "reason": "The images are the same ticket.",
            }
        ],
        "quality_coverage": quality,
    }

    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="human-confirmed near duplicate",
    ):
        module._bind_formal_review(
            repository=Repository(),  # type: ignore[arg-type]
            dataset_id=manifest.dataset_id,
            review_package=review_package,
        )


def test_manual_backend_has_no_formal_release_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    identity = OcrRuntimeIdentity(
        runtime_kind="cpu",
        profile_id="manual-test",
        runtime_fingerprint="e" * 64,
    )
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="cpu",
        gateways={"cpu": _Gateway(identity)},
    )
    repository = SimpleNamespace(
        runtime=_runtime(
            data_root=data_root,
            repository_root=project_root,
        )
    )
    try:
        with pytest.raises(
            module.FormalLockedSetReleaseError,
            match="manually composed",
        ):
            module._require_formal_backend_authority(
                repository=repository,  # type: ignore[arg-type]
                backend=backend,
            )
    finally:
        backend.close()


def test_formal_backend_cannot_cross_application_data_roots(
    tmp_path: Path,
    project_root: Path,
) -> None:
    backend_root = tmp_path / "backend-data"
    repository_root = tmp_path / "repository-data"
    backend_root.mkdir()
    repository_root.mkdir()
    backend = _authority_backend(
        data_root=backend_root,
        repository_root=project_root,
    )
    repository = SimpleNamespace(
        runtime=_runtime(
            data_root=repository_root,
            repository_root=project_root,
        )
    )
    try:
        with pytest.raises(
            module.FormalLockedSetReleaseError,
            match="another application runtime",
        ):
            module._require_formal_backend_authority(
                repository=repository,  # type: ignore[arg-type]
                backend=backend,
            )
    finally:
        backend.close()


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("actor_id", "another-developer"),
        ("idempotency_key", "another-key"),
        ("quality_coverage", {"changed": True}),
        ("decisions", [{"changed": True}]),
        ("run_context", {"changed": True}),
    ),
)
def test_formal_replay_rejects_changed_idempotency_inputs(
    field: str,
    replacement: object,
) -> None:
    evaluation, scan, quality, decisions, run_context = _records()
    values: dict[str, Any] = {
        "dataset_state": "formal_evaluated",
        "persisted_scan": scan,
        "quality_coverage": quality,
        "decisions": decisions,
        "run_context": run_context,
        "actor_id": "developer-test",
        "idempotency_key": "formal-replay-001",
    }
    values[field] = replacement

    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="idempotency input",
    ):
        module._committed_replay(evaluation, **values)


def test_formal_replay_rejects_a_coherent_new_application_build_manifest() -> None:
    evaluation, scan, quality, decisions, run_context = _records()
    changed_context = json.loads(_canonical_json(run_context))
    changed_manifest_payload = changed_context["application_build_manifest"]
    changed_manifest_payload["sources"][0]["sha256"] = "f" * 64
    changed_manifest = ApplicationBuildManifest.from_payload(
        changed_manifest_payload
    )
    changed_context["application_build_sha256"] = changed_manifest.canonical_sha256

    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="idempotency input",
    ):
        module._committed_replay(
            evaluation,
            dataset_state="formal_evaluated",
            persisted_scan=scan,
            quality_coverage=quality,
            decisions=decisions,
            run_context=changed_context,
            actor_id="developer-test",
            idempotency_key="formal-replay-001",
        )


def test_permanently_invalidated_set_cannot_replay_old_accuracy_claim() -> None:
    evaluation, scan, quality, decisions, run_context = _records()

    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="permanently invalidated",
    ):
        module._committed_replay(
            evaluation,
            dataset_state="invalidated_to_development",
            persisted_scan=scan,
            quality_coverage=quality,
            decisions=decisions,
            run_context=run_context,
            actor_id="developer-test",
            idempotency_key="formal-replay-001",
        )


def test_public_formal_boundary_stops_invalidated_replay_before_evidence_or_ocr(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    backend = _authority_backend(
        data_root=data_root,
        repository_root=project_root,
    )
    evaluation, _scan, _quality, _decisions, _run_context = _records()

    class InvalidatedRepository:
        runtime = _runtime(
            data_root=data_root,
            repository_root=project_root,
        )

        def get_formal_release_evaluation(
            self,
            dataset_id: str,
        ) -> LockedSetFormalEvaluationRecord:
            assert dataset_id == "locked-replay"
            return evaluation

        def get_dataset(self, dataset_id: str) -> SimpleNamespace:
            assert dataset_id == "locked-replay"
            return SimpleNamespace(state="invalidated_to_development")

        def get_replayable_formal_release_evaluation(
            self,
            dataset_id: str,
        ) -> None:
            assert dataset_id == "locked-replay"
            raise module.LockedSetStateTransitionError("permanently invalidated")

        def get_manifest(self, dataset_id: str) -> None:
            raise AssertionError(f"invalidated replay read evidence for {dataset_id}")

    try:
        with pytest.raises(
            module.FormalLockedSetReleaseError,
            match="permanently invalidated",
        ):
            module.evaluate_formal_locked_set_release(
                locked_repository=InvalidatedRepository(),  # type: ignore[arg-type]
                ocr_backend=backend,
                live_development_authority=_development_authority(),
                dataset_id="locked-replay",
                review_package={},
                actor_id="developer-test",
                idempotency_key="formal-replay-001",
            )
    finally:
        backend.close()


def test_identical_current_formal_input_replays_without_ocr() -> None:
    evaluation, scan, quality, decisions, run_context = _records()

    replay = module._committed_replay(
        evaluation,
        dataset_state="formal_evaluated",
        persisted_scan=scan,
        quality_coverage=quality,
        decisions=decisions,
        run_context=run_context,
        actor_id="developer-test",
        idempotency_key="formal-replay-001",
    )

    assert replay.replayed is True
    assert replay.evaluation is evaluation
    assert replay.committed_report["formal_accuracy_claim"] is True


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("formal_accuracy_claim_scope", "all_evidence"),
        ("derived_scenario_accuracy_claim", True),
        ("derived_prevalence_claim", True),
        ("quality_coverage_sha256", "0" * 64),
        ("derived_adversarial_suite", {"suite_sha256": "0" * 64}),
        ("derived_adversarial_gate", {"scenario_count": 4, "passed": False}),
        ("observed_locked_set_gate", {"passed": False}),
        ("runtime_execution_gate", {"passed": False}),
    ),
)
def test_formal_replay_rejects_broadened_or_unbound_accuracy_claim(
    field: str,
    replacement: object,
) -> None:
    evaluation, scan, quality, decisions, run_context = _records()
    committed_report = json.loads(evaluation.committed_report_json)
    committed_report[field] = replacement
    committed_json = _canonical_json(committed_report)
    tampered_evaluation = replace(
        evaluation,
        committed_report_json=committed_json,
        committed_report_sha256=hashlib.sha256(committed_json.encode("utf-8")).hexdigest(),
    )

    with pytest.raises(
        module.FormalLockedSetReleaseError,
        match="claim boundary",
    ):
        module._committed_replay(
            tampered_evaluation,
            dataset_state="formal_evaluated",
            persisted_scan=scan,
            quality_coverage=quality,
            decisions=decisions,
            run_context=run_context,
            actor_id="developer-test",
            idempotency_key="formal-replay-001",
        )
