from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import dahe.verification.ledger as ledger_module
import dahe.verification.loop9_final_acceptance as final_acceptance_module
from dahe.verification.ledger import LedgerConflictError, LedgerStore
from dahe.verification.loop9_dataset_isolation import (
    DatasetKind,
    Loop9DatasetEntry,
    Loop9DatasetImage,
    Loop9DatasetManifest,
)
from dahe.verification.loop9_final_acceptance import (
    Loop9FinalAcceptanceError,
    Loop9FinalAcceptanceInputs,
    Loop9FinalAcceptanceReplay,
    accept_loop9_shadow,
    verify_formal_request_audit_evidence,
    verify_operational_acceptance_evidence,
)
from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64
SHA_8 = "8" * 64
SHA_9 = "9" * 64


def _canonical_sha256(value: object) -> str:
    import hashlib

    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _request_audit(
    scope: str,
    *,
    source_authority_sha256: str,
) -> dict[str, object]:
    if scope == "current_locked_50":
        item_count, image_count, terminal_count = 50, 100, 50
        operation_counts = {
            "download_ticket_image": 100,
            "get_waybill_detail": 50,
            "list_waybills": 1,
        }
        contract, selection = SHA_B, SHA_C
    elif scope == "real_shadow_30":
        item_count, image_count, terminal_count = 30, 60, 30
        operation_counts = {
            "download_ticket_image": 60,
            "get_waybill_detail": 30,
            "list_waybills": 1,
        }
        contract, selection = SHA_B, SHA_C
    else:
        item_count, image_count, terminal_count = 15, 30, 3
        operation_counts = {
            "download_ticket_image": 30,
            "get_waybill_detail": 15,
            "list_daily_waybills": 3,
        }
        contract, selection = SHA_8, SHA_9
    total = sum(operation_counts.values())
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_formal_request_audit",
        "scope": scope,
        "source_build_sha256": SHA_A,
        "contract_canonical_sha256": contract,
        "contract_selection_sha256": selection,
        "source_authority_sha256": source_authority_sha256,
        "attempted_request_count": total,
        "allowed_request_count": total,
        "succeeded_request_count": total,
        "denied_request_count": 0,
        "operation_counts": operation_counts,
        "platform_write_request_count": 0,
        "redirect_count": 0,
        "source_item_count": item_count,
        "evidence_image_count": image_count,
        "terminal_result_count": terminal_count,
    }
    return {**body, "canonical_sha256": _canonical_sha256(body)}


def _request_audits() -> dict[str, dict[str, object]]:
    return {
        "current_locked_50": _request_audit(
            "current_locked_50",
            source_authority_sha256=SHA_D,
        ),
        "real_shadow_30": _request_audit(
            "real_shadow_30",
            source_authority_sha256=SHA_F,
        ),
        "daily_validation": _request_audit(
            "daily_validation",
            source_authority_sha256=SHA_2,
        ),
    }


def _operational_document() -> dict[str, object]:
    audits = _request_audits()
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_operational_acceptance_evidence",
        "source_build_sha256": SHA_A,
        "settlement_contract_sha256": SHA_B,
        "settlement_selection_sha256": SHA_C,
        "current_locked_selection_sha256": SHA_D,
        "current_locked_gate_sha256": SHA_E,
        "real_shadow_selection_sha256": SHA_F,
        "real_shadow_machine_evaluation_sha256": SHA_1,
        "daily_snapshot_validation_sha256": SHA_2,
        "dataset_isolation_sha256": SHA_3,
        "request_audit_summaries": {
            scope: {
                key: value
                for key, value in audit.items()
                if key
                in {
                    "allowed_request_count",
                    "attempted_request_count",
                    "canonical_sha256",
                    "denied_request_count",
                    "operation_counts",
                    "platform_write_request_count",
                    "redirect_count",
                    "succeeded_request_count",
                }
            }
            for scope, audit in audits.items()
        },
        "real_shadow_reconciliation": {
            "source_item_count": 30,
            "unique_item_count": 30,
            "machine_item_count": 30,
            "human_review_count": 30,
            "terminal_outcome_count": 30,
            "missing_item_count": 0,
            "duplicate_submission_count": 0,
            "technical_failure_in_review_count": 0,
        },
        "fault_injections": [
            {
                "scenario": scenario,
                "passed": True,
                "committed_result_loss_count": 0,
                "duplicate_submission_count": 0,
                "technical_failure_in_review_count": 0,
                "evidence_sha256": digest,
            }
            for scenario, digest in (
                ("browser_closed", SHA_4),
                ("transient_network_failure", SHA_5),
                ("main_application_restart", SHA_6),
                ("gpu_worker_failure", SHA_7),
            )
        ],
        "performance": {
            "cpu_ocr": {
                "sample_count": 160,
                "p50_ms": 1200,
                "p95_ms": 2600,
            },
            "gpu_ocr": {
                "sample_count": 160,
                "p50_ms": 180,
                "p95_ms": 410,
            },
            "role_validation": {
                "sample_count": 160,
                "p50_ms": 8,
                "p95_ms": 20,
            },
            "end_to_end": {
                "sample_count": 80,
                "p50_ms": 2200,
                "p95_ms": 5100,
            },
        },
        "no_silent_omission": True,
    }
    return {**body, "canonical_sha256": _canonical_sha256(body)}


def _replay() -> Loop9FinalAcceptanceReplay:
    operational = verify_operational_acceptance_evidence(
        _operational_document()
    )
    return Loop9FinalAcceptanceReplay(
        source_build_sha256=SHA_A,
        settlement_contract_sha256=SHA_B,
        settlement_selection_sha256=SHA_C,
        daily_contract_sha256=SHA_8,
        daily_selection_sha256=SHA_9,
        read_contract_validation_sha256=SHA_4,
        current_locked_selection_sha256=SHA_D,
        current_locked_gate_sha256=SHA_E,
        current_locked_machine_evaluation_sha256=SHA_5,
        real_shadow_selection_sha256=SHA_F,
        real_shadow_human_review_seal_sha256=SHA_6,
        real_shadow_machine_evaluation_sha256=SHA_1,
        daily_snapshot_validation_sha256=SHA_2,
        dataset_isolation_sha256=SHA_3,
        formal_run_evidence_sha256=SHA_7,
        operational_evidence=operational,
        request_audits=_request_audits(),
        data_references={
            "read_contract_validation": (
                "platform-read-contract-validation/" + SHA_4 + ".json"
            ),
            "current_locked_gate": (
                "verification/loop9/current-locked-gates/"
                + SHA_E[:2]
                + "/"
                + SHA_E
                + ".json"
            ),
            "real_shadow_package": "verification/loop9/review/real-shadow-30",
            "real_shadow_seal": (
                "verification/loop9/review/" + SHA_6 + ".json"
            ),
            "real_shadow_machine_evaluation": (
                "verification/loop9/machine-truth-evaluations/"
                + SHA_1[:2]
                + "/"
                + SHA_1
                + ".json"
            ),
            "daily_snapshot_validation": (
                "verification/loop9/daily/" + SHA_2 + ".json"
            ),
            "dataset_isolation": (
                "verification/loop9/isolation/" + SHA_3 + ".json"
            ),
            "formal_run_evidence": (
                "verification/loop9/formal-run-evidence/sha256/"
                + SHA_7[:2]
                + "/"
                + SHA_7[2:4]
                + "/"
                + SHA_7
                + ".json"
            ),
        },
    )


def _ledger(project_root: Path, tmp_path: Path) -> Path:
    source = json.loads(
        (
            project_root
            / "tests"
            / "fixtures"
            / "loop9-active-ledger.json"
        ).read_text(encoding="utf-8")
    )
    source["revision"] = 41
    source["status"] = "in_progress"
    source["schema_version"] = 2
    source["waiver"] = None
    source.pop("acceptance", None)
    source.pop("operational_acceptance", None)
    source["gate_results"] = [
        gate
        for gate in source["gate_results"]
        if gate["id"] != "loop-9-operational-read-only-cutover"
    ]
    for gate in source["gate_results"]:
        if gate["status"] != "passed":
            gate["status"] = "pending"
            gate["evidence"] = None
    path = tmp_path / "project" / "verification" / "loop-ledger.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(source, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest = path.parent.parent / source["input_manifest"]["path"]
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_bytes(b"input")
    source["input_manifest"]["sha256"] = __import__("hashlib").sha256(
        b"input"
    ).hexdigest()
    path.write_text(
        json.dumps(source, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def _inputs(project: Path) -> Loop9FinalAcceptanceInputs:
    data = project / "data"
    return Loop9FinalAcceptanceInputs(
        project_root=project,
        data_root=data,
        read_contract_validation_path=data / "read-contract.json",
        current_locked_selection_sha256=SHA_D,
        real_shadow_selection_sha256=SHA_F,
        real_shadow_package_dir=data / "review-package",
        real_shadow_seal_path=data / "review-seal.json",
        real_shadow_machine_evaluation_path=data / "machine.json",
        daily_snapshot_validation_path=data / "daily.json",
        discovery_development_path=data / "discovery.json",
        current_locked_50_path=data / "locked.json",
        real_shadow_30_path=data / "shadow.json",
        daily_validation_dataset_path=data / "daily-dataset.json",
        source_development_authority_path=data / "authority.json",
        dataset_isolation_path=data / "isolation.json",
        formal_run_evidence_sha256=SHA_7,
        locked_job_id="locked-job",
        real_shadow_job_id="real-shadow-job",
        fault_scenarios={
            scenario: FaultScenarioIdentity(
                run_id=f"{scenario}-run",
                job_id=f"{scenario}-job",
            )
            for scenario in (
                "browser_closed",
                "gpu_worker_failure",
                "main_application_restart",
                "transient_network_failure",
            )
        },
    )


def test_acceptance_entry_accepts_inputs_but_not_external_replay() -> None:
    parameters = inspect.signature(accept_loop9_shadow).parameters

    assert "inputs" in parameters
    assert "replay" not in parameters
    assert "project_root" not in parameters


def test_internal_terminal_writer_accepts_inputs_not_caller_replay() -> None:
    parameters = inspect.signature(
        LedgerStore._commit_verified_shadow_acceptance
    ).parameters

    assert "inputs" in parameters
    assert "replay" not in parameters
    assert "document" not in parameters


def test_final_read_gate_rejects_settlement_nonempty_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "data"
    validation_root = data_root / "platform-read-contract-validation"
    validation_root.mkdir(parents=True)
    validation_path = validation_root / f"{SHA_4}.json"
    settlement = SimpleNamespace(
        manifest=SimpleNamespace(
            canonical_sha256=SHA_B,
            source_discovery_sha256=SHA_C,
        ),
        contract_file_sha256=SHA_D,
        freeze_evidence_sha256=SHA_E,
        selection_sha256=SHA_F,
    )
    daily = SimpleNamespace(
        manifest=SimpleNamespace(
            canonical_sha256=SHA_1,
            source_discovery_sha256=SHA_2,
        ),
        contract_file_sha256=SHA_3,
        freeze_evidence_sha256=SHA_5,
        selection_sha256=SHA_6,
    )
    result = SimpleNamespace(
        canonical_sha256=SHA_4,
        identity_context_sha256=SHA_7,
        development_exclusion_sha256=SHA_8,
        development_exclusion_inventory_sha256=SHA_9,
    )
    document: dict[str, object] = {
        "schema_version": 4,
        "build_sha256": SHA_A,
        "contract_canonical_sha256": SHA_B,
        "contract_file_sha256": SHA_D,
        "freeze_evidence_sha256": SHA_E,
        "selection_sha256": SHA_F,
        "source_discovery_sha256": SHA_C,
        "validation_mode": "settlement_nonempty",
        "daily_contract_canonical_sha256": None,
        "daily_contract_file_sha256": None,
        "daily_contract_freeze_evidence_sha256": None,
        "daily_contract_selection_sha256": None,
        "daily_contract_source_discovery_sha256": None,
        "forbidden_request_count": 0,
        "platform_write_request_count": 0,
        "redirect_count": 0,
    }
    monkeypatch.setattr(
        final_acceptance_module,
        "_load_result",
        lambda _path: (result, document),
    )

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="approved composite",
    ):
        final_acceptance_module._validate_read_contract_gate(
            data_root=data_root,
            validation_path=validation_path,
            source_build_sha256=SHA_A,
            identity_context_sha256=SHA_7,
            settlement=settlement,
            daily=daily,
        )


@pytest.mark.parametrize(
    ("schema_version", "should_pass"),
    ((4, False), (5, True)),
)
def test_final_daily_gate_requires_current_schema_five(
    schema_version: int,
    should_pass: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily = SimpleNamespace(
        manifest=SimpleNamespace(canonical_sha256=SHA_B),
        selection_sha256=SHA_C,
    )
    payload: dict[str, object] = {
        "schema_version": schema_version,
        "build_sha256": SHA_A,
        "contract_sha256": SHA_B,
        "contract_selection": {"selection_sha256": SHA_C},
        "snapshot_count": 3,
        "candidate_count": 1,
        "forbidden_request_count": 0,
        "platform_write_request_count": 0,
        "redirect_count": 0,
    }
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_current_daily_snapshot_validation_from_store",
        lambda value, **_kwargs: value,
    )

    if should_pass:
        assert (
            final_acceptance_module._validate_daily_gate(
                payload=payload,
                data_root=Path.cwd(),
                project_root=Path.cwd(),
                source_build_sha256=SHA_A,
                daily=daily,
            )
            == payload
        )
    else:
        with pytest.raises(
            Loop9FinalAcceptanceError,
            match="authority changed",
        ):
            final_acceptance_module._validate_daily_gate(
                payload=payload,
                data_root=Path.cwd(),
                project_root=Path.cwd(),
                source_build_sha256=SHA_A,
                daily=daily,
            )


def _daily_dataset_manifest(
    *,
    source_snapshot_sha256: str,
) -> Loop9DatasetManifest:
    return Loop9DatasetManifest(
        dataset_id="loop9-daily-validation",
        dataset_kind=DatasetKind.DAILY_VALIDATION,
        build_sha256=SHA_A,
        contract_sha256=SHA_B,
        source_job_id="daily-triplet-source",
        source_snapshot_sha256=source_snapshot_sha256,
        entries=(
            Loop9DatasetEntry(
                platform_identity_sha256=SHA_C,
                scope_exclusion_token=None,
                images=(
                    Loop9DatasetImage(
                        image_sha256=SHA_D,
                        perceptual_fingerprint=None,
                    ),
                ),
            ),
        ),
        identity_context_sha256=SHA_E,
    )


def _daily_gate_binding() -> dict[str, object]:
    return {
        "canonical_sha256": SHA_F,
        "snapshot_count": 3,
        "snapshot_evidence": [
            {
                "snapshot_id": f"daily-snapshot-{index}",
                "job_id": f"daily-snapshot-{index}",
                "access_window_id": f"daily-window-{index}",
                "snapshot_fingerprint": str(index) * 64,
            }
            for index in range(1, 4)
        ],
    }


def test_final_dataset_isolation_binds_daily_manifest_to_current_gate() -> None:
    manifest = _daily_dataset_manifest(
        source_snapshot_sha256=SHA_F,
    )

    final_acceptance_module._validate_daily_dataset_gate_binding(
        daily_manifest=manifest,
        daily_gate=_daily_gate_binding(),
    )

    mismatched = _daily_dataset_manifest(
        source_snapshot_sha256=SHA_1,
    )
    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="current daily Gate",
    ):
        final_acceptance_module._validate_daily_dataset_gate_binding(
            daily_manifest=mismatched,
            daily_gate=_daily_gate_binding(),
        )


def test_final_dataset_isolation_requires_same_three_snapshot_authorities() -> None:
    gate = _daily_gate_binding()
    snapshots = list(gate["snapshot_evidence"])
    snapshots[2] = deepcopy(snapshots[1])
    gate["snapshot_evidence"] = snapshots

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="three snapshot authorities",
    ):
        final_acceptance_module._validate_daily_dataset_gate_binding(
            daily_manifest=_daily_dataset_manifest(
                source_snapshot_sha256=SHA_F,
            ),
            daily_gate=gate,
        )


def test_final_dataset_isolation_replay_enforces_current_daily_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path)
    persisted = SimpleNamespace(
        full_history_exclusion_authority_sha256=SHA_1,
    )
    full_history = SimpleNamespace(
        development_exclusions=object(),
        legacy_loop7_exclusions=object(),
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "load_formal_development_authority",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda _authority: object(),
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "load_loop9_dataset_isolation_evidence",
        lambda _path: persisted,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "load_stored_loop9_full_history_exclusion_authority",
        lambda **_kwargs: full_history,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "load_loop9_dataset_manifest",
        lambda _path: _daily_dataset_manifest(
            source_snapshot_sha256=SHA_1,
        ),
    )

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="dataset isolation replay failed",
    ):
        final_acceptance_module._replay_dataset_isolation(
            inputs=inputs,
            data_root=inputs.data_root,
            source_build_sha256=SHA_A,
            settlement=SimpleNamespace(
                manifest=SimpleNamespace(canonical_sha256=SHA_B),
                selection_sha256=SHA_C,
            ),
            daily=SimpleNamespace(
                manifest=SimpleNamespace(canonical_sha256=SHA_D),
                selection_sha256=SHA_E,
            ),
            daily_gate=_daily_gate_binding(),
        )


def test_final_dataset_isolation_uses_store_rebuilt_daily_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path)
    rebuilt_daily = _daily_dataset_manifest(
        source_snapshot_sha256=SHA_F,
    )
    persisted_daily = replace(
        rebuilt_daily,
        source_job_id="attacker-rehashed-source-job",
    )
    persisted_isolation = SimpleNamespace(
        canonical_sha256=SHA_1,
        full_history_exclusion_authority_sha256=SHA_2,
        to_payload=lambda: {"canonical_sha256": SHA_1},
    )
    full_history = SimpleNamespace(
        development_exclusions=object(),
        legacy_loop7_exclusions=object(),
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        final_acceptance_module,
        "load_formal_development_authority",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda _authority: object(),
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "load_loop9_dataset_isolation_evidence",
        lambda _path: persisted_isolation,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "load_stored_loop9_full_history_exclusion_authority",
        lambda **_kwargs: full_history,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "load_loop9_dataset_manifest",
        lambda path: (
            persisted_daily
            if path == inputs.daily_validation_dataset_path
            else object()
        ),
    )
    replay_calls: list[object] = []
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_current_daily_dataset_manifest_from_store",
        lambda persisted, **_kwargs: (
            replay_calls.append(persisted)
            or SimpleNamespace(manifest=rebuilt_daily)
        ),
        raising=False,
    )

    def validate(**values: object) -> object:
        captured.update(values)
        return persisted_isolation

    monkeypatch.setattr(
        final_acceptance_module,
        "validate_loop9_dataset_isolation",
        validate,
    )

    assert (
        final_acceptance_module._replay_dataset_isolation(
            inputs=inputs,
            data_root=inputs.data_root,
            source_build_sha256=SHA_A,
            settlement=SimpleNamespace(
                manifest=SimpleNamespace(canonical_sha256=SHA_B),
                selection_sha256=SHA_C,
            ),
            daily=SimpleNamespace(
                manifest=SimpleNamespace(canonical_sha256=SHA_B),
                selection_sha256=SHA_C,
            ),
            daily_gate=_daily_gate_binding(),
        )
        == SHA_1
    )
    assert replay_calls == [persisted_daily]
    assert captured["daily_validation"] is rebuilt_daily


@pytest.mark.parametrize(
    "field",
    (
        "daily_contract_canonical_sha256",
        "daily_contract_file_sha256",
        "daily_contract_freeze_evidence_sha256",
        "daily_contract_selection_sha256",
        "daily_contract_source_discovery_sha256",
    ),
)
def test_final_read_gate_binds_every_daily_authority_sha(
    field: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "data"
    validation_root = data_root / "platform-read-contract-validation"
    validation_root.mkdir(parents=True)
    validation_path = validation_root / f"{SHA_4}.json"
    settlement = SimpleNamespace(
        manifest=SimpleNamespace(
            canonical_sha256=SHA_B,
            source_discovery_sha256=SHA_C,
        ),
        contract_file_sha256=SHA_D,
        freeze_evidence_sha256=SHA_E,
        selection_sha256=SHA_F,
    )
    daily = SimpleNamespace(
        manifest=SimpleNamespace(
            canonical_sha256=SHA_1,
            source_discovery_sha256=SHA_2,
        ),
        contract_file_sha256=SHA_3,
        freeze_evidence_sha256=SHA_5,
        selection_sha256=SHA_6,
    )
    result = SimpleNamespace(
        canonical_sha256=SHA_4,
        identity_context_sha256=SHA_7,
        development_exclusion_sha256=SHA_8,
        development_exclusion_inventory_sha256=SHA_9,
    )
    document: dict[str, object] = {
        "schema_version": 4,
        "build_sha256": SHA_A,
        "contract_canonical_sha256": SHA_B,
        "contract_file_sha256": SHA_D,
        "freeze_evidence_sha256": SHA_E,
        "selection_sha256": SHA_F,
        "source_discovery_sha256": SHA_C,
        "validation_mode": "settlement_empty_daily_nonempty",
        "daily_contract_canonical_sha256": SHA_1,
        "daily_contract_file_sha256": SHA_3,
        "daily_contract_freeze_evidence_sha256": SHA_5,
        "daily_contract_selection_sha256": SHA_6,
        "daily_contract_source_discovery_sha256": SHA_2,
        "forbidden_request_count": 0,
        "platform_write_request_count": 0,
        "redirect_count": 0,
    }
    document[field] = SHA_9
    monkeypatch.setattr(
        final_acceptance_module,
        "_load_result",
        lambda _path: (result, document),
    )

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="daily read authority",
    ):
        final_acceptance_module._validate_read_contract_gate(
            data_root=data_root,
            validation_path=validation_path,
            source_build_sha256=SHA_A,
            identity_context_sha256=SHA_7,
            settlement=settlement,
            daily=daily,
        )


def test_acceptance_rejects_repository_ledger_copy(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    copied_project = ledger_path.parents[1]
    output = (
        copied_project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="repository root",
    ):
        accept_loop9_shadow(
            inputs=_inputs(copied_project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )


def test_acceptance_rejects_noncanonical_ledger_path_inside_repository(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    copied_ledger = ledger_path.with_name("loop-ledger-copy.json")
    copied_ledger.write_bytes(ledger_path.read_bytes())
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="active repository ledger",
    ):
        accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=copied_ledger,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )


def test_request_audit_requires_zero_denied_write_and_redirect() -> None:
    accepted = verify_formal_request_audit_evidence(
        _request_audits()["real_shadow_30"]
    )
    assert accepted["succeeded_request_count"] > 0

    for field in (
        "denied_request_count",
        "platform_write_request_count",
        "redirect_count",
    ):
        forged = deepcopy(_request_audits()["real_shadow_30"])
        forged[field] = 1
        forged["canonical_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in forged.items()
                if key != "canonical_sha256"
            }
        )
        with pytest.raises(
            Loop9FinalAcceptanceError,
            match="request audit",
        ):
            verify_formal_request_audit_evidence(forged)


def test_operational_evidence_requires_all_audit_summaries() -> None:
    accepted = verify_operational_acceptance_evidence(
        _operational_document()
    )
    assert accepted["no_silent_omission"] is True

    forged = deepcopy(_operational_document())
    forged["request_audit_summaries"].pop("daily_validation")
    forged["canonical_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in forged.items()
            if key != "canonical_sha256"
        }
    )
    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="request audit",
    ):
        verify_operational_acceptance_evidence(forged)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["fault_injections"].pop(),
            "fault injection",
        ),
        (
            lambda value: value["real_shadow_reconciliation"].__setitem__(
                "missing_item_count", 1
            ),
            "reconciliation",
        ),
        (
            lambda value: value["performance"]["gpu_ocr"].__setitem__(
                "sample_count", 0
            ),
            "performance",
        ),
        (
            lambda value: value.__setitem__("no_silent_omission", False),
            "silent omission",
        ),
    ],
)
def test_operational_evidence_fails_closed(
    mutation: Callable[[dict[str, object]], object],
    message: str,
) -> None:
    forged = deepcopy(_operational_document())
    mutation(forged)
    forged["canonical_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in forged.items()
            if key != "canonical_sha256"
        }
    )
    with pytest.raises(Loop9FinalAcceptanceError, match=message):
        verify_operational_acceptance_evidence(forged)


def test_operational_evidence_rejects_hash_tampering() -> None:
    forged = _operational_document()
    forged["source_build_sha256"] = SHA_B
    with pytest.raises(Loop9FinalAcceptanceError, match="integrity"):
        verify_operational_acceptance_evidence(forged)


def test_final_replay_binds_immutable_formal_run_evidence() -> None:
    replay = _replay()
    object.__setattr__(replay, "formal_run_evidence_sha256", SHA_9)

    evidence = replay.evidence_payload(
        accepted_at="2026-07-30T00:00:00Z"
    )

    assert evidence["formal_run_evidence_sha256"] == SHA_9


@pytest.mark.parametrize(
    "field",
    (
        "source_build_sha256",
        "contract_canonical_sha256",
        "contract_selection_sha256",
        "source_authority_sha256",
    ),
)
def test_request_audit_authority_tampering_rejects_replay(
    field: str,
) -> None:
    replay = _replay()
    audits = deepcopy(replay.request_audits)
    forged = dict(audits["real_shadow_30"])
    forged[field] = SHA_9
    forged["canonical_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in forged.items()
            if key != "canonical_sha256"
        }
    )
    audits["real_shadow_30"] = forged
    object.__setattr__(replay, "request_audits", audits)

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="authority binding",
    ):
        replay.verify()


def test_request_audit_summary_must_match_deep_evidence() -> None:
    replay = _replay()
    operational = deepcopy(replay.operational_evidence)
    summaries = operational["request_audit_summaries"]
    summaries["real_shadow_30"]["canonical_sha256"] = SHA_9
    operational["canonical_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in operational.items()
            if key != "canonical_sha256"
        }
    )
    object.__setattr__(replay, "operational_evidence", operational)

    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="does not reconcile",
    ):
        replay.verify()


def test_acceptance_is_immutable_atomic_and_idempotent(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    replay = _replay()
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )
    replay_call_count = 0

    def replay_from_inputs(
        _inputs: Loop9FinalAcceptanceInputs,
    ) -> Loop9FinalAcceptanceReplay:
        nonlocal replay_call_count
        replay_call_count += 1
        return replay

    monkeypatch.setattr(
        final_acceptance_module,
        "replay_loop9_final_acceptance",
        replay_from_inputs,
    )
    inputs = _inputs(project)
    before_document = LedgerStore(ledger_path).read()

    first = accept_loop9_shadow(
        inputs=inputs,
        ledger_path=ledger_path,
        output_directory=output,
        expected_ledger_revision=41,
        clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        remaining_risks=("known residual risk",),
    )
    accepted = LedgerStore(ledger_path).read()

    assert accepted["status"] == "shadow_accepted"
    assert accepted["schema_version"] == 3
    assert accepted["revision"] == 42
    assert accepted["last_accepted_git_commit"] == (
        accepted["acceptance"]["previous_last_accepted_git_commit"]
    )
    assert all(
        gate["status"] == "passed" for gate in accepted["gate_results"]
    )
    assert first["canonical_sha256"] == accepted["acceptance"]["sha256"]
    for field in (
        "project_id",
        "current_loop",
        "run_id",
        "input_manifest",
        "last_accepted_git_commit",
    ):
        assert accepted[field] == before_document[field]
    before_gates = before_document["gate_results"]
    accepted_gates = accepted["gate_results"]
    assert [gate["id"] for gate in accepted_gates[:-1]] == [
        gate["id"] for gate in before_gates
    ]
    for before_gate, accepted_gate in zip(
        before_gates,
        accepted_gates[:-1],
        strict=True,
    ):
        if before_gate["id"] in final_acceptance_module._UPDATABLE_GATE_IDS:
            assert accepted_gate == {
                "id": before_gate["id"],
                "status": "passed",
                "evidence": accepted["acceptance"]["evidence"],
            }
        else:
            assert accepted_gate == before_gate
    assert accepted_gates[-1] == {
        "id": final_acceptance_module._FINAL_GATE_ID,
        "status": "passed",
        "evidence": accepted["acceptance"]["evidence"],
    }
    assert accepted["unresolved_risks"] == ["known residual risk"]
    assert accepted["next_inputs"] == []
    assert replay_call_count == 2

    second = accept_loop9_shadow(
        inputs=inputs,
        ledger_path=ledger_path,
        output_directory=output,
        expected_ledger_revision=41,
        clock=lambda: datetime(2026, 7, 30, 13, 0, tzinfo=UTC),
    )
    assert second == first
    assert LedgerStore(ledger_path).read()["revision"] == 42
    assert replay_call_count == 3


def test_failed_replay_or_binding_preserves_ledger(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    before = ledger_path.read_bytes()
    replay = _replay()
    forged_operational = dict(replay.operational_evidence)
    forged_operational["real_shadow_selection_sha256"] = SHA_A
    forged_operational["canonical_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in forged_operational.items()
            if key != "canonical_sha256"
        }
    )
    forged = deepcopy(replay)
    object.__setattr__(
        forged,
        "operational_evidence",
        forged_operational,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_loop9_final_acceptance",
        lambda _inputs: forged,
    )

    with pytest.raises(Loop9FinalAcceptanceError, match="authority"):
        accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )

    assert ledger_path.read_bytes() == before
    assert list(output.iterdir()) == []


def test_evidence_tampered_after_replay_cannot_close_ledger(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    before = ledger_path.read_bytes()
    replay = _replay()
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_loop9_final_acceptance",
        lambda _inputs: replay,
    )
    def tamper_before_replace(_: Path) -> None:
        evidence = next(output.glob("*.json"))
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["gate_passed"] = False
        evidence.write_text(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(
        final_acceptance_module,
        "LedgerStore",
        lambda path: LedgerStore(
            path,
            before_replace=tamper_before_replace,
        ),
    )
    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="update failed",
    ):
        accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )

    assert ledger_path.read_bytes() == before


def test_ledger_and_evidence_acceptance_times_must_match(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    before = ledger_path.read_bytes()
    replay = _replay()
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_loop9_final_acceptance",
        lambda _inputs: replay,
    )
    original = LedgerStore._commit_verified_shadow_acceptance

    def replace_with_time_mismatch(
        store: LedgerStore,
        **kwargs: object,
    ) -> dict[str, object]:
        kwargs["accepted_at"] = "2026-07-30T12:00:01+00:00"
        return original(store, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        LedgerStore,
        "_commit_verified_shadow_acceptance",
        replace_with_time_mismatch,
    )
    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="update failed",
    ):
        accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )

    assert ledger_path.read_bytes() == before


def test_caller_forged_terminal_document_cannot_close_ledger(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    before = ledger_path.read_bytes()
    replay = _replay()
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_loop9_final_acceptance",
        lambda _inputs: replay,
    )
    original = LedgerStore._commit_verified_shadow_acceptance

    def inject_forged_document(
        store: LedgerStore,
        **kwargs: object,
    ) -> dict[str, object]:
        document = deepcopy(store.read())
        evidence_path = kwargs["evidence_path"]
        evidence_sha256 = kwargs["evidence_sha256"]
        accepted_at = kwargs["accepted_at"]
        document["schema_version"] = 3
        document["revision"] = int(document["revision"]) + 1
        document["status"] = "shadow_accepted"
        document["waiver"] = None
        document["run_id"] = "forged-run"
        document["input_manifest"] = {
            "path": "verification/forged-input.json",
            "sha256": "a" * 64,
        }
        document["next_inputs"] = []
        document["acceptance"] = {
            "kind": "loop9_shadow_acceptance",
            "accepted_at": accepted_at,
            "evidence": evidence_path,
            "sha256": evidence_sha256,
            "previous_status": "in_progress",
            "previous_last_accepted_git_commit": document[
                "last_accepted_git_commit"
            ],
        }
        gates = document["gate_results"]
        assert isinstance(gates, list)
        for gate in gates:
            assert isinstance(gate, dict)
            if gate["id"] in final_acceptance_module._UPDATABLE_GATE_IDS:
                gate["status"] = "passed"
                gate["evidence"] = evidence_path
        gates[0] = {
            "id": "forged-gate",
            "status": "passed",
            "evidence": evidence_path,
        }
        gates.append(
            {
                "id": final_acceptance_module._FINAL_GATE_ID,
                "status": "passed",
                "evidence": evidence_path,
            }
        )
        kwargs["document"] = document
        return original(store, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        LedgerStore,
        "_commit_verified_shadow_acceptance",
        inject_forged_document,
    )
    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="update failed",
    ):
        accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )

    assert ledger_path.read_bytes() == before


@pytest.mark.parametrize(
    "mutation",
    ("missing", "tampered", "symlink", "reparse"),
)
def test_terminal_writer_revalidates_input_manifest(
    mutation: str,
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    before = ledger_path.read_bytes()
    replay = _replay()
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_loop9_final_acceptance",
        lambda _inputs: replay,
    )
    original = LedgerStore._commit_verified_shadow_acceptance

    def mutate_manifest_before_terminal_write(
        store: LedgerStore,
        **kwargs: object,
    ) -> dict[str, object]:
        current = store.read()
        reference = current["input_manifest"]
        assert isinstance(reference, dict)
        raw_path = reference["path"]
        assert isinstance(raw_path, str)
        manifest = project / raw_path
        if mutation == "missing":
            manifest.unlink()
        elif mutation == "tampered":
            manifest.write_bytes(b"tampered")
        elif mutation == "symlink":
            original_is_symlink = Path.is_symlink

            def report_manifest_symlink(path: Path) -> bool:
                return (
                    path == manifest
                    or original_is_symlink(path)
                )

            monkeypatch.setattr(
                Path,
                "is_symlink",
                report_manifest_symlink,
            )
        else:
            original_reparse_check = ledger_module._is_reparse_point

            def report_manifest_reparse(path: Path) -> bool:
                return (
                    path == manifest
                    or original_reparse_check(path)
                )

            monkeypatch.setattr(
                ledger_module,
                "_is_reparse_point",
                report_manifest_reparse,
            )
        return original(store, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        LedgerStore,
        "_commit_verified_shadow_acceptance",
        mutate_manifest_before_terminal_write,
    )
    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="update failed",
    ):
        accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )

    assert ledger_path.read_bytes() == before


def test_temporary_ledger_time_tamper_cannot_reach_final_replace(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    before = ledger_path.read_bytes()
    replay = _replay()
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )
    monkeypatch.setattr(
        final_acceptance_module,
        "replay_loop9_final_acceptance",
        lambda _inputs: replay,
    )

    def tamper_temporary_ledger(path: Path) -> None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["acceptance"]["accepted_at"] = (
            "2026-07-30T12:00:01+00:00"
        )
        path.write_text(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(
        final_acceptance_module,
        "LedgerStore",
        lambda path: LedgerStore(
            path,
            before_replace=tamper_temporary_ledger,
        ),
    )
    with pytest.raises(
        Loop9FinalAcceptanceError,
        match="update failed",
    ):
        accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )

    assert ledger_path.read_bytes() == before


def test_concurrent_revision_change_cannot_race_deep_replay_and_write(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = _ledger(project_root, tmp_path)
    project = ledger_path.parents[1]
    output = (
        project
        / "verification"
        / "loops"
        / "loop-9"
        / "formal"
    )
    output.mkdir(parents=True)
    store = LedgerStore(ledger_path)
    stale = deepcopy(store.read())
    stale["revision"] = 42
    stale["status"] = "blocked"
    stale["unresolved_risks"] = ["concurrent stale update"]
    replay = _replay()
    monkeypatch.setattr(
        final_acceptance_module,
        "REPOSITORY_ROOT",
        project,
    )

    def concurrent_write() -> str:
        try:
            LedgerStore(ledger_path).replace(
                expected_revision=41,
                document=stale,
            )
        except LedgerConflictError:
            return "conflict"
        return "written"

    with ThreadPoolExecutor(max_workers=1) as executor:
        future_holder: list[Future[str]] = []

        def replay_with_competing_writer(
            _inputs: Loop9FinalAcceptanceInputs,
        ) -> Loop9FinalAcceptanceReplay:
            future_holder.append(executor.submit(concurrent_write))
            return replay

        monkeypatch.setattr(
            final_acceptance_module,
            "replay_loop9_final_acceptance",
            replay_with_competing_writer,
        )
        accepted = accept_loop9_shadow(
            inputs=_inputs(project),
            ledger_path=ledger_path,
            output_directory=output,
            expected_ledger_revision=41,
            clock=lambda: datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )
        future = future_holder[0]
        assert future.result(timeout=5) == "conflict"

    assert accepted["gate_passed"] is True
    assert LedgerStore(ledger_path).read()["status"] == "shadow_accepted"
