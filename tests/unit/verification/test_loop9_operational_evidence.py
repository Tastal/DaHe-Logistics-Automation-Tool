from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
    Loop9FormalRunEvidence,
    Loop9FormalRunEvidenceError,
    Loop9FormalRunEvidenceStore,
    Loop9FormalRunRequest,
    _capture_request_audit_binding,
    _scheduler_projection_summary,
    _validate_current_daily_validation_for_formal_run,
    fault_injector_contract_sha256,
    recompute_machine_performance,
    replay_persisted_fault_scenario,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
SHA_0 = "0" * 64
SHA_1 = "1" * 64


def _request() -> Loop9FormalRunRequest:
    return Loop9FormalRunRequest(
        locked_job_id="locked-job",
        real_shadow_selection_sha256=SHA_A,
        real_shadow_job_id="shadow-job",
        real_shadow_machine_evaluation_sha256=SHA_B,
        daily_snapshot_validation_sha256=SHA_C,
        dataset_isolation_sha256=SHA_D,
        fault_scenarios={
            scenario: FaultScenarioIdentity(
                run_id=f"run-{scenario}",
                job_id=f"job-{scenario}",
            )
            for scenario in (
                "browser_closed",
                "gpu_worker_failure",
                "main_application_restart",
                "transient_network_failure",
            )
        },
    )


def _audit_document(
    *,
    purpose: str,
    succeeded: int,
) -> dict[str, object]:
    authority = {
        "build_sha256": SHA_A,
        "daily_contract_selection_sha256": (
            SHA_E if purpose == "daily_snapshot" else None
        ),
        "daily_contract_sha256": (
            SHA_D if purpose == "daily_snapshot" else None
        ),
        "settlement_contract_selection_sha256": SHA_C,
        "settlement_contract_sha256": SHA_B,
    }
    operation_counts = {
        operation: {
            "allowed": succeeded if operation == "list_waybills" else 0,
            "attempted": succeeded if operation == "list_waybills" else 0,
            "denied": 0,
            "failed": 0,
            "redirect": 0,
            "succeeded": succeeded if operation == "list_waybills" else 0,
        }
        for operation in (
            "list_waybills",
            "get_waybill_detail",
            "download_ticket_image",
            "list_daily_waybills",
        )
    }
    body: dict[str, object] = {
        "authority": authority,
        "event_chain_sha256": SHA_F,
        "event_count": succeeded * 3,
        "expected_succeeded_operations": {
            "list_waybills": succeeded
        },
        "job_id_sha256": SHA_0,
        "kind": "loop9_platform_read_audit",
        "operation_counts": operation_counts,
        "platform_write_request_count": 0,
        "purpose": purpose,
        "redirect_count": 0,
        "request_counts": {
            "allowed": succeeded,
            "attempted": succeeded,
            "denied": 0,
            "succeeded": succeeded,
        },
        "schema_version": 1,
    }
    return {
        **body,
        "canonical_sha256": __import__("hashlib")
        .sha256(
            json.dumps(
                body,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        .hexdigest(),
    }


def _evidence() -> Loop9FormalRunEvidence:
    return Loop9FormalRunEvidence.create(
        source_build_sha256=SHA_A,
        settlement_contract_sha256=SHA_B,
        settlement_contract_selection_sha256=SHA_C,
        daily_contract_sha256=SHA_D,
        daily_contract_selection_sha256=SHA_E,
        current_locked_selection_sha256=SHA_F,
        current_locked_gate_sha256=SHA_0,
        real_shadow_selection_sha256=SHA_1,
        real_shadow_machine_evaluation_sha256=SHA_A,
        daily_snapshot_validation_sha256=SHA_B,
        dataset_isolation_sha256=SHA_C,
        scheduler_projections={
            "current_locked_50": {
                "job_id_sha256": SHA_D,
                "projection_sha256": SHA_E,
                "item_count": 50,
                "technical_review_leak_count": 0,
                "terminal_result_count": 50,
            },
            "real_shadow_30": {
                "job_id_sha256": SHA_F,
                "projection_sha256": SHA_0,
                "item_count": 30,
                "technical_review_leak_count": 0,
                "terminal_result_count": 30,
            },
        },
        request_audits={
            name: _audit_document(
                purpose=(
                    "daily_snapshot"
                    if name.startswith("daily_snapshot_")
                    else name
                ),
                succeeded=count,
            )
            for name, count in (
                ("current_locked_50", 150),
                ("daily_snapshot_1", 1),
                ("daily_snapshot_2", 1),
                ("daily_snapshot_3", 1),
                ("real_shadow_30", 90),
            )
        },
        fault_injections={
            scenario: {
                "run_id_sha256": SHA_A,
                "job_id_sha256": SHA_B,
                "injection_event_sha256": SHA_C,
                "event_chain_sha256": SHA_C,
                "failure_attempt_sha256": SHA_D,
                "checkpoint_sha256": SHA_E,
                "recovery_attempt_sha256": SHA_F,
                "source_lease_sha256": SHA_D,
                "recovery_lease_sha256": SHA_E,
                "source_instance_sha256": SHA_0,
                "recovery_instance_sha256": SHA_1,
                "job_sha256": SHA_F,
                "work_item_results_sha256": SHA_0,
                "missing_item_count": 0,
                "duplicate_result_count": 0,
                "technical_review_leak_count": 0,
            }
            for scenario in (
                "browser_closed",
                "gpu_worker_failure",
                "main_application_restart",
                "transient_network_failure",
            )
        },
        performance={
            scope: {
                "sample_size": sample_size,
                "p50_ms": "1",
                "p95_ms": "2",
                "samples_sha256": SHA_A,
            }
            for scope, sample_size in (
                ("cpu_ocr", 160),
                ("gpu_ocr", 160),
                ("role_validation", 160),
                ("end_to_end", 80),
            )
        },
        reconciliation={
            "source_item_count": 80,
            "terminal_result_count": 80,
            "missing_item_count": 0,
            "duplicate_result_count": 0,
            "technical_review_leak_count": 0,
        },
    )


def test_capture_binding_rejects_selection_audit_copy_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dahe.adapters.files.settlement_capture_manifest import (
        SettlementCaptureManifestStore,
    )
    from dahe.application.chengfeng.shadow_selection import (
        FormalShadowSelectionManifest,
    )

    capture = SimpleNamespace(
        request_audit_sha256=SHA_A,
        request_audit_counts={"attempted": 1},
        source_job_id="capture-job",
    )
    monkeypatch.setattr(
        SettlementCaptureManifestStore,
        "load",
        lambda _self, _sha256: capture,
    )
    selection = object.__new__(FormalShadowSelectionManifest)
    object.__setattr__(selection, "source_capture_sha256", SHA_B)
    object.__setattr__(
        selection,
        "batch_manifest",
        SimpleNamespace(
            schema_version=2,
            source_capture_sha256=SHA_B,
            request_audit_sha256=SHA_A,
            request_audit_counts={"attempted": 2},
        ),
    )

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="selection request audit binding is invalid",
    ):
        _capture_request_audit_binding(
            tmp_path.resolve(),
            selection=selection,
            label="locked",
        )


@pytest.mark.parametrize(
    ("schema_version", "should_pass"),
    ((4, False), (5, True)),
)
def test_operational_evidence_requires_current_daily_schema_five(
    schema_version: int,
    should_pass: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import dahe.verification.daily_snapshot_validation as daily_validation

    payload: dict[str, object] = {
        "schema_version": schema_version,
        "canonical_sha256": SHA_C,
        "build_sha256": SHA_A,
        "contract_sha256": SHA_D,
    }
    monkeypatch.setattr(
        daily_validation,
        "replay_current_daily_snapshot_validation_from_store",
        lambda value, **_kwargs: value,
    )

    if should_pass:
        assert (
            _validate_current_daily_validation_for_formal_run(
                payload,
                data_root=tmp_path.resolve(),
                project_root=tmp_path.resolve(),
                expected_canonical_sha256=SHA_C,
                source_build_sha256=SHA_A,
                daily_contract_sha256=SHA_D,
            )
            == payload
        )
    else:
        with pytest.raises(
            Loop9FormalRunEvidenceError,
            match="authority changed",
        ):
            _validate_current_daily_validation_for_formal_run(
                payload,
                data_root=tmp_path.resolve(),
                project_root=tmp_path.resolve(),
                expected_canonical_sha256=SHA_C,
                source_build_sha256=SHA_A,
                daily_contract_sha256=SHA_D,
            )


def test_request_accepts_only_four_named_fault_scenarios() -> None:
    request = _request()
    assert set(request.fault_scenarios) == {
        "browser_closed",
        "gpu_worker_failure",
        "main_application_restart",
        "transient_network_failure",
    }

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="exactly four",
    ):
        Loop9FormalRunRequest(
            locked_job_id=request.locked_job_id,
            real_shadow_selection_sha256=(
                request.real_shadow_selection_sha256
            ),
            real_shadow_job_id=request.real_shadow_job_id,
            real_shadow_machine_evaluation_sha256=(
                request.real_shadow_machine_evaluation_sha256
            ),
            daily_snapshot_validation_sha256=(
                request.daily_snapshot_validation_sha256
            ),
            dataset_isolation_sha256=request.dataset_isolation_sha256,
            fault_scenarios={
                key: value
                for key, value in request.fault_scenarios.items()
                if key != "browser_closed"
            },
        )


@pytest.mark.parametrize("identity_field", ("run_id", "job_id"))
def test_request_rejects_duplicate_fault_identities(
    identity_field: str,
) -> None:
    request = _request()
    identities = dict(request.fault_scenarios)
    first = identities["browser_closed"]
    second = identities["gpu_worker_failure"]
    identities["gpu_worker_failure"] = FaultScenarioIdentity(
        run_id=(
            first.run_id
            if identity_field == "run_id"
            else second.run_id
        ),
        job_id=(
            first.job_id
            if identity_field == "job_id"
            else second.job_id
        ),
    )

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="unique",
    ):
        Loop9FormalRunRequest(
            locked_job_id=request.locked_job_id,
            real_shadow_selection_sha256=(
                request.real_shadow_selection_sha256
            ),
            real_shadow_job_id=request.real_shadow_job_id,
            real_shadow_machine_evaluation_sha256=(
                request.real_shadow_machine_evaluation_sha256
            ),
            daily_snapshot_validation_sha256=(
                request.daily_snapshot_validation_sha256
            ),
            dataset_isolation_sha256=request.dataset_isolation_sha256,
            fault_scenarios=identities,
        )


@pytest.mark.parametrize(
    "review_reason",
    (
        "browser_runtime_closed",
        "technical_failure",
        "browser_worker_request_failed",
    ),
)
def test_scheduler_projection_rejects_non_business_review_reason_without_diagnostic(
    review_reason: str,
) -> None:
    from dahe.verification.loop9_machine_results import (
        SchedulerBatchProjection,
    )

    projection = object.__new__(SchedulerBatchProjection)
    object.__setattr__(projection, "job_id", "formal-job")
    object.__setattr__(projection, "job_status", "succeeded")
    object.__setattr__(projection, "projection_sha256", SHA_A)
    object.__setattr__(
        projection,
        "items",
        (
                SimpleNamespace(
                    business_outcome="awaiting_review",
                    decision="review",
                    diagnostic_code=None,
                    review_reason=review_reason,
                status="succeeded",
                work_item_id="formal-item",
            ),
        ),
    )

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="technical failure leaked",
    ):
        _scheduler_projection_summary(projection, expected_count=1)


def test_machine_performance_requires_raw_role_and_end_to_end_records() -> None:
    machine = {
        "results": [
            {
                "image_evaluations": [
                    {
                        "incremental_elapsed_ms": "12",
                        "runtime_comparison": {
                            "selected_runtime_kind": "gpu",
                        },
                        "runtime_observations": [
                            {
                                "runtime_kind": "cpu",
                                "timing": {
                                    "wall_elapsed_ms": "10",
                                    "worker_elapsed_ms": "9",
                                },
                                "role": {"predicted": "loading"},
                            },
                            {
                                "runtime_kind": "gpu",
                                "timing": {
                                    "wall_elapsed_ms": "3",
                                    "worker_elapsed_ms": "2",
                                },
                                "role": {"predicted": "loading"},
                            },
                        ],
                    }
                ]
            }
        ]
    }

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match=r"role\.elapsed_ms",
    ):
        recompute_machine_performance(
            (machine,),
            end_to_end_duration_ms=("20",),
        )


def test_machine_performance_is_recomputed_from_raw_samples() -> None:
    observations = []
    for index in range(1, 21):
        observations.append(
            {
                "incremental_elapsed_ms": str(index + 10),
                "runtime_comparison": {
                    "selected_runtime_kind": "gpu",
                },
                "runtime_observations": [
                    {
                        "runtime_kind": "cpu",
                        "timing": {
                            "wall_elapsed_ms": str(index + 1),
                            "worker_elapsed_ms": str(index),
                        },
                        "role": {
                            "elapsed_ms": str(index / 10),
                            "predicted": "loading",
                        },
                    },
                    {
                        "runtime_kind": "gpu",
                        "timing": {
                            "wall_elapsed_ms": str(index / 2),
                            "worker_elapsed_ms": str(index / 4),
                        },
                        "role": {
                            "elapsed_ms": str(index / 20),
                            "predicted": "loading",
                        },
                    },
                ],
            }
        )
    result = recompute_machine_performance(
        ({"results": [{"image_evaluations": observations}]},),
        end_to_end_duration_ms=tuple(str(index) for index in range(1, 11)),
    )

    assert result["cpu_ocr"]["sample_size"] == 20
    assert result["cpu_ocr"]["p50_ms"] == "11"
    assert result["cpu_ocr"]["p95_ms"] == "20"
    assert result["end_to_end"]["p50_ms"] == "5"
    assert result["end_to_end"]["p95_ms"] == "10"
    assert result["role_validation"]["sample_size"] == 20


def test_evidence_rejects_tampering_and_has_fixed_content_address(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    evidence = _evidence()
    store = Loop9FormalRunEvidenceStore(root)
    path = store.persist(evidence)

    assert path == (
        root
        / "verification"
        / "loop9"
        / "formal-run-evidence"
        / "sha256"
        / evidence.canonical_sha256[:2]
        / evidence.canonical_sha256[2:4]
        / f"{evidence.canonical_sha256}.json"
    )
    assert store.load_persisted(evidence.canonical_sha256) == evidence

    forged = deepcopy(evidence.to_payload())
    forged["reconciliation"]["missing_item_count"] = 1  # type: ignore[index]
    path.write_text(
        json.dumps(forged, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match=r"integrity|canonical|reconciliation",
    ):
        store.load_persisted(evidence.canonical_sha256)


def test_evidence_rejects_request_audit_expected_count_tampering() -> None:
    payload = deepcopy(_evidence().to_payload())
    audit = payload["request_audits"]["real_shadow_30"]  # type: ignore[index]
    audit["expected_succeeded_operations"]["list_waybills"] = 89  # type: ignore[index]
    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="request audit",
    ):
        Loop9FormalRunEvidence.from_payload(payload)


def test_evidence_rejects_valid_audit_bound_to_another_build() -> None:
    payload = deepcopy(_evidence().to_payload())
    audit = payload["request_audits"]["real_shadow_30"]  # type: ignore[index]
    audit["authority"]["build_sha256"] = SHA_B  # type: ignore[index]
    audit["canonical_sha256"] = __import__("hashlib").sha256(
        json.dumps(
            {
                key: value
                for key, value in audit.items()  # type: ignore[union-attr]
                if key != "canonical_sha256"
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="request audit",
    ):
        Loop9FormalRunEvidence.from_payload(payload)


def test_fault_evidence_binds_terminal_chain_and_reconciled_rows() -> None:
    fault = _evidence().fault_injections["browser_closed"]

    assert fault["event_chain_sha256"] == SHA_C
    assert fault["source_lease_sha256"] == SHA_D
    assert fault["recovery_lease_sha256"] == SHA_E
    assert fault["job_sha256"] == SHA_F
    assert fault["work_item_results_sha256"] == SHA_0


def test_store_does_not_publish_from_user_supplied_counts(
    tmp_path: Path,
) -> None:
    store = Loop9FormalRunEvidenceStore(tmp_path.resolve())
    assert not hasattr(store, "publish_from_payload")
    assert not hasattr(store, "publish_from_counts")


def test_replay_rejects_non_absolute_project_root_before_derivation(
    tmp_path: Path,
) -> None:
    store = Loop9FormalRunEvidenceStore(tmp_path.resolve())
    evidence = _evidence()
    store.persist(evidence)

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="project root is unsafe",
    ):
        store.load_and_replay(
            evidence.canonical_sha256,
            project_root=Path("."),
            request=_request(),
        )


def test_fault_contract_is_stable_and_missing_event_chain_fails_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    database = root / "database" / "dahe.sqlite3"
    database.parent.mkdir()
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE application_instances (instance_id TEXT);
            CREATE TABLE checkpoints (checkpoint_id TEXT);
            CREATE TABLE jobs (job_id TEXT);
            CREATE TABLE leases (lease_id TEXT);
            CREATE TABLE stage_attempts (stage_attempt_id TEXT);
            CREATE TABLE work_items (work_item_id TEXT);
            CREATE TABLE event_outbox (
                event_id INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                aggregate_type TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                record_version INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()

    contract_sha256 = fault_injector_contract_sha256()
    assert len(contract_sha256) == 64
    assert set(contract_sha256) <= set("0123456789abcdef")
    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="missing the protected",
    ):
        replay_persisted_fault_scenario(
            data_root=root,
            scenario="browser_closed",
            identity=FaultScenarioIdentity(
                run_id="formal-browser-run",
                job_id="formal-browser-job",
            ),
            current_build_sha256=SHA_A,
        )
