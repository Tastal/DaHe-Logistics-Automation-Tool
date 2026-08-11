from __future__ import annotations

import hashlib
import json
import shutil
import socket
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.live_contract_selection import (
    select_live_read_contract,
)
from dahe.adapters.chengfeng.live_manifest import LiveReadContractManifest
from dahe.adapters.sqlite.platform_access import SqlitePlatformAccessRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_fault_injection import (
    FAULT_SCENARIOS,
    FaultScenarioRunIdentity,
    Loop9FaultInjectionError,
    Loop9FaultInjectionResult,
    Loop9FaultInjectionRunner,
    load_fault_injection_result,
    publish_fault_injection_result,
)
from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
    Loop9FormalRunEvidenceError,
    replay_persisted_fault_scenario,
)

pytestmark = pytest.mark.integration


def test_fault_result_file_is_idempotent_and_tamper_evident(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    from dahe.verification.loop9_operational_evidence import (
        fault_injector_contract_sha256,
    )

    build_sha256 = "b" * 64
    scenarios = {
        scenario: FaultScenarioRunIdentity(
            run_id=f"run-{scenario}",
            job_id=f"job-{scenario}",
        )
        for scenario in FAULT_SCENARIOS
    }
    body = {
        "injector_contract_sha256": fault_injector_contract_sha256(),
        "scenarios": {
            scenario: {
                "job_id": identity.job_id,
                "run_id": identity.run_id,
            }
            for scenario, identity in sorted(scenarios.items())
        },
        "source_build_sha256": build_sha256,
    }
    result = Loop9FaultInjectionResult(
        source_build_sha256=build_sha256,
        injector_contract_sha256=fault_injector_contract_sha256(),
        scenarios=scenarios,
        result_sha256=hashlib.sha256(_canonical(body)).hexdigest(),
    )

    path = publish_fault_injection_result(data_root=data_root, result=result)
    assert publish_fault_injection_result(
        data_root=data_root,
        result=result,
    ) == path
    assert load_fault_injection_result(
        path,
        expected_build_sha256=build_sha256,
    ) == result

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["scenarios"]["browser_closed"]["job_id"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        Loop9FaultInjectionError,
        match="verification failed",
    ):
        load_fault_injection_result(
            path,
            expected_build_sha256=build_sha256,
        )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _select_settlement_contract(
    *,
    project_root: Path,
    data_root: Path,
) -> None:
    directory = data_root / "platform-read-contract"
    directory.mkdir(parents=True)
    source = (
        project_root
        / "fixtures"
        / "chengfeng"
        / "loop9-read-only.invalid.json"
    ).read_bytes()
    manifest = LiveReadContractManifest.model_validate_json(
        source,
        strict=True,
    )
    canonical_sha256 = manifest.canonical_sha256
    contract_path = directory / f"{canonical_sha256}.json"
    contract_path.write_bytes(source)
    contract_file_sha256 = hashlib.sha256(source).hexdigest()
    freeze_body = {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_freeze",
        "classification": "development_only",
        "source_discovery_sha256": manifest.source_discovery_sha256,
        "source_observation_count": manifest.source_observation_count,
        "contract_canonical_sha256": canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "selected_observation_count": 3,
        "excluded_observation_count": 0,
        "potentially_mutating_observation_count": 0,
        "potentially_mutating_path_sha256s": [],
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    freeze_sha256 = hashlib.sha256(_canonical(freeze_body)).hexdigest()
    (
        directory / f"{canonical_sha256}.freeze-evidence.json"
    ).write_bytes(
        _canonical({**freeze_body, "canonical_sha256": freeze_sha256})
        + b"\n"
    )
    select_live_read_contract(
        data_root=data_root,
        contract_canonical_sha256=canonical_sha256,
        contract_file_sha256=contract_file_sha256,
        freeze_evidence_sha256=freeze_sha256,
    )


def _formal_data_root(
    *,
    project_root: Path,
    tmp_path: Path,
    name: str = "formal-loop9-data",
) -> Path:
    data_root = (tmp_path / name).resolve()
    data_root.mkdir()
    _select_settlement_contract(
        project_root=project_root,
        data_root=data_root,
    )
    build_sha256 = current_loop9_build_sha256(project_root)
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="loop9-fault-authority-seed",
    )
    try:
        SqlitePlatformAccessRepository(runtime).issue(
            purpose=AccessPurpose.PRODUCTION_SHADOW,
            job_id="loop9-formal-shadow-authority",
            session_id="loop9-formal-shadow-session",
            build_sha256=build_sha256,
            duration_minutes=60,
            legacy_idle_confirmed=True,
            no_settlement_or_payment_confirmed=True,
            same_account_session_risk_accepted=True,
            run_mode="shadow",
            idempotency_key="loop9-formal-shadow-authority",
            request_hash=hashlib.sha256(
                b"loop9-formal-shadow-authority"
            ).hexdigest(),
            now=datetime(2026, 7, 30, 8, tzinfo=UTC),
        )
    finally:
        runtime.close()
    return data_root


def _run(
    *,
    project_root: Path,
    tmp_path: Path,
) -> tuple[Path, object]:
    data_root = _formal_data_root(
        project_root=project_root,
        tmp_path=tmp_path,
    )
    result = Loop9FaultInjectionRunner(
        project_root=project_root,
        data_root=data_root,
    ).run()
    return data_root, result


def _copy_replay_root(
    *,
    source: Path,
    target: Path,
) -> Path:
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns("database"),
    )
    database_root = target / "database"
    database_root.mkdir()
    source_database = source / "database" / "dahe.sqlite3"
    target_database = database_root / "dahe.sqlite3"
    with (
        sqlite3.connect(source_database) as source_connection,
        sqlite3.connect(target_database) as target_connection,
    ):
        source_connection.backup(target_connection)
    return target


def test_four_protected_faults_are_real_replayable_scheduler_transitions(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root, result = _run(project_root=project_root, tmp_path=tmp_path)
    build_sha256 = current_loop9_build_sha256(project_root)

    assert result.source_build_sha256 == build_sha256
    assert set(result.scenarios) == set(FAULT_SCENARIOS)
    with sqlite3.connect(data_root / "database" / "dahe.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        for scenario in FAULT_SCENARIOS:
            identity = result.scenarios[scenario]
            replay = replay_persisted_fault_scenario(
                data_root=data_root,
                scenario=scenario,
                identity=FaultScenarioIdentity(
                    run_id=identity.run_id,
                    job_id=identity.job_id,
                ),
                current_build_sha256=build_sha256,
            )
            assert replay["missing_item_count"] == 0
            assert replay["duplicate_result_count"] == 0
            assert replay["technical_review_leak_count"] == 0

            job = connection.execute(
                "SELECT status, diagnostic_code FROM jobs WHERE job_id = ?",
                (identity.job_id,),
            ).fetchone()
            items = connection.execute(
                """
                SELECT status, business_outcome, review_reason, diagnostic_code
                FROM work_items WHERE job_id = ?
                """,
                (identity.job_id,),
            ).fetchall()
            attempts = connection.execute(
                """
                SELECT status, runtime_kind, error_kind
                FROM stage_attempts WHERE consumer_job_id = ?
                ORDER BY started_sequence, stage_attempt_id
                """,
                (identity.job_id,),
            ).fetchall()
            assert job is not None
            assert tuple(job) == ("succeeded", None)
            assert items
            assert all(row["status"] == "succeeded" for row in items)
            assert all(row["review_reason"] is None for row in items)
            assert all(row["diagnostic_code"] is None for row in items)
            assert any(
                row["error_kind"]
                in {
                    "browser_runtime_closed",
                    "gpu_worker_failure",
                    "application_instance_stopped",
                    "transient_network_failure",
                }
                for row in attempts
            )
            if scenario == "gpu_worker_failure":
                assert any(
                    row["status"] == "failed"
                    and row["runtime_kind"] == "gpu"
                    and row["error_kind"] == "gpu_worker_failure"
                    for row in attempts
                )


def test_main_restart_crosses_a_persisted_application_instance_boundary(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root, result = _run(project_root=project_root, tmp_path=tmp_path)
    identity = result.scenarios["main_application_restart"]

    with sqlite3.connect(data_root / "database" / "dahe.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        events = connection.execute(
            """
            SELECT payload_json FROM event_outbox
            WHERE aggregate_id = ?
              AND event_type LIKE 'verification.fault_injection.%'
            ORDER BY event_id
            """,
            (identity.job_id,),
        ).fetchall()
        assert len(events) == 3
        import json

        recovered = json.loads(events[-1]["payload_json"])
        assert recovered["source_instance_id"] != recovered["recovery_instance_id"]
        source = connection.execute(
            """
            SELECT status, stopped_at FROM application_instances
            WHERE instance_id = ?
            """,
            (recovered["source_instance_id"],),
        ).fetchone()
        assert source is not None
        assert source["status"] in {"crashed", "stopped"}
        assert source["stopped_at"] is not None
        failure = connection.execute(
            """
            SELECT status, error_kind FROM stage_attempts
            WHERE stage_attempt_id = ?
            """,
            (recovered["failed_stage_attempt_id"],),
        ).fetchone()
        assert failure is not None
        assert tuple(failure) == ("abandoned", "application_instance_stopped")


def test_retry_is_idempotent_and_does_not_duplicate_rows(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root, first = _run(project_root=project_root, tmp_path=tmp_path)
    database = data_root / "database" / "dahe.sqlite3"
    with sqlite3.connect(database) as connection:
        before = {
            table: connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "jobs",
                "work_items",
                "stage_attempts",
                "checkpoints",
                "leases",
                "application_instances",
                "event_outbox",
            )
        }

    second = Loop9FaultInjectionRunner(
        project_root=project_root,
        data_root=data_root,
    ).run()
    with sqlite3.connect(database) as connection:
        after = {
            table: connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in before
        }

    assert second == first
    assert after == before


def test_interruption_after_observed_failure_resumes_without_duplicate_chain(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root = _formal_data_root(
        project_root=project_root,
        tmp_path=tmp_path,
        name="interrupted-formal-data",
    )
    interrupted = False

    def interrupt_once(scenario: str) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise RuntimeError(f"simulated interruption after {scenario}")

    with pytest.raises(RuntimeError, match="simulated interruption"):
        Loop9FaultInjectionRunner(
            project_root=project_root,
            data_root=data_root,
            failure_hook=interrupt_once,
        ).run()

    result = Loop9FaultInjectionRunner(
        project_root=project_root,
        data_root=data_root,
    ).run()
    with sqlite3.connect(data_root / "database" / "dahe.sqlite3") as connection:
        for scenario, identity in result.scenarios.items():
            count = connection.execute(
                """
                SELECT COUNT(*) FROM event_outbox
                WHERE aggregate_id = ?
                  AND event_type LIKE 'verification.fault_injection.%'
                """,
                (identity.job_id,),
            ).fetchone()[0]
            assert count == 3, scenario


def test_runner_never_attempts_a_network_connection(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("fault injector attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    from dahe.adapters.chengfeng.browser_runtime import (
        IsolatedBrowserRuntime,
    )
    from dahe.adapters.chengfeng.live_connector_runtime import (
        LiveConnectorRuntime,
    )
    from dahe.adapters.chengfeng.verified_connector import (
        VerifiedChengfengConnector,
    )

    monkeypatch.setattr(
        IsolatedBrowserRuntime,
        "start_human_login",
        reject_network,
    )
    monkeypatch.setattr(
        LiveConnectorRuntime,
        "execute",
        reject_network,
    )
    monkeypatch.setattr(
        VerifiedChengfengConnector,
        "list_waybills",
        reject_network,
    )
    data_root, result = _run(project_root=project_root, tmp_path=tmp_path)

    assert len(result.scenarios) == 4
    with sqlite3.connect(data_root / "database" / "dahe.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM platform_access_windows"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM settlement_capture_invocations"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM daily_capture_invocations"
            ).fetchone()[0]
            == 0
        )


def test_missing_or_tampered_fault_event_fails_deep_replay(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root, result = _run(project_root=project_root, tmp_path=tmp_path)
    build_sha256 = current_loop9_build_sha256(project_root)
    identity = result.scenarios["browser_closed"]
    database = data_root / "database" / "dahe.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE event_outbox
            SET payload_json = replace(
                payload_json,
                'browser_runtime_closed',
                'transient_network_failure'
            )
            WHERE aggregate_id = ?
              AND event_type =
                  'verification.fault_injection.failure_observed'
            """,
            (identity.job_id,),
        )
        connection.commit()

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match=r"protected injector|integrity|identities",
    ):
        replay_persisted_fault_scenario(
            data_root=data_root,
            scenario="browser_closed",
            identity=FaultScenarioIdentity(
                run_id=identity.run_id,
                job_id=identity.job_id,
            ),
            current_build_sha256=build_sha256,
        )


def test_missing_fault_event_fails_deep_replay(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root, result = _run(project_root=project_root, tmp_path=tmp_path)
    build_sha256 = current_loop9_build_sha256(project_root)
    identity = result.scenarios["transient_network_failure"]
    database = data_root / "database" / "dahe.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            DELETE FROM event_outbox
            WHERE aggregate_id = ?
              AND event_type = 'verification.fault_injection.recovered'
            """,
            (identity.job_id,),
        )
        connection.commit()

    with pytest.raises(
        Loop9FormalRunEvidenceError,
        match="missing the protected",
    ):
        replay_persisted_fault_scenario(
            data_root=data_root,
            scenario="transient_network_failure",
            identity=FaultScenarioIdentity(
                run_id=identity.run_id,
                job_id=identity.job_id,
            ),
            current_build_sha256=build_sha256,
        )


def test_deep_replay_rejects_job_checkpoint_and_lease_semantic_tampering(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root, result = _run(
        project_root=project_root,
        tmp_path=tmp_path,
    )
    build_sha256 = current_loop9_build_sha256(project_root)
    identity = result.scenarios["browser_closed"]
    with sqlite3.connect(data_root / "database" / "dahe.sqlite3") as connection:
        recovered_row = connection.execute(
            """
            SELECT payload_json
            FROM event_outbox
            WHERE aggregate_id = ?
              AND event_type = 'verification.fault_injection.recovered'
            """,
            (identity.job_id,),
        ).fetchone()
    assert recovered_row is not None
    recovered = json.loads(recovered_row[0])
    checkpoint_id = recovered["checkpoint_id"]
    failed_attempt_id = recovered["failed_stage_attempt_id"]
    recovery_attempt_id = recovered["recovery_stage_attempt_id"]

    mutations = {
        "wrong-job-kind": (
            "UPDATE jobs SET job_kind = 'business' WHERE job_id = ?",
            (identity.job_id,),
        ),
        "wrong-scope": (
            "UPDATE jobs SET scope_label = 'tampered scope' WHERE job_id = ?",
            (identity.job_id,),
        ),
        "wrong-checkpoint-stage": (
            "UPDATE checkpoints SET stage = 'audit.compare' "
            "WHERE checkpoint_id = ?",
            (checkpoint_id,),
        ),
        "wrong-checkpoint-payload": (
            "UPDATE checkpoints SET payload_json = '{}' "
            "WHERE checkpoint_id = ?",
            (checkpoint_id,),
        ),
        "wrong-source-lease-release": (
            "UPDATE leases SET release_reason = 'atomic_stage_completed' "
            "WHERE stage_attempt_id = ?",
            (failed_attempt_id,),
        ),
        "wrong-recovery-lease-release": (
            "UPDATE leases SET release_reason = 'tampered' "
            "WHERE stage_attempt_id = ?",
            (recovery_attempt_id,),
        ),
    }
    for name, (statement, parameters) in mutations.items():
        replay_root = _copy_replay_root(
            source=data_root,
            target=(tmp_path / f"replay-{name}").resolve(),
        )
        with sqlite3.connect(
            replay_root / "database" / "dahe.sqlite3"
        ) as connection:
            connection.execute(statement, parameters)
            connection.commit()
        with pytest.raises(Loop9FormalRunEvidenceError):
            replay_persisted_fault_scenario(
                data_root=replay_root,
                scenario="browser_closed",
                identity=FaultScenarioIdentity(
                    run_id=identity.run_id,
                    job_id=identity.job_id,
                ),
                current_build_sha256=build_sha256,
            )


def test_runner_rejects_relative_or_symlink_data_roots(
    project_root: Path,
    tmp_path: Path,
) -> None:
    with pytest.raises(Loop9FaultInjectionError, match="absolute"):
        Loop9FaultInjectionRunner(
            project_root=project_root,
            data_root=Path("relative"),
        )

    target = (tmp_path / "target").resolve()
    target.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Windows symlink privilege is unavailable")
    with pytest.raises(Loop9FaultInjectionError, match="unsafe"):
        Loop9FaultInjectionRunner(
            project_root=project_root,
            data_root=alias.absolute(),
        )


def test_runner_rejects_uninitialized_or_non_loop9_root_without_database(
    project_root: Path,
    tmp_path: Path,
) -> None:
    uninitialized = (tmp_path / "uninitialized").resolve()
    uninitialized.mkdir()

    with pytest.raises(
        Loop9FaultInjectionError,
        match=r"formal|authority|database|Chengfeng",
    ):
        Loop9FaultInjectionRunner(
            project_root=project_root,
            data_root=uninitialized,
        ).run()

    assert not (uninitialized / "database").exists()
    assert not (
        uninitialized / "runtime" / "test-fixture-root.json"
    ).exists()


def test_runner_rejects_a_running_formal_data_root(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root = _formal_data_root(
        project_root=project_root,
        tmp_path=tmp_path,
        name="running-formal-data",
    )
    guard = SingleInstanceGuard(
        data_root,
        8877,
        "test-running-instance",
    )
    with guard, pytest.raises(
        Loop9FaultInjectionError,
        match=r"running|instance",
    ):
        Loop9FaultInjectionRunner(
            project_root=project_root,
            data_root=data_root,
        ).run()


def test_formal_root_gets_exactly_four_current_build_fixed_jobs(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root, result = _run(
        project_root=project_root,
        tmp_path=tmp_path,
    )
    build_sha256 = current_loop9_build_sha256(project_root)

    with sqlite3.connect(data_root / "database" / "dahe.sqlite3") as connection:
        jobs = connection.execute(
            """
            SELECT job_kind, run_mode, scope_label, conflict_key
            FROM jobs
            WHERE conflict_key LIKE 'test_fixture:loop9-fault:%'
            ORDER BY scope_label
            """
        ).fetchall()

    assert len(jobs) == len(FAULT_SCENARIOS)
    assert {
        row[2].removeprefix("Loop 9 protected fault: ")
        for row in jobs
    } == set(FAULT_SCENARIOS)
    assert all(row[0] == "test_fixture" for row in jobs)
    assert all(row[1] == "shadow" for row in jobs)
    assert all(row[3].endswith(build_sha256) for row in jobs)
    assert len(result.scenarios) == len(jobs)
    assert not (
        data_root / "runtime" / "test-fixture-root.json"
    ).exists()
