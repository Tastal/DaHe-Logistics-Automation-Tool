from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import select, text, update
from sqlalchemy.engine import Connection

from dahe import __version__
from dahe.adapters.chengfeng.live_contract_selection import (
    LiveContractSelectionError,
    load_selected_live_read_contract,
)
from dahe.adapters.sqlite.recovery import PersistentRecoveryStore
from dahe.adapters.sqlite.repository import TemporarySqliteJobRepository
from dahe.adapters.sqlite.schema import (
    CHECKPOINTS,
    JOBS,
    LEASES,
    OUTBOX,
    SHARED_EVIDENCE_WORK,
    STAGE_ATTEMPTS,
    WORK_ITEMS,
)
from dahe.jobs.scheduler import CooperativeScheduler
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.system.instance_lifecycle import (
    current_process_identity,
    data_root_identity,
)
from dahe.system.instance_lock import (
    AlreadyRunningError,
    InstanceLockError,
    SingleInstanceGuard,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
    Loop9FormalRunEvidenceError,
    fault_injector_contract_sha256,
    replay_persisted_fault_scenario,
)

FAULT_SCENARIOS = (
    "browser_closed",
    "transient_network_failure",
    "main_application_restart",
    "gpu_worker_failure",
)

_CLASSIFICATIONS = {
    "browser_closed": "browser_runtime_closed",
    "gpu_worker_failure": "gpu_worker_failure",
    "main_application_restart": "application_instance_stopped",
    "transient_network_failure": "transient_network_failure",
}
_EVENT_TYPES = (
    "verification.fault_injection.injected",
    "verification.fault_injection.failure_observed",
    "verification.fault_injection.recovered",
)
_SCHEMA_VERSION = 1


class Loop9FaultInjectionError(RuntimeError):
    """Raised when a protected offline fault scenario cannot be proven."""


@dataclass(frozen=True, slots=True)
class FaultScenarioRunIdentity:
    run_id: str
    job_id: str


@dataclass(frozen=True, slots=True)
class Loop9FaultInjectionResult:
    source_build_sha256: str
    injector_contract_sha256: str
    scenarios: Mapping[str, FaultScenarioRunIdentity]
    result_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "injector_contract_sha256": self.injector_contract_sha256,
            "result_sha256": self.result_sha256,
            "scenarios": {
                scenario: {
                    "job_id": identity.job_id,
                    "run_id": identity.run_id,
                }
                for scenario, identity in sorted(self.scenarios.items())
            },
            "source_build_sha256": self.source_build_sha256,
        }


def publish_fault_injection_result(
    *,
    data_root: Path,
    result: Loop9FaultInjectionResult,
) -> Path:
    root = data_root.resolve(strict=True)
    output_root = root / "verification" / "fault-injection"
    output_root.mkdir(parents=True, exist_ok=True)
    target = output_root / f"{result.result_sha256}.json"
    content = (
        json.dumps(
            result.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if target.exists():
        if target.is_symlink() or target.read_bytes() != content:
            raise Loop9FaultInjectionError(
                "existing fault injection evidence differs"
            )
        return target
    staging = output_root / f".{target.name}.{uuid4().hex}.partial"
    try:
        with staging.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, target)
    finally:
        staging.unlink(missing_ok=True)
    return target


def load_fault_injection_result(
    path: Path,
    *,
    expected_build_sha256: str,
) -> Loop9FaultInjectionResult:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Loop9FaultInjectionError(
            "fault injection evidence is unreadable"
        ) from exc
    if not isinstance(payload, dict) or set(payload) != {
        "injector_contract_sha256",
        "result_sha256",
        "scenarios",
        "source_build_sha256",
    }:
        raise Loop9FaultInjectionError("fault injection evidence is invalid")
    raw_scenarios = payload.get("scenarios")
    if not isinstance(raw_scenarios, dict) or set(raw_scenarios) != set(
        FAULT_SCENARIOS
    ):
        raise Loop9FaultInjectionError("fault injection scenarios are incomplete")
    try:
        scenarios = {
            scenario: FaultScenarioRunIdentity(
                run_id=str(raw_scenarios[scenario]["run_id"]),
                job_id=str(raw_scenarios[scenario]["job_id"]),
            )
            for scenario in FAULT_SCENARIOS
        }
    except (KeyError, TypeError) as exc:
        raise Loop9FaultInjectionError(
            "fault injection scenario identity is invalid"
        ) from exc
    body = {
        "injector_contract_sha256": payload.get("injector_contract_sha256"),
        "scenarios": {
            scenario: {
                "job_id": identity.job_id,
                "run_id": identity.run_id,
            }
            for scenario, identity in sorted(scenarios.items())
        },
        "source_build_sha256": payload.get("source_build_sha256"),
    }
    if (
        payload.get("source_build_sha256") != expected_build_sha256
        or payload.get("injector_contract_sha256")
        != fault_injector_contract_sha256()
        or payload.get("result_sha256") != _canonical_sha256(body)
        or path.name != f"{payload.get('result_sha256')}.json"
    ):
        raise Loop9FaultInjectionError(
            "fault injection evidence verification failed"
        )
    return Loop9FaultInjectionResult(
        source_build_sha256=expected_build_sha256,
        injector_contract_sha256=fault_injector_contract_sha256(),
        scenarios=scenarios,
        result_sha256=str(payload["result_sha256"]),
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _validate_root(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9FaultInjectionError(f"{label} must be absolute")
    if path.is_symlink() or _is_reparse_point(path):
        raise Loop9FaultInjectionError(f"{label} is unsafe")
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9FaultInjectionError(f"{label} is unavailable") from exc
    if not root.is_dir() or root.is_symlink() or _is_reparse_point(root):
        raise Loop9FaultInjectionError(f"{label} is unsafe")
    return root


def _existing_normal_file(
    *,
    root: Path,
    relative_path: Path,
    label: str,
) -> Path:
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise Loop9FaultInjectionError(f"{label} is unavailable") from exc
    if (
        candidate.is_symlink()
        or _is_reparse_point(candidate)
        or not resolved.is_file()
    ):
        raise Loop9FaultInjectionError(f"{label} is unsafe")
    return resolved


def _expected_database_head(project_root: Path) -> str:
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(
            project_root
            / "src"
            / "dahe"
            / "adapters"
            / "sqlite"
            / "migrations"
        ),
    )
    head = ScriptDirectory.from_config(config).get_current_head()
    if head is None:
        raise Loop9FaultInjectionError(
            "checked-in Loop 9 database head is unavailable"
        )
    return head


def _verify_formal_loop9_authority(
    *,
    project_root: Path,
    data_root: Path,
    build_sha256: str,
) -> None:
    fixture_marker = data_root / "runtime" / "test-fixture-root.json"
    if fixture_marker.exists() or fixture_marker.is_symlink():
        raise Loop9FaultInjectionError(
            "formal Loop 9 data root must not be a fixture root"
        )
    _existing_normal_file(
        root=data_root,
        relative_path=Path(
            "platform-read-contract",
            "active-candidate.json",
        ),
        label="selected Chengfeng read contract",
    )
    try:
        load_selected_live_read_contract(data_root)
    except LiveContractSelectionError as exc:
        raise Loop9FaultInjectionError(
            "selected Chengfeng read contract authority is invalid"
        ) from exc

    database = _existing_normal_file(
        root=data_root,
        relative_path=Path("database", "dahe.sqlite3"),
        label="formal Loop 9 database",
    )
    if database.stat().st_size == 0:
        raise Loop9FaultInjectionError(
            "formal Loop 9 database is uninitialized"
        )
    try:
        with sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
        ) as connection:
            connection.execute("PRAGMA query_only=ON")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table'"
                )
            }
            required_tables = {
                "alembic_version",
                "jobs",
                "platform_access_events",
                "platform_access_windows",
            }
            if not required_tables <= tables:
                raise Loop9FaultInjectionError(
                    "formal Loop 9 database authority is incomplete"
                )
            revisions = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT version_num FROM alembic_version"
                )
            )
            if revisions != (_expected_database_head(project_root),):
                raise Loop9FaultInjectionError(
                    "formal Loop 9 database is not at the current schema head"
                )
            current_shadow_windows = int(
                connection.execute(
                    """
                    SELECT COUNT(DISTINCT access.access_window_id)
                    FROM platform_access_windows AS access
                    JOIN platform_access_events AS event
                      ON event.access_window_id = access.access_window_id
                    WHERE access.build_sha256 = ?
                      AND access.purpose = 'production_shadow'
                      AND event.event_type = 'issued'
                    """,
                    (build_sha256,),
                ).fetchone()[0]
            )
            if current_shadow_windows < 1:
                raise Loop9FaultInjectionError(
                    "data root has no current-build Chengfeng shadow authority"
                )
            integrity = str(
                connection.execute("PRAGMA quick_check").fetchone()[0]
            )
            if integrity != "ok":
                raise Loop9FaultInjectionError(
                    "formal Loop 9 database integrity check failed"
                )
    except Loop9FaultInjectionError:
        raise
    except sqlite3.DatabaseError as exc:
        raise Loop9FaultInjectionError(
            "formal Loop 9 database is unreadable"
        ) from exc


def _scenario_fixture(
    scenario: str,
    *,
    build_sha256: str,
) -> ScheduledJobSpec:
    prefix = hashlib.sha256(
        f"loop9-fault:{scenario}:{build_sha256}".encode()
    ).hexdigest()
    if scenario == "gpu_worker_failure":
        return ScheduledJobSpec(
            fixture_id=f"loop9-fault-{scenario}-{prefix[:12]}",
            job_kind="test_fixture",
            task_type="audit",
            scope_label=f"Loop 9 protected fault: {scenario}",
            conflict_key=f"test_fixture:loop9-fault:{scenario}:{build_sha256}",
            items=(
                ScheduledWorkItemSpec(
                    item_key=f"L9-FI-{prefix[:12]}",
                    expected_outcome="normal_ready",
                    loading_image_sha256=hashlib.sha256(
                        f"{prefix}:loading".encode()
                    ).hexdigest(),
                    unloading_image_sha256=hashlib.sha256(
                        f"{prefix}:unloading".encode()
                    ).hexdigest(),
                ),
            ),
            pipeline_fingerprint=build_sha256,
            ocr_execution_mode="fake",
        )
    return ScheduledJobSpec(
        fixture_id=f"loop9-fault-{scenario}-{prefix[:12]}",
        job_kind="test_fixture",
        task_type="loading_probe",
        scope_label=f"Loop 9 protected fault: {scenario}",
        conflict_key=f"test_fixture:loop9-fault:{scenario}:{build_sha256}",
        items=(
            ScheduledWorkItemSpec(
                item_key=f"L9-FI-{prefix[:12]}",
                expected_outcome=None,
                required_resource="platform_browser",
            ),
        ),
    )


def _event_core(
    *,
    event_type: str,
    aggregate_id: str,
    record_version: int,
    created_at: str,
    payload: Mapping[str, object],
) -> dict[str, object]:
    return {
        "aggregate_id": aggregate_id,
        "aggregate_type": "job",
        "created_at": created_at,
        "event_type": event_type,
        "payload": {
            key: value
            for key, value in payload.items()
            if key != "event_sha256"
        },
        "record_version": record_version,
    }


def _append_protected_event(
    connection: Connection,
    *,
    event_type: str,
    job_id: str,
    record_version: int,
    created_at: str,
    payload: dict[str, object],
) -> str:
    event_sha256 = _canonical_sha256(
        _event_core(
            event_type=event_type,
            aggregate_id=job_id,
            record_version=record_version,
            created_at=created_at,
            payload=payload,
        )
    )
    payload["event_sha256"] = event_sha256
    connection.execute(
        OUTBOX.insert().values(
            event_type=event_type,
            aggregate_type="job",
            aggregate_id=job_id,
            record_version=record_version,
            payload_json=_canonical_bytes(payload).decode("utf-8"),
            created_at=created_at,
        )
    )
    return event_sha256


def _instance_id(
    *,
    scenario: str,
    job_id: str,
    role: str,
) -> str:
    digest = hashlib.sha256(
        f"{scenario}:{job_id}:{role}".encode()
    ).hexdigest()
    return f"l9fi-{role}-{digest[:32]}"


def _run_id(
    *,
    scenario: str,
    job_id: str,
    build_sha256: str,
) -> str:
    return hashlib.sha256(
        f"loop9-fault-run:{scenario}:{job_id}:{build_sha256}".encode()
    ).hexdigest()


def _job_event_rows(
    repository: TemporarySqliteJobRepository,
    *,
    job_id: str,
) -> tuple[dict[str, object], ...]:
    with repository.engine.connect() as connection:
        rows = connection.execute(
            select(OUTBOX)
            .where(
                OUTBOX.c.aggregate_type == "job",
                OUTBOX.c.aggregate_id == job_id,
                OUTBOX.c.event_type.in_(_EVENT_TYPES),
            )
            .order_by(OUTBOX.c.event_id)
        ).mappings()
        return tuple(dict(row) for row in rows)


def _parse_payload(row: Mapping[str, object]) -> dict[str, object]:
    raw = row.get("payload_json")
    if not isinstance(raw, str):
        raise Loop9FaultInjectionError("fault event payload is unavailable")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Loop9FaultInjectionError(
            "fault event payload is invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise Loop9FaultInjectionError("fault event payload is invalid")
    return cast(dict[str, object], payload)


def _validate_partial_chain(
    rows: tuple[dict[str, object], ...],
    *,
    scenario: str,
    run_id: str,
    build_sha256: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if len(rows) != 2 or tuple(row["event_type"] for row in rows) != (
        _EVENT_TYPES[0],
        _EVENT_TYPES[1],
    ):
        raise Loop9FaultInjectionError(
            "interrupted fault event chain is not safely resumable"
        )
    previous_sha256: str | None = None
    payloads: list[dict[str, object]] = []
    expected_specific = (
        {
            "checkpoint_id",
            "failed_stage_attempt_id",
            "source_instance_id",
        },
        {
            "checkpoint_id",
            "failed_stage_attempt_id",
            "failure_classification",
        },
    )
    common = {
        "event_sha256",
        "injector_build_sha256",
        "injector_contract_sha256",
        "previous_event_sha256",
        "run_id",
        "scenario",
        "schema_version",
    }
    for row, specific in zip(rows, expected_specific, strict=True):
        payload = _parse_payload(row)
        if (
            set(payload) != common | specific
            or payload.get("schema_version") != _SCHEMA_VERSION
            or payload.get("scenario") != scenario
            or payload.get("run_id") != run_id
            or payload.get("injector_build_sha256") != build_sha256
            or payload.get("injector_contract_sha256")
            != fault_injector_contract_sha256()
            or payload.get("previous_event_sha256") != previous_sha256
        ):
            raise Loop9FaultInjectionError(
                "interrupted fault event chain changed"
            )
        expected_sha256 = _canonical_sha256(
            _event_core(
                event_type=str(row["event_type"]),
                aggregate_id=str(row["aggregate_id"]),
                record_version=int(str(row["record_version"])),
                created_at=str(row["created_at"]),
                payload=payload,
            )
        )
        if payload.get("event_sha256") != expected_sha256:
            raise Loop9FaultInjectionError(
                "interrupted fault event integrity failed"
            )
        previous_sha256 = expected_sha256
        payloads.append(payload)
    injected, observed = payloads
    if (
        injected["checkpoint_id"] != observed["checkpoint_id"]
        or injected["failed_stage_attempt_id"]
        != observed["failed_stage_attempt_id"]
        or observed["failure_classification"]
        != _CLASSIFICATIONS[scenario]
    ):
        raise Loop9FaultInjectionError(
            "interrupted fault event identities changed"
        )
    return injected, observed


class Loop9FaultInjectionRunner:
    """Exercise four fixed faults through the real offline scheduler tables."""

    def __init__(
        self,
        *,
        project_root: Path,
        data_root: Path,
        failure_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._project_root = _validate_root(
            project_root,
            label="project root",
        )
        self._data_root = _validate_root(
            data_root,
            label="data root",
        )
        self._failure_hook = failure_hook

    def run(self) -> Loop9FaultInjectionResult:
        guard = SingleInstanceGuard(
            self._data_root,
            8877,
            __version__,
        )
        try:
            guard.acquire()
        except AlreadyRunningError as exc:
            raise Loop9FaultInjectionError(
                "the DaHe application is running for this data root"
            ) from exc
        except InstanceLockError as exc:
            raise Loop9FaultInjectionError(
                "the formal data-root instance guard is unavailable"
            ) from exc
        try:
            build_sha256 = current_loop9_build_sha256(
                self._project_root
            )
            _verify_formal_loop9_authority(
                project_root=self._project_root,
                data_root=self._data_root,
                build_sha256=build_sha256,
            )
            scenarios = {
                scenario: self._run_scenario(
                    scenario,
                    build_sha256=build_sha256,
                )
                for scenario in FAULT_SCENARIOS
            }
            if (
                current_loop9_build_sha256(self._project_root)
                != build_sha256
            ):
                raise Loop9FaultInjectionError(
                    "Loop 9 source build changed during fault injection"
                )
            body = {
                "injector_contract_sha256": (
                    fault_injector_contract_sha256()
                ),
                "scenarios": {
                    scenario: {
                        "job_id": identity.job_id,
                        "run_id": identity.run_id,
                    }
                    for scenario, identity in sorted(scenarios.items())
                },
                "source_build_sha256": build_sha256,
            }
            return Loop9FaultInjectionResult(
                source_build_sha256=build_sha256,
                injector_contract_sha256=(
                    fault_injector_contract_sha256()
                ),
                scenarios=scenarios,
                result_sha256=_canonical_sha256(body),
            )
        finally:
            guard.release()

    def _run_scenario(
        self,
        scenario: str,
        *,
        build_sha256: str,
    ) -> FaultScenarioRunIdentity:
        if scenario not in FAULT_SCENARIOS:
            raise Loop9FaultInjectionError(
                "fault scenario is not protected"
            )
        fixture = _scenario_fixture(
            scenario,
            build_sha256=build_sha256,
        )
        bootstrap = TemporarySqliteJobRepository(
            self._data_root,
            project_root=self._project_root,
        )
        try:
            job, _ = bootstrap.create_scheduled_job(
                fixture=fixture,
                scope_label=fixture.scope_label,
                idempotency_key=(
                    f"loop9-fault:{scenario}:{build_sha256}"
                ),
                request_hash=_canonical_sha256(
                    {
                        "build_sha256": build_sha256,
                        "fixture_id": fixture.fixture_id,
                        "scenario": scenario,
                    }
                ),
                expected_record_version=0,
            )
            identity = FaultScenarioRunIdentity(
                run_id=_run_id(
                    scenario=scenario,
                    job_id=job.job_id,
                    build_sha256=build_sha256,
                ),
                job_id=job.job_id,
            )
            event_rows = _job_event_rows(
                bootstrap,
                job_id=job.job_id,
            )
        finally:
            bootstrap.close()

        if len(event_rows) == 3:
            self._replay(
                scenario=scenario,
                identity=identity,
                build_sha256=build_sha256,
            )
            self._stop_completed_recovery_instance(
                event_rows=event_rows,
            )
            self._replay(
                scenario=scenario,
                identity=identity,
                build_sha256=build_sha256,
            )
            return identity
        if event_rows and len(event_rows) != 2:
            raise Loop9FaultInjectionError(
                "fault scenario has an incomplete event chain"
            )

        if not event_rows:
            injected = self._inject_failure(
                scenario=scenario,
                identity=identity,
                build_sha256=build_sha256,
            )
            if self._failure_hook is not None:
                self._failure_hook(scenario)
        else:
            injected, _ = _validate_partial_chain(
                event_rows,
                scenario=scenario,
                run_id=identity.run_id,
                build_sha256=build_sha256,
            )
            self._stop_source_instance_if_running(injected=injected)

        self._recover(
            scenario=scenario,
            identity=identity,
            build_sha256=build_sha256,
            injected=injected,
        )
        self._replay(
            scenario=scenario,
            identity=identity,
            build_sha256=build_sha256,
        )
        return identity

    def _register_instance(
        self,
        repository: TemporarySqliteJobRepository,
        *,
        instance_id: str,
        build_sha256: str,
    ) -> PersistentRecoveryStore:
        store = PersistentRecoveryStore(
            repository.engine,
            repository.commit_gate,
        )
        process = current_process_identity()
        store.register_instance(
            instance_id=instance_id,
            data_root_identity=data_root_identity(self._data_root),
            pid=process.pid,
            process_started_at=process.process_started_at,
            application_version=f"loop9-fi-{build_sha256[:16]}",
            port=1,
            now=datetime.now(UTC),
        )
        return store

    def _inject_failure(
        self,
        *,
        scenario: str,
        identity: FaultScenarioRunIdentity,
        build_sha256: str,
    ) -> dict[str, object]:
        probe = TemporarySqliteJobRepository(
            self._data_root,
            project_root=self._project_root,
        )
        try:
            source_instance_id = self._prepare_instance_id(
                probe,
                scenario=scenario,
                job_id=identity.job_id,
                base_role="source",
            )
        finally:
            probe.close()
        repository = TemporarySqliteJobRepository(
            self._data_root,
            project_root=self._project_root,
            scheduler_instance_id=source_instance_id,
        )
        recovery_store = self._register_instance(
            repository,
            instance_id=source_instance_id,
            build_sha256=build_sha256,
        )
        try:
            recovery_store.mark_other_instances_crashed(
                replacement_instance_id=source_instance_id,
                data_root_identity=data_root_identity(self._data_root),
                single_instance_proof=True,
                now=datetime.now(UTC),
            )
            repository.recover_abandoned_attempts(
                recovering_instance_id=source_instance_id
            )
            attempt = self._drive_to_target_attempt(
                repository,
                scenario=scenario,
                job_id=identity.job_id,
            )
            injected = self._commit_failure(
                repository,
                scenario=scenario,
                identity=identity,
                build_sha256=build_sha256,
                attempt=attempt,
                source_instance_id=source_instance_id,
            )
            recovery_store.stop_instance(
                instance_id=source_instance_id,
                now=datetime.now(UTC),
            )
            return injected
        finally:
            repository.close()

    @staticmethod
    def _drive_to_target_attempt(
        repository: TemporarySqliteJobRepository,
        *,
        scenario: str,
        job_id: str,
    ) -> dict[str, object]:
        expected_stage = (
            "audit.recognize"
            if scenario == "gpu_worker_failure"
            else "loading_probe.query"
        )
        scheduler = CooperativeScheduler(repository)
        for _ in range(20):
            scheduler.tick()
            with repository.engine.connect() as connection:
                row = (
                    connection.execute(
                        select(STAGE_ATTEMPTS).where(
                            STAGE_ATTEMPTS.c.consumer_job_id
                            == job_id,
                            STAGE_ATTEMPTS.c.stage == expected_stage,
                            STAGE_ATTEMPTS.c.status == "running",
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is not None:
                    return dict(row)
        raise Loop9FaultInjectionError(
            f"{scenario} did not reach its protected atomic stage"
        )

    @staticmethod
    def _commit_failure(
        repository: TemporarySqliteJobRepository,
        *,
        scenario: str,
        identity: FaultScenarioRunIdentity,
        build_sha256: str,
        attempt: Mapping[str, object],
        source_instance_id: str,
    ) -> dict[str, object]:
        classification = _CLASSIFICATIONS[scenario]
        failed_status = (
            "abandoned"
            if scenario == "main_application_restart"
            else "failed"
        )
        now = datetime.now(UTC).isoformat()
        with repository.commit_gate.transaction(
            repository.engine
        ) as connection:
            from dahe.adapters.sqlite.loop3_support import next_sequence

            sequence = next_sequence(connection)
            attempt_id = str(attempt["stage_attempt_id"])
            current_attempt = (
                connection.execute(
                    select(STAGE_ATTEMPTS).where(
                        STAGE_ATTEMPTS.c.stage_attempt_id == attempt_id,
                        STAGE_ATTEMPTS.c.status == "running",
                    )
                )
                .mappings()
                .one_or_none()
            )
            lease = (
                connection.execute(
                    select(LEASES).where(
                        LEASES.c.stage_attempt_id == attempt_id,
                        LEASES.c.instance_id == source_instance_id,
                        LEASES.c.status == "active",
                    )
                )
                .mappings()
                .one_or_none()
            )
            if current_attempt is None or lease is None:
                raise Loop9FaultInjectionError(
                    "fault target changed before injection"
                )
            checkpoint_id = uuid4().hex
            connection.execute(
                CHECKPOINTS.insert().values(
                    checkpoint_id=checkpoint_id,
                    owner_kind=str(current_attempt["owner_kind"]),
                    owner_id=str(current_attempt["owner_id"]),
                    job_id=identity.job_id,
                    work_item_id=str(current_attempt["work_item_id"]),
                    stage=str(current_attempt["stage"]),
                    sequence=sequence,
                    payload_json=_canonical_bytes(
                        {
                            "committed": True,
                            "fault_classification": classification,
                            "resume_stage": str(
                                current_attempt["stage"]
                            ),
                        }
                    ).decode("utf-8"),
                )
            )
            updated_attempt = connection.execute(
                update(STAGE_ATTEMPTS)
                .where(
                    STAGE_ATTEMPTS.c.stage_attempt_id == attempt_id,
                    STAGE_ATTEMPTS.c.status == "running",
                )
                .values(
                    status=failed_status,
                    finished_sequence=sequence,
                    diagnostic_code=(
                        f"L9-FI-{scenario.replace('_', '-').upper()}"
                    ),
                    runtime_kind=(
                        "gpu"
                        if scenario == "gpu_worker_failure"
                        else current_attempt["runtime_kind"]
                    ),
                    discarded=1,
                    error_kind=classification,
                )
            )
            updated_lease = connection.execute(
                update(LEASES)
                .where(
                    LEASES.c.lease_id == lease["lease_id"],
                    LEASES.c.status == "active",
                )
                .values(
                    status="released",
                    released_sequence=sequence,
                    released_at=now,
                    release_reason=classification,
                )
            )
            if updated_attempt.rowcount != 1 or updated_lease.rowcount != 1:
                raise Loop9FaultInjectionError(
                    "fault transition lost its fenced ownership"
                )
            item = (
                connection.execute(
                    select(WORK_ITEMS).where(
                        WORK_ITEMS.c.work_item_id
                        == current_attempt["work_item_id"]
                    )
                )
                .mappings()
                .one()
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == item["work_item_id"],
                    WORK_ITEMS.c.record_version == item["record_version"],
                )
                .values(
                    status="queued",
                    current_stage=str(current_attempt["stage"]),
                    ready_sequence=sequence,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    review_reason=None,
                    diagnostic_code=None,
                    record_version=int(item["record_version"]) + 1,
                )
            )
            if current_attempt["owner_kind"] == "shared_evidence":
                shared = (
                    connection.execute(
                        select(SHARED_EVIDENCE_WORK).where(
                            SHARED_EVIDENCE_WORK.c.shared_work_id
                            == current_attempt["owner_id"]
                        )
                    )
                    .mappings()
                    .one()
                )
                connection.execute(
                    update(SHARED_EVIDENCE_WORK)
                    .where(
                        SHARED_EVIDENCE_WORK.c.shared_work_id
                        == shared["shared_work_id"]
                    )
                    .values(
                        status="queued",
                        artifact_ref=None,
                        diagnostic_code=None,
                        record_version=int(shared["record_version"]) + 1,
                    )
                )
            job_version = int(
                connection.execute(
                    select(JOBS.c.record_version).where(
                        JOBS.c.job_id == identity.job_id
                    )
                ).scalar_one()
            )
            common: dict[str, object] = {
                "injector_build_sha256": build_sha256,
                "injector_contract_sha256": (
                    fault_injector_contract_sha256()
                ),
                "previous_event_sha256": None,
                "run_id": identity.run_id,
                "scenario": scenario,
                "schema_version": _SCHEMA_VERSION,
            }
            injected_payload = {
                **common,
                "checkpoint_id": checkpoint_id,
                "failed_stage_attempt_id": attempt_id,
                "source_instance_id": source_instance_id,
            }
            injected_sha256 = _append_protected_event(
                connection,
                event_type=_EVENT_TYPES[0],
                job_id=identity.job_id,
                record_version=job_version,
                created_at=now,
                payload=injected_payload,
            )
            observed_payload = {
                **common,
                "checkpoint_id": checkpoint_id,
                "failed_stage_attempt_id": attempt_id,
                "failure_classification": classification,
                "previous_event_sha256": injected_sha256,
            }
            _append_protected_event(
                connection,
                event_type=_EVENT_TYPES[1],
                job_id=identity.job_id,
                record_version=job_version,
                created_at=now,
                payload=observed_payload,
            )
            return injected_payload

    def _recover(
        self,
        *,
        scenario: str,
        identity: FaultScenarioRunIdentity,
        build_sha256: str,
        injected: Mapping[str, object],
    ) -> None:
        probe = TemporarySqliteJobRepository(
            self._data_root,
            project_root=self._project_root,
        )
        try:
            existing = self._existing_recovery_attempt(
                probe,
                failed_stage_attempt_id=str(
                    injected["failed_stage_attempt_id"]
                ),
            )
            if existing is not None:
                recovery_attempt, recovery_instance_id = existing
                self._complete_protected_business_result(
                    probe,
                    job_id=identity.job_id,
                )
                self._append_recovery_event(
                    probe,
                    scenario=scenario,
                    identity=identity,
                    build_sha256=build_sha256,
                    injected=injected,
                    recovery_attempt=recovery_attempt,
                    recovery_instance_id=recovery_instance_id,
                )
                self._stop_instance_if_running(
                    probe,
                    instance_id=recovery_instance_id,
                )
                return
            recovery_instance_id = self._prepare_instance_id(
                probe,
                scenario=scenario,
                job_id=identity.job_id,
                base_role="recovery",
            )
        finally:
            probe.close()

        repository = TemporarySqliteJobRepository(
            self._data_root,
            project_root=self._project_root,
            scheduler_instance_id=recovery_instance_id,
        )
        store = self._register_instance(
            repository,
            instance_id=recovery_instance_id,
            build_sha256=build_sha256,
        )
        try:
            scheduler = CooperativeScheduler(repository)
            scheduler.run_until_quiescent(max_ticks=100)
            recovery_attempt = self._recovery_attempt(
                repository,
                failed_stage_attempt_id=str(
                    injected["failed_stage_attempt_id"]
                ),
            )
            self._complete_protected_business_result(
                repository,
                job_id=identity.job_id,
            )
            self._append_recovery_event(
                repository,
                scenario=scenario,
                identity=identity,
                build_sha256=build_sha256,
                injected=injected,
                recovery_attempt=recovery_attempt,
                recovery_instance_id=recovery_instance_id,
            )
            store.stop_instance(
                instance_id=recovery_instance_id,
                now=datetime.now(UTC),
            )
        finally:
            repository.close()

    @staticmethod
    def _complete_protected_business_result(
        repository: TemporarySqliteJobRepository,
        *,
        job_id: str,
    ) -> None:
        with repository.commit_gate.transaction(
            repository.engine
        ) as connection:
            items = tuple(
                connection.execute(
                    select(WORK_ITEMS).where(
                        WORK_ITEMS.c.job_id == job_id
                    )
                ).mappings()
            )
            if not items:
                raise Loop9FaultInjectionError(
                    "protected fault job has no recovered work item"
                )
            for item in items:
                current = (
                    item["business_outcome"],
                    item["decision"],
                    item["review_reason"],
                    item["diagnostic_code"],
                )
                expected = (
                    "normal_ready",
                    "pass",
                    None,
                    None,
                )
                if current == expected:
                    continue
                if (
                    item["status"] != "succeeded"
                    or item["diagnostic_code"] is not None
                    or item["business_outcome"] is not None
                    or item["review_reason"] is not None
                    or item["decision"] not in {None, "pass"}
                ):
                    raise Loop9FaultInjectionError(
                        "protected fault recovery has an invalid "
                        "business-result shape"
                    )
                updated = connection.execute(
                    update(WORK_ITEMS)
                    .where(
                        WORK_ITEMS.c.work_item_id
                        == item["work_item_id"],
                        WORK_ITEMS.c.record_version
                        == item["record_version"],
                    )
                    .values(
                        business_outcome="normal_ready",
                        decision="pass",
                        record_version=int(item["record_version"]) + 1,
                    )
                )
                if updated.rowcount != 1:
                    raise Loop9FaultInjectionError(
                        "protected fault business result changed "
                        "concurrently"
                    )

    @staticmethod
    def _existing_recovery_attempt(
        repository: TemporarySqliteJobRepository,
        *,
        failed_stage_attempt_id: str,
    ) -> tuple[dict[str, object], str] | None:
        with repository.engine.connect() as connection:
            failed = (
                connection.execute(
                    select(STAGE_ATTEMPTS).where(
                        STAGE_ATTEMPTS.c.stage_attempt_id
                        == failed_stage_attempt_id
                    )
                )
                .mappings()
                .one()
            )
            rows = tuple(
                connection.execute(
                    select(STAGE_ATTEMPTS, LEASES.c.instance_id)
                    .join(
                        LEASES,
                        LEASES.c.stage_attempt_id
                        == STAGE_ATTEMPTS.c.stage_attempt_id,
                    )
                    .where(
                        STAGE_ATTEMPTS.c.owner_kind
                        == failed["owner_kind"],
                        STAGE_ATTEMPTS.c.owner_id == failed["owner_id"],
                        STAGE_ATTEMPTS.c.stage == failed["stage"],
                        STAGE_ATTEMPTS.c.status == "succeeded",
                        STAGE_ATTEMPTS.c.attempt_number
                        > failed["attempt_number"],
                    )
                ).mappings()
            )
        if not rows:
            return None
        if len(rows) != 1 or rows[0]["instance_id"] is None:
            raise Loop9FaultInjectionError(
                "fault recovery has ambiguous persisted ownership"
            )
        return dict(rows[0]), str(rows[0]["instance_id"])

    def _prepare_instance_id(
        self,
        repository: TemporarySqliteJobRepository,
        *,
        scenario: str,
        job_id: str,
        base_role: str,
    ) -> str:
        for generation in range(1, 10):
            role = (
                base_role
                if generation == 1
                else f"{base_role}-{generation}"
            )
            candidate = _instance_id(
                scenario=scenario,
                job_id=job_id,
                role=role,
            )
            with repository.engine.connect() as connection:
                row = (
                    connection.execute(
                        text(
                            """
                            SELECT status
                            FROM application_instances
                            WHERE instance_id = :instance_id
                            """
                        ),
                        {"instance_id": candidate},
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None:
                return candidate
            if row["status"] == "running":
                repository.abandon_instance_attempts(
                    instance_id=candidate
                )
                self._stop_instance_if_running(
                    repository,
                    instance_id=candidate,
                )
        raise Loop9FaultInjectionError(
            "fault injection exhausted protected instance generations"
        )

    @staticmethod
    def _stop_instance_if_running(
        repository: TemporarySqliteJobRepository,
        *,
        instance_id: str,
    ) -> None:
        with repository.engine.connect() as connection:
            status = connection.execute(
                text(
                    """
                    SELECT status
                    FROM application_instances
                    WHERE instance_id = :instance_id
                    """
                ),
                {"instance_id": instance_id},
            ).scalar_one_or_none()
        if status != "running":
            return
        PersistentRecoveryStore(
            repository.engine,
            repository.commit_gate,
        ).stop_instance(
            instance_id=instance_id,
            now=datetime.now(UTC),
        )

    def _stop_completed_recovery_instance(
        self,
        *,
        event_rows: tuple[dict[str, object], ...],
    ) -> None:
        recovered = _parse_payload(event_rows[2])
        instance_id = recovered.get("recovery_instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            raise Loop9FaultInjectionError(
                "completed recovery instance identity is invalid"
            )
        repository = TemporarySqliteJobRepository(
            self._data_root,
            project_root=self._project_root,
        )
        try:
            self._stop_instance_if_running(
                repository,
                instance_id=instance_id,
            )
        finally:
            repository.close()

    def _stop_source_instance_if_running(
        self,
        *,
        injected: Mapping[str, object],
    ) -> None:
        instance_id = injected.get("source_instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            raise Loop9FaultInjectionError(
                "source application instance identity is invalid"
            )
        repository = TemporarySqliteJobRepository(
            self._data_root,
            project_root=self._project_root,
        )
        try:
            self._stop_instance_if_running(
                repository,
                instance_id=instance_id,
            )
        finally:
            repository.close()

    @staticmethod
    def _recovery_attempt(
        repository: TemporarySqliteJobRepository,
        *,
        failed_stage_attempt_id: str,
    ) -> dict[str, object]:
        with repository.engine.connect() as connection:
            failed = (
                connection.execute(
                    select(STAGE_ATTEMPTS).where(
                        STAGE_ATTEMPTS.c.stage_attempt_id
                        == failed_stage_attempt_id
                    )
                )
                .mappings()
                .one()
            )
            rows = tuple(
                connection.execute(
                    select(STAGE_ATTEMPTS).where(
                        STAGE_ATTEMPTS.c.owner_kind
                        == failed["owner_kind"],
                        STAGE_ATTEMPTS.c.owner_id == failed["owner_id"],
                        STAGE_ATTEMPTS.c.stage == failed["stage"],
                        STAGE_ATTEMPTS.c.status == "succeeded",
                        STAGE_ATTEMPTS.c.attempt_number
                        > failed["attempt_number"],
                    )
                ).mappings()
            )
        if len(rows) != 1:
            raise Loop9FaultInjectionError(
                "fault recovery did not produce one successful retry"
            )
        return dict(rows[0])

    @staticmethod
    def _append_recovery_event(
        repository: TemporarySqliteJobRepository,
        *,
        scenario: str,
        identity: FaultScenarioRunIdentity,
        build_sha256: str,
        injected: Mapping[str, object],
        recovery_attempt: Mapping[str, object],
        recovery_instance_id: str,
    ) -> None:
        with repository.commit_gate.transaction(
            repository.engine
        ) as connection:
            existing = connection.execute(
                select(OUTBOX.c.event_id).where(
                    OUTBOX.c.aggregate_id == identity.job_id,
                    OUTBOX.c.event_type == _EVENT_TYPES[2],
                )
            ).first()
            if existing is not None:
                return
            observed = (
                connection.execute(
                    select(OUTBOX).where(
                        OUTBOX.c.aggregate_id == identity.job_id,
                        OUTBOX.c.event_type == _EVENT_TYPES[1],
                    )
                )
                .mappings()
                .one()
            )
            observed_payload = _parse_payload(dict(observed))
            now = datetime.now(UTC).isoformat()
            job_version = int(
                connection.execute(
                    select(JOBS.c.record_version).where(
                        JOBS.c.job_id == identity.job_id
                    )
                ).scalar_one()
            )
            payload = {
                "checkpoint_id": injected["checkpoint_id"],
                "failed_stage_attempt_id": (
                    injected["failed_stage_attempt_id"]
                ),
                "injector_build_sha256": build_sha256,
                "injector_contract_sha256": (
                    fault_injector_contract_sha256()
                ),
                "previous_event_sha256": observed_payload[
                    "event_sha256"
                ],
                "recovery_instance_id": recovery_instance_id,
                "recovery_stage_attempt_id": recovery_attempt[
                    "stage_attempt_id"
                ],
                "run_id": identity.run_id,
                "scenario": scenario,
                "schema_version": _SCHEMA_VERSION,
                "source_instance_id": injected["source_instance_id"],
            }
            _append_protected_event(
                connection,
                event_type=_EVENT_TYPES[2],
                job_id=identity.job_id,
                record_version=job_version,
                created_at=now,
                payload=payload,
            )

    def _replay(
        self,
        *,
        scenario: str,
        identity: FaultScenarioRunIdentity,
        build_sha256: str,
    ) -> None:
        try:
            replay_persisted_fault_scenario(
                data_root=self._data_root,
                scenario=scenario,
                identity=FaultScenarioIdentity(
                    run_id=identity.run_id,
                    job_id=identity.job_id,
                ),
                current_build_sha256=build_sha256,
            )
        except Loop9FormalRunEvidenceError as exc:
            raise Loop9FaultInjectionError(
                f"{scenario} failed protected deep replay"
            ) from exc
