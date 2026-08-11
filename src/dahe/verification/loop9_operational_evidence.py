from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe.domain.audit.decisions import DecisionReason

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FAULT_SCENARIOS = frozenset(
    {
        "browser_closed",
        "gpu_worker_failure",
        "main_application_restart",
        "transient_network_failure",
    }
)
_REQUEST_AUDIT_SCOPES = frozenset(
    {
        "current_locked_50",
        "daily_snapshot_1",
        "daily_snapshot_2",
        "daily_snapshot_3",
        "real_shadow_30",
    }
)
_PERFORMANCE_SCOPES = frozenset(
    {
        "cpu_ocr",
        "end_to_end",
        "gpu_ocr",
        "role_validation",
    }
)
_EXPECTED_PERFORMANCE_SAMPLE_SIZES = {
    "cpu_ocr": 160,
    "end_to_end": 80,
    "gpu_ocr": 160,
    "role_validation": 160,
}
_SCHEDULER_SCOPES = frozenset(
    {
        "current_locked_50",
        "real_shadow_30",
    }
)
_KIND = "loop9_formal_run_evidence"
_SCHEMA_VERSION = 2
_MAX_FILE_BYTES = 2 * 1024 * 1024
_FAULT_EVENT_TYPES = (
    "verification.fault_injection.injected",
    "verification.fault_injection.failure_observed",
    "verification.fault_injection.recovered",
)
_FAULT_CLASSIFICATIONS = {
    "browser_closed": "browser_runtime_closed",
    "gpu_worker_failure": "gpu_worker_failure",
    "main_application_restart": "application_instance_stopped",
    "transient_network_failure": "transient_network_failure",
}
_BUSINESS_REVIEW_REASONS = frozenset(
    reason.value for reason in DecisionReason
)


class Loop9FormalRunEvidenceError(RuntimeError):
    """Raised when actual formal-run records cannot prove Loop 9."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Loop9FormalRunEvidenceError(
            "formal run evidence is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


_FAULT_INJECTOR_CONTRACT_SHA256 = _canonical_sha256(
    {
        "event_types": list(_FAULT_EVENT_TYPES),
        "failure_classifications": _FAULT_CLASSIFICATIONS,
        "kind": "loop9_protected_fault_injector_contract",
        "schema_version": 1,
    }
)


def fault_injector_contract_sha256() -> str:
    """Return the protected fault-event contract identity."""

    return _FAULT_INJECTOR_CONTRACT_SHA256


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9FormalRunEvidenceError(f"{label} SHA-256 is invalid")
    return value


def _required_text(
    value: object,
    *,
    label: str,
    maximum: int = 160,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise Loop9FormalRunEvidenceError(f"{label} is invalid")
    return value


def _required_int(
    value: object,
    *,
    label: str,
    minimum: int = 0,
) -> int:
    if type(value) is not int or value < minimum:
        raise Loop9FormalRunEvidenceError(f"{label} is invalid")
    return value


def _decimal(value: object, *, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise Loop9FormalRunEvidenceError(f"{label} is invalid")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise Loop9FormalRunEvidenceError(f"{label} is invalid") from exc
    if not result.is_finite() or result < 0:
        raise Loop9FormalRunEvidenceError(f"{label} is invalid")
    return result


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == normalized.to_integral():
        return format(normalized, "f")
    return format(normalized, "f").rstrip("0").rstrip(".")


def _nearest_rank(values: Sequence[Decimal], probability: Decimal) -> Decimal:
    if not values:
        raise Loop9FormalRunEvidenceError(
            "performance duration records are unavailable"
        )
    ordered = sorted(values)
    rank = math.ceil(float(Decimal(len(ordered)) * probability))
    return ordered[max(1, rank) - 1]


def _sample_summary(values: Sequence[Decimal]) -> dict[str, object]:
    samples = tuple(values)
    return {
        "p50_ms": _decimal_text(_nearest_rank(samples, Decimal("0.50"))),
        "p95_ms": _decimal_text(_nearest_rank(samples, Decimal("0.95"))),
        "sample_size": len(samples),
        "samples_sha256": _canonical_sha256(
            [_decimal_text(value) for value in samples]
        ),
    }


def recompute_machine_performance(
    machine_results: Sequence[Mapping[str, object]],
    *,
    end_to_end_duration_ms: Sequence[object],
) -> dict[str, dict[str, object]]:
    """Recompute metrics from individual immutable observations.

    Summary values in machine-result or acceptance files are deliberately
    ignored. Role timing must be a distinct raw field; it is never estimated
    by subtracting OCR timings.
    """

    cpu: list[Decimal] = []
    gpu: list[Decimal] = []
    roles: list[Decimal] = []
    for machine_index, machine in enumerate(machine_results):
        raw_results = machine.get("results")
        if not isinstance(raw_results, list):
            raise Loop9FormalRunEvidenceError(
                "machine result has no raw item observations"
            )
        for item_index, item in enumerate(raw_results):
            if not isinstance(item, Mapping):
                raise Loop9FormalRunEvidenceError(
                    "machine result item observation is invalid"
                )
            raw_images = item.get("image_evaluations")
            if not isinstance(raw_images, list):
                raise Loop9FormalRunEvidenceError(
                    "machine result has no raw image observations"
                )
            for image_index, image in enumerate(raw_images):
                if not isinstance(image, Mapping):
                    raise Loop9FormalRunEvidenceError(
                        "machine result image observation is invalid"
                    )
                comparison = image.get("runtime_comparison")
                if not isinstance(comparison, Mapping):
                    raise Loop9FormalRunEvidenceError(
                        "machine result runtime comparison is unavailable"
                    )
                selected_runtime = comparison.get("selected_runtime_kind")
                if selected_runtime not in {"cpu", "gpu"}:
                    raise Loop9FormalRunEvidenceError(
                        "machine result selected runtime is invalid"
                    )
                observations = image.get("runtime_observations")
                if not isinstance(observations, list):
                    raise Loop9FormalRunEvidenceError(
                        "machine result runtime observations are unavailable"
                    )
                selected_role: Decimal | None = None
                observed_runtime_kinds: set[str] = set()
                for observation_index, observation in enumerate(observations):
                    if not isinstance(observation, Mapping):
                        raise Loop9FormalRunEvidenceError(
                            "machine runtime observation is invalid"
                        )
                    runtime_kind = observation.get("runtime_kind")
                    if (
                        runtime_kind not in {"cpu", "gpu"}
                        or runtime_kind in observed_runtime_kinds
                    ):
                        raise Loop9FormalRunEvidenceError(
                            "machine runtime observation identity is invalid"
                        )
                    observed_runtime_kinds.add(cast(str, runtime_kind))
                    timing = observation.get("timing")
                    if not isinstance(timing, Mapping):
                        raise Loop9FormalRunEvidenceError(
                            "machine runtime timing is unavailable"
                        )
                    wall = _decimal(
                        timing.get("wall_elapsed_ms"),
                        label=(
                            "machine runtime "
                            f"{machine_index}:{item_index}:{image_index}:"
                            f"{observation_index} wall elapsed time"
                        ),
                    )
                    if runtime_kind == "cpu":
                        cpu.append(wall)
                    else:
                        gpu.append(wall)
                    role = observation.get("role")
                    if not isinstance(role, Mapping) or "elapsed_ms" not in role:
                        raise Loop9FormalRunEvidenceError(
                            "machine result is missing role.elapsed_ms "
                            "duration records"
                        )
                    role_elapsed = _decimal(
                        role.get("elapsed_ms"),
                        label="role validation elapsed time",
                    )
                    if runtime_kind == selected_runtime:
                        selected_role = role_elapsed
                if observed_runtime_kinds != {"cpu", "gpu"}:
                    raise Loop9FormalRunEvidenceError(
                        "machine result lacks complete CPU/GPU observations"
                    )
                if selected_role is None:
                    raise Loop9FormalRunEvidenceError(
                        "selected role duration record is unavailable"
                    )
                roles.append(selected_role)
    end_to_end = [
        _decimal(value, label="end-to-end elapsed time")
        for value in end_to_end_duration_ms
    ]
    return {
        "cpu_ocr": _sample_summary(cpu),
        "end_to_end": _sample_summary(end_to_end),
        "gpu_ocr": _sample_summary(gpu),
        "role_validation": _sample_summary(roles),
    }


@dataclass(frozen=True, slots=True)
class FaultScenarioIdentity:
    run_id: str
    job_id: str

    def __post_init__(self) -> None:
        _required_text(self.run_id, label="fault run identity")
        _required_text(self.job_id, label="fault job identity")


@dataclass(frozen=True, slots=True)
class Loop9FormalRunRequest:
    locked_job_id: str
    real_shadow_selection_sha256: str
    real_shadow_job_id: str
    real_shadow_machine_evaluation_sha256: str
    daily_snapshot_validation_sha256: str
    dataset_isolation_sha256: str
    fault_scenarios: Mapping[str, FaultScenarioIdentity]

    def __post_init__(self) -> None:
        _required_text(self.locked_job_id, label="locked job identity")
        _required_text(
            self.real_shadow_job_id,
            label="real shadow job identity",
        )
        for value, label in (
            (
                self.real_shadow_selection_sha256,
                "real shadow selection",
            ),
            (
                self.real_shadow_machine_evaluation_sha256,
                "real shadow machine evaluation",
            ),
            (
                self.daily_snapshot_validation_sha256,
                "daily snapshot validation",
            ),
            (self.dataset_isolation_sha256, "dataset isolation"),
        ):
            _required_sha256(value, label=label)
        if (
            not isinstance(self.fault_scenarios, Mapping)
            or set(self.fault_scenarios) != _FAULT_SCENARIOS
            or any(
                not isinstance(value, FaultScenarioIdentity)
                for value in self.fault_scenarios.values()
            )
        ):
            raise Loop9FormalRunEvidenceError(
                "exactly four named fault scenario identities are required"
            )
        if (
            len(
                {
                    identity.run_id
                    for identity in self.fault_scenarios.values()
                }
            )
            != len(_FAULT_SCENARIOS)
            or len(
                {
                    identity.job_id
                    for identity in self.fault_scenarios.values()
                }
            )
            != len(_FAULT_SCENARIOS)
        ):
            raise Loop9FormalRunEvidenceError(
                "fault scenario run and job identities must be unique"
            )
        object.__setattr__(
            self,
            "fault_scenarios",
            dict(self.fault_scenarios),
        )


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_database(data_root: Path) -> Path:
    try:
        database = (data_root / "database" / "dahe.sqlite3").resolve(
            strict=True
        )
        database.relative_to(data_root)
    except (OSError, ValueError) as exc:
        raise Loop9FormalRunEvidenceError(
            "formal scheduler database is unavailable"
        ) from exc
    if (
        not database.is_file()
        or database.is_symlink()
        or _is_reparse_point(database)
    ):
        raise Loop9FormalRunEvidenceError(
            "formal scheduler database is unsafe"
        )
    return database


def _read_only_database(data_root: Path) -> sqlite3.Connection:
    database = _safe_database(data_root)
    try:
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.Error as exc:
        raise Loop9FormalRunEvidenceError(
            "formal scheduler database could not be opened read-only"
        ) from exc


def _database_tables(connection: sqlite3.Connection) -> set[str]:
    try:
        return {
            cast(str, row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    except sqlite3.Error as exc:
        raise Loop9FormalRunEvidenceError(
            "formal scheduler schema is unreadable"
        ) from exc


def _json_object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, str):
        raise Loop9FormalRunEvidenceError(f"{label} is invalid")
    try:
        raw = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda nested: (_ for _ in ()).throw(
                Loop9FormalRunEvidenceError(
                    f"non-finite JSON value {nested} is forbidden"
                )
            ),
        )
    except json.JSONDecodeError as exc:
        raise Loop9FormalRunEvidenceError(f"{label} is invalid") from exc
    if not isinstance(raw, dict):
        raise Loop9FormalRunEvidenceError(f"{label} is invalid")
    return raw


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


def _load_fault_event_chain(
    connection: sqlite3.Connection,
    *,
    scenario: str,
    identity: FaultScenarioIdentity,
    current_build_sha256: str,
) -> tuple[tuple[sqlite3.Row, dict[str, object]], ...]:
    placeholders = ",".join("?" for _ in _FAULT_EVENT_TYPES)
    try:
        rows = connection.execute(
            f"""
            SELECT event_id, event_type, aggregate_type, aggregate_id,
                   record_version, payload_json, created_at
            FROM event_outbox
            WHERE aggregate_type = 'job'
              AND aggregate_id = ?
              AND event_type IN ({placeholders})
            ORDER BY event_id
            """,
            (identity.job_id, *_FAULT_EVENT_TYPES),
        ).fetchall()
    except sqlite3.Error as exc:
        raise Loop9FormalRunEvidenceError(
            "fault injection outbox evidence is unavailable"
        ) from exc
    matches: list[tuple[sqlite3.Row, dict[str, object]]] = []
    previous_sha256: str | None = None
    for row in rows:
        payload = _json_object(
            row["payload_json"],
            label="fault injection event payload",
        )
        if payload.get("run_id") != identity.run_id:
            continue
        expected_common = {
            "event_sha256",
            "injector_build_sha256",
            "injector_contract_sha256",
            "previous_event_sha256",
            "run_id",
            "scenario",
            "schema_version",
        }
        event_type = cast(str, row["event_type"])
        event_specific = {
            "verification.fault_injection.injected": {
                "checkpoint_id",
                "failed_stage_attempt_id",
                "source_instance_id",
            },
            "verification.fault_injection.failure_observed": {
                "checkpoint_id",
                "failed_stage_attempt_id",
                "failure_classification",
            },
            "verification.fault_injection.recovered": {
                "checkpoint_id",
                "failed_stage_attempt_id",
                "recovery_instance_id",
                "recovery_stage_attempt_id",
                "source_instance_id",
            },
        }[event_type]
        if (
            set(payload) != expected_common | event_specific
            or payload.get("schema_version") != 1
            or payload.get("scenario") != scenario
            or payload.get("injector_build_sha256")
            != current_build_sha256
            or payload.get("injector_contract_sha256")
            != _FAULT_INJECTOR_CONTRACT_SHA256
            or payload.get("previous_event_sha256") != previous_sha256
        ):
            raise Loop9FormalRunEvidenceError(
                f"{scenario} fault event is not from the protected injector"
            )
        declared = _required_sha256(
            payload.get("event_sha256"),
            label=f"{scenario} fault event",
        )
        expected = _canonical_sha256(
            _event_core(
                event_type=event_type,
                aggregate_id=cast(str, row["aggregate_id"]),
                record_version=cast(int, row["record_version"]),
                created_at=cast(str, row["created_at"]),
                payload=payload,
            )
        )
        if declared != expected:
            raise Loop9FormalRunEvidenceError(
                f"{scenario} fault event integrity failed"
            )
        previous_sha256 = declared
        matches.append((row, payload))
    if (
        len(matches) != 3
        or tuple(row["event_type"] for row, _ in matches)
        != _FAULT_EVENT_TYPES
    ):
        raise Loop9FormalRunEvidenceError(
            f"{scenario} is missing the protected "
            "injection -> failure -> recovery event chain"
        )
    return tuple(matches)


def _one_row(
    connection: sqlite3.Connection,
    statement: str,
    parameters: tuple[object, ...],
    *,
    label: str,
) -> sqlite3.Row:
    try:
        rows = connection.execute(statement, parameters).fetchall()
    except sqlite3.Error as exc:
        raise Loop9FormalRunEvidenceError(f"{label} is unavailable") from exc
    if len(rows) != 1:
        raise Loop9FormalRunEvidenceError(f"{label} is unavailable")
    return cast(sqlite3.Row, rows[0])


def _fault_projection(
    connection: sqlite3.Connection,
    *,
    scenario: str,
    identity: FaultScenarioIdentity,
    current_build_sha256: str,
) -> dict[str, object]:
    events = _load_fault_event_chain(
        connection,
        scenario=scenario,
        identity=identity,
        current_build_sha256=current_build_sha256,
    )
    injected = events[0][1]
    failed_event = events[1][1]
    recovered = events[2][1]
    failed_id = _required_text(
        injected.get("failed_stage_attempt_id"),
        label=f"{scenario} failed stage attempt",
    )
    checkpoint_id = _required_text(
        injected.get("checkpoint_id"),
        label=f"{scenario} checkpoint",
    )
    source_instance_id = _required_text(
        injected.get("source_instance_id"),
        label=f"{scenario} source instance",
    )
    recovery_attempt_id = _required_text(
        recovered.get("recovery_stage_attempt_id"),
        label=f"{scenario} recovery stage attempt",
    )
    recovery_instance_id = _required_text(
        recovered.get("recovery_instance_id"),
        label=f"{scenario} recovery instance",
    )
    expected_classification = _FAULT_CLASSIFICATIONS[scenario]
    expected_task_type = (
        "audit" if scenario == "gpu_worker_failure" else "loading_probe"
    )
    expected_stage = (
        "audit.recognize"
        if scenario == "gpu_worker_failure"
        else "loading_probe.query"
    )
    if (
        failed_event.get("failed_stage_attempt_id") != failed_id
        or recovered.get("failed_stage_attempt_id") != failed_id
        or failed_event.get("checkpoint_id") != checkpoint_id
        or recovered.get("checkpoint_id") != checkpoint_id
        or recovered.get("source_instance_id") != source_instance_id
        or failed_event.get("failure_classification")
        != expected_classification
    ):
        raise Loop9FormalRunEvidenceError(
            f"{scenario} fault event identities changed"
        )
    failed_attempt = _one_row(
        connection,
        """
        SELECT stage_attempt_id, consumer_job_id, work_item_id, stage,
               status, attempt_number, started_sequence, finished_sequence,
               diagnostic_code, runtime_kind, error_kind
        FROM stage_attempts
        WHERE stage_attempt_id = ?
        """,
        (failed_id,),
        label=f"{scenario} failed stage attempt",
    )
    recovery_attempt = _one_row(
        connection,
        """
        SELECT stage_attempt_id, consumer_job_id, work_item_id, stage,
               status, attempt_number, started_sequence, finished_sequence,
               diagnostic_code, runtime_kind, error_kind
        FROM stage_attempts
        WHERE stage_attempt_id = ?
        """,
        (recovery_attempt_id,),
        label=f"{scenario} recovery stage attempt",
    )
    expected_failed_status = (
        "abandoned"
        if scenario == "main_application_restart"
        else "failed"
    )
    if (
        failed_attempt["consumer_job_id"] != identity.job_id
        or recovery_attempt["consumer_job_id"] != identity.job_id
        or failed_attempt["work_item_id"]
        != recovery_attempt["work_item_id"]
        or failed_attempt["stage"] != recovery_attempt["stage"]
        or failed_attempt["status"] != expected_failed_status
        or failed_attempt["error_kind"] != expected_classification
        or not failed_attempt["diagnostic_code"]
        or failed_attempt["finished_sequence"] is None
        or recovery_attempt["status"] != "succeeded"
        or recovery_attempt["diagnostic_code"] is not None
        or recovery_attempt["error_kind"] is not None
        or recovery_attempt["finished_sequence"] is None
        or recovery_attempt["attempt_number"]
        <= failed_attempt["attempt_number"]
        or recovery_attempt["started_sequence"]
        <= failed_attempt["started_sequence"]
        or (
            scenario == "gpu_worker_failure"
            and failed_attempt["runtime_kind"] != "gpu"
        )
    ):
        raise Loop9FormalRunEvidenceError(
            f"{scenario} stage-attempt recovery is invalid"
        )
    checkpoint = _one_row(
        connection,
        """
        SELECT checkpoint_id, job_id, work_item_id, stage, sequence,
               payload_json
        FROM checkpoints
        WHERE checkpoint_id = ?
        """,
        (checkpoint_id,),
        label=f"{scenario} checkpoint",
    )
    checkpoint_payload = _json_object(
        checkpoint["payload_json"],
        label=f"{scenario} checkpoint payload",
    )
    if (
        checkpoint["job_id"] != identity.job_id
        or checkpoint["work_item_id"] != failed_attempt["work_item_id"]
        or failed_attempt["stage"] != expected_stage
        or recovery_attempt["stage"] != expected_stage
        or checkpoint["stage"] != expected_stage
        or checkpoint["sequence"] != failed_attempt["finished_sequence"]
        or checkpoint["sequence"] >= recovery_attempt["started_sequence"]
        or checkpoint_payload
        != {
            "committed": True,
            "fault_classification": expected_classification,
            "resume_stage": expected_stage,
        }
    ):
        raise Loop9FormalRunEvidenceError(
            f"{scenario} recovery checkpoint is inconsistent"
        )
    source_lease = _one_row(
        connection,
        """
        SELECT lease_id, instance_id, stage_attempt_id, job_id,
               work_item_id, status, release_reason
        FROM leases
        WHERE stage_attempt_id = ? AND instance_id = ?
        """,
        (failed_id, source_instance_id),
        label=f"{scenario} source lease",
    )
    recovery_lease = _one_row(
        connection,
        """
        SELECT lease_id, instance_id, stage_attempt_id, job_id,
               work_item_id, status, release_reason
        FROM leases
        WHERE stage_attempt_id = ? AND instance_id = ?
        """,
        (recovery_attempt_id, recovery_instance_id),
        label=f"{scenario} recovery lease",
    )
    if (
        source_lease["job_id"] != identity.job_id
        or recovery_lease["job_id"] != identity.job_id
        or source_lease["work_item_id"] != failed_attempt["work_item_id"]
        or recovery_lease["work_item_id"]
        != failed_attempt["work_item_id"]
        or source_lease["status"] != "released"
        or source_lease["release_reason"] != expected_classification
        or recovery_lease["status"] != "released"
        or recovery_lease["release_reason"]
        != "atomic_stage_completed"
    ):
        raise Loop9FormalRunEvidenceError(
            f"{scenario} recovery leases are inconsistent"
        )
    source_instance = _one_row(
        connection,
        """
        SELECT instance_id, status, stopped_at
        FROM application_instances
        WHERE instance_id = ?
        """,
        (source_instance_id,),
        label=f"{scenario} source application instance",
    )
    recovery_instance = _one_row(
        connection,
        """
        SELECT instance_id, status, stopped_at
        FROM application_instances
        WHERE instance_id = ?
        """,
        (recovery_instance_id,),
        label=f"{scenario} recovery application instance",
    )
    if scenario == "main_application_restart" and (
        source_instance_id == recovery_instance_id
        or source_instance["status"] not in {"stale", "stopped"}
        or source_instance["stopped_at"] is None
    ):
        raise Loop9FormalRunEvidenceError(
            "main application restart did not cross an instance boundary"
        )
    job = _one_row(
        connection,
        """
        SELECT task_type, scope_label, scope_fixture_id,
               scope_fingerprint, run_mode, status, diagnostic_code,
               job_kind, ocr_execution_mode, conflict_key
        FROM jobs
        WHERE job_id = ?
        """,
        (identity.job_id,),
        label=f"{scenario} job",
    )
    scope_fixture_id = job["scope_fixture_id"]
    if (
        not isinstance(scope_fixture_id, str)
        or re.fullmatch(
            rf"loop9-fault-{re.escape(scenario)}-[0-9a-f]{{12}}",
            scope_fixture_id,
        )
        is None
        or job["task_type"] != expected_task_type
        or job["scope_label"] != f"Loop 9 protected fault: {scenario}"
        or job["scope_fingerprint"]
        != _hash_text(f"{expected_task_type}:{scope_fixture_id}")
        or job["run_mode"] != "shadow"
        or job["status"] != "succeeded"
        or job["diagnostic_code"] is not None
        or job["job_kind"] != "test_fixture"
        or job["ocr_execution_mode"] != "fake"
        or job["conflict_key"]
        != (
            f"test_fixture:loop9-fault:{scenario}:"
            f"{current_build_sha256}"
        )
    ):
        raise Loop9FormalRunEvidenceError(
            f"{scenario} recovery job identity or scope is invalid"
        )
    try:
        items = connection.execute(
            """
            SELECT work_item_id, item_index, status, business_outcome,
                   decision, review_reason, diagnostic_code
            FROM work_items
            WHERE job_id = ?
            ORDER BY item_index, work_item_id
            """,
            (identity.job_id,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise Loop9FormalRunEvidenceError(
            f"{scenario} work-item reconciliation is unavailable"
        ) from exc
    if (
        not items
        or len({row["work_item_id"] for row in items}) != len(items)
        or len({row["item_index"] for row in items}) != len(items)
        or any(row["status"] != "succeeded" for row in items)
    ):
        raise Loop9FormalRunEvidenceError(
            f"{scenario} work-item recovery has missing results"
        )
    technical_review_leaks = sum(
        1
        for row in items
        if row["diagnostic_code"] is not None
        or not _has_valid_business_result_shape(row)
    )
    if technical_review_leaks:
        raise Loop9FormalRunEvidenceError(
            f"{scenario} technical failure leaked into business review"
        )
    return {
        "checkpoint_sha256": _canonical_sha256(dict(checkpoint)),
        "duplicate_result_count": 0,
        "event_chain_sha256": cast(
            str,
            recovered["event_sha256"],
        ),
        "failure_attempt_sha256": _canonical_sha256(dict(failed_attempt)),
        "injection_event_sha256": cast(
            str,
            injected["event_sha256"],
        ),
        "job_id_sha256": _hash_text(identity.job_id),
        "job_sha256": _canonical_sha256(dict(job)),
        "missing_item_count": 0,
        "recovery_attempt_sha256": _canonical_sha256(
            dict(recovery_attempt)
        ),
        "recovery_instance_sha256": _canonical_sha256(
            dict(recovery_instance)
        ),
        "recovery_lease_sha256": _canonical_sha256(
            dict(recovery_lease)
        ),
        "run_id_sha256": _hash_text(identity.run_id),
        "source_instance_sha256": _canonical_sha256(
            dict(source_instance)
        ),
        "source_lease_sha256": _canonical_sha256(dict(source_lease)),
        "technical_review_leak_count": 0,
        "work_item_results_sha256": _canonical_sha256(
            [dict(row) for row in items]
        ),
    }


def replay_persisted_fault_scenario(
    *,
    data_root: Path,
    scenario: str,
    identity: FaultScenarioIdentity,
    current_build_sha256: str,
) -> dict[str, object]:
    """Read and verify one protected fault chain from production tables."""

    if (
        not isinstance(data_root, Path)
        or not data_root.is_absolute()
        or data_root.is_symlink()
        or _is_reparse_point(data_root)
        or not isinstance(identity, FaultScenarioIdentity)
        or scenario not in _FAULT_SCENARIOS
    ):
        raise Loop9FormalRunEvidenceError(
            "fault replay technical identities are invalid"
        )
    try:
        root = data_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9FormalRunEvidenceError(
            "fault replay data root is unavailable"
        ) from exc
    if not root.is_dir():
        raise Loop9FormalRunEvidenceError(
            "fault replay data root is unsafe"
        )
    build_sha256 = _required_sha256(
        current_build_sha256,
        label="fault replay build",
    )
    connection = _read_only_database(root)
    try:
        required_tables = {
            "application_instances",
            "checkpoints",
            "event_outbox",
            "jobs",
            "leases",
            "stage_attempts",
            "work_items",
        }
        missing_tables = sorted(
            required_tables - _database_tables(connection)
        )
        if missing_tables:
            raise Loop9FormalRunEvidenceError(
                "formal fault replay is missing production tables: "
                + ", ".join(missing_tables)
            )
        return _fault_projection(
            connection,
            scenario=scenario,
            identity=identity,
            current_build_sha256=build_sha256,
        )
    finally:
        connection.close()


def _work_item_end_to_end_durations(
    connection: sqlite3.Connection,
    *,
    job_ids: Sequence[str],
    expected_work_item_ids: Sequence[str],
) -> tuple[str, ...]:
    expected = set(expected_work_item_ids)
    if len(expected) != len(expected_work_item_ids):
        raise Loop9FormalRunEvidenceError(
            "formal scheduler work-item identities are duplicated"
        )
    placeholders = ",".join("?" for _ in job_ids)
    try:
        rows = connection.execute(
            f"""
            SELECT aggregate_id, created_at, record_version
            FROM event_outbox
            WHERE aggregate_type = 'work_item'
              AND event_type = 'work_item.changed'
              AND json_extract(payload_json, '$.job_id')
                  IN ({placeholders})
            ORDER BY event_id
            """,
            tuple(job_ids),
        ).fetchall()
    except sqlite3.Error as exc:
        raise Loop9FormalRunEvidenceError(
            "end-to-end work-item duration records are unavailable"
        ) from exc
    by_item: dict[str, list[sqlite3.Row]] = {
        work_item_id: [] for work_item_id in expected
    }
    for row in rows:
        aggregate_id = cast(str, row["aggregate_id"])
        if aggregate_id in by_item:
            by_item[aggregate_id].append(row)
    durations: list[str] = []
    for work_item_id in sorted(expected):
        events = by_item[work_item_id]
        if (
            len(events) < 2
            or len({row["record_version"] for row in events}) < 2
        ):
            raise Loop9FormalRunEvidenceError(
                "end-to-end work-item duration records require "
                "at least two persisted state events per item"
            )
        try:
            started = datetime.fromisoformat(cast(str, events[0]["created_at"]))
            finished = datetime.fromisoformat(cast(str, events[-1]["created_at"]))
        except (TypeError, ValueError) as exc:
            raise Loop9FormalRunEvidenceError(
                "end-to-end work-item event timestamps are invalid"
            ) from exc
        elapsed = Decimal(str((finished - started).total_seconds())) * Decimal(
            "1000"
        )
        if elapsed < 0:
            raise Loop9FormalRunEvidenceError(
                "end-to-end work-item event ordering is invalid"
            )
        durations.append(_decimal_text(elapsed))
    return tuple(durations)


def _safe_existing_file(
    data_root: Path,
    path: Path,
    *,
    label: str,
) -> Path:
    if not path.is_absolute():
        raise Loop9FormalRunEvidenceError(f"{label} path is not absolute")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(data_root)
    except (OSError, ValueError) as exc:
        raise Loop9FormalRunEvidenceError(
            f"{label} path escaped the data root"
        ) from exc
    if (
        path.is_symlink()
        or _is_reparse_point(path)
        or not resolved.is_file()
        or resolved.stat().st_size > _MAX_FILE_BYTES
    ):
        raise Loop9FormalRunEvidenceError(f"{label} path is unsafe")
    return resolved


def _resolve_digest_named_json(
    data_root: Path,
    canonical_sha256: str,
    *,
    label: str,
) -> Path:
    digest = _required_sha256(canonical_sha256, label=label)
    candidates = tuple(data_root.rglob(f"{digest}.json"))
    safe = tuple(
        _safe_existing_file(data_root, candidate, label=label)
        for candidate in candidates
    )
    if len(safe) != 1:
        raise Loop9FormalRunEvidenceError(
            f"{label} must have exactly one digest-named immutable file"
        )
    return safe[0]


def _load_canonical_json_file(
    data_root: Path,
    path: Path,
    *,
    label: str,
) -> dict[str, object]:
    resolved = _safe_existing_file(data_root, path, label=label)
    try:
        content = resolved.read_bytes()
        raw = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                Loop9FormalRunEvidenceError(
                    f"non-finite JSON value {value} is forbidden"
                )
            ),
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise Loop9FormalRunEvidenceError(f"{label} is unreadable") from exc
    if not isinstance(raw, dict):
        raise Loop9FormalRunEvidenceError(f"{label} is invalid")
    compact = _canonical_bytes(raw) + b"\n"
    indented = (
        json.dumps(
            raw,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if content not in {compact, indented}:
        raise Loop9FormalRunEvidenceError(f"{label} is not canonical")
    return raw


def _find_review_package(
    data_root: Path,
    *,
    package_sha256: str,
    selection_sha256: str,
) -> Path:
    from dahe.verification.loop9_human_review import (
        load_loop9_review_package,
    )

    matches: list[Path] = []
    for candidate in data_root.rglob("review-package.json"):
        try:
            package = load_loop9_review_package(candidate.parent)
        except Exception:
            continue
        if (
            package.payload.get("canonical_sha256") == package_sha256
            and package.formal_selection.canonical_sha256
            == selection_sha256
        ):
            matches.append(candidate.parent.resolve(strict=True))
    if len(set(matches)) != 1:
        raise Loop9FormalRunEvidenceError(
            "real shadow review package authority is unavailable or ambiguous"
        )
    return matches[0]


def _find_review_seal(
    data_root: Path,
    *,
    package_dir: Path,
    seal_sha256: str,
) -> Path:
    from dahe.verification.loop9_human_review import (
        _load_and_validate_seal,
        load_loop9_review_package,
    )

    package = load_loop9_review_package(package_dir)
    matches: list[Path] = []
    for candidate in data_root.rglob("*.json"):
        if "seal" not in candidate.name.lower():
            continue
        try:
            resolved = _safe_existing_file(
                data_root,
                candidate,
                label="real shadow human review seal",
            )
            seal = _load_and_validate_seal(
                package=package,
                seal_path=resolved,
            )
        except Exception:
            continue
        if seal.get("canonical_sha256") == seal_sha256:
            matches.append(resolved)
    if len(set(matches)) != 1:
        raise Loop9FormalRunEvidenceError(
            "real shadow human review seal is unavailable or ambiguous"
        )
    return matches[0]


def _request_audit_binding(
    source: object,
    *,
    label: str,
) -> tuple[str, Mapping[str, object]]:
    audit_sha256 = getattr(source, "request_audit_sha256", None)
    audit_counts = getattr(source, "request_audit_counts", None)
    if (
        not isinstance(audit_sha256, str)
        or _SHA256.fullmatch(audit_sha256) is None
        or not isinstance(audit_counts, Mapping)
    ):
        raise Loop9FormalRunEvidenceError(
            f"{label} lacks upstream-bound request audit evidence"
        )
    return audit_sha256, audit_counts


def _request_audit_document(
    evidence: object,
) -> dict[str, object]:
    from dahe.verification.loop9_request_audit import (
        PlatformReadAuditEvidence,
    )

    if not isinstance(evidence, PlatformReadAuditEvidence):
        raise Loop9FormalRunEvidenceError(
            "platform request audit evidence is invalid"
        )
    return evidence.to_payload()


def _assert_bound_request_counts(
    *,
    label: str,
    bound: Mapping[str, object],
    evidence: object,
) -> None:
    from dahe.verification.loop9_request_audit import (
        PlatformReadAuditEvidence,
    )

    if not isinstance(evidence, PlatformReadAuditEvidence):
        raise Loop9FormalRunEvidenceError(
            f"{label} request audit evidence is invalid"
        )
    expected_candidates = (
        evidence.request_counts.to_payload(),
        {
            key: value
            for key, value in evidence.to_payload().items()
            if key != "canonical_sha256"
        },
        {
            "event_count": evidence.event_count,
            "operation_counts": {
                operation: counts.to_payload()
                for operation, counts in evidence.operation_counts.items()
            },
            "platform_write_request_count": (
                evidence.platform_write_request_count
            ),
            "redirect_count": evidence.redirect_count,
            "request_counts": evidence.request_counts.to_payload(),
        },
    )
    if dict(bound) not in expected_candidates:
        raise Loop9FormalRunEvidenceError(
            f"{label} request audit bound counts changed"
        )


def _machine_result_path(
    data_root: Path,
    machine_result_sha256: str,
) -> Path:
    digest = _required_sha256(
        machine_result_sha256,
        label="machine result",
    )
    return _safe_existing_file(
        data_root,
        (
            data_root
            / "verification"
            / "loop9"
            / "machine-results"
            / digest[:2]
            / f"{digest}.json"
        ),
        label="machine result",
    )


def _has_valid_business_result_shape(item: object) -> bool:
    if isinstance(item, sqlite3.Row):
        outcome = item["business_outcome"]
        decision = item["decision"]
        reason = item["review_reason"]
    else:
        outcome = getattr(item, "business_outcome", None)
        decision = getattr(item, "decision", None)
        reason = getattr(item, "review_reason", None)
    if outcome == "normal_ready":
        return decision == "pass" and reason is None
    if outcome == "confirmed_problem":
        return decision == "problem" and reason is None
    if outcome == "awaiting_review":
        return (
            decision
            in {"review", "weight_mismatch", "suspected_problem"}
            and reason in _BUSINESS_REVIEW_REASONS
        )
    return False


def _scheduler_projection_summary(
    projection: object,
    *,
    expected_count: int,
) -> tuple[dict[str, object], tuple[str, ...]]:
    from dahe.verification.loop9_machine_results import (
        SchedulerBatchProjection,
    )

    if not isinstance(projection, SchedulerBatchProjection):
        raise Loop9FormalRunEvidenceError(
            "scheduler projection type is invalid"
        )
    terminal = sum(
        1
        for item in projection.items
        if item.status == "succeeded"
        and item.diagnostic_code is None
        and item.business_outcome
        in {"normal_ready", "awaiting_review", "confirmed_problem"}
    )
    technical_review_leaks = sum(
        1
        for item in projection.items
        if not _has_valid_business_result_shape(item)
    )
    if (
        projection.job_status != "succeeded"
        or len(projection.items) != expected_count
        or terminal != expected_count
        or technical_review_leaks != 0
    ):
        if technical_review_leaks:
            raise Loop9FormalRunEvidenceError(
                "formal scheduler projection has a technical failure "
                "leaked into business review"
            )
        raise Loop9FormalRunEvidenceError(
            "formal scheduler projection has missing terminal results"
        )
    return (
        {
            "item_count": len(projection.items),
            "job_id_sha256": _hash_text(projection.job_id),
            "projection_sha256": projection.projection_sha256,
            "technical_review_leak_count": technical_review_leaks,
            "terminal_result_count": terminal,
        },
        tuple(item.work_item_id for item in projection.items),
    )


def _capture_request_audit_binding(
    data_root: Path,
    *,
    selection: object,
    label: str,
) -> tuple[str, Mapping[str, object], str]:
    from dahe.adapters.files.settlement_capture_manifest import (
        SettlementCaptureManifestStore,
    )
    from dahe.application.chengfeng.shadow_batch import (
        SCHEMA_VERSION as SHADOW_BATCH_SCHEMA_VERSION,
    )
    from dahe.application.chengfeng.shadow_selection import (
        FormalShadowSelectionManifest,
    )

    if not isinstance(selection, FormalShadowSelectionManifest):
        raise Loop9FormalRunEvidenceError(
            f"{label} selection authority is invalid"
        )
    capture = SettlementCaptureManifestStore(data_root).load(
        selection.source_capture_sha256
    )
    audit_sha256, counts = _request_audit_binding(
        capture,
        label=f"{label} capture",
    )
    batch = selection.batch_manifest
    if (
        batch.schema_version != SHADOW_BATCH_SCHEMA_VERSION
        or batch.source_capture_sha256 != selection.source_capture_sha256
        or batch.request_audit_sha256 != audit_sha256
        or batch.request_audit_counts is None
        or dict(batch.request_audit_counts) != dict(counts)
    ):
        raise Loop9FormalRunEvidenceError(
            f"{label} selection request audit binding is invalid"
        )
    return audit_sha256, counts, capture.source_job_id


def _validate_current_daily_validation_for_formal_run(
    payload: object,
    *,
    data_root: Path,
    project_root: Path,
    expected_canonical_sha256: str,
    source_build_sha256: str,
    daily_contract_sha256: str,
) -> dict[str, object]:
    from dahe.verification.daily_snapshot_validation import (
        replay_current_daily_snapshot_validation_from_store,
    )

    try:
        validated = replay_current_daily_snapshot_validation_from_store(
            payload,
            data_root=data_root,
            project_root=project_root,
            source_build_sha256=source_build_sha256,
        )
    except Exception as exc:
        raise Loop9FormalRunEvidenceError(
            "daily snapshot validation replay failed"
        ) from exc
    if (
        validated.get("schema_version") != 5
        or validated.get("canonical_sha256")
        != expected_canonical_sha256
        or validated.get("build_sha256") != source_build_sha256
        or validated.get("contract_sha256")
        != daily_contract_sha256
    ):
        raise Loop9FormalRunEvidenceError(
            "daily snapshot validation authority changed"
        )
    return validated


def _derive_formal_run_evidence(
    *,
    project_root: Path,
    data_root: Path,
    request: Loop9FormalRunRequest,
) -> Loop9FormalRunEvidence:
    from dahe.adapters.chengfeng.daily_contract_selection import (
        load_selected_daily_read_contract,
    )
    from dahe.adapters.chengfeng.live_contract_selection import (
        load_selected_live_read_contract,
    )
    from dahe.adapters.files.platform_request_audit import (
        PlatformReadAuditAuthority,
        PlatformReadAuditEvidenceStore,
    )
    from dahe.adapters.files.shadow_selection_manifest import (
        FormalShadowSelectionStore,
    )
    from dahe.application.chengfeng.shadow_batch import (
        ShadowBatchTargetKind,
    )
    from dahe.verification.loop9_build import (
        current_loop9_build_sha256,
    )
    from dahe.verification.loop9_dataset_isolation import (
        load_loop9_dataset_isolation_evidence,
    )
    from dahe.verification.loop9_machine_results import (
        evaluate_sealed_machine_results,
        load_machine_result_manifest,
        load_machine_truth_evaluation,
        read_scheduler_batch_projection,
    )

    try:
        source_build_sha256 = current_loop9_build_sha256(project_root)
        settlement = load_selected_live_read_contract(data_root)
        daily = load_selected_daily_read_contract(data_root)
        selection_store = FormalShadowSelectionStore(data_root)
        locked = selection_store.load(ShadowBatchTargetKind.CURRENT_LOCKED_50)
        locked_gate = selection_store.require_current_locked_gate(
            expected_current_build_sha256=source_build_sha256,
            expected_settlement_contract_sha256=(
                settlement.manifest.canonical_sha256
            ),
        )
        real_shadow = selection_store.load_active_real_shadow_manifest(
            request.real_shadow_selection_sha256,
            expected_current_build_sha256=source_build_sha256,
            expected_settlement_contract_sha256=(
                settlement.manifest.canonical_sha256
            ),
        )
    except Exception as exc:
        raise Loop9FormalRunEvidenceError(
            "active build, contract, selection or locked Gate replay failed"
        ) from exc
    if (
        locked.batch_manifest.source_build_sha256
        != source_build_sha256
        or real_shadow.batch_manifest.source_build_sha256
        != source_build_sha256
        or locked_gate.selection_sha256 != locked.canonical_sha256
        or real_shadow.prior_selection_sha256s
        != (locked.canonical_sha256,)
        or real_shadow.locked_gate_evidence_sha256
        != locked_gate.canonical_sha256
    ):
        raise Loop9FormalRunEvidenceError(
            "formal selection authority chain changed"
        )

    real_evaluation_path = _resolve_digest_named_json(
        data_root,
        request.real_shadow_machine_evaluation_sha256,
        label="real shadow machine evaluation",
    )
    try:
        real_evaluation = load_machine_truth_evaluation(
            real_evaluation_path
        )
    except Exception as exc:
        raise Loop9FormalRunEvidenceError(
            "real shadow machine evaluation is invalid"
        ) from exc
    if (
        real_evaluation.get("canonical_sha256")
        != request.real_shadow_machine_evaluation_sha256
        or real_evaluation.get("source_batch_sha256")
        != real_shadow.batch_manifest.canonical_sha256
        or real_evaluation.get("review_kind")
        != ShadowBatchTargetKind.REAL_SHADOW_30.value
        or real_evaluation.get("gate_passed") is not True
        or real_evaluation.get("item_count") != 30
        or real_evaluation.get("image_count") != 60
        or real_evaluation.get("runtime_observation_count") != 120
        or any(
            real_evaluation.get(field_name) != 0
            for field_name in (
                "high_confidence_role_error_count",
                "technical_failure_count",
                "wrong_auto_pass_count",
            )
        )
    ):
        raise Loop9FormalRunEvidenceError(
            "real shadow machine Gate did not pass"
        )
    package_sha256 = _required_sha256(
        real_evaluation.get("package_sha256"),
        label="real shadow review package",
    )
    seal_sha256 = _required_sha256(
        real_evaluation.get("seal_sha256"),
        label="real shadow human review seal",
    )
    package_dir = _find_review_package(
        data_root,
        package_sha256=package_sha256,
        selection_sha256=real_shadow.canonical_sha256,
    )
    seal_path = _find_review_seal(
        data_root,
        package_dir=package_dir,
        seal_sha256=seal_sha256,
    )
    real_machine_sha256 = _required_sha256(
        real_evaluation.get("machine_result_sha256"),
        label="real shadow machine result",
    )
    real_machine_path = _machine_result_path(
        data_root,
        real_machine_sha256,
    )
    try:
        real_machine = load_machine_result_manifest(real_machine_path)
        replayed_real_evaluation = evaluate_sealed_machine_results(
            package_dir=package_dir,
            seal_path=seal_path,
            machine_result_path=real_machine_path,
        )
    except Exception as exc:
        raise Loop9FormalRunEvidenceError(
            "real shadow human and machine evidence replay failed"
        ) from exc
    if replayed_real_evaluation != real_evaluation:
        raise Loop9FormalRunEvidenceError(
            "real shadow machine evaluation replay changed"
        )

    locked_machine_path = _safe_existing_file(
        data_root,
        data_root / locked_gate.machine_result_relative_path,
        label="current locked machine result",
    )
    try:
        locked_machine = load_machine_result_manifest(
            locked_machine_path
        )
        locked_projection = read_scheduler_batch_projection(
            data_root=data_root,
            batch=locked.batch_manifest,
            job_id=request.locked_job_id,
        )
        real_projection = read_scheduler_batch_projection(
            data_root=data_root,
            batch=real_shadow.batch_manifest,
            job_id=request.real_shadow_job_id,
        )
    except Exception as exc:
        raise Loop9FormalRunEvidenceError(
            "formal scheduler projection replay failed"
        ) from exc
    if (
        locked_machine.get("scheduler") != locked_projection.to_payload()
        or real_machine.get("scheduler") != real_projection.to_payload()
    ):
        raise Loop9FormalRunEvidenceError(
            "formal machine result no longer matches SQLite scheduler records"
        )
    locked_projection_summary, locked_work_items = (
        _scheduler_projection_summary(
            locked_projection,
            expected_count=50,
        )
    )
    real_projection_summary, real_work_items = (
        _scheduler_projection_summary(
            real_projection,
            expected_count=30,
        )
    )

    locked_audit_sha256, locked_audit_counts, locked_capture_job = (
        _capture_request_audit_binding(
            data_root,
            selection=locked,
            label="current locked 50",
        )
    )
    real_audit_sha256, real_audit_counts, real_capture_job = (
        _capture_request_audit_binding(
            data_root,
            selection=real_shadow,
            label="real shadow 30",
        )
    )
    settlement_audit_authority = PlatformReadAuditAuthority(
        build_sha256=source_build_sha256,
        settlement_contract_sha256=(
            settlement.manifest.canonical_sha256
        ),
        settlement_contract_selection_sha256=(
            settlement.selection_sha256
        ),
    )
    audit_store = PlatformReadAuditEvidenceStore(data_root)
    try:
        locked_audit = audit_store.load(
            locked_audit_sha256,
            expected_job_id=locked_capture_job,
            expected_authority=settlement_audit_authority,
        )
        real_audit = audit_store.load(
            real_audit_sha256,
            expected_job_id=real_capture_job,
            expected_authority=settlement_audit_authority,
        )
    except Exception as exc:
        raise Loop9FormalRunEvidenceError(
            "formal 50/30 platform request audit replay failed"
        ) from exc
    if (
        locked_audit.purpose != "current_locked_50"
        or real_audit.purpose != "real_shadow_30"
    ):
        raise Loop9FormalRunEvidenceError(
            "formal 50/30 request audit purpose changed"
        )
    _assert_bound_request_counts(
        label="current locked 50",
        bound=locked_audit_counts,
        evidence=locked_audit,
    )
    _assert_bound_request_counts(
        label="real shadow 30",
        bound=real_audit_counts,
        evidence=real_audit,
    )

    daily_validation_path = _resolve_digest_named_json(
        data_root,
        request.daily_snapshot_validation_sha256,
        label="daily snapshot validation",
    )
    daily_payload = _load_canonical_json_file(
        data_root,
        daily_validation_path,
        label="daily snapshot validation",
    )
    daily_validation = (
        _validate_current_daily_validation_for_formal_run(
            daily_payload,
            data_root=data_root,
            project_root=project_root,
            expected_canonical_sha256=(
                request.daily_snapshot_validation_sha256
            ),
            source_build_sha256=source_build_sha256,
            daily_contract_sha256=daily.manifest.canonical_sha256,
        )
    )
    snapshots = daily_validation.get("snapshot_evidence")
    audit_sha256s = daily_validation.get("request_audit_sha256s")
    if (
        not isinstance(snapshots, list)
        or len(snapshots) != 3
        or not isinstance(audit_sha256s, list)
        or len(audit_sha256s) != 3
    ):
        raise Loop9FormalRunEvidenceError(
            "daily snapshot request audit bindings are incomplete"
        )
    daily_audit_authority = PlatformReadAuditAuthority(
        build_sha256=source_build_sha256,
        settlement_contract_sha256=(
            settlement.manifest.canonical_sha256
        ),
        settlement_contract_selection_sha256=(
            settlement.selection_sha256
        ),
        daily_contract_sha256=daily.manifest.canonical_sha256,
        daily_contract_selection_sha256=daily.selection_sha256,
    )
    request_audits: dict[str, dict[str, object]] = {
        "current_locked_50": _request_audit_document(locked_audit),
        "real_shadow_30": _request_audit_document(real_audit),
    }
    for index, (snapshot, audit_sha256) in enumerate(
        zip(snapshots, audit_sha256s, strict=True),
        start=1,
    ):
        if (
            not isinstance(snapshot, Mapping)
            or snapshot.get("request_audit_sha256") != audit_sha256
        ):
            raise Loop9FormalRunEvidenceError(
                "daily snapshot request audit identity changed"
            )
        job_id = _required_text(
            snapshot.get("job_id"),
            label=f"daily snapshot {index} job",
        )
        try:
            audit = audit_store.load(
                _required_sha256(
                    audit_sha256,
                    label=f"daily snapshot {index} request audit",
                ),
                expected_job_id=job_id,
                expected_authority=daily_audit_authority,
            )
        except Exception as exc:
            raise Loop9FormalRunEvidenceError(
                f"daily snapshot {index} request audit replay failed"
            ) from exc
        if audit.purpose != "daily_snapshot":
            raise Loop9FormalRunEvidenceError(
                f"daily snapshot {index} request audit purpose changed"
            )
        bound_counts = {
            "authority": snapshot.get("request_audit_authority"),
            "event_chain_sha256": snapshot.get(
                "request_audit_event_chain_sha256"
            ),
            "event_count": snapshot.get("request_audit_event_count"),
            "expected_succeeded_operations": snapshot.get(
                "request_audit_expected_succeeded_operations"
            ),
            "job_id_sha256": snapshot.get(
                "request_audit_job_id_sha256"
            ),
            "kind": snapshot.get("request_audit_kind"),
            "operation_counts": snapshot.get(
                "request_audit_operation_counts"
            ),
            "platform_write_request_count": snapshot.get(
                "platform_write_request_count"
            ),
            "redirect_count": snapshot.get("redirect_count"),
            "purpose": snapshot.get("request_audit_purpose"),
            "request_counts": snapshot.get(
                "request_audit_request_counts"
            ),
            "schema_version": snapshot.get(
                "request_audit_schema_version"
            ),
        }
        _assert_bound_request_counts(
            label=f"daily snapshot {index}",
            bound=bound_counts,
            evidence=audit,
        )
        request_audits[f"daily_snapshot_{index}"] = (
            _request_audit_document(audit)
        )

    isolation_path = _resolve_digest_named_json(
        data_root,
        request.dataset_isolation_sha256,
        label="dataset isolation evidence",
    )
    try:
        isolation = load_loop9_dataset_isolation_evidence(isolation_path)
    except Exception as exc:
        raise Loop9FormalRunEvidenceError(
            "dataset isolation evidence replay failed"
        ) from exc
    if isolation.canonical_sha256 != request.dataset_isolation_sha256:
        raise Loop9FormalRunEvidenceError(
            "dataset isolation evidence identity changed"
        )

    connection = _read_only_database(data_root)
    try:
        tables = _database_tables(connection)
        required_tables = {
            "application_instances",
            "checkpoints",
            "event_outbox",
            "jobs",
            "leases",
            "stage_attempts",
            "work_items",
        }
        missing_tables = sorted(required_tables - tables)
        if missing_tables:
            raise Loop9FormalRunEvidenceError(
                "formal fault replay is missing production tables: "
                + ", ".join(missing_tables)
            )
        fault_injections = {
            scenario: _fault_projection(
                connection,
                scenario=scenario,
                identity=request.fault_scenarios[scenario],
                current_build_sha256=source_build_sha256,
            )
            for scenario in sorted(_FAULT_SCENARIOS)
        }
        end_to_end = _work_item_end_to_end_durations(
            connection,
            job_ids=(
                request.locked_job_id,
                request.real_shadow_job_id,
            ),
            expected_work_item_ids=(
                *locked_work_items,
                *real_work_items,
            ),
        )
    finally:
        connection.close()
    performance = recompute_machine_performance(
        (locked_machine, real_machine),
        end_to_end_duration_ms=end_to_end,
    )
    for scope, expected_size in (
        _EXPECTED_PERFORMANCE_SAMPLE_SIZES.items()
    ):
        if performance[scope]["sample_size"] != expected_size:
            raise Loop9FormalRunEvidenceError(
                f"{scope} raw performance sample count is incomplete"
            )

    return Loop9FormalRunEvidence.create(
        source_build_sha256=source_build_sha256,
        settlement_contract_sha256=(
            settlement.manifest.canonical_sha256
        ),
        settlement_contract_selection_sha256=(
            settlement.selection_sha256
        ),
        daily_contract_sha256=daily.manifest.canonical_sha256,
        daily_contract_selection_sha256=daily.selection_sha256,
        current_locked_selection_sha256=locked.canonical_sha256,
        current_locked_gate_sha256=locked_gate.canonical_sha256,
        real_shadow_selection_sha256=real_shadow.canonical_sha256,
        real_shadow_machine_evaluation_sha256=(
            request.real_shadow_machine_evaluation_sha256
        ),
        daily_snapshot_validation_sha256=(
            request.daily_snapshot_validation_sha256
        ),
        dataset_isolation_sha256=request.dataset_isolation_sha256,
        scheduler_projections={
            "current_locked_50": locked_projection_summary,
            "real_shadow_30": real_projection_summary,
        },
        request_audits=request_audits,
        fault_injections=fault_injections,
        performance=performance,
        reconciliation={
            "duplicate_result_count": 0,
            "missing_item_count": 0,
            "source_item_count": sum(
                cast(int, projection["item_count"])
                for projection in (
                    locked_projection_summary,
                    real_projection_summary,
                )
            ),
            "technical_review_leak_count": sum(
                cast(int, projection["technical_review_leak_count"])
                for projection in (
                    locked_projection_summary,
                    real_projection_summary,
                )
            ),
            "terminal_result_count": sum(
                cast(int, projection["terminal_result_count"])
                for projection in (
                    locked_projection_summary,
                    real_projection_summary,
                )
            ),
        },
    )


def _validate_scheduler_projections(
    value: object,
) -> dict[str, dict[str, object]]:
    if not isinstance(value, Mapping) or set(value) != _SCHEDULER_SCOPES:
        raise Loop9FormalRunEvidenceError(
            "scheduler projections are incomplete"
        )
    result: dict[str, dict[str, object]] = {}
    for scope, expected_count in (
        ("current_locked_50", 50),
        ("real_shadow_30", 30),
    ):
        projection = value.get(scope)
        if not isinstance(projection, Mapping) or set(projection) != {
            "item_count",
            "job_id_sha256",
            "projection_sha256",
            "technical_review_leak_count",
            "terminal_result_count",
        }:
            raise Loop9FormalRunEvidenceError(
                f"{scope} scheduler projection is invalid"
            )
        _required_sha256(
            projection.get("job_id_sha256"),
            label=f"{scope} scheduler job",
        )
        _required_sha256(
            projection.get("projection_sha256"),
            label=f"{scope} scheduler projection",
        )
        if (
            projection.get("item_count") != expected_count
            or projection.get("terminal_result_count") != expected_count
            or projection.get("technical_review_leak_count") != 0
        ):
            raise Loop9FormalRunEvidenceError(
                f"{scope} scheduler projection is incomplete"
            )
        result[scope] = dict(projection)
    return result


def _validate_request_audits(
    value: object,
    *,
    source_build_sha256: str,
    settlement_contract_sha256: str,
    settlement_contract_selection_sha256: str,
    daily_contract_sha256: str,
    daily_contract_selection_sha256: str,
) -> dict[str, dict[str, object]]:
    from dahe.verification.loop9_request_audit import (
        PlatformReadAuditEvidence,
    )

    if not isinstance(value, Mapping) or set(value) != _REQUEST_AUDIT_SCOPES:
        raise Loop9FormalRunEvidenceError(
            "exactly five request audit authorities are required"
        )
    result: dict[str, dict[str, object]] = {}
    for scope, raw in value.items():
        try:
            audit = PlatformReadAuditEvidence.from_payload(dict(raw))
        except Exception as exc:
            raise Loop9FormalRunEvidenceError(
                f"{scope} request audit evidence is invalid"
            ) from exc
        expected_purpose = (
            "daily_snapshot"
            if cast(str, scope).startswith("daily_snapshot_")
            else cast(str, scope)
        )
        expected_authority = {
            "build_sha256": source_build_sha256,
            "daily_contract_selection_sha256": (
                daily_contract_selection_sha256
                if expected_purpose == "daily_snapshot"
                else None
            ),
            "daily_contract_sha256": (
                daily_contract_sha256
                if expected_purpose == "daily_snapshot"
                else None
            ),
            "settlement_contract_selection_sha256": (
                settlement_contract_selection_sha256
            ),
            "settlement_contract_sha256": (
                settlement_contract_sha256
            ),
        }
        actual_succeeded = {
            operation: counts.succeeded
            for operation, counts in audit.operation_counts.items()
            if counts.succeeded
        }
        if (
            audit.purpose != expected_purpose
            or audit.authority.to_payload() != expected_authority
            or audit.request_counts.attempted < 1
            or audit.request_counts.allowed
            != audit.request_counts.attempted
            or audit.request_counts.succeeded
            != audit.request_counts.attempted
            or audit.request_counts.denied != 0
            or audit.platform_write_request_count != 0
            or audit.redirect_count != 0
            or audit.event_count
            != audit.request_counts.attempted * 3
            or actual_succeeded
            != dict(audit.expected_succeeded_operations)
            or any(
                counts.attempted != counts.allowed
                or counts.allowed != counts.succeeded
                or counts.denied != 0
                or counts.failed != 0
                or counts.redirect != 0
                for counts in audit.operation_counts.values()
            )
        ):
            raise Loop9FormalRunEvidenceError(
                f"{scope} request audit is not clean"
            )
        result[cast(str, scope)] = audit.to_payload()
    return result


def _validate_faults(
    value: object,
) -> dict[str, dict[str, object]]:
    if not isinstance(value, Mapping) or set(value) != _FAULT_SCENARIOS:
        raise Loop9FormalRunEvidenceError(
            "fault injection evidence is incomplete"
        )
    expected_fields = {
        "checkpoint_sha256",
        "duplicate_result_count",
        "event_chain_sha256",
        "failure_attempt_sha256",
        "injection_event_sha256",
        "job_id_sha256",
        "job_sha256",
        "missing_item_count",
        "recovery_attempt_sha256",
        "recovery_instance_sha256",
        "recovery_lease_sha256",
        "run_id_sha256",
        "source_instance_sha256",
        "source_lease_sha256",
        "technical_review_leak_count",
        "work_item_results_sha256",
    }
    result: dict[str, dict[str, object]] = {}
    for scenario, raw in value.items():
        if not isinstance(raw, Mapping) or set(raw) != expected_fields:
            raise Loop9FormalRunEvidenceError(
                f"{scenario} fault evidence is invalid"
            )
        for field_name in (
            "checkpoint_sha256",
            "event_chain_sha256",
            "failure_attempt_sha256",
            "injection_event_sha256",
            "job_id_sha256",
            "job_sha256",
            "recovery_attempt_sha256",
            "recovery_instance_sha256",
            "recovery_lease_sha256",
            "run_id_sha256",
            "source_instance_sha256",
            "source_lease_sha256",
            "work_item_results_sha256",
        ):
            _required_sha256(
                raw.get(field_name),
                label=f"{scenario} {field_name}",
            )
        if any(
            raw.get(field_name) != 0
            for field_name in (
                "duplicate_result_count",
                "missing_item_count",
                "technical_review_leak_count",
            )
        ):
            raise Loop9FormalRunEvidenceError(
                f"{scenario} fault recovery did not reconcile"
            )
        result[cast(str, scenario)] = dict(raw)
    return result


def _validate_performance(
    value: object,
) -> dict[str, dict[str, object]]:
    if not isinstance(value, Mapping) or set(value) != _PERFORMANCE_SCOPES:
        raise Loop9FormalRunEvidenceError(
            "formal performance evidence is incomplete"
        )
    result: dict[str, dict[str, object]] = {}
    for scope, expected_size in _EXPECTED_PERFORMANCE_SAMPLE_SIZES.items():
        raw = value.get(scope)
        if not isinstance(raw, Mapping) or set(raw) != {
            "p50_ms",
            "p95_ms",
            "sample_size",
            "samples_sha256",
        }:
            raise Loop9FormalRunEvidenceError(
                f"{scope} performance evidence is invalid"
            )
        p50 = _decimal(raw.get("p50_ms"), label=f"{scope} P50")
        p95 = _decimal(raw.get("p95_ms"), label=f"{scope} P95")
        _required_sha256(
            raw.get("samples_sha256"),
            label=f"{scope} performance samples",
        )
        if raw.get("sample_size") != expected_size or p50 > p95:
            raise Loop9FormalRunEvidenceError(
                f"{scope} performance evidence is incomplete"
            )
        result[scope] = dict(raw)
    return result


def _validate_reconciliation(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != {
        "duplicate_result_count",
        "missing_item_count",
        "source_item_count",
        "technical_review_leak_count",
        "terminal_result_count",
    }:
        raise Loop9FormalRunEvidenceError(
            "formal result reconciliation is invalid"
        )
    if (
        value.get("source_item_count") != 80
        or value.get("terminal_result_count") != 80
        or any(
            value.get(field_name) != 0
            for field_name in (
                "duplicate_result_count",
                "missing_item_count",
                "technical_review_leak_count",
            )
        )
    ):
        raise Loop9FormalRunEvidenceError(
            "formal result reconciliation did not pass"
        )
    return {
        str(key): cast(int, nested)
        for key, nested in value.items()
    }


@dataclass(frozen=True, slots=True)
class Loop9FormalRunEvidence:
    source_build_sha256: str
    settlement_contract_sha256: str
    settlement_contract_selection_sha256: str
    daily_contract_sha256: str
    daily_contract_selection_sha256: str
    current_locked_selection_sha256: str
    current_locked_gate_sha256: str
    real_shadow_selection_sha256: str
    real_shadow_machine_evaluation_sha256: str
    daily_snapshot_validation_sha256: str
    dataset_isolation_sha256: str
    scheduler_projections: Mapping[str, Mapping[str, object]]
    request_audits: Mapping[str, Mapping[str, object]]
    fault_injections: Mapping[str, Mapping[str, object]]
    performance: Mapping[str, Mapping[str, object]]
    reconciliation: Mapping[str, int]
    schema_version: int = _SCHEMA_VERSION
    kind: str = _KIND
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION or self.kind != _KIND:
            raise Loop9FormalRunEvidenceError(
                "formal run evidence version is unsupported"
            )
        for value, label in (
            (self.source_build_sha256, "source build"),
            (self.settlement_contract_sha256, "settlement contract"),
            (
                self.settlement_contract_selection_sha256,
                "settlement contract selection",
            ),
            (self.daily_contract_sha256, "daily contract"),
            (
                self.daily_contract_selection_sha256,
                "daily contract selection",
            ),
            (
                self.current_locked_selection_sha256,
                "current locked selection",
            ),
            (self.current_locked_gate_sha256, "current locked gate"),
            (self.real_shadow_selection_sha256, "real shadow selection"),
            (
                self.real_shadow_machine_evaluation_sha256,
                "real shadow machine evaluation",
            ),
            (
                self.daily_snapshot_validation_sha256,
                "daily snapshot validation",
            ),
            (self.dataset_isolation_sha256, "dataset isolation"),
        ):
            _required_sha256(value, label=label)
        object.__setattr__(
            self,
            "scheduler_projections",
            _validate_scheduler_projections(self.scheduler_projections),
        )
        object.__setattr__(
            self,
            "request_audits",
            _validate_request_audits(
                self.request_audits,
                source_build_sha256=self.source_build_sha256,
                settlement_contract_sha256=(
                    self.settlement_contract_sha256
                ),
                settlement_contract_selection_sha256=(
                    self.settlement_contract_selection_sha256
                ),
                daily_contract_sha256=self.daily_contract_sha256,
                daily_contract_selection_sha256=(
                    self.daily_contract_selection_sha256
                ),
            ),
        )
        object.__setattr__(
            self,
            "fault_injections",
            _validate_faults(self.fault_injections),
        )
        object.__setattr__(
            self,
            "performance",
            _validate_performance(self.performance),
        )
        object.__setattr__(
            self,
            "reconciliation",
            _validate_reconciliation(self.reconciliation),
        )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._body()),
        )

    @classmethod
    def create(cls, **values: object) -> Loop9FormalRunEvidence:
        return cls(**values)  # type: ignore[arg-type]

    def _body(self) -> dict[str, object]:
        return {
            "current_locked_gate_sha256": (
                self.current_locked_gate_sha256
            ),
            "current_locked_selection_sha256": (
                self.current_locked_selection_sha256
            ),
            "daily_contract_selection_sha256": (
                self.daily_contract_selection_sha256
            ),
            "daily_contract_sha256": self.daily_contract_sha256,
            "daily_snapshot_validation_sha256": (
                self.daily_snapshot_validation_sha256
            ),
            "dataset_isolation_sha256": self.dataset_isolation_sha256,
            "fault_injections": {
                key: dict(value)
                for key, value in sorted(self.fault_injections.items())
            },
            "kind": self.kind,
            "performance": {
                key: dict(value)
                for key, value in sorted(self.performance.items())
            },
            "real_shadow_machine_evaluation_sha256": (
                self.real_shadow_machine_evaluation_sha256
            ),
            "real_shadow_selection_sha256": (
                self.real_shadow_selection_sha256
            ),
            "reconciliation": dict(self.reconciliation),
            "request_audits": {
                key: dict(value)
                for key, value in sorted(self.request_audits.items())
            },
            "scheduler_projections": {
                key: dict(value)
                for key, value in sorted(self.scheduler_projections.items())
            },
            "schema_version": self.schema_version,
            "settlement_contract_selection_sha256": (
                self.settlement_contract_selection_sha256
            ),
            "settlement_contract_sha256": (
                self.settlement_contract_sha256
            ),
            "source_build_sha256": self.source_build_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._body(),
            "canonical_sha256": self.canonical_sha256,
        }

    @classmethod
    def from_payload(cls, value: object) -> Loop9FormalRunEvidence:
        expected = {
            "canonical_sha256",
            "current_locked_gate_sha256",
            "current_locked_selection_sha256",
            "daily_contract_selection_sha256",
            "daily_contract_sha256",
            "daily_snapshot_validation_sha256",
            "dataset_isolation_sha256",
            "fault_injections",
            "kind",
            "performance",
            "real_shadow_machine_evaluation_sha256",
            "real_shadow_selection_sha256",
            "reconciliation",
            "request_audits",
            "scheduler_projections",
            "schema_version",
            "settlement_contract_selection_sha256",
            "settlement_contract_sha256",
            "source_build_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise Loop9FormalRunEvidenceError(
                "formal run evidence shape is invalid"
            )
        raw = dict(value)
        evidence = cls(
            source_build_sha256=cast(str, raw["source_build_sha256"]),
            settlement_contract_sha256=cast(
                str,
                raw["settlement_contract_sha256"],
            ),
            settlement_contract_selection_sha256=cast(
                str,
                raw["settlement_contract_selection_sha256"],
            ),
            daily_contract_sha256=cast(
                str,
                raw["daily_contract_sha256"],
            ),
            daily_contract_selection_sha256=cast(
                str,
                raw["daily_contract_selection_sha256"],
            ),
            current_locked_selection_sha256=cast(
                str,
                raw["current_locked_selection_sha256"],
            ),
            current_locked_gate_sha256=cast(
                str,
                raw["current_locked_gate_sha256"],
            ),
            real_shadow_selection_sha256=cast(
                str,
                raw["real_shadow_selection_sha256"],
            ),
            real_shadow_machine_evaluation_sha256=cast(
                str,
                raw["real_shadow_machine_evaluation_sha256"],
            ),
            daily_snapshot_validation_sha256=cast(
                str,
                raw["daily_snapshot_validation_sha256"],
            ),
            dataset_isolation_sha256=cast(
                str,
                raw["dataset_isolation_sha256"],
            ),
            scheduler_projections=cast(
                Mapping[str, Mapping[str, object]],
                raw["scheduler_projections"],
            ),
            request_audits=cast(
                Mapping[str, Mapping[str, object]],
                raw["request_audits"],
            ),
            fault_injections=cast(
                Mapping[str, Mapping[str, object]],
                raw["fault_injections"],
            ),
            performance=cast(
                Mapping[str, Mapping[str, object]],
                raw["performance"],
            ),
            reconciliation=cast(
                Mapping[str, int],
                raw["reconciliation"],
            ),
            schema_version=cast(int, raw["schema_version"]),
            kind=cast(str, raw["kind"]),
        )
        if raw["canonical_sha256"] != evidence.canonical_sha256:
            raise Loop9FormalRunEvidenceError(
                "formal run evidence integrity failed"
            )
        return evidence


def _is_reparse_point(path: Path) -> bool:
    try:
        value = path.lstat()
    except OSError:
        return False
    attributes = getattr(value, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9FormalRunEvidenceError(
                "formal run evidence contains duplicate keys"
            )
        result[key] = value
    return result


class Loop9FormalRunEvidenceStore:
    """Content-addressed immutable storage for derived formal-run evidence."""

    def __init__(self, data_root: Path) -> None:
        if not isinstance(data_root, Path) or not data_root.is_absolute():
            raise Loop9FormalRunEvidenceError(
                "formal run data root must be absolute"
            )
        try:
            root = data_root.resolve(strict=True)
        except OSError as exc:
            raise Loop9FormalRunEvidenceError(
                "formal run data root is unavailable"
            ) from exc
        if (
            data_root.is_symlink()
            or _is_reparse_point(data_root)
            or not root.is_dir()
        ):
            raise Loop9FormalRunEvidenceError(
                "formal run data root is unsafe"
            )
        self.data_root = root
        self.root = (
            root
            / "verification"
            / "loop9"
            / "formal-run-evidence"
            / "sha256"
        )

    def path_for(self, canonical_sha256: str) -> Path:
        digest = _required_sha256(
            canonical_sha256,
            label="formal run evidence",
        )
        return (
            self.root
            / digest[:2]
            / digest[2:4]
            / f"{digest}.json"
        )

    @staticmethod
    def _project_root(project_root: Path) -> Path:
        if (
            not isinstance(project_root, Path)
            or not project_root.is_absolute()
            or project_root.is_symlink()
            or _is_reparse_point(project_root)
        ):
            raise Loop9FormalRunEvidenceError(
                "formal run project root is unsafe"
            )
        try:
            resolved = project_root.resolve(strict=True)
        except OSError as exc:
            raise Loop9FormalRunEvidenceError(
                "formal run project root is unavailable"
            ) from exc
        if not resolved.is_dir():
            raise Loop9FormalRunEvidenceError(
                "formal run project root is unsafe"
            )
        return resolved

    def publish(
        self,
        *,
        project_root: Path,
        request: Loop9FormalRunRequest,
    ) -> Loop9FormalRunEvidence:
        """Derive and publish evidence only from current protected records."""

        resolved_project_root = self._project_root(project_root)
        if not isinstance(request, Loop9FormalRunRequest):
            raise Loop9FormalRunEvidenceError(
                "formal run technical identities are invalid"
            )
        derived = _derive_formal_run_evidence(
            project_root=resolved_project_root,
            data_root=self.data_root,
            request=request,
        )
        self.persist(derived)
        return self.load_and_replay(
            derived.canonical_sha256,
            project_root=resolved_project_root,
            request=request,
        )

    def load_and_replay(
        self,
        canonical_sha256: str,
        *,
        project_root: Path,
        request: Loop9FormalRunRequest,
    ) -> Loop9FormalRunEvidence:
        """Reload immutable evidence and independently rederive every field."""

        resolved_project_root = self._project_root(project_root)
        persisted = self.load_persisted(canonical_sha256)
        replayed = _derive_formal_run_evidence(
            project_root=resolved_project_root,
            data_root=self.data_root,
            request=request,
        )
        if (
            replayed.canonical_sha256 != persisted.canonical_sha256
            or replayed.to_payload() != persisted.to_payload()
        ):
            raise Loop9FormalRunEvidenceError(
                "formal run evidence no longer matches source records"
            )
        return replayed

    def persist(self, evidence: Loop9FormalRunEvidence) -> Path:
        if not isinstance(evidence, Loop9FormalRunEvidence):
            raise Loop9FormalRunEvidenceError(
                "formal run evidence object is invalid"
            )
        output = self.path_for(evidence.canonical_sha256)
        output.parent.mkdir(parents=True, exist_ok=True)
        if (
            output.parent.is_symlink()
            or _is_reparse_point(output.parent)
            or output.parent.resolve(strict=True) != output.parent
        ):
            raise Loop9FormalRunEvidenceError(
                "formal run evidence directory is unsafe"
            )
        content = _canonical_bytes(evidence.to_payload()) + b"\n"
        if output.exists():
            existing = self.load_persisted(evidence.canonical_sha256)
            if existing != evidence:
                raise Loop9FormalRunEvidenceError(
                    "formal run evidence identity conflicts"
                )
            return output
        staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
        try:
            with staged.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(staged, output)
            except FileExistsError:
                existing = self.load_persisted(evidence.canonical_sha256)
                if existing != evidence:
                    raise Loop9FormalRunEvidenceError(
                        "formal run evidence identity conflicts"
                    ) from None
            except OSError as exc:
                raise Loop9FormalRunEvidenceError(
                    "formal run evidence could not be published atomically"
                ) from exc
        finally:
            staged.unlink(missing_ok=True)
        return output

    def load_persisted(
        self,
        canonical_sha256: str,
    ) -> Loop9FormalRunEvidence:
        path = self.path_for(canonical_sha256)
        try:
            resolved = path.resolve(strict=True)
            content = resolved.read_bytes()
        except OSError as exc:
            raise Loop9FormalRunEvidenceError(
                "formal run evidence is unavailable"
            ) from exc
        if (
            path.is_symlink()
            or _is_reparse_point(path)
            or not resolved.is_file()
            or resolved != path
            or len(content) > _MAX_FILE_BYTES
        ):
            raise Loop9FormalRunEvidenceError(
                "formal run evidence path is unsafe"
            )
        try:
            raw = json.loads(
                content.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    Loop9FormalRunEvidenceError(
                        f"non-finite JSON value {value} is forbidden"
                    )
                ),
            )
        except (
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise Loop9FormalRunEvidenceError(
                "formal run evidence is unreadable"
            ) from exc
        evidence = Loop9FormalRunEvidence.from_payload(raw)
        if (
            evidence.canonical_sha256 != canonical_sha256
            or content != _canonical_bytes(evidence.to_payload()) + b"\n"
        ):
            raise Loop9FormalRunEvidenceError(
                "formal run evidence is not canonical"
            )
        return evidence
