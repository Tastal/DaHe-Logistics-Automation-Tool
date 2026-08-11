from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.engine import RowMapping

from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditError,
    PlatformReadAuditEvidenceStore,
)
from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationConflictError,
    SqliteDailyInvocationStore,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    DAILY_CANDIDATE_SNAPSHOTS,
    DAILY_CAPTURE_INVOCATIONS,
    DAILY_OBSERVATIONS,
    DAILY_RECORD_REVISIONS,
    JOBS,
    PLATFORM_ACCESS_WINDOWS,
    WORK_ITEMS,
)
from dahe.application.daily.capture import (
    DailyCaptureCheckpoint,
    DailyCaptureError,
    DailyCaptureRequest,
)
from dahe.domain.daily.calendar import SHANGHAI
from dahe.domain.daily.models import (
    DailyCandidateSnapshot,
    DailyRecordRevision,
    DailyWaybillObservation,
    canonical_json,
    revision_id_for,
)
from dahe.ports.daily import (
    DailyObservationSaveResult,
    DailySnapshotCaptureAuthority,
    DailySnapshotSaveResult,
)


class DailyStoreConflictError(RuntimeError):
    """Raised when immutable daily data conflicts with durable state."""


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("daily timestamps must be timezone-aware")
    return value.astimezone(SHANGHAI).isoformat()


def _payload(row: RowMapping) -> object:
    try:
        return json.loads(str(row["payload_json"]))
    except (TypeError, ValueError) as exc:
        raise DailyStoreConflictError("stored daily payload is invalid") from exc


def _snapshot(row: RowMapping) -> DailyCandidateSnapshot:
    snapshot = DailyCandidateSnapshot.from_payload(_payload(row))
    if snapshot.fingerprint != str(row["fingerprint"]):
        raise DailyStoreConflictError("stored daily snapshot fingerprint is invalid")
    return snapshot


def _observation(row: RowMapping) -> DailyWaybillObservation:
    observation = DailyWaybillObservation.from_payload(_payload(row))
    if observation.fingerprint != str(row["observation_fingerprint"]):
        raise DailyStoreConflictError(
            "stored daily observation fingerprint is invalid"
        )
    if observation.field_fingerprint != str(row["field_fingerprint"]):
        raise DailyStoreConflictError(
            "stored daily observation field fingerprint is invalid"
        )
    return observation


def _revision(row: RowMapping) -> DailyRecordRevision:
    revision = DailyRecordRevision.from_payload(_payload(row))
    if revision.revision_id != str(row["revision_id"]):
        raise DailyStoreConflictError("stored daily revision identity is invalid")
    if revision.field_fingerprint != str(row["field_fingerprint"]):
        raise DailyStoreConflictError(
            "stored daily revision field fingerprint is invalid"
        )
    return revision


class SqliteDailyStore:
    """Append-only store for Loop 9 loading and unloading observations."""

    def __init__(self, runtime: SqliteRuntime) -> None:
        self._engine = runtime.engine
        self._commit_gate = runtime.commit_gate
        self._request_audit = PlatformReadAuditEvidenceStore(
            runtime.data_root
        )
        self._invocations = SqliteDailyInvocationStore(runtime)

    def save_snapshot(
        self,
        snapshot: DailyCandidateSnapshot,
    ) -> DailySnapshotSaveResult:
        with self._commit_gate.transaction(self._engine) as connection:
            existing = (
                connection.execute(
                    select(DAILY_CANDIDATE_SNAPSHOTS).where(
                        DAILY_CANDIDATE_SNAPSHOTS.c.snapshot_id
                        == snapshot.snapshot_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                stored = _snapshot(existing)
                if stored.fingerprint != snapshot.fingerprint:
                    raise DailyStoreConflictError(
                        "daily snapshot identity has different content"
                    )
                return DailySnapshotSaveResult(
                    snapshot=stored,
                    replayed=True,
                )

            connection.execute(
                DAILY_CANDIDATE_SNAPSHOTS.insert().values(
                    snapshot_id=snapshot.snapshot_id,
                    target_business_date=(
                        snapshot.target_business_date.isoformat()
                    ),
                    query_started_at=_timestamp(snapshot.query_window.start),
                    query_ended_at=_timestamp(snapshot.query_window.end),
                    query_safety_ended_at=_timestamp(
                        snapshot.query_window.safety_end
                    ),
                    source_contract_sha256=snapshot.source_contract_sha256,
                    candidate_count=len(snapshot.candidates),
                    payload_json=canonical_json(snapshot.to_payload()),
                    fingerprint=snapshot.fingerprint,
                    captured_at=_timestamp(snapshot.captured_at),
                )
            )
            return DailySnapshotSaveResult(
                snapshot=snapshot,
                replayed=False,
            )

    def get_snapshot(self, snapshot_id: str) -> DailyCandidateSnapshot:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(DAILY_CANDIDATE_SNAPSHOTS).where(
                        DAILY_CANDIDATE_SNAPSHOTS.c.snapshot_id
                        == snapshot_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise DailyStoreConflictError("daily snapshot does not exist")
        return _snapshot(row)

    def get_formal_snapshot_authority(
        self,
        snapshot_id: str,
    ) -> DailySnapshotCaptureAuthority:
        """Load and verify the durable capture chain for one snapshot."""

        with self._engine.connect() as connection:
            snapshot_row = (
                connection.execute(
                    select(DAILY_CANDIDATE_SNAPSHOTS).where(
                        DAILY_CANDIDATE_SNAPSHOTS.c.snapshot_id
                        == snapshot_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            invocation_row = (
                connection.execute(
                    select(DAILY_CAPTURE_INVOCATIONS).where(
                        DAILY_CAPTURE_INVOCATIONS.c.invocation_id
                        == snapshot_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if snapshot_row is None:
                raise DailyStoreConflictError(
                    "daily snapshot does not exist"
                )
            if invocation_row is None:
                raise DailyStoreConflictError(
                    "daily snapshot has no capture invocation"
                )
            job_id = str(invocation_row["job_id"])
            access_window_id = str(
                invocation_row["access_window_id"]
            )
            job_row = (
                connection.execute(
                    select(JOBS).where(JOBS.c.job_id == job_id)
                )
                .mappings()
                .one_or_none()
            )
            access_row = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == access_window_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            work_rows = tuple(
                connection.execute(
                    select(
                        WORK_ITEMS.c.status,
                        WORK_ITEMS.c.current_stage,
                    ).where(WORK_ITEMS.c.job_id == job_id)
                ).mappings()
            )
            observation_count = int(
                connection.execute(
                    select(func.count()).select_from(
                        DAILY_OBSERVATIONS
                    ).where(
                        DAILY_OBSERVATIONS.c.snapshot_id
                        == snapshot_id
                    )
                ).scalar_one()
            )
        if job_row is None or access_row is None:
            raise DailyStoreConflictError(
                "daily snapshot capture authority is incomplete"
            )
        snapshot = _snapshot(snapshot_row)
        try:
            request = DailyCaptureRequest.from_payload(
                json.loads(str(invocation_row["request_json"]))
            )
            checkpoint = (
                None
                if invocation_row["checkpoint_json"] is None
                else DailyCaptureCheckpoint.from_payload(
                    json.loads(
                        str(invocation_row["checkpoint_json"])
                    )
                )
            )
            lineage = self._invocations.access_window_lineage(job_id)
        except (
            DailyCaptureError,
            DailyInvocationConflictError,
            TypeError,
            ValueError,
        ) as exc:
            raise DailyStoreConflictError(
                "stored daily invocation request is invalid"
            ) from exc
        if (
            request.invocation_id != snapshot_id
            or request.fingerprint
            != str(invocation_row["request_fingerprint"])
            or request.business_date != snapshot.target_business_date
            or request.receive_place != snapshot.receive_place
            or str(access_row["job_id"]) != job_id
            or str(job_row["job_id"]) != job_id
            or str(job_row["task_type"]) != "daily"
            or str(job_row["job_kind"]) != "business"
            or checkpoint is None
            or checkpoint.snapshot is None
            or checkpoint.snapshot.snapshot_id != snapshot_id
            or checkpoint.completed_observation_count
            != len(snapshot.candidates)
        ):
            raise DailyStoreConflictError(
                "daily snapshot capture authority is inconsistent"
            )
        try:
            request_audit = self._request_audit.load_sealed_for_job(
                job_id=job_id
            )
        except PlatformReadAuditError as exc:
            raise DailyStoreConflictError(
                "daily snapshot request audit is unavailable"
            ) from exc
        if (
            request_audit.purpose != "daily_snapshot"
            or request_audit.authority.build_sha256
            != str(access_row["build_sha256"])
            or request_audit.authority.daily_contract_sha256
            != request.source_contract_sha256
            or len(checkpoint.completed_detail_captures)
            != len(snapshot.candidates)
        ):
            raise DailyStoreConflictError(
                "daily snapshot request audit authority changed"
            )
        read_access: dict[str, str] = {
            f"list:{index}": access_id
            for index, access_id in enumerate(
                checkpoint.list_read_access_window_ids,
                start=1,
            )
        }
        for capture in checkpoint.completed_detail_captures:
            identity = hashlib.sha256(
                capture.platform_waybill_id.encode("utf-8")
            ).hexdigest()
            read_access.update(
                {
                    f"detail:{identity}:{index}": access_id
                    for index, access_id in enumerate(
                        capture.detail_read_access_window_ids,
                        start=1,
                    )
                }
            )
            read_access.update(
                {
                    f"image:{identity}:{slot}": access_id
                    for slot, access_id in (
                        capture.image_read_access_window_ids
                    )
                }
            )
        raw_expected_counts = {
            "list_daily_waybills": len(
                checkpoint.list_read_access_window_ids
            ),
            "get_waybill_detail": sum(
                capture.detail_read_count
                for capture in checkpoint.completed_detail_captures
            ),
            "download_ticket_image": sum(
                capture.image_read_count
                for capture in checkpoint.completed_detail_captures
            ),
        }
        expected_counts = {
            operation: count
            for operation, count in raw_expected_counts.items()
            if count
        }
        if (
            not read_access
            or not set(read_access.values()).issubset(
                set(lineage.access_window_ids)
            )
            or dict(
                request_audit.expected_succeeded_operations
            )
            != expected_counts
        ):
            raise DailyStoreConflictError(
                "daily snapshot request lineage is inconsistent"
            )
        return DailySnapshotCaptureAuthority(
            snapshot=snapshot,
            invocation_id=str(invocation_row["invocation_id"]),
            job_id=job_id,
            access_window_id=access_window_id,
            access_window_ids=lineage.access_window_ids,
            read_access_window_ids=read_access,
            capture_build_sha256=str(access_row["build_sha256"]),
            access_purpose=str(access_row["purpose"]),
            access_consumed=access_row["consumed_at"] is not None,
            invocation_contract_sha256=(
                request.source_contract_sha256
            ),
            invocation_status=str(invocation_row["status"]),
            invocation_next_stage=str(invocation_row["next_stage"]),
            invocation_diagnostic_code=(
                None
                if invocation_row["diagnostic_code"] is None
                else str(invocation_row["diagnostic_code"])
            ),
            job_status=str(job_row["status"]),
            job_current_stage=(
                None
                if job_row["current_stage"] is None
                else str(job_row["current_stage"])
            ),
            job_diagnostic_code=(
                None
                if job_row["diagnostic_code"] is None
                else str(job_row["diagnostic_code"])
            ),
            work_item_count=len(work_rows),
            succeeded_work_item_count=sum(
                row["status"] == "succeeded" for row in work_rows
            ),
            completed_stage_work_item_count=sum(
                row["current_stage"] == "daily.complete"
                for row in work_rows
            ),
            observation_count=observation_count,
            request_audit_sha256=request_audit.canonical_sha256,
            request_audit_job_id_sha256=(
                request_audit.job_id_sha256
            ),
            request_audit_purpose=request_audit.purpose,
            request_audit_authority=(
                request_audit.authority.to_payload()
            ),
            request_audit_request_counts=(
                request_audit.request_counts.to_payload()
            ),
            request_audit_operation_counts={
                operation: counts.to_payload()
                for operation, counts in (
                    request_audit.operation_counts.items()
                )
            },
            request_audit_event_count=request_audit.event_count,
            request_audit_event_chain_sha256=(
                request_audit.event_chain_sha256
            ),
            request_audit_expected_succeeded_operations=dict(
                request_audit.expected_succeeded_operations
            ),
            request_audit_kind=request_audit.kind,
            request_audit_schema_version=request_audit.schema_version,
            forbidden_request_count=(
                request_audit.request_counts.denied
            ),
            platform_write_request_count=(
                request_audit.platform_write_request_count
            ),
            redirect_count=request_audit.redirect_count,
        )

    def list_snapshot_observations(
        self,
        snapshot_id: str,
    ) -> tuple[DailyWaybillObservation, ...]:
        """Read one immutable snapshot's observations in stable identity order."""

        snapshot = self.get_snapshot(snapshot_id)
        with self._engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(DAILY_OBSERVATIONS)
                    .where(
                        DAILY_OBSERVATIONS.c.snapshot_id == snapshot_id
                    )
                    .order_by(
                        DAILY_OBSERVATIONS.c.platform_waybill_id,
                        DAILY_OBSERVATIONS.c.observation_id,
                    )
                ).mappings()
            )
        observations = tuple(_observation(row) for row in rows)
        if (
            len(observations) != len(snapshot.candidates)
            or {
                observation.platform_waybill_id
                for observation in observations
            }
            != {
                candidate.platform_waybill_id
                for candidate in snapshot.candidates
            }
        ):
            raise DailyStoreConflictError(
                "daily snapshot observation inventory is incomplete"
            )
        return observations

    def save_observation(
        self,
        observation: DailyWaybillObservation,
    ) -> DailyObservationSaveResult:
        with self._commit_gate.transaction(self._engine) as connection:
            existing = (
                connection.execute(
                    select(DAILY_OBSERVATIONS).where(
                        DAILY_OBSERVATIONS.c.observation_id
                        == observation.observation_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                stored = _observation(existing)
                if stored.fingerprint != observation.fingerprint:
                    raise DailyStoreConflictError(
                        "daily observation identity has different content"
                    )
                applied_revision = self._revision_for_observation(
                    connection,
                    existing,
                )
                if applied_revision is None:
                    raise DailyStoreConflictError(
                        "stored daily observation has no record revision"
                    )
                return DailyObservationSaveResult(
                    observation=stored,
                    revision=applied_revision,
                    replayed=True,
                    revision_appended=False,
                )

            snapshot_row = (
                connection.execute(
                    select(DAILY_CANDIDATE_SNAPSHOTS).where(
                        DAILY_CANDIDATE_SNAPSHOTS.c.snapshot_id
                        == observation.snapshot_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if snapshot_row is None:
                raise DailyStoreConflictError("daily snapshot does not exist")
            snapshot = _snapshot(snapshot_row)
            candidate_ids = {
                candidate.platform_waybill_id
                for candidate in snapshot.candidates
            }
            if observation.platform_waybill_id not in candidate_ids:
                raise DailyStoreConflictError(
                    "daily observation is not part of its snapshot"
                )
            if observation.observed_at < snapshot.captured_at:
                raise DailyStoreConflictError(
                    "daily observation predates its snapshot"
                )

            connection.execute(
                DAILY_OBSERVATIONS.insert().values(
                    observation_id=observation.observation_id,
                    snapshot_id=observation.snapshot_id,
                    platform_waybill_id=observation.platform_waybill_id,
                    waybill_number=observation.waybill_number,
                    source_detail_sha256=observation.source_detail_sha256,
                    loading_ticket_sha256=observation.loading_ticket_sha256,
                    unloading_ticket_sha256=(
                        observation.unloading_ticket_sha256
                    ),
                    field_fingerprint=observation.field_fingerprint,
                    payload_json=canonical_json(observation.to_payload()),
                    observation_fingerprint=observation.fingerprint,
                    observed_at=_timestamp(observation.observed_at),
                )
            )

            latest = self._latest_revision(
                connection,
                observation.platform_waybill_id,
            )
            if (
                latest is not None
                and latest.field_fingerprint
                == observation.field_fingerprint
            ):
                return DailyObservationSaveResult(
                    observation=observation,
                    revision=latest,
                    replayed=False,
                    revision_appended=False,
                )

            revision_number = (
                1 if latest is None else latest.revision_number + 1
            )
            revision = DailyRecordRevision(
                revision_id=revision_id_for(
                    platform_waybill_id=observation.platform_waybill_id,
                    revision_number=revision_number,
                    field_fingerprint=observation.field_fingerprint,
                ),
                platform_waybill_id=observation.platform_waybill_id,
                revision_number=revision_number,
                observation_id=observation.observation_id,
                field_fingerprint=observation.field_fingerprint,
                fields=observation.fields,
                waybill_number=observation.waybill_number,
                loading_ticket_sha256=observation.loading_ticket_sha256,
                unloading_ticket_sha256=(
                    observation.unloading_ticket_sha256
                ),
                created_at=observation.observed_at,
            )
            connection.execute(
                DAILY_RECORD_REVISIONS.insert().values(
                    revision_id=revision.revision_id,
                    platform_waybill_id=revision.platform_waybill_id,
                    revision_number=revision.revision_number,
                    observation_id=revision.observation_id,
                    field_fingerprint=revision.field_fingerprint,
                    payload_json=canonical_json(revision.to_payload()),
                    created_at=_timestamp(revision.created_at),
                )
            )
            return DailyObservationSaveResult(
                observation=observation,
                revision=revision,
                replayed=False,
                revision_appended=True,
            )

    def list_revisions(
        self,
        platform_waybill_id: str,
    ) -> tuple[DailyRecordRevision, ...]:
        with self._engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(DAILY_RECORD_REVISIONS)
                    .where(
                        DAILY_RECORD_REVISIONS.c.platform_waybill_id
                        == platform_waybill_id
                    )
                    .order_by(
                        DAILY_RECORD_REVISIONS.c.revision_number
                    )
                ).mappings()
            )
        return tuple(_revision(row) for row in rows)

    def list_latest_revisions_for_business_date(
        self,
        *,
        business_date: date,
        receive_place_keyword: str,
    ) -> tuple[DailyRecordRevision, ...]:
        keyword = receive_place_keyword.strip()
        if not keyword:
            raise ValueError("receive_place_keyword is required")
        with self._engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(DAILY_RECORD_REVISIONS)
                    .join(
                        DAILY_OBSERVATIONS,
                        DAILY_OBSERVATIONS.c.observation_id
                        == DAILY_RECORD_REVISIONS.c.observation_id,
                    )
                    .join(
                        DAILY_CANDIDATE_SNAPSHOTS,
                        DAILY_CANDIDATE_SNAPSHOTS.c.snapshot_id
                        == DAILY_OBSERVATIONS.c.snapshot_id,
                    )
                    .where(
                        DAILY_CANDIDATE_SNAPSHOTS.c.target_business_date
                        == business_date.isoformat(),
                        DAILY_CANDIDATE_SNAPSHOTS.c.payload_json.contains(
                            keyword
                        ),
                    )
                    .order_by(
                        DAILY_RECORD_REVISIONS.c.platform_waybill_id,
                        DAILY_RECORD_REVISIONS.c.revision_number.desc(),
                    )
                ).mappings()
            )
        latest: dict[str, DailyRecordRevision] = {}
        for row in rows:
            revision = _revision(row)
            latest.setdefault(revision.platform_waybill_id, revision)
        return tuple(latest[key] for key in sorted(latest))

    def list_latest_revisions_for_business_date_any(
        self,
        *,
        business_date: date,
    ) -> tuple[DailyRecordRevision, ...]:
        """Return the latest machine revision for every waybill in one day."""

        with self._engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(DAILY_RECORD_REVISIONS)
                    .join(
                        DAILY_OBSERVATIONS,
                        DAILY_OBSERVATIONS.c.observation_id
                        == DAILY_RECORD_REVISIONS.c.observation_id,
                    )
                    .join(
                        DAILY_CANDIDATE_SNAPSHOTS,
                        DAILY_CANDIDATE_SNAPSHOTS.c.snapshot_id
                        == DAILY_OBSERVATIONS.c.snapshot_id,
                    )
                    .where(
                        DAILY_CANDIDATE_SNAPSHOTS.c.target_business_date
                        == business_date.isoformat()
                    )
                    .order_by(
                        DAILY_RECORD_REVISIONS.c.platform_waybill_id,
                        DAILY_RECORD_REVISIONS.c.revision_number.desc(),
                    )
                ).mappings()
            )
        latest: dict[str, DailyRecordRevision] = {}
        for row in rows:
            revision = _revision(row)
            latest.setdefault(revision.platform_waybill_id, revision)
        return tuple(latest[key] for key in sorted(latest))

    @staticmethod
    def _latest_revision(
        connection: Any,
        platform_waybill_id: str,
    ) -> DailyRecordRevision | None:
        row: RowMapping | None = (
            connection.execute(
                select(DAILY_RECORD_REVISIONS)
                .where(
                    DAILY_RECORD_REVISIONS.c.platform_waybill_id
                    == platform_waybill_id
                )
                .order_by(
                    DAILY_RECORD_REVISIONS.c.revision_number.desc()
                )
                .limit(1)
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _revision(row)

    @staticmethod
    def _revision_for_observation(
        connection: Any,
        observation: RowMapping,
    ) -> DailyRecordRevision | None:
        direct: RowMapping | None = (
            connection.execute(
                select(DAILY_RECORD_REVISIONS).where(
                    DAILY_RECORD_REVISIONS.c.observation_id
                    == observation["observation_id"]
                )
            )
            .mappings()
            .one_or_none()
        )
        if direct is not None:
            return _revision(direct)
        inherited: RowMapping | None = (
            connection.execute(
                select(DAILY_RECORD_REVISIONS)
                .where(
                    DAILY_RECORD_REVISIONS.c.platform_waybill_id
                    == observation["platform_waybill_id"],
                    DAILY_RECORD_REVISIONS.c.field_fingerprint
                    == observation["field_fingerprint"],
                    DAILY_RECORD_REVISIONS.c.created_at
                    <= observation["observed_at"],
                )
                .order_by(
                    DAILY_RECORD_REVISIONS.c.revision_number.desc()
                )
                .limit(1)
            )
            .mappings()
            .one_or_none()
        )
        return None if inherited is None else _revision(inherited)
