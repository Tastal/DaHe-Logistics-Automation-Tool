from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from uuid import uuid4

from sqlalchemy import select, update

from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    DAILY_CAPTURE_INVOCATIONS,
    DAILY_MANUAL_REVISION_IDEMPOTENCY,
    DAILY_MANUAL_REVISIONS,
    DAILY_OBSERVATIONS,
    DAILY_OPERATIONAL_OCR_BATCHES,
    DAILY_REPORTS,
    JOBS,
    OCR_RUN_GENERATIONS,
    WORK_ITEMS,
)
from dahe.application.daily.unloading_time import extract_unloading_time
from dahe.domain.daily.models import DailyObservationFields, DailyRecordRevision
from dahe.ports.jobs import IdempotencyConflictError, RecordVersionConflictError

EDITABLE_FIELDS = frozenset(
    {
        "loading_net_tonnes",
        "loading_time",
        "unloading_net_tonnes",
        "unloading_time",
    }
)
_LOADING_FIELDS = frozenset({"loading_net_tonnes", "loading_time"})
_UNLOADING_FIELDS = frozenset({"unloading_net_tonnes", "unloading_time"})


class DailyItemConflictError(RuntimeError):
    """Raised when a daily item or revision cannot be changed safely."""


@dataclass(frozen=True, slots=True)
class DailyItemView:
    machine: DailyRecordRevision
    effective_fields: DailyObservationFields
    field_sources: dict[str, str]
    record_version: int
    updated_at: str
    materialized_at: str


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _request_hash(platform_waybill_id: str, changes: dict[str, object]) -> str:
    return hashlib.sha256(
        _json(
            {
                "changes": changes,
                "platform_waybill_id": platform_waybill_id,
                "schema_version": 1,
            }
        ).encode("utf-8")
    ).hexdigest()


def _record_version(machine_revision: int, manual_revision: int) -> int:
    return machine_revision * 1_000_000 + manual_revision


def _field_payload(fields: DailyObservationFields) -> dict[str, object]:
    return fields.to_payload()


class SqliteDailyItemRepository:
    """Project machine observations with append-only human field revisions."""

    def __init__(self, runtime: SqliteRuntime, daily_store: SqliteDailyStore) -> None:
        self._runtime = runtime
        self._daily_store = daily_store

    def list_items(self, business_date: date) -> tuple[DailyItemView, ...]:
        revisions = self._daily_store.list_latest_revisions_for_business_date_any(
            business_date=business_date
        )
        materialized = self._load_materialized_observations(revisions)
        revisions = tuple(
            revision
            for revision in revisions
            if revision.observation_id in materialized
        )
        outputs = self._load_latest_unloading_outputs(
            tuple(
                waybill_number
                for revision in revisions
                if (waybill_number := revision.waybill_number) is not None
            )
        )
        return tuple(
            self._view_for_machine(
                revision,
                unloading_output=(
                    outputs.get(revision.waybill_number)
                    if revision.waybill_number is not None
                    else None
                ),
                materialized_at=materialized[revision.observation_id],
            )
            for revision in revisions
        )

    def get_item(self, platform_waybill_id: str) -> DailyItemView:
        revisions = self._daily_store.list_revisions(platform_waybill_id)
        if not revisions:
            raise DailyItemConflictError("daily item does not exist")
        machine = revisions[-1]
        materialized = self._load_materialized_observations((machine,))
        if machine.observation_id not in materialized:
            raise DailyItemConflictError("daily item processing is not complete")
        outputs = self._load_latest_unloading_outputs(
            (machine.waybill_number,) if machine.waybill_number is not None else ()
        )
        output = (
            outputs.get(machine.waybill_number)
            if machine.waybill_number is not None
            else None
        )
        return self._view_for_machine(
            machine,
            unloading_output=output,
            materialized_at=materialized[machine.observation_id],
        )

    def effective_revisions(
        self,
        *,
        business_date: date,
        receive_place_keyword: str,
    ) -> tuple[DailyRecordRevision, ...]:
        machine = self._daily_store.list_latest_revisions_for_business_date(
            business_date=business_date,
            receive_place_keyword=receive_place_keyword,
        )
        result: list[DailyRecordRevision] = []
        materialized = self._load_materialized_observations(machine)
        machine = tuple(
            revision
            for revision in machine
            if revision.observation_id in materialized
        )
        outputs = self._load_latest_unloading_outputs(
            tuple(
                waybill_number
                for revision in machine
                if (waybill_number := revision.waybill_number) is not None
            )
        )
        for revision in machine:
            view = self._view_for_machine(
                revision,
                unloading_output=(
                    outputs.get(revision.waybill_number)
                    if revision.waybill_number is not None
                    else None
                ),
                materialized_at=materialized[revision.observation_id],
            )
            result.append(
                DailyRecordRevision(
                    revision_id=revision.revision_id,
                    platform_waybill_id=revision.platform_waybill_id,
                    revision_number=revision.revision_number,
                    observation_id=revision.observation_id,
                    field_fingerprint=revision.field_fingerprint,
                    fields=view.effective_fields,
                    waybill_number=revision.waybill_number,
                    loading_ticket_sha256=revision.loading_ticket_sha256,
                    unloading_ticket_sha256=revision.unloading_ticket_sha256,
                    created_at=revision.created_at,
                )
            )
        return tuple(result)

    def append_revision(
        self,
        *,
        platform_waybill_id: str,
        expected_record_version: int,
        changes: dict[str, object],
        idempotency_key: str,
    ) -> tuple[DailyItemView, bool]:
        if not changes:
            raise DailyItemConflictError("没有需要保存的修改")
        unknown = set(changes) - EDITABLE_FIELDS
        if unknown:
            raise DailyItemConflictError("修改包含不允许的字段")
        request_hash = _request_hash(platform_waybill_id, changes)
        with self._runtime.engine.connect() as connection:
            replay = connection.execute(
                select(DAILY_MANUAL_REVISION_IDEMPOTENCY).where(
                    DAILY_MANUAL_REVISION_IDEMPOTENCY.c.idempotency_key
                    == idempotency_key
                )
            ).mappings().one_or_none()
        if replay is not None:
            if (
                str(replay["request_hash"]) != request_hash
                or str(replay["platform_waybill_id"]) != platform_waybill_id
            ):
                raise IdempotencyConflictError("daily item idempotency key reused")
            return self.get_item(platform_waybill_id), True

        machine = self._daily_store.list_revisions(platform_waybill_id)
        if not machine:
            raise DailyItemConflictError("daily item does not exist")
        current = machine[-1]
        with self._runtime.engine.connect() as connection:
            manual_count = int(
                connection.execute(
                    select(DAILY_MANUAL_REVISIONS.c.manual_revision_number)
                    .where(
                        DAILY_MANUAL_REVISIONS.c.platform_waybill_id
                        == platform_waybill_id
                    )
                    .order_by(
                        DAILY_MANUAL_REVISIONS.c.manual_revision_number.desc()
                    )
                    .limit(1)
                ).scalar_one_or_none()
                or 0
            )
        actual_version = _record_version(current.revision_number, manual_count)
        if expected_record_version != actual_version:
            raise RecordVersionConflictError("daily item changed")

        action_id = uuid4().hex
        created_at = datetime.now(UTC).isoformat()
        new_version = _record_version(current.revision_number, manual_count + 1)
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            connection.execute(
                DAILY_MANUAL_REVISIONS.insert().values(
                    action_id=action_id,
                    platform_waybill_id=platform_waybill_id,
                    manual_revision_number=manual_count + 1,
                    base_observation_id=current.observation_id,
                    base_loading_ticket_sha256=current.loading_ticket_sha256,
                    base_unloading_ticket_sha256=current.unloading_ticket_sha256,
                    changes_json=_json(changes),
                    request_hash=request_hash,
                    created_at=created_at,
                )
            )
            connection.execute(
                DAILY_MANUAL_REVISION_IDEMPOTENCY.insert().values(
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    platform_waybill_id=platform_waybill_id,
                    action_id=action_id,
                    result_record_version=new_version,
                    created_at=created_at,
                )
            )
            connection.execute(
                update(DAILY_REPORTS)
                .where(DAILY_REPORTS.c.business_date == self._business_date(current))
                .values(stale=1, record_version=DAILY_REPORTS.c.record_version + 1)
            )
        return self.get_item(platform_waybill_id), False

    def _business_date(self, revision: DailyRecordRevision) -> str:
        with self._runtime.engine.connect() as connection:
            from dahe.adapters.sqlite.schema import (  # local to avoid a broad import cycle
                DAILY_CANDIDATE_SNAPSHOTS,
                DAILY_OBSERVATIONS,
            )

            value = connection.execute(
                select(DAILY_CANDIDATE_SNAPSHOTS.c.target_business_date)
                .join(
                    DAILY_OBSERVATIONS,
                    DAILY_OBSERVATIONS.c.snapshot_id
                    == DAILY_CANDIDATE_SNAPSHOTS.c.snapshot_id,
                )
                .where(DAILY_OBSERVATIONS.c.observation_id == revision.observation_id)
            ).scalar_one()
        return str(value)

    def business_date_for(self, revision: DailyRecordRevision) -> date:
        """Return the business date associated with a projected item."""

        return date.fromisoformat(self._business_date(revision))

    def _view_for_machine(
        self,
        machine: DailyRecordRevision,
        *,
        unloading_output: tuple[str, str] | None = None,
        materialized_at: str | None = None,
    ) -> DailyItemView:
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(DAILY_MANUAL_REVISIONS)
                    .where(
                        DAILY_MANUAL_REVISIONS.c.platform_waybill_id
                        == machine.platform_waybill_id
                    )
                    .order_by(DAILY_MANUAL_REVISIONS.c.manual_revision_number)
                ).mappings()
            )
        payload = _field_payload(machine.fields)
        sources = {field: "machine" for field in EDITABLE_FIELDS}
        updated_at = machine.created_at.isoformat()
        if payload.get("unloading_time") is None and unloading_output is not None:
            extracted = extract_unloading_time(
                unloading_output[0],
                loading_time=machine.fields.loading_time,
                planned_date=machine.fields.planned_date,
            )
            if extracted is not None:
                payload["unloading_time"] = extracted.isoformat()
                sources["unloading_time"] = "ocr"
                updated_at = unloading_output[1]
        for row in rows:
            try:
                changes = json.loads(str(row["changes_json"]))
            except (TypeError, ValueError) as exc:
                raise DailyItemConflictError("stored daily revision is invalid") from exc
            if not isinstance(changes, dict):
                raise DailyItemConflictError("stored daily revision is invalid")
            loading_valid = row["base_loading_ticket_sha256"] == machine.loading_ticket_sha256
            unloading_valid = (
                row["base_unloading_ticket_sha256"]
                == machine.unloading_ticket_sha256
            )
            for field, value in changes.items():
                valid_for_current_ticket = (
                    field in _LOADING_FIELDS and loading_valid
                ) or (field in _UNLOADING_FIELDS and unloading_valid)
                if valid_for_current_ticket:
                    payload[field] = value
                    sources[field] = "manual"
            updated_at = str(row["created_at"])
        fields = DailyObservationFields.from_payload(payload)
        return DailyItemView(
            machine=machine,
            effective_fields=fields,
            field_sources=sources,
            record_version=_record_version(machine.revision_number, len(rows)),
            updated_at=updated_at,
            materialized_at=materialized_at or machine.created_at.isoformat(),
        )

    def _load_materialized_observations(
        self,
        revisions: tuple[DailyRecordRevision, ...],
    ) -> dict[str, str]:
        """Return only observations whose local machine processing is final."""

        if not revisions:
            return {}
        observation_ids = tuple(revision.observation_id for revision in revisions)
        with self._runtime.engine.connect() as connection:
            observation_rows = tuple(
                connection.execute(
                    select(
                        DAILY_OBSERVATIONS.c.observation_id,
                        DAILY_OBSERVATIONS.c.waybill_number,
                        DAILY_OBSERVATIONS.c.loading_ticket_sha256,
                        DAILY_OBSERVATIONS.c.unloading_ticket_sha256,
                        DAILY_CAPTURE_INVOCATIONS.c.job_id,
                        JOBS.c.status,
                    )
                    .select_from(
                        DAILY_OBSERVATIONS.outerjoin(
                            DAILY_CAPTURE_INVOCATIONS,
                            DAILY_CAPTURE_INVOCATIONS.c.invocation_id
                            == DAILY_OBSERVATIONS.c.snapshot_id,
                        ).outerjoin(
                            JOBS,
                            JOBS.c.job_id == DAILY_CAPTURE_INVOCATIONS.c.job_id,
                        )
                    )
                    .where(DAILY_OBSERVATIONS.c.observation_id.in_(observation_ids))
                ).mappings()
            )
            job_ids = tuple(
                sorted(
                    {
                        str(row["job_id"])
                        for row in observation_rows
                        if row["job_id"] is not None
                    }
                )
            )
            batch_rows = (
                ()
                if not job_ids
                else tuple(
                    connection.execute(
                        select(DAILY_OPERATIONAL_OCR_BATCHES).where(
                            DAILY_OPERATIONAL_OCR_BATCHES.c.daily_job_id.in_(job_ids)
                        )
                    ).mappings()
                )
            )
            ocr_job_to_daily = {
                str(row["ocr_job_id"]): str(row["daily_job_id"])
                for row in batch_rows
                if row["ocr_job_id"] is not None
            }
            processed_rows = (
                ()
                if not ocr_job_to_daily
                else tuple(
                    connection.execute(
                        select(
                            WORK_ITEMS.c.job_id,
                            WORK_ITEMS.c.waybill_number,
                            OCR_RUN_GENERATIONS.c.updated_at,
                        )
                        .join(
                            OCR_RUN_GENERATIONS,
                            OCR_RUN_GENERATIONS.c.work_item_id
                            == WORK_ITEMS.c.work_item_id,
                        )
                        .where(
                            WORK_ITEMS.c.job_id.in_(tuple(ocr_job_to_daily)),
                            WORK_ITEMS.c.status == "succeeded",
                            OCR_RUN_GENERATIONS.c.status == "succeeded",
                        )
                    )
                )
            )
        batches_by_job: dict[str, list[str]] = {}
        for row in batch_rows:
            batches_by_job.setdefault(str(row["daily_job_id"]), []).append(
                str(row["created_at"])
            )
        processed: dict[tuple[str, str], str] = {}
        for ocr_job_id, waybill_number, updated_at in processed_rows:
            daily_job_id = ocr_job_to_daily[str(ocr_job_id)]
            processed[(daily_job_id, str(waybill_number))] = str(updated_at)

        result: dict[str, str] = {}
        revision_created = {
            revision.observation_id: revision.created_at.isoformat()
            for revision in revisions
        }
        for row in observation_rows:
            observation_id = str(row["observation_id"])
            if row["job_id"] is None:
                # Historical and isolated fixtures predate operational OCR links.
                result[observation_id] = revision_created[observation_id]
                continue
            job_id = str(row["job_id"])
            if str(row["status"]) != "succeeded":
                continue
            missing_ticket = (
                row["loading_ticket_sha256"] is None
                or row["unloading_ticket_sha256"] is None
            )
            if missing_ticket and batches_by_job.get(job_id):
                result[observation_id] = max(batches_by_job[job_id])
                continue
            waybill_number = row["waybill_number"]
            if waybill_number is not None:
                processed_at = processed.get((job_id, str(waybill_number)))
                if processed_at is not None:
                    result[observation_id] = processed_at
        return result

    def _load_latest_unloading_outputs(
        self,
        waybill_numbers: tuple[str, ...],
    ) -> dict[str, tuple[str, str]]:
        if not waybill_numbers:
            return {}
        linked_jobs = select(DAILY_OPERATIONAL_OCR_BATCHES.c.ocr_job_id).where(
            DAILY_OPERATIONAL_OCR_BATCHES.c.ocr_job_id.is_not(None)
        )
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(
                        WORK_ITEMS.c.waybill_number,
                        OCR_RUN_GENERATIONS.c.unloading_output_json,
                        OCR_RUN_GENERATIONS.c.updated_at,
                    )
                    .join(
                        OCR_RUN_GENERATIONS,
                        OCR_RUN_GENERATIONS.c.work_item_id
                        == WORK_ITEMS.c.work_item_id,
                    )
                    .where(
                        WORK_ITEMS.c.job_id.in_(linked_jobs),
                        WORK_ITEMS.c.waybill_number.in_(waybill_numbers),
                        OCR_RUN_GENERATIONS.c.status == "succeeded",
                        OCR_RUN_GENERATIONS.c.unloading_output_json.is_not(None),
                    )
                    .order_by(OCR_RUN_GENERATIONS.c.updated_at.desc())
                )
            )
        result: dict[str, tuple[str, str]] = {}
        for waybill_number, output_json, updated_at in rows:
            key = str(waybill_number)
            if key not in result:
                result[key] = (str(output_json), str(updated_at))
        return result
