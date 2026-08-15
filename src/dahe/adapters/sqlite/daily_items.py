from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
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
    OPERATIONAL_CAPTURE_RUNS,
    OPERATIONAL_REVIEW_LINKS,
    PLATFORM_JOB_SUBJECTS,
    WORK_ITEMS,
)
from dahe.application.daily.unloading_time import (
    extract_loading_time,
    extract_unloading_time,
)
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


@dataclass(frozen=True, slots=True)
class DailySourceContext:
    source_job_id: str
    source_record_version: int
    capture_mode: str
    online_capture_complete: bool


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _request_hash(
    contract_subject_code: str,
    platform_waybill_id: str,
    changes: dict[str, object],
) -> str:
    return hashlib.sha256(
        _json(
            {
                "changes": changes,
                "contract_subject_code": contract_subject_code,
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

    def list_items(
        self,
        business_date: date,
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> tuple[DailyItemView, ...]:
        source = self.latest_source_context(
            business_date,
            contract_subject_code=contract_subject_code,
        )
        revisions = self._daily_store.list_latest_revisions_for_business_date_any(
            business_date=business_date,
            contract_subject_code=contract_subject_code,
        )
        if (
            source is not None
            and source.capture_mode == "whole_run_v1"
            and source.online_capture_complete
        ):
            current_observations = self._daily_store.list_snapshot_observations(
                source.source_job_id
            )
            revision_by_waybill = {
                revision.platform_waybill_id: revision
                for revision in revisions
            }
            revisions = tuple(
                replace(
                    revision,
                    observation_id=observation.observation_id,
                    fields=observation.fields,
                    waybill_number=observation.waybill_number,
                    loading_ticket_sha256=observation.loading_ticket_sha256,
                    unloading_ticket_sha256=(
                        observation.unloading_ticket_sha256
                    ),
                    created_at=observation.observed_at,
                )
                for observation in current_observations
                if (
                    (revision := revision_by_waybill.get(
                        observation.platform_waybill_id
                    ))
                    is not None
                    and revision.field_fingerprint
                    == observation.field_fingerprint
                )
            )
        materialized = self._load_materialized_observations(
            revisions,
            source_job_id=(None if source is None else source.source_job_id),
        )
        revisions = tuple(
            revision
            for revision in revisions
            if revision.observation_id in materialized
        )
        if source is not None and source.capture_mode == "whole_run_v1":
            source_order = self._whole_run_waybill_order(source.source_job_id)
            revisions = tuple(
                sorted(
                    revisions,
                    key=lambda revision: source_order.get(
                        revision.waybill_number or "",
                        len(source_order),
                    ),
                )
            )
        outputs = self._load_latest_ocr_outputs(
            tuple(
                waybill_number
                for revision in revisions
                if (waybill_number := revision.waybill_number) is not None
            ),
            contract_subject_code=contract_subject_code,
        )
        return tuple(
            self._view_for_machine(
                revision,
                ocr_outputs=(
                    outputs.get(revision.waybill_number)
                    if revision.waybill_number is not None
                    else None
                ),
                materialized_at=materialized[revision.observation_id],
                contract_subject_code=contract_subject_code,
            )
            for revision in revisions
        )

    def latest_source_context(
        self,
        business_date: date,
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> DailySourceContext | None:
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(
                        DAILY_CAPTURE_INVOCATIONS.c.job_id,
                        DAILY_CAPTURE_INVOCATIONS.c.request_json,
                        JOBS.c.record_version,
                        JOBS.c.status,
                        JOBS.c.scope_fixture_id,
                        JOBS.c.created_sequence,
                    )
                    .join(JOBS, JOBS.c.job_id == DAILY_CAPTURE_INVOCATIONS.c.job_id)
                    .join(
                        PLATFORM_JOB_SUBJECTS,
                        PLATFORM_JOB_SUBJECTS.c.job_id == JOBS.c.job_id,
                    )
                    .where(JOBS.c.task_type == "daily")
                    .where(
                        PLATFORM_JOB_SUBJECTS.c.contract_subject_code
                        == contract_subject_code
                    )
                    .order_by(JOBS.c.created_sequence.desc(), JOBS.c.created_at.desc())
                ).mappings()
            )
            selected = next(
                (
                    row
                    for row in rows
                    if json.loads(str(row["request_json"])).get("business_date")
                    == business_date.isoformat()
                ),
                None,
            )
            if selected is None:
                return None
            source_job_id = str(selected["job_id"])
            capture = connection.execute(
                select(
                    OPERATIONAL_CAPTURE_RUNS.c.capture_mode,
                    OPERATIONAL_CAPTURE_RUNS.c.status,
                ).where(OPERATIONAL_CAPTURE_RUNS.c.job_id == source_job_id)
            ).mappings().one_or_none()
        return DailySourceContext(
            source_job_id=source_job_id,
            source_record_version=int(selected["record_version"]),
            capture_mode=(
                "whole_run_v1"
                if capture is None
                and str(selected["scope_fixture_id"]).startswith(
                    "daily-operational-whole-run-v1:"
                )
                else "batch_v1"
                if capture is None
                else str(capture["capture_mode"])
            ),
            online_capture_complete=bool(
                str(selected["status"]) == "succeeded"
                and capture is not None
                and str(capture["status"]) == "complete"
            ),
        )

    def get_item(
        self,
        platform_waybill_id: str,
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> DailyItemView:
        revisions = self._daily_store.list_revisions(
            platform_waybill_id,
            contract_subject_code=contract_subject_code,
        )
        if not revisions:
            raise DailyItemConflictError("daily item does not exist")
        machine = revisions[-1]
        materialized = self._load_materialized_observations((machine,))
        if machine.observation_id not in materialized:
            raise DailyItemConflictError("daily item processing is not complete")
        outputs = self._load_latest_ocr_outputs(
            (machine.waybill_number,) if machine.waybill_number is not None else (),
            contract_subject_code=contract_subject_code,
        )
        output = (
            outputs.get(machine.waybill_number)
            if machine.waybill_number is not None
            else None
        )
        return self._view_for_machine(
            machine,
            ocr_outputs=output,
            materialized_at=materialized[machine.observation_id],
            contract_subject_code=contract_subject_code,
        )

    def effective_revisions(
        self,
        *,
        business_date: date,
        receive_place_keyword: str,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> tuple[DailyRecordRevision, ...]:
        machine = self._daily_store.list_latest_revisions_for_business_date(
            business_date=business_date,
            receive_place_keyword=receive_place_keyword,
            contract_subject_code=contract_subject_code,
        )
        result: list[DailyRecordRevision] = []
        materialized = self._load_materialized_observations(machine)
        machine = tuple(
            revision
            for revision in machine
            if revision.observation_id in materialized
        )
        outputs = self._load_latest_ocr_outputs(
            tuple(
                waybill_number
                for revision in machine
                if (waybill_number := revision.waybill_number) is not None
            ),
            contract_subject_code=contract_subject_code,
        )
        for revision in machine:
            view = self._view_for_machine(
                revision,
                ocr_outputs=(
                    outputs.get(revision.waybill_number)
                    if revision.waybill_number is not None
                    else None
                ),
                materialized_at=materialized[revision.observation_id],
                contract_subject_code=contract_subject_code,
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

    def manual_loading_time_ids(
        self,
        revisions: tuple[DailyRecordRevision, ...],
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> frozenset[str]:
        """Return waybills whose effective loading time was explicitly reviewed."""

        if not revisions:
            return frozenset()
        identities = tuple(revision.platform_waybill_id for revision in revisions)
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(
                        DAILY_MANUAL_REVISIONS.c.platform_waybill_id,
                        DAILY_MANUAL_REVISIONS.c.changes_json,
                    )
                    .where(
                        DAILY_MANUAL_REVISIONS.c.platform_waybill_id.in_(identities),
                        DAILY_MANUAL_REVISIONS.c.contract_subject_code
                        == contract_subject_code,
                    )
                    .order_by(
                        DAILY_MANUAL_REVISIONS.c.platform_waybill_id,
                        DAILY_MANUAL_REVISIONS.c.manual_revision_number,
                    )
                ).mappings()
            )
        result: set[str] = set()
        for row in rows:
            payload = json.loads(str(row["changes_json"]))
            if isinstance(payload, dict) and "loading_time" in payload:
                result.add(str(row["platform_waybill_id"]))
        return frozenset(result)

    def primary_loading_time_ids(
        self,
        revisions: tuple[DailyRecordRevision, ...],
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> frozenset[str]:
        """Return waybills whose effective loading time came from OCR or review."""

        result = set(
            self.manual_loading_time_ids(
                revisions,
                contract_subject_code=contract_subject_code,
            )
        )
        outputs = self._load_latest_ocr_outputs(
            tuple(
                waybill_number
                for revision in revisions
                if (waybill_number := revision.waybill_number) is not None
            ),
            contract_subject_code=contract_subject_code,
        )
        for revision in revisions:
            if revision.waybill_number is None:
                continue
            output = outputs.get(revision.waybill_number)
            if output is None:
                continue
            if extract_loading_time(
                output[0],
                platform_loading_time=revision.fields.loading_time,
                planned_date=revision.fields.planned_date,
            ) is not None:
                result.add(revision.platform_waybill_id)
        return frozenset(result)

    def append_revision(
        self,
        *,
        platform_waybill_id: str,
        expected_record_version: int,
        changes: dict[str, object],
        idempotency_key: str,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> tuple[DailyItemView, bool]:
        if not changes:
            raise DailyItemConflictError("没有需要保存的修改")
        unknown = set(changes) - EDITABLE_FIELDS
        if unknown:
            raise DailyItemConflictError("修改包含不允许的字段")
        request_hash = _request_hash(
            contract_subject_code,
            platform_waybill_id,
            changes,
        )
        with self._runtime.engine.connect() as connection:
            replay = connection.execute(
                select(DAILY_MANUAL_REVISION_IDEMPOTENCY).where(
                    DAILY_MANUAL_REVISION_IDEMPOTENCY.c.idempotency_key
                    == idempotency_key,
                    DAILY_MANUAL_REVISION_IDEMPOTENCY.c.contract_subject_code
                    == contract_subject_code,
                )
            ).mappings().one_or_none()
        if replay is not None:
            if (
                str(replay["request_hash"]) != request_hash
                or str(replay["platform_waybill_id"]) != platform_waybill_id
            ):
                raise IdempotencyConflictError("daily item idempotency key reused")
            return self.get_item(
                platform_waybill_id,
                contract_subject_code=contract_subject_code,
            ), True

        machine = self._daily_store.list_revisions(
            platform_waybill_id,
            contract_subject_code=contract_subject_code,
        )
        if not machine:
            raise DailyItemConflictError("daily item does not exist")
        current = machine[-1]
        with self._runtime.engine.connect() as connection:
            manual_count = int(
                connection.execute(
                    select(DAILY_MANUAL_REVISIONS.c.manual_revision_number)
                    .where(
                        DAILY_MANUAL_REVISIONS.c.platform_waybill_id
                        == platform_waybill_id,
                        DAILY_MANUAL_REVISIONS.c.contract_subject_code
                        == contract_subject_code,
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
                    contract_subject_code=contract_subject_code,
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
                    contract_subject_code=contract_subject_code,
                    request_hash=request_hash,
                    platform_waybill_id=platform_waybill_id,
                    action_id=action_id,
                    result_record_version=new_version,
                    created_at=created_at,
                )
            )
            connection.execute(
                update(DAILY_REPORTS)
                .where(
                    DAILY_REPORTS.c.business_date == self._business_date(current),
                    DAILY_REPORTS.c.contract_subject_code
                    == contract_subject_code,
                )
                .values(stale=1, record_version=DAILY_REPORTS.c.record_version + 1)
            )
        return self.get_item(
            platform_waybill_id,
            contract_subject_code=contract_subject_code,
        ), False

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
        ocr_outputs: tuple[str | None, str | None, str] | None = None,
        materialized_at: str | None = None,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> DailyItemView:
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(DAILY_MANUAL_REVISIONS)
                    .where(
                        DAILY_MANUAL_REVISIONS.c.platform_waybill_id
                        == machine.platform_waybill_id,
                        DAILY_MANUAL_REVISIONS.c.contract_subject_code
                        == contract_subject_code,
                    )
                    .order_by(DAILY_MANUAL_REVISIONS.c.manual_revision_number)
                ).mappings()
            )
        payload = _field_payload(machine.fields)
        sources = {field: "machine" for field in EDITABLE_FIELDS}
        updated_at = machine.created_at.isoformat()
        loading_output = None if ocr_outputs is None else ocr_outputs[0]
        unloading_output = None if ocr_outputs is None else ocr_outputs[1]
        outputs_updated_at = None if ocr_outputs is None else ocr_outputs[2]
        if loading_output is not None:
            extracted_loading = extract_loading_time(
                loading_output,
                platform_loading_time=machine.fields.loading_time,
                planned_date=machine.fields.planned_date,
            )
            if extracted_loading is not None:
                payload["loading_time"] = extracted_loading.isoformat()
                sources["loading_time"] = "ocr"
                assert outputs_updated_at is not None
                updated_at = outputs_updated_at
        if payload.get("unloading_time") is None and unloading_output is not None:
            effective_loading_time = DailyObservationFields.from_payload(
                payload
            ).loading_time
            extracted = extract_unloading_time(
                unloading_output,
                loading_time=effective_loading_time,
                planned_date=machine.fields.planned_date,
            )
            if extracted is not None:
                payload["unloading_time"] = extracted.isoformat()
                sources["unloading_time"] = "ocr"
                assert outputs_updated_at is not None
                updated_at = outputs_updated_at
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
        *,
        source_job_id: str | None = None,
    ) -> dict[str, str]:
        """Return only observations whose local machine processing is final."""

        if not revisions:
            return {}
        observation_ids = tuple(revision.observation_id for revision in revisions)
        with self._runtime.engine.connect() as connection:
            observation_query = (
                select(
                    DAILY_OBSERVATIONS.c.observation_id,
                    DAILY_OBSERVATIONS.c.waybill_number,
                    DAILY_OBSERVATIONS.c.loading_ticket_sha256,
                    DAILY_OBSERVATIONS.c.unloading_ticket_sha256,
                    DAILY_OBSERVATIONS.c.observed_at,
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
            )
            if source_job_id is not None:
                observation_query = observation_query.where(
                    DAILY_CAPTURE_INVOCATIONS.c.job_id == source_job_id
                )
            observation_rows = tuple(
                connection.execute(observation_query).mappings()
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
            whole_rows = (
                ()
                if not job_ids
                else tuple(
                    connection.execute(
                        select(OPERATIONAL_REVIEW_LINKS).where(
                            OPERATIONAL_REVIEW_LINKS.c.source_job_id.in_(job_ids),
                            OPERATIONAL_REVIEW_LINKS.c.business_kind == "daily",
                        )
                    ).mappings()
                )
            )
            ocr_job_to_daily = {
                str(row["ocr_job_id"]): str(row["daily_job_id"])
                for row in batch_rows
                if row["ocr_job_id"] is not None
            }
            ocr_job_to_daily.update(
                {
                    str(row["review_job_id"]): str(row["source_job_id"])
                    for row in whole_rows
                    if row["review_job_id"] is not None
                }
            )
            processed_rows = (
                ()
                if not ocr_job_to_daily
                else tuple(
                    connection.execute(
                        select(
                            WORK_ITEMS.c.job_id,
                            WORK_ITEMS.c.waybill_number,
                            WORK_ITEMS.c.status,
                            OCR_RUN_GENERATIONS.c.updated_at,
                        )
                        .select_from(
                            WORK_ITEMS.outerjoin(
                            OCR_RUN_GENERATIONS,
                            OCR_RUN_GENERATIONS.c.work_item_id
                            == WORK_ITEMS.c.work_item_id,
                            )
                        )
                        .where(
                            WORK_ITEMS.c.job_id.in_(tuple(ocr_job_to_daily)),
                            WORK_ITEMS.c.status.in_(("succeeded", "waiting_user")),
                            (
                                OCR_RUN_GENERATIONS.c.status == "succeeded"
                            )
                            | OCR_RUN_GENERATIONS.c.status.is_(None),
                        )
                    )
                )
            )
            whole_review_jobs = {
                str(row["review_job_id"]): str(row["source_job_id"])
                for row in whole_rows
                if row["review_job_id"] is not None
            }
            whole_status_rows = (
                ()
                if not whole_review_jobs
                else tuple(
                    connection.execute(
                        select(
                            WORK_ITEMS.c.job_id,
                            WORK_ITEMS.c.waybill_number,
                            WORK_ITEMS.c.status,
                            WORK_ITEMS.c.item_index,
                        )
                        .where(
                            WORK_ITEMS.c.job_id.in_(tuple(whole_review_jobs))
                        )
                        .order_by(WORK_ITEMS.c.job_id, WORK_ITEMS.c.item_index)
                    ).mappings()
                )
            )
        batches_by_job: dict[str, list[str]] = {}
        for row in batch_rows:
            batches_by_job.setdefault(str(row["daily_job_id"]), []).append(
                str(row["created_at"])
            )
        for row in whole_rows:
            batches_by_job.setdefault(str(row["source_job_id"]), []).append(
                str(row["created_at"])
            )
        processed: dict[tuple[str, str], str] = {}
        for ocr_job_id, waybill_number, _status, updated_at in processed_rows:
            daily_job_id = ocr_job_to_daily[str(ocr_job_id)]
            processed[(daily_job_id, str(waybill_number))] = (
                str(updated_at)
                if updated_at is not None
                else max(batches_by_job[daily_job_id])
            )
        whole_prefix_waybills: dict[str, set[str]] = {}
        blocked_whole_jobs: set[str] = set()
        for row in whole_status_rows:
            review_job_id = str(row["job_id"])
            source_id = whole_review_jobs[review_job_id]
            if source_id in blocked_whole_jobs:
                continue
            if (
                str(row["status"]) not in {"succeeded", "waiting_user"}
            ):
                blocked_whole_jobs.add(source_id)
                continue
            whole_prefix_waybills.setdefault(source_id, set()).add(
                str(row["waybill_number"])
            )

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
            waybill_number = row["waybill_number"]
            if waybill_number is not None:
                if (
                    job_id in whole_prefix_waybills
                    and str(waybill_number)
                    not in whole_prefix_waybills[job_id]
                ):
                    continue
                if (
                    job_id in {str(value["source_job_id"]) for value in whole_rows}
                    and job_id not in whole_prefix_waybills
                ):
                    continue
                processed_at = processed.get((job_id, str(waybill_number)))
                if processed_at is not None:
                    result[observation_id] = processed_at
        return result

    def _whole_run_waybill_order(self, source_job_id: str) -> dict[str, int]:
        with self._runtime.engine.connect() as connection:
            items_json = connection.execute(
                select(OPERATIONAL_CAPTURE_RUNS.c.items_json).where(
                    OPERATIONAL_CAPTURE_RUNS.c.job_id == source_job_id,
                    OPERATIONAL_CAPTURE_RUNS.c.capture_mode == "whole_run_v1",
                )
            ).scalar_one_or_none()
        if items_json is None:
            return {}
        try:
            payload = json.loads(str(items_json))
        except (TypeError, ValueError) as exc:
            raise DailyItemConflictError(
                "whole-run source order is invalid"
            ) from exc
        if not isinstance(payload, list):
            raise DailyItemConflictError("whole-run source order is invalid")
        result: dict[str, int] = {}
        for index, item in enumerate(payload):
            if not isinstance(item, dict):
                raise DailyItemConflictError("whole-run source order is invalid")
            waybill_number = item.get("waybill_number")
            if not isinstance(waybill_number, str) or not waybill_number:
                raise DailyItemConflictError("whole-run source order is invalid")
            result[waybill_number] = index
        return result

    def _load_latest_ocr_outputs(
        self,
        waybill_numbers: tuple[str, ...],
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> dict[str, tuple[str | None, str | None, str]]:
        if not waybill_numbers:
            return {}
        linked_jobs = select(DAILY_OPERATIONAL_OCR_BATCHES.c.ocr_job_id).where(
            DAILY_OPERATIONAL_OCR_BATCHES.c.ocr_job_id.is_not(None)
        ).union(
            select(OPERATIONAL_REVIEW_LINKS.c.review_job_id).where(
                OPERATIONAL_REVIEW_LINKS.c.business_kind == "daily",
                OPERATIONAL_REVIEW_LINKS.c.review_job_id.is_not(None),
            )
        )
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(
                        WORK_ITEMS.c.waybill_number,
                        OCR_RUN_GENERATIONS.c.loading_output_json,
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
                        WORK_ITEMS.c.job_id.in_(
                            select(PLATFORM_JOB_SUBJECTS.c.job_id).where(
                                PLATFORM_JOB_SUBJECTS.c.contract_subject_code
                                == contract_subject_code
                            )
                        ),
                        WORK_ITEMS.c.waybill_number.in_(waybill_numbers),
                        OCR_RUN_GENERATIONS.c.status == "succeeded",
                        (
                            OCR_RUN_GENERATIONS.c.loading_output_json.is_not(None)
                            | OCR_RUN_GENERATIONS.c.unloading_output_json.is_not(None)
                        ),
                    )
                    .order_by(OCR_RUN_GENERATIONS.c.updated_at.desc())
                )
            )
        result: dict[str, tuple[str | None, str | None, str]] = {}
        for waybill_number, loading_json, unloading_json, updated_at in rows:
            key = str(waybill_number)
            if key not in result:
                result[key] = (
                    None if loading_json is None else str(loading_json),
                    None if unloading_json is None else str(unloading_json),
                    str(updated_at),
                )
        return result
