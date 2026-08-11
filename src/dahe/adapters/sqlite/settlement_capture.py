from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from uuid import uuid4

from sqlalchemy import select, text, update
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.loop3_support import next_sequence
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    BUSINESS_CONNECTION_READS,
    BUSINESS_CONNECTION_SESSIONS,
    CHECKPOINTS,
    CONFLICT_KEYS,
    IDEMPOTENCY_RECORDS,
    JOBS,
    OUTBOX,
    PLATFORM_ACCESS_EVENTS,
    PLATFORM_ACCESS_WINDOWS,
    PLATFORM_CONTROL_IDEMPOTENCY,
    SETTLEMENT_CAPTURE_IDENTITIES,
    SETTLEMENT_CAPTURE_INVOCATIONS,
    SETTLEMENT_CAPTURE_STRATEGIES,
    WORK_ITEMS,
)
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowError,
    AccessWindowGrant,
    issue_access_window,
)
from dahe.application.chengfeng.durable_capture import (
    CaptureCheckpointError,
    DurableCaptureCheckpoint,
    capture_read_key,
)
from dahe.application.chengfeng.settlement_capture import (
    HISTORICAL_SETTLEMENT_CAPTURE_PAGE_SIZE,
    SETTLEMENT_CAPTURE_PAGE_SIZE,
    ProtectedBusinessIdentity,
    SettlementCaptureAccessWindowLineage,
    SettlementCaptureContractError,
    SettlementCaptureManifest,
    SettlementCaptureReadAccessBinding,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
    ShadowCaptureBinding,
    _validate_complete_pagination,
)
from dahe.jobs.models import JobStatus, WorkItemStatus
from dahe.ports.chengfeng import (
    CURRENT_PENDING_SETTLEMENT_SCOPE,
    HISTORICAL_SETTLED_SCOPE,
    ChengfengStage,
)
from dahe.ports.jobs import (
    ActiveScopeConflictError,
    IdempotencyConflictError,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_PURPOSES = {"formal_locked_set", "production_shadow"}
_START_OPERATION = "POST:/api/v1/platform/settlement-captures"


class SettlementCaptureStoreConflictError(RuntimeError):
    """Raised when protected capture state cannot advance atomically."""


@dataclass(frozen=True, slots=True)
class SettlementCaptureInvocationRecord:
    invocation_id: str
    job_id: str
    access_window_id: str
    scope: str
    page_size: int
    source_build_sha256: str
    contract_canonical_sha256: str
    contract_file_sha256: str
    contract_selection_sha256: str
    identity_context_sha256: str
    status: str
    manifest_sha256: str | None
    selection_manifest_sha256: str | None
    batch_manifest_sha256: str | None
    diagnostic_code: str | None
    record_version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class SettlementCaptureStartRecord:
    """One atomic Job, access-window, and invocation start result."""

    target_kind: ShadowBatchTargetKind
    job_id: str
    work_item_id: str
    access_window: AccessWindowGrant
    access_record_version: int
    invocation: SettlementCaptureInvocationRecord
    created: bool


@dataclass(frozen=True, slots=True)
class SettlementCaptureAccessRolloverRecord:
    """One durable access-window replacement for the original capture."""

    invocation: SettlementCaptureInvocationRecord
    old_access_window_id: str
    new_access_window_id: str
    idempotent_replay: bool


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _rollover_authority_payload(
    *,
    job_id: str,
    session_id: str,
    purpose: str,
    source_build_sha256: str,
    contract_canonical_sha256: str,
    contract_file_sha256: str,
    contract_selection_sha256: str,
    identity_context_sha256: str,
    old_access_window_id: str,
    new_access_window_id: str,
) -> dict[str, object]:
    return {
        "contract_canonical_sha256": contract_canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "contract_selection_sha256": contract_selection_sha256,
        "identity_context_sha256": identity_context_sha256,
        "job_id": job_id,
        "new_access_window_id": new_access_window_id,
        "old_access_window_id": old_access_window_id,
        "purpose": purpose,
        "session_id": session_id,
        "source_build_sha256": source_build_sha256,
    }


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SettlementCaptureStoreConflictError(
            "settlement capture timestamp must be timezone-aware"
        )
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise SettlementCaptureStoreConflictError(
            "stored settlement capture timestamp is invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SettlementCaptureStoreConflictError(
            "stored settlement capture timestamp is invalid"
        )
    return parsed.astimezone(UTC)


def _require_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SettlementCaptureStoreConflictError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _access_record(row: RowMapping) -> AccessWindowGrant:
    issued_at = _parse_timestamp(row["issued_at"])
    expires_at = _parse_timestamp(row["expires_at"])
    consumed_at = (
        None
        if row["consumed_at"] is None
        else _parse_timestamp(row["consumed_at"])
    )
    return AccessWindowGrant(
        access_window_id=str(row["access_window_id"]),
        purpose=AccessPurpose(str(row["purpose"])),
        job_id=str(row["job_id"]),
        session_id=str(row["session_id"]),
        build_sha256=str(row["build_sha256"]),
        issued_at=issued_at,
        expires_at=expires_at,
        token_digest=str(row["token_digest"]),
        consumed_at=consumed_at,
        token="",
    )


def _purpose_for_target(
    target_kind: ShadowBatchTargetKind,
) -> AccessPurpose:
    if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        return AccessPurpose.FORMAL_LOCKED_SET
    if target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
        return AccessPurpose.PRODUCTION_SHADOW
    if target_kind is ShadowBatchTargetKind.OPERATIONAL_COMPAT:
        return AccessPurpose.PRODUCTION_SHADOW
    raise SettlementCaptureStoreConflictError(
        "settlement capture target is invalid"
    )


def _target_for_purpose(purpose: AccessPurpose) -> ShadowBatchTargetKind:
    if purpose is AccessPurpose.FORMAL_LOCKED_SET:
        return ShadowBatchTargetKind.CURRENT_LOCKED_50
    if purpose is AccessPurpose.PRODUCTION_SHADOW:
        return ShadowBatchTargetKind.REAL_SHADOW_30
    raise SettlementCaptureStoreConflictError(
        "settlement capture purpose is invalid"
    )


def _capture_contract_for_target(
    target_kind: ShadowBatchTargetKind,
    source_scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
) -> tuple[str, int]:
    if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        if source_scope == CURRENT_PENDING_SETTLEMENT_SCOPE:
            return source_scope, SETTLEMENT_CAPTURE_PAGE_SIZE
        if source_scope == HISTORICAL_SETTLED_SCOPE:
            return source_scope, HISTORICAL_SETTLEMENT_CAPTURE_PAGE_SIZE
        raise SettlementCaptureStoreConflictError(
            "settlement capture source scope is invalid"
        )
    if target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
        if source_scope != CURRENT_PENDING_SETTLEMENT_SCOPE:
            raise SettlementCaptureStoreConflictError(
                "real shadow source scope must remain current"
            )
        return (
            CURRENT_PENDING_SETTLEMENT_SCOPE,
            SETTLEMENT_CAPTURE_PAGE_SIZE,
        )
    if target_kind is ShadowBatchTargetKind.OPERATIONAL_COMPAT:
        if source_scope != CURRENT_PENDING_SETTLEMENT_SCOPE:
            raise SettlementCaptureStoreConflictError(
                "operational source scope must remain current"
            )
        return (
            CURRENT_PENDING_SETTLEMENT_SCOPE,
            SETTLEMENT_CAPTURE_PAGE_SIZE,
        )
    raise SettlementCaptureStoreConflictError(
        "settlement capture target is invalid"
    )


def _record(row: RowMapping) -> SettlementCaptureInvocationRecord:
    status = str(row["status"])
    manifest_sha = (
        None
        if row["manifest_sha256"] is None
        else str(row["manifest_sha256"])
    )
    diagnostic = (
        None
        if row["diagnostic_code"] is None
        else str(row["diagnostic_code"])
    )
    selection_manifest_sha = (
        None
        if row["selection_manifest_sha256"] is None
        else str(row["selection_manifest_sha256"])
    )
    batch_manifest_sha = (
        None
        if row["batch_manifest_sha256"] is None
        else str(row["batch_manifest_sha256"])
    )
    scope = str(row["scope"])
    page_size = int(row["page_size"])
    if (
        status
        not in {
            "collecting",
            "sealed",
            "selected",
            "operational_ready",
            "selection_blocked",
            "failed",
        }
        or (
            status
            in {
                "sealed",
                "selected",
                "operational_ready",
                "selection_blocked",
            }
        )
        != (manifest_sha is not None)
        or (status == "selected")
        != (
            selection_manifest_sha is not None
            and batch_manifest_sha is not None
        )
        or (selection_manifest_sha is None)
        != (batch_manifest_sha is None)
        or (
            status == "operational_ready"
            and (
                selection_manifest_sha is not None
                or batch_manifest_sha is not None
            )
        )
        or (status in {"selection_blocked", "failed"})
        != (diagnostic is not None)
        or (scope, page_size)
        not in {
            (
                CURRENT_PENDING_SETTLEMENT_SCOPE,
                SETTLEMENT_CAPTURE_PAGE_SIZE,
            ),
            (
                HISTORICAL_SETTLED_SCOPE,
                HISTORICAL_SETTLEMENT_CAPTURE_PAGE_SIZE,
            ),
        }
    ):
        raise SettlementCaptureStoreConflictError(
            "stored settlement capture state is invalid"
        )
    return SettlementCaptureInvocationRecord(
        invocation_id=str(row["invocation_id"]),
        job_id=str(row["job_id"]),
        access_window_id=str(row["access_window_id"]),
        scope=scope,
        page_size=page_size,
        source_build_sha256=str(row["source_build_sha256"]),
        contract_canonical_sha256=str(
            row["contract_canonical_sha256"]
        ),
        contract_file_sha256=str(row["contract_file_sha256"]),
        contract_selection_sha256=str(
            row["contract_selection_sha256"]
        ),
        identity_context_sha256=str(row["identity_context_sha256"]),
        status=status,
        manifest_sha256=manifest_sha,
        selection_manifest_sha256=selection_manifest_sha,
        batch_manifest_sha256=batch_manifest_sha,
        diagnostic_code=diagnostic,
        record_version=int(row["record_version"]),
        created_at=_parse_timestamp(row["created_at"]),
        updated_at=_parse_timestamp(row["updated_at"]),
    )


def _invocation_id(
    *,
    job_id: str,
    access_window_id: str,
    source_build_sha256: str,
    contract_canonical_sha256: str,
    contract_file_sha256: str,
    contract_selection_sha256: str,
    identity_context_sha256: str,
    scope: str,
    page_size: int,
) -> str:
    return _canonical_sha256(
        {
            "access_window_id": access_window_id,
            "contract_canonical_sha256": contract_canonical_sha256,
            "contract_file_sha256": contract_file_sha256,
            "contract_selection_sha256": contract_selection_sha256,
            "identity_context_sha256": identity_context_sha256,
            "job_id": job_id,
            "page_size": page_size,
            "scope": scope,
            "source_build_sha256": source_build_sha256,
        }
    )[:32]


class SqliteSettlementCaptureStore:
    """Atomically seal complete captures and their protected business map."""

    def __init__(self, runtime: SqliteRuntime) -> None:
        self._engine = runtime.engine
        self._commit_gate = runtime.commit_gate

    @staticmethod
    def _get(
        connection: Connection,
        invocation_id: str,
    ) -> SettlementCaptureInvocationRecord:
        row = (
            connection.execute(
                select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                    == invocation_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise SettlementCaptureStoreConflictError(
                "settlement capture invocation does not exist"
            )
        return _record(row)

    def get(
        self,
        invocation_id: str,
    ) -> SettlementCaptureInvocationRecord:
        with self._engine.connect() as connection:
            return self._get(connection, invocation_id)

    def get_by_job(
        self,
        job_id: str,
    ) -> SettlementCaptureInvocationRecord:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id == job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise SettlementCaptureStoreConflictError(
                "settlement capture invocation does not exist"
            )
        return _record(row)

    def has_business_session_binding(self, job_id: str) -> bool:
        with self._engine.connect() as connection:
            binding = connection.execute(
                select(BUSINESS_CONNECTION_READS.c.job_id).where(
                    BUSINESS_CONNECTION_READS.c.job_id == job_id
                )
            ).scalar_one_or_none()
        return binding is not None

    def capture_strategy(self, job_id: str) -> str:
        with self._engine.connect() as connection:
            strategy = connection.execute(
                select(SETTLEMENT_CAPTURE_STRATEGIES.c.strategy).where(
                    SETTLEMENT_CAPTURE_STRATEGIES.c.job_id == job_id
                )
            ).scalar_one_or_none()
        return "legacy" if strategy is None else str(strategy)

    def replay_start(
        self,
        *,
        target_kind: ShadowBatchTargetKind,
        idempotency_key: str,
        request_hash: str,
        business_session_id: str | None = None,
    ) -> SettlementCaptureStartRecord | None:
        """Return one committed start before any browser state is mutated."""

        if (
            not isinstance(target_kind, ShadowBatchTargetKind)
            or not isinstance(idempotency_key, str)
            or not idempotency_key
            or len(idempotency_key) > 200
            or _SHA256.fullmatch(request_hash) is None
            or (
                business_session_id is not None
                and (
                    not business_session_id
                    or len(business_session_id) > 32
                )
            )
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture replay identity is invalid"
            )
        with self._engine.connect() as connection:
            replay = (
                connection.execute(
                    select(IDEMPOTENCY_RECORDS).where(
                        IDEMPOTENCY_RECORDS.c.operation
                        == _START_OPERATION,
                        IDEMPOTENCY_RECORDS.c.idempotency_key
                        == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is None:
                return None
            if str(replay["request_hash"]) != request_hash:
                raise IdempotencyConflictError(
                    "the idempotency key belongs to a different request"
                )
            job_id = str(replay["job_id"])
            invocation_row = (
                connection.execute(
                    select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                        == job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            item_id = connection.execute(
                select(WORK_ITEMS.c.work_item_id).where(
                    WORK_ITEMS.c.job_id == job_id
                )
            ).scalar_one_or_none()
            if invocation_row is None or item_id is None:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture start replay is incomplete"
                )
            invocation = _record(invocation_row)
            access_row = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == invocation.access_window_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if access_row is None:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access replay is unavailable"
                )
            run_mode = connection.execute(
                select(JOBS.c.run_mode).where(JOBS.c.job_id == job_id)
            ).scalar_one()
            replay_target = (
                ShadowBatchTargetKind.OPERATIONAL_COMPAT
                if run_mode == "operational"
                else _target_for_purpose(
                    AccessPurpose(str(access_row["purpose"]))
                )
            )
            if replay_target is not target_kind:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture target replay changed"
                )
            if business_session_id is not None:
                business_read = connection.execute(
                    select(BUSINESS_CONNECTION_READS).where(
                        BUSINESS_CONNECTION_READS.c.job_id == job_id,
                        BUSINESS_CONNECTION_READS.c.business_session_id
                        == business_session_id,
                    )
                ).first()
                if business_read is None:
                    raise SettlementCaptureStoreConflictError(
                        "business connection read replay is incomplete"
                    )
            return SettlementCaptureStartRecord(
                target_kind=target_kind,
                job_id=job_id,
                work_item_id=str(item_id),
                access_window=_access_record(access_row),
                access_record_version=int(access_row["record_version"]),
                invocation=invocation,
                created=False,
            )

    @staticmethod
    def _access_window_lineage(
        connection: Connection,
        invocation: SettlementCaptureInvocationRecord,
    ) -> SettlementCaptureAccessWindowLineage:
        event_rows = tuple(
            connection.execute(
                select(OUTBOX)
                .where(
                    OUTBOX.c.aggregate_type == "settlement_capture",
                    OUTBOX.c.aggregate_id == invocation.job_id,
                    OUTBOX.c.event_type
                    == "settlement_capture.access_window_rebound",
                )
                .order_by(OUTBOX.c.record_version, OUTBOX.c.event_id)
            ).mappings()
        )
        parsed_events: list[tuple[RowMapping, dict[str, object]]] = []
        for row in event_rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access lineage is invalid"
                ) from exc
            if not isinstance(payload, dict) or any(
                type(key) is not str for key in payload
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access lineage is invalid"
                )
            parsed_events.append((row, payload))

        access_window_ids: list[str]
        if not parsed_events:
            access_window_ids = [invocation.access_window_id]
        else:
            record_versions = [
                int(row["record_version"])
                for row, _payload in parsed_events
            ]
            if (
                record_versions[0] != 2
                or record_versions
                != list(
                    range(
                        record_versions[0],
                        record_versions[0] + len(record_versions),
                    )
                )
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access lineage is not append-only"
                )
            first_old = parsed_events[0][1].get(
                "old_access_window_id"
            )
            if not isinstance(first_old, str) or not first_old:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access lineage is invalid"
                )
            access_window_ids = [first_old]
            for _row, payload in parsed_events:
                old_access_window_id = payload.get(
                    "old_access_window_id"
                )
                new_access_window_id = payload.get(
                    "new_access_window_id"
                )
                if (
                    not isinstance(old_access_window_id, str)
                    or not old_access_window_id
                    or not isinstance(new_access_window_id, str)
                    or not new_access_window_id
                    or old_access_window_id != access_window_ids[-1]
                    or new_access_window_id in access_window_ids
                ):
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture access lineage is not append-only"
                    )
                access_window_ids.append(new_access_window_id)
            if access_window_ids[-1] != invocation.access_window_id:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access lineage was superseded"
                )

        access_rows = tuple(
            connection.execute(
                select(PLATFORM_ACCESS_WINDOWS).where(
                    PLATFORM_ACCESS_WINDOWS.c.access_window_id.in_(
                        tuple(access_window_ids)
                    )
                )
            ).mappings()
        )
        access_by_id = {
            str(row["access_window_id"]): row for row in access_rows
        }
        if set(access_by_id) != set(access_window_ids):
            raise SettlementCaptureStoreConflictError(
                "settlement capture access lineage is unavailable"
            )
        ordered_access = tuple(
            access_by_id[access_window_id]
            for access_window_id in access_window_ids
        )
        first_access = ordered_access[0]
        session_id = str(first_access["session_id"])
        purpose = str(first_access["purpose"])
        if (
            purpose not in _ALLOWED_PURPOSES
            or invocation.source_build_sha256
            != str(first_access["build_sha256"])
            or any(
                str(access["job_id"]) != invocation.job_id
                or str(access["session_id"]) != session_id
                or str(access["purpose"]) != purpose
                or str(access["build_sha256"])
                != invocation.source_build_sha256
                for access in ordered_access
            )
            or any(
                _parse_timestamp(current["issued_at"])
                >= _parse_timestamp(following["issued_at"])
                for current, following in pairwise(ordered_access)
            )
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture access lineage authority changed"
            )

        allowed_event_keys = {
            "authority_sha256",
            "contract_canonical_sha256",
            "contract_file_sha256",
            "contract_selection_sha256",
            "identity_context_sha256",
            "job_id",
            "new_access_window_id",
            "old_access_window_id",
            "purpose",
            "session_id",
            "source_build_sha256",
        }
        for _row, payload in parsed_events:
            old_access_window_id = str(
                payload["old_access_window_id"]
            )
            new_access_window_id = str(
                payload["new_access_window_id"]
            )
            expected = _rollover_authority_payload(
                job_id=invocation.job_id,
                session_id=session_id,
                purpose=purpose,
                source_build_sha256=invocation.source_build_sha256,
                contract_canonical_sha256=(
                    invocation.contract_canonical_sha256
                ),
                contract_file_sha256=(
                    invocation.contract_file_sha256
                ),
                contract_selection_sha256=(
                    invocation.contract_selection_sha256
                ),
                identity_context_sha256=(
                    invocation.identity_context_sha256
                ),
                old_access_window_id=old_access_window_id,
                new_access_window_id=new_access_window_id,
            )
            keys = set(payload)
            if (
                not {
                    "old_access_window_id",
                    "new_access_window_id",
                }.issubset(keys)
                or not keys.issubset(allowed_event_keys)
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access lineage authority is invalid"
                )
            if "authority_sha256" in payload:
                expected_with_digest = {
                    **expected,
                    "authority_sha256": _canonical_sha256(expected),
                }
                if payload != expected_with_digest:
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture access lineage authority changed"
                    )
            elif any(
                payload[key] != expected[key]
                for key in keys
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access lineage authority changed"
                )

        try:
            return SettlementCaptureAccessWindowLineage(
                job_id=invocation.job_id,
                session_id=session_id,
                purpose=purpose,
                source_build_sha256=invocation.source_build_sha256,
                contract_canonical_sha256=(
                    invocation.contract_canonical_sha256
                ),
                contract_file_sha256=(
                    invocation.contract_file_sha256
                ),
                contract_selection_sha256=(
                    invocation.contract_selection_sha256
                ),
                identity_context_sha256=(
                    invocation.identity_context_sha256
                ),
                access_window_ids=tuple(access_window_ids),
            )
        except SettlementCaptureContractError as exc:
            raise SettlementCaptureStoreConflictError(
                "settlement capture access lineage is invalid"
            ) from exc

    def access_window_lineage(
        self,
        invocation_id: str,
    ) -> SettlementCaptureAccessWindowLineage:
        with self._engine.connect() as connection:
            invocation = self._get(connection, invocation_id)
            return self._access_window_lineage(
                connection,
                invocation,
            )

    @staticmethod
    def _validate_rollover_checkpoint_lineage(
        connection: Connection,
        *,
        job_id: str,
    ) -> None:
        rows = tuple(
            connection.execute(
                select(
                    CHECKPOINTS.c.owner_id,
                    CHECKPOINTS.c.job_id,
                    CHECKPOINTS.c.payload_json,
                )
                .where(
                    CHECKPOINTS.c.owner_kind == "chengfeng_capture",
                    (
                        (CHECKPOINTS.c.job_id == job_id)
                        | CHECKPOINTS.c.job_id.is_(None)
                    ),
                )
                .order_by(CHECKPOINTS.c.sequence.desc())
            ).mappings()
        )
        latest_by_capture: dict[str, DurableCaptureCheckpoint] = {}
        for row in rows:
            owner_id = str(row["owner_id"])
            if owner_id in latest_by_capture:
                continue
            try:
                payload = json.loads(str(row["payload_json"]))
                checkpoint = DurableCaptureCheckpoint.from_payload(
                    payload
                )
            except (
                CaptureCheckpointError,
                TypeError,
                json.JSONDecodeError,
                ValueError,
            ) as exc:
                if row["job_id"] == job_id:
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture checkpoint lineage is invalid"
                    ) from exc
                continue
            if checkpoint.job_id != job_id:
                continue
            latest_by_capture[owner_id] = checkpoint

        if any(
            (
                checkpoint.page is not None
                or checkpoint.details
                or checkpoint.ticket_images
            )
            and not checkpoint.read_access_window_ids
            for checkpoint in latest_by_capture.values()
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture checkpoint access lineage is unavailable"
            )

    def retire_terminal_access(
        self,
        *,
        job_id: str,
        now: datetime,
    ) -> bool:
        """Idempotently invalidate one terminal capture access window."""

        if (
            not isinstance(job_id, str)
            or not job_id
            or len(job_id) > 32
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture job identity is invalid"
            )
        timestamp = _timestamp(now)
        instant = _parse_timestamp(timestamp)
        with self._commit_gate.transaction(self._engine) as connection:
            row = (
                connection.execute(
                    select(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.status.label(
                            "invocation_status"
                        ),
                        PLATFORM_ACCESS_WINDOWS,
                        JOBS.c.status.label("job_status"),
                    )
                    .join(
                        PLATFORM_ACCESS_WINDOWS,
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == SETTLEMENT_CAPTURE_INVOCATIONS.c.access_window_id,
                    )
                    .join(
                        JOBS,
                        JOBS.c.job_id
                        == SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id,
                    )
                    .where(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id == job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture terminal authority is unavailable"
                )
            if row["consumed_at"] is not None:
                return False
            job_status = JobStatus(str(row["job_status"]))
            invocation_status = str(row["invocation_status"])
            expired = _parse_timestamp(row["expires_at"]) <= instant
            if (
                not job_status.is_terminal
                and invocation_status
                not in {"selected", "selection_blocked", "failed"}
                and invocation_status != "operational_ready"
                and not expired
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture is not eligible for terminal cleanup"
                )
            access_window_id = str(row["access_window_id"])
            access_version = int(row["record_version"])
            updated = connection.execute(
                update(PLATFORM_ACCESS_WINDOWS)
                .where(
                    PLATFORM_ACCESS_WINDOWS.c.access_window_id
                    == access_window_id,
                    PLATFORM_ACCESS_WINDOWS.c.record_version
                    == access_version,
                    PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                )
                .values(
                    consumed_at=timestamp,
                    record_version=access_version + 1,
                    updated_at=timestamp,
                )
            )
            if updated.rowcount != 1:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access cleanup changed concurrently"
                )
            connection.execute(
                PLATFORM_ACCESS_EVENTS.insert().values(
                    access_window_id=access_window_id,
                    event_type="consumed",
                    record_version=access_version + 1,
                    created_at=timestamp,
                )
            )
        return True

    def reconcile_terminal_or_expired_access(
        self,
        *,
        now: datetime,
    ) -> tuple[str, ...]:
        """Recover access windows left usable by a prior process exit."""

        instant = _parse_timestamp(_timestamp(now))
        with self._engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id,
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.status.label(
                            "invocation_status"
                        ),
                        PLATFORM_ACCESS_WINDOWS.c.expires_at,
                        JOBS.c.status.label("job_status"),
                    )
                    .join(
                        PLATFORM_ACCESS_WINDOWS,
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == SETTLEMENT_CAPTURE_INVOCATIONS.c.access_window_id,
                    )
                    .join(
                        JOBS,
                        JOBS.c.job_id
                        == SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id,
                    )
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None)
                    )
                ).mappings()
            )
        candidates = tuple(
            sorted(
                str(row["job_id"])
                for row in rows
                if (
                    JobStatus(str(row["job_status"])).is_terminal
                    or str(row["invocation_status"])
                    in {
                        "selected",
                        "operational_ready",
                        "selection_blocked",
                        "failed",
                    }
                    or _parse_timestamp(row["expires_at"]) <= instant
                )
            )
        )
        reconciled: list[str] = []
        for job_id in candidates:
            if self.retire_terminal_access(job_id=job_id, now=instant):
                reconciled.append(job_id)
        return tuple(reconciled)

    def rebind_access_window(
        self,
        *,
        job_id: str,
        new_access_window_id: str,
        expected_invocation_record_version: int,
        expected_browser_record_version: int,
        session_id: str,
        source_build_sha256: str,
        contract_canonical_sha256: str,
        contract_file_sha256: str,
        contract_selection_sha256: str,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> SettlementCaptureAccessRolloverRecord:
        """Replace an inactive window without replacing the paused Job."""

        if (
            not isinstance(job_id, str)
            or not job_id
            or len(job_id) > 32
            or not isinstance(new_access_window_id, str)
            or not new_access_window_id
            or len(new_access_window_id) > 32
            or not isinstance(session_id, str)
            or not session_id
            or len(session_id) > 100
            or isinstance(expected_invocation_record_version, bool)
            or not isinstance(expected_invocation_record_version, int)
            or expected_invocation_record_version < 1
            or isinstance(expected_browser_record_version, bool)
            or not isinstance(expected_browser_record_version, int)
            or expected_browser_record_version < 1
            or not isinstance(idempotency_key, str)
            or not idempotency_key
            or len(idempotency_key) > 200
            or _SHA256.fullmatch(request_hash) is None
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture rollover identity is invalid"
            )
        for label, value in (
            ("source build SHA-256", source_build_sha256),
            ("contract canonical SHA-256", contract_canonical_sha256),
            ("contract file SHA-256", contract_file_sha256),
            ("contract selection SHA-256", contract_selection_sha256),
        ):
            _require_sha256(value, label=label)

        operation = "settlement_capture_access_window_rebind"
        instant = _parse_timestamp(_timestamp(now))
        timestamp = _timestamp(instant)
        try:
            with self._commit_gate.transaction(self._engine) as connection:
                replay = (
                    connection.execute(
                        select(PLATFORM_CONTROL_IDEMPOTENCY).where(
                            PLATFORM_CONTROL_IDEMPOTENCY.c.operation
                            == operation,
                            PLATFORM_CONTROL_IDEMPOTENCY.c.idempotency_key
                            == idempotency_key,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if replay is not None:
                    if (
                        str(replay["request_hash"]) != request_hash
                        or str(replay["session_id"]) != session_id
                        or str(replay["access_window_id"])
                        != new_access_window_id
                    ):
                        raise IdempotencyConflictError(
                            "the idempotency key belongs to a different request"
                        )
                    replay_invocation_row = (
                        connection.execute(
                            select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                                SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                                == job_id
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if replay_invocation_row is None:
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover replay is unavailable"
                        )
                    replay_invocation = _record(replay_invocation_row)
                    if (
                        replay_invocation.access_window_id
                        != new_access_window_id
                        or replay_invocation.record_version
                        != int(replay["result_record_version"])
                    ):
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover replay was superseded"
                        )
                    event_row = (
                        connection.execute(
                            select(OUTBOX).where(
                                OUTBOX.c.aggregate_type
                                == "settlement_capture",
                                OUTBOX.c.aggregate_id == job_id,
                                OUTBOX.c.event_type
                                == (
                                    "settlement_capture."
                                    "access_window_rebound"
                                ),
                                OUTBOX.c.record_version
                                == int(replay["result_record_version"]),
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if event_row is None:
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover history is unavailable"
                        )
                    try:
                        event_payload = json.loads(
                            str(event_row["payload_json"])
                        )
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover replay authority is invalid"
                        ) from exc
                    if not isinstance(event_payload, dict):
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover replay authority is invalid"
                        )
                    old_access_window_id = event_payload.get(
                        "old_access_window_id"
                    )
                    if not isinstance(old_access_window_id, str):
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover replay authority is invalid"
                        )
                    access_rows = (
                        connection.execute(
                            select(PLATFORM_ACCESS_WINDOWS).where(
                                PLATFORM_ACCESS_WINDOWS.c.access_window_id.in_(
                                    (
                                        old_access_window_id,
                                        new_access_window_id,
                                    )
                                )
                            )
                        )
                        .mappings()
                        .all()
                    )
                    access_by_id = {
                        str(row["access_window_id"]): row
                        for row in access_rows
                    }
                    old_access = access_by_id.get(old_access_window_id)
                    new_access = access_by_id.get(new_access_window_id)
                    if old_access is None or new_access is None:
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover replay authority is invalid"
                        )
                    purpose = str(old_access["purpose"])
                    expected_authority = _rollover_authority_payload(
                        job_id=job_id,
                        session_id=session_id,
                        purpose=purpose,
                        source_build_sha256=source_build_sha256,
                        contract_canonical_sha256=(
                            contract_canonical_sha256
                        ),
                        contract_file_sha256=contract_file_sha256,
                        contract_selection_sha256=(
                            contract_selection_sha256
                        ),
                        identity_context_sha256=(
                            replay_invocation.identity_context_sha256
                        ),
                        old_access_window_id=old_access_window_id,
                        new_access_window_id=new_access_window_id,
                    )
                    expected_authority_sha256 = _canonical_sha256(
                        expected_authority
                    )
                    if (
                        replay_invocation.job_id != job_id
                        or replay_invocation.source_build_sha256
                        != source_build_sha256
                        or replay_invocation.contract_canonical_sha256
                        != contract_canonical_sha256
                        or replay_invocation.contract_file_sha256
                        != contract_file_sha256
                        or replay_invocation.contract_selection_sha256
                        != contract_selection_sha256
                        or purpose not in _ALLOWED_PURPOSES
                        or any(
                            str(access[field]) != expected
                            for access in (old_access, new_access)
                            for field, expected in (
                                ("job_id", job_id),
                                ("session_id", session_id),
                                ("build_sha256", source_build_sha256),
                                ("purpose", purpose),
                            )
                        )
                        or {
                            key: value
                            for key, value in event_payload.items()
                            if key != "authority_sha256"
                        }
                        != expected_authority
                        or event_payload.get("authority_sha256")
                        != expected_authority_sha256
                    ):
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture rollover replay authority changed"
                        )
                    return SettlementCaptureAccessRolloverRecord(
                        invocation=replay_invocation,
                        old_access_window_id=old_access_window_id,
                        new_access_window_id=new_access_window_id,
                        idempotent_replay=True,
                    )

                invocation_row = (
                    connection.execute(
                        select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                            SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id == job_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                job_row = (
                    connection.execute(
                        select(JOBS).where(JOBS.c.job_id == job_id)
                    )
                    .mappings()
                    .one_or_none()
                )
                if invocation_row is None or job_row is None:
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture rollover authority is unavailable"
                    )
                invocation = _record(invocation_row)
                if invocation.status != "collecting":
                    raise SettlementCaptureStoreConflictError(
                        "only a collecting settlement capture can roll over"
                    )
                if JobStatus(str(job_row["status"])) is not JobStatus.PAUSED:
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture must be paused before rollover"
                    )
                if (
                    invocation.source_build_sha256 != source_build_sha256
                ):
                    raise SettlementCaptureStoreConflictError(
                        "capture build authority changed"
                    )
                if (
                    invocation.contract_canonical_sha256
                    != contract_canonical_sha256
                    or invocation.contract_file_sha256
                    != contract_file_sha256
                    or invocation.contract_selection_sha256
                    != contract_selection_sha256
                ):
                    raise SettlementCaptureStoreConflictError(
                        "capture contract authority changed"
                    )
                if (
                    invocation.record_version
                    != expected_invocation_record_version
                ):
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture invocation record version is stale"
                    )
                self._validate_rollover_checkpoint_lineage(
                    connection,
                    job_id=job_id,
                )

                old_row = (
                    connection.execute(
                        select(PLATFORM_ACCESS_WINDOWS).where(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id
                            == invocation.access_window_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if old_row is None:
                    raise SettlementCaptureStoreConflictError(
                        "prior access window is unavailable"
                    )
                old_expired = (
                    _parse_timestamp(old_row["expires_at"]) <= instant
                )
                if old_row["consumed_at"] is None and not old_expired:
                    raise SettlementCaptureStoreConflictError(
                        "prior access window is still active"
                    )
                if (
                    str(old_row["job_id"]) != job_id
                    or str(old_row["session_id"]) != session_id
                    or str(old_row["build_sha256"])
                    != source_build_sha256
                    or str(old_row["purpose"]) not in _ALLOWED_PURPOSES
                ):
                    raise SettlementCaptureStoreConflictError(
                        "prior access window changed capture authority"
                    )

                replacement_row = (
                    connection.execute(
                        select(PLATFORM_ACCESS_WINDOWS).where(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id
                            == new_access_window_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if replacement_row is None:
                    raise SettlementCaptureStoreConflictError(
                        "replacement access window is unavailable"
                    )
                if (
                    new_access_window_id == invocation.access_window_id
                    or str(replacement_row["job_id"]) != job_id
                    or str(replacement_row["session_id"]) != session_id
                    or str(replacement_row["build_sha256"])
                    != source_build_sha256
                    or str(replacement_row["purpose"])
                    != str(old_row["purpose"])
                ):
                    raise SettlementCaptureStoreConflictError(
                        "replacement access window changed capture authority"
                    )
                if (
                    replacement_row["consumed_at"] is not None
                    or _parse_timestamp(replacement_row["expires_at"])
                    <= instant
                    or _parse_timestamp(replacement_row["issued_at"])
                    <= _parse_timestamp(old_row["issued_at"])
                ):
                    raise SettlementCaptureStoreConflictError(
                        "replacement access window is not currently valid"
                    )

                browser_row = (
                    connection.execute(
                        text(
                            """
                            SELECT * FROM browser_control_sessions
                            WHERE session_id = :session_id
                            """
                        ),
                        {"session_id": session_id},
                    )
                    .mappings()
                    .one_or_none()
                )
                if browser_row is None:
                    raise SettlementCaptureStoreConflictError(
                        "browser control authority is unavailable"
                    )
                if (
                    int(browser_row["record_version"])
                    != expected_browser_record_version
                ):
                    raise SettlementCaptureStoreConflictError(
                        "browser control record version is stale"
                    )
                if (
                    str(browser_row["browser_control_mode"]) != "idle"
                    or str(browser_row["browser_lifecycle"])
                    not in {"ready", "stopped"}
                    or any(
                        browser_row[field] is not None
                        for field in (
                            "holder_kind",
                            "holder_id",
                            "instance_id",
                            "worker_id",
                            "job_id",
                            "fencing_token",
                        )
                    )
                ):
                    raise SettlementCaptureStoreConflictError(
                        "browser must be idle before access rollover"
                    )

                purpose = str(old_row["purpose"])
                authority_payload = _rollover_authority_payload(
                    job_id=job_id,
                    session_id=session_id,
                    purpose=purpose,
                    source_build_sha256=source_build_sha256,
                    contract_canonical_sha256=(
                        contract_canonical_sha256
                    ),
                    contract_file_sha256=contract_file_sha256,
                    contract_selection_sha256=(
                        contract_selection_sha256
                    ),
                    identity_context_sha256=(
                        invocation.identity_context_sha256
                    ),
                    old_access_window_id=invocation.access_window_id,
                    new_access_window_id=new_access_window_id,
                )
                authority_sha256 = _canonical_sha256(authority_payload)
                next_browser_epoch = (
                    int(browser_row["control_epoch"]) + 1
                )
                next_browser_version = (
                    expected_browser_record_version + 1
                )
                browser_fenced = connection.execute(
                    text(
                        """
                        UPDATE browser_control_sessions
                        SET control_epoch = :control_epoch,
                            record_version = :record_version,
                            updated_at = :updated_at
                        WHERE session_id = :session_id
                          AND record_version = :expected_record_version
                          AND browser_control_mode = 'idle'
                          AND browser_lifecycle IN ('ready', 'stopped')
                          AND holder_kind IS NULL
                          AND holder_id IS NULL
                          AND instance_id IS NULL
                          AND worker_id IS NULL
                          AND job_id IS NULL
                          AND fencing_token IS NULL
                        """
                    ),
                    {
                        "control_epoch": next_browser_epoch,
                        "record_version": next_browser_version,
                        "updated_at": timestamp,
                        "session_id": session_id,
                        "expected_record_version": (
                            expected_browser_record_version
                        ),
                    },
                )
                if browser_fenced.rowcount != 1:
                    raise SettlementCaptureStoreConflictError(
                        "browser control changed during access rollover"
                    )
                connection.execute(
                    text(
                        """
                        INSERT INTO browser_control_events (
                            session_id, event_type, control_epoch,
                            payload_json, created_at
                        ) VALUES (
                            :session_id, :event_type, :control_epoch,
                            :payload_json, :created_at
                        )
                        """
                    ),
                    {
                        "session_id": session_id,
                        "event_type": (
                            "browser.access_window_rebound"
                        ),
                        "control_epoch": next_browser_epoch,
                        "payload_json": _canonical(
                            {
                                "authority_sha256": authority_sha256,
                                "new_access_window_id": (
                                    new_access_window_id
                                ),
                                "old_access_window_id": (
                                    invocation.access_window_id
                                ),
                            }
                        ),
                        "created_at": timestamp,
                    },
                )

                if old_row["consumed_at"] is None:
                    old_version = int(old_row["record_version"])
                    retired = connection.execute(
                        update(PLATFORM_ACCESS_WINDOWS)
                        .where(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id
                            == invocation.access_window_id,
                            PLATFORM_ACCESS_WINDOWS.c.record_version
                            == old_version,
                            PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                        )
                        .values(
                            consumed_at=timestamp,
                            record_version=old_version + 1,
                            updated_at=timestamp,
                        )
                    )
                    if retired.rowcount != 1:
                        raise SettlementCaptureStoreConflictError(
                            "prior access window changed concurrently"
                        )
                    connection.execute(
                        PLATFORM_ACCESS_EVENTS.insert().values(
                            access_window_id=invocation.access_window_id,
                            event_type="consumed",
                            record_version=old_version + 1,
                            created_at=timestamp,
                        )
                    )

                next_version = invocation.record_version + 1
                rebound = connection.execute(
                    update(SETTLEMENT_CAPTURE_INVOCATIONS)
                    .where(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                        == invocation.invocation_id,
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.record_version
                        == expected_invocation_record_version,
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.access_window_id
                        == invocation.access_window_id,
                    )
                    .values(
                        access_window_id=new_access_window_id,
                        record_version=next_version,
                        updated_at=timestamp,
                    )
                )
                if rebound.rowcount != 1:
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture rollover changed concurrently"
                    )
                connection.execute(
                    PLATFORM_CONTROL_IDEMPOTENCY.insert().values(
                        operation=operation,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        session_id=session_id,
                        access_window_id=new_access_window_id,
                        result_record_version=next_version,
                        created_at=timestamp,
                    )
                )
                connection.execute(
                    OUTBOX.insert().values(
                        event_type=(
                            "settlement_capture.access_window_rebound"
                        ),
                        aggregate_type="settlement_capture",
                        aggregate_id=job_id,
                        record_version=next_version,
                        payload_json=_canonical(
                            {
                                **authority_payload,
                                "authority_sha256": authority_sha256,
                            }
                        ),
                        created_at=timestamp,
                    )
                )
                updated_invocation = self._get(
                    connection,
                    invocation.invocation_id,
                )
                return SettlementCaptureAccessRolloverRecord(
                    invocation=updated_invocation,
                    old_access_window_id=invocation.access_window_id,
                    new_access_window_id=new_access_window_id,
                    idempotent_replay=False,
                )
        except IntegrityError as exc:
            raise SettlementCaptureStoreConflictError(
                "settlement capture rollover changed concurrently"
            ) from exc

    def target_kind(
        self,
        invocation_id: str,
    ) -> ShadowBatchTargetKind:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(
                    PLATFORM_ACCESS_WINDOWS.c.purpose,
                    JOBS.c.run_mode,
                )
                .join(
                    SETTLEMENT_CAPTURE_INVOCATIONS,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.access_window_id
                    == PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                )
                .where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                    == invocation_id
                )
                .join(
                    JOBS,
                    JOBS.c.job_id
                    == SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id,
                )
            ).one_or_none()
        if row is None:
            raise SettlementCaptureStoreConflictError(
                "settlement capture target authority is unavailable"
            )
        if str(row.run_mode) == "operational":
            return ShadowBatchTargetKind.OPERATIONAL_COMPAT
        return _target_for_purpose(
            AccessPurpose(str(row.purpose))
        )

    def create_start(
        self,
        *,
        target_kind: ShadowBatchTargetKind,
        source_scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
        session_id: str,
        source_build_sha256: str,
        contract_canonical_sha256: str,
        contract_file_sha256: str,
        contract_selection_sha256: str,
        identity_context_sha256: str,
        duration_minutes: int,
        legacy_idle_confirmed: bool,
        no_settlement_or_payment_confirmed: bool,
        same_account_session_risk_accepted: bool,
        idempotency_key: str,
        request_hash: str,
        now: datetime | None = None,
        business_session_id: str | None = None,
        business_session_expected_record_version: int | None = None,
        business_session_confirmation_sha256: str | None = None,
        business_session_expires_at: datetime | None = None,
        capture_strategy: str = "legacy",
    ) -> SettlementCaptureStartRecord:
        """Create every scheduler-visible start authority in one transaction."""

        if not isinstance(target_kind, ShadowBatchTargetKind):
            raise SettlementCaptureStoreConflictError(
                "settlement capture target is invalid"
            )
        capture_scope, capture_page_size = _capture_contract_for_target(
            target_kind,
            source_scope,
        )
        if capture_strategy not in {"legacy", "batch_v1"} or (
            capture_strategy == "batch_v1"
            and target_kind
            is not ShadowBatchTargetKind.OPERATIONAL_COMPAT
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture strategy is invalid"
            )
        if (
            not isinstance(session_id, str)
            or not session_id
            or len(session_id) > 100
            or not isinstance(idempotency_key, str)
            or not idempotency_key
            or len(idempotency_key) > 200
            or _SHA256.fullmatch(request_hash) is None
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture start identity is invalid"
            )
        business_session_bound = business_session_id is not None
        if business_session_bound != (
            business_session_expected_record_version is not None
        ):
            raise SettlementCaptureStoreConflictError(
                "business connection session binding is incomplete"
            )
        if business_session_bound and (
            target_kind is not ShadowBatchTargetKind.OPERATIONAL_COMPAT
            or not isinstance(business_session_id, str)
            or not business_session_id
            or len(business_session_id) > 32
            or isinstance(
                business_session_expected_record_version,
                bool,
            )
            or not isinstance(
                business_session_expected_record_version,
                int,
            )
            or business_session_expected_record_version < 1
        ):
            raise SettlementCaptureStoreConflictError(
                "business connection session binding is invalid"
            )
        business_session_created = (
            business_session_confirmation_sha256 is not None
        )
        if business_session_created != (
            business_session_expires_at is not None
        ):
            raise SettlementCaptureStoreConflictError(
                "business connection session creation is incomplete"
            )
        if business_session_created and (
            business_session_bound
            or target_kind
            is not ShadowBatchTargetKind.OPERATIONAL_COMPAT
            or not isinstance(
                business_session_confirmation_sha256,
                str,
            )
            or _SHA256.fullmatch(
                business_session_confirmation_sha256
            )
            is None
        ):
            raise SettlementCaptureStoreConflictError(
                "business connection session creation is invalid"
            )
        maximum_duration = (
            720
            if target_kind
            is ShadowBatchTargetKind.OPERATIONAL_COMPAT
            else 120
        )
        if (
            isinstance(duration_minutes, bool)
            or not isinstance(duration_minutes, int)
            or not 60 <= duration_minutes <= maximum_duration
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture duration must be between 60 and "
                f"{maximum_duration} minutes"
            )
        for label, value in (
            ("source build SHA-256", source_build_sha256),
            ("contract canonical SHA-256", contract_canonical_sha256),
            ("contract file SHA-256", contract_file_sha256),
            ("contract selection SHA-256", contract_selection_sha256),
            ("identity context SHA-256", identity_context_sha256),
        ):
            _require_sha256(value, label=label)

        operation = _START_OPERATION
        instant = datetime.now(UTC) if now is None else now
        timestamp = _timestamp(instant)
        business_session_expiry = (
            None
            if business_session_expires_at is None
            else _timestamp(business_session_expires_at)
        )
        if (
            business_session_created
            and business_session_expires_at is not None
            and business_session_expires_at <= instant
        ):
            raise SettlementCaptureStoreConflictError(
                "business connection session expiry is invalid"
            )
        purpose = _purpose_for_target(target_kind)
        conflict_key = f"settlement_capture:{target_kind.value}"
        fixture_id = f"settlement-capture-{target_kind.value}-v1"
        scope_fingerprint = hashlib.sha256(
            f"settlement_capture:{fixture_id}".encode()
        ).hexdigest()

        try:
            with self._commit_gate.transaction(self._engine) as connection:
                replay = (
                    connection.execute(
                        select(IDEMPOTENCY_RECORDS).where(
                            IDEMPOTENCY_RECORDS.c.operation == operation,
                            IDEMPOTENCY_RECORDS.c.idempotency_key
                            == idempotency_key,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if replay is not None:
                    if str(replay["request_hash"]) != request_hash:
                        raise IdempotencyConflictError(
                            "the idempotency key belongs to a different request"
                        )
                    replay_job_id = str(replay["job_id"])
                    invocation_row = (
                        connection.execute(
                            select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                                SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                                == replay_job_id
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    item_id = connection.execute(
                        select(WORK_ITEMS.c.work_item_id).where(
                            WORK_ITEMS.c.job_id == replay_job_id
                        )
                    ).scalar_one_or_none()
                    if invocation_row is None or item_id is None:
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture start replay is incomplete"
                        )
                    invocation = _record(invocation_row)
                    access_row = (
                        connection.execute(
                            select(PLATFORM_ACCESS_WINDOWS).where(
                                PLATFORM_ACCESS_WINDOWS.c.access_window_id
                                == invocation.access_window_id
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if access_row is None:
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture access replay is unavailable"
                        )
                    replay_access = _access_record(access_row)
                    replay_run_mode = connection.execute(
                        select(JOBS.c.run_mode).where(
                            JOBS.c.job_id == replay_job_id
                        )
                    ).scalar_one()
                    replay_target = (
                        ShadowBatchTargetKind.OPERATIONAL_COMPAT
                        if replay_run_mode == "operational"
                        else _target_for_purpose(
                            replay_access.purpose
                        )
                    )
                    if replay_target is not target_kind:
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture target replay changed"
                        )
                    if (
                        invocation.scope != capture_scope
                        or invocation.page_size != capture_page_size
                    ):
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture source scope replay changed"
                        )
                    if business_session_bound or business_session_created:
                        business_read = connection.execute(
                            select(BUSINESS_CONNECTION_READS).where(
                                BUSINESS_CONNECTION_READS.c.job_id
                                == replay_job_id,
                            )
                        ).mappings().one_or_none()
                        if business_read is None:
                            raise SettlementCaptureStoreConflictError(
                                "business connection read replay is incomplete"
                            )
                        if (
                            business_session_bound
                            and str(business_read["business_session_id"])
                            != business_session_id
                        ):
                            raise SettlementCaptureStoreConflictError(
                                "business connection read replay changed"
                            )
                    return SettlementCaptureStartRecord(
                        target_kind=target_kind,
                        job_id=replay_job_id,
                        work_item_id=str(item_id),
                        access_window=replay_access,
                        access_record_version=int(
                            access_row["record_version"]
                        ),
                        invocation=invocation,
                        created=False,
                    )

                conflict = (
                    connection.execute(
                        select(
                            CONFLICT_KEYS.c.job_id,
                            CONFLICT_KEYS.c.active,
                        ).where(
                            CONFLICT_KEYS.c.conflict_key == conflict_key
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if conflict is not None and bool(conflict["active"]):
                    raise ActiveScopeConflictError(
                        "an active job already owns this conflict key"
                    )
                business_session = None
                if business_session_bound:
                    business_session = (
                        connection.execute(
                            select(BUSINESS_CONNECTION_SESSIONS).where(
                                BUSINESS_CONNECTION_SESSIONS.c.business_session_id
                                == business_session_id
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if (
                        business_session is None
                        or business_session["status"] != "active"
                        or int(business_session["record_version"])
                        != business_session_expected_record_version
                        or str(business_session["platform_session_id"])
                        != session_id
                        or str(business_session["build_sha256"])
                        != source_build_sha256
                        or _parse_timestamp(business_session["expires_at"])
                        <= instant
                    ):
                        raise SettlementCaptureStoreConflictError(
                            "business connection session is stale or expired"
                        )
                if business_session_created:
                    active_business_sessions = tuple(
                        connection.execute(
                            select(BUSINESS_CONNECTION_SESSIONS).where(
                                BUSINESS_CONNECTION_SESSIONS.c.platform_session_id
                                == session_id,
                                BUSINESS_CONNECTION_SESSIONS.c.status
                                == "active",
                            )
                        ).mappings()
                    )
                    for active_session in active_business_sessions:
                        active_expiry = _parse_timestamp(
                            active_session["expires_at"]
                        )
                        if active_expiry > instant:
                            raise SettlementCaptureStoreConflictError(
                                "an active business connection session already exists"
                            )
                        connection.execute(
                            update(BUSINESS_CONNECTION_SESSIONS)
                            .where(
                                BUSINESS_CONNECTION_SESSIONS.c.business_session_id
                                == active_session["business_session_id"],
                                BUSINESS_CONNECTION_SESSIONS.c.record_version
                                == active_session["record_version"],
                            )
                            .values(
                                status="closed",
                                closed_at=timestamp,
                                close_reason="expired",
                                record_version=(
                                    int(active_session["record_version"])
                                    + 1
                                ),
                                updated_at=timestamp,
                            )
                        )
                overlapping = tuple(
                    connection.execute(
                        select(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                            PLATFORM_ACCESS_WINDOWS.c.purpose,
                            JOBS.c.run_mode,
                        )
                        .outerjoin(
                            JOBS,
                            JOBS.c.job_id
                            == PLATFORM_ACCESS_WINDOWS.c.job_id,
                        )
                        .where(
                            PLATFORM_ACCESS_WINDOWS.c.session_id
                            == session_id,
                            PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                        )
                    ).mappings()
                )
                if overlapping and (
                    target_kind
                    is not ShadowBatchTargetKind.OPERATIONAL_COMPAT
                    or any(
                        str(row["run_mode"]) != "operational"
                        for row in overlapping
                    )
                ):
                    raise SettlementCaptureStoreConflictError(
                        "browser session already has an unconsumed access window"
                    )

                sequence = next_sequence(connection)
                job_id = uuid4().hex
                work_item_id = uuid4().hex
                grant = issue_access_window(
                    purpose=purpose,
                    job_id=job_id,
                    session_id=session_id,
                    build_sha256=source_build_sha256,
                    duration_minutes=duration_minutes,
                    legacy_idle_confirmed=legacy_idle_confirmed,
                    no_settlement_or_payment_confirmed=(
                        no_settlement_or_payment_confirmed
                    ),
                    same_account_session_risk_accepted=(
                        same_account_session_risk_accepted
                    ),
                    run_mode=(
                        "operational"
                        if target_kind
                        is ShadowBatchTargetKind.OPERATIONAL_COMPAT
                        else "shadow"
                    ),
                    now=instant,
                )
                invocation_id = _invocation_id(
                    job_id=job_id,
                    access_window_id=grant.access_window_id,
                    source_build_sha256=source_build_sha256,
                    contract_canonical_sha256=(
                        contract_canonical_sha256
                    ),
                    contract_file_sha256=contract_file_sha256,
                    contract_selection_sha256=(
                        contract_selection_sha256
                    ),
                    identity_context_sha256=identity_context_sha256,
                    scope=capture_scope,
                    page_size=capture_page_size,
                )

                connection.execute(
                    JOBS.insert().values(
                        job_id=job_id,
                        task_type="settlement_capture",
                        scope_label=(
                            "业务待结算采集"
                            if target_kind
                            is ShadowBatchTargetKind.OPERATIONAL_COMPAT
                            else (
                                "正式锁定集采集"
                                if target_kind
                                is ShadowBatchTargetKind.CURRENT_LOCKED_50
                                else "真实影子批次采集"
                            )
                        ),
                        scope_fixture_id=fixture_id,
                        scope_fingerprint=scope_fingerprint,
                        run_mode=(
                            "operational"
                            if target_kind
                            is ShadowBatchTargetKind.OPERATIONAL_COMPAT
                            else "shadow"
                        ),
                        status=JobStatus.QUEUED.value,
                        current_stage="settlement_capture.read",
                        diagnostic_code=None,
                        job_kind="business",
                        ocr_execution_mode="fake",
                        conflict_key=conflict_key,
                        created_sequence=sequence,
                        record_version=1,
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )
                if conflict is None:
                    connection.execute(
                        CONFLICT_KEYS.insert().values(
                            conflict_key=conflict_key,
                            job_id=job_id,
                            active=1,
                        )
                    )
                else:
                    connection.execute(
                        update(CONFLICT_KEYS)
                        .where(
                            CONFLICT_KEYS.c.conflict_key == conflict_key
                        )
                        .values(job_id=job_id, active=1)
                    )
                connection.execute(
                    WORK_ITEMS.insert().values(
                        work_item_id=work_item_id,
                        job_id=job_id,
                        record_version=1,
                        waybill_number=f"capture:{target_kind.value}",
                        vehicle_number="待结算数据采集",
                        status=WorkItemStatus.QUEUED.value,
                        current_stage="settlement_capture.read",
                        item_index=0,
                        attempt_count=0,
                        download_complete=0,
                        loading_ocr_complete=0,
                        unloading_ocr_complete=0,
                        ready_sequence=sequence,
                    )
                )
                connection.execute(
                    PLATFORM_ACCESS_WINDOWS.insert().values(
                        **grant.to_persisted_payload(),
                        record_version=1,
                        idempotency_key=f"capture-start:{job_id}",
                        request_hash=request_hash,
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )
                connection.execute(
                    PLATFORM_ACCESS_EVENTS.insert().values(
                        access_window_id=grant.access_window_id,
                        event_type="issued",
                        record_version=1,
                        created_at=timestamp,
                    )
                )
                created_business_session_id = None
                if business_session_created:
                    assert business_session_confirmation_sha256 is not None
                    assert business_session_expiry is not None
                    created_business_session_id = uuid4().hex
                    connection.execute(
                        BUSINESS_CONNECTION_SESSIONS.insert().values(
                            business_session_id=created_business_session_id,
                            platform_session_id=session_id,
                            build_sha256=source_build_sha256,
                            login_access_window_id=grant.access_window_id,
                            confirmation_sha256=(
                                business_session_confirmation_sha256
                            ),
                            status="active",
                            expires_at=business_session_expiry,
                            closed_at=None,
                            close_reason=None,
                            record_version=1,
                            created_at=timestamp,
                            updated_at=timestamp,
                        )
                    )
                connection.execute(
                    SETTLEMENT_CAPTURE_INVOCATIONS.insert().values(
                        invocation_id=invocation_id,
                        job_id=job_id,
                        access_window_id=grant.access_window_id,
                        scope=capture_scope,
                        page_size=capture_page_size,
                        source_build_sha256=source_build_sha256,
                        contract_canonical_sha256=(
                            contract_canonical_sha256
                        ),
                        contract_file_sha256=contract_file_sha256,
                        contract_selection_sha256=(
                            contract_selection_sha256
                        ),
                        identity_context_sha256=identity_context_sha256,
                        status="collecting",
                        manifest_sha256=None,
                        manifest_json=None,
                        selection_manifest_sha256=None,
                        batch_manifest_sha256=None,
                        diagnostic_code=None,
                        record_version=1,
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )
                connection.execute(
                    SETTLEMENT_CAPTURE_STRATEGIES.insert().values(
                        job_id=job_id,
                        strategy=capture_strategy,
                        created_at=timestamp,
                    )
                )
                connection.execute(
                    IDEMPOTENCY_RECORDS.insert().values(
                        operation=operation,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        job_id=job_id,
                        created_at=timestamp,
                    )
                )
                connection.execute(
                    OUTBOX.insert().values(
                        event_type="job.queued",
                        aggregate_type="job",
                        aggregate_id=job_id,
                        record_version=1,
                        payload_json=_canonical(
                            {
                                "job_id": job_id,
                                "job_status": JobStatus.QUEUED.value,
                            }
                        ),
                        created_at=timestamp,
                    )
                )
                if (
                    business_session is not None
                    or created_business_session_id is not None
                ):
                    bound_session_id = (
                        created_business_session_id
                        if created_business_session_id is not None
                        else business_session_id
                    )
                    bound_record_version = (
                        1
                        if created_business_session_id is not None
                        else business_session_expected_record_version
                    )
                    assert bound_session_id is not None
                    assert bound_record_version is not None
                    connection.execute(
                        BUSINESS_CONNECTION_READS.insert().values(
                            business_session_id=bound_session_id,
                            job_id=job_id,
                            access_window_id=grant.access_window_id,
                            created_at=timestamp,
                        )
                    )
                    updated_session = connection.execute(
                        update(BUSINESS_CONNECTION_SESSIONS)
                        .where(
                            BUSINESS_CONNECTION_SESSIONS.c.business_session_id
                            == bound_session_id,
                            BUSINESS_CONNECTION_SESSIONS.c.record_version
                            == bound_record_version,
                        )
                        .values(
                            record_version=bound_record_version + 1,
                            updated_at=timestamp,
                        )
                    )
                    if updated_session.rowcount != 1:
                        raise SettlementCaptureStoreConflictError(
                            "business connection session changed concurrently"
                        )
                return SettlementCaptureStartRecord(
                    target_kind=target_kind,
                    job_id=job_id,
                    work_item_id=work_item_id,
                    access_window=grant,
                    access_record_version=1,
                    invocation=self._get(connection, invocation_id),
                    created=True,
                )
        except AccessWindowError as exc:
            raise SettlementCaptureStoreConflictError(str(exc)) from exc
        except IntegrityError as exc:
            raise SettlementCaptureStoreConflictError(
                "settlement capture start changed concurrently"
            ) from exc

    def create(
        self,
        *,
        job_id: str,
        access_window_id: str,
        source_build_sha256: str,
        contract_canonical_sha256: str,
        contract_file_sha256: str,
        contract_selection_sha256: str,
        identity_context_sha256: str,
        scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
        now: datetime | None = None,
    ) -> SettlementCaptureInvocationRecord:
        for label, value in (
            ("source build SHA-256", source_build_sha256),
            ("contract canonical SHA-256", contract_canonical_sha256),
            ("contract file SHA-256", contract_file_sha256),
            ("contract selection SHA-256", contract_selection_sha256),
            ("identity context SHA-256", identity_context_sha256),
        ):
            _require_sha256(value, label=label)
        if (
            not isinstance(job_id, str)
            or not job_id
            or len(job_id) > 32
            or not isinstance(access_window_id, str)
            or not access_window_id
            or len(access_window_id) > 32
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture binding is invalid"
            )
        instant = datetime.now(UTC) if now is None else now
        timestamp = _timestamp(instant)
        if scope == CURRENT_PENDING_SETTLEMENT_SCOPE:
            page_size = SETTLEMENT_CAPTURE_PAGE_SIZE
        elif scope == HISTORICAL_SETTLED_SCOPE:
            page_size = HISTORICAL_SETTLEMENT_CAPTURE_PAGE_SIZE
        else:
            raise SettlementCaptureStoreConflictError(
                "settlement capture scope is invalid"
            )
        invocation_id = _invocation_id(
            job_id=job_id,
            access_window_id=access_window_id,
            source_build_sha256=source_build_sha256,
            contract_canonical_sha256=contract_canonical_sha256,
            contract_file_sha256=contract_file_sha256,
            contract_selection_sha256=contract_selection_sha256,
            identity_context_sha256=identity_context_sha256,
            scope=scope,
            page_size=page_size,
        )
        try:
            with self._commit_gate.transaction(self._engine) as connection:
                existing = (
                    connection.execute(
                        select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                            (
                                SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                                == invocation_id
                            )
                            | (
                                SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                                == job_id
                            )
                            | (
                                SETTLEMENT_CAPTURE_INVOCATIONS.c.access_window_id
                                == access_window_id
                            )
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    record = _record(existing)
                    if (
                        record.invocation_id != invocation_id
                        or record.job_id != job_id
                        or record.access_window_id != access_window_id
                    ):
                        raise SettlementCaptureStoreConflictError(
                            "settlement capture binding is already owned"
                        )
                    return record

                job_type = connection.execute(
                    select(JOBS.c.task_type).where(
                        JOBS.c.job_id == job_id
                    )
                ).scalar_one_or_none()
                if job_type != "settlement_capture":
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture job is unavailable"
                    )
                access = (
                    connection.execute(
                        select(PLATFORM_ACCESS_WINDOWS).where(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id
                            == access_window_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if (
                    access is None
                    or str(access["job_id"]) != job_id
                    or str(access["purpose"]) not in _ALLOWED_PURPOSES
                    or str(access["build_sha256"]) != source_build_sha256
                ):
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture access authority is invalid"
                    )
                if access["consumed_at"] is not None:
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture access window is consumed"
                    )
                if _parse_timestamp(access["expires_at"]) <= instant:
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture access window is expired"
                    )
                connection.execute(
                    SETTLEMENT_CAPTURE_INVOCATIONS.insert().values(
                        invocation_id=invocation_id,
                        job_id=job_id,
                        access_window_id=access_window_id,
                        scope=scope,
                        page_size=page_size,
                        source_build_sha256=source_build_sha256,
                        contract_canonical_sha256=(
                            contract_canonical_sha256
                        ),
                        contract_file_sha256=contract_file_sha256,
                        contract_selection_sha256=(
                            contract_selection_sha256
                        ),
                        identity_context_sha256=identity_context_sha256,
                        status="collecting",
                        manifest_sha256=None,
                        manifest_json=None,
                        selection_manifest_sha256=None,
                        batch_manifest_sha256=None,
                        diagnostic_code=None,
                        record_version=1,
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )
                return self._get(connection, invocation_id)
        except IntegrityError as exc:
            raise SettlementCaptureStoreConflictError(
                "settlement capture binding changed concurrently"
            ) from exc

    @staticmethod
    def _validate_checkpoint_chain(
        connection: Connection,
        *,
        manifest: SettlementCaptureManifest,
    ) -> None:
        bindings: list[ShadowCaptureBinding] = []
        expected_read_bindings: list[
            SettlementCaptureReadAccessBinding
        ] = []
        lineage = manifest.access_window_lineage
        for source in sorted(
            manifest.sources,
            key=lambda value: value.page_number,
        ):
            payload_json = connection.execute(
                select(CHECKPOINTS.c.payload_json)
                .where(
                    CHECKPOINTS.c.owner_kind == "chengfeng_capture",
                    CHECKPOINTS.c.owner_id == source.capture_id,
                )
                .order_by(CHECKPOINTS.c.sequence.desc())
                .limit(1)
            ).scalar_one_or_none()
            if payload_json is None:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture checkpoint is missing"
                )
            try:
                payload = json.loads(str(payload_json))
                checkpoint = DurableCaptureCheckpoint.from_payload(payload)
            except (
                CaptureCheckpointError,
                TypeError,
                json.JSONDecodeError,
                ValueError,
            ) as exc:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture checkpoint is invalid"
                ) from exc
            if (
                _canonical_sha256(payload) != source.checkpoint_sha256
                or checkpoint.capture_id != source.capture_id
                or checkpoint.job_id != source.job_id
                or checkpoint.scope != source.scope
                or checkpoint.page_number != source.page_number
                or checkpoint.page_size != source.page_size
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture checkpoint authority changed"
                )
            access_by_read = dict(
                checkpoint.read_access_window_ids
            )
            if lineage is not None:
                ordered_reads: list[tuple[str, str, str]] = [
                    (
                        "list",
                        _canonical_sha256(
                            {
                                "capture_id": checkpoint.capture_id,
                                "read_kind": "list",
                            }
                        ),
                        capture_read_key(ChengfengStage.LIST_QUERY),
                    )
                ]
                ordered_reads.extend(
                    (
                        "detail",
                        hashlib.sha256(
                            detail.platform_waybill_id.encode(
                                "utf-8"
                            )
                        ).hexdigest(),
                        capture_read_key(
                            ChengfengStage.DETAIL_QUERY,
                            detail.platform_waybill_id,
                        ),
                    )
                    for detail in checkpoint.details
                )
                ordered_reads.extend(
                    (
                        "image",
                        hashlib.sha256(
                            ticket.ticket_ref.encode("utf-8")
                        ).hexdigest(),
                        capture_read_key(
                            ChengfengStage.IMAGE_DOWNLOAD,
                            ticket.ticket_ref,
                        ),
                    )
                    for detail in checkpoint.details
                    for ticket in detail.tickets
                )
                ordered_reads.extend(
                    (
                        "detail",
                        hashlib.sha256(
                            key.encode("utf-8")
                        ).hexdigest(),
                        key,
                    )
                    for key in access_by_read
                    if key.startswith("detail-refresh:")
                )
                if (
                    not access_by_read
                    and len(lineage.access_window_ids) == 1
                ):
                    access_by_read = {
                        key: lineage.access_window_ids[0]
                        for _kind, _subject, key in ordered_reads
                    }
                if (
                    set(access_by_read)
                    != {
                        key
                        for _kind, _subject, key in ordered_reads
                    }
                    or access_by_read["list"]
                    != source.access_window_id
                ):
                    raise SettlementCaptureStoreConflictError(
                        "settlement capture checkpoint access lineage changed"
                    )
                expected_read_bindings.extend(
                    SettlementCaptureReadAccessBinding(
                        capture_id=checkpoint.capture_id,
                        read_kind=read_kind,
                        subject_sha256=subject_sha256,
                        access_window_id=access_by_read[key],
                    )
                    for read_kind, subject_sha256, key in ordered_reads
                )
            bindings.append(
                ShadowCaptureBinding(
                    checkpoint=checkpoint,
                    access_window_id=(
                        source.access_window_id
                        if lineage is None
                        else lineage.access_window_ids[0]
                    ),
                    source_build_sha256=manifest.source_build_sha256,
                    contract_canonical_sha256=(
                        manifest.contract_canonical_sha256
                    ),
                    contract_file_sha256=(
                        manifest.contract_file_sha256
                    ),
                    contract_selection_sha256=(
                        manifest.contract_selection_sha256
                    ),
                )
            )
        if lineage is not None:
            window_position = {
                access_window_id: index
                for index, access_window_id in enumerate(
                    lineage.access_window_ids
                )
            }
            if any(
                binding.access_window_id not in window_position
                for binding in expected_read_bindings
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture read access lineage changed"
                )
            kind_position = {
                "list": 0,
                "detail": 1,
                "image": 2,
            }
            canonical_expected = tuple(
                sorted(
                    expected_read_bindings,
                    key=lambda binding: (
                        window_position[binding.access_window_id],
                        kind_position[binding.read_kind],
                        binding.capture_id,
                        binding.subject_sha256,
                    ),
                )
            )
            if canonical_expected != manifest.read_access_bindings:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture read access lineage changed"
                )
        try:
            _validate_complete_pagination(tuple(bindings))
        except ValueError as exc:
            raise SettlementCaptureStoreConflictError(
                "settlement capture pagination is incomplete"
            ) from exc

    @staticmethod
    def _validate_manifest_binding(
        *,
        invocation: SettlementCaptureInvocationRecord,
        manifest: SettlementCaptureManifest,
        access_window_lineage: SettlementCaptureAccessWindowLineage,
    ) -> None:
        manifest.verify_integrity()
        if (
            manifest.source_job_id != invocation.job_id
            or manifest.source_access_window_id
            != invocation.access_window_id
            or manifest.source_build_sha256
            != invocation.source_build_sha256
            or manifest.contract_canonical_sha256
            != invocation.contract_canonical_sha256
            or manifest.contract_file_sha256
            != invocation.contract_file_sha256
            or manifest.contract_selection_sha256
            != invocation.contract_selection_sha256
            or manifest.identity_context_sha256
            != invocation.identity_context_sha256
            or any(
                source.scope != invocation.scope
                or source.page_size != invocation.page_size
                for source in manifest.sources
            )
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture manifest authority does not match"
            )
        if manifest.access_window_lineage is None:
            if (
                len(access_window_lineage.access_window_ids) != 1
                or manifest.source_access_window_id
                != access_window_lineage.access_window_ids[0]
            ):
                raise SettlementCaptureStoreConflictError(
                    "legacy settlement capture cannot span access windows"
                )
        elif (
            manifest.access_window_lineage
            != access_window_lineage
        ):
            raise SettlementCaptureStoreConflictError(
                "settlement capture manifest access lineage does not match"
            )

    @staticmethod
    def _validate_protected_identities(
        *,
        manifest: SettlementCaptureManifest,
        protected_identities: tuple[ProtectedBusinessIdentity, ...],
    ) -> None:
        if (
            not isinstance(protected_identities, tuple)
            or any(
                not isinstance(value, ProtectedBusinessIdentity)
                for value in protected_identities
            )
        ):
            raise SettlementCaptureStoreConflictError(
                "protected business identity mapping is invalid"
            )
        expected = {
            item.item_identity_sha256 for item in manifest.items
        }
        actual = {
            item.item_identity_sha256 for item in protected_identities
        }
        if (
            expected != actual
            or len(actual) != len(protected_identities)
            or len(
                {
                    item.platform_waybill_id
                    for item in protected_identities
                }
            )
            != len(protected_identities)
            or len(
                {item.waybill_number for item in protected_identities}
            )
            != len(protected_identities)
            or not {
                item.source_page_number
                for item in protected_identities
            }.issubset(
                {source.page_number for source in manifest.sources}
            )
        ):
            raise SettlementCaptureStoreConflictError(
                "protected business identity mapping does not reconcile"
            )

    def seal(
        self,
        *,
        invocation_id: str,
        expected_record_version: int,
        manifest: SettlementCaptureManifest,
        protected_identities: tuple[ProtectedBusinessIdentity, ...],
        now: datetime | None = None,
    ) -> SettlementCaptureInvocationRecord:
        instant = datetime.now(UTC) if now is None else now
        timestamp = _timestamp(instant)
        try:
            self._validate_protected_identities(
                manifest=manifest,
                protected_identities=protected_identities,
            )
        except SettlementCaptureContractError as exc:
            raise SettlementCaptureStoreConflictError(
                "settlement capture manifest is invalid"
            ) from exc
        manifest_json = _canonical(manifest.to_payload())
        with self._commit_gate.transaction(self._engine) as connection:
            current = self._get(connection, invocation_id)
            access_window_lineage = self._access_window_lineage(
                connection,
                current,
            )
            self._validate_manifest_binding(
                invocation=current,
                manifest=manifest,
                access_window_lineage=access_window_lineage,
            )
            if current.status in {
                "sealed",
                "selected",
                "selection_blocked",
            }:
                if current.manifest_sha256 != manifest.canonical_sha256:
                    raise SettlementCaptureStoreConflictError(
                        "sealed settlement capture differs"
                    )
                self._validate_stored_identities(
                    connection,
                    invocation_id=invocation_id,
                    protected_identities=protected_identities,
                )
                return current
            if current.status != "collecting":
                raise SettlementCaptureStoreConflictError(
                    "settlement capture invocation is terminal"
                )
            if current.record_version != expected_record_version:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture record version is stale"
                )
            self._validate_checkpoint_chain(
                connection,
                manifest=manifest,
            )
            access = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == current.access_window_id
                    )
                )
                .mappings()
                .one()
            )
            if (
                str(access["job_id"]) != current.job_id
                or str(access["purpose"]) not in _ALLOWED_PURPOSES
                or str(access["build_sha256"])
                != current.source_build_sha256
            ):
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access authority changed"
                )
            if access["consumed_at"] is not None:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access window is consumed"
                )
            if _parse_timestamp(access["expires_at"]) <= instant:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access window is expired"
                )

            for protected in protected_identities:
                connection.execute(
                    SETTLEMENT_CAPTURE_IDENTITIES.insert().values(
                        invocation_id=invocation_id,
                        item_identity_sha256=(
                            protected.item_identity_sha256
                        ),
                        platform_waybill_id=protected.platform_waybill_id,
                        waybill_number=protected.waybill_number,
                        vehicle_number=protected.vehicle_number,
                        source_page_number=protected.source_page_number,
                        created_at=timestamp,
                    )
                )
            updated = connection.execute(
                update(SETTLEMENT_CAPTURE_INVOCATIONS)
                .where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                    == invocation_id,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.record_version
                    == expected_record_version,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.status
                    == "collecting",
                )
                .values(
                    status="sealed",
                    manifest_sha256=manifest.canonical_sha256,
                    manifest_json=manifest_json,
                    record_version=expected_record_version + 1,
                    updated_at=timestamp,
                )
            )
            if updated.rowcount != 1:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture record version changed"
                )
            access_version = int(access["record_version"])
            consumed = connection.execute(
                update(PLATFORM_ACCESS_WINDOWS)
                .where(
                    PLATFORM_ACCESS_WINDOWS.c.access_window_id
                    == current.access_window_id,
                    PLATFORM_ACCESS_WINDOWS.c.record_version
                    == access_version,
                    PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                )
                .values(
                    consumed_at=timestamp,
                    record_version=access_version + 1,
                    updated_at=timestamp,
                )
            )
            if consumed.rowcount != 1:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture access window changed"
                )
            connection.execute(
                PLATFORM_ACCESS_EVENTS.insert().values(
                    access_window_id=current.access_window_id,
                    event_type="consumed",
                    record_version=access_version + 1,
                    created_at=timestamp,
                )
            )
            return self._get(connection, invocation_id)

    def mark_selected(
        self,
        *,
        invocation_id: str,
        expected_record_version: int,
        selection_manifest_sha256: str,
        batch_manifest_sha256: str,
        now: datetime | None = None,
    ) -> SettlementCaptureInvocationRecord:
        _require_sha256(
            selection_manifest_sha256,
            label="selection manifest SHA-256",
        )
        _require_sha256(
            batch_manifest_sha256,
            label="batch manifest SHA-256",
        )
        timestamp = _timestamp(
            datetime.now(UTC) if now is None else now
        )
        with self._commit_gate.transaction(self._engine) as connection:
            current = self._get(connection, invocation_id)
            if current.status == "selected":
                if (
                    current.selection_manifest_sha256
                    != selection_manifest_sha256
                    or current.batch_manifest_sha256
                    != batch_manifest_sha256
                ):
                    raise SettlementCaptureStoreConflictError(
                        "selected settlement capture differs"
                    )
                return current
            if current.status != "sealed":
                raise SettlementCaptureStoreConflictError(
                    "only a sealed settlement capture can be selected"
                )
            if current.record_version != expected_record_version:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture record version is stale"
                )
            updated = connection.execute(
                update(SETTLEMENT_CAPTURE_INVOCATIONS)
                .where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                    == invocation_id,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.record_version
                    == expected_record_version,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.status == "sealed",
                )
                .values(
                    status="selected",
                    selection_manifest_sha256=selection_manifest_sha256,
                    batch_manifest_sha256=batch_manifest_sha256,
                    record_version=expected_record_version + 1,
                    updated_at=timestamp,
                )
            )
            if updated.rowcount != 1:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture selection changed concurrently"
                )
            return self._get(connection, invocation_id)

    def mark_operational_ready(
        self,
        *,
        invocation_id: str,
        expected_record_version: int,
        capture_sha256: str,
        now: datetime | None = None,
    ) -> SettlementCaptureInvocationRecord:
        """Seal an operational capture without creating formal Loop 9 evidence."""

        _require_sha256(
            capture_sha256,
            label="operational capture SHA-256",
        )
        timestamp = _timestamp(
            datetime.now(UTC) if now is None else now
        )
        with self._commit_gate.transaction(self._engine) as connection:
            current = self._get(connection, invocation_id)
            run_mode = connection.execute(
                select(JOBS.c.run_mode).where(
                    JOBS.c.job_id == current.job_id
                )
            ).scalar_one()
            if run_mode != "operational":
                raise SettlementCaptureStoreConflictError(
                    "formal capture cannot be marked operational"
                )
            if current.status == "operational_ready":
                if current.manifest_sha256 != capture_sha256:
                    raise SettlementCaptureStoreConflictError(
                        "operational capture identity changed"
                    )
                return current
            if (
                current.status != "collecting"
                or current.record_version != expected_record_version
            ):
                raise SettlementCaptureStoreConflictError(
                    "operational capture state changed"
                )
            updated = connection.execute(
                update(SETTLEMENT_CAPTURE_INVOCATIONS)
                .where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                    == invocation_id,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.record_version
                    == expected_record_version,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.status
                    == "collecting",
                )
                .values(
                    status="operational_ready",
                    manifest_sha256=capture_sha256,
                    manifest_json=None,
                    selection_manifest_sha256=None,
                    batch_manifest_sha256=None,
                    diagnostic_code=None,
                    record_version=expected_record_version + 1,
                    updated_at=timestamp,
                )
            )
            if updated.rowcount != 1:
                raise SettlementCaptureStoreConflictError(
                    "operational capture changed concurrently"
                )
            return self._get(connection, invocation_id)

    def block_selection(
        self,
        *,
        invocation_id: str,
        expected_record_version: int,
        diagnostic_code: str,
        now: datetime | None = None,
    ) -> SettlementCaptureInvocationRecord:
        if (
            not isinstance(diagnostic_code, str)
            or not diagnostic_code
            or len(diagnostic_code) > 100
            or diagnostic_code != diagnostic_code.strip()
        ):
            raise SettlementCaptureStoreConflictError(
                "selection diagnostic code is invalid"
            )
        timestamp = _timestamp(
            datetime.now(UTC) if now is None else now
        )
        with self._commit_gate.transaction(self._engine) as connection:
            current = self._get(connection, invocation_id)
            if current.status == "selection_blocked":
                if current.diagnostic_code != diagnostic_code:
                    raise SettlementCaptureStoreConflictError(
                        "blocked settlement capture diagnostic differs"
                    )
                return current
            if current.status != "sealed":
                raise SettlementCaptureStoreConflictError(
                    "only a sealed settlement capture can be blocked"
                )
            if current.record_version != expected_record_version:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture record version is stale"
                )
            updated = connection.execute(
                update(SETTLEMENT_CAPTURE_INVOCATIONS)
                .where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                    == invocation_id,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.record_version
                    == expected_record_version,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.status == "sealed",
                )
                .values(
                    status="selection_blocked",
                    diagnostic_code=diagnostic_code,
                    record_version=expected_record_version + 1,
                    updated_at=timestamp,
                )
            )
            if updated.rowcount != 1:
                raise SettlementCaptureStoreConflictError(
                    "settlement capture selection changed concurrently"
                )
            return self._get(connection, invocation_id)

    @staticmethod
    def _validate_stored_identities(
        connection: Connection,
        *,
        invocation_id: str,
        protected_identities: tuple[ProtectedBusinessIdentity, ...],
    ) -> None:
        rows = tuple(
            connection.execute(
                select(SETTLEMENT_CAPTURE_IDENTITIES)
                .where(
                    SETTLEMENT_CAPTURE_IDENTITIES.c.invocation_id
                    == invocation_id
                )
                .order_by(
                    SETTLEMENT_CAPTURE_IDENTITIES.c.item_identity_sha256
                )
            ).mappings()
        )
        expected = tuple(
            sorted(
                protected_identities,
                key=lambda value: value.item_identity_sha256,
            )
        )
        actual = tuple(
            ProtectedBusinessIdentity(
                item_identity_sha256=str(row["item_identity_sha256"]),
                platform_waybill_id=str(row["platform_waybill_id"]),
                waybill_number=str(row["waybill_number"]),
                vehicle_number=(
                    None
                    if row["vehicle_number"] is None
                    else str(row["vehicle_number"])
                ),
                source_page_number=int(row["source_page_number"]),
            )
            for row in rows
        )
        if actual != expected:
            raise SettlementCaptureStoreConflictError(
                "stored protected business identity mapping differs"
            )

    def load_manifest(
        self,
        invocation_id: str,
    ) -> SettlementCaptureManifest:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.status,
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.manifest_json,
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.manifest_sha256,
                    ).where(
                        SETTLEMENT_CAPTURE_INVOCATIONS.c.invocation_id
                        == invocation_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        if (
            row is None
            or row["status"]
            not in {"sealed", "selected", "selection_blocked"}
            or row["manifest_json"] is None
            or row["manifest_sha256"] is None
        ):
            raise SettlementCaptureStoreConflictError(
                "sealed settlement capture is unavailable"
            )
        try:
            payload = json.loads(str(row["manifest_json"]))
            manifest = SettlementCaptureManifest.from_payload(payload)
        except (
            SettlementCaptureContractError,
            TypeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise SettlementCaptureStoreConflictError(
                "sealed settlement capture is invalid"
            ) from exc
        if manifest.canonical_sha256 != str(row["manifest_sha256"]):
            raise SettlementCaptureStoreConflictError(
                "sealed settlement capture is invalid"
            )
        with self._engine.connect() as connection:
            invocation = self._get(connection, invocation_id)
            access_window_lineage = self._access_window_lineage(
                connection,
                invocation,
            )
            self._validate_manifest_binding(
                invocation=invocation,
                manifest=manifest,
                access_window_lineage=access_window_lineage,
            )
        return manifest

    def resolve_business_identities(
        self,
        *,
        invocation_id: str,
        item_identity_sha256s: tuple[str, ...],
    ) -> tuple[ProtectedBusinessIdentity, ...]:
        if (
            not isinstance(item_identity_sha256s, tuple)
            or not item_identity_sha256s
            or len(set(item_identity_sha256s))
            != len(item_identity_sha256s)
        ):
            raise SettlementCaptureStoreConflictError(
                "selected business identity request is invalid"
            )
        for value in item_identity_sha256s:
            _require_sha256(value, label="selected item identity")
        with self._engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(SETTLEMENT_CAPTURE_IDENTITIES).where(
                        SETTLEMENT_CAPTURE_IDENTITIES.c.invocation_id
                        == invocation_id,
                        SETTLEMENT_CAPTURE_IDENTITIES.c.item_identity_sha256.in_(
                            item_identity_sha256s
                        ),
                    )
                ).mappings()
            )
        by_id = {
            str(row["item_identity_sha256"]): row for row in rows
        }
        if set(by_id) != set(item_identity_sha256s):
            raise SettlementCaptureStoreConflictError(
                "selected business identity is unavailable"
            )
        return tuple(
            ProtectedBusinessIdentity(
                item_identity_sha256=value,
                platform_waybill_id=str(
                    by_id[value]["platform_waybill_id"]
                ),
                waybill_number=str(by_id[value]["waybill_number"]),
                vehicle_number=(
                    None
                    if by_id[value]["vehicle_number"] is None
                    else str(by_id[value]["vehicle_number"])
                ),
                source_page_number=int(
                    by_id[value]["source_page_number"]
                ),
            )
            for value in item_identity_sha256s
        )
