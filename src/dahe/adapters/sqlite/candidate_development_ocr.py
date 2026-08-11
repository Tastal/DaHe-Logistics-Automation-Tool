from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import cast
from uuid import uuid4

from sqlalchemy import insert, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS,
    CANDIDATE_DEVELOPMENT_OCR_RUNS,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_COMPLETION_STATUSES = frozenset(
    {
        "completed",
        "completed_with_runtime_differences",
    }
)
_TERMINAL_STATUSES = frozenset({"succeeded", "technical_failed"})


class CandidateDevelopmentOcrRunPersistenceError(RuntimeError):
    """Raised when completed OCR run authority cannot persist safely."""


@dataclass(frozen=True, slots=True)
class CandidateDevelopmentOcrRunAuthorityInput:
    evidence_sha256: str
    evidence_blob_sha256: str
    evidence_relative_path: str
    evidence_byte_size: int
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    reviewer_id: str
    application_build_sha256: str
    composition_evidence_sha256: str
    runtime_set_sha256: str
    pipeline_contract_sha256: str
    completion_status: str
    completed_at: str


@dataclass(frozen=True, slots=True)
class CandidateDevelopmentOcrRunAuthorityRecord:
    evidence_sha256: str
    evidence_blob_sha256: str
    evidence_relative_path: str
    evidence_byte_size: int
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    reviewer_id: str
    application_build_sha256: str
    composition_evidence_sha256: str
    runtime_set_sha256: str
    pipeline_contract_sha256: str
    completion_status: str
    completed_at: str
    authority_payload_json: str
    authority_sha256: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CandidateDevelopmentOcrTerminalAttemptInput:
    evidence_sha256: str
    evidence_blob_sha256: str
    evidence_relative_path: str
    evidence_byte_size: int
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    reviewer_id: str
    application_build_sha256: str
    composition_evidence_sha256: str
    runtime_set_sha256: str
    pipeline_contract_sha256: str
    completion_status: str
    completed_at: str
    terminal_status: str


@dataclass(frozen=True, slots=True)
class CandidateDevelopmentOcrTerminalAttemptRecord:
    attempt_sequence: int
    scope_sha256: str
    evidence_sha256: str
    evidence_blob_sha256: str
    evidence_relative_path: str
    evidence_byte_size: int
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    reviewer_id: str
    application_build_sha256: str
    composition_evidence_sha256: str
    runtime_set_sha256: str
    pipeline_contract_sha256: str
    completion_status: str
    terminal_status: str
    authorized_evidence_sha256: str | None
    completed_at: str
    attempt_payload_json: str
    attempt_sha256: str
    created_at: str


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "candidate OCR run authority is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        _canonical_json(value).encode("utf-8")
    ).hexdigest()


def _validate_text(
    value: str,
    *,
    label: str,
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > maximum
    ):
        raise CandidateDevelopmentOcrRunPersistenceError(
            f"{label} is invalid"
        )
    return value


def _validate_sha256(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PATTERN.fullmatch(value) is None
    ):
        raise CandidateDevelopmentOcrRunPersistenceError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _validate_input(
    value: CandidateDevelopmentOcrRunAuthorityInput,
) -> CandidateDevelopmentOcrRunAuthorityInput:
    if not isinstance(
        value,
        CandidateDevelopmentOcrRunAuthorityInput,
    ):
        raise CandidateDevelopmentOcrRunPersistenceError(
            "candidate OCR run authority input is invalid"
        )
    for field in (
        "evidence_sha256",
        "evidence_blob_sha256",
        "package_sha256",
        "review_history_authority_sha256",
        "source_authority_sha256",
        "application_build_sha256",
        "composition_evidence_sha256",
        "runtime_set_sha256",
        "pipeline_contract_sha256",
    ):
        _validate_sha256(
            getattr(value, field),
            label=field,
        )
    if (
        isinstance(value.evidence_byte_size, bool)
        or not isinstance(value.evidence_byte_size, int)
        or value.evidence_byte_size <= 0
    ):
        raise CandidateDevelopmentOcrRunPersistenceError(
            "evidence byte size is invalid"
        )
    relative_path = PurePosixPath(
        _validate_text(
            value.evidence_relative_path,
            label="evidence relative path",
            maximum=500,
        )
    )
    expected = PurePosixPath(
        "development",
        "protected-candidate-review-ocr",
        "records",
        "sha256",
        value.evidence_sha256[:2],
        value.evidence_sha256[2:4],
        f"{value.evidence_sha256}.json",
    )
    if (
        relative_path != expected
        or relative_path.is_absolute()
        or "\\" in value.evidence_relative_path
        or ":" in value.evidence_relative_path
        or ".." in relative_path.parts
    ):
        raise CandidateDevelopmentOcrRunPersistenceError(
            "evidence relative path is invalid"
        )
    _validate_text(
        value.reviewer_id,
        label="reviewer ID",
        maximum=200,
    )
    if value.completion_status not in _COMPLETION_STATUSES:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "completion status is invalid"
        )
    completed_at = _validate_text(
        value.completed_at,
        label="completion time",
        maximum=40,
    )
    try:
        parsed = datetime.fromisoformat(completed_at)
    except ValueError as exc:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "completion time is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "completion time must include a timezone"
        )
    return value


def _terminal_input_from_authority(
    value: CandidateDevelopmentOcrRunAuthorityInput,
) -> CandidateDevelopmentOcrTerminalAttemptInput:
    return CandidateDevelopmentOcrTerminalAttemptInput(
        **asdict(value),
        terminal_status="succeeded",
    )


def _authority_input_from_terminal(
    value: CandidateDevelopmentOcrTerminalAttemptInput,
) -> CandidateDevelopmentOcrRunAuthorityInput:
    return CandidateDevelopmentOcrRunAuthorityInput(
        **{
            field: getattr(value, field)
            for field in CandidateDevelopmentOcrRunAuthorityInput.__dataclass_fields__
        }
    )


def _validate_terminal_input(
    value: CandidateDevelopmentOcrTerminalAttemptInput,
) -> CandidateDevelopmentOcrTerminalAttemptInput:
    if not isinstance(value, CandidateDevelopmentOcrTerminalAttemptInput):
        raise CandidateDevelopmentOcrRunPersistenceError(
            "candidate OCR terminal attempt input is invalid"
        )
    if value.terminal_status not in _TERMINAL_STATUSES:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "candidate OCR terminal status is invalid"
        )
    if value.terminal_status == "succeeded":
        _validate_input(_authority_input_from_terminal(value))
        return value
    if value.completion_status != "failed":
        raise CandidateDevelopmentOcrRunPersistenceError(
            "failed candidate OCR attempt has an invalid completion status"
        )
    probe = _authority_input_from_terminal(
        CandidateDevelopmentOcrTerminalAttemptInput(
            **{
                **asdict(value),
                "completion_status": "completed",
                "terminal_status": "succeeded",
            }
        )
    )
    _validate_input(probe)
    return value


def _scope_payload(
    value: CandidateDevelopmentOcrTerminalAttemptInput,
) -> dict[str, object]:
    return {
        "application_build_sha256": value.application_build_sha256,
        "composition_evidence_sha256": (
            value.composition_evidence_sha256
        ),
        "kind": "candidate_development_ocr_attempt_scope",
        "package_sha256": value.package_sha256,
        "pipeline_contract_sha256": value.pipeline_contract_sha256,
        "review_history_authority_sha256": (
            value.review_history_authority_sha256
        ),
        "reviewer_id": value.reviewer_id,
        "runtime_set_sha256": value.runtime_set_sha256,
        "schema_version": 1,
        "source_authority_sha256": value.source_authority_sha256,
    }


def candidate_development_ocr_scope_sha256(
    value: (
        CandidateDevelopmentOcrRunAuthorityInput
        | CandidateDevelopmentOcrTerminalAttemptInput
    ),
) -> str:
    terminal = (
        _terminal_input_from_authority(_validate_input(value))
        if isinstance(value, CandidateDevelopmentOcrRunAuthorityInput)
        else _validate_terminal_input(value)
    )
    return _canonical_sha256(_scope_payload(terminal))


def _attempt_payload(
    value: CandidateDevelopmentOcrTerminalAttemptInput,
) -> dict[str, object]:
    scope_sha256 = candidate_development_ocr_scope_sha256(value)
    return {
        "completed_at": value.completed_at,
        "completion_status": value.completion_status,
        "evidence_blob_sha256": value.evidence_blob_sha256,
        "evidence_byte_size": value.evidence_byte_size,
        "evidence_relative_path": value.evidence_relative_path,
        "evidence_sha256": value.evidence_sha256,
        "kind": "candidate_development_ocr_terminal_attempt",
        "schema_version": 1,
        "scope": _scope_payload(value),
        "scope_sha256": scope_sha256,
        "terminal_status": value.terminal_status,
    }


def _authority_payload(
    value: CandidateDevelopmentOcrRunAuthorityInput,
) -> dict[str, object]:
    return {
        "application_build_sha256": value.application_build_sha256,
        "completed_at": value.completed_at,
        "completion_status": value.completion_status,
        "composition_evidence_sha256": (
            value.composition_evidence_sha256
        ),
        "evidence_blob_sha256": value.evidence_blob_sha256,
        "evidence_byte_size": value.evidence_byte_size,
        "evidence_relative_path": value.evidence_relative_path,
        "evidence_sha256": value.evidence_sha256,
        "kind": "candidate_development_ocr_run_authority",
        "package_sha256": value.package_sha256,
        "pipeline_contract_sha256": value.pipeline_contract_sha256,
        "review_history_authority_sha256": (
            value.review_history_authority_sha256
        ),
        "reviewer_id": value.reviewer_id,
        "runtime_set_sha256": value.runtime_set_sha256,
        "schema_version": 1,
        "source_authority_sha256": value.source_authority_sha256,
    }


def _record_from_mapping(
    value: dict[str, object],
) -> CandidateDevelopmentOcrRunAuthorityRecord:
    record = CandidateDevelopmentOcrRunAuthorityRecord(
        evidence_sha256=str(value["evidence_sha256"]),
        evidence_blob_sha256=str(value["evidence_blob_sha256"]),
        evidence_relative_path=str(value["evidence_relative_path"]),
        evidence_byte_size=cast(int, value["evidence_byte_size"]),
        package_sha256=str(value["package_sha256"]),
        review_history_authority_sha256=str(
            value["review_history_authority_sha256"]
        ),
        source_authority_sha256=str(
            value["source_authority_sha256"]
        ),
        reviewer_id=str(value["reviewer_id"]),
        application_build_sha256=str(
            value["application_build_sha256"]
        ),
        composition_evidence_sha256=str(
            value["composition_evidence_sha256"]
        ),
        runtime_set_sha256=str(value["runtime_set_sha256"]),
        pipeline_contract_sha256=str(
            value["pipeline_contract_sha256"]
        ),
        completion_status=str(value["completion_status"]),
        completed_at=str(value["completed_at"]),
        authority_payload_json=str(value["authority_payload_json"]),
        authority_sha256=str(value["authority_sha256"]),
        created_at=str(value["created_at"]),
    )
    authority_input = _validate_input(
        CandidateDevelopmentOcrRunAuthorityInput(
            evidence_sha256=record.evidence_sha256,
            evidence_blob_sha256=record.evidence_blob_sha256,
            evidence_relative_path=record.evidence_relative_path,
            evidence_byte_size=record.evidence_byte_size,
            package_sha256=record.package_sha256,
            review_history_authority_sha256=(
                record.review_history_authority_sha256
            ),
            source_authority_sha256=record.source_authority_sha256,
            reviewer_id=record.reviewer_id,
            application_build_sha256=(
                record.application_build_sha256
            ),
            composition_evidence_sha256=(
                record.composition_evidence_sha256
            ),
            runtime_set_sha256=record.runtime_set_sha256,
            pipeline_contract_sha256=(
                record.pipeline_contract_sha256
            ),
            completion_status=record.completion_status,
            completed_at=record.completed_at,
        )
    )
    payload = _authority_payload(authority_input)
    if (
        record.authority_payload_json != _canonical_json(payload)
        or record.authority_sha256 != _canonical_sha256(payload)
    ):
        raise CandidateDevelopmentOcrRunPersistenceError(
            "candidate OCR run authority does not reconcile"
        )
    _validate_text(
        record.created_at,
        label="authority creation time",
        maximum=40,
    )
    try:
        created_at = datetime.fromisoformat(record.created_at)
    except ValueError as exc:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "authority creation time is invalid"
        ) from exc
    if created_at.tzinfo is None:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "authority creation time must include a timezone"
        )
    return record


def _attempt_record_from_mapping(
    value: dict[str, object],
) -> CandidateDevelopmentOcrTerminalAttemptRecord:
    terminal_input = _validate_terminal_input(
        CandidateDevelopmentOcrTerminalAttemptInput(
            evidence_sha256=str(value["evidence_sha256"]),
            evidence_blob_sha256=str(value["evidence_blob_sha256"]),
            evidence_relative_path=str(value["evidence_relative_path"]),
            evidence_byte_size=cast(int, value["evidence_byte_size"]),
            package_sha256=str(value["package_sha256"]),
            review_history_authority_sha256=str(
                value["review_history_authority_sha256"]
            ),
            source_authority_sha256=str(
                value["source_authority_sha256"]
            ),
            reviewer_id=str(value["reviewer_id"]),
            application_build_sha256=str(
                value["application_build_sha256"]
            ),
            composition_evidence_sha256=str(
                value["composition_evidence_sha256"]
            ),
            runtime_set_sha256=str(value["runtime_set_sha256"]),
            pipeline_contract_sha256=str(
                value["pipeline_contract_sha256"]
            ),
            completion_status=str(value["completion_status"]),
            completed_at=str(value["completed_at"]),
            terminal_status=str(value["terminal_status"]),
        )
    )
    payload = _attempt_payload(terminal_input)
    record = CandidateDevelopmentOcrTerminalAttemptRecord(
        attempt_sequence=cast(int, value["attempt_sequence"]),
        scope_sha256=str(value["scope_sha256"]),
        **asdict(terminal_input),
        authorized_evidence_sha256=(
            None
            if value["authorized_evidence_sha256"] is None
            else str(value["authorized_evidence_sha256"])
        ),
        attempt_payload_json=str(value["attempt_payload_json"]),
        attempt_sha256=str(value["attempt_sha256"]),
        created_at=str(value["created_at"]),
    )
    expected_authorized = (
        terminal_input.evidence_sha256
        if terminal_input.terminal_status == "succeeded"
        else None
    )
    if (
        isinstance(record.attempt_sequence, bool)
        or record.attempt_sequence <= 0
        or record.scope_sha256
        != candidate_development_ocr_scope_sha256(terminal_input)
        or record.authorized_evidence_sha256 != expected_authorized
        or record.attempt_payload_json != _canonical_json(payload)
        or record.attempt_sha256 != _canonical_sha256(payload)
    ):
        raise CandidateDevelopmentOcrRunPersistenceError(
            "candidate OCR terminal attempt does not reconcile"
        )
    created_at = _validate_text(
        record.created_at,
        label="terminal attempt creation time",
        maximum=40,
    )
    try:
        parsed_created_at = datetime.fromisoformat(created_at)
    except ValueError as exc:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "terminal attempt creation time is invalid"
        ) from exc
    if parsed_created_at.tzinfo is None:
        raise CandidateDevelopmentOcrRunPersistenceError(
            "terminal attempt creation time must include a timezone"
        )
    return record


def _insert_terminal_attempt(
    connection: Connection,
    value: CandidateDevelopmentOcrTerminalAttemptInput,
    *,
    created_at: str,
) -> tuple[CandidateDevelopmentOcrTerminalAttemptRecord, bool]:
    validated = _validate_terminal_input(value)
    existing = connection.execute(
        select(CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS).where(
            CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS.c.evidence_sha256
            == validated.evidence_sha256
        )
    ).mappings().one_or_none()
    if existing is not None:
        record = _attempt_record_from_mapping(dict(existing))
        comparable = {
            field: getattr(record, field)
            for field in asdict(validated)
        }
        if comparable != asdict(validated):
            raise CandidateDevelopmentOcrRunPersistenceError(
                "candidate OCR terminal attempt conflicts with "
                "the existing evidence identity"
            )
        return record, False
    payload = _attempt_payload(validated)
    result = connection.execute(
        insert(CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS).values(
            **asdict(validated),
            scope_sha256=(
                candidate_development_ocr_scope_sha256(validated)
            ),
            authorized_evidence_sha256=(
                validated.evidence_sha256
                if validated.terminal_status == "succeeded"
                else None
            ),
            attempt_payload_json=_canonical_json(payload),
            attempt_sha256=_canonical_sha256(payload),
            created_at=created_at,
        )
    )
    sequence = result.lastrowid
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise CandidateDevelopmentOcrRunPersistenceError(
            "candidate OCR terminal attempt sequence was not generated"
        )
    row = connection.execute(
        select(CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS).where(
            CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS.c.attempt_sequence
            == sequence
        )
    ).mappings().one()
    return _attempt_record_from_mapping(dict(row)), True


def _withdraw_dependent_shadows_after_failure(
    connection: Connection,
    value: CandidateDevelopmentOcrTerminalAttemptInput,
    *,
    attempt_sequence: int,
    created_at: str,
) -> None:
    if value.terminal_status != "technical_failed":
        return
    shadows = (
        connection.execute(
            text(
                """
                SELECT DISTINCT
                    pointer.family_id,
                    pointer.version_id,
                    pointer.record_version,
                    event.evaluation_id
                FROM template_shadow_pointers AS pointer
                JOIN template_lifecycle_events AS event
                  ON event.version_id = pointer.version_id
                 AND event.operation = 'publish_shadow'
                 AND event.to_lifecycle = 'shadow'
                JOIN template_lifecycle_attempts AS lifecycle_attempt
                  ON lifecycle_attempt.evaluation_id = event.evaluation_id
                 AND lifecycle_attempt.terminal_status = 'succeeded'
                WHERE lifecycle_attempt.package_sha256 = :package_sha256
                  AND lifecycle_attempt.review_history_authority_sha256 =
                      :review_history_authority_sha256
                  AND lifecycle_attempt.source_authority_sha256 =
                      :source_authority_sha256
                  AND lifecycle_attempt.reviewer_id = :reviewer_id
                  AND lifecycle_attempt.ocr_capture_build_sha256 =
                      :application_build_sha256
                  AND lifecycle_attempt.composition_evidence_sha256 =
                      :composition_evidence_sha256
                  AND lifecycle_attempt.runtime_set_sha256 =
                      :runtime_set_sha256
                  AND lifecycle_attempt.pipeline_contract_sha256 =
                      :pipeline_contract_sha256
                """
            ),
            {
                "application_build_sha256": (
                    value.application_build_sha256
                ),
                "composition_evidence_sha256": (
                    value.composition_evidence_sha256
                ),
                "package_sha256": value.package_sha256,
                "pipeline_contract_sha256": (
                    value.pipeline_contract_sha256
                ),
                "review_history_authority_sha256": (
                    value.review_history_authority_sha256
                ),
                "reviewer_id": value.reviewer_id,
                "runtime_set_sha256": value.runtime_set_sha256,
                "source_authority_sha256": (
                    value.source_authority_sha256
                ),
            },
        )
        .mappings()
        .all()
    )
    for shadow in shadows:
        connection.execute(
            text(
                """
                DELETE FROM template_shadow_pointers
                WHERE family_id = :family_id
                  AND version_id = :version_id
                  AND record_version = :record_version
                """
            ),
            {
                "family_id": str(shadow["family_id"]),
                "record_version": int(shadow["record_version"]),
                "version_id": str(shadow["version_id"]),
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO template_audit_events (
                    audit_id, event_kind, family_id, version_id,
                    actor_id, developer_authorization_id,
                    detail_json, created_at
                ) VALUES (
                    :audit_id, :event_kind, :family_id, :version_id,
                    :actor_id, NULL, :detail_json, :created_at
                )
                """
            ),
            {
                "actor_id": "loop7-candidate-ocr-terminal-ledger",
                "audit_id": uuid4().hex,
                "created_at": created_at,
                "detail_json": _canonical_json(
                    {
                        "candidate_ocr_attempt_sequence": (
                            attempt_sequence
                        ),
                        "evaluation_id": str(
                            shadow["evaluation_id"]
                        ),
                    }
                ),
                "event_kind": (
                    "template.shadow_withdrawn_after_ocr_failure"
                ),
                "family_id": str(shadow["family_id"]),
                "version_id": str(shadow["version_id"]),
            },
        )


class SqliteCandidateDevelopmentOcrRunRepository:
    """Persist immutable authority for completed development OCR runs."""

    def __init__(self, *, runtime: SqliteRuntime) -> None:
        if not isinstance(runtime, SqliteRuntime):
            raise CandidateDevelopmentOcrRunPersistenceError(
                "SQLite runtime is invalid"
            )
        self.runtime = runtime

    def get(
        self,
        evidence_sha256: str,
    ) -> CandidateDevelopmentOcrRunAuthorityRecord:
        identity = _validate_sha256(
            evidence_sha256,
            label="evidence SHA-256",
        )
        with self.runtime.engine.connect() as connection:
            row = connection.execute(
                select(CANDIDATE_DEVELOPMENT_OCR_RUNS).where(
                    CANDIDATE_DEVELOPMENT_OCR_RUNS.c.evidence_sha256
                    == identity
                )
            ).mappings().one_or_none()
        if row is None:
            raise CandidateDevelopmentOcrRunPersistenceError(
                "completed candidate OCR run authority does not exist"
            )
        return _record_from_mapping(dict(row))

    def record_completed_run(
        self,
        value: CandidateDevelopmentOcrRunAuthorityInput,
    ) -> tuple[CandidateDevelopmentOcrRunAuthorityRecord, bool]:
        validated = _validate_input(value)
        payload = _authority_payload(validated)
        payload_json = _canonical_json(payload)
        authority_sha256 = _canonical_sha256(payload)
        created_at = datetime.now(UTC).isoformat()
        row = {
            **asdict(validated),
            "authority_payload_json": payload_json,
            "authority_sha256": authority_sha256,
            "created_at": created_at,
        }
        try:
            with self.runtime.commit_gate.transaction(
                self.runtime.engine
            ) as connection:
                existing = connection.execute(
                    select(CANDIDATE_DEVELOPMENT_OCR_RUNS).where(
                        CANDIDATE_DEVELOPMENT_OCR_RUNS.c.evidence_sha256
                        == validated.evidence_sha256
                    )
                ).mappings().one_or_none()
                created = existing is None
                if existing is not None:
                    record = _record_from_mapping(dict(existing))
                    comparable = {
                        field: getattr(record, field)
                        for field in asdict(validated)
                    }
                    if comparable != asdict(validated):
                        raise CandidateDevelopmentOcrRunPersistenceError(
                            "candidate OCR run authority conflicts with "
                            "the existing logical evidence identity"
                        )
                else:
                    connection.execute(
                        insert(CANDIDATE_DEVELOPMENT_OCR_RUNS).values(**row)
                    )
                    record = _record_from_mapping(row)
                _insert_terminal_attempt(
                    connection,
                    _terminal_input_from_authority(validated),
                    created_at=created_at,
                )
        except IntegrityError as exc:
            raise CandidateDevelopmentOcrRunPersistenceError(
                "candidate OCR run authority could not be committed"
            ) from exc
        return record, created

    def record_failed_run(
        self,
        value: CandidateDevelopmentOcrTerminalAttemptInput,
    ) -> tuple[CandidateDevelopmentOcrTerminalAttemptRecord, bool]:
        validated = _validate_terminal_input(value)
        if validated.terminal_status != "technical_failed":
            raise CandidateDevelopmentOcrRunPersistenceError(
                "failed candidate OCR run must be a technical failure"
            )
        try:
            with self.runtime.commit_gate.transaction(
                self.runtime.engine
            ) as connection:
                created_at = datetime.now(UTC).isoformat()
                attempt, created = _insert_terminal_attempt(
                    connection,
                    validated,
                    created_at=created_at,
                )
                if created:
                    _withdraw_dependent_shadows_after_failure(
                        connection,
                        validated,
                        attempt_sequence=attempt.attempt_sequence,
                        created_at=created_at,
                    )
                return attempt, created
        except IntegrityError as exc:
            raise CandidateDevelopmentOcrRunPersistenceError(
                "candidate OCR terminal attempt could not be committed"
            ) from exc

    def get_latest_terminal_attempt_for_scope(
        self,
        value: (
            CandidateDevelopmentOcrRunAuthorityInput
            | CandidateDevelopmentOcrTerminalAttemptInput
        ),
    ) -> CandidateDevelopmentOcrTerminalAttemptRecord:
        scope_sha256 = candidate_development_ocr_scope_sha256(value)
        with self.runtime.engine.connect() as connection:
            row = connection.execute(
                select(CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS)
                .where(
                    CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS.c.scope_sha256
                    == scope_sha256
                )
                .order_by(
                    CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS.c.attempt_sequence.desc()
                )
                .limit(1)
            ).mappings().one_or_none()
        if row is None:
            raise CandidateDevelopmentOcrRunPersistenceError(
                "candidate OCR terminal attempt does not exist"
            )
        return _attempt_record_from_mapping(dict(row))

    def require_latest_success(
        self,
        evidence_sha256: str,
    ) -> CandidateDevelopmentOcrTerminalAttemptRecord:
        authority = self.get(evidence_sha256)
        latest = self.get_latest_terminal_attempt_for_scope(
            CandidateDevelopmentOcrRunAuthorityInput(
                **{
                    field: getattr(authority, field)
                    for field in (
                        CandidateDevelopmentOcrRunAuthorityInput
                        .__dataclass_fields__
                    )
                }
            )
        )
        if (
            latest.terminal_status != "succeeded"
            or latest.evidence_sha256 != authority.evidence_sha256
            or latest.authorized_evidence_sha256
            != authority.evidence_sha256
        ):
            raise CandidateDevelopmentOcrRunPersistenceError(
                "latest terminal attempt is not the exact successful "
                "candidate OCR evidence"
            )
        return latest
