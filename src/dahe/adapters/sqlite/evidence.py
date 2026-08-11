from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
    StoredEvidence,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime


class EvidenceImportError(RuntimeError):
    """Raised when a frozen evidence bundle is invalid."""


class EvidenceImportIdempotencyConflictError(RuntimeError):
    """Raised when an import idempotency key is reused for different input."""


class EvidenceNotFoundError(LookupError):
    """Raised when a durable evidence identity does not exist."""


class EvidenceRecordVersionConflictError(RuntimeError):
    """Raised when a durable evidence mutation uses an older record version."""


class EvidenceCleanupConflictError(RuntimeError):
    """Raised when cleanup already fenced new references."""


@dataclass(frozen=True, slots=True)
class ImportResult:
    import_id: str
    created: bool
    image_sha256s: dict[str, str]


@dataclass(frozen=True, slots=True)
class EvidenceReferenceRecord:
    reference_id: str
    sha256: str
    owner_kind: str
    owner_id: str
    role: str
    record_version: int


@dataclass(frozen=True, slots=True)
class EvidenceHoldRecord:
    hold_id: str
    sha256: str
    hold_kind: str
    owner_id: str
    record_version: int
    evidence_record_version: int


@dataclass(frozen=True, slots=True)
class EvidenceCleanupClaimRecord:
    claim_id: str
    sha256: str
    record_version: int


@dataclass(frozen=True, slots=True)
class EvidenceState:
    sha256: str
    record_version: int
    references: tuple[EvidenceReferenceRecord, ...]
    active_reference_count: int
    active_hold_count: int
    active_cleanup_claim: EvidenceCleanupClaimRecord | None


@dataclass(frozen=True, slots=True)
class _PreparedImage:
    platform_waybill_id: str
    slot: str
    stored: StoredEvidence


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _json_fingerprint_value(value: object) -> object:
    if isinstance(value, bytes):
        return {
            "byte_size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    if isinstance(value, Mapping):
        return {
            str(key): _json_fingerprint_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_fingerprint_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise EvidenceImportError(f"unsupported bundle value: {type(value).__name__}")


def _request_hash(bundle: Mapping[str, object]) -> str:
    payload = json.dumps(
        _json_fingerprint_value(bundle),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _required_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise EvidenceImportError(f"{key} must be a non-empty string")
    return value


class DurableEvidenceRepository:
    """Commit immutable snapshots and their evidence references atomically."""

    def __init__(
        self,
        *,
        runtime: SqliteRuntime,
        evidence_store: ContentAddressedEvidenceStore,
    ) -> None:
        self.runtime = runtime
        self.evidence_store = evidence_store

    def _prepare_images(
        self,
        waybills: Sequence[Mapping[str, object]],
    ) -> list[_PreparedImage]:
        prepared: list[_PreparedImage] = []
        for waybill in waybills:
            platform_waybill_id = _required_string(waybill, "platform_waybill_id")
            raw_images = waybill.get("images")
            if not isinstance(raw_images, Sequence) or isinstance(
                raw_images, (str, bytes, bytearray)
            ):
                raise EvidenceImportError("images must be a sequence")
            for raw_image in raw_images:
                if not isinstance(raw_image, Mapping):
                    raise EvidenceImportError("each image must be an object")
                image = cast(Mapping[str, object], raw_image)
                slot = _required_string(image, "slot")
                content = image.get("content")
                if not isinstance(content, bytes):
                    raise EvidenceImportError("image content must be bytes")
                media_type = _required_string(image, "media_type")
                prepared.append(
                    _PreparedImage(
                        platform_waybill_id=platform_waybill_id,
                        slot=slot,
                        stored=self.evidence_store.put_bytes(
                            content,
                            media_type=media_type,
                        ),
                    )
                )
        return prepared

    def import_bundle(
        self,
        bundle: Mapping[str, object],
        *,
        idempotency_key: str,
        failpoint: Callable[[str], None] | None = None,
    ) -> ImportResult:
        if not idempotency_key:
            raise ValueError("idempotency_key is required")
        capture_id = _required_string(bundle, "capture_id")
        captured_at = _required_string(bundle, "captured_at")
        contract_version = _required_string(bundle, "request_contract_version")
        raw_waybills = bundle.get("waybills")
        if not isinstance(raw_waybills, Sequence) or isinstance(
            raw_waybills, (str, bytes, bytearray)
        ):
            raise EvidenceImportError("waybills must be a sequence")
        waybills: list[Mapping[str, object]] = []
        for raw_waybill in raw_waybills:
            if not isinstance(raw_waybill, Mapping):
                raise EvidenceImportError("each waybill must be an object")
            waybills.append(cast(Mapping[str, object], raw_waybill))
        if not waybills:
            raise EvidenceImportError("at least one waybill is required")

        request_hash = _request_hash(bundle)
        prepared = self._prepare_images(waybills)
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = (
                connection.execute(
                    text(
                        "SELECT import_id, request_hash FROM evidence_imports "
                        "WHERE idempotency_key = :key"
                    ),
                    {"key": idempotency_key},
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if str(replay["request_hash"]) != request_hash:
                    raise EvidenceImportIdempotencyConflictError(
                        "idempotency key belongs to different evidence input"
                    )
                return self._result_for_import(
                    connection,
                    str(replay["import_id"]),
                    created=False,
                )

            import_id = uuid4().hex
            connection.execute(
                text(
                    "INSERT INTO evidence_imports "
                    "(import_id, idempotency_key, request_hash, capture_id, created_at) "
                    "VALUES (:import_id, :idempotency_key, :request_hash, :capture_id, :now)"
                ),
                {
                    "import_id": import_id,
                    "idempotency_key": idempotency_key,
                    "request_hash": request_hash,
                    "capture_id": capture_id,
                    "now": now,
                },
            )

            role_hashes: dict[str, str] = {}
            for waybill in waybills:
                platform_waybill_id = _required_string(waybill, "platform_waybill_id")
                waybill_number = _required_string(waybill, "waybill_number")
                raw_fields = waybill.get("business_fields")
                if not isinstance(raw_fields, Mapping):
                    raise EvidenceImportError("business_fields must be an object")
                fields_json = json.dumps(
                    _json_fingerprint_value(raw_fields),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                snapshot_id = uuid4().hex
                snapshot_identity = json.dumps(
                    {
                        "business_fields": json.loads(fields_json),
                        "capture_id": capture_id,
                        "platform_waybill_id": platform_waybill_id,
                        "request_contract_version": contract_version,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                connection.execute(
                    text(
                        "INSERT INTO platform_snapshots "
                        "(snapshot_id, import_id, platform_waybill_id, waybill_number, "
                        "captured_at, request_contract_version, business_fields_json, "
                        "content_sha256) VALUES "
                        "(:snapshot_id, :import_id, :platform_waybill_id, :waybill_number, "
                        ":captured_at, :contract_version, :fields_json, :content_sha256)"
                    ),
                    {
                        "snapshot_id": snapshot_id,
                        "import_id": import_id,
                        "platform_waybill_id": platform_waybill_id,
                        "waybill_number": waybill_number,
                        "captured_at": captured_at,
                        "contract_version": contract_version,
                        "fields_json": fields_json,
                        "content_sha256": hashlib.sha256(snapshot_identity).hexdigest(),
                    },
                )
                if failpoint is not None:
                    failpoint("after_snapshot_insert")

                raw_decision = waybill.get("audit_decision")
                if raw_decision is not None:
                    if not isinstance(raw_decision, Mapping):
                        raise EvidenceImportError("audit_decision must be an object")
                    decision = cast(Mapping[str, object], raw_decision)
                    decision_name = _required_string(decision, "decision")
                    business_outcome = _required_string(decision, "business_outcome")
                    rule_version = _required_string(decision, "rule_version")
                    eligible_for_handoff = decision.get("eligible_for_handoff")
                    if not isinstance(eligible_for_handoff, bool):
                        raise EvidenceImportError("eligible_for_handoff must be a boolean")
                    connection.execute(
                        text(
                            "INSERT INTO audit_decisions "
                            "(decision_id, snapshot_id, decision, business_outcome, "
                            "rule_version, eligible_for_handoff, record_version, created_at) "
                            "VALUES (:decision_id, :snapshot_id, :decision, "
                            ":business_outcome, :rule_version, :eligible_for_handoff, 1, :now)"
                        ),
                        {
                            "decision_id": uuid4().hex,
                            "snapshot_id": snapshot_id,
                            "decision": decision_name,
                            "business_outcome": business_outcome,
                            "rule_version": rule_version,
                            "eligible_for_handoff": int(eligible_for_handoff),
                            "now": now,
                        },
                    )
                    if failpoint is not None:
                        failpoint("after_decision_insert")

                for image in prepared:
                    if image.platform_waybill_id != platform_waybill_id:
                        continue
                    self._insert_blob(connection, image.stored, now)
                    reference_id = uuid4().hex
                    connection.execute(
                        text(
                            "INSERT INTO evidence_references "
                            "(reference_id, sha256, snapshot_id, owner_kind, owner_id, role, "
                            "idempotency_key, record_version, created_at) VALUES "
                            "(:reference_id, :sha256, :snapshot_id, 'platform_snapshot', "
                            ":owner_id, :role, :idempotency_key, 1, :now)"
                        ),
                        {
                            "reference_id": reference_id,
                            "sha256": image.stored.sha256,
                            "snapshot_id": snapshot_id,
                            "owner_id": snapshot_id,
                            "role": image.slot,
                            "idempotency_key": (
                                f"import:{import_id}:{platform_waybill_id}:{image.slot}"
                            ),
                            "now": now,
                        },
                    )
                    connection.execute(
                        text(
                            "UPDATE evidence_blobs "
                            "SET record_version = record_version + 1 WHERE sha256 = :sha256"
                        ),
                        {"sha256": image.stored.sha256},
                    )
                    role_hashes[image.slot] = image.stored.sha256

            return ImportResult(
                import_id=import_id,
                created=True,
                image_sha256s=role_hashes,
            )

    @staticmethod
    def _insert_blob(
        connection: Connection,
        stored: StoredEvidence,
        now: str,
    ) -> None:
        connection.execute(
            text(
                "INSERT OR IGNORE INTO evidence_blobs "
                "(sha256, relative_path, byte_size, media_type, storage_state, "
                "record_version, created_at, verified_at) VALUES "
                "(:sha256, :relative_path, :byte_size, :media_type, 'available', 1, "
                ":now, :now)"
            ),
            {
                "sha256": stored.sha256,
                "relative_path": stored.relative_path,
                "byte_size": stored.byte_size,
                "media_type": stored.media_type,
                "now": now,
            },
        )
        row = (
            connection.execute(
                text("SELECT relative_path, byte_size FROM evidence_blobs WHERE sha256 = :sha256"),
                {"sha256": stored.sha256},
            )
            .mappings()
            .one()
        )
        if (
            str(row["relative_path"]) != stored.relative_path
            or int(row["byte_size"]) != stored.byte_size
        ):
            raise EvidenceImportError("existing evidence metadata conflicts with its SHA-256")

    @staticmethod
    def _result_for_import(
        connection: Connection,
        import_id: str,
        *,
        created: bool,
    ) -> ImportResult:
        rows = connection.execute(
            text(
                "SELECT r.role, r.sha256 FROM evidence_references AS r "
                "JOIN platform_snapshots AS s ON s.snapshot_id = r.snapshot_id "
                "WHERE s.import_id = :import_id AND r.released_at IS NULL"
            ),
            {"import_id": import_id},
        )
        return ImportResult(
            import_id=import_id,
            created=created,
            image_sha256s={str(role): str(sha256) for role, sha256 in rows},
        )

    def get_evidence_state(self, sha256: str) -> EvidenceState:
        with self.runtime.engine.connect() as connection:
            blob = (
                connection.execute(
                    text("SELECT record_version FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": sha256},
                )
                .mappings()
                .one_or_none()
            )
            if blob is None:
                raise EvidenceNotFoundError(sha256)
            reference_rows = connection.execute(
                text(
                    "SELECT reference_id, sha256, owner_kind, owner_id, role, record_version "
                    "FROM evidence_references "
                    "WHERE sha256 = :sha256 AND released_at IS NULL "
                    "ORDER BY reference_id"
                ),
                {"sha256": sha256},
            ).mappings()
            references = tuple(
                EvidenceReferenceRecord(
                    reference_id=str(row["reference_id"]),
                    sha256=str(row["sha256"]),
                    owner_kind=str(row["owner_kind"]),
                    owner_id=str(row["owner_id"]),
                    role=str(row["role"]),
                    record_version=int(row["record_version"]),
                )
                for row in reference_rows
            )
            active_holds = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_holds "
                        "WHERE sha256 = :sha256 AND released_at IS NULL"
                    ),
                    {"sha256": sha256},
                ).scalar_one()
            )
            claim_row = (
                connection.execute(
                    text(
                        "SELECT claim_id, sha256, record_version "
                        "FROM evidence_cleanup_claims "
                        "WHERE sha256 = :sha256 AND status = 'active'"
                    ),
                    {"sha256": sha256},
                )
                .mappings()
                .one_or_none()
            )
        claim = (
            None
            if claim_row is None
            else EvidenceCleanupClaimRecord(
                claim_id=str(claim_row["claim_id"]),
                sha256=str(claim_row["sha256"]),
                record_version=int(claim_row["record_version"]),
            )
        )
        return EvidenceState(
            sha256=sha256,
            record_version=int(blob["record_version"]),
            references=references,
            active_reference_count=len(references),
            active_hold_count=active_holds,
            active_cleanup_claim=claim,
        )

    @staticmethod
    def _assert_blob_version(
        connection: Connection,
        sha256: str,
        expected_record_version: int,
    ) -> None:
        actual = connection.execute(
            text("SELECT record_version FROM evidence_blobs WHERE sha256 = :sha256"),
            {"sha256": sha256},
        ).scalar_one_or_none()
        if actual is None:
            raise EvidenceNotFoundError(sha256)
        if int(actual) != expected_record_version:
            raise EvidenceRecordVersionConflictError("evidence record version is stale")

    @staticmethod
    def _bump_blob(
        connection: Connection,
        sha256: str,
        expected_record_version: int,
    ) -> int:
        result = connection.execute(
            text(
                "UPDATE evidence_blobs SET record_version = record_version + 1 "
                "WHERE sha256 = :sha256 AND record_version = :expected"
            ),
            {"sha256": sha256, "expected": expected_record_version},
        )
        if result.rowcount != 1:
            raise EvidenceRecordVersionConflictError("evidence record version is stale")
        return expected_record_version + 1

    def release_reference(
        self,
        reference_id: str,
        *,
        expected_record_version: int,
        idempotency_key: str,
    ) -> None:
        del idempotency_key
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT sha256, record_version, released_at FROM evidence_references "
                        "WHERE reference_id = :reference_id"
                    ),
                    {"reference_id": reference_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise EvidenceNotFoundError(reference_id)
            if int(row["record_version"]) != expected_record_version:
                raise EvidenceRecordVersionConflictError("reference record version is stale")
            if row["released_at"] is not None:
                return
            result = connection.execute(
                text(
                    "UPDATE evidence_references "
                    "SET released_at = :now, record_version = record_version + 1 "
                    "WHERE reference_id = :reference_id "
                    "AND record_version = :expected AND released_at IS NULL"
                ),
                {
                    "now": now,
                    "reference_id": reference_id,
                    "expected": expected_record_version,
                },
            )
            if result.rowcount != 1:
                raise EvidenceRecordVersionConflictError("reference record version is stale")
            blob_version = int(
                connection.execute(
                    text("SELECT record_version FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": str(row["sha256"])},
                ).scalar_one()
            )
            self._bump_blob(connection, str(row["sha256"]), blob_version)

    def add_hold(
        self,
        *,
        sha256: str,
        hold_kind: str,
        owner_id: str,
        reason: str,
        expected_record_version: int,
        idempotency_key: str,
    ) -> EvidenceHoldRecord:
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            self._assert_blob_version(connection, sha256, expected_record_version)
            hold_id = uuid4().hex
            connection.execute(
                text(
                    "INSERT INTO evidence_holds "
                    "(hold_id, sha256, hold_kind, owner_id, reason, idempotency_key, "
                    "record_version, created_at) VALUES "
                    "(:hold_id, :sha256, :hold_kind, :owner_id, :reason, "
                    ":idempotency_key, 1, :now)"
                ),
                {
                    "hold_id": hold_id,
                    "sha256": sha256,
                    "hold_kind": hold_kind,
                    "owner_id": owner_id,
                    "reason": reason,
                    "idempotency_key": idempotency_key,
                    "now": now,
                },
            )
            evidence_version = self._bump_blob(
                connection,
                sha256,
                expected_record_version,
            )
            return EvidenceHoldRecord(
                hold_id=hold_id,
                sha256=sha256,
                hold_kind=hold_kind,
                owner_id=owner_id,
                record_version=1,
                evidence_record_version=evidence_version,
            )

    def release_hold(
        self,
        hold_id: str,
        *,
        expected_record_version: int,
        idempotency_key: str,
    ) -> None:
        del idempotency_key
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT sha256, record_version, released_at FROM evidence_holds "
                        "WHERE hold_id = :hold_id"
                    ),
                    {"hold_id": hold_id},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise EvidenceNotFoundError(hold_id)
            if int(row["record_version"]) != expected_record_version:
                raise EvidenceRecordVersionConflictError("hold record version is stale")
            if row["released_at"] is not None:
                return
            result = connection.execute(
                text(
                    "UPDATE evidence_holds "
                    "SET released_at = :now, record_version = record_version + 1 "
                    "WHERE hold_id = :hold_id AND record_version = :expected "
                    "AND released_at IS NULL"
                ),
                {
                    "now": now,
                    "hold_id": hold_id,
                    "expected": expected_record_version,
                },
            )
            if result.rowcount != 1:
                raise EvidenceRecordVersionConflictError("hold record version is stale")
            sha256 = str(row["sha256"])
            blob_version = int(
                connection.execute(
                    text("SELECT record_version FROM evidence_blobs WHERE sha256 = :sha256"),
                    {"sha256": sha256},
                ).scalar_one()
            )
            self._bump_blob(connection, sha256, blob_version)

    def add_reference(
        self,
        *,
        sha256: str,
        owner_kind: str,
        owner_id: str,
        role: str,
        expected_record_version: int,
        idempotency_key: str,
    ) -> EvidenceReferenceRecord:
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            self._assert_blob_version(connection, sha256, expected_record_version)
            active_claim = connection.execute(
                text(
                    "SELECT claim_id FROM evidence_cleanup_claims "
                    "WHERE sha256 = :sha256 AND status = 'active'"
                ),
                {"sha256": sha256},
            ).first()
            if active_claim is not None:
                raise EvidenceCleanupConflictError("cleanup already owns this evidence")
            reference_id = uuid4().hex
            connection.execute(
                text(
                    "INSERT INTO evidence_references "
                    "(reference_id, sha256, snapshot_id, owner_kind, owner_id, role, "
                    "idempotency_key, record_version, created_at) VALUES "
                    "(:reference_id, :sha256, NULL, :owner_kind, :owner_id, :role, "
                    ":idempotency_key, 1, :now)"
                ),
                {
                    "reference_id": reference_id,
                    "sha256": sha256,
                    "owner_kind": owner_kind,
                    "owner_id": owner_id,
                    "role": role,
                    "idempotency_key": idempotency_key,
                    "now": now,
                },
            )
            self._bump_blob(connection, sha256, expected_record_version)
            return EvidenceReferenceRecord(
                reference_id=reference_id,
                sha256=sha256,
                owner_kind=owner_kind,
                owner_id=owner_id,
                role=role,
                record_version=1,
            )

    def claim_for_cleanup(
        self,
        *,
        sha256: str,
        claim_id: str,
        expected_record_version: int,
    ) -> EvidenceCleanupClaimRecord | None:
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            self._assert_blob_version(connection, sha256, expected_record_version)
            active_references = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_references "
                        "WHERE sha256 = :sha256 AND released_at IS NULL"
                    ),
                    {"sha256": sha256},
                ).scalar_one()
            )
            active_holds = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_holds "
                        "WHERE sha256 = :sha256 AND released_at IS NULL"
                    ),
                    {"sha256": sha256},
                ).scalar_one()
            )
            if active_references or active_holds:
                return None
            active_claim = (
                connection.execute(
                    text(
                        "SELECT claim_id, record_version FROM evidence_cleanup_claims "
                        "WHERE sha256 = :sha256 AND status = 'active'"
                    ),
                    {"sha256": sha256},
                )
                .mappings()
                .one_or_none()
            )
            if active_claim is not None:
                if str(active_claim["claim_id"]) != claim_id:
                    raise EvidenceCleanupConflictError("evidence already has a cleanup claim")
                return EvidenceCleanupClaimRecord(
                    claim_id=claim_id,
                    sha256=sha256,
                    record_version=int(active_claim["record_version"]),
                )
            connection.execute(
                text(
                    "INSERT INTO evidence_cleanup_claims "
                    "(claim_id, sha256, record_version, status, created_at) "
                    "VALUES (:claim_id, :sha256, 1, 'active', :now)"
                ),
                {"claim_id": claim_id, "sha256": sha256, "now": now},
            )
            self._bump_blob(connection, sha256, expected_record_version)
            return EvidenceCleanupClaimRecord(
                claim_id=claim_id,
                sha256=sha256,
                record_version=1,
            )
