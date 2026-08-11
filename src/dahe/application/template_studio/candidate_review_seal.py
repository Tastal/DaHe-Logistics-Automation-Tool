from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewFormalExport,
)
from dahe.application.template_studio.candidate_review_semantics import (
    CANDIDATE_REVIEW_SOURCE_AUTHORITY_V3_FIELDS,
    CandidateReviewSemanticError,
    candidate_review_manifest_payload,
    candidate_review_manifest_sha256,
    validate_candidate_review_semantic_authority,
)
from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
    FormalDevelopmentAuthorityError,
    load_formal_development_authority,
    parse_formal_development_authority,
)
from dahe.verification.locked_set_acceptance import (
    locked_set_quality_coverage_sha256,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_NAMES = frozenset(
    {
        "manifest.json",
        "quality-coverage.json",
        "review-history-authority.json",
        "source-authority.json",
        "development-authority.json",
    }
)
_SEAL_FILE_NAMES = _ARTIFACT_NAMES | {"seal.json"}
_SOURCE_AUTHORITY_FIELDS = CANDIDATE_REVIEW_SOURCE_AUTHORITY_V3_FIELDS
_HISTORY_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "package_sha256",
        "sample_count",
        "latest_record_count",
        "history_record_count",
        "idempotency_record_count",
        "latest_records",
        "history_records",
        "idempotency_records",
    }
)
_REVIEW_RECORD_FIELDS = frozenset(
    {
        "sample_id",
        "record_version",
        "review_status",
        "decision",
        "review_payload",
        "created_at",
        "updated_at",
    }
)
_SOURCE_RECORD_FIELDS = _REVIEW_RECORD_FIELDS | {"record_evidence_sha256"}
_IDEMPOTENCY_RECORD_FIELDS = frozenset(
    {
        "sample_id",
        "resulting_record_version",
        "idempotency_key",
        "request_hash",
        "created_at",
    }
)
_SEAL_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "dataset_id",
        "package_sha256",
        "manifest_sha256",
        "quality_coverage_sha256",
        "source_authority_sha256",
        "review_history_authority_sha256",
        "record_set_sha256",
        "development_authority_sha256",
        "artifact_sha256s",
        "seal_sha256",
    }
)


class CandidateReviewSealError(RuntimeError):
    """Raised when candidate-review evidence cannot be sealed or verified."""


@dataclass(frozen=True, slots=True)
class CandidateReviewSeal:
    seal_sha256: str
    seal_root: Path
    seal_payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class _PreparedSeal:
    seal_sha256: str
    seal_payload: dict[str, object]
    artifact_payloads: dict[str, dict[str, object]]


def _canonical_json(value: object, *, label: str) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise CandidateReviewSealError(f"{label} is not canonical JSON") from exc


def _normalized_object(value: object, *, label: str) -> dict[str, object]:
    encoded = _canonical_json(value, label=label)
    try:
        normalized = json.loads(encoded)
    except json.JSONDecodeError as exc:  # pragma: no cover - produced internally
        raise CandidateReviewSealError(f"{label} is not canonical JSON") from exc
    if not isinstance(normalized, dict):
        raise CandidateReviewSealError(f"{label} must be a JSON object")
    return cast(dict[str, object], normalized)


def _canonical_sha256(value: object, *, label: str) -> str:
    return hashlib.sha256(_canonical_json(value, label=label).encode("utf-8")).hexdigest()


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise CandidateReviewSealError(f"{label} must be a canonical SHA-256")
    return value


def _required_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise CandidateReviewSealError(f"{label} is invalid")
    return value


def _required_count(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateReviewSealError(f"{label} is invalid")
    return value


def _is_schema_version_one(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 1


def _is_schema_version_three(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 3


def _required_object_list(
    value: object,
    *,
    label: str,
) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CandidateReviewSealError(f"{label} must be a JSON object list")
    return cast(list[dict[str, object]], value)


def _review_record(
    value: Mapping[str, object],
    *,
    label: str,
    source_record: bool,
    package_sha256: str,
) -> tuple[dict[str, object], tuple[str, int]]:
    expected_fields = _SOURCE_RECORD_FIELDS if source_record else _REVIEW_RECORD_FIELDS
    if set(value) != expected_fields:
        raise CandidateReviewSealError(f"{label} contains unexpected fields")
    sample_id = _required_text(
        value.get("sample_id"),
        label=f"{label} sample ID",
    )
    record_version = _required_count(
        value.get("record_version"),
        label=f"{label} record version",
    )
    if record_version < 1:
        raise CandidateReviewSealError(f"{label} record version is invalid")
    review_status = value.get("review_status")
    if (
        review_status not in {"confirmed", "replace_candidate"}
        or value.get("decision") != review_status
    ):
        raise CandidateReviewSealError(f"{label} decision is invalid")
    if not isinstance(value.get("review_payload"), dict):
        raise CandidateReviewSealError(f"{label} review payload must be a JSON object")
    _required_text(
        value.get("created_at"),
        label=f"{label} creation time",
    )
    _required_text(
        value.get("updated_at"),
        label=f"{label} update time",
    )
    base = {key: value[key] for key in _REVIEW_RECORD_FIELDS}
    normalized_base = _normalized_object(
        base,
        label=label,
    )
    if source_record:
        declared_evidence_sha256 = _required_sha256(
            value.get("record_evidence_sha256"),
            label=f"{label} evidence SHA-256",
        )
        evidence = {
            "schema_version": 1,
            "package_sha256": package_sha256,
            **normalized_base,
        }
        if (
            _canonical_sha256(
                evidence,
                label=f"{label} evidence",
            )
            != declared_evidence_sha256
        ):
            raise CandidateReviewSealError(f"{label} evidence SHA-256 is inconsistent")
    return normalized_base, (sample_id, record_version)


def _validate_formal_authority_records(
    *,
    manifest: Mapping[str, object],
    source: Mapping[str, object],
    history: Mapping[str, object],
    package_sha256: str,
    record_set_sha256: str,
) -> None:
    try:
        validate_candidate_review_semantic_authority(
            manifest_payload=manifest,
            source_authority_payload=source,
        )
    except CandidateReviewSemanticError as exc:
        raise CandidateReviewSealError("formal source semantic authority is inconsistent") from exc
    if (
        set(source) != _SOURCE_AUTHORITY_FIELDS
        or not _is_schema_version_three(source.get("schema_version"))
        or source.get("kind") != "candidate_review_formal_source_authority"
        or source.get("authority_scope") != "computed_unsealed_snapshot"
        or source.get("persistent_seal") is not False
    ):
        raise CandidateReviewSealError("formal source authority contract is invalid")
    source_records = _required_object_list(
        source.get("records"),
        label="formal source records",
    )
    record_count = _required_count(
        source.get("record_count"),
        label="formal source record count",
    )
    if record_count != 50 or len(source_records) != record_count:
        raise CandidateReviewSealError("formal source record counts do not reconcile")
    reviewer_id = _required_text(
        source.get("configured_reviewer_id"),
        label="configured reviewer ID",
    )
    _required_text(
        source.get("package_id"),
        label="candidate package ID",
    )
    source_bases: list[dict[str, object]] = []
    source_keys: list[tuple[str, int]] = []
    record_identities: list[dict[str, object]] = []
    for index, record in enumerate(source_records):
        base, key = _review_record(
            record,
            label=f"formal source record {index + 1}",
            source_record=True,
            package_sha256=package_sha256,
        )
        source_bases.append(base)
        source_keys.append(key)
        if base.get("review_status") != "confirmed" or base.get("decision") != "confirmed":
            raise CandidateReviewSealError("formal source records must be confirmed")
        record_identities.append(
            {
                "sample_id": key[0],
                "record_version": key[1],
                "record_evidence_sha256": record["record_evidence_sha256"],
            }
        )
    if source_keys != sorted(source_keys) or len({key[0] for key in source_keys}) != record_count:
        raise CandidateReviewSealError("formal source records are not canonical")
    expected_record_set_sha256 = _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package_sha256,
            "configured_reviewer_id": reviewer_id,
            "records": record_identities,
        },
        label="record set",
    )
    if expected_record_set_sha256 != record_set_sha256:
        raise CandidateReviewSealError("record-set SHA-256 is inconsistent")

    verified_images = _required_object_list(
        source.get("verified_images"),
        label="verified images",
    )
    verified_image_count = _required_count(
        source.get("verified_image_count"),
        label="verified image count",
    )
    if verified_image_count != 100 or len(verified_images) != verified_image_count:
        raise CandidateReviewSealError("verified image counts do not reconcile")
    declared_verified_image_set_sha256 = _required_sha256(
        source.get("verified_image_set_sha256"),
        label="verified image-set SHA-256",
    )
    if (
        _canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": package_sha256,
                "images": verified_images,
            },
            label="verified image set",
        )
        != declared_verified_image_set_sha256
    ):
        raise CandidateReviewSealError("verified image-set SHA-256 is inconsistent")

    if (
        set(history) != _HISTORY_AUTHORITY_FIELDS
        or not _is_schema_version_one(history.get("schema_version"))
        or history.get("kind") != "locked_set_review_authority_snapshot"
    ):
        raise CandidateReviewSealError("review history authority contract is invalid")
    if history.get("package_sha256") != package_sha256:
        raise CandidateReviewSealError("review history package does not match the formal export")
    latest_records = _required_object_list(
        history.get("latest_records"),
        label="review history latest records",
    )
    history_records = _required_object_list(
        history.get("history_records"),
        label="review history records",
    )
    idempotency_records = _required_object_list(
        history.get("idempotency_records"),
        label="review history idempotency records",
    )
    sample_count = _required_count(
        history.get("sample_count"),
        label="review history sample count",
    )
    latest_count = _required_count(
        history.get("latest_record_count"),
        label="review history latest record count",
    )
    history_count = _required_count(
        history.get("history_record_count"),
        label="review history record count",
    )
    idempotency_count = _required_count(
        history.get("idempotency_record_count"),
        label="review history idempotency record count",
    )
    if (
        sample_count != record_count
        or latest_count != record_count
        or len(latest_records) != latest_count
        or len(history_records) != history_count
        or len(idempotency_records) != idempotency_count
        or history_count < latest_count
        or idempotency_count != history_count
    ):
        raise CandidateReviewSealError("review history record counts do not reconcile")

    latest_bases: list[dict[str, object]] = []
    latest_keys: list[tuple[str, int]] = []
    for index, record in enumerate(latest_records):
        base, key = _review_record(
            record,
            label=f"review history latest record {index + 1}",
            source_record=False,
            package_sha256=package_sha256,
        )
        latest_bases.append(base)
        latest_keys.append(key)
    if latest_keys != source_keys or latest_bases != source_bases:
        raise CandidateReviewSealError(
            "review history latest records do not match the formal export"
        )

    normalized_history_records: list[dict[str, object]] = []
    history_keys: list[tuple[str, int]] = []
    for index, record in enumerate(history_records):
        base, key = _review_record(
            record,
            label=f"review history record {index + 1}",
            source_record=False,
            package_sha256=package_sha256,
        )
        normalized_history_records.append(base)
        history_keys.append(key)
    if history_keys != sorted(history_keys) or len(set(history_keys)) != len(history_keys):
        raise CandidateReviewSealError("review history records are not canonical")
    history_by_sample: dict[str, list[tuple[int, dict[str, object]]]] = {}
    for record, key in zip(
        normalized_history_records,
        history_keys,
        strict=True,
    ):
        history_by_sample.setdefault(key[0], []).append((key[1], record))
    if set(history_by_sample) != {key[0] for key in source_keys}:
        raise CandidateReviewSealError("review history records do not cover the formal export")
    latest_by_sample = {
        key[0]: (key[1], record)
        for key, record in zip(
            latest_keys,
            latest_bases,
            strict=True,
        )
    }
    for sample_id, versions in history_by_sample.items():
        if [version for version, _ in versions] != list(range(1, len(versions) + 1)) or versions[
            -1
        ] != latest_by_sample[sample_id]:
            raise CandidateReviewSealError("review history versions do not reconcile")

    idempotency_keys: list[tuple[str, int, str]] = []
    idempotency_targets: list[tuple[str, int]] = []
    for record in idempotency_records:
        if set(record) != _IDEMPOTENCY_RECORD_FIELDS:
            raise CandidateReviewSealError(
                "review history idempotency record contains unexpected fields"
            )
        sample_id = _required_text(
            record.get("sample_id"),
            label="review history idempotency sample ID",
        )
        version = _required_count(
            record.get("resulting_record_version"),
            label="review history idempotency record version",
        )
        if version < 1:
            raise CandidateReviewSealError("review history idempotency record version is invalid")
        idempotency_key = _required_text(
            record.get("idempotency_key"),
            label="review history idempotency key",
        )
        _required_sha256(
            record.get("request_hash"),
            label="review history request SHA-256",
        )
        _required_text(
            record.get("created_at"),
            label="review history idempotency creation time",
        )
        idempotency_targets.append((sample_id, version))
        idempotency_keys.append((sample_id, version, idempotency_key))
    if (
        idempotency_keys != sorted(idempotency_keys)
        or len(set(idempotency_targets)) != len(idempotency_targets)
        or idempotency_targets != history_keys
    ):
        raise CandidateReviewSealError("review history idempotency records do not reconcile")


def _resolved_review_data_root(review_data_root: Path) -> Path:
    if not review_data_root.is_absolute():
        raise CandidateReviewSealError("review_data_root must be an explicit absolute path")
    try:
        resolved = review_data_root.resolve(strict=True)
    except OSError as exc:
        raise CandidateReviewSealError("review_data_root is unavailable") from exc
    if not resolved.is_dir():
        raise CandidateReviewSealError("review_data_root must be a directory")
    return resolved


def _is_direct_child(path: Path, parent: Path) -> bool:
    try:
        return os.path.normcase(os.fspath(path.parent.resolve(strict=True))) == os.path.normcase(
            os.fspath(parent.resolve(strict=True))
        )
    except OSError:
        return False


def _seals_root(
    review_data_root: Path,
    *,
    create: bool,
) -> Path | None:
    candidate = review_data_root / "seals"
    if not candidate.exists():
        if not create:
            return None
        try:
            candidate.mkdir()
        except OSError as exc:
            raise CandidateReviewSealError("seal store cannot be created") from exc
    try:
        if candidate.is_symlink():
            raise CandidateReviewSealError("seal store must not be a symbolic link")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CandidateReviewSealError("seal store is invalid") from exc
    if not resolved.is_dir() or not _is_direct_child(resolved, review_data_root):
        raise CandidateReviewSealError("seal store is invalid")
    return resolved


def _source_authority_sha256(
    payload: Mapping[str, object],
) -> str:
    without_hash = dict(payload)
    without_hash.pop("source_authority_sha256", None)
    return _canonical_sha256(
        without_hash,
        label="source authority",
    )


def _prepare_seal(
    *,
    formal_export: CandidateReviewFormalExport,
    review_history_authority_payload: Mapping[str, object],
    review_history_authority_sha256: str,
    development_authority: FormalDevelopmentAuthority,
) -> _PreparedSeal:
    if not isinstance(formal_export, CandidateReviewFormalExport):
        raise CandidateReviewSealError("formal export contract is invalid")
    manifest = _normalized_object(
        formal_export.manifest_payload,
        label="manifest",
    )
    quality = _normalized_object(
        formal_export.quality_coverage_payload,
        label="quality coverage",
    )
    source = _normalized_object(
        formal_export.source_authority_payload,
        label="source authority",
    )
    history = _normalized_object(
        review_history_authority_payload,
        label="review history authority",
    )
    if not isinstance(
        development_authority,
        FormalDevelopmentAuthority,
    ):
        raise CandidateReviewSealError("development authority contract is invalid")
    development = _normalized_object(
        development_authority.payload,
        label="development authority",
    )
    try:
        parsed_development = parse_formal_development_authority(development)
    except FormalDevelopmentAuthorityError as exc:
        raise CandidateReviewSealError("development authority contract is invalid") from exc
    if parsed_development != development_authority:
        raise CandidateReviewSealError("development authority changed before sealing")

    manifest_sha256 = _required_sha256(
        formal_export.manifest_sha256,
        label="manifest SHA-256",
    )
    try:
        manifest_payload_sha256 = candidate_review_manifest_sha256(manifest)
    except CandidateReviewSemanticError as exc:
        raise CandidateReviewSealError("manifest semantic authority is invalid") from exc
    if (
        manifest_payload_sha256 != manifest_sha256
        or formal_export.manifest.canonical_sha256 != manifest_sha256
        or candidate_review_manifest_payload(formal_export.manifest) != manifest
    ):
        raise CandidateReviewSealError("manifest SHA-256 does not match the formal export")
    quality_sha256 = _required_sha256(
        formal_export.quality_coverage_sha256,
        label="quality coverage SHA-256",
    )
    if (
        quality.get("quality_coverage_sha256") != quality_sha256
        or locked_set_quality_coverage_sha256(quality) != quality_sha256
    ):
        raise CandidateReviewSealError("quality coverage SHA-256 does not match the formal export")
    export_source_sha256 = _required_sha256(
        formal_export.source_authority_sha256,
        label="source authority SHA-256",
    )
    if (
        source.get("source_authority_sha256") != export_source_sha256
        or _source_authority_sha256(source) != export_source_sha256
    ):
        raise CandidateReviewSealError("source authority SHA-256 does not match the formal export")
    try:
        validate_candidate_review_semantic_authority(
            manifest_payload=manifest,
            source_authority_payload=source,
        )
    except CandidateReviewSemanticError as exc:
        raise CandidateReviewSealError("formal source semantic authority is inconsistent") from exc
    source_schema_version = source.get("schema_version")
    if source_schema_version not in {2, 3} or (
        source_schema_version == 3 and source.get("quality_coverage_sha256") != quality_sha256
    ):
        raise CandidateReviewSealError(
            "quality coverage SHA-256 does not match the source authority"
        )
    sealed_source_without_hash = dict(source)
    sealed_source_without_hash.pop("source_authority_sha256", None)
    sealed_source_without_hash["schema_version"] = 3
    sealed_source_without_hash["quality_coverage_sha256"] = quality_sha256
    source_sha256 = _canonical_sha256(
        sealed_source_without_hash,
        label="source authority",
    )
    source = {
        **sealed_source_without_hash,
        "source_authority_sha256": source_sha256,
    }
    record_set_sha256 = _required_sha256(
        formal_export.record_set_sha256,
        label="record-set SHA-256",
    )
    history_sha256 = _required_sha256(
        review_history_authority_sha256,
        label="review history authority SHA-256",
    )
    if (
        _canonical_sha256(
            history,
            label="review history authority",
        )
        != history_sha256
    ):
        raise CandidateReviewSealError(
            "review history authority SHA-256 does not match its payload"
        )

    dataset_id = _required_text(
        manifest.get("dataset_id"),
        label="manifest dataset ID",
    )
    if (
        quality.get("dataset_id") != dataset_id
        or quality.get("manifest_sha256") != manifest_sha256
        or source.get("dataset_id") != dataset_id
        or source.get("manifest_sha256") != manifest_sha256
        or source.get("record_set_sha256") != record_set_sha256
    ):
        raise CandidateReviewSealError("formal export authority bindings do not reconcile")
    package_sha256 = _required_sha256(
        source.get("package_sha256"),
        label="candidate package SHA-256",
    )
    _validate_formal_authority_records(
        manifest=manifest,
        source=source,
        history=history,
        package_sha256=package_sha256,
        record_set_sha256=record_set_sha256,
    )

    artifact_payloads = {
        "manifest.json": manifest,
        "quality-coverage.json": quality,
        "review-history-authority.json": history,
        "source-authority.json": source,
        "development-authority.json": development,
    }
    artifact_sha256s = {
        name: _canonical_sha256(
            payload,
            label=name,
        )
        for name, payload in sorted(artifact_payloads.items())
    }
    seal_without_hash: dict[str, object] = {
        "schema_version": 1,
        "kind": "candidate_review_formal_seal",
        "dataset_id": dataset_id,
        "package_sha256": package_sha256,
        "manifest_sha256": manifest_sha256,
        "quality_coverage_sha256": quality_sha256,
        "source_authority_sha256": source_sha256,
        "review_history_authority_sha256": history_sha256,
        "record_set_sha256": record_set_sha256,
        "development_authority_sha256": (development_authority.authority_sha256),
        "artifact_sha256s": artifact_sha256s,
    }
    seal_sha256 = _canonical_sha256(
        seal_without_hash,
        label="seal",
    )
    return _PreparedSeal(
        seal_sha256=seal_sha256,
        seal_payload={
            **seal_without_hash,
            "seal_sha256": seal_sha256,
        },
        artifact_payloads=artifact_payloads,
    )


def _write_json_exclusive(path: Path, payload: object) -> None:
    content = (_canonical_json(payload, label=path.name) + "\n").encode("utf-8")
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _read_canonical_object(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise CandidateReviewSealError("existing seal is inconsistent")
    try:
        content = path.read_bytes()
        decoded = content.decode("utf-8")
        payload = json.loads(decoded)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateReviewSealError("existing seal is inconsistent") from exc
    normalized = _normalized_object(
        payload,
        label=path.name,
    )
    expected = (_canonical_json(normalized, label=path.name) + "\n").encode("utf-8")
    if content != expected:
        raise CandidateReviewSealError("existing seal is inconsistent")
    return normalized


def _validate_seal_directory(
    *,
    seal_root: Path,
    expected_seal_sha256: str,
    expected: _PreparedSeal | None = None,
) -> CandidateReviewSeal:
    seal_sha256 = _required_sha256(
        expected_seal_sha256,
        label="seal SHA-256",
    )
    try:
        if seal_root.is_symlink():
            raise CandidateReviewSealError("existing seal is inconsistent")
        resolved = seal_root.resolve(strict=True)
    except OSError as exc:
        raise CandidateReviewSealError("existing seal is inconsistent") from exc
    if not resolved.is_dir():
        raise CandidateReviewSealError("existing seal is inconsistent")
    try:
        entries = tuple(resolved.iterdir())
    except OSError as exc:
        raise CandidateReviewSealError("existing seal is inconsistent") from exc
    if {entry.name for entry in entries} != _SEAL_FILE_NAMES or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise CandidateReviewSealError("existing seal is inconsistent")
    payloads = {name: _read_canonical_object(resolved / name) for name in _SEAL_FILE_NAMES}
    seal_payload = payloads["seal.json"]
    if (
        set(seal_payload) != _SEAL_PAYLOAD_FIELDS
        or not _is_schema_version_one(seal_payload.get("schema_version"))
        or seal_payload.get("kind") != "candidate_review_formal_seal"
    ):
        raise CandidateReviewSealError("existing seal is inconsistent")
    declared_seal_sha256 = _required_sha256(
        seal_payload.get("seal_sha256"),
        label="seal SHA-256",
    )
    seal_without_hash = dict(seal_payload)
    seal_without_hash.pop("seal_sha256")
    if (
        declared_seal_sha256 != seal_sha256
        or _canonical_sha256(seal_without_hash, label="seal") != seal_sha256
    ):
        raise CandidateReviewSealError("existing seal is inconsistent")
    raw_artifact_hashes = seal_payload.get("artifact_sha256s")
    if not isinstance(raw_artifact_hashes, dict) or set(raw_artifact_hashes) != _ARTIFACT_NAMES:
        raise CandidateReviewSealError("existing seal is inconsistent")
    for name in _ARTIFACT_NAMES:
        declared = _required_sha256(
            raw_artifact_hashes.get(name),
            label=f"{name} SHA-256",
        )
        if (
            _canonical_sha256(
                payloads[name],
                label=name,
            )
            != declared
        ):
            raise CandidateReviewSealError("existing seal is inconsistent")

    manifest = payloads["manifest.json"]
    quality = payloads["quality-coverage.json"]
    source = payloads["source-authority.json"]
    development = payloads["development-authority.json"]
    history = payloads["review-history-authority.json"]
    package_sha256 = _required_sha256(
        seal_payload.get("package_sha256"),
        label="candidate package SHA-256",
    )
    record_set_sha256 = _required_sha256(
        seal_payload.get("record_set_sha256"),
        label="record-set SHA-256",
    )
    try:
        _validate_formal_authority_records(
            manifest=manifest,
            source=source,
            history=history,
            package_sha256=package_sha256,
            record_set_sha256=record_set_sha256,
        )
    except CandidateReviewSealError as exc:
        raise CandidateReviewSealError("existing seal is inconsistent") from exc
    try:
        development_authority = parse_formal_development_authority(development)
    except FormalDevelopmentAuthorityError as exc:
        raise CandidateReviewSealError("existing seal is inconsistent") from exc
    if (
        seal_payload.get("manifest_sha256") != candidate_review_manifest_sha256(manifest)
        or seal_payload.get("quality_coverage_sha256")
        != locked_set_quality_coverage_sha256(quality)
        or quality.get("quality_coverage_sha256") != seal_payload.get("quality_coverage_sha256")
        or seal_payload.get("source_authority_sha256") != _source_authority_sha256(source)
        or source.get("source_authority_sha256") != seal_payload.get("source_authority_sha256")
        or source.get("quality_coverage_sha256") != seal_payload.get("quality_coverage_sha256")
        or seal_payload.get("review_history_authority_sha256")
        != _canonical_sha256(
            history,
            label="review history authority",
        )
        or source.get("record_set_sha256") != seal_payload.get("record_set_sha256")
        or development_authority.authority_sha256
        != seal_payload.get("development_authority_sha256")
        or source.get("package_sha256") != package_sha256
        or source.get("dataset_id") != seal_payload.get("dataset_id")
        or source.get("manifest_sha256") != seal_payload.get("manifest_sha256")
        or quality.get("dataset_id") != seal_payload.get("dataset_id")
        or quality.get("manifest_sha256") != seal_payload.get("manifest_sha256")
        or manifest.get("dataset_id") != seal_payload.get("dataset_id")
    ):
        raise CandidateReviewSealError("existing seal is inconsistent")
    if expected is not None and (
        expected.seal_sha256 != seal_sha256
        or expected.seal_payload != seal_payload
        or any(expected.artifact_payloads[name] != payloads[name] for name in _ARTIFACT_NAMES)
    ):
        raise CandidateReviewSealError("existing seal is inconsistent")
    return CandidateReviewSeal(
        seal_sha256=seal_sha256,
        seal_root=resolved,
        seal_payload=seal_payload,
    )


def _cleanup_staging(staging: Path) -> None:
    if not staging.exists():
        return
    for entry in staging.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            raise CandidateReviewSealError("seal staging cleanup failed")
        entry.unlink()
    staging.rmdir()


def create_candidate_review_seal(
    *,
    review_data_root: Path,
    formal_export: CandidateReviewFormalExport,
    review_history_authority_payload: Mapping[str, object],
    review_history_authority_sha256: str,
) -> CandidateReviewSeal:
    """Atomically publish one immutable, content-addressed formal export seal."""

    resolved_data_root = _resolved_review_data_root(review_data_root)
    try:
        development_authority = load_formal_development_authority(
            resolved_data_root / "development-authority.json"
        )
    except FormalDevelopmentAuthorityError as exc:
        raise CandidateReviewSealError("development authority is unavailable") from exc
    prepared = _prepare_seal(
        formal_export=formal_export,
        review_history_authority_payload=(review_history_authority_payload),
        review_history_authority_sha256=(review_history_authority_sha256),
        development_authority=development_authority,
    )
    seals_root = _seals_root(
        resolved_data_root,
        create=True,
    )
    if seals_root is None:  # pragma: no cover - create=True
        raise CandidateReviewSealError("seal store cannot be created")
    target = seals_root / prepared.seal_sha256
    if target.exists() or target.is_symlink():
        return _validate_seal_directory(
            seal_root=target,
            expected_seal_sha256=prepared.seal_sha256,
            expected=prepared,
        )

    staging = seals_root / (f".{prepared.seal_sha256}.staging-{uuid4().hex}")
    try:
        staging.mkdir()
        for name in sorted(_ARTIFACT_NAMES):
            _write_json_exclusive(
                staging / name,
                prepared.artifact_payloads[name],
            )
        _write_json_exclusive(
            staging / "seal.json",
            prepared.seal_payload,
        )
        _validate_seal_directory(
            seal_root=staging,
            expected_seal_sha256=prepared.seal_sha256,
            expected=prepared,
        )
        if target.exists() or target.is_symlink():
            _cleanup_staging(staging)
            return _validate_seal_directory(
                seal_root=target,
                expected_seal_sha256=prepared.seal_sha256,
                expected=prepared,
            )
        try:
            staging.replace(target)
        except OSError:
            if not target.exists() and not target.is_symlink():
                raise
            _cleanup_staging(staging)
            return _validate_seal_directory(
                seal_root=target,
                expected_seal_sha256=prepared.seal_sha256,
                expected=prepared,
            )
        return _validate_seal_directory(
            seal_root=target,
            expected_seal_sha256=prepared.seal_sha256,
            expected=prepared,
        )
    except CandidateReviewSealError:
        _cleanup_staging(staging)
        raise
    except OSError as exc:
        _cleanup_staging(staging)
        raise CandidateReviewSealError("seal publication failed") from exc


def validate_candidate_review_seal(
    *,
    review_data_root: Path,
    seal_sha256: str,
) -> CandidateReviewSeal:
    """Rehash and validate one seal without changing the store."""

    canonical_sha256 = _required_sha256(
        seal_sha256,
        label="seal SHA-256",
    )
    resolved_data_root = _resolved_review_data_root(review_data_root)
    seals_root = _seals_root(
        resolved_data_root,
        create=False,
    )
    if seals_root is None:
        raise CandidateReviewSealError("existing seal is inconsistent")
    target = seals_root / canonical_sha256
    if not target.exists() or not _is_direct_child(target, seals_root):
        raise CandidateReviewSealError("existing seal is inconsistent")
    return _validate_seal_directory(
        seal_root=target,
        expected_seal_sha256=canonical_sha256,
    )


def discover_candidate_review_seals(
    review_data_root: Path,
) -> tuple[CandidateReviewSeal, ...]:
    """Discover every valid seal, failing closed on any unknown store entry."""

    resolved_data_root = _resolved_review_data_root(review_data_root)
    seals_root = _seals_root(
        resolved_data_root,
        create=False,
    )
    if seals_root is None:
        return ()
    try:
        entries = tuple(
            sorted(
                seals_root.iterdir(),
                key=lambda path: path.name,
            )
        )
    except OSError as exc:
        raise CandidateReviewSealError("seal store is invalid") from exc
    if any(
        _SHA256_PATTERN.fullmatch(entry.name) is None or entry.is_symlink() or not entry.is_dir()
        for entry in entries
    ):
        raise CandidateReviewSealError("seal store is invalid")
    return tuple(
        validate_candidate_review_seal(
            review_data_root=resolved_data_root,
            seal_sha256=entry.name,
        )
        for entry in entries
    )


def is_candidate_review_sealed(
    review_data_root: Path,
) -> bool:
    """Return whether a valid seal exists; corrupt stores fail closed."""

    return bool(discover_candidate_review_seals(review_data_root))
