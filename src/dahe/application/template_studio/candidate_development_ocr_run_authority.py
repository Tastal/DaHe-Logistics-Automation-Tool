from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from dahe.adapters.sqlite.candidate_development_ocr import (
    CandidateDevelopmentOcrRunAuthorityInput,
    CandidateDevelopmentOcrRunAuthorityRecord,
    CandidateDevelopmentOcrRunPersistenceError,
    CandidateDevelopmentOcrTerminalAttemptInput,
    CandidateDevelopmentOcrTerminalAttemptRecord,
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.application.template_studio.candidate_role_ocr_evidence import (
    load_protected_candidate_development_ocr_evidence,
    validate_failed_candidate_development_ocr_evidence,
)
from dahe.application.template_studio.candidate_role_source_authority import (
    CandidateRoleEvaluationError,
)


class CandidateDevelopmentOcrRunAuthorityError(RuntimeError):
    """Raised when a protected OCR run lacks exact durable authority."""


@dataclass(frozen=True, slots=True)
class AuthorizedCandidateDevelopmentOcrEvidence:
    payload: dict[str, object]
    record_content: bytes
    authority: CandidateDevelopmentOcrRunAuthorityRecord


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
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR run authority is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        _canonical_json(value).encode("utf-8")
    ).hexdigest()


def _mapping(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CandidateDevelopmentOcrRunAuthorityError(
            f"{label} must be an object"
        )
    return cast(Mapping[str, object], value)


def _text(
    value: object,
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
        raise CandidateDevelopmentOcrRunAuthorityError(
            f"{label} is invalid"
        )
    return value


def _resolved_root(
    repository: SqliteCandidateDevelopmentOcrRunRepository,
    data_root: Path,
) -> Path:
    if not isinstance(
        repository,
        SqliteCandidateDevelopmentOcrRunRepository,
    ):
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR run repository is invalid"
        )
    if not data_root.is_absolute():
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR data root must be absolute"
        )
    try:
        resolved = data_root.resolve(strict=True)
    except OSError as exc:
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR data root is unavailable"
        ) from exc
    if (
        resolved != data_root
        or not resolved.is_dir()
        or repository.runtime.data_root != resolved
    ):
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR repository data root changed identity"
        )
    return resolved


def _record_bytes(
    *,
    data_root: Path,
    evidence_path: Path,
    payload: Mapping[str, object],
) -> tuple[bytes, str, str]:
    if not evidence_path.is_absolute():
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR evidence path must be absolute"
        )
    try:
        resolved = evidence_path.resolve(strict=True)
        relative_path = resolved.relative_to(data_root).as_posix()
        content = resolved.read_bytes()
        decoded = json.loads(content)
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR evidence changed after validation"
        ) from exc
    if (
        resolved != evidence_path
        or decoded != payload
        or not content
    ):
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR evidence changed after validation"
        )
    return (
        content,
        hashlib.sha256(content).hexdigest(),
        relative_path,
    )


def _authority_input(
    *,
    payload: Mapping[str, object],
    record_content: bytes,
    evidence_blob_sha256: str,
    evidence_relative_path: str,
) -> CandidateDevelopmentOcrRunAuthorityInput:
    source = _mapping(
        payload.get("source"),
        label="candidate OCR source",
    )
    factory = _mapping(
        payload.get("factory_qualification"),
        label="candidate OCR factory qualification",
    )
    return CandidateDevelopmentOcrRunAuthorityInput(
        evidence_sha256=_text(
            payload.get("evidence_sha256"),
            label="candidate OCR evidence SHA-256",
            maximum=64,
        ),
        evidence_blob_sha256=evidence_blob_sha256,
        evidence_relative_path=evidence_relative_path,
        evidence_byte_size=len(record_content),
        package_sha256=_text(
            source.get("package_sha256"),
            label="candidate package SHA-256",
            maximum=64,
        ),
        review_history_authority_sha256=_text(
            source.get("review_history_authority_sha256"),
            label="candidate review-history authority SHA-256",
            maximum=64,
        ),
        source_authority_sha256=_text(
            source.get("source_authority_sha256"),
            label="candidate source authority SHA-256",
            maximum=64,
        ),
        reviewer_id=_text(
            payload.get("reviewer_id"),
            label="candidate reviewer ID",
            maximum=200,
        ),
        application_build_sha256=_text(
            payload.get("application_build_sha256"),
            label="candidate application build SHA-256",
            maximum=64,
        ),
        composition_evidence_sha256=_text(
            factory.get("composition_evidence_sha256"),
            label="candidate OCR composition SHA-256",
            maximum=64,
        ),
        runtime_set_sha256=_text(
            factory.get("runtime_set_sha256"),
            label="candidate OCR runtime-set SHA-256",
            maximum=64,
        ),
        pipeline_contract_sha256=_text(
            payload.get("pipeline_contract_sha256"),
            label="candidate OCR pipeline-contract SHA-256",
            maximum=64,
        ),
        completion_status=_text(
            payload.get("status"),
            label="candidate OCR completion status",
            maximum=50,
        ),
        completed_at=_text(
            payload.get("generated_at"),
            label="candidate OCR completion time",
            maximum=40,
        ),
    )


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


def _validated_file(
    repository: SqliteCandidateDevelopmentOcrRunRepository,
    *,
    data_root: Path,
    evidence_path: Path,
) -> tuple[
    dict[str, object],
    bytes,
    CandidateDevelopmentOcrRunAuthorityInput,
]:
    root = _resolved_root(repository, data_root)
    try:
        payload = load_protected_candidate_development_ocr_evidence(
            evidence_path,
            data_root=root,
        )
    except CandidateRoleEvaluationError as exc:
        raise CandidateDevelopmentOcrRunAuthorityError(
            str(exc)
        ) from exc
    content, blob_sha256, relative_path = _record_bytes(
        data_root=root,
        evidence_path=evidence_path,
        payload=payload,
    )
    return (
        payload,
        content,
        _authority_input(
            payload=payload,
            record_content=content,
            evidence_blob_sha256=blob_sha256,
            evidence_relative_path=relative_path,
        ),
    )


def record_candidate_development_ocr_run_authority(
    repository: SqliteCandidateDevelopmentOcrRunRepository,
    *,
    data_root: Path,
    evidence_path: Path,
) -> tuple[CandidateDevelopmentOcrRunAuthorityRecord, bool]:
    """Validate a successful protected write and append its DB authority."""

    _, _, authority_input = _validated_file(
        repository,
        data_root=data_root,
        evidence_path=evidence_path,
    )
    try:
        return repository.record_completed_run(authority_input)
    except CandidateDevelopmentOcrRunPersistenceError as exc:
        raise CandidateDevelopmentOcrRunAuthorityError(
            str(exc)
        ) from exc


def _raw_terminal_attempt_input(
    repository: SqliteCandidateDevelopmentOcrRunRepository,
    *,
    data_root: Path,
    evidence_path: Path,
) -> CandidateDevelopmentOcrTerminalAttemptInput:
    root = _resolved_root(repository, data_root)
    try:
        content = evidence_path.read_bytes()
        decoded = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR terminal evidence is unreadable"
        ) from exc
    if not isinstance(decoded, dict) or not content:
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR terminal evidence must be an object"
        )
    payload = cast(dict[str, object], decoded)
    content_again, blob_sha256, relative_path = _record_bytes(
        data_root=root,
        evidence_path=evidence_path,
        payload=payload,
    )
    evidence_sha256 = _text(
        payload.get("evidence_sha256"),
        label="candidate OCR evidence SHA-256",
        maximum=64,
    )
    logical_payload = {
        key: value
        for key, value in payload.items()
        if key != "evidence_sha256"
    }
    if (
        len(evidence_sha256) != 64
        or _canonical_sha256(logical_payload) != evidence_sha256
        or evidence_path.stem != evidence_sha256
    ):
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR terminal evidence identity does not reconcile"
        )
    authority_input = _authority_input(
        payload=payload,
        record_content=content_again,
        evidence_blob_sha256=blob_sha256,
        evidence_relative_path=relative_path,
    )
    status = authority_input.completion_status
    if status == "failed":
        try:
            validate_failed_candidate_development_ocr_evidence(
                payload,
                data_root=root,
            )
        except CandidateRoleEvaluationError as exc:
            raise CandidateDevelopmentOcrRunAuthorityError(
                str(exc)
            ) from exc
    terminal_status = (
        "technical_failed" if status == "failed" else "succeeded"
    )
    return CandidateDevelopmentOcrTerminalAttemptInput(
        **asdict(authority_input),
        terminal_status=terminal_status,
    )


def record_candidate_development_ocr_terminal_attempt(
    repository: SqliteCandidateDevelopmentOcrRunRepository,
    *,
    data_root: Path,
    evidence_path: Path,
) -> tuple[CandidateDevelopmentOcrTerminalAttemptRecord, bool]:
    """Record every protected terminal OCR outcome in DB sequence order."""

    terminal_input = _raw_terminal_attempt_input(
        repository,
        data_root=data_root,
        evidence_path=evidence_path,
    )
    try:
        if terminal_input.terminal_status == "technical_failed":
            return repository.record_failed_run(terminal_input)
        _, _, strict_authority_input = _validated_file(
            repository,
            data_root=data_root,
            evidence_path=evidence_path,
        )
        observed_authority_input = (
            CandidateDevelopmentOcrRunAuthorityInput(
                **{
                    field: getattr(terminal_input, field)
                    for field in (
                        CandidateDevelopmentOcrRunAuthorityInput
                        .__dataclass_fields__
                    )
                }
            )
        )
        if strict_authority_input != observed_authority_input:
            raise CandidateDevelopmentOcrRunAuthorityError(
                "candidate OCR terminal and strict authority "
                "validation do not reconcile"
            )
        _, created = repository.record_completed_run(
            strict_authority_input
        )
        return (
            repository.require_latest_success(
                terminal_input.evidence_sha256
            ),
            created,
        )
    except CandidateDevelopmentOcrRunPersistenceError as exc:
        raise CandidateDevelopmentOcrRunAuthorityError(str(exc)) from exc


def load_authorized_candidate_development_ocr_evidence(
    repository: SqliteCandidateDevelopmentOcrRunRepository,
    *,
    data_root: Path,
    evidence_path: Path,
    expected_evidence_sha256: str,
) -> AuthorizedCandidateDevelopmentOcrEvidence:
    """Load one strict OCR record only when file and DB authority agree."""

    payload, content, authority_input = _validated_file(
        repository,
        data_root=data_root,
        evidence_path=evidence_path,
    )
    if authority_input.evidence_sha256 != expected_evidence_sha256:
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR evidence identity does not match"
        )
    try:
        record = repository.get(expected_evidence_sha256)
        repository.require_latest_success(expected_evidence_sha256)
    except CandidateDevelopmentOcrRunPersistenceError as exc:
        raise CandidateDevelopmentOcrRunAuthorityError(
            str(exc)
        ) from exc
    observed = asdict(authority_input)
    persisted = {
        field: getattr(record, field)
        for field in observed
    }
    expected_authority_payload = _authority_payload(authority_input)
    if (
        persisted != observed
        or record.authority_payload_json
        != _canonical_json(expected_authority_payload)
        or record.authority_sha256
        != _canonical_sha256(expected_authority_payload)
    ):
        raise CandidateDevelopmentOcrRunAuthorityError(
            "candidate OCR file and database authority do not reconcile"
        )
    return AuthorizedCandidateDevelopmentOcrEvidence(
        payload=payload,
        record_content=content,
        authority=record,
    )
