from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from dahe.domain.daily.models import DailyCandidateSnapshot
from dahe.ports.daily import DailySnapshotCaptureAuthority

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CURRENT_FORMAL_SCHEMA_VERSION = 5
_READ_BINDING_KEY = re.compile(
    r"^(?:list:[1-9][0-9]*|"
    r"detail:[0-9a-f]{64}:[1-9][0-9]*|"
    r"image:[0-9a-f]{64}:(?:loading|unloading))$"
)
_EVIDENCE_KEYS = {
    "build_sha256",
    "candidate_count",
    "canonical_sha256",
    "contract_sha256",
    "contract_selection",
    "forbidden_request_count",
    "gate_passed",
    "identity_set_sha256",
    "platform_write_request_count",
    "query_scope",
    "redirect_count",
    "request_audit_sha256s",
    "schema_version",
    "settlement_contract_authority",
    "snapshot_count",
    "snapshot_evidence",
}


class DailySnapshotValidationError(RuntimeError):
    """Raised when three live daily snapshots cannot form formal evidence."""


@dataclass(frozen=True, slots=True)
class DailyContractSelectionBinding:
    """Immutable identity chain for the selected daily read contract."""

    contract_canonical_sha256: str
    contract_file_sha256: str
    freeze_evidence_sha256: str
    selection_sha256: str
    source_discovery_sha256: str

    def __post_init__(self) -> None:
        for field, value in self.to_payload().items():
            _required_sha256(value, field=field)

    def to_payload(self) -> dict[str, str]:
        return {
            "contract_canonical_sha256": self.contract_canonical_sha256,
            "contract_file_sha256": self.contract_file_sha256,
            "freeze_evidence_sha256": self.freeze_evidence_sha256,
            "selection_sha256": self.selection_sha256,
            "source_discovery_sha256": self.source_discovery_sha256,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> DailyContractSelectionBinding:
        expected = {
            "contract_canonical_sha256",
            "contract_file_sha256",
            "freeze_evidence_sha256",
            "selection_sha256",
            "source_discovery_sha256",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise DailySnapshotValidationError(
                "selected daily contract evidence is invalid"
            )
        return cls(
            contract_canonical_sha256=_required_sha256(
                value.get("contract_canonical_sha256"),
                field="contract_canonical_sha256",
            ),
            contract_file_sha256=_required_sha256(
                value.get("contract_file_sha256"),
                field="contract_file_sha256",
            ),
            freeze_evidence_sha256=_required_sha256(
                value.get("freeze_evidence_sha256"),
                field="freeze_evidence_sha256",
            ),
            selection_sha256=_required_sha256(
                value.get("selection_sha256"),
                field="selection_sha256",
            ),
            source_discovery_sha256=_required_sha256(
                value.get("source_discovery_sha256"),
                field="source_discovery_sha256",
            ),
        )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _required_sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise DailySnapshotValidationError(
            f"{field} must be a lowercase SHA-256"
        )
    return value


def _query_scope(snapshot: DailyCandidateSnapshot) -> dict[str, object]:
    return {
        "business_date": snapshot.target_business_date.isoformat(),
        "query_end": snapshot.query_window.end.isoformat(),
        "query_safety_end": snapshot.query_window.safety_end.isoformat(),
        "query_start": snapshot.query_window.start.isoformat(),
        "receive_place": snapshot.receive_place,
    }


def _identity_payload(
    snapshot: DailyCandidateSnapshot,
) -> tuple[dict[str, str], ...]:
    if any(
        candidate.waybill_number is None
        for candidate in snapshot.candidates
    ):
        raise DailySnapshotValidationError(
            "daily validation candidate identity is incomplete"
        )
    return tuple(
        sorted(
            (
                {
                    "platform_waybill_id": candidate.platform_waybill_id,
                    "waybill_number": (
                        candidate.waybill_number
                        if candidate.waybill_number is not None
                        else ""
                    ),
                }
                for candidate in snapshot.candidates
            ),
            key=lambda value: (
                value["platform_waybill_id"],
                value["waybill_number"],
            ),
        )
    )


def validate_daily_snapshot_triplet(
    authorities: Sequence[DailySnapshotCaptureAuthority],
    *,
    build_sha256: str,
    expected_contract_sha256: str,
    contract_selection: DailyContractSelectionBinding,
) -> dict[str, object]:
    """Create replayable evidence for three independent reads of one scope."""

    build = _required_sha256(build_sha256, field="build_sha256")
    contract = _required_sha256(
        expected_contract_sha256,
        field="expected_contract_sha256",
    )
    if (
        not isinstance(
            contract_selection,
            DailyContractSelectionBinding,
        )
        or contract_selection.contract_canonical_sha256 != contract
    ):
        raise DailySnapshotValidationError(
            "selected daily contract does not match the capture contract"
        )
    if len(authorities) != 3:
        raise DailySnapshotValidationError(
            "daily validation requires exactly three snapshots"
        )
    if any(
        not isinstance(authority, DailySnapshotCaptureAuthority)
        for authority in authorities
    ):
        raise DailySnapshotValidationError(
            "daily validation capture authority type is invalid"
        )
    for authority in authorities:
        _validate_capture_authority(
            authority,
            build_sha256=build,
            contract_sha256=contract,
        )
        _validate_read_bindings(
            access_window_id=authority.access_window_id,
            access_window_ids=authority.access_window_ids,
            read_access_window_ids=authority.read_access_window_ids,
            expected_operations=(
                authority.request_audit_expected_succeeded_operations
            ),
        )
    settlement_authorities = tuple(
        _validate_request_audit_authority(
            authority.request_audit_authority,
            build_sha256=build,
            daily_contract_sha256=contract,
            daily_selection_sha256=contract_selection.selection_sha256,
        )
        for authority in authorities
    )
    if any(
        value != settlement_authorities[0]
        for value in settlement_authorities[1:]
    ):
        raise DailySnapshotValidationError(
            "daily validation settlement audit authority changed"
        )
    for authority in authorities:
        _required_sha256(
            authority.request_audit_sha256,
            field="request_audit_sha256",
        )
        if (
            _required_sha256(
                authority.request_audit_job_id_sha256,
                field="request_audit_job_id_sha256",
            )
            != hashlib.sha256(authority.job_id.encode("utf-8")).hexdigest()
            or authority.request_audit_purpose != "daily_snapshot"
            or authority.request_audit_kind
            != "loop9_platform_read_audit"
            or authority.request_audit_schema_version != 1
        ):
            raise DailySnapshotValidationError(
                "daily validation request audit job identity changed"
            )
        _required_sha256(
            authority.request_audit_event_chain_sha256,
            field="request_audit_event_chain_sha256",
        )
        _validate_request_audit_counts(
            request_counts=authority.request_audit_request_counts,
            operation_counts=authority.request_audit_operation_counts,
            event_count=authority.request_audit_event_count,
        )
        _validate_request_audit_expected_operations(
            expected=(
                authority.request_audit_expected_succeeded_operations
            ),
            operation_counts=authority.request_audit_operation_counts,
            candidate_count=len(authority.snapshot.candidates),
        )
        if (
            authority.request_audit_request_counts.get("denied")
            != authority.forbidden_request_count
        ):
            raise DailySnapshotValidationError(
                "daily validation request audit counters changed"
            )
    if len(
        {
            authority.request_audit_sha256
            for authority in authorities
        }
    ) != 3:
        raise DailySnapshotValidationError(
            "daily validation request audits are not independent"
        )
    all_access_window_ids = [
        access_window_id
        for authority in authorities
        for access_window_id in authority.access_window_ids
    ]
    if (
        len({authority.access_window_id for authority in authorities})
        != 3
        or len(set(all_access_window_ids))
        != len(all_access_window_ids)
    ):
        raise DailySnapshotValidationError(
            "daily validation requires three independent access windows"
        )
    snapshots = tuple(
        authority.snapshot for authority in authorities
    )
    snapshot_ids = tuple(snapshot.snapshot_id for snapshot in snapshots)
    snapshot_fingerprints = tuple(
        snapshot.fingerprint for snapshot in snapshots
    )
    if (
        len(set(snapshot_ids)) != 3
        or len(set(snapshot_fingerprints)) != 3
    ):
        raise DailySnapshotValidationError(
            "daily validation snapshots are not independent"
        )
    captured_at = tuple(snapshot.captured_at for snapshot in snapshots)
    if len(set(captured_at)) != 3 or captured_at != tuple(
        sorted(captured_at)
    ):
        raise DailySnapshotValidationError(
            "daily validation snapshots are not independently ordered"
        )

    scopes = tuple(_query_scope(snapshot) for snapshot in snapshots)
    if any(scope != scopes[0] for scope in scopes[1:]):
        raise DailySnapshotValidationError(
            "daily validation query scope changed"
        )
    if any(
        snapshot.source_contract_sha256 != contract
        for snapshot in snapshots
    ):
        raise DailySnapshotValidationError(
            "daily validation contract changed"
        )

    identity_payloads = tuple(
        _identity_payload(snapshot) for snapshot in snapshots
    )
    if any(
        identities != identity_payloads[0]
        for identities in identity_payloads[1:]
    ):
        raise DailySnapshotValidationError(
            "daily validation identity set changed"
        )
    candidate_count = len(identity_payloads[0])
    if any(
        len(snapshot.candidates) != candidate_count
        for snapshot in snapshots
    ):
        raise DailySnapshotValidationError(
            "daily validation candidate count changed"
        )
    identity_set_sha256 = _sha256(identity_payloads[0])
    snapshot_evidence: list[dict[str, object]] = [
        {
            "access_consumed": authority.access_consumed,
            "access_purpose": authority.access_purpose,
            "access_window_id": authority.access_window_id,
            "access_window_ids": list(
                authority.access_window_ids
            ),
            "capture_build_sha256": authority.capture_build_sha256,
            "captured_at": snapshot.captured_at.isoformat(),
            "forbidden_request_count": (
                authority.forbidden_request_count
            ),
            "identity_set_sha256": identity_set_sha256,
            "invocation_contract_sha256": (
                authority.invocation_contract_sha256
            ),
            "invocation_diagnostic_code": (
                authority.invocation_diagnostic_code
            ),
            "invocation_id": authority.invocation_id,
            "invocation_next_stage": (
                authority.invocation_next_stage
            ),
            "invocation_status": authority.invocation_status,
            "job_current_stage": authority.job_current_stage,
            "job_diagnostic_code": authority.job_diagnostic_code,
            "job_id": authority.job_id,
            "job_status": authority.job_status,
            "observation_count": authority.observation_count,
            "platform_write_request_count": (
                authority.platform_write_request_count
            ),
            "redirect_count": authority.redirect_count,
            "read_access_window_ids": dict(
                sorted(authority.read_access_window_ids.items())
            ),
            "request_audit_authority": dict(
                authority.request_audit_authority
            ),
            "request_audit_event_count": (
                authority.request_audit_event_count
            ),
            "request_audit_event_chain_sha256": (
                authority.request_audit_event_chain_sha256
            ),
            "request_audit_expected_succeeded_operations": dict(
                authority.request_audit_expected_succeeded_operations
            ),
            "request_audit_job_id_sha256": (
                authority.request_audit_job_id_sha256
            ),
            "request_audit_operation_counts": {
                operation: dict(counts)
                for operation, counts in (
                    authority.request_audit_operation_counts.items()
                )
            },
            "request_audit_kind": authority.request_audit_kind,
            "request_audit_purpose": authority.request_audit_purpose,
            "request_audit_request_counts": dict(
                authority.request_audit_request_counts
            ),
            "request_audit_sha256": authority.request_audit_sha256,
            "request_audit_schema_version": (
                authority.request_audit_schema_version
            ),
            "snapshot_fingerprint": snapshot.fingerprint,
            "snapshot_id": snapshot.snapshot_id,
            "succeeded_work_item_count": (
                authority.succeeded_work_item_count
            ),
            "completed_stage_work_item_count": (
                authority.completed_stage_work_item_count
            ),
            "work_item_count": authority.work_item_count,
        }
        for authority, snapshot in zip(
            authorities,
            snapshots,
            strict=True,
        )
    ]
    if any(
        _request_audit_sha256_from_snapshot(snapshot)
        != snapshot["request_audit_sha256"]
        for snapshot in snapshot_evidence
    ):
        raise DailySnapshotValidationError(
            "daily validation request audit integrity changed"
        )
    body: dict[str, object] = {
        "build_sha256": build,
        "candidate_count": candidate_count,
        "contract_sha256": contract,
        "contract_selection": contract_selection.to_payload(),
        "forbidden_request_count": sum(
            authority.forbidden_request_count
            for authority in authorities
        ),
        "gate_passed": True,
        "identity_set_sha256": identity_set_sha256,
        "platform_write_request_count": sum(
            authority.platform_write_request_count
            for authority in authorities
        ),
        "query_scope": scopes[0],
        "redirect_count": sum(
            authority.redirect_count for authority in authorities
        ),
        "request_audit_sha256s": [
            authority.request_audit_sha256
            for authority in authorities
        ],
        "schema_version": _CURRENT_FORMAL_SCHEMA_VERSION,
        "settlement_contract_authority": settlement_authorities[0],
        "snapshot_count": 3,
        "snapshot_evidence": snapshot_evidence,
    }
    return {
        **body,
        "canonical_sha256": _sha256(body),
    }


def _validate_capture_authority(
    authority: DailySnapshotCaptureAuthority,
    *,
    build_sha256: str,
    contract_sha256: str,
) -> None:
    snapshot = authority.snapshot
    if not isinstance(snapshot, DailyCandidateSnapshot):
        raise DailySnapshotValidationError(
            "daily validation snapshot type is invalid"
        )
    if authority.capture_build_sha256 != build_sha256:
        raise DailySnapshotValidationError(
            "daily validation capture build changed"
        )
    if (
        authority.access_purpose != "production_shadow"
        or authority.access_consumed is not True
    ):
        raise DailySnapshotValidationError(
            "daily validation access authority is incomplete"
        )
    if (
        authority.invocation_id != snapshot.snapshot_id
        or authority.job_id != snapshot.snapshot_id
        or not authority.access_window_id
        or not authority.access_window_ids
        or authority.access_window_ids[-1]
        != authority.access_window_id
        or len(set(authority.access_window_ids))
        != len(authority.access_window_ids)
    ):
        raise DailySnapshotValidationError(
            "daily validation invocation identity is inconsistent"
        )
    if (
        authority.invocation_contract_sha256
        != contract_sha256
        or snapshot.source_contract_sha256
        != contract_sha256
    ):
        raise DailySnapshotValidationError(
            "daily validation contract changed"
        )
    if (
        authority.invocation_status != "succeeded"
        or authority.invocation_next_stage != "daily.complete"
        or authority.invocation_diagnostic_code is not None
    ):
        raise DailySnapshotValidationError(
            "daily validation invocation is not terminally successful"
        )
    if (
        authority.job_status != "succeeded"
        or authority.job_current_stage != "daily.complete"
        or authority.job_diagnostic_code is not None
    ):
        raise DailySnapshotValidationError(
            "daily validation job is not terminally successful"
        )
    if (
        authority.work_item_count != 1
        or authority.succeeded_work_item_count != 1
        or authority.completed_stage_work_item_count != 1
    ):
        raise DailySnapshotValidationError(
            "daily validation work item is not terminally successful"
        )
    if authority.observation_count != len(snapshot.candidates):
        raise DailySnapshotValidationError(
            "daily validation observation count is incomplete"
        )
    if any(
        type(value) is not int or value != 0
        for value in (
            authority.forbidden_request_count,
            authority.platform_write_request_count,
            authority.redirect_count,
        )
    ):
        raise DailySnapshotValidationError(
            "daily validation read-only counters are not zero"
        )


def _validate_request_audit_authority(
    value: object,
    *,
    build_sha256: str,
    daily_contract_sha256: str,
    daily_selection_sha256: str,
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "build_sha256",
        "daily_contract_selection_sha256",
        "daily_contract_sha256",
        "settlement_contract_selection_sha256",
        "settlement_contract_sha256",
    }:
        raise DailySnapshotValidationError(
            "daily validation request audit authority is invalid"
        )
    for field, item in value.items():
        _required_sha256(item, field=f"request_audit_authority.{field}")
    if (
        value["build_sha256"] != build_sha256
        or value["daily_contract_sha256"] != daily_contract_sha256
        or value["daily_contract_selection_sha256"]
        != daily_selection_sha256
    ):
        raise DailySnapshotValidationError(
            "daily validation request audit authority changed"
        )
    return {
        "contract_selection_sha256": str(
            value["settlement_contract_selection_sha256"]
        ),
        "contract_sha256": str(value["settlement_contract_sha256"]),
    }


def _validate_request_audit_counts(
    *,
    request_counts: object,
    operation_counts: object,
    event_count: object,
) -> None:
    request_keys = {"allowed", "attempted", "denied", "succeeded"}
    operation_names = {
        "download_ticket_image",
        "get_waybill_detail",
        "list_daily_waybills",
        "list_waybills",
    }
    operation_keys = {
        "allowed",
        "attempted",
        "denied",
        "failed",
        "redirect",
        "succeeded",
    }
    if (
        not isinstance(request_counts, dict)
        or set(request_counts) != request_keys
        or not isinstance(operation_counts, dict)
        or set(operation_counts) != operation_names
        or type(event_count) is not int
        or event_count < 1
    ):
        raise DailySnapshotValidationError(
            "daily validation request audit counts are invalid"
        )
    if any(
        type(request_counts[key]) is not int
        or request_counts[key] < 0
        for key in request_keys
    ):
        raise DailySnapshotValidationError(
            "daily validation request audit counts are invalid"
        )
    total_phases = 0
    totals = {key: 0 for key in request_keys}
    for operation in operation_names:
        counts = operation_counts[operation]
        if (
            not isinstance(counts, dict)
            or set(counts) != operation_keys
            or any(
                type(counts[key]) is not int or counts[key] < 0
                for key in operation_keys
            )
        ):
            raise DailySnapshotValidationError(
                "daily validation request audit counts are invalid"
            )
        total_phases += sum(int(counts[key]) for key in operation_keys)
        for key in request_keys:
            totals[key] += int(counts[key])
    if (
        totals != request_counts
        or total_phases != event_count
        or request_counts["denied"] != 0
    ):
        raise DailySnapshotValidationError(
            "daily validation request audit counts are inconsistent"
        )


def _validate_request_audit_expected_operations(
    *,
    expected: object,
    operation_counts: object,
    candidate_count: int,
) -> None:
    allowed_operations = {
        "download_ticket_image",
        "get_waybill_detail",
        "list_daily_waybills",
    }
    if (
        not isinstance(expected, dict)
        or not expected
        or not set(expected).issubset(allowed_operations)
        or any(
            type(value) is not int or value < 1
            for value in expected.values()
        )
        or not isinstance(operation_counts, dict)
    ):
        raise DailySnapshotValidationError(
            "daily validation request audit expected operations are invalid"
        )
    for operation in {
        "download_ticket_image",
        "get_waybill_detail",
        "list_daily_waybills",
        "list_waybills",
    }:
        counts = operation_counts.get(operation)
        if (
            not isinstance(counts, dict)
            or counts.get("succeeded") != expected.get(operation, 0)
        ):
            raise DailySnapshotValidationError(
                "daily validation request audit expected operations changed"
            )
    if (
        expected.get("get_waybill_detail", 0) < candidate_count
        or expected.get("download_ticket_image", 0)
        > candidate_count * 2
        or expected.get("list_daily_waybills", 0) < 2
    ):
        raise DailySnapshotValidationError(
            "daily validation request audit expected operations changed"
        )


def _validate_read_bindings(
    *,
    access_window_id: object,
    access_window_ids: object,
    read_access_window_ids: object,
    expected_operations: object,
) -> None:
    if (
        not isinstance(access_window_id, str)
        or not isinstance(access_window_ids, (tuple, list))
        or not access_window_ids
        or any(
            not isinstance(value, str) or not value
            for value in access_window_ids
        )
        or len(set(access_window_ids)) != len(access_window_ids)
        or access_window_ids[-1] != access_window_id
        or not isinstance(read_access_window_ids, Mapping)
        or not isinstance(expected_operations, dict)
    ):
        raise DailySnapshotValidationError(
            "daily validation read access lineage is invalid"
        )
    bindings = dict(read_access_window_ids)
    if (
        not bindings
        or any(
            not isinstance(key, str)
            or _READ_BINDING_KEY.fullmatch(key) is None
            or not isinstance(value, str)
            or value not in access_window_ids
            for key, value in bindings.items()
        )
    ):
        raise DailySnapshotValidationError(
            "daily validation read access binding is invalid"
        )
    actual_counts = {
        "list_daily_waybills": sum(
            key.startswith("list:") for key in bindings
        ),
        "get_waybill_detail": sum(
            key.startswith("detail:") for key in bindings
        ),
        "download_ticket_image": sum(
            key.startswith("image:") for key in bindings
        ),
    }
    if any(
        actual_counts[operation]
        != expected_operations.get(operation, 0)
        for operation in actual_counts
    ):
        raise DailySnapshotValidationError(
            "daily validation read access count changed"
        )


def _request_audit_sha256_from_snapshot(
    snapshot: dict[str, object],
) -> str:
    body = {
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
        "purpose": snapshot.get("request_audit_purpose"),
        "redirect_count": snapshot.get("redirect_count"),
        "request_counts": snapshot.get("request_audit_request_counts"),
        "schema_version": snapshot.get("request_audit_schema_version"),
    }
    return _sha256(body)


def verify_daily_snapshot_validation_evidence(
    payload: object,
) -> dict[str, object]:
    """Verify current or historical read-only daily validation evidence."""

    if not isinstance(payload, dict) or set(payload) != _EVIDENCE_KEYS:
        raise DailySnapshotValidationError(
            "daily validation evidence shape is invalid"
        )
    declared = _required_sha256(
        payload.get("canonical_sha256"),
        field="canonical_sha256",
    )
    body: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if key != "canonical_sha256"
    }
    if _sha256(body) != declared:
        raise DailySnapshotValidationError(
            "daily validation evidence integrity check failed"
        )
    schema_version = payload.get("schema_version")
    if (
        schema_version not in {4, 5}
        or payload.get("gate_passed") is not True
        or payload.get("snapshot_count") != 3
        or type(payload.get("candidate_count")) is not int
        or int(payload["candidate_count"]) < 0
    ):
        raise DailySnapshotValidationError(
            "daily validation evidence result is invalid"
        )
    _required_sha256(payload.get("build_sha256"), field="build_sha256")
    _required_sha256(
        payload.get("contract_sha256"),
        field="contract_sha256",
    )
    selection = DailyContractSelectionBinding.from_payload(
        payload.get("contract_selection")
    )
    if selection.contract_canonical_sha256 != payload["contract_sha256"]:
        raise DailySnapshotValidationError(
            "selected daily contract does not match the capture contract"
        )
    settlement_authority = payload.get(
        "settlement_contract_authority"
    )
    if not isinstance(settlement_authority, dict) or set(
        settlement_authority
    ) != {
        "contract_selection_sha256",
        "contract_sha256",
    }:
        raise DailySnapshotValidationError(
            "daily validation settlement audit authority is invalid"
        )
    for field, value in settlement_authority.items():
        _required_sha256(value, field=f"settlement_authority.{field}")
    request_audit_sha256s = payload.get("request_audit_sha256s")
    if (
        not isinstance(request_audit_sha256s, list)
        or len(request_audit_sha256s) != 3
        or len(set(request_audit_sha256s)) != 3
    ):
        raise DailySnapshotValidationError(
            "daily validation request audits are invalid"
        )
    for value in request_audit_sha256s:
        _required_sha256(value, field="request_audit_sha256")
    if any(
        type(payload.get(field)) is not int
        or payload.get(field) != 0
        for field in (
            "forbidden_request_count",
            "platform_write_request_count",
            "redirect_count",
        )
    ):
        raise DailySnapshotValidationError(
            "daily validation read-only counters are not zero"
        )
    identity_set_sha256 = _required_sha256(
        payload.get("identity_set_sha256"),
        field="identity_set_sha256",
    )
    query_scope = payload.get("query_scope")
    if not isinstance(query_scope, dict) or set(query_scope) != {
        "business_date",
        "query_end",
        "query_safety_end",
        "query_start",
        "receive_place",
    }:
        raise DailySnapshotValidationError(
            "daily validation query scope is invalid"
        )
    try:
        business_date = date.fromisoformat(
            _plain_text(
                query_scope.get("business_date"),
                field="business_date",
                maximum=10,
            )
        )
    except ValueError as exc:
        raise DailySnapshotValidationError(
            "daily validation query scope is invalid"
        ) from exc
    query_start = _evidence_time(
        query_scope.get("query_start"),
        field="query_start",
    )
    query_end = _evidence_time(
        query_scope.get("query_end"),
        field="query_end",
    )
    query_safety_end = _evidence_time(
        query_scope.get("query_safety_end"),
        field="query_safety_end",
    )
    _plain_text(
        query_scope.get("receive_place"),
        field="receive_place",
        maximum=100,
    )
    if (
        business_date.isoformat()
        != query_scope.get("business_date")
        or not query_start <= query_end <= query_safety_end
    ):
        raise DailySnapshotValidationError(
            "daily validation query scope is invalid"
        )
    snapshots = payload.get("snapshot_evidence")
    if not isinstance(snapshots, list) or len(snapshots) != 3:
        raise DailySnapshotValidationError(
            "daily validation snapshot evidence is invalid"
        )
    snapshot_ids: list[str] = []
    access_window_ids: list[str] = []
    lineage_access_window_ids: list[str] = []
    fingerprints: list[str] = []
    captured_at: list[datetime] = []
    for snapshot_index, snapshot in enumerate(snapshots):
        expected_snapshot_keys = {
            "access_consumed",
            "access_purpose",
            "access_window_id",
            "capture_build_sha256",
            "captured_at",
            "completed_stage_work_item_count",
            "forbidden_request_count",
            "identity_set_sha256",
            "invocation_contract_sha256",
            "invocation_diagnostic_code",
            "invocation_id",
            "invocation_next_stage",
            "invocation_status",
            "job_current_stage",
            "job_diagnostic_code",
            "job_id",
            "job_status",
            "observation_count",
            "platform_write_request_count",
            "redirect_count",
            "request_audit_authority",
            "request_audit_event_count",
            "request_audit_event_chain_sha256",
            "request_audit_expected_succeeded_operations",
            "request_audit_job_id_sha256",
            "request_audit_kind",
            "request_audit_operation_counts",
            "request_audit_purpose",
            "request_audit_request_counts",
            "request_audit_schema_version",
            "request_audit_sha256",
            "snapshot_fingerprint",
            "snapshot_id",
            "succeeded_work_item_count",
            "work_item_count",
        }
        if schema_version == 5:
            expected_snapshot_keys.update(
                {
                    "access_window_ids",
                    "read_access_window_ids",
                }
            )
        if (
            not isinstance(snapshot, dict)
            or set(snapshot) != expected_snapshot_keys
        ):
            raise DailySnapshotValidationError(
                "daily validation snapshot evidence is invalid"
            )
        if (
            _required_sha256(
                snapshot.get("identity_set_sha256"),
                field="snapshot identity_set_sha256",
            )
            != identity_set_sha256
        ):
            raise DailySnapshotValidationError(
                "daily validation snapshot identity is inconsistent"
            )
        audit_sha256 = _required_sha256(
            snapshot.get("request_audit_sha256"),
            field="request_audit_sha256",
        )
        if audit_sha256 != request_audit_sha256s[snapshot_index]:
            raise DailySnapshotValidationError(
                "daily validation request audit identity changed"
            )
        if (
            _request_audit_sha256_from_snapshot(snapshot)
            != audit_sha256
        ):
            raise DailySnapshotValidationError(
                "daily validation request audit integrity changed"
            )
        job_id = _plain_text(
            snapshot.get("job_id"),
            field="job_id",
            maximum=100,
        )
        if (
            _required_sha256(
                snapshot.get("request_audit_job_id_sha256"),
                field="request_audit_job_id_sha256",
            )
            != hashlib.sha256(job_id.encode("utf-8")).hexdigest()
            or snapshot.get("request_audit_purpose") != "daily_snapshot"
            or snapshot.get("request_audit_kind")
            != "loop9_platform_read_audit"
            or snapshot.get("request_audit_schema_version") != 1
        ):
            raise DailySnapshotValidationError(
                "daily validation request audit job identity changed"
            )
        _required_sha256(
            snapshot.get("request_audit_event_chain_sha256"),
            field="request_audit_event_chain_sha256",
        )
        audit_settlement = _validate_request_audit_authority(
            snapshot.get("request_audit_authority"),
            build_sha256=cast(str, payload["build_sha256"]),
            daily_contract_sha256=cast(
                str,
                payload["contract_sha256"],
            ),
            daily_selection_sha256=selection.selection_sha256,
        )
        if audit_settlement != settlement_authority:
            raise DailySnapshotValidationError(
                "daily validation request audit authority changed"
            )
        _validate_request_audit_counts(
            request_counts=snapshot.get("request_audit_request_counts"),
            operation_counts=snapshot.get(
                "request_audit_operation_counts"
            ),
            event_count=snapshot.get("request_audit_event_count"),
        )
        _validate_request_audit_expected_operations(
            expected=snapshot.get(
                "request_audit_expected_succeeded_operations"
            ),
            operation_counts=snapshot.get(
                "request_audit_operation_counts"
            ),
            candidate_count=cast(int, payload["candidate_count"]),
        )
        snapshot_ids.append(
            _plain_text(
                snapshot.get("snapshot_id"),
                field="snapshot_id",
                maximum=100,
            )
        )
        access_window_ids.append(
            _plain_text(
                snapshot.get("access_window_id"),
                field="access_window_id",
                maximum=100,
            )
        )
        if schema_version == 5:
            raw_lineage = snapshot.get("access_window_ids")
            raw_bindings = snapshot.get(
                "read_access_window_ids"
            )
            _validate_read_bindings(
                access_window_id=access_window_ids[-1],
                access_window_ids=raw_lineage,
                read_access_window_ids=raw_bindings,
                expected_operations=snapshot.get(
                    "request_audit_expected_succeeded_operations"
                ),
            )
            assert isinstance(raw_lineage, list)
            lineage_access_window_ids.extend(raw_lineage)
        else:
            lineage_access_window_ids.append(
                access_window_ids[-1]
            )
        build = _required_sha256(
            snapshot.get("capture_build_sha256"),
            field="capture_build_sha256",
        )
        invocation_id = _plain_text(
            snapshot.get("invocation_id"),
            field="invocation_id",
            maximum=100,
        )
        if (
            build != payload["build_sha256"]
            or _required_sha256(
                snapshot.get("invocation_contract_sha256"),
                field="invocation_contract_sha256",
            )
            != payload["contract_sha256"]
            or snapshot.get("access_purpose")
            != "production_shadow"
            or snapshot.get("access_consumed") is not True
            or invocation_id != snapshot.get("snapshot_id")
            or job_id != snapshot.get("snapshot_id")
            or snapshot.get("invocation_status") != "succeeded"
            or snapshot.get("invocation_next_stage")
            != "daily.complete"
            or snapshot.get("invocation_diagnostic_code") is not None
            or snapshot.get("job_status") != "succeeded"
            or snapshot.get("job_current_stage") != "daily.complete"
            or snapshot.get("job_diagnostic_code") is not None
            or snapshot.get("work_item_count") != 1
            or snapshot.get("succeeded_work_item_count") != 1
            or snapshot.get("completed_stage_work_item_count") != 1
            or snapshot.get("forbidden_request_count") != 0
            or snapshot.get("platform_write_request_count") != 0
            or snapshot.get("redirect_count") != 0
        ):
            raise DailySnapshotValidationError(
                "daily validation snapshot authority is invalid"
            )
        observation_count = snapshot.get("observation_count")
        if (
            type(observation_count) is not int
            or observation_count != payload["candidate_count"]
        ):
            raise DailySnapshotValidationError(
                "daily validation observation count is invalid"
            )
        fingerprints.append(
            _required_sha256(
                snapshot.get("snapshot_fingerprint"),
                field="snapshot_fingerprint",
            )
        )
        captured_at.append(
            _evidence_time(
                snapshot.get("captured_at"),
                field="captured_at",
            )
        )
    if (
        len(set(snapshot_ids)) != 3
        or len(set(access_window_ids)) != 3
        or len(set(lineage_access_window_ids))
        != len(lineage_access_window_ids)
        or len(set(fingerprints)) != 3
        or len(set(captured_at)) != 3
        or captured_at != sorted(captured_at)
    ):
        raise DailySnapshotValidationError(
            "daily validation snapshot evidence is not independent"
        )
    return dict(payload)


def verify_current_daily_snapshot_validation_evidence(
    payload: object,
) -> dict[str, object]:
    """Require the current formal schema and its complete read lineage."""

    validated = verify_daily_snapshot_validation_evidence(payload)
    if (
        validated.get("schema_version")
        != _CURRENT_FORMAL_SCHEMA_VERSION
    ):
        raise DailySnapshotValidationError(
            "current formal daily validation requires schema version 5"
        )
    return validated


def _load_current_daily_replay_inputs(
    *,
    data_root: Path,
    project_root: Path,
    snapshot_ids: tuple[str, str, str],
) -> tuple[
    str,
    DailyContractSelectionBinding,
    tuple[
        DailySnapshotCaptureAuthority,
        DailySnapshotCaptureAuthority,
        DailySnapshotCaptureAuthority,
    ],
]:
    from dahe.adapters.chengfeng.daily_contract_selection import (
        load_selected_daily_read_contract,
    )
    from dahe.adapters.sqlite.daily_store import SqliteDailyStore
    from dahe.adapters.sqlite.runtime import SqliteRuntime

    selected = load_selected_daily_read_contract(data_root)
    binding = DailyContractSelectionBinding(
        contract_canonical_sha256=(
            selected.manifest.canonical_sha256
        ),
        contract_file_sha256=selected.contract_file_sha256,
        freeze_evidence_sha256=selected.freeze_evidence_sha256,
        selection_sha256=selected.selection_sha256,
        source_discovery_sha256=(
            selected.manifest.source_discovery_sha256
        ),
    )
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=f"loop9-daily-replay-{uuid4().hex}",
    )
    try:
        store = SqliteDailyStore(runtime)
        authorities = tuple(
            store.get_formal_snapshot_authority(snapshot_id)
            for snapshot_id in snapshot_ids
        )
    finally:
        runtime.close()
    if len(authorities) != 3:
        raise DailySnapshotValidationError(
            "formal SQLite daily snapshot authority count changed"
        )
    return (
        selected.manifest.canonical_sha256,
        binding,
        authorities,
    )


def replay_current_daily_snapshot_validation_from_store(
    payload: object,
    *,
    data_root: Path,
    project_root: Path,
    source_build_sha256: str,
) -> dict[str, object]:
    """Rebuild current formal evidence from durable SQLite authorities."""

    validated = verify_current_daily_snapshot_validation_evidence(
        payload
    )
    if (
        not data_root.is_absolute()
        or not project_root.is_absolute()
        or not data_root.is_dir()
        or not project_root.is_dir()
        or data_root.is_symlink()
        or project_root.is_symlink()
    ):
        raise DailySnapshotValidationError(
            "formal daily replay roots are invalid"
        )
    _required_sha256(
        source_build_sha256,
        field="source_build_sha256",
    )
    snapshots = validated.get("snapshot_evidence")
    assert isinstance(snapshots, list)
    snapshot_ids = tuple(
        _plain_text(
            cast(dict[str, object], snapshot).get("snapshot_id"),
            field="snapshot_id",
            maximum=100,
        )
        for snapshot in snapshots
    )
    if len(snapshot_ids) != 3:
        raise DailySnapshotValidationError(
            "formal daily snapshot identities are invalid"
        )
    try:
        (
            selected_contract_sha256,
            contract_selection,
            authorities,
        ) = _load_current_daily_replay_inputs(
            data_root=data_root,
            project_root=project_root,
            snapshot_ids=snapshot_ids,
        )
        rebuilt = validate_daily_snapshot_triplet(
            authorities,
            build_sha256=source_build_sha256,
            expected_contract_sha256=selected_contract_sha256,
            contract_selection=contract_selection,
        )
    except DailySnapshotValidationError:
        raise
    except Exception as exc:
        raise DailySnapshotValidationError(
            "formal SQLite daily snapshot replay failed"
        ) from exc
    if (
        rebuilt != validated
        or rebuilt.get("canonical_sha256")
        != validated.get("canonical_sha256")
    ):
        raise DailySnapshotValidationError(
            "daily validation evidence does not match formal SQLite authorities"
        )
    return validated


def _plain_text(
    value: object,
    *,
    field: str,
    maximum: int,
) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DailySnapshotValidationError(
            f"daily validation {field} is invalid"
        )
    return value


def _evidence_time(value: object, *, field: str) -> datetime:
    raw = _plain_text(value, field=field, maximum=40)
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise DailySnapshotValidationError(
            f"daily validation {field} is invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DailySnapshotValidationError(
            f"daily validation {field} is invalid"
        )
    return parsed
