from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast
from uuid import uuid4

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_OPERATIONS = (
    "list_waybills",
    "get_waybill_detail",
    "download_ticket_image",
    "list_daily_waybills",
)
_SAFE_OPERATION_SET = frozenset(_SAFE_OPERATIONS)
_UNSAFE_OPERATION = "unsafe_operation"
_PHASES = frozenset(
    {
        "attempted",
        "allowed",
        "succeeded",
        "denied",
        "failed",
        "redirect",
    }
)
_TERMINAL_PHASES = frozenset({"succeeded", "denied", "failed", "redirect"})
_PURPOSES = frozenset(
    {
        "current_locked_50",
        "real_shadow_30",
        "daily_snapshot",
        "daily_validation",
        "operational_daily",
        "operational_settlement",
    }
)
_EVENT_KIND = "loop9_platform_read_audit_event"
_EVIDENCE_KIND = "loop9_platform_read_audit"
_SEAL_KIND = "loop9_platform_read_audit_seal"
_ZERO_SHA256 = "0" * 64
_MAX_EVENT_BYTES = 16 * 1024
_MAX_EVIDENCE_BYTES = 128 * 1024
_MAX_SEAL_BYTES = 8 * 1024

_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


class PlatformReadAuditError(RuntimeError):
    """Raised when a formal platform-read audit cannot be trusted."""


@dataclass(frozen=True, slots=True)
class PlatformReadRequestCounts:
    attempted: int
    allowed: int
    succeeded: int
    denied: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (
                self.attempted,
                self.allowed,
                self.succeeded,
                self.denied,
            )
        ):
            raise PlatformReadAuditError("request audit counts are invalid")

    def to_payload(self) -> dict[str, int]:
        return {
            "allowed": self.allowed,
            "attempted": self.attempted,
            "denied": self.denied,
            "succeeded": self.succeeded,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> PlatformReadRequestCounts:
        if not isinstance(value, dict) or set(value) != {
            "allowed",
            "attempted",
            "denied",
            "succeeded",
        }:
            raise PlatformReadAuditError(
                "request audit count shape is invalid"
            )
        return cls(
            attempted=cast(int, value.get("attempted")),
            allowed=cast(int, value.get("allowed")),
            succeeded=cast(int, value.get("succeeded")),
            denied=cast(int, value.get("denied")),
        )


@dataclass(frozen=True, slots=True)
class PlatformReadOperationCounts:
    attempted: int
    allowed: int
    succeeded: int
    denied: int
    failed: int
    redirect: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (
                self.attempted,
                self.allowed,
                self.succeeded,
                self.denied,
                self.failed,
                self.redirect,
            )
        ):
            raise PlatformReadAuditError(
                "operation audit counts are invalid"
            )

    def to_payload(self) -> dict[str, int]:
        return {
            "allowed": self.allowed,
            "attempted": self.attempted,
            "denied": self.denied,
            "failed": self.failed,
            "redirect": self.redirect,
            "succeeded": self.succeeded,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> PlatformReadOperationCounts:
        if not isinstance(value, dict) or set(value) != {
            "allowed",
            "attempted",
            "denied",
            "failed",
            "redirect",
            "succeeded",
        }:
            raise PlatformReadAuditError(
                "operation audit count shape is invalid"
            )
        return cls(
            attempted=cast(int, value.get("attempted")),
            allowed=cast(int, value.get("allowed")),
            succeeded=cast(int, value.get("succeeded")),
            denied=cast(int, value.get("denied")),
            failed=cast(int, value.get("failed")),
            redirect=cast(int, value.get("redirect")),
        )


@dataclass(frozen=True, slots=True)
class PlatformReadAuditAuthority:
    build_sha256: str
    settlement_contract_sha256: str
    settlement_contract_selection_sha256: str
    daily_contract_sha256: str | None = None
    daily_contract_selection_sha256: str | None = None

    def __post_init__(self) -> None:
        _required_sha256(self.build_sha256, label="build identity")
        _required_sha256(
            self.settlement_contract_sha256,
            label="settlement contract identity",
        )
        _required_sha256(
            self.settlement_contract_selection_sha256,
            label="settlement contract selection identity",
        )
        if (self.daily_contract_sha256 is None) != (
            self.daily_contract_selection_sha256 is None
        ):
            raise PlatformReadAuditError(
                "daily contract authority is incomplete"
            )
        if self.daily_contract_sha256 is not None:
            _required_sha256(
                self.daily_contract_sha256,
                label="daily contract identity",
            )
            _required_sha256(
                self.daily_contract_selection_sha256,
                label="daily contract selection identity",
            )

    def to_payload(self) -> dict[str, object]:
        return {
            "build_sha256": self.build_sha256,
            "daily_contract_selection_sha256": (
                self.daily_contract_selection_sha256
            ),
            "daily_contract_sha256": self.daily_contract_sha256,
            "settlement_contract_selection_sha256": (
                self.settlement_contract_selection_sha256
            ),
            "settlement_contract_sha256": (
                self.settlement_contract_sha256
            ),
        }

    def binding_for(self, operation: str) -> tuple[str, str]:
        if operation == "list_daily_waybills":
            if (
                self.daily_contract_sha256 is None
                or self.daily_contract_selection_sha256 is None
            ):
                raise PlatformReadAuditError(
                    "daily operation has no daily contract authority"
                )
            return (
                self.daily_contract_sha256,
                self.daily_contract_selection_sha256,
            )
        return (
            self.settlement_contract_sha256,
            self.settlement_contract_selection_sha256,
        )

    @classmethod
    def from_payload(cls, value: object) -> PlatformReadAuditAuthority:
        if not isinstance(value, dict) or set(value) != {
            "build_sha256",
            "daily_contract_selection_sha256",
            "daily_contract_sha256",
            "settlement_contract_selection_sha256",
            "settlement_contract_sha256",
        }:
            raise PlatformReadAuditError(
                "platform read audit authority shape is invalid"
            )
        return cls(
            build_sha256=cast(str, value.get("build_sha256")),
            settlement_contract_sha256=cast(
                str,
                value.get("settlement_contract_sha256"),
            ),
            settlement_contract_selection_sha256=cast(
                str,
                value.get("settlement_contract_selection_sha256"),
            ),
            daily_contract_sha256=cast(
                str | None,
                value.get("daily_contract_sha256"),
            ),
            daily_contract_selection_sha256=cast(
                str | None,
                value.get("daily_contract_selection_sha256"),
            ),
        )


@dataclass(frozen=True, slots=True)
class PlatformReadAuditEvidence:
    job_id_sha256: str
    authority: PlatformReadAuditAuthority
    purpose: str
    request_counts: PlatformReadRequestCounts
    operation_counts: Mapping[str, PlatformReadOperationCounts]
    expected_succeeded_operations: Mapping[str, int]
    platform_write_request_count: int
    redirect_count: int
    event_count: int
    event_chain_sha256: str
    canonical_sha256: str
    schema_version: int = 1
    kind: str = _EVIDENCE_KIND

    def __post_init__(self) -> None:
        for label, value in (
            ("job identity", self.job_id_sha256),
            ("event chain identity", self.event_chain_sha256),
            ("audit evidence identity", self.canonical_sha256),
        ):
            _required_sha256(value, label=label)
        if (
            self.schema_version != 1
            or self.kind != _EVIDENCE_KIND
            or self.purpose not in _PURPOSES
            or type(self.platform_write_request_count) is not int
            or self.platform_write_request_count < 0
            or type(self.redirect_count) is not int
            or self.redirect_count < 0
            or type(self.event_count) is not int
            or self.event_count < 1
            or not isinstance(
                self.request_counts,
                PlatformReadRequestCounts,
            )
            or not isinstance(self.authority, PlatformReadAuditAuthority)
            or set(self.operation_counts) != _SAFE_OPERATION_SET
        ):
            raise PlatformReadAuditError(
                "platform read audit evidence is invalid"
            )
        for operation, counts in self.operation_counts.items():
            if (
                operation not in _SAFE_OPERATION_SET
                or not isinstance(counts, PlatformReadOperationCounts)
            ):
                raise PlatformReadAuditError(
                    "platform read operation evidence is invalid"
                )
        expected = _validated_expected_counts(
            self.expected_succeeded_operations
        )
        object.__setattr__(
            self,
            "operation_counts",
            dict(self.operation_counts),
        )
        object.__setattr__(
            self,
            "expected_succeeded_operations",
            expected,
        )

    def _body(self) -> dict[str, object]:
        return {
            "authority": self.authority.to_payload(),
            "event_chain_sha256": self.event_chain_sha256,
            "event_count": self.event_count,
            "expected_succeeded_operations": dict(
                sorted(self.expected_succeeded_operations.items())
            ),
            "job_id_sha256": self.job_id_sha256,
            "kind": self.kind,
            "operation_counts": {
                operation: self.operation_counts[operation].to_payload()
                for operation in _SAFE_OPERATIONS
            },
            "platform_write_request_count": (
                self.platform_write_request_count
            ),
            "purpose": self.purpose,
            "redirect_count": self.redirect_count,
            "request_counts": self.request_counts.to_payload(),
            "schema_version": self.schema_version,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._body(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._body()) != self.canonical_sha256:
            raise PlatformReadAuditError(
                "platform read audit evidence integrity failed"
            )

    @classmethod
    def from_payload(cls, value: object) -> PlatformReadAuditEvidence:
        if not isinstance(value, dict) or set(value) != {
            "authority",
            "canonical_sha256",
            "event_chain_sha256",
            "event_count",
            "expected_succeeded_operations",
            "job_id_sha256",
            "kind",
            "operation_counts",
            "platform_write_request_count",
            "purpose",
            "redirect_count",
            "request_counts",
            "schema_version",
        }:
            raise PlatformReadAuditError(
                "platform read audit evidence shape is invalid"
            )
        raw_operations = value.get("operation_counts")
        if not isinstance(raw_operations, dict):
            raise PlatformReadAuditError(
                "platform read operation evidence is invalid"
            )
        evidence = cls(
            job_id_sha256=cast(str, value.get("job_id_sha256")),
            authority=PlatformReadAuditAuthority.from_payload(
                value.get("authority")
            ),
            purpose=cast(str, value.get("purpose")),
            request_counts=PlatformReadRequestCounts.from_payload(
                value.get("request_counts")
            ),
            operation_counts={
                str(operation): PlatformReadOperationCounts.from_payload(
                    counts
                )
                for operation, counts in raw_operations.items()
            },
            expected_succeeded_operations=cast(
                Mapping[str, int],
                value.get("expected_succeeded_operations"),
            ),
            platform_write_request_count=cast(
                int,
                value.get("platform_write_request_count"),
            ),
            redirect_count=cast(int, value.get("redirect_count")),
            event_count=cast(int, value.get("event_count")),
            event_chain_sha256=cast(
                str,
                value.get("event_chain_sha256"),
            ),
            canonical_sha256=cast(str, value.get("canonical_sha256")),
            schema_version=cast(int, value.get("schema_version")),
            kind=cast(str, value.get("kind")),
        )
        evidence.verify_integrity()
        return evidence


@dataclass(frozen=True, slots=True)
class PlatformReadAuditToken:
    job_id: str
    job_id_sha256: str
    build_sha256: str
    contract_sha256: str
    contract_selection_sha256: str
    operation: str
    request_token_sha256: str


@dataclass(frozen=True, slots=True)
class _AuditEvent:
    sequence: int
    prior_event_sha256: str
    job_id_sha256: str
    build_sha256: str
    contract_sha256: str
    contract_selection_sha256: str
    operation: str
    request_token_sha256: str
    phase: str
    created_at: str
    event_sha256: str

    def _body(self) -> dict[str, object]:
        return {
            "build_sha256": self.build_sha256,
            "contract_selection_sha256": self.contract_selection_sha256,
            "contract_sha256": self.contract_sha256,
            "created_at": self.created_at,
            "job_id_sha256": self.job_id_sha256,
            "kind": _EVENT_KIND,
            "operation": self.operation,
            "phase": self.phase,
            "prior_event_sha256": self.prior_event_sha256,
            "request_token_sha256": self.request_token_sha256,
            "schema_version": 1,
            "sequence": self.sequence,
        }

    def to_payload(self) -> dict[str, object]:
        return {**self._body(), "event_sha256": self.event_sha256}

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        prior_event_sha256: str,
        job_id_sha256: str,
        build_sha256: str,
        contract_sha256: str,
        contract_selection_sha256: str,
        operation: str,
        request_token_sha256: str,
        phase: str,
        created_at: datetime,
    ) -> _AuditEvent:
        body: dict[str, object] = {
            "build_sha256": build_sha256,
            "contract_selection_sha256": contract_selection_sha256,
            "contract_sha256": contract_sha256,
            "created_at": _timestamp(created_at),
            "job_id_sha256": job_id_sha256,
            "kind": _EVENT_KIND,
            "operation": operation,
            "phase": phase,
            "prior_event_sha256": prior_event_sha256,
            "request_token_sha256": request_token_sha256,
            "schema_version": 1,
            "sequence": sequence,
        }
        return cls(
            sequence=sequence,
            prior_event_sha256=prior_event_sha256,
            job_id_sha256=job_id_sha256,
            build_sha256=build_sha256,
            contract_sha256=contract_sha256,
            contract_selection_sha256=contract_selection_sha256,
            operation=operation,
            request_token_sha256=request_token_sha256,
            phase=phase,
            created_at=cast(str, body["created_at"]),
            event_sha256=_canonical_sha256(body),
        )

    @classmethod
    def from_payload(cls, value: object) -> _AuditEvent:
        if not isinstance(value, dict) or set(value) != {
            "build_sha256",
            "contract_selection_sha256",
            "contract_sha256",
            "created_at",
            "event_sha256",
            "job_id_sha256",
            "kind",
            "operation",
            "phase",
            "prior_event_sha256",
            "request_token_sha256",
            "schema_version",
            "sequence",
        }:
            raise PlatformReadAuditError(
                "platform read audit event shape is invalid"
            )
        if (
            value.get("schema_version") != 1
            or value.get("kind") != _EVENT_KIND
            or value.get("operation")
            not in {*_SAFE_OPERATION_SET, _UNSAFE_OPERATION}
            or value.get("phase") not in _PHASES
            or type(value.get("sequence")) is not int
            or cast(int, value.get("sequence")) < 1
        ):
            raise PlatformReadAuditError(
                "platform read audit event is invalid"
            )
        event = cls(
            sequence=cast(int, value.get("sequence")),
            prior_event_sha256=_required_sha256(
                value.get("prior_event_sha256"),
                label="prior event identity",
            ),
            job_id_sha256=_required_sha256(
                value.get("job_id_sha256"),
                label="job identity",
            ),
            build_sha256=_required_sha256(
                value.get("build_sha256"),
                label="build identity",
            ),
            contract_sha256=_required_sha256(
                value.get("contract_sha256"),
                label="contract identity",
            ),
            contract_selection_sha256=_required_sha256(
                value.get("contract_selection_sha256"),
                label="contract selection identity",
            ),
            operation=cast(str, value.get("operation")),
            request_token_sha256=_required_sha256(
                value.get("request_token_sha256"),
                label="request token identity",
            ),
            phase=cast(str, value.get("phase")),
            created_at=_timestamp_from_payload(value.get("created_at")),
            event_sha256=_required_sha256(
                value.get("event_sha256"),
                label="event identity",
            ),
        )
        if _canonical_sha256(event._body()) != event.event_sha256:
            raise PlatformReadAuditError(
                "platform read audit event integrity failed"
            )
        return event


class PlatformReadAuditEvidenceStore:
    """Append request lifecycle events and seal replayable per-job evidence."""

    def __init__(
        self,
        data_root: Path,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.data_root = data_root.resolve()
        self.root = self.data_root / "platform-request-audit"
        self.events_root = self.root / "events"
        self.evidence_root = self.root / "evidence" / "sha256"
        self.seals_root = self.root / "seals"
        self.locks_root = self.root / "locks"
        self.staging_root = self.root / ".staging"
        for directory in (
            self.events_root,
            self.evidence_root,
            self.seals_root,
            self.locks_root,
            self.staging_root,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            if directory.is_symlink():
                raise PlatformReadAuditError(
                    "platform read audit directory is unsafe"
                )
        self._clock = clock
        self._verified_event_cache: dict[str, tuple[_AuditEvent, ...]] = {}
        self._verified_event_cache_shape: dict[str, tuple[int, str | None]] = {}

    @staticmethod
    def job_id_sha256(job_id: str) -> str:
        return hashlib.sha256(
            _required_job_id(job_id).encode("utf-8")
        ).hexdigest()

    def attempt(
        self,
        *,
        job_id: str,
        build_sha256: str,
        contract_sha256: str,
        contract_selection_sha256: str,
        operation: str,
        request_material: object | None = None,
    ) -> PlatformReadAuditToken:
        del request_material
        normalized_operation = (
            operation if operation in _SAFE_OPERATION_SET else _UNSAFE_OPERATION
        )
        token = PlatformReadAuditToken(
            job_id=_required_job_id(job_id),
            job_id_sha256=self.job_id_sha256(job_id),
            build_sha256=_required_sha256(
                build_sha256,
                label="build identity",
            ),
            contract_sha256=_required_sha256(
                contract_sha256,
                label="contract identity",
            ),
            contract_selection_sha256=_required_sha256(
                contract_selection_sha256,
                label="contract selection identity",
            ),
            operation=normalized_operation,
            request_token_sha256=hashlib.sha256(
                uuid4().bytes
            ).hexdigest(),
        )
        with self._job_guard(token.job_id):
            self._assert_not_sealed(token.job_id)
            self._append_unlocked(token, phase="attempted")
        return token

    def allowed(self, token: PlatformReadAuditToken) -> None:
        if token.operation not in _SAFE_OPERATION_SET:
            raise PlatformReadAuditError(
                "unsafe platform operation cannot be allowed"
            )
        self._transition(token, phase="allowed")

    def succeeded(self, token: PlatformReadAuditToken) -> None:
        self._transition(token, phase="succeeded")

    def denied(self, token: PlatformReadAuditToken) -> None:
        self._transition(token, phase="denied")

    def failed(self, token: PlatformReadAuditToken) -> None:
        self._transition(token, phase="failed")

    def redirected(self, token: PlatformReadAuditToken) -> None:
        self._transition(token, phase="redirect")

    def recover_incomplete(
        self,
        *,
        job_id: str,
        build_sha256: str,
    ) -> int:
        with self._job_guard(job_id):
            self._assert_not_sealed(job_id)
            events = self._load_events(
                job_id=job_id,
                expected_build_sha256=build_sha256,
            )
            states = _request_states(events)
            recovered = 0
            for request_token, state in states.items():
                if state["phase"] in _TERMINAL_PHASES:
                    continue
                self._append_unlocked(
                    PlatformReadAuditToken(
                        job_id=job_id,
                        job_id_sha256=self.job_id_sha256(job_id),
                        build_sha256=build_sha256,
                        contract_sha256=cast(
                            str,
                            state["contract_sha256"],
                        ),
                        contract_selection_sha256=cast(
                            str,
                            state["contract_selection_sha256"],
                        ),
                        operation=cast(str, state["operation"]),
                        request_token_sha256=request_token,
                    ),
                    phase="failed",
                )
                recovered += 1
            return recovered

    def seal(
        self,
        *,
        job_id: str,
        authority: PlatformReadAuditAuthority,
        purpose: str,
        expected_succeeded_operations: Mapping[str, int],
    ) -> PlatformReadAuditEvidence:
        if purpose not in _PURPOSES:
            raise PlatformReadAuditError(
                "platform read audit purpose is invalid"
            )
        expected = _validated_expected_counts(
            expected_succeeded_operations
        )
        with self._job_guard(job_id):
            existing_seal = self._read_seal_marker(job_id)
            if existing_seal is not None:
                if (
                    existing_seal["authority"] != authority.to_payload()
                    or existing_seal["purpose"] != purpose
                ):
                    raise PlatformReadAuditError(
                        "platform read audit seal authority changed"
                    )
                evidence = self._load_evidence_unlocked(
                    cast(str, existing_seal["evidence_sha256"]),
                    expected_job_id=job_id,
                    expected_authority=authority,
                )
                if dict(evidence.expected_succeeded_operations) != expected:
                    raise PlatformReadAuditError(
                        "platform read audit seal counts changed"
                    )
                return evidence
            events = self._load_events(
                job_id=job_id,
                expected_build_sha256=authority.build_sha256,
            )
            if not events:
                raise PlatformReadAuditError(
                    "platform read audit has no events"
                )
            _validate_event_contract_bindings(
                events,
                authority=authority,
                purpose=purpose,
            )
            operation_counts, request_counts, writes, redirects = (
                _summarize_events(events)
            )
            states = _request_states(events)
            if any(
                state["phase"] not in _TERMINAL_PHASES
                for state in states.values()
            ):
                raise PlatformReadAuditError(
                    "platform read audit has incomplete requests"
                )
            if request_counts.denied or writes or redirects:
                raise PlatformReadAuditError(
                    "platform read audit is not clean"
                )
            actual_succeeded = {
                operation: operation_counts[operation].succeeded
                for operation in _SAFE_OPERATIONS
                if operation_counts[operation].succeeded
            }
            if actual_succeeded != expected:
                raise PlatformReadAuditError(
                    "platform read audit operation counts do not match"
                )
            body: dict[str, object] = {
                "authority": authority.to_payload(),
                "event_chain_sha256": events[-1].event_sha256,
                "event_count": len(events),
                "expected_succeeded_operations": dict(
                    sorted(expected.items())
                ),
                "job_id_sha256": self.job_id_sha256(job_id),
                "kind": _EVIDENCE_KIND,
                "operation_counts": {
                    operation: operation_counts[operation].to_payload()
                    for operation in _SAFE_OPERATIONS
                },
                "platform_write_request_count": writes,
                "purpose": purpose,
                "redirect_count": redirects,
                "request_counts": request_counts.to_payload(),
                "schema_version": 1,
            }
            evidence = PlatformReadAuditEvidence(
                job_id_sha256=cast(str, body["job_id_sha256"]),
                authority=authority,
                purpose=purpose,
                request_counts=request_counts,
                operation_counts=operation_counts,
                expected_succeeded_operations=expected,
                platform_write_request_count=writes,
                redirect_count=redirects,
                event_count=len(events),
                event_chain_sha256=events[-1].event_sha256,
                canonical_sha256=_canonical_sha256(body),
            )
            self._write_evidence(evidence)
            self._write_seal_marker(evidence, job_id=job_id)
            return evidence

    def path_for(self, canonical_sha256: str) -> Path:
        digest = _required_sha256(
            canonical_sha256,
            label="audit evidence identity",
        )
        target = (
            self.evidence_root
            / digest[:2]
            / digest[2:4]
            / f"{digest}.json"
        ).resolve()
        if not target.is_relative_to(self.evidence_root):
            raise PlatformReadAuditError(
                "platform read audit evidence path escaped"
            )
        return target

    def load(
        self,
        canonical_sha256: str,
        *,
        expected_job_id: str,
        expected_authority: PlatformReadAuditAuthority,
    ) -> PlatformReadAuditEvidence:
        with self._job_guard(expected_job_id):
            marker = self._read_seal_marker(expected_job_id)
            if (
                marker is None
                or marker["evidence_sha256"] != canonical_sha256
                or marker["authority"] != expected_authority.to_payload()
            ):
                raise PlatformReadAuditError(
                    "platform read audit seal changed"
                )
            return self._load_evidence_unlocked(
                canonical_sha256,
                expected_job_id=expected_job_id,
                expected_authority=expected_authority,
            )

    def load_sealed_for_job(
        self,
        *,
        job_id: str,
    ) -> PlatformReadAuditEvidence:
        """Deep-load the immutable seal; callers must still check authority."""

        with self._job_guard(job_id):
            marker = self._read_seal_marker(job_id)
            if marker is None:
                raise PlatformReadAuditError(
                    "platform read audit is not sealed"
                )
            authority = PlatformReadAuditAuthority.from_payload(
                marker["authority"]
            )
            return self._load_evidence_unlocked(
                cast(str, marker["evidence_sha256"]),
                expected_job_id=job_id,
                expected_authority=authority,
            )

    def _load_evidence_unlocked(
        self,
        canonical_sha256: str,
        *,
        expected_job_id: str,
        expected_authority: PlatformReadAuditAuthority,
    ) -> PlatformReadAuditEvidence:
        target = self.path_for(canonical_sha256)
        payload = _read_json(
            target,
            maximum_bytes=_MAX_EVIDENCE_BYTES,
            label="platform read audit evidence",
        )
        evidence = PlatformReadAuditEvidence.from_payload(payload)
        if (
            evidence.canonical_sha256 != canonical_sha256
            or evidence.job_id_sha256
            != self.job_id_sha256(expected_job_id)
            or evidence.authority != expected_authority
        ):
            raise PlatformReadAuditError(
                "platform read audit authority changed"
            )
        expected_content = _canonical_content(evidence.to_payload())
        if target.read_bytes() != expected_content:
            raise PlatformReadAuditError(
                "platform read audit evidence is not canonical"
            )
        events = self._load_events(
            job_id=expected_job_id,
            expected_build_sha256=expected_authority.build_sha256,
        )
        _validate_event_contract_bindings(
            events,
            authority=expected_authority,
            purpose=evidence.purpose,
        )
        if (
            len(events) != evidence.event_count
            or not events
            or events[-1].event_sha256
            != evidence.event_chain_sha256
        ):
            raise PlatformReadAuditError(
                "platform read audit event chain changed"
            )
        operation_counts, request_counts, writes, redirects = (
            _summarize_events(events)
        )
        if (
            request_counts != evidence.request_counts
            or operation_counts != evidence.operation_counts
            or writes != evidence.platform_write_request_count
            or redirects != evidence.redirect_count
            or {
                operation: operation_counts[operation].succeeded
                for operation in _SAFE_OPERATIONS
                if operation_counts[operation].succeeded
            }
            != dict(evidence.expected_succeeded_operations)
        ):
            raise PlatformReadAuditError(
                "platform read audit replay changed"
            )
        return evidence

    def _transition(
        self,
        token: PlatformReadAuditToken,
        *,
        phase: str,
    ) -> None:
        with self._job_guard(token.job_id):
            self._assert_not_sealed(token.job_id)
            events = self._load_events(
                job_id=token.job_id,
                expected_build_sha256=token.build_sha256,
                allow_cached=True,
            )
            states = _request_states(events)
            state = states.get(token.request_token_sha256)
            if state is None:
                raise PlatformReadAuditError(
                    "platform read audit token is unknown"
                )
            prior_phase = state["phase"]
            valid = (
                (phase == "allowed" and prior_phase == "attempted")
                or (
                    phase == "denied"
                    and prior_phase == "attempted"
                )
                or (
                    phase in {"succeeded", "failed", "redirect"}
                    and prior_phase == "allowed"
                )
                or (
                    phase == "failed"
                    and prior_phase == "attempted"
                )
            )
            if (
                not valid
                or state["operation"] != token.operation
                or state["contract_sha256"] != token.contract_sha256
                or state["contract_selection_sha256"]
                != token.contract_selection_sha256
                or token.job_id_sha256 != self.job_id_sha256(token.job_id)
            ):
                raise PlatformReadAuditError(
                    "platform read audit transition is invalid"
                )
            self._append_unlocked(token, phase=phase)

    def _append_unlocked(
        self,
        token: PlatformReadAuditToken,
        *,
        phase: str,
    ) -> None:
        if phase not in _PHASES:
            raise PlatformReadAuditError(
                "platform read audit phase is invalid"
            )
        events = self._load_events(
            job_id=token.job_id,
            expected_build_sha256=token.build_sha256,
            allow_cached=True,
        )
        binding_is_daily = token.operation == "list_daily_waybills"
        for existing in events:
            if (
                (existing.operation == "list_daily_waybills")
                == binding_is_daily
                and (
                    existing.contract_sha256 != token.contract_sha256
                    or existing.contract_selection_sha256
                    != token.contract_selection_sha256
                )
            ):
                raise PlatformReadAuditError(
                    "platform read audit event chain authority changed"
                )
        sequence = len(events) + 1
        prior = (
            _ZERO_SHA256 if not events else events[-1].event_sha256
        )
        event = _AuditEvent.create(
            sequence=sequence,
            prior_event_sha256=prior,
            job_id_sha256=token.job_id_sha256,
            build_sha256=token.build_sha256,
            contract_sha256=token.contract_sha256,
            contract_selection_sha256=(
                token.contract_selection_sha256
            ),
            operation=token.operation,
            request_token_sha256=token.request_token_sha256,
            phase=phase,
            created_at=self._clock(),
        )
        job_root = self._event_job_root(token.job_id)
        job_root.mkdir(parents=True, exist_ok=True)
        if job_root.is_symlink():
            raise PlatformReadAuditError(
                "platform read audit event directory is unsafe"
            )
        target = job_root / (
            f"{sequence:08d}-{event.event_sha256}.json"
        )
        self._atomic_write(
            target,
            _canonical_content(event.to_payload()),
        )
        self._verified_event_cache[token.job_id] = (*events, event)
        self._verified_event_cache_shape[token.job_id] = (
            sequence,
            target.name,
        )

    @contextmanager
    def _job_guard(self, job_id: str) -> Iterator[None]:
        job_digest = self.job_id_sha256(job_id)
        lock_path = (self.locks_root / f"{job_digest}.lock").resolve()
        if not lock_path.is_relative_to(self.locks_root):
            raise PlatformReadAuditError(
                "platform read audit lock path escaped"
            )
        key = str(lock_path).casefold()
        with _PROCESS_LOCKS_GUARD:
            process_lock = _PROCESS_LOCKS.setdefault(
                key,
                threading.RLock(),
            )
        with process_lock:
            try:
                with lock_path.open("a+b") as handle:
                    handle.seek(0, os.SEEK_END)
                    if handle.tell() == 0:
                        handle.write(b"\0")
                        handle.flush()
                        os.fsync(handle.fileno())
                    handle.seek(0)
                    _lock_file(handle)
                    try:
                        yield
                    finally:
                        handle.seek(0)
                        _unlock_file(handle)
            except OSError as exc:
                raise PlatformReadAuditError(
                    "platform read audit lock failed"
                ) from exc

    def _seal_path(self, job_id: str) -> Path:
        target = (
            self.seals_root / f"{self.job_id_sha256(job_id)}.json"
        ).resolve()
        if not target.is_relative_to(self.seals_root):
            raise PlatformReadAuditError(
                "platform read audit seal path escaped"
            )
        return target

    def _read_seal_marker(
        self,
        job_id: str,
    ) -> dict[str, object] | None:
        target = self._seal_path(job_id)
        if not target.exists():
            return None
        payload = _read_json(
            target,
            maximum_bytes=_MAX_SEAL_BYTES,
            label="platform read audit seal",
        )
        if not isinstance(payload, dict) or set(payload) != {
            "authority",
            "canonical_sha256",
            "evidence_sha256",
            "job_id_sha256",
            "kind",
            "purpose",
            "schema_version",
        }:
            raise PlatformReadAuditError(
                "platform read audit seal shape is invalid"
            )
        body = {
            "authority": PlatformReadAuditAuthority.from_payload(
                payload.get("authority")
            ).to_payload(),
            "evidence_sha256": _required_sha256(
                payload.get("evidence_sha256"),
                label="audit evidence identity",
            ),
            "job_id_sha256": _required_sha256(
                payload.get("job_id_sha256"),
                label="job identity",
            ),
            "kind": payload.get("kind"),
            "purpose": payload.get("purpose"),
            "schema_version": payload.get("schema_version"),
        }
        canonical_sha256 = _required_sha256(
            payload.get("canonical_sha256"),
            label="audit seal identity",
        )
        if (
            body["schema_version"] != 1
            or body["kind"] != _SEAL_KIND
            or body["purpose"] not in _PURPOSES
            or body["job_id_sha256"] != self.job_id_sha256(job_id)
            or _canonical_sha256(body) != canonical_sha256
            or target.is_symlink()
            or target.read_bytes() != _canonical_content(payload)
        ):
            raise PlatformReadAuditError(
                "platform read audit seal integrity failed"
            )
        return payload

    def _assert_not_sealed(self, job_id: str) -> None:
        if self._read_seal_marker(job_id) is not None:
            raise PlatformReadAuditError(
                "platform read audit is sealed"
            )

    def _write_seal_marker(
        self,
        evidence: PlatformReadAuditEvidence,
        *,
        job_id: str,
    ) -> None:
        body: dict[str, object] = {
            "authority": evidence.authority.to_payload(),
            "evidence_sha256": evidence.canonical_sha256,
            "job_id_sha256": evidence.job_id_sha256,
            "kind": _SEAL_KIND,
            "purpose": evidence.purpose,
            "schema_version": 1,
        }
        payload = {
            **body,
            "canonical_sha256": _canonical_sha256(body),
        }
        target = self._seal_path(job_id)
        content = _canonical_content(payload)
        if target.exists():
            if target.is_symlink() or target.read_bytes() != content:
                raise PlatformReadAuditError(
                    "existing platform read audit seal differs"
                )
            return
        self._atomic_write(target, content)

    def _event_job_root(self, job_id: str) -> Path:
        candidate = (
            self.events_root / self.job_id_sha256(job_id)
        ).resolve()
        if not candidate.is_relative_to(self.events_root):
            raise PlatformReadAuditError(
                "platform read audit event path escaped"
            )
        return candidate

    def _load_events(
        self,
        *,
        job_id: str,
        expected_build_sha256: str,
        allow_cached: bool = False,
    ) -> tuple[_AuditEvent, ...]:
        build = _required_sha256(
            expected_build_sha256,
            label="build identity",
        )
        cached = self._verified_event_cache.get(job_id)
        if allow_cached and cached is not None:
            if cached and any(event.build_sha256 != build for event in cached):
                raise PlatformReadAuditError(
                    "platform read audit event chain build changed"
                )
            root = self._event_job_root(job_id)
            names = tuple(
                sorted(
                    path.name
                    for path in root.iterdir()
                    if path.suffix == ".json"
                )
            )
            if self._verified_event_cache_shape.get(job_id) == (
                len(names),
                None if not names else names[-1],
            ):
                return cached
        root = self._event_job_root(job_id)
        if not root.exists():
            return ()
        if not root.is_dir() or root.is_symlink():
            raise PlatformReadAuditError(
                "platform read audit event directory is unsafe"
            )
        events: list[_AuditEvent] = []
        previous = _ZERO_SHA256
        for path in sorted(root.iterdir(), key=lambda value: value.name):
            if not path.is_file() or path.is_symlink():
                raise PlatformReadAuditError(
                    "platform read audit event entry is unsafe"
                )
            event = _AuditEvent.from_payload(
                _read_json(
                    path,
                    maximum_bytes=_MAX_EVENT_BYTES,
                    label="platform read audit event",
                )
            )
            expected_name = (
                f"{event.sequence:08d}-{event.event_sha256}.json"
            )
            if (
                path.name != expected_name
                or event.sequence != len(events) + 1
                or event.prior_event_sha256 != previous
                or event.job_id_sha256 != self.job_id_sha256(job_id)
                or event.build_sha256 != build
                or path.read_bytes()
                != _canonical_content(event.to_payload())
            ):
                raise PlatformReadAuditError(
                    "platform read audit event chain is invalid"
                )
            events.append(event)
            previous = event.event_sha256
        _request_states(tuple(events))
        result = tuple(events)
        self._verified_event_cache[job_id] = result
        self._verified_event_cache_shape[job_id] = (
            len(events),
            None
            if not events
            else f"{events[-1].sequence:08d}-{events[-1].event_sha256}.json",
        )
        return result

    def _write_evidence(
        self,
        evidence: PlatformReadAuditEvidence,
    ) -> None:
        target = self.path_for(evidence.canonical_sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.parent.is_symlink():
            raise PlatformReadAuditError(
                "platform read audit evidence directory is unsafe"
            )
        content = _canonical_content(evidence.to_payload())
        if target.exists():
            if (
                target.is_symlink()
                or target.read_bytes() != content
            ):
                raise PlatformReadAuditError(
                    "existing platform read audit evidence differs"
                )
            return
        self._atomic_write(target, content)

    def _atomic_write(self, target: Path, content: bytes) -> None:
        staged = self.staging_root / f"{uuid4().hex}.part"
        try:
            with staged.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staged, target)
        except OSError as exc:
            raise PlatformReadAuditError(
                "platform read audit could not be committed"
            ) from exc
        finally:
            staged.unlink(missing_ok=True)


def _required_job_id(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 200
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PlatformReadAuditError(
            "platform read audit job identity is invalid"
        )
    return value


def _required_sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PlatformReadAuditError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _validated_expected_counts(
    value: Mapping[str, int],
) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise PlatformReadAuditError(
            "expected platform read counts are invalid"
        )
    result: dict[str, int] = {}
    for operation, count in value.items():
        if (
            operation not in _SAFE_OPERATION_SET
            or type(count) is not int
            or count < 0
        ):
            raise PlatformReadAuditError(
                "expected platform read counts are invalid"
            )
        if count:
            result[operation] = count
    return result


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PlatformReadAuditError(
            "platform read audit time must be timezone-aware"
        )
    return value.astimezone(UTC).isoformat()


def _timestamp_from_payload(value: object) -> str:
    if type(value) is not str:
        raise PlatformReadAuditError(
            "platform read audit time is invalid"
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PlatformReadAuditError(
            "platform read audit time is invalid"
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.astimezone(UTC).isoformat() != value
    ):
        raise PlatformReadAuditError(
            "platform read audit time is invalid"
        )
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_content(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _read_json(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
) -> object:
    if not path.is_file() or path.is_symlink():
        raise PlatformReadAuditError(f"{label} is unavailable")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise PlatformReadAuditError(f"{label} is unreadable") from exc
    if not content or len(content) > maximum_bytes:
        raise PlatformReadAuditError(f"{label} size is invalid")
    try:
        return json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlatformReadAuditError(f"{label} is invalid") from exc


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PlatformReadAuditError(
                "platform read audit contains duplicate fields"
            )
        result[key] = value
    return result


def _request_states(
    events: tuple[_AuditEvent, ...],
) -> dict[str, dict[str, object]]:
    states: dict[str, dict[str, object]] = {}
    for event in events:
        state = states.get(event.request_token_sha256)
        if event.phase == "attempted":
            if state is not None:
                raise PlatformReadAuditError(
                    "platform read audit request token was reused"
                )
            states[event.request_token_sha256] = {
                "contract_selection_sha256": (
                    event.contract_selection_sha256
                ),
                "contract_sha256": event.contract_sha256,
                "operation": event.operation,
                "phase": event.phase,
            }
            continue
        if (
            state is None
            or state["operation"] != event.operation
            or state["contract_sha256"] != event.contract_sha256
            or state["contract_selection_sha256"]
            != event.contract_selection_sha256
        ):
            raise PlatformReadAuditError(
                "platform read audit request lifecycle is invalid"
            )
        prior = state["phase"]
        if not (
            (event.phase == "allowed" and prior == "attempted")
            or (
                event.phase == "denied"
                and prior == "attempted"
            )
            or (
                event.phase in {"succeeded", "redirect"}
                and prior == "allowed"
            )
            or (
                event.phase == "failed"
                and prior in {"attempted", "allowed"}
            )
        ):
            raise PlatformReadAuditError(
                "platform read audit request lifecycle is invalid"
            )
        state["phase"] = event.phase
    return states


def _validate_event_contract_bindings(
    events: tuple[_AuditEvent, ...],
    *,
    authority: PlatformReadAuditAuthority,
    purpose: str,
) -> None:
    if purpose in {
        "current_locked_50",
        "operational_settlement",
        "real_shadow_30",
    } and (
        authority.daily_contract_sha256 is not None
        or authority.daily_contract_selection_sha256 is not None
    ):
        raise PlatformReadAuditError(
            "settlement audit cannot bind a daily contract"
        )
    if purpose in {
        "daily_snapshot",
        "daily_validation",
        "operational_daily",
    } and (
        authority.daily_contract_sha256 is None
        or authority.daily_contract_selection_sha256 is None
    ):
        raise PlatformReadAuditError(
            "daily audit has no daily contract authority"
        )
    for event in events:
        expected_contract, expected_selection = authority.binding_for(
            event.operation
        )
        if (
            event.contract_sha256 != expected_contract
            or event.contract_selection_sha256 != expected_selection
        ):
            raise PlatformReadAuditError(
                "platform read audit operation contract changed"
            )


def _summarize_events(
    events: tuple[_AuditEvent, ...],
) -> tuple[
    dict[str, PlatformReadOperationCounts],
    PlatformReadRequestCounts,
    int,
    int,
]:
    mutable = {
        operation: {
            "attempted": 0,
            "allowed": 0,
            "succeeded": 0,
            "denied": 0,
            "failed": 0,
            "redirect": 0,
        }
        for operation in _SAFE_OPERATIONS
    }
    totals = {
        "attempted": 0,
        "allowed": 0,
        "succeeded": 0,
        "denied": 0,
    }
    writes = 0
    redirects = 0
    for event in events:
        if event.operation == _UNSAFE_OPERATION:
            if event.phase == "attempted":
                writes += 1
                totals["attempted"] += 1
            elif event.phase == "denied":
                totals["denied"] += 1
            continue
        mutable[event.operation][event.phase] += 1
        if event.phase in totals:
            totals[event.phase] += 1
        if event.phase == "redirect":
            redirects += 1
    return (
        {
            operation: PlatformReadOperationCounts(
                **counts,
            )
            for operation, counts in mutable.items()
        },
        PlatformReadRequestCounts(**totals),
        writes,
        redirects,
    )


def _lock_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        return
    import fcntl

    fcntl.flock(  # type: ignore[attr-defined]
        handle.fileno(),
        fcntl.LOCK_EX,  # type: ignore[attr-defined]
    )


def _unlock_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(  # type: ignore[attr-defined]
        handle.fileno(),
        fcntl.LOCK_UN,  # type: ignore[attr-defined]
    )
