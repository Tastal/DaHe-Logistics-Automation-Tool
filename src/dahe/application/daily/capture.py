from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import cast

from dahe.domain.daily.calendar import (
    SHANGHAI,
    CandidateQueryWindow,
    DailyDomainError,
    candidate_query_window,
)
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyWaybillObservation,
)
from dahe.ports.daily import (
    DailyDetailCaptureContractError,
    DailyDetailCaptureState,
    DailyDetailCaptureStep,
    DailyDetailEvidence,
    DailyDetailEvidencePort,
    DailyPlatformReadPort,
    DailyReadStore,
    DailyWaybillPage,
    DailyWaybillSummary,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DailyCaptureError(RuntimeError):
    """Raised when typed daily capture results violate the frozen invocation."""


class DailyCaptureStage(StrEnum):
    LIST_PAGE = "daily.list_page"
    SAVE_SNAPSHOT = "daily.save_snapshot"
    OBSERVE_CANDIDATE = "daily.observe_candidate"
    SAVE_OBSERVATION = "daily.save_observation"


@dataclass(frozen=True, slots=True)
class DailyCaptureRequest:
    invocation_id: str
    business_date: date
    receive_place: str
    now: datetime
    source_contract_sha256: str
    page_size: int = 100

    def __post_init__(self) -> None:
        _bounded_text(
            self.invocation_id,
            field="invocation_id",
            maximum=128,
        )
        if type(self.business_date) is not date or isinstance(self.business_date, datetime):
            raise DailyCaptureError("business_date must be a calendar date")
        _safe_receive_place(self.receive_place)
        if self.now.tzinfo is None or self.now.utcoffset() is None:
            raise DailyCaptureError("now must be timezone-aware")
        if _SHA256.fullmatch(self.source_contract_sha256) is None:
            raise DailyCaptureError("source_contract_sha256 must be a lowercase SHA-256")
        if type(self.page_size) is not int or not 1 <= self.page_size <= 100:
            raise DailyCaptureError("page_size is outside the daily contract")
        candidate_query_window(self.business_date, now=self.now)

    def constructor_payload(self) -> dict[str, object]:
        return {
            "invocation_id": self.invocation_id,
            "business_date": self.business_date,
            "receive_place": self.receive_place,
            "now": self.now,
            "source_contract_sha256": self.source_contract_sha256,
            "page_size": self.page_size,
        }

    @property
    def query_window(self) -> CandidateQueryWindow:
        return candidate_query_window(self.business_date, now=self.now)

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "business_date": self.business_date.isoformat(),
                "invocation_id": self.invocation_id,
                "now": self.now.astimezone(SHANGHAI).isoformat(),
                "page_size": self.page_size,
                "receive_place": self.receive_place,
                "source_contract_sha256": self.source_contract_sha256,
            }
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "business_date": self.business_date.isoformat(),
            "invocation_id": self.invocation_id,
            "now": self.now.astimezone(SHANGHAI).isoformat(),
            "page_size": self.page_size,
            "receive_place": self.receive_place,
            "schema_version": 1,
            "source_contract_sha256": self.source_contract_sha256,
        }

    @classmethod
    def from_payload(cls, payload: object) -> DailyCaptureRequest:
        value = _strict_object(
            payload,
            keys={
                "business_date",
                "invocation_id",
                "now",
                "page_size",
                "receive_place",
                "schema_version",
                "source_contract_sha256",
            },
            field="daily capture request",
        )
        if value["schema_version"] != 1:
            raise DailyCaptureError(
                "daily capture request schema is unsupported"
            )
        if (
            type(value["business_date"]) is not str
            or type(value["invocation_id"]) is not str
            or type(value["now"]) is not str
            or type(value["page_size"]) is not int
            or type(value["receive_place"]) is not str
            or type(value["source_contract_sha256"]) is not str
        ):
            raise DailyCaptureError(
                "daily capture request field type is invalid"
            )
        try:
            business_date = date.fromisoformat(value["business_date"])
            now = datetime.fromisoformat(value["now"])
        except ValueError as exc:
            raise DailyCaptureError(
                "daily capture request timestamp is invalid"
            ) from exc
        try:
            return cls(
                invocation_id=value["invocation_id"],
                business_date=business_date,
                receive_place=value["receive_place"],
                now=now,
                source_contract_sha256=value["source_contract_sha256"],
                page_size=value["page_size"],
            )
        except (DailyCaptureError, TypeError, ValueError) as exc:
            raise DailyCaptureError(
                "daily capture request payload is invalid"
            ) from exc


@dataclass(frozen=True, slots=True)
class DailyCaptureCheckpoint:
    invocation_id: str
    invocation_fingerprint: str
    revision: int
    pages: tuple[DailyWaybillPage, ...] = ()
    verification_pages: tuple[DailyWaybillPage, ...] = ()
    list_read_access_window_ids: tuple[str, ...] = ()
    snapshot_captured_at: datetime | None = None
    snapshot: DailyCandidateSnapshot | None = None
    pending_detail_capture: DailyDetailCaptureState | None = None
    pending_observation: DailyWaybillObservation | None = None
    pending_observation_capture: DailyDetailCaptureState | None = None
    completed_observation_ids: tuple[str, ...] = ()
    completed_detail_captures: tuple[
        DailyDetailCaptureState, ...
    ] = ()

    @property
    def completed_observation_count(self) -> int:
        return len(self.completed_observation_ids)

    def to_payload(self) -> dict[str, object]:
        return {
            "completed_observation_ids": list(self.completed_observation_ids),
            "completed_detail_captures": [
                capture.to_payload()
                for capture in self.completed_detail_captures
            ],
            "invocation_fingerprint": self.invocation_fingerprint,
            "invocation_id": self.invocation_id,
            "list_read_access_window_ids": list(
                self.list_read_access_window_ids
            ),
            "pages": [_page_to_payload(page) for page in self.pages],
            "pending_detail_capture": (
                None
                if self.pending_detail_capture is None
                else self.pending_detail_capture.to_payload()
            ),
            "pending_observation": (
                None if self.pending_observation is None else self.pending_observation.to_payload()
            ),
            "pending_observation_capture": (
                None
                if self.pending_observation_capture is None
                else self.pending_observation_capture.to_payload()
            ),
            "revision": self.revision,
            "schema_version": 4,
            "snapshot": (None if self.snapshot is None else self.snapshot.to_payload()),
            "snapshot_captured_at": (
                None
                if self.snapshot_captured_at is None
                else self.snapshot_captured_at.astimezone(SHANGHAI).isoformat()
            ),
            "verification_pages": [
                _page_to_payload(page)
                for page in self.verification_pages
            ],
        }

    @classmethod
    def from_payload(cls, payload: object) -> DailyCaptureCheckpoint:
        if not isinstance(payload, dict):
            raise DailyCaptureError("daily capture checkpoint fields do not match schema")
        schema_version = payload.get("schema_version")
        if (
            type(schema_version) is not int
            or schema_version not in {1, 2, 3, 4}
        ):
            raise DailyCaptureError("daily capture checkpoint schema is unsupported")
        keys = {
            "completed_observation_ids",
            "invocation_fingerprint",
            "invocation_id",
            "pages",
            "pending_observation",
            "revision",
            "schema_version",
            "snapshot",
        }
        if schema_version in {2, 3, 4}:
            keys.add("snapshot_captured_at")
        if schema_version in {3, 4}:
            keys.add("verification_pages")
        if schema_version == 4:
            keys.update(
                {
                    "completed_detail_captures",
                    "list_read_access_window_ids",
                    "pending_detail_capture",
                    "pending_observation_capture",
                }
            )
        value = _strict_object(
            payload,
            keys=keys,
            field="daily capture checkpoint",
        )
        pages = value["pages"]
        verification_pages = (
            value["verification_pages"]
            if schema_version in {3, 4}
            else []
        )
        completed = value["completed_observation_ids"]
        list_read_windows = (
            value["list_read_access_window_ids"]
            if schema_version == 4
            else []
        )
        completed_captures = (
            value["completed_detail_captures"]
            if schema_version == 4
            else []
        )
        if (
            not isinstance(pages, list)
            or not isinstance(verification_pages, list)
            or not isinstance(completed, list)
            or not isinstance(completed_captures, list)
            or not isinstance(list_read_windows, list)
            or any(type(item) is not str for item in list_read_windows)
        ):
            raise DailyCaptureError("daily capture checkpoint collection is invalid")
        snapshot_payload = value["snapshot"]
        observation_payload = value["pending_observation"]
        detail_capture_payload = (
            value["pending_detail_capture"]
            if schema_version == 4
            else None
        )
        observation_capture_payload = (
            value["pending_observation_capture"]
            if schema_version == 4
            else None
        )
        try:
            snapshot = (
                None
                if snapshot_payload is None
                else DailyCandidateSnapshot.from_payload(snapshot_payload)
            )
            pending = (
                None
                if observation_payload is None
                else DailyWaybillObservation.from_payload(observation_payload)
            )
            pending_detail_capture = (
                None
                if detail_capture_payload is None
                else DailyDetailCaptureState.from_payload(
                    detail_capture_payload
                )
            )
            pending_observation_capture = (
                None
                if observation_capture_payload is None
                else DailyDetailCaptureState.from_payload(
                    observation_capture_payload
                )
            )
            restored_completed_captures = tuple(
                DailyDetailCaptureState.from_payload(capture)
                for capture in completed_captures
            )
        except (
            DailyDetailCaptureContractError,
            DailyDomainError,
        ) as exc:
            raise DailyCaptureError("daily capture checkpoint domain payload is invalid") from exc
        revision = value["revision"]
        if type(revision) is not int or revision < 0:
            raise DailyCaptureError("daily capture checkpoint revision is invalid")
        invocation_id = value["invocation_id"]
        invocation_fingerprint = value["invocation_fingerprint"]
        if type(invocation_id) is not str or type(invocation_fingerprint) is not str:
            raise DailyCaptureError("daily capture checkpoint identity is invalid")
        if any(type(item) is not str for item in completed):
            raise DailyCaptureError("daily capture completed identity is invalid")
        restored_snapshot_captured_at = (
            snapshot.captured_at
            if schema_version == 1 and snapshot is not None
            else (
                None
                if schema_version == 1
                else _optional_aware_datetime(
                    value["snapshot_captured_at"],
                    field="snapshot_captured_at",
                )
            )
        )
        snapshot_captured_at = (
            restored_snapshot_captured_at
            if schema_version in {3, 4} or snapshot is not None
            else None
        )
        return cls(
            invocation_id=invocation_id,
            invocation_fingerprint=invocation_fingerprint,
            revision=revision,
            pages=tuple(_page_from_payload(page) for page in pages),
            verification_pages=tuple(
                _page_from_payload(page)
                for page in verification_pages
            ),
            list_read_access_window_ids=tuple(list_read_windows),
            snapshot_captured_at=snapshot_captured_at,
            snapshot=snapshot,
            pending_detail_capture=pending_detail_capture,
            pending_observation=pending,
            pending_observation_capture=(
                pending_observation_capture
            ),
            completed_observation_ids=tuple(completed),
            completed_detail_captures=(
                restored_completed_captures
            ),
        )


@dataclass(frozen=True, slots=True)
class DailyCaptureStepResult:
    checkpoint: DailyCaptureCheckpoint
    completed_stage: DailyCaptureStage
    has_more: bool
    next_stage: DailyCaptureStage | None
    platform_read_performed: bool
    store_commit_performed: bool


class DailyCaptureService:
    """Advance one daily capture invocation by exactly one safe operation."""

    def __init__(
        self,
        *,
        platform: DailyPlatformReadPort,
        detail_evidence: DailyDetailEvidencePort,
        store: DailyReadStore,
        access_window_id: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._platform = platform
        self._detail_evidence = detail_evidence
        self._store = store
        if (
            access_window_id is not None
            and (
                not isinstance(access_window_id, str)
                or not access_window_id
                or len(access_window_id) > 100
            )
        ):
            raise DailyCaptureError(
                "daily capture access window identity is invalid"
            )
        self._access_window_id = access_window_id
        self._clock = clock

    def advance(
        self,
        *,
        request: DailyCaptureRequest,
        checkpoint: DailyCaptureCheckpoint | None,
    ) -> DailyCaptureStepResult:
        current = self._checkpoint(request, checkpoint)
        if self._needs_list_page(current):
            return self._read_next_page(request, current)
        if current.snapshot is None:
            return self._save_snapshot(request, current)
        if current.pending_observation is not None:
            return self._save_pending_observation(current)
        if current.completed_observation_count < len(current.snapshot.candidates):
            return self._observe_next_candidate(current)
        raise DailyCaptureError("daily capture invocation is already complete")

    @staticmethod
    def _checkpoint(
        request: DailyCaptureRequest,
        checkpoint: DailyCaptureCheckpoint | None,
    ) -> DailyCaptureCheckpoint:
        if checkpoint is None:
            return DailyCaptureCheckpoint(
                invocation_id=request.invocation_id,
                invocation_fingerprint=request.fingerprint,
                revision=0,
            )
        if (
            checkpoint.invocation_id != request.invocation_id
            or checkpoint.invocation_fingerprint != request.fingerprint
        ):
            raise DailyCaptureError("daily capture checkpoint belongs to another invocation")
        if checkpoint.revision < 0:
            raise DailyCaptureError("daily capture checkpoint is invalid")
        _validate_checkpoint_pages(
            checkpoint.pages,
            requested_page_size=request.page_size,
        )
        if checkpoint.list_read_access_window_ids and (
            len(checkpoint.list_read_access_window_ids)
            != len(checkpoint.pages)
            + len(checkpoint.verification_pages)
            or any(
                not access_window_id
                for access_window_id in (
                    checkpoint.list_read_access_window_ids
                )
            )
        ):
            raise DailyCaptureError(
                "daily list read access lineage is invalid"
            )
        _validate_checkpoint_pages(
            checkpoint.verification_pages,
            requested_page_size=request.page_size,
        )
        if (
            checkpoint.snapshot is not None
            and checkpoint.snapshot.snapshot_id != request.invocation_id
        ):
            raise DailyCaptureError("daily snapshot identity is inconsistent")
        if checkpoint.snapshot_captured_at is not None:
            _validate_actual_time(
                checkpoint.snapshot_captured_at,
                field="snapshot_captured_at",
                not_before=request.query_window.end,
            )
        if (
            checkpoint.verification_pages
            and DailyCaptureService._needs_primary_page(checkpoint)
        ):
            raise DailyCaptureError(
                "daily verification pages precede the primary pagination"
            )
        if checkpoint.verification_pages and (
            checkpoint.verification_pages[0].total
            != checkpoint.pages[0].total
            or checkpoint.verification_pages[0].page_size
            != checkpoint.pages[0].page_size
        ):
            raise DailyCaptureError(
                "daily pagination changed between stability passes"
            )
        if (
            checkpoint.verification_pages
            and not DailyCaptureService._needs_verification_page(checkpoint)
            and _pagination_content(checkpoint.pages)
            != _pagination_content(checkpoint.verification_pages)
        ):
            raise DailyCaptureError(
                "daily pagination stability check failed"
            )
        if (
            checkpoint.snapshot is None
            and checkpoint.snapshot_captured_at is not None
            and DailyCaptureService._needs_verification_page(checkpoint)
        ):
            raise DailyCaptureError(
                "daily snapshot time precedes pagination verification"
            )
        if checkpoint.snapshot is not None and (
            checkpoint.snapshot_captured_at is None
            or checkpoint.snapshot.captured_at != checkpoint.snapshot_captured_at
        ):
            raise DailyCaptureError("daily snapshot capture time is inconsistent")
        if checkpoint.pending_observation is not None and checkpoint.snapshot is None:
            raise DailyCaptureError("daily pending observation has no saved snapshot")
        if checkpoint.pending_observation is not None:
            assert checkpoint.snapshot_captured_at is not None
            _validate_actual_time(
                checkpoint.pending_observation.observed_at,
                field="pending observation observed_at",
                not_before=checkpoint.snapshot_captured_at,
            )
        if (
            checkpoint.pending_detail_capture is not None
            and checkpoint.pending_observation is not None
        ):
            raise DailyCaptureError(
                "daily detail capture and observation cannot both be pending"
            )
        if (
            checkpoint.pending_observation_capture is not None
            and checkpoint.pending_observation is None
        ):
            raise DailyCaptureError(
                "daily observation capture has no pending observation"
            )
        if (
            checkpoint.pending_observation_capture is not None
            and not checkpoint.pending_observation_capture.complete
        ):
            raise DailyCaptureError(
                "daily observation capture is incomplete"
            )
        if checkpoint.completed_detail_captures and (
            len(checkpoint.completed_detail_captures)
            != checkpoint.completed_observation_count
            or any(
                not capture.complete
                for capture in checkpoint.completed_detail_captures
            )
        ):
            raise DailyCaptureError(
                "daily completed detail capture lineage is invalid"
            )
        if checkpoint.snapshot is not None:
            next_index = checkpoint.completed_observation_count
            if next_index < len(checkpoint.snapshot.candidates):
                expected_candidate = checkpoint.snapshot.candidates[
                    next_index
                ]
                for capture in (
                    checkpoint.pending_detail_capture,
                    checkpoint.pending_observation_capture,
                ):
                    if capture is not None and (
                        capture.platform_waybill_id
                        != expected_candidate.platform_waybill_id
                        or (
                            expected_candidate.waybill_number
                            is not None
                            and capture.waybill_number
                            != expected_candidate.waybill_number
                        )
                    ):
                        raise DailyCaptureError(
                            "daily detail capture belongs to another candidate"
                        )
        if checkpoint.snapshot is not None and checkpoint.completed_observation_count > len(
            checkpoint.snapshot.candidates
        ):
            raise DailyCaptureError("daily capture checkpoint overstates completed observations")
        if len(set(checkpoint.completed_observation_ids)) != len(
            checkpoint.completed_observation_ids
        ):
            raise DailyCaptureError("daily capture checkpoint has duplicate observations")
        return checkpoint

    @staticmethod
    def _needs_list_page(
        checkpoint: DailyCaptureCheckpoint,
    ) -> bool:
        if checkpoint.snapshot is not None:
            return False
        return (
            DailyCaptureService._needs_primary_page(checkpoint)
            or DailyCaptureService._needs_verification_page(checkpoint)
        )

    @staticmethod
    def _needs_primary_page(
        checkpoint: DailyCaptureCheckpoint,
    ) -> bool:
        if not checkpoint.pages:
            return True
        first = checkpoint.pages[0]
        return len(checkpoint.pages) < _page_count(
            first.total,
            first.page_size,
        )

    @staticmethod
    def _needs_verification_page(
        checkpoint: DailyCaptureCheckpoint,
    ) -> bool:
        if not checkpoint.pages:
            return False
        first = checkpoint.pages[0]
        if len(checkpoint.pages) < _page_count(
            first.total,
            first.page_size,
        ):
            return False
        return len(checkpoint.verification_pages) < _page_count(
            first.total,
            first.page_size,
        )

    def _read_next_page(
        self,
        request: DailyCaptureRequest,
        checkpoint: DailyCaptureCheckpoint,
    ) -> DailyCaptureStepResult:
        verifying = not self._needs_primary_page(checkpoint)
        previous_pages = (
            checkpoint.verification_pages
            if verifying
            else checkpoint.pages
        )
        page_number = len(previous_pages) + 1
        page = self._platform.list_waybills(
            query_window=request.query_window,
            receive_place=request.receive_place,
            page_number=page_number,
            page_size=request.page_size,
        )
        if not isinstance(page, DailyWaybillPage):
            raise DailyCaptureError("daily platform returned an invalid list page")
        _validate_page(
            page,
            expected_page_number=page_number,
            requested_page_size=request.page_size,
            previous_pages=previous_pages,
        )
        if verifying and (
            page.total != checkpoint.pages[0].total
            or page.page_size != checkpoint.pages[0].page_size
        ):
            raise DailyCaptureError(
                "daily pagination changed between stability passes"
            )
        if verifying:
            updated = replace(
                checkpoint,
                revision=checkpoint.revision + 1,
                verification_pages=(
                    *checkpoint.verification_pages,
                    page,
                ),
                list_read_access_window_ids=(
                    checkpoint.list_read_access_window_ids
                    if self._access_window_id is None
                    else (
                        *checkpoint.list_read_access_window_ids,
                        self._access_window_id,
                    )
                ),
            )
        else:
            updated = replace(
                checkpoint,
                revision=checkpoint.revision + 1,
                pages=(*checkpoint.pages, page),
                list_read_access_window_ids=(
                    checkpoint.list_read_access_window_ids
                    if self._access_window_id is None
                    else (
                        *checkpoint.list_read_access_window_ids,
                        self._access_window_id,
                    )
                ),
            )
        if verifying and not self._needs_verification_page(updated):
            if _pagination_content(updated.pages) != _pagination_content(
                updated.verification_pages
            ):
                raise DailyCaptureError(
                    "daily pagination stability check failed"
                )
            updated = replace(
                updated,
                snapshot_captured_at=_clock_time(
                    self._clock,
                    field="snapshot capture clock",
                    not_before=request.query_window.end,
                ),
            )
        return self._result(
            updated,
            completed_stage=DailyCaptureStage.LIST_PAGE,
            platform_read_performed=True,
            store_commit_performed=False,
        )

    def _save_snapshot(
        self,
        request: DailyCaptureRequest,
        checkpoint: DailyCaptureCheckpoint,
    ) -> DailyCaptureStepResult:
        if checkpoint.snapshot_captured_at is None:
            raise DailyCaptureError("daily snapshot capture time was not checkpointed")
        if self._needs_verification_page(checkpoint) or (
            _pagination_content(checkpoint.pages)
            != _pagination_content(checkpoint.verification_pages)
        ):
            raise DailyCaptureError(
                "daily pagination stability was not verified"
            )
        candidates = _candidates(checkpoint.pages)
        snapshot = DailyCandidateSnapshot(
            snapshot_id=request.invocation_id,
            target_business_date=request.business_date,
            receive_place=request.receive_place,
            query_window=request.query_window,
            source_contract_sha256=request.source_contract_sha256,
            candidates=candidates,
            captured_at=checkpoint.snapshot_captured_at,
        )
        saved = self._store.save_snapshot(snapshot)
        if saved.snapshot != snapshot:
            raise DailyCaptureError("daily store replayed a different snapshot")
        updated = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
            snapshot=saved.snapshot,
        )
        return self._result(
            updated,
            completed_stage=DailyCaptureStage.SAVE_SNAPSHOT,
            platform_read_performed=False,
            store_commit_performed=True,
        )

    def _observe_next_candidate(
        self,
        checkpoint: DailyCaptureCheckpoint,
    ) -> DailyCaptureStepResult:
        assert checkpoint.snapshot is not None
        candidate = checkpoint.snapshot.candidates[checkpoint.completed_observation_count]
        advance = getattr(self._detail_evidence, "advance", None)
        capture_state: DailyDetailCaptureState | None = None
        if callable(advance):
            raw_step = advance(
                candidate=candidate,
                state=checkpoint.pending_detail_capture,
            )
            if not isinstance(raw_step, DailyDetailCaptureStep):
                raise DailyCaptureError(
                    "daily detail adapter returned invalid capture step"
                )
            if raw_step.evidence is None:
                updated = replace(
                    checkpoint,
                    revision=checkpoint.revision + 1,
                    pending_detail_capture=raw_step.state,
                )
                return self._result(
                    updated,
                    completed_stage=(
                        DailyCaptureStage.OBSERVE_CANDIDATE
                    ),
                    platform_read_performed=(
                        raw_step.platform_read_performed
                    ),
                    store_commit_performed=False,
                )
            evidence = raw_step.evidence
            capture_state = raw_step.state
            platform_read_performed = (
                raw_step.platform_read_performed
            )
        else:
            observe = getattr(self._detail_evidence, "observe", None)
            if not callable(observe):
                raise DailyCaptureError(
                    "daily detail adapter has no capture operation"
                )
            evidence = observe(candidate=candidate)
            platform_read_performed = True
        if not isinstance(evidence, DailyDetailEvidence):
            raise DailyCaptureError("daily detail adapter returned invalid evidence")
        if evidence.platform_waybill_id != candidate.platform_waybill_id:
            raise DailyCaptureError("daily detail result does not match the requested candidate")
        if (
            candidate.waybill_number is not None
            and evidence.waybill_number != candidate.waybill_number
        ):
            raise DailyCaptureError("daily detail result does not match the requested candidate")
        observed_at = _clock_time(
            self._clock,
            field="observation clock",
            not_before=checkpoint.snapshot.captured_at,
        )
        observation = DailyWaybillObservation(
            observation_id=_observation_id(
                snapshot_id=checkpoint.snapshot.snapshot_id,
                candidate=candidate,
                evidence=evidence,
            ),
            snapshot_id=checkpoint.snapshot.snapshot_id,
            platform_waybill_id=evidence.platform_waybill_id,
            waybill_number=evidence.waybill_number,
            fields=evidence.fields,
            loading_ticket_sha256=evidence.loading_ticket_sha256,
            unloading_ticket_sha256=evidence.unloading_ticket_sha256,
            source_detail_sha256=evidence.source_detail_sha256,
            observed_at=observed_at,
        )
        updated = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
            pending_detail_capture=None,
            pending_observation=observation,
            pending_observation_capture=capture_state,
        )
        return self._result(
            updated,
            completed_stage=DailyCaptureStage.OBSERVE_CANDIDATE,
            platform_read_performed=platform_read_performed,
            store_commit_performed=False,
        )

    def _save_pending_observation(
        self,
        checkpoint: DailyCaptureCheckpoint,
    ) -> DailyCaptureStepResult:
        assert checkpoint.pending_observation is not None
        saved = self._store.save_observation(checkpoint.pending_observation)
        if saved.observation != checkpoint.pending_observation:
            raise DailyCaptureError("daily store replayed a different observation")
        updated = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
            pending_observation=None,
            pending_observation_capture=None,
            completed_observation_ids=(
                *checkpoint.completed_observation_ids,
                saved.observation.observation_id,
            ),
            completed_detail_captures=(
                checkpoint.completed_detail_captures
                if checkpoint.pending_observation_capture is None
                else (
                    *checkpoint.completed_detail_captures,
                    checkpoint.pending_observation_capture,
                )
            ),
        )
        return self._result(
            updated,
            completed_stage=DailyCaptureStage.SAVE_OBSERVATION,
            platform_read_performed=False,
            store_commit_performed=True,
        )

    @classmethod
    def _result(
        cls,
        checkpoint: DailyCaptureCheckpoint,
        *,
        completed_stage: DailyCaptureStage,
        platform_read_performed: bool,
        store_commit_performed: bool,
    ) -> DailyCaptureStepResult:
        next_stage = cls._next_stage(checkpoint)
        return DailyCaptureStepResult(
            checkpoint=checkpoint,
            completed_stage=completed_stage,
            has_more=next_stage is not None,
            next_stage=next_stage,
            platform_read_performed=platform_read_performed,
            store_commit_performed=store_commit_performed,
        )

    @staticmethod
    def _next_stage(
        checkpoint: DailyCaptureCheckpoint,
    ) -> DailyCaptureStage | None:
        if DailyCaptureService._needs_list_page(checkpoint):
            return DailyCaptureStage.LIST_PAGE
        if checkpoint.snapshot is None:
            return DailyCaptureStage.SAVE_SNAPSHOT
        if checkpoint.pending_observation is not None:
            return DailyCaptureStage.SAVE_OBSERVATION
        if checkpoint.pending_detail_capture is not None:
            return DailyCaptureStage.OBSERVE_CANDIDATE
        if checkpoint.completed_observation_count < len(checkpoint.snapshot.candidates):
            return DailyCaptureStage.OBSERVE_CANDIDATE
        return None


def _candidates(
    pages: tuple[DailyWaybillPage, ...],
) -> tuple[DailyCandidate, ...]:
    if not pages:
        raise DailyCaptureError("daily snapshot has no list page")
    expected_count = pages[0].total
    candidates = tuple(
        DailyCandidate(
            platform_waybill_id=item.platform_waybill_id,
            waybill_number=item.waybill_number,
            vehicle_number=item.vehicle_number,
            platform_loading_time=item.platform_loading_time,
        )
        for page in pages
        for item in page.items
    )
    if len(candidates) != expected_count:
        raise DailyCaptureError("daily pagination does not exactly reconcile to its total")
    return candidates


def _pagination_content(
    pages: tuple[DailyWaybillPage, ...],
) -> tuple[tuple[str, str, str, str], ...]:
    """Return the complete order-independent summary for one pagination pass."""
    candidates = _candidates(pages)
    return tuple(
        sorted(
            (
                candidate.platform_waybill_id,
                candidate.waybill_number or "",
                candidate.vehicle_number or "",
                (
                    ""
                    if candidate.platform_loading_time is None
                    else candidate.platform_loading_time.astimezone(
                        SHANGHAI
                    ).isoformat()
                ),
            )
            for candidate in candidates
        )
    )


def _validate_page(
    page: DailyWaybillPage,
    *,
    expected_page_number: int,
    requested_page_size: int,
    previous_pages: tuple[DailyWaybillPage, ...],
) -> None:
    if (
        type(page.page_number) is not int
        or page.page_number != expected_page_number
        or type(page.page_size) is not int
        or page.page_size != requested_page_size
        or type(page.total) is not int
        or page.total < 0
        or not isinstance(page.items, tuple)
        or len(page.items) > requested_page_size
    ):
        raise DailyCaptureError("daily pagination changed during capture")
    if previous_pages and page.total != previous_pages[0].total:
        raise DailyCaptureError("daily pagination changed during capture")
    page_count = _page_count(page.total, requested_page_size)
    if expected_page_number > page_count:
        raise DailyCaptureError("daily pagination exceeds its reported total")
    expected_items = (
        0
        if page.total == 0
        else (
            requested_page_size
            if expected_page_number < page_count
            else page.total - requested_page_size * (page_count - 1)
        )
    )
    if len(page.items) != expected_items:
        raise DailyCaptureError("daily pagination does not exactly reconcile to its total")
    platform_ids: set[str] = set()
    waybill_numbers: set[str] = set()
    for prior in (*previous_pages, page):
        for item in prior.items:
            if (
                not isinstance(item.platform_waybill_id, str)
                or not item.platform_waybill_id
                or not isinstance(item.waybill_number, str)
                or not item.waybill_number
            ):
                raise DailyCaptureError("daily list contains an invalid waybill identity")
            if item.platform_waybill_id in platform_ids or item.waybill_number in waybill_numbers:
                raise DailyCaptureError("daily list contains a duplicate waybill identity")
            platform_ids.add(item.platform_waybill_id)
            waybill_numbers.add(item.waybill_number)


def _validate_checkpoint_pages(
    pages: tuple[DailyWaybillPage, ...],
    *,
    requested_page_size: int,
) -> None:
    previous: tuple[DailyWaybillPage, ...] = ()
    for expected_page_number, page in enumerate(pages, start=1):
        _validate_page(
            page,
            expected_page_number=expected_page_number,
            requested_page_size=requested_page_size,
            previous_pages=previous,
        )
        previous = (*previous, page)


def _page_count(total: int, page_size: int) -> int:
    return max(1, (total + page_size - 1) // page_size)


def _observation_id(
    *,
    snapshot_id: str,
    candidate: DailyCandidate,
    evidence: DailyDetailEvidence,
) -> str:
    return _fingerprint(
        {
            "candidate": candidate.to_payload(),
            "evidence": {
                "fields": evidence.fields.to_payload(),
                "loading_ticket_sha256": evidence.loading_ticket_sha256,
                "platform_waybill_id": evidence.platform_waybill_id,
                "source_detail_sha256": evidence.source_detail_sha256,
                "unloading_ticket_sha256": (evidence.unloading_ticket_sha256),
                "waybill_number": evidence.waybill_number,
            },
            "snapshot_id": snapshot_id,
        }
    )[:32]


def _page_to_payload(page: DailyWaybillPage) -> dict[str, object]:
    return {
        "items": [
            {
                "platform_loading_time": (
                    None
                    if item.platform_loading_time is None
                    else item.platform_loading_time.astimezone(SHANGHAI).isoformat()
                ),
                "platform_waybill_id": item.platform_waybill_id,
                "vehicle_number": item.vehicle_number,
                "waybill_number": item.waybill_number,
            }
            for item in page.items
        ],
        "page_number": page.page_number,
        "page_size": page.page_size,
        "total": page.total,
    }


def _page_from_payload(payload: object) -> DailyWaybillPage:
    value = _strict_object(
        payload,
        keys={"items", "page_number", "page_size", "total"},
        field="daily waybill page",
    )
    raw_items = value["items"]
    if not isinstance(raw_items, list):
        raise DailyCaptureError("daily waybill page items are invalid")
    items: list[DailyWaybillSummary] = []
    for raw_item in raw_items:
        item = _strict_object(
            raw_item,
            keys={
                "platform_loading_time",
                "platform_waybill_id",
                "vehicle_number",
                "waybill_number",
            },
            field="daily waybill summary",
        )
        platform_id = item["platform_waybill_id"]
        waybill_number = item["waybill_number"]
        vehicle_number = item["vehicle_number"]
        if (
            type(platform_id) is not str
            or type(waybill_number) is not str
            or (vehicle_number is not None and type(vehicle_number) is not str)
        ):
            raise DailyCaptureError("daily waybill summary identity is invalid")
        items.append(
            DailyWaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=vehicle_number,
                platform_loading_time=_optional_aware_datetime(
                    item["platform_loading_time"],
                    field="platform_loading_time",
                ),
            )
        )
    page_number = value["page_number"]
    page_size = value["page_size"]
    total = value["total"]
    if any(type(number) is not int for number in (page_number, page_size, total)):
        raise DailyCaptureError("daily waybill pagination is invalid")
    return DailyWaybillPage(
        page_number=cast(int, page_number),
        page_size=cast(int, page_size),
        total=cast(int, total),
        items=tuple(items),
    )


def _strict_object(
    value: object,
    *,
    keys: set[str],
    field: str,
) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or any(type(key) is not str for key in value)
        or set(value) != keys
    ):
        raise DailyCaptureError(f"{field} fields do not match schema")
    return value


def _optional_aware_datetime(
    value: object,
    *,
    field: str,
) -> datetime | None:
    if value is None:
        return None
    if type(value) is not str:
        raise DailyCaptureError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise DailyCaptureError(f"{field} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DailyCaptureError(f"{field} is invalid")
    return parsed.astimezone(SHANGHAI)


def _validate_actual_time(
    value: datetime,
    *,
    field: str,
    not_before: datetime,
) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise DailyCaptureError(f"{field} must be timezone-aware")
    normalized = value.astimezone(SHANGHAI)
    if normalized < not_before:
        raise DailyCaptureError(f"{field} precedes its source read")
    return normalized


def _clock_time(
    clock: Callable[[], datetime],
    *,
    field: str,
    not_before: datetime,
) -> datetime:
    return _validate_actual_time(
        clock(),
        field=field,
        not_before=not_before,
    )


def _fingerprint(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _bounded_text(
    value: str,
    *,
    field: str,
    maximum: int,
) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DailyCaptureError(f"{field} is invalid")


def _safe_receive_place(value: str) -> None:
    _bounded_text(value, field="receive_place", maximum=100)
    if "://" in value or "?" in value or "#" in value:
        raise DailyCaptureError("receive_place is invalid")
