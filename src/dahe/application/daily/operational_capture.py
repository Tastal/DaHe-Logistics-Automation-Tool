from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol

from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
)
from dahe.application.chengfeng.operational_capture import (
    WHOLE_RUN_CAPTURE_MODE,
    FastOperationalSettlementCaptureCoordinator,
    OperationalBatchCaptureStore,
    OperationalCaptureContractError,
)
from dahe.application.daily.capture import (
    DailyCaptureCheckpoint,
    DailyCaptureRequest,
)
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyWaybillObservation,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserNavigationAuthorizer,
    ChengfengReadPort,
    WaybillDetail,
    WaybillSummary,
)
from dahe.ports.daily import DailyPlatformReadPort, DailyReadStore


class DailyOperationalInvocation(Protocol):
    @property
    def invocation_id(self) -> str: ...

    @property
    def job_id(self) -> str: ...

    @property
    def access_window_id(self) -> str: ...

    @property
    def record_version(self) -> int: ...

    @property
    def request(self) -> DailyCaptureRequest: ...

    @property
    def checkpoint(self) -> DailyCaptureCheckpoint | None: ...


@dataclass(frozen=True, slots=True)
class OperationalDailyStepResult:
    has_more: bool
    checkpoint: DailyCaptureCheckpoint
    platform_read_performed: bool
    request_audit_counts: dict[str, int] | None = None


@dataclass(frozen=True, slots=True)
class _CaptureInvocationView:
    invocation_id: str
    job_id: str
    access_window_id: str
    scope: str
    page_size: int
    record_version: int
    status: str = "collecting"


@dataclass(frozen=True, slots=True)
class _FrozenDailyList:
    candidates: tuple[DailyCandidate, ...]
    platform_display_total: int | None
    response_total: int
    response_page_count: int
    unique_identity_total: int
    query_scope_sha256: str | None
    scope_complete: bool
    scope_diagnostic_code: str | None
    list_request_count: int


class _DailyListTotalChanged(RuntimeError):
    """Signals one stale or racing page response during list freezing."""

    def __init__(
        self,
        *,
        list_request_count: int,
        expected_total: int,
        actual_total: int,
    ) -> None:
        super().__init__("daily list total changed")
        self.list_request_count = list_request_count
        self.expected_total = expected_total
        self.actual_total = actual_total


class FastOperationalDailyCaptureCoordinator:
    """Freeze one daily list and persist one frozen-size batch per step."""

    def __init__(
        self,
        *,
        detail_adapter: ChengfengReadPort,
        navigation_authorizer: BrowserNavigationAuthorizer,
        batch_store: OperationalBatchCaptureStore,
        daily_store: DailyReadStore,
        clock: Callable[[], datetime],
        concurrency_provider: Callable[[], tuple[int, int]] | None = None,
        progress_sink: Callable[[str, str, int, int], None] | None = None,
    ) -> None:
        self._detail_adapter = detail_adapter
        self._navigation_authorizer = navigation_authorizer
        self._batch_store = batch_store
        self._daily_store = daily_store
        self._clock = clock
        self._concurrency_provider = concurrency_provider
        self._progress_sink = progress_sink
        self._list_request_counts: dict[str, int] = {}

    def advance(
        self,
        *,
        invocation: DailyOperationalInvocation,
        authority: BrowserCommandAuthority,
        list_port: DailyPlatformReadPort,
    ) -> OperationalDailyStepResult:
        request = invocation.request
        scope = f"daily:{request.business_date.isoformat()}"
        view = _CaptureInvocationView(
            invocation_id=invocation.invocation_id,
            job_id=invocation.job_id,
            access_window_id=invocation.access_window_id,
            scope=scope,
            page_size=1,
            record_version=invocation.record_version,
        )
        def read_list(
            _view: object,
            _authority: BrowserCommandAuthority,
        ) -> tuple[WaybillSummary, ...]:
            frozen = self._freeze_daily_list(
                request=request,
                list_port=list_port,
            )
            self._list_request_counts[invocation.job_id] = (
                frozen.list_request_count
            )
            snapshot = DailyCandidateSnapshot(
                snapshot_id=request.invocation_id,
                target_business_date=request.business_date,
                receive_place=request.receive_place,
                query_window=request.query_window,
                source_contract_sha256=request.source_contract_sha256,
                candidates=frozen.candidates,
                captured_at=max(self._clock(), request.query_window.end),
                platform_display_total=frozen.platform_display_total,
                response_total=frozen.response_total,
                response_page_count=frozen.response_page_count,
                unique_identity_total=frozen.unique_identity_total,
                query_scope_sha256=frozen.query_scope_sha256,
                scope_complete=frozen.scope_complete,
                scope_diagnostic_code=frozen.scope_diagnostic_code,
            )
            saved = self._daily_store.save_snapshot(snapshot)
            if saved.snapshot != snapshot:
                raise OperationalCaptureContractError(
                    "operational daily snapshot replay changed"
                )
            if not snapshot.scope_complete:
                raise OperationalCaptureContractError(
                    "operational daily scope is incomplete"
                )
            return tuple(
                WaybillSummary(
                    platform_waybill_id=candidate.platform_waybill_id,
                    waybill_number=(
                        candidate.waybill_number
                        or candidate.platform_waybill_id
                    ),
                    vehicle_number=candidate.vehicle_number,
                )
                for candidate in frozen.candidates
            )

        snapshot = self._snapshot_if_available(request.invocation_id)

        def matches(
            summary: WaybillSummary,
            detail: WaybillDetail,
        ) -> bool:
            if detail.platform_waybill_id != summary.platform_waybill_id:
                return False
            current = snapshot
            if current is None:
                current = self._snapshot_if_available(
                    request.invocation_id
                )
            if current is None:
                return detail.waybill_number == summary.waybill_number
            candidate = next(
                (
                    item
                    for item in current.candidates
                    if item.platform_waybill_id
                    == summary.platform_waybill_id
                ),
                None,
            )
            return bool(
                candidate is not None
                and (
                    candidate.waybill_number is None
                    or detail.waybill_number
                    == candidate.waybill_number
                )
            )

        def normalize_detail(
            summary: WaybillSummary,
            detail: WaybillDetail,
        ) -> WaybillDetail:
            current = self._daily_store.get_snapshot(
                request.invocation_id
            )
            candidate = next(
                item
                for item in current.candidates
                if item.platform_waybill_id
                == summary.platform_waybill_id
            )
            if candidate.waybill_number is None:
                return replace(
                    detail,
                    waybill_number=summary.waybill_number,
                )
            return detail

        coordinator = FastOperationalSettlementCaptureCoordinator(
            adapter=self._detail_adapter,
            navigation_authorizer=self._navigation_authorizer,
            batch_store=self._batch_store,
            list_reader=read_list,
            summary_matches_detail=matches,
            detail_normalizer=normalize_detail,
            concurrency_provider=self._concurrency_provider,
            progress_sink=self._progress_sink,
            capture_mode=WHOLE_RUN_CAPTURE_MODE,
        )
        step = coordinator.advance(
            invocation=view,
            authority=authority,
        )
        snapshot = self._snapshot_if_available(request.invocation_id)
        if snapshot is None:
            snapshot = self._daily_store.get_snapshot(
                request.invocation_id
            )
        list_request_count = self._list_request_counts.get(
            invocation.job_id,
            max(
                1,
                (
                    len(snapshot.candidates)
                    + request.page_size
                    - 1
                )
                // request.page_size,
            ),
        )
        previous_ids = (
            ()
            if invocation.checkpoint is None
            else invocation.checkpoint.completed_observation_ids
        )
        completed_ids = list(previous_ids)
        known_ids = set(completed_ids)
        for batch in step.checkpoints:
            for observation in self._observations(
                snapshot=snapshot,
                checkpoint=batch,
            ):
                if observation.observation_id in known_ids:
                    continue
                saved = self._daily_store.save_observation(observation)
                if saved.observation != observation:
                    raise OperationalCaptureContractError(
                        "operational daily observation replay changed"
                    )
                known_ids.add(observation.observation_id)
                completed_ids.append(observation.observation_id)
        if not step.has_more and len(completed_ids) != len(
            snapshot.candidates
        ):
            raise OperationalCaptureContractError(
                "operational daily observations are incomplete"
            )
        revision = (
            1
            if invocation.checkpoint is None
            else invocation.checkpoint.revision + 1
        )
        checkpoint = DailyCaptureCheckpoint(
            invocation_id=request.invocation_id,
            invocation_fingerprint=request.fingerprint,
            revision=revision,
            snapshot_captured_at=snapshot.captured_at,
            snapshot=snapshot,
            completed_observation_ids=tuple(completed_ids),
        )
        result = OperationalDailyStepResult(
            has_more=step.has_more,
            checkpoint=checkpoint,
            platform_read_performed=step.platform_read_performed,
            request_audit_counts=(
                None
                if step.has_more
                else {
                    "list_daily_waybills": list_request_count,
                    "get_waybill_detail": sum(
                        len(batch.details) for batch in step.checkpoints
                    ),
                    "download_ticket_image": sum(
                        len(batch.ticket_images)
                        for batch in step.checkpoints
                    ),
                }
            ),
        )
        if not step.has_more:
            self._list_request_counts.pop(invocation.job_id, None)
        return result

    def _freeze_daily_list(
        self,
        *,
        request: DailyCaptureRequest,
        list_port: DailyPlatformReadPort,
    ) -> _FrozenDailyList:
        attempted_request_count = 0
        for attempt in range(2):
            try:
                frozen = self._freeze_daily_list_once(
                    request=request,
                    list_port=list_port,
                )
                return replace(
                    frozen,
                    list_request_count=(
                        attempted_request_count
                        + frozen.list_request_count
                    ),
                )
            except _DailyListTotalChanged as exc:
                attempted_request_count += exc.list_request_count
                if attempt == 1:
                    raise OperationalCaptureContractError(
                        "operational daily total changed during freeze: "
                        f"page={exc.list_request_count},"
                        f"expected={exc.expected_total},"
                        f"actual={exc.actual_total}"
                    ) from exc
        raise AssertionError("daily list freeze retry is unreachable")

    def _freeze_daily_list_once(
        self,
        *,
        request: DailyCaptureRequest,
        list_port: DailyPlatformReadPort,
    ) -> _FrozenDailyList:
        page_number = 1
        effective_page_size = request.page_size
        total: int | None = None
        platform_display_total: int | None = None
        query_scope_sha256: str | None = None
        response_page_count: int | None = None
        pages_complete = True
        diagnostic_code: str | None = None
        candidates: list[DailyCandidate] = []
        while True:
            page = list_port.list_waybills(
                query_window=request.query_window,
                receive_place=request.receive_place,
                page_number=page_number,
                page_size=effective_page_size,
            )
            if (
                page.page_number != page_number
                or page.page_size != effective_page_size
                or page.total < 0
            ):
                raise OperationalCaptureContractError(
                    "operational daily pagination changed"
                )
            if total is None:
                total = page.total
                platform_display_total = page.platform_display_total
                query_scope_sha256 = page.query_scope_sha256
                response_page_count = page.response_page_count
                if (
                    page.response_total is None
                    or page.response_page_count is None
                    or page.query_scope_sha256 is None
                ):
                    pages_complete = False
                    diagnostic_code = "CF-DAILY-SCOPE-EVIDENCE-MISSING"
            elif page.total != total:
                raise _DailyListTotalChanged(
                    list_request_count=page_number,
                    expected_total=total,
                    actual_total=page.total,
                )
            if page.response_total not in {None, page.total}:
                pages_complete = False
                diagnostic_code = "CF-DAILY-SCOPE-RESPONSE-TOTAL-MISMATCH"
            if page.response_page_count != response_page_count:
                pages_complete = False
                diagnostic_code = "CF-DAILY-SCOPE-PAGE-COUNT-MISMATCH"
            if page.platform_display_total != platform_display_total:
                pages_complete = False
                diagnostic_code = "CF-DAILY-SCOPE-DISPLAY-TOTAL-CHANGED"
            if page.query_scope_sha256 != query_scope_sha256:
                pages_complete = False
                diagnostic_code = "CF-DAILY-SCOPE-HASH-CHANGED"
            if not page.scope_complete:
                pages_complete = False
                diagnostic_code = (
                    page.scope_diagnostic_code
                    or "CF-DAILY-SCOPE-INCOMPLETE"
                )
            candidates.extend(
                DailyCandidate(
                    platform_waybill_id=item.platform_waybill_id,
                    waybill_number=item.waybill_number,
                    vehicle_number=item.vehicle_number,
                    platform_loading_time=item.platform_loading_time,
                )
                for item in page.items
            )
            if (
                page_number == 1
                and total > len(page.items)
                and 0 < len(page.items) < effective_page_size
            ):
                effective_page_size = len(page.items)
            if len(candidates) >= total:
                break
            if not page.items:
                raise OperationalCaptureContractError(
                    "operational daily list ended before its total"
                )
            page_number += 1
        assert total is not None
        expected_page_count = max(
            1,
            (total + effective_page_size - 1) // effective_page_size,
        )
        if (
            response_page_count is None
            or response_page_count != expected_page_count
            or page_number != expected_page_count
        ):
            pages_complete = False
            diagnostic_code = "CF-DAILY-SCOPE-PAGE-COUNT-MISMATCH"
        identities = [item.platform_waybill_id for item in candidates]
        unique_identity_total = len(set(identities))
        if len(candidates) != total:
            pages_complete = False
            diagnostic_code = "CF-DAILY-SCOPE-RESPONSE-TOTAL-MISMATCH"
        if unique_identity_total != total:
            pages_complete = False
            diagnostic_code = "CF-DAILY-SCOPE-IDENTITY-MISMATCH"
        if (
            platform_display_total is not None
            and platform_display_total != total
        ):
            pages_complete = False
            diagnostic_code = "CF-DAILY-SCOPE-DISPLAY-TOTAL-MISMATCH"
        # The Chengfeng page query is the authoritative business scope.  The
        # extra safety window intentionally captures records posted around the
        # 14:00 boundary; applying a second local time filter silently dropped
        # six identities from an otherwise reconciled 68-item response.
        frozen_candidates = tuple(candidates)
        if len(frozen_candidates) != total:
            pages_complete = False
            diagnostic_code = "CF-DAILY-SCOPE-LOCAL-IDENTITY-LOSS"
        return _FrozenDailyList(
            candidates=frozen_candidates,
            platform_display_total=platform_display_total,
            response_total=total,
            response_page_count=(
                expected_page_count
                if response_page_count is None
                else response_page_count
            ),
            unique_identity_total=unique_identity_total,
            query_scope_sha256=query_scope_sha256,
            scope_complete=pages_complete,
            scope_diagnostic_code=(
                None if pages_complete else diagnostic_code
            ),
            list_request_count=page_number,
        )

    def _snapshot_if_available(
        self,
        snapshot_id: str,
    ) -> DailyCandidateSnapshot | None:
        try:
            return self._daily_store.get_snapshot(snapshot_id)
        except RuntimeError:
            return None

    def _observations(
        self,
        *,
        snapshot: DailyCandidateSnapshot,
        checkpoint: DurableCaptureCheckpoint,
    ) -> tuple[DailyWaybillObservation, ...]:
        candidate_by_id = {
            item.platform_waybill_id: item
            for item in snapshot.candidates
        }
        observed_at = max(self._clock(), snapshot.captured_at)
        observations: list[DailyWaybillObservation] = []
        for detail in checkpoint.details:
            candidate = candidate_by_id.get(detail.platform_waybill_id)
            if candidate is None:
                raise OperationalCaptureContractError(
                    "operational daily detail is outside its snapshot"
                )
            ticket_hashes = {
                ticket.slot: checkpoint.ticket_images[
                    ticket.ticket_ref
                ].sha256
                for ticket in detail.tickets
            }
            fields = DailyObservationFields(
                shipping_mine=None,
                planned_date=None,
                loading_time=None,
                vehicle_number=(
                    detail.vehicle_number or candidate.vehicle_number
                ),
                loading_net_tonnes=None,
                unloading_net_tonnes=None,
                coal_type=None,
                unloading_place=None,
                unloading_time=None,
            )
            normalized = {
                "fields": fields.to_payload(),
                "loading_ticket_sha256": ticket_hashes.get("loading"),
                "platform_waybill_id": detail.platform_waybill_id,
                "unloading_ticket_sha256": ticket_hashes.get(
                    "unloading"
                ),
                "waybill_number": candidate.waybill_number,
            }
            source_sha256 = _sha256(normalized)
            evidence = {
                **normalized,
                "source_detail_sha256": source_sha256,
            }
            observation_id = _sha256(
                {
                    "candidate": candidate.to_payload(),
                    "evidence": evidence,
                    "snapshot_id": snapshot.snapshot_id,
                }
            )[:32]
            observations.append(
                DailyWaybillObservation(
                    observation_id=observation_id,
                    snapshot_id=snapshot.snapshot_id,
                    platform_waybill_id=detail.platform_waybill_id,
                    waybill_number=candidate.waybill_number,
                    fields=fields,
                    loading_ticket_sha256=ticket_hashes.get("loading"),
                    unloading_ticket_sha256=ticket_hashes.get(
                        "unloading"
                    ),
                    source_detail_sha256=source_sha256,
                    observed_at=observed_at,
                )
            )
        return tuple(observations)


def _sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
