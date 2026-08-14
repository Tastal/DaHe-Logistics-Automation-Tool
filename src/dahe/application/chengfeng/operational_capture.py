from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Literal, Protocol

from dahe.application.chengfeng.durable_capture import (
    CHECKPOINT_SCHEMA_VERSION,
    DurableCaptureCheckpoint,
    DurableCaptureCheckpointStore,
    DurableChengfengCaptureCoordinator,
)
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserNavigationAuthorizer,
    ChengfengReadPort,
    ChengfengStage,
    DownloadedTicketImage,
    OperationalWaybillEvidence,
    TransientNetworkError,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)

OPERATIONAL_BATCH_SIZE = 20
OPERATIONAL_LIST_PAGE_SIZE = 50
OPERATIONAL_DETAIL_CONCURRENCY = 4
OPERATIONAL_IMAGE_CONCURRENCY = 6
WHOLE_RUN_CAPTURE_MODE = "whole_run_v1"
BATCH_CAPTURE_MODE = "batch_v1"


class OperationalCaptureContractError(ValueError):
    """Raised when operational evidence cannot form one complete audit job."""


class OperationalCaptureInvocation(Protocol):
    @property
    def invocation_id(self) -> str: ...

    @property
    def job_id(self) -> str: ...

    @property
    def access_window_id(self) -> str: ...

    @property
    def scope(self) -> str: ...

    @property
    def page_size(self) -> int: ...

    @property
    def record_version(self) -> int: ...

    @property
    def status(self) -> str: ...


@dataclass(frozen=True, slots=True)
class OperationalCaptureStepResult:
    has_more: bool
    platform_read_performed: bool
    checkpoint_revision: int | None
    capture_sha256: str | None
    checkpoints: tuple[DurableCaptureCheckpoint, ...] = ()


@dataclass(frozen=True, slots=True)
class OperationalCaptureRun:
    job_id: str
    scope: str
    total: int
    items: tuple[WaybillSummary, ...]
    next_item_index: int
    committed_batch_count: int
    batch_size: int
    detail_concurrency: int
    image_concurrency: int
    status: str
    record_version: int
    capture_mode: str = BATCH_CAPTURE_MODE
    metadata_checked_count: int = 0
    reused_count: int = 0
    images_downloaded_count: int = 0


class OperationalBatchCaptureStore(Protocol):
    def load_operational_run(
        self,
        *,
        job_id: str,
    ) -> OperationalCaptureRun | None: ...

    def freeze_operational_run(
        self,
        *,
        job_id: str,
        scope: str,
        items: tuple[WaybillSummary, ...],
        capture_mode: str,
        batch_size: int,
        detail_concurrency: int,
        image_concurrency: int,
        authority: BrowserCommandAuthority,
    ) -> OperationalCaptureRun: ...

    def commit_operational_batch(
        self,
        *,
        run: OperationalCaptureRun,
        checkpoint: DurableCaptureCheckpoint,
        images: tuple[DownloadedTicketImage, ...],
        authority: BrowserCommandAuthority,
        access_window_id: str,
        source_revisions: dict[str, str],
    ) -> tuple[OperationalCaptureRun, DurableCaptureCheckpoint]: ...

    def capture_id(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> str: ...

    def load(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None: ...


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _validated_checkpoints(
    checkpoints: Sequence[DurableCaptureCheckpoint],
) -> tuple[DurableCaptureCheckpoint, ...]:
    if (
        not isinstance(checkpoints, Sequence)
        or isinstance(checkpoints, (str, bytes))
        or not checkpoints
        or any(
            not isinstance(item, DurableCaptureCheckpoint)
            for item in checkpoints
        )
    ):
        raise OperationalCaptureContractError(
            "operational capture requires one or more checkpoints"
        )
    ordered = tuple(
        sorted(checkpoints, key=lambda item: item.page_number)
    )
    first = ordered[0]
    if first.page is None:
        raise OperationalCaptureContractError(
            "operational capture has no first page"
        )
    expected_pages = max(
        1,
        (first.page.total + first.page_size - 1) // first.page_size,
    )
    if (
        tuple(item.page_number for item in ordered)
        != tuple(range(1, expected_pages + 1))
        or any(
            item.job_id != first.job_id
            or item.scope != first.scope
            or item.page_size != first.page_size
            or item.page is None
            or item.page.total != first.page.total
            or len(item.details) != len(item.page.items)
            for item in ordered
        )
    ):
        raise OperationalCaptureContractError(
            "operational capture pagination is incomplete"
        )
    summaries = [
        summary
        for checkpoint in ordered
        for summary in checkpoint.page.items  # type: ignore[union-attr]
    ]
    details = [
        detail
        for checkpoint in ordered
        for detail in checkpoint.details
    ]
    if (
        len(summaries) != first.page.total
        or len(details) != first.page.total
        or len(
            {item.platform_waybill_id for item in summaries}
        )
        != len(summaries)
        or len(
            {item.waybill_number for item in summaries}
        )
        != len(summaries)
    ):
        raise OperationalCaptureContractError(
            "operational capture count or identity is inconsistent"
        )
    for checkpoint in ordered:
        expected_refs = {
            ticket.ticket_ref
            for candidate in checkpoint.details
            for ticket in candidate.tickets
        }
        if set(checkpoint.ticket_images) != expected_refs:
            raise OperationalCaptureContractError(
                "operational capture ticket evidence is incomplete"
            )
        for detail in checkpoint.details:
            tickets = {ticket.slot: ticket for ticket in detail.tickets}
            if (
                not set(tickets).issubset({"loading", "unloading"})
                or len(tickets) != len(detail.tickets)
            ):
                raise OperationalCaptureContractError(
                    "operational capture ticket evidence is incomplete"
                )
    return ordered


class FastOperationalSettlementCaptureCoordinator:
    """Freeze one authoritative list and publish only validated capture units."""

    def __init__(
        self,
        *,
        adapter: ChengfengReadPort,
        navigation_authorizer: BrowserNavigationAuthorizer,
        batch_store: OperationalBatchCaptureStore,
        list_reader: Callable[
            [OperationalCaptureInvocation, BrowserCommandAuthority],
            tuple[WaybillSummary, ...],
        ]
        | None = None,
        summary_matches_detail: Callable[
            [WaybillSummary, WaybillDetail], bool
        ]
        | None = None,
        detail_normalizer: Callable[
            [WaybillSummary, WaybillDetail], WaybillDetail
        ]
        | None = None,
        concurrency_provider: Callable[[], tuple[int, int]] | None = None,
        batch_size_provider: Callable[[], int] | None = None,
        progress_sink: Callable[[str, str, int, int], None] | None = None,
        capture_mode: str = BATCH_CAPTURE_MODE,
    ) -> None:
        self._adapter = adapter
        self._navigation_authorizer = navigation_authorizer
        self._store = batch_store
        self._list_reader = list_reader
        self._summary_matches_detail = (
            summary_matches_detail
            or (
                lambda summary, detail: (
                    detail.platform_waybill_id
                    == summary.platform_waybill_id
                    and detail.waybill_number
                    == summary.waybill_number
                )
            )
        )
        self._detail_normalizer = (
            detail_normalizer or (lambda _summary, detail: detail)
        )
        self._concurrency_provider = concurrency_provider or (
            lambda: (
                OPERATIONAL_DETAIL_CONCURRENCY,
                OPERATIONAL_IMAGE_CONCURRENCY,
            )
        )
        self._batch_size_provider = batch_size_provider or (
            lambda: OPERATIONAL_BATCH_SIZE
        )
        self._progress_sink = progress_sink
        if capture_mode not in {BATCH_CAPTURE_MODE, WHOLE_RUN_CAPTURE_MODE}:
            raise OperationalCaptureContractError("operational capture mode is invalid")
        self._capture_mode = capture_mode

    def _batch_size(self) -> int:
        value = self._batch_size_provider()
        if value not in {20, 50, 100}:
            raise OperationalCaptureContractError(
                "operational batch size must be 20, 50, or 100"
            )
        return value

    def _capture_unit_size(self, total: int) -> int:
        if self._capture_mode == WHOLE_RUN_CAPTURE_MODE:
            return max(1, total)
        return self._batch_size()

    def _authorize(self, authority: BrowserCommandAuthority) -> None:
        self._navigation_authorizer.authorize(authority)

    def _freeze_list(
        self,
        *,
        invocation: OperationalCaptureInvocation,
        authority: BrowserCommandAuthority,
    ) -> OperationalCaptureRun:
        if self._list_reader is not None:
            detail_concurrency, image_concurrency = self._concurrency_provider()
            frozen_items = self._list_reader(invocation, authority)
            if (
                not isinstance(frozen_items, tuple)
                or any(
                    not isinstance(item, WaybillSummary)
                    for item in frozen_items
                )
                or len(
                    {item.platform_waybill_id for item in frozen_items}
                )
                != len(frozen_items)
                or len({item.waybill_number for item in frozen_items})
                != len(frozen_items)
            ):
                raise OperationalCaptureContractError(
                    "operational list reader returned invalid identities"
                )
            return self._store.freeze_operational_run(
                job_id=invocation.job_id,
                scope=invocation.scope,
                items=frozen_items,
                capture_mode=self._capture_mode,
                batch_size=self._capture_unit_size(len(frozen_items)),
                detail_concurrency=detail_concurrency,
                image_concurrency=image_concurrency,
                authority=authority,
            )
        items: list[WaybillSummary] = []
        expected_total: int | None = None
        page_number = 1
        while True:
            self._authorize(authority)
            page = self._adapter.list_waybills(
                authority=authority,
                scope=invocation.scope,
                page_number=page_number,
                page_size=OPERATIONAL_LIST_PAGE_SIZE,
            )
            self._authorize(authority)
            if (
                page.page_number != page_number
                or page.page_size != OPERATIONAL_LIST_PAGE_SIZE
                or page.total < 0
            ):
                raise OperationalCaptureContractError(
                    "operational list pagination changed"
                )
            if expected_total is None:
                expected_total = page.total
            elif page.total != expected_total:
                raise OperationalCaptureContractError(
                    "operational list total changed during freeze"
                )
            items.extend(page.items)
            if len(items) >= expected_total:
                break
            if not page.items:
                raise OperationalCaptureContractError(
                    "operational list ended before its declared total"
                )
            page_number += 1
        assert expected_total is not None
        if len(items) != expected_total:
            raise OperationalCaptureContractError(
                "operational list count differs from its declared total"
            )
        if (
            len({item.platform_waybill_id for item in items}) != len(items)
            or len({item.waybill_number for item in items}) != len(items)
        ):
            raise OperationalCaptureContractError(
                "operational list contains duplicate identities"
            )
        detail_concurrency, image_concurrency = self._concurrency_provider()
        return self._store.freeze_operational_run(
            job_id=invocation.job_id,
            scope=invocation.scope,
            items=tuple(items),
            capture_mode=self._capture_mode,
            batch_size=self._capture_unit_size(len(items)),
            detail_concurrency=detail_concurrency,
            image_concurrency=image_concurrency,
            authority=authority,
        )

    def _batch_checkpoint(
        self,
        *,
        invocation: OperationalCaptureInvocation,
        run: OperationalCaptureRun,
        authority: BrowserCommandAuthority,
    ) -> tuple[
        DurableCaptureCheckpoint,
        tuple[DownloadedTicketImage, ...],
        dict[str, str],
    ]:
        start = run.next_item_index
        summaries = run.items[start : start + run.batch_size]
        if not summaries:
            raise OperationalCaptureContractError(
                "operational batch has no remaining identities"
            )
        evidence = self._read_batch(
            job_id=invocation.job_id,
            completed_before=start,
            total=run.total,
            summaries=tuple(summaries),
            authority=authority,
            detail_concurrency=run.detail_concurrency,
            image_concurrency=run.image_concurrency,
        )
        details: list[WaybillDetail] = []
        images: list[DownloadedTicketImage] = []
        source_revisions: dict[str, str] = {}
        for summary, item in zip(summaries, evidence, strict=True):
            detail = self._detail_normalizer(summary, item.detail)
            if not self._summary_matches_detail(summary, detail):
                raise OperationalCaptureContractError(
                    "operational detail changed frozen identity"
                )
            slots = {ticket.slot for ticket in detail.tickets}
            if (
                not slots.issubset({"loading", "unloading"})
                or len(slots) != len(detail.tickets)
                or len(detail.tickets) > 2
            ):
                raise OperationalCaptureContractError(
                    "operational detail has invalid ticket slots"
                )
            details.append(detail)
            if item.source_revision_sha256 is not None:
                source_revisions[
                    summary.platform_waybill_id
                ] = item.source_revision_sha256
            image_by_ref = {
                image.ticket_ref: image for image in item.images
            }
            if len(image_by_ref) != len(item.images):
                raise OperationalCaptureContractError(
                    "operational batch contains duplicate image identities"
                )
            if set(image_by_ref) != {
                ticket.ticket_ref for ticket in detail.tickets
            }:
                raise OperationalCaptureContractError(
                    "operational batch image references are incomplete"
                )
            for ticket in detail.tickets:
                try:
                    image = image_by_ref[ticket.ticket_ref]
                except KeyError as exc:
                    raise OperationalCaptureContractError(
                        "operational batch image is missing"
                    ) from exc
                if (
                    image.ticket_ref != ticket.ticket_ref
                    or ticket.media_type
                    not in {
                        "application/octet-stream",
                        image.media_type,
                    }
                ):
                    raise OperationalCaptureContractError(
                        "operational image changed ticket identity"
                    )
                images.append(image)
        batch_number = run.committed_batch_count + 1
        checkpoint = DurableCaptureCheckpoint(
            schema_version=CHECKPOINT_SCHEMA_VERSION,
            capture_id=self._store.capture_id(
                job_id=invocation.job_id,
                scope=invocation.scope,
                page_number=batch_number,
                page_size=run.batch_size,
            ),
            job_id=invocation.job_id,
            scope=invocation.scope,
            page_number=batch_number,
            page_size=run.batch_size,
            stage=ChengfengStage.IMAGE_DOWNLOAD,
            revision=0,
            completed_list=True,
            completed_detail_ids=tuple(
                detail.platform_waybill_id for detail in details
            ),
            ticket_images={},
            read_access_window_ids={},
            detail_capability_worker_ids={
                detail.platform_waybill_id: (
                    self._adapter.ticket_capability_authority_id
                )
                for detail in details
            },
            detail_capability_access_window_ids={
                detail.platform_waybill_id: invocation.access_window_id
                for detail in details
            },
            page=WaybillPage(
                page_number=batch_number,
                page_size=run.batch_size,
                total=run.total,
                items=tuple(summaries),
            ),
            details=tuple(details),
        )
        return checkpoint, tuple(images), source_revisions

    def _read_batch(
        self,
        *,
        job_id: str,
        completed_before: int,
        total: int,
        summaries: tuple[WaybillSummary, ...],
        authority: BrowserCommandAuthority,
        detail_concurrency: int,
        image_concurrency: int,
    ) -> tuple[OperationalWaybillEvidence, ...]:
        reader_name = (
            "read_waybill_whole_run"
            if self._capture_mode == WHOLE_RUN_CAPTURE_MODE
            else "read_waybill_batch"
        )
        batch_reader = getattr(self._adapter, reader_name, None)
        if not callable(batch_reader) and self._capture_mode == WHOLE_RUN_CAPTURE_MODE:
            batch_reader = getattr(self._adapter, "read_waybill_batch", None)
        if not callable(batch_reader):
            evidence: list[OperationalWaybillEvidence] = []
            for summary in summaries:
                self._authorize(authority)
                detail = self._adapter.get_waybill_detail(
                    authority=authority,
                    platform_waybill_id=(
                        summary.platform_waybill_id
                    ),
                )
                self._authorize(authority)
                images = tuple(
                    self._adapter.download_ticket_image(
                        authority=authority,
                        ticket_ref=ticket.ticket_ref,
                    )
                    for ticket in detail.tickets
                )
                self._authorize(authority)
                evidence.append(
                    OperationalWaybillEvidence(
                        detail=detail,
                        images=images,
                    )
                )
            return tuple(evidence)
        attempts = (
            ((detail_concurrency, image_concurrency),)
            if self._capture_mode == WHOLE_RUN_CAPTURE_MODE
            else (
                (detail_concurrency, image_concurrency),
                (min(detail_concurrency, 2), min(image_concurrency, 3)),
                (1, 1),
            )
        )
        last_error: TransientNetworkError | None = None
        progress_sink = self._progress_sink
        for detail_limit, image_limit in attempts:
            self._authorize(authority)
            try:
                kwargs: dict[str, object] = {
                    "authority": authority,
                    "summaries": summaries,
                    "detail_concurrency": detail_limit,
                    "image_concurrency": image_limit,
                }
                supported_parameters = inspect.signature(batch_reader).parameters
                if "active_job_id" in supported_parameters:
                    kwargs["active_job_id"] = job_id
                if progress_sink is not None and "progress_callback" in supported_parameters:
                    def on_progress(
                        phase: str,
                        completed: int,
                        _batch_total: int,
                    ) -> None:
                        multiplier = 2 if phase == "image" else 1
                        progress_sink(
                            job_id,
                            phase,
                            min(
                                total * multiplier,
                                completed_before * multiplier + completed,
                            ),
                            total * multiplier,
                        )

                    kwargs["progress_callback"] = on_progress
                result = batch_reader(
                    **kwargs,
                )
                self._authorize(authority)
            except TransientNetworkError as exc:
                last_error = exc
                continue
            if (
                not isinstance(result, tuple)
                or len(result) != len(summaries)
                or any(
                    not isinstance(item, OperationalWaybillEvidence)
                    for item in result
                )
            ):
                raise OperationalCaptureContractError(
                    "operational batch result is invalid"
                )
            return result
        assert last_error is not None
        raise last_error

    def _completed_checkpoints(
        self,
        run: OperationalCaptureRun,
    ) -> tuple[DurableCaptureCheckpoint, ...]:
        expected_batches = max(
            1,
            (run.total + run.batch_size - 1) // run.batch_size,
        )
        checkpoints: list[DurableCaptureCheckpoint] = []
        for batch_number in range(1, expected_batches + 1):
            checkpoint = self._store.load(
                job_id=run.job_id,
                scope=run.scope,
                page_number=batch_number,
                page_size=run.batch_size,
            )
            if checkpoint is None:
                raise OperationalCaptureContractError(
                    "operational batch sequence is incomplete"
                )
            checkpoints.append(checkpoint)
        return _validated_checkpoints(tuple(checkpoints))

    def advance(
        self,
        *,
        invocation: OperationalCaptureInvocation,
        authority: BrowserCommandAuthority,
    ) -> OperationalCaptureStepResult:
        if invocation.status != "collecting":
            raise OperationalCaptureContractError(
                "fast operational capture is unavailable"
            )
        run = self._store.load_operational_run(job_id=invocation.job_id)
        if run is None:
            run = self._freeze_list(
                invocation=invocation,
                authority=authority,
            )
            if run.total > 0 and run.capture_mode != WHOLE_RUN_CAPTURE_MODE:
                return OperationalCaptureStepResult(
                    has_more=True,
                    platform_read_performed=True,
                    checkpoint_revision=run.record_version,
                    capture_sha256=None,
                )
        committed_checkpoint: DurableCaptureCheckpoint | None = None
        if run.total == 0 and run.status != "complete":
            empty_checkpoint = DurableCaptureCheckpoint(
                schema_version=CHECKPOINT_SCHEMA_VERSION,
                capture_id=self._store.capture_id(
                    job_id=invocation.job_id,
                    scope=invocation.scope,
                    page_number=1,
                    page_size=run.batch_size,
                ),
                job_id=invocation.job_id,
                scope=invocation.scope,
                page_number=1,
                page_size=run.batch_size,
                stage=ChengfengStage.IMAGE_DOWNLOAD,
                revision=0,
                completed_list=True,
                completed_detail_ids=(),
                ticket_images={},
                page=WaybillPage(
                    page_number=1,
                    page_size=run.batch_size,
                    total=0,
                    items=(),
                ),
                details=(),
            )
            run, committed_checkpoint = (
                self._store.commit_operational_batch(
                run=run,
                checkpoint=empty_checkpoint,
                    images=(),
                    authority=authority,
                    access_window_id=invocation.access_window_id,
                    source_revisions={},
                )
            )
        elif run.status != "complete":
            checkpoint, images, source_revisions = self._batch_checkpoint(
                invocation=invocation,
                run=run,
                authority=authority,
            )
            run, committed_checkpoint = (
                self._store.commit_operational_batch(
                run=run,
                checkpoint=checkpoint,
                    images=images,
                    authority=authority,
                    access_window_id=invocation.access_window_id,
                    source_revisions=source_revisions,
                )
            )
        if run.status != "complete":
            return OperationalCaptureStepResult(
                has_more=True,
                platform_read_performed=True,
                checkpoint_revision=run.record_version,
                capture_sha256=None,
                checkpoints=(
                    ()
                    if committed_checkpoint is None
                    else (committed_checkpoint,)
                ),
            )
        checkpoints = self._completed_checkpoints(run)
        return OperationalCaptureStepResult(
            has_more=False,
            platform_read_performed=True,
            checkpoint_revision=run.record_version,
            capture_sha256=operational_capture_sha256(checkpoints),
            checkpoints=checkpoints,
        )


class OperationalSettlementCaptureCoordinator:
    """Advance one compatible page quantum without formal Loop 9 selection."""

    def __init__(
        self,
        *,
        durable_coordinator: DurableChengfengCaptureCoordinator,
        checkpoint_store: DurableCaptureCheckpointStore,
    ) -> None:
        self._durable = durable_coordinator
        self._checkpoints = checkpoint_store

    @staticmethod
    def _complete(
        checkpoint: DurableCaptureCheckpoint | None,
    ) -> bool:
        if checkpoint is None or checkpoint.page is None:
            return False
        if len(checkpoint.details) != len(checkpoint.page.items):
            return False
        expected_refs = {
            ticket.ticket_ref
            for detail in checkpoint.details
            for ticket in detail.tickets
        }
        return set(checkpoint.ticket_images) == expected_refs

    def _load(
        self,
        invocation: OperationalCaptureInvocation,
        page_number: int,
    ) -> DurableCaptureCheckpoint | None:
        return self._checkpoints.load(
            job_id=invocation.job_id,
            scope=invocation.scope,
            page_number=page_number,
            page_size=invocation.page_size,
        )

    def _collected(
        self,
        invocation: OperationalCaptureInvocation,
    ) -> tuple[
        int,
        int | None,
        tuple[DurableCaptureCheckpoint, ...] | None,
    ]:
        first = self._load(invocation, 1)
        if not self._complete(first):
            return (
                1,
                None if first is None else first.revision,
                None,
            )
        assert first is not None
        assert first.page is not None
        expected_pages = max(
            1,
            (
                first.page.total
                + invocation.page_size
                - 1
            )
            // invocation.page_size,
        )
        completed = [first]
        latest_revision = first.revision
        for page_number in range(2, expected_pages + 1):
            checkpoint = self._load(invocation, page_number)
            if checkpoint is not None:
                latest_revision = max(
                    latest_revision,
                    checkpoint.revision,
                )
            if not self._complete(checkpoint):
                return page_number, latest_revision, None
            assert checkpoint is not None
            completed.append(checkpoint)
        return expected_pages + 1, latest_revision, tuple(completed)

    def advance(
        self,
        *,
        invocation: OperationalCaptureInvocation,
        authority: BrowserCommandAuthority,
    ) -> OperationalCaptureStepResult:
        if invocation.status == "operational_ready":
            raise OperationalCaptureContractError(
                "operational capture is already complete"
            )
        if invocation.status != "collecting":
            raise OperationalCaptureContractError(
                "operational capture is unavailable"
            )
        page_number, previous_revision, completed = self._collected(
            invocation
        )
        if completed is not None:
            return OperationalCaptureStepResult(
                has_more=False,
                platform_read_performed=False,
                checkpoint_revision=previous_revision,
                capture_sha256=operational_capture_sha256(completed),
                checkpoints=completed,
            )
        step = self._durable.advance(
            authority=authority,
            scope=invocation.scope,
            page_number=page_number,
            page_size=invocation.page_size,
            access_window_id=invocation.access_window_id,
        )
        next_page, latest_revision, completed = self._collected(
            invocation
        )
        _ = next_page
        if completed is None:
            return OperationalCaptureStepResult(
                has_more=True,
                platform_read_performed=step.platform_read_performed,
                checkpoint_revision=(
                    step.checkpoint.revision
                    if step.checkpoint.revision > 0
                    else latest_revision
                ),
                capture_sha256=None,
            )
        return OperationalCaptureStepResult(
            has_more=False,
            platform_read_performed=step.platform_read_performed,
            checkpoint_revision=max(
                step.checkpoint.revision,
                latest_revision or 0,
            ),
            capture_sha256=operational_capture_sha256(completed),
            checkpoints=completed,
        )


def operational_capture_sha256(
    checkpoints: Sequence[DurableCaptureCheckpoint],
) -> str:
    ordered = _validated_checkpoints(checkpoints)
    return _canonical_sha256(
        {
            "kind": "chengfeng_operational_capture",
            "schema_version": 1,
            "pages": [
                {
                    "page_number": checkpoint.page_number,
                    "page_size": checkpoint.page_size,
                    "total": checkpoint.page.total,  # type: ignore[union-attr]
                    "items": [
                        {
                            "platform_waybill_id": detail.platform_waybill_id,
                            "waybill_number": detail.waybill_number,
                            "vehicle_number": detail.vehicle_number,
                            "loading_net": detail.loading_net,
                            "unloading_net": detail.unloading_net,
                            "tickets": [
                                {
                                    "slot": ticket.slot,
                                    "sha256": checkpoint.ticket_images[
                                        ticket.ticket_ref
                                    ].sha256,
                                }
                                for ticket in detail.tickets
                            ],
                        }
                        for detail in checkpoint.details
                    ],
                }
                for checkpoint in ordered
            ],
        }
    )


def scheduled_job_from_operational_checkpoints(
    *,
    checkpoints: Sequence[DurableCaptureCheckpoint],
    pipeline_fingerprint: str,
) -> ScheduledJobSpec:
    ordered = _validated_checkpoints(checkpoints)
    if (
        len(pipeline_fingerprint) != 64
        or pipeline_fingerprint != pipeline_fingerprint.lower()
        or any(
            character not in "0123456789abcdef"
            for character in pipeline_fingerprint
        )
    ):
        raise OperationalCaptureContractError(
            "operational OCR pipeline identity is invalid"
        )
    items: list[ScheduledWorkItemSpec] = []
    for checkpoint in ordered:
        for detail in checkpoint.details:
            tickets = {ticket.slot: ticket for ticket in detail.tickets}
            loading_ticket = tickets.get("loading")
            unloading_ticket = tickets.get("unloading")
            loading = (
                None
                if loading_ticket is None
                else checkpoint.ticket_images[
                    loading_ticket.ticket_ref
                ]
            )
            unloading = (
                None
                if unloading_ticket is None
                else checkpoint.ticket_images[
                    unloading_ticket.ticket_ref
                ]
            )
            missing_ticket = loading is None or unloading is None
            items.append(
                ScheduledWorkItemSpec(
                    item_key=detail.waybill_number,
                    expected_outcome=(
                        "awaiting_review" if missing_ticket else None
                    ),
                    review_reason=(
                        "missing_ticket" if missing_ticket else None
                    ),
                    loading_image_sha256=(
                        None if loading is None else loading.sha256
                    ),
                    unloading_image_sha256=(
                        None if unloading is None else unloading.sha256
                    ),
                    loading_image_relative_path=(
                        None
                        if loading is None
                        else f"evidence/{loading.relative_path}"
                    ),
                    unloading_image_relative_path=(
                        None
                        if unloading is None
                        else f"evidence/{unloading.relative_path}"
                    ),
                    vehicle_number=detail.vehicle_number,
                    platform_loading_net=detail.loading_net,
                    platform_unloading_net=detail.unloading_net,
                    evidence_preloaded=True,
                )
            )
    capture_sha256 = operational_capture_sha256(ordered)
    return ScheduledJobSpec(
        fixture_id=f"chengfeng-operational:{capture_sha256}",
        job_kind="business",
        task_type="audit",
        scope_label="成丰待结算",
        conflict_key=f"audit:chengfeng-operational:{capture_sha256}",
        items=tuple(items),
        pipeline_fingerprint=pipeline_fingerprint,
        ocr_execution_mode="local",
        run_mode="operational",
    )


def scheduled_job_from_operational_batch(
    *,
    checkpoint: DurableCaptureCheckpoint,
    pipeline_fingerprint: str,
) -> ScheduledJobSpec:
    if checkpoint.page is None:
        raise OperationalCaptureContractError(
            "operational batch has no frozen page"
        )
    normalized = replace(
        checkpoint,
        page_number=1,
        page=WaybillPage(
            page_number=1,
            page_size=checkpoint.page_size,
            total=len(checkpoint.page.items),
            items=checkpoint.page.items,
        ),
    )
    return scheduled_job_from_operational_checkpoints(
        checkpoints=(normalized,),
        pipeline_fingerprint=pipeline_fingerprint,
    )


def scheduled_whole_run_review_job(
    *,
    checkpoint: DurableCaptureCheckpoint,
    pipeline_fingerprint: str,
    source_job_id: str,
    business_kind: Literal["settlement", "daily"],
    scope_label: str,
) -> ScheduledJobSpec:
    """Bind one offline review job to one atomic platform capture."""
    if len(source_job_id) != 32:
        raise OperationalCaptureContractError("whole-run source job id is invalid")
    base = scheduled_job_from_operational_batch(
        checkpoint=checkpoint,
        pipeline_fingerprint=pipeline_fingerprint,
    )
    return replace(
        base,
        fixture_id=f"{business_kind}-whole-run:{source_job_id}",
        job_kind="business" if business_kind == "settlement" else "observation",
        scope_label=scope_label,
        conflict_key=f"{business_kind}-ocr:{source_job_id}:whole",
    )


def load_complete_operational_checkpoints(
    *,
    checkpoint_store: DurableCaptureCheckpointStore,
    job_id: str,
    scope: str,
    page_size: int,
) -> tuple[DurableCaptureCheckpoint, ...]:
    first = checkpoint_store.load(
        job_id=job_id,
        scope=scope,
        page_number=1,
        page_size=page_size,
    )
    if first is None or first.page is None:
        raise OperationalCaptureContractError(
            "operational capture first page is unavailable"
        )
    expected_pages = max(
        1,
        (first.page.total + page_size - 1) // page_size,
    )
    checkpoints: list[DurableCaptureCheckpoint] = []
    for page_number in range(1, expected_pages + 1):
        checkpoint = checkpoint_store.load(
            job_id=job_id,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )
        if checkpoint is None:
            raise OperationalCaptureContractError(
                "operational capture pagination is incomplete"
            )
        checkpoints.append(checkpoint)
    return _validated_checkpoints(tuple(checkpoints))
