from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text, update
from sqlalchemy.engine import Connection

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
    StoredEvidence,
)
from dahe.adapters.sqlite.browser_control import authorize_navigation_in_transaction
from dahe.adapters.sqlite.loop3_support import next_sequence
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    CHECKPOINTS,
    OPERATIONAL_CAPTURE_RUNS,
    OPERATIONAL_EVIDENCE_REUSE,
    OUTBOX,
)
from dahe.application.chengfeng.durable_capture import (
    CaptureCheckpointError,
    CaptureInvocationMismatchError,
    DurableCaptureCheckpoint,
    PersistedTicketImage,
    capture_detail_refresh_read_key,
    capture_read_key,
)
from dahe.application.chengfeng.operational_capture import (
    OperationalCaptureRun,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    ChengfengStage,
    DownloadedTicketImage,
    TicketImageReuseCandidate,
    WaybillDetail,
    WaybillReuseCandidate,
    WaybillSummary,
)

_OWNER_KIND = "chengfeng_capture"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _operational_items_payload(
    items: tuple[WaybillSummary, ...],
) -> list[dict[str, str | None]]:
    return [
        {
            "platform_waybill_id": item.platform_waybill_id,
            "vehicle_number": item.vehicle_number,
            "waybill_number": item.waybill_number,
        }
        for item in items
    ]


def _operational_items_json(
    items: tuple[WaybillSummary, ...],
) -> str:
    return json.dumps(
        _operational_items_payload(items),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _operational_run(row: object) -> OperationalCaptureRun:
    mapping = row
    try:
        raw_items = json.loads(str(mapping["items_json"]))  # type: ignore[index]
    except (TypeError, json.JSONDecodeError, KeyError) as exc:
        raise CaptureCheckpointError(
            "operational list manifest is invalid"
        ) from exc
    if not isinstance(raw_items, list):
        raise CaptureCheckpointError(
            "operational list manifest must be a list"
        )
    items: list[WaybillSummary] = []
    for raw in raw_items:
        if not isinstance(raw, dict) or set(raw) != {
            "platform_waybill_id",
            "vehicle_number",
            "waybill_number",
        }:
            raise CaptureCheckpointError(
                "operational list item is invalid"
            )
        platform_id = raw["platform_waybill_id"]
        waybill_number = raw["waybill_number"]
        vehicle_number = raw["vehicle_number"]
        if (
            not isinstance(platform_id, str)
            or not platform_id
            or not isinstance(waybill_number, str)
            or not waybill_number
            or (
                vehicle_number is not None
                and not isinstance(vehicle_number, str)
            )
        ):
            raise CaptureCheckpointError(
                "operational list identity is invalid"
            )
        items.append(
            WaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=vehicle_number,
            )
        )
    canonical = _operational_items_json(tuple(items))
    if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != str(
        mapping["items_sha256"]  # type: ignore[index]
    ):
        raise CaptureCheckpointError(
            "operational list manifest hash changed"
        )
    return OperationalCaptureRun(
        job_id=str(mapping["job_id"]),  # type: ignore[index]
        scope=str(mapping["scope"]),  # type: ignore[index]
        total=int(mapping["total"]),  # type: ignore[index]
        items=tuple(items),
        next_item_index=int(mapping["next_item_index"]),  # type: ignore[index]
        committed_batch_count=int(
            mapping["committed_batch_count"]  # type: ignore[index]
        ),
        batch_size=int(mapping["batch_size"]),  # type: ignore[index]
        detail_concurrency=int(
            mapping["detail_concurrency"]  # type: ignore[index]
        ),
        image_concurrency=int(
            mapping["image_concurrency"]  # type: ignore[index]
        ),
        status=str(mapping["status"]),  # type: ignore[index]
        record_version=int(mapping["record_version"]),  # type: ignore[index]
        metadata_checked_count=int(
            mapping["metadata_checked_count"]  # type: ignore[index]
        ),
        reused_count=int(mapping["reused_count"]),  # type: ignore[index]
        images_downloaded_count=int(
            mapping["images_downloaded_count"]  # type: ignore[index]
        ),
    )


class SqliteChengfengCaptureStore:
    """Append connector results to Loop 4 checkpoints and evidence tables."""

    def __init__(
        self,
        *,
        runtime: SqliteRuntime,
        evidence_store: ContentAddressedEvidenceStore,
        failpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.runtime = runtime
        self.evidence_store = evidence_store
        self._failpoint = failpoint

    @staticmethod
    def capture_id(
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> str:
        if not job_id or not scope or page_number < 1 or page_size < 1:
            raise ValueError("capture identity requires job, scope, and positive page values")
        encoded = json.dumps(
            {
                "job_id": job_id,
                "page_number": page_number,
                "page_size": page_size,
                "scope": scope,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def load(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None:
        return self.load_by_capture_id(
            capture_id=self.capture_id(
                job_id=job_id,
                scope=scope,
                page_number=page_number,
                page_size=page_size,
            ),
            job_id=job_id,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )

    def load_by_capture_id(
        self,
        *,
        capture_id: str,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None:
        with self.runtime.engine.connect() as connection:
            checkpoint = self._load_latest(connection, capture_id)
        if checkpoint is None:
            return None
        self._validate_invocation(
            checkpoint,
            capture_id=capture_id,
            job_id=job_id,
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )
        return checkpoint

    def commit_checkpoint(
        self,
        checkpoint: DurableCaptureCheckpoint,
        authority: BrowserCommandAuthority,
    ) -> DurableCaptureCheckpoint:
        self._validate_checkpoint_identity(checkpoint)
        self._validate_commit_authority(checkpoint, authority)
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            current = self._load_latest(connection, checkpoint.capture_id)
            self._validate_non_image_transition(current, checkpoint)
            self._authorize_commit(connection, authority)
            committed = replace(checkpoint, revision=checkpoint.revision + 1)
            self._insert_checkpoint(connection, committed)
            return committed

    def commit_image(
        self,
        checkpoint: DurableCaptureCheckpoint,
        image: DownloadedTicketImage,
        authority: BrowserCommandAuthority,
        *,
        access_window_id: str | None = None,
    ) -> DurableCaptureCheckpoint:
        self._validate_checkpoint_identity(checkpoint)
        self._validate_commit_authority(checkpoint, authority)
        if image.ticket_ref in checkpoint.ticket_images:
            raise CaptureCheckpointError("ticket image already has a committed checkpoint")
        if hashlib.sha256(image.content).hexdigest() != image.sha256:
            raise CaptureCheckpointError("downloaded image content does not match its SHA-256")
        expected_refs = {
            ticket.ticket_ref for detail in checkpoint.details for ticket in detail.tickets
        }
        if image.ticket_ref not in expected_refs:
            raise CaptureCheckpointError("downloaded image is absent from committed detail results")
        read_access_window_ids = dict(
            checkpoint.read_access_window_ids
        )
        if access_window_id is not None:
            if (
                not access_window_id
                or len(access_window_id) > 32
            ):
                raise CaptureCheckpointError(
                    "capture read access window is invalid"
                )
            if not read_access_window_ids:
                read_access_window_ids.update(
                    {
                        "list": access_window_id,
                        **{
                            capture_read_key(
                                ChengfengStage.DETAIL_QUERY,
                                detail.platform_waybill_id,
                            ): access_window_id
                            for detail in checkpoint.details
                        },
                    }
                )
            image_read_key = capture_read_key(
                ChengfengStage.IMAGE_DOWNLOAD,
                image.ticket_ref,
            )
            existing_access_window_id = (
                read_access_window_ids.get(image_read_key)
            )
            if (
                existing_access_window_id is not None
                and existing_access_window_id
                != access_window_id
            ):
                raise CaptureCheckpointError(
                    "capture read access binding cannot be replaced"
                )
            read_access_window_ids[
                image_read_key
            ] = access_window_id
        elif read_access_window_ids:
            raise CaptureCheckpointError(
                "capture read access window is required"
            )

        stored = self.evidence_store.put_bytes(
            image.content,
            media_type=image.media_type,
        )
        if stored.sha256 != image.sha256:
            raise CaptureCheckpointError("evidence store returned a different image identity")
        if self._failpoint is not None:
            self._failpoint("after_image_put")

        persisted = PersistedTicketImage(
            ticket_ref=image.ticket_ref,
            sha256=stored.sha256,
            relative_path=stored.relative_path,
            byte_size=stored.byte_size,
            media_type=stored.media_type,
        )
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            current = self._load_latest(connection, checkpoint.capture_id)
            self._validate_image_transition(current, checkpoint)
            self._authorize_commit(connection, authority)
            self._insert_blob(connection, stored)
            self._insert_image_reference(
                connection,
                checkpoint=checkpoint,
                persisted=persisted,
            )
            if self._failpoint is not None:
                self._failpoint("after_image_reference")
            committed = replace(
                checkpoint,
                revision=checkpoint.revision + 1,
                ticket_images={
                    **checkpoint.ticket_images,
                    image.ticket_ref: persisted,
                },
                read_access_window_ids=read_access_window_ids,
            )
            self._insert_checkpoint(connection, committed)
            return committed

    def read_image(self, image: PersistedTicketImage) -> bytes:
        expected_path = self.evidence_store.path_for(image.sha256)
        relative_path = expected_path.relative_to(self.evidence_store.root).as_posix()
        if relative_path != image.relative_path:
            raise CaptureCheckpointError("checkpoint image path disagrees with content identity")
        content = self.evidence_store.read_bytes(image.sha256)
        if len(content) != image.byte_size:
            raise CaptureCheckpointError("checkpoint image size disagrees with stored content")
        return content

    def load_operational_run(
        self,
        *,
        job_id: str,
    ) -> OperationalCaptureRun | None:
        with self.runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    select(OPERATIONAL_CAPTURE_RUNS).where(
                        OPERATIONAL_CAPTURE_RUNS.c.job_id == job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _operational_run(row)

    def latest_completed_operational_job_id(
        self,
        *,
        scope: str,
    ) -> str | None:
        """Return the latest completed run for one exact business scope."""

        if not scope:
            raise CaptureCheckpointError(
                "operational capture scope is required"
            )
        with self.runtime.engine.connect() as connection:
            job_id = connection.execute(
                select(OPERATIONAL_CAPTURE_RUNS.c.job_id)
                .where(
                    OPERATIONAL_CAPTURE_RUNS.c.scope == scope,
                    OPERATIONAL_CAPTURE_RUNS.c.status == "complete",
                )
                .order_by(OPERATIONAL_CAPTURE_RUNS.c.updated_at.desc())
                .limit(1)
            ).scalar_one_or_none()
        return None if job_id is None else str(job_id)

    def freeze_operational_run(
        self,
        *,
        job_id: str,
        scope: str,
        items: tuple[WaybillSummary, ...],
        batch_size: int,
        detail_concurrency: int,
        image_concurrency: int,
        authority: BrowserCommandAuthority,
    ) -> OperationalCaptureRun:
        if authority.job_id != job_id:
            raise CaptureInvocationMismatchError(
                "browser authority does not own the operational run"
            )
        if (
            not scope
            or batch_size not in {15, 20, 50, 100}
            or not 1 <= detail_concurrency <= 4
            or not 1 <= image_concurrency <= 6
            or len({item.platform_waybill_id for item in items})
            != len(items)
            or len({item.waybill_number for item in items}) != len(items)
        ):
            raise CaptureCheckpointError(
                "operational list freeze input is invalid"
            )
        items_json = _operational_items_json(items)
        items_sha256 = hashlib.sha256(
            items_json.encode("utf-8")
        ).hexdigest()
        timestamp = _utc_now()
        with self.runtime.commit_gate.transaction(
            self.runtime.engine
        ) as connection:
            replay = (
                connection.execute(
                    select(OPERATIONAL_CAPTURE_RUNS).where(
                        OPERATIONAL_CAPTURE_RUNS.c.job_id == job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                run = _operational_run(replay)
                if (
                    run.scope != scope
                    or run.items != items
                    or run.batch_size != batch_size
                    or run.detail_concurrency != detail_concurrency
                    or run.image_concurrency != image_concurrency
                ):
                    raise CaptureCheckpointError(
                        "operational list freeze conflicts with its replay"
                    )
                return run
            self._authorize_commit(connection, authority)
            connection.execute(
                OPERATIONAL_CAPTURE_RUNS.insert().values(
                    job_id=job_id,
                    scope=scope,
                    total=len(items),
                    items_json=items_json,
                    items_sha256=items_sha256,
                    next_item_index=0,
                    committed_batch_count=0,
                    batch_size=batch_size,
                    detail_concurrency=detail_concurrency,
                    image_concurrency=image_concurrency,
                    status="collecting",
                    record_version=1,
                    metadata_checked_count=0,
                    reused_count=0,
                    images_downloaded_count=0,
                    created_at=timestamp,
                    updated_at=timestamp,
                )
            )
            connection.execute(
                OUTBOX.insert().values(
                    event_type="settlement_capture.list_frozen",
                    aggregate_type="settlement_capture",
                    aggregate_id=job_id,
                    record_version=1,
                    payload_json=json.dumps(
                        {"total": len(items), "committed_batches": 0},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    created_at=timestamp,
                )
            )
            row = (
                connection.execute(
                    select(OPERATIONAL_CAPTURE_RUNS).where(
                        OPERATIONAL_CAPTURE_RUNS.c.job_id == job_id
                    )
                )
                .mappings()
                .one()
            )
            return _operational_run(row)

    def commit_operational_batch(
        self,
        *,
        run: OperationalCaptureRun,
        checkpoint: DurableCaptureCheckpoint,
        images: tuple[DownloadedTicketImage, ...],
        authority: BrowserCommandAuthority,
        access_window_id: str,
        source_revisions: dict[str, str],
    ) -> tuple[OperationalCaptureRun, DurableCaptureCheckpoint]:
        self._validate_checkpoint_identity(checkpoint)
        self._validate_commit_authority(checkpoint, authority)
        expected_batch = run.committed_batch_count + 1
        expected_items = run.items[
            run.next_item_index : run.next_item_index + run.batch_size
        ]
        if (
            run.status != "collecting"
            or checkpoint.page_number != expected_batch
            or checkpoint.page_size != run.batch_size
            or checkpoint.page is None
            or checkpoint.page.total != run.total
            or checkpoint.page.items != expected_items
            or len(checkpoint.details) != len(expected_items)
            or tuple(
                detail.platform_waybill_id
                for detail in checkpoint.details
            )
            != tuple(item.platform_waybill_id for item in expected_items)
            or not access_window_id
        ):
            raise CaptureCheckpointError(
                "operational batch does not continue the frozen run"
            )
        expected_refs = {
            ticket.ticket_ref
            for detail in checkpoint.details
            for ticket in detail.tickets
        }
        if (
            len(images) != len(expected_refs)
            or {image.ticket_ref for image in images} != expected_refs
        ):
            raise CaptureCheckpointError(
                "operational batch images are incomplete"
            )
        if not set(source_revisions).issubset(
            {detail.platform_waybill_id for detail in checkpoint.details}
        ) or any(
            len(value) != 64 for value in source_revisions.values()
        ):
            raise CaptureCheckpointError(
                "operational source revision input is invalid"
            )
        stored_images: list[tuple[DownloadedTicketImage, StoredEvidence]] = []
        for image in images:
            if image.reused_from_cache:
                if image.content or image.validator_sha256 is None:
                    raise CaptureCheckpointError(
                        "operational reused image metadata is invalid"
                    )
                try:
                    content = self.evidence_store.read_bytes(image.sha256)
                except Exception as exc:
                    raise CaptureCheckpointError(
                        "operational reused image evidence is unavailable"
                    ) from exc
            else:
                content = image.content
            if hashlib.sha256(content).hexdigest() != image.sha256:
                raise CaptureCheckpointError(
                    "operational image content hash changed"
                )
            stored = self.evidence_store.put_bytes(
                content,
                media_type=image.media_type,
            )
            if stored.sha256 != image.sha256:
                raise CaptureCheckpointError(
                    "evidence store changed operational image identity"
                )
            stored_images.append((image, stored))
        persisted = {
            image.ticket_ref: PersistedTicketImage(
                ticket_ref=image.ticket_ref,
                sha256=stored.sha256,
                relative_path=stored.relative_path,
                byte_size=stored.byte_size,
                media_type=stored.media_type,
            )
            for image, stored in stored_images
        }
        read_access = {
            "list": access_window_id,
            **{
                capture_read_key(
                    ChengfengStage.DETAIL_QUERY,
                    detail.platform_waybill_id,
                ): access_window_id
                for detail in checkpoint.details
            },
            **{
                capture_read_key(
                    ChengfengStage.IMAGE_DOWNLOAD,
                    image.ticket_ref,
                ): access_window_id
                for image in images
            },
        }
        committed = replace(
            checkpoint,
            revision=1,
            ticket_images=persisted,
            read_access_window_ids=read_access,
        )
        consumed = len(checkpoint.details)
        reused_details = sum(
            1
            for detail in checkpoint.details
            if detail.tickets
            and detail.platform_waybill_id in source_revisions
            and all(
                next(
                    image
                    for image in images
                    if image.ticket_ref == ticket.ticket_ref
                ).reused_from_cache
                for ticket in detail.tickets
            )
        )
        downloaded_images = sum(
            1 for image in images if not image.reused_from_cache
        )
        next_index = min(run.total, run.next_item_index + consumed)
        is_complete = next_index == run.total
        with self.runtime.commit_gate.transaction(
            self.runtime.engine
        ) as connection:
            current_run_row = (
                connection.execute(
                    select(OPERATIONAL_CAPTURE_RUNS).where(
                        OPERATIONAL_CAPTURE_RUNS.c.job_id == run.job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if current_run_row is None:
                raise CaptureCheckpointError(
                    "operational run disappeared before batch commit"
                )
            current_run = _operational_run(current_run_row)
            current_checkpoint = self._load_latest(
                connection,
                checkpoint.capture_id,
            )
            if current_run.record_version != run.record_version:
                if (
                    current_checkpoint is not None
                    and current_checkpoint.to_payload()
                    == committed.to_payload()
                    and current_run.committed_batch_count
                    >= expected_batch
                ):
                    return current_run, current_checkpoint
                raise CaptureCheckpointError(
                    "operational batch run version is stale"
                )
            if current_checkpoint is not None:
                raise CaptureCheckpointError(
                    "operational batch checkpoint already exists"
                )
            self._authorize_commit(connection, authority)
            for _, stored in stored_images:
                self._insert_blob(connection, stored)
            for persisted_image in persisted.values():
                self._insert_image_reference(
                    connection,
                    checkpoint=committed,
                    persisted=persisted_image,
                )
            self._insert_checkpoint(connection, committed)
            self._upsert_operational_reuse(
                connection,
                checkpoint=checkpoint,
                images=images,
                source_revisions=source_revisions,
            )
            updated = connection.execute(
                update(OPERATIONAL_CAPTURE_RUNS)
                .where(
                    OPERATIONAL_CAPTURE_RUNS.c.job_id == run.job_id,
                    OPERATIONAL_CAPTURE_RUNS.c.record_version
                    == run.record_version,
                )
                .values(
                    next_item_index=next_index,
                    committed_batch_count=expected_batch,
                    status="complete" if is_complete else "collecting",
                    record_version=run.record_version + 1,
                    metadata_checked_count=(
                        run.metadata_checked_count + consumed
                    ),
                    reused_count=run.reused_count + reused_details,
                    images_downloaded_count=(
                        run.images_downloaded_count + downloaded_images
                    ),
                    updated_at=_utc_now(),
                )
            )
            if updated.rowcount != 1:
                raise CaptureCheckpointError(
                    "operational batch progress changed concurrently"
                )
            connection.execute(
                OUTBOX.insert().values(
                    event_type=(
                        "settlement_capture.platform_read_complete"
                        if is_complete
                        else "settlement_capture.batch_committed"
                    ),
                    aggregate_type="settlement_capture",
                    aggregate_id=run.job_id,
                    record_version=run.record_version + 1,
                    payload_json=json.dumps(
                        {
                            "total": run.total,
                            "captured": next_index,
                            "images_downloaded": (
                                run.images_downloaded_count
                                + downloaded_images
                            ),
                            "committed_batches": expected_batch,
                            "platform_released": False,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    created_at=_utc_now(),
                )
            )
            row = (
                connection.execute(
                    select(OPERATIONAL_CAPTURE_RUNS).where(
                        OPERATIONAL_CAPTURE_RUNS.c.job_id == run.job_id
                    )
                )
                .mappings()
                .one()
            )
            return _operational_run(row), committed

    def load_reuse_candidates(
        self,
        *,
        summaries: tuple[WaybillSummary, ...],
    ) -> tuple[WaybillReuseCandidate, ...]:
        if not summaries:
            return ()
        identities = tuple(
            summary.platform_waybill_id for summary in summaries
        )
        with self.runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    select(OPERATIONAL_EVIDENCE_REUSE).where(
                        OPERATIONAL_EVIDENCE_REUSE.c.platform_waybill_id.in_(
                            identities
                        )
                    )
                )
                .mappings()
                .all()
            )
        by_id = {str(row["platform_waybill_id"]): row for row in rows}
        candidates: list[WaybillReuseCandidate] = []
        for identity in identities:
            row = by_id.get(identity)
            if row is None:
                continue
            images: list[TicketImageReuseCandidate] = []
            for slot in ("loading", "unloading"):
                sha256 = row[f"{slot}_sha256"]
                media_type = row[f"{slot}_media_type"]
                validator_sha256 = row[f"{slot}_validator_sha256"]
                if sha256 is None:
                    continue
                try:
                    self.evidence_store.read_bytes(str(sha256))
                except Exception:
                    images = []
                    break
                images.append(
                    TicketImageReuseCandidate(
                        slot=slot,
                        sha256=str(sha256),
                        media_type=str(media_type),
                        validator_sha256=str(validator_sha256),
                    )
                )
            if not images:
                continue
            candidates.append(
                WaybillReuseCandidate(
                    platform_waybill_id=identity,
                    source_revision_sha256=str(
                        row["source_revision_sha256"]
                    ),
                    images=tuple(images),
                )
            )
        return tuple(candidates)

    @staticmethod
    def _upsert_operational_reuse(
        connection: Connection,
        *,
        checkpoint: DurableCaptureCheckpoint,
        images: tuple[DownloadedTicketImage, ...],
        source_revisions: dict[str, str],
    ) -> None:
        image_by_ref = {image.ticket_ref: image for image in images}
        for detail in checkpoint.details:
            source_revision = source_revisions.get(
                detail.platform_waybill_id
            )
            if source_revision is None or not detail.tickets:
                continue
            payload: dict[str, object | None] = {
                "platform_waybill_id": detail.platform_waybill_id,
                "source_revision_sha256": source_revision,
                "loading_sha256": None,
                "loading_media_type": None,
                "loading_validator_sha256": None,
                "unloading_sha256": None,
                "unloading_media_type": None,
                "unloading_validator_sha256": None,
                "updated_at": _utc_now(),
            }
            complete = True
            for ticket in detail.tickets:
                image = image_by_ref[ticket.ticket_ref]
                if image.validator_sha256 is None:
                    complete = False
                    break
                payload[f"{ticket.slot}_sha256"] = image.sha256
                payload[f"{ticket.slot}_media_type"] = image.media_type
                payload[f"{ticket.slot}_validator_sha256"] = (
                    image.validator_sha256
                )
            if not complete:
                continue
            existing = connection.execute(
                select(
                    OPERATIONAL_EVIDENCE_REUSE.c.platform_waybill_id
                ).where(
                    OPERATIONAL_EVIDENCE_REUSE.c.platform_waybill_id
                    == detail.platform_waybill_id
                )
            ).one_or_none()
            if existing is None:
                connection.execute(
                    OPERATIONAL_EVIDENCE_REUSE.insert().values(**payload)
                )
            else:
                connection.execute(
                    update(OPERATIONAL_EVIDENCE_REUSE)
                    .where(
                        OPERATIONAL_EVIDENCE_REUSE.c.platform_waybill_id
                        == detail.platform_waybill_id
                    )
                    .values(**payload)
                )

    @staticmethod
    def _authorize_commit(
        connection: Connection,
        authority: BrowserCommandAuthority,
    ) -> None:
        authorize_navigation_in_transaction(
            connection,
            session_id=authority.session_id,
            instance_id=authority.instance_id,
            worker_id=authority.worker_id,
            job_id=authority.job_id,
            control_epoch=authority.control_epoch,
            fencing_token=authority.fencing_token,
        )

    @staticmethod
    def _validate_commit_authority(
        checkpoint: DurableCaptureCheckpoint,
        authority: BrowserCommandAuthority,
    ) -> None:
        if checkpoint.job_id != authority.job_id:
            raise CaptureInvocationMismatchError(
                "browser authority job does not own this capture checkpoint"
            )

    @staticmethod
    def _validate_invocation(
        checkpoint: DurableCaptureCheckpoint,
        *,
        capture_id: str,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> None:
        if (
            checkpoint.capture_id != capture_id
            or checkpoint.job_id != job_id
            or checkpoint.scope != scope
            or checkpoint.page_number != page_number
            or checkpoint.page_size != page_size
        ):
            raise CaptureInvocationMismatchError(
                "persisted capture input does not match this invocation"
            )

    def _validate_checkpoint_identity(
        self,
        checkpoint: DurableCaptureCheckpoint,
    ) -> None:
        expected = self.capture_id(
            job_id=checkpoint.job_id,
            scope=checkpoint.scope,
            page_number=checkpoint.page_number,
            page_size=checkpoint.page_size,
        )
        if checkpoint.capture_id != expected:
            raise CaptureInvocationMismatchError(
                "capture_id does not match its structured invocation"
            )

    @staticmethod
    def _same_identity(
        left: DurableCaptureCheckpoint,
        right: DurableCaptureCheckpoint,
    ) -> bool:
        return (
            left.capture_id == right.capture_id
            and left.job_id == right.job_id
            and left.scope == right.scope
            and left.page_number == right.page_number
            and left.page_size == right.page_size
            and left.schema_version == right.schema_version
        )

    @classmethod
    def _validate_current(
        cls,
        current: DurableCaptureCheckpoint | None,
        proposed: DurableCaptureCheckpoint,
    ) -> None:
        if current is None:
            if proposed.revision != 0:
                raise CaptureCheckpointError("first capture checkpoint has a stale revision")
            return
        if not cls._same_identity(current, proposed):
            raise CaptureInvocationMismatchError("capture checkpoint identity changed")
        if current.revision != proposed.revision:
            raise CaptureCheckpointError("capture checkpoint revision is stale")

    @staticmethod
    def _same_detail_business_evidence(
        current: WaybillDetail,
        proposed: WaybillDetail,
        *,
        committed_ticket_refs: set[str],
    ) -> bool:
        if (
            current.platform_waybill_id
            != proposed.platform_waybill_id
            or current.waybill_number != proposed.waybill_number
            or current.vehicle_number != proposed.vehicle_number
            or current.loading_net != proposed.loading_net
            or current.unloading_net != proposed.unloading_net
        ):
            return False
        current_by_slot = {
            ticket.slot: ticket for ticket in current.tickets
        }
        proposed_by_slot = {
            ticket.slot: ticket for ticket in proposed.tickets
        }
        if (
            len(current_by_slot) != len(current.tickets)
            or len(proposed_by_slot) != len(proposed.tickets)
            or set(current_by_slot) != set(proposed_by_slot)
            or tuple(
                ticket.slot for ticket in current.tickets
            )
            != tuple(
                ticket.slot for ticket in proposed.tickets
            )
        ):
            return False
        for slot, current_ticket in current_by_slot.items():
            proposed_ticket = proposed_by_slot[slot]
            if proposed_ticket.media_type != current_ticket.media_type:
                return False
            if (
                current_ticket.ticket_ref in committed_ticket_refs
                and proposed_ticket.ticket_ref
                != current_ticket.ticket_ref
            ):
                return False
        return True

    @classmethod
    def _is_detail_capability_refresh(
        cls,
        current: DurableCaptureCheckpoint,
        proposed: DurableCaptureCheckpoint,
    ) -> bool:
        if (
            proposed.stage is not ChengfengStage.DETAIL_QUERY
            or proposed.completed_detail_ids
            != current.completed_detail_ids
            or len(proposed.details) != len(current.details)
        ):
            return False
        current_worker_ids = dict(
            current.detail_capability_worker_ids
        )
        proposed_worker_ids = dict(
            proposed.detail_capability_worker_ids
        )
        changed_worker_ids = {
            platform_waybill_id
            for platform_waybill_id in (
                set(current_worker_ids) | set(proposed_worker_ids)
            )
            if current_worker_ids.get(platform_waybill_id)
            != proposed_worker_ids.get(platform_waybill_id)
        }
        current_access_ids = dict(
            current.detail_capability_access_window_ids
        )
        proposed_access_ids = dict(
            proposed.detail_capability_access_window_ids
        )
        changed_access_ids = {
            platform_waybill_id
            for platform_waybill_id in (
                set(current_access_ids) | set(proposed_access_ids)
            )
            if current_access_ids.get(platform_waybill_id)
            != proposed_access_ids.get(platform_waybill_id)
        }
        committed_ticket_refs = set(current.ticket_images)
        changed_detail_ids: set[str] = set()
        for current_detail, proposed_detail in zip(
            current.details,
            proposed.details,
            strict=True,
        ):
            if not cls._same_detail_business_evidence(
                current_detail,
                proposed_detail,
                committed_ticket_refs=committed_ticket_refs,
            ):
                return False
            if current_detail != proposed_detail:
                changed_detail_ids.add(
                    current_detail.platform_waybill_id
                )
        changed_ids = (
            changed_worker_ids
            | changed_access_ids
            | changed_detail_ids
        )
        if len(changed_ids) != 1:
            return False
        refreshed_id = next(iter(changed_ids))
        if (
            refreshed_id not in proposed_worker_ids
            or refreshed_id not in current.completed_detail_ids
        ):
            return False
        if any(
            current_access_ids.get(platform_waybill_id)
            != proposed_access_ids.get(platform_waybill_id)
            for platform_waybill_id in (
                (
                    set(current_access_ids)
                    | set(proposed_access_ids)
                )
                - {refreshed_id}
            )
        ):
            return False
        if changed_detail_ids - {refreshed_id}:
            return False
        proposed_refs = [
            ticket.ticket_ref
            for detail in proposed.details
            for ticket in detail.tickets
        ]
        return (
            len(proposed_refs) == len(set(proposed_refs))
            and cls._has_exact_detail_refresh_read_binding(
                current,
                proposed,
                refreshed_id=refreshed_id,
            )
        )

    @staticmethod
    def _has_exact_detail_refresh_read_binding(
        current: DurableCaptureCheckpoint,
        proposed: DurableCaptureCheckpoint,
        *,
        refreshed_id: str,
    ) -> bool:
        current_reads = dict(current.read_access_window_ids)
        proposed_reads = dict(proposed.read_access_window_ids)
        proposed_worker_id = (
            proposed.detail_capability_worker_ids.get(refreshed_id)
        )
        proposed_access_window_id = (
            proposed.detail_capability_access_window_ids.get(
                refreshed_id
            )
        )
        if (
            proposed_worker_id is None
            or proposed_access_window_id is None
        ):
            return (
                proposed_access_window_id is None
                and not current_reads
                and not proposed_reads
            )

        platform_digest = hashlib.sha256(
            refreshed_id.encode("utf-8")
        ).hexdigest()
        prefix = f"detail-refresh:{platform_digest}:"
        refresh_indexes: list[int] = []
        for key in current_reads:
            if not key.startswith(prefix):
                continue
            parts = key.split(":")
            if len(parts) != 5:
                return False
            try:
                refresh_indexes.append(int(parts[4]))
            except ValueError:
                return False
        if sorted(refresh_indexes) != list(
            range(1, len(refresh_indexes) + 1)
        ):
            return False
        expected_key = capture_detail_refresh_read_key(
            platform_waybill_id=refreshed_id,
            worker_id=proposed_worker_id,
            access_window_id=proposed_access_window_id,
            refresh_index=len(refresh_indexes) + 1,
        )
        if expected_key in current_reads:
            return False
        expected_reads = {
            **current_reads,
            expected_key: proposed_access_window_id,
        }
        return proposed_reads == expected_reads

    @classmethod
    def _validate_non_image_transition(
        cls,
        current: DurableCaptureCheckpoint | None,
        proposed: DurableCaptureCheckpoint,
    ) -> None:
        cls._validate_current(current, proposed)
        if current is None:
            if (
                proposed.stage is not ChengfengStage.BROWSER_START
                or proposed.page is not None
                or proposed.details
                or proposed.ticket_images
            ):
                raise CaptureCheckpointError("invalid initial capture checkpoint")
            return
        if proposed.ticket_images != current.ticket_images:
            raise CaptureCheckpointError("image results require commit_image")
        if any(
            proposed.read_access_window_ids.get(key) != value
            for key, value in current.read_access_window_ids.items()
        ):
            raise CaptureCheckpointError(
                "committed read access binding cannot be replaced"
            )
        if current.page is None and proposed.page is not None:
            if (
                proposed.stage is not ChengfengStage.LIST_QUERY
                or current.details
                or proposed.details
            ):
                raise CaptureCheckpointError("invalid list result transition")
            return
        if proposed.page != current.page:
            raise CaptureCheckpointError("committed list result cannot be replaced")
        removed_capability_ids = (
            set(current.detail_capability_worker_ids)
            - set(proposed.detail_capability_worker_ids)
        )
        if (
            proposed.stage is ChengfengStage.IMAGE_DOWNLOAD
            and proposed.details == current.details
            and len(removed_capability_ids) == 1
        ):
            invalidated_id = next(iter(removed_capability_ids))
            expected_worker_ids = dict(
                current.detail_capability_worker_ids
            )
            expected_worker_ids.pop(invalidated_id)
            expected_access_ids = dict(
                current.detail_capability_access_window_ids
            )
            expected_access_ids.pop(invalidated_id, None)
            if (
                dict(proposed.detail_capability_worker_ids)
                == expected_worker_ids
                and dict(
                    proposed.detail_capability_access_window_ids
                )
                == expected_access_ids
            ):
                return
        if cls._is_detail_capability_refresh(current, proposed):
            return
        if proposed.details != current.details:
            if (
                proposed.stage is not ChengfengStage.DETAIL_QUERY
                or len(proposed.details) != len(current.details) + 1
                or proposed.details[:-1] != current.details
            ):
                raise CaptureCheckpointError("invalid detail result transition")
            return
        raise CaptureCheckpointError("checkpoint has no valid atomic transition")

    @classmethod
    def _validate_image_transition(
        cls,
        current: DurableCaptureCheckpoint | None,
        proposed: DurableCaptureCheckpoint,
    ) -> None:
        cls._validate_current(current, proposed)
        if current is None:
            raise CaptureCheckpointError("image cannot precede capture state")
        if (
            proposed.stage is not ChengfengStage.IMAGE_DOWNLOAD
            or proposed.page != current.page
            or proposed.details != current.details
            or proposed.completed_detail_ids != current.completed_detail_ids
            or proposed.ticket_images != current.ticket_images
            or proposed.read_access_window_ids
            != current.read_access_window_ids
            or proposed.detail_capability_worker_ids
            != current.detail_capability_worker_ids
            or proposed.detail_capability_access_window_ids
            != current.detail_capability_access_window_ids
        ):
            raise CaptureCheckpointError("invalid image result transition")

    @staticmethod
    def _load_latest(
        connection: Connection,
        capture_id: str,
    ) -> DurableCaptureCheckpoint | None:
        payload_json = connection.execute(
            select(CHECKPOINTS.c.payload_json)
            .where(
                CHECKPOINTS.c.owner_kind == _OWNER_KIND,
                CHECKPOINTS.c.owner_id == capture_id,
            )
            .order_by(CHECKPOINTS.c.sequence.desc())
            .limit(1)
        ).scalar_one_or_none()
        if payload_json is None:
            return None
        try:
            payload = json.loads(str(payload_json))
        except (TypeError, json.JSONDecodeError) as exc:
            raise CaptureCheckpointError("capture checkpoint JSON is invalid") from exc
        return DurableCaptureCheckpoint.from_payload(payload)

    @staticmethod
    def _insert_checkpoint(
        connection: Connection,
        checkpoint: DurableCaptureCheckpoint,
    ) -> None:
        connection.execute(
            CHECKPOINTS.insert().values(
                checkpoint_id=uuid4().hex,
                owner_kind=_OWNER_KIND,
                owner_id=checkpoint.capture_id,
                job_id=checkpoint.job_id,
                work_item_id=None,
                stage=checkpoint.stage.value,
                sequence=next_sequence(connection),
                payload_json=json.dumps(
                    checkpoint.to_payload(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )

    @staticmethod
    def _insert_blob(
        connection: Connection,
        stored: StoredEvidence,
    ) -> None:
        now = _utc_now()
        connection.execute(
            text(
                "INSERT OR IGNORE INTO evidence_blobs "
                "(sha256, relative_path, byte_size, media_type, storage_state, "
                "record_version, created_at, verified_at) VALUES "
                "(:sha256, :relative_path, :byte_size, :media_type, 'available', "
                "1, :now, :now)"
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
            raise CaptureCheckpointError("existing evidence metadata conflicts with its SHA-256")

    @staticmethod
    def _reference_identity(
        checkpoint: DurableCaptureCheckpoint,
        ticket_ref: str,
    ) -> tuple[str, str]:
        ticket_hash = hashlib.sha256(ticket_ref.encode("utf-8")).hexdigest()
        owner_id = f"{checkpoint.capture_id[:32]}:{ticket_hash[:32]}"
        idempotency_key = f"chengfeng-capture:{checkpoint.capture_id}:{ticket_hash}"
        return owner_id, idempotency_key

    @classmethod
    def _insert_image_reference(
        cls,
        connection: Connection,
        *,
        checkpoint: DurableCaptureCheckpoint,
        persisted: PersistedTicketImage,
    ) -> None:
        owner_id, idempotency_key = cls._reference_identity(
            checkpoint,
            persisted.ticket_ref,
        )
        replay = (
            connection.execute(
                text(
                    "SELECT sha256, owner_kind, owner_id, role "
                    "FROM evidence_references WHERE idempotency_key = :key"
                ),
                {"key": idempotency_key},
            )
            .mappings()
            .one_or_none()
        )
        if replay is not None:
            if (
                str(replay["sha256"]) != persisted.sha256
                or str(replay["owner_kind"]) != _OWNER_KIND
                or str(replay["owner_id"]) != owner_id
                or str(replay["role"]) != "ticket_image"
            ):
                raise CaptureCheckpointError("image reference idempotency identity conflicts")
            return
        connection.execute(
            text(
                "INSERT INTO evidence_references "
                "(reference_id, sha256, snapshot_id, owner_kind, owner_id, role, "
                "idempotency_key, record_version, created_at) VALUES "
                "(:reference_id, :sha256, NULL, :owner_kind, :owner_id, "
                "'ticket_image', :idempotency_key, 1, :created_at)"
            ),
            {
                "reference_id": uuid4().hex,
                "sha256": persisted.sha256,
                "owner_kind": _OWNER_KIND,
                "owner_id": owner_id,
                "idempotency_key": idempotency_key,
                "created_at": _utc_now(),
            },
        )
        connection.execute(
            text(
                "UPDATE evidence_blobs SET record_version = record_version + 1 "
                "WHERE sha256 = :sha256"
            ),
            {"sha256": persisted.sha256},
        )
