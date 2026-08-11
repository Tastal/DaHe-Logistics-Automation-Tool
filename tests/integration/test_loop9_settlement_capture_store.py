from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from dahe import __version__
from dahe.adapters.sqlite.browser_control import BrowserControlStore
from dahe.adapters.sqlite.platform_access import (
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.recovery import PersistentRecoveryStore
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import CHECKPOINTS, JOBS
from dahe.adapters.sqlite.settlement_capture import (
    SettlementCaptureStoreConflictError,
    SqliteSettlementCaptureStore,
)
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    PersistedTicketImage,
    capture_detail_refresh_read_key,
    capture_read_key,
)
from dahe.application.chengfeng.settlement_capture import (
    LINEAGE_SCHEMA_VERSION,
    ProtectedBusinessIdentity,
    SettlementCaptureManifest,
    SettlementCaptureReadAccessBinding,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchImage,
    ShadowBatchItem,
    ShadowBatchSource,
)
from dahe.jobs.models import JobStatus, WorkItemStatus
from dahe.jobs.scheduler import CooperativeScheduler
from dahe.jobs.settlement_capture_execution import (
    SETTLEMENT_CAPTURE_STAGE,
    AsyncSettlementCaptureExecutionBackend,
    SettlementCaptureStageExecution,
    SettlementCaptureStageWork,
)
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.ports.chengfeng import (
    ChengfengStage,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)
from dahe.system.instance_lifecycle import data_root_identity
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
)

PROJECT_ROOT = Path(__file__).parents[2]
BUILD_SHA = "a" * 64
CONTRACT_CANONICAL_SHA = "b" * 64
CONTRACT_FILE_SHA = "c" * 64
CONTRACT_SELECTION_SHA = "d" * 64
IDENTITY_CONTEXT_SHA = "e" * 64
NOW = datetime.now(UTC).replace(microsecond=0)


def _runtime(tmp_path: Path) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="settlement-capture-test",
    )


def _fingerprint(sha256: str) -> ImagePerceptualFingerprint:
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=sha256,
        width=8,
        height=8,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop,
                average_hash="0" * 64,
                difference_hash="1" * 64,
            )
            for crop in (1000, 920, 840, 760)
        ),
    )


def _manifest(
    *,
    job_id: str,
    access_window_id: str,
    checkpoint_payload: dict[str, object],
) -> tuple[SettlementCaptureManifest, ProtectedBusinessIdentity]:
    images: list[ShadowBatchImage] = []
    for index, slot in enumerate(("loading", "unloading"), start=1):
        sha256 = f"{index:064x}"
        images.append(
            ShadowBatchImage(
                slot=slot,
                sha256=sha256,
                relative_path=(
                    f"sha256/{sha256[:2]}/{sha256[2:4]}/"
                    f"{sha256}.blob"
                ),
                byte_size=100,
                media_type="image/png",
                perceptual_fingerprint=_fingerprint(sha256),
            )
        )
    item = ShadowBatchItem(
        platform_waybill_id_digest="3" * 64,
        waybill_number_digest="4" * 64,
        vehicle_number_digest="5" * 64,
        platform_loading_net="32.10",
        platform_unloading_net="31.90",
        images=(images[0], images[1]),
    )
    checkpoint_sha = hashlib.sha256(
        json.dumps(
            checkpoint_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    manifest = SettlementCaptureManifest(
        source_build_sha256=BUILD_SHA,
        contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
        contract_file_sha256=CONTRACT_FILE_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        identity_context_sha256=IDENTITY_CONTEXT_SHA,
        sources=(
            ShadowBatchSource(
                access_window_id=access_window_id,
                job_id=job_id,
                capture_id="capture-page-one",
                scope="current",
                page_number=1,
                page_size=50,
                checkpoint_sha256=checkpoint_sha,
            ),
        ),
        items=(item,),
    )
    protected = ProtectedBusinessIdentity(
        item_identity_sha256=item.item_identity_sha256,
        platform_waybill_id="platform-real-1",
        waybill_number="CF-REAL-1",
        vehicle_number="陕A12345",
        source_page_number=1,
    )
    return manifest, protected


def _prepare(
    runtime: SqliteRuntime,
    *,
    job_id: str = "capture-job-001",
    create_job: bool = True,
) -> tuple[
    SqliteSettlementCaptureStore,
    SqlitePlatformAccessRepository,
    str,
    str,
    dict[str, object],
]:
    created_at = NOW.isoformat()
    if create_job:
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                JOBS.insert().values(
                    job_id=job_id,
                    task_type="settlement_capture",
                    scope_label="成丰待结算采集",
                    scope_fixture_id="chengfeng-pending-settlement",
                    scope_fingerprint="f" * 64,
                    run_mode="shadow",
                    status="queued",
                    current_stage="settlement_capture.read",
                    diagnostic_code=None,
                    job_kind="business",
                    ocr_execution_mode="fake",
                    conflict_key="settlement_capture:current",
                    created_sequence=1,
                    record_version=1,
                    created_at=created_at,
                    updated_at=created_at,
                )
            )
    access = SqlitePlatformAccessRepository(runtime)
    grant, _ = access.issue(
        purpose=AccessPurpose.FORMAL_LOCKED_SET,
        job_id=job_id,
        session_id="browser-session-1",
        build_sha256=BUILD_SHA,
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="shadow",
        idempotency_key="settlement-access-1",
        request_hash=hashlib.sha256(b"settlement-access-1").hexdigest(),
        now=NOW,
    )
    browser_control = BrowserControlStore(
        runtime.engine,
        runtime.commit_gate,
    )
    initial_control = browser_control.initialize(
        session_id="browser-session-1",
        now=NOW,
    )
    browser_control.mark_ready(
        session_id="browser-session-1",
        expected_record_version=initial_control.record_version,
        now=NOW,
    )
    store = SqliteSettlementCaptureStore(runtime)
    invocation = store.create(
        job_id=job_id,
        access_window_id=grant.access_window_id,
        source_build_sha256=BUILD_SHA,
        contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
        contract_file_sha256=CONTRACT_FILE_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        identity_context_sha256=IDENTITY_CONTEXT_SHA,
        now=NOW,
    )
    ticket_images = {
        "ticket-loading-1": PersistedTicketImage(
            ticket_ref="ticket-loading-1",
            sha256="1" * 64,
            relative_path=(
                "sha256/11/11/"
                f"{'1' * 64}.blob"
            ),
            byte_size=100,
            media_type="image/png",
        ),
        "ticket-unloading-1": PersistedTicketImage(
            ticket_ref="ticket-unloading-1",
            sha256="2" * 64,
            relative_path=(
                "sha256/22/22/"
                f"{'2' * 64}.blob"
            ),
            byte_size=100,
            media_type="image/png",
        ),
    }
    checkpoint = DurableCaptureCheckpoint(
        capture_id="capture-page-one",
        job_id=job_id,
        scope="current",
        page_number=1,
        page_size=50,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        revision=4,
        completed_list=True,
        completed_detail_ids=("platform-real-1",),
        ticket_images=ticket_images,
        page=WaybillPage(
            page_number=1,
            page_size=50,
            total=1,
            items=(
                WaybillSummary(
                    platform_waybill_id="platform-real-1",
                    waybill_number="CF-REAL-1",
                    vehicle_number="陕A12345",
                ),
            ),
        ),
        details=(
            WaybillDetail(
                platform_waybill_id="platform-real-1",
                waybill_number="CF-REAL-1",
                vehicle_number="陕A12345",
                loading_net="32.10",
                unloading_net="31.90",
                tickets=(
                    TicketReference(
                        slot="loading",
                        ticket_ref="ticket-loading-1",
                        media_type="image/png",
                    ),
                    TicketReference(
                        slot="unloading",
                        ticket_ref="ticket-unloading-1",
                        media_type="image/png",
                    ),
                ),
            ),
        ),
    )
    checkpoint_payload = checkpoint.to_payload()
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            CHECKPOINTS.insert().values(
                checkpoint_id="checkpoint-one",
                owner_kind="chengfeng_capture",
                owner_id="capture-page-one",
                job_id=None,
                work_item_id=None,
                stage="image_download",
                sequence=2,
                payload_json=json.dumps(
                    checkpoint_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
    return (
        store,
        access,
        invocation.invocation_id,
        grant.access_window_id,
        checkpoint_payload,
    )


class _SettlementCaptureExecutor:
    def __init__(
        self,
        *,
        fail_immediately: bool = False,
        wait_external: bool = False,
        waiting_diagnostic_code: str = (
            "CF-SETTLEMENT-ACCESS-WINDOW-EXPIRED"
        ),
    ) -> None:
        self.calls: list[SettlementCaptureStageWork] = []
        self.fail_immediately = fail_immediately
        self.wait_external = wait_external
        self.waiting_diagnostic_code = waiting_diagnostic_code
        self.store: SqliteSettlementCaptureStore | None = None
        self.invocation_id: str | None = None
        self.manifest: SettlementCaptureManifest | None = None
        self.protected: ProtectedBusinessIdentity | None = None

    def configure(
        self,
        *,
        store: SqliteSettlementCaptureStore,
        invocation_id: str,
        manifest: SettlementCaptureManifest,
        protected: ProtectedBusinessIdentity,
    ) -> None:
        self.store = store
        self.invocation_id = invocation_id
        self.manifest = manifest
        self.protected = protected

    def __call__(
        self,
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        self.calls.append(work)
        if self.fail_immediately:
            return SettlementCaptureStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="failed",
                completed_stage=work.stage,
                next_stage=None,
                platform_read_performed=False,
                checkpoint_revision=None,
                manifest_sha256=None,
                diagnostic_code="CF-SETTLEMENT-CAPTURE-TECHNICAL",
            )
        if self.wait_external:
            return SettlementCaptureStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="waiting_external",
                completed_stage=work.stage,
                next_stage=work.stage,
                platform_read_performed=False,
                checkpoint_revision=None,
                manifest_sha256=None,
                diagnostic_code=self.waiting_diagnostic_code,
            )
        existing_status = (
            None
            if self.store is None or self.invocation_id is None
            else self.store.get(self.invocation_id).status
        )
        if len(self.calls) == 1 and existing_status != "sealed":
            return SettlementCaptureStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="succeeded",
                completed_stage=work.stage,
                next_stage=SETTLEMENT_CAPTURE_STAGE,
                platform_read_performed=True,
                checkpoint_revision=4,
                manifest_sha256=None,
                diagnostic_code=None,
            )
        assert self.store is not None
        assert self.invocation_id is not None
        assert self.manifest is not None
        assert self.protected is not None
        current = self.store.get(self.invocation_id)
        if current.status == "collecting":
            current = self.store.seal(
                invocation_id=self.invocation_id,
                expected_record_version=current.record_version,
                manifest=self.manifest,
                protected_identities=(self.protected,),
                now=NOW + timedelta(minutes=1),
            )
        assert current.status == "sealed"
        selected = self.store.mark_selected(
            invocation_id=self.invocation_id,
            expected_record_version=current.record_version,
            selection_manifest_sha256="7" * 64,
            batch_manifest_sha256="8" * 64,
            now=NOW + timedelta(minutes=2),
        )
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="succeeded",
            completed_stage=work.stage,
            next_stage=None,
            platform_read_performed=(len(self.calls) > 1),
            checkpoint_revision=4,
            manifest_sha256=selected.manifest_sha256,
            selection_manifest_sha256=(
                selected.selection_manifest_sha256
            ),
            batch_manifest_sha256=selected.batch_manifest_sha256,
            diagnostic_code=None,
        )


def _tick_until_terminal(
    scheduler: CooperativeScheduler,
    repository: SqliteJobRepository,
    job_id: str,
) -> None:
    for _ in range(200):
        scheduler.tick()
        if repository.get_job(job_id).status.is_terminal:
            return
        time.sleep(0.002)
    raise AssertionError(
        "settlement capture scheduler did not reach a terminal state"
    )


def _register_scheduler_instance(
    runtime: SqliteRuntime,
    instance_id: str,
) -> None:
    PersistentRecoveryStore(
        runtime.engine,
        runtime.commit_gate,
    ).register_instance(
        instance_id=instance_id,
        data_root_identity=data_root_identity(runtime.data_root),
        pid=1,
        process_started_at=NOW.isoformat(),
        application_version=__version__,
        port=8877,
        now=NOW,
    )


def _create_capture_job(
    repository: SqliteJobRepository,
    *,
    suffix: str,
) -> str:
    job, created = repository.create_scheduled_job(
        fixture=ScheduledJobSpec(
            fixture_id=f"pending-settlement-{suffix}",
            job_kind="business",
            task_type="settlement_capture",
            scope_label="成丰待结算采集",
            conflict_key=f"settlement_capture:{suffix}",
            items=(
                ScheduledWorkItemSpec(
                    item_key=f"pending-settlement-{suffix}",
                    expected_outcome=None,
                    required_resource="platform_browser",
                ),
            ),
        ),
        scope_label="成丰待结算采集",
        idempotency_key=f"settlement-capture-create-{suffix}",
        request_hash=hashlib.sha256(
            f"settlement-capture-create-{suffix}".encode()
        ).hexdigest(),
        expected_record_version=0,
    )
    assert created is True
    assert job.current_stage == SETTLEMENT_CAPTURE_STAGE
    return job.job_id


def test_seal_atomically_consumes_window_and_keeps_raw_identity_protected(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        (
            store,
            access,
            invocation_id,
            access_window_id,
            checkpoint_payload,
        ) = _prepare(runtime)
        manifest, protected = _manifest(
            job_id="capture-job-001",
            access_window_id=access_window_id,
            checkpoint_payload=checkpoint_payload,
        )

        sealed = store.seal(
            invocation_id=invocation_id,
            expected_record_version=1,
            manifest=manifest,
            protected_identities=(protected,),
            now=NOW + timedelta(minutes=1),
        )
        replay = store.seal(
            invocation_id=invocation_id,
            expected_record_version=1,
            manifest=manifest,
            protected_identities=(protected,),
            now=NOW + timedelta(minutes=2),
        )

        assert sealed.status == "sealed"
        assert replay == sealed
        assert access.get(access_window_id).consumed_at == (
            NOW + timedelta(minutes=1)
        )
        assert store.load_manifest(
            invocation_id
        ).canonical_sha256 == manifest.canonical_sha256
        assert store.resolve_business_identities(
            invocation_id=invocation_id,
            item_identity_sha256s=(protected.item_identity_sha256,),
        ) == (protected,)
        outward = json.dumps(
            manifest.to_payload(),
            ensure_ascii=False,
            sort_keys=True,
        )
        assert "platform-real-1" not in outward
        assert "CF-REAL-1" not in outward
        assert "陕A12345" not in outward
    finally:
        runtime.close()


def test_sqlite_seal_rejects_tampered_cross_window_read_binding(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    rollover_at = NOW + timedelta(minutes=61)
    try:
        (
            store,
            access,
            invocation_id,
            original_window_id,
            checkpoint_payload,
        ) = _prepare(runtime)
        job_id = "capture-job-001"
        detail_key = capture_read_key(
            ChengfengStage.DETAIL_QUERY,
            "platform-real-1",
        )
        loading_key = capture_read_key(
            ChengfengStage.IMAGE_DOWNLOAD,
            "ticket-loading-1",
        )
        unloading_key = capture_read_key(
            ChengfengStage.IMAGE_DOWNLOAD,
            "ticket-unloading-1",
        )
        incomplete_payload = json.loads(
            json.dumps(checkpoint_payload)
        )
        incomplete_payload["revision"] = 3
        incomplete_payload["ticket_images"].pop(
            "ticket-unloading-1"
        )
        incomplete_payload["read_access_window_ids"] = {
            "list": original_window_id,
            detail_key: original_window_id,
            loading_key: original_window_id,
        }
        DurableCaptureCheckpoint.from_payload(incomplete_payload)
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                CHECKPOINTS.update()
                .where(CHECKPOINTS.c.checkpoint_id == "checkpoint-one")
                .values(
                    payload_json=json.dumps(
                        incomplete_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            )
            connection.execute(
                JOBS.update()
                .where(JOBS.c.job_id == job_id)
                .values(status="paused")
            )

        assert store.reconcile_terminal_or_expired_access(
            now=rollover_at
        ) == (job_id,)
        replacement, replayed = access.issue(
            purpose=AccessPurpose.FORMAL_LOCKED_SET,
            job_id=job_id,
            session_id="browser-session-1",
            build_sha256=BUILD_SHA,
            duration_minutes=60,
            legacy_idle_confirmed=True,
            no_settlement_or_payment_confirmed=True,
            same_account_session_risk_accepted=True,
            run_mode="shadow",
            idempotency_key="settlement-access-2",
            request_hash=hashlib.sha256(
                b"settlement-access-2"
            ).hexdigest(),
            now=rollover_at,
        )
        assert replayed is False
        browser = BrowserControlStore(
            runtime.engine,
            runtime.commit_gate,
        ).get("browser-session-1")
        invocation = store.get(invocation_id)
        rollover = store.rebind_access_window(
            job_id=job_id,
            new_access_window_id=replacement.access_window_id,
            expected_invocation_record_version=(
                invocation.record_version
            ),
            expected_browser_record_version=browser.record_version,
            session_id="browser-session-1",
            source_build_sha256=BUILD_SHA,
            contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
            contract_file_sha256=CONTRACT_FILE_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
            idempotency_key="settlement-access-rebind-2",
            request_hash=hashlib.sha256(
                b"settlement-access-rebind-2"
            ).hexdigest(),
            now=rollover_at,
        )

        final_payload = json.loads(json.dumps(checkpoint_payload))
        final_payload["read_access_window_ids"] = {
            "list": original_window_id,
            detail_key: original_window_id,
            loading_key: original_window_id,
            unloading_key: replacement.access_window_id,
        }
        DurableCaptureCheckpoint.from_payload(final_payload)
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                CHECKPOINTS.insert().values(
                    checkpoint_id="checkpoint-two",
                    owner_kind="chengfeng_capture",
                    owner_id="capture-page-one",
                    job_id=None,
                    work_item_id=None,
                    stage="image_download",
                    sequence=3,
                    payload_json=json.dumps(
                        final_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
            )

        legacy_manifest, protected = _manifest(
            job_id=job_id,
            access_window_id=original_window_id,
            checkpoint_payload=final_payload,
        )
        lineage = store.access_window_lineage(invocation_id)
        list_subject_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "capture_id": "capture-page-one",
                    "read_kind": "list",
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        bindings = (
            SettlementCaptureReadAccessBinding(
                capture_id="capture-page-one",
                read_kind="list",
                subject_sha256=list_subject_sha256,
                access_window_id=original_window_id,
            ),
            SettlementCaptureReadAccessBinding(
                capture_id="capture-page-one",
                read_kind="detail",
                subject_sha256=hashlib.sha256(
                    b"platform-real-1"
                ).hexdigest(),
                access_window_id=original_window_id,
            ),
            SettlementCaptureReadAccessBinding(
                capture_id="capture-page-one",
                read_kind="image",
                subject_sha256=hashlib.sha256(
                    b"ticket-loading-1"
                ).hexdigest(),
                access_window_id=replacement.access_window_id,
            ),
            SettlementCaptureReadAccessBinding(
                capture_id="capture-page-one",
                read_kind="image",
                subject_sha256=hashlib.sha256(
                    b"ticket-unloading-1"
                ).hexdigest(),
                access_window_id=replacement.access_window_id,
            ),
        )
        tampered_manifest = SettlementCaptureManifest(
            source_build_sha256=legacy_manifest.source_build_sha256,
            contract_canonical_sha256=(
                legacy_manifest.contract_canonical_sha256
            ),
            contract_file_sha256=legacy_manifest.contract_file_sha256,
            contract_selection_sha256=(
                legacy_manifest.contract_selection_sha256
            ),
            identity_context_sha256=(
                legacy_manifest.identity_context_sha256
            ),
            sources=legacy_manifest.sources,
            items=legacy_manifest.items,
            access_window_lineage=lineage,
            read_access_bindings=bindings,
            schema_version=LINEAGE_SCHEMA_VERSION,
        )

        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="read access lineage changed",
        ):
            store.seal(
                invocation_id=invocation_id,
                expected_record_version=(
                    rollover.invocation.record_version
                ),
                manifest=tampered_manifest,
                protected_identities=(protected,),
                now=rollover_at + timedelta(minutes=1),
            )
        assert access.get(replacement.access_window_id).consumed_at is None
    finally:
        runtime.close()


def test_seal_rejects_missing_checkpoint_without_consuming_window(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        (
            store,
            access,
            invocation_id,
            access_window_id,
            checkpoint_payload,
        ) = _prepare(runtime)
        manifest, protected = _manifest(
            job_id="capture-job-001",
            access_window_id=access_window_id,
            checkpoint_payload=checkpoint_payload,
        )
        changed_source = ShadowBatchSource(
            access_window_id=access_window_id,
            job_id="capture-job-001",
            capture_id="missing-capture-page",
            scope="current",
            page_number=1,
            page_size=50,
            checkpoint_sha256=manifest.sources[0].checkpoint_sha256,
        )
        changed = SettlementCaptureManifest(
            source_build_sha256=manifest.source_build_sha256,
            contract_canonical_sha256=manifest.contract_canonical_sha256,
            contract_file_sha256=manifest.contract_file_sha256,
            contract_selection_sha256=manifest.contract_selection_sha256,
            identity_context_sha256=manifest.identity_context_sha256,
            sources=(changed_source,),
            items=manifest.items,
        )

        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="checkpoint",
        ):
            store.seal(
                invocation_id=invocation_id,
                expected_record_version=1,
                manifest=changed,
                protected_identities=(protected,),
                now=NOW + timedelta(minutes=1),
            )
        assert access.get(access_window_id).consumed_at is None
    finally:
        runtime.close()


def test_seal_accepts_canonical_read_binding_order(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        (
            store,
            access,
            invocation_id,
            access_window_id,
            checkpoint_payload,
        ) = _prepare(runtime)
        lineage = store.access_window_lineage(invocation_id)
        checkpoint = DurableCaptureCheckpoint.from_payload(
            checkpoint_payload
        )
        detail_refresh_key = capture_detail_refresh_read_key(
            platform_waybill_id="platform-real-1",
            worker_id="worker-refresh-1",
            access_window_id=access_window_id,
            refresh_index=1,
        )
        checkpoint_payload["read_access_window_ids"] = {
            capture_read_key(ChengfengStage.LIST_QUERY): access_window_id,
            capture_read_key(
                ChengfengStage.DETAIL_QUERY,
                "platform-real-1",
            ): access_window_id,
            capture_read_key(
                ChengfengStage.IMAGE_DOWNLOAD,
                "ticket-loading-1",
            ): access_window_id,
            capture_read_key(
                ChengfengStage.IMAGE_DOWNLOAD,
                "ticket-unloading-1",
            ): access_window_id,
            detail_refresh_key: access_window_id,
        }
        checkpoint = DurableCaptureCheckpoint.from_payload(
            checkpoint_payload
        )
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                CHECKPOINTS.update()
                .where(CHECKPOINTS.c.checkpoint_id == "checkpoint-one")
                .values(
                    payload_json=json.dumps(
                        checkpoint_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            )
        legacy_manifest, protected = _manifest(
            job_id="capture-job-001",
            access_window_id=access_window_id,
            checkpoint_payload=checkpoint_payload,
        )
        list_subject_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "capture_id": checkpoint.capture_id,
                    "read_kind": "list",
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        bindings = tuple(
            sorted(
                (
                    SettlementCaptureReadAccessBinding(
                        capture_id=checkpoint.capture_id,
                        read_kind="list",
                        subject_sha256=list_subject_sha256,
                        access_window_id=access_window_id,
                    ),
                    SettlementCaptureReadAccessBinding(
                        capture_id=checkpoint.capture_id,
                        read_kind="detail",
                        subject_sha256=hashlib.sha256(
                            b"platform-real-1"
                        ).hexdigest(),
                        access_window_id=access_window_id,
                    ),
                    SettlementCaptureReadAccessBinding(
                        capture_id=checkpoint.capture_id,
                        read_kind="detail",
                        subject_sha256=hashlib.sha256(
                            detail_refresh_key.encode("utf-8")
                        ).hexdigest(),
                        access_window_id=access_window_id,
                    ),
                    SettlementCaptureReadAccessBinding(
                        capture_id=checkpoint.capture_id,
                        read_kind="image",
                        subject_sha256=hashlib.sha256(
                            b"ticket-loading-1"
                        ).hexdigest(),
                        access_window_id=access_window_id,
                    ),
                    SettlementCaptureReadAccessBinding(
                        capture_id=checkpoint.capture_id,
                        read_kind="image",
                        subject_sha256=hashlib.sha256(
                            b"ticket-unloading-1"
                        ).hexdigest(),
                        access_window_id=access_window_id,
                    ),
                ),
                key=lambda value: (
                    {"list": 0, "detail": 1, "image": 2}[
                        value.read_kind
                    ],
                    value.capture_id,
                    value.subject_sha256,
                ),
            )
        )
        manifest = SettlementCaptureManifest(
            source_build_sha256=legacy_manifest.source_build_sha256,
            contract_canonical_sha256=(
                legacy_manifest.contract_canonical_sha256
            ),
            contract_file_sha256=legacy_manifest.contract_file_sha256,
            contract_selection_sha256=(
                legacy_manifest.contract_selection_sha256
            ),
            identity_context_sha256=(
                legacy_manifest.identity_context_sha256
            ),
            sources=legacy_manifest.sources,
            items=legacy_manifest.items,
            access_window_lineage=lineage,
            read_access_bindings=bindings,
            schema_version=LINEAGE_SCHEMA_VERSION,
        )

        sealed = store.seal(
            invocation_id=invocation_id,
            expected_record_version=1,
            manifest=manifest,
            protected_identities=(protected,),
            now=NOW + timedelta(minutes=1),
        )

        assert sealed.status == "sealed"
        assert access.get(access_window_id).consumed_at is not None
    finally:
        runtime.close()


def test_seal_rejects_cross_build_and_expired_access(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        (
            store,
            access,
            invocation_id,
            access_window_id,
            checkpoint_payload,
        ) = _prepare(runtime)
        manifest, protected = _manifest(
            job_id="capture-job-001",
            access_window_id=access_window_id,
            checkpoint_payload=checkpoint_payload,
        )
        changed = SettlementCaptureManifest(
            source_build_sha256="0" * 64,
            contract_canonical_sha256=manifest.contract_canonical_sha256,
            contract_file_sha256=manifest.contract_file_sha256,
            contract_selection_sha256=manifest.contract_selection_sha256,
            identity_context_sha256=manifest.identity_context_sha256,
            sources=manifest.sources,
            items=manifest.items,
        )
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="authority",
        ):
            store.seal(
                invocation_id=invocation_id,
                expected_record_version=1,
                manifest=changed,
                protected_identities=(protected,),
                now=NOW + timedelta(minutes=1),
            )
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="expired",
        ):
            store.seal(
                invocation_id=invocation_id,
                expected_record_version=1,
                manifest=manifest,
                protected_identities=(protected,),
                now=NOW + timedelta(minutes=61),
            )
        assert access.get(access_window_id).consumed_at is None
    finally:
        runtime.close()


def test_scheduler_seals_capture_through_existing_browser_resource(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    _register_scheduler_instance(runtime, "settlement-capture-test")
    executor = _SettlementCaptureExecutor()
    backend = AsyncSettlementCaptureExecutionBackend(execute=executor)
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="settlement-capture-test",
        settlement_capture_execution_backend=backend,
    )
    try:
        job_id = _create_capture_job(repository, suffix="current")
        (
            store,
            access,
            invocation_id,
            access_window_id,
            checkpoint_payload,
        ) = _prepare(
            runtime,
            job_id=job_id,
            create_job=False,
        )
        manifest, protected = _manifest(
            job_id=job_id,
            access_window_id=access_window_id,
            checkpoint_payload=checkpoint_payload,
        )
        executor.configure(
            store=store,
            invocation_id=invocation_id,
            manifest=manifest,
            protected=protected,
        )

        scheduler = CooperativeScheduler(repository)
        _tick_until_terminal(scheduler, repository, job_id)

        completed = repository.get_job(job_id)
        item = repository.list_items(job_id)[0]
        attempts = [
            attempt
            for attempt in repository.list_stage_attempts()
            if attempt["consumer_job_id"] == job_id
        ]
        assert completed.status is JobStatus.SUCCEEDED
        assert completed.current_stage == "settlement_capture.complete"
        assert item.status is WorkItemStatus.SUCCEEDED
        assert item.current_stage == "settlement_capture.complete"
        assert len(executor.calls) == 2
        assert [
            (attempt["stage"], attempt["resource_name"], attempt["status"])
            for attempt in attempts
        ] == [
            (
                SETTLEMENT_CAPTURE_STAGE,
                "platform_browser",
                "succeeded",
            ),
            (
                SETTLEMENT_CAPTURE_STAGE,
                "platform_browser",
                "succeeded",
            ),
        ]
        assert store.get(invocation_id).status == "selected"
        assert access.get(access_window_id).consumed_at == (
            NOW + timedelta(minutes=1)
        )
        assert not [
            lease
            for resource in repository.resources_projection()
            for lease in resource["active_leases"]
        ]
    finally:
        repository.close()


def test_scheduler_recovers_a_committed_seal_without_another_browser_read(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    _register_scheduler_instance(runtime, "settlement-recovery-test")
    executor = _SettlementCaptureExecutor()
    backend = AsyncSettlementCaptureExecutionBackend(execute=executor)
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="settlement-recovery-test",
        settlement_capture_execution_backend=backend,
    )
    try:
        job_id = _create_capture_job(repository, suffix="recovery")
        (
            store,
            _access,
            invocation_id,
            access_window_id,
            checkpoint_payload,
        ) = _prepare(
            runtime,
            job_id=job_id,
            create_job=False,
        )
        manifest, protected = _manifest(
            job_id=job_id,
            access_window_id=access_window_id,
            checkpoint_payload=checkpoint_payload,
        )
        store.seal(
            invocation_id=invocation_id,
            expected_record_version=1,
            manifest=manifest,
            protected_identities=(protected,),
            now=NOW + timedelta(minutes=1),
        )
        executor.configure(
            store=store,
            invocation_id=invocation_id,
            manifest=manifest,
            protected=protected,
        )

        scheduler = CooperativeScheduler(repository)
        _tick_until_terminal(scheduler, repository, job_id)

        job = repository.get_job(job_id)
        item = repository.list_items(job_id)[0]
        assert job.status is JobStatus.SUCCEEDED
        assert item.status is WorkItemStatus.SUCCEEDED
        assert item.current_stage == "settlement_capture.complete"
        attempts = [
            attempt
            for attempt in repository.list_stage_attempts()
            if attempt["consumer_job_id"] == job_id
        ]
        assert len(attempts) == 1
        assert attempts[0]["status"] == "succeeded"
        assert executor.calls[0].stage == SETTLEMENT_CAPTURE_STAGE
        assert store.get(invocation_id).status == "selected"
    finally:
        repository.close()


def test_scheduler_keeps_capture_technical_failure_out_of_human_review(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    _register_scheduler_instance(runtime, "settlement-failure-test")
    executor = _SettlementCaptureExecutor(fail_immediately=True)
    backend = AsyncSettlementCaptureExecutionBackend(execute=executor)
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="settlement-failure-test",
        settlement_capture_execution_backend=backend,
    )
    try:
        job_id = _create_capture_job(repository, suffix="failure")
        (
            store,
            access,
            invocation_id,
            _access_window_id,
            _checkpoint_payload,
        ) = _prepare(
            runtime,
            job_id=job_id,
            create_job=False,
        )

        scheduler = CooperativeScheduler(repository)
        _tick_until_terminal(scheduler, repository, job_id)

        job = repository.get_job(job_id)
        item = repository.list_items(job_id)[0]
        invocation = store.get(invocation_id)
        assert job.status is JobStatus.FAILED
        assert item.status is WorkItemStatus.FAILED
        assert item.business_outcome is None
        assert item.review_reason is None
        assert item.diagnostic_code == (
            "CF-SETTLEMENT-CAPTURE-TECHNICAL"
        )
        assert invocation.status == "collecting"
        assert (
            access.get(invocation.access_window_id).consumed_at
            is not None
        )
    finally:
        repository.close()


def test_login_intervention_wait_uses_login_reason(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    _register_scheduler_instance(runtime, "settlement-login-wait-test")
    executor = _SettlementCaptureExecutor(
        wait_external=True,
        waiting_diagnostic_code="CF-LOGIN-INTERVENTION-REQUIRED",
    )
    backend = AsyncSettlementCaptureExecutionBackend(execute=executor)
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="settlement-login-wait-test",
        settlement_capture_execution_backend=backend,
    )
    try:
        job_id = _create_capture_job(repository, suffix="login-wait")
        _prepare(runtime, job_id=job_id, create_job=False)

        scheduler = CooperativeScheduler(repository)
        for _ in range(200):
            scheduler.tick()
            if repository.get_job(job_id).status is JobStatus.PAUSED:
                break
            time.sleep(0.002)
        else:
            raise AssertionError("login intervention did not pause")

        item = repository.list_items(job_id)[0]
        paused_job = repository.get_job(job_id)
        assert paused_job.diagnostic_code == (
            "CF-LOGIN-INTERVENTION-REQUIRED"
        )
        assert item.status is WorkItemStatus.WAITING_EXTERNAL
        assert item.waiting_reason_kind == "external"
        assert item.waiting_reason == "login_required"
        assert item.diagnostic_code == "CF-LOGIN-INTERVENTION-REQUIRED"
        assert item.business_outcome is None
        assert item.review_reason is None

        resumed = repository.resume_platform_waiting_job(
            job_id=job_id,
            allowed_diagnostic_codes=frozenset(
                {"CF-LOGIN-INTERVENTION-REQUIRED"}
            ),
        )
        assert resumed.status is JobStatus.QUEUED
        assert resumed.diagnostic_code is None
        resumed_item = repository.list_items(job_id)[0]
        assert resumed_item.status is WorkItemStatus.QUEUED
        assert resumed_item.waiting_reason is None
        assert resumed_item.diagnostic_code is None
    finally:
        repository.close()


def test_expired_capture_waits_for_rollover_and_resumes_without_losing_evidence(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    _register_scheduler_instance(
        runtime,
        "settlement-external-wait-test",
    )
    executor = _SettlementCaptureExecutor(wait_external=True)
    backend = AsyncSettlementCaptureExecutionBackend(
        execute=executor
    )
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="settlement-external-wait-test",
        settlement_capture_execution_backend=backend,
    )
    try:
        job_id = _create_capture_job(
            repository,
            suffix="external-wait",
        )
        (
            store,
            access,
            invocation_id,
            original_window_id,
            checkpoint_payload,
        ) = _prepare(
            runtime,
            job_id=job_id,
            create_job=False,
        )
        checkpoint_payload["read_access_window_ids"] = {
            capture_read_key(ChengfengStage.LIST_QUERY): (
                original_window_id
            ),
            capture_read_key(
                ChengfengStage.DETAIL_QUERY,
                "platform-real-1",
            ): original_window_id,
            capture_read_key(
                ChengfengStage.IMAGE_DOWNLOAD,
                "ticket-loading-1",
            ): original_window_id,
            capture_read_key(
                ChengfengStage.IMAGE_DOWNLOAD,
                "ticket-unloading-1",
            ): original_window_id,
        }
        DurableCaptureCheckpoint.from_payload(checkpoint_payload)
        with runtime.commit_gate.transaction(
            runtime.engine
        ) as connection:
            connection.execute(
                CHECKPOINTS.update()
                .where(
                    CHECKPOINTS.c.checkpoint_id
                    == "checkpoint-one"
                )
                .values(
                    payload_json=json.dumps(
                        checkpoint_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            )
        with runtime.engine.connect() as connection:
            checkpoint_before = tuple(
                connection.execute(
                    select(
                        CHECKPOINTS.c.checkpoint_id,
                        CHECKPOINTS.c.payload_json,
                    ).where(
                        CHECKPOINTS.c.owner_kind
                        == "chengfeng_capture"
                    )
                )
            )

        scheduler = CooperativeScheduler(repository)
        for _ in range(200):
            scheduler.tick()
            if repository.get_job(job_id).status is JobStatus.PAUSED:
                break
            time.sleep(0.002)
        else:
            raise AssertionError(
                "expired settlement capture did not pause"
            )

        waiting_item = repository.list_items(job_id)[0]
        assert waiting_item.status is WorkItemStatus.WAITING_EXTERNAL
        assert waiting_item.business_outcome is None
        assert waiting_item.review_reason is None
        assert waiting_item.waiting_reason_kind == "external"
        assert waiting_item.waiting_reason == "access_window_expired"
        assert waiting_item.diagnostic_code == (
            "CF-SETTLEMENT-ACCESS-WINDOW-EXPIRED"
        )
        assert not [
            lease
            for resource in repository.resources_projection()
            for lease in resource["active_leases"]
        ]
        assert store.get(invocation_id).status == "collecting"
        assert access.get(original_window_id).consumed_at is None

        rollover_at = NOW + timedelta(minutes=61)
        assert store.reconcile_terminal_or_expired_access(
            now=rollover_at
        ) == (job_id,)
        replacement, replayed = access.issue(
            purpose=AccessPurpose.FORMAL_LOCKED_SET,
            job_id=job_id,
            session_id="browser-session-1",
            build_sha256=BUILD_SHA,
            duration_minutes=60,
            legacy_idle_confirmed=True,
            no_settlement_or_payment_confirmed=True,
            same_account_session_risk_accepted=True,
            run_mode="shadow",
            idempotency_key="settlement-external-wait-window",
            request_hash=hashlib.sha256(
                b"settlement-external-wait-window"
            ).hexdigest(),
            now=rollover_at,
        )
        assert replayed is False
        invocation = store.get(invocation_id)
        browser = BrowserControlStore(
            runtime.engine,
            runtime.commit_gate,
        ).get("browser-session-1")
        rebound = store.rebind_access_window(
            job_id=job_id,
            new_access_window_id=replacement.access_window_id,
            expected_invocation_record_version=(
                invocation.record_version
            ),
            expected_browser_record_version=browser.record_version,
            session_id="browser-session-1",
            source_build_sha256=BUILD_SHA,
            contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
            contract_file_sha256=CONTRACT_FILE_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
            idempotency_key="settlement-external-wait-rebind",
            request_hash=hashlib.sha256(
                b"settlement-external-wait-rebind"
            ).hexdigest(),
            now=rollover_at,
        )
        assert rebound.invocation.access_window_id == (
            replacement.access_window_id
        )
        assert store.access_window_lineage(
            invocation_id
        ).access_window_ids == (
            original_window_id,
            replacement.access_window_id,
        )
        assert access.get(original_window_id).consumed_at == rollover_at

        paused = repository.get_job(job_id)
        resumed, replayed = repository.request_job_control(
            job_id=job_id,
            action="resume",
            expected_record_version=paused.record_version,
            idempotency_key="settlement-external-wait-resume",
            request_hash=hashlib.sha256(
                b"settlement-external-wait-resume"
            ).hexdigest(),
        )
        assert replayed is False
        assert resumed.status is JobStatus.QUEUED
        resumed_item = repository.list_items(job_id)[0]
        assert resumed_item.status is WorkItemStatus.QUEUED
        assert resumed_item.waiting_reason_kind is None
        assert resumed_item.waiting_reason is None
        assert resumed_item.diagnostic_code is None

        with runtime.engine.connect() as connection:
            checkpoint_after = tuple(
                connection.execute(
                    select(
                        CHECKPOINTS.c.checkpoint_id,
                        CHECKPOINTS.c.payload_json,
                    ).where(
                        CHECKPOINTS.c.owner_kind
                        == "chengfeng_capture"
                    )
                )
            )
        assert checkpoint_after == checkpoint_before
    finally:
        repository.close()
