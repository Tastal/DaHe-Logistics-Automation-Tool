from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from dahe.adapters.chengfeng.browser_gate import SqliteBrowserNavigationAuthorizer
from dahe.adapters.chengfeng.connector_runtime import (
    ConnectorRuntimePort,
    FrozenConnectorRuntime,
)
from dahe.adapters.chengfeng.frozen import (
    FrozenChengfengAdapter,
    FrozenFault,
    FrozenTransport,
)
from dahe.adapters.chengfeng.manifest import FrozenContractManifest
from dahe.adapters.chengfeng.protocol import ConnectorCommand, ConnectorResult
from dahe.adapters.chengfeng.verified_connector import VerifiedChengfengConnector
from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.adapters.sqlite.browser_control import (
    BrowserControlStore,
    NavigationRejectedError,
)
from dahe.adapters.sqlite.chengfeng_capture import SqliteChengfengCaptureStore
from dahe.adapters.sqlite.contract_subjects import SqliteContractSubjectStore
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.durable_capture import (
    CaptureCheckpointError,
    CaptureInvocationMismatchError,
    CaptureResult,
    DurableCaptureCheckpoint,
    DurableChengfengCaptureCoordinator,
    capture_detail_refresh_read_key,
)
from dahe.application.chengfeng.operational_capture import (
    FastOperationalSettlementCaptureCoordinator,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserNavigationAuthorizer,
    ChengfengOperation,
    ChengfengReadPort,
    ChengfengStage,
    ConnectorProtocolError,
    DownloadedTicketImage,
    TicketReference,
    WaybillDetail,
    WaybillSummary,
)

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "chengfeng" / "loop5-synthetic-v1"


def test_fast_operational_batch_commits_one_database_checkpoint(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _browser, authority = _acquire_authority(runtime)
    subject_store = SqliteContractSubjectStore(runtime)
    subject_store.initialize()
    subject_store.bind_job(
        job_id=authority.job_id,
        subject_code="shanxi_guienbo",
    )
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(
            tmp_path / "evidence"
        ),
    )
    adapter, _transport = _adapter(store=store)
    coordinator = FastOperationalSettlementCaptureCoordinator(
        adapter=adapter,
        navigation_authorizer=SqliteBrowserNavigationAuthorizer(
            BrowserControlStore(runtime.engine, runtime.commit_gate)
        ),
        batch_store=store,
    )
    invocation = SimpleNamespace(
        invocation_id="fixture-fast",
        job_id=authority.job_id,
        access_window_id="fixture-window",
        scope="loop5-synthetic-scope",
        page_size=50,
        record_version=1,
        status="collecting",
    )

    frozen = coordinator.advance(
        invocation=invocation,
        authority=authority,
    )
    assert frozen.has_more is True
    completed = coordinator.advance(
        invocation=invocation,
        authority=authority,
    )

    assert completed.has_more is False
    assert completed.capture_sha256 is not None
    run = store.load_operational_run(job_id=authority.job_id)
    assert run is not None
    assert run.status == "complete"
    assert run.committed_batch_count == 1
    assert (
        store.latest_completed_operational_job_id(
            scope="loop5-synthetic-scope"
        )
        == authority.job_id
    )
    with runtime.engine.connect() as connection:
        checkpoint_count = connection.execute(
            text(
                "SELECT COUNT(*) FROM checkpoints "
                "WHERE owner_kind = 'chengfeng_capture'"
            )
        ).scalar_one()
    assert checkpoint_count == 1


def test_interleaved_capture_downloads_images_before_next_detail(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(
            tmp_path / "evidence"
        ),
    )
    commands: list[ConnectorCommand] = []
    adapter, _transport = _adapter(
        store=store,
        runtime_wrapper=lambda wrapped: RecordingRuntime(
            wrapped,
            commands,
        ),
    )
    coordinator = DurableChengfengCaptureCoordinator(
        adapter=adapter,
        navigation_authorizer=SqliteBrowserNavigationAuthorizer(
            BrowserControlStore(runtime.engine, runtime.commit_gate)
        ),
        checkpoint_store=store,
        interleave_images=True,
    )

    try:
        result = _run_to_complete(
            coordinator,
            authority=authority,
        )

        assert len(result.details) == 2
        assert len(result.images) == 4
        assert [command.operation for command in commands] == [
            ChengfengOperation.LIST_WAYBILLS,
            ChengfengOperation.GET_WAYBILL_DETAIL,
            ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
            ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
            ChengfengOperation.GET_WAYBILL_DETAIL,
            ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
            ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
        ]
    finally:
        runtime.close()


def test_verified_operational_reuse_index_survives_restart(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    evidence = ContentAddressedEvidenceStore(tmp_path / "evidence")
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=evidence,
    )
    loading_content = b"verified-loading-image"
    unloading_content = b"verified-unloading-image"
    loading = evidence.put_bytes(loading_content, media_type="image/jpeg")
    unloading = evidence.put_bytes(unloading_content, media_type="image/jpeg")
    detail = WaybillDetail(
        platform_waybill_id="platform-reuse-001",
        waybill_number="YD-REUSE-001",
        vehicle_number="TEST-REUSE",
        loading_net="32.80",
        unloading_net="32.76",
        tickets=(
            TicketReference(
                slot="loading",
                ticket_ref="loading-reuse-001",
                media_type="image/jpeg",
            ),
            TicketReference(
                slot="unloading",
                ticket_ref="unloading-reuse-001",
                media_type="image/jpeg",
            ),
        ),
    )
    checkpoint = replace(
        DurableCaptureCheckpoint.initial(
            capture_id="reuse-capture",
            job_id="reuse-job",
            scope="current",
            page_number=1,
            page_size=15,
        ),
        details=(detail,),
        completed_detail_ids=(detail.platform_waybill_id,),
    )
    images = (
        DownloadedTicketImage(
            ticket_ref="loading-reuse-001",
            media_type="image/jpeg",
            content=loading_content,
            sha256=loading.sha256,
            validator_sha256="a" * 64,
        ),
        DownloadedTicketImage(
            ticket_ref="unloading-reuse-001",
            media_type="image/jpeg",
            content=unloading_content,
            sha256=unloading.sha256,
            validator_sha256="b" * 64,
        ),
    )
    summary = WaybillSummary(
        platform_waybill_id=detail.platform_waybill_id,
        waybill_number=detail.waybill_number,
        vehicle_number=detail.vehicle_number,
    )
    try:
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            store._upsert_operational_reuse(
                connection,
                checkpoint=checkpoint,
                images=images,
                source_revisions={detail.platform_waybill_id: "c" * 64},
            )
        runtime.close()

        reopened = _runtime(tmp_path, project_root)
        try:
            reloaded = SqliteChengfengCaptureStore(
                runtime=reopened,
                evidence_store=ContentAddressedEvidenceStore(
                    tmp_path / "evidence"
                ),
            ).load_reuse_candidates(summaries=(summary,))
            assert len(reloaded) == 1
            assert reloaded[0].source_revision_sha256 == "c" * 64
            assert tuple(image.slot for image in reloaded[0].images) == (
                "loading",
                "unloading",
            )
        finally:
            reopened.close()
    finally:
        runtime.close()


def test_operational_reuse_index_rejects_unvalidated_images(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    evidence = ContentAddressedEvidenceStore(tmp_path / "evidence")
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=evidence,
    )
    content = b"unvalidated-image"
    stored = evidence.put_bytes(content, media_type="image/jpeg")
    detail = WaybillDetail(
        platform_waybill_id="platform-unvalidated-001",
        waybill_number="YD-UNVALIDATED-001",
        vehicle_number=None,
        loading_net=None,
        unloading_net=None,
        tickets=(
            TicketReference(
                slot="loading",
                ticket_ref="loading-unvalidated-001",
                media_type="image/jpeg",
            ),
        ),
    )
    checkpoint = replace(
        DurableCaptureCheckpoint.initial(
            capture_id="unvalidated-capture",
            job_id="unvalidated-job",
            scope="current",
            page_number=1,
            page_size=15,
        ),
        details=(detail,),
        completed_detail_ids=(detail.platform_waybill_id,),
    )
    image = DownloadedTicketImage(
        ticket_ref="loading-unvalidated-001",
        media_type="image/jpeg",
        content=content,
        sha256=stored.sha256,
        validator_sha256=None,
    )
    try:
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            store._upsert_operational_reuse(
                connection,
                checkpoint=checkpoint,
                images=(image,),
                source_revisions={detail.platform_waybill_id: "d" * 64},
            )
        candidates = store.load_reuse_candidates(
            summaries=(
                WaybillSummary(
                    platform_waybill_id=detail.platform_waybill_id,
                    waybill_number=detail.waybill_number,
                    vehicle_number=detail.vehicle_number,
                ),
            )
        )
        assert candidates == ()
    finally:
        runtime.close()


class DelegatingRuntime:
    wrapped: ConnectorRuntimePort

    @property
    def ticket_capability_authority_id(self) -> str:
        return self.wrapped.ticket_capability_authority_id

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool:
        return self.wrapped.ticket_image_capability_is_current(ticket_ref)


class CrashOnSecondDetailRuntime(DelegatingRuntime):
    def __init__(self, wrapped: ConnectorRuntimePort) -> None:
        self.wrapped = wrapped
        self.detail_calls = 0

    def execute(self, command_ndjson: str | bytes) -> str | bytes:
        command = ConnectorCommand.from_ndjson(command_ndjson)
        if command.operation is ChengfengOperation.GET_WAYBILL_DETAIL:
            self.detail_calls += 1
            if self.detail_calls == 2:
                raise RuntimeError("synthetic process crash before the second detail result")
        return self.wrapped.execute(command_ndjson)


class RecordingRuntime(DelegatingRuntime):
    def __init__(
        self,
        wrapped: ConnectorRuntimePort,
        commands: list[ConnectorCommand],
    ) -> None:
        self.wrapped = wrapped
        self.commands = commands

    def execute(self, command_ndjson: str | bytes) -> str | bytes:
        self.commands.append(ConnectorCommand.from_ndjson(command_ndjson))
        return self.wrapped.execute(command_ndjson)


class MismatchedResultRuntime(DelegatingRuntime):
    def __init__(self, wrapped: ConnectorRuntimePort) -> None:
        self.wrapped = wrapped

    def execute(self, command_ndjson: str | bytes) -> str | bytes:
        result = ConnectorResult.from_ndjson(self.wrapped.execute(command_ndjson))
        return replace(result, command_id="cmd-unrelated-result").to_ndjson()


class TamperStagedPayloadRuntime(DelegatingRuntime):
    def __init__(self, wrapped: ConnectorRuntimePort, *, data_root: Path) -> None:
        self.wrapped = wrapped
        self.data_root = data_root

    def execute(self, command_ndjson: str | bytes) -> str | bytes:
        raw_result = self.wrapped.execute(command_ndjson)
        result = ConnectorResult.from_ndjson(raw_result)
        if result.payload_references:
            target = self.data_root / result.payload_references[0].relative_path
            with target.open("ab") as handle:
                handle.write(b"tampered")
        return raw_result


class RejectPostReadAuthorizer:
    def __init__(
        self,
        *,
        delegate: SqliteBrowserNavigationAuthorizer,
        browser_store: BrowserControlStore,
        release_on_call: int = 2,
    ) -> None:
        self.delegate = delegate
        self.browser_store = browser_store
        self.release_on_call = release_on_call
        self.calls = 0

    def authorize(self, authority: BrowserCommandAuthority) -> None:
        self.delegate.authorize(authority)
        self.calls += 1
        if self.calls == self.release_on_call:
            self.browser_store.release_automated(
                session_id=authority.session_id,
                instance_id=authority.instance_id,
                worker_id=authority.worker_id,
                job_id=authority.job_id,
                control_epoch=authority.control_epoch,
                fencing_token=authority.fencing_token,
                now=datetime.now(UTC),
            )


def _runtime(tmp_path: Path, project_root: Path) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop5-instance",
    )


def _acquire_authority(
    runtime: SqliteRuntime,
) -> tuple[BrowserControlStore, BrowserCommandAuthority]:
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id=None,
    )
    try:
        job, created = repository.create_job(
            task_type="audit",
            scope_label="Loop 5 durable capture",
            scope_fixture_id="loop5-durable-capture",
            idempotency_key="loop5-durable-capture-job",
            request_hash=hashlib.sha256(
                b"loop5-durable-capture-job"
            ).hexdigest(),
        )
        assert created is True
    finally:
        repository.stop_ocr_execution()

    browser_store = BrowserControlStore(runtime.engine, runtime.commit_gate)
    now = datetime.now(UTC)
    initial = browser_store.initialize(session_id="chengfeng_session", now=now)
    ready = browser_store.mark_ready(
        session_id=initial.session_id,
        expected_record_version=initial.record_version,
        now=now,
    )
    grant = browser_store.acquire_automated(
        session_id=ready.session_id,
        instance_id="loop5-instance",
        worker_id="loop5-worker",
        job_id=job.job_id,
        expected_record_version=ready.record_version,
        now=now,
        ttl=timedelta(minutes=5),
    )
    assert grant.fencing_token is not None
    return (
        browser_store,
        BrowserCommandAuthority(
            session_id=grant.session_id,
            instance_id="loop5-instance",
            worker_id="loop5-worker",
            job_id=job.job_id,
            control_epoch=grant.control_epoch,
            fencing_token=grant.fencing_token,
        ),
    )


def _adapter(
    *,
    store: SqliteChengfengCaptureStore,
    authorizer: BrowserNavigationAuthorizer | None = None,
    runtime_wrapper: Callable[[ConnectorRuntimePort], ConnectorRuntimePort] | None = None,
) -> tuple[VerifiedChengfengConnector, FrozenTransport]:
    manifest = FrozenContractManifest.load(FIXTURE_ROOT)
    transport = FrozenTransport(manifest=manifest)
    frozen_adapter = FrozenChengfengAdapter(manifest=manifest, transport=transport)
    navigation_authorizer = authorizer or SqliteBrowserNavigationAuthorizer(
        BrowserControlStore(store.runtime.engine, store.runtime.commit_gate)
    )
    connector_runtime: ConnectorRuntimePort = FrozenConnectorRuntime(
        adapter=frozen_adapter,
        data_root=store.runtime.data_root,
        authorizer=navigation_authorizer,
    )
    if runtime_wrapper is not None:
        connector_runtime = runtime_wrapper(connector_runtime)
    return (
        VerifiedChengfengConnector(
            runtime=connector_runtime,
            data_root=store.runtime.data_root,
            authorizer=navigation_authorizer,
        ),
        transport,
    )


def _coordinator(
    *,
    adapter: ChengfengReadPort,
    store: SqliteChengfengCaptureStore,
    authorizer: BrowserNavigationAuthorizer | None = None,
    recover_browser: (
        Callable[[BrowserCommandAuthority, ChengfengStage], BrowserCommandAuthority] | None
    ) = None,
) -> DurableChengfengCaptureCoordinator:
    navigation_authorizer = authorizer or SqliteBrowserNavigationAuthorizer(
        BrowserControlStore(store.runtime.engine, store.runtime.commit_gate)
    )
    return DurableChengfengCaptureCoordinator(
        adapter=adapter,
        navigation_authorizer=navigation_authorizer,
        checkpoint_store=store,
        recover_browser=recover_browser,
    )


def _run_to_complete(
    coordinator: DurableChengfengCaptureCoordinator,
    *,
    authority: BrowserCommandAuthority,
) -> CaptureResult:
    active_authority = authority
    for _ in range(20):
        step = coordinator.advance(
            authority=active_authority,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        active_authority = step.authority
        if not step.has_more:
            return coordinator.capture_result(
                job_id=active_authority.job_id,
                scope="loop5-synthetic-scope",
                page_number=1,
                page_size=50,
            )
    raise AssertionError("durable capture did not finish within its bounded atomic steps")


def _capture_through_all_details(
    *,
    store: SqliteChengfengCaptureStore,
    authority: BrowserCommandAuthority,
    access_window_id: str,
) -> DurableCaptureCheckpoint:
    adapter, _ = _adapter(store=store)
    coordinator = _coordinator(adapter=adapter, store=store)
    active_authority = authority
    checkpoint: DurableCaptureCheckpoint | None = None
    for _ in range(4):
        step = coordinator.advance(
            authority=active_authority,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
            access_window_id=access_window_id,
        )
        active_authority = step.authority
        checkpoint = step.checkpoint
    assert checkpoint is not None
    assert len(checkpoint.details) == 2
    assert checkpoint.ticket_images == {}
    return checkpoint


class RefreshingReadPort:
    def __init__(self, delegate: ChengfengReadPort) -> None:
        self.delegate = delegate
        self.refreshed_refs: dict[str, str] = {}
        self.refresh_count = 0

    @property
    def ticket_capability_authority_id(self) -> str:
        return str(self.delegate.ticket_capability_authority_id)

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool:
        original_ref = self.refreshed_refs.get(ticket_ref)
        return original_ref is not None and bool(
            self.delegate.ticket_image_capability_is_current(
                original_ref
            )
        )

    def list_waybills(self, **kwargs: object) -> object:
        return self.delegate.list_waybills(**kwargs)  # type: ignore[arg-type]

    def get_waybill_detail(self, **kwargs: object) -> object:
        detail = self.delegate.get_waybill_detail(  # type: ignore[arg-type]
            **kwargs
        )
        self.refresh_count += 1
        tickets = []
        for ticket in detail.tickets:
            refreshed_ref = (
                f"{ticket.ticket_ref}-refresh-{self.refresh_count}"
            )
            self.refreshed_refs[refreshed_ref] = ticket.ticket_ref
            tickets.append(
                replace(ticket, ticket_ref=refreshed_ref)
            )
        return replace(detail, tickets=tuple(tickets))

    def download_ticket_image(self, **kwargs: object) -> object:
        ticket_ref = str(kwargs["ticket_ref"])
        original_ref = self.refreshed_refs[ticket_ref]
        image = self.delegate.download_ticket_image(
            authority=kwargs["authority"],  # type: ignore[arg-type]
            ticket_ref=original_ref,
        )
        return replace(image, ticket_ref=ticket_ref)


def test_interleaved_capture_resumes_legacy_detail_page_with_first_image(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(
            tmp_path / "evidence"
        ),
    )
    _capture_through_all_details(
        store=store,
        authority=authority,
        access_window_id="window-1",
    )
    commands: list[ConnectorCommand] = []
    base_adapter, _transport = _adapter(
        store=store,
        runtime_wrapper=lambda wrapped: RecordingRuntime(
            wrapped,
            commands,
        ),
    )
    adapter = RefreshingReadPort(base_adapter)
    coordinator = DurableChengfengCaptureCoordinator(
        adapter=adapter,
        navigation_authorizer=SqliteBrowserNavigationAuthorizer(
            BrowserControlStore(runtime.engine, runtime.commit_gate)
        ),
        checkpoint_store=store,
        interleave_images=True,
    )

    try:
        coordinator.advance(
            authority=authority,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
            access_window_id="window-1",
        )
        coordinator.advance(
            authority=authority,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
            access_window_id="window-1",
        )

        assert [command.operation for command in commands] == [
            ChengfengOperation.GET_WAYBILL_DETAIL,
            ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
        ]
    finally:
        runtime.close()


def _detail_refresh_proposal(
    checkpoint: DurableCaptureCheckpoint,
    *,
    refreshed_id: str,
    worker_id: str,
    access_window_id: str,
    read_access_window_ids: dict[str, str] | None = None,
    replace_missing_ticket_ref: bool = False,
) -> DurableCaptureCheckpoint:
    details = list(checkpoint.details)
    if replace_missing_ticket_ref:
        detail_index = next(
            index
            for index, detail in enumerate(details)
            if detail.platform_waybill_id == refreshed_id
        )
        detail = details[detail_index]
        details[detail_index] = replace(
            detail,
            tickets=(
                replace(
                    detail.tickets[0],
                    ticket_ref=f"{detail.tickets[0].ticket_ref}-refreshed",
                ),
                *detail.tickets[1:],
            ),
        )
    worker_ids = dict(checkpoint.detail_capability_worker_ids)
    worker_ids[refreshed_id] = worker_id
    access_window_ids = dict(
        checkpoint.detail_capability_access_window_ids
    )
    access_window_ids[refreshed_id] = access_window_id
    if read_access_window_ids is None:
        read_access_window_ids = dict(
            checkpoint.read_access_window_ids
        )
        platform_digest = hashlib.sha256(
            refreshed_id.encode("utf-8")
        ).hexdigest()
        refresh_index = (
            sum(
                key.startswith(
                    f"detail-refresh:{platform_digest}:"
                )
                for key in read_access_window_ids
            )
            + 1
        )
        read_access_window_ids[
            capture_detail_refresh_read_key(
                platform_waybill_id=refreshed_id,
                worker_id=worker_id,
                access_window_id=access_window_id,
                refresh_index=refresh_index,
            )
        ] = access_window_id
    return replace(
        checkpoint,
        stage=ChengfengStage.DETAIL_QUERY,
        details=tuple(details),
        detail_capability_worker_ids=worker_ids,
        detail_capability_access_window_ids=access_window_ids,
        read_access_window_ids=read_access_window_ids,
    )


def test_detail_capability_refresh_requires_exact_next_read_binding(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id = checkpoint.completed_detail_ids[0]
        proposal = _detail_refresh_proposal(
            checkpoint,
            refreshed_id=refreshed_id,
            worker_id="capability-worker-new",
            access_window_id="window-new",
            read_access_window_ids=dict(
                checkpoint.read_access_window_ids
            ),
        )

        with pytest.raises(
            CaptureCheckpointError,
            match="valid atomic transition",
        ):
            store.commit_checkpoint(proposal, authority)
    finally:
        runtime.close()


def test_detail_capability_refresh_rejects_second_waybill_read_binding(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id, unrelated_id = checkpoint.completed_detail_ids
        worker_id = "capability-worker-new"
        access_window_id = "window-new"
        read_bindings = dict(checkpoint.read_access_window_ids)
        read_bindings[
            capture_detail_refresh_read_key(
                platform_waybill_id=refreshed_id,
                worker_id=worker_id,
                access_window_id=access_window_id,
                refresh_index=1,
            )
        ] = access_window_id
        read_bindings[
            capture_detail_refresh_read_key(
                platform_waybill_id=unrelated_id,
                worker_id=worker_id,
                access_window_id=access_window_id,
                refresh_index=1,
            )
        ] = access_window_id
        proposal = _detail_refresh_proposal(
            checkpoint,
            refreshed_id=refreshed_id,
            worker_id=worker_id,
            access_window_id=access_window_id,
            read_access_window_ids=read_bindings,
        )

        with pytest.raises(
            CaptureCheckpointError,
            match="valid atomic transition",
        ):
            store.commit_checkpoint(proposal, authority)
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "mismatch",
    [
        pytest.param("worker-digest", id="worker-digest"),
        pytest.param("window-digest", id="window-digest"),
        pytest.param("window-binding", id="window-binding"),
    ],
)
def test_detail_capability_refresh_rejects_mismatched_read_identity(
    tmp_path: Path,
    project_root: Path,
    mismatch: str,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id = checkpoint.completed_detail_ids[0]
        worker_id = "capability-worker-new"
        access_window_id = "window-new"
        key = capture_detail_refresh_read_key(
            platform_waybill_id=refreshed_id,
            worker_id=(
                "capability-worker-wrong"
                if mismatch == "worker-digest"
                else worker_id
            ),
            access_window_id=(
                "window-wrong"
                if mismatch == "window-digest"
                else access_window_id
            ),
            refresh_index=1,
        )
        read_bindings = dict(checkpoint.read_access_window_ids)
        read_bindings[key] = (
            "window-wrong"
            if mismatch == "window-binding"
            else access_window_id
        )
        proposal = _detail_refresh_proposal(
            checkpoint,
            refreshed_id=refreshed_id,
            worker_id=worker_id,
            access_window_id=access_window_id,
            read_access_window_ids=read_bindings,
        )

        with pytest.raises(
            CaptureCheckpointError,
            match="valid atomic transition",
        ):
            store.commit_checkpoint(proposal, authority)
    finally:
        runtime.close()


def test_detail_capability_refresh_rejects_ticket_tuple_reordering(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id = checkpoint.completed_detail_ids[0]
        proposal = _detail_refresh_proposal(
            checkpoint,
            refreshed_id=refreshed_id,
            worker_id="capability-worker-new",
            access_window_id="window-new",
        )
        refreshed_detail = proposal.details[0]
        proposal = replace(
            proposal,
            details=(
                replace(
                    refreshed_detail,
                    tickets=tuple(
                        reversed(refreshed_detail.tickets)
                    ),
                ),
                *proposal.details[1:],
            ),
        )

        with pytest.raises(
            CaptureCheckpointError,
            match="transition",
        ):
            store.commit_checkpoint(proposal, authority)
    finally:
        runtime.close()


def test_detail_capability_refresh_allows_same_worker_with_new_window(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id = checkpoint.completed_detail_ids[0]
        worker_id = checkpoint.detail_capability_worker_ids[
            refreshed_id
        ]
        proposal = _detail_refresh_proposal(
            checkpoint,
            refreshed_id=refreshed_id,
            worker_id=worker_id,
            access_window_id="window-new",
        )

        committed = store.commit_checkpoint(proposal, authority)

        assert committed.revision == checkpoint.revision + 1
        assert (
            committed.detail_capability_access_window_ids[
                refreshed_id
            ]
            == "window-new"
        )
    finally:
        runtime.close()


def test_detail_capability_refresh_requires_contiguous_read_sequence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id = checkpoint.completed_detail_ids[0]
        worker_id = checkpoint.detail_capability_worker_ids[
            refreshed_id
        ]
        first = store.commit_checkpoint(
            _detail_refresh_proposal(
                checkpoint,
                refreshed_id=refreshed_id,
                worker_id=worker_id,
                access_window_id="window-new",
            ),
            authority,
        )
        skipped_reads = dict(first.read_access_window_ids)
        skipped_reads[
            capture_detail_refresh_read_key(
                platform_waybill_id=refreshed_id,
                worker_id=worker_id,
                access_window_id="window-next",
                refresh_index=3,
            )
        ] = "window-next"
        skipped = _detail_refresh_proposal(
            first,
            refreshed_id=refreshed_id,
            worker_id=worker_id,
            access_window_id="window-next",
            read_access_window_ids=skipped_reads,
        )

        with pytest.raises(
            CaptureCheckpointError,
            match="valid atomic transition",
        ):
            store.commit_checkpoint(skipped, authority)

        committed = store.commit_checkpoint(
            _detail_refresh_proposal(
                first,
                refreshed_id=refreshed_id,
                worker_id=worker_id,
                access_window_id="window-next",
            ),
            authority,
        )
        assert committed.revision == first.revision + 1
    finally:
        runtime.close()


def test_detail_capability_refresh_allows_missing_ticket_ref_change_only(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id = checkpoint.completed_detail_ids[0]
        worker_id = checkpoint.detail_capability_worker_ids[
            refreshed_id
        ]
        access_window_id = (
            checkpoint.detail_capability_access_window_ids[
                refreshed_id
            ]
        )
        proposal = _detail_refresh_proposal(
            checkpoint,
            refreshed_id=refreshed_id,
            worker_id=worker_id,
            access_window_id=access_window_id,
            replace_missing_ticket_ref=True,
        )

        committed = store.commit_checkpoint(proposal, authority)

        assert (
            committed.details[0].tickets[0].ticket_ref
            != checkpoint.details[0].tickets[0].ticket_ref
        )
    finally:
        runtime.close()


def test_detail_capability_refresh_rejects_no_op(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        refreshed_id = checkpoint.completed_detail_ids[0]
        proposal = _detail_refresh_proposal(
            checkpoint,
            refreshed_id=refreshed_id,
            worker_id=checkpoint.detail_capability_worker_ids[
                refreshed_id
            ],
            access_window_id=(
                checkpoint.detail_capability_access_window_ids[
                    refreshed_id
                ]
            ),
        )

        with pytest.raises(
            CaptureCheckpointError,
            match="valid atomic transition",
        ):
            store.commit_checkpoint(proposal, authority)
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "tampered_map",
    [
        pytest.param("worker", id="worker"),
        pytest.param("access-window", id="access-window"),
    ],
)
def test_commit_image_preserves_detail_capability_maps(
    tmp_path: Path,
    project_root: Path,
    tampered_map: str,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    try:
        checkpoint = _capture_through_all_details(
            store=store,
            authority=authority,
            access_window_id="window-old",
        )
        target_id = checkpoint.completed_detail_ids[0]
        proposal_changes: dict[str, object]
        if tampered_map == "worker":
            worker_ids = dict(
                checkpoint.detail_capability_worker_ids
            )
            worker_ids[target_id] = "capability-worker-tampered"
            proposal_changes = {
                "detail_capability_worker_ids": worker_ids,
            }
        else:
            access_ids = dict(
                checkpoint.detail_capability_access_window_ids
            )
            access_ids[target_id] = "window-tampered"
            proposal_changes = {
                "detail_capability_access_window_ids": access_ids,
            }
        pending = replace(
            checkpoint,
            stage=ChengfengStage.IMAGE_DOWNLOAD,
            **proposal_changes,
        )
        ticket_ref = checkpoint.details[0].tickets[0].ticket_ref
        content = b"capability-map-preservation"
        image = DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type="image/png",
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )

        with pytest.raises(
            CaptureCheckpointError,
            match="invalid image result transition",
        ):
            store.commit_image(
                pending,
                image,
                authority,
                access_window_id="window-old",
            )

        committed = store.commit_image(
            replace(
                checkpoint,
                stage=ChengfengStage.IMAGE_DOWNLOAD,
            ),
            image,
            authority,
            access_window_id="window-old",
        )
        assert (
            dict(committed.detail_capability_worker_ids)
            == dict(checkpoint.detail_capability_worker_ids)
        )
        assert (
            dict(committed.detail_capability_access_window_ids)
            == dict(
                checkpoint.detail_capability_access_window_ids
            )
        )
    finally:
        runtime.close()


def test_durable_capture_commits_structured_checkpoints_and_evidence(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    evidence_store = ContentAddressedEvidenceStore(tmp_path / "evidence")
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=evidence_store,
    )
    commands: list[ConnectorCommand] = []
    adapter, transport = _adapter(
        store=store,
        runtime_wrapper=lambda connector_runtime: RecordingRuntime(
            connector_runtime,
            commands,
        ),
    )
    try:
        result = _run_to_complete(
            _coordinator(adapter=adapter, store=store),
            authority=authority,
        )

        assert result.page.total == 2
        assert len(result.details) == 2
        assert len(result.images) == 4
        assert transport.request_count("list_waybills") == 1
        assert transport.request_count("get_waybill_detail") == 2
        assert transport.request_count("download_ticket_image") == 4
        staged_payloads = tuple((tmp_path / "connector-staging").rglob("payload.*"))
        assert staged_payloads == ()
        assert len(commands) == 7
        assert len({command.command_id for command in commands}) == 7
        assert all(command.authority.job_id == authority.job_id for command in commands)

        checkpoint = store.load(
            job_id=authority.job_id,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        assert checkpoint is not None
        assert checkpoint.completed_list is True
        assert checkpoint.completed_detail_ids == (
            "synthetic-waybill-001",
            "synthetic-waybill-002",
        )
        assert set(checkpoint.ticket_images) == {
            "synthetic-ticket-load-001",
            "synthetic-ticket-unload-001",
            "synthetic-ticket-load-002",
            "synthetic-ticket-unload-002",
        }
        for image in checkpoint.ticket_images.values():
            assert not Path(image.relative_path).is_absolute()
            assert evidence_store.read_bytes(image.sha256)

        with runtime.engine.connect() as connection:
            checkpoint_rows = connection.execute(
                text(
                    "SELECT payload_json FROM checkpoints "
                    "WHERE owner_kind = 'chengfeng_capture' ORDER BY sequence"
                )
            ).all()
            blob_count = int(
                connection.execute(text("SELECT count(*) FROM evidence_blobs")).scalar_one()
            )
            reference_count = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_references "
                        "WHERE owner_kind = 'chengfeng_capture'"
                    )
                ).scalar_one()
            )
        assert len(checkpoint_rows) == 8
        assert blob_count == 1
        assert reference_count == 4
        persisted_json = "\n".join(str(row[0]) for row in checkpoint_rows)
        assert authority.fencing_token not in persisted_json
        assert "iVBOR" not in persisted_json
        parsed = json.loads(str(checkpoint_rows[-1][0]))
        assert parsed["job_id"] == authority.job_id
        assert parsed["scope"] == "loop5-synthetic-scope"
        assert parsed["page_number"] == 1
        assert parsed["page_size"] == 50
    finally:
        runtime.close()


def test_each_advance_performs_at_most_one_platform_read(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    adapter, transport = _adapter(store=store)
    coordinator = _coordinator(adapter=adapter, store=store)
    try:
        for _ in range(20):
            before = sum(
                transport.request_count(operation)
                for operation in (
                    "list_waybills",
                    "get_waybill_detail",
                    "download_ticket_image",
                )
            )
            step = coordinator.advance(
                authority=authority,
                scope="loop5-synthetic-scope",
                page_number=1,
                page_size=50,
            )
            after = sum(
                transport.request_count(operation)
                for operation in (
                    "list_waybills",
                    "get_waybill_detail",
                    "download_ticket_image",
                )
            )
            assert after - before in {0, 1}
            assert step.platform_read_performed is (after - before == 1)
            if not step.has_more:
                break
        else:
            raise AssertionError("durable capture did not complete")

        assert (
            len(
                coordinator.capture_result(
                    job_id=authority.job_id,
                    scope="loop5-synthetic-scope",
                    page_number=1,
                    page_size=50,
                ).images
            )
            == 4
        )
    finally:
        runtime.close()


def test_post_read_fence_failure_does_not_commit_the_list_result(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    browser_store, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    adapter, transport = _adapter(store=store)
    try:
        setup = _coordinator(adapter=adapter, store=store)
        setup.advance(
            authority=authority,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        fenced = _coordinator(
            adapter=adapter,
            store=store,
            authorizer=RejectPostReadAuthorizer(
                delegate=SqliteBrowserNavigationAuthorizer(browser_store),
                browser_store=browser_store,
            ),
        )
        with pytest.raises(NavigationRejectedError):
            fenced.advance(
                authority=authority,
                scope="loop5-synthetic-scope",
                page_number=1,
                page_size=50,
            )

        checkpoint = store.load(
            job_id=authority.job_id,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        assert checkpoint is not None
        assert checkpoint.completed_list is False
        assert checkpoint.revision == 1
        assert transport.request_count("list_waybills") == 1
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "failure_case",
    [
        pytest.param("mismatched-result", id="mismatched-result"),
        pytest.param("tampered-staged-payload", id="tampered-staged-payload"),
    ],
)
def test_untrusted_connector_result_cannot_reach_checkpoint_or_evidence(
    tmp_path: Path,
    project_root: Path,
    failure_case: str,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    runtime_wrapper: Callable[[ConnectorRuntimePort], ConnectorRuntimePort]
    if failure_case == "mismatched-result":
        runtime_wrapper = MismatchedResultRuntime
    else:
        def tamper_runtime(
            connector_runtime: ConnectorRuntimePort,
        ) -> ConnectorRuntimePort:
            return TamperStagedPayloadRuntime(
                connector_runtime,
                data_root=tmp_path,
            )

        runtime_wrapper = tamper_runtime
    adapter, transport = _adapter(
        store=store,
        runtime_wrapper=runtime_wrapper,
    )
    coordinator = _coordinator(adapter=adapter, store=store)
    try:
        coordinator.advance(
            authority=authority,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        with pytest.raises(ConnectorProtocolError):
            coordinator.advance(
                authority=authority,
                scope="loop5-synthetic-scope",
                page_number=1,
                page_size=50,
            )

        checkpoint = store.load(
            job_id=authority.job_id,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        assert checkpoint is not None
        assert checkpoint.revision == 1
        assert checkpoint.page is None
        assert transport.request_count("list_waybills") == 1
        with runtime.engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM evidence_blobs")).scalar_one() == 0
            assert (
                connection.execute(text("SELECT count(*) FROM evidence_references")).scalar_one()
                == 0
            )
    finally:
        runtime.close()


def test_connector_runtime_rejects_stale_authority_before_frozen_read(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    browser_store, authority = _acquire_authority(runtime)
    manifest = FrozenContractManifest.load(FIXTURE_ROOT)
    transport = FrozenTransport(manifest=manifest)
    navigation_authorizer = SqliteBrowserNavigationAuthorizer(browser_store)
    connector_runtime = FrozenConnectorRuntime(
        adapter=FrozenChengfengAdapter(manifest=manifest, transport=transport),
        data_root=runtime.data_root,
        authorizer=navigation_authorizer,
    )
    command = ConnectorCommand(
        protocol_version=1,
        command_id="cmd-stale-authority",
        operation=ChengfengOperation.LIST_WAYBILLS,
        authority=authority,
        parameters={
            "scope": "loop5-synthetic-scope",
            "page_number": 1,
            "page_size": 50,
        },
        credential_reference=None,
    )
    try:
        browser_store.release_automated(
            session_id=authority.session_id,
            instance_id=authority.instance_id,
            worker_id=authority.worker_id,
            job_id=authority.job_id,
            control_epoch=authority.control_epoch,
            fencing_token=authority.fencing_token,
            now=datetime.now(UTC),
        )
        with pytest.raises(NavigationRejectedError):
            connector_runtime.execute(command.to_ndjson())
        assert transport.request_count("list_waybills") == 0
        assert not tuple((tmp_path / "connector-staging").rglob("payload.*"))
    finally:
        runtime.close()


def test_new_coordinator_resumes_after_last_committed_detail_without_repeating_reads(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    adapter, first_transport = _adapter(
        store=store,
        runtime_wrapper=CrashOnSecondDetailRuntime,
    )
    try:
        with pytest.raises(RuntimeError, match="second detail"):
            _run_to_complete(
                _coordinator(adapter=adapter, store=store),
                authority=authority,
            )

        checkpoint = store.load(
            job_id=authority.job_id,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        assert checkpoint is not None
        assert checkpoint.completed_detail_ids == ("synthetic-waybill-001",)
        assert first_transport.request_count("list_waybills") == 1
        assert first_transport.request_count("get_waybill_detail") == 1

        runtime.close()
        runtime = _runtime(tmp_path, project_root)
        store = SqliteChengfengCaptureStore(
            runtime=runtime,
            evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
        )
        resumed_adapter, resumed_transport = _adapter(store=store)
        result = _run_to_complete(
            _coordinator(adapter=resumed_adapter, store=store),
            authority=authority,
        )

        assert len(result.details) == 2
        assert resumed_transport.request_count("list_waybills") == 0
        assert resumed_transport.request_count("get_waybill_detail") == 1
        assert resumed_transport.request_count("download_ticket_image") == 4

        replay_adapter, replay_transport = _adapter(store=store)
        replay_result = _run_to_complete(
            _coordinator(adapter=replay_adapter, store=store),
            authority=authority,
        )
        assert replay_result == result
        assert replay_transport.request_count("list_waybills") == 0
        assert replay_transport.request_count("get_waybill_detail") == 0
        assert replay_transport.request_count("download_ticket_image") == 0
    finally:
        runtime.close()


def test_image_file_precedes_atomic_reference_and_checkpoint_commit(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    evidence_store = ContentAddressedEvidenceStore(tmp_path / "evidence")
    fail_once = True

    def failpoint(stage: str) -> None:
        nonlocal fail_once
        if stage == "after_image_reference" and fail_once:
            fail_once = False
            raise RuntimeError("synthetic crash after image reference")

    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=evidence_store,
        failpoint=failpoint,
    )
    adapter, _ = _adapter(store=store)
    try:
        with pytest.raises(RuntimeError, match="after image reference"):
            _run_to_complete(
                _coordinator(adapter=adapter, store=store),
                authority=authority,
            )

        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM evidence_references "
                        "WHERE owner_kind = 'chengfeng_capture'"
                    )
                ).scalar_one()
                == 0
            )
        checkpoint = store.load(
            job_id=authority.job_id,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        assert checkpoint is not None
        assert checkpoint.ticket_images == {}
        assert tuple((tmp_path / "evidence" / "sha256").rglob("*.blob"))

        resumed_adapter, resumed_transport = _adapter(store=store)
        result = _run_to_complete(
            _coordinator(adapter=resumed_adapter, store=store),
            authority=authority,
        )
        assert len(result.images) == 4
        assert resumed_transport.request_count("list_waybills") == 0
        assert resumed_transport.request_count("get_waybill_detail") == 0
        assert resumed_transport.request_count("download_ticket_image") == 4
    finally:
        runtime.close()


def test_fake_browser_close_retries_only_the_uncommitted_image(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    browser_store, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    commands: list[ConnectorCommand] = []
    adapter, transport = _adapter(
        store=store,
        runtime_wrapper=lambda connector_runtime: RecordingRuntime(
            connector_runtime,
            commands,
        ),
    )
    transport.fail_next(
        operation="download_ticket_image",
        fault=FrozenFault.BROWSER_CLOSED,
    )
    replacements: list[str] = []

    def recover(
        old: BrowserCommandAuthority,
        checkpoint: object,
    ) -> BrowserCommandAuthority:
        replacements.append(str(checkpoint))
        now = datetime.now(UTC)
        recovery = browser_store.begin_automatic_recovery(
            session_id=old.session_id,
            instance_id=old.instance_id,
            worker_id=old.worker_id,
            job_id=old.job_id,
            expected_control_epoch=old.control_epoch,
            reason="synthetic browser close",
            now=now,
        )
        grant = browser_store.complete_automatic_recovery(
            session_id=old.session_id,
            expected_control_epoch=recovery.control_epoch,
            instance_id=old.instance_id,
            worker_id=f"{old.worker_id}-rebuilt",
            job_id=old.job_id,
            connector_stopped=True,
            context_rebuilt=True,
            read_only_firewall_verified=True,
            now=now,
            ttl=timedelta(minutes=5),
        )
        assert grant.fencing_token is not None
        return BrowserCommandAuthority(
            session_id=grant.session_id,
            instance_id=old.instance_id,
            worker_id=f"{old.worker_id}-rebuilt",
            job_id=old.job_id,
            control_epoch=grant.control_epoch,
            fencing_token=grant.fencing_token,
        )

    try:
        result = _run_to_complete(
            _coordinator(
                adapter=adapter,
                store=store,
                recover_browser=recover,
            ),
            authority=authority,
        )

        assert len(result.images) == 4
        assert replacements == ["image_download"]
        assert transport.request_count("list_waybills") == 1
        assert transport.request_count("get_waybill_detail") == 3
        assert transport.request_count("download_ticket_image") == 5
        image_commands = [
            command
            for command in commands
            if command.operation is ChengfengOperation.DOWNLOAD_TICKET_IMAGE
        ]
        assert len(image_commands) == 5
        failed_command, recovered_command = image_commands[:2]
        assert failed_command.parameters == recovered_command.parameters
        assert failed_command.command_id != recovered_command.command_id
        assert recovered_command.authority.control_epoch > failed_command.authority.control_epoch
        assert (
            recovered_command.authority.fencing_token
            != failed_command.authority.fencing_token
        )
    finally:
        runtime.close()


def test_invalid_browser_replacement_cannot_commit_the_unfinished_image(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    adapter, transport = _adapter(store=store)
    coordinator = _coordinator(adapter=adapter, store=store)
    try:
        for _ in range(10):
            step = coordinator.advance(
                authority=authority,
                scope="loop5-synthetic-scope",
                page_number=1,
                page_size=50,
            )
            if step.next_stage is not None and step.next_stage.value == "image_download":
                break
        else:
            raise AssertionError("capture did not reach its first image boundary")

        transport.fail_next(
            operation="download_ticket_image",
            fault=FrozenFault.BROWSER_CLOSED,
        )

        def invalid_recovery(
            old: BrowserCommandAuthority,
            checkpoint: object,
        ) -> BrowserCommandAuthority:
            del checkpoint
            return BrowserCommandAuthority(
                session_id=old.session_id,
                instance_id=old.instance_id,
                worker_id=f"{old.worker_id}-rebuilt",
                job_id="different-job",
                control_epoch=old.control_epoch + 1,
                fencing_token="replacement-token",
            )

        with pytest.raises(CaptureCheckpointError, match="ownership"):
            _coordinator(
                adapter=adapter,
                store=store,
                recover_browser=invalid_recovery,
            ).advance(
                authority=authority,
                scope="loop5-synthetic-scope",
                page_number=1,
                page_size=50,
            )

        checkpoint = store.load(
            job_id=authority.job_id,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )
        assert checkpoint is not None
        assert checkpoint.ticket_images == {}
        assert transport.request_count("download_ticket_image") == 1
    finally:
        runtime.close()


def test_checkpoint_identity_cannot_be_reused_for_a_different_invocation(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    adapter, _ = _adapter(store=store)
    try:
        _run_to_complete(
            _coordinator(adapter=adapter, store=store),
            authority=authority,
        )

        with pytest.raises(CaptureInvocationMismatchError):
            store.load_by_capture_id(
                capture_id=store.capture_id(
                    job_id=authority.job_id,
                    scope="loop5-synthetic-scope",
                    page_number=1,
                    page_size=50,
                ),
                job_id="different-job",
                scope="loop5-synthetic-scope",
                page_number=1,
                page_size=50,
            )
    finally:
        runtime.close()


def test_store_rejects_a_valid_grant_for_a_different_checkpoint_job(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    _, authority = _acquire_authority(runtime)
    store = SqliteChengfengCaptureStore(
        runtime=runtime,
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
    )
    wrong_job_id = "job-not-owned-by-browser-grant"
    checkpoint = DurableCaptureCheckpoint.initial(
        capture_id=store.capture_id(
            job_id=wrong_job_id,
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        ),
        job_id=wrong_job_id,
        scope="loop5-synthetic-scope",
        page_number=1,
        page_size=50,
    )
    try:
        with pytest.raises(CaptureInvocationMismatchError, match="does not own"):
            store.commit_checkpoint(checkpoint, authority)
        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM checkpoints WHERE owner_kind = 'chengfeng_capture'")
                ).scalar_one()
                == 0
            )
    finally:
        runtime.close()
