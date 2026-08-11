from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditEvidenceStore,
)
from dahe.adapters.files.settlement_capture_manifest import (
    SettlementCaptureManifestStore,
    SettlementCaptureManifestStoreError,
)
from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    DurableChengfengCaptureCoordinator,
    PersistedTicketImage,
    capture_read_key,
)
from dahe.application.chengfeng.settlement_capture import (
    PaginatedSettlementCaptureCoordinator,
    ProtectedBusinessIdentity,
    SettlementCaptureAccessWindowLineage,
    SettlementCaptureContractError,
    SettlementCaptureManifest,
)
from dahe.application.chengfeng.shadow_batch import (
    chengfeng_shadow_identity_context_sha256,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    ChengfengStage,
    DownloadedTicketImage,
    TicketImageCapabilityExpiredError,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)

NOW = datetime(2026, 7, 30, 8, 0, tzinfo=UTC)


def _png(color: tuple[int, int, int]) -> bytes:
    image = Image.new("RGB", (8, 8), color=color)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


@dataclass(frozen=True)
class Invocation:
    invocation_id: str = "invocation-1"
    job_id: str = "job-1"
    access_window_id: str = "window-1"
    source_build_sha256: str = "a" * 64
    contract_canonical_sha256: str = "b" * 64
    contract_file_sha256: str = "c" * 64
    contract_selection_sha256: str = "d" * 64
    identity_context_sha256: str = (
        chengfeng_shadow_identity_context_sha256(
            salt=b"loop9-test-identity-salt-32-bytes",
            namespace="chengfeng-production-account-v1",
        )
    )
    scope: str = "settled_history"
    page_size: int = 100
    status: str = "collecting"
    manifest_sha256: str | None = None
    record_version: int = 1


class InvocationStore:
    def __init__(self) -> None:
        self.record = Invocation()
        self.lineage = SettlementCaptureAccessWindowLineage(
            job_id=self.record.job_id,
            session_id="session-1",
            purpose="formal_locked_set",
            source_build_sha256=self.record.source_build_sha256,
            contract_canonical_sha256=(
                self.record.contract_canonical_sha256
            ),
            contract_file_sha256=self.record.contract_file_sha256,
            contract_selection_sha256=(
                self.record.contract_selection_sha256
            ),
            identity_context_sha256=self.record.identity_context_sha256,
            access_window_ids=(self.record.access_window_id,),
        )
        self.manifest: SettlementCaptureManifest | None = None
        self.protected: tuple[ProtectedBusinessIdentity, ...] = ()
        self.seal_calls = 0

    def get(self, invocation_id: str) -> Invocation:
        assert invocation_id == self.record.invocation_id
        return self.record

    def seal(
        self,
        *,
        invocation_id: str,
        expected_record_version: int,
        manifest: SettlementCaptureManifest,
        protected_identities: tuple[ProtectedBusinessIdentity, ...],
        now: datetime,
    ) -> Invocation:
        assert invocation_id == self.record.invocation_id
        assert expected_record_version == self.record.record_version
        assert now == NOW
        self.seal_calls += 1
        self.manifest = manifest
        self.protected = protected_identities
        self.record = replace(
            self.record,
            status="sealed",
            manifest_sha256=manifest.canonical_sha256,
            record_version=2,
        )
        return self.record

    def load_manifest(self, invocation_id: str) -> SettlementCaptureManifest:
        assert invocation_id == self.record.invocation_id
        assert self.manifest is not None
        return self.manifest

    def access_window_lineage(
        self,
        invocation_id: str,
    ) -> SettlementCaptureAccessWindowLineage:
        assert invocation_id == self.record.invocation_id
        return self.lineage


class MemoryCheckpointStore:
    def __init__(self) -> None:
        self.checkpoints: dict[
            tuple[str, str, int, int],
            DurableCaptureCheckpoint,
        ] = {}
        self.content: dict[str, bytes] = {}

    @property
    def checkpoint(self) -> DurableCaptureCheckpoint | None:
        """Keep single-page recovery tests explicit and backward compatible."""

        if not self.checkpoints:
            return None
        if len(self.checkpoints) != 1:
            raise AssertionError(
                "single-checkpoint view cannot represent multiple pages"
            )
        return next(iter(self.checkpoints.values()))

    @staticmethod
    def _key(
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> tuple[str, str, int, int]:
        return (job_id, scope, page_number, page_size)

    def capture_id(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> str:
        return f"{job_id}-{scope}-{page_number}-{page_size}"

    def load(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None:
        return self.checkpoints.get(
            self._key(
                job_id=job_id,
                scope=scope,
                page_number=page_number,
                page_size=page_size,
            )
        )

    def commit_checkpoint(
        self,
        checkpoint: DurableCaptureCheckpoint,
        authority: BrowserCommandAuthority,
    ) -> DurableCaptureCheckpoint:
        assert checkpoint.job_id == authority.job_id
        committed = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
        )
        self.checkpoints[
            self._key(
                job_id=committed.job_id,
                scope=committed.scope,
                page_number=committed.page_number,
                page_size=committed.page_size,
            )
        ] = committed
        return committed

    def commit_image(
        self,
        checkpoint: DurableCaptureCheckpoint,
        image: DownloadedTicketImage,
        authority: BrowserCommandAuthority,
        *,
        access_window_id: str | None = None,
    ) -> DurableCaptureCheckpoint:
        assert checkpoint.job_id == authority.job_id
        relative_path = (
            f"sha256/{image.sha256[:2]}/{image.sha256[2:4]}/"
            f"{image.sha256}.blob"
        )
        persisted = PersistedTicketImage(
            ticket_ref=image.ticket_ref,
            sha256=image.sha256,
            relative_path=relative_path,
            byte_size=len(image.content),
            media_type=image.media_type,
        )
        self.content[relative_path] = image.content
        read_access_window_ids = dict(
            checkpoint.read_access_window_ids
        )
        if access_window_id is not None:
            read_access_window_ids[
                capture_read_key(
                    ChengfengStage.IMAGE_DOWNLOAD,
                    image.ticket_ref,
                )
            ] = access_window_id
        committed = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
            ticket_images={
                **checkpoint.ticket_images,
                image.ticket_ref: persisted,
            },
            read_access_window_ids=read_access_window_ids,
        )
        self.checkpoints[
            self._key(
                job_id=committed.job_id,
                scope=committed.scope,
                page_number=committed.page_number,
                page_size=committed.page_size,
            )
        ] = committed
        return committed

    def read_image(self, image: PersistedTicketImage) -> bytes:
        return self.content[image.relative_path]

    def read_verified_image(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
    ) -> bytes:
        content = self.content[relative_path]
        assert hashlib.sha256(content).hexdigest() == expected_sha256
        return content


class FakeReadAdapter:
    def __init__(
        self,
        request_audit: PlatformReadAuditEvidenceStore,
    ) -> None:
        self.calls = 0
        self.loading = _png((255, 0, 0))
        self.unloading = _png((0, 255, 0))
        self.request_audit = request_audit

    def _audit(self, operation: str) -> object:
        token = self.request_audit.attempt(
            job_id="job-1",
            build_sha256="a" * 64,
            contract_sha256="b" * 64,
            contract_selection_sha256="d" * 64,
            operation=operation,
        )
        self.request_audit.allowed(token)
        return token

    def list_waybills(
        self,
        *,
        authority: BrowserCommandAuthority,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> WaybillPage:
        token = self._audit("list_waybills")
        self.calls += 1
        assert authority.job_id == "job-1"
        assert scope == "settled_history"
        assert page_number == 1
        assert page_size == 100
        result = WaybillPage(
            page_number=1,
            page_size=100,
            total=1,
            items=(
                WaybillSummary(
                    platform_waybill_id="platform-real-1",
                    waybill_number="CF-REAL-1",
                    vehicle_number="陕A12345",
                ),
            ),
        )
        self.request_audit.succeeded(token)
        return result

    def get_waybill_detail(
        self,
        *,
        authority: BrowserCommandAuthority,
        platform_waybill_id: str,
    ) -> WaybillDetail:
        token = self._audit("get_waybill_detail")
        self.calls += 1
        assert platform_waybill_id == "platform-real-1"
        result = WaybillDetail(
            platform_waybill_id=platform_waybill_id,
            waybill_number="CF-REAL-1",
            vehicle_number="陕A12345",
            loading_net="32.10",
            unloading_net="31.90",
            tickets=(
                TicketReference(
                    slot="loading",
                    ticket_ref="ticket-loading",
                    media_type="image/png",
                ),
                TicketReference(
                    slot="unloading",
                    ticket_ref="ticket-unloading",
                    media_type="image/png",
                ),
            ),
        )
        self.request_audit.succeeded(token)
        return result

    def download_ticket_image(
        self,
        *,
        authority: BrowserCommandAuthority,
        ticket_ref: str,
    ) -> DownloadedTicketImage:
        token = self._audit("download_ticket_image")
        self.calls += 1
        content = (
            self.loading
            if ticket_ref == "ticket-loading"
            else self.unloading
        )
        result = DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type="image/png",
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )
        self.request_audit.succeeded(token)
        return result


class RestartingReadAdapter(FakeReadAdapter):
    def __init__(
        self,
        request_audit: PlatformReadAuditEvidenceStore,
    ) -> None:
        super().__init__(request_audit)
        self.valid_ticket_refs: set[str] = set()
        self.detail_calls = 0
        self.downloaded_ticket_refs: list[str] = []

    def get_waybill_detail(
        self,
        *,
        authority: BrowserCommandAuthority,
        platform_waybill_id: str,
    ) -> WaybillDetail:
        token = self._audit("get_waybill_detail")
        self.calls += 1
        self.detail_calls += 1
        assert platform_waybill_id == "platform-real-1"
        loading_ref = f"ticket-{authority.worker_id}-loading"
        unloading_ref = f"ticket-{authority.worker_id}-unloading"
        self.valid_ticket_refs.update({loading_ref, unloading_ref})
        result = WaybillDetail(
            platform_waybill_id=platform_waybill_id,
            waybill_number="CF-REAL-1",
            vehicle_number="陕A12345",
            loading_net="32.10",
            unloading_net="31.90",
            tickets=(
                TicketReference(
                    slot="loading",
                    ticket_ref=loading_ref,
                    media_type="image/png",
                ),
                TicketReference(
                    slot="unloading",
                    ticket_ref=unloading_ref,
                    media_type="image/png",
                ),
            ),
        )
        self.request_audit.succeeded(token)
        return result

    def download_ticket_image(
        self,
        *,
        authority: BrowserCommandAuthority,
        ticket_ref: str,
    ) -> DownloadedTicketImage:
        if ticket_ref not in self.valid_ticket_refs:
            raise TicketImageCapabilityExpiredError()
        token = self._audit("download_ticket_image")
        self.calls += 1
        self.downloaded_ticket_refs.append(ticket_ref)
        content = (
            self.loading
            if ticket_ref.endswith("-loading")
            else self.unloading
        )
        result = DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type="image/png",
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )
        self.request_audit.succeeded(token)
        return result


class OutwardStore:
    def __init__(self) -> None:
        self.manifests: list[SettlementCaptureManifest] = []

    def seal(self, manifest: SettlementCaptureManifest) -> object:
        self.manifests.append(manifest)
        return object()


def test_each_advance_reads_at_most_once_and_seals_after_completeness(
    tmp_path: Path,
) -> None:
    request_audit = PlatformReadAuditEvidenceStore(tmp_path.resolve())
    adapter = FakeReadAdapter(request_audit)
    checkpoints = MemoryCheckpointStore()
    invocations = InvocationStore()
    outward = OutwardStore()
    authority_checks: list[int] = []
    durable = DurableChengfengCaptureCoordinator(
        adapter=adapter,
        navigation_authorizer=type(
            "Authorizer",
            (),
            {"authorize": lambda self, authority: None},
        )(),
        checkpoint_store=checkpoints,
    )
    coordinator = PaginatedSettlementCaptureCoordinator(
        durable_coordinator=durable,
        checkpoint_store=checkpoints,
        invocation_store=invocations,
        outward_store=outward,
        image_reader=checkpoints,
        identity_salt=b"loop9-test-identity-salt-32-bytes",
        identity_namespace="chengfeng-production-account-v1",
        validate_authority=(
            lambda invocation, authority, now: authority_checks.append(
                adapter.calls
            )
        ),
        clock=lambda: NOW,
        request_audit_store=request_audit,
    )
    authority = BrowserCommandAuthority(
        session_id="session-1",
        instance_id="instance-1",
        worker_id="worker-1",
        job_id="job-1",
        control_epoch=1,
        fencing_token="fence-1",
    )

    read_flags: list[bool] = []
    for _ in range(10):
        calls_before = adapter.calls
        result = coordinator.advance(
            invocation_id="invocation-1",
            authority=authority,
        )
        read_flags.append(result.platform_read_performed)
        assert adapter.calls - calls_before <= 1
        if not result.has_more:
            break
    else:
        raise AssertionError("settlement capture did not seal")

    assert adapter.calls == 4
    assert sum(read_flags) == 4
    assert invocations.seal_calls == 1
    assert invocations.record.status == "sealed"
    assert len(invocations.protected) == 1
    assert invocations.protected[0].waybill_number == "CF-REAL-1"
    assert len(outward.manifests) == 1
    assert len(outward.manifests[0].sources) == 1
    assert outward.manifests[0].sources[0].scope == (
        "settled_history"
    )
    assert outward.manifests[0].schema_version == 3
    assert outward.manifests[0].request_audit_sha256 is not None
    assert outward.manifests[0].request_audit_counts is not None
    assert outward.manifests[0].request_audit_counts["purpose"] == (
        "current_locked_50"
    )
    assert len(authority_checks) >= len(read_flags)

    manifest = outward.manifests[0]
    manifest_store = SettlementCaptureManifestStore(tmp_path.resolve())
    manifest_store.seal(manifest)
    assert (
        manifest_store.load(manifest.canonical_sha256).canonical_sha256
        == manifest.canonical_sha256
    )
    assert manifest.request_audit_sha256 is not None
    audit_path = request_audit.path_for(manifest.request_audit_sha256)
    audit_payload = json.loads(audit_path.read_text(encoding="utf-8"))
    audit_payload["purpose"] = "real_shadow_30"
    audit_path.write_text(
        json.dumps(audit_payload, ensure_ascii=False),
        encoding="utf-8",
    )
    with pytest.raises(
        SettlementCaptureManifestStoreError,
        match="request audit is unavailable",
    ):
        manifest_store.load(manifest.canonical_sha256)


def test_historical_capture_caps_candidate_source_at_two_pages() -> None:
    invocation = Invocation()

    assert PaginatedSettlementCaptureCoordinator._expected_pages(
        invocation,
        total=1,
    ) == 1
    assert PaginatedSettlementCaptureCoordinator._expected_pages(
        invocation,
        total=100,
    ) == 1
    assert PaginatedSettlementCaptureCoordinator._expected_pages(
        invocation,
        total=101,
    ) == 2
    assert PaginatedSettlementCaptureCoordinator._expected_pages(
        invocation,
        total=200,
    ) == 2
    assert PaginatedSettlementCaptureCoordinator._expected_pages(
        invocation,
        total=201,
    ) == 2
    assert PaginatedSettlementCaptureCoordinator._expected_pages(
        invocation,
        total=23_595,
    ) == 2


def test_rebound_window_resumes_only_the_unfinished_image(
    tmp_path: Path,
) -> None:
    request_audit = PlatformReadAuditEvidenceStore(tmp_path.resolve())
    adapter = RestartingReadAdapter(request_audit)
    checkpoints = MemoryCheckpointStore()
    invocations = InvocationStore()
    outward = OutwardStore()
    durable = DurableChengfengCaptureCoordinator(
        adapter=adapter,
        navigation_authorizer=type(
            "Authorizer",
            (),
            {"authorize": lambda self, authority: None},
        )(),
        checkpoint_store=checkpoints,
    )
    coordinator = PaginatedSettlementCaptureCoordinator(
        durable_coordinator=durable,
        checkpoint_store=checkpoints,
        invocation_store=invocations,
        outward_store=outward,
        image_reader=checkpoints,
        identity_salt=b"loop9-test-identity-salt-32-bytes",
        identity_namespace="chengfeng-production-account-v1",
        validate_authority=lambda invocation, authority, now: None,
        clock=lambda: NOW,
        request_audit_store=request_audit,
    )
    original_authority = BrowserCommandAuthority(
        session_id="session-1",
        instance_id="instance-1",
        worker_id="worker-1",
        job_id="job-1",
        control_epoch=1,
        fencing_token="fence-1",
    )

    while adapter.calls < 3:
        result = coordinator.advance(
            invocation_id="invocation-1",
            authority=original_authority,
        )
        assert result.has_more is True
    assert adapter.calls == 3
    assert checkpoints.checkpoint is not None
    checkpoint_before = checkpoints.checkpoint
    assert checkpoint_before.completed_list is True
    assert checkpoint_before.completed_detail_ids == ("platform-real-1",)
    assert tuple(checkpoint_before.ticket_images) == (
        "ticket-worker-1-loading",
    )
    assert checkpoint_before.read_access_window_ids == {
        "list": "window-1",
        (
            "detail:"
            + hashlib.sha256(b"platform-real-1").hexdigest()
        ): "window-1",
        (
            "image:"
            + hashlib.sha256(
                b"ticket-worker-1-loading"
            ).hexdigest()
        ): "window-1",
    }

    invocations.record = replace(
        invocations.record,
        access_window_id="window-2",
        record_version=2,
    )
    invocations.lineage = replace(
        invocations.lineage,
        access_window_ids=("window-1", "window-2"),
    )
    replacement_authority = BrowserCommandAuthority(
        session_id="session-1",
        instance_id="instance-1",
        worker_id="worker-2",
        job_id="job-1",
        control_epoch=3,
        fencing_token="fence-2",
    )
    while True:
        result = coordinator.advance(
            invocation_id="invocation-1",
            authority=replacement_authority,
        )
        if not result.has_more:
            break

    assert adapter.calls == 5
    assert invocations.seal_calls == 1
    assert invocations.record.status == "sealed"
    assert len(outward.manifests) == 1
    manifest = outward.manifests[0]
    assert manifest.sources[0].access_window_id == "window-1"
    assert manifest.access_window_lineage is not None
    assert manifest.access_window_lineage.access_window_ids == (
        "window-1",
        "window-2",
    )
    assert [
        (binding.read_kind, binding.access_window_id)
        for binding in manifest.read_access_bindings
    ] == [
        ("list", "window-1"),
        ("detail", "window-1"),
        ("image", "window-1"),
        ("detail", "window-2"),
        ("image", "window-2"),
    ]
    round_tripped = DurableCaptureCheckpoint.from_payload(
        checkpoints.checkpoint.to_payload()
    )
    assert (
        round_tripped.read_access_window_ids[
            "image:"
            + hashlib.sha256(
                b"ticket-worker-2-unloading"
            ).hexdigest()
        ]
        == "window-2"
    )


@pytest.mark.parametrize("roll_access_window", (False, True))
def test_restart_refreshes_detail_capability_and_only_reads_missing_image(
    tmp_path: Path,
    roll_access_window: bool,
) -> None:
    request_audit = PlatformReadAuditEvidenceStore(tmp_path.resolve())
    first_adapter = RestartingReadAdapter(request_audit)
    checkpoints = MemoryCheckpointStore()
    invocations = InvocationStore()
    outward = OutwardStore()

    def coordinator_for(
        adapter: RestartingReadAdapter,
    ) -> PaginatedSettlementCaptureCoordinator:
        durable = DurableChengfengCaptureCoordinator(
            adapter=adapter,
            navigation_authorizer=type(
                "Authorizer",
                (),
                {"authorize": lambda self, authority: None},
            )(),
            checkpoint_store=checkpoints,
        )
        return PaginatedSettlementCaptureCoordinator(
            durable_coordinator=durable,
            checkpoint_store=checkpoints,
            invocation_store=invocations,
            outward_store=outward,
            image_reader=checkpoints,
            identity_salt=b"loop9-test-identity-salt-32-bytes",
            identity_namespace="chengfeng-production-account-v1",
            validate_authority=lambda invocation, authority, now: None,
            clock=lambda: NOW,
            request_audit_store=request_audit,
        )

    first = coordinator_for(first_adapter)
    authority_one = BrowserCommandAuthority(
        session_id="session-1",
        instance_id="instance-1",
        worker_id="worker-1",
        job_id="job-1",
        control_epoch=1,
        fencing_token="fence-1",
    )
    for _ in range(10):
        first.advance(
            invocation_id="invocation-1",
            authority=authority_one,
        )
        checkpoint = checkpoints.checkpoint
        assert checkpoint is not None
        if len(checkpoint.ticket_images) == 1:
            break
    else:
        raise AssertionError("first image did not commit before restart")

    checkpoint = checkpoints.checkpoint
    assert checkpoint is not None
    first_ref = next(iter(checkpoint.ticket_images))
    assert checkpoint.detail_capability_worker_ids == {
        "platform-real-1": "worker-1"
    }
    assert checkpoint.detail_capability_access_window_ids == {
        "platform-real-1": "window-1"
    }
    if roll_access_window:
        invocations.record = replace(
            invocations.record,
            access_window_id="window-2",
            record_version=2,
        )
        invocations.lineage = replace(
            invocations.lineage,
            access_window_ids=("window-1", "window-2"),
        )
    replacement_adapter = RestartingReadAdapter(request_audit)
    replacement = coordinator_for(replacement_adapter)
    authority_two = BrowserCommandAuthority(
        session_id="session-1",
        instance_id="instance-1",
        worker_id="worker-2",
        job_id="job-1",
        control_epoch=2,
        fencing_token="fence-2",
    )

    for _ in range(10):
        result = replacement.advance(
            invocation_id="invocation-1",
            authority=authority_two,
        )
        if not result.has_more:
            break
    else:
        raise AssertionError("restarted capture did not seal")

    assert replacement_adapter.detail_calls == 1
    assert replacement_adapter.downloaded_ticket_refs == [
        "ticket-worker-2-unloading"
    ]
    assert first_ref == "ticket-worker-1-loading"
    assert len(checkpoints.content) == 2
    assert len(outward.manifests) == 1
    manifest = outward.manifests[0]
    assert manifest.request_audit_counts is not None
    assert manifest.request_audit_counts[
        "expected_succeeded_operations"
    ] == {
        "download_ticket_image": 2,
        "get_waybill_detail": 2,
        "list_waybills": 1,
    }
    bindings = [
        (binding.read_kind, binding.access_window_id)
        for binding in manifest.read_access_bindings
    ]
    assert bindings == (
        [
            ("list", "window-1"),
            ("detail", "window-1"),
            ("image", "window-1"),
            ("detail", "window-2"),
            ("image", "window-2"),
        ]
        if roll_access_window
        else [
            ("list", "window-1"),
            ("detail", "window-1"),
            ("detail", "window-1"),
            ("image", "window-1"),
            ("image", "window-1"),
        ]
    )
    assert all(
        binding.read_kind
        in {
            ChengfengStage.LIST_QUERY.value.removesuffix("_query"),
            ChengfengStage.DETAIL_QUERY.value.removesuffix("_query"),
            ChengfengStage.IMAGE_DOWNLOAD.value.removesuffix("_download"),
        }
        for binding in manifest.read_access_bindings
    )

    if roll_access_window:
        tampered = manifest.to_payload()
        raw_bindings = list(tampered["read_access_bindings"])
        tampered["read_access_bindings"] = [
            raw_bindings[-1],
            *raw_bindings[:-1],
        ]
        canonical_payload = {
            key: value
            for key, value in tampered.items()
            if key != "canonical_sha256"
        }
        tampered["canonical_sha256"] = hashlib.sha256(
            json.dumps(
                canonical_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        with pytest.raises(
            SettlementCaptureContractError,
            match="append-only",
        ):
            SettlementCaptureManifest.from_payload(tampered)
