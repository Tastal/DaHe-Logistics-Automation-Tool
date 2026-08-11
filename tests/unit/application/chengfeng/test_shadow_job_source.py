from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.adapters.files.shadow_batch_manifest import (
    ContentAddressedShadowImageReader,
    ShadowBatchManifestStore,
)
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowGrant,
)
from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    PersistedTicketImage,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
    ShadowCaptureBinding,
    build_chengfeng_shadow_batch,
)
from dahe.application.chengfeng.shadow_job_source import (
    ChengfengShadowJobSourceError,
    ChengfengShadowJobSourceResolver,
    ShadowJobExecutionAuthority,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.ports.chengfeng import (
    ChengfengStage,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)

BUILD_SHA = "a" * 64
CONTRACT_CANONICAL_SHA = "b" * 64
CONTRACT_FILE_SHA = "c" * 64
CONTRACT_SELECTION_SHA = "d" * 64
PIPELINE_SHA = "e" * 64


class _CaptureReader:
    def __init__(self, checkpoint: DurableCaptureCheckpoint) -> None:
        self.checkpoint = checkpoint

    def load_by_capture_id(
        self,
        *,
        capture_id: str,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None:
        if (
            capture_id,
            job_id,
            scope,
            page_number,
            page_size,
        ) != (
            self.checkpoint.capture_id,
            self.checkpoint.job_id,
            self.checkpoint.scope,
            self.checkpoint.page_number,
            self.checkpoint.page_size,
        ):
            return None
        return self.checkpoint


class _AccessReader:
    def __init__(self, grant: AccessWindowGrant) -> None:
        self.grant = grant

    def get_with_version(
        self,
        access_window_id: str,
    ) -> tuple[AccessWindowGrant, int]:
        if access_window_id != self.grant.access_window_id:
            raise KeyError(access_window_id)
        return self.grant, 2


class _SelectionReader:
    def __init__(
        self,
        selection: FormalShadowSelectionManifest,
    ) -> None:
        self.selection = selection

    def load(
        self,
        target_kind: ShadowBatchTargetKind,
    ) -> FormalShadowSelectionManifest:
        if self.selection.target_kind is not target_kind:
            raise KeyError(target_kind)
        return self.selection

    def load_active_real_shadow_manifest(
        self,
        canonical_sha256: str,
        *,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> FormalShadowSelectionManifest:
        batch = self.selection.batch_manifest
        if (
            self.selection.target_kind
            is not ShadowBatchTargetKind.REAL_SHADOW_30
            or self.selection.canonical_sha256 != canonical_sha256
            or batch.source_build_sha256
            != expected_current_build_sha256
            or batch.contract_canonical_sha256
            != expected_settlement_contract_sha256
        ):
            raise KeyError(canonical_sha256)
        return self.selection


def _png(seed: int) -> bytes:
    image = Image.new(
        "RGB",
        (8, 8),
        color=(seed % 251, (seed * 7) % 251, (seed * 17) % 251),
    )
    image.putpixel((seed % 8, (seed // 8) % 8), (255, 255, seed % 251))
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _checkpoint(
    evidence: ContentAddressedEvidenceStore,
    *,
    count: int,
) -> DurableCaptureCheckpoint:
    summaries: list[WaybillSummary] = []
    details: list[WaybillDetail] = []
    images: dict[str, PersistedTicketImage] = {}
    for index in range(count):
        platform_id = f"platform-{index:03d}"
        waybill_number = f"CF-{202607300000 + index}"
        summaries.append(
            WaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=f"vehicle-{index:03d}",
            )
        )
        tickets: list[TicketReference] = []
        for slot, seed in (
            ("loading", index * 2),
            ("unloading", index * 2 + 1),
        ):
            ticket_ref = f"ticket-{slot}-{index:03d}"
            stored = evidence.put_bytes(_png(seed), media_type="image/png")
            images[ticket_ref] = PersistedTicketImage(
                ticket_ref=ticket_ref,
                sha256=stored.sha256,
                relative_path=stored.relative_path,
                byte_size=stored.byte_size,
                media_type=stored.media_type,
            )
            tickets.append(
                TicketReference(
                    slot=slot,
                    ticket_ref=ticket_ref,
                    media_type="application/octet-stream",
                )
            )
        details.append(
            WaybillDetail(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=f"vehicle-{index:03d}",
                loading_net=f"{30 + index % 10}.10",
                unloading_net=f"{29 + index % 10}.90",
                tickets=tuple(tickets),
            )
        )
    return DurableCaptureCheckpoint(
        capture_id="capture-source-job-001-1",
        job_id="source-job-001",
        scope="current",
        page_number=1,
        page_size=count,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        revision=4 + count * 3,
        completed_list=True,
        completed_detail_ids=tuple(
            detail.platform_waybill_id for detail in details
        ),
        ticket_images=images,
        page=WaybillPage(
            page_number=1,
            page_size=count,
            total=count,
            items=tuple(summaries),
        ),
        details=tuple(details),
    )


def _grant(
    *,
    consumed: bool = True,
    purpose: AccessPurpose = AccessPurpose.PRODUCTION_SHADOW,
    build_sha256: str = BUILD_SHA,
) -> AccessWindowGrant:
    now = datetime(2026, 7, 30, tzinfo=UTC)
    return AccessWindowGrant(
        access_window_id="access-window-001",
        purpose=purpose,
        job_id="source-job-001",
        session_id="session-001",
        build_sha256=build_sha256,
        issued_at=now,
        expires_at=now + timedelta(minutes=60),
        token_digest="f" * 64,
        consumed_at=now + timedelta(minutes=10) if consumed else None,
    )


def _resolver_fixture(
    tmp_path: Path,
    *,
    grant: AccessWindowGrant | None = None,
    authority: ShadowJobExecutionAuthority | None = None,
    target_kind: ShadowBatchTargetKind = ShadowBatchTargetKind.REAL_SHADOW_30,
) -> tuple[
    ChengfengShadowJobSourceResolver,
    str,
    DurableCaptureCheckpoint,
]:
    evidence = ContentAddressedEvidenceStore(tmp_path / "data" / "evidence")
    image_reader = ContentAddressedShadowImageReader(evidence)
    checkpoint = _checkpoint(evidence, count=target_kind.expected_count)
    binding = ShadowCaptureBinding(
        checkpoint=checkpoint,
        access_window_id="access-window-001",
        source_build_sha256=BUILD_SHA,
        contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
        contract_file_sha256=CONTRACT_FILE_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
    )
    batch = build_chengfeng_shadow_batch(
        bindings=(binding,),
        target_kind=target_kind,
        pipeline_fingerprint=PIPELINE_SHA,
        identity_salt=b"loop9-shadow-job-source-test-salt",
        identity_namespace="loop9-shadow-job-source-test",
        image_reader=image_reader,
    )
    manifest_store = ShadowBatchManifestStore(
        tmp_path / "data" / "chengfeng-shadow-batches"
    )
    sealed = manifest_store.seal(batch.manifest)
    selection = FormalShadowSelectionManifest(
        target_kind=target_kind,
        source_capture_sha256="1" * 64,
        full_history_exclusion_authority_sha256="2" * 64,
        exclusion_child_index_head_sha256="3" * 64,
        exclusion_source_boundary_sha256="4" * 64,
        exclusion_source_inventory_high_watermark=1,
        selection_seed_authority_sha256="5" * 64,
        rank_commitment_sha256="6" * 64,
        prior_selection_sha256s=(
            ()
            if target_kind
            is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else ("7" * 64,)
        ),
        batch_manifest=batch.manifest,
        locked_gate_evidence_sha256=(
            None
            if target_kind
            is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else "8" * 64
        ),
    )
    resolver = ChengfengShadowJobSourceResolver(
        manifest_store=manifest_store,
        selection_reader=_SelectionReader(selection),
        capture_reader=_CaptureReader(checkpoint),
        access_reader=_AccessReader(
            grant
            or _grant(
                purpose=(
                    AccessPurpose.FORMAL_LOCKED_SET
                    if target_kind
                    is ShadowBatchTargetKind.CURRENT_LOCKED_50
                    else AccessPurpose.PRODUCTION_SHADOW
                )
            )
        ),
        image_reader=image_reader,
        authority=authority
        or ShadowJobExecutionAuthority(
            build_sha256=BUILD_SHA,
            contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
            contract_file_sha256=CONTRACT_FILE_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
        ),
    )
    return resolver, sealed.canonical_sha256, checkpoint


def test_resolver_revalidates_sources_and_returns_existing_scheduler_spec(
    tmp_path: Path,
) -> None:
    resolver, manifest_sha256, _ = _resolver_fixture(tmp_path)

    spec = resolver.resolve(
        target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
        manifest_sha256=manifest_sha256,
    )

    assert spec.job_kind == "business"
    assert spec.task_type == "audit"
    assert spec.ocr_execution_mode == "local"
    assert spec.pipeline_fingerprint == PIPELINE_SHA
    assert len(spec.items) == 30
    assert all(
        item.loading_image_relative_path is not None
        and item.loading_image_relative_path.startswith("evidence/sha256/")
        and item.unloading_image_relative_path is not None
        and item.unloading_image_relative_path.startswith("evidence/sha256/")
        for item in spec.items
    )


def test_resolver_preserves_exact_current_locked_fifty_contract(
    tmp_path: Path,
) -> None:
    resolver, manifest_sha256, _ = _resolver_fixture(
        tmp_path,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
    )

    spec = resolver.resolve(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        manifest_sha256=manifest_sha256,
    )

    assert len(spec.items) == 50
    assert spec.scope_label == "current_locked_50"


@pytest.mark.parametrize(
    ("grant", "authority", "message"),
    [
        (_grant(consumed=False), None, "consumed"),
        (
            _grant(purpose=AccessPurpose.FORMAL_LOCKED_SET),
            None,
            "purpose",
        ),
        (
            _grant(build_sha256="9" * 64),
            None,
            "build",
        ),
        (
            None,
            ShadowJobExecutionAuthority(
                build_sha256="9" * 64,
                contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
                contract_file_sha256=CONTRACT_FILE_SHA,
                contract_selection_sha256=CONTRACT_SELECTION_SHA,
            ),
            "build",
        ),
    ],
)
def test_resolver_rejects_unsealed_window_or_changed_authority(
    tmp_path: Path,
    grant: AccessWindowGrant | None,
    authority: ShadowJobExecutionAuthority | None,
    message: str,
) -> None:
    resolver, manifest_sha256, _ = _resolver_fixture(
        tmp_path,
        grant=grant,
        authority=authority,
    )

    with pytest.raises(ChengfengShadowJobSourceError, match=message):
        resolver.resolve(
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            manifest_sha256=manifest_sha256,
        )


def test_resolver_rejects_changed_capture_checkpoint(
    tmp_path: Path,
) -> None:
    resolver, manifest_sha256, checkpoint = _resolver_fixture(tmp_path)
    resolver.capture_reader = _CaptureReader(
        replace(checkpoint, revision=checkpoint.revision + 1)
    )

    with pytest.raises(
        ChengfengShadowJobSourceError,
        match="checkpoint",
    ):
        resolver.resolve(
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            manifest_sha256=manifest_sha256,
        )


def test_manifest_store_rejects_noncanonical_file_tampering(
    tmp_path: Path,
) -> None:
    resolver, manifest_sha256, _ = _resolver_fixture(tmp_path)
    store = resolver.manifest_store
    path = store.path_for(manifest_sha256)
    content = path.read_bytes()
    path.write_bytes(b" " + content)

    with pytest.raises(ChengfengShadowJobSourceError, match="canonical"):
        resolver.resolve(
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            manifest_sha256=manifest_sha256,
        )


def test_resolver_rejects_batch_outside_active_formal_selection(
    tmp_path: Path,
) -> None:
    resolver, manifest_sha256, _ = _resolver_fixture(tmp_path)
    selection = resolver.selection_reader.load(
        ShadowBatchTargetKind.REAL_SHADOW_30
    )
    resolver.selection_reader = _SelectionReader(
        replace(
            selection,
            batch_manifest=replace(
                selection.batch_manifest,
                pipeline_fingerprint="0" * 64,
            ),
        )
    )

    with pytest.raises(
        ChengfengShadowJobSourceError,
        match="active formal selection",
    ):
        resolver.resolve(
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            manifest_sha256=manifest_sha256,
        )
