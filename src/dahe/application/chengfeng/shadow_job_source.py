from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowGrant,
)
from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
)
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchContractError,
    ChengfengShadowBatchManifest,
    SafeImageReader,
    ShadowBatchItem,
    ShadowBatchTargetKind,
    ShadowCaptureBinding,
    build_chengfeng_shadow_batch,
    scheduled_job_from_shadow_manifest,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.jobs.specs import ScheduledJobSpec


class ChengfengShadowJobSourceError(RuntimeError):
    """Raised when a sealed real-platform batch cannot be reauthorized."""


class ShadowBatchManifestReader(Protocol):
    def load(
        self,
        canonical_sha256: str,
    ) -> ChengfengShadowBatchManifest: ...


class FormalShadowSelectionReader(Protocol):
    def load(
        self,
        target_kind: ShadowBatchTargetKind,
    ) -> FormalShadowSelectionManifest: ...

    def load_active_real_shadow_manifest(
        self,
        canonical_sha256: str,
        *,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> FormalShadowSelectionManifest: ...


class ShadowCaptureReader(Protocol):
    def load_by_capture_id(
        self,
        *,
        capture_id: str,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None: ...


class ShadowAccessReader(Protocol):
    def get_with_version(
        self,
        access_window_id: str,
    ) -> tuple[AccessWindowGrant, int]: ...


class ChengfengShadowJobSource(Protocol):
    def resolve(
        self,
        *,
        target_kind: ShadowBatchTargetKind,
        manifest_sha256: str,
    ) -> ScheduledJobSpec: ...


@dataclass(frozen=True, slots=True)
class ShadowJobExecutionAuthority:
    build_sha256: str
    contract_canonical_sha256: str
    contract_file_sha256: str
    contract_selection_sha256: str


def _image_payload(item: ShadowBatchItem) -> tuple[object, ...]:
    return (
        item.platform_loading_net,
        item.platform_unloading_net,
        tuple(
            (
                image.slot,
                image.sha256,
                image.relative_path,
                image.byte_size,
                image.media_type,
                json.dumps(
                    image.perceptual_fingerprint.to_record(),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
            for image in item.images
        ),
    )


def _purpose(target_kind: ShadowBatchTargetKind) -> AccessPurpose:
    return (
        AccessPurpose.FORMAL_LOCKED_SET
        if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50
        else AccessPurpose.PRODUCTION_SHADOW
    )


@dataclass(slots=True)
class ChengfengShadowJobSourceResolver:
    manifest_store: ShadowBatchManifestReader
    selection_reader: FormalShadowSelectionReader
    capture_reader: ShadowCaptureReader
    access_reader: ShadowAccessReader
    image_reader: SafeImageReader
    authority: ShadowJobExecutionAuthority

    def _load_bindings(
        self,
        manifest: ChengfengShadowBatchManifest,
    ) -> tuple[ShadowCaptureBinding, ...]:
        bindings: list[ShadowCaptureBinding] = []
        expected_purpose = _purpose(manifest.target_kind)
        for source in manifest.sources:
            try:
                grant, _ = self.access_reader.get_with_version(
                    source.access_window_id
                )
            except Exception as exc:
                raise ChengfengShadowJobSourceError(
                    "source access window is unavailable"
                ) from exc
            if grant.access_window_id != source.access_window_id:
                raise ChengfengShadowJobSourceError(
                    "source access-window identity changed"
                )
            if grant.purpose is not expected_purpose:
                raise ChengfengShadowJobSourceError(
                    "source access-window purpose changed"
                )
            if grant.job_id != source.job_id:
                raise ChengfengShadowJobSourceError(
                    "source access-window job binding changed"
                )
            if grant.build_sha256 != self.authority.build_sha256:
                raise ChengfengShadowJobSourceError(
                    "source access-window build binding changed"
                )
            if grant.consumed_at is None:
                raise ChengfengShadowJobSourceError(
                    "source access window is not consumed and sealed"
                )
            try:
                checkpoint = self.capture_reader.load_by_capture_id(
                    capture_id=source.capture_id,
                    job_id=source.job_id,
                    scope=source.scope,
                    page_number=source.page_number,
                    page_size=source.page_size,
                )
            except Exception as exc:
                raise ChengfengShadowJobSourceError(
                    "source capture checkpoint is unavailable"
                ) from exc
            if checkpoint is None:
                raise ChengfengShadowJobSourceError(
                    "source capture checkpoint is unavailable"
                )
            bindings.append(
                ShadowCaptureBinding(
                    checkpoint=checkpoint,
                    access_window_id=source.access_window_id,
                    source_build_sha256=self.authority.build_sha256,
                    contract_canonical_sha256=(
                        self.authority.contract_canonical_sha256
                    ),
                    contract_file_sha256=self.authority.contract_file_sha256,
                    contract_selection_sha256=(
                        self.authority.contract_selection_sha256
                    ),
                )
            )
        return tuple(bindings)

    def _verify_current_authority(
        self,
        manifest: ChengfengShadowBatchManifest,
    ) -> None:
        expected = (
            self.authority.build_sha256,
            self.authority.contract_canonical_sha256,
            self.authority.contract_file_sha256,
            self.authority.contract_selection_sha256,
        )
        actual = (
            manifest.source_build_sha256,
            manifest.contract_canonical_sha256,
            manifest.contract_file_sha256,
            manifest.contract_selection_sha256,
        )
        if actual[0] != expected[0]:
            raise ChengfengShadowJobSourceError(
                "shadow batch build authority changed"
            )
        if actual[1:] != expected[1:]:
            raise ChengfengShadowJobSourceError(
                "shadow batch contract authority changed"
            )

    def resolve(
        self,
        *,
        target_kind: ShadowBatchTargetKind,
        manifest_sha256: str,
    ) -> ScheduledJobSpec:
        try:
            selection = self.selection_reader.load(target_kind)
            if target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
                selection = (
                    self.selection_reader.load_active_real_shadow_manifest(
                        selection.canonical_sha256,
                        expected_current_build_sha256=(
                            self.authority.build_sha256
                        ),
                        expected_settlement_contract_sha256=(
                            self.authority.contract_canonical_sha256
                        ),
                    )
                )
        except Exception as exc:
            raise ChengfengShadowJobSourceError(
                "formal selection build or contract authority is unavailable"
            ) from exc
        try:
            manifest = self.manifest_store.load(manifest_sha256)
        except Exception as exc:
            raise ChengfengShadowJobSourceError(
                f"shadow batch manifest is not canonical: {exc}"
            ) from exc
        if manifest.target_kind is not target_kind:
            raise ChengfengShadowJobSourceError(
                "shadow batch target kind changed"
            )
        if (
            selection.target_kind is not target_kind
            or selection.batch_manifest.canonical_sha256
            != manifest.canonical_sha256
            or selection.batch_manifest.to_payload()
            != manifest.to_payload()
        ):
            raise ChengfengShadowJobSourceError(
                "shadow batch is not the active formal selection"
            )
        self._verify_current_authority(manifest)
        bindings = self._load_bindings(manifest)
        try:
            revalidated = build_chengfeng_shadow_batch(
                bindings=bindings,
                target_kind=target_kind,
                pipeline_fingerprint=manifest.pipeline_fingerprint,
                identity_salt=hashlib.sha256(
                    (
                        "dahe:shadow-source-revalidation:v1:"
                        + manifest.identity_context_sha256
                    ).encode("ascii")
                ).digest(),
                identity_namespace="shadow-source-revalidation-v1",
                image_reader=self.image_reader,
            )
        except ChengfengShadowBatchContractError as exc:
            raise ChengfengShadowJobSourceError(
                f"source capture checkpoint validation failed: {exc}"
            ) from exc
        if revalidated.manifest.sources != manifest.sources:
            raise ChengfengShadowJobSourceError(
                "source capture checkpoint identity changed"
            )
        expected_evidence = sorted(
            (_image_payload(item) for item in manifest.items),
            key=repr,
        )
        actual_evidence = sorted(
            (_image_payload(item) for item in revalidated.manifest.items),
            key=repr,
        )
        if actual_evidence != expected_evidence:
            raise ChengfengShadowJobSourceError(
                "source capture evidence changed"
            )
        return scheduled_job_from_shadow_manifest(manifest)
