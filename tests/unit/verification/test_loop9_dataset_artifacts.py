from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import date, datetime, timedelta
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

import dahe.verification.loop9_dataset_artifacts as artifacts_module
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
    ShadowBatchImage,
    ShadowBatchItem,
    ShadowBatchSource,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.domain.daily.calendar import (
    SHANGHAI,
    CandidateQueryWindow,
    business_day_window,
)
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyWaybillObservation,
)
from dahe.ports.daily import DailySnapshotCaptureAuthority
from dahe.verification.daily_snapshot_validation import (
    DailyContractSelectionBinding,
    validate_daily_snapshot_triplet,
)
from dahe.verification.image_similarity import build_image_fingerprint
from dahe.verification.loop9_dataset_artifacts import (
    Loop9DailyTripletInventory,
    Loop9DatasetArtifactError,
    build_daily_dataset_manifest,
    build_daily_triplet_inventory,
    build_discovery_dataset_manifest,
    build_formal_dataset_manifest,
    build_legacy_loop7_exclusion_inventory,
    identity_context_sha256,
    merge_loop9_exclusion_inventories,
    platform_waybill_identity_digest,
)
from dahe.verification.loop9_dataset_isolation import (
    DatasetKind,
    ExclusionKind,
    Loop9DatasetExclusionInventory,
    Loop9DatasetIsolationError,
    parse_loop9_dataset_manifest,
)
from tests.fixtures.formal_development_authority import (
    formal_development_authority,
)

BUILD_SHA = "a" * 64
SETTLEMENT_CONTRACT_SHA = "b" * 64
DAILY_CONTRACT_SHA = "c" * 64
DAILY_CONTRACT_SELECTION = DailyContractSelectionBinding(
    contract_canonical_sha256=DAILY_CONTRACT_SHA,
    contract_file_sha256="d" * 64,
    freeze_evidence_sha256="e" * 64,
    selection_sha256="f" * 64,
    source_discovery_sha256="1" * 64,
)
IDENTITY_KEY = b"loop9-identity-key-material-32bytes"
IDENTITY_NAMESPACE = "chengfeng-production-account-v1"


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def test_legacy_loop7_inventory_preserves_the_formal_source_boundary() -> None:
    authority = formal_development_authority()
    identity_context = _sha("loop9-installation-identity-context")

    inventory = build_legacy_loop7_exclusion_inventory(
        inventory_id="loop9-legacy-loop7-source",
        source_authority=authority,
        identity_context_sha256=identity_context,
    )

    assert inventory.exclusion_kind is ExclusionKind.LEGACY_LOOP7
    assert inventory.identity_context_sha256 == identity_context
    assert inventory.platform_identity_sha256s == tuple(
        sorted(authority.waybill_identity_sha256s)
    )
    assert inventory.image_sha256s == tuple(
        sorted(authority.image_sha256s)
    )
    assert {
        fingerprint.content_sha256
        for fingerprint in inventory.perceptual_fingerprints
    } == set(authority.image_sha256s)
    assert inventory.scope_exclusion_tokens == ()
    inventory.verify_integrity()


def _png(seed: int) -> bytes:
    image = Image.new(
        "RGB",
        (32, 24),
        (seed % 251, (seed * 7) % 251, (seed * 13) % 251),
    )
    image.putpixel((seed % 32, seed % 24), (255, 255, seed % 251))
    output = BytesIO()
    image.save(output, "PNG")
    return output.getvalue()


class _Images:
    def __init__(self, values: dict[str, bytes]) -> None:
        self._values = values

    def read_verified_image(self, image_sha256: str) -> bytes:
        return self._values[image_sha256]


def _shadow_manifest(
    target: ShadowBatchTargetKind,
) -> ChengfengShadowBatchManifest:
    items = []
    for index in range(target.expected_count):
        images = []
        for slot, seed in (("loading", index * 2), ("unloading", index * 2 + 1)):
            content = _png(seed)
            sha256 = hashlib.sha256(content).hexdigest()
            images.append(
                ShadowBatchImage(
                    slot=slot,
                    sha256=sha256,
                    relative_path=(
                        f"sha256/{sha256[:2]}/{sha256[2:4]}/{sha256}.blob"
                    ),
                    byte_size=len(content),
                    media_type="image/png",
                    perceptual_fingerprint=build_image_fingerprint(content),
                )
            )
        items.append(
            ShadowBatchItem(
                platform_waybill_id_digest=(
                    platform_waybill_identity_digest(
                        salt=IDENTITY_KEY,
                        namespace=IDENTITY_NAMESPACE,
                        source_identity=f"platform-{index}",
                    )
                ),
                waybill_number_digest=_sha(f"waybill-{index}"),
                vehicle_number_digest=None,
                platform_loading_net="30.00",
                platform_unloading_net="29.90",
                images=(images[0], images[1]),
            )
        )
    return ChengfengShadowBatchManifest(
        target_kind=target,
        source_build_sha256=BUILD_SHA,
        contract_canonical_sha256=SETTLEMENT_CONTRACT_SHA,
        contract_file_sha256="d" * 64,
        contract_selection_sha256="e" * 64,
        pipeline_fingerprint="f" * 64,
        identity_context_sha256=identity_context_sha256(
            salt=IDENTITY_KEY,
            namespace=IDENTITY_NAMESPACE,
        ),
        sources=(
            ShadowBatchSource(
                access_window_id="window-1",
                job_id="source-job-1",
                capture_id="capture-1",
                scope="current",
                page_number=1,
                page_size=target.expected_count,
                checkpoint_sha256="1" * 64,
            ),
        ),
        items=tuple(items),
    )


def _formal_selection(
    target: ShadowBatchTargetKind,
    *,
    batch: ChengfengShadowBatchManifest | None = None,
) -> FormalShadowSelectionManifest:
    selected_batch = batch or _shadow_manifest(target)
    return FormalShadowSelectionManifest(
        target_kind=target,
        source_capture_sha256=_sha(f"capture:{target.value}"),
        full_history_exclusion_authority_sha256=_sha(
            f"exclusions:{target.value}"
        ),
        exclusion_child_index_head_sha256=_sha(
            f"exclusion-head:{target.value}"
        ),
        exclusion_source_boundary_sha256=_sha(
            f"exclusion-boundary:{target.value}"
        ),
        exclusion_source_inventory_high_watermark=100,
        selection_seed_authority_sha256=_sha(
            f"selection-seed:{target.value}"
        ),
        rank_commitment_sha256=_sha(f"rank:{target.value}"),
        prior_selection_sha256s=(
            ()
            if target is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else (_sha("locked-selection"),)
        ),
        batch_manifest=selected_batch,
        locked_gate_evidence_sha256=(
            None
            if target is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else _sha("current-locked-gate")
        ),
    )


def _development_inventory() -> Loop9DatasetExclusionInventory:
    contents = (_png(1001), _png(1002))
    fingerprints = tuple(build_image_fingerprint(value) for value in contents)
    return Loop9DatasetExclusionInventory(
        inventory_id="contract-validation-window-1",
        exclusion_kind=ExclusionKind.DEVELOPMENT,
        platform_identity_sha256s=(_sha("discovery-waybill"),),
        image_sha256s=tuple(
            fingerprint.content_sha256 for fingerprint in fingerprints
        ),
        scope_exclusion_tokens=(),
        perceptual_fingerprints=fingerprints,
        identity_context_sha256=identity_context_sha256(
            salt=IDENTITY_KEY,
            namespace=IDENTITY_NAMESPACE,
        ),
    )


def _validation_document(
    inventory: Loop9DatasetExclusionInventory,
) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": 3,
        "kind": "loop9_live_read_contract_validation",
        "classification": "development_only",
        "access_window_id": "window-1",
        "build_sha256": BUILD_SHA,
        "contract_canonical_sha256": SETTLEMENT_CONTRACT_SHA,
        "development_exclusion_inventory_sha256": inventory.canonical_sha256,
        "identity_context_sha256": inventory.identity_context_sha256,
        "gate_passed": True,
        "forbidden_request_count": 0,
        "platform_write_request_count": 0,
        "redirect_count": 0,
        "raw_request_values_retained": False,
        "raw_response_values_retained": False,
        "signed_image_urls_retained": False,
    }
    return {
        **body,
        "canonical_sha256": hashlib.sha256(
            __import__("json").dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
    }


def _daily_authority(
    index: int,
) -> tuple[DailySnapshotCaptureAuthority, tuple[DailyWaybillObservation, ...]]:
    business_date = date(2026, 7, 28)
    business_window = business_day_window(business_date)
    window = CandidateQueryWindow(
        business_date=business_date,
        start=business_window.start - timedelta(minutes=30),
        end=business_window.end,
        safety_end=business_window.end + timedelta(minutes=30),
    )
    snapshot_id = f"daily-snapshot-{index}"
    candidates = tuple(
        DailyCandidate(
            platform_waybill_id=f"platform-{candidate}",
            waybill_number=f"WB-{candidate}",
        )
        for candidate in range(2)
    )
    snapshot = DailyCandidateSnapshot(
        snapshot_id=snapshot_id,
        target_business_date=business_date,
        receive_place="test-place",
        query_window=window,
        source_contract_sha256=DAILY_CONTRACT_SHA,
        candidates=candidates,
        captured_at=datetime(2026, 7, 29, 15 + index, tzinfo=SHANGHAI),
    )
    observations = []
    for candidate in range(2):
        loading = _png(2000 + candidate)
        unloading = _png(3000 + candidate)
        observations.append(
            DailyWaybillObservation(
                observation_id=f"observation-{index}-{candidate}",
                snapshot_id=snapshot_id,
                platform_waybill_id=f"platform-{candidate}",
                waybill_number=f"WB-{candidate}",
                fields=DailyObservationFields(
                    shipping_mine=None,
                    planned_date=None,
                    loading_time=None,
                    vehicle_number=None,
                    loading_net_tonnes=None,
                    unloading_net_tonnes=None,
                    coal_type=None,
                    unloading_place=None,
                    unloading_time=None,
                ),
                loading_ticket_sha256=hashlib.sha256(loading).hexdigest(),
                unloading_ticket_sha256=hashlib.sha256(unloading).hexdigest(),
                source_detail_sha256=_sha(f"detail-{index}-{candidate}"),
                observed_at=datetime(
                    2026,
                    7,
                    29,
                    15 + index,
                    5,
                    tzinfo=SHANGHAI,
                ),
            )
        )
    audit_job_sha256 = hashlib.sha256(snapshot_id.encode()).hexdigest()
    audit_event_chain_sha256 = _sha(f"request-audit-chain-{index}")
    audit_authority = {
        "build_sha256": BUILD_SHA,
        "daily_contract_selection_sha256": (
            DAILY_CONTRACT_SELECTION.selection_sha256
        ),
        "daily_contract_sha256": DAILY_CONTRACT_SHA,
        "settlement_contract_selection_sha256": "9" * 64,
        "settlement_contract_sha256": SETTLEMENT_CONTRACT_SHA,
    }
    audit_request_counts = {
        "allowed": 8,
        "attempted": 8,
        "denied": 0,
        "succeeded": 8,
    }
    audit_operation_counts = {
        "download_ticket_image": {
            "allowed": 4,
            "attempted": 4,
            "denied": 0,
            "failed": 0,
            "redirect": 0,
            "succeeded": 4,
        },
        "get_waybill_detail": {
            "allowed": 2,
            "attempted": 2,
            "denied": 0,
            "failed": 0,
            "redirect": 0,
            "succeeded": 2,
        },
        "list_daily_waybills": {
            "allowed": 2,
            "attempted": 2,
            "denied": 0,
            "failed": 0,
            "redirect": 0,
            "succeeded": 2,
        },
        "list_waybills": {
            "allowed": 0,
            "attempted": 0,
            "denied": 0,
            "failed": 0,
            "redirect": 0,
            "succeeded": 0,
        },
    }
    audit_expected = {
        "download_ticket_image": 4,
        "get_waybill_detail": 2,
        "list_daily_waybills": 2,
    }
    audit_body = {
        "authority": audit_authority,
        "event_chain_sha256": audit_event_chain_sha256,
        "event_count": 24,
        "expected_succeeded_operations": audit_expected,
        "job_id_sha256": audit_job_sha256,
        "kind": "loop9_platform_read_audit",
        "operation_counts": audit_operation_counts,
        "platform_write_request_count": 0,
        "purpose": "daily_snapshot",
        "redirect_count": 0,
        "request_counts": audit_request_counts,
        "schema_version": 1,
    }
    audit_sha256 = hashlib.sha256(
        json.dumps(
            audit_body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    access_window_id = f"window-{index}"
    read_access_window_ids = {
        "list:1": access_window_id,
        "list:2": access_window_id,
    }
    for candidate in range(2):
        identity = hashlib.sha256(
            f"platform-{candidate}".encode()
        ).hexdigest()
        read_access_window_ids[
            f"detail:{identity}:1"
        ] = access_window_id
        read_access_window_ids[
            f"image:{identity}:loading"
        ] = access_window_id
        read_access_window_ids[
            f"image:{identity}:unloading"
        ] = access_window_id
    return (
        DailySnapshotCaptureAuthority(
            snapshot=snapshot,
            invocation_id=snapshot_id,
            job_id=snapshot_id,
            access_window_id=access_window_id,
            access_window_ids=(access_window_id,),
            read_access_window_ids=read_access_window_ids,
            capture_build_sha256=BUILD_SHA,
            access_purpose="production_shadow",
            access_consumed=True,
            invocation_contract_sha256=DAILY_CONTRACT_SHA,
            invocation_status="succeeded",
            invocation_next_stage="daily.complete",
            invocation_diagnostic_code=None,
            job_status="succeeded",
            job_current_stage="daily.complete",
            job_diagnostic_code=None,
            work_item_count=1,
            succeeded_work_item_count=1,
            completed_stage_work_item_count=1,
            observation_count=2,
            request_audit_sha256=audit_sha256,
            request_audit_job_id_sha256=audit_job_sha256,
            request_audit_purpose="daily_snapshot",
            request_audit_authority=audit_authority,
            request_audit_request_counts=audit_request_counts,
            request_audit_operation_counts=audit_operation_counts,
            request_audit_event_count=24,
            request_audit_event_chain_sha256=audit_event_chain_sha256,
            request_audit_expected_succeeded_operations=audit_expected,
            request_audit_kind="loop9_platform_read_audit",
            request_audit_schema_version=1,
            forbidden_request_count=0,
            platform_write_request_count=0,
            redirect_count=0,
        ),
        tuple(observations),
    )


def _daily_evidence(
    authorities: tuple[DailySnapshotCaptureAuthority, ...],
) -> dict[str, object]:
    return validate_daily_snapshot_triplet(
        authorities,
        build_sha256=BUILD_SHA,
        expected_contract_sha256=DAILY_CONTRACT_SHA,
        contract_selection=DAILY_CONTRACT_SELECTION,
    )


def _historical_daily_evidence(
    authorities: tuple[DailySnapshotCaptureAuthority, ...],
) -> dict[str, object]:
    current = _daily_evidence(authorities)
    snapshots = []
    for raw_snapshot in current["snapshot_evidence"]:
        assert isinstance(raw_snapshot, dict)
        snapshot = dict(raw_snapshot)
        snapshot.pop("access_window_ids")
        snapshot.pop("read_access_window_ids")
        snapshots.append(snapshot)
    body = {
        **current,
        "schema_version": 4,
        "snapshot_evidence": snapshots,
    }
    body.pop("canonical_sha256")
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return body


def test_builds_discovery_manifest_from_bound_sanitized_validation() -> None:
    inventory = _development_inventory()

    result = build_discovery_dataset_manifest(
        dataset_id="loop9-discovery-development",
        validation_document=_validation_document(inventory),
        development_inventory=inventory,
    )

    assert result.dataset_kind is DatasetKind.DISCOVERY_DEVELOPMENT
    assert result.build_sha256 == BUILD_SHA
    assert result.contract_sha256 == SETTLEMENT_CONTRACT_SHA
    assert (
        result.source_snapshot_sha256
        == _validation_document(inventory)["canonical_sha256"]
    )
    assert len(result.entries) == 1
    assert result.entries[0].platform_identity_sha256 == _sha(
        "discovery-waybill"
    )
    assert len(result.entries[0].images) == 2
    assert (
        parse_loop9_dataset_manifest(result.to_payload()).canonical_sha256
        == result.canonical_sha256
    )


def test_discovery_manifest_rejects_unbound_or_unsafe_validation() -> None:
    inventory = _development_inventory()
    document = _validation_document(inventory)
    document["platform_write_request_count"] = 1

    with pytest.raises(Loop9DatasetArtifactError, match="integrity"):
        build_discovery_dataset_manifest(
            dataset_id="loop9-discovery-development",
            validation_document=document,
            development_inventory=inventory,
        )

    document = _validation_document(inventory)
    document["development_exclusion_inventory_sha256"] = "f" * 64
    with pytest.raises(Loop9DatasetArtifactError, match="integrity"):
        build_discovery_dataset_manifest(
            dataset_id="loop9-discovery-development",
            validation_document=document,
            development_inventory=inventory,
        )


@pytest.mark.parametrize(
    ("target", "expected_kind", "expected_count"),
    (
        (
            ShadowBatchTargetKind.CURRENT_LOCKED_50,
            DatasetKind.CURRENT_LOCKED_50,
            50,
        ),
        (
            ShadowBatchTargetKind.REAL_SHADOW_30,
            DatasetKind.REAL_SHADOW_30,
            30,
        ),
    ),
)
def test_builds_formal_manifest_from_verified_shadow_batch(
    target: ShadowBatchTargetKind,
    expected_kind: DatasetKind,
    expected_count: int,
) -> None:
    source = _shadow_manifest(target)
    selection = _formal_selection(target, batch=source)

    result = build_formal_dataset_manifest(
        dataset_id=f"loop9-{target.value}",
        shadow_batch=source,
        formal_selection=selection,
    )

    assert result.dataset_kind is expected_kind
    assert len(result.entries) == expected_count
    assert result.image_count == expected_count * 2
    assert result.build_sha256 == BUILD_SHA
    assert result.contract_sha256 == SETTLEMENT_CONTRACT_SHA
    assert result.source_job_id == "source-job-1"
    assert result.source_snapshot_sha256 == source.canonical_sha256
    assert result.formal_selection_sha256 == selection.canonical_sha256
    assert (
        result.locked_gate_evidence_sha256
        == selection.locked_gate_evidence_sha256
    )
    assert (
        result.identity_context_sha256
        == source.identity_context_sha256
    )


def test_formal_manifest_rejects_a_batch_outside_the_selection() -> None:
    source = _shadow_manifest(ShadowBatchTargetKind.CURRENT_LOCKED_50)
    other = replace(
        source,
        sources=(
            replace(
                source.sources[0],
                checkpoint_sha256=_sha("other-checkpoint"),
            ),
        ),
    )
    selection = _formal_selection(
        ShadowBatchTargetKind.CURRENT_LOCKED_50,
        batch=source,
    )

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="formal selection",
    ):
        build_formal_dataset_manifest(
            dataset_id="loop9-current-locked-50",
            shadow_batch=other,
            formal_selection=selection,
        )


def test_formal_manifest_rejects_multiple_source_jobs() -> None:
    source = _shadow_manifest(ShadowBatchTargetKind.REAL_SHADOW_30)
    changed = replace(
        source,
        sources=(
            source.sources[0],
            replace(
                source.sources[0],
                capture_id="capture-2",
                job_id="source-job-2",
                page_number=2,
            ),
        ),
    )

    with pytest.raises(Loop9DatasetArtifactError, match="one source Job"):
        build_formal_dataset_manifest(
            dataset_id="loop9-real-shadow-30",
            shadow_batch=changed,
            formal_selection=_formal_selection(
                ShadowBatchTargetKind.REAL_SHADOW_30,
                batch=changed,
            ),
        )


def test_builds_daily_triplet_inventory_and_manifest_without_raw_identity() -> None:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)
    observations = {
        pair[0].snapshot.snapshot_id: pair[1] for pair in pairs
    }
    image_values: dict[str, bytes] = {}
    for candidate in range(2):
        for content in (_png(2000 + candidate), _png(3000 + candidate)):
            image_values[hashlib.sha256(content).hexdigest()] = content

    inventory = build_daily_triplet_inventory(
        daily_validation=_daily_evidence(authorities),
        contract_selection=DAILY_CONTRACT_SELECTION,
        authorities=authorities,
        observations_by_snapshot=observations,
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        image_reader=_Images(image_values),
    )
    replayed = Loop9DailyTripletInventory.from_payload(
        inventory.to_payload()
    )
    manifest = build_daily_dataset_manifest(
        dataset_id="loop9-daily-triplet",
        inventory=replayed,
    )

    assert inventory.identity_context_sha256 == identity_context_sha256(
        salt=IDENTITY_KEY,
        namespace=IDENTITY_NAMESPACE,
    )
    assert len(inventory.snapshot_bindings) == 3
    assert len(inventory.entries) == 2
    assert all(len(entry.images) == 2 for entry in inventory.entries)
    assert manifest.dataset_kind is DatasetKind.DAILY_VALIDATION
    assert manifest.build_sha256 == BUILD_SHA
    assert manifest.contract_sha256 == DAILY_CONTRACT_SHA
    assert (
        manifest.identity_context_sha256
        == inventory.identity_context_sha256
    )
    encoded = __import__("json").dumps(inventory.to_payload())
    assert "platform-0" not in encoded
    assert IDENTITY_NAMESPACE not in encoded
    assert IDENTITY_KEY.decode() not in encoded


def _daily_artifacts() -> tuple[
    dict[str, object],
    Loop9DailyTripletInventory,
    object,
    tuple[
        tuple[
            DailySnapshotCaptureAuthority,
            tuple[DailyWaybillObservation, ...],
        ],
        ...,
    ],
    dict[str, bytes],
]:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)
    observations = {
        pair[0].snapshot.snapshot_id: pair[1] for pair in pairs
    }
    image_values: dict[str, bytes] = {}
    for candidate in range(2):
        for content in (_png(2000 + candidate), _png(3000 + candidate)):
            image_values[hashlib.sha256(content).hexdigest()] = content
    evidence = _daily_evidence(authorities)
    inventory = build_daily_triplet_inventory(
        daily_validation=evidence,
        contract_selection=DAILY_CONTRACT_SELECTION,
        authorities=authorities,
        observations_by_snapshot=observations,
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        image_reader=_Images(image_values),
    )
    manifest = build_daily_dataset_manifest(
        dataset_id="loop9-daily-validation",
        inventory=inventory,
    )
    return evidence, inventory, manifest, pairs, image_values


def _rehash_manifest(payload: dict[str, object]) -> dict[str, object]:
    body = deepcopy(payload)
    body.pop("canonical_sha256")
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return body


@pytest.mark.parametrize(
    "tamper",
    (
        "entry_identity",
        "entry_image",
        "entry_fingerprint",
        "source_job_id",
    ),
)
def test_current_daily_manifest_replay_rejects_rehashed_authority_tampering(
    tamper: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence, inventory, manifest, _pairs, _images = _daily_artifacts()
    payload = manifest.to_payload()
    entries = payload["entries"]
    assert isinstance(entries, list)
    first = entries[0]
    second = entries[1]
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    first_images = first["images"]
    second_images = second["images"]
    assert isinstance(first_images, list)
    assert isinstance(second_images, list)
    if tamper == "entry_identity":
        first["platform_identity_sha256"] = "9" * 64
    elif tamper == "entry_image":
        first_images[0] = deepcopy(second_images[0])
    elif tamper == "entry_fingerprint":
        image = first_images[0]
        assert isinstance(image, dict)
        fingerprint = image["perceptual_fingerprint"]
        assert isinstance(fingerprint, dict)
        fingerprint["width"] = int(fingerprint["width"]) + 1
        fingerprint_body = dict(fingerprint)
        fingerprint_body.pop("canonical_sha256")
        fingerprint["canonical_sha256"] = hashlib.sha256(
            json.dumps(
                fingerprint_body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    else:
        payload["source_job_id"] = "daily-triplet-rehashed-tamper"
    tampered = _rehash_manifest(payload)
    rebuilt = SimpleNamespace(
        inventory=inventory,
        manifest=manifest,
    )
    monkeypatch.setattr(
        artifacts_module,
        "rebuild_current_daily_dataset_artifacts_from_store",
        lambda **_kwargs: rebuilt,
        raising=False,
    )

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="persisted daily dataset manifest",
    ):
        artifacts_module.replay_current_daily_dataset_manifest_from_store(
            tampered,
            daily_validation=evidence,
            data_root=tmp_path,
            project_root=tmp_path,
            source_build_sha256=BUILD_SHA,
            expected_dataset_id="loop9-daily-validation",
        )


def test_current_daily_dataset_rebuild_reloads_every_formal_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence, inventory, manifest, pairs, images = _daily_artifacts()
    data_root = (tmp_path / "formal").resolve()
    project_root = (tmp_path / "project").resolve()
    (data_root / "evidence").mkdir(parents=True)
    project_root.mkdir()
    loaded_authorities: list[str] = []
    loaded_observations: list[str] = []
    closed: list[bool] = []
    replay_calls: list[tuple[Path, Path, str]] = []

    class FakeRuntime:
        def __init__(self, **values: object) -> None:
            assert values["data_root"] == data_root
            assert values["project_root"] == project_root

        def close(self) -> None:
            closed.append(True)

    class FakeStore:
        def __init__(self, _runtime: object) -> None:
            pass

        def get_formal_snapshot_authority(
            self,
            snapshot_id: str,
        ) -> DailySnapshotCaptureAuthority:
            loaded_authorities.append(snapshot_id)
            return next(
                pair[0]
                for pair in pairs
                if pair[0].snapshot.snapshot_id == snapshot_id
            )

        def list_snapshot_observations(
            self,
            snapshot_id: str,
        ) -> tuple[DailyWaybillObservation, ...]:
            loaded_observations.append(snapshot_id)
            return next(
                pair[1]
                for pair in pairs
                if pair[0].snapshot.snapshot_id == snapshot_id
            )

    monkeypatch.setattr(artifacts_module, "SqliteRuntime", FakeRuntime, raising=False)
    monkeypatch.setattr(artifacts_module, "SqliteDailyStore", FakeStore, raising=False)
    monkeypatch.setattr(
        artifacts_module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=DAILY_CONTRACT_SHA,
                source_discovery_sha256=(
                    DAILY_CONTRACT_SELECTION.source_discovery_sha256
                ),
            ),
            contract_file_sha256=(
                DAILY_CONTRACT_SELECTION.contract_file_sha256
            ),
            freeze_evidence_sha256=(
                DAILY_CONTRACT_SELECTION.freeze_evidence_sha256
            ),
            selection_sha256=DAILY_CONTRACT_SELECTION.selection_sha256,
        ),
        raising=False,
    )
    monkeypatch.setattr(
        artifacts_module,
        "load_loop9_identity_authority",
        lambda _root: SimpleNamespace(
            salt=IDENTITY_KEY,
            namespace=IDENTITY_NAMESPACE,
            context_sha256=inventory.identity_context_sha256,
        ),
        raising=False,
    )
    monkeypatch.setattr(
        artifacts_module,
        "_DataRootVerifiedImageReader",
        lambda _root: _Images(images),
        raising=False,
    )

    def replay(
        value: object,
        *,
        data_root: Path,
        project_root: Path,
        source_build_sha256: str,
    ) -> dict[str, object]:
        replay_calls.append(
            (data_root, project_root, source_build_sha256)
        )
        assert value == evidence
        return evidence

    monkeypatch.setattr(
        artifacts_module,
        "replay_current_daily_snapshot_validation_from_store",
        replay,
        raising=False,
    )

    rebuilt = (
        artifacts_module.rebuild_current_daily_dataset_artifacts_from_store(
            dataset_id="loop9-daily-validation",
            daily_validation=evidence,
            data_root=data_root,
            project_root=project_root,
            source_build_sha256=BUILD_SHA,
        )
    )

    snapshot_ids = [
        pair[0].snapshot.snapshot_id for pair in pairs
    ]
    assert rebuilt.inventory.to_payload() == inventory.to_payload()
    assert rebuilt.manifest.to_payload() == manifest.to_payload()
    assert loaded_authorities == snapshot_ids
    assert loaded_observations == snapshot_ids
    assert replay_calls == [(data_root, project_root, BUILD_SHA)]
    assert closed == [True]


def test_daily_triplet_build_rejects_historical_schema_four() -> None:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="daily validation evidence is invalid",
    ):
        build_daily_triplet_inventory(
            daily_validation=_historical_daily_evidence(authorities),
            contract_selection=DAILY_CONTRACT_SELECTION,
            authorities=authorities,
            observations_by_snapshot={
                pair[0].snapshot.snapshot_id: pair[1]
                for pair in pairs
            },
            identity_salt=IDENTITY_KEY,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=_Images({}),
        )


def test_daily_inventory_replay_rejects_a_different_selected_contract() -> None:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)
    changed_selection = replace(
        DAILY_CONTRACT_SELECTION,
        selection_sha256="2" * 64,
    )

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="selected daily contract",
    ):
        build_daily_triplet_inventory(
            daily_validation=_daily_evidence(authorities),
            contract_selection=changed_selection,
            authorities=authorities,
            observations_by_snapshot={
                pair[0].snapshot.snapshot_id: pair[1]
                for pair in pairs
            },
            identity_salt=IDENTITY_KEY,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=_Images({}),
        )


def test_daily_inventory_fails_when_an_observation_or_image_is_missing() -> None:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)
    observations = {
        pair[0].snapshot.snapshot_id: pair[1] for pair in pairs
    }
    evidence = _daily_evidence(authorities)
    images: dict[str, bytes] = {}
    for candidate in range(2):
        for content in (_png(2000 + candidate), _png(3000 + candidate)):
            images[hashlib.sha256(content).hexdigest()] = content

    first_id = authorities[0].snapshot.snapshot_id
    missing_observation = dict(observations)
    missing_observation[first_id] = missing_observation[first_id][:-1]
    with pytest.raises(Loop9DatasetArtifactError, match="observation"):
        build_daily_triplet_inventory(
            daily_validation=evidence,
            contract_selection=DAILY_CONTRACT_SELECTION,
            authorities=authorities,
            observations_by_snapshot=missing_observation,
            identity_salt=IDENTITY_KEY,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=_Images(images),
        )

    missing_images = dict(images)
    missing_images.pop(next(iter(missing_images)))
    with pytest.raises(Loop9DatasetArtifactError, match="image"):
        build_daily_triplet_inventory(
            daily_validation=evidence,
            contract_selection=DAILY_CONTRACT_SELECTION,
            authorities=authorities,
            observations_by_snapshot=observations,
            identity_salt=IDENTITY_KEY,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=_Images(missing_images),
        )


def test_daily_inventory_does_not_fabricate_absent_ticket_images() -> None:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)
    observations = {
        pair[0].snapshot.snapshot_id: tuple(
            replace(
                observation,
                loading_ticket_sha256=None,
                unloading_ticket_sha256=None,
            )
            for observation in pair[1]
        )
        for pair in pairs
    }

    with pytest.raises(Loop9DatasetArtifactError, match="no ticket image"):
        build_daily_triplet_inventory(
            daily_validation=_daily_evidence(authorities),
            contract_selection=DAILY_CONTRACT_SELECTION,
            authorities=authorities,
            observations_by_snapshot=observations,
            identity_salt=IDENTITY_KEY,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=_Images({}),
        )


def test_current_daily_dataset_rebuild_rejects_historical_schema_four(
    tmp_path: Path,
) -> None:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="current daily validation",
    ):
        artifacts_module.rebuild_current_daily_dataset_artifacts_from_store(
            dataset_id="loop9-daily-validation",
            daily_validation=_historical_daily_evidence(authorities),
            data_root=tmp_path.resolve(),
            project_root=tmp_path.resolve(),
            source_build_sha256=BUILD_SHA,
        )


def test_daily_inventory_replay_requires_every_perceptual_fingerprint() -> None:
    pairs = tuple(_daily_authority(index) for index in range(3))
    authorities = tuple(pair[0] for pair in pairs)
    observations = {
        pair[0].snapshot.snapshot_id: pair[1] for pair in pairs
    }
    image_values: dict[str, bytes] = {}
    for candidate in range(2):
        for content in (_png(2000 + candidate), _png(3000 + candidate)):
            image_values[hashlib.sha256(content).hexdigest()] = content
    inventory = build_daily_triplet_inventory(
        daily_validation=_daily_evidence(authorities),
        contract_selection=DAILY_CONTRACT_SELECTION,
        authorities=authorities,
        observations_by_snapshot=observations,
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        image_reader=_Images(image_values),
    )
    entries = list(inventory.entries)
    images = list(entries[0].images)
    images[0] = replace(images[0], perceptual_fingerprint=None)
    entries[0] = replace(entries[0], images=tuple(images))

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="perceptual fingerprint",
    ):
        replace(inventory, entries=tuple(entries))


def test_merges_exclusion_inventories_and_rejects_conflicting_fingerprint() -> None:
    first = _development_inventory()
    second_content = _png(9999)
    second_fingerprint = build_image_fingerprint(second_content)
    second = Loop9DatasetExclusionInventory(
        inventory_id="development-second",
        exclusion_kind=ExclusionKind.DEVELOPMENT,
        platform_identity_sha256s=(_sha("development-second"),),
        image_sha256s=(second_fingerprint.content_sha256,),
        scope_exclusion_tokens=(_sha("scope-second"),),
        perceptual_fingerprints=(second_fingerprint,),
        identity_context_sha256=first.identity_context_sha256,
    )

    merged = merge_loop9_exclusion_inventories(
        inventory_id="development-all",
        exclusion_kind=ExclusionKind.DEVELOPMENT,
        inventories=(first, second),
    )

    assert len(merged.platform_identity_sha256s) == 2
    assert len(merged.image_sha256s) == 3
    assert len(merged.perceptual_fingerprints) == 3
    assert merged.scope_exclusion_tokens == (_sha("scope-second"),)

    with pytest.raises(Loop9DatasetIsolationError, match="classification"):
        merge_loop9_exclusion_inventories(
            inventory_id="wrong-kind",
            exclusion_kind=ExclusionKind.LEGACY_LOOP7,
            inventories=(first,),
        )

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="perceptual fingerprint",
    ):
        merge_loop9_exclusion_inventories(
            inventory_id="incomplete-fingerprints",
            exclusion_kind=ExclusionKind.DEVELOPMENT,
            inventories=(
                replace(
                    first,
                    perceptual_fingerprints=(
                        first.perceptual_fingerprints[0],
                    ),
                ),
            ),
        )
