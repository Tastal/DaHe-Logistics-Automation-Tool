from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
    build_image_fingerprint,
)
from dahe.verification.loop9_dataset_isolation import (
    DatasetKind,
    ExclusionKind,
    Loop9DatasetEntry,
    Loop9DatasetExclusionInventory,
    Loop9DatasetImage,
    Loop9DatasetIsolationError,
    Loop9DatasetManifest,
    Loop9ExclusionSourceBoundary,
    Loop9FullHistoryExclusionAuthority,
    build_loop9_full_history_exclusion_authority,
    discovery_scope_exclusion_token,
    load_loop9_dataset_manifest,
    parse_loop9_dataset_isolation_evidence,
    parse_loop9_dataset_manifest,
    parse_loop9_exclusion_inventory,
    parse_loop9_full_history_exclusion_authority,
    platform_identity_sha256,
    validate_loop9_dataset_isolation,
)

EXPECTED_CURRENT_BUILD_SHA256 = hashlib.sha256(
    b"expected-current-build"
).hexdigest()
EXPECTED_SETTLEMENT_CONTRACT_SHA256 = hashlib.sha256(
    b"expected-settlement-contract"
).hexdigest()
EXPECTED_DAILY_CONTRACT_SHA256 = hashlib.sha256(
    b"expected-daily-contract"
).hexdigest()
EXPECTED_SETTLEMENT_SELECTION_SHA256 = hashlib.sha256(
    b"expected-settlement-selection"
).hexdigest()
EXPECTED_DAILY_SELECTION_SHA256 = hashlib.sha256(
    b"expected-daily-selection"
).hexdigest()
IDENTITY_KEY = b"loop9-dataset-isolation-test-key"
IDENTITY_NAMESPACE = "chengfeng:waybill"
EXPECTED_IDENTITY_CONTEXT_SHA256 = hashlib.sha256(
    b"dahe:chengfeng-shadow:identity-context:v1\0"
    + IDENTITY_NAMESPACE.encode("utf-8")
    + b"\0"
    + hashlib.sha256(IDENTITY_KEY).digest()
).hexdigest()


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fingerprint(label: str) -> ImagePerceptualFingerprint:
    content_sha256 = _sha256(f"image:{label}")
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=content_sha256,
        width=320,
        height=180,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop_permille,
                average_hash=_sha256(f"average:{label}:{crop_permille}"),
                difference_hash=_sha256(f"difference:{label}:{crop_permille}"),
            )
            for crop_permille in (1000, 920, 840, 760)
        ),
    )


def _image(
    label: str,
    *,
    include_fingerprint: bool = False,
) -> Loop9DatasetImage:
    fingerprint = _fingerprint(label) if include_fingerprint else None
    return Loop9DatasetImage(
        image_sha256=_sha256(f"image:{label}"),
        perceptual_fingerprint=fingerprint,
    )


def _entry(
    label: str,
    *,
    image_count: int = 2,
    platform_identity: str | None = None,
    scope_exclusion_token: str | None = None,
    include_fingerprints: bool = False,
) -> Loop9DatasetEntry:
    return Loop9DatasetEntry(
        platform_identity_sha256=(
            platform_identity
            if platform_identity is not None
            else platform_identity_sha256(
                identity_salt=IDENTITY_KEY,
                identity_namespace=IDENTITY_NAMESPACE,
                source_identity=f"waybill:{label}",
            )
        ),
        scope_exclusion_token=scope_exclusion_token,
        images=tuple(
            _image(
                f"{label}:{index}",
                include_fingerprint=include_fingerprints,
            )
            for index in range(image_count)
        ),
    )


def _manifest(
    kind: DatasetKind,
    *,
    prefix: str,
    count: int,
    source_job_id: str | None = None,
    source_snapshot_sha256: str | None = None,
    unidentified_discovery_entry: bool = False,
    build_sha256: str | None = None,
    contract_sha256: str | None = None,
    identity_context_sha256: str | None = None,
    include_fingerprints: bool | None = None,
    formal_selection_sha256: str | None = None,
    locked_gate_evidence_sha256: str | None = None,
) -> Loop9DatasetManifest:
    job_id = source_job_id or f"job-{prefix}"
    snapshot_sha256 = source_snapshot_sha256 or _sha256(f"snapshot:{prefix}")
    fingerprint_required = (
        kind is not DatasetKind.DISCOVERY_DEVELOPMENT
        if include_fingerprints is None
        else include_fingerprints
    )
    entries = [
        _entry(
            f"{prefix}:{index}",
            include_fingerprints=fingerprint_required,
        )
        for index in range(count)
    ]
    if unidentified_discovery_entry:
        entries[-1] = Loop9DatasetEntry(
            platform_identity_sha256=None,
            scope_exclusion_token=discovery_scope_exclusion_token(
                source_job_id=job_id,
                source_snapshot_sha256=snapshot_sha256,
            ),
            images=entries[-1].images,
        )
    return Loop9DatasetManifest(
        dataset_id=f"dataset-{prefix}",
        dataset_kind=kind,
        build_sha256=build_sha256 or _sha256(f"build:{prefix}"),
        contract_sha256=contract_sha256 or _sha256(f"contract:{prefix}"),
        source_job_id=job_id,
        source_snapshot_sha256=snapshot_sha256,
        entries=tuple(entries),
        identity_context_sha256=(
            identity_context_sha256
            or EXPECTED_IDENTITY_CONTEXT_SHA256
        ),
        formal_selection_sha256=(
            formal_selection_sha256
            or (
                _sha256(f"selection:{prefix}")
                if kind
                in {
                    DatasetKind.CURRENT_LOCKED_50,
                    DatasetKind.REAL_SHADOW_30,
                }
                else None
            )
        ),
        locked_gate_evidence_sha256=(
            locked_gate_evidence_sha256
            or (
                _sha256("current-locked-gate")
                if kind is DatasetKind.REAL_SHADOW_30
                else None
            )
        ),
    )


def _exclusions(
    kind: ExclusionKind,
    *,
    prefix: str,
) -> Loop9DatasetExclusionInventory:
    fingerprint = _fingerprint(f"excluded:{prefix}")
    return Loop9DatasetExclusionInventory(
        inventory_id=f"inventory-{prefix}",
        exclusion_kind=kind,
        platform_identity_sha256s=(_sha256(f"excluded-identity:{prefix}"),),
        image_sha256s=(fingerprint.content_sha256,),
        scope_exclusion_tokens=(
            (_sha256(f"excluded-scope:{prefix}"),)
            if kind is ExclusionKind.DEVELOPMENT
            else ()
        ),
        perceptual_fingerprints=(fingerprint,),
        identity_context_sha256=EXPECTED_IDENTITY_CONTEXT_SHA256,
    )


def _source_boundary(
    *inventories: Loop9DatasetExclusionInventory,
) -> Loop9ExclusionSourceBoundary:
    images = {
        image_sha256
        for inventory in inventories
        for image_sha256 in inventory.image_sha256s
    }
    identities = {
        identity_sha256
        for inventory in inventories
        for identity_sha256 in inventory.platform_identity_sha256s
    }
    fingerprints = {
        fingerprint.content_sha256: fingerprint
        for inventory in inventories
        for fingerprint in inventory.perceptual_fingerprints
    }
    return Loop9ExclusionSourceBoundary(
        source_authority_sha256=_sha256("formal-development-authority"),
        source_exclusion_snapshot_sha256=_sha256(
            "formal-development-exclusion-snapshot"
        ),
        source_inventory_high_watermark=17,
        image_sha256s=tuple(sorted(images)),
        platform_identity_count=len(identities),
        perceptual_fingerprints=tuple(
            fingerprints[key] for key in sorted(fingerprints)
        ),
    )


def _full_history_authority(
    development: Loop9DatasetExclusionInventory,
    loop7: Loop9DatasetExclusionInventory,
) -> tuple[
    Loop9ExclusionSourceBoundary,
    Loop9FullHistoryExclusionAuthority,
]:
    boundary = _source_boundary(development, loop7)
    authority = build_loop9_full_history_exclusion_authority(
        source_boundary=boundary,
        child_inventories=(development, loop7),
        expected_current_build_sha256=EXPECTED_CURRENT_BUILD_SHA256,
        expected_settlement_contract_sha256=(
            EXPECTED_SETTLEMENT_CONTRACT_SHA256
        ),
        expected_daily_contract_sha256=EXPECTED_DAILY_CONTRACT_SHA256,
        expected_settlement_selection_sha256=(
            EXPECTED_SETTLEMENT_SELECTION_SHA256
        ),
        expected_daily_selection_sha256=EXPECTED_DAILY_SELECTION_SHA256,
    )
    return boundary, authority


def _valid_inputs() -> dict[str, object]:
    development = _exclusions(
        ExclusionKind.DEVELOPMENT,
        prefix="development",
    )
    loop7 = _exclusions(
        ExclusionKind.LEGACY_LOOP7,
        prefix="loop7",
    )
    boundary, authority = _full_history_authority(development, loop7)
    return {
        "expected_current_build_sha256": EXPECTED_CURRENT_BUILD_SHA256,
        "expected_settlement_contract_sha256": (
            EXPECTED_SETTLEMENT_CONTRACT_SHA256
        ),
        "expected_daily_contract_sha256": EXPECTED_DAILY_CONTRACT_SHA256,
        "expected_settlement_selection_sha256": (
            EXPECTED_SETTLEMENT_SELECTION_SHA256
        ),
        "expected_daily_selection_sha256": EXPECTED_DAILY_SELECTION_SHA256,
        "discovery_development": _manifest(
            DatasetKind.DISCOVERY_DEVELOPMENT,
            prefix="discovery",
            count=2,
            unidentified_discovery_entry=True,
            contract_sha256=_sha256("development-discovery-contract"),
        ),
        "current_locked_50": _manifest(
            DatasetKind.CURRENT_LOCKED_50,
            prefix="locked",
            count=50,
            build_sha256=EXPECTED_CURRENT_BUILD_SHA256,
            contract_sha256=EXPECTED_SETTLEMENT_CONTRACT_SHA256,
        ),
        "real_shadow_30": _manifest(
            DatasetKind.REAL_SHADOW_30,
            prefix="shadow",
            count=30,
            build_sha256=EXPECTED_CURRENT_BUILD_SHA256,
            contract_sha256=EXPECTED_SETTLEMENT_CONTRACT_SHA256,
        ),
        "daily_validation": _manifest(
            DatasetKind.DAILY_VALIDATION,
            prefix="daily",
            count=3,
            build_sha256=EXPECTED_CURRENT_BUILD_SHA256,
            contract_sha256=EXPECTED_DAILY_CONTRACT_SHA256,
        ),
        "development_exclusions": development,
        "legacy_loop7_exclusions": loop7,
        "expected_exclusion_source_boundary": boundary,
        "full_history_exclusion_authority": authority,
    }


def _ticket_bytes(*, image_format: str) -> bytes:
    image = Image.new("RGB", (320, 180), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((25, 20, 295, 160), outline="black", width=4)
    draw.line((45, 55, 275, 55), fill="black", width=3)
    draw.line((45, 95, 250, 95), fill="black", width=3)
    draw.text((50, 120), "32.70", fill="black")
    output = BytesIO()
    image.save(output, format=image_format, quality=95)
    return output.getvalue()


def test_valid_isolation_evidence_is_normalized_and_replayable() -> None:
    inputs = _valid_inputs()

    first = validate_loop9_dataset_isolation(**inputs)
    second = validate_loop9_dataset_isolation(**inputs)

    assert first.canonical_sha256 == second.canonical_sha256
    assert first.to_payload() == second.to_payload()
    assert first.to_payload()["isolation_passed"] is True
    assert first.to_payload()["current_locked_image_count"] == 100
    assert first.to_payload()["real_shadow_entry_count"] == 30
    assert (
        first.to_payload()["expected_current_build_sha256"]
        == EXPECTED_CURRENT_BUILD_SHA256
    )
    assert (
        first.to_payload()["expected_settlement_contract_sha256"]
        == EXPECTED_SETTLEMENT_CONTRACT_SHA256
    )
    assert (
        first.to_payload()["expected_daily_contract_sha256"]
        == EXPECTED_DAILY_CONTRACT_SHA256
    )
    assert (
        first.to_payload()["expected_settlement_selection_sha256"]
        == EXPECTED_SETTLEMENT_SELECTION_SHA256
    )
    assert (
        first.to_payload()["expected_daily_selection_sha256"]
        == EXPECTED_DAILY_SELECTION_SHA256
    )
    assert (
        first.to_payload()["expected_identity_context_sha256"]
        == EXPECTED_IDENTITY_CONTEXT_SHA256
    )
    assert (
        first.to_payload()["full_history_exclusion_authority_sha256"]
        == inputs["full_history_exclusion_authority"].canonical_sha256
    )
    assert (
        first.to_payload()["exclusion_source_boundary_sha256"]
        == inputs["expected_exclusion_source_boundary"].canonical_sha256
    )
    assert first.to_payload()["source_inventory_high_watermark"] == 17
    bindings = first.to_payload()["dataset_bindings"]
    assert isinstance(bindings, list)
    binding_by_kind = {
        binding["dataset_kind"]: binding
        for binding in bindings
        if isinstance(binding, dict)
    }
    assert (
        binding_by_kind["current_locked_50"]["build_sha256"]
        == EXPECTED_CURRENT_BUILD_SHA256
    )
    assert (
        binding_by_kind["real_shadow_30"]["contract_sha256"]
        == EXPECTED_SETTLEMENT_CONTRACT_SHA256
    )
    assert (
        binding_by_kind["current_locked_50"][
            "formal_selection_sha256"
        ]
        == inputs["current_locked_50"].formal_selection_sha256
    )
    assert (
        binding_by_kind["real_shadow_30"][
            "locked_gate_evidence_sha256"
        ]
        == inputs["real_shadow_30"].locked_gate_evidence_sha256
    )
    assert (
        binding_by_kind["daily_validation"]["contract_sha256"]
        == EXPECTED_DAILY_CONTRACT_SHA256
    )
    assert (
        binding_by_kind["discovery_development"]["build_sha256"]
        != EXPECTED_CURRENT_BUILD_SHA256
    )
    assert (
        binding_by_kind["discovery_development"]["contract_sha256"]
        != EXPECTED_SETTLEMENT_CONTRACT_SHA256
    )
    assert (
        first.to_payload()["discovery_development_binding_policy"]
        == "recorded_source_authority_only"
    )
    replayed = parse_loop9_dataset_isolation_evidence(first.to_payload())
    assert replayed.to_payload() == first.to_payload()
    assert replayed.canonical_sha256 == first.canonical_sha256


def test_full_history_authority_is_canonical_and_replayable() -> None:
    inputs = _valid_inputs()
    authority = inputs["full_history_exclusion_authority"]
    assert isinstance(authority, Loop9FullHistoryExclusionAuthority)

    replayed = parse_loop9_full_history_exclusion_authority(
        authority.to_payload()
    )

    assert replayed.to_payload() == authority.to_payload()
    assert replayed.canonical_sha256 == authority.canonical_sha256
    assert replayed.source_inventory_high_watermark == 17
    assert replayed.child_inventory_count == 2
    assert replayed.development_exclusion_sha256 == (
        inputs["development_exclusions"].canonical_sha256
    )
    assert replayed.legacy_loop7_exclusion_sha256 == (
        inputs["legacy_loop7_exclusions"].canonical_sha256
    )


def test_full_history_authority_rejects_missing_child_history() -> None:
    development = _exclusions(
        ExclusionKind.DEVELOPMENT,
        prefix="partial-development",
    )
    loop7 = _exclusions(
        ExclusionKind.LEGACY_LOOP7,
        prefix="partial-loop7",
    )
    boundary = _source_boundary(development, loop7)

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="complete source history",
    ):
        build_loop9_full_history_exclusion_authority(
            source_boundary=boundary,
            child_inventories=(development,),
            expected_current_build_sha256=EXPECTED_CURRENT_BUILD_SHA256,
            expected_settlement_contract_sha256=(
                EXPECTED_SETTLEMENT_CONTRACT_SHA256
            ),
            expected_daily_contract_sha256=EXPECTED_DAILY_CONTRACT_SHA256,
            expected_settlement_selection_sha256=(
                EXPECTED_SETTLEMENT_SELECTION_SHA256
            ),
            expected_daily_selection_sha256=(
                EXPECTED_DAILY_SELECTION_SHA256
            ),
        )


def test_full_history_authority_rejects_tampered_child_and_boundary() -> None:
    inputs = _valid_inputs()
    authority = inputs["full_history_exclusion_authority"]
    assert isinstance(authority, Loop9FullHistoryExclusionAuthority)
    payload = copy.deepcopy(authority.to_payload())
    children = payload["child_inventories"]
    assert isinstance(children, list)
    assert isinstance(children[0], dict)
    children[0]["inventory_id"] = "tampered-child"

    with pytest.raises(Loop9DatasetIsolationError):
        parse_loop9_full_history_exclusion_authority(payload)

    payload = copy.deepcopy(authority.to_payload())
    source = payload["source_boundary"]
    assert isinstance(source, dict)
    source["source_inventory_high_watermark"] = 16
    with pytest.raises(Loop9DatasetIsolationError):
        parse_loop9_full_history_exclusion_authority(payload)


def test_formal_gate_rejects_partial_or_wrong_full_history_authority() -> None:
    inputs = _valid_inputs()
    replacement_development = _exclusions(
        ExclusionKind.DEVELOPMENT,
        prefix="caller-supplied-partial",
    )
    inputs["development_exclusions"] = replacement_development

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="full-history exclusion authority",
    ):
        validate_loop9_dataset_isolation(**inputs)

    inputs = _valid_inputs()
    boundary = inputs["expected_exclusion_source_boundary"]
    assert isinstance(boundary, Loop9ExclusionSourceBoundary)
    inputs["expected_exclusion_source_boundary"] = replace(
        boundary,
        source_inventory_high_watermark=18,
    )
    with pytest.raises(
        Loop9DatasetIsolationError,
        match="source boundary",
    ):
        validate_loop9_dataset_isolation(**inputs)


def test_persisted_isolation_evidence_tampering_is_rejected() -> None:
    payload = validate_loop9_dataset_isolation(
        **_valid_inputs()
    ).to_payload()
    payload["real_shadow_entry_count"] = 29

    with pytest.raises(Loop9DatasetIsolationError, match="integrity"):
        parse_loop9_dataset_isolation_evidence(payload)


@pytest.mark.parametrize(
    "argument_name",
    (
        "expected_current_build_sha256",
        "expected_settlement_contract_sha256",
        "expected_daily_contract_sha256",
        "expected_settlement_selection_sha256",
        "expected_daily_selection_sha256",
    ),
)
def test_expected_authority_sha256_values_are_strict(
    argument_name: str,
) -> None:
    inputs = _valid_inputs()
    inputs[argument_name] = "A" * 64

    with pytest.raises(Loop9DatasetIsolationError, match="lowercase SHA-256"):
        validate_loop9_dataset_isolation(**inputs)


@pytest.mark.parametrize(
    ("manifest_name", "field_name", "expected_message"),
    (
        ("current_locked_50", "build_sha256", "current build"),
        ("real_shadow_30", "build_sha256", "current build"),
        ("daily_validation", "build_sha256", "current build"),
        ("current_locked_50", "contract_sha256", "settlement contract"),
        ("real_shadow_30", "contract_sha256", "settlement contract"),
        ("daily_validation", "contract_sha256", "daily contract"),
    ),
)
def test_cross_build_and_cross_contract_manifests_are_rejected(
    manifest_name: str,
    field_name: str,
    expected_message: str,
) -> None:
    inputs = _valid_inputs()
    manifest = inputs[manifest_name]
    assert isinstance(manifest, Loop9DatasetManifest)
    inputs[manifest_name] = replace(
        manifest,
        **{field_name: _sha256(f"tampered:{manifest_name}:{field_name}")},
    )

    with pytest.raises(Loop9DatasetIsolationError, match=expected_message):
        validate_loop9_dataset_isolation(**inputs)


def test_formal_identity_contexts_must_match() -> None:
    inputs = _valid_inputs()
    daily = inputs["daily_validation"]
    assert isinstance(daily, Loop9DatasetManifest)
    inputs["daily_validation"] = replace(
        daily,
        identity_context_sha256=_sha256("different-identity-context"),
    )

    with pytest.raises(Loop9DatasetIsolationError, match="identity context"):
        validate_loop9_dataset_isolation(**inputs)


def test_discovery_and_exclusion_identity_contexts_must_match_formal() -> None:
    inputs = _valid_inputs()
    discovery = inputs["discovery_development"]
    assert isinstance(discovery, Loop9DatasetManifest)
    inputs["discovery_development"] = replace(
        discovery,
        identity_context_sha256=_sha256("different-discovery-context"),
    )
    with pytest.raises(Loop9DatasetIsolationError, match="identity context"):
        validate_loop9_dataset_isolation(**inputs)

    inputs = _valid_inputs()
    development = inputs["development_exclusions"]
    assert isinstance(development, Loop9DatasetExclusionInventory)
    inputs["development_exclusions"] = replace(
        development,
        identity_context_sha256=_sha256("different-inventory-context"),
    )
    with pytest.raises(Loop9DatasetIsolationError, match="identity context"):
        validate_loop9_dataset_isolation(**inputs)


def test_legacy_contextless_exclusion_inventory_is_readable_but_not_formal() -> None:
    current = _exclusions(
        ExclusionKind.DEVELOPMENT,
        prefix="legacy-readable",
    )
    payload = current.to_payload()
    payload.pop("identity_context_sha256")
    payload["schema_version"] = 1
    body = {
        key: value
        for key, value in payload.items()
        if key != "canonical_sha256"
    }
    payload["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    legacy = parse_loop9_exclusion_inventory(payload)
    assert legacy.identity_context_sha256 is None
    assert legacy.artifact_schema_version == 1

    inputs = _valid_inputs()
    inputs["development_exclusions"] = legacy
    with pytest.raises(Loop9DatasetIsolationError, match=r"legacy.*identity"):
        validate_loop9_dataset_isolation(**inputs)


def test_discovery_source_authority_is_development_only_but_persisted() -> None:
    inputs = _valid_inputs()
    first = validate_loop9_dataset_isolation(**inputs)
    discovery = inputs["discovery_development"]
    assert isinstance(discovery, Loop9DatasetManifest)
    replacement_contract = _sha256("another-development-discovery-contract")
    inputs["discovery_development"] = replace(
        discovery,
        contract_sha256=replacement_contract,
    )

    second = validate_loop9_dataset_isolation(**inputs)

    assert first.canonical_sha256 != second.canonical_sha256
    bindings = second.to_payload()["dataset_bindings"]
    assert isinstance(bindings, list)
    discovery_binding = next(
        binding
        for binding in bindings
        if isinstance(binding, dict)
        and binding["dataset_kind"] == "discovery_development"
    )
    assert discovery_binding["contract_sha256"] == replacement_contract


@pytest.mark.parametrize(
    ("field_name", "expected_message"),
    (
        ("expected_current_build_sha256", "current build binding"),
        (
            "expected_settlement_contract_sha256",
            "settlement contract binding",
        ),
        ("expected_daily_contract_sha256", "daily contract binding"),
        (
            "expected_identity_context_sha256",
            "identity context binding",
        ),
        (
            "expected_settlement_selection_sha256",
            "settlement selection",
        ),
        (
            "expected_daily_selection_sha256",
            "daily selection",
        ),
    ),
)
def test_persisted_expected_authority_binding_tampering_is_rejected(
    field_name: str,
    expected_message: str,
) -> None:
    evidence = validate_loop9_dataset_isolation(**_valid_inputs())

    with pytest.raises(Loop9DatasetIsolationError, match=expected_message):
        replace(
            evidence,
            **{field_name: _sha256(f"tampered-evidence:{field_name}")},
        )


@pytest.mark.parametrize(
    "manifest_name",
    ("current_locked_50", "real_shadow_30", "daily_validation"),
)
def test_every_formal_image_requires_a_perceptual_fingerprint(
    manifest_name: str,
) -> None:
    inputs = _valid_inputs()
    manifest = inputs[manifest_name]
    assert isinstance(manifest, Loop9DatasetManifest)
    entries = list(manifest.entries)
    first_images = list(entries[0].images)
    first_images[0] = replace(
        first_images[0],
        perceptual_fingerprint=None,
    )
    entries[0] = replace(entries[0], images=tuple(first_images))
    inputs[manifest_name] = replace(manifest, entries=tuple(entries))

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="perceptual fingerprint for every image",
    ):
        validate_loop9_dataset_isolation(**inputs)


@pytest.mark.parametrize(
    "inventory_name",
    ("development_exclusions", "legacy_loop7_exclusions"),
)
def test_every_excluded_image_requires_a_perceptual_fingerprint(
    inventory_name: str,
) -> None:
    inputs = _valid_inputs()
    inventory = inputs[inventory_name]
    assert isinstance(inventory, Loop9DatasetExclusionInventory)
    inputs[inventory_name] = replace(
        inventory,
        perceptual_fingerprints=(),
    )

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="perceptual fingerprint for every excluded image",
    ):
        validate_loop9_dataset_isolation(**inputs)


def test_manifest_order_does_not_change_normalized_sha256() -> None:
    manifest = _manifest(
        DatasetKind.CURRENT_LOCKED_50,
        prefix="locked-order",
        count=50,
    )
    payload = manifest.to_payload()
    entries = payload["entries"]
    assert isinstance(entries, list)
    entries.reverse()
    for entry in entries:
        assert isinstance(entry, dict)
        images = entry["images"]
        assert isinstance(images, list)
        images.reverse()

    replayed = parse_loop9_dataset_manifest(payload)

    assert replayed.canonical_sha256 == manifest.canonical_sha256
    assert replayed.to_payload() == manifest.to_payload()


def test_platform_identity_is_irreversible_and_raw_identity_is_rejected() -> None:
    first = platform_identity_sha256(
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        source_identity="CF-123",
    )
    second = platform_identity_sha256(
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        source_identity="CF-123",
    )

    assert first == second
    assert first != "CF-123"
    assert (
        platform_identity_sha256(
            identity_salt=b"different-loop9-dataset-isolation-key",
            identity_namespace=IDENTITY_NAMESPACE,
            source_identity="CF-123",
        )
        != first
    )
    with pytest.raises(Loop9DatasetIsolationError, match="identity"):
        Loop9DatasetEntry(
            platform_identity_sha256="CF-123",
            scope_exclusion_token=None,
            images=(_image("raw-identity"),),
        )


def test_discovery_without_identity_requires_machine_verifiable_scope_token() -> None:
    with pytest.raises(Loop9DatasetIsolationError, match="scope exclusion token"):
        Loop9DatasetManifest(
            dataset_id="dataset-invalid-discovery",
            dataset_kind=DatasetKind.DISCOVERY_DEVELOPMENT,
            build_sha256=_sha256("build"),
            contract_sha256=_sha256("contract"),
            source_job_id="job-discovery",
            source_snapshot_sha256=_sha256("snapshot"),
            identity_context_sha256=EXPECTED_IDENTITY_CONTEXT_SHA256,
            entries=(
                Loop9DatasetEntry(
                    platform_identity_sha256=None,
                    scope_exclusion_token="a" * 64,
                    images=(_image("discovery-no-identity"),),
                ),
            ),
        )


@pytest.mark.parametrize(
    ("argument_name", "replacement_name"),
    (
        ("current_locked_50", "real_shadow_30"),
        ("real_shadow_30", "current_locked_50"),
        ("daily_validation", "discovery_development"),
    ),
)
def test_validator_rejects_wrong_dataset_classification(
    argument_name: str,
    replacement_name: str,
) -> None:
    inputs = _valid_inputs()
    inputs[argument_name] = inputs[replacement_name]

    with pytest.raises(Loop9DatasetIsolationError, match="classification"):
        validate_loop9_dataset_isolation(**inputs)


@pytest.mark.parametrize(
    ("kind", "count", "message"),
    (
        (DatasetKind.CURRENT_LOCKED_50, 49, "50"),
        (DatasetKind.REAL_SHADOW_30, 29, "30"),
    ),
)
def test_fixed_dataset_counts_are_fail_closed(
    kind: DatasetKind,
    count: int,
    message: str,
) -> None:
    with pytest.raises(Loop9DatasetIsolationError, match=message):
        _manifest(kind, prefix=f"wrong-count:{kind.value}", count=count)


def test_locked_set_requires_exactly_100_unique_images() -> None:
    entries = list(
        _manifest(
            DatasetKind.CURRENT_LOCKED_50,
            prefix="locked-unique",
            count=50,
        ).entries
    )
    entries[0] = replace(entries[0], images=(entries[0].images[0],))
    with pytest.raises(Loop9DatasetIsolationError, match="100 unique"):
        Loop9DatasetManifest(
            dataset_id="locked-missing-image",
            dataset_kind=DatasetKind.CURRENT_LOCKED_50,
            build_sha256=_sha256("build:missing"),
            contract_sha256=_sha256("contract:missing"),
            source_job_id="job-locked-missing",
            source_snapshot_sha256=_sha256("snapshot:missing"),
            entries=tuple(entries),
            identity_context_sha256=EXPECTED_IDENTITY_CONTEXT_SHA256,
            formal_selection_sha256=_sha256("selection:locked-missing"),
        )

    entries = list(
        _manifest(
            DatasetKind.CURRENT_LOCKED_50,
            prefix="locked-duplicate",
            count=50,
        ).entries
    )
    entries[1] = replace(
        entries[1],
        images=(entries[0].images[0], entries[1].images[1]),
    )
    with pytest.raises(Loop9DatasetIsolationError, match="100 unique"):
        Loop9DatasetManifest(
            dataset_id="locked-duplicate-image",
            dataset_kind=DatasetKind.CURRENT_LOCKED_50,
            build_sha256=_sha256("build:duplicate"),
            contract_sha256=_sha256("contract:duplicate"),
            source_job_id="job-locked-duplicate",
            source_snapshot_sha256=_sha256("snapshot:duplicate"),
            entries=tuple(entries),
            identity_context_sha256=EXPECTED_IDENTITY_CONTEXT_SHA256,
            formal_selection_sha256=_sha256("selection:locked-duplicate"),
        )


def test_shadow_set_requires_exactly_60_unique_images() -> None:
    entries = list(
        _manifest(
            DatasetKind.REAL_SHADOW_30,
            prefix="shadow-unique",
            count=30,
        ).entries
    )
    entries[0] = replace(entries[0], images=(entries[0].images[0],))

    with pytest.raises(Loop9DatasetIsolationError, match="60 unique"):
        Loop9DatasetManifest(
            dataset_id="shadow-missing-image",
            dataset_kind=DatasetKind.REAL_SHADOW_30,
            build_sha256=EXPECTED_CURRENT_BUILD_SHA256,
            contract_sha256=EXPECTED_SETTLEMENT_CONTRACT_SHA256,
            source_job_id="job-shadow-missing",
            source_snapshot_sha256=_sha256("snapshot:shadow-missing"),
            entries=tuple(entries),
            identity_context_sha256=EXPECTED_IDENTITY_CONTEXT_SHA256,
            formal_selection_sha256=_sha256("selection:shadow-missing"),
            locked_gate_evidence_sha256=_sha256("current-locked-gate"),
        )


@pytest.mark.parametrize("overlap_kind", ("platform_identity", "image"))
def test_exact_overlap_between_dataset_classes_is_rejected(
    overlap_kind: str,
) -> None:
    inputs = _valid_inputs()
    locked = inputs["current_locked_50"]
    shadow = inputs["real_shadow_30"]
    assert isinstance(locked, Loop9DatasetManifest)
    assert isinstance(shadow, Loop9DatasetManifest)
    shadow_entries = list(shadow.entries)
    if overlap_kind == "platform_identity":
        shadow_entries[0] = replace(
            shadow_entries[0],
            platform_identity_sha256=locked.entries[0].platform_identity_sha256,
        )
    else:
        shadow_entries[0] = replace(
            shadow_entries[0],
            images=(locked.entries[0].images[0], shadow_entries[0].images[1]),
        )
    inputs["real_shadow_30"] = replace(shadow, entries=tuple(shadow_entries))

    with pytest.raises(Loop9DatasetIsolationError, match="exact"):
        validate_loop9_dataset_isolation(**inputs)


def test_perceptual_near_overlap_between_datasets_is_rejected() -> None:
    inputs = _valid_inputs()
    locked = inputs["current_locked_50"]
    shadow = inputs["real_shadow_30"]
    assert isinstance(locked, Loop9DatasetManifest)
    assert isinstance(shadow, Loop9DatasetManifest)
    locked_fingerprint = build_image_fingerprint(_ticket_bytes(image_format="PNG"))
    shadow_fingerprint = build_image_fingerprint(_ticket_bytes(image_format="JPEG"))
    assert locked_fingerprint.content_sha256 != shadow_fingerprint.content_sha256

    locked_entries = list(locked.entries)
    locked_entries[0] = replace(
        locked_entries[0],
        images=(
            Loop9DatasetImage(
                image_sha256=locked_fingerprint.content_sha256,
                perceptual_fingerprint=locked_fingerprint,
            ),
            locked_entries[0].images[1],
        ),
    )
    shadow_entries = list(shadow.entries)
    shadow_entries[0] = replace(
        shadow_entries[0],
        images=(
            Loop9DatasetImage(
                image_sha256=shadow_fingerprint.content_sha256,
                perceptual_fingerprint=shadow_fingerprint,
            ),
            shadow_entries[0].images[1],
        ),
    )
    inputs["current_locked_50"] = replace(locked, entries=tuple(locked_entries))
    inputs["real_shadow_30"] = replace(shadow, entries=tuple(shadow_entries))

    with pytest.raises(Loop9DatasetIsolationError, match="perceptual"):
        validate_loop9_dataset_isolation(**inputs)


@pytest.mark.parametrize(
    ("inventory_argument", "overlap_kind"),
    (
        ("development_exclusions", "platform_identity"),
        ("development_exclusions", "image"),
        ("legacy_loop7_exclusions", "platform_identity"),
        ("legacy_loop7_exclusions", "image"),
    ),
)
def test_formal_datasets_cannot_overlap_development_or_loop7_exclusions(
    inventory_argument: str,
    overlap_kind: str,
) -> None:
    inputs = _valid_inputs()
    locked = inputs["current_locked_50"]
    inventory = inputs[inventory_argument]
    assert isinstance(locked, Loop9DatasetManifest)
    assert isinstance(inventory, Loop9DatasetExclusionInventory)
    if overlap_kind == "platform_identity":
        inputs[inventory_argument] = replace(
            inventory,
            platform_identity_sha256s=(
                locked.entries[0].platform_identity_sha256,
            ),
        )
    else:
        locked_fingerprint = (
            locked.entries[0].images[0].perceptual_fingerprint
        )
        assert locked_fingerprint is not None
        inputs[inventory_argument] = replace(
            inventory,
            image_sha256s=(locked.entries[0].images[0].image_sha256,),
            perceptual_fingerprints=(locked_fingerprint,),
        )

    with pytest.raises(Loop9DatasetIsolationError, match="exclusion"):
        validate_loop9_dataset_isolation(**inputs)


def test_discovery_scope_exclusion_blocks_reuse_of_the_same_source_scope() -> None:
    inputs = _valid_inputs()
    discovery = inputs["discovery_development"]
    daily = inputs["daily_validation"]
    assert isinstance(discovery, Loop9DatasetManifest)
    assert isinstance(daily, Loop9DatasetManifest)
    inputs["daily_validation"] = replace(
        daily,
        source_job_id=discovery.source_job_id,
        source_snapshot_sha256=discovery.source_snapshot_sha256,
    )

    with pytest.raises(Loop9DatasetIsolationError, match="scope"):
        validate_loop9_dataset_isolation(**inputs)


def test_manifest_and_exclusion_integrity_tampering_is_rejected() -> None:
    manifest = _manifest(
        DatasetKind.DAILY_VALIDATION,
        prefix="tamper-manifest",
        count=2,
    )
    manifest_payload = manifest.to_payload()
    manifest_payload["dataset_id"] = "tampered-dataset-id"
    with pytest.raises(Loop9DatasetIsolationError, match="integrity"):
        parse_loop9_dataset_manifest(manifest_payload)

    inventory = _exclusions(ExclusionKind.DEVELOPMENT, prefix="tamper-exclusion")
    inventory_payload = copy.deepcopy(inventory.to_payload())
    inventory_payload["inventory_id"] = "tampered-exclusion-id"
    with pytest.raises(Loop9DatasetIsolationError, match="integrity"):
        parse_loop9_exclusion_inventory(inventory_payload)


def test_persisted_manifest_loader_rejects_duplicate_json_fields(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        DatasetKind.DAILY_VALIDATION,
        prefix="duplicate-json",
        count=2,
    )
    encoded = json.dumps(
        manifest.to_payload(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    needle = f'"dataset_id":"{manifest.dataset_id}"'
    path = (tmp_path / "duplicate.json").resolve()
    path.write_text(
        encoded.replace(needle, f"{needle},{needle}", 1),
        encoding="utf-8",
    )

    with pytest.raises(Loop9DatasetIsolationError, match="duplicate"):
        load_loop9_dataset_manifest(path)
