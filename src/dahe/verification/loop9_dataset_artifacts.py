from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from dahe.adapters.chengfeng.daily_contract_selection import (
    DailyContractSelectionError,
    SelectedDailyReadContract,
    load_selected_daily_read_contract,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.identity_authority import (
    Loop9IdentityAuthorityError,
    load_loop9_identity_authority,
)
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchContractError,
    ChengfengShadowBatchManifest,
    ShadowBatchTargetKind,
    chengfeng_shadow_identity_context_sha256,
    chengfeng_shadow_identity_digest,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionContractError,
    FormalShadowSelectionManifest,
)
from dahe.domain.daily.models import DailyWaybillObservation
from dahe.ports.daily import DailySnapshotCaptureAuthority
from dahe.verification.daily_snapshot_validation import (
    DailyContractSelectionBinding,
    DailySnapshotValidationError,
    replay_current_daily_snapshot_validation_from_store,
    validate_daily_snapshot_triplet,
    verify_current_daily_snapshot_validation_evidence,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
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
    exclusion_source_boundary_from_formal_development_authority,
)

SCHEMA_VERSION = 1
CURRENT_DAILY_DATASET_ID = "loop9-daily-validation"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Loop9DatasetArtifactError(ValueError):
    """Raised when source evidence cannot become a formal isolation artifact."""


class VerifiedImageReader(Protocol):
    """Read one local content-addressed image after the caller's path checks."""

    def read_verified_image(self, image_sha256: str) -> bytes: ...


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9DatasetArtifactError(f"{label} must be a lowercase SHA-256")
    return value


def _required_text(value: object, *, label: str, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise Loop9DatasetArtifactError(f"{label} is invalid")
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise Loop9DatasetArtifactError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise Loop9DatasetArtifactError(f"{label} must be an array")
    return cast(Sequence[object], value)


def identity_context_sha256(*, salt: bytes, namespace: str) -> str:
    """Use exactly the identity context used by Chengfeng shadow batches."""

    _identity_inputs(salt=salt, namespace=namespace)
    return chengfeng_shadow_identity_context_sha256(
        salt=salt,
        namespace=namespace,
    )


def platform_waybill_identity_digest(
    *,
    salt: bytes,
    namespace: str,
    source_identity: str,
) -> str:
    """Produce the same irreversible platform-waybill digest as a shadow batch."""

    _identity_inputs(salt=salt, namespace=namespace)
    return chengfeng_shadow_identity_digest(
        salt=salt,
        namespace=namespace,
        field_name="platform_waybill_id",
        value=_required_text(
            source_identity,
            label="platform waybill identity",
            maximum=500,
        ),
    )


def _identity_inputs(*, salt: bytes, namespace: str) -> None:
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise Loop9DatasetArtifactError(
            "identity key must contain at least 16 bytes"
        )
    _required_text(namespace, label="identity namespace", maximum=100)


@dataclass(frozen=True, slots=True)
class DailySnapshotInventoryBinding:
    snapshot_id: str
    job_id: str
    access_window_id: str
    snapshot_fingerprint: str
    entry_count: int
    image_count: int
    inventory_sha256: str

    def __post_init__(self) -> None:
        _required_text(self.snapshot_id, label="daily snapshot ID")
        _required_text(self.job_id, label="daily source Job ID")
        _required_text(
            self.access_window_id,
            label="daily access-window ID",
        )
        _required_sha256(
            self.snapshot_fingerprint,
            label="daily snapshot fingerprint",
        )
        _required_sha256(
            self.inventory_sha256,
            label="daily snapshot inventory SHA-256",
        )
        if (
            type(self.entry_count) is not int
            or self.entry_count < 1
            or type(self.image_count) is not int
            or self.image_count < 1
        ):
            raise Loop9DatasetArtifactError(
                "daily snapshot inventory counts are invalid"
            )

    def to_payload(self) -> dict[str, object]:
        return {
            "access_window_id": self.access_window_id,
            "entry_count": self.entry_count,
            "image_count": self.image_count,
            "inventory_sha256": self.inventory_sha256,
            "job_id": self.job_id,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "snapshot_id": self.snapshot_id,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> DailySnapshotInventoryBinding:
        raw = _mapping(value, label="daily snapshot inventory binding")
        expected = {
            "access_window_id",
            "entry_count",
            "image_count",
            "inventory_sha256",
            "job_id",
            "snapshot_fingerprint",
            "snapshot_id",
        }
        if set(raw) != expected:
            raise Loop9DatasetArtifactError(
                "daily snapshot inventory binding contract is invalid"
            )
        return cls(
            snapshot_id=cast(str, raw.get("snapshot_id")),
            job_id=cast(str, raw.get("job_id")),
            access_window_id=cast(str, raw.get("access_window_id")),
            snapshot_fingerprint=cast(
                str,
                raw.get("snapshot_fingerprint"),
            ),
            entry_count=cast(int, raw.get("entry_count")),
            image_count=cast(int, raw.get("image_count")),
            inventory_sha256=cast(str, raw.get("inventory_sha256")),
        )


@dataclass(frozen=True, slots=True)
class Loop9DailyTripletInventory:
    daily_validation_sha256: str
    build_sha256: str
    contract_sha256: str
    identity_context_sha256: str
    snapshot_bindings: tuple[DailySnapshotInventoryBinding, ...]
    entries: tuple[Loop9DatasetEntry, ...]
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_sha256(
            self.daily_validation_sha256,
            label="daily validation SHA-256",
        )
        _required_sha256(self.build_sha256, label="daily build SHA-256")
        _required_sha256(
            self.contract_sha256,
            label="daily contract SHA-256",
        )
        _required_sha256(
            self.identity_context_sha256,
            label="daily identity-context SHA-256",
        )
        if (
            not isinstance(self.snapshot_bindings, tuple)
            or len(self.snapshot_bindings) != 3
            or any(
                not isinstance(binding, DailySnapshotInventoryBinding)
                for binding in self.snapshot_bindings
            )
        ):
            raise Loop9DatasetArtifactError(
                "daily triplet requires exactly three snapshot bindings"
            )
        if (
            len({value.snapshot_id for value in self.snapshot_bindings}) != 3
            or len({value.job_id for value in self.snapshot_bindings}) != 3
            or len(
                {value.access_window_id for value in self.snapshot_bindings}
            )
            != 3
            or len(
                {value.snapshot_fingerprint for value in self.snapshot_bindings}
            )
            != 3
        ):
            raise Loop9DatasetArtifactError(
                "daily triplet snapshot bindings are not independent"
            )
        if (
            not isinstance(self.entries, tuple)
            or not self.entries
            or any(
                not isinstance(entry, Loop9DatasetEntry)
                for entry in self.entries
            )
            or any(
                entry.platform_identity_sha256 is None
                or entry.scope_exclusion_token is not None
                or not entry.images
                for entry in self.entries
            )
        ):
            raise Loop9DatasetArtifactError(
                "daily triplet identity and image inventory is incomplete"
            )
        if any(
            image.perceptual_fingerprint is None
            for entry in self.entries
            for image in entry.images
        ):
            raise Loop9DatasetArtifactError(
                "daily triplet requires a perceptual fingerprint for every image"
            )
        identities = tuple(
            cast(str, entry.platform_identity_sha256)
            for entry in self.entries
        )
        if len(identities) != len(set(identities)):
            raise Loop9DatasetArtifactError(
                "daily triplet contains duplicate platform identities"
            )
        expected_entries = len(self.entries)
        expected_images = sum(len(entry.images) for entry in self.entries)
        if any(
            binding.entry_count != expected_entries
            or binding.image_count != expected_images
            for binding in self.snapshot_bindings
        ):
            raise Loop9DatasetArtifactError(
                "daily triplet snapshot inventory counts are inconsistent"
            )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "build_sha256": self.build_sha256,
            "contract_sha256": self.contract_sha256,
            "daily_validation_sha256": self.daily_validation_sha256,
            "entries": sorted(
                (
                    {
                        "images": sorted(
                            (
                                {
                                    "image_sha256": image.image_sha256,
                                    "perceptual_fingerprint": (
                                        cast(
                                            ImagePerceptualFingerprint,
                                            image.perceptual_fingerprint,
                                        ).to_record()
                                    ),
                                }
                                for image in entry.images
                            ),
                            key=_canonical_json,
                        ),
                        "platform_identity_sha256": (
                            entry.platform_identity_sha256
                        ),
                        "scope_exclusion_token": None,
                    }
                    for entry in self.entries
                ),
                key=_canonical_json,
            ),
            "identity_context_sha256": self.identity_context_sha256,
            "kind": "loop9_daily_triplet_inventory",
            "schema_version": SCHEMA_VERSION,
            "snapshot_bindings": [
                binding.to_payload()
                for binding in sorted(
                    self.snapshot_bindings,
                    key=lambda item: item.snapshot_id,
                )
            ],
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    @classmethod
    def from_payload(cls, value: object) -> Loop9DailyTripletInventory:
        raw = _mapping(value, label="daily triplet inventory")
        expected = {
            "build_sha256",
            "canonical_sha256",
            "contract_sha256",
            "daily_validation_sha256",
            "entries",
            "identity_context_sha256",
            "kind",
            "schema_version",
            "snapshot_bindings",
        }
        if (
            set(raw) != expected
            or raw.get("kind") != "loop9_daily_triplet_inventory"
            or raw.get("schema_version") != SCHEMA_VERSION
        ):
            raise Loop9DatasetArtifactError(
                "daily triplet inventory contract is invalid"
            )
        try:
            entries = tuple(
                Loop9DatasetEntry.from_payload(entry)
                for entry in _sequence(
                    raw.get("entries"),
                    label="daily triplet entries",
                )
            )
        except Loop9DatasetIsolationError as exc:
            raise Loop9DatasetArtifactError(
                "daily triplet entries are invalid"
            ) from exc
        inventory = cls(
            daily_validation_sha256=cast(
                str,
                raw.get("daily_validation_sha256"),
            ),
            build_sha256=cast(str, raw.get("build_sha256")),
            contract_sha256=cast(str, raw.get("contract_sha256")),
            identity_context_sha256=cast(
                str,
                raw.get("identity_context_sha256"),
            ),
            snapshot_bindings=tuple(
                DailySnapshotInventoryBinding.from_payload(binding)
                for binding in _sequence(
                    raw.get("snapshot_bindings"),
                    label="daily snapshot bindings",
                )
            ),
            entries=entries,
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="daily triplet inventory canonical SHA-256",
        )
        if declared != inventory.canonical_sha256:
            raise Loop9DatasetArtifactError(
                "daily triplet inventory integrity is invalid"
            )
        return inventory


@dataclass(frozen=True, slots=True)
class Loop9CurrentDailyDatasetArtifacts:
    """Current formal daily inventory and its derived isolation manifest."""

    inventory: Loop9DailyTripletInventory
    manifest: Loop9DatasetManifest

    def __post_init__(self) -> None:
        if (
            not isinstance(self.inventory, Loop9DailyTripletInventory)
            or not isinstance(self.manifest, Loop9DatasetManifest)
            or self.manifest.dataset_kind
            is not DatasetKind.DAILY_VALIDATION
            or self.manifest.build_sha256
            != self.inventory.build_sha256
            or self.manifest.contract_sha256
            != self.inventory.contract_sha256
            or self.manifest.source_snapshot_sha256
            != self.inventory.daily_validation_sha256
            or self.manifest.identity_context_sha256
            != self.inventory.identity_context_sha256
            or sorted(
                (
                    entry._canonical_payload()
                    for entry in self.manifest.entries
                ),
                key=_canonical_json,
            )
            != sorted(
                (
                    entry._canonical_payload()
                    for entry in self.inventory.entries
                ),
                key=_canonical_json,
            )
        ):
            raise Loop9DatasetArtifactError(
                "current daily dataset artifacts are inconsistent"
            )


def build_discovery_dataset_manifest(
    *,
    dataset_id: str,
    validation_document: Mapping[str, object],
    development_inventory: Loop9DatasetExclusionInventory,
) -> Loop9DatasetManifest:
    """Bind one sanitized real validation sample as development-only data."""

    if not isinstance(development_inventory, Loop9DatasetExclusionInventory):
        raise Loop9DatasetArtifactError(
            "development exclusion inventory is invalid"
        )
    development_inventory.verify_integrity()
    document = _mapping(
        validation_document,
        label="sanitized validation evidence",
    )
    canonical_sha256 = _required_sha256(
        document.get("canonical_sha256"),
        label="sanitized validation evidence SHA-256",
    )
    validation_body = {
        key: value
        for key, value in document.items()
        if key != "canonical_sha256"
    }
    if _canonical_sha256(validation_body) != canonical_sha256:
        raise Loop9DatasetArtifactError(
            "sanitized validation evidence integrity is invalid"
        )
    if (
        document.get("schema_version") != 3
        or document.get("kind")
        != "loop9_live_read_contract_validation"
        or document.get("classification") != "development_only"
        or document.get("gate_passed") is not True
        or document.get("forbidden_request_count") != 0
        or document.get("platform_write_request_count") != 0
        or document.get("redirect_count") != 0
        or document.get("raw_request_values_retained") is not False
        or document.get("raw_response_values_retained") is not False
        or document.get("signed_image_urls_retained") is not False
    ):
        raise Loop9DatasetArtifactError(
            "sanitized validation is not a successful read-only gate"
        )
    if (
        development_inventory.exclusion_kind
        is not ExclusionKind.DEVELOPMENT
        or document.get("development_exclusion_inventory_sha256")
        != development_inventory.canonical_sha256
        or document.get("identity_context_sha256")
        != development_inventory.identity_context_sha256
        or development_inventory.artifact_schema_version != 2
        or len(development_inventory.platform_identity_sha256s) != 1
        or len(development_inventory.image_sha256s) != 2
        or len(development_inventory.perceptual_fingerprints) != 2
        or development_inventory.scope_exclusion_tokens
    ):
        raise Loop9DatasetArtifactError(
            "sanitized validation development inventory binding is invalid"
        )
    fingerprint_by_image = {
        fingerprint.content_sha256: fingerprint
        for fingerprint in development_inventory.perceptual_fingerprints
    }
    if set(fingerprint_by_image) != set(development_inventory.image_sha256s):
        raise Loop9DatasetArtifactError(
            "sanitized validation development inventory is incomplete"
        )
    access_window_id = _required_text(
        document.get("access_window_id"),
        label="validation access-window ID",
        maximum=32,
    )
    return Loop9DatasetManifest(
        dataset_id=_required_text(
            dataset_id,
            label="discovery dataset ID",
            maximum=100,
        ),
        dataset_kind=DatasetKind.DISCOVERY_DEVELOPMENT,
        build_sha256=_required_sha256(
            document.get("build_sha256"),
            label="validation build SHA-256",
        ),
        contract_sha256=_required_sha256(
            document.get("contract_canonical_sha256"),
            label="validation contract SHA-256",
        ),
        source_job_id=f"access-window-{access_window_id}",
        source_snapshot_sha256=canonical_sha256,
        entries=(
            Loop9DatasetEntry(
                platform_identity_sha256=(
                    development_inventory.platform_identity_sha256s[0]
                ),
                scope_exclusion_token=None,
                images=tuple(
                    Loop9DatasetImage(
                        image_sha256=image_sha256,
                        perceptual_fingerprint=(
                            fingerprint_by_image[image_sha256]
                        ),
                    )
                    for image_sha256 in sorted(
                        development_inventory.image_sha256s
                    )
                ),
            ),
        ),
        identity_context_sha256=(
            development_inventory.identity_context_sha256
        ),
    )


def build_formal_dataset_manifest(
    *,
    dataset_id: str,
    shadow_batch: ChengfengShadowBatchManifest,
    formal_selection: FormalShadowSelectionManifest,
) -> Loop9DatasetManifest:
    """Convert a sealed local-OCR shadow batch to an isolation manifest."""

    if not isinstance(shadow_batch, ChengfengShadowBatchManifest):
        raise Loop9DatasetArtifactError(
            "shadow batch manifest is invalid"
        )
    try:
        shadow_batch.verify_integrity()
    except ChengfengShadowBatchContractError as exc:
        raise Loop9DatasetArtifactError(
            "shadow batch manifest integrity is invalid"
        ) from exc
    if not isinstance(formal_selection, FormalShadowSelectionManifest):
        raise Loop9DatasetArtifactError(
            "formal selection manifest is invalid"
        )
    try:
        formal_selection.verify_integrity()
    except FormalShadowSelectionContractError as exc:
        raise Loop9DatasetArtifactError(
            "formal selection manifest integrity is invalid"
        ) from exc
    if (
        formal_selection.target_kind is not shadow_batch.target_kind
        or formal_selection.batch_manifest.to_payload()
        != shadow_batch.to_payload()
    ):
        raise Loop9DatasetArtifactError(
            "shadow batch does not match the formal selection"
        )
    source_job_ids = {source.job_id for source in shadow_batch.sources}
    if len(source_job_ids) != 1:
        raise Loop9DatasetArtifactError(
            "formal batch must be bound to one source Job"
        )
    kind = (
        DatasetKind.CURRENT_LOCKED_50
        if shadow_batch.target_kind
        is ShadowBatchTargetKind.CURRENT_LOCKED_50
        else DatasetKind.REAL_SHADOW_30
    )
    return Loop9DatasetManifest(
        dataset_id=_required_text(
            dataset_id,
            label="formal dataset ID",
            maximum=100,
        ),
        dataset_kind=kind,
        build_sha256=shadow_batch.source_build_sha256,
        contract_sha256=shadow_batch.contract_canonical_sha256,
        source_job_id=next(iter(source_job_ids)),
        source_snapshot_sha256=shadow_batch.canonical_sha256,
        entries=tuple(
            Loop9DatasetEntry(
                platform_identity_sha256=(
                    item.platform_waybill_id_digest
                ),
                scope_exclusion_token=None,
                images=tuple(
                    Loop9DatasetImage(
                        image_sha256=image.sha256,
                        perceptual_fingerprint=(
                            image.perceptual_fingerprint
                        ),
                    )
                    for image in item.images
                ),
            )
            for item in shadow_batch.items
        ),
        identity_context_sha256=shadow_batch.identity_context_sha256,
        formal_selection_sha256=formal_selection.canonical_sha256,
        locked_gate_evidence_sha256=(
            formal_selection.locked_gate_evidence_sha256
        ),
    )


def build_daily_triplet_inventory(
    *,
    daily_validation: object,
    contract_selection: DailyContractSelectionBinding,
    authorities: Sequence[DailySnapshotCaptureAuthority],
    observations_by_snapshot: Mapping[
        str,
        Sequence[DailyWaybillObservation],
    ],
    identity_salt: bytes,
    identity_namespace: str,
    image_reader: VerifiedImageReader,
) -> Loop9DailyTripletInventory:
    """Inventory every identity and image in three verified daily snapshots."""

    try:
        verified = verify_current_daily_snapshot_validation_evidence(
            daily_validation
        )
    except DailySnapshotValidationError as exc:
        raise Loop9DatasetArtifactError(
            "daily validation evidence is invalid"
        ) from exc
    if verified.get("schema_version") != 5:
        raise Loop9DatasetArtifactError(
            "current daily validation schema is not version 5"
        )
    build_sha256 = _required_sha256(
        verified.get("build_sha256"),
        label="daily validation build SHA-256",
    )
    contract_sha256 = _required_sha256(
        verified.get("contract_sha256"),
        label="daily validation contract SHA-256",
    )
    if (
        not isinstance(
            contract_selection,
            DailyContractSelectionBinding,
        )
        or verified.get("contract_selection")
        != contract_selection.to_payload()
    ):
        raise Loop9DatasetArtifactError(
            "selected daily contract does not match validation evidence"
        )
    normalized_authorities = tuple(authorities)
    try:
        rebuilt = validate_daily_snapshot_triplet(
            normalized_authorities,
            build_sha256=build_sha256,
            expected_contract_sha256=contract_sha256,
            contract_selection=contract_selection,
        )
    except DailySnapshotValidationError as exc:
        raise Loop9DatasetArtifactError(
            "daily snapshot authorities are invalid"
        ) from exc
    if rebuilt != verified:
        raise Loop9DatasetArtifactError(
            "daily validation evidence does not match current authorities"
        )
    _identity_inputs(
        salt=identity_salt,
        namespace=identity_namespace,
    )
    if not hasattr(image_reader, "read_verified_image"):
        raise Loop9DatasetArtifactError(
            "daily verified image reader is invalid"
        )

    snapshot_entries: list[tuple[Loop9DatasetEntry, ...]] = []
    snapshot_bindings: list[DailySnapshotInventoryBinding] = []
    for authority in normalized_authorities:
        snapshot_id = authority.snapshot.snapshot_id
        observations = tuple(
            observations_by_snapshot.get(snapshot_id, ())
        )
        expected_ids = {
            candidate.platform_waybill_id
            for candidate in authority.snapshot.candidates
        }
        observed_ids = {
            observation.platform_waybill_id
            for observation in observations
        }
        if (
            len(observations) != authority.observation_count
            or len(observations) != len(authority.snapshot.candidates)
            or observed_ids != expected_ids
            or any(
                not isinstance(observation, DailyWaybillObservation)
                or observation.snapshot_id != snapshot_id
                for observation in observations
            )
        ):
            raise Loop9DatasetArtifactError(
                "daily snapshot observation inventory is incomplete"
            )
        entries = tuple(
            _daily_observation_entry(
                observation=observation,
                identity_salt=identity_salt,
                identity_namespace=identity_namespace,
                image_reader=image_reader,
            )
            for observation in observations
        )
        normalized_entries = tuple(
            sorted(
                entries,
                key=lambda entry: cast(
                    str,
                    entry.platform_identity_sha256,
                ),
            )
        )
        inventory_payload = [
            entry._canonical_payload() for entry in normalized_entries
        ]
        snapshot_entries.append(normalized_entries)
        snapshot_bindings.append(
            DailySnapshotInventoryBinding(
                snapshot_id=snapshot_id,
                job_id=authority.job_id,
                access_window_id=authority.access_window_id,
                snapshot_fingerprint=authority.snapshot.fingerprint,
                entry_count=len(normalized_entries),
                image_count=sum(
                    len(entry.images) for entry in normalized_entries
                ),
                inventory_sha256=_canonical_sha256(
                    {
                        "entries": inventory_payload,
                        "snapshot_fingerprint": (
                            authority.snapshot.fingerprint
                        ),
                        "snapshot_id": snapshot_id,
                    }
                ),
            )
        )
    first_payload = [
        entry._canonical_payload() for entry in snapshot_entries[0]
    ]
    if any(
        [entry._canonical_payload() for entry in entries]
        != first_payload
        for entries in snapshot_entries[1:]
    ):
        raise Loop9DatasetArtifactError(
            "daily triplet identity or image inventory changed between snapshots"
        )
    return Loop9DailyTripletInventory(
        daily_validation_sha256=cast(
            str,
            verified["canonical_sha256"],
        ),
        build_sha256=build_sha256,
        contract_sha256=contract_sha256,
        identity_context_sha256=identity_context_sha256(
            salt=identity_salt,
            namespace=identity_namespace,
        ),
        snapshot_bindings=tuple(snapshot_bindings),
        entries=snapshot_entries[0],
    )


def _daily_observation_entry(
    *,
    observation: DailyWaybillObservation,
    identity_salt: bytes,
    identity_namespace: str,
    image_reader: VerifiedImageReader,
) -> Loop9DatasetEntry:
    image_sha256s = tuple(
        value
        for value in (
            observation.loading_ticket_sha256,
            observation.unloading_ticket_sha256,
        )
        if value is not None
    )
    if not image_sha256s:
        raise Loop9DatasetArtifactError(
            "daily formal observation has no ticket image; image isolation cannot pass"
        )
    if len(image_sha256s) != len(set(image_sha256s)):
        raise Loop9DatasetArtifactError(
            "daily formal observation contains a duplicate ticket image"
        )
    images: list[Loop9DatasetImage] = []
    for image_sha256 in image_sha256s:
        _required_sha256(
            image_sha256,
            label="daily ticket image SHA-256",
        )
        try:
            content = image_reader.read_verified_image(image_sha256)
        except (KeyError, OSError, RuntimeError) as exc:
            raise Loop9DatasetArtifactError(
                "daily ticket image is unavailable"
            ) from exc
        if (
            not isinstance(content, bytes)
            or hashlib.sha256(content).hexdigest() != image_sha256
        ):
            raise Loop9DatasetArtifactError(
                "daily ticket image content does not match its identity"
            )
        try:
            fingerprint = build_image_fingerprint(content)
        except ImageSimilarityContractError as exc:
            raise Loop9DatasetArtifactError(
                "daily ticket image perceptual fingerprint failed"
            ) from exc
        images.append(
            Loop9DatasetImage(
                image_sha256=image_sha256,
                perceptual_fingerprint=fingerprint,
            )
        )
    return Loop9DatasetEntry(
        platform_identity_sha256=platform_waybill_identity_digest(
            salt=identity_salt,
            namespace=identity_namespace,
            source_identity=observation.platform_waybill_id,
        ),
        scope_exclusion_token=None,
        images=tuple(images),
    )


def build_daily_dataset_manifest(
    *,
    dataset_id: str,
    inventory: Loop9DailyTripletInventory,
) -> Loop9DatasetManifest:
    """Bind a replay-verified daily triplet inventory to dataset isolation."""

    if not isinstance(inventory, Loop9DailyTripletInventory):
        raise Loop9DatasetArtifactError(
            "daily triplet inventory is invalid"
        )
    replayed = Loop9DailyTripletInventory.from_payload(
        inventory.to_payload()
    )
    return Loop9DatasetManifest(
        dataset_id=_required_text(
            dataset_id,
            label="daily dataset ID",
            maximum=100,
        ),
        dataset_kind=DatasetKind.DAILY_VALIDATION,
        build_sha256=replayed.build_sha256,
        contract_sha256=replayed.contract_sha256,
        source_job_id=(
            f"daily-triplet-{replayed.canonical_sha256[:32]}"
        ),
        source_snapshot_sha256=replayed.daily_validation_sha256,
        entries=replayed.entries,
        identity_context_sha256=replayed.identity_context_sha256,
    )


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(
        attributes
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _resolved_formal_root(path: Path, *, label: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.is_symlink()
        or _is_reparse_point(path)
    ):
        raise Loop9DatasetArtifactError(f"{label} is unsafe")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9DatasetArtifactError(
            f"{label} is unavailable"
        ) from exc
    if (
        resolved != path
        or not resolved.is_dir()
        or _is_reparse_point(resolved)
    ):
        raise Loop9DatasetArtifactError(f"{label} is unsafe")
    return resolved


class _DataRootVerifiedImageReader:
    """Read only immutable content-addressed evidence from one formal root."""

    def __init__(self, data_root: Path) -> None:
        root = _resolved_formal_root(data_root, label="formal data root")
        evidence = root / "evidence"
        content_root = evidence / "sha256"
        for path in (evidence, content_root):
            if path.is_symlink() or _is_reparse_point(path):
                raise Loop9DatasetArtifactError(
                    "daily evidence root is unsafe"
                )
        try:
            self._root = content_root.resolve(strict=True)
        except OSError as exc:
            raise Loop9DatasetArtifactError(
                "daily evidence root is unavailable"
            ) from exc
        if (
            self._root != content_root
            or not self._root.is_dir()
            or _is_reparse_point(self._root)
        ):
            raise Loop9DatasetArtifactError(
                "daily evidence root is unsafe"
            )

    def read_verified_image(self, image_sha256: str) -> bytes:
        digest = _required_sha256(
            image_sha256,
            label="daily ticket image SHA-256",
        )
        first = self._root / digest[:2]
        second = first / digest[2:4]
        target = second / f"{digest}.blob"
        for path in (first, second, target):
            if path.is_symlink() or _is_reparse_point(path):
                raise Loop9DatasetArtifactError(
                    "daily ticket image path is unsafe"
                )
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(self._root)
            before = resolved.stat()
            content = resolved.read_bytes()
            after = resolved.stat()
        except (OSError, ValueError) as exc:
            raise Loop9DatasetArtifactError(
                "daily ticket image is unavailable"
            ) from exc
        if (
            resolved != target
            or not resolved.is_file()
            or _is_reparse_point(resolved)
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or len(content) != before.st_size
        ):
            raise Loop9DatasetArtifactError(
                "daily ticket image changed while it was being read"
            )
        return content


def _daily_contract_selection_binding(
    selected: SelectedDailyReadContract,
) -> DailyContractSelectionBinding:
    return DailyContractSelectionBinding(
        contract_canonical_sha256=(
            selected.manifest.canonical_sha256
        ),
        contract_file_sha256=selected.contract_file_sha256,
        freeze_evidence_sha256=selected.freeze_evidence_sha256,
        selection_sha256=selected.selection_sha256,
        source_discovery_sha256=(
            selected.manifest.source_discovery_sha256
        ),
    )


def _daily_snapshot_ids(
    daily_validation: Mapping[str, object],
) -> tuple[str, str, str]:
    snapshots = daily_validation.get("snapshot_evidence")
    if not isinstance(snapshots, list) or len(snapshots) != 3:
        raise Loop9DatasetArtifactError(
            "current daily validation must bind exactly three snapshots"
        )
    snapshot_ids: list[str] = []
    for snapshot in snapshots:
        if (
            not isinstance(snapshot, Mapping)
            or not isinstance(snapshot.get("snapshot_id"), str)
            or not cast(str, snapshot["snapshot_id"])
        ):
            raise Loop9DatasetArtifactError(
                "current daily validation snapshot identity is invalid"
            )
        snapshot_ids.append(cast(str, snapshot["snapshot_id"]))
    if len(set(snapshot_ids)) != 3:
        raise Loop9DatasetArtifactError(
            "current daily validation snapshot identities are not independent"
        )
    return cast(tuple[str, str, str], tuple(snapshot_ids))


def rebuild_current_daily_dataset_artifacts_from_store(
    *,
    dataset_id: str,
    daily_validation: object,
    data_root: Path,
    project_root: Path,
    source_build_sha256: str,
) -> Loop9CurrentDailyDatasetArtifacts:
    """Rebuild current daily inventory and manifest from formal authorities."""

    formal_root = _resolved_formal_root(
        data_root,
        label="formal data root",
    )
    repository_root = _resolved_formal_root(
        project_root,
        label="project root",
    )
    build_sha256 = _required_sha256(
        source_build_sha256,
        label="current Loop 9 build SHA-256",
    )
    try:
        validated = replay_current_daily_snapshot_validation_from_store(
            daily_validation,
            data_root=formal_root,
            project_root=repository_root,
            source_build_sha256=build_sha256,
        )
    except DailySnapshotValidationError as exc:
        raise Loop9DatasetArtifactError(
            "current daily validation evidence is invalid"
        ) from exc
    if validated.get("schema_version") != 5:
        raise Loop9DatasetArtifactError(
            "current daily validation requires schema version 5"
        )
    snapshot_ids = _daily_snapshot_ids(validated)
    try:
        selected = load_selected_daily_read_contract(formal_root)
    except DailyContractSelectionError as exc:
        raise Loop9DatasetArtifactError(
            "selected daily contract evidence is unavailable"
        ) from exc
    runtime = SqliteRuntime(
        data_root=formal_root,
        project_root=repository_root,
        instance_id=f"loop9-daily-dataset-replay-{uuid4().hex}",
    )
    try:
        store = SqliteDailyStore(runtime)
        authorities = tuple(
            store.get_formal_snapshot_authority(snapshot_id)
            for snapshot_id in snapshot_ids
        )
        observations = {
            snapshot_id: store.list_snapshot_observations(snapshot_id)
            for snapshot_id in snapshot_ids
        }
    finally:
        runtime.close()
    try:
        identity = load_loop9_identity_authority(formal_root)
    except Loop9IdentityAuthorityError as exc:
        raise Loop9DatasetArtifactError(
            "formal platform identity authority is unavailable"
        ) from exc
    inventory = build_daily_triplet_inventory(
        daily_validation=validated,
        contract_selection=_daily_contract_selection_binding(selected),
        authorities=authorities,
        observations_by_snapshot=observations,
        identity_salt=identity.salt,
        identity_namespace=identity.namespace,
        image_reader=_DataRootVerifiedImageReader(formal_root),
    )
    if inventory.identity_context_sha256 != identity.context_sha256:
        raise Loop9DatasetArtifactError(
            "formal platform identity authority changed"
        )
    manifest = build_daily_dataset_manifest(
        dataset_id=dataset_id,
        inventory=inventory,
    )
    return Loop9CurrentDailyDatasetArtifacts(
        inventory=inventory,
        manifest=manifest,
    )


def replay_current_daily_dataset_manifest_from_store(
    persisted_manifest: object,
    *,
    daily_validation: object,
    data_root: Path,
    project_root: Path,
    source_build_sha256: str,
    expected_dataset_id: str,
) -> Loop9CurrentDailyDatasetArtifacts:
    """Rebuild and compare every field of a persisted current daily manifest."""

    try:
        persisted = (
            Loop9DatasetManifest.from_payload(
                persisted_manifest.to_payload()
            )
            if isinstance(persisted_manifest, Loop9DatasetManifest)
            else Loop9DatasetManifest.from_payload(persisted_manifest)
        )
    except Loop9DatasetIsolationError as exc:
        raise Loop9DatasetArtifactError(
            "persisted daily dataset manifest is invalid"
        ) from exc
    expected_id = _required_text(
        expected_dataset_id,
        label="expected daily dataset ID",
        maximum=100,
    )
    if (
        persisted.dataset_kind is not DatasetKind.DAILY_VALIDATION
        or persisted.dataset_id != expected_id
    ):
        raise Loop9DatasetArtifactError(
            "persisted daily dataset manifest classification is invalid"
        )
    rebuilt = rebuild_current_daily_dataset_artifacts_from_store(
        dataset_id=expected_id,
        daily_validation=daily_validation,
        data_root=data_root,
        project_root=project_root,
        source_build_sha256=source_build_sha256,
    )
    if (
        rebuilt.manifest.canonical_sha256
        != persisted.canonical_sha256
        or rebuilt.manifest.to_payload() != persisted.to_payload()
    ):
        raise Loop9DatasetArtifactError(
            "persisted daily dataset manifest does not match formal authorities"
        )
    return rebuilt


def merge_loop9_exclusion_inventories(
    *,
    inventory_id: str,
    exclusion_kind: ExclusionKind,
    inventories: Sequence[Loop9DatasetExclusionInventory],
) -> Loop9DatasetExclusionInventory:
    """Merge compatible immutable exclusion inventories without weakening them."""

    if not isinstance(exclusion_kind, ExclusionKind):
        raise Loop9DatasetIsolationError(
            "exclusion inventory classification is invalid"
        )
    normalized = tuple(inventories)
    if (
        not normalized
        or any(
            not isinstance(value, Loop9DatasetExclusionInventory)
            for value in normalized
        )
    ):
        raise Loop9DatasetArtifactError(
            "one or more exclusion inventories are required"
        )
    fingerprint_by_image: dict[str, ImagePerceptualFingerprint] = {}
    platform_identities: set[str] = set()
    image_sha256s: set[str] = set()
    scope_tokens: set[str] = set()
    identity_contexts: set[str] = set()
    for inventory in normalized:
        inventory.verify_integrity()
        if inventory.exclusion_kind is not exclusion_kind:
            raise Loop9DatasetIsolationError(
                "exclusion inventory classification is invalid"
            )
        if (
            inventory.artifact_schema_version != 2
            or inventory.identity_context_sha256 is None
        ):
            raise Loop9DatasetArtifactError(
                "legacy exclusion inventory cannot be merged into the current gate"
            )
        identity_contexts.add(inventory.identity_context_sha256)
        if set(inventory.image_sha256s) != {
            fingerprint.content_sha256
            for fingerprint in inventory.perceptual_fingerprints
        }:
            raise Loop9DatasetArtifactError(
                "exclusion inventory requires a perceptual fingerprint "
                "for every excluded image"
            )
        platform_identities.update(inventory.platform_identity_sha256s)
        image_sha256s.update(inventory.image_sha256s)
        scope_tokens.update(inventory.scope_exclusion_tokens)
        for fingerprint in inventory.perceptual_fingerprints:
            existing = fingerprint_by_image.setdefault(
                fingerprint.content_sha256,
                fingerprint,
            )
            if existing.canonical_sha256 != fingerprint.canonical_sha256:
                raise Loop9DatasetArtifactError(
                    "one excluded image has conflicting perceptual fingerprints"
                )
    if len(identity_contexts) != 1:
        raise Loop9DatasetArtifactError(
            "exclusion inventories use different identity contexts"
        )
    return Loop9DatasetExclusionInventory(
        inventory_id=_required_text(
            inventory_id,
            label="merged exclusion inventory ID",
            maximum=100,
        ),
        exclusion_kind=exclusion_kind,
        platform_identity_sha256s=tuple(sorted(platform_identities)),
        image_sha256s=tuple(sorted(image_sha256s)),
        scope_exclusion_tokens=tuple(sorted(scope_tokens)),
        perceptual_fingerprints=tuple(
            fingerprint_by_image[image_sha256]
            for image_sha256 in sorted(fingerprint_by_image)
        ),
        identity_context_sha256=next(iter(identity_contexts)),
    )


def build_legacy_loop7_exclusion_inventory(
    *,
    inventory_id: str,
    source_authority: object,
    identity_context_sha256: str,
) -> Loop9DatasetExclusionInventory:
    """Convert the sealed Loop 7 boundary into one current immutable child."""

    try:
        boundary = (
            exclusion_source_boundary_from_formal_development_authority(
                source_authority
            )
        )
    except Loop9DatasetIsolationError as exc:
        raise Loop9DatasetArtifactError(
            "legacy Loop 7 source authority is invalid"
        ) from exc
    waybill_identity_sha256s = getattr(
        source_authority,
        "waybill_identity_sha256s",
        None,
    )
    if (
        not isinstance(waybill_identity_sha256s, frozenset)
        or len(waybill_identity_sha256s)
        != boundary.platform_identity_count
    ):
        raise Loop9DatasetArtifactError(
            "legacy Loop 7 platform identity boundary is incomplete"
        )
    inventory = Loop9DatasetExclusionInventory(
        inventory_id=_required_text(
            inventory_id,
            label="legacy Loop 7 exclusion inventory ID",
            maximum=100,
        ),
        exclusion_kind=ExclusionKind.LEGACY_LOOP7,
        platform_identity_sha256s=tuple(
            sorted(waybill_identity_sha256s)
        ),
        image_sha256s=boundary.image_sha256s,
        scope_exclusion_tokens=(),
        perceptual_fingerprints=boundary.perceptual_fingerprints,
        identity_context_sha256=_required_sha256(
            identity_context_sha256,
            label="legacy Loop 7 identity context SHA-256",
        ),
    )
    if (
        set(inventory.image_sha256s)
        != {
            fingerprint.content_sha256
            for fingerprint in inventory.perceptual_fingerprints
        }
        or len(inventory.platform_identity_sha256s)
        != boundary.platform_identity_count
    ):
        raise Loop9DatasetArtifactError(
            "legacy Loop 7 exclusion conversion is incomplete"
        )
    return inventory
