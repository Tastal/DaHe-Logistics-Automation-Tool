from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast

from dahe.application.chengfeng.settlement_capture import (
    SCHEMA_VERSION as SETTLEMENT_CAPTURE_SCHEMA_VERSION,
)
from dahe.application.chengfeng.settlement_capture import (
    SettlementCaptureManifest,
)
from dahe.application.chengfeng.shadow_batch import (
    HISTORICAL_CAPTURE_MAX_ITEMS,
    HISTORICAL_CAPTURE_MAX_PAGES,
    HISTORICAL_CAPTURE_PAGE_SIZE,
    ChengfengShadowBatchManifest,
    ShadowBatchItem,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_batch import (
    SCHEMA_VERSION as SHADOW_BATCH_SCHEMA_VERSION,
)
from dahe.ports.chengfeng import (
    CURRENT_PENDING_SETTLEMENT_SCOPE,
    HISTORICAL_SETTLED_SCOPE,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
    find_near_duplicate_candidates,
)
from dahe.verification.loop9_dataset_isolation import (
    discovery_scope_exclusion_token,
)

SCHEMA_VERSION = 2
SOURCE_KIND = "chengfeng_formal_selection"
SELECTION_POLICY = "hmac_rank_v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FormalShadowSelectionContractError(ValueError):
    """Raised when a formal 50/30 selection is not independently safe."""


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
        raise FormalShadowSelectionContractError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise FormalShadowSelectionContractError(
            f"{label} must be an object"
        )
    return cast(Mapping[str, object], value)


def _array(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise FormalShadowSelectionContractError(
            f"{label} must be an array"
        )
    return cast(Sequence[object], value)


@dataclass(frozen=True, slots=True)
class SelectionSeedAuthority:
    """Installation-local stable seed; callers cannot choose selected rows."""

    seed: bytes = field(repr=False)
    policy: str = SELECTION_POLICY
    authority_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.seed, bytes)
            or len(self.seed) != 32
            or self.policy != SELECTION_POLICY
        ):
            raise FormalShadowSelectionContractError(
                "selection seed authority is invalid"
            )
        object.__setattr__(
            self,
            "authority_sha256",
            hashlib.sha256(
                b"dahe:loop9:formal-selection-authority:v1\0"
                + self.policy.encode("ascii")
                + b"\0"
                + self.seed
            ).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class FormalSelectionExclusionSnapshot:
    """Verified full-history exclusions required before formal ranking."""

    authority_sha256: str
    child_index_head_sha256: str
    source_boundary_sha256: str
    source_inventory_high_watermark: int
    identity_context_sha256: str
    expected_current_build_sha256: str
    expected_settlement_contract_sha256: str
    expected_settlement_selection_sha256: str
    excluded_platform_identity_sha256s: tuple[str, ...]
    excluded_image_sha256s: tuple[str, ...]
    excluded_scope_exclusion_tokens: tuple[str, ...]
    excluded_perceptual_fingerprints: tuple[
        ImagePerceptualFingerprint,
        ...,
    ]

    def __post_init__(self) -> None:
        for label, value in (
            ("exclusion authority SHA-256", self.authority_sha256),
            (
                "exclusion child-index head SHA-256",
                self.child_index_head_sha256,
            ),
            (
                "exclusion source-boundary SHA-256",
                self.source_boundary_sha256,
            ),
            ("identity context SHA-256", self.identity_context_sha256),
            (
                "expected current build SHA-256",
                self.expected_current_build_sha256,
            ),
            (
                "expected settlement contract SHA-256",
                self.expected_settlement_contract_sha256,
            ),
            (
                "expected settlement selection SHA-256",
                self.expected_settlement_selection_sha256,
            ),
        ):
            _required_sha256(value, label=label)
        if (
            isinstance(self.source_inventory_high_watermark, bool)
            or not isinstance(self.source_inventory_high_watermark, int)
            or self.source_inventory_high_watermark < 1
        ):
            raise FormalShadowSelectionContractError(
                "exclusion source inventory high-watermark is invalid"
            )
        for label, values in (
            (
                "excluded platform identity SHA-256 values",
                self.excluded_platform_identity_sha256s,
            ),
            (
                "excluded image SHA-256 values",
                self.excluded_image_sha256s,
            ),
            (
                "excluded scope tokens",
                self.excluded_scope_exclusion_tokens,
            ),
        ):
            if (
                not isinstance(values, tuple)
                or len(values) != len(set(values))
            ):
                raise FormalShadowSelectionContractError(
                    f"{label} are invalid"
                )
            for value in values:
                _required_sha256(value, label=label)
        if (
            not isinstance(self.excluded_perceptual_fingerprints, tuple)
            or len(
                {
                    fingerprint.content_sha256
                    for fingerprint in (
                        self.excluded_perceptual_fingerprints
                    )
                }
            )
            != len(self.excluded_perceptual_fingerprints)
        ):
            raise FormalShadowSelectionContractError(
                "excluded perceptual fingerprints are invalid"
            )
        for fingerprint in self.excluded_perceptual_fingerprints:
            if not isinstance(fingerprint, ImagePerceptualFingerprint):
                raise FormalShadowSelectionContractError(
                    "excluded perceptual fingerprint is invalid"
                )
            try:
                fingerprint.verify_integrity()
            except ImageSimilarityContractError as exc:
                raise FormalShadowSelectionContractError(
                    "excluded perceptual fingerprint is invalid"
                ) from exc


@dataclass(frozen=True, slots=True)
class FormalShadowSelectionManifest:
    """Outward-safe authority proving one deterministic exact selection."""

    target_kind: ShadowBatchTargetKind
    source_capture_sha256: str
    full_history_exclusion_authority_sha256: str
    exclusion_child_index_head_sha256: str
    exclusion_source_boundary_sha256: str
    exclusion_source_inventory_high_watermark: int
    selection_seed_authority_sha256: str
    rank_commitment_sha256: str
    prior_selection_sha256s: tuple[str, ...]
    batch_manifest: ChengfengShadowBatchManifest
    locked_gate_evidence_sha256: str | None = None
    selection_policy: str = SELECTION_POLICY
    source_kind: str = SOURCE_KIND
    schema_version: int = SCHEMA_VERSION
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.target_kind, ShadowBatchTargetKind)
            or self.batch_manifest.target_kind is not self.target_kind
        ):
            raise FormalShadowSelectionContractError(
                "selection target kind is invalid"
            )
        if (
            self.selection_policy != SELECTION_POLICY
            or self.source_kind != SOURCE_KIND
            or type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
        ):
            raise FormalShadowSelectionContractError(
                "formal selection version is unsupported"
            )
        for label, value in (
            ("source capture SHA-256", self.source_capture_sha256),
            (
                "full-history exclusion authority SHA-256",
                self.full_history_exclusion_authority_sha256,
            ),
            (
                "exclusion child-index head SHA-256",
                self.exclusion_child_index_head_sha256,
            ),
            (
                "exclusion source-boundary SHA-256",
                self.exclusion_source_boundary_sha256,
            ),
            (
                "selection seed authority SHA-256",
                self.selection_seed_authority_sha256,
            ),
            ("rank commitment SHA-256", self.rank_commitment_sha256),
        ):
            _required_sha256(value, label=label)
        if (
            isinstance(self.exclusion_source_inventory_high_watermark, bool)
            or not isinstance(
                self.exclusion_source_inventory_high_watermark,
                int,
            )
            or self.exclusion_source_inventory_high_watermark < 1
        ):
            raise FormalShadowSelectionContractError(
                "exclusion source inventory high-watermark is invalid"
            )
        if (
            not isinstance(self.prior_selection_sha256s, tuple)
            or len(set(self.prior_selection_sha256s))
            != len(self.prior_selection_sha256s)
        ):
            raise FormalShadowSelectionContractError(
                "prior selection authority is invalid"
            )
        for value in self.prior_selection_sha256s:
            _required_sha256(value, label="prior selection SHA-256")
        if self.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
            if self.locked_gate_evidence_sha256 is not None:
                raise FormalShadowSelectionContractError(
                    "locked selection must not bind a locked gate"
                )
        elif self.locked_gate_evidence_sha256 is None:
            raise FormalShadowSelectionContractError(
                "real shadow selection requires locked gate evidence"
            )
        else:
            _required_sha256(
                self.locked_gate_evidence_sha256,
                label="locked gate evidence SHA-256",
            )
        self.batch_manifest.verify_integrity()
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "batch_manifest": self.batch_manifest.to_payload(),
            "exclusion_child_index_head_sha256": (
                self.exclusion_child_index_head_sha256
            ),
            "exclusion_source_boundary_sha256": (
                self.exclusion_source_boundary_sha256
            ),
            "exclusion_source_inventory_high_watermark": (
                self.exclusion_source_inventory_high_watermark
            ),
            "full_history_exclusion_authority_sha256": (
                self.full_history_exclusion_authority_sha256
            ),
            "locked_gate_evidence_sha256": (
                self.locked_gate_evidence_sha256
            ),
            "prior_selection_sha256s": sorted(
                self.prior_selection_sha256s
            ),
            "rank_commitment_sha256": self.rank_commitment_sha256,
            "schema_version": self.schema_version,
            "selection_policy": self.selection_policy,
            "selection_seed_authority_sha256": (
                self.selection_seed_authority_sha256
            ),
            "source_capture_sha256": self.source_capture_sha256,
            "source_kind": self.source_kind,
            "target_kind": self.target_kind.value,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        self.batch_manifest.verify_integrity()
        if _canonical_sha256(self._canonical_payload()) != (
            self.canonical_sha256
        ):
            raise FormalShadowSelectionContractError(
                "formal selection manifest integrity is invalid"
            )

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> FormalShadowSelectionManifest:
        raw = _mapping(value, label="formal selection manifest")
        expected = {
            "batch_manifest",
            "canonical_sha256",
            "exclusion_child_index_head_sha256",
            "exclusion_source_boundary_sha256",
            "exclusion_source_inventory_high_watermark",
            "full_history_exclusion_authority_sha256",
            "locked_gate_evidence_sha256",
            "prior_selection_sha256s",
            "rank_commitment_sha256",
            "schema_version",
            "selection_policy",
            "selection_seed_authority_sha256",
            "source_capture_sha256",
            "source_kind",
            "target_kind",
        }
        if set(raw) != expected:
            raise FormalShadowSelectionContractError(
                "formal selection manifest contract is invalid"
            )
        try:
            target_kind = ShadowBatchTargetKind(
                cast(str, raw.get("target_kind"))
            )
        except (TypeError, ValueError) as exc:
            raise FormalShadowSelectionContractError(
                "formal selection target kind is invalid"
            ) from exc
        manifest = cls(
            target_kind=target_kind,
            source_capture_sha256=cast(
                str,
                raw.get("source_capture_sha256"),
            ),
            full_history_exclusion_authority_sha256=cast(
                str,
                raw.get("full_history_exclusion_authority_sha256"),
            ),
            exclusion_child_index_head_sha256=cast(
                str,
                raw.get("exclusion_child_index_head_sha256"),
            ),
            exclusion_source_boundary_sha256=cast(
                str,
                raw.get("exclusion_source_boundary_sha256"),
            ),
            exclusion_source_inventory_high_watermark=cast(
                int,
                raw.get("exclusion_source_inventory_high_watermark"),
            ),
            selection_seed_authority_sha256=cast(
                str,
                raw.get("selection_seed_authority_sha256"),
            ),
            rank_commitment_sha256=cast(
                str,
                raw.get("rank_commitment_sha256"),
            ),
            prior_selection_sha256s=tuple(
                cast(str, item)
                for item in _array(
                    raw.get("prior_selection_sha256s"),
                    label="prior selection SHA-256 values",
                )
            ),
            batch_manifest=ChengfengShadowBatchManifest.from_payload(
                _mapping(
                    raw.get("batch_manifest"),
                    label="selected shadow batch",
                )
            ),
            locked_gate_evidence_sha256=cast(
                str | None,
                raw.get("locked_gate_evidence_sha256"),
            ),
            selection_policy=cast(str, raw.get("selection_policy")),
            source_kind=cast(str, raw.get("source_kind")),
            schema_version=cast(int, raw.get("schema_version")),
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="formal selection canonical SHA-256",
        )
        if declared != manifest.canonical_sha256:
            raise FormalShadowSelectionContractError(
                "formal selection manifest integrity is invalid"
            )
        return manifest


def _selection_authority(
    manifest: ChengfengShadowBatchManifest,
) -> tuple[str, str, str, str, str, str]:
    return (
        manifest.source_build_sha256,
        manifest.contract_canonical_sha256,
        manifest.contract_file_sha256,
        manifest.contract_selection_sha256,
        manifest.pipeline_fingerprint,
        manifest.identity_context_sha256,
    )


def _rank(
    *,
    seed_authority: SelectionSeedAuthority,
    capture: SettlementCaptureManifest,
    target_kind: ShadowBatchTargetKind,
    item: ShadowBatchItem,
) -> str:
    return hmac.new(
        seed_authority.seed,
        (
            "dahe:loop9:formal-selection-rank:v1\0"
            f"{SELECTION_POLICY}\0"
            f"{capture.canonical_sha256}\0"
            f"{target_kind.value}\0"
            f"{item.item_identity_sha256}"
        ).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _has_near_duplicate(
    *,
    item_fingerprints: Sequence[ImagePerceptualFingerprint],
    inventory: Sequence[ImagePerceptualFingerprint],
) -> bool:
    if not inventory:
        return False
    try:
        return any(
            find_near_duplicate_candidates(
                probe=fingerprint,
                inventory=inventory,
            )
            for fingerprint in item_fingerprints
        )
    except ImageSimilarityContractError as exc:
        raise FormalShadowSelectionContractError(
            "perceptual exclusion evidence is invalid"
        ) from exc


def select_formal_shadow_batch(
    *,
    capture: SettlementCaptureManifest,
    target_kind: ShadowBatchTargetKind,
    pipeline_fingerprint: str,
    seed_authority: SelectionSeedAuthority,
    exclusion_snapshot: FormalSelectionExclusionSnapshot,
    prior_selections: Sequence[FormalShadowSelectionManifest],
    locked_gate_evidence_sha256: str | None = None,
) -> FormalShadowSelectionManifest:
    """Select exact 50/30 rows by a stable authority, never a caller list."""

    if not isinstance(capture, SettlementCaptureManifest):
        raise FormalShadowSelectionContractError(
            "sealed settlement capture is required"
        )
    capture.verify_integrity()
    if (
        capture.schema_version != SETTLEMENT_CAPTURE_SCHEMA_VERSION
        or capture.request_audit_sha256 is None
        or capture.request_audit_counts is None
    ):
        raise FormalShadowSelectionContractError(
            "formal selection requires an audited settlement capture"
        )
    if not isinstance(target_kind, ShadowBatchTargetKind):
        raise FormalShadowSelectionContractError(
            "formal selection target kind is invalid"
        )
    source_scopes = {source.scope for source in capture.sources}
    if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        historical_sources = tuple(
            sorted(capture.sources, key=lambda source: source.page_number)
        )
        historical_source_valid = (
            source_scopes == {HISTORICAL_SETTLED_SCOPE}
            and 1 <= len(historical_sources)
            <= HISTORICAL_CAPTURE_MAX_PAGES
            and tuple(
                source.page_number for source in historical_sources
            )
            == tuple(range(1, len(historical_sources) + 1))
            and all(
                source.page_size == HISTORICAL_CAPTURE_PAGE_SIZE
                for source in historical_sources
            )
            and 1 <= len(capture.items)
            <= HISTORICAL_CAPTURE_MAX_ITEMS
            and (
                len(historical_sources) == 1
                or len(capture.items) > HISTORICAL_CAPTURE_PAGE_SIZE
            )
        )
        current_source_valid = (
            source_scopes == {CURRENT_PENDING_SETTLEMENT_SCOPE}
            and bool(capture.sources)
            and all(
                source.page_size == 50
                for source in capture.sources
            )
        )
        if not historical_source_valid and not current_source_valid:
            raise FormalShadowSelectionContractError(
                "locked selection source is not an approved bounded source"
            )
        if locked_gate_evidence_sha256 is not None:
            raise FormalShadowSelectionContractError(
                "locked selection must not bind a locked gate"
            )
    elif (
        source_scopes != {CURRENT_PENDING_SETTLEMENT_SCOPE}
        or any(source.page_size != 50 for source in capture.sources)
    ):
        raise FormalShadowSelectionContractError(
            "real shadow selection source is not current pending settlement"
        )
    elif locked_gate_evidence_sha256 is None:
        raise FormalShadowSelectionContractError(
            "real shadow selection requires locked gate evidence"
        )
    else:
        _required_sha256(
            locked_gate_evidence_sha256,
            label="locked gate evidence SHA-256",
        )
    _required_sha256(
        pipeline_fingerprint,
        label="pipeline fingerprint",
    )
    if not isinstance(seed_authority, SelectionSeedAuthority):
        raise FormalShadowSelectionContractError(
            "selection seed authority is invalid"
        )
    if not isinstance(
        exclusion_snapshot,
        FormalSelectionExclusionSnapshot,
    ):
        raise FormalShadowSelectionContractError(
            "verified full-history exclusion snapshot is required"
        )
    if (
        exclusion_snapshot.identity_context_sha256
        != capture.identity_context_sha256
        or exclusion_snapshot.expected_current_build_sha256
        != capture.source_build_sha256
        or exclusion_snapshot.expected_settlement_contract_sha256
        != capture.contract_canonical_sha256
        or exclusion_snapshot.expected_settlement_selection_sha256
        != capture.contract_selection_sha256
    ):
        raise FormalShadowSelectionContractError(
            "full-history exclusion authority does not match the capture"
        )
    capture_scope = discovery_scope_exclusion_token(
        source_job_id=capture.source_job_id,
        source_snapshot_sha256=capture.canonical_sha256,
    )
    if capture_scope in set(
        exclusion_snapshot.excluded_scope_exclusion_tokens
    ):
        raise FormalShadowSelectionContractError(
            "sealed capture overlaps an excluded discovery scope"
        )
    if (
        not isinstance(prior_selections, Sequence)
        or isinstance(prior_selections, (str, bytes))
        or any(
            not isinstance(value, FormalShadowSelectionManifest)
            for value in prior_selections
        )
    ):
        raise FormalShadowSelectionContractError(
            "prior selection authority is invalid"
        )

    prior = tuple(prior_selections)
    if len({value.canonical_sha256 for value in prior}) != len(prior):
        raise FormalShadowSelectionContractError(
            "prior selection authority contains duplicates"
        )
    if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        if any(
            value.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50
            for value in prior
        ):
            raise FormalShadowSelectionContractError(
                "locked selection authority already exists"
            )
    else:
        locked = tuple(
            value
            for value in prior
            if value.target_kind
            is ShadowBatchTargetKind.CURRENT_LOCKED_50
        )
        if len(locked) != 1:
            raise FormalShadowSelectionContractError(
                "real shadow selection requires one locked selection authority"
            )

    expected_authority = (
        capture.source_build_sha256,
        capture.contract_canonical_sha256,
        capture.contract_file_sha256,
        capture.contract_selection_sha256,
        pipeline_fingerprint,
        capture.identity_context_sha256,
    )
    excluded_item_ids: set[str] = set()
    excluded_image_sha256s = set(
        exclusion_snapshot.excluded_image_sha256s
    )
    excluded_platform_identity_sha256s = set(
        exclusion_snapshot.excluded_platform_identity_sha256s
    )
    excluded_fingerprints = {
        fingerprint.content_sha256: fingerprint
        for fingerprint in (
            exclusion_snapshot.excluded_perceptual_fingerprints
        )
    }
    for value in prior:
        value.verify_integrity()
        if (
            _selection_authority(value.batch_manifest)
            != expected_authority
            or value.selection_seed_authority_sha256
            != seed_authority.authority_sha256
        ):
            raise FormalShadowSelectionContractError(
                "prior selection authority does not match the capture"
            )
        item_ids = {
            item.item_identity_sha256
            for item in value.batch_manifest.items
        }
        if excluded_item_ids.intersection(item_ids):
            raise FormalShadowSelectionContractError(
                "prior formal selections overlap"
            )
        excluded_item_ids.update(item_ids)
        for item in value.batch_manifest.items:
            excluded_platform_identity_sha256s.add(
                item.platform_waybill_id_digest
            )
            for image in item.images:
                excluded_image_sha256s.add(image.sha256)
                existing_fingerprint = excluded_fingerprints.get(
                    image.sha256
                )
                if (
                    existing_fingerprint is not None
                    and existing_fingerprint.to_record()
                    != image.perceptual_fingerprint.to_record()
                ):
                    raise FormalShadowSelectionContractError(
                        "prior selection contains conflicting perceptual "
                        "evidence"
                    )
                excluded_fingerprints[image.sha256] = (
                    image.perceptual_fingerprint
                )

    excluded_fingerprint_inventory = tuple(
        excluded_fingerprints[key]
        for key in sorted(excluded_fingerprints)
    )
    ranked = sorted(
        (
            (
                _rank(
                    seed_authority=seed_authority,
                    capture=capture,
                    target_kind=target_kind,
                    item=item,
                ),
                item.item_identity_sha256,
                item,
            )
            for item in capture.items
            if item.item_identity_sha256 not in excluded_item_ids
        ),
        key=lambda value: (value[0], value[1]),
    )
    required = target_kind.expected_count
    if required is None:
        raise FormalShadowSelectionContractError(
            "operational captures cannot enter formal selection"
        )
    selected_items: list[ShadowBatchItem] = []
    selected_image_sha256s: set[str] = set()
    selected_fingerprints: list[ImagePerceptualFingerprint] = []
    rank_evidence: list[dict[str, object]] = []
    eligible_count = 0
    for rank_sha, item_identity, item in ranked:
        image_sha256s = tuple(image.sha256 for image in item.images)
        fingerprints = tuple(
            image.perceptual_fingerprint for image in item.images
        )
        blocked_reason: str | None = None
        if item.platform_waybill_id_digest in (
            excluded_platform_identity_sha256s
        ):
            blocked_reason = "excluded_platform_identity"
        elif len(set(image_sha256s)) != len(image_sha256s):
            blocked_reason = "duplicate_image_within_waybill"
        elif excluded_image_sha256s.intersection(image_sha256s):
            blocked_reason = "excluded_exact_image"
        elif selected_image_sha256s.intersection(image_sha256s):
            blocked_reason = "duplicate_image_in_selection"
        elif _has_near_duplicate(
            item_fingerprints=fingerprints,
            inventory=excluded_fingerprint_inventory,
        ):
            blocked_reason = "excluded_perceptual_image"
        elif any(
            _has_near_duplicate(
                item_fingerprints=(fingerprint,),
                inventory=(*fingerprints[:index], *fingerprints[index + 1 :]),
            )
            for index, fingerprint in enumerate(fingerprints)
        ):
            blocked_reason = "perceptual_duplicate_within_waybill"
        elif _has_near_duplicate(
            item_fingerprints=fingerprints,
            inventory=selected_fingerprints,
        ):
            blocked_reason = "perceptual_duplicate_in_selection"
        if blocked_reason is None:
            eligible_count += 1
        accepted = blocked_reason is None and len(selected_items) < required
        rank_evidence.append(
            {
                "accepted": accepted,
                "blocked_reason": blocked_reason,
                "item_identity_sha256": item_identity,
                "rank_sha256": rank_sha,
            }
        )
        if not accepted:
            continue
        selected_items.append(item)
        selected_image_sha256s.update(image_sha256s)
        selected_fingerprints.extend(fingerprints)
    if len(selected_items) < required:
        raise FormalShadowSelectionContractError(
            "sealed capture has insufficient eligible waybills"
        )
    if (
        target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50
        and source_scopes == {CURRENT_PENDING_SETTLEMENT_SCOPE}
        and eligible_count < 80
    ):
        raise FormalShadowSelectionContractError(
            "current locked selection does not preserve the 30-waybill reserve"
        )
    selected = tuple(selected_items)
    rank_commitment = _canonical_sha256(rank_evidence)
    batch = ChengfengShadowBatchManifest(
        target_kind=target_kind,
        source_build_sha256=capture.source_build_sha256,
        contract_canonical_sha256=capture.contract_canonical_sha256,
        contract_file_sha256=capture.contract_file_sha256,
        contract_selection_sha256=(
            capture.contract_selection_sha256
        ),
        pipeline_fingerprint=pipeline_fingerprint,
        identity_context_sha256=capture.identity_context_sha256,
        sources=capture.sources,
        items=selected,
        source_capture_sha256=capture.canonical_sha256,
        request_audit_sha256=capture.request_audit_sha256,
        request_audit_counts=capture.request_audit_counts,
        schema_version=SHADOW_BATCH_SCHEMA_VERSION,
    )
    result = FormalShadowSelectionManifest(
        target_kind=target_kind,
        source_capture_sha256=capture.canonical_sha256,
        full_history_exclusion_authority_sha256=(
            exclusion_snapshot.authority_sha256
        ),
        exclusion_child_index_head_sha256=(
            exclusion_snapshot.child_index_head_sha256
        ),
        exclusion_source_boundary_sha256=(
            exclusion_snapshot.source_boundary_sha256
        ),
        exclusion_source_inventory_high_watermark=(
            exclusion_snapshot.source_inventory_high_watermark
        ),
        selection_seed_authority_sha256=(
            seed_authority.authority_sha256
        ),
        rank_commitment_sha256=rank_commitment,
        prior_selection_sha256s=tuple(
            value.canonical_sha256 for value in prior
        ),
        batch_manifest=batch,
        locked_gate_evidence_sha256=locked_gate_evidence_sha256,
    )
    result.verify_integrity()
    return result
