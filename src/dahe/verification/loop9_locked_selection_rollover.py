from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe.application.chengfeng.shadow_batch import ShadowBatchTargetKind
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionContractError,
    FormalShadowSelectionManifest,
)
from dahe.verification.loop9_dataset_isolation import (
    ExclusionKind,
    Loop9DatasetExclusionInventory,
    Loop9DatasetIsolationError,
)
from dahe.verification.loop9_human_review import (
    Loop9HumanReviewError,
    Loop9ReviewPackage,
    _parse_reviews,
)

SCHEMA_VERSION = 1
FAILURE_REASON = "natural_coverage_incomplete"
REQUIRED_CONDITIONS = (
    "blur",
    "crop",
    "glare",
    "printed",
    "rotation_0",
    "rotation_90",
    "rotation_180",
    "rotation_270",
    "screen",
    "unknown_layout",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 20 * 1024 * 1024
_STORE_RELATIVE = (
    Path("verification") / "loop9-locked-selection-failures"
)


class Loop9LockedSelectionRolloverError(ValueError):
    """Raised when a failed locked selection cannot be retired safely."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9LockedSelectionRolloverError(
                "failure attestation contains duplicate fields"
            )
        result[key] = value
    return result


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9LockedSelectionRolloverError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise Loop9LockedSelectionRolloverError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
    ):
        raise Loop9LockedSelectionRolloverError(f"{label} must be an array")
    return value


def _normalize_coverage(
    value: object,
) -> dict[str, tuple[str, ...]]:
    raw = _mapping(value, label="locked selection quality coverage")
    if set(raw) != set(REQUIRED_CONDITIONS):
        raise Loop9LockedSelectionRolloverError(
            "locked selection quality coverage contract is invalid"
        )
    normalized: dict[str, tuple[str, ...]] = {}
    for condition in REQUIRED_CONDITIONS:
        hashes = tuple(
            _required_sha256(
                item,
                label=f"{condition} coverage image",
            )
            for item in _sequence(
                raw[condition],
                label=f"{condition} coverage images",
            )
        )
        if len(hashes) != len(set(hashes)):
            raise Loop9LockedSelectionRolloverError(
                "locked selection quality coverage contains duplicates"
            )
        normalized[condition] = tuple(sorted(hashes))
    return normalized


def _normalized_review_payloads(
    value: object,
) -> tuple[dict[str, object], ...]:
    reviews = tuple(
        _mapping(item, label="failed locked selection review")
        for item in _sequence(
            value,
            label="failed locked selection reviews",
        )
    )
    if len(reviews) != 50:
        raise Loop9LockedSelectionRolloverError(
            "failed locked selection requires exactly 50 reviews"
        )
    identities: set[str] = set()
    image_sha256s: set[str] = set()
    normalized: list[dict[str, object]] = []
    for review in reviews:
        if set(review) != {
            "item_identity_sha256",
            "confirmed_at",
            "images",
            "pair_condition",
            "confirmation",
        }:
            raise Loop9LockedSelectionRolloverError(
                "failed locked selection review contract is invalid"
            )
        identity = _required_sha256(
            review["item_identity_sha256"],
            label="failed locked selection item identity",
        )
        if identity in identities:
            raise Loop9LockedSelectionRolloverError(
                "failed locked selection contains duplicate reviews"
            )
        identities.add(identity)
        images = tuple(
            _mapping(image, label="failed locked selection review image")
            for image in _sequence(
                review["images"],
                label="failed locked selection review images",
            )
        )
        if len(images) != 2:
            raise Loop9LockedSelectionRolloverError(
                "failed locked selection review requires two images"
            )
        for image in images:
            digest = _required_sha256(
                image.get("image_sha256"),
                label="failed locked selection review image",
            )
            if digest in image_sha256s:
                raise Loop9LockedSelectionRolloverError(
                    "failed locked selection contains duplicate images"
                )
            image_sha256s.add(digest)
        normalized.append(json.loads(_canonical_json(review)))
    if len(image_sha256s) != 100:
        raise Loop9LockedSelectionRolloverError(
            "failed locked selection requires exactly 100 image truths"
        )
    return tuple(
        sorted(
            normalized,
            key=lambda review: cast(
                str,
                review["item_identity_sha256"],
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class LockedSelectionCoverageFailureAttestation:
    """Immutable proof that a reviewed 50-item set failed natural coverage."""

    selection_sha256: str
    source_batch_sha256: str
    package_sha256: str
    review_answers_sha256: str
    review_count: int
    image_truth_count: int
    source_build_sha256: str
    contract_canonical_sha256: str
    contract_selection_sha256: str
    pipeline_fingerprint: str
    identity_context_sha256: str
    selection_exclusion_authority_sha256: str
    selection_exclusion_child_head_sha256: str
    coverage: Mapping[str, Sequence[str]]
    missing_conditions: tuple[str, ...]
    reviews: tuple[dict[str, object], ...]
    gate_passed: bool = False
    failure_reason: str = FAILURE_REASON
    schema_version: int = SCHEMA_VERSION
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for label, value in (
            ("selection SHA-256", self.selection_sha256),
            ("source batch SHA-256", self.source_batch_sha256),
            ("review package SHA-256", self.package_sha256),
            ("review answers SHA-256", self.review_answers_sha256),
            ("source build SHA-256", self.source_build_sha256),
            ("contract canonical SHA-256", self.contract_canonical_sha256),
            ("contract selection SHA-256", self.contract_selection_sha256),
            ("pipeline fingerprint", self.pipeline_fingerprint),
            ("identity context SHA-256", self.identity_context_sha256),
            (
                "selection exclusion authority SHA-256",
                self.selection_exclusion_authority_sha256,
            ),
            (
                "selection exclusion child head SHA-256",
                self.selection_exclusion_child_head_sha256,
            ),
        ):
            _required_sha256(value, label=label)
        if (
            self.schema_version != SCHEMA_VERSION
            or self.gate_passed is not False
            or self.failure_reason != FAILURE_REASON
            or self.review_count != 50
            or self.image_truth_count != 100
        ):
            raise Loop9LockedSelectionRolloverError(
                "locked selection coverage failure attestation is invalid"
            )
        coverage = _normalize_coverage(dict(self.coverage))
        reviews = _normalized_review_payloads(self.reviews)
        review_images = {
            cast(str, image["image_sha256"])
            for review in reviews
            for image in cast(list[dict[str, object]], review["images"])
        }
        if any(
            not set(image_sha256s).issubset(review_images)
            for image_sha256s in coverage.values()
        ):
            raise Loop9LockedSelectionRolloverError(
                "coverage references an image outside the failed selection"
            )
        missing = tuple(
            condition
            for condition in REQUIRED_CONDITIONS
            if not coverage[condition]
        )
        if (
            not missing
            or tuple(self.missing_conditions) != missing
            or len(set(self.missing_conditions))
            != len(self.missing_conditions)
        ):
            raise Loop9LockedSelectionRolloverError(
                "locked selection missing conditions are invalid"
            )
        object.__setattr__(self, "coverage", coverage)
        object.__setattr__(self, "reviews", reviews)
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "contract_canonical_sha256": self.contract_canonical_sha256,
            "contract_selection_sha256": self.contract_selection_sha256,
            "coverage": {
                condition: list(self.coverage[condition])
                for condition in REQUIRED_CONDITIONS
            },
            "failure_reason": self.failure_reason,
            "gate_passed": self.gate_passed,
            "identity_context_sha256": self.identity_context_sha256,
            "image_truth_count": self.image_truth_count,
            "missing_conditions": list(self.missing_conditions),
            "package_sha256": self.package_sha256,
            "pipeline_fingerprint": self.pipeline_fingerprint,
            "review_answers_sha256": self.review_answers_sha256,
            "review_count": self.review_count,
            "reviews": list(self.reviews),
            "schema_version": self.schema_version,
            "selection_exclusion_authority_sha256": (
                self.selection_exclusion_authority_sha256
            ),
            "selection_exclusion_child_head_sha256": (
                self.selection_exclusion_child_head_sha256
            ),
            "selection_sha256": self.selection_sha256,
            "source_batch_sha256": self.source_batch_sha256,
            "source_build_sha256": self.source_build_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise Loop9LockedSelectionRolloverError(
                "locked selection coverage failure attestation integrity is invalid"
            )

    def verify_selection(
        self,
        selection: FormalShadowSelectionManifest,
    ) -> None:
        try:
            selection.verify_integrity()
        except FormalShadowSelectionContractError as exc:
            raise Loop9LockedSelectionRolloverError(
                "failed locked selection integrity is invalid"
            ) from exc
        batch = selection.batch_manifest
        if (
            selection.target_kind
            is not ShadowBatchTargetKind.CURRENT_LOCKED_50
            or self.selection_sha256 != selection.canonical_sha256
            or self.source_batch_sha256 != batch.canonical_sha256
            or self.source_build_sha256 != batch.source_build_sha256
            or self.contract_canonical_sha256
            != batch.contract_canonical_sha256
            or self.contract_selection_sha256
            != batch.contract_selection_sha256
            or self.pipeline_fingerprint != batch.pipeline_fingerprint
            or self.identity_context_sha256
            != batch.identity_context_sha256
            or self.selection_exclusion_authority_sha256
            != selection.full_history_exclusion_authority_sha256
            or self.selection_exclusion_child_head_sha256
            != selection.exclusion_child_index_head_sha256
        ):
            raise Loop9LockedSelectionRolloverError(
                "coverage failure attestation belongs to another selection"
            )
        review_identities = {
            cast(str, review["item_identity_sha256"])
            for review in self.reviews
        }
        review_images = {
            cast(str, image["image_sha256"])
            for review in self.reviews
            for image in cast(list[dict[str, object]], review["images"])
        }
        if (
            review_identities
            != {
                item.item_identity_sha256
                for item in batch.items
            }
            or review_images
            != {
                image.sha256
                for item in batch.items
                for image in item.images
            }
        ):
            raise Loop9LockedSelectionRolloverError(
                "coverage failure reviews belong to another selection"
            )

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> LockedSelectionCoverageFailureAttestation:
        raw = _mapping(
            value,
            label="locked selection coverage failure attestation",
        )
        expected = {
            "canonical_sha256",
            "contract_canonical_sha256",
            "contract_selection_sha256",
            "coverage",
            "failure_reason",
            "gate_passed",
            "identity_context_sha256",
            "image_truth_count",
            "missing_conditions",
            "package_sha256",
            "pipeline_fingerprint",
            "review_answers_sha256",
            "review_count",
            "reviews",
            "schema_version",
            "selection_exclusion_authority_sha256",
            "selection_exclusion_child_head_sha256",
            "selection_sha256",
            "source_batch_sha256",
            "source_build_sha256",
        }
        if set(raw) != expected:
            raise Loop9LockedSelectionRolloverError(
                "locked selection coverage failure attestation contract is invalid"
            )
        try:
            attestation = cls(
                selection_sha256=cast(str, raw["selection_sha256"]),
                source_batch_sha256=cast(str, raw["source_batch_sha256"]),
                package_sha256=cast(str, raw["package_sha256"]),
                review_answers_sha256=cast(
                    str,
                    raw["review_answers_sha256"],
                ),
                review_count=cast(int, raw["review_count"]),
                image_truth_count=cast(int, raw["image_truth_count"]),
                source_build_sha256=cast(str, raw["source_build_sha256"]),
                contract_canonical_sha256=cast(
                    str,
                    raw["contract_canonical_sha256"],
                ),
                contract_selection_sha256=cast(
                    str,
                    raw["contract_selection_sha256"],
                ),
                pipeline_fingerprint=cast(
                    str,
                    raw["pipeline_fingerprint"],
                ),
                identity_context_sha256=cast(
                    str,
                    raw["identity_context_sha256"],
                ),
                selection_exclusion_authority_sha256=cast(
                    str,
                    raw["selection_exclusion_authority_sha256"],
                ),
                selection_exclusion_child_head_sha256=cast(
                    str,
                    raw["selection_exclusion_child_head_sha256"],
                ),
                coverage=cast(Mapping[str, Sequence[str]], raw["coverage"]),
                missing_conditions=tuple(
                    cast(Sequence[str], raw["missing_conditions"])
                ),
                reviews=tuple(
                    cast(Sequence[dict[str, object]], raw["reviews"])
                ),
                gate_passed=cast(bool, raw["gate_passed"]),
                failure_reason=cast(str, raw["failure_reason"]),
                schema_version=cast(int, raw["schema_version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, Loop9LockedSelectionRolloverError):
                raise
            raise Loop9LockedSelectionRolloverError(
                "locked selection coverage failure attestation contract is invalid"
            ) from exc
        if raw["canonical_sha256"] != attestation.canonical_sha256:
            raise Loop9LockedSelectionRolloverError(
                "locked selection coverage failure attestation integrity is invalid"
            )
        return attestation


def _coverage_from_reviews(
    reviews: Sequence[Mapping[str, object]],
) -> dict[str, tuple[str, ...]]:
    coverage: dict[str, list[str]] = {
        condition: [] for condition in REQUIRED_CONDITIONS
    }
    for review in reviews:
        for image in cast(Sequence[Mapping[str, object]], review["images"]):
            digest = cast(str, image["image_sha256"])
            for condition in cast(
                Sequence[str],
                image["quality_conditions"],
            ):
                if condition in coverage:
                    coverage[condition].append(digest)
    return {
        condition: tuple(sorted(hashes))
        for condition, hashes in coverage.items()
    }


def build_locked_selection_coverage_failure_attestation(
    *,
    selection: FormalShadowSelectionManifest,
    package: Loop9ReviewPackage,
    review_answers: object,
) -> LockedSelectionCoverageFailureAttestation:
    """Bind one complete reviewed 50 that failed the natural coverage gate."""

    try:
        selection.verify_integrity()
    except FormalShadowSelectionContractError as exc:
        raise Loop9LockedSelectionRolloverError(
            "locked selection integrity is invalid"
        ) from exc
    if (
        selection.target_kind
        is not ShadowBatchTargetKind.CURRENT_LOCKED_50
        or package.source_batch.target_kind
        is not ShadowBatchTargetKind.CURRENT_LOCKED_50
        or package.source_batch.canonical_sha256
        != selection.batch_manifest.canonical_sha256
        or package.formal_selection.canonical_sha256
        != selection.canonical_sha256
        or package.payload.get("kind") != "loop9_human_review_package"
        or package.payload.get("review_kind") != "current_locked_50"
        or package.payload.get("item_count") != 50
        or package.payload.get("image_count") != 100
    ):
        raise Loop9LockedSelectionRolloverError(
            "locked selection and review package do not match"
        )
    try:
        review_answers_sha256, reviews = _parse_reviews(
            package=package,
            value=review_answers,
        )
    except Loop9HumanReviewError as exc:
        raise Loop9LockedSelectionRolloverError(
            "locked selection review answers are invalid"
        ) from exc
    coverage = _coverage_from_reviews(reviews)
    missing = tuple(
        condition
        for condition in REQUIRED_CONDITIONS
        if not coverage[condition]
    )
    if not missing:
        raise Loop9LockedSelectionRolloverError(
            "locked selection quality coverage already passed"
        )
    batch = selection.batch_manifest
    attestation = LockedSelectionCoverageFailureAttestation(
        selection_sha256=selection.canonical_sha256,
        source_batch_sha256=batch.canonical_sha256,
        package_sha256=_required_sha256(
            package.payload.get("canonical_sha256"),
            label="review package SHA-256",
        ),
        review_answers_sha256=review_answers_sha256,
        review_count=len(reviews),
        image_truth_count=sum(
            len(cast(Sequence[object], review["images"]))
            for review in reviews
        ),
        source_build_sha256=batch.source_build_sha256,
        contract_canonical_sha256=batch.contract_canonical_sha256,
        contract_selection_sha256=batch.contract_selection_sha256,
        pipeline_fingerprint=batch.pipeline_fingerprint,
        identity_context_sha256=batch.identity_context_sha256,
        selection_exclusion_authority_sha256=(
            selection.full_history_exclusion_authority_sha256
        ),
        selection_exclusion_child_head_sha256=(
            selection.exclusion_child_index_head_sha256
        ),
        coverage=coverage,
        missing_conditions=missing,
        reviews=tuple(reviews),
    )
    attestation.verify_selection(selection)
    return attestation


def development_inventory_from_failed_locked_selection(
    *,
    selection: FormalShadowSelectionManifest,
    failure_attestation: LockedSelectionCoverageFailureAttestation,
) -> Loop9DatasetExclusionInventory:
    """Create the exact development exclusion inventory for the failed 50."""

    failure_attestation.verify_integrity()
    failure_attestation.verify_selection(selection)
    batch = selection.batch_manifest
    inventory = Loop9DatasetExclusionInventory(
        inventory_id=(
            f"loop9-failed-locked-{selection.canonical_sha256[:16]}"
        ),
        exclusion_kind=ExclusionKind.DEVELOPMENT,
        platform_identity_sha256s=tuple(
            sorted(
                item.platform_waybill_id_digest
                for item in batch.items
            )
        ),
        image_sha256s=tuple(
            sorted(
                image.sha256
                for item in batch.items
                for image in item.images
            )
        ),
        scope_exclusion_tokens=(),
        perceptual_fingerprints=tuple(
            sorted(
                (
                    image.perceptual_fingerprint
                    for item in batch.items
                    for image in item.images
                ),
                key=lambda fingerprint: fingerprint.content_sha256,
            )
        ),
        identity_context_sha256=batch.identity_context_sha256,
    )
    try:
        inventory.verify_integrity()
    except Loop9DatasetIsolationError as exc:
        raise Loop9LockedSelectionRolloverError(
            "failed locked selection exclusion inventory is invalid"
        ) from exc
    return inventory


def persist_locked_selection_failure_attestation(
    *,
    data_root: Path,
    attestation: LockedSelectionCoverageFailureAttestation,
) -> Path:
    """Persist one content-addressed failure attestation without overwriting."""

    if not isinstance(data_root, Path) or not data_root.is_absolute():
        raise Loop9LockedSelectionRolloverError(
            "failure attestation data root must be absolute"
        )
    root = data_root.resolve()
    if root != data_root or data_root.is_symlink() or not root.is_dir():
        raise Loop9LockedSelectionRolloverError(
            "failure attestation data root is unsafe"
        )
    attestation.verify_integrity()
    store = root / _STORE_RELATIVE
    try:
        store.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise Loop9LockedSelectionRolloverError(
            "failure attestation store is unavailable"
        ) from exc
    if store.is_symlink() or store.resolve() != store:
        raise Loop9LockedSelectionRolloverError(
            "failure attestation store is unsafe"
        )
    target = store / f"{attestation.canonical_sha256}.json"
    content = (
        json.dumps(
            attestation.to_payload(),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if target.exists():
        if (
            not target.is_file()
            or target.is_symlink()
            or target.read_bytes() != content
        ):
            raise Loop9LockedSelectionRolloverError(
                "failure attestation already exists with different content"
            )
        return target
    staging = store / f".{target.name}.{uuid4().hex}.tmp"
    try:
        with staging.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staging, target)
        except FileExistsError:
            if target.read_bytes() != content:
                raise Loop9LockedSelectionRolloverError(
                    "failure attestation already exists with different content"
                ) from None
        except OSError as exc:
            raise Loop9LockedSelectionRolloverError(
                "failure attestation could not be published atomically"
            ) from exc
    finally:
        staging.unlink(missing_ok=True)
    return target


def load_locked_selection_failure_attestation(
    path: Path,
) -> LockedSelectionCoverageFailureAttestation:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise Loop9LockedSelectionRolloverError(
            "failure attestation path is unsafe"
        )
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
    except OSError as exc:
        raise Loop9LockedSelectionRolloverError(
            "failure attestation is unavailable"
        ) from exc
    if not content or len(content) > _MAX_JSON_BYTES:
        raise Loop9LockedSelectionRolloverError(
            "failure attestation file is invalid"
        )
    try:
        payload = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except Loop9LockedSelectionRolloverError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9LockedSelectionRolloverError(
            "failure attestation file is invalid"
        ) from exc
    attestation = LockedSelectionCoverageFailureAttestation.from_payload(
        payload
    )
    expected_content = (
        json.dumps(
            attestation.to_payload(),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if (
        content != expected_content
        or path.name != f"{attestation.canonical_sha256}.json"
    ):
        raise Loop9LockedSelectionRolloverError(
            "failure attestation path identity is invalid"
        )
    return attestation
