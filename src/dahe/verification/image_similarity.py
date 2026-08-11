from __future__ import annotations

import hashlib
import json
import re
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from io import BytesIO
from typing import cast

from PIL import Image, ImageOps, UnidentifiedImageError

SCHEMA_VERSION = 1
ALGORITHM_VERSION = "dahe.ticket-image-similarity.v1"
DEFAULT_MAX_PIXELS = 40_000_000

_HASH_SIDE = 16
_HASH_HEX_LENGTH = (_HASH_SIDE * _HASH_SIDE) // 4
_DISTANCE_DENOMINATOR = _HASH_SIDE * _HASH_SIDE * 2
_DISTANCE_LIMIT = 80
_CENTER_CROP_PERMILLE = (1000, 920, 840, 760)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ImageSimilarityContractError(ValueError):
    """Raised when near-duplicate evidence cannot safely authorize a gate."""


class ReviewOutcome(StrEnum):
    DUPLICATE = "duplicate"
    DISTINCT = "distinct"


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _required_text(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ImageSimilarityContractError(f"{label} is required")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ImageSimilarityContractError(f"{label} is too long")
    return normalized


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ImageSimilarityContractError(f"{label} must be a lowercase SHA-256")
    return value


def _timezone_aware_time(value: object) -> str:
    raw = _required_text(value, label="decision time", maximum=80)
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ImageSimilarityContractError("decision time must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ImageSimilarityContractError("decision time must include a timezone")
    return parsed.isoformat(timespec="seconds")


def _bits_to_hex(bits: Sequence[bool]) -> str:
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return f"{value:0{len(bits) // 4}x}"


def _hamming_distance(first: str, second: str) -> int:
    return (int(first, 16) ^ int(second, 16)).bit_count()


@dataclass(frozen=True, slots=True)
class PerceptualViewHash:
    crop_permille: int
    average_hash: str
    difference_hash: str

    def __post_init__(self) -> None:
        if self.crop_permille not in _CENTER_CROP_PERMILLE:
            raise ImageSimilarityContractError("fingerprint crop scale is unsupported")
        for label, value in (
            ("average hash", self.average_hash),
            ("difference hash", self.difference_hash),
        ):
            if (
                not isinstance(value, str)
                or len(value) != _HASH_HEX_LENGTH
                or re.fullmatch(r"[0-9a-f]+", value) is None
            ):
                raise ImageSimilarityContractError(f"{label} is invalid")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "average_hash": self.average_hash,
            "crop_permille": self.crop_permille,
            "difference_hash": self.difference_hash,
        }


@dataclass(frozen=True, slots=True)
class ImagePerceptualFingerprint:
    algorithm_version: str
    content_sha256: str
    width: int
    height: int
    view_hashes: tuple[PerceptualViewHash, ...]
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.algorithm_version != ALGORITHM_VERSION:
            raise ImageSimilarityContractError("fingerprint algorithm version is unsupported")
        _required_sha256(self.content_sha256, label="image content hash")
        if (
            isinstance(self.width, bool)
            or isinstance(self.height, bool)
            or self.width < 1
            or self.height < 1
        ):
            raise ImageSimilarityContractError("fingerprint image dimensions are invalid")
        if tuple(view.crop_permille for view in self.view_hashes) != _CENTER_CROP_PERMILLE:
            raise ImageSimilarityContractError("fingerprint view set is incomplete")
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "algorithm_version": self.algorithm_version,
            "content_sha256": self.content_sha256,
            "height": self.height,
            "schema_version": SCHEMA_VERSION,
            "view_hashes": [view.canonical_payload() for view in self.view_hashes],
            "width": self.width,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise ImageSimilarityContractError("fingerprint integrity check failed")

    def to_record(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    @classmethod
    def from_record(
        cls,
        raw: Mapping[str, object],
    ) -> ImagePerceptualFingerprint:
        expected_keys = {
            "algorithm_version",
            "canonical_sha256",
            "content_sha256",
            "height",
            "schema_version",
            "view_hashes",
            "width",
        }
        if set(raw) != expected_keys or raw.get("schema_version") != SCHEMA_VERSION:
            raise ImageSimilarityContractError("fingerprint record contract is invalid")
        raw_views = raw.get("view_hashes")
        if not isinstance(raw_views, list):
            raise ImageSimilarityContractError("fingerprint record views are invalid")
        views: list[PerceptualViewHash] = []
        view_keys = {"average_hash", "crop_permille", "difference_hash"}
        for raw_view in raw_views:
            if not isinstance(raw_view, dict) or set(raw_view) != view_keys:
                raise ImageSimilarityContractError("fingerprint record view is invalid")
            crop_permille = raw_view.get("crop_permille")
            average_hash = raw_view.get("average_hash")
            difference_hash = raw_view.get("difference_hash")
            if (
                isinstance(crop_permille, bool)
                or not isinstance(crop_permille, int)
                or not isinstance(average_hash, str)
                or not isinstance(difference_hash, str)
            ):
                raise ImageSimilarityContractError("fingerprint record view is invalid")
            views.append(
                PerceptualViewHash(
                    crop_permille=crop_permille,
                    average_hash=average_hash,
                    difference_hash=difference_hash,
                )
            )
        algorithm_version = raw.get("algorithm_version")
        content_sha256 = raw.get("content_sha256")
        width = raw.get("width")
        height = raw.get("height")
        if (
            not isinstance(algorithm_version, str)
            or not isinstance(content_sha256, str)
            or isinstance(width, bool)
            or not isinstance(width, int)
            or isinstance(height, bool)
            or not isinstance(height, int)
        ):
            raise ImageSimilarityContractError("fingerprint record fields are invalid")
        fingerprint = cls(
            algorithm_version=algorithm_version,
            content_sha256=content_sha256,
            width=width,
            height=height,
            view_hashes=tuple(views),
        )
        stored_sha256 = _required_sha256(
            raw.get("canonical_sha256"),
            label="fingerprint integrity hash",
        )
        if fingerprint.canonical_sha256 != stored_sha256:
            raise ImageSimilarityContractError("fingerprint integrity check failed")
        return fingerprint


def _center_crop(image: Image.Image, crop_permille: int) -> Image.Image:
    width, height = image.size
    crop_width = max(1, (width * crop_permille) // 1000)
    crop_height = max(1, (height * crop_permille) // 1000)
    left = (width - crop_width) // 2
    top = (height - crop_height) // 2
    return image.crop((left, top, left + crop_width, top + crop_height))


def _average_hash(image: Image.Image) -> str:
    resized = image.resize((_HASH_SIDE, _HASH_SIDE), Image.Resampling.LANCZOS)
    pixels = cast(Sequence[int], resized.get_flattened_data())
    mean = sum(pixels) / len(pixels)
    return _bits_to_hex(tuple(value >= mean for value in pixels))


def _difference_hash(image: Image.Image) -> str:
    resized = image.resize((_HASH_SIDE + 1, _HASH_SIDE), Image.Resampling.LANCZOS)
    pixels = cast(Sequence[int], resized.get_flattened_data())
    bits: list[bool] = []
    stride = _HASH_SIDE + 1
    for row in range(_HASH_SIDE):
        offset = row * stride
        for column in range(_HASH_SIDE):
            bits.append(pixels[offset + column] > pixels[offset + column + 1])
    return _bits_to_hex(bits)


def build_image_fingerprint(
    content: bytes,
    *,
    max_pixels: int = DEFAULT_MAX_PIXELS,
) -> ImagePerceptualFingerprint:
    """Decode one local image and produce deterministic, versioned evidence."""

    if not isinstance(content, bytes) or not content:
        raise ImageSimilarityContractError("image bytes are required for decoding")
    if isinstance(max_pixels, bool) or not isinstance(max_pixels, int) or max_pixels < 1:
        raise ImageSimilarityContractError("pixel limit must be a positive integer")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(content)) as opened:
                if int(getattr(opened, "n_frames", 1)) != 1:
                    raise ImageSimilarityContractError(
                        "multi-frame images cannot enter the similarity gate"
                    )
                width, height = opened.size
                if width < 1 or height < 1 or width * height > max_pixels:
                    raise ImageSimilarityContractError("image exceeds the configured pixel limit")
                opened.load()
                normalized = ImageOps.exif_transpose(opened).convert("L")
    except ImageSimilarityContractError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
    ) as exc:
        raise ImageSimilarityContractError("image decode failed") from exc

    width, height = normalized.size
    if width * height > max_pixels:
        raise ImageSimilarityContractError("image exceeds the configured pixel limit")
    view_hashes = tuple(
        PerceptualViewHash(
            crop_permille=crop_permille,
            average_hash=_average_hash(_center_crop(normalized, crop_permille)),
            difference_hash=_difference_hash(_center_crop(normalized, crop_permille)),
        )
        for crop_permille in _CENTER_CROP_PERMILLE
    )
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=hashlib.sha256(content).hexdigest(),
        width=width,
        height=height,
        view_hashes=view_hashes,
    )


@dataclass(frozen=True, slots=True)
class NearDuplicateCandidate:
    algorithm_version: str
    probe_image_sha256: str
    inventory_image_sha256: str
    probe_fingerprint_sha256: str
    inventory_fingerprint_sha256: str
    probe_crop_permille: int
    inventory_crop_permille: int
    distance_numerator: int
    distance_denominator: int
    distance_limit: int
    evidence_sha256: str = field(init=False)
    candidate_id: str = field(init=False)

    def __post_init__(self) -> None:
        if self.algorithm_version != ALGORITHM_VERSION:
            raise ImageSimilarityContractError("candidate algorithm version is unsupported")
        for label, value in (
            ("probe image hash", self.probe_image_sha256),
            ("inventory image hash", self.inventory_image_sha256),
            ("probe fingerprint hash", self.probe_fingerprint_sha256),
            ("inventory fingerprint hash", self.inventory_fingerprint_sha256),
        ):
            _required_sha256(value, label=label)
        if (
            self.probe_crop_permille not in _CENTER_CROP_PERMILLE
            or self.inventory_crop_permille not in _CENTER_CROP_PERMILLE
        ):
            raise ImageSimilarityContractError("candidate crop evidence is invalid")
        if (
            self.distance_denominator != _DISTANCE_DENOMINATOR
            or self.distance_limit != _DISTANCE_LIMIT
            or self.distance_numerator < 0
            or self.distance_numerator > self.distance_denominator
        ):
            raise ImageSimilarityContractError("candidate distance evidence is invalid")
        evidence_sha256 = _canonical_sha256(self._evidence_payload())
        object.__setattr__(self, "evidence_sha256", evidence_sha256)
        object.__setattr__(
            self,
            "candidate_id",
            _canonical_sha256(
                {
                    "algorithm_version": self.algorithm_version,
                    "evidence_sha256": evidence_sha256,
                    "schema_version": SCHEMA_VERSION,
                }
            ),
        )

    def _ordered_members(self) -> list[dict[str, object]]:
        members = [
            {
                "content_sha256": self.probe_image_sha256,
                "crop_permille": self.probe_crop_permille,
                "fingerprint_sha256": self.probe_fingerprint_sha256,
            },
            {
                "content_sha256": self.inventory_image_sha256,
                "crop_permille": self.inventory_crop_permille,
                "fingerprint_sha256": self.inventory_fingerprint_sha256,
            },
        ]
        return sorted(
            members,
            key=lambda member: (
                cast(str, member["content_sha256"]),
                cast(str, member["fingerprint_sha256"]),
                cast(int, member["crop_permille"]),
            ),
        )

    def _evidence_payload(self) -> dict[str, object]:
        return {
            "algorithm_version": self.algorithm_version,
            "distance_denominator": self.distance_denominator,
            "distance_limit": self.distance_limit,
            "distance_numerator": self.distance_numerator,
            "members": self._ordered_members(),
            "schema_version": SCHEMA_VERSION,
        }

    def verify_integrity(self) -> None:
        evidence_sha256 = _canonical_sha256(self._evidence_payload())
        candidate_id = _canonical_sha256(
            {
                "algorithm_version": self.algorithm_version,
                "evidence_sha256": evidence_sha256,
                "schema_version": SCHEMA_VERSION,
            }
        )
        if evidence_sha256 != self.evidence_sha256 or candidate_id != self.candidate_id:
            raise ImageSimilarityContractError("candidate integrity check failed")


def _fingerprint_distance(
    first: ImagePerceptualFingerprint,
    second: ImagePerceptualFingerprint,
) -> tuple[int, int, int]:
    best: tuple[int, int, int] | None = None
    for first_view in first.view_hashes:
        for second_view in second.view_hashes:
            distance = _hamming_distance(
                first_view.average_hash,
                second_view.average_hash,
            ) + _hamming_distance(
                first_view.difference_hash,
                second_view.difference_hash,
            )
            candidate = (
                distance,
                first_view.crop_permille,
                second_view.crop_permille,
            )
            if best is None or candidate < best:
                best = candidate
    if best is None:
        raise ImageSimilarityContractError("fingerprint has no comparable views")
    return best


def find_near_duplicate_candidates(
    *,
    probe: ImagePerceptualFingerprint,
    inventory: Sequence[ImagePerceptualFingerprint],
) -> tuple[NearDuplicateCandidate, ...]:
    """Return possible matches only; a candidate is never an automatic verdict."""

    if not isinstance(probe, ImagePerceptualFingerprint):
        raise ImageSimilarityContractError("probe fingerprint is required")
    probe.verify_integrity()
    if not inventory:
        raise ImageSimilarityContractError("similarity inventory is empty")

    seen_inventory_hashes: set[str] = set()
    candidates: list[NearDuplicateCandidate] = []
    for existing in inventory:
        if not isinstance(existing, ImagePerceptualFingerprint):
            raise ImageSimilarityContractError("inventory fingerprint is invalid")
        existing.verify_integrity()
        if existing.algorithm_version != probe.algorithm_version:
            raise ImageSimilarityContractError("fingerprint algorithm versions differ")
        if existing.content_sha256 in seen_inventory_hashes:
            raise ImageSimilarityContractError("similarity inventory contains a duplicate identity")
        seen_inventory_hashes.add(existing.content_sha256)
        distance, probe_crop, inventory_crop = _fingerprint_distance(probe, existing)
        if distance <= _DISTANCE_LIMIT:
            candidates.append(
                NearDuplicateCandidate(
                    algorithm_version=ALGORITHM_VERSION,
                    probe_image_sha256=probe.content_sha256,
                    inventory_image_sha256=existing.content_sha256,
                    probe_fingerprint_sha256=probe.canonical_sha256,
                    inventory_fingerprint_sha256=existing.canonical_sha256,
                    probe_crop_permille=probe_crop,
                    inventory_crop_permille=inventory_crop,
                    distance_numerator=distance,
                    distance_denominator=_DISTANCE_DENOMINATOR,
                    distance_limit=_DISTANCE_LIMIT,
                )
            )
    return tuple(sorted(candidates, key=lambda candidate: candidate.candidate_id))


@dataclass(frozen=True, slots=True)
class NearDuplicateDecision:
    candidate_id: str
    candidate_evidence_sha256: str
    outcome: ReviewOutcome
    operator_id: str
    note: str
    decided_at: str
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_sha256(self.candidate_id, label="candidate ID")
        _required_sha256(
            self.candidate_evidence_sha256,
            label="candidate evidence hash",
        )
        if not isinstance(self.outcome, ReviewOutcome):
            raise ImageSimilarityContractError("review outcome is invalid")
        operator = _required_text(
            self.operator_id,
            label="review operator",
            maximum=200,
        )
        if not isinstance(self.note, str):
            raise ImageSimilarityContractError("review note must be text")
        note = self.note.strip()
        if len(note) > 1000:
            raise ImageSimilarityContractError("review note is too long")
        if self.outcome is ReviewOutcome.DISTINCT and not note:
            raise ImageSimilarityContractError("review note is required for a distinct decision")
        decided_at = _timezone_aware_time(self.decided_at)
        object.__setattr__(self, "operator_id", operator)
        object.__setattr__(self, "note", note)
        object.__setattr__(self, "decided_at", decided_at)
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    @classmethod
    def create(
        cls,
        *,
        candidate: NearDuplicateCandidate,
        outcome: ReviewOutcome,
        operator_id: str,
        note: str,
        decided_at: str,
    ) -> NearDuplicateDecision:
        if not isinstance(candidate, NearDuplicateCandidate):
            raise ImageSimilarityContractError("current candidate is required")
        candidate.verify_integrity()
        return cls(
            candidate_id=candidate.candidate_id,
            candidate_evidence_sha256=candidate.evidence_sha256,
            outcome=outcome,
            operator_id=operator_id,
            note=note,
            decided_at=decided_at,
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "candidate_evidence_sha256": self.candidate_evidence_sha256,
            "candidate_id": self.candidate_id,
            "decided_at": self.decided_at,
            "note": self.note,
            "operator_id": self.operator_id,
            "outcome": self.outcome.value,
            "schema_version": SCHEMA_VERSION,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise ImageSimilarityContractError("decision integrity check failed")

    def to_record(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    @classmethod
    def from_record(cls, raw: Mapping[str, object]) -> NearDuplicateDecision:
        expected_keys = {
            "candidate_evidence_sha256",
            "candidate_id",
            "canonical_sha256",
            "decided_at",
            "note",
            "operator_id",
            "outcome",
            "schema_version",
        }
        if set(raw) != expected_keys or raw.get("schema_version") != SCHEMA_VERSION:
            raise ImageSimilarityContractError("decision record contract is invalid")
        outcome_value = raw.get("outcome")
        if not isinstance(outcome_value, str):
            raise ImageSimilarityContractError("review outcome is invalid")
        try:
            outcome = ReviewOutcome(outcome_value)
        except ValueError as exc:
            raise ImageSimilarityContractError("review outcome is invalid") from exc
        decision = cls(
            candidate_id=cast(str, raw.get("candidate_id")),
            candidate_evidence_sha256=cast(
                str,
                raw.get("candidate_evidence_sha256"),
            ),
            outcome=outcome,
            operator_id=cast(str, raw.get("operator_id")),
            note=cast(str, raw.get("note")),
            decided_at=cast(str, raw.get("decided_at")),
        )
        stored_sha256 = _required_sha256(
            raw.get("canonical_sha256"),
            label="decision integrity hash",
        )
        if decision.canonical_sha256 != stored_sha256:
            raise ImageSimilarityContractError("decision integrity check failed")
        return decision


@dataclass(frozen=True, slots=True)
class ImageSimilarityGateResult:
    passed: bool
    blocked_reason: str | None
    candidates: tuple[NearDuplicateCandidate, ...]
    decision_sha256s: tuple[str, ...]
    decision_set_sha256: str | None
    canonical_sha256: str


def _gate_result(
    *,
    probe: ImagePerceptualFingerprint,
    inventory: Sequence[ImagePerceptualFingerprint],
    passed: bool,
    blocked_reason: str | None,
    candidates: tuple[NearDuplicateCandidate, ...],
    decisions: tuple[NearDuplicateDecision, ...],
    decision_set_sha256: str | None,
) -> ImageSimilarityGateResult:
    decision_sha256s = tuple(sorted(decision.canonical_sha256 for decision in decisions))
    canonical_sha256 = _canonical_sha256(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "blocked_reason": blocked_reason,
            "candidate_ids": [candidate.candidate_id for candidate in candidates],
            "decision_set_sha256": decision_set_sha256,
            "decision_sha256s": list(decision_sha256s),
            "inventory_fingerprint_sha256s": sorted(item.canonical_sha256 for item in inventory),
            "passed": passed,
            "probe_fingerprint_sha256": probe.canonical_sha256,
            "schema_version": SCHEMA_VERSION,
        }
    )
    return ImageSimilarityGateResult(
        passed=passed,
        blocked_reason=blocked_reason,
        candidates=candidates,
        decision_sha256s=decision_sha256s,
        decision_set_sha256=decision_set_sha256,
        canonical_sha256=canonical_sha256,
    )


def evaluate_image_similarity_gate(
    *,
    probe: ImagePerceptualFingerprint,
    inventory: Sequence[ImagePerceptualFingerprint],
    decisions: Sequence[NearDuplicateDecision],
) -> ImageSimilarityGateResult:
    """Apply human decisions without ever treating a candidate as automatically safe."""

    if not isinstance(probe, ImagePerceptualFingerprint):
        raise ImageSimilarityContractError("probe fingerprint is required")
    probe.verify_integrity()
    inventory_items = tuple(inventory)
    decision_items = tuple(decisions)
    if not inventory_items:
        if decision_items:
            raise ImageSimilarityContractError("a decision does not belong to a current candidate")
        return _gate_result(
            probe=probe,
            inventory=(),
            passed=False,
            blocked_reason="inventory_empty",
            candidates=(),
            decisions=(),
            decision_set_sha256=None,
        )

    candidates = find_near_duplicate_candidates(
        probe=probe,
        inventory=inventory_items,
    )
    candidates_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    decisions_by_id: dict[str, NearDuplicateDecision] = {}
    for decision in decision_items:
        if not isinstance(decision, NearDuplicateDecision):
            raise ImageSimilarityContractError("review decision is invalid")
        decision.verify_integrity()
        candidate = candidates_by_id.get(decision.candidate_id)
        if candidate is None or candidate.evidence_sha256 != decision.candidate_evidence_sha256:
            raise ImageSimilarityContractError("a decision does not belong to a current candidate")
        if decision.candidate_id in decisions_by_id:
            raise ImageSimilarityContractError(
                "a current candidate has conflicting review decisions"
            )
        decisions_by_id[decision.candidate_id] = decision

    ordered_decisions = tuple(
        decisions_by_id[candidate_id] for candidate_id in sorted(decisions_by_id)
    )
    decision_set_sha256 = _canonical_sha256(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "decision_sha256s": [decision.canonical_sha256 for decision in ordered_decisions],
            "schema_version": SCHEMA_VERSION,
        }
    )

    unresolved = set(candidates_by_id).difference(decisions_by_id)
    duplicate_confirmed = any(
        decision.outcome is ReviewOutcome.DUPLICATE for decision in ordered_decisions
    )
    if duplicate_confirmed:
        passed = False
        blocked_reason = "duplicate_confirmed"
    elif unresolved:
        passed = False
        blocked_reason = "unresolved_candidates"
    else:
        passed = True
        blocked_reason = None
    return _gate_result(
        probe=probe,
        inventory=inventory_items,
        passed=passed,
        blocked_reason=blocked_reason,
        candidates=candidates,
        decisions=ordered_decisions,
        decision_set_sha256=decision_set_sha256,
    )
