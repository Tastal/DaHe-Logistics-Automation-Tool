from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Protocol

from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
    NearDuplicateCandidate,
    NearDuplicateDecision,
    find_near_duplicate_candidates,
)

SCAN_SCHEMA_VERSION = 1
REQUIRED_PROBE_COUNT = 100

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SIMILARITY_QUANTUM = Decimal("0.0001")


class LockedSetSimilarityScanError(ValueError):
    """Raised when a complete authoritative similarity scan cannot be proven."""


class PersistedFingerprintRecordLike(Protocol):
    @property
    def image_sha256(self) -> str: ...

    @property
    def fingerprint_json(self) -> str: ...

    @property
    def fingerprint_json_sha256(self) -> str: ...


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise LockedSetSimilarityScanError("similarity evidence is not canonical JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise LockedSetSimilarityScanError(f"{label} must be a lowercase SHA-256")
    return value


def _required_text(value: object, *, label: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LockedSetSimilarityScanError(f"{label} is required")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise LockedSetSimilarityScanError(f"{label} is too long")
    return normalized


@dataclass(frozen=True, slots=True)
class PersistedFingerprintRecord:
    """Storage-neutral shape returned by an authoritative snapshot adapter."""

    image_sha256: str
    fingerprint_json: str
    fingerprint_json_sha256: str

    def __post_init__(self) -> None:
        _required_sha256(self.image_sha256, label="persisted image identity")
        _required_sha256(
            self.fingerprint_json_sha256,
            label="persisted fingerprint record hash",
        )
        if not isinstance(self.fingerprint_json, str) or not self.fingerprint_json:
            raise LockedSetSimilarityScanError("persisted fingerprint JSON is required")

    @classmethod
    def create(
        cls,
        fingerprint: ImagePerceptualFingerprint,
    ) -> PersistedFingerprintRecord:
        if not isinstance(fingerprint, ImagePerceptualFingerprint):
            raise LockedSetSimilarityScanError("a code-owned image fingerprint is required")
        fingerprint.verify_integrity()
        fingerprint_json = _canonical_json(fingerprint.to_record())
        return cls(
            image_sha256=fingerprint.content_sha256,
            fingerprint_json=fingerprint_json,
            fingerprint_json_sha256=hashlib.sha256(fingerprint_json.encode("utf-8")).hexdigest(),
        )


def _load_persisted_fingerprint(
    record: PersistedFingerprintRecordLike,
) -> ImagePerceptualFingerprint:
    try:
        image_sha256 = record.image_sha256
        fingerprint_json = record.fingerprint_json
        record_sha256 = record.fingerprint_json_sha256
    except AttributeError as exc:
        raise LockedSetSimilarityScanError("persisted fingerprint record is incomplete") from exc
    _required_sha256(image_sha256, label="persisted image identity")
    _required_sha256(record_sha256, label="persisted fingerprint record hash")
    if not isinstance(fingerprint_json, str) or not fingerprint_json:
        raise LockedSetSimilarityScanError("persisted fingerprint JSON is required")
    actual_record_sha256 = hashlib.sha256(fingerprint_json.encode("utf-8")).hexdigest()
    if actual_record_sha256 != record_sha256:
        raise LockedSetSimilarityScanError("persisted fingerprint record hash does not match JSON")
    try:
        raw = json.loads(fingerprint_json)
    except json.JSONDecodeError as exc:
        raise LockedSetSimilarityScanError("persisted fingerprint JSON cannot be decoded") from exc
    if not isinstance(raw, dict) or _canonical_json(raw) != fingerprint_json:
        raise LockedSetSimilarityScanError("persisted fingerprint JSON is not canonical")
    try:
        fingerprint = ImagePerceptualFingerprint.from_record(raw)
    except ImageSimilarityContractError as exc:
        raise LockedSetSimilarityScanError("persisted fingerprint integrity is invalid") from exc
    if fingerprint.content_sha256 != image_sha256:
        raise LockedSetSimilarityScanError("persisted fingerprint belongs to another image")
    return fingerprint


def _detector_fingerprint() -> str:
    return _canonical_sha256(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "comparison_scopes": [
                "probe_to_inventory",
                "probe_to_probe",
            ],
            "required_probe_count": REQUIRED_PROBE_COUNT,
            "scan_schema_version": SCAN_SCHEMA_VERSION,
        }
    )


def _set_fingerprint(
    fingerprints: Sequence[ImagePerceptualFingerprint],
) -> str:
    return _canonical_sha256(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "members": [
                {
                    "content_sha256": fingerprint.content_sha256,
                    "fingerprint_sha256": fingerprint.canonical_sha256,
                }
                for fingerprint in fingerprints
            ],
            "schema_version": SCAN_SCHEMA_VERSION,
        }
    )


def _similarity(candidate: NearDuplicateCandidate) -> str:
    value = (
        Decimal(candidate.distance_denominator - candidate.distance_numerator)
        / Decimal(candidate.distance_denominator)
    ).quantize(_SIMILARITY_QUANTUM, rounding=ROUND_HALF_EVEN)
    return format(value, ".4f")


@dataclass(frozen=True, slots=True)
class LockedSetSimilarityCandidate:
    comparison_scope: str
    candidate: NearDuplicateCandidate

    def __post_init__(self) -> None:
        if self.comparison_scope not in {
            "probe_to_inventory",
            "probe_to_probe",
        }:
            raise LockedSetSimilarityScanError("similarity comparison scope is invalid")
        self.candidate.verify_integrity()

    def to_payload(self) -> dict[str, object]:
        return {
            "candidate_evidence_sha256": self.candidate.evidence_sha256,
            "candidate_id": self.candidate.candidate_id,
            "comparison_scope": self.comparison_scope,
            "detector": self.candidate.algorithm_version,
            "distance_denominator": self.candidate.distance_denominator,
            "distance_limit": self.candidate.distance_limit,
            "distance_numerator": self.candidate.distance_numerator,
            "excluded_image_sha256": self.candidate.inventory_image_sha256,
            "locked_image_sha256": self.candidate.probe_image_sha256,
            "similarity": _similarity(self.candidate),
        }


@dataclass(frozen=True, slots=True)
class LockedSetSimilarityScan:
    dataset_id: str
    manifest_sha256: str
    exclusion_snapshot_sha256: str
    detector_fingerprint: str
    probe_set_fingerprint: str
    inventory_set_fingerprint: str
    locked_image_count: int
    excluded_image_count: int
    candidate_entries: tuple[LockedSetSimilarityCandidate, ...]
    scan_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        _required_text(self.dataset_id, label="locked dataset ID")
        for label, value in (
            ("locked manifest hash", self.manifest_sha256),
            ("exclusion snapshot hash", self.exclusion_snapshot_sha256),
            ("similarity detector fingerprint", self.detector_fingerprint),
            ("locked probe-set fingerprint", self.probe_set_fingerprint),
            ("inventory-set fingerprint", self.inventory_set_fingerprint),
        ):
            _required_sha256(value, label=label)
        if self.locked_image_count != REQUIRED_PROBE_COUNT:
            raise LockedSetSimilarityScanError(
                "similarity scan must cover exactly 100 locked images"
            )
        if self.excluded_image_count < 0:
            raise LockedSetSimilarityScanError(
                "authoritative similarity inventory count is invalid"
            )
        candidate_ids = [entry.candidate.candidate_id for entry in self.candidate_entries]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise LockedSetSimilarityScanError("similarity scan candidate IDs are duplicated")
        object.__setattr__(
            self,
            "scan_fingerprint",
            _canonical_sha256(self._payload_without_fingerprint()),
        )

    @property
    def review_candidates(self) -> tuple[NearDuplicateCandidate, ...]:
        return tuple(entry.candidate for entry in self.candidate_entries)

    def _payload_without_fingerprint(self) -> dict[str, object]:
        return {
            "candidates": [entry.to_payload() for entry in self.candidate_entries],
            "completed": True,
            "dataset_id": self.dataset_id,
            "detector_fingerprint": self.detector_fingerprint,
            "excluded_image_count": self.excluded_image_count,
            "exclusion_snapshot_sha256": self.exclusion_snapshot_sha256,
            "inventory_set_fingerprint": self.inventory_set_fingerprint,
            "locked_image_count": self.locked_image_count,
            "manifest_sha256": self.manifest_sha256,
            "probe_set_fingerprint": self.probe_set_fingerprint,
            "schema_version": SCAN_SCHEMA_VERSION,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._payload_without_fingerprint(),
            "scan_fingerprint": self.scan_fingerprint,
        }

    def verify_integrity(self) -> None:
        for entry in self.candidate_entries:
            entry.candidate.verify_integrity()
        if _canonical_sha256(self._payload_without_fingerprint()) != self.scan_fingerprint:
            raise LockedSetSimilarityScanError("similarity scan integrity is invalid")


def recompute_scan_fingerprint(payload: Mapping[str, object]) -> str:
    """Recompute the acceptance-compatible scan integrity field."""

    if not isinstance(payload, Mapping):
        raise LockedSetSimilarityScanError("similarity scan payload must be a mapping")
    body = dict(payload)
    body.pop("scan_fingerprint", None)
    return _canonical_sha256(body)


def _validated_probes(
    probes: Sequence[ImagePerceptualFingerprint],
) -> tuple[ImagePerceptualFingerprint, ...]:
    if len(probes) != REQUIRED_PROBE_COUNT:
        raise LockedSetSimilarityScanError("similarity scan requires exactly 100 code-owned probes")
    validated: list[ImagePerceptualFingerprint] = []
    for probe in probes:
        if not isinstance(probe, ImagePerceptualFingerprint):
            raise LockedSetSimilarityScanError("locked probe fingerprint is invalid")
        try:
            probe.verify_integrity()
        except ImageSimilarityContractError as exc:
            raise LockedSetSimilarityScanError(
                "locked probe fingerprint integrity is invalid"
            ) from exc
        if probe.algorithm_version != ALGORITHM_VERSION:
            raise LockedSetSimilarityScanError("locked probe algorithm version is unsupported")
        validated.append(probe)
    identities = [probe.content_sha256 for probe in validated]
    if len(identities) != len(set(identities)):
        raise LockedSetSimilarityScanError("locked probe identities must be unique")
    return tuple(sorted(validated, key=lambda probe: probe.content_sha256))


def _validated_inventory(
    records: Sequence[PersistedFingerprintRecordLike],
) -> tuple[ImagePerceptualFingerprint, ...]:
    validated = [_load_persisted_fingerprint(record) for record in records]
    for fingerprint in validated:
        if fingerprint.algorithm_version != ALGORITHM_VERSION:
            raise LockedSetSimilarityScanError(
                "inventory fingerprint algorithm version is unsupported"
            )
    identities = [fingerprint.content_sha256 for fingerprint in validated]
    if len(identities) != len(set(identities)):
        raise LockedSetSimilarityScanError("authoritative inventory identities must be unique")
    return tuple(sorted(validated, key=lambda fingerprint: fingerprint.content_sha256))


def _candidate_entries(
    *,
    probes: tuple[ImagePerceptualFingerprint, ...],
    inventory: tuple[ImagePerceptualFingerprint, ...],
) -> tuple[LockedSetSimilarityCandidate, ...]:
    entries: list[LockedSetSimilarityCandidate] = []
    try:
        if inventory:
            for probe in probes:
                entries.extend(
                    LockedSetSimilarityCandidate(
                        comparison_scope="probe_to_inventory",
                        candidate=candidate,
                    )
                    for candidate in find_near_duplicate_candidates(
                        probe=probe,
                        inventory=inventory,
                    )
                )
        for index, probe in enumerate(probes[:-1]):
            entries.extend(
                LockedSetSimilarityCandidate(
                    comparison_scope="probe_to_probe",
                    candidate=candidate,
                )
                for candidate in find_near_duplicate_candidates(
                    probe=probe,
                    inventory=probes[index + 1 :],
                )
            )
    except ImageSimilarityContractError as exc:
        raise LockedSetSimilarityScanError("similarity detector rejected scan evidence") from exc
    ordered = tuple(
        sorted(
            entries,
            key=lambda entry: (
                entry.candidate.candidate_id,
                entry.comparison_scope,
            ),
        )
    )
    candidate_ids = [entry.candidate.candidate_id for entry in ordered]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise LockedSetSimilarityScanError(
            "similarity detector produced duplicate candidate identities"
        )
    return ordered


def scan_locked_set_similarity(
    *,
    dataset_id: str,
    manifest_sha256: str,
    exclusion_snapshot_sha256: str,
    probes: Sequence[ImagePerceptualFingerprint],
    persisted_inventory: Sequence[PersistedFingerprintRecordLike],
) -> LockedSetSimilarityScan:
    """Scan all locked images against history and each other without a verdict."""

    normalized_dataset_id = _required_text(
        dataset_id,
        label="locked dataset ID",
    )
    normalized_manifest_sha256 = _required_sha256(
        manifest_sha256,
        label="locked manifest hash",
    )
    normalized_snapshot_sha256 = _required_sha256(
        exclusion_snapshot_sha256,
        label="exclusion snapshot hash",
    )
    try:
        probe_items = tuple(probes)
    except TypeError as exc:
        raise LockedSetSimilarityScanError("locked probe collection is missing") from exc
    try:
        inventory_items = tuple(persisted_inventory)
    except TypeError as exc:
        raise LockedSetSimilarityScanError("authoritative inventory collection is missing") from exc
    validated_probes = _validated_probes(probe_items)
    validated_inventory = _validated_inventory(inventory_items)
    entries = _candidate_entries(
        probes=validated_probes,
        inventory=validated_inventory,
    )
    return LockedSetSimilarityScan(
        dataset_id=normalized_dataset_id,
        manifest_sha256=normalized_manifest_sha256,
        exclusion_snapshot_sha256=normalized_snapshot_sha256,
        detector_fingerprint=_detector_fingerprint(),
        probe_set_fingerprint=_set_fingerprint(validated_probes),
        inventory_set_fingerprint=_set_fingerprint(validated_inventory),
        locked_image_count=len(validated_probes),
        excluded_image_count=len(validated_inventory),
        candidate_entries=entries,
    )


def bind_similarity_decisions(
    *,
    scan: LockedSetSimilarityScan,
    decisions: Sequence[NearDuplicateDecision],
) -> list[dict[str, object]]:
    """Bind existing human decisions to this exact scan for acceptance."""

    if not isinstance(scan, LockedSetSimilarityScan):
        raise LockedSetSimilarityScanError("a current similarity scan is required")
    scan.verify_integrity()
    candidates = {candidate.candidate_id: candidate for candidate in scan.review_candidates}
    reviewed: dict[str, NearDuplicateDecision] = {}
    for decision in decisions:
        if not isinstance(decision, NearDuplicateDecision):
            raise LockedSetSimilarityScanError(
                "manual review must use an existing near-duplicate decision"
            )
        try:
            decision.verify_integrity()
        except ImageSimilarityContractError as exc:
            raise LockedSetSimilarityScanError(
                "manual similarity decision integrity is invalid"
            ) from exc
        candidate = candidates.get(decision.candidate_id)
        if candidate is None or candidate.evidence_sha256 != decision.candidate_evidence_sha256:
            raise LockedSetSimilarityScanError(
                "manual decision does not belong to the current scan"
            )
        if decision.candidate_id in reviewed:
            raise LockedSetSimilarityScanError(
                "manual decisions for a current candidate are duplicated"
            )
        if not decision.note:
            raise LockedSetSimilarityScanError("manual similarity decision reason is required")
        reviewed[decision.candidate_id] = decision
    if set(reviewed) != set(candidates):
        raise LockedSetSimilarityScanError(
            "current scan candidates require complete manual decisions"
        )
    return [
        {
            "candidate_id": decision.candidate_id,
            "decided_at": decision.decided_at,
            "decision_evidence_sha256": decision.canonical_sha256,
            "reason": decision.note,
            "reviewer_id": decision.operator_id,
            "scan_fingerprint": scan.scan_fingerprint,
            "verdict": decision.outcome.value,
        }
        for decision in (reviewed[candidate_id] for candidate_id in sorted(reviewed))
    ]
