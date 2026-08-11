from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from PIL import Image

from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthorityError,
    parse_formal_development_authority,
)
from dahe.verification.locked_set import source_waybill_identity_sha256
from dahe.verification.locked_set_review_package import (
    LockedSetReviewPackageError,
    load_locked_set_review_package,
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SUPPORTED_IMAGE_SUFFIXES = frozenset({".bmp", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"})


class CandidateContractError(ValueError):
    """Raised when legacy evidence cannot safely become a review candidate."""


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_inside(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((path, root)) == os.fspath(root)
    except ValueError:
        return False


def _required_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CandidateContractError(f"{label} is required")
    return value.strip()


def _image_hash(value: object) -> str:
    digest = _required_text(value, label="declared image SHA-256").lower()
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise CandidateContractError("declared image SHA-256 is invalid")
    return digest


def _safe_image_path(
    value: object,
    *,
    legacy_root: Path,
    evidence_root: Path,
) -> Path:
    path = Path(_required_text(value, label="legacy image path")).resolve(strict=True)
    if not path.is_file():
        raise CandidateContractError("legacy image path is not a file")
    if not _is_inside(path, legacy_root):
        raise CandidateContractError("legacy image path is outside the legacy data root")
    if not _is_inside(path, evidence_root):
        raise CandidateContractError("legacy image path is outside the immutable evidence root")
    if path.suffix.lower() not in SUPPORTED_IMAGE_SUFFIXES:
        raise CandidateContractError("legacy image media type is unsupported")
    return path


def _image_size(path: Path) -> tuple[int, int]:
    try:
        with Image.open(path) as image:
            image.verify()
        with Image.open(path) as image:
            width, height = image.size
    except (OSError, ValueError) as exc:
        raise CandidateContractError("legacy image is not readable media") from exc
    if width < 1 or height < 1:
        raise CandidateContractError("legacy image dimensions are invalid")
    return width, height


def _waybill_identity(raw_waybill_id: str) -> str:
    return source_waybill_identity_sha256(
        source_namespace="chengfeng_waybill_no",
        source_id=raw_waybill_id,
    )


@dataclass(frozen=True, slots=True)
class LegacyCandidateImage:
    submitted_slot: str
    image_sha256: str
    source_path: Path
    width: int
    height: int
    selection_clues: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "submitted_slot": self.submitted_slot,
            "image_sha256": self.image_sha256,
            "width": self.width,
            "height": self.height,
            "selection_clues": list(self.selection_clues),
        }


@dataclass(frozen=True, slots=True)
class LegacyCandidateWaybill:
    candidate_id: str
    waybill_identity_sha256: str
    images: tuple[LegacyCandidateImage, LegacyCandidateImage]
    selection_clues: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "waybill_identity_sha256": self.waybill_identity_sha256,
            "selection_clues": list(self.selection_clues),
            "images": [image.to_payload() for image in self.images],
        }


@dataclass(frozen=True, slots=True)
class LegacyCandidateIndex:
    legacy_data_root: Path
    source_manifest_sha256s: tuple[str, ...]
    exclusion_snapshot_sha256: str
    excluded_image_identity_count: int
    excluded_waybill_identity_count: int
    source_waybill_count: int
    eligible_waybill_count: int
    excluded_waybill_count: int
    incomplete_waybill_count: int
    conflicting_source_waybill_count: int
    waybills: tuple[LegacyCandidateWaybill, ...]

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": 1,
            "kind": "legacy_locked_set_candidate_index",
            "source_manifest_sha256s": list(self.source_manifest_sha256s),
            "exclusion_snapshot_sha256": self.exclusion_snapshot_sha256,
            "excluded_image_identity_count": self.excluded_image_identity_count,
            "excluded_waybill_identity_count": self.excluded_waybill_identity_count,
            "source_waybill_count": self.source_waybill_count,
            "eligible_waybill_count": self.eligible_waybill_count,
            "excluded_waybill_count": self.excluded_waybill_count,
            "incomplete_waybill_count": self.incomplete_waybill_count,
            "conflicting_source_waybill_count": (self.conflicting_source_waybill_count),
            "waybills": [waybill.to_payload() for waybill in self.waybills],
        }
        return {**payload, "canonical_sha256": _canonical_sha256(payload)}


@dataclass(frozen=True, slots=True)
class _SourcePair:
    raw_waybill_id: str
    loading_path: Path
    loading_hash: str
    unloading_path: Path
    unloading_hash: str


@dataclass(frozen=True, slots=True)
class _ResultHint:
    image_rotations: dict[str, int]
    needs_review: bool


def _load_json_object(path: Path) -> dict[str, object]:
    if path.suffix.lower() != ".json":
        raise CandidateContractError("legacy structured input must be JSON")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateContractError("legacy structured input is not readable JSON") from exc
    if not isinstance(value, dict):
        raise CandidateContractError("legacy structured input must be an object")
    return cast(dict[str, object], value)


def _load_result_hints(
    result_roots: tuple[Path, ...],
    *,
    legacy_root: Path,
) -> dict[str, _ResultHint]:
    hints: dict[str, _ResultHint] = {}
    for raw_root in result_roots:
        root = raw_root.resolve(strict=True)
        if not root.is_dir() or not _is_inside(root, legacy_root):
            raise CandidateContractError("legacy result root is outside the legacy data root")
        for path in sorted(root.rglob("results.json")):
            if not _is_inside(path.resolve(), root):
                raise CandidateContractError("legacy result path escaped its approved root")
            payload = _load_json_object(path)
            rows = payload.get("results")
            if not isinstance(rows, list):
                continue
            for raw_row in rows:
                if not isinstance(raw_row, dict):
                    continue
                raw_waybill_id = raw_row.get("waybill_no")
                if not isinstance(raw_waybill_id, str) or not raw_waybill_id.strip():
                    continue
                rotations: dict[str, int] = {}
                for slot in ("loading", "unloading"):
                    digest = raw_row.get(f"{slot}_image_sha256")
                    rotation = raw_row.get(f"{slot}_image_rotation")
                    if (
                        isinstance(digest, str)
                        and SHA256_PATTERN.fullmatch(digest.lower())
                        and isinstance(rotation, int)
                        and not isinstance(rotation, bool)
                        and rotation in {0, 90, 180, 270}
                    ):
                        rotations[digest.lower()] = rotation
                status = raw_row.get("effective_status")
                previous = hints.get(raw_waybill_id.strip())
                if previous is not None:
                    rotations = {
                        **previous.image_rotations,
                        **rotations,
                    }
                hints[raw_waybill_id.strip()] = _ResultHint(
                    image_rotations=rotations,
                    needs_review=(
                        status in {"review", "mismatch"}
                        or (previous is not None and previous.needs_review)
                    ),
                )
    return hints


def _source_pairs(
    *,
    legacy_root: Path,
    acquisition_root: Path,
) -> tuple[dict[str, _SourcePair], tuple[str, ...], int, int]:
    resolved_acquisition_root = acquisition_root.resolve(strict=True)
    if not resolved_acquisition_root.is_dir() or not _is_inside(
        resolved_acquisition_root, legacy_root
    ):
        raise CandidateContractError("acquisition root is outside the legacy data root")
    evidence_root = (legacy_root / "daily-reports" / "evidence").resolve(strict=True)
    pairs: dict[str, _SourcePair] = {}
    conflicting_waybills: set[str] = set()
    incomplete = 0
    manifest_hashes: list[str] = []
    manifests = sorted(resolved_acquisition_root.glob("*.json"))
    if not manifests:
        raise CandidateContractError("no immutable acquisition JSON was found")
    for manifest_path in manifests:
        manifest_hashes.append(_file_sha256(manifest_path))
        payload = _load_json_object(manifest_path)
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            raise CandidateContractError("acquisition JSON items must be an array")
        for raw_item in raw_items:
            if not isinstance(raw_item, dict):
                incomplete += 1
                continue
            raw_waybill_id = raw_item.get("waybill_no")
            if not isinstance(raw_waybill_id, str) or not raw_waybill_id.strip():
                incomplete += 1
                continue
            required = (
                raw_item.get("loading_image_path"),
                raw_item.get("loading_image_sha256"),
                raw_item.get("unloading_image_path"),
                raw_item.get("unloading_image_sha256"),
            )
            if any(value is None or value == "" for value in required):
                incomplete += 1
                continue
            loading_path = _safe_image_path(
                raw_item.get("loading_image_path"),
                legacy_root=legacy_root,
                evidence_root=evidence_root,
            )
            unloading_path = _safe_image_path(
                raw_item.get("unloading_image_path"),
                legacy_root=legacy_root,
                evidence_root=evidence_root,
            )
            loading_hash = _image_hash(raw_item.get("loading_image_sha256"))
            unloading_hash = _image_hash(raw_item.get("unloading_image_sha256"))
            identity = raw_waybill_id.strip()
            candidate = _SourcePair(
                raw_waybill_id=raw_waybill_id.strip(),
                loading_path=loading_path,
                loading_hash=loading_hash,
                unloading_path=unloading_path,
                unloading_hash=unloading_hash,
            )
            if identity in conflicting_waybills:
                continue
            existing = pairs.get(identity)
            if existing is None:
                pairs[identity] = candidate
                continue
            if (
                existing.loading_hash == candidate.loading_hash
                and existing.unloading_hash == candidate.unloading_hash
            ):
                continue
            pairs.pop(identity)
            conflicting_waybills.add(identity)
    return (
        pairs,
        tuple(sorted(manifest_hashes)),
        incomplete,
        len(conflicting_waybills),
    )


def build_candidate_index(
    *,
    legacy_data_root: Path,
    acquisition_root: Path,
    excluded_image_hashes: set[str] | frozenset[str],
    excluded_waybill_identity_hashes: set[str] | frozenset[str] = frozenset(),
    legacy_result_roots: tuple[Path, ...],
) -> LegacyCandidateIndex:
    legacy_root = legacy_data_root.resolve(strict=True)
    if not legacy_root.is_dir():
        raise CandidateContractError("legacy data root is not a directory")
    excluded = frozenset(value.lower() for value in excluded_image_hashes)
    if any(SHA256_PATTERN.fullmatch(value) is None for value in excluded):
        raise CandidateContractError("excluded image SHA-256 is invalid")
    excluded_waybills = frozenset(value.lower() for value in excluded_waybill_identity_hashes)
    if any(SHA256_PATTERN.fullmatch(value) is None for value in excluded_waybills):
        raise CandidateContractError("excluded waybill identity SHA-256 is invalid")
    pairs, manifest_hashes, incomplete, conflicting = _source_pairs(
        legacy_root=legacy_root,
        acquisition_root=acquisition_root,
    )
    image_use_counts: dict[str, int] = {}
    for pair in pairs.values():
        for digest in (pair.loading_hash, pair.unloading_hash):
            image_use_counts[digest] = image_use_counts.get(digest, 0) + 1
    result_hints = _load_result_hints(
        legacy_result_roots,
        legacy_root=legacy_root,
    )
    excluded_waybill_count = 0
    candidates: list[LegacyCandidateWaybill] = []
    for raw_waybill_id in sorted(pairs):
        pair = pairs[raw_waybill_id]
        identity = _waybill_identity(raw_waybill_id)
        if identity in excluded_waybills or {pair.loading_hash, pair.unloading_hash}.intersection(
            excluded
        ):
            excluded_waybill_count += 1
            continue
        if pair.loading_hash == pair.unloading_hash:
            excluded_waybill_count += 1
            continue
        for path, declared_hash in (
            (pair.loading_path, pair.loading_hash),
            (pair.unloading_path, pair.unloading_hash),
        ):
            if _file_sha256(path) != declared_hash:
                raise CandidateContractError(
                    "declared image SHA-256 does not match immutable evidence"
                )
        hint = result_hints.get(raw_waybill_id)
        waybill_clues: list[str] = []
        if hint is not None and hint.needs_review:
            waybill_clues.append("legacy_review_hint")
        if any(image_use_counts[digest] > 1 for digest in (pair.loading_hash, pair.unloading_hash)):
            waybill_clues.append("historical_hash_reuse_hint")
        images: list[LegacyCandidateImage] = []
        for slot, path, digest in (
            ("loading", pair.loading_path, pair.loading_hash),
            ("unloading", pair.unloading_path, pair.unloading_hash),
        ):
            width, height = _image_size(path)
            clues: list[str] = []
            rotation = hint.image_rotations.get(digest) if hint is not None else None
            if rotation in {0, 90, 180, 270}:
                clues.append(f"rotation_{rotation}_hint")
                if rotation != 0:
                    waybill_clues.append(f"rotation_{rotation}_hint")
            images.append(
                LegacyCandidateImage(
                    submitted_slot=slot,
                    image_sha256=digest,
                    source_path=path,
                    width=width,
                    height=height,
                    selection_clues=tuple(sorted(set(clues))),
                )
            )
        candidates.append(
            LegacyCandidateWaybill(
                candidate_id=f"candidate-{identity[:20]}",
                waybill_identity_sha256=identity,
                images=cast(
                    tuple[LegacyCandidateImage, LegacyCandidateImage],
                    tuple(images),
                ),
                selection_clues=tuple(sorted(set(waybill_clues))),
            )
        )
    return LegacyCandidateIndex(
        legacy_data_root=legacy_root,
        source_manifest_sha256s=manifest_hashes,
        exclusion_snapshot_sha256=_canonical_sha256(
            {
                "excluded_image_sha256s": sorted(excluded),
                "excluded_waybill_identity_sha256s": sorted(excluded_waybills),
                "schema_version": 1,
            }
        ),
        excluded_image_identity_count=len(excluded),
        excluded_waybill_identity_count=len(excluded_waybills),
        source_waybill_count=len(pairs) + conflicting,
        eligible_waybill_count=len(candidates),
        excluded_waybill_count=excluded_waybill_count,
        incomplete_waybill_count=incomplete,
        conflicting_source_waybill_count=conflicting,
        waybills=tuple(candidates),
    )


def _review_image_payload(
    image: LegacyCandidateImage,
    *,
    relative_path: str,
) -> dict[str, object]:
    return {
        "submitted_slot": image.submitted_slot,
        "image_sha256": image.image_sha256,
        "relative_path": relative_path,
        "width": image.width,
        "height": image.height,
        "selection_clues": list(image.selection_clues),
        "human_review": {
            "role": None,
            "ordinary_net": None,
            "quality_conditions": [],
            "notes": None,
        },
    }


def _validated_external_exclusion_snapshot(
    value: dict[str, object],
) -> dict[str, object]:
    expected_keys = {
        "schema_version",
        "image_identity_count",
        "waybill_identity_count",
        "source_file_sha256s",
        "canonical_sha256",
        "image_sha256s",
        "waybill_identity_sha256s",
    }
    if set(value) != expected_keys or value.get("schema_version") != 1:
        raise CandidateContractError("external exclusion snapshot contract is unsupported")

    def hashes(key: str) -> list[str]:
        raw = value.get(key)
        if not isinstance(raw, list) or any(
            not isinstance(item, str) or SHA256_PATTERN.fullmatch(item.lower()) is None
            for item in raw
        ):
            raise CandidateContractError("external exclusion snapshot contains an invalid SHA-256")
        normalized = sorted(item.lower() for item in raw)
        if len(normalized) != len(set(normalized)):
            raise CandidateContractError(
                "external exclusion snapshot contains duplicate identities"
            )
        return normalized

    image_hashes = hashes("image_sha256s")
    waybill_hashes = hashes("waybill_identity_sha256s")
    source_hashes = hashes("source_file_sha256s")
    if value.get("image_identity_count") != len(image_hashes) or value.get(
        "waybill_identity_count"
    ) != len(waybill_hashes):
        raise CandidateContractError(
            "external exclusion snapshot counts do not match its identities"
        )
    canonical_payload = {
        "image_sha256s": image_hashes,
        "schema_version": 1,
        "source_file_sha256s": source_hashes,
        "waybill_identity_sha256s": waybill_hashes,
    }
    declared_hash = value.get("canonical_sha256")
    if not isinstance(declared_hash, str) or declared_hash.lower() != _canonical_sha256(
        canonical_payload
    ):
        raise CandidateContractError("external exclusion snapshot canonical SHA-256 does not match")
    return {
        "schema_version": 1,
        "image_identity_count": len(image_hashes),
        "waybill_identity_count": len(waybill_hashes),
        "source_file_sha256s": source_hashes,
        "canonical_sha256": declared_hash.lower(),
        "image_sha256s": image_hashes,
        "waybill_identity_sha256s": waybill_hashes,
    }


def stage_review_package(
    *,
    index: LegacyCandidateIndex,
    selected_candidate_ids: list[str] | tuple[str, ...],
    output_root: Path,
    package_id: str,
    external_exclusion_snapshot: dict[str, object],
    development_authority: dict[str, object],
) -> dict[str, object]:
    if len(selected_candidate_ids) != 50 or len(set(selected_candidate_ids)) != 50:
        raise CandidateContractError("a review package requires exactly 50 candidates")
    normalized_package_id = package_id.strip()
    if not normalized_package_id:
        raise CandidateContractError("package ID is required")
    if len(normalized_package_id) > 200:
        raise CandidateContractError("package ID is too long")
    manifest_hashes = list(index.source_manifest_sha256s)
    if not manifest_hashes:
        raise CandidateContractError("candidate index requires a source manifest")
    if any(SHA256_PATTERN.fullmatch(value) is None for value in manifest_hashes):
        raise CandidateContractError("candidate index contains an invalid source manifest SHA-256")
    if len(manifest_hashes) != len(set(manifest_hashes)):
        raise CandidateContractError("candidate index contains a duplicate source manifest SHA-256")
    resolved_output = output_root.resolve()
    if resolved_output.exists():
        raise CandidateContractError("review output root must not already exist")
    if _is_inside(resolved_output, index.legacy_data_root):
        raise CandidateContractError("review output must stay outside the legacy data root")
    candidates = {waybill.candidate_id: waybill for waybill in index.waybills}
    try:
        selected = [candidates[candidate_id] for candidate_id in selected_candidate_ids]
    except KeyError as exc:
        raise CandidateContractError("selected candidate does not exist") from exc
    image_hashes = [image.image_sha256 for waybill in selected for image in waybill.images]
    if len(set(image_hashes)) != 100:
        raise CandidateContractError("selected candidates must contain 100 unique images")
    exclusion_snapshot = _validated_external_exclusion_snapshot(external_exclusion_snapshot)
    candidate_exclusion_sha256 = _canonical_sha256(
        {
            "excluded_image_sha256s": exclusion_snapshot["image_sha256s"],
            "excluded_waybill_identity_sha256s": (exclusion_snapshot["waybill_identity_sha256s"]),
            "schema_version": 1,
        }
    )
    if candidate_exclusion_sha256 != index.exclusion_snapshot_sha256:
        raise CandidateContractError(
            "external exclusion snapshot does not match the candidate index"
        )
    try:
        authority = parse_formal_development_authority(development_authority)
    except FormalDevelopmentAuthorityError as exc:
        raise CandidateContractError("development authority is invalid") from exc
    if authority.image_sha256s != frozenset(
        cast(list[str], exclusion_snapshot["image_sha256s"])
    ) or authority.waybill_identity_sha256s != frozenset(
        cast(
            list[str],
            exclusion_snapshot["waybill_identity_sha256s"],
        )
    ):
        raise CandidateContractError("development authority does not match candidate exclusions")

    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    validation_root = resolved_output.parent / (f".{resolved_output.name}.staging-{uuid4().hex}")
    staging = validation_root / "locked-set-review"
    if validation_root.exists():
        raise CandidateContractError("review staging path already exists")
    try:
        image_root = staging / "images"
        image_root.mkdir(parents=True)
        waybill_payloads: list[dict[str, object]] = []
        for sequence, waybill in enumerate(selected, start=1):
            review_images: list[dict[str, object]] = []
            for image in waybill.images:
                suffix = image.source_path.suffix.lower()
                relative_path = f"images/{image.image_sha256}{suffix}"
                target = staging / Path(relative_path)
                shutil.copyfile(image.source_path, target)
                if _file_sha256(target) != image.image_sha256:
                    raise CandidateContractError("staged evidence SHA-256 changed")
                review_images.append(
                    _review_image_payload(
                        image,
                        relative_path=relative_path,
                    )
                )
            waybill_payloads.append(
                {
                    "sample_id": f"L7-{sequence:03d}",
                    "candidate_id": waybill.candidate_id,
                    "waybill_identity_sha256": waybill.waybill_identity_sha256,
                    "selection_clues": list(waybill.selection_clues),
                    "images": review_images,
                    "pair_review": {
                        "conditions": [],
                        "notes": None,
                    },
                    "review_status": "pending",
                    "record_version": 0,
                    "reviewer_id": None,
                    "reviewed_at": None,
                }
            )
        package_without_hash: dict[str, object] = {
            "schema_version": 1,
            "kind": "locked_set_candidate_review",
            "package_id": normalized_package_id,
            "status": "awaiting_human_review",
            "generated_at": datetime.now(UTC).isoformat(),
            "tuning_prohibited": True,
            "source_snapshot": {
                "manifest_sha256s": list(index.source_manifest_sha256s),
                "candidate_index_sha256": index.to_payload()["canonical_sha256"],
                "exclusion_snapshot_sha256": index.exclusion_snapshot_sha256,
                "external_exclusion_snapshot_sha256": (exclusion_snapshot["canonical_sha256"]),
                "external_exclusion_file_sha256": _canonical_sha256(exclusion_snapshot),
                "development_authority_sha256": (authority.authority_sha256),
                "development_authority_file_sha256": _canonical_sha256(authority.payload),
                "excluded_waybill_count": index.excluded_waybill_count,
                "conflicting_source_waybill_count": (index.conflicting_source_waybill_count),
            },
            "waybills": waybill_payloads,
        }
        package = {
            **package_without_hash,
            "canonical_sha256": _canonical_sha256(package_without_hash),
        }
        package_path = staging / "review-package.json"
        package_path.write_text(
            json.dumps(package, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (staging / "external-exclusion-snapshot.json").write_text(
            json.dumps(
                exclusion_snapshot,
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (staging / "development-authority.json").write_bytes(
            (_canonical_json(authority.payload) + "\n").encode("utf-8"),
        )
        try:
            validated = load_locked_set_review_package(validation_root)
        except LockedSetReviewPackageError as exc:
            raise CandidateContractError(
                f"staged review package failed runtime validation: {exc}"
            ) from exc
        if (
            validated.package_id != normalized_package_id
            or validated.canonical_sha256 != package["canonical_sha256"]
        ):
            raise CandidateContractError("staged review package runtime identity does not match")
        staging.replace(resolved_output)
        # The package is already atomically published. An empty temporary
        # parent is harmless and must not turn success into an ambiguous
        # failure after publication.
        with suppress(OSError):
            validation_root.rmdir()
        return package
    except BaseException:
        if validation_root.exists():
            shutil.rmtree(validation_root, ignore_errors=True)
        raise
