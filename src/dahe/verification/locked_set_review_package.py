from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from PIL import Image, UnidentifiedImageError

from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
    FormalDevelopmentAuthorityError,
    load_formal_development_authority,
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SELECTION_CLUES = {
    "historical_hash_reuse_hint",
    "legacy_review_hint",
    "rotation_0_hint",
    "rotation_90_hint",
    "rotation_180_hint",
    "rotation_270_hint",
}
_SUPPORTED_MEDIA_TYPES = {
    "BMP": "image/bmp",
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "TIFF": "image/tiff",
    "WEBP": "image/webp",
}


class LockedSetReviewPackageError(ValueError):
    """Raised when the explicit offline review package is unsafe."""


class LockedSetReviewImageChangedError(RuntimeError):
    """Raised when package-bound image bytes change after startup."""


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise LockedSetReviewPackageError("review package image is missing or unreadable") from exc
    return digest.hexdigest()


def _is_inside(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((path, root)) == os.fspath(root)
    except ValueError:
        return False


def _object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LockedSetReviewPackageError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _required_text(value: object, *, label: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LockedSetReviewPackageError(f"{label} is required")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise LockedSetReviewPackageError(f"{label} is too long")
    return normalized


def _sha256(value: object, *, label: str) -> str:
    digest = _required_text(value, label=label, maximum=64).lower()
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise LockedSetReviewPackageError(f"{label} must be a lowercase SHA-256")
    return digest


def _selection_clues(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise LockedSetReviewPackageError(f"{label} must be an array")
    clues: list[str] = []
    for raw in value:
        clue = _required_text(raw, label=label, maximum=100)
        if clue not in _SELECTION_CLUES:
            raise LockedSetReviewPackageError(f"{label} contains an unsupported selection clue")
        if clue in clues:
            raise LockedSetReviewPackageError(f"{label} contains a duplicate")
        clues.append(clue)
    return tuple(clues)


def _sha256_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise LockedSetReviewPackageError(f"{label} must be an array")
    hashes = [_sha256(item, label=label) for item in value]
    if len(hashes) != len(set(hashes)):
        raise LockedSetReviewPackageError(f"{label} contains a duplicate")
    return sorted(hashes)


def _validate_source_snapshot(
    value: object,
    *,
    review_root: Path,
) -> FormalDevelopmentAuthority:
    source = _object(value, label="review source snapshot")
    manifest_hashes = _sha256_list(
        source.get("manifest_sha256s"),
        label="source manifest SHA-256",
    )
    if not manifest_hashes:
        raise LockedSetReviewPackageError("review source snapshot requires a source manifest")
    _sha256(
        source.get("candidate_index_sha256"),
        label="candidate index SHA-256",
    )
    exclusion_snapshot_sha256 = _sha256(
        source.get("exclusion_snapshot_sha256"),
        label="candidate exclusion snapshot SHA-256",
    )
    external_snapshot_sha256 = _sha256(
        source.get("external_exclusion_snapshot_sha256"),
        label="external exclusion snapshot SHA-256",
    )
    external_file_sha256 = _sha256(
        source.get("external_exclusion_file_sha256"),
        label="external exclusion file SHA-256",
    )
    excluded_waybill_count = source.get("excluded_waybill_count")
    if (
        not isinstance(excluded_waybill_count, int)
        or isinstance(excluded_waybill_count, bool)
        or excluded_waybill_count < 0
    ):
        raise LockedSetReviewPackageError("review source excluded-waybill count is invalid")
    expected_keys = {
        "manifest_sha256s",
        "candidate_index_sha256",
        "exclusion_snapshot_sha256",
        "external_exclusion_snapshot_sha256",
        "external_exclusion_file_sha256",
        "development_authority_sha256",
        "development_authority_file_sha256",
        "excluded_waybill_count",
        "conflicting_source_waybill_count",
    }
    if set(source) != expected_keys:
        raise LockedSetReviewPackageError("review source snapshot contract is unsupported")
    conflicting_source_waybill_count = source.get("conflicting_source_waybill_count")
    if (
        not isinstance(conflicting_source_waybill_count, int)
        or isinstance(conflicting_source_waybill_count, bool)
        or conflicting_source_waybill_count < 0
    ):
        raise LockedSetReviewPackageError("review source conflicting-waybill count is invalid")

    try:
        snapshot_path = (review_root / "external-exclusion-snapshot.json").resolve(strict=True)
    except OSError as exc:
        raise LockedSetReviewPackageError("external exclusion snapshot is missing") from exc
    if not snapshot_path.is_file() or not _is_inside(
        snapshot_path,
        review_root,
    ):
        raise LockedSetReviewPackageError(
            "external exclusion snapshot must stay inside the review package"
        )
    try:
        external = _object(
            json.loads(snapshot_path.read_text(encoding="utf-8")),
            label="external exclusion snapshot",
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise LockedSetReviewPackageError(
            "external exclusion snapshot is not readable JSON"
        ) from exc
    if _canonical_sha256(external) != external_file_sha256:
        raise LockedSetReviewPackageError(
            "external exclusion snapshot changed after package staging"
        )
    expected_external_keys = {
        "schema_version",
        "image_identity_count",
        "waybill_identity_count",
        "source_file_sha256s",
        "canonical_sha256",
        "image_sha256s",
        "waybill_identity_sha256s",
    }
    if set(external) != expected_external_keys or external.get("schema_version") != 1:
        raise LockedSetReviewPackageError("external exclusion snapshot contract is unsupported")
    image_hashes = _sha256_list(
        external.get("image_sha256s"),
        label="external excluded image SHA-256",
    )
    waybill_hashes = _sha256_list(
        external.get("waybill_identity_sha256s"),
        label="external excluded waybill SHA-256",
    )
    source_hashes = _sha256_list(
        external.get("source_file_sha256s"),
        label="external exclusion source-file SHA-256",
    )
    if external.get("image_identity_count") != len(image_hashes) or external.get(
        "waybill_identity_count"
    ) != len(waybill_hashes):
        raise LockedSetReviewPackageError("external exclusion snapshot counts do not match")
    external_core = {
        "image_sha256s": image_hashes,
        "schema_version": 1,
        "source_file_sha256s": source_hashes,
        "waybill_identity_sha256s": waybill_hashes,
    }
    if (
        external.get("canonical_sha256") != _canonical_sha256(external_core)
        or external.get("canonical_sha256") != external_snapshot_sha256
    ):
        raise LockedSetReviewPackageError(
            "external exclusion snapshot canonical SHA-256 does not match"
        )
    candidate_core = {
        "excluded_image_sha256s": image_hashes,
        "excluded_waybill_identity_sha256s": waybill_hashes,
        "schema_version": 1,
    }
    if _canonical_sha256(candidate_core) != exclusion_snapshot_sha256:
        raise LockedSetReviewPackageError(
            "external exclusion snapshot does not match the candidate index"
        )
    authority_sha256 = _sha256(
        source.get("development_authority_sha256"),
        label="development authority SHA-256",
    )
    authority_file_sha256 = _sha256(
        source.get("development_authority_file_sha256"),
        label="development authority file SHA-256",
    )
    try:
        authority_path = (review_root / "development-authority.json").resolve(strict=True)
        authority = load_formal_development_authority(
            authority_path,
            expected_sha256=authority_sha256,
        )
    except (OSError, FormalDevelopmentAuthorityError) as exc:
        raise LockedSetReviewPackageError("development authority is invalid") from exc
    if (
        not _is_inside(authority_path, review_root)
        or _canonical_sha256(authority.payload) != authority_file_sha256
        or authority.image_sha256s != frozenset(image_hashes)
        or authority.waybill_identity_sha256s != frozenset(waybill_hashes)
    ):
        raise LockedSetReviewPackageError("development authority does not match the review source")
    return authority


def _safe_image_path(
    value: object,
    *,
    review_root: Path,
    image_root: Path,
) -> tuple[str, Path]:
    raw = _required_text(value, label="review image relative path")
    if "\\" in raw or ":" in raw or raw.startswith("//"):
        raise LockedSetReviewPackageError("review image path must stay inside the review package")
    relative = PurePosixPath(raw)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.parts[0] != "images"
        or ".." in relative.parts
        or "." in relative.parts
    ):
        raise LockedSetReviewPackageError("review image path must stay inside the review package")
    try:
        resolved = (review_root / Path(relative.as_posix())).resolve(strict=True)
    except OSError as exc:
        raise LockedSetReviewPackageError("review package image is missing or unreadable") from exc
    if (
        not resolved.is_file()
        or not _is_inside(resolved, review_root)
        or not _is_inside(resolved, image_root)
    ):
        raise LockedSetReviewPackageError("review image path must stay inside the review package")
    return relative.as_posix(), resolved


def _verified_media(
    path: Path,
    *,
    declared_width: object,
    declared_height: object,
) -> tuple[int, int, str]:
    if (
        not isinstance(declared_width, int)
        or isinstance(declared_width, bool)
        or declared_width < 1
        or not isinstance(declared_height, int)
        or isinstance(declared_height, bool)
        or declared_height < 1
    ):
        raise LockedSetReviewPackageError("review image dimensions are invalid")
    try:
        with Image.open(path) as image:
            image.verify()
        with Image.open(path) as image:
            actual_width, actual_height = image.size
            media_type = _SUPPORTED_MEDIA_TYPES.get(str(image.format).upper())
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        raise LockedSetReviewPackageError("review package image is not supported media") from exc
    if media_type is None:
        raise LockedSetReviewPackageError("review package image is not supported media")
    if (actual_width, actual_height) != (declared_width, declared_height):
        raise LockedSetReviewPackageError("review image dimensions do not match the package")
    return actual_width, actual_height, media_type


@dataclass(frozen=True, slots=True)
class LockedSetReviewImage:
    submitted_slot: str
    image_sha256: str
    relative_path: str
    path: Path
    width: int
    height: int
    media_type: str
    selection_clues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LockedSetReviewItem:
    sample_id: str
    candidate_id: str
    waybill_identity_sha256: str
    position: int
    selection_clues: tuple[str, ...]
    images: tuple[LockedSetReviewImage, LockedSetReviewImage]


@dataclass(frozen=True, slots=True)
class LockedSetReviewPackage:
    package_id: str
    canonical_sha256: str
    review_root: Path
    items: tuple[LockedSetReviewItem, ...]
    items_by_sample_id: dict[str, LockedSetReviewItem]
    images_by_sha256: dict[str, LockedSetReviewImage]
    development_authority: FormalDevelopmentAuthority | None = None

    def read_verified_image(self, image_sha256: str) -> tuple[bytes, str]:
        image = self.images_by_sha256.get(image_sha256)
        if image is None:
            raise KeyError(image_sha256)
        try:
            content = image.path.read_bytes()
        except OSError as exc:
            raise LockedSetReviewImageChangedError("review image is no longer readable") from exc
        if hashlib.sha256(content).hexdigest() != image.image_sha256:
            raise LockedSetReviewImageChangedError("review image changed after package validation")
        return content, image.media_type


def _load_image(
    value: object,
    *,
    review_root: Path,
    image_root: Path,
    seen_hashes: set[str],
    seen_paths: set[str],
) -> LockedSetReviewImage:
    raw = _object(value, label="review image")
    if set(raw) != {
        "submitted_slot",
        "image_sha256",
        "relative_path",
        "width",
        "height",
        "selection_clues",
        "human_review",
    }:
        raise LockedSetReviewPackageError("review image contains unexpected fields")
    slot = _required_text(raw.get("submitted_slot"), label="submitted slot")
    if slot not in {"loading", "unloading"}:
        raise LockedSetReviewPackageError("submitted slot must be loading or unloading")
    digest = _sha256(raw.get("image_sha256"), label="review image SHA-256")
    if digest in seen_hashes:
        raise LockedSetReviewPackageError(
            "review package must contain 100 unique image SHA-256 values"
        )
    relative_path, path = _safe_image_path(
        raw.get("relative_path"),
        review_root=review_root,
        image_root=image_root,
    )
    if relative_path in seen_paths:
        raise LockedSetReviewPackageError("review package image paths must be unique")
    if _file_sha256(path) != digest:
        raise LockedSetReviewPackageError("review image SHA-256 does not match the package")
    width, height, media_type = _verified_media(
        path,
        declared_width=raw.get("width"),
        declared_height=raw.get("height"),
    )
    if raw.get("human_review") != {
        "role": None,
        "ordinary_net": None,
        "quality_conditions": [],
        "notes": None,
    }:
        raise LockedSetReviewPackageError("candidate package must not embed human review truth")
    seen_hashes.add(digest)
    seen_paths.add(relative_path)
    return LockedSetReviewImage(
        submitted_slot=slot,
        image_sha256=digest,
        relative_path=relative_path,
        path=path,
        width=width,
        height=height,
        media_type=media_type,
        selection_clues=_selection_clues(
            raw.get("selection_clues"),
            label="image selection clues",
        ),
    )


def load_locked_set_review_package(data_root: Path) -> LockedSetReviewPackage:
    """Load and rehash the one explicit offline candidate-review package."""

    try:
        resolved_data_root = data_root.resolve(strict=True)
        review_root = (resolved_data_root / "locked-set-review").resolve(strict=True)
        image_root = (review_root / "images").resolve(strict=True)
        package_path = (review_root / "review-package.json").resolve(strict=True)
    except OSError as exc:
        raise LockedSetReviewPackageError(
            "locked-set review package is missing from the explicit data root"
        ) from exc
    if (
        not resolved_data_root.is_dir()
        or not review_root.is_dir()
        or not image_root.is_dir()
        or not package_path.is_file()
        or not _is_inside(review_root, resolved_data_root)
        or not _is_inside(image_root, review_root)
        or not _is_inside(package_path, review_root)
    ):
        raise LockedSetReviewPackageError(
            "locked-set review package must stay inside the explicit data root"
        )
    try:
        root = _object(
            json.loads(package_path.read_text(encoding="utf-8")),
            label="review package",
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise LockedSetReviewPackageError("locked-set review package is not readable JSON") from exc
    declared_hash = _sha256(
        root.get("canonical_sha256"),
        label="review package canonical SHA-256",
    )
    without_hash = {key: value for key, value in root.items() if key != "canonical_sha256"}
    if _canonical_sha256(without_hash) != declared_hash:
        raise LockedSetReviewPackageError(
            "review package canonical SHA-256 does not match its content"
        )
    if (
        root.get("schema_version") != 1
        or root.get("kind") != "locked_set_candidate_review"
        or root.get("status") != "awaiting_human_review"
        or root.get("tuning_prohibited") is not True
    ):
        raise LockedSetReviewPackageError("locked-set review package contract is unsupported")
    if set(root) != {
        "schema_version",
        "kind",
        "package_id",
        "status",
        "generated_at",
        "tuning_prohibited",
        "source_snapshot",
        "waybills",
        "canonical_sha256",
    }:
        raise LockedSetReviewPackageError("review package contains unexpected fields")
    development_authority = _validate_source_snapshot(
        root.get("source_snapshot"),
        review_root=review_root,
    )
    package_id = _required_text(
        root.get("package_id"),
        label="review package ID",
        maximum=200,
    )
    raw_waybills = root.get("waybills")
    if not isinstance(raw_waybills, list) or len(raw_waybills) != 50:
        raise LockedSetReviewPackageError("locked-set review package requires exactly 50 waybills")
    seen_sample_ids: set[str] = set()
    seen_candidate_ids: set[str] = set()
    seen_waybill_identities: set[str] = set()
    seen_hashes: set[str] = set()
    seen_paths: set[str] = set()
    items: list[LockedSetReviewItem] = []
    for position, value in enumerate(raw_waybills, start=1):
        raw = _object(value, label="review waybill")
        if set(raw) != {
            "sample_id",
            "candidate_id",
            "waybill_identity_sha256",
            "selection_clues",
            "images",
            "pair_review",
            "review_status",
            "record_version",
            "reviewer_id",
            "reviewed_at",
        }:
            raise LockedSetReviewPackageError("review waybill contains unexpected fields")
        sample_id = _required_text(
            raw.get("sample_id"),
            label="sample ID",
            maximum=100,
        )
        candidate_id = _required_text(
            raw.get("candidate_id"),
            label="candidate ID",
            maximum=200,
        )
        identity = _sha256(
            raw.get("waybill_identity_sha256"),
            label="waybill identity SHA-256",
        )
        if (
            sample_id in seen_sample_ids
            or candidate_id in seen_candidate_ids
            or identity in seen_waybill_identities
        ):
            raise LockedSetReviewPackageError("review waybill identities must be unique")
        if (
            raw.get("review_status") != "pending"
            or raw.get("record_version") != 0
            or raw.get("reviewer_id") is not None
            or raw.get("reviewed_at") is not None
        ):
            raise LockedSetReviewPackageError("candidate review waybills must start pending")
        if raw.get("pair_review") != {"conditions": [], "notes": None}:
            raise LockedSetReviewPackageError("candidate package must not embed pair review truth")
        raw_images = raw.get("images")
        if not isinstance(raw_images, list) or len(raw_images) != 2:
            raise LockedSetReviewPackageError("each review waybill requires exactly two images")
        images = tuple(
            _load_image(
                image,
                review_root=review_root,
                image_root=image_root,
                seen_hashes=seen_hashes,
                seen_paths=seen_paths,
            )
            for image in raw_images
        )
        if {image.submitted_slot for image in images} != {
            "loading",
            "unloading",
        }:
            raise LockedSetReviewPackageError(
                "each review waybill requires loading and unloading submitted slots"
            )
        seen_sample_ids.add(sample_id)
        seen_candidate_ids.add(candidate_id)
        seen_waybill_identities.add(identity)
        items.append(
            LockedSetReviewItem(
                sample_id=sample_id,
                candidate_id=candidate_id,
                waybill_identity_sha256=identity,
                position=position,
                selection_clues=_selection_clues(
                    raw.get("selection_clues"),
                    label="waybill selection clues",
                ),
                images=cast(
                    tuple[LockedSetReviewImage, LockedSetReviewImage],
                    images,
                ),
            )
        )
    if len(seen_hashes) != 100:
        raise LockedSetReviewPackageError("locked-set review package requires 100 unique images")
    item_tuple = tuple(items)
    return LockedSetReviewPackage(
        package_id=package_id,
        canonical_sha256=declared_hash,
        review_root=review_root,
        items=item_tuple,
        items_by_sample_id={item.sample_id: item for item in item_tuple},
        images_by_sha256={
            image.image_sha256: image for item in item_tuple for image in item.images
        },
        development_authority=development_authority,
    )
