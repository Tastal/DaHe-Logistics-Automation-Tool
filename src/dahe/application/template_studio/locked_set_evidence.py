from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedTicketImage,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_LOCKED_WAYBILL_COUNT = 50
_LOCKED_IMAGE_COUNT = 100


class LockedSetEvidenceStagingError(RuntimeError):
    """Raised when locked-set bytes cannot be safely staged as evidence."""


@dataclass(frozen=True, slots=True)
class StagedLockedImageEvidence:
    image_sha256: str
    relative_path: str
    storage_relative_path: str
    byte_size: int
    media_type: str


@dataclass(frozen=True, slots=True)
class LockedSetEvidenceInventory:
    images: tuple[StagedLockedImageEvidence, ...]


@dataclass(frozen=True, slots=True)
class _VerifiedLockedImage:
    image_sha256: str
    source_path: Path


def _validate_manifest(
    manifest: LockedSetManifest,
) -> tuple[LockedTicketImage, ...]:
    if not isinstance(manifest, LockedSetManifest):
        raise LockedSetEvidenceStagingError("locked-set manifest is invalid")
    if manifest.dataset_kind != "locked" or manifest.tuning_prohibited is not True:
        raise LockedSetEvidenceStagingError("locked-set manifest is not sealed against tuning")
    if (
        manifest.waybill_count != _LOCKED_WAYBILL_COUNT
        or manifest.image_count != _LOCKED_IMAGE_COUNT
    ):
        raise LockedSetEvidenceStagingError(
            "locked-set evidence staging requires 50 waybills and 100 images"
        )

    images = tuple(image for waybill in manifest.waybills for image in waybill.images)
    if any(not isinstance(image, LockedTicketImage) for image in images):
        raise LockedSetEvidenceStagingError("locked-set manifest contains an invalid image record")
    if any(_SHA256_PATTERN.fullmatch(image.image_sha256) is None for image in images):
        raise LockedSetEvidenceStagingError("locked-set image identity must be a lowercase SHA-256")
    if len({image.image_sha256 for image in images}) != _LOCKED_IMAGE_COUNT:
        raise LockedSetEvidenceStagingError(
            "locked-set evidence staging requires 100 unique image identities"
        )
    return tuple(sorted(images, key=lambda image: image.image_sha256))


def _safe_source_path(*, dataset_root: Path, relative_path: str) -> Path:
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or "\\" in relative_path
        or ":" in relative_path
        or relative_path.startswith("//")
    ):
        raise LockedSetEvidenceStagingError(
            "locked-set image path is not a safe POSIX relative path"
        )
    portable = PurePosixPath(relative_path)
    if (
        portable.is_absolute()
        or ".." in portable.parts
        or "." in portable.parts
        or portable.as_posix() != relative_path
    ):
        raise LockedSetEvidenceStagingError("locked-set image path escaped the dataset root")
    try:
        source = (dataset_root / portable).resolve(strict=True)
    except OSError as exc:
        raise LockedSetEvidenceStagingError("locked-set image is missing or unreadable") from exc
    if not source.is_relative_to(dataset_root) or not source.is_file():
        raise LockedSetEvidenceStagingError("locked-set image path escaped the dataset root")
    return source


def _verify_sources(
    *,
    images: tuple[LockedTicketImage, ...],
    dataset_root: Path,
) -> tuple[_VerifiedLockedImage, ...]:
    verified: list[_VerifiedLockedImage] = []
    for image in images:
        source = _safe_source_path(
            dataset_root=dataset_root,
            relative_path=image.relative_path,
        )
        digest = hashlib.sha256()
        byte_count = 0
        try:
            with source.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    byte_count += len(chunk)
        except OSError as exc:
            raise LockedSetEvidenceStagingError(
                "locked-set image is missing or unreadable"
            ) from exc
        if byte_count == 0:
            raise LockedSetEvidenceStagingError("locked-set image cannot be empty")
        if digest.hexdigest() != image.image_sha256:
            raise LockedSetEvidenceStagingError(
                "locked-set image content does not match its sealed SHA-256"
            )
        verified.append(
            _VerifiedLockedImage(
                image_sha256=image.image_sha256,
                source_path=source,
            )
        )
    return tuple(verified)


def _inventory_relative_path(image_sha256: str) -> str:
    return f"evidence/sha256/{image_sha256[:2]}/{image_sha256[2:4]}/{image_sha256}.blob"


def stage_locked_set_evidence(
    *,
    manifest: LockedSetManifest,
    dataset_root: Path,
    evidence_store: ContentAddressedEvidenceStore,
) -> LockedSetEvidenceInventory:
    """Copy verified locked bytes into the truth-free evidence boundary."""

    images = _validate_manifest(manifest)
    try:
        resolved_root = dataset_root.resolve(strict=True)
    except OSError as exc:
        raise LockedSetEvidenceStagingError("locked-set dataset root is unavailable") from exc
    if not resolved_root.is_dir():
        raise LockedSetEvidenceStagingError("locked-set dataset root must be a directory")
    if (
        not isinstance(evidence_store, ContentAddressedEvidenceStore)
        or evidence_store.root.name.casefold() != "evidence"
        or not evidence_store.root.is_dir()
    ):
        raise LockedSetEvidenceStagingError(
            "locked-set evidence store must use the data-root evidence directory"
        )

    # Verify the complete batch before the first durable evidence write.
    verified = _verify_sources(images=images, dataset_root=resolved_root)
    inventory: list[StagedLockedImageEvidence] = []
    for image in verified:
        try:
            content = image.source_path.read_bytes()
            if hashlib.sha256(content).hexdigest() != image.image_sha256:
                raise LockedSetEvidenceStagingError(
                    "locked-set image changed during evidence staging"
                )
            stored = evidence_store.put_bytes(content)
        except LockedSetEvidenceStagingError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise LockedSetEvidenceStagingError(
                "locked-set evidence could not be stored safely"
            ) from exc
        expected_relative_path = _inventory_relative_path(image.image_sha256)
        actual_relative_path = f"evidence/{stored.relative_path}"
        if stored.sha256 != image.image_sha256 or actual_relative_path != expected_relative_path:
            raise LockedSetEvidenceStagingError(
                "locked-set evidence identity did not reconcile after storage"
            )
        inventory.append(
            StagedLockedImageEvidence(
                image_sha256=image.image_sha256,
                relative_path=expected_relative_path,
                storage_relative_path=stored.relative_path,
                byte_size=stored.byte_size,
                media_type=stored.media_type,
            )
        )

    return LockedSetEvidenceInventory(images=tuple(inventory))
