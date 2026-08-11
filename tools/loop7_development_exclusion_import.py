from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import cast

from PIL import Image, UnidentifiedImageError

from dahe import __version__
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.sqlite.locked_set import (
    DevelopmentExclusionEvidence,
    DevelopmentExclusionImportOutcome,
    SqliteLockedSetRepository,
)
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewAuthoritySnapshot,
    LockedSetReviewRecord,
    SqliteLockedSetReviewRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewFormalExport,
    build_candidate_review_formal_export,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.verification.image_similarity import (
    ImageSimilarityContractError,
    build_image_fingerprint,
)
from dahe.verification.legacy_locked_set_candidates import (
    SUPPORTED_IMAGE_SUFFIXES,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImageChangedError,
    LockedSetReviewPackage,
    load_locked_set_review_package,
)

ROOT = Path(__file__).resolve().parents[1]
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DEVELOPMENT_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "development_only",
        "formal_release_eligible",
        "reason",
        "dataset_id",
        "package_sha256",
        "record_count",
        "record_set_sha256",
        "history_record_count",
        "review_history_authority_sha256",
        "verified_image_count",
        "verified_image_set_sha256",
        "manifest_sha256",
        "quality_coverage_sha256",
        "source_authority_sha256",
        "snapshot_sha256",
    }
)
_EXTERNAL_EXCLUSION_FIELDS = frozenset(
    {
        "schema_version",
        "image_identity_count",
        "waybill_identity_count",
        "source_file_sha256s",
        "canonical_sha256",
        "image_sha256s",
        "waybill_identity_sha256s",
    }
)
_MEDIA_TYPES = {
    "BMP": "image/bmp",
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "TIFF": "image/tiff",
    "WEBP": "image/webp",
}


class DevelopmentExclusionImportError(RuntimeError):
    """Raised when a development exclusion import cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class RootContract:
    review_data_root: Path
    development_snapshot: Path
    data_root: Path
    image_roots: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class ValidatedDevelopmentSnapshot:
    snapshot_sha256: str
    dataset_id: str
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class ExternalExclusions:
    canonical_sha256: str
    image_sha256s: frozenset[str]
    waybill_identity_sha256s: frozenset[str]


@dataclass(frozen=True, slots=True)
class DevelopmentImportAuthority:
    canonical_sha256: str
    development_image_sha256s: tuple[str, ...]
    prior_waybill_identity_sha256s: tuple[str, ...]
    development_image_set_sha256: str
    prior_waybill_identity_set_sha256: str
    payload: dict[str, object]


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DevelopmentExclusionImportError("authority contains invalid JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _absolute_path(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(candidate)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Import a completed candidate-review set and all inherited "
            "exclusions into an isolated development evidence profile."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--review-data-root",
        type=_absolute_path,
        required=True,
        help=(
            "Absolute source application-data root containing the "
            "candidate review package and review database."
        ),
    )
    parser.add_argument(
        "--development-snapshot",
        type=_absolute_path,
        required=True,
        help=("Absolute development-only snapshot created by loop7_candidate_review_export.py."),
    )
    parser.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
        help="Absolute isolated target application-data root.",
    )
    parser.add_argument(
        "--image-root",
        type=_absolute_path,
        action="append",
        required=True,
        help=(
            "Absolute read-only image root used only to locate inherited "
            "image SHA-256 identities. Repeat for additional isolated roots."
        ),
    )
    return parser


def _is_path_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _assert_path_chain_has_no_links(
    path: Path,
    *,
    label: str,
) -> None:
    candidates: list[Path] = []
    current = path
    while True:
        candidates.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(candidates):
        if _is_path_link(candidate):
            raise DevelopmentExclusionImportError(f"{label} must not contain a path link")


def _existing_directory(path: Path, *, label: str) -> Path:
    _assert_path_chain_has_no_links(path, label=label)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DevelopmentExclusionImportError(f"{label} is unavailable") from exc
    if not resolved.is_dir():
        raise DevelopmentExclusionImportError(f"{label} must be a directory")
    return resolved


def _target_directory(path: Path) -> Path:
    _assert_path_chain_has_no_links(
        path,
        label="target data root",
    )
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise DevelopmentExclusionImportError("target data root cannot be resolved safely") from exc
    if resolved.exists() and not resolved.is_dir():
        raise DevelopmentExclusionImportError("target data root must be a directory")
    return resolved


def _existing_json_file(path: Path, *, label: str) -> Path:
    _assert_path_chain_has_no_links(path, label=label)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DevelopmentExclusionImportError(f"{label} is unavailable") from exc
    if not resolved.is_file() or resolved.suffix.lower() != ".json":
        raise DevelopmentExclusionImportError(f"{label} must be a JSON file")
    return resolved


def _same_or_descendant(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _paths_overlap(first: Path, second: Path) -> bool:
    return _same_or_descendant(
        first,
        second,
    ) or _same_or_descendant(second, first)


def _path_key(path: Path) -> str:
    return os.path.normcase(os.fspath(path))


def _validate_root_contract(
    *,
    review_data_root: Path,
    development_snapshot: Path,
    data_root: Path,
    image_roots: Sequence[Path],
) -> RootContract:
    source = _existing_directory(
        review_data_root,
        label="review data root",
    )
    snapshot = _existing_json_file(
        development_snapshot,
        label="development snapshot",
    )
    target = _target_directory(data_root)
    roots = tuple(
        _existing_directory(
            root,
            label="image root",
        )
        for root in image_roots
    )
    if not roots:
        raise DevelopmentExclusionImportError("at least one image root is required")
    keys = tuple(_path_key(root) for root in roots)
    if len(keys) != len(set(keys)):
        raise DevelopmentExclusionImportError("image-root parameters contain a duplicate")

    named_roots = (
        ("review data root", source),
        ("target data root", target),
        *((f"image root {index}", root) for index, root in enumerate(roots, start=1)),
    )
    for index, (first_label, first) in enumerate(named_roots):
        for second_label, second in named_roots[index + 1 :]:
            if _paths_overlap(first, second):
                raise DevelopmentExclusionImportError(f"{first_label} and {second_label} overlap")
    if any(_same_or_descendant(snapshot, root) for _, root in named_roots):
        raise DevelopmentExclusionImportError(
            "development snapshot must stay outside all data and image roots"
        )
    return RootContract(
        review_data_root=source,
        development_snapshot=snapshot,
        data_root=target,
        image_roots=tuple(sorted(roots, key=_path_key)),
    )


def _read_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DevelopmentExclusionImportError(f"{label} is not readable JSON") from exc
    if not isinstance(value, dict):
        raise DevelopmentExclusionImportError(f"{label} must contain a JSON object")
    return cast(dict[str, object], value)


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise DevelopmentExclusionImportError(f"{label} must be a lowercase SHA-256")
    return value


def _required_text(
    value: object,
    *,
    label: str,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise DevelopmentExclusionImportError(f"{label} is required")
    normalized = value.strip()
    if not normalized or normalized != value or len(normalized) > maximum:
        raise DevelopmentExclusionImportError(f"{label} is invalid")
    return normalized


def _required_count(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DevelopmentExclusionImportError(f"{label} must be a non-negative integer")
    return value


def _validate_development_snapshot(
    path: Path,
    *,
    package: LockedSetReviewPackage,
    authority: LockedSetReviewAuthoritySnapshot,
    formal_export: CandidateReviewFormalExport,
) -> ValidatedDevelopmentSnapshot:
    if (
        authority.package_sha256 != package.canonical_sha256
        or _canonical_sha256(authority.payload) != authority.canonical_sha256
    ):
        raise DevelopmentExclusionImportError(
            "confirmed review authority does not match the review package"
        )
    payload = _read_json_object(
        path,
        label="development snapshot",
    )
    if (
        set(payload) != _DEVELOPMENT_SNAPSHOT_FIELDS
        or payload.get("schema_version") != 1
        or payload.get("kind") != "candidate_review_development_snapshot"
    ):
        raise DevelopmentExclusionImportError("development snapshot contract is unsupported")
    if (
        payload.get("development_only") is not True
        or payload.get("formal_release_eligible") is not False
    ):
        raise DevelopmentExclusionImportError("development snapshot must be nonformal")
    _required_text(
        payload.get("reason"),
        label="development snapshot reason",
        maximum=2000,
    )
    dataset_id = _required_text(
        payload.get("dataset_id"),
        label="development snapshot dataset ID",
        maximum=200,
    )
    declared_snapshot_sha256 = _required_sha256(
        payload.get("snapshot_sha256"),
        label="development snapshot SHA-256",
    )
    without_hash = dict(payload)
    without_hash.pop("snapshot_sha256")
    if _canonical_sha256(without_hash) != declared_snapshot_sha256:
        raise DevelopmentExclusionImportError("development snapshot SHA-256 does not match")

    source = formal_export.source_authority_payload
    expected_bindings: dict[str, object] = {
        "dataset_id": formal_export.manifest.dataset_id,
        "package_sha256": package.canonical_sha256,
        "record_count": len(authority.latest_records),
        "record_set_sha256": (formal_export.record_set_sha256),
        "history_record_count": len(authority.history_records),
        "review_history_authority_sha256": (authority.canonical_sha256),
        "verified_image_count": source.get("verified_image_count"),
        "verified_image_set_sha256": source.get("verified_image_set_sha256"),
        "manifest_sha256": formal_export.manifest_sha256,
        "quality_coverage_sha256": (formal_export.quality_coverage_sha256),
        "source_authority_sha256": (formal_export.source_authority_sha256),
    }
    if (
        dataset_id != formal_export.manifest.dataset_id
        or any(payload.get(field) != expected for field, expected in expected_bindings.items())
        or _required_count(
            payload.get("record_count"),
            label="development snapshot record count",
        )
        != 50
        or _required_count(
            payload.get("verified_image_count"),
            label="development snapshot image count",
        )
        != 100
    ):
        raise DevelopmentExclusionImportError(
            "development snapshot authority bindings do not reconcile"
        )
    for field in (
        "package_sha256",
        "record_set_sha256",
        "review_history_authority_sha256",
        "verified_image_set_sha256",
        "manifest_sha256",
        "quality_coverage_sha256",
        "source_authority_sha256",
    ):
        _required_sha256(
            payload.get(field),
            label=f"development snapshot {field}",
        )
    return ValidatedDevelopmentSnapshot(
        snapshot_sha256=declared_snapshot_sha256,
        dataset_id=dataset_id,
        payload=payload,
    )


def _reviewer_id(
    records: Sequence[LockedSetReviewRecord],
) -> str:
    reviewers: set[str] = set()
    for record in records:
        raw_reviewer = record.review_payload.get("reviewer_id")
        reviewers.add(
            _required_text(
                raw_reviewer,
                label="confirmed review reviewer",
                maximum=100,
            )
        )
    if len(records) != 50 or len(reviewers) != 1:
        raise DevelopmentExclusionImportError(
            "confirmed review authority must have one fixed reviewer"
        )
    return next(iter(reviewers))


def _sha256_list(
    value: object,
    *,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise DevelopmentExclusionImportError(f"{label} must be an array")
    hashes = tuple(_required_sha256(item, label=label) for item in value)
    if tuple(sorted(hashes)) != hashes or len(hashes) != len(set(hashes)):
        raise DevelopmentExclusionImportError(f"{label} must be sorted and unique")
    return hashes


def _load_external_exclusions(
    *,
    package: LockedSetReviewPackage,
    review_data_root: Path,
) -> ExternalExclusions:
    path = package.review_root / "external-exclusion-snapshot.json"
    _assert_path_chain_has_no_links(
        path,
        label="external exclusion snapshot",
    )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DevelopmentExclusionImportError("external exclusion snapshot is unavailable") from exc
    if not resolved.is_file() or not _same_or_descendant(
        resolved,
        package.review_root,
    ):
        raise DevelopmentExclusionImportError(
            "external exclusion snapshot escaped the review package"
        )
    payload = _read_json_object(
        resolved,
        label="external exclusion snapshot",
    )
    if set(payload) != _EXTERNAL_EXCLUSION_FIELDS or payload.get("schema_version") != 1:
        raise DevelopmentExclusionImportError("external exclusion snapshot contract is unsupported")
    image_hashes = _sha256_list(
        payload.get("image_sha256s"),
        label="external image SHA-256",
    )
    waybill_hashes = _sha256_list(
        payload.get("waybill_identity_sha256s"),
        label="external waybill SHA-256",
    )
    source_file_hashes = _sha256_list(
        payload.get("source_file_sha256s"),
        label="external source-file SHA-256",
    )
    if _required_count(
        payload.get("image_identity_count"),
        label="external image count",
    ) != len(image_hashes) or _required_count(
        payload.get("waybill_identity_count"),
        label="external waybill count",
    ) != len(waybill_hashes):
        raise DevelopmentExclusionImportError("external exclusion snapshot counts do not reconcile")
    core = {
        "image_sha256s": list(image_hashes),
        "schema_version": 1,
        "source_file_sha256s": list(source_file_hashes),
        "waybill_identity_sha256s": list(waybill_hashes),
    }
    canonical_sha256 = _required_sha256(
        payload.get("canonical_sha256"),
        label="external exclusion snapshot SHA-256",
    )
    if _canonical_sha256(core) != canonical_sha256:
        raise DevelopmentExclusionImportError("external exclusion snapshot SHA-256 does not match")

    reloaded = load_locked_set_review_package(review_data_root)
    if (
        reloaded.canonical_sha256 != package.canonical_sha256
        or reloaded.review_root != package.review_root
    ):
        raise DevelopmentExclusionImportError("review package changed while reading exclusions")
    return ExternalExclusions(
        canonical_sha256=canonical_sha256,
        image_sha256s=frozenset(image_hashes),
        waybill_identity_sha256s=frozenset(waybill_hashes),
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(
                lambda: source.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)
    except OSError as exc:
        raise DevelopmentExclusionImportError("image evidence is unreadable") from exc
    return digest.hexdigest()


def _resolve_prior_image_paths(
    *,
    image_roots: Sequence[Path],
    expected_sha256s: frozenset[str],
) -> dict[str, Path]:
    for digest in expected_sha256s:
        _required_sha256(
            digest,
            label="expected prior image SHA-256",
        )
    found: dict[str, Path] = {}
    for root in sorted(image_roots, key=_path_key):
        for current, directory_names, file_names in os.walk(
            root,
            followlinks=False,
        ):
            current_path = Path(current)
            for name in directory_names:
                candidate = current_path / name
                if _is_path_link(candidate):
                    raise DevelopmentExclusionImportError("image root contains a path link")
            directory_names[:] = sorted(directory_names)
            for name in sorted(file_names):
                candidate = current_path / name
                if _is_path_link(candidate):
                    raise DevelopmentExclusionImportError("image root contains a path link")
                if candidate.suffix.lower() not in SUPPORTED_IMAGE_SUFFIXES:
                    continue
                if not candidate.is_file():
                    raise DevelopmentExclusionImportError("image root contains a non-file entry")
                digest = _file_sha256(candidate)
                if digest in expected_sha256s:
                    found.setdefault(digest, candidate)
    missing = expected_sha256s.difference(found)
    if missing:
        raise DevelopmentExclusionImportError("one or more inherited image identities are missing")
    return {digest: found[digest] for digest in sorted(found)}


def _media_type(content: bytes) -> str:
    try:
        with Image.open(BytesIO(content)) as image:
            image.verify()
            media_type = _MEDIA_TYPES.get(str(image.format).upper())
    except (
        OSError,
        SyntaxError,
        ValueError,
        UnidentifiedImageError,
    ) as exc:
        raise DevelopmentExclusionImportError("image evidence is not a supported image") from exc
    if media_type is None:
        raise DevelopmentExclusionImportError("image evidence media type is unsupported")
    return media_type


def _prepare_one_image(
    *,
    content: bytes,
    expected_sha256: str,
    evidence_store: ContentAddressedEvidenceStore,
    expected_media_type: str | None = None,
) -> DevelopmentExclusionEvidence:
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise DevelopmentExclusionImportError("image evidence changed before import")
    media_type = _media_type(content)
    if expected_media_type is not None and media_type != expected_media_type:
        raise DevelopmentExclusionImportError("review image media type changed before import")
    try:
        fingerprint = build_image_fingerprint(content)
    except ImageSimilarityContractError as exc:
        raise DevelopmentExclusionImportError(
            "image evidence cannot produce a code-owned fingerprint"
        ) from exc
    stored = evidence_store.put_bytes(
        content,
        media_type=media_type,
    )
    if stored.sha256 != expected_sha256 or evidence_store.read_bytes(expected_sha256) != content:
        raise DevelopmentExclusionImportError(
            "target content-addressed evidence verification failed"
        )
    return DevelopmentExclusionEvidence(
        image_sha256=stored.sha256,
        storage_relative_path=stored.relative_path,
        byte_size=stored.byte_size,
        media_type=stored.media_type,
        perceptual_fingerprint=fingerprint,
    )


def _read_prior_image(
    path: Path,
    *,
    expected_sha256: str,
) -> bytes:
    _assert_path_chain_has_no_links(
        path,
        label="prior image",
    )
    try:
        if not path.is_file():
            raise OSError
        content = path.read_bytes()
    except OSError as exc:
        raise DevelopmentExclusionImportError("prior image is unavailable") from exc
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise DevelopmentExclusionImportError("prior image changed after resolution")
    return content


def _prepare_import_images(
    *,
    package: LockedSetReviewPackage,
    prior_image_paths: Mapping[str, Path],
    data_root: Path,
) -> tuple[DevelopmentExclusionEvidence, ...]:
    store = ContentAddressedEvidenceStore(data_root / "evidence")
    prepared: list[DevelopmentExclusionEvidence] = []
    for image_sha256 in sorted(package.images_by_sha256):
        package_image = package.images_by_sha256[image_sha256]
        lexical_path = package.review_root / Path(package_image.relative_path)
        _assert_path_chain_has_no_links(
            lexical_path,
            label="review package image",
        )
        try:
            content, media_type = package.read_verified_image(image_sha256)
        except LockedSetReviewImageChangedError as exc:
            raise DevelopmentExclusionImportError(
                "review package image changed before import"
            ) from exc
        prepared.append(
            _prepare_one_image(
                content=content,
                expected_sha256=image_sha256,
                evidence_store=store,
                expected_media_type=media_type,
            )
        )
    for image_sha256, path in sorted(prior_image_paths.items()):
        prepared.append(
            _prepare_one_image(
                content=_read_prior_image(
                    path,
                    expected_sha256=image_sha256,
                ),
                expected_sha256=image_sha256,
                evidence_store=store,
            )
        )
    if len(prepared) != len({image.image_sha256 for image in prepared}):
        raise DevelopmentExclusionImportError("development image identities overlap")
    return tuple(
        sorted(
            prepared,
            key=lambda image: image.image_sha256,
        )
    )


def _set_sha256(
    *,
    kind: str,
    identities: Sequence[str],
) -> str:
    return _canonical_sha256(
        {
            "schema_version": 1,
            "kind": kind,
            "identities": list(identities),
        }
    )


def _build_import_authority(
    *,
    package: LockedSetReviewPackage,
    development_snapshot: ValidatedDevelopmentSnapshot,
    formal_export: CandidateReviewFormalExport,
    external_exclusions: ExternalExclusions,
) -> DevelopmentImportAuthority:
    current_images = frozenset(package.images_by_sha256)
    current_waybills = frozenset(item.waybill_identity_sha256 for item in package.items)
    if len(current_images) != 100 or len(current_waybills) != 50:
        raise DevelopmentExclusionImportError("candidate review package membership is incomplete")
    if current_images.intersection(
        external_exclusions.image_sha256s
    ) or current_waybills.intersection(external_exclusions.waybill_identity_sha256s):
        raise DevelopmentExclusionImportError("current and inherited exclusion identities overlap")
    image_sha256s = tuple(sorted(current_images | external_exclusions.image_sha256s))
    waybill_sha256s = tuple(sorted(current_waybills | external_exclusions.waybill_identity_sha256s))
    image_set_sha256 = _set_sha256(
        kind="development_image_set",
        identities=image_sha256s,
    )
    waybill_set_sha256 = _set_sha256(
        kind="prior_waybill_identity_set",
        identities=waybill_sha256s,
    )
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "candidate_review_development_exclusion_import",
        "development_snapshot_sha256": (development_snapshot.snapshot_sha256),
        "package_sha256": package.canonical_sha256,
        "record_set_sha256": (formal_export.record_set_sha256),
        "review_history_authority_sha256": (
            development_snapshot.payload["review_history_authority_sha256"]
        ),
        "source_authority_sha256": (formal_export.source_authority_sha256),
        "manifest_sha256": formal_export.manifest_sha256,
        "quality_coverage_sha256": (formal_export.quality_coverage_sha256),
        "external_exclusion_snapshot_sha256": (external_exclusions.canonical_sha256),
        "development_image_count": len(image_sha256s),
        "development_image_set_sha256": image_set_sha256,
        "prior_waybill_identity_count": len(waybill_sha256s),
        "prior_waybill_identity_set_sha256": (waybill_set_sha256),
    }
    return DevelopmentImportAuthority(
        canonical_sha256=_canonical_sha256(payload),
        development_image_sha256s=image_sha256s,
        prior_waybill_identity_sha256s=waybill_sha256s,
        development_image_set_sha256=image_set_sha256,
        prior_waybill_identity_set_sha256=(waybill_set_sha256),
        payload=payload,
    )


def _config(data_root: Path) -> AppConfig:
    return AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=data_root,
    )


def _review_authority(
    *,
    data_root: Path,
    instance_id: str,
    package_sha256: str,
) -> LockedSetReviewAuthoritySnapshot:
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=ROOT,
        instance_id=instance_id,
    )
    try:
        return SqliteLockedSetReviewRepository(
            runtime=runtime,
            package_sha256=package_sha256,
        ).build_authority_snapshot()
    finally:
        runtime.close()


def _import_target(
    *,
    data_root: Path,
    instance_id: str,
    authority: DevelopmentImportAuthority,
    images: Sequence[DevelopmentExclusionEvidence],
) -> DevelopmentExclusionImportOutcome:
    if {image.image_sha256 for image in images} != set(authority.development_image_sha256s):
        raise DevelopmentExclusionImportError("prepared evidence does not match import authority")
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=ROOT,
        instance_id=instance_id,
    )
    try:
        return SqliteLockedSetRepository(runtime=runtime).import_development_exclusions(
            source_authority_sha256=(authority.canonical_sha256),
            images=images,
            waybill_identity_sha256s=(authority.prior_waybill_identity_sha256s),
        )
    finally:
        runtime.close()


def _locked_guards(
    stack: ExitStack,
    *,
    source_root: Path,
    source_config: AppConfig,
    target_root: Path,
    target_config: AppConfig,
) -> dict[str, SingleInstanceGuard]:
    profiles = (
        ("source", source_root, source_config),
        ("target", target_root, target_config),
    )
    guards: dict[str, SingleInstanceGuard] = {}
    for name, data_root, config in sorted(
        profiles,
        key=lambda profile: _path_key(profile[1]),
    ):
        guards[name] = stack.enter_context(
            SingleInstanceGuard(
                data_root,
                config.port,
                __version__,
            )
        )
    return guards


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    contract = _validate_root_contract(
        review_data_root=arguments.review_data_root,
        development_snapshot=arguments.development_snapshot,
        data_root=arguments.data_root,
        image_roots=tuple(arguments.image_root),
    )
    source_config = _config(contract.review_data_root)
    target_config = _config(contract.data_root)
    source_root = prepare_startup_environment(
        source_config,
        ROOT,
    )
    target_root = prepare_startup_environment(
        target_config,
        ROOT,
    )
    refreshed = _validate_root_contract(
        review_data_root=source_root,
        development_snapshot=(contract.development_snapshot),
        data_root=target_root,
        image_roots=contract.image_roots,
    )
    if (
        refreshed.review_data_root != contract.review_data_root
        or refreshed.data_root != contract.data_root
        or refreshed.image_roots != contract.image_roots
    ):
        raise DevelopmentExclusionImportError("prepared data roots changed identity")

    with ExitStack() as stack:
        guards = _locked_guards(
            stack,
            source_root=source_root,
            source_config=source_config,
            target_root=target_root,
            target_config=target_config,
        )
        package = load_locked_set_review_package(source_root)
        review_authority = _review_authority(
            data_root=source_root,
            instance_id=guards["source"].instance_id,
            package_sha256=package.canonical_sha256,
        )
        reviewer_id = _reviewer_id(review_authority.latest_records)
        snapshot_payload = _read_json_object(
            contract.development_snapshot,
            label="development snapshot",
        )
        dataset_id = _required_text(
            snapshot_payload.get("dataset_id"),
            label="development snapshot dataset ID",
            maximum=200,
        )
        formal_export = build_candidate_review_formal_export(
            package=package,
            records=review_authority.latest_records,
            configured_reviewer_id=reviewer_id,
            dataset_id=dataset_id,
        )
        development_snapshot = _validate_development_snapshot(
            contract.development_snapshot,
            package=package,
            authority=review_authority,
            formal_export=formal_export,
        )
        external_exclusions = _load_external_exclusions(
            package=package,
            review_data_root=source_root,
        )
        import_authority = _build_import_authority(
            package=package,
            development_snapshot=development_snapshot,
            formal_export=formal_export,
            external_exclusions=external_exclusions,
        )
        prior_image_paths = _resolve_prior_image_paths(
            image_roots=contract.image_roots,
            expected_sha256s=(external_exclusions.image_sha256s),
        )
        prepared_images = _prepare_import_images(
            package=package,
            prior_image_paths=prior_image_paths,
            data_root=target_root,
        )
        outcome = _import_target(
            data_root=target_root,
            instance_id=guards["target"].instance_id,
            authority=import_authority,
            images=prepared_images,
        )

    print(
        json.dumps(
            {
                "applied": outcome.applied,
                "development_image_count": (outcome.development_image_count),
                "development_image_set_sha256": (import_authority.development_image_set_sha256),
                "import_authority_sha256": (outcome.source_authority_sha256),
                "prior_waybill_identity_count": (outcome.prior_waybill_identity_count),
                "prior_waybill_identity_set_sha256": (
                    import_authority.prior_waybill_identity_set_sha256
                ),
                "status": (
                    "development_exclusions_imported"
                    if outcome.applied
                    else "development_exclusions_already_imported"
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
