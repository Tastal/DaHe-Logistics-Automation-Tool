from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import cast

from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class LockedSetContractError(ValueError):
    """Raised when an acceptance set is not independent or fully labeled."""


def source_waybill_identity_sha256(
    *,
    source_namespace: str,
    source_id: str,
) -> str:
    """Create one stable de-identified identity shared by import and review."""

    namespace = source_namespace.strip()
    identity = source_id.strip()
    if not namespace or not identity:
        raise LockedSetContractError("source waybill namespace and identity are required")
    if namespace == "chengfeng_waybill_no":
        return hashlib.sha256(
            b"dahe:persisted-waybill-identity:v1\0"
            + identity.encode("utf-8")
        ).hexdigest()
    return _canonical_sha256(
        {
            "schema_version": 1,
            "source_id": identity,
            "source_namespace": namespace,
        }
    )


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validated_hashes(
    values: set[str] | frozenset[str],
    *,
    label: str,
) -> frozenset[str]:
    normalized = frozenset(values)
    if any(SHA256_PATTERN.fullmatch(value) is None for value in normalized):
        raise LockedSetContractError(f"{label} contains an invalid SHA-256")
    return normalized


@dataclass(frozen=True, slots=True)
class LockedSetExclusionSnapshot:
    """A sourced, content-addressed inventory of every release exclusion."""

    source_id: str
    template_reference_image_hashes: frozenset[str]
    development_image_hashes: frozenset[str]
    calibration_image_hashes: frozenset[str]
    shadow_image_hashes: frozenset[str]
    prior_locked_image_hashes: frozenset[str]
    prior_waybill_identity_hashes: frozenset[str]
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise LockedSetContractError("exclusion snapshot source is required")
        for label, values in (
            (
                "template reference exclusions",
                self.template_reference_image_hashes,
            ),
            ("development exclusions", self.development_image_hashes),
            ("calibration exclusions", self.calibration_image_hashes),
            ("shadow exclusions", self.shadow_image_hashes),
            ("prior locked-image exclusions", self.prior_locked_image_hashes),
            (
                "prior waybill identity exclusions",
                self.prior_waybill_identity_hashes,
            ),
        ):
            if not isinstance(values, frozenset):
                raise LockedSetContractError(f"{label} must be a frozen identity set")
            _validated_hashes(values, label=label)
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    @classmethod
    def create(
        cls,
        *,
        source_id: str,
        template_reference_image_hashes: set[str] | frozenset[str],
        development_image_hashes: set[str] | frozenset[str],
        calibration_image_hashes: set[str] | frozenset[str],
        shadow_image_hashes: set[str] | frozenset[str],
        prior_locked_image_hashes: set[str] | frozenset[str],
        prior_waybill_identity_hashes: set[str] | frozenset[str],
    ) -> LockedSetExclusionSnapshot:
        return cls(
            source_id=source_id.strip(),
            template_reference_image_hashes=_validated_hashes(
                template_reference_image_hashes,
                label="template reference exclusions",
            ),
            development_image_hashes=_validated_hashes(
                development_image_hashes,
                label="development exclusions",
            ),
            calibration_image_hashes=_validated_hashes(
                calibration_image_hashes,
                label="calibration exclusions",
            ),
            shadow_image_hashes=_validated_hashes(
                shadow_image_hashes,
                label="shadow exclusions",
            ),
            prior_locked_image_hashes=_validated_hashes(
                prior_locked_image_hashes,
                label="prior locked-image exclusions",
            ),
            prior_waybill_identity_hashes=_validated_hashes(
                prior_waybill_identity_hashes,
                label="prior waybill identity exclusions",
            ),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "calibration_image_hashes": sorted(self.calibration_image_hashes),
            "development_image_hashes": sorted(self.development_image_hashes),
            "prior_locked_image_hashes": sorted(self.prior_locked_image_hashes),
            "prior_waybill_identity_hashes": sorted(self.prior_waybill_identity_hashes),
            "schema_version": 1,
            "shadow_image_hashes": sorted(self.shadow_image_hashes),
            "source_id": self.source_id,
            "template_reference_image_hashes": sorted(self.template_reference_image_hashes),
        }

    @property
    def exclusion_counts(self) -> dict[str, int]:
        return {
            "calibration_images": len(self.calibration_image_hashes),
            "development_images": len(self.development_image_hashes),
            "prior_locked_images": len(self.prior_locked_image_hashes),
            "prior_waybill_identities": len(self.prior_waybill_identity_hashes),
            "shadow_images": len(self.shadow_image_hashes),
            "template_reference_images": len(self.template_reference_image_hashes),
        }


@dataclass(frozen=True, slots=True)
class LockedTicketImage:
    image_sha256: str
    relative_path: str
    slot: TicketSlot
    role: TicketRole
    ordinary_net: Decimal | None


@dataclass(frozen=True, slots=True)
class LockedWaybill:
    sample_id: str
    waybill_identity_sha256: str
    images: tuple[LockedTicketImage, LockedTicketImage]


@dataclass(frozen=True, slots=True)
class LockedSetManifest:
    dataset_id: str
    dataset_kind: str
    tuning_prohibited: bool
    waybills: tuple[LockedWaybill, ...]

    @property
    def waybill_count(self) -> int:
        return len(self.waybills)

    @property
    def image_count(self) -> int:
        return sum(len(waybill.images) for waybill in self.waybills)

    @property
    def canonical_sha256(self) -> str:
        return _canonical_manifest_sha256(self)


@dataclass(frozen=True, slots=True)
class LockedSetFileVerification:
    manifest_sha256: str
    image_count: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class LockedSetReleaseAttestation:
    dataset_id: str
    manifest_sha256: str
    exclusion_source_id: str
    exclusion_snapshot_sha256: str
    waybill_count: int
    image_count: int
    total_bytes: int
    exclusion_counts: dict[str, int]
    attestation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "attestation_sha256",
            _canonical_sha256(
                {
                    "dataset_id": self.dataset_id,
                    "exclusion_counts": self.exclusion_counts,
                    "exclusion_snapshot_sha256": (self.exclusion_snapshot_sha256),
                    "exclusion_source_id": self.exclusion_source_id,
                    "image_count": self.image_count,
                    "manifest_sha256": self.manifest_sha256,
                    "schema_version": 1,
                    "total_bytes": self.total_bytes,
                    "waybill_count": self.waybill_count,
                }
            ),
        )


def _object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LockedSetContractError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LockedSetContractError(f"{label} must be a non-empty string")
    return value.strip()


def _relative_path(value: object) -> str:
    raw = _text(value, label="image relative path")
    if "\\" in raw or ":" in raw or raw.startswith("//"):
        raise LockedSetContractError("image relative path must be a safe POSIX path")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise LockedSetContractError("image relative path must stay inside the dataset")
    return path.as_posix()


def _ordinary_net(
    value: object,
    *,
    role: TicketRole,
) -> Decimal | None:
    if value is None:
        if role is TicketRole.UNKNOWN:
            return None
        raise LockedSetContractError("a loading or unloading ticket requires ordinary net truth")
    if not isinstance(value, str):
        raise LockedSetContractError("ordinary net must be human-confirmed text")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise LockedSetContractError("ordinary net must be a decimal tonne value") from exc
    if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent != -2:
        raise LockedSetContractError("ordinary net must use two decimal tonne precision")
    return amount


def _load_image(
    raw: object,
    *,
    seen_hashes: set[str],
    template_reference_hashes: frozenset[str],
) -> LockedTicketImage:
    image = _object(raw, label="locked image")
    sha256 = _text(image.get("image_sha256"), label="image SHA-256")
    if SHA256_PATTERN.fullmatch(sha256) is None:
        raise LockedSetContractError("image SHA-256 must be 64 lowercase hexadecimal characters")
    if sha256 in seen_hashes:
        raise LockedSetContractError("duplicate image hashes are not allowed in the locked set")
    if sha256 in template_reference_hashes:
        raise LockedSetContractError(
            "locked set contains an excluded image identity from a template reference"
        )
    seen_hashes.add(sha256)

    slot_text = _text(image.get("submitted_slot"), label="submitted slot")
    try:
        slot = TicketSlot(slot_text)
    except ValueError as exc:
        raise LockedSetContractError("submitted slot must be loading or unloading") from exc
    role_text = _text(image.get("role"), label="human-confirmed role")
    try:
        role = TicketRole(role_text)
    except ValueError as exc:
        raise LockedSetContractError(
            "human-confirmed role must be loading, unloading, or unknown"
        ) from exc
    return LockedTicketImage(
        image_sha256=sha256,
        relative_path=_relative_path(image.get("relative_path")),
        slot=slot,
        role=role,
        ordinary_net=_ordinary_net(image.get("ordinary_net"), role=role),
    )


def _load_locked_set_manifest(
    path: Path,
    *,
    template_reference_hashes: set[str] | frozenset[str],
) -> LockedSetManifest:
    try:
        root = _object(json.loads(path.read_text(encoding="utf-8")), label="manifest")
    except (OSError, json.JSONDecodeError) as exc:
        raise LockedSetContractError("locked-set manifest is not readable JSON") from exc
    if root.get("schema_version") != 1:
        raise LockedSetContractError("locked-set schema version is unsupported")
    if root.get("dataset_kind") != "locked" or root.get("tuning_prohibited") is not True:
        raise LockedSetContractError("locked set must prohibit tuning")

    raw_waybills = root.get("waybills")
    if not isinstance(raw_waybills, list) or len(raw_waybills) != 50:
        raise LockedSetContractError("locked set must contain exactly 50 waybills")

    reference_hashes = frozenset(template_reference_hashes)
    if any(SHA256_PATTERN.fullmatch(value) is None for value in reference_hashes):
        raise LockedSetContractError("template reference hash is invalid")
    seen_hashes: set[str] = set()
    seen_sample_ids: set[str] = set()
    seen_waybill_identities: set[str] = set()
    waybills: list[LockedWaybill] = []
    for raw_waybill in raw_waybills:
        waybill = _object(raw_waybill, label="locked waybill")
        sample_id = _text(waybill.get("sample_id"), label="sample ID")
        if sample_id in seen_sample_ids:
            raise LockedSetContractError("locked-set sample IDs must be unique")
        seen_sample_ids.add(sample_id)
        waybill_identity = _text(
            waybill.get("waybill_identity_sha256"),
            label="waybill identity SHA-256",
        )
        if SHA256_PATTERN.fullmatch(waybill_identity) is None:
            raise LockedSetContractError("waybill identity must be a lowercase SHA-256")
        if waybill_identity in seen_waybill_identities:
            raise LockedSetContractError("locked-set waybill identities must be unique")
        seen_waybill_identities.add(waybill_identity)
        if waybill.get("human_confirmed") is not True:
            raise LockedSetContractError("every locked waybill requires human confirmation")
        if waybill.get("label_source") != "direct_image_review":
            raise LockedSetContractError("locked labels must come from direct image review")
        raw_images = waybill.get("images")
        if not isinstance(raw_images, list) or len(raw_images) != 2:
            raise LockedSetContractError("each locked waybill must contain exactly two images")
        images = tuple(
            _load_image(
                raw_image,
                seen_hashes=seen_hashes,
                template_reference_hashes=reference_hashes,
            )
            for raw_image in raw_images
        )
        slots = {image.slot for image in images}
        if slots != {TicketSlot.LOADING, TicketSlot.UNLOADING}:
            raise LockedSetContractError(
                "each locked waybill needs one image for each submitted slot"
            )
        waybills.append(
            LockedWaybill(
                sample_id=sample_id,
                waybill_identity_sha256=waybill_identity,
                images=cast(tuple[LockedTicketImage, LockedTicketImage], images),
            )
        )

    return LockedSetManifest(
        dataset_id=_text(root.get("dataset_id"), label="dataset ID"),
        dataset_kind="locked",
        tuning_prohibited=True,
        waybills=tuple(waybills),
    )


def load_locked_set_manifest_for_development(
    path: Path,
    *,
    template_reference_hashes: set[str] | frozenset[str],
) -> LockedSetManifest:
    """Development-only parser; it is not a release attestation."""

    return _load_locked_set_manifest(
        path,
        template_reference_hashes=template_reference_hashes,
    )


def _canonical_manifest_sha256(manifest: LockedSetManifest) -> str:
    payload = {
        "dataset_id": manifest.dataset_id,
        "dataset_kind": manifest.dataset_kind,
        "schema_version": 1,
        "tuning_prohibited": manifest.tuning_prohibited,
        "waybills": [
            {
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "ordinary_net": (
                            None if image.ordinary_net is None else format(image.ordinary_net, "f")
                        ),
                        "relative_path": image.relative_path,
                        "role": image.role.value,
                        "submitted_slot": image.slot.value,
                    }
                    for image in waybill.images
                ],
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": waybill.waybill_identity_sha256,
            }
            for waybill in manifest.waybills
        ],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
    except OSError as exc:
        raise LockedSetContractError("locked-set image is missing or unreadable") from exc
    if byte_count == 0:
        raise LockedSetContractError("locked-set image cannot be empty")
    return digest.hexdigest(), byte_count


def _verify_locked_set_files(
    manifest: LockedSetManifest,
    *,
    dataset_root: Path,
) -> LockedSetFileVerification:
    """Verify the sealed image bytes before a release evaluation can start."""

    if not isinstance(manifest, LockedSetManifest):
        raise LockedSetContractError("locked-set manifest is invalid")
    try:
        root = dataset_root.resolve(strict=True)
    except OSError as exc:
        raise LockedSetContractError("locked-set dataset root is unavailable") from exc
    if not root.is_dir():
        raise LockedSetContractError("locked-set dataset root must be a directory")

    total_bytes = 0
    verified_count = 0
    for waybill in manifest.waybills:
        for image in waybill.images:
            try:
                candidate = (root / PurePosixPath(image.relative_path)).resolve(strict=True)
            except OSError as exc:
                raise LockedSetContractError("locked-set image is missing or unreadable") from exc
            if not candidate.is_relative_to(root) or not candidate.is_file():
                raise LockedSetContractError("locked-set image path escaped the dataset root")
            actual_sha256, byte_count = _file_sha256(candidate)
            if actual_sha256 != image.image_sha256:
                raise LockedSetContractError(
                    "locked-set image content hash does not match the sealed label"
                )
            verified_count += 1
            total_bytes += byte_count

    if verified_count != manifest.image_count:
        raise LockedSetContractError("locked-set image count did not reconcile")
    return LockedSetFileVerification(
        manifest_sha256=_canonical_manifest_sha256(manifest),
        image_count=verified_count,
        total_bytes=total_bytes,
    )


def _verify_locked_set_isolation(
    manifest: LockedSetManifest,
    *,
    exclusion_snapshot: LockedSetExclusionSnapshot,
) -> None:
    """Reject exact image or stable source-waybill reuse."""

    locked_hashes = {
        image.image_sha256 for waybill in manifest.waybills for image in waybill.images
    }
    excluded_images = (
        exclusion_snapshot.template_reference_image_hashes
        | exclusion_snapshot.development_image_hashes
        | exclusion_snapshot.calibration_image_hashes
        | exclusion_snapshot.shadow_image_hashes
        | exclusion_snapshot.prior_locked_image_hashes
    )
    if locked_hashes.intersection(excluded_images):
        raise LockedSetContractError("locked set contains an excluded image identity")
    locked_waybill_identities = {waybill.waybill_identity_sha256 for waybill in manifest.waybills}
    if locked_waybill_identities.intersection(exclusion_snapshot.prior_waybill_identity_hashes):
        raise LockedSetContractError("locked set contains an excluded waybill identity")


def preflight_locked_set_release(
    *,
    manifest_path: Path,
    dataset_root: Path,
    exclusion_snapshot: LockedSetExclusionSnapshot,
) -> LockedSetReleaseAttestation:
    """Run the only supported release preflight as one fail-closed operation."""

    if not isinstance(exclusion_snapshot, LockedSetExclusionSnapshot):
        raise LockedSetContractError(
            "a sourced exclusion snapshot is required for release preflight"
        )
    manifest = _load_locked_set_manifest(
        manifest_path,
        template_reference_hashes=(exclusion_snapshot.template_reference_image_hashes),
    )
    if manifest.waybill_count != 50 or manifest.image_count != 100:
        raise LockedSetContractError(
            "release preflight requires exactly 50 waybills and 100 images"
        )
    _verify_locked_set_isolation(
        manifest,
        exclusion_snapshot=exclusion_snapshot,
    )
    file_verification = _verify_locked_set_files(
        manifest,
        dataset_root=dataset_root,
    )
    return LockedSetReleaseAttestation(
        dataset_id=manifest.dataset_id,
        manifest_sha256=file_verification.manifest_sha256,
        exclusion_source_id=exclusion_snapshot.source_id,
        exclusion_snapshot_sha256=exclusion_snapshot.canonical_sha256,
        waybill_count=manifest.waybill_count,
        image_count=file_verification.image_count,
        total_bytes=file_verification.total_bytes,
        exclusion_counts=exclusion_snapshot.exclusion_counts,
    )
