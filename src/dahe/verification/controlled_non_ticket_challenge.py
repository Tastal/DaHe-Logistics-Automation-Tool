from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import cast
from uuid import uuid4

from PIL import Image, ImageDraw, ImageOps, UnidentifiedImageError

from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthorityError,
    load_formal_development_authority,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION as SIMILARITY_ALGORITHM_VERSION,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
    build_image_fingerprint,
    find_near_duplicate_candidates,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImageChangedError,
    LockedSetReviewPackageError,
    load_locked_set_review_package,
)

SCHEMA_VERSION = 1
REDACTION_ALGORITHM_VERSION = "dahe.controlled-non-ticket-redaction.v1"

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_KEYS = {
    "canonical_sha256",
    "created_at",
    "development_authority_sha256",
    "dimensions",
    "expected_safety_outcome",
    "human_truth",
    "kind",
    "novelty_results",
    "operator_id",
    "package_sha256",
    "redacted_sha256",
    "redaction_algorithm_version",
    "redactions",
    "schema_version",
    "similarity_algorithm_version",
    "source_fingerprint",
    "source_sha256",
}


class ControlledNonTicketChallengeError(ValueError):
    """Raised when controlled challenge evidence cannot safely be released."""


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ControlledNonTicketChallengeError("challenge evidence is not canonical JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _manifest_bytes(value: Mapping[str, object]) -> bytes:
    try:
        content = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ControlledNonTicketChallengeError("challenge manifest is not JSON") from exc
    return (content + "\n").encode("utf-8")


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ControlledNonTicketChallengeError(f"{label} must be a lowercase SHA-256")
    return value


def _required_text(value: object, *, label: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ControlledNonTicketChallengeError(f"{label} is required")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ControlledNonTicketChallengeError(f"{label} is too long")
    return normalized


def _aware_timestamp(value: datetime | str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ControlledNonTicketChallengeError(
                "challenge time must be ISO-8601"
            ) from exc
    else:
        raise ControlledNonTicketChallengeError("challenge time is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ControlledNonTicketChallengeError("challenge time must include a timezone")
    return parsed.isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True, order=True)
class RedactionRectangle:
    """One half-open pixel rectangle: [x1, y1, x2, y2)."""

    x1: int
    y1: int
    x2: int
    y2: int

    def __post_init__(self) -> None:
        values = (self.x1, self.y1, self.x2, self.y2)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise ControlledNonTicketChallengeError(
                "redaction rectangle coordinates must be integers"
            )
        if self.x1 < 0 or self.y1 < 0 or self.x2 <= self.x1 or self.y2 <= self.y1:
            raise ControlledNonTicketChallengeError("redaction rectangle is invalid")

    def validate_bounds(self, *, width: int, height: int) -> None:
        if self.x2 > width or self.y2 > height:
            raise ControlledNonTicketChallengeError(
                "redaction rectangle exceeds image dimensions"
            )

    def to_payload(self) -> dict[str, int]:
        return {
            "x1": self.x1,
            "x2": self.x2,
            "y1": self.y1,
            "y2": self.y2,
        }

    @classmethod
    def from_payload(cls, raw: object) -> RedactionRectangle:
        if not isinstance(raw, dict) or set(raw) != {"x1", "x2", "y1", "y2"}:
            raise ControlledNonTicketChallengeError(
                "redaction rectangle record is invalid"
            )
        return cls(
            x1=raw["x1"],
            y1=raw["y1"],
            x2=raw["x2"],
            y2=raw["y2"],
        )


@dataclass(frozen=True, slots=True)
class ChallengeContext:
    development_authority_sha256: str
    development_fingerprints: tuple[ImagePerceptualFingerprint, ...]
    package_sha256: str
    locked_set_fingerprints: tuple[ImagePerceptualFingerprint, ...]

    def __post_init__(self) -> None:
        _required_sha256(
            self.development_authority_sha256,
            label="development authority SHA-256",
        )
        _required_sha256(self.package_sha256, label="locked-set package SHA-256")
        if not self.development_fingerprints:
            raise ControlledNonTicketChallengeError(
                "development fingerprint inventory is empty"
            )
        if len(self.locked_set_fingerprints) != 100:
            raise ControlledNonTicketChallengeError(
                "current locked-set inventory must contain exactly 100 images"
            )
        for label, fingerprints in (
            ("development", self.development_fingerprints),
            ("locked set", self.locked_set_fingerprints),
        ):
            identities: set[str] = set()
            for fingerprint in fingerprints:
                if not isinstance(fingerprint, ImagePerceptualFingerprint):
                    raise ControlledNonTicketChallengeError(
                        f"{label} fingerprint inventory is invalid"
                    )
                try:
                    fingerprint.verify_integrity()
                except ImageSimilarityContractError as exc:
                    raise ControlledNonTicketChallengeError(
                        f"{label} fingerprint inventory is invalid"
                    ) from exc
                if fingerprint.algorithm_version != SIMILARITY_ALGORITHM_VERSION:
                    raise ControlledNonTicketChallengeError(
                        f"{label} fingerprint algorithm is unsupported"
                    )
                if fingerprint.content_sha256 in identities:
                    raise ControlledNonTicketChallengeError(
                        f"{label} fingerprint inventory contains duplicate identities"
                    )
                identities.add(fingerprint.content_sha256)


@dataclass(frozen=True, slots=True)
class ControlledNonTicketChallenge:
    manifest_path: Path
    redacted_image_path: Path
    payload: dict[str, object]


def _reject_symbolic_links(path: Path, *, allow_missing: bool) -> Path:
    if not path.is_absolute():
        raise ControlledNonTicketChallengeError("challenge paths must be absolute")
    lexical = Path(os.path.abspath(os.fspath(path)))
    current = lexical
    while True:
        if current.exists() or current.is_symlink():
            if current.is_symlink():
                raise ControlledNonTicketChallengeError(
                    "challenge paths must not contain a symbolic link"
                )
        elif not allow_missing:
            raise ControlledNonTicketChallengeError("challenge path does not exist")
        if current.parent == current:
            break
        current = current.parent
    return lexical


def load_controlled_challenge_context(
    *,
    development_authority_path: Path,
    package_data_root: Path,
) -> ChallengeContext:
    """Rehash the immutable authority and current 100-image package."""

    authority_path = _reject_symbolic_links(
        development_authority_path,
        allow_missing=False,
    )
    package_root = _reject_symbolic_links(
        package_data_root,
        allow_missing=False,
    )
    try:
        authority = load_formal_development_authority(authority_path)
        package = load_locked_set_review_package(package_root)
    except (
        FormalDevelopmentAuthorityError,
        LockedSetReviewImageChangedError,
        LockedSetReviewPackageError,
    ) as exc:
        raise ControlledNonTicketChallengeError(
            "challenge authority inputs are invalid"
        ) from exc
    if (
        package.development_authority is None
        or package.development_authority.authority_sha256
        != authority.authority_sha256
    ):
        raise ControlledNonTicketChallengeError(
            "locked-set package development authority does not match"
        )
    try:
        development_fingerprints = tuple(
            item.to_image_fingerprint() for item in authority.perceptual_fingerprints
        )
        locked_fingerprints = tuple(
            build_image_fingerprint(package.read_verified_image(image_sha256)[0])
            for image_sha256 in sorted(package.images_by_sha256)
        )
    except (
        ImageSimilarityContractError,
        KeyError,
        LockedSetReviewImageChangedError,
        OSError,
        ValueError,
    ) as exc:
        raise ControlledNonTicketChallengeError(
            "challenge fingerprint inventories cannot be verified"
        ) from exc
    return ChallengeContext(
        development_authority_sha256=authority.authority_sha256,
        development_fingerprints=development_fingerprints,
        package_sha256=package.canonical_sha256,
        locked_set_fingerprints=locked_fingerprints,
    )


def _normalized_redactions(
    redactions: Sequence[RedactionRectangle],
    *,
    width: int,
    height: int,
) -> tuple[RedactionRectangle, ...]:
    if not redactions:
        raise ControlledNonTicketChallengeError(
            "at least one redaction rectangle is required"
        )
    normalized = tuple(sorted(redactions))
    if len(set(normalized)) != len(normalized):
        raise ControlledNonTicketChallengeError(
            "redaction rectangles must not be duplicated"
        )
    for rectangle in normalized:
        if not isinstance(rectangle, RedactionRectangle):
            raise ControlledNonTicketChallengeError(
                "redaction rectangle is invalid"
            )
        rectangle.validate_bounds(width=width, height=height)
    return normalized


def _decode_rgb(content: bytes) -> Image.Image:
    try:
        with Image.open(BytesIO(content)) as opened:
            if int(getattr(opened, "n_frames", 1)) != 1:
                raise ControlledNonTicketChallengeError(
                    "multi-frame source images are unsupported"
                )
            opened.load()
            return ImageOps.exif_transpose(opened).convert("RGB")
    except ControlledNonTicketChallengeError:
        raise
    except (OSError, SyntaxError, UnidentifiedImageError, ValueError) as exc:
        raise ControlledNonTicketChallengeError("source image cannot be decoded") from exc


def _redacted_png(
    content: bytes,
    redactions: Sequence[RedactionRectangle],
) -> tuple[bytes, int, int, tuple[RedactionRectangle, ...]]:
    try:
        source_fingerprint = build_image_fingerprint(content)
    except ImageSimilarityContractError as exc:
        raise ControlledNonTicketChallengeError("source image cannot be verified") from exc
    image = _decode_rgb(content)
    width, height = image.size
    if (width, height) != (source_fingerprint.width, source_fingerprint.height):
        raise ControlledNonTicketChallengeError(
            "source image dimensions are inconsistent"
        )
    normalized = _normalized_redactions(
        redactions,
        width=width,
        height=height,
    )
    draw = ImageDraw.Draw(image)
    for rectangle in normalized:
        draw.rectangle(
            (
                rectangle.x1,
                rectangle.y1,
                rectangle.x2 - 1,
                rectangle.y2 - 1,
            ),
            fill=(0, 0, 0),
        )
    output = BytesIO()
    image.save(
        output,
        format="PNG",
        compress_level=9,
        optimize=False,
    )
    return output.getvalue(), width, height, normalized


def _inventory_identity_sha256(
    fingerprints: Sequence[ImagePerceptualFingerprint],
) -> str:
    return _canonical_sha256(
        [
            {
                "content_sha256": fingerprint.content_sha256,
                "fingerprint_sha256": fingerprint.canonical_sha256,
            }
            for fingerprint in sorted(
                fingerprints,
                key=lambda item: item.content_sha256,
            )
        ]
    )


def _novelty_result(
    *,
    probe: ImagePerceptualFingerprint,
    inventory: Sequence[ImagePerceptualFingerprint],
    label: str,
) -> dict[str, object]:
    identities = {item.content_sha256 for item in inventory}
    exact_match_count = int(probe.content_sha256 in identities)
    try:
        candidates = find_near_duplicate_candidates(
            probe=probe,
            inventory=inventory,
        )
    except ImageSimilarityContractError as exc:
        raise ControlledNonTicketChallengeError(
            f"{label} novelty comparison failed"
        ) from exc
    base: dict[str, object] = {
        "exact_match_count": exact_match_count,
        "inventory_identity_sha256": _inventory_identity_sha256(inventory),
        "inventory_image_count": len(inventory),
        "near_duplicate_candidate_count": len(candidates),
        "passed": exact_match_count == 0 and not candidates,
        "probe_fingerprint_sha256": probe.canonical_sha256,
    }
    result = {**base, "result_sha256": _canonical_sha256(base)}
    if result["passed"] is not True:
        raise ControlledNonTicketChallengeError(
            f"{label} image is not independent of the required inventory"
        )
    return result


def _build_payload(
    *,
    source_fingerprint: ImagePerceptualFingerprint,
    redacted_content: bytes,
    width: int,
    height: int,
    redactions: tuple[RedactionRectangle, ...],
    operator_id: str,
    created_at: str,
    context: ChallengeContext,
) -> dict[str, object]:
    try:
        redacted_fingerprint = build_image_fingerprint(redacted_content)
    except ImageSimilarityContractError as exc:
        raise ControlledNonTicketChallengeError(
            "challenge image fingerprints cannot be built"
        ) from exc
    novelty = {
        "redacted_vs_current_locked_set": _novelty_result(
            probe=redacted_fingerprint,
            inventory=context.locked_set_fingerprints,
            label="redacted locked set",
        ),
        "redacted_vs_development": _novelty_result(
            probe=redacted_fingerprint,
            inventory=context.development_fingerprints,
            label="redacted development",
        ),
        "source_vs_development": _novelty_result(
            probe=source_fingerprint,
            inventory=context.development_fingerprints,
            label="source development",
        ),
    }
    payload: dict[str, object] = {
        "created_at": created_at,
        "development_authority_sha256": (
            context.development_authority_sha256
        ),
        "dimensions": {"height": height, "width": width},
        "expected_safety_outcome": {
            "automatic_outcome": "awaiting_review",
            "role_issue": "role_unknown",
            "safety_route": "non_automatic",
        },
        "human_truth": {
            "document_class": "non_ticket",
            "ordinary_net": None,
            "ticket_role": "unknown",
        },
        "kind": "controlled_non_ticket_challenge",
        "novelty_results": novelty,
        "operator_id": operator_id,
        "package_sha256": context.package_sha256,
        "redacted_sha256": hashlib.sha256(redacted_content).hexdigest(),
        "redaction_algorithm_version": REDACTION_ALGORITHM_VERSION,
        "redactions": [rectangle.to_payload() for rectangle in redactions],
        "schema_version": SCHEMA_VERSION,
        "similarity_algorithm_version": SIMILARITY_ALGORITHM_VERSION,
        "source_fingerprint": source_fingerprint.to_record(),
        "source_sha256": source_fingerprint.content_sha256,
    }
    return {**payload, "canonical_sha256": _canonical_sha256(payload)}


def _artifact_paths(
    *,
    output_root: Path,
    redacted_sha256: str,
) -> tuple[Path, Path, Path]:
    lexical_root = _reject_symbolic_links(output_root, allow_missing=True)
    try:
        resolved_root = lexical_root.resolve(strict=False)
    except OSError as exc:
        raise ControlledNonTicketChallengeError(
            "challenge output root cannot be resolved"
        ) from exc
    target = (
        resolved_root
        / "controlled-non-ticket"
        / redacted_sha256[:2]
        / redacted_sha256
    )
    return target, target / "manifest.json", target / "redacted.png"


def _remove_staging_directory(path: Path) -> None:
    for name in ("manifest.json", "redacted.png"):
        (path / name).unlink(missing_ok=True)
    with suppress(FileNotFoundError):
        path.rmdir()


def _commit_artifact_directory(
    *,
    target: Path,
    manifest_content: bytes,
    redacted_content: bytes,
) -> bool:
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.parent / f".{target.name}.{uuid4().hex}.tmp"
    try:
        staging.mkdir()
        for name, content in (
            ("redacted.png", redacted_content),
            ("manifest.json", manifest_content),
        ):
            with (staging / name).open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        try:
            os.rename(staging, target)
        except OSError as exc:
            if target.is_dir():
                return False
            raise ControlledNonTicketChallengeError(
                "challenge artifact could not be committed atomically"
            ) from exc
        return True
    finally:
        if staging.exists():
            _remove_staging_directory(staging)


def create_controlled_non_ticket_challenge(
    *,
    source_image: Path,
    output_root: Path,
    redactions: Sequence[RedactionRectangle],
    operator_id: str,
    created_at: datetime | str,
    context: ChallengeContext,
) -> ControlledNonTicketChallenge:
    """Redact and seal one independent, offline non-ticket challenge."""

    if not isinstance(context, ChallengeContext):
        raise ControlledNonTicketChallengeError("challenge context is required")
    source_candidate = _reject_symbolic_links(source_image, allow_missing=False)
    try:
        source_path = source_candidate.resolve(strict=True)
        source_content = source_path.read_bytes()
    except OSError as exc:
        raise ControlledNonTicketChallengeError("source image is not readable") from exc
    if not source_path.is_file() or not source_content:
        raise ControlledNonTicketChallengeError("source image is not readable")
    redacted_content, width, height, normalized_redactions = _redacted_png(
        source_content,
        redactions,
    )
    try:
        source_fingerprint = build_image_fingerprint(source_content)
    except ImageSimilarityContractError as exc:
        raise ControlledNonTicketChallengeError(
            "source image fingerprint cannot be built"
        ) from exc
    payload = _build_payload(
        source_fingerprint=source_fingerprint,
        redacted_content=redacted_content,
        width=width,
        height=height,
        redactions=normalized_redactions,
        operator_id=_required_text(operator_id, label="challenge operator"),
        created_at=_aware_timestamp(created_at),
        context=context,
    )
    redacted_sha256 = cast(str, payload["redacted_sha256"])
    target, manifest_path, _redacted_path = _artifact_paths(
        output_root=output_root,
        redacted_sha256=redacted_sha256,
    )
    if target.exists():
        _reject_symbolic_links(target, allow_missing=False)
        existing = load_controlled_non_ticket_challenge(
            manifest_path=manifest_path,
            context=context,
            source_image=source_path,
        )
        if existing.payload != payload:
            raise ControlledNonTicketChallengeError(
                "challenge artifact target already has different evidence"
            )
        return existing
    _commit_artifact_directory(
        target=target,
        manifest_content=_manifest_bytes(payload),
        redacted_content=redacted_content,
    )
    created = load_controlled_non_ticket_challenge(
        manifest_path=manifest_path,
        context=context,
        source_image=source_path,
    )
    if created.payload != payload:
        raise ControlledNonTicketChallengeError(
            "challenge artifact changed during commit"
        )
    return created


def _load_manifest(path: Path) -> tuple[Path, dict[str, object]]:
    candidate = _reject_symbolic_links(path, allow_missing=False)
    try:
        resolved = candidate.resolve(strict=True)
        content = resolved.read_bytes()
        parsed = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControlledNonTicketChallengeError(
            "challenge manifest is not readable"
        ) from exc
    if (
        not resolved.is_file()
        or not isinstance(parsed, dict)
        or set(parsed) != _MANIFEST_KEYS
        or content != _manifest_bytes(parsed)
    ):
        raise ControlledNonTicketChallengeError(
            "challenge manifest contract is invalid"
        )
    return resolved, parsed


def _parse_manifest(
    raw: dict[str, object],
) -> tuple[
    str,
    str,
    int,
    int,
    tuple[RedactionRectangle, ...],
    str,
    str,
    ImagePerceptualFingerprint,
]:
    if (
        raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind") != "controlled_non_ticket_challenge"
        or raw.get("human_truth")
        != {
            "document_class": "non_ticket",
            "ordinary_net": None,
            "ticket_role": "unknown",
        }
        or raw.get("expected_safety_outcome")
        != {
            "automatic_outcome": "awaiting_review",
            "role_issue": "role_unknown",
            "safety_route": "non_automatic",
        }
        or raw.get("redaction_algorithm_version") != REDACTION_ALGORITHM_VERSION
        or raw.get("similarity_algorithm_version")
        != SIMILARITY_ALGORITHM_VERSION
    ):
        raise ControlledNonTicketChallengeError(
            "challenge manifest version is unsupported"
        )
    source_sha256 = _required_sha256(
        raw.get("source_sha256"),
        label="source SHA-256",
    )
    source_fingerprint_raw = raw.get("source_fingerprint")
    if not isinstance(source_fingerprint_raw, dict):
        raise ControlledNonTicketChallengeError(
            "challenge source fingerprint is invalid"
        )
    try:
        source_fingerprint = ImagePerceptualFingerprint.from_record(
            source_fingerprint_raw
        )
    except ImageSimilarityContractError as exc:
        raise ControlledNonTicketChallengeError(
            "challenge source fingerprint is invalid"
        ) from exc
    if source_fingerprint.content_sha256 != source_sha256:
        raise ControlledNonTicketChallengeError(
            "challenge source fingerprint does not match its source SHA-256"
        )
    redacted_sha256 = _required_sha256(
        raw.get("redacted_sha256"),
        label="redacted SHA-256",
    )
    _required_sha256(
        raw.get("development_authority_sha256"),
        label="development authority SHA-256",
    )
    _required_sha256(
        raw.get("package_sha256"),
        label="locked-set package SHA-256",
    )
    operator = _required_text(raw.get("operator_id"), label="challenge operator")
    created_at = _aware_timestamp(cast(str, raw.get("created_at")))
    dimensions = raw.get("dimensions")
    if (
        not isinstance(dimensions, dict)
        or set(dimensions) != {"height", "width"}
        or isinstance(dimensions.get("width"), bool)
        or not isinstance(dimensions.get("width"), int)
        or cast(int, dimensions["width"]) < 1
        or isinstance(dimensions.get("height"), bool)
        or not isinstance(dimensions.get("height"), int)
        or cast(int, dimensions["height"]) < 1
    ):
        raise ControlledNonTicketChallengeError(
            "challenge image dimensions are invalid"
        )
    width = cast(int, dimensions["width"])
    height = cast(int, dimensions["height"])
    if (source_fingerprint.width, source_fingerprint.height) != (width, height):
        raise ControlledNonTicketChallengeError(
            "challenge source fingerprint dimensions do not match"
        )
    raw_redactions = raw.get("redactions")
    if not isinstance(raw_redactions, list):
        raise ControlledNonTicketChallengeError(
            "challenge redactions are invalid"
        )
    redactions = _normalized_redactions(
        tuple(RedactionRectangle.from_payload(item) for item in raw_redactions),
        width=width,
        height=height,
    )
    declared_canonical = _required_sha256(
        raw.get("canonical_sha256"),
        label="challenge canonical SHA-256",
    )
    without_canonical = {
        key: value for key, value in raw.items() if key != "canonical_sha256"
    }
    if _canonical_sha256(without_canonical) != declared_canonical:
        raise ControlledNonTicketChallengeError(
            "challenge manifest canonical SHA-256 does not match"
        )
    return (
        source_sha256,
        redacted_sha256,
        width,
        height,
        redactions,
        operator,
        created_at,
        source_fingerprint,
    )


def load_controlled_non_ticket_challenge(
    *,
    manifest_path: Path,
    context: ChallengeContext,
    source_image: Path | None = None,
) -> ControlledNonTicketChallenge:
    """Rebuild redaction and novelty results before accepting persisted evidence."""

    if not isinstance(context, ChallengeContext):
        raise ControlledNonTicketChallengeError("challenge context is required")
    resolved_manifest, payload = _load_manifest(manifest_path)
    (
        source_sha256,
        redacted_sha256,
        width,
        height,
        redactions,
        operator,
        created_at,
        source_fingerprint,
    ) = _parse_manifest(payload)
    if (
        payload["development_authority_sha256"]
        != context.development_authority_sha256
    ):
        raise ControlledNonTicketChallengeError(
            "challenge development authority changed"
        )
    if payload["package_sha256"] != context.package_sha256:
        raise ControlledNonTicketChallengeError(
            "challenge locked-set package changed"
        )
    expected_parent = resolved_manifest.parent
    if (
        expected_parent.name != redacted_sha256
        or expected_parent.parent.name != redacted_sha256[:2]
        or resolved_manifest.name != "manifest.json"
    ):
        raise ControlledNonTicketChallengeError(
            "challenge artifact is not content addressed"
        )
    redacted_path = expected_parent / "redacted.png"
    _reject_symbolic_links(redacted_path, allow_missing=False)
    try:
        redacted_content = redacted_path.read_bytes()
    except OSError as exc:
        raise ControlledNonTicketChallengeError(
            "challenge redacted image is not readable"
        ) from exc
    if (
        not redacted_path.is_file()
        or hashlib.sha256(redacted_content).hexdigest() != redacted_sha256
    ):
        raise ControlledNonTicketChallengeError("challenge redacted image changed")
    if source_image is not None:
        source_candidate = _reject_symbolic_links(
            source_image,
            allow_missing=False,
        )
        try:
            source_path = source_candidate.resolve(strict=True)
            source_content = source_path.read_bytes()
        except OSError as exc:
            raise ControlledNonTicketChallengeError(
                "challenge source image is not readable"
            ) from exc
        if (
            not source_path.is_file()
            or hashlib.sha256(source_content).hexdigest() != source_sha256
        ):
            raise ControlledNonTicketChallengeError(
                "challenge source image changed"
            )
        rebuilt, rebuilt_width, rebuilt_height, rebuilt_redactions = _redacted_png(
            source_content,
            redactions,
        )
        try:
            rebuilt_source_fingerprint = build_image_fingerprint(source_content)
        except ImageSimilarityContractError as exc:
            raise ControlledNonTicketChallengeError(
                "challenge source image fingerprint cannot be rebuilt"
            ) from exc
        if (
            rebuilt != redacted_content
            or rebuilt_width != width
            or rebuilt_height != height
            or rebuilt_redactions != redactions
            or rebuilt_source_fingerprint != source_fingerprint
        ):
            raise ControlledNonTicketChallengeError(
                "challenge redacted image does not match its source contract"
            )
    recomputed = _build_payload(
        source_fingerprint=source_fingerprint,
        redacted_content=redacted_content,
        width=width,
        height=height,
        redactions=redactions,
        operator_id=operator,
        created_at=created_at,
        context=context,
    )
    if recomputed != payload:
        raise ControlledNonTicketChallengeError(
            "challenge manifest does not match recomputed evidence"
        )
    if {path.name for path in expected_parent.iterdir()} != {
        "manifest.json",
        "redacted.png",
    }:
        raise ControlledNonTicketChallengeError(
            "challenge artifact directory contains unexpected files"
        )
    return ControlledNonTicketChallenge(
        manifest_path=resolved_manifest,
        redacted_image_path=redacted_path,
        payload=payload,
    )
