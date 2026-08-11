from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import cast
from uuid import uuid4

from PIL import Image, UnidentifiedImageError

from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchContractError,
    ChengfengShadowBatchManifest,
    ShadowBatchItem,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionContractError,
    FormalShadowSelectionManifest,
)
from dahe.verification.loop9_dataset_isolation import (
    DatasetKind,
    Loop9DatasetIsolationError,
    Loop9DatasetManifest,
)

SCHEMA_VERSION = 1
_MAX_JSON_BYTES = 20 * 1024 * 1024
_MAX_IMAGE_BYTES = 50 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PERSONNEL_FIELD = re.compile(
    r"(?:^|_)(?:reviewer|operator|actor|employee|staff|username|"
    r"windows_sid|handler|handled_by|assignee|person)(?:_|$)"
)
_ROTATIONS = {
    "rotation_0",
    "rotation_90",
    "rotation_180",
    "rotation_270",
}
_QUALITY_CONDITIONS = _ROTATIONS | {
    "blur",
    "crop",
    "glare",
    "printed",
    "screen",
    "unknown_layout",
}
_LOCKED_REQUIRED_CONDITIONS = (
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
_ROLES = {"loading", "unloading", "unknown"}
_PAIR_CONDITIONS = {
    "normal_pair",
    "suspected_swapped",
    "both_loading",
    "both_unloading",
    "unknown_or_non_ticket",
}
_MEDIA_TYPES = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
}


class Loop9HumanReviewError(ValueError):
    """Raised when Loop 9 human-review evidence is unsafe or inconsistent."""


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
        raise Loop9HumanReviewError(f"{label} must be a lowercase SHA-256")
    return value


def _required_text(
    value: object,
    *,
    label: str,
    maximum: int = 200,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise Loop9HumanReviewError(f"{label} is invalid")
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise Loop9HumanReviewError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise Loop9HumanReviewError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _reject_personnel_fields(value: object, *, label: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str) and _PERSONNEL_FIELD.search(key.lower()):
                raise Loop9HumanReviewError(
                    f"{label} contains a prohibited personnel identity field"
                )
            _reject_personnel_fields(nested, label=label)
    elif isinstance(value, list):
        for nested in value:
            _reject_personnel_fields(nested, label=label)


def _verify_canonical_payload(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    raw = _mapping(value, label=label)
    declared = _required_sha256(
        raw.get("canonical_sha256"),
        label=f"{label} canonical SHA-256",
    )
    core = {key: nested for key, nested in raw.items() if key != "canonical_sha256"}
    if _canonical_sha256(core) != declared:
        raise Loop9HumanReviewError(f"{label} integrity is invalid")
    return raw


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    reparse_flag = getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _resolved_existing_file(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9HumanReviewError(f"{label} path must be absolute")
    if path.is_symlink() or _is_reparse_point(path):
        raise Loop9HumanReviewError(f"{label} path is unsafe")
    try:
        resolved = path.resolve(strict=True)
        if (
            not resolved.is_file()
            or resolved.is_symlink()
            or _is_reparse_point(resolved)
        ):
            raise Loop9HumanReviewError(f"{label} file is unsafe")
    except OSError as exc:
        raise Loop9HumanReviewError(f"{label} file is unavailable") from exc
    return resolved


def _resolved_existing_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9HumanReviewError(f"{label} path must be absolute")
    if path.is_symlink() or _is_reparse_point(path):
        raise Loop9HumanReviewError(f"{label} path is unsafe")
    try:
        resolved = path.resolve(strict=True)
        if (
            not resolved.is_dir()
            or resolved.is_symlink()
            or _is_reparse_point(resolved)
        ):
            raise Loop9HumanReviewError(f"{label} directory is unsafe")
    except OSError as exc:
        raise Loop9HumanReviewError(f"{label} directory is unavailable") from exc
    return resolved


def _safe_output(path: Path, *, label: str) -> tuple[Path, Path]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9HumanReviewError(f"{label} path must be absolute")
    if path.exists() or path.is_symlink():
        raise Loop9HumanReviewError(f"{label} already exists")
    parent = _resolved_existing_directory(path.parent, label=f"{label} parent")
    candidate = Path(os.path.abspath(os.fspath(path)))
    if candidate.parent != parent:
        raise Loop9HumanReviewError(f"{label} path is unsafe")
    return parent, candidate


def _load_json(path: Path, *, label: str) -> object:
    resolved = _resolved_existing_file(path, label=label)
    try:
        size = resolved.stat().st_size
        if size < 2 or size > _MAX_JSON_BYTES:
            raise Loop9HumanReviewError(f"{label} file size is invalid")
        content = resolved.read_bytes()
        return json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9HumanReviewError(f"{label} is not readable UTF-8 JSON") from exc


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9HumanReviewError("JSON contains duplicate fields")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> object:
    raise Loop9HumanReviewError(f"JSON contains a non-finite value: {value}")


def _json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_file_exclusive(path: Path, content: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise Loop9HumanReviewError("review evidence could not be written") from exc


def _write_json_exclusive(path: Path, payload: dict[str, object]) -> None:
    parent, output = _safe_output(path, label="output")
    staged = parent / f".{output.name}.{uuid4().hex}.tmp"
    try:
        _write_file_exclusive(staged, _json_bytes(payload))
        try:
            os.link(staged, output)
        except FileExistsError as exc:
            raise Loop9HumanReviewError("output already exists") from exc
        except OSError as exc:
            raise Loop9HumanReviewError(
                "output could not be published atomically"
            ) from exc
    finally:
        staged.unlink(missing_ok=True)


def _content_addressed_path(digest: str) -> PurePosixPath:
    return PurePosixPath(
        "sha256",
        digest[:2],
        digest[2:4],
        f"{digest}.blob",
    )


def _safe_relative_path(value: object, *, label: str) -> PurePosixPath:
    raw = _required_text(value, label=label, maximum=500)
    if "\\" in raw or ":" in raw or raw.startswith("//"):
        raise Loop9HumanReviewError(f"{label} is unsafe")
    relative = PurePosixPath(raw)
    if (
        relative.is_absolute()
        or not relative.parts
        or "." in relative.parts
        or ".." in relative.parts
    ):
        raise Loop9HumanReviewError(f"{label} is unsafe")
    return relative


def _read_verified_image(
    *,
    image_root: Path,
    relative_path: str,
    expected_sha256: str,
    expected_size: int,
    expected_media_type: str,
) -> bytes:
    relative = _safe_relative_path(
        relative_path,
        label="source image relative path",
    )
    if relative != _content_addressed_path(expected_sha256):
        raise Loop9HumanReviewError("source image path is not content-addressed")
    candidate = image_root / Path(relative.as_posix())
    if candidate.is_symlink() or _is_reparse_point(candidate):
        raise Loop9HumanReviewError("source image path is unsafe")
    try:
        resolved = candidate.resolve(strict=True)
        if (
            not resolved.is_file()
            or not resolved.is_relative_to(image_root)
            or resolved.is_symlink()
            or _is_reparse_point(resolved)
        ):
            raise Loop9HumanReviewError("source image path is unsafe")
        if not 0 < resolved.stat().st_size <= _MAX_IMAGE_BYTES:
            raise Loop9HumanReviewError("source image size is unsafe")
        content = resolved.read_bytes()
    except OSError as exc:
        raise Loop9HumanReviewError("source image is unavailable") from exc
    if (
        len(content) != expected_size
        or hashlib.sha256(content).hexdigest() != expected_sha256
    ):
        raise Loop9HumanReviewError("source image integrity is invalid")
    try:
        with Image.open(resolved) as image:
            image.verify()
        with Image.open(resolved) as image:
            media_type = _MEDIA_TYPES.get(str(image.format).upper())
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        raise Loop9HumanReviewError("source image media is invalid") from exc
    if media_type != expected_media_type:
        raise Loop9HumanReviewError("source image media type does not match")
    return content


def _parse_batch(value: object) -> ChengfengShadowBatchManifest:
    try:
        return ChengfengShadowBatchManifest.from_payload(value)
    except ChengfengShadowBatchContractError as exc:
        raise Loop9HumanReviewError("source batch manifest is invalid") from exc


def _parse_dataset(value: object) -> Loop9DatasetManifest:
    try:
        return Loop9DatasetManifest.from_payload(value)
    except Loop9DatasetIsolationError as exc:
        raise Loop9HumanReviewError("dataset manifest is invalid") from exc


def _parse_formal_selection(
    value: object,
) -> FormalShadowSelectionManifest:
    try:
        return FormalShadowSelectionManifest.from_payload(value)
    except FormalShadowSelectionContractError as exc:
        raise Loop9HumanReviewError(
            "formal selection manifest is invalid"
        ) from exc


def _validate_source_binding(
    *,
    batch: ChengfengShadowBatchManifest,
    dataset: Loop9DatasetManifest,
    formal_selection: FormalShadowSelectionManifest,
) -> None:
    try:
        formal_selection.verify_integrity()
    except FormalShadowSelectionContractError as exc:
        raise Loop9HumanReviewError(
            "formal selection manifest integrity is invalid"
        ) from exc
    expected_kind = DatasetKind(batch.target_kind.value)
    if dataset.dataset_kind is not expected_kind:
        raise Loop9HumanReviewError("source batch and dataset classifications differ")
    if dataset.build_sha256 != batch.source_build_sha256:
        raise Loop9HumanReviewError("source build binding does not match")
    if dataset.contract_sha256 != batch.contract_canonical_sha256:
        raise Loop9HumanReviewError("source contract binding does not match")
    if dataset.source_snapshot_sha256 != batch.canonical_sha256:
        raise Loop9HumanReviewError("source snapshot binding does not match")
    if (
        formal_selection.target_kind is not batch.target_kind
        or formal_selection.batch_manifest.to_payload()
        != batch.to_payload()
        or dataset.formal_selection_sha256
        != formal_selection.canonical_sha256
        or dataset.locked_gate_evidence_sha256
        != formal_selection.locked_gate_evidence_sha256
    ):
        raise Loop9HumanReviewError(
            "formal selection authority binding does not match"
        )
    source_jobs = {source.job_id for source in batch.sources}
    if source_jobs != {dataset.source_job_id}:
        raise Loop9HumanReviewError("source job binding does not match")

    batch_by_identity = {
        item.platform_waybill_id_digest: item for item in batch.items
    }
    dataset_by_identity = {
        entry.platform_identity_sha256: entry for entry in dataset.entries
    }
    if set(batch_by_identity) != set(dataset_by_identity):
        raise Loop9HumanReviewError("dataset platform identity binding does not match")
    for identity, item in batch_by_identity.items():
        entry = dataset_by_identity[identity]
        source_hashes = {image.sha256 for image in item.images}
        dataset_hashes = {image.image_sha256 for image in entry.images}
        if source_hashes != dataset_hashes:
            raise Loop9HumanReviewError("dataset image binding does not match")
        source_fingerprints = {
            image.sha256: image.perceptual_fingerprint.canonical_sha256
            for image in item.images
        }
        dataset_fingerprints = {
            image.image_sha256: (
                None
                if image.perceptual_fingerprint is None
                else image.perceptual_fingerprint.canonical_sha256
            )
            for image in entry.images
        }
        if (
            any(value is None for value in dataset_fingerprints.values())
            or source_fingerprints != dataset_fingerprints
        ):
            raise Loop9HumanReviewError(
                "dataset perceptual fingerprint binding does not match"
            )


def _normalize_weight(value: object, *, role: str, label: str) -> str | None:
    if role == "unknown":
        if value is not None:
            raise Loop9HumanReviewError(f"{label} must be empty for an unknown role")
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        raise Loop9HumanReviewError(f"{label} is invalid")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise Loop9HumanReviewError(f"{label} is invalid") from exc
    exponent = amount.as_tuple().exponent
    if (
        not amount.is_finite()
        or amount <= 0
        or amount >= Decimal("1000")
        or not isinstance(exponent, int)
        or exponent < -2
    ):
        raise Loop9HumanReviewError(f"{label} is invalid")
    return format(amount.quantize(Decimal("0.01")), "f")


def _normalize_conditions(value: object, *, label: str) -> list[str]:
    raw = _sequence(value, label=label)
    conditions = [
        _required_text(item, label=label, maximum=40) for item in raw
    ]
    if (
        len(conditions) != len(set(conditions))
        or not set(conditions).issubset(_QUALITY_CONDITIONS)
        or len(set(conditions).intersection(_ROTATIONS)) != 1
    ):
        raise Loop9HumanReviewError(
            f"{label} requires one rotation and supported quality values"
        )
    return sorted(conditions)


def _normalize_truth_images(
    value: object,
    *,
    item: ShadowBatchItem,
    label: str,
) -> list[dict[str, object]]:
    raw_images = _sequence(value, label=f"{label} images")
    if len(raw_images) != 2:
        raise Loop9HumanReviewError(f"{label} requires exactly two images")
    expected_by_slot = {image.slot: image for image in item.images}
    normalized: list[dict[str, object]] = []
    seen_slots: set[str] = set()
    for raw_value in raw_images:
        raw = _mapping(raw_value, label=f"{label} image")
        expected_keys = {
            "slot",
            "image_sha256",
            "role",
            "ordinary_net",
            "quality_conditions",
        }
        if set(raw) != expected_keys:
            raise Loop9HumanReviewError(f"{label} image contract is invalid")
        slot = _required_text(raw.get("slot"), label=f"{label} image slot")
        if slot not in {"loading", "unloading"} or slot in seen_slots:
            raise Loop9HumanReviewError(f"{label} image slots are invalid")
        expected_image = expected_by_slot[slot]
        digest = _required_sha256(
            raw.get("image_sha256"),
            label=f"{label} image SHA-256",
        )
        if digest != expected_image.sha256:
            raise Loop9HumanReviewError(f"{label} image binding does not match")
        role = _required_text(raw.get("role"), label=f"{label} image role")
        if role not in _ROLES:
            raise Loop9HumanReviewError(f"{label} image role is invalid")
        conditions = _normalize_conditions(
            raw.get("quality_conditions"),
            label=f"{label} quality conditions",
        )
        ordinary_net = _normalize_weight(
            raw.get("ordinary_net"),
            role=role,
            label=f"{label} ordinary net",
        )
        if "unknown_layout" in conditions and (
            role != "unknown" or ordinary_net is not None
        ):
            raise Loop9HumanReviewError(
                "unknown-layout truth requires an unknown role and empty weight"
            )
        seen_slots.add(slot)
        normalized.append(
            {
                "slot": slot,
                "image_sha256": digest,
                "role": role,
                "ordinary_net": ordinary_net,
                "quality_conditions": conditions,
            }
        )
    if seen_slots != {"loading", "unloading"}:
        raise Loop9HumanReviewError(f"{label} requires both upload slots")
    return sorted(normalized, key=lambda image: cast(str, image["slot"]))


def _validate_pair_condition(
    value: object,
    *,
    images: Sequence[Mapping[str, object]],
    label: str,
) -> str:
    condition = _required_text(value, label=label, maximum=40)
    if condition not in _PAIR_CONDITIONS:
        raise Loop9HumanReviewError(f"{label} is invalid")
    roles = {
        cast(str, image["slot"]): cast(str, image["role"])
        for image in images
    }
    valid = {
        "normal_pair": roles == {
            "loading": "loading",
            "unloading": "unloading",
        },
        "suspected_swapped": roles == {
            "loading": "unloading",
            "unloading": "loading",
        },
        "both_loading": set(roles.values()) == {"loading"},
        "both_unloading": set(roles.values()) == {"unloading"},
        "unknown_or_non_ticket": "unknown" in roles.values(),
    }
    if not valid[condition]:
        raise Loop9HumanReviewError(f"{label} does not match the image roles")
    return condition


def _parse_suggestions(
    value: object,
    *,
    batch: ChengfengShadowBatchManifest,
) -> dict[str, dict[str, object]]:
    _reject_personnel_fields(value, label="draft suggestions")
    raw = _verify_canonical_payload(value, label="draft suggestions")
    expected = {
        "schema_version",
        "kind",
        "target_kind",
        "source_batch_sha256",
        "source_build_sha256",
        "source_contract_sha256",
        "origin",
        "formal_system_results_accessed",
        "suggestions",
        "canonical_sha256",
    }
    if (
        set(raw) != expected
        or raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind") != "loop9_independent_draft_suggestions"
        or raw.get("target_kind") != ShadowBatchTargetKind.CURRENT_LOCKED_50.value
        or raw.get("source_batch_sha256") != batch.canonical_sha256
        or raw.get("source_build_sha256") != batch.source_build_sha256
        or raw.get("source_contract_sha256")
        != batch.contract_canonical_sha256
        or raw.get("origin") != "independent_visual_assistance"
        or raw.get("formal_system_results_accessed") is not False
    ):
        raise Loop9HumanReviewError(
            "draft suggestions are not independently bound to the source"
        )
    by_item = {item.item_identity_sha256: item for item in batch.items}
    normalized: dict[str, dict[str, object]] = {}
    for raw_value in _sequence(raw.get("suggestions"), label="draft suggestions"):
        suggestion = _mapping(raw_value, label="draft suggestion")
        if set(suggestion) != {
            "item_identity_sha256",
            "truth_status",
            "images",
            "pair_condition",
        }:
            raise Loop9HumanReviewError("draft suggestion contract is invalid")
        identity = _required_sha256(
            suggestion.get("item_identity_sha256"),
            label="draft suggestion item identity",
        )
        if identity in normalized or identity not in by_item:
            raise Loop9HumanReviewError("draft suggestion item binding is invalid")
        if suggestion.get("truth_status") != "unconfirmed_non_truth":
            raise Loop9HumanReviewError("draft suggestion must not claim human truth")
        images = _normalize_truth_images(
            suggestion.get("images"),
            item=by_item[identity],
            label="draft suggestion",
        )
        pair_condition = _validate_pair_condition(
            suggestion.get("pair_condition"),
            images=images,
            label="draft suggestion pair condition",
        )
        normalized[identity] = {
            "item_identity_sha256": identity,
            "truth_status": "unconfirmed_non_truth",
            "images": images,
            "pair_condition": pair_condition,
        }
    if set(normalized) != set(by_item):
        raise Loop9HumanReviewError("draft suggestions must cover exactly 50 items")
    return normalized


def _parse_machine_results(
    value: object,
    *,
    batch: ChengfengShadowBatchManifest,
) -> dict[str, dict[str, object]]:
    _reject_personnel_fields(value, label="machine results")
    raw = _verify_canonical_payload(value, label="machine results")
    expected = {
        "schema_version",
        "kind",
        "target_kind",
        "source_batch_sha256",
        "source_build_sha256",
        "source_contract_sha256",
        "pipeline_fingerprint",
        "results",
        "canonical_sha256",
    }
    if (
        set(raw) != expected
        or raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind") != "loop9_machine_audit_results"
        or raw.get("target_kind") != ShadowBatchTargetKind.REAL_SHADOW_30.value
        or raw.get("source_batch_sha256") != batch.canonical_sha256
        or raw.get("source_build_sha256") != batch.source_build_sha256
        or raw.get("source_contract_sha256")
        != batch.contract_canonical_sha256
        or raw.get("pipeline_fingerprint") != batch.pipeline_fingerprint
    ):
        raise Loop9HumanReviewError("machine results authority binding is invalid")
    by_item = {item.item_identity_sha256: item for item in batch.items}
    normalized: dict[str, dict[str, object]] = {}
    for raw_value in _sequence(raw.get("results"), label="machine results"):
        result = _mapping(raw_value, label="machine result")
        if set(result) != {
            "item_identity_sha256",
            "automatic_outcome",
            "issue_code",
            "diagnostic_code",
            "images",
            "result_sha256",
        }:
            raise Loop9HumanReviewError("machine result contract is invalid")
        result_core = {
            key: nested for key, nested in result.items() if key != "result_sha256"
        }
        if _canonical_sha256(result_core) != _required_sha256(
            result.get("result_sha256"),
            label="machine result SHA-256",
        ):
            raise Loop9HumanReviewError("machine result integrity is invalid")
        identity = _required_sha256(
            result.get("item_identity_sha256"),
            label="machine result item identity",
        )
        if identity in normalized or identity not in by_item:
            raise Loop9HumanReviewError("machine result item binding is invalid")
        outcome = _required_text(
            result.get("automatic_outcome"),
            label="machine automatic outcome",
            maximum=40,
        )
        if outcome not in {"normal_ready", "awaiting_review", "technical_failed"}:
            raise Loop9HumanReviewError("machine automatic outcome is invalid")
        issue = result.get("issue_code")
        diagnostic = result.get("diagnostic_code")
        if issue is not None:
            issue = _required_text(issue, label="machine issue code", maximum=100)
        if diagnostic is not None:
            diagnostic = _required_text(
                diagnostic,
                label="machine diagnostic code",
                maximum=100,
            )
        raw_images = _sequence(result.get("images"), label="machine result images")
        expected_images = {
            image.slot: image for image in by_item[identity].images
        }
        images: list[dict[str, object]] = []
        if outcome == "technical_failed":
            if raw_images or diagnostic is None:
                raise Loop9HumanReviewError(
                    "technical failure requires a diagnostic and no business result"
                )
        else:
            if len(raw_images) != 2 or diagnostic is not None:
                raise Loop9HumanReviewError(
                    "business machine result requires exactly two images"
                )
            seen_slots: set[str] = set()
            for raw_image in raw_images:
                image = _mapping(raw_image, label="machine result image")
                if set(image) != {
                    "slot",
                    "image_sha256",
                    "predicted_role",
                    "ordinary_net",
                    "role_high_confidence",
                }:
                    raise Loop9HumanReviewError(
                        "machine result image contract is invalid"
                    )
                slot = _required_text(
                    image.get("slot"),
                    label="machine result image slot",
                )
                if slot not in expected_images or slot in seen_slots:
                    raise Loop9HumanReviewError(
                        "machine result image slot is invalid"
                    )
                digest = _required_sha256(
                    image.get("image_sha256"),
                    label="machine result image SHA-256",
                )
                if digest != expected_images[slot].sha256:
                    raise Loop9HumanReviewError(
                        "machine result image binding does not match"
                    )
                role = _required_text(
                    image.get("predicted_role"),
                    label="machine predicted role",
                )
                if role not in _ROLES:
                    raise Loop9HumanReviewError("machine predicted role is invalid")
                high_confidence = image.get("role_high_confidence")
                if not isinstance(high_confidence, bool):
                    raise Loop9HumanReviewError(
                        "machine role confidence flag is invalid"
                    )
                ordinary_net = _normalize_weight(
                    image.get("ordinary_net"),
                    role=role,
                    label="machine ordinary net",
                )
                seen_slots.add(slot)
                images.append(
                    {
                        "slot": slot,
                        "image_sha256": digest,
                        "predicted_role": role,
                        "ordinary_net": ordinary_net,
                        "role_high_confidence": high_confidence,
                    }
                )
            if seen_slots != {"loading", "unloading"}:
                raise Loop9HumanReviewError(
                    "machine result requires both upload slots"
                )
        normalized_core: dict[str, object] = {
            "item_identity_sha256": identity,
            "automatic_outcome": outcome,
            "issue_code": issue,
            "diagnostic_code": diagnostic,
            "images": sorted(
                images,
                key=lambda image: cast(str, image["slot"]),
            ),
        }
        normalized[identity] = {
            **normalized_core,
            "result_sha256": _canonical_sha256(normalized_core),
        }
    if set(normalized) != set(by_item):
        raise Loop9HumanReviewError("machine results must cover exactly 30 items")
    return normalized


def _binding_payload(
    *,
    batch: ChengfengShadowBatchManifest,
    dataset: Loop9DatasetManifest,
) -> dict[str, object]:
    return {
        "contract_canonical_sha256": batch.contract_canonical_sha256,
        "contract_file_sha256": batch.contract_file_sha256,
        "contract_selection_sha256": batch.contract_selection_sha256,
        "dataset_id": dataset.dataset_id,
        "dataset_manifest_sha256": dataset.canonical_sha256,
        "formal_selection_sha256": (
            dataset.formal_selection_sha256
        ),
        "identity_context_sha256": batch.identity_context_sha256,
        "pipeline_fingerprint": batch.pipeline_fingerprint,
        "locked_gate_evidence_sha256": (
            dataset.locked_gate_evidence_sha256
        ),
        "source_batch_sha256": batch.canonical_sha256,
        "source_build_sha256": batch.source_build_sha256,
        "source_job_id": dataset.source_job_id,
        "source_snapshot_sha256": dataset.source_snapshot_sha256,
    }


def _item_payload(
    *,
    position: int,
    item: ShadowBatchItem,
    review_kind: ShadowBatchTargetKind,
    auxiliary: Mapping[str, dict[str, object]],
) -> dict[str, object]:
    images = [
        {
            "slot": image.slot,
            "image_sha256": image.sha256,
            "relative_path": (
                PurePosixPath("images") / _content_addressed_path(image.sha256)
            ).as_posix(),
            "byte_size": image.byte_size,
            "media_type": image.media_type,
            "perceptual_fingerprint_sha256": (
                image.perceptual_fingerprint.canonical_sha256
            ),
        }
        for image in item.images
    ]
    payload: dict[str, object] = {
        "position": position,
        "item_identity_sha256": item.item_identity_sha256,
        "platform_identity_sha256": item.platform_waybill_id_digest,
        "platform_weights": {
            "loading": item.platform_loading_net,
            "unloading": item.platform_unloading_net,
        },
        "images": images,
    }
    if review_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        payload["draft_suggestion"] = auxiliary[item.item_identity_sha256]
    else:
        payload["machine_result"] = auxiliary[item.item_identity_sha256]
    return payload


def _package_core(
    *,
    batch: ChengfengShadowBatchManifest,
    dataset: Loop9DatasetManifest,
    auxiliary: Mapping[str, dict[str, object]],
    source_files: Mapping[str, object],
) -> dict[str, object]:
    sorted_items = sorted(batch.items, key=lambda item: item.item_identity_sha256)
    core: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "loop9_human_review_package",
        "review_kind": batch.target_kind.value,
        "status": "awaiting_human_confirmation",
        "item_count": len(sorted_items),
        "image_count": sum(len(item.images) for item in sorted_items),
        "binding": _binding_payload(batch=batch, dataset=dataset),
        "source_files": dict(source_files),
        "items": [
            _item_payload(
                position=position,
                item=item,
                review_kind=batch.target_kind,
                auxiliary=auxiliary,
            )
            for position, item in enumerate(sorted_items, start=1)
        ],
    }
    if batch.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        core["draft_advisory"] = {
            "truth_status": "unconfirmed_non_truth",
            "formal_system_results_accessed": False,
            "message": "辅助建议，尚未成为真值",  # noqa: RUF001
        }
    else:
        core["result_advisory"] = {
            "machine_results_are_not_human_truth": True,
            "human_confirmation_required_for_every_item": True,
            "message": "机器结果必须逐条与原图人工核对",
        }
    return core


def _source_file_record(
    *,
    relative_path: str,
    content: bytes,
    canonical_sha256: str,
) -> dict[str, object]:
    return {
        "relative_path": relative_path,
        "file_sha256": hashlib.sha256(content).hexdigest(),
        "canonical_sha256": canonical_sha256,
    }


def _cleanup_staging(staging: Path, *, parent: Path) -> None:
    if (
        staging.parent == parent
        and staging.name.startswith(".loop9-review-")
        and staging.exists()
        and not staging.is_symlink()
        and not _is_reparse_point(staging)
    ):
        shutil.rmtree(staging)


@dataclass(frozen=True, slots=True)
class Loop9ReviewPackage:
    root: Path
    payload: dict[str, object]
    source_batch: ChengfengShadowBatchManifest
    dataset_manifest: Loop9DatasetManifest
    formal_selection: FormalShadowSelectionManifest
    auxiliary: dict[str, object]

    def read_verified_image(
        self,
        image_sha256: str,
    ) -> tuple[bytes, str]:
        """Read one packaged image after repeating its content-address check."""

        digest = _required_sha256(
            image_sha256,
            label="review image SHA-256",
        )
        matches = [
            image
            for item in self.source_batch.items
            for image in item.images
            if image.sha256 == digest
        ]
        if len(matches) != 1:
            raise Loop9HumanReviewError(
                "review image identity is unavailable or duplicated"
            )
        image = matches[0]
        content = _read_verified_image(
            image_root=self.root / "images",
            relative_path=_content_addressed_path(digest).as_posix(),
            expected_sha256=digest,
            expected_size=image.byte_size,
            expected_media_type=image.media_type,
        )
        return content, image.media_type


def prepare_loop9_review_package(
    *,
    source_batch_path: Path,
    dataset_manifest_path: Path,
    formal_selection: FormalShadowSelectionManifest,
    image_root: Path,
    auxiliary_path: Path,
    output_dir: Path,
) -> Loop9ReviewPackage:
    """Create one immutable, content-addressed offline review package."""

    source_batch_payload = _load_json(
        source_batch_path,
        label="source batch manifest",
    )
    dataset_payload = _load_json(
        dataset_manifest_path,
        label="dataset manifest",
    )
    auxiliary_payload = _load_json(auxiliary_path, label="review auxiliary")
    _reject_personnel_fields(auxiliary_payload, label="review auxiliary")
    batch = _parse_batch(source_batch_payload)
    dataset = _parse_dataset(dataset_payload)
    if not isinstance(formal_selection, FormalShadowSelectionManifest):
        raise Loop9HumanReviewError(
            "formal selection authority is required"
        )
    _validate_source_binding(
        batch=batch,
        dataset=dataset,
        formal_selection=formal_selection,
    )
    if batch.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        auxiliary = _parse_suggestions(auxiliary_payload, batch=batch)
    else:
        auxiliary = _parse_machine_results(auxiliary_payload, batch=batch)
    resolved_image_root = _resolved_existing_directory(
        image_root,
        label="image root",
    )
    parent, output = _safe_output(output_dir, label="review package")
    staging = parent / f".loop9-review-{uuid4().hex}.tmp"
    try:
        staging.mkdir()
        source_dir = staging / "source"
        source_dir.mkdir()
        package_image_root = staging / "images"
        package_image_root.mkdir()

        serialized_sources = {
            "source_batch": _json_bytes(source_batch_payload),
            "dataset_manifest": _json_bytes(dataset_payload),
            "formal_selection": _json_bytes(
                formal_selection.to_payload()
            ),
            "auxiliary": _json_bytes(auxiliary_payload),
        }
        source_paths = {
            "source_batch": "source/source-batch.json",
            "dataset_manifest": "source/dataset-manifest.json",
            "formal_selection": "source/formal-selection.json",
            "auxiliary": "source/review-auxiliary.json",
        }
        canonical_values = {
            "source_batch": batch.canonical_sha256,
            "dataset_manifest": dataset.canonical_sha256,
            "formal_selection": formal_selection.canonical_sha256,
            "auxiliary": _required_sha256(
                _mapping(
                    auxiliary_payload,
                    label="review auxiliary",
                ).get("canonical_sha256"),
                label="review auxiliary canonical SHA-256",
            ),
        }
        source_files: dict[str, object] = {}
        for key, content in serialized_sources.items():
            relative = source_paths[key]
            _write_file_exclusive(staging / Path(relative), content)
            source_files[key] = _source_file_record(
                relative_path=relative,
                content=content,
                canonical_sha256=canonical_values[key],
            )

        for item in batch.items:
            for image in item.images:
                content = _read_verified_image(
                    image_root=resolved_image_root,
                    relative_path=image.relative_path,
                    expected_sha256=image.sha256,
                    expected_size=image.byte_size,
                    expected_media_type=image.media_type,
                )
                image_relative = _content_addressed_path(image.sha256)
                destination = package_image_root / Path(
                    image_relative.as_posix()
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                _write_file_exclusive(destination, content)

        core = _package_core(
            batch=batch,
            dataset=dataset,
            auxiliary=auxiliary,
            source_files=source_files,
        )
        payload = {**core, "canonical_sha256": _canonical_sha256(core)}
        _reject_personnel_fields(payload, label="review package")
        _write_file_exclusive(staging / "review-package.json", _json_bytes(payload))
        try:
            staging.rename(output)
        except OSError as exc:
            raise Loop9HumanReviewError(
                "review package could not be published atomically"
            ) from exc
    except Exception:
        _cleanup_staging(staging, parent=parent)
        raise
    return load_loop9_review_package(output)


def _package_source_file(
    *,
    root: Path,
    record: object,
    expected_relative_path: str,
    label: str,
) -> object:
    raw = _mapping(record, label=f"{label} source record")
    if set(raw) != {"relative_path", "file_sha256", "canonical_sha256"}:
        raise Loop9HumanReviewError(f"{label} source record is invalid")
    if raw.get("relative_path") != expected_relative_path:
        raise Loop9HumanReviewError(f"{label} source path is invalid")
    path = root / Path(expected_relative_path)
    resolved = _resolved_existing_file(path, label=label)
    if not resolved.is_relative_to(root):
        raise Loop9HumanReviewError(f"{label} source path is unsafe")
    content = resolved.read_bytes()
    if hashlib.sha256(content).hexdigest() != _required_sha256(
        raw.get("file_sha256"),
        label=f"{label} source file SHA-256",
    ):
        raise Loop9HumanReviewError(f"{label} source file integrity is invalid")
    value = _load_json(resolved, label=label)
    if _mapping(value, label=label).get("canonical_sha256") != _required_sha256(
        raw.get("canonical_sha256"),
        label=f"{label} canonical SHA-256",
    ):
        raise Loop9HumanReviewError(f"{label} canonical binding is invalid")
    return value


def _validate_packaged_images(
    *,
    root: Path,
    batch: ChengfengShadowBatchManifest,
) -> None:
    for item in batch.items:
        for image in item.images:
            relative = (
                PurePosixPath("images") / _content_addressed_path(image.sha256)
            )
            _read_verified_image(
                image_root=root / "images",
                relative_path=_content_addressed_path(image.sha256).as_posix(),
                expected_sha256=image.sha256,
                expected_size=image.byte_size,
                expected_media_type=image.media_type,
            )
            if not (root / Path(relative.as_posix())).is_file():
                raise Loop9HumanReviewError("review package image is unavailable")


def _validate_package_inventory(
    *,
    root: Path,
    batch: ChengfengShadowBatchManifest,
) -> None:
    expected = {
        "review-package.json",
        "source/source-batch.json",
        "source/dataset-manifest.json",
        "source/formal-selection.json",
        "source/review-auxiliary.json",
    }
    expected.update(
        (
            PurePosixPath("images")
            / _content_addressed_path(image.sha256)
        ).as_posix()
        for item in batch.items
        for image in item.images
    )
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink() or _is_reparse_point(path):
            raise Loop9HumanReviewError("review package contains an unsafe path")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        raise Loop9HumanReviewError(
            "review package file inventory is incomplete or contains extras"
        )


def load_loop9_review_package(path: Path) -> Loop9ReviewPackage:
    """Reload and independently rehash an immutable Loop 9 review package."""

    root = _resolved_existing_directory(path, label="review package")
    package_path = root / "review-package.json"
    package_value = _load_json(package_path, label="review package")
    _reject_personnel_fields(package_value, label="review package")
    package_raw = _verify_canonical_payload(
        package_value,
        label="review package",
    )
    common_fields = {
        "schema_version",
        "kind",
        "review_kind",
        "status",
        "item_count",
        "image_count",
        "binding",
        "source_files",
        "items",
        "canonical_sha256",
    }
    review_kind = package_raw.get("review_kind")
    expected_fields = set(common_fields)
    if review_kind == ShadowBatchTargetKind.CURRENT_LOCKED_50.value:
        expected_fields.add("draft_advisory")
    elif review_kind == ShadowBatchTargetKind.REAL_SHADOW_30.value:
        expected_fields.add("result_advisory")
    else:
        raise Loop9HumanReviewError("review package classification is invalid")
    if (
        set(package_raw) != expected_fields
        or package_raw.get("schema_version") != SCHEMA_VERSION
        or package_raw.get("kind") != "loop9_human_review_package"
        or package_raw.get("status") != "awaiting_human_confirmation"
    ):
        raise Loop9HumanReviewError("review package contract is invalid")
    source_files = _mapping(
        package_raw.get("source_files"),
        label="review package source files",
    )
    if set(source_files) != {
        "source_batch",
        "dataset_manifest",
        "formal_selection",
        "auxiliary",
    }:
        raise Loop9HumanReviewError("review package source files are incomplete")
    batch_payload = _package_source_file(
        root=root,
        record=source_files["source_batch"],
        expected_relative_path="source/source-batch.json",
        label="source batch manifest",
    )
    dataset_payload = _package_source_file(
        root=root,
        record=source_files["dataset_manifest"],
        expected_relative_path="source/dataset-manifest.json",
        label="dataset manifest",
    )
    auxiliary_payload = _package_source_file(
        root=root,
        record=source_files["auxiliary"],
        expected_relative_path="source/review-auxiliary.json",
        label="review auxiliary",
    )
    formal_selection_payload = _package_source_file(
        root=root,
        record=source_files["formal_selection"],
        expected_relative_path="source/formal-selection.json",
        label="formal selection manifest",
    )
    batch = _parse_batch(batch_payload)
    dataset = _parse_dataset(dataset_payload)
    formal_selection = _parse_formal_selection(
        formal_selection_payload
    )
    _validate_source_binding(
        batch=batch,
        dataset=dataset,
        formal_selection=formal_selection,
    )
    if batch.target_kind.value != review_kind:
        raise Loop9HumanReviewError("review package classification binding is invalid")
    if batch.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        auxiliary = _parse_suggestions(auxiliary_payload, batch=batch)
    else:
        auxiliary = _parse_machine_results(auxiliary_payload, batch=batch)
    expected_core = _package_core(
        batch=batch,
        dataset=dataset,
        auxiliary=auxiliary,
        source_files=source_files,
    )
    actual_core = {
        key: value
        for key, value in package_raw.items()
        if key != "canonical_sha256"
    }
    if actual_core != expected_core:
        raise Loop9HumanReviewError("review package source binding is invalid")
    _validate_packaged_images(root=root, batch=batch)
    _validate_package_inventory(root=root, batch=batch)
    return Loop9ReviewPackage(
        root=root,
        payload=dict(package_raw),
        source_batch=batch,
        dataset_manifest=dataset,
        formal_selection=formal_selection,
        auxiliary=dict(_mapping(auxiliary_payload, label="review auxiliary")),
    )


def _parse_confirmed_at(value: object) -> str:
    text = _required_text(
        value,
        label="review confirmation time",
        maximum=40,
    )
    if not text.endswith("Z"):
        raise Loop9HumanReviewError("review confirmation time must be UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise Loop9HumanReviewError(
            "review confirmation time is invalid"
        ) from exc
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise Loop9HumanReviewError("review confirmation time must be UTC")
    return text


def normalize_loop9_review_truth(
    *,
    package: Loop9ReviewPackage,
    item_identity_sha256: str,
    value: object,
) -> dict[str, object]:
    """Normalize one UI review with the same contract used by formal sealing."""

    identity = _required_sha256(
        item_identity_sha256,
        label="human review item identity",
    )
    items = {
        item.item_identity_sha256: item
        for item in package.source_batch.items
    }
    item = items.get(identity)
    if item is None:
        raise Loop9HumanReviewError("human review item binding is invalid")
    raw = _mapping(value, label="human review truth")
    if set(raw) != {"images", "pair_condition"}:
        raise Loop9HumanReviewError("human review truth contract is invalid")
    images = _normalize_truth_images(
        raw.get("images"),
        item=item,
        label="human review truth",
    )
    pair_condition = _validate_pair_condition(
        raw.get("pair_condition"),
        images=images,
        label="human review truth pair condition",
    )
    return {
        "images": images,
        "pair_condition": pair_condition,
    }


def _parse_reviews(
    *,
    package: Loop9ReviewPackage,
    value: object,
) -> tuple[str, list[dict[str, object]]]:
    _reject_personnel_fields(value, label="human review answers")
    raw = _verify_canonical_payload(value, label="human review answers")
    if set(raw) != {
        "schema_version",
        "kind",
        "review_kind",
        "package_sha256",
        "reviews",
        "canonical_sha256",
    }:
        raise Loop9HumanReviewError("human review answers contract is invalid")
    review_kind = cast(str, package.payload["review_kind"])
    if (
        raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind") != "loop9_human_review_answers"
        or raw.get("review_kind") != review_kind
        or raw.get("package_sha256") != package.payload["canonical_sha256"]
    ):
        raise Loop9HumanReviewError("human review answers binding is invalid")
    items_by_identity = {
        item.item_identity_sha256: item for item in package.source_batch.items
    }
    reviews: dict[str, dict[str, object]] = {}
    for raw_value in _sequence(raw.get("reviews"), label="human reviews"):
        review = _mapping(raw_value, label="human review")
        if set(review) != {
            "item_identity_sha256",
            "confirmed_at",
            "images",
            "pair_condition",
            "confirmation",
        }:
            raise Loop9HumanReviewError(
                "human review contains a prohibited identity or unexpected field"
            )
        identity = _required_sha256(
            review.get("item_identity_sha256"),
            label="human review item identity",
        )
        if identity in reviews or identity not in items_by_identity:
            raise Loop9HumanReviewError("human review item binding is invalid")
        images = _normalize_truth_images(
            review.get("images"),
            item=items_by_identity[identity],
            label="human review",
        )
        pair_condition = _validate_pair_condition(
            review.get("pair_condition"),
            images=images,
            label="human review pair condition",
        )
        confirmation = _required_text(
            review.get("confirmation"),
            label="human review confirmation",
            maximum=40,
        )
        allowed = (
            {"suggestion_confirmed", "corrected"}
            if review_kind == ShadowBatchTargetKind.CURRENT_LOCKED_50.value
            else {"machine_result_confirmed", "difference_confirmed"}
        )
        if confirmation not in allowed:
            raise Loop9HumanReviewError("human review confirmation is invalid")
        reviews[identity] = {
            "item_identity_sha256": identity,
            "confirmed_at": _parse_confirmed_at(review.get("confirmed_at")),
            "images": images,
            "pair_condition": pair_condition,
            "confirmation": confirmation,
        }
    expected_count = package.source_batch.target_kind.expected_count
    if len(reviews) != expected_count or set(reviews) != set(items_by_identity):
        raise Loop9HumanReviewError(
            f"human review answers require exactly {expected_count} confirmed items"
        )
    return cast(str, raw["canonical_sha256"]), [
        reviews[identity] for identity in sorted(reviews)
    ]


def _truth_without_advisory(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "images": value["images"],
        "pair_condition": value["pair_condition"],
    }


def _quality_coverage(reviews: Sequence[Mapping[str, object]]) -> dict[str, object]:
    conditions: dict[str, list[str]] = {
        condition: [] for condition in _LOCKED_REQUIRED_CONDITIONS
    }
    for review in reviews:
        for image in cast(Sequence[Mapping[str, object]], review["images"]):
            digest = cast(str, image["image_sha256"])
            for condition in cast(Sequence[str], image["quality_conditions"]):
                if condition in conditions:
                    conditions[condition].append(digest)
    missing = [
        condition for condition, hashes in conditions.items() if not hashes
    ]
    if missing:
        raise Loop9HumanReviewError(
            "locked review quality coverage is incomplete: " + ", ".join(missing)
        )
    if set(conditions["printed"]).intersection(conditions["screen"]):
        raise Loop9HumanReviewError(
            "printed and screen quality conditions require different images"
        )
    for hashes in conditions.values():
        hashes.sort()
    return {
        "passed": True,
        "conditions": conditions,
    }


def _platform_weights(item: ShadowBatchItem) -> dict[str, str]:
    return {
        "loading": format(Decimal(item.platform_loading_net).quantize(Decimal("0.01")), "f"),
        "unloading": format(
            Decimal(item.platform_unloading_net).quantize(Decimal("0.01")),
            "f",
        ),
    }


def _expected_human_outcome(
    *,
    item: ShadowBatchItem,
    review: Mapping[str, object],
) -> str:
    if review["pair_condition"] != "normal_pair":
        return "awaiting_review"
    human_weights = {
        cast(str, image["slot"]): cast(str, image["ordinary_net"])
        for image in cast(Sequence[Mapping[str, object]], review["images"])
    }
    return (
        "normal_ready"
        if human_weights == _platform_weights(item)
        else "awaiting_review"
    )


def _compare_machine_result(
    *,
    item: ShadowBatchItem,
    review: Mapping[str, object],
    result: Mapping[str, object],
) -> tuple[dict[str, object], int]:
    outcome = cast(str, result["automatic_outcome"])
    expected_outcome = _expected_human_outcome(item=item, review=review)
    if outcome == "technical_failed":
        return (
            {
                "classification": "technical_failure",
                "expected_outcome": expected_outcome,
                "actual_outcome": outcome,
                "image_difference_count": 0,
                "high_confidence_role_error_count": 0,
                "wrong_auto_pass": False,
                "diagnostic_code": result["diagnostic_code"],
            },
            0,
        )
    truth_by_slot = {
        cast(str, image["slot"]): image
        for image in cast(Sequence[Mapping[str, object]], review["images"])
    }
    image_difference_count = 0
    high_confidence_role_error_count = 0
    for machine_image in cast(
        Sequence[Mapping[str, object]],
        result["images"],
    ):
        slot = cast(str, machine_image["slot"])
        truth = truth_by_slot[slot]
        role_error = machine_image["predicted_role"] != truth["role"]
        weight_error = machine_image["ordinary_net"] != truth["ordinary_net"]
        if role_error or weight_error:
            image_difference_count += 1
        if role_error and machine_image["role_high_confidence"] is True:
            high_confidence_role_error_count += 1
    exact = image_difference_count == 0 and outcome == expected_outcome
    wrong_auto_pass = outcome == "normal_ready" and (
        expected_outcome != "normal_ready" or image_difference_count > 0
    )
    classification = (
        "match"
        if exact
        else ("wrong_auto_pass" if wrong_auto_pass else "reviewed_difference")
    )
    return (
        {
            "classification": classification,
            "expected_outcome": expected_outcome,
            "actual_outcome": outcome,
            "image_difference_count": image_difference_count,
            "high_confidence_role_error_count": (
                high_confidence_role_error_count
            ),
            "wrong_auto_pass": wrong_auto_pass,
            "diagnostic_code": None,
        },
        high_confidence_role_error_count,
    )


def _build_seal_core(
    *,
    package: Loop9ReviewPackage,
    review_answers_sha256: str,
    reviews: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    kind = package.source_batch.target_kind
    item_by_identity = {
        item.item_identity_sha256: item for item in package.source_batch.items
    }
    stored_reviews: list[dict[str, object]] = []
    confirmation_counts: dict[str, int] = {}
    core: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "loop9_human_review_seal",
        "review_kind": kind.value,
        "status": "sealed",
        "package_sha256": package.payload["canonical_sha256"],
        "dataset_manifest_sha256": (
            package.dataset_manifest.canonical_sha256
        ),
        "source_build_sha256": package.source_batch.source_build_sha256,
        "contract_canonical_sha256": (
            package.source_batch.contract_canonical_sha256
        ),
        "review_answers_sha256": review_answers_sha256,
        "review_count": len(reviews),
        "image_truth_count": sum(
            len(cast(Sequence[object], review["images"])) for review in reviews
        ),
    }
    if kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        suggestions = _parse_suggestions(
            package.auxiliary,
            batch=package.source_batch,
        )
        for review in reviews:
            identity = cast(str, review["item_identity_sha256"])
            confirmation = cast(str, review["confirmation"])
            truth = _truth_without_advisory(review)
            suggestion_truth = _truth_without_advisory(suggestions[identity])
            if confirmation == "suggestion_confirmed" and truth != suggestion_truth:
                raise Loop9HumanReviewError(
                    "suggestion-confirmed review differs from its draft"
                )
            if confirmation == "corrected" and truth == suggestion_truth:
                raise Loop9HumanReviewError(
                    "corrected review must change the draft suggestion"
                )
            confirmation_counts[confirmation] = (
                confirmation_counts.get(confirmation, 0) + 1
            )
            stored_reviews.append(dict(review))
        core["quality_coverage"] = _quality_coverage(reviews)
        core["confirmation_summary"] = {
            "corrected": confirmation_counts.get("corrected", 0),
            "suggestion_confirmed": confirmation_counts.get(
                "suggestion_confirmed",
                0,
            ),
        }
        core["human_review_complete"] = True
        core["formal_accuracy_claim"] = False
    else:
        machine_results = _parse_machine_results(
            package.auxiliary,
            batch=package.source_batch,
        )
        matched = 0
        differences = 0
        technical_failures = 0
        wrong_auto_pass = 0
        high_confidence_errors = 0
        for review in reviews:
            identity = cast(str, review["item_identity_sha256"])
            comparison, high_confidence_count = _compare_machine_result(
                item=item_by_identity[identity],
                review=review,
                result=machine_results[identity],
            )
            classification = cast(str, comparison["classification"])
            expected_confirmation = (
                "machine_result_confirmed"
                if classification == "match"
                else "difference_confirmed"
            )
            if review["confirmation"] != expected_confirmation:
                raise Loop9HumanReviewError(
                    "human confirmation does not match the computed difference"
                )
            matched += classification == "match"
            differences += classification in {
                "reviewed_difference",
                "wrong_auto_pass",
            }
            technical_failures += classification == "technical_failure"
            wrong_auto_pass += classification == "wrong_auto_pass"
            high_confidence_errors += high_confidence_count
            stored_reviews.append(
                {
                    **dict(review),
                    "comparison": comparison,
                }
            )
        summary = {
            "matched_count": matched,
            "reviewed_difference_count": differences,
            "technical_failure_count": technical_failures,
            "wrong_auto_pass_count": wrong_auto_pass,
            "high_confidence_role_error_count": high_confidence_errors,
            "unresolved_difference_count": 0,
        }
        core["comparison_summary"] = summary
        core["shadow_gate_passed"] = (
            technical_failures == 0
            and wrong_auto_pass == 0
            and high_confidence_errors == 0
        )
        core["human_review_complete"] = True
    core["reviews"] = stored_reviews
    _reject_personnel_fields(core, label="human review seal")
    return core


def seal_loop9_review(
    *,
    package_dir: Path,
    review_answers_path: Path,
    output_path: Path,
) -> dict[str, object]:
    """Seal all per-item human truth without recording personnel identity."""

    package = load_loop9_review_package(package_dir)
    answers_value = _load_json(
        review_answers_path,
        label="human review answers",
    )
    review_answers_sha256, reviews = _parse_reviews(
        package=package,
        value=answers_value,
    )
    core = _build_seal_core(
        package=package,
        review_answers_sha256=review_answers_sha256,
        reviews=reviews,
    )
    payload = {**core, "canonical_sha256": _canonical_sha256(core)}
    _write_json_exclusive(output_path, payload)
    return payload


def _load_and_validate_seal(
    *,
    package: Loop9ReviewPackage,
    seal_path: Path,
) -> dict[str, object]:
    value = _load_json(seal_path, label="human review seal")
    _reject_personnel_fields(value, label="human review seal")
    raw = _verify_canonical_payload(value, label="human review seal")
    review_kind = package.source_batch.target_kind
    common_fields = {
        "schema_version",
        "kind",
        "review_kind",
        "status",
        "package_sha256",
        "dataset_manifest_sha256",
        "source_build_sha256",
        "contract_canonical_sha256",
        "review_answers_sha256",
        "review_count",
        "image_truth_count",
        "human_review_complete",
        "reviews",
        "canonical_sha256",
    }
    expected = set(common_fields)
    if review_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
        expected.update(
            {
                "quality_coverage",
                "confirmation_summary",
                "formal_accuracy_claim",
            }
        )
    else:
        expected.update({"comparison_summary", "shadow_gate_passed"})
    if (
        set(raw) != expected
        or raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind") != "loop9_human_review_seal"
        or raw.get("review_kind") != review_kind.value
        or raw.get("status") != "sealed"
        or raw.get("package_sha256") != package.payload["canonical_sha256"]
        or raw.get("dataset_manifest_sha256")
        != package.dataset_manifest.canonical_sha256
        or raw.get("source_build_sha256")
        != package.source_batch.source_build_sha256
        or raw.get("contract_canonical_sha256")
        != package.source_batch.contract_canonical_sha256
    ):
        raise Loop9HumanReviewError("human review seal binding is invalid")
    raw_reviews = _sequence(raw.get("reviews"), label="sealed reviews")
    human_reviews: list[Mapping[str, object]] = []
    for value in raw_reviews:
        review = _mapping(value, label="sealed review")
        if review_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
            if set(review) != {
                "item_identity_sha256",
                "confirmed_at",
                "images",
                "pair_condition",
                "confirmation",
                "comparison",
            }:
                raise Loop9HumanReviewError("sealed shadow review is invalid")
            human_reviews.append(
                {
                    key: nested
                    for key, nested in review.items()
                    if key != "comparison"
                }
            )
        else:
            human_reviews.append(review)
    expected_core = _build_seal_core(
        package=package,
        review_answers_sha256=_required_sha256(
            raw.get("review_answers_sha256"),
            label="review answers SHA-256",
        ),
        reviews=human_reviews,
    )
    actual_core = {
        key: nested for key, nested in raw.items() if key != "canonical_sha256"
    }
    if actual_core != expected_core:
        raise Loop9HumanReviewError("human review seal replay does not reconcile")
    return dict(raw)


def _validate_isolation_evidence(
    *,
    package: Loop9ReviewPackage,
    path: Path,
) -> str:
    value = _load_json(path, label="dataset isolation evidence")
    _reject_personnel_fields(value, label="dataset isolation evidence")
    raw = _verify_canonical_payload(value, label="dataset isolation evidence")
    if (
        raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("isolation_passed") is not True
        or raw.get("exact_identity_overlap_count") != 0
        or raw.get("exact_image_overlap_count") != 0
        or raw.get("perceptual_overlap_count") != 0
        or raw.get("current_locked_image_count") != 100
        or raw.get("real_shadow_entry_count") != 30
    ):
        raise Loop9HumanReviewError("dataset isolation gate did not pass")
    bindings = _sequence(
        raw.get("dataset_bindings"),
        label="dataset isolation bindings",
    )
    binding_kinds = [
        binding.get("dataset_kind")
        for binding in bindings
        if isinstance(binding, dict)
    ]
    if (
        len(binding_kinds) != len(bindings)
        or set(binding_kinds)
        != {
            "discovery_development",
            "current_locked_50",
            "real_shadow_30",
            "daily_validation",
        }
        or len(binding_kinds) != len(set(binding_kinds))
    ):
        raise Loop9HumanReviewError(
            "dataset isolation evidence bindings are incomplete"
        )
    expected_kind = package.source_batch.target_kind.value
    matching = [
        _mapping(binding, label="dataset isolation binding")
        for binding in bindings
        if isinstance(binding, dict)
        and binding.get("dataset_kind") == expected_kind
    ]
    if len(matching) != 1:
        raise Loop9HumanReviewError(
            "dataset isolation evidence has no unique review binding"
        )
    binding = matching[0]
    expected = {
        "dataset_kind": expected_kind,
        "dataset_id": package.dataset_manifest.dataset_id,
        "manifest_sha256": package.dataset_manifest.canonical_sha256,
        "formal_selection_sha256": (
            package.dataset_manifest.formal_selection_sha256
        ),
        "build_sha256": package.source_batch.source_build_sha256,
        "contract_sha256": package.source_batch.contract_canonical_sha256,
        "source_job_id": package.dataset_manifest.source_job_id,
        "source_snapshot_sha256": (
            package.dataset_manifest.source_snapshot_sha256
        ),
        "locked_gate_evidence_sha256": (
            package.dataset_manifest.locked_gate_evidence_sha256
        ),
        "entry_count": package.source_batch.target_kind.expected_count,
        "image_count": sum(
            len(item.images) for item in package.source_batch.items
        ),
    }
    for key, expected_value in expected.items():
        if binding.get(key) != expected_value:
            raise Loop9HumanReviewError(
                "dataset isolation binding does not match the review package"
            )
    return _required_sha256(
        raw.get("canonical_sha256"),
        label="dataset isolation evidence SHA-256",
    )


def replay_loop9_review(
    *,
    package_dir: Path,
    seal_path: Path,
    isolation_evidence_path: Path,
) -> dict[str, object]:
    """Replay package, image, seal and cross-dataset isolation hashes."""

    package = load_loop9_review_package(package_dir)
    seal = _load_and_validate_seal(package=package, seal_path=seal_path)
    isolation_sha256 = _validate_isolation_evidence(
        package=package,
        path=isolation_evidence_path,
    )
    core: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "loop9_human_review_replay",
        "review_kind": package.source_batch.target_kind.value,
        "package_sha256": package.payload["canonical_sha256"],
        "seal_sha256": seal["canonical_sha256"],
        "dataset_manifest_sha256": (
            package.dataset_manifest.canonical_sha256
        ),
        "source_build_sha256": package.source_batch.source_build_sha256,
        "contract_canonical_sha256": (
            package.source_batch.contract_canonical_sha256
        ),
        "cross_dataset_isolation_sha256": isolation_sha256,
        "cross_dataset_isolation_passed": True,
        "review_count": seal["review_count"],
        "image_truth_count": seal["image_truth_count"],
        "human_review_complete": True,
        "human_review_seal_valid": True,
        "machine_comparison_gate_passed": (
            None
            if package.source_batch.target_kind
            is ShadowBatchTargetKind.CURRENT_LOCKED_50
            else seal["shadow_gate_passed"]
        ),
        "formal_accuracy_claim": False,
        "replay_passed": True,
    }
    _reject_personnel_fields(core, label="human review replay")
    return {**core, "canonical_sha256": _canonical_sha256(core)}


def write_loop9_review_evidence(
    *,
    output_path: Path,
    payload: dict[str, object],
) -> None:
    """Publish a verified replay payload without permitting overwrite."""

    _reject_personnel_fields(payload, label="human review replay")
    raw = _verify_canonical_payload(payload, label="human review replay")
    if (
        raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind") != "loop9_human_review_replay"
        or raw.get("replay_passed") is not True
    ):
        raise Loop9HumanReviewError("human review replay contract is invalid")
    _write_json_exclusive(output_path, dict(raw))
