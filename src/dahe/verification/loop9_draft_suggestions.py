from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
    ShadowBatchItem,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)

SCHEMA_VERSION = 1
_MAX_JSON_BYTES = 20 * 1024 * 1024
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
_ROLES = {"loading", "unloading", "unknown"}
_PAIR_CONDITIONS = {
    "normal_pair",
    "suspected_swapped",
    "both_loading",
    "both_unloading",
    "unknown_or_non_ticket",
}


class Loop9DraftSuggestionError(ValueError):
    """Raised when an independent visual draft is unsafe or inconsistent."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise Loop9DraftSuggestionError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise Loop9DraftSuggestionError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9DraftSuggestionError(
            f"{label} must be a lowercase SHA-256"
        )
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
        raise Loop9DraftSuggestionError(f"{label} is invalid")
    return value


def _reject_personnel_fields(value: object, *, label: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str) and _PERSONNEL_FIELD.search(key.lower()):
                raise Loop9DraftSuggestionError(
                    f"{label} contains a prohibited personnel identity field"
                )
            _reject_personnel_fields(nested, label=label)
    elif isinstance(value, list):
        for nested in value:
            _reject_personnel_fields(nested, label=label)


def verify_current_locked_source_binding(
    *,
    formal_selection: FormalShadowSelectionManifest,
    source_batch: ChengfengShadowBatchManifest,
) -> None:
    """Verify the exact 50-item batch embedded in one formal selection."""

    if (
        not isinstance(formal_selection, FormalShadowSelectionManifest)
        or not isinstance(source_batch, ChengfengShadowBatchManifest)
        or formal_selection.target_kind
        is not ShadowBatchTargetKind.CURRENT_LOCKED_50
        or source_batch.target_kind
        is not ShadowBatchTargetKind.CURRENT_LOCKED_50
        or formal_selection.batch_manifest.to_payload()
        != source_batch.to_payload()
    ):
        raise Loop9DraftSuggestionError(
            "source batch does not match the current locked formal selection"
        )
    formal_selection.verify_integrity()
    source_batch.verify_integrity()


def _source_binding_payload(
    *,
    formal_selection: FormalShadowSelectionManifest,
    source_batch: ChengfengShadowBatchManifest,
    suggestions: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    identities: list[dict[str, object]] = []
    for suggestion in suggestions:
        images = _sequence(
            suggestion.get("images"),
            label="draft suggestion images",
        )
        identities.append(
            {
                "images": sorted(
                    (
                        {
                            "image_sha256": _required_sha256(
                                _mapping(
                                    image,
                                    label="draft suggestion image",
                                ).get("image_sha256"),
                                label="draft image SHA-256",
                            ),
                            "slot": _required_text(
                                _mapping(
                                    image,
                                    label="draft suggestion image",
                                ).get("slot"),
                                label="draft image slot",
                            ),
                        }
                        for image in images
                    ),
                    key=lambda item: item["slot"],
                ),
                "item_identity_sha256": _required_sha256(
                    suggestion.get("item_identity_sha256"),
                    label="draft item identity",
                ),
            }
        )
    return {
        "formal_system_results_accessed": False,
        "origin": "independent_visual_assistance",
        "source_batch_sha256": source_batch.canonical_sha256,
        "source_build_sha256": source_batch.source_build_sha256,
        "source_contract_sha256": source_batch.contract_canonical_sha256,
        "source_selection_sha256": formal_selection.canonical_sha256,
        "target_kind": ShadowBatchTargetKind.CURRENT_LOCKED_50.value,
        "item_image_bindings": sorted(
            identities,
            key=lambda item: cast(str, item["item_identity_sha256"]),
        ),
    }


def _blank_suggestion(item: ShadowBatchItem) -> dict[str, object]:
    return {
        "images": [
            {
                "image_sha256": image.sha256,
                "ordinary_net": None,
                "quality_conditions": [],
                "role": "unknown",
                "slot": image.slot,
            }
            for image in item.images
        ],
        "item_identity_sha256": item.item_identity_sha256,
        "pair_condition": "unknown",
    }


def build_blank_draft_template(
    *,
    formal_selection: FormalShadowSelectionManifest,
    source_batch: ChengfengShadowBatchManifest,
) -> dict[str, object]:
    """Build an unconfirmed, identity-bound template without guessing roles."""

    verify_current_locked_source_binding(
        formal_selection=formal_selection,
        source_batch=source_batch,
    )
    suggestions = [
        _blank_suggestion(item)
        for item in sorted(
            source_batch.items,
            key=lambda value: value.item_identity_sha256,
        )
    ]
    binding = _source_binding_payload(
        formal_selection=formal_selection,
        source_batch=source_batch,
        suggestions=suggestions,
    )
    return {
        "formal_system_results_accessed": False,
        "kind": "loop9_independent_draft_working_template",
        "origin": "independent_visual_assistance",
        "schema_version": SCHEMA_VERSION,
        "source_batch_sha256": source_batch.canonical_sha256,
        "source_binding_sha256": _canonical_sha256(binding),
        "source_build_sha256": source_batch.source_build_sha256,
        "source_contract_sha256": source_batch.contract_canonical_sha256,
        "source_selection_sha256": formal_selection.canonical_sha256,
        "suggestions": suggestions,
        "target_kind": ShadowBatchTargetKind.CURRENT_LOCKED_50.value,
    }


def _normalize_weight(value: object, *, role: str, label: str) -> str | None:
    if role == "unknown":
        if value is not None:
            raise Loop9DraftSuggestionError(
                f"{label} must be empty for an unknown role"
            )
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        raise Loop9DraftSuggestionError(f"{label} is invalid")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise Loop9DraftSuggestionError(f"{label} is invalid") from exc
    exponent = amount.as_tuple().exponent
    if (
        not amount.is_finite()
        or amount <= 0
        or amount >= Decimal("1000")
        or not isinstance(exponent, int)
        or exponent < -2
    ):
        raise Loop9DraftSuggestionError(f"{label} is invalid")
    return format(amount.quantize(Decimal("0.01")), "f")


def _normalize_quality_conditions(
    value: object,
    *,
    label: str,
) -> list[str]:
    conditions = [
        _required_text(item, label=label, maximum=40)
        for item in _sequence(value, label=label)
    ]
    if (
        len(conditions) != len(set(conditions))
        or not set(conditions).issubset(_QUALITY_CONDITIONS)
        or len(set(conditions).intersection(_ROTATIONS)) != 1
    ):
        raise Loop9DraftSuggestionError(
            f"{label} requires one rotation and supported quality values"
        )
    return sorted(conditions)


def _normalize_images(
    value: object,
    *,
    item: ShadowBatchItem,
    label: str,
) -> list[dict[str, object]]:
    images = _sequence(value, label=f"{label} images")
    if len(images) != 2:
        raise Loop9DraftSuggestionError(
            f"{label} requires exactly two images"
        )
    expected_by_slot = {image.slot: image for image in item.images}
    normalized: list[dict[str, object]] = []
    seen_slots: set[str] = set()
    for value in images:
        raw = _mapping(value, label=f"{label} image")
        if set(raw) != {
            "image_sha256",
            "ordinary_net",
            "quality_conditions",
            "role",
            "slot",
        }:
            raise Loop9DraftSuggestionError(
                f"{label} image contract is invalid"
            )
        slot = _required_text(
            raw.get("slot"),
            label=f"{label} image slot",
        )
        if slot not in expected_by_slot or slot in seen_slots:
            raise Loop9DraftSuggestionError(
                f"{label} image slots are invalid"
            )
        digest = _required_sha256(
            raw.get("image_sha256"),
            label=f"{label} image SHA-256",
        )
        if digest != expected_by_slot[slot].sha256:
            raise Loop9DraftSuggestionError(
                f"{label} image binding does not match"
            )
        role = _required_text(
            raw.get("role"),
            label=f"{label} image role",
        )
        if role not in _ROLES:
            raise Loop9DraftSuggestionError(
                f"{label} image role is invalid"
            )
        ordinary_net = _normalize_weight(
            raw.get("ordinary_net"),
            role=role,
            label=f"{label} ordinary net",
        )
        conditions = _normalize_quality_conditions(
            raw.get("quality_conditions"),
            label=f"{label} quality conditions",
        )
        if "unknown_layout" in conditions and (
            role != "unknown" or ordinary_net is not None
        ):
            raise Loop9DraftSuggestionError(
                "unknown-layout suggestion requires an unknown role "
                "and empty weight"
            )
        seen_slots.add(slot)
        normalized.append(
            {
                "image_sha256": digest,
                "ordinary_net": ordinary_net,
                "quality_conditions": conditions,
                "role": role,
                "slot": slot,
            }
        )
    if seen_slots != {"loading", "unloading"}:
        raise Loop9DraftSuggestionError(
            f"{label} requires both upload slots"
        )
    return sorted(normalized, key=lambda image: cast(str, image["slot"]))


def _normalize_pair_condition(
    value: object,
    *,
    images: Sequence[Mapping[str, object]],
    label: str,
) -> str:
    condition = _required_text(value, label=label, maximum=40)
    if condition not in _PAIR_CONDITIONS:
        raise Loop9DraftSuggestionError(f"{label} is invalid")
    roles = {
        cast(str, image["slot"]): cast(str, image["role"])
        for image in images
    }
    valid = {
        "normal_pair": roles
        == {"loading": "loading", "unloading": "unloading"},
        "suspected_swapped": roles
        == {"loading": "unloading", "unloading": "loading"},
        "both_loading": set(roles.values()) == {"loading"},
        "both_unloading": set(roles.values()) == {"unloading"},
        "unknown_or_non_ticket": "unknown" in roles.values(),
    }
    if not valid[condition]:
        raise Loop9DraftSuggestionError(
            f"{label} does not match the image roles"
        )
    return condition


def seal_independent_draft_suggestions(
    *,
    formal_selection: FormalShadowSelectionManifest,
    source_batch: ChengfengShadowBatchManifest,
    draft: object,
) -> dict[str, object]:
    """Normalize a manually prepared draft into review-only suggestions."""

    verify_current_locked_source_binding(
        formal_selection=formal_selection,
        source_batch=source_batch,
    )
    _reject_personnel_fields(draft, label="draft suggestions")
    raw = _mapping(draft, label="draft suggestions")
    if (
        set(raw)
        != {
            "formal_system_results_accessed",
            "kind",
            "origin",
            "schema_version",
            "source_batch_sha256",
            "source_binding_sha256",
            "source_build_sha256",
            "source_contract_sha256",
            "source_selection_sha256",
            "suggestions",
            "target_kind",
        }
        or raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind")
        != "loop9_independent_draft_working_template"
        or raw.get("target_kind")
        != ShadowBatchTargetKind.CURRENT_LOCKED_50.value
        or raw.get("origin") != "independent_visual_assistance"
        or raw.get("formal_system_results_accessed") is not False
        or raw.get("source_selection_sha256")
        != formal_selection.canonical_sha256
        or raw.get("source_batch_sha256")
        != source_batch.canonical_sha256
        or raw.get("source_build_sha256")
        != source_batch.source_build_sha256
        or raw.get("source_contract_sha256")
        != source_batch.contract_canonical_sha256
    ):
        raise Loop9DraftSuggestionError(
            "draft suggestions are not independently bound to the source"
        )
    expected_items = {
        item.item_identity_sha256: item for item in source_batch.items
    }
    raw_suggestions = [
        _mapping(value, label="draft suggestion")
        for value in _sequence(
            raw.get("suggestions"),
            label="draft suggestions",
        )
    ]
    declared_binding = _required_sha256(
        raw.get("source_binding_sha256"),
        label="draft source binding SHA-256",
    )
    actual_binding = _canonical_sha256(
        _source_binding_payload(
            formal_selection=formal_selection,
            source_batch=source_batch,
            suggestions=raw_suggestions,
        )
    )
    if declared_binding != actual_binding:
        raise Loop9DraftSuggestionError(
            "draft source binding integrity is invalid"
        )
    normalized: list[dict[str, object]] = []
    seen_items: set[str] = set()
    for raw_suggestion in raw_suggestions:
        if set(raw_suggestion) != {
            "images",
            "item_identity_sha256",
            "pair_condition",
        }:
            raise Loop9DraftSuggestionError(
                "draft suggestion contract is invalid"
            )
        identity = _required_sha256(
            raw_suggestion.get("item_identity_sha256"),
            label="draft item identity",
        )
        if identity in seen_items or identity not in expected_items:
            raise Loop9DraftSuggestionError(
                "draft suggestion item binding is invalid"
            )
        images = _normalize_images(
            raw_suggestion.get("images"),
            item=expected_items[identity],
            label="draft suggestion",
        )
        pair_condition = _normalize_pair_condition(
            raw_suggestion.get("pair_condition"),
            images=images,
            label="draft suggestion pair condition",
        )
        seen_items.add(identity)
        normalized.append(
            {
                "images": images,
                "item_identity_sha256": identity,
                "pair_condition": pair_condition,
                "truth_status": "unconfirmed_non_truth",
            }
        )
    if seen_items != set(expected_items):
        raise Loop9DraftSuggestionError(
            "draft suggestions must cover exactly 50 items"
        )
    core: dict[str, object] = {
        "formal_system_results_accessed": False,
        "kind": "loop9_independent_draft_suggestions",
        "origin": "independent_visual_assistance",
        "schema_version": SCHEMA_VERSION,
        "source_batch_sha256": source_batch.canonical_sha256,
        "source_build_sha256": source_batch.source_build_sha256,
        "source_contract_sha256": source_batch.contract_canonical_sha256,
        "suggestions": sorted(
            normalized,
            key=lambda item: cast(str, item["item_identity_sha256"]),
        ),
        "target_kind": ShadowBatchTargetKind.CURRENT_LOCKED_50.value,
    }
    return {**core, "canonical_sha256": _canonical_sha256(core)}


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    reparse_flag = getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _resolved_existing_file(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9DraftSuggestionError(f"{label} path must be absolute")
    if path.is_symlink() or _is_reparse_point(path):
        raise Loop9DraftSuggestionError(f"{label} path is unsafe")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9DraftSuggestionError(f"{label} is unavailable") from exc
    if (
        resolved != Path(os.path.abspath(os.fspath(path)))
        or not resolved.is_file()
    ):
        raise Loop9DraftSuggestionError(f"{label} path is unsafe")
    return resolved


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9DraftSuggestionError(
                "draft JSON contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise Loop9DraftSuggestionError(
        f"draft JSON contains a non-finite value: {value}"
    )


def load_draft_document(path: Path) -> object:
    """Load one bounded UTF-8 draft without tolerating duplicate fields."""

    source = _resolved_existing_file(path, label="draft")
    try:
        size = source.stat().st_size
        if size < 2 or size > _MAX_JSON_BYTES:
            raise Loop9DraftSuggestionError(
                "draft file size is invalid"
            )
        return json.loads(
            source.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9DraftSuggestionError(
            "draft is not readable UTF-8 JSON"
        ) from exc


def _safe_new_output(path: Path) -> tuple[Path, Path]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9DraftSuggestionError("output path must be absolute")
    if path.exists() or path.is_symlink():
        raise Loop9DraftSuggestionError("output already exists")
    parent = path.parent
    if parent.is_symlink() or _is_reparse_point(parent):
        raise Loop9DraftSuggestionError("output parent is unsafe")
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise Loop9DraftSuggestionError(
            "output parent is unavailable"
        ) from exc
    candidate = Path(os.path.abspath(os.fspath(path)))
    if not resolved_parent.is_dir() or candidate.parent != resolved_parent:
        raise Loop9DraftSuggestionError("output path is unsafe")
    return resolved_parent, candidate


def persist_new_draft_document(
    *,
    output: Path,
    payload: Mapping[str, object],
) -> Path:
    """Publish canonical JSON atomically without replacing an existing file."""

    parent, target = _safe_new_output(output)
    content = _canonical_json(payload) + b"\n"
    staged = parent / f".{target.name}.{uuid4().hex}.tmp"
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, target)
        except FileExistsError as exc:
            raise Loop9DraftSuggestionError(
                "output already exists"
            ) from exc
        except OSError as exc:
            raise Loop9DraftSuggestionError(
                "output could not be published atomically"
            ) from exc
    except Loop9DraftSuggestionError:
        raise
    except OSError as exc:
        raise Loop9DraftSuggestionError(
            "draft evidence could not be written"
        ) from exc
    finally:
        staged.unlink(missing_ok=True)
    return target
