from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from typing import Literal, Self, cast
from urllib.parse import quote

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.responses import Response

from dahe import __version__
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewIdempotencyConflictError,
    LockedSetReviewRecord,
    LockedSetReviewRecordVersionConflictError,
    SqliteLockedSetReviewRepository,
)
from dahe.api.errors import ApiError
from dahe.application.template_studio.candidate_review_seal import (
    CandidateReviewSealError,
    is_candidate_review_sealed,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImageChangedError,
    LockedSetReviewItem,
    LockedSetReviewPackage,
)

QualityCondition = Literal[
    "blur",
    "glare",
    "crop",
    "rotation_0",
    "rotation_90",
    "rotation_180",
    "rotation_270",
    "screen",
    "printed",
    "unknown_layout",
    "non_ticket",
]
PairCondition = Literal[
    "normal_pair",
    "swapped_pair",
    "same_role_pair",
    "duplicate_upload",
    "pair_unknown",
]
_QUALITY_ORDER = {
    value: index
    for index, value in enumerate(
        (
            "blur",
            "glare",
            "crop",
            "rotation_0",
            "rotation_90",
            "rotation_180",
            "rotation_270",
            "screen",
            "printed",
            "unknown_layout",
            "non_ticket",
        )
    )
}
_PAIR_ORDER = {
    value: index
    for index, value in enumerate(
        (
            "normal_pair",
            "swapped_pair",
            "same_role_pair",
            "duplicate_upload",
            "pair_unknown",
        )
    )
}
_ROTATIONS = {
    "rotation_0",
    "rotation_90",
    "rotation_180",
    "rotation_270",
}
_PRIMARY_PAIR_CONDITIONS = {
    "normal_pair",
    "swapped_pair",
    "same_role_pair",
    "pair_unknown",
}


class LockedSetReviewImageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    submitted_slot: Literal["loading", "unloading"]
    role: Literal["loading", "unloading", "unknown"]
    ordinary_net: str | None
    quality_conditions: tuple[QualityCondition, ...]
    notes: str | None = Field(default=None, max_length=1000)

    @field_validator("quality_conditions")
    @classmethod
    def validate_quality_conditions(
        cls,
        value: tuple[QualityCondition, ...],
    ) -> tuple[QualityCondition, ...]:
        if len(set(value)) != len(value):
            raise ValueError("quality conditions must not repeat")
        if len(_ROTATIONS.intersection(value)) != 1:
            raise ValueError("quality conditions require exactly one rotation")
        return tuple(sorted(value, key=_QUALITY_ORDER.__getitem__))

    @field_validator("notes")
    @classmethod
    def normalize_notes(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def validate_role_weight(self) -> Self:
        if self.role == "unknown":
            if self.ordinary_net is not None:
                raise ValueError("unknown role requires a null ordinary net")
            return self
        if self.ordinary_net is None:
            raise ValueError("known ticket role requires an ordinary net")
        try:
            amount = Decimal(self.ordinary_net)
        except InvalidOperation as exc:
            raise ValueError("ordinary net must be a decimal tonne value") from exc
        if (
            not amount.is_finite()
            or amount <= 0
            or amount.as_tuple().exponent != -2
        ):
            raise ValueError(
                "ordinary net must be positive with two decimal places"
            )
        self.ordinary_net = format(amount, "f")
        return self


class SaveLockedSetReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=0)
    decision: Literal["confirmed", "replace_candidate"]
    images: tuple[LockedSetReviewImageRequest, ...] = ()
    pair_conditions: tuple[PairCondition, ...] = ()
    pair_notes: str | None = Field(default=None, max_length=1000)
    replace_reason: str | None = Field(default=None, max_length=1000)

    @field_validator("pair_conditions")
    @classmethod
    def normalize_pair_conditions(
        cls,
        value: tuple[PairCondition, ...],
    ) -> tuple[PairCondition, ...]:
        if len(set(value)) != len(value):
            raise ValueError("pair conditions must not repeat")
        return tuple(sorted(value, key=_PAIR_ORDER.__getitem__))

    @field_validator("pair_notes", "replace_reason")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if len(self.images) not in {0, 2}:
            raise ValueError("review images must be empty or contain both slots")
        if self.images:
            if {image.submitted_slot for image in self.images} != {
                "loading",
                "unloading",
            }:
                raise ValueError(
                    "review images require loading and unloading submitted slots"
                )
            self.images = tuple(
                sorted(
                    self.images,
                    key=lambda image: (
                        0 if image.submitted_slot == "loading" else 1
                    ),
                )
            )
        if self.decision == "confirmed":
            if len(self.images) != 2:
                raise ValueError("confirmed review requires both images")
            primary_conditions = _PRIMARY_PAIR_CONDITIONS.intersection(
                self.pair_conditions
            )
            if len(primary_conditions) != 1:
                raise ValueError(
                    "confirmed review requires exactly one primary pair condition"
                )
            if self.replace_reason is not None:
                raise ValueError(
                    "confirmed review cannot include a replacement reason"
                )
            for image in self.images:
                if (
                    {
                        "non_ticket",
                        "unknown_layout",
                    }.intersection(image.quality_conditions)
                    and image.role != "unknown"
                ):
                    raise ValueError(
                        "a non-ticket or unknown-layout image requires an unknown role"
                    )
            roles = {
                image.submitted_slot: image.role
                for image in self.images
            }
            primary = next(iter(primary_conditions))
            if primary == "normal_pair" and roles != {
                "loading": "loading",
                "unloading": "unloading",
            }:
                raise ValueError(
                    "normal pair roles must match their submitted slots"
                )
            if primary == "swapped_pair" and roles != {
                "loading": "unloading",
                "unloading": "loading",
            }:
                raise ValueError(
                    "swapped pair roles must be opposite their submitted slots"
                )
            if primary == "same_role_pair" and not (
                roles["loading"] == roles["unloading"]
                and roles["loading"] in {"loading", "unloading"}
            ):
                raise ValueError(
                    "same-role pair requires two matching known roles"
                )
            if primary == "pair_unknown" and "unknown" not in roles.values():
                raise ValueError(
                    "unknown pair requires at least one unknown image role"
                )
        else:
            if self.replace_reason is None:
                raise ValueError(
                    "replacement decision requires a replacement reason"
                )
            if self.images or self.pair_conditions or self.pair_notes is not None:
                raise ValueError(
                    "replacement decision cannot include partial review truth"
                )
        return self


def _request_hash(
    sample_id: str,
    payload: SaveLockedSetReviewRequest,
) -> str:
    encoded = json.dumps(
        {
            "sample_id": sample_id,
            "payload": payload.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _blank_human_review() -> dict[str, object]:
    return {
        "role": None,
        "ordinary_net": None,
        "quality_conditions": [],
        "notes": None,
    }


def _progress(
    package: LockedSetReviewPackage,
    records: tuple[LockedSetReviewRecord, ...],
) -> dict[str, int]:
    completed = len(records)
    replacements = sum(
        record.decision == "replace_candidate" for record in records
    )
    return {
        "total": len(package.items),
        "completed": completed,
        "remaining": len(package.items) - completed,
        "replace_candidate": replacements,
    }


def _package_status(progress: dict[str, int]) -> str:
    if progress["completed"] == 0:
        return "awaiting_human_review"
    if progress["remaining"] > 0:
        return "in_progress"
    if progress["replace_candidate"] > 0:
        return "replacement_required"
    return "completed"


def _image_url(image_sha256: str) -> str:
    return (
        "/api/v1/locked-set-review/images/"
        f"{quote(image_sha256, safe='')}"
        f"?client_version={quote(__version__, safe='')}"
    )


def _project_detail(
    item: LockedSetReviewItem,
    record: LockedSetReviewRecord | None,
) -> dict[str, object]:
    payload = {} if record is None else record.review_payload
    raw_images = payload.get("images", [])
    images_by_slot: dict[str, dict[str, object]] = {}
    if isinstance(raw_images, list):
        for value in raw_images:
            if not isinstance(value, dict):
                continue
            slot = value.get("submitted_slot")
            if slot in {"loading", "unloading"}:
                images_by_slot[str(slot)] = cast(
                    dict[str, object],
                    value,
                )
    return {
        "sample_id": item.sample_id,
        "candidate_id": item.candidate_id,
        "position": item.position,
        "record_version": 0 if record is None else record.record_version,
        "review_status": (
            "pending" if record is None else record.review_status
        ),
        "selection_clues": list(item.selection_clues),
        "images": [
            {
                "submitted_slot": image.submitted_slot,
                "image_url": _image_url(image.image_sha256),
                "selection_clues": list(image.selection_clues),
                "human_review": images_by_slot.get(
                    image.submitted_slot,
                    _blank_human_review(),
                ),
            }
            for image in item.images
        ],
        "pair_review": {
            "conditions": payload.get("pair_conditions", []),
            "notes": payload.get("pair_notes"),
        },
        "decision": None if record is None else record.decision,
        "replace_reason": payload.get("replace_reason"),
    }


def build_locked_set_review_router(
    *,
    package: LockedSetReviewPackage,
    repository: SqliteLockedSetReviewRepository,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/locked-set-review",
        tags=["locked-set-review"],
    )
    session_dependency = require_session
    write_dependency = require_write

    def _item(sample_id: str) -> LockedSetReviewItem:
        item = package.items_by_sample_id.get(sample_id)
        if item is None:
            raise ApiError(
                404,
                "locked_set_review_item_not_found",
                "没有找到这条复核样本",
            )
        return item

    @router.get("")
    def get_review_index(
        _: None = Depends(session_dependency),
    ) -> dict[str, object]:
        records = repository.list_records()
        by_sample = {record.sample_id: record for record in records}
        progress = _progress(package, records)
        return {
            "package": {
                "package_id": package.package_id,
                "status": _package_status(progress),
            },
            "progress": progress,
            "items": [
                {
                    "sample_id": item.sample_id,
                    "position": item.position,
                    "review_status": (
                        "pending"
                        if item.sample_id not in by_sample
                        else by_sample[item.sample_id].review_status
                    ),
                    "record_version": (
                        0
                        if item.sample_id not in by_sample
                        else by_sample[item.sample_id].record_version
                    ),
                    "decision": (
                        None
                        if item.sample_id not in by_sample
                        else by_sample[item.sample_id].decision
                    ),
                }
                for item in package.items
            ],
        }

    @router.get("/items/{sample_id}")
    def get_review_item(
        sample_id: str,
        _: None = Depends(session_dependency),
    ) -> dict[str, object]:
        item = _item(sample_id)
        return _project_detail(
            item,
            repository.get(sample_id),
        )

    @router.get("/images/{image_sha256}")
    def get_review_image(
        image_sha256: str,
        _: None = Depends(session_dependency),
    ) -> Response:
        try:
            content, media_type = package.read_verified_image(
                image_sha256.lower()
            )
        except KeyError as exc:
            raise ApiError(
                404,
                "locked_set_review_image_not_found",
                "没有找到这张复核图片",
            ) from exc
        except LockedSetReviewImageChangedError as exc:
            raise ApiError(
                409,
                "locked_set_review_image_changed",
                "复核图片已变化。请停止复核并重新生成样本",
            ) from exc
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Cache-Control": "no-store",
                "ETag": f'"{image_sha256.lower()}"',
            },
        )

    @router.post("/items/{sample_id}/review")
    def save_review_item(
        sample_id: str,
        payload: SaveLockedSetReviewRequest,
        idempotency_key: str = Depends(write_dependency),
    ) -> dict[str, object]:
        try:
            formally_sealed = is_candidate_review_sealed(
                package.review_root
            )
        except CandidateReviewSealError as exc:
            raise ApiError(
                409,
                "locked_set_review_seal_invalid",
                "复核封存证据无效。已停止保存。请联系开发人员检查",
            ) from exc
        if formally_sealed:
            raise ApiError(
                409,
                "locked_set_review_formally_sealed",
                "本批复核已经正式封存。不能再修改",
            )
        item = _item(sample_id)
        stored_payload = payload.model_dump(mode="json")
        stored_payload.pop("expected_record_version")
        try:
            record, _ = repository.save(
                sample_id=sample_id,
                review_status=payload.decision,
                decision=payload.decision,
                review_payload=stored_payload,
                expected_record_version=payload.expected_record_version,
                idempotency_key=idempotency_key,
                request_hash=_request_hash(sample_id, payload),
            )
        except LockedSetReviewIdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "该操作编号已经用于其他复核。请刷新后重试",
            ) from exc
        except LockedSetReviewRecordVersionConflictError as exc:
            raise ApiError(
                409,
                "record_version_conflict",
                "这条复核已更新。请刷新后重试",
            ) from exc
        return {
            "item": _project_detail(
                item,
                record,
            ),
            "progress": _progress(package, repository.list_records()),
        }

    return router
