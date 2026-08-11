from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, cast
from urllib.parse import quote
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import Response

from dahe import __version__
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewIdempotencyConflictError,
    LockedSetReviewRecord,
    LockedSetReviewRecordVersionConflictError,
    SqliteLockedSetReviewRepository,
)
from dahe.api.errors import ApiError
from dahe.verification.loop9_human_review import (
    Loop9HumanReviewError,
    Loop9ReviewPackage,
    normalize_loop9_review_truth,
)

_EXPORT_SAMPLE_ID = "__loop9_answers_export__"
_REVIEW_KINDS = {"current_locked_50": 50, "real_shadow_30": 30}
_PAIR_CONDITIONS = {
    "normal_pair",
    "suspected_swapped",
    "both_loading",
    "both_unloading",
    "unknown_or_non_ticket",
}


class Loop9ReviewWorkspaceError(RuntimeError):
    """Base error for the isolated Loop 9 human-review workspace."""


class Loop9ReviewIncompleteError(Loop9ReviewWorkspaceError):
    """Raised when answers are exported before every item is confirmed."""


class Loop9ReviewRevisionConflictError(Loop9ReviewWorkspaceError):
    """Raised when an export request references stale review state."""


class Loop9ReviewPackagePort(Protocol):
    @property
    def payload(self) -> dict[str, object]: ...

    def read_verified_image(
        self,
        image_sha256: str,
    ) -> tuple[bytes, str]: ...


class Loop9ReviewTruthImage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slot: Literal["loading", "unloading"]
    image_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    role: Literal["loading", "unloading", "unknown"]
    ordinary_net: str | None
    quality_conditions: tuple[
        Literal[
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
        ],
        ...,
    ]


class Loop9ReviewTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    images: list[Loop9ReviewTruthImage] = Field(min_length=2, max_length=2)
    pair_condition: Literal[
        "normal_pair",
        "suspected_swapped",
        "both_loading",
        "both_unloading",
        "unknown_or_non_ticket",
    ]


class SaveLoop9ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_record_version: int = Field(ge=0)
    truth: Loop9ReviewTruth


class ConfirmLoop9ReviewRequest(SaveLoop9ReviewRequest):
    verified_image_sha256s: list[str] = Field(
        min_length=2,
        max_length=2,
    )


class ExportLoop9ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_review_revision_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _request_hash(
    *,
    action: str,
    item_identity_sha256: str,
    expected_record_version: int,
    truth: Mapping[str, object],
    verified_image_sha256s: tuple[str, ...],
) -> str:
    return _canonical_sha256(
        {
            "action": action,
            "expected_record_version": expected_record_version,
            "item_identity_sha256": item_identity_sha256,
            "truth": dict(truth),
            "verified_image_sha256s": verified_image_sha256s,
        }
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise Loop9ReviewWorkspaceError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _sequence_of_mappings(
    value: object,
    *,
    label: str,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise Loop9ReviewWorkspaceError(f"{label} must be an array")
    return [_mapping(item, label=label) for item in value]


def _pair_condition_for_roles(roles: Mapping[str, object]) -> str | None:
    if roles == {"loading": "loading", "unloading": "unloading"}:
        return "normal_pair"
    if roles == {"loading": "unloading", "unloading": "loading"}:
        return "suspected_swapped"
    if set(roles.values()) == {"loading"}:
        return "both_loading"
    if set(roles.values()) == {"unloading"}:
        return "both_unloading"
    if "unknown" in roles.values():
        return "unknown_or_non_ticket"
    return None


class Loop9ReviewWorkspace:
    """Project immutable Loop 9 packages onto the existing append-only review store."""

    def __init__(
        self,
        *,
        package: Loop9ReviewPackagePort,
        repository: SqliteLockedSetReviewRepository,
        output_root: Path,
    ) -> None:
        package_sha256 = package.payload.get("canonical_sha256")
        review_kind = package.payload.get("review_kind")
        if (
            package.payload.get("kind") != "loop9_human_review_package"
            or not isinstance(package_sha256, str)
            or len(package_sha256) != 64
            or review_kind not in _REVIEW_KINDS
        ):
            raise Loop9ReviewWorkspaceError("Loop 9 review package is invalid")
        if repository.package_sha256 != package_sha256:
            raise Loop9ReviewWorkspaceError(
                "Loop 9 review repository belongs to another package"
            )
        raw_items = _sequence_of_mappings(
            package.payload.get("items"),
            label="review package items",
        )
        expected_count = _REVIEW_KINDS[review_kind]
        if (
            len(raw_items) != expected_count
            or package.payload.get("item_count") != expected_count
        ):
            raise Loop9ReviewWorkspaceError(
                "Loop 9 review package item count is invalid"
            )
        items: dict[str, dict[str, object]] = {}
        for item in raw_items:
            identity = item.get("item_identity_sha256")
            if (
                not isinstance(identity, str)
                or len(identity) != 64
                or identity in items
            ):
                raise Loop9ReviewWorkspaceError(
                    "Loop 9 review item identity is invalid"
                )
            items[identity] = item
        if not output_root.is_absolute():
            raise Loop9ReviewWorkspaceError(
                "Loop 9 review output root must be absolute"
            )
        self.package = package
        self.repository = repository
        self.output_root = output_root.resolve(strict=False)
        self.package_sha256 = package_sha256
        self.review_kind = review_kind
        self._items = items
        self._ordered_items = tuple(
            sorted(
                raw_items,
                key=lambda item: int(cast(int, item["position"])),
            )
        )

    def _latest_records(self) -> dict[str, LockedSetReviewRecord]:
        return {
            record.sample_id: record
            for record in self.repository.list_records()
            if record.sample_id in self._items
        }

    def _state(
        self,
        record: LockedSetReviewRecord | None,
    ) -> dict[str, object] | None:
        if record is None:
            return None
        payload = record.review_payload
        if (
            set(payload)
            != {
                "schema_version",
                "kind",
                "review_kind",
                "item_identity_sha256",
                "review_status",
                "truth",
                "confirmation",
                "confirmed_at",
            }
            or payload.get("schema_version") != 1
            or payload.get("kind") != "loop9_review_item_state"
            or payload.get("review_kind") != self.review_kind
            or payload.get("item_identity_sha256") != record.sample_id
            or payload.get("review_status") not in {"draft", "confirmed"}
        ):
            raise Loop9ReviewWorkspaceError(
                "stored Loop 9 review state is invalid"
            )
        return payload

    def _review_revision_sha256(
        self,
        records: Mapping[str, LockedSetReviewRecord],
    ) -> str:
        return _canonical_sha256(
            {
                "package_sha256": self.package_sha256,
                "records": [
                    {
                        "item_identity_sha256": identity,
                        "record_version": record.record_version,
                        "review_status": record.review_payload.get(
                            "review_status"
                        ),
                    }
                    for identity, record in sorted(records.items())
                ],
            }
        )

    def _advisory_message(self) -> str:
        field = (
            "draft_advisory"
            if self.review_kind == "current_locked_50"
            else "result_advisory"
        )
        advisory = _mapping(
            self.package.payload.get(field),
            label="review advisory",
        )
        message = advisory.get("message")
        if not isinstance(message, str) or not message:
            raise Loop9ReviewWorkspaceError(
                "Loop 9 review advisory message is invalid"
            )
        return message

    def index(self) -> dict[str, object]:
        records = self._latest_records()
        confirmed = 0
        drafts = 0
        summaries: list[dict[str, object]] = []
        for item in self._ordered_items:
            identity = cast(str, item["item_identity_sha256"])
            record = records.get(identity)
            state = self._state(record)
            status = "pending" if state is None else state["review_status"]
            if status == "confirmed":
                confirmed += 1
            elif status == "draft":
                drafts += 1
            summaries.append(
                {
                    "item_identity_sha256": identity,
                    "position": item["position"],
                    "review_status": status,
                    "record_version": 0 if record is None else record.record_version,
                }
            )
        return {
            "package_sha256": self.package_sha256,
            "review_kind": self.review_kind,
            "advisory_message": self._advisory_message(),
            "review_revision_sha256": self._review_revision_sha256(records),
            "progress": {
                "total": len(self._ordered_items),
                "confirmed": confirmed,
                "draft": drafts,
                "remaining": len(self._ordered_items) - confirmed,
            },
            "items": summaries,
        }

    def _initial_truth(
        self,
        item: Mapping[str, object],
    ) -> dict[str, object] | None:
        if self.review_kind != "current_locked_50":
            return None
        suggestion = _mapping(
            item.get("draft_suggestion"),
            label="review draft suggestion",
        )
        return self._normalize_truth(
            cast(str, item["item_identity_sha256"]),
            {
                "images": suggestion.get("images"),
                "pair_condition": suggestion.get("pair_condition"),
            },
        )

    def item(self, item_identity_sha256: str) -> dict[str, object]:
        item = self._items.get(item_identity_sha256)
        if item is None:
            raise KeyError(item_identity_sha256)
        record = self.repository.get(item_identity_sha256)
        state = self._state(record)
        return {
            "item_identity_sha256": item_identity_sha256,
            "position": item["position"],
            "review_kind": self.review_kind,
            "review_status": "pending" if state is None else state["review_status"],
            "record_version": 0 if record is None else record.record_version,
            "platform_weights": item["platform_weights"],
            "images": [
                {
                    **image,
                    "image_url": (
                        "/api/v1/loop9-review/images/"
                        f"{quote(cast(str, image['image_sha256']), safe='')}"
                        "?client_version="
                        f"{quote(__version__, safe='')}"
                    ),
                }
                for image in _sequence_of_mappings(
                    item["images"],
                    label="review item images",
                )
            ],
            "advisory": (
                item.get("draft_suggestion")
                if self.review_kind == "current_locked_50"
                else item.get("machine_result")
            ),
            "truth": (
                self._initial_truth(item)
                if state is None
                else state["truth"]
            ),
            "confirmation": None if state is None else state["confirmation"],
            "confirmed_at": None if state is None else state["confirmed_at"],
        }

    def _normalize_truth(
        self,
        item_identity_sha256: str,
        truth: object,
    ) -> dict[str, object]:
        try:
            return normalize_loop9_review_truth(
                package=cast(Loop9ReviewPackage, self.package),
                item_identity_sha256=item_identity_sha256,
                value=truth,
            )
        except Loop9HumanReviewError as exc:
            raise Loop9ReviewWorkspaceError(str(exc)) from exc

    def _save(
        self,
        *,
        item_identity_sha256: str,
        truth: Loop9ReviewTruth,
        expected_record_version: int,
        idempotency_key: str,
        review_status: Literal["draft", "confirmed"],
        verified_image_sha256s: tuple[str, ...] = (),
    ) -> dict[str, object]:
        if item_identity_sha256 not in self._items:
            raise KeyError(item_identity_sha256)
        normalized = self._normalize_truth(
            item_identity_sha256,
            truth.model_dump(mode="json"),
        )
        if review_status == "confirmed":
            expected_image_sha256s = sorted(
                cast(str, image["image_sha256"])
                for image in _sequence_of_mappings(
                    self._items[item_identity_sha256]["images"],
                    label="review item images",
                )
            )
            if (
                len(set(verified_image_sha256s)) != 2
                or sorted(verified_image_sha256s)
                != expected_image_sha256s
            ):
                raise Loop9ReviewWorkspaceError(
                    "both original review images must be explicitly verified"
                )
        confirmation = (
            None
            if review_status == "draft"
            else self._confirmation(
                item_identity_sha256=item_identity_sha256,
                truth=normalized,
            )
        )
        confirmed_at = None if review_status == "draft" else _utc_now()
        stored_payload: dict[str, object] = {
            "schema_version": 1,
            "kind": "loop9_review_item_state",
            "review_kind": self.review_kind,
            "item_identity_sha256": item_identity_sha256,
            "review_status": review_status,
            "truth": normalized,
            "confirmation": confirmation,
            "confirmed_at": confirmed_at,
        }
        record, _ = self.repository.save(
            sample_id=item_identity_sha256,
            review_status="confirmed",
            decision="confirmed",
            review_payload=stored_payload,
            expected_record_version=expected_record_version,
            idempotency_key=idempotency_key,
            request_hash=_request_hash(
                action=review_status,
                item_identity_sha256=item_identity_sha256,
                expected_record_version=expected_record_version,
                truth=normalized,
                verified_image_sha256s=verified_image_sha256s,
            ),
        )
        return self.item(record.sample_id)

    def save_draft(
        self,
        *,
        item_identity_sha256: str,
        truth: Loop9ReviewTruth,
        expected_record_version: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        return self._save(
            item_identity_sha256=item_identity_sha256,
            truth=truth,
            expected_record_version=expected_record_version,
            idempotency_key=idempotency_key,
            review_status="draft",
        )

    def confirm(
        self,
        *,
        item_identity_sha256: str,
        truth: Loop9ReviewTruth,
        expected_record_version: int,
        idempotency_key: str,
        verified_image_sha256s: list[str],
    ) -> dict[str, object]:
        return self._save(
            item_identity_sha256=item_identity_sha256,
            truth=truth,
            expected_record_version=expected_record_version,
            idempotency_key=idempotency_key,
            review_status="confirmed",
            verified_image_sha256s=tuple(verified_image_sha256s),
        )

    def _confirmation(
        self,
        *,
        item_identity_sha256: str,
        truth: Mapping[str, object],
    ) -> str:
        item = self._items[item_identity_sha256]
        if self.review_kind == "current_locked_50":
            expected = self._initial_truth(item)
            return (
                "suggestion_confirmed"
                if truth == expected
                else "corrected"
            )
        machine = _mapping(
            item.get("machine_result"),
            label="review machine result",
        )
        machine_images = _sequence_of_mappings(
            machine.get("images"),
            label="review machine images",
        )
        machine_by_slot = {
            cast(str, image["slot"]): image
            for image in machine_images
        }
        truth_images = _sequence_of_mappings(
            truth.get("images"),
            label="review truth images",
        )
        roles: dict[str, object] = {}
        matched = len(machine_by_slot) == 2
        for image in truth_images:
            slot = cast(str, image["slot"])
            roles[slot] = image["role"]
            machine_image = machine_by_slot.get(slot)
            matched = bool(
                matched
                and machine_image is not None
                and machine_image.get("image_sha256")
                == image.get("image_sha256")
                and machine_image.get("predicted_role") == image.get("role")
                and machine_image.get("ordinary_net")
                == image.get("ordinary_net")
            )
        matched = bool(
            matched
            and _pair_condition_for_roles(roles)
            == truth.get("pair_condition")
        )
        return (
            "machine_result_confirmed"
            if matched
            else "difference_confirmed"
        )

    def read_verified_image(
        self,
        image_sha256: str,
    ) -> tuple[bytes, str]:
        known = {
            cast(str, image["image_sha256"])
            for item in self._ordered_items
            for image in _sequence_of_mappings(
                item["images"],
                label="review item images",
            )
        }
        if image_sha256 not in known:
            raise KeyError(image_sha256)
        return self.package.read_verified_image(image_sha256)

    def export_answers(
        self,
        *,
        expected_review_revision_sha256: str,
        idempotency_key: str,
    ) -> dict[str, object]:
        records = self._latest_records()
        revision = self._review_revision_sha256(records)
        if expected_review_revision_sha256 != revision:
            raise Loop9ReviewRevisionConflictError(
                "Loop 9 review state changed before export"
            )
        reviews: list[dict[str, object]] = []
        for identity in sorted(self._items):
            record = records.get(identity)
            state = self._state(record)
            if state is None or state["review_status"] != "confirmed":
                raise Loop9ReviewIncompleteError(
                    "every Loop 9 review item must be confirmed before export"
                )
            truth = _mapping(state["truth"], label="stored review truth")
            reviews.append(
                {
                    "item_identity_sha256": identity,
                    "confirmed_at": state["confirmed_at"],
                    "images": truth["images"],
                    "pair_condition": truth["pair_condition"],
                    "confirmation": state["confirmation"],
                }
            )
        core: dict[str, object] = {
            "schema_version": 1,
            "kind": "loop9_human_review_answers",
            "review_kind": self.review_kind,
            "package_sha256": self.package_sha256,
            "reviews": reviews,
        }
        canonical_sha256 = _canonical_sha256(core)
        payload = {**core, "canonical_sha256": canonical_sha256}
        content = (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self.output_root.mkdir(parents=True, exist_ok=True)
        output_path = (
            self.output_root
            / f"loop9-human-review-answers-{canonical_sha256}.json"
        )
        if output_path.exists():
            if (
                not output_path.is_file()
                or output_path.is_symlink()
                or output_path.read_bytes() != content
            ):
                raise Loop9ReviewWorkspaceError(
                    "existing Loop 9 review export does not match"
                )
        else:
            staging = self.output_root / f".loop9-review-{uuid4().hex}.tmp"
            try:
                with staging.open("xb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                staging.replace(output_path)
            finally:
                if staging.exists():
                    staging.unlink()
        marker = self.repository.get(_EXPORT_SAMPLE_ID)
        marker_version = 0 if marker is None else marker.record_version
        export_request = {
            "expected_review_revision_sha256": (
                expected_review_revision_sha256
            ),
            "output_sha256": canonical_sha256,
        }
        self.repository.save(
            sample_id=_EXPORT_SAMPLE_ID,
            review_status="confirmed",
            decision="confirmed",
            review_payload={
                "schema_version": 1,
                "kind": "loop9_review_answers_export",
                "review_revision_sha256": revision,
                "output_file": output_path.name,
                "output_sha256": canonical_sha256,
            },
            expected_record_version=marker_version,
            idempotency_key=idempotency_key,
            request_hash=_canonical_sha256(export_request),
        )
        return {
            "path": output_path,
            "canonical_sha256": canonical_sha256,
            "review_revision_sha256": revision,
        }


def build_loop9_review_router(
    *,
    workspace: Loop9ReviewWorkspace,
    require_session: Callable[..., None],
    require_write: Callable[..., str],
) -> APIRouter:
    """Build the isolated, offline-only Loop 9 review API."""

    router = APIRouter(
        prefix="/api/v1/loop9-review",
        tags=["loop9-review"],
    )
    session_dependency = require_session
    write_dependency = require_write

    def _item(item_identity_sha256: str) -> dict[str, object]:
        try:
            return workspace.item(item_identity_sha256)
        except KeyError as exc:
            raise ApiError(
                404,
                "loop9_review_item_not_found",
                "没有找到这条人工复核项目",
            ) from exc

    @router.get("")
    def get_review_index(
        _: None = Depends(session_dependency),
    ) -> dict[str, object]:
        return workspace.index()

    @router.get("/items/{item_identity_sha256}")
    def get_review_item(
        item_identity_sha256: str,
        _: None = Depends(session_dependency),
    ) -> dict[str, object]:
        return _item(item_identity_sha256)

    @router.get("/images/{image_sha256}")
    def get_review_image(
        image_sha256: str,
        _: None = Depends(session_dependency),
    ) -> Response:
        try:
            content, media_type = workspace.read_verified_image(
                image_sha256.lower()
            )
        except KeyError as exc:
            raise ApiError(
                404,
                "loop9_review_image_not_found",
                "没有找到这张人工复核图片",
            ) from exc
        except Loop9HumanReviewError as exc:
            raise ApiError(
                409,
                "loop9_review_image_changed",
                "复核图片完整性校验失败。已停止读取",
            ) from exc
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Cache-Control": "no-store",
                "ETag": f'"{image_sha256.lower()}"',
            },
        )

    def _save(
        *,
        action: Literal["draft", "confirm"],
        item_identity_sha256: str,
        payload: SaveLoop9ReviewRequest,
        idempotency_key: str,
    ) -> dict[str, object]:
        try:
            if action == "draft":
                item = workspace.save_draft(
                    item_identity_sha256=item_identity_sha256,
                    truth=payload.truth,
                    expected_record_version=payload.expected_record_version,
                    idempotency_key=idempotency_key,
                )
            else:
                if not isinstance(payload, ConfirmLoop9ReviewRequest):
                    raise Loop9ReviewWorkspaceError(
                        "confirmation image checks are missing"
                    )
                item = workspace.confirm(
                    item_identity_sha256=item_identity_sha256,
                    truth=payload.truth,
                    expected_record_version=payload.expected_record_version,
                    idempotency_key=idempotency_key,
                    verified_image_sha256s=(
                        payload.verified_image_sha256s
                    ),
                )
        except KeyError as exc:
            raise ApiError(
                404,
                "loop9_review_item_not_found",
                "没有找到这条人工复核项目",
            ) from exc
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
        except Loop9ReviewWorkspaceError as exc:
            raise ApiError(
                422,
                "loop9_review_truth_invalid",
                "复核内容不完整或相互矛盾，请检查后重试",  # noqa: RUF001
            ) from exc
        return {
            "item": item,
            "progress": workspace.index()["progress"],
            "review_revision_sha256": workspace.index()[
                "review_revision_sha256"
            ],
        }

    @router.post("/items/{item_identity_sha256}/draft")
    def save_review_draft(
        item_identity_sha256: str,
        payload: SaveLoop9ReviewRequest,
        idempotency_key: str = Depends(write_dependency),
    ) -> dict[str, object]:
        return _save(
            action="draft",
            item_identity_sha256=item_identity_sha256,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @router.post("/items/{item_identity_sha256}/confirm")
    def confirm_review_item(
        item_identity_sha256: str,
        payload: ConfirmLoop9ReviewRequest,
        idempotency_key: str = Depends(write_dependency),
    ) -> dict[str, object]:
        return _save(
            action="confirm",
            item_identity_sha256=item_identity_sha256,
            payload=payload,
            idempotency_key=idempotency_key,
        )

    @router.post("/export")
    def export_review_answers(
        payload: ExportLoop9ReviewRequest,
        idempotency_key: str = Depends(write_dependency),
    ) -> dict[str, object]:
        try:
            result = workspace.export_answers(
                expected_review_revision_sha256=(
                    payload.expected_review_revision_sha256
                ),
                idempotency_key=idempotency_key,
            )
        except Loop9ReviewIncompleteError as exc:
            raise ApiError(
                409,
                "loop9_review_incomplete",
                "全部项目确认后才能导出",
            ) from exc
        except Loop9ReviewRevisionConflictError as exc:
            raise ApiError(
                409,
                "review_revision_conflict",
                "复核内容已变化。请刷新后重试",
            ) from exc
        except LockedSetReviewIdempotencyConflictError as exc:
            raise ApiError(
                409,
                "idempotency_key_reused",
                "该操作编号已经用于其他导出。请刷新后重试",
            ) from exc
        output_path = cast(Path, result["path"])
        return {
            "file_name": output_path.name,
            "canonical_sha256": result["canonical_sha256"],
            "review_revision_sha256": result[
                "review_revision_sha256"
            ],
        }

    return router
