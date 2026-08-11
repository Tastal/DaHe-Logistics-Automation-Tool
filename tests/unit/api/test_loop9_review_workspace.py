from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewIdempotencyConflictError,
    LockedSetReviewRecordVersionConflictError,
    SqliteLockedSetReviewRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.api.loop9_review import (
    Loop9ReviewIncompleteError,
    Loop9ReviewTruth,
    Loop9ReviewWorkspace,
    Loop9ReviewWorkspaceError,
    build_loop9_review_router,
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


@dataclass
class _FakeSourceImage:
    slot: str
    sha256: str


@dataclass
class _FakeSourceItem:
    item_identity_sha256: str
    images: tuple[_FakeSourceImage, _FakeSourceImage]


@dataclass
class _FakeSourceBatch:
    items: tuple[_FakeSourceItem, ...]


@dataclass
class _FakePackage:
    root: Path
    payload: dict[str, object]
    source_batch: _FakeSourceBatch
    image_content: dict[str, bytes]
    read_count: int = 0

    def read_verified_image(self, image_sha256: str) -> tuple[bytes, str]:
        self.read_count += 1
        return self.image_content[image_sha256], "image/png"


def _review_package(
    tmp_path: Path,
    *,
    review_kind: str,
) -> _FakePackage:
    item_count = 50 if review_kind == "current_locked_50" else 30
    image_content: dict[str, bytes] = {}
    items: list[dict[str, object]] = []
    source_items: list[_FakeSourceItem] = []
    for position in range(1, item_count + 1):
        identity = hashlib.sha256(
            f"{review_kind}:item:{position}".encode()
        ).hexdigest()
        images: list[dict[str, object]] = []
        truth_images: list[dict[str, object]] = []
        machine_images: list[dict[str, object]] = []
        for slot in ("loading", "unloading"):
            content = f"{identity}:{slot}".encode()
            image_sha256 = hashlib.sha256(content).hexdigest()
            image_content[image_sha256] = content
            images.append(
                {
                    "slot": slot,
                    "image_sha256": image_sha256,
                    "relative_path": (
                        f"images/sha256/{image_sha256[:2]}/"
                        f"{image_sha256[2:4]}/{image_sha256}.blob"
                    ),
                    "byte_size": len(content),
                    "media_type": "image/png",
                    "perceptual_fingerprint_sha256": "f" * 64,
                }
            )
            ordinary_net = "30.00" if slot == "loading" else "29.80"
            truth_images.append(
                {
                    "slot": slot,
                    "image_sha256": image_sha256,
                    "role": slot,
                    "ordinary_net": ordinary_net,
                    "quality_conditions": ["rotation_0"],
                }
            )
            machine_images.append(
                {
                    "slot": slot,
                    "image_sha256": image_sha256,
                    "predicted_role": slot,
                    "ordinary_net": ordinary_net,
                    "role_high_confidence": True,
                }
            )
        item: dict[str, object] = {
            "position": position,
            "item_identity_sha256": identity,
            "platform_identity_sha256": hashlib.sha256(
                f"platform:{position}".encode()
            ).hexdigest(),
            "platform_weights": {"loading": "30.00", "unloading": "29.80"},
            "images": images,
        }
        if review_kind == "current_locked_50":
            item["draft_suggestion"] = {
                "item_identity_sha256": identity,
                "truth_status": "unconfirmed_non_truth",
                "images": truth_images,
                "pair_condition": "normal_pair",
            }
        else:
            machine_core = {
                "item_identity_sha256": identity,
                "automatic_outcome": "normal_ready",
                "issue_code": None,
                "diagnostic_code": None,
                "images": machine_images,
            }
            item["machine_result"] = {
                **machine_core,
                "result_sha256": _canonical_sha256(machine_core),
            }
        items.append(item)
        source_items.append(
            _FakeSourceItem(
                item_identity_sha256=identity,
                images=cast(
                    tuple[_FakeSourceImage, _FakeSourceImage],
                    tuple(
                        _FakeSourceImage(
                            slot=cast(str, image["slot"]),
                            sha256=cast(str, image["image_sha256"]),
                        )
                        for image in images
                    ),
                ),
            )
        )
    core: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_human_review_package",
        "review_kind": review_kind,
        "status": "awaiting_human_confirmation",
        "item_count": item_count,
        "image_count": item_count * 2,
        "binding": {},
        "source_files": {},
        "items": items,
    }
    if review_kind == "current_locked_50":
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
    return _FakePackage(
        root=tmp_path / "immutable-package",
        payload={**core, "canonical_sha256": _canonical_sha256(core)},
        source_batch=_FakeSourceBatch(items=tuple(source_items)),
        image_content=image_content,
    )


@pytest.fixture
def runtime(
    tmp_path: Path,
    project_root: Path,
) -> Iterator[SqliteRuntime]:
    opened = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="loop9-review-workspace-test",
    )
    try:
        yield opened
    finally:
        opened.close()


def _truth(item: dict[str, object]) -> Loop9ReviewTruth:
    suggestion = cast(dict[str, object], item["draft_suggestion"])
    return Loop9ReviewTruth.model_validate(
        {
            "images": suggestion["images"],
            "pair_condition": suggestion["pair_condition"],
        }
    )


def _verified_image_sha256s(item: dict[str, object]) -> list[str]:
    return [
        cast(str, image["image_sha256"])
        for image in cast(list[dict[str, object]], item["images"])
    ]


def _workspace(
    *,
    package: _FakePackage,
    runtime: SqliteRuntime,
    output_root: Path,
) -> Loop9ReviewWorkspace:
    return Loop9ReviewWorkspace(
        package=package,
        repository=SqliteLockedSetReviewRepository(
            runtime=runtime,
            package_sha256=cast(str, package.payload["canonical_sha256"]),
        ),
        output_root=output_root,
    )


def test_locked_review_draft_is_durable_idempotent_and_versioned(
    tmp_path: Path,
    runtime: SqliteRuntime,
) -> None:
    package = _review_package(tmp_path, review_kind="current_locked_50")
    workspace = _workspace(
        package=package,
        runtime=runtime,
        output_root=tmp_path / "exports",
    )
    index = workspace.index()
    assert index["review_kind"] == "current_locked_50"
    assert index["advisory_message"] == "辅助建议，尚未成为真值"  # noqa: RUF001
    assert index["progress"] == {
        "total": 50,
        "confirmed": 0,
        "draft": 0,
        "remaining": 50,
    }
    first = cast(dict[str, object], package.payload["items"][0])
    identity = cast(str, first["item_identity_sha256"])
    truth = _truth(first)

    saved = workspace.save_draft(
        item_identity_sha256=identity,
        truth=truth,
        expected_record_version=0,
        idempotency_key="draft-item-1",
    )
    assert saved["record_version"] == 1
    assert saved["review_status"] == "draft"
    assert workspace.item(identity)["review_status"] == "draft"

    replay = workspace.save_draft(
        item_identity_sha256=identity,
        truth=truth,
        expected_record_version=0,
        idempotency_key="draft-item-1",
    )
    assert replay["record_version"] == 1
    with pytest.raises(LockedSetReviewIdempotencyConflictError):
        changed = truth.model_copy(deep=True)
        changed.images[0].ordinary_net = "31.00"
        workspace.save_draft(
            item_identity_sha256=identity,
            truth=changed,
            expected_record_version=1,
            idempotency_key="draft-item-1",
        )
    verified = _verified_image_sha256s(first)
    with pytest.raises(
        Loop9ReviewWorkspaceError,
        match="both original review images",
    ):
        workspace.confirm(
            item_identity_sha256=identity,
            truth=truth,
            expected_record_version=1,
            idempotency_key="confirm-duplicate-image-check",
            verified_image_sha256s=[verified[0], verified[0]],
        )
    with pytest.raises(LockedSetReviewRecordVersionConflictError):
        workspace.confirm(
            item_identity_sha256=identity,
            truth=truth,
            expected_record_version=0,
            idempotency_key="confirm-stale-item-1",
            verified_image_sha256s=_verified_image_sha256s(first),
        )

    confirmed = workspace.confirm(
        item_identity_sha256=identity,
        truth=truth,
        expected_record_version=1,
        idempotency_key="confirm-item-1",
        verified_image_sha256s=_verified_image_sha256s(first),
    )
    assert confirmed["record_version"] == 2
    assert confirmed["review_status"] == "confirmed"
    assert confirmed["confirmation"] == "suggestion_confirmed"
    assert workspace.index()["progress"] == {
        "total": 50,
        "confirmed": 1,
        "draft": 0,
        "remaining": 49,
    }


def test_shadow_review_infers_machine_confirmation_without_identity_fields(
    tmp_path: Path,
    runtime: SqliteRuntime,
) -> None:
    package = _review_package(tmp_path, review_kind="real_shadow_30")
    workspace = _workspace(
        package=package,
        runtime=runtime,
        output_root=tmp_path / "exports",
    )
    first = cast(dict[str, object], package.payload["items"][0])
    identity = cast(str, first["item_identity_sha256"])
    machine = cast(dict[str, object], first["machine_result"])
    truth = Loop9ReviewTruth.model_validate(
        {
            "images": [
                {
                    "slot": image["slot"],
                    "image_sha256": image["image_sha256"],
                    "role": image["predicted_role"],
                    "ordinary_net": image["ordinary_net"],
                    "quality_conditions": ["rotation_0"],
                }
                for image in cast(list[dict[str, object]], machine["images"])
            ],
            "pair_condition": "normal_pair",
        }
    )
    confirmed = workspace.confirm(
        item_identity_sha256=identity,
        truth=truth,
        expected_record_version=0,
        idempotency_key="confirm-shadow-item-1",
        verified_image_sha256s=_verified_image_sha256s(first),
    )
    assert confirmed["confirmation"] == "machine_result_confirmed"
    serialized = json.dumps(confirmed, ensure_ascii=False).lower()
    assert "reviewer" not in serialized
    assert "operator" not in serialized
    assert "actor" not in serialized
    assert "notes" not in serialized

    changed = truth.model_copy(deep=True)
    changed.images[0].ordinary_net = "31.00"
    difference = workspace.confirm(
        item_identity_sha256=identity,
        truth=changed,
        expected_record_version=1,
        idempotency_key="correct-shadow-item-1",  # gitleaks:allow
        verified_image_sha256s=_verified_image_sha256s(first),
    )
    assert difference["confirmation"] == "difference_confirmed"


def test_export_requires_every_item_and_writes_canonical_answers_atomically(
    tmp_path: Path,
    runtime: SqliteRuntime,
) -> None:
    package = _review_package(tmp_path, review_kind="current_locked_50")
    workspace = _workspace(
        package=package,
        runtime=runtime,
        output_root=tmp_path / "exports",
    )
    with pytest.raises(Loop9ReviewIncompleteError):
        workspace.export_answers(
            expected_review_revision_sha256=cast(
                str,
                workspace.index()["review_revision_sha256"],
            ),
            idempotency_key="export-incomplete",
        )

    for item in cast(list[dict[str, object]], package.payload["items"]):
        identity = cast(str, item["item_identity_sha256"])
        workspace.confirm(
            item_identity_sha256=identity,
            truth=_truth(item),
            expected_record_version=0,
            idempotency_key=f"confirm-{identity}",
            verified_image_sha256s=_verified_image_sha256s(item),
        )
    revision = cast(str, workspace.index()["review_revision_sha256"])
    exported = workspace.export_answers(
        expected_review_revision_sha256=revision,
        idempotency_key="export-complete",
    )
    output = cast(Path, exported["path"])
    assert output.is_file()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["kind"] == "loop9_human_review_answers"
    assert payload["review_kind"] == "current_locked_50"
    assert len(payload["reviews"]) == 50
    core = {
        key: value
        for key, value in payload.items()
        if key != "canonical_sha256"
    }
    assert payload["canonical_sha256"] == _canonical_sha256(core)
    assert output.name == (
        f"loop9-human-review-answers-{payload['canonical_sha256']}.json"
    )
    assert workspace.export_answers(
        expected_review_revision_sha256=revision,
        idempotency_key="export-complete",
    )["path"] == output


def test_image_reads_always_use_package_integrity_verifier(
    tmp_path: Path,
    runtime: SqliteRuntime,
) -> None:
    package = _review_package(tmp_path, review_kind="current_locked_50")
    workspace = _workspace(
        package=package,
        runtime=runtime,
        output_root=tmp_path / "exports",
    )
    first = cast(dict[str, object], package.payload["items"][0])
    first_image = cast(list[dict[str, object]], first["images"])[0]
    digest = cast(str, first_image["image_sha256"])

    content, media_type = workspace.read_verified_image(digest)

    assert content == package.image_content[digest]
    assert media_type == "image/png"
    assert package.read_count == 1


def test_review_router_exposes_draft_confirm_and_verified_image_endpoints(
    tmp_path: Path,
    runtime: SqliteRuntime,
) -> None:
    package = _review_package(tmp_path, review_kind="current_locked_50")
    workspace = _workspace(
        package=package,
        runtime=runtime,
        output_root=tmp_path / "exports",
    )
    app = FastAPI()

    def require_write(
        idempotency_key: str = Header(alias="Idempotency-Key"),
    ) -> str:
        return idempotency_key

    app.include_router(
        build_loop9_review_router(
            workspace=workspace,
            require_session=lambda: None,
            require_write=require_write,
        )
    )
    first = cast(dict[str, object], package.payload["items"][0])
    identity = cast(str, first["item_identity_sha256"])
    truth = _truth(first).model_dump(mode="json")

    with TestClient(app) as client:
        index = client.get("/api/v1/loop9-review")
        assert index.status_code == 200
        assert index.json()["progress"]["total"] == 50

        detail = client.get(f"/api/v1/loop9-review/items/{identity}")
        assert detail.status_code == 200
        image_url = detail.json()["images"][0]["image_url"]
        image = client.get(image_url)
        assert image.status_code == 200
        assert image.headers["cache-control"] == "no-store"

        draft = client.post(
            f"/api/v1/loop9-review/items/{identity}/draft",
            json={
                "expected_record_version": 0,
                "truth": truth,
            },
            headers={"Idempotency-Key": "api-draft"},
        )
        assert draft.status_code == 200
        assert draft.json()["item"]["review_status"] == "draft"

        missing_image_checks = client.post(
            f"/api/v1/loop9-review/items/{identity}/confirm",
            json={
                "expected_record_version": 1,
                "truth": truth,
            },
            headers={"Idempotency-Key": "api-confirm-missing-checks"},
        )
        assert missing_image_checks.status_code == 422

        confirmed = client.post(
            f"/api/v1/loop9-review/items/{identity}/confirm",
            json={
                "expected_record_version": 1,
                "truth": truth,
                "verified_image_sha256s": (
                    _verified_image_sha256s(first)
                ),
            },
            headers={"Idempotency-Key": "api-confirm"},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["item"]["review_status"] == "confirmed"
        assert confirmed.json()["item"]["confirmation"] == (
            "suggestion_confirmed"
        )

        prohibited = client.post(
            f"/api/v1/loop9-review/items/{identity}/confirm",
            json={
                "expected_record_version": 2,
                "truth": truth,
                "verified_image_sha256s": (
                    _verified_image_sha256s(first)
                ),
                "reviewer_id": "not-allowed",
            },
            headers={"Idempotency-Key": "api-prohibited"},
        )
        assert prohibited.status_code == 422
