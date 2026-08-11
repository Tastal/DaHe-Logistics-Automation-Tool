from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec

LOOP8_OFFLINE_FIXTURE_ID = "loop8-offline-v1"
LOOP8_OFFLINE_PIPELINE_FINGERPRINT = hashlib.sha256(
    b"dahe.loop8.offline.acceptance.v1"
).hexdigest()
EXPECTED_SCENARIOS = (
    "clear_normal",
    "rotated_or_alternate_layout",
    "numeric_mismatch",
    "role_unknown",
    "swapped_slots",
    "both_loading",
    "both_unloading",
    "exact_duplicate_image",
    "missing_ticket",
    "ticket_weight_format_suspicious",
    "ocr_weight_disagreement",
    "ocr_worker_failure",
)


class OfflineBatchContractError(ValueError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_absolute_file(path: Path) -> Path:
    if not path.is_absolute():
        raise OfflineBatchContractError("offline batch manifest must be absolute")
    resolved = path.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_file():
        raise OfflineBatchContractError(
            "offline batch manifest must be a regular file"
        )
    return resolved


def load_loop8_offline_batch(manifest_path: Path) -> ScheduledJobSpec:
    resolved = _require_absolute_file(manifest_path)
    raw = json.loads(resolved.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise OfflineBatchContractError("unsupported offline batch schema")
    if raw.get("fixture_id") != LOOP8_OFFLINE_FIXTURE_ID:
        raise OfflineBatchContractError("offline batch fixture identity differs")
    manifest_sha256 = raw.get("manifest_sha256")
    unsigned = dict(raw)
    unsigned.pop("manifest_sha256", None)
    canonical = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != manifest_sha256:
        raise OfflineBatchContractError("offline batch manifest hash differs")
    items = raw.get("items")
    if not isinstance(items, list) or len(items) != 12:
        raise OfflineBatchContractError("offline batch must contain 12 items")
    if tuple(item.get("scenario") for item in items) != EXPECTED_SCENARIOS:
        raise OfflineBatchContractError(
            "offline batch scenarios are incomplete or reordered"
        )
    specs: list[ScheduledWorkItemSpec] = []
    evidence_root = resolved.parents[1] / "evidence"
    for index, item in enumerate(items, start=1):
        loading_sha = str(item["loading_image_sha256"])
        unloading_sha = str(item["unloading_image_sha256"])
        for sha256 in {loading_sha, unloading_sha} - {"0" * 64}:
            path = (
                evidence_root
                / "sha256"
                / sha256[:2]
                / sha256[2:4]
                / f"{sha256}.blob"
            )
            if not path.is_file() or _sha256_file(path) != sha256:
                raise OfflineBatchContractError(
                    f"offline evidence differs for item {index}"
                )
        specs.append(
            ScheduledWorkItemSpec(
                item_key=f"OFFLINE-{index:03d}",
                expected_outcome=str(item["expected_outcome"]),
                review_reason=item.get("review_reason"),
                loading_image_sha256=loading_sha,
                unloading_image_sha256=unloading_sha,
                vehicle_number=f"匿名车辆-{index:03d}",
                platform_loading_net=item.get("platform_loading_net"),
                platform_unloading_net=item.get("platform_unloading_net"),
                ticket_loading_net=item.get("ticket_loading_net"),
                ticket_unloading_net=item.get("ticket_unloading_net"),
                diagnostic_code=item.get("diagnostic_code"),
            )
        )
    return ScheduledJobSpec(
        fixture_id=LOOP8_OFFLINE_FIXTURE_ID,
        job_kind="business",
        task_type="audit",
        scope_label="Loop 8 完全离线验收批次",
        conflict_key="audit:loop8-offline-v1",
        items=tuple(specs),
        pipeline_fingerprint=LOOP8_OFFLINE_PIPELINE_FINGERPRINT,
        ocr_execution_mode="fake",
    )
