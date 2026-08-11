from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from dahe.application.audit.offline_batch import (  # noqa: E402
    EXPECTED_SCENARIOS,
    LOOP8_OFFLINE_FIXTURE_ID,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare the identity-free Loop 8 offline acceptance batch."
    )
    parser.add_argument("--formal-report", type=Path, required=True)
    parser.add_argument("--source-image-root", type=Path, required=True)
    parser.add_argument("--output-data-root", type=Path, required=True)
    return parser


def _absolute_regular(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    resolved = path.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_file():
        raise ValueError(f"{label} must be a regular file")
    return resolved


def _absolute_directory(path: Path, label: str, *, create: bool) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    if create:
        path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise ValueError(f"{label} must be a regular directory")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_evidence(source_root: Path, output_root: Path, sha256: str) -> None:
    matches = tuple(source_root.glob(f"{sha256}.*"))
    if len(matches) != 1:
        raise ValueError(f"source image {sha256} is missing or ambiguous")
    source = matches[0].resolve(strict=True)
    if not source.is_relative_to(source_root) or source.is_symlink():
        raise ValueError("source evidence escaped its approved directory")
    if _sha256_file(source) != sha256:
        raise ValueError(f"source image hash differs: {sha256}")
    target = (
        output_root
        / "evidence"
        / "sha256"
        / sha256[:2]
        / sha256[2:4]
        / f"{sha256}.blob"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if _sha256_file(target) != sha256:
            raise ValueError(f"existing evidence hash differs: {sha256}")
        return
    staged = target.with_suffix(".partial")
    if staged.exists():
        raise ValueError(f"staged evidence already exists: {sha256}")
    shutil.copyfile(source, staged)
    if _sha256_file(staged) != sha256:
        staged.unlink(missing_ok=True)
        raise ValueError(f"copied evidence hash differs: {sha256}")
    os.replace(staged, target)


def _item(
    scenario: str,
    loading: str,
    unloading: str,
    *,
    expected_outcome: str,
    review_reason: str | None = None,
    platform_loading_net: str = "32.70",
    platform_unloading_net: str = "32.60",
    ticket_loading_net: str | None = "32.70",
    ticket_unloading_net: str | None = "32.60",
    diagnostic_code: str | None = None,
) -> dict[str, object]:
    return {
        "diagnostic_code": diagnostic_code,
        "expected_outcome": expected_outcome,
        "loading_image_sha256": loading,
        "platform_loading_net": platform_loading_net,
        "platform_unloading_net": platform_unloading_net,
        "review_reason": review_reason,
        "scenario": scenario,
        "ticket_loading_net": ticket_loading_net,
        "ticket_unloading_net": ticket_unloading_net,
        "unloading_image_sha256": unloading,
    }


def main() -> int:
    args = _parser().parse_args()
    report_path = _absolute_regular(args.formal_report, "formal report")
    image_root = _absolute_directory(
        args.source_image_root,
        "source image root",
        create=False,
    )
    output_root = _absolute_directory(
        args.output_data_root,
        "output data root",
        create=True,
    )
    manifest_path = (
        output_root / "offline-audit" / f"{LOOP8_OFFLINE_FIXTURE_ID}.json"
    )
    if manifest_path.exists():
        raise ValueError("offline batch manifest already exists")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    committed = report["committed_report"]
    pair_results = list(committed["pair_results"])
    normal = [
        pair
        for pair in pair_results
        if pair["automatic_outcome"] == "normal_ready"
    ]
    unknown = next(
        pair
        for pair in pair_results
        if pair["automatic_outcome"] == "awaiting_review"
    )
    derived = {
        item["scenario_id"]: item
        for item in committed["derived_adversarial_results"]["results"]
    }
    base = normal[:3]
    zero = "0" * 64
    items = [
        _item(
            "clear_normal",
            base[0]["loading_slot_image_sha256"],
            base[0]["unloading_slot_image_sha256"],
            expected_outcome="normal_ready",
        ),
        _item(
            "rotated_or_alternate_layout",
            base[1]["loading_slot_image_sha256"],
            base[1]["unloading_slot_image_sha256"],
            expected_outcome="normal_ready",
        ),
        _item(
            "numeric_mismatch",
            base[2]["loading_slot_image_sha256"],
            base[2]["unloading_slot_image_sha256"],
            expected_outcome="awaiting_review",
            review_reason="numeric_mismatch",
            ticket_unloading_net="32.50",
        ),
        _item(
            "role_unknown",
            unknown["loading_slot_image_sha256"],
            unknown["unloading_slot_image_sha256"],
            expected_outcome="awaiting_review",
            review_reason="role_unknown",
            ticket_loading_net=None,
            ticket_unloading_net=None,
        ),
        *[
            _item(
                scenario,
                derived[scenario]["loading_slot_image_sha256"],
                derived[scenario]["unloading_slot_image_sha256"],
                expected_outcome="awaiting_review",
                review_reason=str(derived[scenario]["role_issue"]),
            )
            for scenario in (
                "swapped_slots",
                "both_loading",
                "both_unloading",
                "exact_duplicate_image",
            )
        ],
        _item(
            "missing_ticket",
            base[0]["loading_slot_image_sha256"],
            zero,
            expected_outcome="awaiting_review",
            review_reason="missing_ticket",
            ticket_unloading_net=None,
        ),
        _item(
            "ticket_weight_format_suspicious",
            base[0]["loading_slot_image_sha256"],
            base[0]["unloading_slot_image_sha256"],
            expected_outcome="awaiting_review",
            review_reason="ticket_weight_format_suspicious",
            ticket_loading_net="3270",
        ),
        _item(
            "ocr_weight_disagreement",
            base[1]["loading_slot_image_sha256"],
            base[1]["unloading_slot_image_sha256"],
            expected_outcome="awaiting_review",
            review_reason="ocr_weight_disagreement",
            ticket_loading_net=None,
        ),
        _item(
            "ocr_worker_failure",
            base[2]["loading_slot_image_sha256"],
            base[2]["unloading_slot_image_sha256"],
            expected_outcome="failed",
            diagnostic_code="OCR-WORKER-OFFLINE-INJECTED",
            ticket_loading_net=None,
            ticket_unloading_net=None,
        ),
    ]
    if tuple(item["scenario"] for item in items) != EXPECTED_SCENARIOS:
        raise AssertionError("internal scenario order differs")
    image_hashes = {
        str(item[key])
        for item in items
        for key in ("loading_image_sha256", "unloading_image_sha256")
        if item[key] != zero
    }
    for sha256 in sorted(image_hashes):
        _copy_evidence(image_root, output_root, sha256)
    unsigned: dict[str, Any] = {
        "fixture_id": LOOP8_OFFLINE_FIXTURE_ID,
        "items": items,
        "offline": True,
        "platform_access": False,
        "schema_version": 1,
        "source_classification": "DaHe development evidence",
        "source_formal_report_sha256": _sha256_file(report_path),
    }
    canonical = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload = {
        **unsigned,
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    staged_manifest = manifest_path.with_suffix(".partial")
    staged_manifest.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(staged_manifest, manifest_path)
    print(
        json.dumps(
            {
                "evidence_count": len(image_hashes),
                "item_count": len(items),
                "manifest_path": str(manifest_path),
                "manifest_sha256": payload["manifest_sha256"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
