from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.ocr_experiment import (
    deterministic_sample,
    load_experiment_manifest,
    load_protected_review_record,
    make_safe_result,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_review_record(root: Path, *, image_count: int = 4) -> Path:
    protected = root / "development" / "protected-candidate-review-ocr"
    copied_images: list[dict[str, object]] = []
    waybill_images: list[dict[str, object]] = []
    for index in range(image_count):
        content = f"development image {index}".encode()
        image_sha256 = _sha256(content)
        relative_path = (
            "development/protected-candidate-review-ocr/evidence/sha256/"
            f"{image_sha256[:2]}/{image_sha256[2:4]}/{image_sha256}.blob"
        )
        image_path = root / relative_path
        image_path.parent.mkdir(parents=True, exist_ok=True)
        image_path.write_bytes(content)
        copied_images.append(
            {
                "byte_size": len(content),
                "image_sha256": image_sha256,
                "media_type": "image/jpeg",
                "relative_path": relative_path,
            }
        )
        waybill_images.append(
            {
                "image_sha256": image_sha256,
                "ordinary_net": f"{30 + index}.00",
                "relative_path": f"images/{image_sha256}.jpg",
                "role": "loading" if index % 2 == 0 else "unloading",
                "submitted_slot": "loading" if index % 2 == 0 else "unloading",
            }
        )
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "protected_candidate_review_ocr_evaluation",
        "evidence_sha256": "0" * 64,
        "development_only": True,
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "copied_images": copied_images,
        "source": {
            "manifest_payload": {
                "dataset_id": "development-only",
                "dataset_kind": "development",
                "schema_version": 1,
                "tuning_prohibited": False,
                "waybills": [
                    {
                        "human_confirmed": True,
                        "images": waybill_images,
                        "label_source": "human_review",
                        "sample_id": "sample-1",
                        "waybill_identity_sha256": "1" * 64,
                    }
                ],
            }
        },
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()
    evidence_sha256 = _sha256(canonical)
    payload["evidence_sha256"] = evidence_sha256
    record = (
        protected
        / "records"
        / "sha256"
        / evidence_sha256[:2]
        / evidence_sha256[2:4]
        / f"{evidence_sha256}.json"
    )
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps(payload), encoding="utf-8")
    return record


def test_manifest_pins_approved_current_tools() -> None:
    manifest = load_experiment_manifest()

    assert manifest.cleanvision.version == "0.3.7"
    assert manifest.cleanvision.wheel_sha256 == (
        "46ad8296a7750c354cef5ac39136f0d0e2c9bbdb88eda68c037877ed2702d74f"
    )
    assert manifest.rapidocr.version == "3.9.2"
    assert manifest.rapidocr.wheel_sha256 == (
        "04d6b8d151f823d930bd91910555f57bea897c0c44fa6794267b94cf9c1ef9a0"
    )
    assert manifest.rapidocr.runtime_backend is not None
    assert manifest.rapidocr.runtime_backend.version == "1.28.0"
    assert manifest.rapidocr.runtime_backend.wheel_sha256 == (
        "c35064f9b3c43c81c5d5d282091401d0f1ff22796d93ccade4ea2ece5e137ab8"
    )


def test_review_record_must_be_absolute_and_in_protected_development_area(
    tmp_path: Path,
) -> None:
    root = tmp_path / "development-root"
    record = _write_review_record(root)

    with pytest.raises(ValueError, match="absolute"):
        load_protected_review_record(Path("relative"), Path("relative.json"))

    outside = tmp_path / "outside.json"
    outside.write_text(record.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="protected development"):
        load_protected_review_record(root.resolve(), outside.resolve())


def test_review_record_verifies_content_addressed_image_bytes(tmp_path: Path) -> None:
    root = (tmp_path / "development-root").resolve()
    record = _write_review_record(root)
    loaded = load_protected_review_record(root, record.resolve())

    assert len(loaded.images) == 4
    assert all(image.human_confirmed for image in loaded.images)

    loaded.images[0].path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="image SHA-256"):
        load_protected_review_record(root, record.resolve())


def test_deterministic_sample_is_stable_and_order_independent(tmp_path: Path) -> None:
    root = (tmp_path / "development-root").resolve()
    record = _write_review_record(root, image_count=8)
    loaded = load_protected_review_record(root, record.resolve())

    first = deterministic_sample(loaded.images, 3)
    second = deterministic_sample(tuple(reversed(loaded.images)), 3)

    assert [item.image_sha256 for item in first] == [
        item.image_sha256 for item in second
    ]
    assert [item.image_sha256 for item in first] == sorted(
        item.image_sha256 for item in first
    )


def test_safe_result_is_development_only_and_contains_no_raw_text_or_paths() -> None:
    payload = make_safe_result(
        source_record_sha256="a" * 64,
        source_image_set_sha256="b" * 64,
        sample_results=[
            {
                "image_sha256": "c" * 64,
                "truth_ordinary_net": "32.70",
                "rapidocr_ordinary_net_candidates": ["32.70"],
                "quality_issue_types": ["blurry"],
                "rapidocr_elapsed_ms": 123.4,
            }
        ],
        tool_runtime_sha256s={"cleanvision": "d" * 64, "rapidocr": "e" * 64},
    )

    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert payload["development_only"] is True
    assert payload["formal_acceptance"] is False
    assert payload["future_locked_set_eligible"] is False
    assert "raw_text" not in serialized
    assert "relative_path" not in serialized
    assert "absolute_path" not in serialized
    assert "platform" not in serialized
