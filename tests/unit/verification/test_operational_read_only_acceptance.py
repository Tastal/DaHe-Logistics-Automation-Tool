from __future__ import annotations

import json
from pathlib import Path

import pytest

from dahe.verification.operational_read_only_acceptance import (
    OperationalReadOnlyAcceptanceError,
    _verify_ocr_qualification,
    _verify_regression,
)


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return path.resolve()


def _regression() -> dict[str, object]:
    return {
        "committed_report": {
            "metrics": {
                "real_image_sample_count": 100,
                "real_pair_sample_count": 50,
                "wrong_auto_pass_count": 0,
            },
            "reconciliation": {
                "duplicate_image_results": [],
                "duplicate_pair_results": [],
                "expected_image_count": 100,
                "expected_pair_count": 50,
                "missing_image_results": [],
                "missing_pair_results": [],
                "result_image_count": 100,
                "result_pair_count": 50,
                "unexpected_image_results": [],
                "unexpected_pair_results": [],
            },
        }
    }


def test_historical_regression_requires_zero_wrong_auto_passes(
    tmp_path: Path,
) -> None:
    path = _write_json(tmp_path / "regression.json", _regression())
    assert _verify_regression(path)["wrong_auto_pass_count"] == 0

    unsafe = _regression()
    unsafe["committed_report"]["metrics"]["wrong_auto_pass_count"] = 1  # type: ignore[index]
    path = _write_json(tmp_path / "unsafe.json", unsafe)
    with pytest.raises(
        OperationalReadOnlyAcceptanceError,
        match="unsafe result",
    ):
        _verify_regression(path)


def test_ocr_qualification_requires_cpu_and_real_gpu_profiles(
    tmp_path: Path,
) -> None:
    reports = []
    for kind in ("cpu", "gpu"):
        reports.append(
            {
                "images": [
                    {
                        "elapsed_ms": 125.0,
                        "field_reliable": True,
                        "image_id": "loading",
                        "image_sha256": "a" * 64,
                        "role": "loading",
                        "verified_image_sha256": "a" * 64,
                    },
                    {
                        "elapsed_ms": 130.0,
                        "field_reliable": True,
                        "image_id": "unloading",
                        "image_sha256": "b" * 64,
                        "role": "unloading",
                        "verified_image_sha256": "b" * 64,
                    },
                ],
                "profile_id": f"{kind}-profile",
                "runtime_kind": kind,
                "stable_device_id": "gpu-device" if kind == "gpu" else None,
                "status": "qualified",
            }
        )
    valid = _write_json(
        tmp_path / "qualification.json",
        {"reports": reports, "schema_version": 2},
    )
    projection = _verify_ocr_qualification(valid)
    assert projection["cpu_profile_id"] == "cpu-profile"
    assert projection["gpu_profile_id"] == "gpu-profile"

    reports[1]["stable_device_id"] = None
    invalid = _write_json(
        tmp_path / "invalid-qualification.json",
        {"reports": reports, "schema_version": 2},
    )
    with pytest.raises(
        OperationalReadOnlyAcceptanceError,
        match="gpu OCR qualification",
    ):
        _verify_ocr_qualification(invalid)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("field_reliable", False),
        ("role", "unknown"),
        ("verified_image_sha256", "c" * 64),
    ),
)
def test_ocr_qualification_rejects_an_unverified_smoke_image(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    reports = []
    for kind in ("cpu", "gpu"):
        reports.append(
            {
                "images": [
                    {
                        "elapsed_ms": 125.0,
                        "field_reliable": True,
                        "image_id": "loading",
                        "image_sha256": "a" * 64,
                        "role": "loading",
                        "verified_image_sha256": "a" * 64,
                    },
                    {
                        "elapsed_ms": 130.0,
                        "field_reliable": True,
                        "image_id": "unloading",
                        "image_sha256": "b" * 64,
                        "role": "unloading",
                        "verified_image_sha256": "b" * 64,
                    },
                ],
                "profile_id": f"{kind}-profile",
                "runtime_kind": kind,
                "stable_device_id": "gpu-device" if kind == "gpu" else None,
                "status": "qualified",
            }
        )
    reports[0]["images"][0][field] = value  # type: ignore[index]
    invalid = _write_json(
        tmp_path / f"invalid-{field}.json",
        {"reports": reports, "schema_version": 2},
    )

    with pytest.raises(
        OperationalReadOnlyAcceptanceError,
        match="cpu OCR qualification",
    ):
        _verify_ocr_qualification(invalid)
