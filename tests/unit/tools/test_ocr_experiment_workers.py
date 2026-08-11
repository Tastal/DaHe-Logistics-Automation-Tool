from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.rapidocr_experiment_worker import extract_numeric_candidates
from tools.run_ocr_experiment import _load_worker_results, _parser


def test_rapidocr_worker_emits_only_normalized_numeric_candidates() -> None:
    candidates = extract_numeric_candidates(
        ("净重 32.70 吨", "车号 123456", "日期 2026-07-31", "备用值 3270")
    )

    assert "32.7" in candidates
    assert "3270" in candidates
    assert "净重 32.70 吨" not in candidates


def test_runner_exposes_no_expected_platform_weight_argument() -> None:
    actions = _parser()._option_string_actions

    assert "--expected-weight" not in actions
    assert "--platform-weight" not in actions
    assert set(actions) == {
        "-h",
        "--help",
        "--development-root",
        "--review-record",
        "--sample-size",
    }


def test_worker_result_rejects_extra_raw_text_or_path(tmp_path: Path) -> None:
    image_sha256 = "a" * 64
    output = tmp_path / "worker.json"
    output.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "rapidocr_development_experiment_worker_result",
                "results": [
                    {
                        "image_sha256": image_sha256,
                        "numeric_candidates": ["32.7"],
                        "elapsed_ms": 1.0,
                        "raw_text": "must not escape",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="worker item"):
        _load_worker_results(
            output,
            expected_kind="rapidocr_development_experiment_worker_result",
            expected_hashes={image_sha256},
            value_fields={"numeric_candidates", "elapsed_ms"},
        )
