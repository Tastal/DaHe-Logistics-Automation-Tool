from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

try:
    from tools.ocr_experiment import (
        ROOT,
        deterministic_sample,
        experiment_root,
        load_experiment_manifest,
        load_protected_review_record,
        make_safe_result,
        require_project_venv,
        tool_python,
    )
except ModuleNotFoundError:  # Direct execution puts tools/ on sys.path.
    from ocr_experiment import (  # type: ignore[import-not-found,no-redef]
        ROOT,
        deterministic_sample,
        experiment_root,
        load_experiment_manifest,
        load_protected_review_record,
        make_safe_result,
        require_project_venv,
        tool_python,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run an isolated development-only image quality and CPU OCR comparison."
    )
    parser.add_argument("--development-root", type=Path, required=True)
    parser.add_argument("--review-record", type=Path, required=True)
    parser.add_argument("--sample-size", type=int, default=20)
    return parser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    if path.exists():
        raise FileExistsError("experiment result already exists")
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _runtime_identity(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("isolated OCR experiment runtime is not installed")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("production_runtime") is not False
        or payload.get("kind") != "isolated_development_ocr_experiment_tool"
    ):
        raise RuntimeError("isolated OCR experiment runtime identity is invalid")
    return _sha256(path)


def _run_worker(command: list[str], *, cwd: Path, label: str) -> None:
    environment = dict(os.environ)
    environment["OC_DISABLE_DOT_ACCESS_WARNING"] = "1"
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        shell=False,
        check=False,
        capture_output=True,
        text=False,
        timeout=600,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{label} worker failed with code {completed.returncode}")


def _load_worker_results(
    path: Path,
    *,
    expected_kind: str,
    expected_hashes: set[str],
    value_fields: set[str],
) -> dict[str, dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "kind", "results"}
        or payload.get("schema_version") != 1
        or payload.get("kind") != expected_kind
        or not isinstance(payload.get("results"), list)
    ):
        raise ValueError("experiment worker result is invalid")
    results: dict[str, dict[str, object]] = {}
    for item in payload["results"]:
        if not isinstance(item, dict) or set(item) != {"image_sha256", *value_fields}:
            raise ValueError("experiment worker item is invalid")
        image_sha256 = item.get("image_sha256")
        if not isinstance(image_sha256, str) or image_sha256 in results:
            raise ValueError("experiment worker image identity is invalid")
        results[image_sha256] = item
    if set(results) != expected_hashes:
        raise ValueError("experiment worker result count differs from the sample")
    return results


def _percentile_95(values: list[float]) -> float:
    if not values:
        raise ValueError("timing sample is empty")
    return sorted(values)[max(0, int(len(values) * 0.95) - 1)]


def main() -> int:
    require_project_venv()
    args = _parser().parse_args()
    if not args.development_root.is_absolute() or not args.review_record.is_absolute():
        raise SystemExit("development paths must be absolute")
    record = load_protected_review_record(args.development_root, args.review_record)
    sample = deterministic_sample(record.images, args.sample_size)
    manifest = load_experiment_manifest()
    created_at = datetime.now(UTC)
    run_id = f"{created_at:%Y%m%dT%H%M%SZ}-{uuid4().hex[:12]}"
    run_root = experiment_root() / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    input_root = run_root / "inputs"
    input_root.mkdir()
    cleanvision_output = run_root / "cleanvision-safe.json"
    rapidocr_output = run_root / "rapidocr-safe.json"
    result_path = run_root / "result.json"
    try:
        for image in sample:
            extension = ".jpg" if image.media_type == "image/jpeg" else ".png"
            target = input_root / f"{image.image_sha256}{extension}"
            shutil.copyfile(image.path, target)
            if _sha256(target) != image.image_sha256:
                raise RuntimeError("experiment input copy SHA-256 does not match")
        runtime_sha256s: dict[str, str] = {}
        for name in ("cleanvision", "rapidocr"):
            pin = manifest.get(name)
            python = tool_python(pin)
            runtime_sha256s[name] = _runtime_identity(
                python.parents[2] / "runtime-installation.json"
            )
        _run_worker(
            [
                os.fspath(tool_python(manifest.cleanvision)),
                "-I",
                os.fspath((ROOT / "tools" / "cleanvision_experiment_worker.py").resolve()),
                "--input-dir",
                os.fspath(input_root.resolve()),
                "--output",
                os.fspath(cleanvision_output.resolve()),
            ],
            cwd=run_root,
            label="CleanVision",
        )
        _run_worker(
            [
                os.fspath(tool_python(manifest.rapidocr)),
                "-I",
                os.fspath((ROOT / "tools" / "rapidocr_experiment_worker.py").resolve()),
                "--input-dir",
                os.fspath(input_root.resolve()),
                "--output",
                os.fspath(rapidocr_output.resolve()),
            ],
            cwd=run_root,
            label="RapidOCR",
        )
        expected_hashes = {image.image_sha256 for image in sample}
        cleanvision = _load_worker_results(
            cleanvision_output,
            expected_kind="cleanvision_development_experiment_worker_result",
            expected_hashes=expected_hashes,
            value_fields={"issue_types"},
        )
        rapidocr = _load_worker_results(
            rapidocr_output,
            expected_kind="rapidocr_development_experiment_worker_result",
            expected_hashes=expected_hashes,
            value_fields={"numeric_candidates", "elapsed_ms"},
        )
        sample_results: list[dict[str, object]] = []
        for image in sample:
            quality_issue_types = cleanvision[image.image_sha256]["issue_types"]
            numeric_candidates = rapidocr[image.image_sha256]["numeric_candidates"]
            elapsed_ms = rapidocr[image.image_sha256]["elapsed_ms"]
            if (
                not isinstance(quality_issue_types, list)
                or not isinstance(numeric_candidates, list)
                or not isinstance(elapsed_ms, int | float)
            ):
                raise ValueError("experiment worker field type is invalid")
            truth_ordinary_net = (
                format(Decimal(image.truth_ordinary_net).normalize(), "f")
                if image.truth_ordinary_net is not None
                else None
            )
            sample_results.append(
                {
                    "image_sha256": image.image_sha256,
                    "truth_ordinary_net": truth_ordinary_net,
                    "rapidocr_ordinary_net_candidates": numeric_candidates,
                    "quality_issue_types": quality_issue_types,
                    "source_quality_conditions": list(image.quality_conditions),
                    "rapidocr_elapsed_ms": elapsed_ms,
                }
            )
        result = make_safe_result(
            source_record_sha256=record.evidence_sha256,
            source_image_set_sha256=record.image_set_sha256,
            sample_results=sample_results,
            tool_runtime_sha256s=runtime_sha256s,
        )
        baseline_by_hash = {
            item.image_sha256: item for item in record.cpu_baselines
        }
        selected_baselines = [
            baseline_by_hash[image.image_sha256]
            for image in sample
            if image.image_sha256 in baseline_by_hash
        ]
        if selected_baselines:
            baseline_times = [item.elapsed_ms for item in selected_baselines]
            result_samples = result.get("samples")
            if not isinstance(result_samples, list):
                raise RuntimeError("safe experiment result has no sample list")
            rapidocr_times = [
                float(item["rapidocr_elapsed_ms"])
                for item in result_samples
                if isinstance(item, dict)
            ]
            baseline_median = statistics.median(baseline_times)
            rapidocr_median = statistics.median(rapidocr_times)
            result["baseline_cpu"] = {
                "sample_count": len(selected_baselines),
                "median_elapsed_ms": round(baseline_median, 3),
                "p95_elapsed_ms": round(_percentile_95(baseline_times), 3),
            }
            result["rapidocr_timing"] = {
                "sample_count": len(rapidocr_times),
                "median_elapsed_ms": round(rapidocr_median, 3),
                "p95_elapsed_ms": round(_percentile_95(rapidocr_times), 3),
                "median_speedup_ratio_vs_baseline_cpu": round(
                    baseline_median / rapidocr_median,
                    3,
                ),
            }
        result["created_at"] = created_at.isoformat()
        result["run_id"] = run_id
        _atomic_json(result_path, result)
    finally:
        shutil.rmtree(input_root, ignore_errors=True)
    print(result_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
