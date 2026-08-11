from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

MODEL_STAGING_PATTERN = re.compile(r"^\.model-staging-[0-9a-f]{32}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explicitly provision the approved local PaddleOCR model set."
    )
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--candidate-cache-root", type=Path, required=True)
    parser.add_argument(
        "--model-source",
        choices=("aistudio", "huggingface", "modelscope", "bos"),
        required=True,
    )
    return parser


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _prepare_candidate_cache(
    *,
    runtime_root: Path,
    candidate_cache_root: Path,
) -> Path:
    resolved_root = runtime_root.resolve(strict=True)
    candidate = candidate_cache_root.resolve()
    if (
        candidate.parent != resolved_root
        or MODEL_STAGING_PATTERN.fullmatch(candidate.name) is None
        or candidate.exists()
        or candidate.is_symlink()
    ):
        raise SystemExit(
            "model provisioning requires a new managed staging cache"
        )
    candidate.mkdir()
    return candidate


def main() -> None:
    args = _parser().parse_args()
    root = Path(__file__).resolve().parents[1]
    runtime_root = args.runtime_root.resolve()
    if os.name == "nt" and not os.fspath(runtime_root).isascii():
        raise SystemExit("PaddleOCR on Windows requires an ASCII OCR runtime root.")
    cache_root = _prepare_candidate_cache(
        runtime_root=runtime_root,
        candidate_cache_root=args.candidate_cache_root,
    )
    os.environ["PADDLE_PDX_CACHE_HOME"] = os.fspath(cache_root)
    os.environ["PADDLE_PDX_MODEL_SOURCE"] = args.model_source
    os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "True"

    spec = json.loads(
        (root / "ocr-runtime" / "model-spec.json").read_text(encoding="utf-8")
    )
    required = tuple(item["name"] for item in spec["models"])
    with contextlib.redirect_stdout(sys.stderr):
        official_models_module = importlib.import_module(
            "paddlex.inference.utils.official_models"
        )
        official_models = official_models_module.official_models
        for name in required:
            official_models.get_model_path(name)

    models_dir = cache_root / "official_models"
    for name in required:
        if not (models_dir / name).is_dir():
            raise SystemExit(f"Provisioning did not produce required model: {name}")
    files = []
    for path in sorted(
        item
        for name in required
        for item in (models_dir / name).rglob("*")
        if item.is_file()
    ):
        if path.is_symlink():
            raise SystemExit("Provisioned model contains a symbolic link.")
        files.append(
            {
                "relative_path": path.relative_to(models_dir).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    manifest = {
        "schema_version": 1,
        "model_set_id": spec["model_set_id"],
        "models": spec["models"],
        "files": files,
    }
    target = models_dir / "model-manifest.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)
    worker_manifest_module = importlib.import_module(
        "dahe_ocr_worker.model_manifest"
    )
    verify_model_manifest = cast(
        Callable[..., object],
        worker_manifest_module.load_and_verify_model_manifest,
    )
    verify_model_manifest(
        models_dir=models_dir,
        manifest_path=target,
    )
    print(
        json.dumps(
            {
                "models_dir": os.fspath(models_dir),
                "manifest": os.fspath(target),
                "manifest_sha256": _sha256(target),
                "file_count": len(files),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
