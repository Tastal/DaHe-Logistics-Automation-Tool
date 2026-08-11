from __future__ import annotations

import argparse
import json
import os
import re
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from uuid import uuid4

_IMAGE_NAME = re.compile(r"^[0-9a-f]{64}\.(?:jpg|png)$")
_NUMBER = re.compile(r"(?<!\d)(\d{1,6}(?:\.\d{1,3})?)(?!\d)")


def extract_numeric_candidates(texts: tuple[str, ...] | list[str]) -> list[str]:
    candidates: set[str] = set()
    for text in texts:
        if not isinstance(text, str):
            raise ValueError("RapidOCR text output is invalid")
        for raw in _NUMBER.findall(text.replace(",", "")):
            try:
                normalized = format(Decimal(raw).normalize(), "f")
            except InvalidOperation as error:
                raise ValueError("RapidOCR numeric output is invalid") from error
            candidates.add(normalized)
    return sorted(candidates, key=lambda value: (len(value), value))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> int:
    args = _parser().parse_args()
    if not args.input_dir.is_absolute() or not args.output.is_absolute():
        raise SystemExit("worker paths must be absolute")
    input_dir = args.input_dir.resolve(strict=True)
    output = args.output.resolve(strict=False)
    if output.exists() or output.parent.resolve(strict=True) != input_dir.parent:
        raise SystemExit("worker output path is invalid")
    images = sorted(path for path in input_dir.iterdir() if path.is_file())
    if not images or any(
        path.is_symlink() or not _IMAGE_NAME.fullmatch(path.name) for path in images
    ):
        raise SystemExit("worker input set is invalid")

    import rapidocr  # type: ignore[import-not-found]
    from rapidocr import RapidOCR

    model_root = str(Path(rapidocr.__file__).resolve().parent / "models")
    engine = RapidOCR(params={"Global.model_root_dir": model_root})
    results: list[dict[str, object]] = []
    for image in images:
        started = time.perf_counter()
        observation = engine(image)
        elapsed_ms = (time.perf_counter() - started) * 1000
        texts = observation.txts or ()
        results.append(
            {
                "image_sha256": image.stem,
                "numeric_candidates": extract_numeric_candidates(tuple(texts)),
                "elapsed_ms": round(elapsed_ms, 3),
            }
        )
    _atomic_json(
        output,
        {
            "schema_version": 1,
            "kind": "rapidocr_development_experiment_worker_result",
            "results": results,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
