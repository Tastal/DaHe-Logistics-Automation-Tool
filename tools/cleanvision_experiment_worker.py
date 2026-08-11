from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from uuid import uuid4

_IMAGE_NAME = re.compile(r"^[0-9a-f]{64}\.(?:jpg|png)$")
_ISSUE_TYPES = (
    "blurry",
    "dark",
    "exact_duplicates",
    "light",
    "low_information",
    "near_duplicates",
    "odd_aspect_ratio",
    "odd_size",
)


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

    from cleanvision import Imagelab  # type: ignore[import-not-found]

    lab = Imagelab(filepaths=[os.fspath(path) for path in images], verbose=False)
    lab.find_issues(
        issue_types={issue_type: {} for issue_type in _ISSUE_TYPES},
        n_jobs=1,
        verbose=False,
    )
    if len(lab.issues.index) != len(images):
        raise RuntimeError("CleanVision result count differs from the input set")
    results: list[dict[str, object]] = []
    for index, image in enumerate(images):
        row = lab.issues.iloc[index]
        issues = [
            issue_type
            for issue_type in _ISSUE_TYPES
            if bool(row.get(f"is_{issue_type}_issue", False))
        ]
        results.append(
            {
                "image_sha256": image.stem,
                "issue_types": issues,
            }
        )
    _atomic_json(
        output,
        {
            "schema_version": 1,
            "kind": "cleanvision_development_experiment_worker_result",
            "results": results,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
