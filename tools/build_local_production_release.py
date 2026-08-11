from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dahe.config.paths import resolve_desktop_directory
from dahe.release.local_release import build_local_release

ROOT = Path(__file__).resolve().parents[1]


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--operational-source-root", type=_absolute, required=True)
    parser.add_argument(
        "--releases-root",
        type=_absolute,
        default=(
            Path(os.environ["LOCALAPPDATA"])
            / "Programs"
            / "DaHeLogistics"
            / "releases"
        ),
    )
    arguments = parser.parse_args()
    result = build_local_release(
        project_root=ROOT,
        releases_root=arguments.releases_root,
        operational_source_root=arguments.operational_source_root,
        desktop_root=resolve_desktop_directory(),
    )
    print(
        json.dumps(
            {
                "launcher": str(result.launcher_path),
                "manifest": str(result.manifest_path),
                "release_root": str(result.release_root),
                "shortcut": str(result.shortcut_path),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
