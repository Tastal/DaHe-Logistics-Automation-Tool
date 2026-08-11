from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from dahe.adapters.ocr.runtime_layout import (
    OcrRuntimeLayoutError,
    activate_composition,
    resolve_active_composition,
    write_composition_manifest,
)


def _legacy(runtime_root: Path) -> None:
    for runtime in ("ocr-cpu", "ocr-gpu"):
        (runtime_root / runtime).mkdir(parents=True)
    models = runtime_root / "model-cache" / "official_models"
    models.mkdir(parents=True)
    (models / "model-manifest.json").write_text("{}", encoding="utf-8")
    qualification = runtime_root / "qualification" / "qualification.json"
    qualification.parent.mkdir()
    qualification.write_text("{}", encoding="utf-8")


def _generation(runtime_root: Path, generation_id: str) -> Path:
    generation = runtime_root / "generations" / generation_id
    for runtime in ("ocr-cpu", "ocr-gpu"):
        runtime_dir = generation / runtime
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "runtime-installation.json").write_text(
            json.dumps({"runtime": runtime}),
            encoding="utf-8",
        )
    models = generation / "model-cache" / "official_models"
    models.mkdir(parents=True)
    (models / "model-manifest.json").write_text(
        json.dumps({"model": generation_id}),
        encoding="utf-8",
    )
    qualification = generation / "qualification" / "qualification.json"
    qualification.parent.mkdir(parents=True)
    qualification.write_text(
        json.dumps(
            {
                "generation": generation_id,
                "reports": [
                    {"runtime_kind": "cpu"},
                    {"runtime_kind": "gpu"},
                ],
            }
        ),
        encoding="utf-8",
    )
    write_composition_manifest(
        generation_dir=generation,
        generation_id=generation_id,
        gpu_present=True,
    )
    return generation


def test_legacy_layout_is_read_only_compatibility_when_pointer_is_absent(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    _legacy(runtime_root)

    active = resolve_active_composition(runtime_root)

    assert active.generation_id is None
    assert active.cpu_runtime == (runtime_root / "ocr-cpu").resolve()
    assert active.gpu_runtime == (runtime_root / "ocr-gpu").resolve()
    assert not (runtime_root / "active-composition.json").exists()


def test_activation_is_one_atomic_pointer_after_a_complete_generation(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    _legacy(runtime_root)
    generation_id = "1" * 32
    generation = _generation(runtime_root, generation_id)

    active = activate_composition(
        runtime_root=runtime_root,
        generation_id=generation_id,
    )
    resolved = resolve_active_composition(runtime_root, allow_legacy=False)

    assert active == resolved
    assert resolved.generation_dir == generation.resolve()
    assert resolved.cpu_runtime == (generation / "ocr-cpu").resolve()
    assert resolved.gpu_runtime == (generation / "ocr-gpu").resolve()
    assert resolved.models_dir == (
        generation / "model-cache" / "official_models"
    ).resolve()
    assert (runtime_root / "ocr-cpu").is_dir()
    assert (runtime_root / "ocr-gpu").is_dir()


def test_failed_candidate_does_not_change_the_previous_pointer(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    first_id = "1" * 32
    _generation(runtime_root, first_id)
    activate_composition(runtime_root=runtime_root, generation_id=first_id)
    pointer_before = (runtime_root / "active-composition.json").read_bytes()

    incomplete_id = "2" * 32
    incomplete = runtime_root / "generations" / incomplete_id
    incomplete.mkdir(parents=True)
    with pytest.raises(OcrRuntimeLayoutError):
        activate_composition(
            runtime_root=runtime_root,
            generation_id=incomplete_id,
        )

    assert (runtime_root / "active-composition.json").read_bytes() == pointer_before
    assert resolve_active_composition(runtime_root).generation_id == first_id


def test_pointer_and_manifest_hashes_are_fail_closed(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    generation_id = "1" * 32
    generation = _generation(runtime_root, generation_id)
    activate_composition(runtime_root=runtime_root, generation_id=generation_id)
    (generation / "composition-manifest.json").write_text(
        '{"tampered":true}',
        encoding="utf-8",
    )

    with pytest.raises(OcrRuntimeLayoutError, match="hash"):
        resolve_active_composition(runtime_root)


def test_generation_rejects_unexpected_top_level_content(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    generation_id = "1" * 32
    generation = _generation(runtime_root, generation_id)
    (generation / "stale-download.tmp").write_bytes(b"partial")

    with pytest.raises(OcrRuntimeLayoutError, match="unexpected"):
        activate_composition(
            runtime_root=runtime_root,
            generation_id=generation_id,
        )


def test_pointer_cannot_escape_the_managed_generation_path(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    (runtime_root / "active-composition.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generation_id": "1" * 32,
                "composition_manifest": "../outside.json",
                "composition_manifest_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(OcrRuntimeLayoutError, match="pointer"):
        resolve_active_composition(runtime_root)


def test_generation_parent_link_is_rejected(
    tmp_path: Path,
) -> None:
    external_root = tmp_path / "external"
    external_root.mkdir()
    generation_id = "1" * 32
    _generation(external_root, generation_id)
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    try:
        os.symlink(
            external_root / "generations",
            runtime_root / "generations",
            target_is_directory=True,
        )
    except OSError:
        pytest.skip("Windows symlink creation requires an unavailable privilege")

    with pytest.raises(OcrRuntimeLayoutError, match="unsafe"):
        activate_composition(
            runtime_root=runtime_root,
            generation_id=generation_id,
        )
