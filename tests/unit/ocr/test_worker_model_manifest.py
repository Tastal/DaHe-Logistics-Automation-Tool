from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

from dahe.adapters.ocr import model_manifest as main_model_manifest
from dahe.adapters.ocr.model_manifest import (
    ModelManifestVerificationError,
    verify_model_manifest,
)

MODEL_PURPOSES = {
    "PP-OCRv6_medium_det": "text_detection",
    "PP-OCRv6_medium_rec": "text_recognition",
}


@contextmanager
def _worker_manifest_module(project_root: Path) -> Iterator[ModuleType]:
    worker_src = str(project_root / "ocr-runtime" / "src")
    sys.path.insert(0, worker_src)
    try:
        yield importlib.import_module("dahe_ocr_worker.model_manifest")
    finally:
        sys.path.remove(worker_src)
        for module_name in tuple(sys.modules):
            if module_name == "dahe_ocr_worker" or module_name.startswith(
                "dahe_ocr_worker."
            ):
                sys.modules.pop(module_name, None)


def _model_set(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "models"
    entries: list[dict[str, object]] = []
    for index, model_name in enumerate(MODEL_PURPOSES, start=1):
        model_dir = root / model_name
        model_dir.mkdir(parents=True)
        model_file = model_dir / "inference.pdmodel"
        payload = f"model-{index}".encode()
        model_file.write_bytes(payload)
        entries.append(
            {
                "relative_path": model_file.relative_to(root).as_posix(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    manifest = {
        "schema_version": 1,
        "model_set_id": "test-model-set",
        "models": [
            {"name": name, "purpose": purpose}
            for name, purpose in MODEL_PURPOSES.items()
        ],
        "files": entries,
    }
    manifest_path = root / "model-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False),
        encoding="utf-8",
    )
    return root, manifest_path


def _verify(project_root: Path, root: Path, manifest_path: Path) -> dict[str, object]:
    with _worker_manifest_module(project_root) as module:
        return module.load_and_verify_model_manifest(
            models_dir=root,
            manifest_path=manifest_path,
        )


def test_model_manifest_accepts_only_the_exact_declared_file_set(
    project_root: Path,
    tmp_path: Path,
) -> None:
    root, manifest_path = _model_set(tmp_path)

    verified = _verify(project_root, root, manifest_path)
    main_verified = verify_model_manifest(
        models_dir=root,
        manifest_path=manifest_path,
    )

    assert verified["model_set_id"] == "test-model-set"
    assert main_verified.model_set_id == verified["model_set_id"]
    assert main_verified.manifest_sha256 == verified["manifest_sha256"]
    assert main_verified.file_count == len(verified["files"])


@pytest.mark.parametrize("mutation", ["extra", "missing", "changed"])
def test_model_manifest_rejects_extra_missing_or_changed_files(
    project_root: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    root, manifest_path = _model_set(tmp_path)
    target = root / "PP-OCRv6_medium_det" / "inference.pdmodel"
    if mutation == "extra":
        (root / "PP-OCRv6_medium_det" / "undeclared.bin").write_bytes(b"extra")
    elif mutation == "missing":
        target.unlink()
    else:
        target.write_bytes(b"changed")

    with (
        _worker_manifest_module(project_root) as module,
        pytest.raises(module.ModelManifestError),
    ):
        module.load_and_verify_model_manifest(
            models_dir=root,
            manifest_path=manifest_path,
        )
    with pytest.raises(ModelManifestVerificationError):
        verify_model_manifest(models_dir=root, manifest_path=manifest_path)


def test_model_manifest_rejects_hard_linked_model_files(
    project_root: Path,
    tmp_path: Path,
) -> None:
    root, manifest_path = _model_set(tmp_path)
    source = root / "PP-OCRv6_medium_det" / "inference.pdmodel"
    link = root / "PP-OCRv6_medium_rec" / "linked.bin"
    os.link(source, link)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append(
        {
            "relative_path": link.relative_to(root).as_posix(),
            "size_bytes": link.stat().st_size,
            "sha256": hashlib.sha256(link.read_bytes()).hexdigest(),
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with (
        _worker_manifest_module(project_root) as module,
        pytest.raises(module.ModelManifestError, match="link"),
    ):
        module.load_and_verify_model_manifest(
            models_dir=root,
            manifest_path=manifest_path,
        )
    with pytest.raises(ModelManifestVerificationError, match="link"):
        verify_model_manifest(models_dir=root, manifest_path=manifest_path)


def test_model_manifest_rejects_reparse_or_symbolic_paths_without_following_them(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, manifest_path = _model_set(tmp_path)
    unsafe = root / "PP-OCRv6_medium_det" / "inference.pdmodel"

    with _worker_manifest_module(project_root) as module:
        original = module._is_reparse_point
        monkeypatch.setattr(
            module,
            "_is_reparse_point",
            lambda path: path == unsafe or original(path),
        )
        with pytest.raises(module.ModelManifestError, match=r"link|reparse"):
            module.load_and_verify_model_manifest(
                models_dir=root,
                manifest_path=manifest_path,
            )
    original_main = main_model_manifest._is_reparse_point
    monkeypatch.setattr(
        main_model_manifest,
        "_is_reparse_point",
        lambda path: path == unsafe or original_main(path),
    )
    with pytest.raises(ModelManifestVerificationError, match=r"link|reparse"):
        verify_model_manifest(models_dir=root, manifest_path=manifest_path)
