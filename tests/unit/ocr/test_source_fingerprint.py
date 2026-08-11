from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.source_fingerprint import (
    SourceFingerprintError,
    installed_worker_source_sha256,
    python_source_tree_sha256,
)
from tools import ocr_runtime_check


def test_worker_source_hash_ignores_interpreter_cache_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker"
    source.mkdir()
    (source / "engine.py").write_text("BUILD = 1\n", encoding="utf-8")
    baseline = python_source_tree_sha256(source)

    cache = source / "__pycache__"
    cache.mkdir()
    (cache / "engine.cpython-312.pyc").write_bytes(b"volatile-cache")
    assert python_source_tree_sha256(source) == baseline

    (source / "engine.py").write_text("BUILD = 2\n", encoding="utf-8")
    assert python_source_tree_sha256(source) != baseline


def test_installed_worker_hash_uses_package_inside_the_selected_runtime(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "ocr-cpu"
    python = runtime / "Scripts" / "python.exe"
    package = runtime / "Lib" / "site-packages" / "dahe_ocr_worker"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"fake")
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "engine.py").write_text("BUILD = 1\n", encoding="utf-8")

    def runner(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        assert command[1:3] == ("-I", "-B")
        del kwargs
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps([str(package)]),
            stderr="",
        )

    assert installed_worker_source_sha256(
        python=python,
        runtime_dir=runtime,
        runner=runner,
    ) == python_source_tree_sha256(package)


def test_installed_worker_package_must_remain_inside_its_runtime(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "ocr-cpu"
    python = runtime / "Scripts" / "python.exe"
    outside = tmp_path / "developer-source" / "dahe_ocr_worker"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"fake")
    outside.mkdir(parents=True)
    (outside / "__init__.py").write_text("", encoding="utf-8")

    def runner(
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del command, kwargs
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps([str(outside)]),
            stderr="",
        )

    with pytest.raises(SourceFingerprintError, match="outside"):
        installed_worker_source_sha256(
            python=python,
            runtime_dir=runtime,
            runner=runner,
        )


def test_qualification_rejects_installed_worker_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "ocr-cpu"
    python = runtime / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"fake")
    (runtime / "runtime-installation.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "runtime_kind": "cpu",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ocr_runtime_check,
        "query_installed_inventory",
        lambda _python: {},
    )
    monkeypatch.setattr(
        ocr_runtime_check,
        "validate_runtime_inventory",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        ocr_runtime_check,
        "python_source_tree_sha256",
        lambda _path: "a" * 64,
    )
    monkeypatch.setattr(
        ocr_runtime_check,
        "installed_worker_source_sha256",
        lambda **_kwargs: "b" * 64,
    )

    with pytest.raises(SystemExit, match="installed OCR worker source"):
        ocr_runtime_check._load_and_verify_installation(
            RuntimeKind.CPU,
            runtime_dir=runtime,
        )
