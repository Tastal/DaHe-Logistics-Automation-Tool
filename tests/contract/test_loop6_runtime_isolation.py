from __future__ import annotations

import tomllib
from pathlib import Path


def _requirements(path: Path) -> set[str]:
    packages: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith(("#", "--")):
            continue
        packages.add(line.split("==", 1)[0])
    return packages


def test_main_application_lock_remains_free_of_ocr_binary_packages(
    project_root: Path,
) -> None:
    pyproject = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    main_dependencies = "\n".join(pyproject["project"]["dependencies"]).lower()
    main_lock = (project_root / "requirements.lock").read_text(encoding="utf-8").lower()

    for package in (
        "paddlepaddle",
        "paddlepaddle-gpu",
        "paddleocr",
        "paddlex",
        "opencv",
    ):
        assert package not in main_dependencies
        assert package not in main_lock


def test_cpu_and_gpu_locks_are_separate_and_mutually_exclusive(
    project_root: Path,
) -> None:
    cpu = _requirements(project_root / "ocr-runtime" / "requirements-cpu.lock")
    gpu = _requirements(project_root / "ocr-runtime" / "requirements-gpu.lock")

    assert "paddlepaddle" in cpu
    assert "paddlepaddle-gpu" not in cpu
    assert not any(package.startswith("nvidia-") for package in cpu)
    assert "paddlepaddle-gpu" in gpu
    assert "paddlepaddle" not in gpu
    assert ("paddleocr" in cpu) == ("paddleocr" in gpu)
    assert ("paddlex" in cpu) == ("paddlex" in gpu)


def test_runtime_layout_is_portable_and_not_committed(project_root: Path) -> None:
    gitignore = (project_root / ".gitignore").read_text(encoding="utf-8")
    bootstrap = (
        project_root / "tools" / "bootstrap_ocr.py"
    ).read_text(encoding="utf-8").lower()
    worker_project = tomllib.loads(
        (project_root / "ocr-runtime" / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert ".runtime/" in gitignore
    assert worker_project["project"]["name"] == "dahe-ocr-worker"
    assert "c:\\users\\" not in bootstrap
    assert "gpu:0" not in bootstrap
    assert "ocr-cpu" in bootstrap
    assert "ocr-gpu" in bootstrap
    assert "--runtime-root" in bootstrap
    assert "choose_ocr_runtime_root" in bootstrap


def test_normal_worker_startup_has_no_model_download_fallback(
    project_root: Path,
) -> None:
    worker_source = "\n".join(
        path.read_text(encoding="utf-8").lower()
        for path in (project_root / "ocr-runtime" / "src" / "dahe_ocr_worker").rglob("*.py")
    )
    assert "text_detection_model_dir" in worker_source
    assert "text_recognition_model_dir" in worker_source
    assert "paddle_pdx_disable_model_source_check" in worker_source
    assert "download_model" not in worker_source
