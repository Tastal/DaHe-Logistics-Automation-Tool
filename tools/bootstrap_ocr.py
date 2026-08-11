from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
import venv
from pathlib import Path
from uuid import uuid4

from dahe.adapters.ocr.model_manifest import verify_model_manifest
from dahe.adapters.ocr.profile_registry import load_qualification_bundle
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.runtime_inventory import (
    inventory_sha256,
    parse_exact_lock,
    query_installed_inventory,
    validate_runtime_inventory,
)
from dahe.adapters.ocr.runtime_layout import (
    ActiveOcrComposition,
    OcrRuntimeLayoutError,
    activate_composition,
    resolve_active_composition,
    write_composition_manifest,
)
from dahe.adapters.ocr.runtime_paths import (
    OcrRuntimePathError,
    choose_ocr_runtime_root,
)
from dahe.adapters.ocr.source_fingerprint import (
    installed_worker_source_sha256,
    python_source_tree_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
RUNTIME_LAYOUT = {
    "cpu": "ocr-cpu",
    "gpu": "ocr-gpu",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build isolated DaHe OCR environments from exact locks."
    )
    parser.add_argument("runtime", choices=("cpu", "gpu", "all"))
    parser.add_argument(
        "--runtime-root",
        type=Path,
        help="ASCII install root for the isolated OCR environments and models.",
    )
    parser.add_argument(
        "--provision-models",
        action="store_true",
        help="Explicitly download the approved open-source models after CPU setup.",
    )
    parser.add_argument(
        "--model-source",
        choices=("aistudio", "huggingface", "modelscope", "bos"),
        default="aistudio",
    )
    parser.add_argument(
        "--precision",
        choices=("fp32", "fp16"),
        default="fp32",
        help="GPU precision to qualify and publish; CPU remains fp32.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="GPU recognition batch size to qualify and publish; CPU remains 1.",
    )
    return parser


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_lock(path: Path, runtime_kind: str) -> None:
    packages: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--"):
            if (
                runtime_kind != "gpu"
                or line
                != "--extra-index-url https://www.paddlepaddle.org.cn/packages/stable/cu130/"
            ):
                raise SystemExit(f"unsupported requirement option in {path.name}")
            continue
        if line.count("==") != 1:
            raise SystemExit(f"every OCR requirement must be exactly pinned: {line}")
        package = line.split("==", 1)[0].lower()
        if package in packages:
            raise SystemExit(f"duplicate package in {path.name}: {package}")
        packages.add(package)
    if runtime_kind == "cpu":
        if "paddlepaddle" not in packages or "paddlepaddle-gpu" in packages:
            raise SystemExit("CPU lock must contain only the CPU Paddle distribution")
        if any(package.startswith("nvidia-") for package in packages):
            raise SystemExit("CPU lock cannot contain NVIDIA runtime wheels")
    else:
        if "paddlepaddle-gpu" not in packages or "paddlepaddle" in packages:
            raise SystemExit("GPU lock must contain only the GPU Paddle distribution")


def _run(command: list[str]) -> None:
    print(f"> {' '.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False, shell=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def _runtime_python(runtime_dir: Path) -> Path:
    return runtime_dir / "Scripts" / "python.exe"


def _worker_version() -> str:
    payload = tomllib.loads(
        (ROOT / "ocr-runtime" / "pyproject.toml").read_text(encoding="utf-8")
    )
    return str(payload["project"]["version"])


def _assert_managed_path(path: Path, *, runtime_root: Path) -> Path:
    resolved_root = runtime_root.resolve()
    resolved = path.resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise SystemExit("refusing to modify a path outside the OCR runtime root")
    return resolved


def _safe_remove_tree(path: Path, *, runtime_root: Path) -> None:
    managed = _assert_managed_path(path, runtime_root=runtime_root)
    if managed.exists():
        shutil.rmtree(managed)


def _write_installation_manifest(
    *,
    runtime_kind: str,
    runtime_dir: Path,
    lock_path: Path,
) -> dict[str, object]:
    python = _runtime_python(runtime_dir)
    inventory = query_installed_inventory(python)
    validate_runtime_inventory(
        runtime_kind=RuntimeKind(runtime_kind),
        locked=parse_exact_lock(lock_path),
        installed=inventory,
        worker_version=_worker_version(),
    )
    subprocess.run(
        (
            os.fspath(python),
            "-I",
            "-c",
            "import dahe_ocr_worker,paddle,paddleocr,paddlex;print('ok')",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    approved_worker_source_sha256 = python_source_tree_sha256(
        ROOT / "ocr-runtime" / "src" / "dahe_ocr_worker"
    )
    installed_source_sha256 = installed_worker_source_sha256(
        python=python,
        runtime_dir=runtime_dir,
    )
    if installed_source_sha256 != approved_worker_source_sha256:
        raise SystemExit(
            "installed OCR worker source differs from the approved source"
        )
    manifest: dict[str, object] = {
        "schema_version": 2,
        "runtime_kind": runtime_kind,
        "python_version": subprocess.run(
            (os.fspath(python), "-c", "import platform;print(platform.python_version())"),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
        ).stdout.strip(),
        "dependency_lock": lock_path.relative_to(ROOT).as_posix(),
        "dependency_lock_sha256": _sha256(lock_path),
        "worker_source_sha256": installed_source_sha256,
        "worker_version": _worker_version(),
        "packages": inventory,
        "package_inventory_sha256": inventory_sha256(inventory),
    }
    target = runtime_dir / "runtime-installation.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)
    return manifest


def _build_candidate(
    runtime_kind: str,
    *,
    runtime_root: Path,
    generation_dir: Path,
) -> Path:
    relative_dir = RUNTIME_LAYOUT[runtime_kind]
    runtime_dir = _assert_managed_path(
        generation_dir / relative_dir,
        runtime_root=runtime_root,
    )
    lock_path = ROOT / "ocr-runtime" / f"requirements-{runtime_kind}.lock"
    _validate_lock(lock_path, runtime_kind)
    runtime_dir.parent.mkdir(parents=True, exist_ok=True)
    if runtime_dir.exists():
        raise SystemExit("OCR runtime candidate already exists")
    venv.EnvBuilder(with_pip=True, clear=False, symlinks=False).create(runtime_dir)
    python = _runtime_python(runtime_dir)
    _run(
        [
            os.fspath(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--requirement",
            os.fspath(lock_path),
        ]
    )
    _run(
        [
            os.fspath(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            os.fspath(ROOT / "ocr-runtime"),
        ]
    )
    _run([os.fspath(python), "-m", "pip", "check"])
    _write_installation_manifest(
        runtime_kind=runtime_kind,
        runtime_dir=runtime_dir,
        lock_path=lock_path,
    )
    return runtime_dir


def _qualify_composition(
    runtime_kinds: tuple[str, ...],
    *,
    runtime_root: Path,
    generation_dir: Path,
    models_dir: Path,
    output_dir: Path,
    precision: str,
    batch_size: int,
) -> None:
    command = [
        os.fspath(EXPECTED_MAIN_PYTHON),
        os.fspath(ROOT / "tools" / "ocr_runtime_check.py"),
        "all" if "gpu" in runtime_kinds else "cpu",
        "--runtime-root",
        os.fspath(runtime_root),
        "--models-dir",
        os.fspath(models_dir),
        "--precision",
        precision,
        "--batch-size",
        str(batch_size),
        "--output",
        os.fspath(output_dir),
    ]
    if "gpu" in runtime_kinds:
        command.extend(
            (
                "--cpu-runtime-dir",
                os.fspath(generation_dir / "ocr-cpu"),
                "--gpu-runtime-dir",
                os.fspath(generation_dir / "ocr-gpu"),
            )
        )
    else:
        command.extend(
            (
                "--runtime-dir",
                os.fspath(generation_dir / "ocr-cpu"),
            )
        )
    _run(command)


def _provision_models(
    *,
    python: Path,
    runtime_root: Path,
    candidate_cache_root: Path,
    model_source: str,
) -> None:
    _run(
        [
            os.fspath(python),
            os.fspath(ROOT / "tools" / "provision_ocr_models.py"),
            "--runtime-root",
            os.fspath(runtime_root),
            "--candidate-cache-root",
            os.fspath(candidate_cache_root),
            "--model-source",
            model_source,
        ]
    )


def _active_composition_or_none(
    runtime_root: Path,
) -> ActiveOcrComposition | None:
    if not (
        (runtime_root / "active-composition.json").exists()
        or (runtime_root / "ocr-cpu").exists()
    ):
        return None
    try:
        return resolve_active_composition(runtime_root, allow_legacy=True)
    except OcrRuntimeLayoutError as exc:
        raise SystemExit(str(exc)) from exc


def _runtime_kinds_for_request(
    requested: str,
    *,
    active: ActiveOcrComposition | None,
) -> tuple[str, ...]:
    if requested == "gpu":
        raise SystemExit(
            "GPU-only activation is unsafe; use runtime=all to rebuild "
            "and qualify CPU and GPU together."
        )
    if (
        requested == "cpu"
        and active is not None
        and active.gpu_runtime is not None
    ):
        raise SystemExit(
            "The active composition includes GPU OCR; use runtime=all "
            "so CPU and GPU remain bound to one verified composition."
        )
    return ("cpu", "gpu") if requested == "all" else ("cpu",)


def _stage_models(
    *,
    runtime_root: Path,
    generation_dir: Path,
    cpu_python: Path,
    active: ActiveOcrComposition | None,
    provision: bool,
    model_source: str,
) -> Path:
    target = generation_dir / "model-cache" / "official_models"
    if provision:
        staging_cache = _assert_managed_path(
            runtime_root / f".model-staging-{generation_dir.name}",
            runtime_root=runtime_root,
        )
        try:
            _provision_models(
                python=cpu_python,
                runtime_root=runtime_root,
                candidate_cache_root=staging_cache,
                model_source=model_source,
            )
            candidate = staging_cache / "official_models"
            verify_model_manifest(
                models_dir=candidate,
                manifest_path=candidate / "model-manifest.json",
            )
            target.parent.mkdir(parents=True)
            os.replace(candidate, target)
        finally:
            if staging_cache.exists():
                _safe_remove_tree(staging_cache, runtime_root=runtime_root)
    else:
        if active is None:
            raise SystemExit(
                "Local OCR models are missing. Run CPU bootstrap with "
                "--provision-models first."
            )
        verify_model_manifest(
            models_dir=active.models_dir,
            manifest_path=active.models_dir / "model-manifest.json",
        )
        target.parent.mkdir(parents=True)
        shutil.copytree(active.models_dir, target)
    verify_model_manifest(
        models_dir=target,
        manifest_path=target / "model-manifest.json",
    )
    return target


def _publish_qualification(
    *,
    runtime_kinds: tuple[str, ...],
    output_dir: Path,
    generation_dir: Path,
) -> Path:
    source = output_dir / "qualification.json"
    bundle = load_qualification_bundle(source)
    qualified_kinds = {report.runtime_kind.value for report in bundle.reports}
    if qualified_kinds != set(runtime_kinds):
        raise SystemExit(
            "qualification does not bind every runtime in the composition"
        )
    target = generation_dir / "qualification" / "qualification.json"
    target.parent.mkdir(parents=True)
    shutil.copy2(source, target)
    return target


def main() -> None:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit(f"Use the project interpreter: {EXPECTED_MAIN_PYTHON}")
    args = _parser().parse_args()
    try:
        runtime_root = choose_ocr_runtime_root(
            repository_root=ROOT,
            explicit_root=args.runtime_root.resolve()
            if args.runtime_root is not None
            else None,
        )
    except OcrRuntimePathError as exc:
        raise SystemExit(str(exc)) from exc
    if args.batch_size < 1 or args.batch_size > 64:
        raise SystemExit("batch size must be between 1 and 64")
    runtime_root.mkdir(parents=True, exist_ok=True)
    active = _active_composition_or_none(runtime_root)
    kinds = _runtime_kinds_for_request(args.runtime, active=active)
    generation_id = uuid4().hex
    generation_dir = _assert_managed_path(
        runtime_root / "generations" / generation_id,
        runtime_root=runtime_root,
    )
    qualification_staging = _assert_managed_path(
        runtime_root / f".qualification-staging-{generation_id}",
        runtime_root=runtime_root,
    )
    activated = False
    try:
        generation_dir.mkdir(parents=True)
        candidates = {
            runtime_kind: _build_candidate(
                runtime_kind,
                runtime_root=runtime_root,
                generation_dir=generation_dir,
            )
            for runtime_kind in kinds
        }
        models_dir = _stage_models(
            runtime_root=runtime_root,
            generation_dir=generation_dir,
            cpu_python=_runtime_python(candidates["cpu"]),
            active=active,
            provision=args.provision_models,
            model_source=args.model_source,
        )
        _qualify_composition(
            kinds,
            runtime_root=runtime_root,
            generation_dir=generation_dir,
            models_dir=models_dir,
            output_dir=qualification_staging,
            precision=args.precision,
            batch_size=args.batch_size,
        )
        _publish_qualification(
            runtime_kinds=kinds,
            output_dir=qualification_staging,
            generation_dir=generation_dir,
        )
        write_composition_manifest(
            generation_dir=generation_dir,
            generation_id=generation_id,
            gpu_present="gpu" in kinds,
        )
        activate_composition(
            runtime_root=runtime_root,
            generation_id=generation_id,
        )
        activated = True
    finally:
        if qualification_staging.exists():
            _safe_remove_tree(
                qualification_staging,
                runtime_root=runtime_root,
            )
        if not activated and generation_dir.exists():
            _safe_remove_tree(generation_dir, runtime_root=runtime_root)


if __name__ == "__main__":
    main()
