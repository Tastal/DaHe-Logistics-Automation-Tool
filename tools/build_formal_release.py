from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path

from dahe import __version__
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.runtime_inventory import (
    inventory_sha256,
    parse_exact_lock,
    query_installed_inventory,
    validate_runtime_inventory,
)
from dahe.adapters.ocr.runtime_layout import (
    ActiveOcrComposition,
    activate_flat_composition,
    resolve_active_composition,
    write_flat_composition_manifest,
)
from dahe.adapters.ocr.source_fingerprint import (
    installed_worker_source_sha256,
    python_source_tree_sha256,
)
from dahe.application.template_studio.fingerprints import (
    TEMPLATE_PIPELINE_SOURCE_MANIFEST,
)
from dahe.release.launcher import (
    VersionPointer,
    _copy_declared_operational_contracts,
    compute_resource_sha256,
    write_version_pointer_atomic,
)
from dahe.verification.loop9_build import current_loop9_build_sha256

try:
    from tools.build_windows_installer import installer_command
    from tools.portable_python_runtime import (
        stage_portable_python_runtime,
        validate_portable_python_runtime,
        validate_release_tree_no_developer_provenance,
    )
    from tools.windows_release import (
        load_windows_release_manifest,
        makensis_path,
        python_embed_archive_path,
        require_project_venv,
    )
except ModuleNotFoundError:
    from build_windows_installer import installer_command  # type: ignore[import-not-found,no-redef]
    from portable_python_runtime import (  # type: ignore[import-not-found,no-redef]
        stage_portable_python_runtime,
        validate_portable_python_runtime,
        validate_release_tree_no_developer_provenance,
    )
    from windows_release import (  # type: ignore[import-not-found,no-redef]
        load_windows_release_manifest,
        makensis_path,
        python_embed_archive_path,
        require_project_venv,
    )

ROOT = Path(__file__).resolve().parents[1]
REVISION = "0041_contract_subject_scope"
MINIMUM_SCHEMA_REVISION = "0039_network_batch_default"
REPOSITORY = "Tastal/DaHe-Logistics-Automation-Tool"
GITHUB_RELEASE_ASSET_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
LEGACY_WINDOWS_FILE_PATH_LIMIT = 259
LEGACY_WINDOWS_DIRECTORY_PATH_LIMIT = 247
MAX_WINDOWS_USER_NAME_LENGTH = 20
CPU_RUNTIME_STAGING_NAME = ".c-00000000"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_github_release_asset_size(path: Path) -> None:
    size = path.stat().st_size
    if size >= GITHUB_RELEASE_ASSET_LIMIT_BYTES:
        raise RuntimeError(
            f"GitHub release asset must be smaller than 2 GiB: {path.name} ({size} bytes)"
        )


def _copy_operational_seed(seed_root: Path, target_root: Path) -> None:
    target_root.mkdir(parents=True, exist_ok=True)
    for name in (
        "operational-template-bundle.json",
        "operational-contract-install.json",
    ):
        source = seed_root / name
        if not source.is_file() or source.is_symlink():
            raise RuntimeError("formal operational seed is incomplete")
        shutil.copy2(source, target_root / name)
    try:
        copied = _copy_declared_operational_contracts(
            source=seed_root,
            target=target_root,
        )
    except RuntimeError as exc:
        raise RuntimeError("formal operational seed contracts are invalid") from exc
    marker = json.loads(
        (seed_root / "operational-contract-install.json").read_text(
            encoding="utf-8"
        )
    )
    if copied != len(marker["copied_files"]):
        raise RuntimeError("formal operational seed contracts are incomplete")


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    return completed.stdout.strip()


def _source_application_version(source_root: Path) -> str:
    source = source_root / "src" / "dahe" / "__init__.py"
    marker = "__version__ = "
    matches = [
        line.removeprefix(marker).strip().strip('"')
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.startswith(marker)
    ]
    if len(matches) != 1 or not matches[0]:
        raise RuntimeError("formal release source version is invalid")
    return matches[0]


def _require_release_tag(source_root: Path, version: str) -> None:
    expected = f"v{version}"
    actual = _git(
        source_root,
        "describe",
        "--tags",
        "--exact-match",
        "--match",
        expected,
        "HEAD",
    )
    if actual != expected:
        raise RuntimeError("formal release tag does not match the source version")


def _copy_updater_binaries(
    updater: Path,
    *,
    payload: Path,
    version_root: Path,
) -> None:
    shutil.copy2(updater, payload / "DaHeUpdater.exe")
    shutil.copy2(updater, version_root / "DaHeUpdater.exe")


def _run_pyinstaller(
    *,
    source_root: Path,
    entrypoint: Path,
    name: str,
    dist_root: Path,
    work_root: Path,
    one_file: bool,
    windowed: bool = False,
) -> Path:
    command = [
        os.fspath(Path(sys.executable)),
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--noupx",
        "--windowed" if windowed else "--console",
        "--paths",
        os.fspath(source_root / "src"),
        "--name",
        name,
        "--distpath",
        os.fspath(dist_root),
        "--workpath",
        os.fspath(work_root / name),
        "--specpath",
        os.fspath(work_root / "spec"),
        "--onefile" if one_file else "--onedir",
        os.fspath(entrypoint),
    ]
    subprocess.run(command, cwd=source_root, check=True, shell=False)
    result = dist_root / (f"{name}.exe" if one_file else name)
    if not result.exists():
        raise RuntimeError(f"PyInstaller did not produce {name}")
    return result


def _browser_worker_source_sha256(source_root: Path) -> str:
    worker_root = (
        source_root / "browser-runtime" / "src" / "dahe_browser_worker"
    )
    digest = hashlib.sha256()
    for path in sorted(worker_root.rglob("*.py")):
        digest.update(
            path.relative_to(worker_root).as_posix().encode("utf-8")
        )
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _copy_browser_runtime(
    source: Path,
    target: Path,
    *,
    source_root: Path,
    embed_archive: Path,
    embed_archive_sha256: str | None = None,
    run_smoke: bool = True,
) -> None:
    manifest_path = source / "runtime-installation.json"
    lock = source_root / "browser-runtime" / "requirements.lock"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "browser runtime does not match formal release source"
        ) from exc
    packages = manifest.get("packages")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("runtime_kind") != "browser"
        or manifest.get("dependency_lock")
        != "browser-runtime/requirements.lock"
        or manifest.get("dependency_lock_sha256")
        != _sha256(lock)
        or manifest.get("worker_source_sha256")
        != _browser_worker_source_sha256(source_root)
        or manifest.get("chromium_provisioned") is not False
        or manifest.get("smoke_selected_browser")
        not in {"chromium", "msedge"}
        or not isinstance(packages, list)
        or "playwright==1.61.0"
        not in {str(item).casefold() for item in packages}
    ):
        raise RuntimeError(
            "browser runtime does not match formal release source"
        )
    target.mkdir(parents=True)
    portable = stage_portable_python_runtime(
        source_runtime=source / "python",
        target_runtime=target / "python",
        embed_archive=embed_archive,
        embed_archive_sha256=embed_archive_sha256,
        python_version="3.12.10",
        worker_source=(
            source_root
            / "browser-runtime"
            / "src"
            / "dahe_browser_worker"
        ),
        worker_package="dahe_browser_worker",
        developer_roots=(source_root, Path.home()),
        run_smoke=run_smoke,
    )
    sanitized_packages = [
        (
            "dahe-browser-worker==0.1.0"
            if str(package).casefold().startswith("dahe-browser-worker @ file:")
            else str(package)
        )
        for package in packages
    ]
    if not any(
        package.casefold().startswith("dahe-browser-worker==")
        for package in sanitized_packages
    ):
        sanitized_packages.append("dahe-browser-worker==0.1.0")
    staged_manifest = {
        **manifest,
        "packages": sorted(sanitized_packages, key=str.casefold),
        "browser_store_packaged": False,
        "portable_python": portable,
    }
    (target / "runtime-installation.json").write_text(
        json.dumps(staged_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    validate_portable_python_runtime(
        target / "python",
        developer_roots=(source_root, Path.home()),
        run_smoke=run_smoke,
        required_import="dahe_browser_worker",
    )


def _cpu_only_qualification(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 2:
        raise RuntimeError("OCR qualification must contain one qualified CPU report")
    reports = payload.get("reports")
    if not isinstance(reports, list) or any(
        not isinstance(report, dict) for report in reports
    ):
        raise RuntimeError("OCR qualification must contain one qualified CPU report")
    cpu_reports = [
        report
        for report in reports
        if report.get("runtime_kind") == "cpu"
        and report.get("status") == "qualified"
    ]
    if len(cpu_reports) != 1:
        raise RuntimeError("OCR qualification must contain one qualified CPU report")
    return {
        "schema_version": 2,
        "reports": [dict(cpu_reports[0])],
        "difference_report": {
            "sample_count": 0,
            "critical_match_count": 0,
            "all_critical_fields_match": True,
            "items": [],
        },
    }


def _ocr_worker_version(source_root: Path) -> str:
    payload = tomllib.loads(
        (source_root / "ocr-runtime" / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    version = payload.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError("OCR worker package metadata is invalid")
    return version


def _stage_ocr_runtime(
    source: Path,
    target: Path,
    *,
    kind: RuntimeKind,
    source_root: Path,
    embed_archive: Path,
    embed_archive_sha256: str | None,
    run_smoke: bool,
) -> None:
    manifest_path = source / "runtime-installation.json"
    lock_path = source_root / "ocr-runtime" / f"requirements-{kind.value}.lock"
    approved_source = (
        source_root / "ocr-runtime" / "src" / "dahe_ocr_worker"
    )
    approved_source_sha256 = python_source_tree_sha256(approved_source)
    worker_version = _ocr_worker_version(source_root)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("OCR runtime does not match formal release source") from exc
    if (
        manifest.get("schema_version") != 2
        or manifest.get("runtime_kind") != kind.value
        or manifest.get("dependency_lock")
        != f"ocr-runtime/requirements-{kind.value}.lock"
        or manifest.get("dependency_lock_sha256") != _sha256(lock_path)
        or manifest.get("worker_source_sha256") != approved_source_sha256
        or manifest.get("worker_version") != worker_version
        or manifest.get("python_version") != "3.12.10"
    ):
        raise RuntimeError("OCR runtime does not match formal release source")
    portable = stage_portable_python_runtime(
        source_runtime=source,
        target_runtime=target,
        embed_archive=embed_archive,
        embed_archive_sha256=embed_archive_sha256,
        python_version="3.12.10",
        worker_source=approved_source,
        worker_package="dahe_ocr_worker",
        developer_roots=(source_root, Path.home()),
        run_smoke=run_smoke,
    )
    staged_manifest = {**manifest, "portable_python": portable}
    (target / "runtime-installation.json").write_text(
        json.dumps(staged_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    validate_portable_python_runtime(
        target,
        developer_roots=(source_root, Path.home()),
        run_smoke=run_smoke,
        required_import="dahe_ocr_worker",
    )
    if not run_smoke:
        return
    python = target / "python.exe"
    installed = query_installed_inventory(python)
    validate_runtime_inventory(
        runtime_kind=kind,
        locked=parse_exact_lock(lock_path),
        installed=installed,
        worker_version=worker_version,
    )
    if manifest.get("package_inventory_sha256") != inventory_sha256(installed):
        raise RuntimeError("portable OCR package inventory changed")
    if installed_worker_source_sha256(
        python=python,
        runtime_dir=target,
    ) != approved_source_sha256:
        raise RuntimeError("portable OCR worker source changed")


def _copy_cpu_runtime(
    source: Path,
    target: Path,
    *,
    source_root: Path,
    embed_archive: Path,
    embed_archive_sha256: str | None = None,
    run_smoke: bool = True,
) -> None:
    composition = resolve_active_composition(source, allow_legacy=False)
    if composition.generation_dir is None or composition.generation_id is None:
        raise RuntimeError("active OCR generation is unavailable")
    target.mkdir(parents=True)
    _stage_ocr_runtime(
        composition.cpu_runtime,
        target / "c",
        kind=RuntimeKind.CPU,
        source_root=source_root,
        embed_archive=embed_archive,
        embed_archive_sha256=embed_archive_sha256,
        run_smoke=run_smoke,
    )
    shutil.copytree(
        composition.models_dir.parent,
        target / "m",
    )
    shutil.copytree(
        composition.qualification_path.parent,
        target / "q",
    )
    qualification_path = target / "q" / "qualification.json"
    qualification = _cpu_only_qualification(
        json.loads(qualification_path.read_text(encoding="utf-8"))
    )
    qualification_path.write_text(
        json.dumps(qualification, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_flat_composition_manifest(
        runtime_root=target,
        generation_id=composition.generation_id,
    )
    activate_flat_composition(
        runtime_root=target,
        generation_id=composition.generation_id,
    )
    verified = resolve_active_composition(target, allow_legacy=False)
    if verified.gpu_runtime is not None:
        raise RuntimeError("CPU release unexpectedly contains a GPU runtime")


def _write_gpu_addon(
    source: Path,
    target: Path,
    *,
    generation_id: str,
    cpu_composition: ActiveOcrComposition,
    packaged_cpu_composition: ActiveOcrComposition,
    source_root: Path,
    embed_archive: Path,
    embed_archive_sha256: str | None = None,
    run_smoke: bool = True,
) -> None:
    if len(generation_id) != 32 or any(
        character not in "0123456789abcdef" for character in generation_id
    ):
        raise RuntimeError("qualified GPU generation is invalid")
    runtime_target = target / "g"
    _stage_ocr_runtime(
        source,
        runtime_target,
        kind=RuntimeKind.GPU,
        source_root=source_root,
        embed_archive=embed_archive,
        embed_archive_sha256=embed_archive_sha256,
        run_smoke=run_smoke,
    )
    try:
        qualification = json.loads(
            cpu_composition.qualification_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("qualified GPU profile is unavailable") from exc
    reports = qualification.get("reports") if isinstance(qualification, dict) else None
    gpu_reports = [
        report
        for report in reports or []
        if isinstance(report, dict)
        and report.get("runtime_kind") == "gpu"
        and report.get("status") == "qualified"
    ]
    if len(gpu_reports) != 1:
        raise RuntimeError("qualified GPU profile is unavailable")
    gpu_report = gpu_reports[0]
    precision = gpu_report.get("precision")
    batch_size = gpu_report.get("batch_size")
    memory_safety_ratio = gpu_report.get("memory_safety_ratio")
    if (
        precision not in {"fp32", "fp16"}
        or type(batch_size) is not int
        or not 1 <= int(batch_size) <= 64
        or str(memory_safety_ratio) not in {"0.80", "0.85", "0.90", "0.95"}
    ):
        raise RuntimeError("qualified GPU profile is invalid")
    if packaged_cpu_composition.generation_id != generation_id:
        raise RuntimeError("packaged CPU generation does not match GPU add-on")
    cpu_manifest = (
        packaged_cpu_composition.cpu_runtime / "runtime-installation.json"
    )
    model_manifest = (
        packaged_cpu_composition.models_dir / "model-manifest.json"
    )
    staged_runtime_manifest = runtime_target / "runtime-installation.json"
    worker_source_sha256 = python_source_tree_sha256(
        source_root / "ocr-runtime" / "src" / "dahe_ocr_worker"
    )
    manifest = {
        "schema_version": 2,
        "layout": "gpu_overlay_v1",
        "application_version": __version__,
        "generation_id": generation_id,
        "gpu_runtime": "g",
        "runtime_installation_sha256": _sha256(
            staged_runtime_manifest
        ),
        "cpu_runtime_installation_sha256": _sha256(cpu_manifest),
        "model_manifest_sha256": _sha256(model_manifest),
        "worker_source_sha256": worker_source_sha256,
        "precision": precision,
        "batch_size": batch_size,
        "memory_safety_ratio": str(memory_safety_ratio),
    }
    (target / "gpu-addon-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _validate_gpu_runtime_legacy_path_budget(
        files=sorted(path for path in target.rglob("*") if path.is_file()),
        package_root=target,
    )


def _validate_gpu_runtime_legacy_path_budget(
    *,
    files: list[Path],
    package_root: Path,
) -> None:
    user_name = "U" * MAX_WINDOWS_USER_NAME_LENGTH
    runtimes_root = Path(
        f"C:/Users/{user_name}/AppData/Local/Programs/"
        "DaHeLogisticsAutomationTool/runtimes"
    )
    targets = (
        runtimes_root,
        runtimes_root / ".g-00000000",
    )
    for source in files:
        relative = source.relative_to(package_root)
        for target in targets:
            projected = target / relative
            if len(os.fspath(projected)) > LEGACY_WINDOWS_FILE_PATH_LIMIT:
                raise RuntimeError(
                    "GPU runtime file exceeds the legacy Windows path budget"
                )
            for parent in projected.parents:
                if parent == target.parent:
                    break
                if len(os.fspath(parent)) > LEGACY_WINDOWS_DIRECTORY_PATH_LIMIT:
                    raise RuntimeError(
                        "GPU runtime directory exceeds the legacy Windows path budget"
                    )


def _zip_tree(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                if path.is_symlink():
                    raise RuntimeError("release payload contains a symbolic link")
                bundle.write(path, path.relative_to(source).as_posix())


def _copy_source_tree(source: Path, target: Path) -> None:
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def _package_cpu_runtime_archive(
    runtime_root: Path,
    archive: Path,
    manifest_path: Path,
) -> None:
    files = sorted(path for path in runtime_root.rglob("*") if path.is_file())
    if not files:
        raise RuntimeError("CPU runtime package is empty")
    _zip_tree(runtime_root, archive)
    pointer = runtime_root / "active-composition.json"
    maximum_relative_file_path = max(
        len(path.relative_to(runtime_root).as_posix()) for path in files
    )
    directories = {
        parent
        for path in files
        for parent in path.relative_to(runtime_root).parents
        if parent != Path(".")
    }
    maximum_relative_directory_path = max(
        (len(path.as_posix()) for path in directories),
        default=0,
    )
    _validate_cpu_runtime_legacy_path_budget(
        files=files,
        runtime_root=runtime_root,
    )
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "layout": "flat_v2",
                "archive_file_name": archive.name,
                "archive_sha256": _sha256(archive),
                "archive_size": archive.stat().st_size,
                "entry_count": len(files),
                "uncompressed_size": sum(path.stat().st_size for path in files),
                "active_composition_sha256": _sha256(pointer),
                "maximum_relative_file_path": maximum_relative_file_path,
                "maximum_relative_directory_path": (
                    maximum_relative_directory_path
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _validate_cpu_runtime_legacy_path_budget(
    *,
    files: list[Path],
    runtime_root: Path,
) -> None:
    user_name = "U" * MAX_WINDOWS_USER_NAME_LENGTH
    install_root = Path(
        f"C:/Users/{user_name}/AppData/Local/Programs/"
        "DaHeLogisticsAutomationTool/runtimes"
    )
    targets = (
        install_root / "ocr-cpu",
        install_root / CPU_RUNTIME_STAGING_NAME,
    )
    for source in files:
        relative = source.relative_to(runtime_root)
        for target in targets:
            projected = target / relative
            if len(os.fspath(projected)) > LEGACY_WINDOWS_FILE_PATH_LIMIT:
                raise RuntimeError(
                    "CPU runtime file exceeds the legacy Windows path budget"
                )
            for parent in projected.parents:
                if parent == target.parent:
                    break
                if len(os.fspath(parent)) > LEGACY_WINDOWS_DIRECTORY_PATH_LIMIT:
                    raise RuntimeError(
                        "CPU runtime directory exceeds the legacy Windows path budget"
                    )


def _stage_installer_payload(payload: Path, staging_root: Path) -> Path:
    target = staging_root / "p"
    if target.exists():
        raise RuntimeError("short installer staging path already exists")
    shutil.move(os.fspath(payload), os.fspath(target))
    return target


def _copy_formal_pipeline_sources(source_root: Path, version_root: Path) -> None:
    for logical_path in TEMPLATE_PIPELINE_SOURCE_MANIFEST:
        project_relative = (
            logical_path == "alembic.ini"
            or logical_path.startswith("tools/")
            or logical_path.startswith("ocr-runtime/")
        )
        source = (
            source_root / logical_path
            if project_relative
            else source_root / "src" / "dahe" / logical_path
        )
        target = (
            version_root / logical_path
            if project_relative
            else version_root / "src" / "dahe" / logical_path
        )
        if target.is_file():
            if _sha256(source) != _sha256(target):
                raise RuntimeError(
                    f"formal pipeline source differs in release payload: {logical_path}"
                )
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the five formal v1 release assets")
    parser.add_argument(
        "--source-root",
        type=Path,
        default=ROOT,
        help="Clean Git checkout whose commit is embedded in the release",
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--browser-runtime-root", type=Path, required=True)
    parser.add_argument("--ocr-runtime-root", type=Path, required=True)
    parser.add_argument("--gpu-runtime-root", type=Path, required=True)
    parser.add_argument("--seed-root", type=Path, required=True)
    return parser


def main() -> int:
    require_project_venv()
    arguments = _parser().parse_args()
    source_root = arguments.source_root.resolve(strict=True)
    source_version = _source_application_version(source_root)
    if source_version != __version__:
        raise RuntimeError(
            "formal release source version differs from the build environment"
        )
    if _git(source_root, "status", "--porcelain"):
        raise RuntimeError("formal release builder requires a clean committed checkout")
    _require_release_tag(source_root, source_version)
    commit = _git(source_root, "rev-parse", "HEAD")
    if len(commit) != 40:
        raise RuntimeError("Git release commit is invalid")
    output = arguments.output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("formal release output root must be empty")
    browser_runtime = arguments.browser_runtime_root.resolve(strict=True)
    ocr_runtime = arguments.ocr_runtime_root.resolve(strict=True)
    gpu_runtime = arguments.gpu_runtime_root.resolve(strict=True)
    seed_root = arguments.seed_root.resolve(strict=True)
    release_tools = load_windows_release_manifest()
    embed_archive = python_embed_archive_path(release_tools).resolve(
        strict=True
    )
    if _sha256(embed_archive) != release_tools.python_embed.asset_sha256:
        raise RuntimeError("CPython embed archive SHA-256 does not match its pin")
    for name in (
        "operational-template-bundle.json",
        "operational-contract-install.json",
    ):
        if not (seed_root / name).is_file():
            raise RuntimeError("formal operational seed is incomplete")

    work = output / ".build"
    dist = work / "pyinstaller-dist"
    payload = work / "installer-payload"
    version_root = payload / "versions" / __version__
    work.mkdir()
    dist.mkdir()
    payload.mkdir()
    app_bundle = _run_pyinstaller(
        source_root=source_root,
        entrypoint=source_root / "tools" / "entrypoints" / "dahe_app.py",
        name="DaHeApp",
        dist_root=dist,
        work_root=work,
        one_file=False,
        windowed=False,
    )
    shutil.copytree(app_bundle, version_root)
    for name in ("src", "frontend", "browser-runtime", "ocr-runtime"):
        source = source_root / name
        if name == "src":
            _copy_source_tree(
                source / "dahe",
                version_root / "src" / "dahe",
            )
        elif name == "frontend":
            shutil.copytree(source / "dist", version_root / "frontend" / "dist")
        else:
            _copy_source_tree(source, version_root / name)
    for name in ("alembic.ini", "version-manifest.json"):
        shutil.copy2(source_root / name, version_root / name)
    _copy_formal_pipeline_sources(source_root, version_root)

    updater = _run_pyinstaller(
        source_root=source_root,
        entrypoint=source_root / "tools" / "entrypoints" / "dahe_updater.py",
        name="DaHeUpdater",
        dist_root=dist,
        work_root=work,
        one_file=True,
    )
    _copy_updater_binaries(
        updater,
        payload=payload,
        version_root=version_root,
    )

    source_build_sha256 = current_loop9_build_sha256(source_root)
    critical = (
        "DaHeApp.exe",
        "DaHeUpdater.exe",
        "alembic.ini",
        "frontend/dist/index.html",
        "version-manifest.json",
    )
    runtime_manifest = {
        "schema_version": 1,
        "kind": "dahe_local_production_read_only_release",
        "application_version": __version__,
        "build_git_commit": commit,
        "source_build_sha256": source_build_sha256,
        "module_modes": {
            "audit": "operational",
            "daily": "operational",
            "dispatch": "disabled",
            "settlement": "disabled",
        },
        "files": {
            name: _sha256(version_root / Path(name)) for name in critical
        },
    }
    (version_root / "runtime-manifest.json").write_text(
        json.dumps(runtime_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    resource_sha256 = compute_resource_sha256(version_root)
    (version_root / "release-identity.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "application_version": __version__,
                "build_git_commit": commit,
                "resource_sha256": resource_sha256,
                "platform_build_sha256": source_build_sha256,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    launcher = _run_pyinstaller(
        source_root=source_root,
        entrypoint=source_root / "tools" / "entrypoints" / "dahe_launcher.py",
        name="DaHeLauncher",
        dist_root=dist,
        work_root=work,
        one_file=True,
    )
    shutil.copy2(launcher, payload / "DaHeLauncher.exe")
    _copy_browser_runtime(
        browser_runtime,
        payload / "runtimes" / "browser",
        source_root=source_root,
        embed_archive=embed_archive,
        embed_archive_sha256=release_tools.python_embed.asset_sha256,
    )
    cpu_runtime_package = work / "ocr-cpu-runtime"
    source_composition = resolve_active_composition(
        ocr_runtime,
        allow_legacy=False,
    )
    if source_composition.generation_id is None:
        raise RuntimeError("qualified OCR generation is unavailable")
    _copy_cpu_runtime(
        ocr_runtime,
        cpu_runtime_package,
        source_root=source_root,
        embed_archive=embed_archive,
        embed_archive_sha256=release_tools.python_embed.asset_sha256,
    )
    packaged_cpu_composition = resolve_active_composition(
        cpu_runtime_package,
        allow_legacy=False,
    )
    _package_cpu_runtime_archive(
        cpu_runtime_package,
        payload / "runtimes" / "ocr-cpu.zip",
        payload / "runtimes" / "cpu-runtime-manifest.json",
    )
    _copy_operational_seed(seed_root, payload / "seed")
    write_version_pointer_atomic(
        payload,
        VersionPointer(
            version=__version__,
            build_git_commit=commit,
            resource_sha256=resource_sha256,
            schema_revision=REVISION,
        ),
    )
    validate_release_tree_no_developer_provenance(
        payload,
        developer_roots=(source_root, Path.home()),
    )

    application_name = (
        f"DaHe-Logistics-Automation-Tool-{__version__}-win-x64.zip"
    )
    application_zip = output / application_name
    _zip_tree(version_root, application_zip)
    _require_github_release_asset_size(application_zip)
    gpu_name = (
        f"DaHe-Logistics-Automation-Tool-{__version__}-gpu-addon-win-x64.zip"
    )
    gpu_root = work / "gpu-addon"
    gpu_root.mkdir()
    _write_gpu_addon(
        gpu_runtime,
        gpu_root,
        generation_id=source_composition.generation_id,
        cpu_composition=source_composition,
        packaged_cpu_composition=packaged_cpu_composition,
        source_root=source_root,
        embed_archive=embed_archive,
        embed_archive_sha256=release_tools.python_embed.asset_sha256,
    )
    validate_release_tree_no_developer_provenance(
        gpu_root,
        developer_roots=(source_root, Path.home()),
    )
    gpu_zip = output / gpu_name
    _zip_tree(gpu_root, gpu_zip)
    _require_github_release_asset_size(gpu_zip)

    manifest = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "version": __version__,
        "release_tag": f"v{__version__}",
        "build_git_commit": commit,
        "application": {
            "file_name": application_name,
            "sha256": _sha256(application_zip),
            "size": application_zip.stat().st_size,
            "url": (
                f"https://github.com/{REPOSITORY}/releases/download/"
                f"v{__version__}/{application_name}"
            ),
        },
        "gpu_addon": {
            "file_name": gpu_name,
            "sha256": _sha256(gpu_zip),
            "size": gpu_zip.stat().st_size,
            "url": (
                f"https://github.com/{REPOSITORY}/releases/download/"
                f"v{__version__}/{gpu_name}"
            ),
        },
        "minimum_schema_revision": MINIMUM_SCHEMA_REVISION,
        "target_schema_revision": REVISION,
        "alembic_revision": REVISION,
        "minimum_updater_version": "1.0.0",
        "resource_sha256": resource_sha256,
    }
    manifest_path = output / "update-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    installer_output = work / "installer-output"
    installer_output.mkdir()
    with tempfile.TemporaryDirectory(prefix="DaHeSetup-") as temporary:
        short_payload = _stage_installer_payload(payload, Path(temporary))
        subprocess.run(
            installer_command(
                makensis=makensis_path(),
                payload_root=short_payload,
                output_root=installer_output,
                app_version=__version__,
                script_path=source_root / "packaging" / "DaHeLogistics.nsi",
            ),
            check=True,
            shell=False,
        )
    setup = next(installer_output.glob("*.exe"))
    shutil.copy2(setup, output / setup.name)
    _require_github_release_asset_size(output / setup.name)
    assets = [
        output / setup.name,
        application_zip,
        gpu_zip,
        manifest_path,
    ]
    sums = output / "SHA256SUMS.txt"
    sums.write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in assets),
        encoding="ascii",
        newline="\n",
    )
    shutil.rmtree(work)
    if len(list(output.iterdir())) != 5:
        raise RuntimeError("formal release must contain exactly five assets")
    print(json.dumps({path.name: _sha256(path) for path in output.iterdir()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
