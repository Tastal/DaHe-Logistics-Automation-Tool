from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntimeError,
    IsolatedBrowserRuntime,
)
from dahe.application.template_studio.fingerprints import (
    TEMPLATE_PIPELINE_SOURCE_MANIFEST,
)
from dahe.verification.loop9_build import current_loop9_build_sha256


class LocalReleaseError(RuntimeError):
    """Raised when a local production payload cannot be built safely."""


@dataclass(frozen=True, slots=True)
class LocalReleaseResult:
    release_root: Path
    manifest_path: Path
    launcher_path: Path
    shortcut_path: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(project_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    return completed.stdout.strip()


def _copy_tree(source: Path, target: Path) -> None:
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(
            "__pycache__",
            "*.pyc",
            "build",
            ".pytest_cache",
        ),
    )


def _copy_formal_pipeline_project_sources(
    *,
    project_root: Path,
    release_root: Path,
) -> None:
    for logical_path in TEMPLATE_PIPELINE_SOURCE_MANIFEST:
        if not logical_path.startswith("tools/"):
            continue
        source = project_root / logical_path
        target = release_root / logical_path
        if not source.is_file() or source.is_symlink():
            raise LocalReleaseError(
                f"formal pipeline release source is unavailable: {logical_path}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _payload_files(release_root: Path) -> list[Path]:
    excluded = {".venv", "runtime-manifest.json"}
    return [
        path
        for path in sorted(release_root.rglob("*"))
        if path.is_file()
        and not any(
            part in excluded for part in path.relative_to(release_root).parts
        )
    ]


def _require_current_browser_runtime(
    *,
    project_root: Path,
    runtime_root: Path,
) -> None:
    runtime = IsolatedBrowserRuntime(
        project_root=project_root,
        data_root=runtime_root / ".release-preflight",
        runtime_root=runtime_root,
    )
    try:
        runtime._validate_installation()
    except BrowserRuntimeError as exc:
        raise LocalReleaseError(
            "isolated browser runtime is stale; run "
            ".\\.venv\\Scripts\\python.exe tools\\bootstrap_browser.py "
            "before building a release"
        ) from exc


def _write_launcher(path: Path) -> None:
    content = "\r\n".join(
        (
            "@echo off",
            "setlocal",
            'set "DAHE_DATA_ROOT=%LOCALAPPDATA%\\DaHeLogistics\\production"',
            '"%~dp0.venv\\Scripts\\python.exe" -m dahe --serve '
            '--production-read-only --data-root "%DAHE_DATA_ROOT%"',
            "if errorlevel 1 pause",
            "endlocal",
            "",
        )
    )
    path.write_text(content, encoding="utf-8", newline="")


def _write_hidden_launcher(
    path: Path,
    *,
    diagnostic_launcher_name: str,
) -> None:
    content = "\r\n".join(
        (
            'Set shell = CreateObject("WScript.Shell")',
            'Set fso = CreateObject("Scripting.FileSystemObject")',
            (
                "launcher = fso.BuildPath("
                "fso.GetParentFolderName(WScript.ScriptFullName), "
                f'"{diagnostic_launcher_name}")'
            ),
            'shell.Run Chr(34) & launcher & Chr(34), 0, False',
            "",
        )
    )
    # Windows Script Host rejects an UTF-8 BOM as an invalid first character.
    # This launcher intentionally contains ASCII only so it remains portable
    # across supported Windows 10 and Windows 11 script-host configurations.
    path.write_text(content, encoding="ascii", newline="")


def _create_shortcut(*, shortcut_path: Path, launcher_path: Path) -> None:
    environment = dict(os.environ)
    environment.update(
        {
            "DAHE_SHORTCUT_PATH": os.fspath(shortcut_path),
            "DAHE_LAUNCHER_PATH": os.fspath(launcher_path),
            "DAHE_WORKING_DIRECTORY": os.fspath(launcher_path.parent),
        }
    )
    script = (
        "$shell = New-Object -ComObject WScript.Shell; "
        "$shortcut = $shell.CreateShortcut($env:DAHE_SHORTCUT_PATH); "
        "$shortcut.TargetPath = $env:DAHE_LAUNCHER_PATH; "
        "$shortcut.WorkingDirectory = $env:DAHE_WORKING_DIRECTORY; "
        "$shortcut.IconLocation = $env:DAHE_LAUNCHER_PATH + ',0'; "
        "$shortcut.Description = '大禾物流自动化平台'; "
        "$shortcut.Save()"
    )
    subprocess.run(
        (
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ),
        check=True,
        env=environment,
        shell=False,
    )
    if not shortcut_path.is_file():
        raise LocalReleaseError("desktop shortcut was not created")


def build_local_release(
    *,
    project_root: Path,
    releases_root: Path,
    operational_source_root: Path,
    desktop_root: Path,
    create_shortcut: bool = True,
) -> LocalReleaseResult:
    project_root = project_root.resolve(strict=True)
    releases_root = releases_root.resolve()
    operational_source_root = operational_source_root.resolve(strict=True)
    desktop_root = desktop_root.resolve(strict=True)
    project_python = (project_root / ".venv" / "Scripts" / "python.exe").resolve()
    if Path(sys.executable).resolve() != project_python:
        raise LocalReleaseError("build the release with the project .venv")
    if _git(project_root, "status", "--porcelain"):
        raise LocalReleaseError("release builds require a clean committed checkout")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise LocalReleaseError("LOCALAPPDATA is unavailable")
    _require_current_browser_runtime(
        project_root=project_root,
        runtime_root=(
            Path(local_app_data)
            / "DaHeLogistics"
            / "runtimes"
            / "browser"
        ),
    )
    commit = _git(project_root, "rev-parse", "HEAD")
    if len(commit) != 40:
        raise LocalReleaseError("Git commit identity is invalid")
    required = (
        project_root / "frontend" / "dist" / "index.html",
        project_root / "requirements-production.lock",
        project_root / "version-manifest.json",
        project_root / "alembic.ini",
        operational_source_root / "operational-template-bundle.json",
        operational_source_root / "operational-contract-install.json",
    )
    if any(not path.is_file() for path in required):
        raise LocalReleaseError("release inputs are incomplete")

    releases_root.mkdir(parents=True, exist_ok=True)
    release_name = f"{__version__}-{commit[:12]}"
    final = releases_root / release_name
    if final.exists():
        raise LocalReleaseError("release directory already exists")
    staging = releases_root / f".{release_name}.partial-{uuid4().hex}"
    if staging.exists():
        raise LocalReleaseError("release staging directory already exists")
    staging.mkdir()
    try:
        _copy_tree(project_root / "src" / "dahe", staging / "src" / "dahe")
        _copy_tree(project_root / "frontend" / "dist", staging / "frontend" / "dist")
        _copy_tree(project_root / "browser-runtime", staging / "browser-runtime")
        _copy_tree(project_root / "ocr-runtime", staging / "ocr-runtime")
        _copy_formal_pipeline_project_sources(
            project_root=project_root,
            release_root=staging,
        )
        for name in (
            "alembic.ini",
            "version-manifest.json",
            "requirements-production.lock",
            "README.md",
        ):
            shutil.copy2(project_root / name, staging / name)
        wheel_root = staging / "wheel"
        wheel_root.mkdir()
        subprocess.run(
            (
                os.fspath(sys.executable),
                "-m",
                "build",
                "--wheel",
                "--outdir",
                os.fspath(wheel_root),
            ),
            cwd=project_root,
            check=True,
            shell=False,
        )
        wheels = tuple(wheel_root.glob("*.whl"))
        if len(wheels) != 1:
            raise LocalReleaseError("release wheel output is invalid")

        subprocess.run(
            (
                os.fspath(sys.executable),
                "-m",
                "venv",
                os.fspath(staging / ".venv"),
            ),
            check=True,
            shell=False,
        )
        release_python = staging / ".venv" / "Scripts" / "python.exe"
        subprocess.run(
            (
                os.fspath(release_python),
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "-r",
                os.fspath(staging / "requirements-production.lock"),
            ),
            check=True,
            shell=False,
        )
        subprocess.run(
            (
                os.fspath(release_python),
                "-m",
                "pip",
                "install",
                "--no-deps",
                os.fspath(wheels[0]),
            ),
            check=True,
            shell=False,
        )
        diagnostic_launcher = staging / "start-dahe-diagnostic.cmd"
        _write_launcher(diagnostic_launcher)
        launcher = staging / "start-dahe.vbs"
        _write_hidden_launcher(
            launcher,
            diagnostic_launcher_name=diagnostic_launcher.name,
        )

        source_fingerprints = {
            path.relative_to(staging).as_posix(): _sha256(path)
            for path in _payload_files(staging)
        }
        external_fingerprints = {
            "operational_contract_install_sha256": _sha256(
                operational_source_root / "operational-contract-install.json"
            ),
            "operational_template_bundle_sha256": _sha256(
                operational_source_root / "operational-template-bundle.json"
            ),
        }
        manifest = {
            "application_version": __version__,
            "build_git_commit": commit,
            "external_fingerprints": external_fingerprints,
            "files": source_fingerprints,
            "kind": "dahe_local_production_read_only_release",
            "module_modes": {
                "audit": "operational",
                "daily": "operational",
                "dispatch": "disabled",
                "settlement": "disabled",
            },
            "schema_version": 1,
            "source_build_sha256": current_loop9_build_sha256(project_root),
        }
        manifest_path = staging / "runtime-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        staging.rename(final)
        final_launcher = final / launcher.name
        shortcut = desktop_root / "大禾物流自动化平台.lnk"
        if create_shortcut:
            _create_shortcut(shortcut_path=shortcut, launcher_path=final_launcher)
        return LocalReleaseResult(
            release_root=final,
            manifest_path=final / manifest_path.name,
            launcher_path=final_launcher,
            shortcut_path=shortcut,
        )
    except Exception:
        if staging.exists() and staging.parent == releases_root:
            shutil.rmtree(staging)
        raise
