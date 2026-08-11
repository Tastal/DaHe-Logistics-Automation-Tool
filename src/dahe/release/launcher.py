from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import webbrowser
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from dahe.release.identity import load_release_identity


class LauncherError(RuntimeError):
    """Raised before an untrusted or incomplete installed version starts."""


_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_COLD_START_READINESS_TIMEOUT_SECONDS = 300
_OPERATIONAL_CONTRACT_PREFIXES = frozenset(
    {
        "daily-platform-read-contract",
        "daily-platform-read-contract-evidence",
        "platform-contract-discovery",
        "platform-read-contract",
    }
)


@dataclass(frozen=True, slots=True)
class VersionPointer:
    version: str
    build_git_commit: str
    resource_sha256: str
    schema_revision: str


def compute_resource_sha256(version_root: Path) -> str:
    root = version_root.resolve(strict=True)
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.name != "release-identity.json"
    )
    if not files:
        raise LauncherError("installed version has no resources")
    for path in files:
        if path.is_symlink():
            raise LauncherError("installed version contains a symbolic link")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(path.stat().st_size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def read_version_pointer(install_root: Path) -> VersionPointer:
    pointer_path = install_root.resolve(strict=True) / "current.json"
    try:
        payload = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LauncherError("installed version pointer is unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "version",
        "build_git_commit",
        "resource_sha256",
        "schema_revision",
    }:
        raise LauncherError("installed version pointer fields are invalid")
    values = (
        payload["version"],
        payload["build_git_commit"],
        payload["resource_sha256"],
        payload["schema_revision"],
    )
    if (
        payload["schema_version"] != 1
        or not all(isinstance(value, str) for value in values)
        or _VERSION.fullmatch(str(payload["version"])) is None
        or _COMMIT.fullmatch(str(payload["build_git_commit"])) is None
        or _SHA256.fullmatch(str(payload["resource_sha256"])) is None
        or _REVISION.fullmatch(str(payload["schema_revision"])) is None
    ):
        raise LauncherError("installed version pointer identity is invalid")
    return VersionPointer(
        version=str(payload["version"]),
        build_git_commit=str(payload["build_git_commit"]),
        resource_sha256=str(payload["resource_sha256"]),
        schema_revision=str(payload["schema_revision"]),
    )


def write_version_pointer_atomic(
    install_root: Path,
    pointer: VersionPointer,
) -> None:
    root = install_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = root / "current.json"
    temporary = root / f".current-{uuid4().hex}.tmp"
    payload = {
        "schema_version": 1,
        "version": pointer.version,
        "build_git_commit": pointer.build_git_commit,
        "resource_sha256": pointer.resource_sha256,
        "schema_revision": pointer.schema_revision,
    }
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, target)


def validate_version_root(
    install_root: Path,
    pointer: VersionPointer,
) -> Path:
    root = install_root.resolve(strict=True)
    version_root = (root / "versions" / pointer.version).resolve(strict=True)
    try:
        version_root.relative_to(root / "versions")
    except ValueError as exc:
        raise LauncherError("installed version escaped the versions directory") from exc
    executable = version_root / "DaHeApp.exe"
    if not executable.is_file() or executable.is_symlink():
        raise LauncherError("installed application executable is unavailable")
    identity = load_release_identity(
        version_root,
        fallback_resource_sha256="0" * 64,
        expected_version=pointer.version,
    )
    if (
        identity.application_version != pointer.version
        or identity.build_git_commit != pointer.build_git_commit
        or identity.resource_sha256 != pointer.resource_sha256
    ):
        raise LauncherError("installed release identity differs from its pointer")
    if compute_resource_sha256(version_root) != pointer.resource_sha256:
        raise LauncherError("installed release resources failed verification")
    return version_root


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_declared_operational_contracts(*, source: Path, target: Path) -> int:
    marker = source / "operational-contract-install.json"
    if not marker.is_file() or marker.is_symlink():
        return 0
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LauncherError("operational contract install marker is unreadable") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or payload.get("kind") != "chengfeng_operational_read_contract_install"
        or payload.get("classification") != "operational_only"
        or payload.get("credential_material_retained") is not False
        or payload.get("request_values_retained") is not False
        or payload.get("response_values_retained") is not False
        or payload.get("platform_write_authorization") is not False
        or not isinstance(payload.get("copied_files"), list)
    ):
        raise LauncherError("operational contract install marker is unsafe")
    copied = 0
    for raw_entry in payload["copied_files"]:
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "relative_path",
            "sha256",
            "size",
        }:
            raise LauncherError("operational contract file declaration is invalid")
        relative_text = raw_entry["relative_path"]
        expected_sha256 = raw_entry["sha256"]
        expected_size = raw_entry["size"]
        if (
            not isinstance(relative_text, str)
            or not relative_text
            or "\\" in relative_text
            or not isinstance(expected_sha256, str)
            or _SHA256.fullmatch(expected_sha256) is None
            or type(expected_size) is not int
            or expected_size < 0
        ):
            raise LauncherError("operational contract file declaration is invalid")
        relative = Path(relative_text)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.parts[0] not in _OPERATIONAL_CONTRACT_PREFIXES
        ):
            raise LauncherError("operational contract path escaped its allowlist")
        source_candidate = source / relative
        try:
            source_file = source_candidate.resolve(strict=True)
            source_file.relative_to(source)
        except (OSError, ValueError) as exc:
            raise LauncherError("declared operational contract file is unavailable") from exc
        if not source_file.is_file() or source_candidate.is_symlink():
            raise LauncherError("declared operational contract file is unsafe")
        if (
            source_file.stat().st_size != expected_size
            or _file_sha256(source_file) != expected_sha256
        ):
            raise LauncherError("declared operational contract file failed verification")
        target_file = target / relative
        try:
            target_file.resolve().relative_to(target)
        except ValueError as exc:
            raise LauncherError("operational contract target escaped the data root") from exc
        if target_file.exists():
            if (
                not target_file.is_file()
                or target_file.is_symlink()
                or target_file.stat().st_size != expected_size
                or _file_sha256(target_file) != expected_sha256
            ):
                raise LauncherError("existing operational contract differs from migration source")
            continue
        target_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = target_file.with_name(f".{target_file.name}.{uuid4().hex}.tmp")
        shutil.copy2(source_file, temporary)
        if (
            temporary.stat().st_size != expected_size
            or _file_sha256(temporary) != expected_sha256
        ):
            temporary.unlink(missing_ok=True)
            raise LauncherError("copied operational contract failed verification")
        os.replace(temporary, target_file)
        copied += 1
    return copied


def migrate_existing_user_data(*, source_root: Path, target_root: Path) -> None:
    """Copy the current DaHe data once; never modify or remove the source."""
    source = source_root.resolve()
    target = target_root.resolve()
    marker = target / "migration-from-0.8.json"
    if not source.is_dir():
        return
    target.mkdir(parents=True, exist_ok=True)
    source_database = source / "database" / "dahe.sqlite3"
    target_database = target / "database" / "dahe.sqlite3"
    if source_database.is_file() and not target_database.exists():
        target_database.parent.mkdir(parents=True, exist_ok=True)
        staging = target_database.with_name(f".{target_database.name}.copy.tmp")
        with (
            closing(
                sqlite3.connect(
                    f"{source_database.resolve().as_uri()}?mode=ro",
                    uri=True,
                )
            ) as source_connection,
            closing(sqlite3.connect(staging)) as target_connection,
        ):
            source_connection.backup(target_connection)
            target_connection.commit()
            if target_connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise LauncherError("copied database failed integrity validation")
        os.replace(staging, target_database)
    for name in (
        "evidence",
        "browser-profile",
        "credentials",
        "logs",
        "backups",
        "quarantine",
    ):
        source_directory = source / name
        target_directory = target / name
        if source_directory.is_dir() and not target_directory.exists():
            shutil.copytree(source_directory, target_directory)
    for name in (
        "operational-template-bundle.json",
        "operational-contract-install.json",
    ):
        source_file = source / name
        target_file = target / name
        if source_file.is_file() and not target_file.exists():
            shutil.copy2(source_file, target_file)
    migrated_contract_files = _copy_declared_operational_contracts(
        source=source,
        target=target,
    )
    temporary = target / f".{marker.name}.tmp"
    temporary.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "source": "DaHeLogistics/production",
                "operational_contract_files_copied": migrated_contract_files,
                "operational_contract_files_verified": True,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, marker)


def install_seed_data(*, install_root: Path, data_root: Path) -> None:
    seed_root = install_root.resolve() / "seed"
    target_root = data_root.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    for name in (
        "operational-template-bundle.json",
        "operational-contract-install.json",
    ):
        source = seed_root / name
        target = target_root / name
        if source.is_file() and not target.exists():
            shutil.copy2(source, target)


def readiness(
    pointer: VersionPointer,
    *,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    url = "http://127.0.0.1:8877/api/v1/system/readiness"
    while time.monotonic() < deadline:
        try:
            request = Request(url, method="GET")
            with urlopen(request, timeout=1) as response:
                if response.status != 200:
                    continue
                payload = json.loads(response.read(64 * 1024))
            if payload == {
                "ready": True,
                "application_version": pointer.version,
                "build_git_commit": pointer.build_git_commit,
                "resource_sha256": pointer.resource_sha256,
                "schema_revision": pointer.schema_revision,
            }:
                return True
        except (OSError, URLError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(0.25)
    return False


def _default_install_root() -> Path:
    explicit = os.environ.get("DAHE_INSTALL_ROOT")
    if explicit:
        return Path(explicit).resolve()
    return Path(sys.executable).resolve().parent


def run_launcher(
    *,
    install_root: Path,
    data_root: Path,
    open_browser: bool = True,
) -> int:
    pointer = read_version_pointer(install_root)
    version_root = validate_version_root(install_root, pointer)
    if readiness(pointer, timeout_seconds=0.3):
        if open_browser:
            webbrowser.open("http://127.0.0.1:8877/", new=2)
        return 0
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        migrate_existing_user_data(
            source_root=Path(local_app_data) / "DaHeLogistics" / "production",
            target_root=data_root,
        )
    install_seed_data(install_root=install_root, data_root=data_root)
    environment = dict(os.environ)
    environment.update(
        {
            "DAHE_INSTALL_ROOT": os.fspath(install_root.resolve()),
            "DAHE_BROWSER_RUNTIME_ROOT": os.fspath(
                install_root.resolve() / "runtimes" / "browser"
            ),
            "DAHE_OCR_RUNTIME_ROOT": os.fspath(
                install_root.resolve() / "runtimes" / "ocr-cpu"
            ),
        }
    )
    process = subprocess.Popen(
        [
            os.fspath(version_root / "DaHeApp.exe"),
            "--serve",
            "--production-read-only",
            "--data-root",
            os.fspath(data_root.resolve()),
            "--no-browser",
        ],
        cwd=version_root,
        env=environment,
        close_fds=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if not readiness(
        pointer,
        timeout_seconds=_COLD_START_READINESS_TIMEOUT_SECONDS,
    ):
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        raise LauncherError("installed application did not become ready")
    if open_browser:
        webbrowser.open("http://127.0.0.1:8877/", new=2)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="DaHeLauncher")
    parser.add_argument("--install-root", type=Path, default=_default_install_root())
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--no-browser", action="store_true")
    arguments = parser.parse_args()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if arguments.data_root is None:
        if not local_app_data:
            raise SystemExit("LOCALAPPDATA is unavailable")
        data_root = Path(local_app_data) / "DaHeLogisticsAutomationTool"
    else:
        data_root = arguments.data_root
    try:
        code = run_launcher(
            install_root=arguments.install_root,
            data_root=data_root,
            open_browser=not arguments.no_browser,
        )
    except LauncherError as exc:
        print(f"DaHe launch failed: {exc}", file=sys.stderr)
        code = 2
    raise SystemExit(code)
