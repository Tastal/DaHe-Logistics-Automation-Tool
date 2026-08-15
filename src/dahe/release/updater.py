from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from http.client import HTTPMessage
from pathlib import Path, PurePosixPath
from typing import IO, Any, Protocol, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from dahe import __version__
from dahe.adapters.ocr.runtime_layout import (
    OcrRuntimeLayoutError,
    resolve_active_composition,
)
from dahe.release.database_upgrade import (
    DatabaseUpgradeResult,
    ReleaseDatabaseUpgrade,
)
from dahe.release.gpu_addon import (
    GpuAddonError,
    gpu_addon_status,
    install_gpu_addon,
)
from dahe.release.identity import load_release_identity
from dahe.release.launcher import (
    VersionPointer,
    compute_resource_sha256,
    read_version_pointer,
    write_version_pointer_atomic,
)
from dahe.release.update_manifest import ReleaseAsset, parse_update_manifest

_ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
_MAX_ARCHIVE_ENTRIES = 20_000
_MAX_RUNTIME_ARCHIVE_ENTRIES = 100_000
_MAX_RUNTIME_UNCOMPRESSED_SIZE = 16 * 1024**3
_CONTENT_RANGE = re.compile(r"^bytes ([0-9]+)-([0-9]+)/([0-9]+)$")
_DOWNLOAD_ATTEMPTS = 4


class UpdaterError(RuntimeError):
    """Raised while leaving the current installed version usable."""


class CpuRuntimeBootstrapError(UpdaterError):
    """Raised with safe, structured evidence for installer diagnostics."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        stage: str,
        winerror: int | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.stage = stage
        self.winerror = winerror


class AssetDownloader(Protocol):
    def download(self, asset: ReleaseAsset, destination: Path) -> None: ...


@dataclass(frozen=True, slots=True)
class UpdateResult:
    state: str
    from_version: str
    to_version: str
    error_code: str | None


class _DownloadRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        parsed = urlsplit(newurl)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_DOWNLOAD_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
        ):
            raise HTTPError(
                newurl,
                code,
                "untrusted update redirect",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GithubAssetDownloader:
    def __init__(
        self,
        *,
        opener: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._opener = opener or build_opener(_DownloadRedirectHandler())
        self._sleep = sleep

    def download(self, asset: ReleaseAsset, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(f"{destination.name}.partial")
        metadata = partial.with_name(f"{partial.name}.json")
        expected_metadata = json.dumps(
            asdict(asset),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if destination.is_file():
            if (
                destination.stat().st_size == asset.size
                and _sha256_file(destination) == asset.sha256
            ):
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)
                return
            destination.unlink()
        if partial.is_file():
            try:
                partial_matches = metadata.read_bytes() == expected_metadata
            except OSError:
                partial_matches = False
            if not partial_matches:
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)
        elif metadata.exists():
            metadata.unlink(missing_ok=True)
        if not metadata.is_file():
            temporary_metadata = metadata.with_name(f".{metadata.name}.tmp")
            temporary_metadata.write_bytes(expected_metadata)
            os.replace(temporary_metadata, metadata)
        last_error: Exception | None = None
        for attempt in range(_DOWNLOAD_ATTEMPTS):
            try:
                offset = partial.stat().st_size if partial.is_file() else 0
                if offset > asset.size:
                    partial.unlink()
                    offset = 0
                if offset == asset.size:
                    if _sha256_file(partial) != asset.sha256:
                        partial.unlink()
                        metadata.unlink(missing_ok=True)
                        raise UpdaterError(
                            "download hash differs from the release"
                        )
                    os.replace(partial, destination)
                    metadata.unlink(missing_ok=True)
                    return
                headers = {
                    "Accept": "application/octet-stream",
                    "User-Agent": "DaHeUpdater/1",
                }
                if offset:
                    headers["Range"] = f"bytes={offset}-"
                request = Request(asset.url, headers=headers, method="GET")
                with self._opener.open(request, timeout=30) as response:
                    status = int(getattr(response, "status", 0))
                    append = offset > 0 and status == 206
                    if offset and status == 200:
                        offset = 0
                        append = False
                    elif status == 206:
                        raw_range = str(response.headers.get("Content-Range", ""))
                        match = _CONTENT_RANGE.fullmatch(raw_range)
                        if (
                            match is None
                            or int(match.group(1)) != offset
                            or int(match.group(2)) != asset.size - 1
                            or int(match.group(3)) != asset.size
                        ):
                            raise UpdaterError(
                                "download content range is invalid"
                            )
                    elif status != 200:
                        raise UpdaterError("download response status is invalid")
                    mode = "ab" if append else "wb"
                    size = offset
                    with partial.open(mode) as handle:
                        while True:
                            chunk = cast(bytes, response.read(1024 * 1024))
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > asset.size:
                                partial.unlink(missing_ok=True)
                                metadata.unlink(missing_ok=True)
                                raise UpdaterError(
                                    "download exceeded its declared size"
                                )
                            handle.write(chunk)
                        handle.flush()
                        os.fsync(handle.fileno())
                if size < asset.size:
                    raise OSError("update download ended before declared size")
                if size != asset.size or _sha256_file(partial) != asset.sha256:
                    partial.unlink(missing_ok=True)
                    metadata.unlink(missing_ok=True)
                    raise UpdaterError(
                        "download hash or size differs from the release"
                    )
                os.replace(partial, destination)
                metadata.unlink(missing_ok=True)
                return
            except Exception as exc:
                last_error = exc
                if isinstance(exc, UpdaterError) and "hash" in str(exc):
                    raise
                if attempt + 1 < _DOWNLOAD_ATTEMPTS:
                    self._sleep(float(2**attempt))
        if isinstance(last_error, UpdaterError):
            raise last_error
        raise UpdaterError("update download failed after retries") from last_error


def safe_extract_application_zip(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    root.mkdir(parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if not members or len(members) > _MAX_ARCHIVE_ENTRIES:
                raise UpdaterError("application archive entry count is invalid")
            for member in members:
                logical = PurePosixPath(member.filename)
                if (
                    logical.is_absolute()
                    or not logical.parts
                    or any(part in {"", ".", ".."} for part in logical.parts)
                    or "\\" in member.filename
                    or (member.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise UpdaterError("application archive contains an unsafe path")
                target = (root / Path(*logical.parts)).resolve()
                try:
                    target.relative_to(root)
                except ValueError as exc:
                    raise UpdaterError(
                        "application archive escaped the version directory"
                    ) from exc
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bootstrap_cpu_runtime(
    *,
    archive: Path,
    manifest_path: Path,
    target: Path,
) -> None:
    stage = "locate"
    staging: Path | None = None
    previous_runtime_backup: Path | None = None
    previous_runtime_moved = False
    activated_runtime = False
    try:
        resolved_archive = archive.resolve(strict=True)
        resolved_manifest = manifest_path.resolve(strict=True)
    except OSError as exc:
        raise CpuRuntimeBootstrapError(
            "CPU runtime package is missing or inaccessible",
            error_code="cpu_runtime_package_missing",
            stage=stage,
            winerror=getattr(exc, "winerror", None),
        ) from exc
    stage = "manifest"
    try:
        manifest = json.loads(resolved_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CpuRuntimeBootstrapError(
            "CPU runtime manifest is unreadable",
            error_code="cpu_runtime_manifest_invalid",
            stage=stage,
            winerror=getattr(exc, "winerror", None),
        ) from exc
    expected_v1 = {
        "schema_version",
        "archive_file_name",
        "archive_sha256",
        "archive_size",
        "entry_count",
        "uncompressed_size",
        "active_composition_sha256",
    }
    expected_v2 = expected_v1 | {
        "layout",
        "maximum_relative_file_path",
        "maximum_relative_directory_path",
    }
    if (
        not isinstance(manifest, dict)
        or (
            manifest.get("schema_version") == 1
            and set(manifest) != expected_v1
        )
        or (
            manifest.get("schema_version") == 2
            and set(manifest) != expected_v2
        )
        or manifest.get("schema_version") not in {1, 2}
    ):
        raise CpuRuntimeBootstrapError(
            "CPU runtime manifest fields are invalid",
            error_code="cpu_runtime_manifest_invalid",
            stage=stage,
        )
    integer_fields = [
        manifest["archive_size"],
        manifest["entry_count"],
        manifest["uncompressed_size"],
    ]
    if manifest["schema_version"] == 2:
        integer_fields.extend(
            (
                manifest["maximum_relative_file_path"],
                manifest["maximum_relative_directory_path"],
            )
        )
    stage = "archive_verify"
    try:
        archive_valid = not (
            manifest["archive_file_name"] != "ocr-cpu.zip"
            or resolved_archive.name != manifest["archive_file_name"]
            or not isinstance(manifest["archive_sha256"], str)
            or len(manifest["archive_sha256"]) != 64
            or not isinstance(manifest["active_composition_sha256"], str)
            or len(manifest["active_composition_sha256"]) != 64
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                for value in integer_fields
            )
            or manifest["entry_count"] > _MAX_RUNTIME_ARCHIVE_ENTRIES
            or manifest["uncompressed_size"] > _MAX_RUNTIME_UNCOMPRESSED_SIZE
            or resolved_archive.stat().st_size != manifest["archive_size"]
            or _sha256_file(resolved_archive) != manifest["archive_sha256"]
            or (
                manifest["schema_version"] == 2
                and manifest["layout"] != "flat_v2"
            )
        )
    except OSError as exc:
        raise CpuRuntimeBootstrapError(
            "CPU runtime archive became inaccessible",
            error_code="cpu_runtime_io_blocked",
            stage=stage,
            winerror=getattr(exc, "winerror", None),
        ) from exc
    if not archive_valid:
        raise CpuRuntimeBootstrapError(
            "CPU runtime archive hash or bounds are invalid",
            error_code="cpu_runtime_archive_invalid",
            stage=stage,
        )
    destination = target.resolve()
    if destination.name != "ocr-cpu" or destination == Path(destination.anchor):
        raise CpuRuntimeBootstrapError(
            "CPU runtime target is invalid",
            error_code="cpu_runtime_target_invalid",
            stage="target",
        )
    pointer_name = "active-composition.json"
    replace_existing = False
    if destination.exists():
        pointer = destination / pointer_name
        if (
            pointer.is_file()
            and _sha256_file(pointer) == manifest["active_composition_sha256"]
        ):
            resolve_active_composition(destination, allow_legacy=False)
            return
        try:
            resolve_active_composition(destination, allow_legacy=False)
        except (OcrRuntimeLayoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CpuRuntimeBootstrapError(
                "a different or invalid CPU runtime already exists",
                error_code="cpu_runtime_target_conflict",
                stage="target",
                winerror=getattr(exc, "winerror", None),
            ) from exc
        replace_existing = True
    staging = destination.with_name(f".c-{uuid4().hex[:8]}")
    stage = "disk_preflight"
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        free_bytes = shutil.disk_usage(destination.parent).free
    except OSError as exc:
        raise CpuRuntimeBootstrapError(
            "CPU runtime installation directory is inaccessible",
            error_code="cpu_runtime_io_blocked",
            stage=stage,
            winerror=getattr(exc, "winerror", None),
        ) from exc
    required_bytes = int(manifest["uncompressed_size"]) + 64 * 1024**2
    if free_bytes < required_bytes:
        raise CpuRuntimeBootstrapError(
            "CPU runtime installation needs more free disk space",
            error_code="cpu_runtime_insufficient_space",
            stage=stage,
        )
    try:
        stage = "archive_inspect"
        with zipfile.ZipFile(resolved_archive) as bundle:
            members = bundle.infolist()
            if len(members) != manifest["entry_count"]:
                raise CpuRuntimeBootstrapError(
                    "CPU runtime archive entry count is invalid",
                    error_code="cpu_runtime_archive_invalid",
                    stage=stage,
                )
            seen: set[PurePosixPath] = set()
            total_size = 0
            maximum_file_path = 0
            maximum_directory_path = 0
            for member in members:
                logical = PurePosixPath(member.filename)
                if (
                    member.is_dir()
                    or logical.is_absolute()
                    or not logical.parts
                    or any(part in {"", ".", ".."} for part in logical.parts)
                    or "\\" in member.filename
                    or (member.external_attr >> 16) & 0o170000 == 0o120000
                    or logical in seen
                ):
                    raise CpuRuntimeBootstrapError(
                        "CPU runtime archive contains an unsafe path",
                        error_code="cpu_runtime_archive_unsafe",
                        stage=stage,
                    )
                seen.add(logical)
                total_size += member.file_size
                if total_size > manifest["uncompressed_size"]:
                    raise CpuRuntimeBootstrapError(
                        "CPU runtime archive expanded beyond its manifest",
                        error_code="cpu_runtime_archive_invalid",
                        stage=stage,
                    )
                maximum_file_path = max(maximum_file_path, len(member.filename))
                maximum_directory_path = max(
                    maximum_directory_path,
                    len(logical.parent.as_posix()) if logical.parent.parts else 0,
                )
            if total_size != manifest["uncompressed_size"]:
                raise CpuRuntimeBootstrapError(
                    "CPU runtime archive size is invalid",
                    error_code="cpu_runtime_archive_invalid",
                    stage=stage,
                )
            if manifest["schema_version"] == 2 and (
                maximum_file_path != manifest["maximum_relative_file_path"]
                or maximum_directory_path
                != manifest["maximum_relative_directory_path"]
            ):
                raise CpuRuntimeBootstrapError(
                    "CPU runtime archive path manifest is invalid",
                    error_code="cpu_runtime_archive_invalid",
                    stage=stage,
                )
            stage = "path_preflight"
            for member in members:
                logical_path = Path(*PurePosixPath(member.filename).parts)
                projected_file = staging / logical_path
                if os.name == "nt" and len(os.fspath(projected_file)) > 259:
                    raise CpuRuntimeBootstrapError(
                        "CPU runtime path is unsupported on this Windows account",
                        error_code="cpu_runtime_path_unsupported",
                        stage=stage,
                    )
                if os.name == "nt" and any(
                    len(os.fspath(parent)) > 247
                    for parent in projected_file.parents
                    if parent != staging.parent
                ):
                    raise CpuRuntimeBootstrapError(
                        "CPU runtime directory is unsupported on this Windows account",
                        error_code="cpu_runtime_path_unsupported",
                        stage=stage,
                    )
            stage = "extract"
            staging.mkdir(parents=True, exist_ok=False)
            for member in members:
                logical = PurePosixPath(member.filename)
                output = staging / Path(*logical.parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, output.open("xb") as handle:
                    shutil.copyfileobj(source, handle, length=1024 * 1024)
        stage = "composition_verify"
        pointer = staging / pointer_name
        if (
            not pointer.is_file()
            or _sha256_file(pointer) != manifest["active_composition_sha256"]
        ):
            raise CpuRuntimeBootstrapError(
                "CPU runtime composition pointer is invalid",
                error_code="cpu_runtime_composition_invalid",
                stage=stage,
            )
        resolve_active_composition(staging, allow_legacy=False)
        stage = "activate"
        if replace_existing:
            previous_runtime_backup = destination.with_name(
                f".c-old-{uuid4().hex[:8]}"
            )
            destination.rename(previous_runtime_backup)
            previous_runtime_moved = True
        staging.rename(destination)
        activated_runtime = True
        resolve_active_composition(destination, allow_legacy=False)
        if previous_runtime_backup is not None:
            shutil.rmtree(previous_runtime_backup, ignore_errors=True)
            previous_runtime_backup = None
    except Exception as exc:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if activated_runtime:
            shutil.rmtree(destination, ignore_errors=True)
        if previous_runtime_moved and previous_runtime_backup is not None:
            if previous_runtime_backup.exists() and not destination.exists():
                previous_runtime_backup.rename(destination)
            shutil.rmtree(previous_runtime_backup, ignore_errors=True)
            previous_runtime_backup = None
        if isinstance(exc, CpuRuntimeBootstrapError):
            raise
        if isinstance(exc, zipfile.BadZipFile):
            raise CpuRuntimeBootstrapError(
                "CPU runtime archive is unreadable",
                error_code="cpu_runtime_archive_invalid",
                stage=stage,
            ) from exc
        if isinstance(exc, OSError):
            winerror = getattr(exc, "winerror", None)
            if winerror in {112}:
                code = "cpu_runtime_insufficient_space"
                message = "CPU runtime installation needs more free disk space"
            elif winerror in {206}:
                code = "cpu_runtime_path_unsupported"
                message = "CPU runtime path is unsupported on this Windows account"
            elif winerror in {2, 5, 32, 33} or isinstance(exc, PermissionError):
                code = "cpu_runtime_io_blocked"
                message = "CPU runtime files were removed, blocked, or are in use"
            else:
                code = "cpu_runtime_io_failed"
                message = "CPU runtime file operation failed"
            raise CpuRuntimeBootstrapError(
                message,
                error_code=code,
                stage=stage,
                winerror=winerror,
            ) from exc
        raise CpuRuntimeBootstrapError(
            "CPU runtime composition validation failed",
            error_code="cpu_runtime_composition_invalid",
            stage=stage,
        ) from exc


def remove_installed_cpu_runtime(install_root: Path) -> None:
    root = install_root.resolve(strict=True)
    runtimes = root / "runtimes"
    target = runtimes / "ocr-cpu"
    if not target.exists():
        return
    is_junction = getattr(target, "is_junction", lambda: False)
    if target.is_symlink() or is_junction() or not target.is_dir():
        raise UpdaterError("installed CPU runtime path is unsafe")
    resolved_runtimes = runtimes.resolve(strict=True)
    resolved_target = target.resolve(strict=True)
    if resolved_runtimes.parent != root or resolved_target.parent != resolved_runtimes:
        raise UpdaterError("installed CPU runtime escaped the program directory")
    try:
        shutil.rmtree(resolved_target)
    except OSError as exc:
        raise UpdaterError("installed CPU runtime could not be removed") from exc
    if target.exists():
        raise UpdaterError("installed CPU runtime removal was incomplete")


def wait_for_process_exit(process_id: int, *, timeout_seconds: float = 60) -> bool:
    if process_id <= 0:
        return True
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            os.kill(process_id, 0)
        except OSError:
            return True
        time.sleep(0.2)
    return False


def _launch_and_wait(launcher_path: Path, install_root: Path) -> bool:
    completed = subprocess.run(
        [
            os.fspath(launcher_path),
            "--install-root",
            os.fspath(install_root),
        ],
        check=False,
        shell=False,
        timeout=120,
    )
    return completed.returncode == 0


class UpdateInstaller:
    def __init__(
        self,
        *,
        install_root: Path,
        data_root: Path,
        downloader: AssetDownloader | None = None,
        process_waiter: Callable[[int], bool] | None = None,
        launch_and_wait: Callable[[Path, Path], bool] | None = None,
    ) -> None:
        self.install_root = install_root.resolve(strict=True)
        self.data_root = data_root.resolve()
        self.downloader = downloader or GithubAssetDownloader()
        self.process_waiter = process_waiter or wait_for_process_exit
        self.launch_and_wait = launch_and_wait or _launch_and_wait
        self.state_path = self.data_root / "updates" / "update-result.json"

    def _write_result(self, result: UpdateResult) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.tmp")
        temporary.write_text(
            json.dumps(
                asdict(result),
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, self.state_path)

    def install(
        self,
        *,
        manifest_path: Path,
        wait_pid: int,
        application_path: Path | None = None,
    ) -> UpdateResult:
        current = read_version_pointer(self.install_root)
        content = manifest_path.resolve(strict=True).read_bytes()
        manifest = parse_update_manifest(
            content,
            current_version=current.version,
            updater_version=__version__,
        )
        available = shutil.disk_usage(self.install_root).free
        database = self.data_root / "database" / "dahe.sqlite3"
        database_size = database.stat().st_size if database.is_file() else 0
        required = manifest.application.size * 3 + database_size * 2 + 256 * 1024**2
        if available < required:
            raise UpdaterError("insufficient disk space for a recoverable update")
        run_root = self.data_root / "updates" / f"install-{uuid4().hex}"
        run_root.mkdir(parents=True, exist_ok=False)
        download_root = self.data_root / "updates" / "downloads"
        download_root.mkdir(parents=True, exist_ok=True)
        archive = download_root / manifest.application.file_name
        staging = run_root / "version"
        final = self.install_root / "versions" / manifest.version
        database_result: DatabaseUpgradeResult | None = None
        pointer_switched = False
        current_stopped = False
        try:
            if application_path is None:
                self.downloader.download(manifest.application, archive)
            else:
                imported = application_path.resolve(strict=True)
                if (
                    imported.name != manifest.application.file_name
                    or imported.stat().st_size != manifest.application.size
                    or _sha256_file(imported) != manifest.application.sha256
                ):
                    raise UpdaterError("imported application asset is invalid")
                archive = imported
            safe_extract_application_zip(archive, staging)
            identity = load_release_identity(
                staging,
                fallback_resource_sha256="0" * 64,
                expected_version=manifest.version,
            )
            if (
                identity.application_version != manifest.version
                or identity.build_git_commit != manifest.build_git_commit
                or identity.resource_sha256 != manifest.resource_sha256
                or compute_resource_sha256(staging) != manifest.resource_sha256
            ):
                raise UpdaterError("downloaded version identity is invalid")
            database_upgrade = ReleaseDatabaseUpgrade(
                project_root=staging,
                data_root=self.data_root,
                staging_root=run_root / "database-preflight",
                minimum_revision=manifest.minimum_schema_revision,
                target_revision=manifest.target_schema_revision,
            )
            database_upgrade.preflight()
            if not self.process_waiter(wait_pid):
                raise UpdaterError("current application did not stop in time")
            current_stopped = True
            if final.exists():
                raise UpdaterError("target version directory already exists")
            final.parent.mkdir(parents=True, exist_ok=True)
            staging.rename(final)
            database_upgrade = ReleaseDatabaseUpgrade(
                project_root=final,
                data_root=self.data_root,
                staging_root=run_root / "database-formal",
                minimum_revision=manifest.minimum_schema_revision,
                target_revision=manifest.target_schema_revision,
            )
            database_result = database_upgrade.apply()
            next_pointer = VersionPointer(
                version=manifest.version,
                build_git_commit=identity.build_git_commit,
                resource_sha256=manifest.resource_sha256,
                schema_revision=manifest.target_schema_revision,
            )
            write_version_pointer_atomic(self.install_root, next_pointer)
            pointer_switched = True
            launcher = self.install_root / "DaHeLauncher.exe"
            if not launcher.is_file() or not self.launch_and_wait(
                launcher,
                self.install_root,
            ):
                raise UpdaterError("updated application failed readiness")
            result = UpdateResult(
                state="succeeded",
                from_version=current.version,
                to_version=manifest.version,
                error_code=None,
            )
            self._write_result(result)
            return result
        except Exception as exc:
            if pointer_switched:
                write_version_pointer_atomic(self.install_root, current)
            if database_result is not None and database_result.backup_path is not None:
                rollback = ReleaseDatabaseUpgrade(
                    project_root=(self.install_root / "versions" / current.version),
                    data_root=self.data_root,
                    staging_root=run_root / "database-rollback",
                    minimum_revision=current.schema_revision,
                    target_revision=current.schema_revision,
                )
                rollback.restore(database_result.backup_path)
            if current_stopped:
                launcher = self.install_root / "DaHeLauncher.exe"
                if launcher.is_file():
                    self.launch_and_wait(launcher, self.install_root)
            result = UpdateResult(
                state="failed",
                from_version=current.version,
                to_version=manifest.version,
                error_code="software_update_failed",
            )
            self._write_result(result)
            if isinstance(exc, UpdaterError):
                raise
            raise UpdaterError("software update failed") from exc


def main() -> None:
    parser = argparse.ArgumentParser(prog="DaHeUpdater")
    operations = parser.add_subparsers(dest="operation", required=True)
    install = operations.add_parser("install")
    install.add_argument("--manifest", type=Path, required=True)
    install.add_argument("--data-root", type=Path, required=True)
    install.add_argument("--wait-pid", type=int, required=True)
    install.add_argument("--install-root", type=Path)
    install.add_argument("--application", type=Path)
    bootstrap = operations.add_parser("bootstrap-cpu-runtime")
    bootstrap.add_argument("--archive", type=Path, required=True)
    bootstrap.add_argument("--manifest", type=Path, required=True)
    bootstrap.add_argument("--target", type=Path, required=True)
    operations.add_parser("remove-cpu-runtime")
    gpu_install = operations.add_parser("gpu-install")
    gpu_install.add_argument("--manifest", type=Path, required=True)
    gpu_install.add_argument("--package", type=Path, required=True)
    gpu_install.add_argument("--install-root", type=Path, required=True)
    gpu_install.add_argument("--json", action="store_true", dest="as_json")
    gpu_status = operations.add_parser("gpu-status")
    gpu_status.add_argument("--install-root", type=Path, required=True)
    gpu_status.add_argument("--json", action="store_true", dest="as_json")
    arguments = parser.parse_args()
    if arguments.operation == "bootstrap-cpu-runtime":
        error_path = arguments.manifest.resolve().parent / "cpu-runtime-bootstrap-error.json"
        try:
            bootstrap_cpu_runtime(
                archive=arguments.archive,
                manifest_path=arguments.manifest,
                target=arguments.target,
            )
            error_path.unlink(missing_ok=True)
            code = 0
        except UpdaterError as exc:
            error_code = getattr(
                exc,
                "error_code",
                "cpu_runtime_bootstrap_failed",
            )
            stage = getattr(exc, "stage", "unknown")
            winerror = getattr(exc, "winerror", None)
            temporary = error_path.with_name(f".{error_path.name}.{uuid4().hex}.tmp")
            temporary.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "error_code": error_code,
                        "stage": stage,
                        "winerror": winerror,
                        "message": str(exc),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
                newline="\n",
            )
            os.replace(temporary, error_path)
            print(
                f"DaHe CPU runtime setup failed [{error_code}/{stage}]: {exc}",
                file=sys.stderr,
            )
            code = 2
        raise SystemExit(code)
    if arguments.operation == "remove-cpu-runtime":
        try:
            remove_installed_cpu_runtime(Path(sys.executable).resolve().parent)
            code = 0
        except UpdaterError as exc:
            print(f"DaHe CPU runtime removal failed: {exc}", file=sys.stderr)
            code = 2
        raise SystemExit(code)
    if arguments.operation == "gpu-status":
        status = gpu_addon_status(arguments.install_root)
        if arguments.as_json:
            print(json.dumps(asdict(status), sort_keys=True))
        else:
            print(status.state)
        raise SystemExit(0 if status.state == "active" else 3)
    if arguments.operation == "gpu-install":
        try:
            gpu_result = install_gpu_addon(
                manifest_path=arguments.manifest,
                package_path=arguments.package,
                install_root=arguments.install_root,
            )
            if arguments.as_json:
                print(json.dumps(asdict(gpu_result), sort_keys=True))
            else:
                print(gpu_result.state)
            code = 0
        except GpuAddonError as exc:
            payload = {
                "state": "failed",
                "gpu_qualified": False,
                "primary_runtime": "cpu",
                "cpu_fallback_available": True,
                "package_version": None,
                "diagnostic_code": exc.error_code,
                "stage": exc.stage,
                "winerror": exc.winerror,
            }
            if arguments.as_json:
                print(json.dumps(payload, sort_keys=True))
            else:
                print(
                    f"DaHe GPU add-on setup failed "
                    f"[{exc.error_code}/{exc.stage}]: {exc}",
                    file=sys.stderr,
                )
            code = 2
        raise SystemExit(code)
    install_root = (
        arguments.install_root.resolve()
        if arguments.install_root is not None
        else Path(sys.executable).resolve().parent
    )
    try:
        result = UpdateInstaller(
            install_root=install_root,
            data_root=arguments.data_root,
        ).install(
            manifest_path=arguments.manifest,
            wait_pid=arguments.wait_pid,
            application_path=arguments.application,
        )
        print(json.dumps(asdict(result), sort_keys=True))
        code = 0
    except UpdaterError as exc:
        print(f"DaHe update failed: {exc}", file=sys.stderr)
        code = 2
    raise SystemExit(code)
