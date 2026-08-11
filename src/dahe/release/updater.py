from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from http.client import HTTPMessage
from pathlib import Path, PurePosixPath
from typing import IO, Protocol, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from dahe.adapters.ocr.runtime_layout import resolve_active_composition
from dahe.release.database_upgrade import (
    DatabaseUpgradeResult,
    ReleaseDatabaseUpgrade,
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


class UpdaterError(RuntimeError):
    """Raised while leaving the current installed version usable."""


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
    def download(self, asset: ReleaseAsset, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.download")
        digest = hashlib.sha256()
        size = 0
        request = Request(
            asset.url,
            headers={"Accept": "application/octet-stream", "User-Agent": "DaHeUpdater/1"},
            method="GET",
        )
        try:
            with (
                build_opener(_DownloadRedirectHandler()).open(
                    request,
                    timeout=30,
                ) as response,
                temporary.open("xb") as handle,
            ):
                while True:
                    chunk = cast(bytes, response.read(1024 * 1024))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > asset.size:
                        raise UpdaterError("download exceeded its declared size")
                    digest.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if size != asset.size or digest.hexdigest() != asset.sha256:
                raise UpdaterError("download hash or size differs from the release")
            os.replace(temporary, destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise


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
    resolved_archive = archive.resolve(strict=True)
    resolved_manifest = manifest_path.resolve(strict=True)
    try:
        manifest = json.loads(resolved_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdaterError("CPU runtime manifest is unreadable") from exc
    expected_fields = {
        "schema_version",
        "archive_file_name",
        "archive_sha256",
        "archive_size",
        "entry_count",
        "uncompressed_size",
        "active_composition_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise UpdaterError("CPU runtime manifest fields are invalid")
    integer_fields = (
        manifest["archive_size"],
        manifest["entry_count"],
        manifest["uncompressed_size"],
    )
    if (
        manifest["schema_version"] != 1
        or manifest["archive_file_name"] != "ocr-cpu.zip"
        or resolved_archive.name != manifest["archive_file_name"]
        or not isinstance(manifest["archive_sha256"], str)
        or len(manifest["archive_sha256"]) != 64
        or not isinstance(manifest["active_composition_sha256"], str)
        or len(manifest["active_composition_sha256"]) != 64
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in integer_fields
        )
        or manifest["entry_count"] > _MAX_RUNTIME_ARCHIVE_ENTRIES
        or manifest["uncompressed_size"] > _MAX_RUNTIME_UNCOMPRESSED_SIZE
        or resolved_archive.stat().st_size != manifest["archive_size"]
        or _sha256_file(resolved_archive) != manifest["archive_sha256"]
    ):
        raise UpdaterError("CPU runtime archive hash or bounds are invalid")
    destination = target.resolve()
    if destination.name != "ocr-cpu" or destination == Path(destination.anchor):
        raise UpdaterError("CPU runtime target is invalid")
    pointer_name = "active-composition.json"
    if destination.exists():
        pointer = destination / pointer_name
        if (
            pointer.is_file()
            and _sha256_file(pointer) == manifest["active_composition_sha256"]
        ):
            resolve_active_composition(destination, allow_legacy=False)
            return
        raise UpdaterError("a different CPU runtime already exists")
    staging = destination.with_name(f".{destination.name}-{uuid4().hex}.staging")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(resolved_archive) as bundle:
            members = bundle.infolist()
            if len(members) != manifest["entry_count"]:
                raise UpdaterError("CPU runtime archive entry count is invalid")
            seen: set[PurePosixPath] = set()
            total_size = 0
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
                    raise UpdaterError("CPU runtime archive contains an unsafe path")
                seen.add(logical)
                total_size += member.file_size
                if total_size > manifest["uncompressed_size"]:
                    raise UpdaterError("CPU runtime archive expanded beyond its manifest")
            if total_size != manifest["uncompressed_size"]:
                raise UpdaterError("CPU runtime archive size is invalid")
            staging.mkdir(parents=True, exist_ok=False)
            for member in members:
                logical = PurePosixPath(member.filename)
                output = staging / Path(*logical.parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, output.open("xb") as handle:
                    shutil.copyfileobj(source, handle, length=1024 * 1024)
        pointer = staging / pointer_name
        if (
            not pointer.is_file()
            or _sha256_file(pointer) != manifest["active_composition_sha256"]
        ):
            raise UpdaterError("CPU runtime composition pointer is invalid")
        resolve_active_composition(staging, allow_legacy=False)
        staging.rename(destination)
    except Exception as exc:
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(exc, UpdaterError):
            raise
        raise UpdaterError("CPU runtime bootstrap failed") from exc


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

    def install(self, *, manifest_path: Path, wait_pid: int) -> UpdateResult:
        current = read_version_pointer(self.install_root)
        content = manifest_path.resolve(strict=True).read_bytes()
        manifest = parse_update_manifest(
            content,
            current_version=current.version,
            updater_version="1.0.0",
        )
        available = shutil.disk_usage(self.install_root).free
        database = self.data_root / "database" / "dahe.sqlite3"
        database_size = database.stat().st_size if database.is_file() else 0
        required = manifest.application.size * 3 + database_size * 2 + 256 * 1024**2
        if available < required:
            raise UpdaterError("insufficient disk space for a recoverable update")
        run_root = self.data_root / "updates" / f"install-{uuid4().hex}"
        run_root.mkdir(parents=True, exist_ok=False)
        archive = run_root / manifest.application.file_name
        staging = run_root / "version"
        final = self.install_root / "versions" / manifest.version
        database_result: DatabaseUpgradeResult | None = None
        pointer_switched = False
        current_stopped = False
        try:
            self.downloader.download(manifest.application, archive)
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
    bootstrap = operations.add_parser("bootstrap-cpu-runtime")
    bootstrap.add_argument("--archive", type=Path, required=True)
    bootstrap.add_argument("--manifest", type=Path, required=True)
    bootstrap.add_argument("--target", type=Path, required=True)
    operations.add_parser("remove-cpu-runtime")
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
            temporary = error_path.with_name(f".{error_path.name}.{uuid4().hex}.tmp")
            temporary.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "error_code": "cpu_runtime_bootstrap_failed",
                        "message": str(exc),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
                newline="\n",
            )
            os.replace(temporary, error_path)
            print(f"DaHe CPU runtime setup failed: {exc}", file=sys.stderr)
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
        )
        print(json.dumps(asdict(result), sort_keys=True))
        code = 0
    except UpdaterError as exc:
        print(f"DaHe update failed: {exc}", file=sys.stderr)
        code = 2
    raise SystemExit(code)
