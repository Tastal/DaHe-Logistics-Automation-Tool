from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
from collections.abc import AsyncIterable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Protocol, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from dahe.release.update_manifest import (
    UpdateManifest,
    UpdateManifestError,
    compare_versions,
    parse_update_manifest,
)

_MANIFEST_URL = (
    "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
    "releases/latest/download/update-manifest.json"
)
_ALLOWED_REDIRECT_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
_MAX_MANIFEST_BYTES = 64 * 1024


class ManifestFetcher(Protocol):
    def fetch(self) -> bytes: ...


class UpdaterLauncher(Protocol):
    def launch(
        self,
        *,
        updater_path: Path,
        manifest_path: Path,
        data_root: Path,
        process_id: int,
        application_path: Path | None,
    ) -> None: ...


class UpdateInstallBlocked(RuntimeError):
    """Raised when starting an update could make active work unsafe."""


@dataclass(frozen=True, slots=True)
class UpdateStatus:
    state: str
    current_version: str
    available_version: str | None
    update_available: bool
    checked_at: str | None
    error_code: str | None

    def to_payload(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class UpdateImport:
    import_id: str
    state: str
    version: str
    application_file_name: str
    application_size: int

    def to_payload(self) -> dict[str, object]:
        return asdict(self)


class _TrustedRedirectHandler(HTTPRedirectHandler):
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
            or parsed.hostname not in _ALLOWED_REDIRECT_HOSTS
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


class GithubManifestFetcher:
    def fetch(self) -> bytes:
        request = Request(
            _MANIFEST_URL,
            headers={"Accept": "application/json", "User-Agent": "DaHeUpdater/1"},
            method="GET",
        )
        with build_opener(_TrustedRedirectHandler()).open(
            request,
            timeout=15,
        ) as response:
            content = cast(bytes, response.read(_MAX_MANIFEST_BYTES + 1))
        if not content or len(content) > _MAX_MANIFEST_BYTES:
            raise OSError("update manifest size is invalid")
        return content


class SubprocessUpdaterLauncher:
    def launch(
        self,
        *,
        updater_path: Path,
        manifest_path: Path,
        data_root: Path,
        process_id: int,
        application_path: Path | None,
    ) -> None:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        command = [
                str(updater_path),
                "install",
                "--manifest",
                str(manifest_path),
                "--data-root",
                str(data_root),
                "--wait-pid",
                str(process_id),
            ]
        if application_path is not None:
            command.extend(["--application", str(application_path)])
        subprocess.Popen(
            command,
            close_fds=True,
            creationflags=creation_flags,
        )


class UpdateService:
    def __init__(
        self,
        *,
        current_version: str,
        updater_version: str,
        data_root: Path,
        updater_path: Path,
        fetcher: ManifestFetcher | None = None,
        launcher: UpdaterLauncher | None = None,
    ) -> None:
        self.current_version = current_version
        self.updater_version = updater_version
        self.data_root = data_root.resolve()
        self.updater_path = updater_path.resolve()
        self.update_root = self.data_root / "updates"
        self.status_path = self.update_root / "update-status.json"
        self.manifest_path = self.update_root / "available-manifest.json"
        self.imports_root = self.update_root / "imports"
        self.import_pointer_path = self.update_root / "available-import.json"
        self._fetcher = fetcher or GithubManifestFetcher()
        self._launcher = launcher or SubprocessUpdaterLauncher()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._status = self._load_status()
        self._application_path = self._load_import_application()

    def _load_status(self) -> UpdateStatus:
        try:
            payload = json.loads(self.status_path.read_text(encoding="utf-8"))
            status = UpdateStatus(**payload)
            if status.current_version != self.current_version:
                raise ValueError("status belongs to another application version")
            return status
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return UpdateStatus(
                state="idle",
                current_version=self.current_version,
                available_version=None,
                update_available=False,
                checked_at=None,
                error_code=None,
            )

    def _write_bytes_atomic(self, target: Path, content: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        temporary.write_bytes(content)
        os.replace(temporary, target)

    def _load_import_application(self) -> Path | None:
        if self._status.state != "available":
            return None
        try:
            payload = json.loads(self.import_pointer_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or set(payload) != {
                "application_file_name",
                "application_size",
                "import_id",
                "version",
            }:
                raise ValueError("update import pointer is invalid")
            import_id = payload["import_id"]
            if not isinstance(import_id, str):
                raise ValueError("update import pointer is invalid")
            root, manifest = self._load_import(import_id)
            application = manifest.application
            if (
                payload["application_file_name"] != application.file_name
                or payload["application_size"] != application.size
                or payload["version"] != manifest.version
                or manifest.version != self._status.available_version
            ):
                raise ValueError("update import pointer is stale")
            target = root / application.file_name
            if not target.is_file() or target.stat().st_size != application.size:
                raise ValueError("update import application is unavailable")
            return target
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.import_pointer_path.unlink(missing_ok=True)
            return None

    def _clear_import_pointer(self) -> None:
        self._application_path = None
        self.import_pointer_path.unlink(missing_ok=True)

    def _set_status(self, status: UpdateStatus) -> UpdateStatus:
        self._write_bytes_atomic(
            self.status_path,
            json.dumps(
                status.to_payload(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        self._status = status
        return status

    def status(self) -> UpdateStatus:
        with self._lock:
            return self._status

    def check(self) -> UpdateStatus:
        with self._lock:
            checked_at = datetime.now(UTC).isoformat()
            try:
                content = self._fetcher.fetch()
                manifest = parse_update_manifest(
                    content,
                    current_version="0.0.0",
                    updater_version=self.updater_version,
                )
                comparison = compare_versions(
                    manifest.version,
                    self.current_version,
                )
                if comparison < 0:
                    return self._set_status(
                        UpdateStatus(
                            state="failed",
                            current_version=self.current_version,
                            available_version=None,
                            update_available=False,
                            checked_at=checked_at,
                            error_code="update_downgrade_rejected",
                        )
                    )
                if comparison == 0:
                    return self._set_status(
                        UpdateStatus(
                            state="up_to_date",
                            current_version=self.current_version,
                            available_version=None,
                            update_available=False,
                            checked_at=checked_at,
                            error_code=None,
                        )
                    )
                self._write_bytes_atomic(self.manifest_path, content)
                self._clear_import_pointer()
                return self._set_status(
                    UpdateStatus(
                        state="available",
                        current_version=self.current_version,
                        available_version=manifest.version,
                        update_available=True,
                        checked_at=checked_at,
                        error_code=None,
                    )
                )
            except (OSError, UpdateManifestError, ValueError):
                return self._set_status(
                    UpdateStatus(
                        state="failed",
                        current_version=self.current_version,
                        available_version=None,
                        update_available=False,
                        checked_at=checked_at,
                        error_code="update_check_failed",
                    )
                )

    def create_import(self, content: bytes) -> UpdateImport:
        with self._lock:
            manifest = parse_update_manifest(
                content,
                current_version=self.current_version,
                updater_version=self.updater_version,
            )
            import_id = uuid4().hex
            root = self.imports_root / import_id
            root.mkdir(parents=True, exist_ok=False)
            self._write_bytes_atomic(root / "update-manifest.json", content)
            return UpdateImport(
                import_id=import_id,
                state="waiting_upload",
                version=manifest.version,
                application_file_name=manifest.application.file_name,
                application_size=manifest.application.size,
            )

    def _load_import(self, import_id: str) -> tuple[Path, UpdateManifest]:
        if (
            len(import_id) != 32
            or any(character not in "0123456789abcdef" for character in import_id)
        ):
            raise ValueError("update import id is invalid")
        root = (self.imports_root / import_id).resolve()
        if not root.is_relative_to(self.imports_root.resolve()) or not root.is_dir():
            raise ValueError("update import is unavailable")
        manifest_path = root / "update-manifest.json"
        manifest = parse_update_manifest(
            manifest_path.read_bytes(),
            current_version=self.current_version,
            updater_version=self.updater_version,
        )
        return root, manifest

    def _publish_import(
        self,
        *,
        root: Path,
        manifest: UpdateManifest,
        temporary: Path,
        size: int,
        digest: str,
    ) -> UpdateStatus:
        application = manifest.application
        if size != application.size or digest != application.sha256:
            raise ValueError("update import hash or size is invalid")
        target = root / application.file_name
        os.replace(temporary, target)
        manifest_path = root / "update-manifest.json"
        self._write_bytes_atomic(self.manifest_path, manifest_path.read_bytes())
        self._application_path = target
        self._write_bytes_atomic(
            self.import_pointer_path,
            json.dumps(
                {
                    "application_file_name": application.file_name,
                    "application_size": application.size,
                    "import_id": root.name,
                    "version": manifest.version,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        return self._set_status(
            UpdateStatus(
                state="available",
                current_version=self.current_version,
                available_version=manifest.version,
                update_available=True,
                checked_at=datetime.now(UTC).isoformat(),
                error_code=None,
            )
        )

    def upload_import(
        self,
        import_id: str,
        chunks: Iterable[bytes],
        *,
        file_name: str | None = None,
    ) -> UpdateStatus:
        with self._lock:
            root, manifest = self._load_import(import_id)
            if file_name is not None and file_name != manifest.application.file_name:
                raise ValueError("update import file name is invalid")
            target = root / manifest.application.file_name
            temporary = target.with_name(f".{target.name}.upload")
            digest = hashlib.sha256()
            size = 0
            try:
                with temporary.open("xb") as handle:
                    for raw in chunks:
                        size += len(raw)
                        if size > manifest.application.size:
                            raise ValueError("update import size is invalid")
                        digest.update(raw)
                        handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                return self._publish_import(
                    root=root,
                    manifest=manifest,
                    temporary=temporary,
                    size=size,
                    digest=digest.hexdigest(),
                )
            except Exception:
                temporary.unlink(missing_ok=True)
                target.unlink(missing_ok=True)
                raise

    async def upload_import_async(
        self,
        import_id: str,
        chunks: AsyncIterable[bytes],
        *,
        file_name: str,
    ) -> UpdateStatus:
        with self._lock:
            root, manifest = self._load_import(import_id)
            if file_name != manifest.application.file_name:
                raise ValueError("update import file name is invalid")
            target = root / manifest.application.file_name
            temporary = target.with_name(f".{target.name}.upload")
            digest = hashlib.sha256()
            size = 0
            try:
                with temporary.open("xb") as handle:
                    async for raw in chunks:
                        size += len(raw)
                        if size > manifest.application.size:
                            raise ValueError("update import size is invalid")
                        digest.update(raw)
                        handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                return self._publish_import(
                    root=root,
                    manifest=manifest,
                    temporary=temporary,
                    size=size,
                    digest=digest.hexdigest(),
                )
            except Exception:
                temporary.unlink(missing_ok=True)
                target.unlink(missing_ok=True)
                raise
    def install(self, *, active_job_count: int, process_id: int) -> UpdateStatus:
        with self._lock:
            if active_job_count:
                raise UpdateInstallBlocked("active work blocks software update")
            if self._status.state != "available" or not self.manifest_path.is_file():
                raise UpdateInstallBlocked("an available verified update is required")
            if not self.updater_path.is_file():
                raise UpdateInstallBlocked("the update program is unavailable")
            self._launcher.launch(
                updater_path=self.updater_path,
                manifest_path=self.manifest_path,
                data_root=self.data_root,
                process_id=process_id,
                application_path=self._application_path,
            )
            return self._set_status(
                UpdateStatus(
                    state="installing",
                    current_version=self.current_version,
                    available_version=self._status.available_version,
                    update_available=True,
                    checked_at=self._status.checked_at,
                    error_code=None,
                )
            )

    def start_periodic_checks(self, *, interval_seconds: float = 6 * 60 * 60) -> None:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._stop_event.clear()

            def run() -> None:
                self.check()
                while not self._stop_event.wait(interval_seconds):
                    self.check()

            self._worker = threading.Thread(
                target=run,
                name="dahe-update-check",
                daemon=True,
            )
            self._worker.start()

    def stop_periodic_checks(self) -> None:
        self._stop_event.set()
