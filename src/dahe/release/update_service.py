from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Protocol, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from dahe.release.update_manifest import (
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
    ) -> None:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.Popen(
            [
                str(updater_path),
                "install",
                "--manifest",
                str(manifest_path),
                "--data-root",
                str(data_root),
                "--wait-pid",
                str(process_id),
            ],
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
        self._fetcher = fetcher or GithubManifestFetcher()
        self._launcher = launcher or SubprocessUpdaterLauncher()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._status = self._load_status()

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
