from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from dahe import __version__
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.release.launcher import (
    VersionPointer,
    compute_resource_sha256,
    read_version_pointer,
    write_version_pointer_atomic,
)
from dahe.release.update_manifest import ReleaseAsset
from dahe.release.updater import (
    GithubAssetDownloader,
    UpdateInstaller,
    UpdaterError,
    bootstrap_cpu_runtime,
    remove_installed_cpu_runtime,
    safe_extract_application_zip,
)

PROJECT_ROOT = Path(__file__).parents[3]
REVISION = "0041_contract_subject_scope"
NEW_VERSION = "1.1.1"


class _DownloadResponse(io.BytesIO):
    def __init__(self, content: bytes, *, status: int, headers: dict[str, str]) -> None:
        super().__init__(content)
        self.status = status
        self.headers = headers

    def __enter__(self) -> _DownloadResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class _DownloadOpener:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests: list[object] = []

    def open(self, request: object, *, timeout: int) -> _DownloadResponse:
        assert timeout == 30
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        assert isinstance(response, _DownloadResponse)
        return response


def _asset(content: bytes) -> ReleaseAsset:
    return ReleaseAsset(
        file_name="DaHe-Logistics-Automation-Tool-1.1.1-win-x64.zip",
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        url=(
            "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
            "releases/download/v1.1.1/"
            "DaHe-Logistics-Automation-Tool-1.1.1-win-x64.zip"
        ),
    )


def _seed_partial(
    *,
    destination: Path,
    asset: ReleaseAsset,
    content: bytes,
) -> Path:
    partial = destination.with_name(f"{destination.name}.partial")
    partial.write_bytes(content)
    partial.with_name(f"{partial.name}.json").write_text(
        json.dumps(
            {
                "file_name": asset.file_name,
                "sha256": asset.sha256,
                "size": asset.size,
                "url": asset.url,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return partial


def test_asset_download_resumes_a_persistent_partial_file(tmp_path: Path) -> None:
    content = b"abcdefghij"
    destination = tmp_path / "application.zip"
    asset = _asset(content)
    partial = _seed_partial(
        destination=destination,
        asset=asset,
        content=content[:4],
    )
    opener = _DownloadOpener(
        [
            _DownloadResponse(
                content[4:],
                status=206,
                headers={
                    "Content-Range": "bytes 4-9/10",
                    "Content-Length": "6",
                },
            )
        ]
    )
    downloader = GithubAssetDownloader(
        opener=opener,
        sleep=lambda _seconds: None,
    )

    downloader.download(asset, destination)

    assert destination.read_bytes() == content
    assert not partial.exists()
    assert not partial.with_name(f"{partial.name}.json").exists()
    request = opener.requests[0]
    assert request.get_header("Range") == "bytes=4-"


def test_asset_download_restarts_when_server_ignores_range(tmp_path: Path) -> None:
    content = b"abcdefghij"
    destination = tmp_path / "application.zip"
    asset = _asset(content)
    _seed_partial(destination=destination, asset=asset, content=content[:4])
    opener = _DownloadOpener(
        [
            _DownloadResponse(
                content,
                status=200,
                headers={"Content-Length": "10"},
            )
        ]
    )

    GithubAssetDownloader(opener=opener, sleep=lambda _seconds: None).download(
        asset,
        destination,
    )

    assert destination.read_bytes() == content


def test_asset_download_rejects_wrong_content_range_and_keeps_partial(
    tmp_path: Path,
) -> None:
    content = b"abcdefghij"
    destination = tmp_path / "application.zip"
    asset = _asset(content)
    partial = _seed_partial(
        destination=destination,
        asset=asset,
        content=content[:4],
    )
    opener = _DownloadOpener(
        [
            _DownloadResponse(
                content[4:],
                status=206,
                headers={"Content-Range": "bytes 3-8/10"},
            )
            for _ in range(4)
        ]
    )

    with pytest.raises(UpdaterError, match="range"):
        GithubAssetDownloader(opener=opener, sleep=lambda _seconds: None).download(
            asset,
            destination,
        )

    assert partial.read_bytes() == content[:4]


def test_asset_download_discards_partial_from_another_manifest(
    tmp_path: Path,
) -> None:
    content = b"abcdefghij"
    destination = tmp_path / "application.zip"
    stale_asset = _asset(b"0123456789")
    partial = _seed_partial(
        destination=destination,
        asset=stale_asset,
        content=b"0123",
    )
    opener = _DownloadOpener(
        [
            _DownloadResponse(
                content,
                status=200,
                headers={"Content-Length": "10"},
            )
        ]
    )

    GithubAssetDownloader(opener=opener, sleep=lambda _seconds: None).download(
        _asset(content),
        destination,
    )

    assert destination.read_bytes() == content
    assert opener.requests[0].get_header("Range") is None
    assert not partial.exists()
    assert not partial.with_name(f"{partial.name}.json").exists()


def test_asset_download_hash_error_removes_untrusted_partial(tmp_path: Path) -> None:
    expected = b"abcdefghij"
    destination = tmp_path / "application.zip"
    opener = _DownloadOpener(
        [
            _DownloadResponse(
                b"0123456789",
                status=200,
                headers={"Content-Length": "10"},
            )
        ]
    )

    with pytest.raises(UpdaterError, match="hash"):
        GithubAssetDownloader(opener=opener, sleep=lambda _seconds: None).download(
            _asset(expected),
            destination,
        )

    assert not destination.with_name(f"{destination.name}.partial").exists()


def _copy_migrations(target: Path) -> None:
    shutil.copy2(PROJECT_ROOT / "alembic.ini", target / "alembic.ini")
    source = PROJECT_ROOT / "src" / "dahe" / "adapters" / "sqlite" / "migrations"
    destination = target / "src" / "dahe" / "adapters" / "sqlite" / "migrations"
    shutil.copytree(source, destination)


def _version_root(root: Path, version: str, commit: str) -> str:
    root.mkdir(parents=True)
    (root / "DaHeApp.exe").write_bytes(f"app-{version}".encode())
    _copy_migrations(root)
    resource = compute_resource_sha256(root)
    (root / "release-identity.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "application_version": version,
                "build_git_commit": commit,
                "resource_sha256": resource,
            }
        ),
        encoding="utf-8",
    )
    return resource


def _setup(tmp_path: Path) -> tuple[Path, Path, Path, bytes]:
    install_root = tmp_path / "install"
    old_root = install_root / "versions" / __version__
    old_resource = _version_root(old_root, __version__, "a" * 40)
    write_version_pointer_atomic(
        install_root,
        VersionPointer(
            version=__version__,
            build_git_commit="a" * 40,
            resource_sha256=old_resource,
            schema_revision=REVISION,
        ),
    )
    (install_root / "DaHeLauncher.exe").write_bytes(b"launcher")
    data_root = tmp_path / "data"
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id="updater-test",
    )
    runtime.close()

    source = tmp_path / "new-version"
    new_resource = _version_root(source, NEW_VERSION, "b" * 40)
    archive = tmp_path / "application.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(source).as_posix())
    archive_content = archive.read_bytes()
    application_name = (
        f"DaHe-Logistics-Automation-Tool-{NEW_VERSION}-win-x64.zip"
    )
    gpu_name = (
        f"DaHe-Logistics-Automation-Tool-{NEW_VERSION}-gpu-addon-win-x64.zip"
    )
    manifest = {
        "schema_version": 1,
        "repository": "Tastal/DaHe-Logistics-Automation-Tool",
        "version": NEW_VERSION,
        "release_tag": f"v{NEW_VERSION}",
        "build_git_commit": "b" * 40,
        "application": {
            "file_name": application_name,
            "sha256": hashlib.sha256(archive_content).hexdigest(),
            "size": len(archive_content),
            "url": (
                "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                f"releases/download/v{NEW_VERSION}/{application_name}"
            ),
        },
        "gpu_addon": {
            "file_name": gpu_name,
            "sha256": "c" * 64,
            "size": 1,
            "url": (
                "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                f"releases/download/v{NEW_VERSION}/{gpu_name}"
            ),
        },
        "minimum_schema_revision": REVISION,
        "target_schema_revision": REVISION,
        "alembic_revision": REVISION,
        "minimum_updater_version": "1.0.0",
        "resource_sha256": new_resource,
    }
    manifest_path = tmp_path / "update-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return install_root, data_root, manifest_path, archive_content


class Downloader:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def download(self, _asset: object, destination: Path) -> None:
        destination.write_bytes(self.content)


def test_update_installs_to_a_new_version_and_switches_atomically(
    tmp_path: Path,
) -> None:
    install_root, data_root, manifest_path, archive = _setup(tmp_path)
    installer = UpdateInstaller(
        install_root=install_root,
        data_root=data_root,
        downloader=Downloader(archive),
        process_waiter=lambda _pid: True,
        launch_and_wait=lambda _launcher, _root: True,
    )

    result = installer.install(manifest_path=manifest_path, wait_pid=123)

    assert result.state == "succeeded"
    assert read_version_pointer(install_root).version == NEW_VERSION
    assert (install_root / "versions" / NEW_VERSION / "DaHeApp.exe").is_file()


def test_readiness_failure_restores_pointer_and_database(tmp_path: Path) -> None:
    install_root, data_root, manifest_path, archive = _setup(tmp_path)
    database_path = data_root / "database" / "dahe.sqlite3"
    with closing(sqlite3.connect(database_path)) as database:
        database.execute("CREATE TABLE preserved(value TEXT)")
        database.execute("INSERT INTO preserved VALUES ('yes')")
        database.commit()
    launch_results = iter((False, True))
    installer = UpdateInstaller(
        install_root=install_root,
        data_root=data_root,
        downloader=Downloader(archive),
        process_waiter=lambda _pid: True,
        launch_and_wait=lambda _launcher, _root: next(launch_results),
    )

    with pytest.raises(UpdaterError, match="readiness"):
        installer.install(manifest_path=manifest_path, wait_pid=123)

    assert read_version_pointer(install_root).version == __version__
    with closing(sqlite3.connect(database_path)) as database:
        assert database.execute("SELECT value FROM preserved").fetchone() == ("yes",)
    assert json.loads(installer.state_path.read_text())["state"] == "failed"


def test_archive_path_traversal_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../outside.exe", b"unsafe")

    with pytest.raises(UpdaterError, match="unsafe"):
        safe_extract_application_zip(archive, tmp_path / "extracted")
    assert not (tmp_path / "outside.exe").exists()


def test_cpu_runtime_bootstrap_verifies_manifest_before_atomic_install(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pointer = b'{"schema_version":1}'
    archive = tmp_path / "ocr-cpu.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("active-composition.json", pointer)
    manifest = tmp_path / "cpu-runtime-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "archive_file_name": "ocr-cpu.zip",
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "archive_size": archive.stat().st_size,
                "entry_count": 1,
                "uncompressed_size": len(pointer),
                "active_composition_sha256": hashlib.sha256(pointer).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "dahe.release.updater.resolve_active_composition",
        lambda *_args, **_kwargs: object(),
    )
    target = tmp_path / "runtimes" / "ocr-cpu"

    bootstrap_cpu_runtime(archive=archive, manifest_path=manifest, target=target)

    assert (target / "active-composition.json").read_bytes() == pointer


def test_cpu_runtime_bootstrap_rejects_archive_hash_mismatch(tmp_path: Path) -> None:
    archive = tmp_path / "ocr-cpu.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("active-composition.json", b"{}")
    manifest = tmp_path / "cpu-runtime-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "archive_file_name": "ocr-cpu.zip",
                "archive_sha256": "0" * 64,
                "archive_size": archive.stat().st_size,
                "entry_count": 1,
                "uncompressed_size": 2,
                "active_composition_sha256": hashlib.sha256(b"{}").hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    target = tmp_path / "runtimes" / "ocr-cpu"

    with pytest.raises(UpdaterError, match="hash"):
        bootstrap_cpu_runtime(archive=archive, manifest_path=manifest, target=target)
    assert not target.exists()


def test_remove_installed_cpu_runtime_handles_deep_program_paths(tmp_path: Path) -> None:
    install_root = tmp_path / "install"
    runtime = install_root / "runtimes" / "ocr-cpu"
    deep = runtime
    while len(str(deep / "runtime.pyc")) <= 280:
        deep /= "long-package-directory"
    deep.mkdir(parents=True)
    (deep / "runtime.pyc").write_bytes(b"cache")

    remove_installed_cpu_runtime(install_root)

    assert not runtime.exists()
    assert install_root.exists()
