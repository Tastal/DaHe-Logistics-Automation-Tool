from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
import sys
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from dahe.adapters.ocr.runtime_layout import (
    activate_flat_composition,
    write_flat_composition_manifest,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.release.gpu_addon import GpuAddonInstallResult, GpuAddonStatus
from dahe.release.launcher import (
    VersionPointer,
    compute_resource_sha256,
    read_version_pointer,
    write_version_pointer_atomic,
)
from dahe.release.update_manifest import ReleaseAsset
from dahe.release.updater import (
    CpuRuntimeBootstrapError,
    GithubAssetDownloader,
    UpdateInstaller,
    UpdaterError,
    bootstrap_cpu_runtime,
    main,
    remove_installed_cpu_runtime,
    safe_extract_application_zip,
)

PROJECT_ROOT = Path(__file__).parents[3]
REVISION = "0042_daily_capture_range"
OLD_VERSION = "1.1.3"
NEW_VERSION = "1.1.4"


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
    old_root = install_root / "versions" / OLD_VERSION
    old_resource = _version_root(old_root, OLD_VERSION, "a" * 40)
    write_version_pointer_atomic(
        install_root,
        VersionPointer(
            version=OLD_VERSION,
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

    assert read_version_pointer(install_root).version == OLD_VERSION
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


def _flat_cpu_archive(
    tmp_path: Path,
    *,
    generation_id: str = "a" * 32,
) -> tuple[Path, Path]:
    runtime = tmp_path / "flat-runtime"
    cpu = runtime / "c"
    cpu.mkdir(parents=True)
    (cpu / "runtime-installation.json").write_text("{}", encoding="utf-8")
    models = runtime / "m" / "official_models"
    models.mkdir(parents=True)
    (models / "model-manifest.json").write_text("{}", encoding="utf-8")
    qualification = runtime / "q" / "qualification.json"
    qualification.parent.mkdir(parents=True)
    qualification.write_text(
        json.dumps({"reports": [{"runtime_kind": "cpu"}]}),
        encoding="utf-8",
    )
    write_flat_composition_manifest(
        runtime_root=runtime,
        generation_id=generation_id,
    )
    activate_flat_composition(
        runtime_root=runtime,
        generation_id=generation_id,
    )
    files = sorted(path for path in runtime.rglob("*") if path.is_file())
    archive = tmp_path / "ocr-cpu.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            bundle.write(path, path.relative_to(runtime).as_posix())
    relative_files = [path.relative_to(runtime) for path in files]
    directories = {
        parent
        for path in relative_files
        for parent in path.parents
        if parent != Path(".")
    }
    pointer = runtime / "active-composition.json"
    manifest = tmp_path / "cpu-runtime-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "layout": "flat_v2",
                "archive_file_name": "ocr-cpu.zip",
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "archive_size": archive.stat().st_size,
                "entry_count": len(files),
                "uncompressed_size": sum(path.stat().st_size for path in files),
                "active_composition_sha256": hashlib.sha256(
                    pointer.read_bytes()
                ).hexdigest(),
                "maximum_relative_file_path": max(
                    len(path.as_posix()) for path in relative_files
                ),
                "maximum_relative_directory_path": max(
                    (len(path.as_posix()) for path in directories),
                    default=0,
                ),
            }
        ),
        encoding="utf-8",
    )
    return archive, manifest


def test_flat_cpu_runtime_bootstrap_installs_atomically_with_short_staging(
    tmp_path: Path,
) -> None:
    archive, manifest = _flat_cpu_archive(tmp_path)
    target = tmp_path / "runtimes" / "ocr-cpu"

    bootstrap_cpu_runtime(archive=archive, manifest_path=manifest, target=target)

    assert (target / "c" / "runtime-installation.json").is_file()
    assert not tuple(target.parent.glob(".c-*"))


def test_cpu_runtime_bootstrap_reinstalls_valid_but_different_composition(
    tmp_path: Path,
) -> None:
    old_archive, old_manifest = _flat_cpu_archive(
        tmp_path / "old",
        generation_id="a" * 32,
    )
    new_archive, new_manifest = _flat_cpu_archive(
        tmp_path / "new",
        generation_id="b" * 32,
    )
    target = tmp_path / "runtimes" / "ocr-cpu"

    bootstrap_cpu_runtime(
        archive=old_archive,
        manifest_path=old_manifest,
        target=target,
    )
    bootstrap_cpu_runtime(
        archive=new_archive,
        manifest_path=new_manifest,
        target=target,
    )

    pointer = target / "active-composition.json"
    assert json.loads(pointer.read_text(encoding="utf-8"))["generation_id"] == (
        "b" * 32
    )
    assert not tuple(target.parent.glob(".c-old-*"))


def test_cpu_runtime_failed_upgrade_restores_previous_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_archive, old_manifest = _flat_cpu_archive(
        tmp_path / "old",
        generation_id="a" * 32,
    )
    new_archive, new_manifest = _flat_cpu_archive(
        tmp_path / "new",
        generation_id="b" * 32,
    )
    target = tmp_path / "runtimes" / "ocr-cpu"
    bootstrap_cpu_runtime(
        archive=old_archive,
        manifest_path=old_manifest,
        target=target,
    )
    old_pointer = (target / "active-composition.json").read_bytes()
    from dahe.release import updater as updater_module

    original_resolve = updater_module.resolve_active_composition
    call_count = 0

    def fail_after_activation(*args: object, **kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            raise RuntimeError("simulated activated composition failure")
        return original_resolve(*args, **kwargs)

    monkeypatch.setattr(
        "dahe.release.updater.resolve_active_composition",
        fail_after_activation,
    )

    with pytest.raises(CpuRuntimeBootstrapError) as failure:
        bootstrap_cpu_runtime(
            archive=new_archive,
            manifest_path=new_manifest,
            target=target,
        )

    assert failure.value.error_code == "cpu_runtime_composition_invalid"
    assert (target / "active-composition.json").read_bytes() == old_pointer
    assert not tuple(target.parent.glob(".c-old-*"))


def test_cpu_runtime_bootstrap_rejects_invalid_existing_composition(
    tmp_path: Path,
) -> None:
    archive, manifest = _flat_cpu_archive(tmp_path)
    target = tmp_path / "runtimes" / "ocr-cpu"

    bootstrap_cpu_runtime(archive=archive, manifest_path=manifest, target=target)

    pointer = target / "active-composition.json"
    pointer.write_text("{", encoding="utf-8")
    with pytest.raises(CpuRuntimeBootstrapError) as failure:
        bootstrap_cpu_runtime(
            archive=archive,
            manifest_path=manifest,
            target=target,
        )
    assert failure.value.error_code == "cpu_runtime_target_conflict"
    assert failure.value.stage == "target"


@pytest.mark.parametrize(
    ("winerror", "expected_code"),
    (
        (206, "cpu_runtime_path_unsupported"),
        (2, "cpu_runtime_io_blocked"),
    ),
)
def test_cpu_runtime_bootstrap_reports_safe_extract_failures_and_cleans_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    winerror: int,
    expected_code: str,
) -> None:
    archive, manifest = _flat_cpu_archive(tmp_path)
    target = tmp_path / "runtimes" / "ocr-cpu"

    def fail_copy(*_args: object, **_kwargs: object) -> None:
        error = OSError("simulated Windows extraction failure")
        error.winerror = winerror
        raise error

    monkeypatch.setattr("dahe.release.updater.shutil.copyfileobj", fail_copy)

    with pytest.raises(CpuRuntimeBootstrapError) as failure:
        bootstrap_cpu_runtime(archive=archive, manifest_path=manifest, target=target)
    assert failure.value.error_code == expected_code
    assert failure.value.stage == "extract"
    assert failure.value.winerror == winerror
    assert not target.exists()
    assert not tuple(target.parent.glob(".c-*"))


def test_cpu_runtime_bootstrap_reports_disk_stage_and_can_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive, manifest = _flat_cpu_archive(tmp_path)
    target = tmp_path / "runtimes" / "ocr-cpu"
    actual = shutil.disk_usage(tmp_path)
    results = iter(
        (
            type(actual)(actual.total, actual.used, 0),
            actual,
        )
    )
    monkeypatch.setattr(
        "dahe.release.updater.shutil.disk_usage",
        lambda _path: next(results),
    )

    with pytest.raises(CpuRuntimeBootstrapError) as failure:
        bootstrap_cpu_runtime(archive=archive, manifest_path=manifest, target=target)
    assert failure.value.error_code == "cpu_runtime_insufficient_space"
    assert failure.value.stage == "disk_preflight"
    assert not target.exists()

    bootstrap_cpu_runtime(archive=archive, manifest_path=manifest, target=target)
    assert (target / "active-composition.json").is_file()


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


def test_gpu_status_cli_returns_authoritative_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "dahe.release.updater.gpu_addon_status",
        lambda _root: GpuAddonStatus(
            state="active",
            gpu_qualified=True,
            primary_runtime="gpu",
            cpu_fallback_available=True,
            package_version="1.1.3",
            diagnostic_code=None,
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["DaHeUpdater", "gpu-status", "--install-root", str(tmp_path), "--json"],
    )

    with pytest.raises(SystemExit) as result:
        main()

    assert result.value.code == 0
    assert json.loads(capsys.readouterr().out)["primary_runtime"] == "gpu"


def test_gpu_install_cli_calls_addon_installer_and_returns_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls: list[tuple[Path, Path, Path]] = []

    def install_gpu(
        *,
        manifest_path: Path,
        package_path: Path,
        install_root: Path,
    ) -> GpuAddonInstallResult:
        calls.append((manifest_path, package_path, install_root))
        return GpuAddonInstallResult(
            state="active",
            package_version="1.1.3",
            primary_runtime="gpu",
            gpu_qualified=True,
            cpu_fallback_available=True,
            diagnostic_code=None,
        )

    manifest = tmp_path / "update-manifest.json"
    package = tmp_path / "gpu.zip"
    monkeypatch.setattr("dahe.release.updater.install_gpu_addon", install_gpu)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "DaHeUpdater",
            "gpu-install",
            "--manifest",
            str(manifest),
            "--package",
            str(package),
            "--install-root",
            str(tmp_path),
            "--json",
        ],
    )

    with pytest.raises(SystemExit) as result:
        main()

    assert result.value.code == 0
    assert calls == [(manifest, package, tmp_path)]
    assert json.loads(capsys.readouterr().out)["gpu_qualified"] is True
