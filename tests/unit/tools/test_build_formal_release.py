from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from tools.build_formal_release import (
    GITHUB_RELEASE_ASSET_LIMIT_BYTES,
    MINIMUM_SCHEMA_REVISION,
    _copy_browser_runtime,
    _copy_formal_pipeline_sources,
    _copy_source_tree,
    _copy_updater_binaries,
    _cpu_only_qualification,
    _package_cpu_runtime_archive,
    _require_github_release_asset_size,
    _require_release_tag,
    _run_pyinstaller,
    _source_application_version,
    _stage_installer_payload,
    _validate_cpu_runtime_legacy_path_budget,
)


def _worker_source_sha256(source_root: Path) -> str:
    worker_root = source_root / "browser-runtime" / "src" / "dahe_browser_worker"
    digest = hashlib.sha256()
    for path in sorted(worker_root.rglob("*.py")):
        digest.update(path.relative_to(worker_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _embed_archive(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("python.exe", b"python")
        bundle.writestr("python3.dll", b"python3")
        bundle.writestr("python312.dll", b"python312")
        bundle.writestr("python312.zip", b"stdlib")
        bundle.writestr("python312._pth", "python312.zip\n.\n#import site\n")
    return path


def test_formal_release_reads_version_from_its_source_checkout(tmp_path: Path) -> None:
    package = tmp_path / "source" / "src" / "dahe"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        '"""Package."""\n\n__version__ = "1.1.0"\n',
        encoding="utf-8",
    )

    assert _source_application_version(tmp_path / "source") == "1.1.0"
    assert MINIMUM_SCHEMA_REVISION == "0039_network_batch_default"


def test_updater_is_carried_by_stable_and_versioned_locations(tmp_path: Path) -> None:
    updater = tmp_path / "build" / "DaHeUpdater.exe"
    updater.parent.mkdir()
    updater.write_bytes(b"versioned updater")
    payload = tmp_path / "payload"
    version_root = payload / "versions" / "1.1.0"
    version_root.mkdir(parents=True)

    _copy_updater_binaries(updater, payload=payload, version_root=version_root)

    assert (payload / "DaHeUpdater.exe").read_bytes() == b"versioned updater"
    assert (version_root / "DaHeUpdater.exe").read_bytes() == b"versioned updater"


def test_formal_release_requires_the_exact_version_tag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_git(_root: Path, *arguments: str) -> str:
        calls.append(arguments)
        return "v1.1.0"

    monkeypatch.setattr("tools.build_formal_release._git", fake_git)

    _require_release_tag(tmp_path, "1.1.0")

    assert calls == [
        ("describe", "--tags", "--exact-match", "--match", "v1.1.0", "HEAD")
    ]


def test_formal_release_rejects_assets_at_or_above_two_gib(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    asset = tmp_path / "asset.zip"
    asset.write_bytes(b"small")

    _require_github_release_asset_size(asset)
    monkeypatch.setattr(
        Path,
        "stat",
        lambda _path: type(
            "StatResult",
            (),
            {"st_size": GITHUB_RELEASE_ASSET_LIMIT_BYTES},
        )(),
    )

    with pytest.raises(RuntimeError, match="smaller than 2 GiB"):
        _require_github_release_asset_size(asset)


def test_browser_runtime_must_match_formal_release_source(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    worker = (
        source_root
        / "browser-runtime"
        / "src"
        / "dahe_browser_worker"
        / "engine.py"
    )
    worker.parent.mkdir(parents=True)
    worker.write_text("WORKER_VERSION = 2\n", encoding="utf-8")
    lock = source_root / "browser-runtime" / "requirements.lock"
    lock.write_text("playwright==1.61.0\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    site_packages = runtime / "python" / "Lib" / "site-packages"
    worker_package = site_packages / "dahe_browser_worker"
    worker_package.mkdir(parents=True)
    (worker_package / "__init__.py").write_text("OLD = True\n", encoding="utf-8")
    smoke_profile = runtime / "browsers" / "smoke-msedge" / "Default" / "Network"
    smoke_profile.mkdir(parents=True)
    (smoke_profile / "Cookies").write_bytes(b"must-not-ship")
    manifest = {
        "schema_version": 1,
        "runtime_kind": "browser",
        "dependency_lock": "browser-runtime/requirements.lock",
        "dependency_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "worker_source_sha256": "0" * 64,
        "packages": ["playwright==1.61.0"],
        "chromium_provisioned": False,
        "smoke_selected_browser": "msedge",
    }
    (runtime / "runtime-installation.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="does not match formal release source"):
        _copy_browser_runtime(
            runtime,
            tmp_path / "rejected",
            source_root=source_root,
            embed_archive=_embed_archive(tmp_path / "python-embed.zip"),
            run_smoke=False,
        )

    manifest["worker_source_sha256"] = _worker_source_sha256(source_root)
    (runtime / "runtime-installation.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    _copy_browser_runtime(
        runtime,
        tmp_path / "accepted",
        source_root=source_root,
        embed_archive=tmp_path / "python-embed.zip",
        run_smoke=False,
    )

    copied = json.loads(
        (tmp_path / "accepted" / "runtime-installation.json").read_text(
            encoding="utf-8"
        )
    )
    assert copied["worker_source_sha256"] == _worker_source_sha256(source_root)
    assert copied["portable_python"]["layout"] == "portable_embed"
    assert copied["portable_python"]["interpreter"] == "python.exe"
    assert (tmp_path / "accepted" / "python" / "python.exe").is_file()
    assert not (tmp_path / "accepted" / "python" / "Scripts").exists()
    assert not tuple((tmp_path / "accepted").rglob("direct_url.json"))
    assert copied["browser_store_packaged"] is False
    assert not (tmp_path / "accepted" / "browsers").exists()
    assert not tuple((tmp_path / "accepted").rglob("Cookies"))


def test_formal_source_copy_excludes_generated_bytecode(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    cache = source / "__pycache__"
    cache.mkdir()
    (cache / "module.cpython-312.pyc").write_bytes(b"developer path")

    target = tmp_path / "target"
    _copy_source_tree(source, target)

    assert (target / "module.py").is_file()
    assert not (target / "__pycache__").exists()
    assert not tuple(target.rglob("*.pyc"))


def test_cpu_only_qualification_removes_gpu_comparison_evidence() -> None:
    cpu_report = {"runtime_kind": "cpu", "status": "qualified", "profile_id": "cpu"}
    gpu_report = {"runtime_kind": "gpu", "status": "qualified", "profile_id": "gpu"}

    assert _cpu_only_qualification(
        {
            "schema_version": 2,
            "reports": [cpu_report, gpu_report],
            "difference_report": {"all_critical_fields_match": True},
        }
    ) == {
        "schema_version": 2,
        "reports": [cpu_report],
        "difference_report": {
            "sample_count": 0,
            "critical_match_count": 0,
            "all_critical_fields_match": True,
            "items": [],
        },
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 1, "reports": []},
        {"schema_version": 2, "reports": []},
        {
            "schema_version": 2,
            "reports": [
                {"runtime_kind": "cpu", "status": "failed"},
                {"runtime_kind": "gpu", "status": "qualified"},
            ],
        },
        {
            "schema_version": 2,
            "reports": [
                {"runtime_kind": "cpu", "status": "qualified"},
                {"runtime_kind": "cpu", "status": "qualified"},
            ],
        },
    ],
)
def test_cpu_only_qualification_rejects_unbound_cpu_evidence(
    payload: dict[str, object],
) -> None:
    with pytest.raises(RuntimeError, match="qualified CPU report"):
        _cpu_only_qualification(payload)


def test_installer_payload_is_moved_to_short_staging_root(tmp_path: Path) -> None:
    payload = tmp_path / "release-output" / ".build" / "installer-payload"
    payload.mkdir(parents=True)
    (payload / "DaHeLauncher.exe").write_bytes(b"launcher")
    staging_root = tmp_path / "short"
    staging_root.mkdir()

    staged = _stage_installer_payload(payload, staging_root)

    assert staged == staging_root / "p"
    assert not payload.exists()
    assert (staged / "DaHeLauncher.exe").read_bytes() == b"launcher"


def test_formal_pipeline_root_sources_are_present_in_release_payload(
    monkeypatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    version = tmp_path / "version"
    files = {
        "alembic.ini": b"alembic",
        "tools/formal.py": b"tool",
        "ocr-runtime/model-spec.json": b"model",
        "application/pipeline.py": b"pipeline",
    }
    for logical_path, content in files.items():
        project_relative = (
            logical_path == "alembic.ini"
            or logical_path.startswith("tools/")
            or logical_path.startswith("ocr-runtime/")
        )
        source_path = (
            source / logical_path
            if project_relative
            else source / "src" / "dahe" / logical_path
        )
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(content)
        if logical_path != "tools/formal.py":
            target_path = (
                version / logical_path
                if project_relative
                else version / "src" / "dahe" / logical_path
            )
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(content)
    monkeypatch.setattr(
        "tools.build_formal_release.TEMPLATE_PIPELINE_SOURCE_MANIFEST",
        tuple(files),
    )

    _copy_formal_pipeline_sources(source, version)

    assert (version / "tools" / "formal.py").read_bytes() == b"tool"


def test_cpu_runtime_archive_has_bounded_install_manifest(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    pointer = runtime / "active-composition.json"
    pointer.write_bytes(b"pointer")
    nested = runtime / "c" / "runtime.bin"
    nested.parent.mkdir()
    nested.write_bytes(b"runtime")
    archive = tmp_path / "payload" / "runtimes" / "ocr-cpu.zip"
    manifest = archive.with_name("cpu-runtime-manifest.json")
    archive.parent.mkdir(parents=True)

    _package_cpu_runtime_archive(runtime, archive, manifest)

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["layout"] == "flat_v2"
    assert payload["archive_file_name"] == "ocr-cpu.zip"
    assert payload["entry_count"] == 2
    assert payload["uncompressed_size"] == len(b"pointerruntime")
    assert payload["active_composition_sha256"] == hashlib.sha256(b"pointer").hexdigest()
    assert payload["maximum_relative_file_path"] == len(
        "active-composition.json"
    )


def test_legacy_deep_cpu_runtime_fails_default_windows_path_budget(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    deep = (
        runtime
        / "generations"
        / ("a" * 32)
        / "ocr-cpu"
        / "Lib"
        / "site-packages"
        / ("nested-package" * 7)
        / "runtime.py"
    )
    deep.parent.mkdir(parents=True)
    deep.write_bytes(b"runtime")

    with pytest.raises(RuntimeError, match="path budget"):
        _validate_cpu_runtime_legacy_path_budget(
            files=[deep],
            runtime_root=runtime,
        )


def test_main_application_uses_hidden_launcher_compatible_console_onedir(
    monkeypatch,
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    entrypoint = source_root / "tools" / "entrypoints" / "dahe_app.py"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("", encoding="utf-8")
    dist = tmp_path / "dist"
    output = dist / "DaHeApp"

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        output.mkdir(parents=True)
        (output / "DaHeApp.exe").write_bytes(b"frozen")
        assert "--onedir" in command
        assert "--onefile" not in command
        assert "--noupx" in command
        assert "--console" in command
        assert "--windowed" not in command
        assert command[command.index("--paths") + 1] == str(source_root / "src")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert (
        _run_pyinstaller(
            source_root=source_root,
            entrypoint=entrypoint,
            name="DaHeApp",
            dist_root=dist,
            work_root=tmp_path / "work",
            one_file=False,
            windowed=False,
        )
        == output
    )


def test_small_stable_updater_is_separate_onefile(
    monkeypatch,
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    entrypoint = source_root / "tools" / "entrypoints" / "dahe_updater.py"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("", encoding="utf-8")
    dist = tmp_path / "dist"
    output = dist / "DaHeUpdater.exe"

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        output.parent.mkdir(parents=True)
        output.write_bytes(b"updater")
        assert "--onefile" in command
        assert "--onedir" not in command
        assert "--noupx" in command
        assert "--windowed" in command
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert (
        _run_pyinstaller(
            source_root=source_root,
            entrypoint=entrypoint,
            name="DaHeUpdater",
            dist_root=dist,
            work_root=tmp_path / "work",
            one_file=True,
        )
        == output
    )
