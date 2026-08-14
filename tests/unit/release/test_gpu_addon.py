from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from dahe.adapters.ocr.runtime_layout import (
    activate_flat_composition,
    resolve_active_composition,
    write_flat_composition_manifest,
)
from dahe.release.gpu_addon import (
    GpuAddonError,
    gpu_addon_status,
    install_gpu_addon,
    resolve_gpu_overlay_composition,
)
from dahe.release.launcher import VersionPointer, write_version_pointer_atomic

VERSION = "1.1.2"
GENERATION_ID = "a" * 32


@pytest.fixture(autouse=True)
def _qualified_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "dahe.release.gpu_addon._qualification_matches_current_device",
        lambda _path: True,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cpu_composition(install_root: Path) -> Path:
    runtime = install_root / "runtimes" / "ocr-cpu"
    cpu = runtime / "c"
    cpu.mkdir(parents=True)
    (cpu / "runtime-installation.json").write_text(
        json.dumps(
            {
                "runtime_kind": "cpu",
                "worker_source_sha256": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    models = runtime / "m" / "official_models"
    models.mkdir(parents=True)
    (models / "model-manifest.json").write_text(
        json.dumps({"model_set_id": "formal-models"}),
        encoding="utf-8",
    )
    qualification = runtime / "q" / "qualification.json"
    qualification.parent.mkdir(parents=True)
    qualification.write_text(
        json.dumps({"schema_version": 2, "reports": [{"runtime_kind": "cpu"}]}),
        encoding="utf-8",
    )
    write_flat_composition_manifest(
        runtime_root=runtime,
        generation_id=GENERATION_ID,
    )
    activate_flat_composition(
        runtime_root=runtime,
        generation_id=GENERATION_ID,
    )
    write_version_pointer_atomic(
        install_root,
        VersionPointer(
            version=VERSION,
            build_git_commit="c" * 40,
            resource_sha256="d" * 64,
            schema_revision="0041_contract_subject_scope",
        ),
    )
    return runtime


def _gpu_package(tmp_path: Path, cpu_root: Path) -> tuple[Path, Path]:
    package_root = tmp_path / "package"
    gpu = package_root / "g"
    gpu.mkdir(parents=True)
    (gpu / "python.exe").write_bytes(b"portable-python")
    (gpu / "runtime-installation.json").write_text(
        json.dumps(
            {
                "runtime_kind": "gpu",
                "worker_source_sha256": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    cpu = resolve_active_composition(cpu_root, allow_legacy=False)
    internal = {
        "schema_version": 2,
        "layout": "gpu_overlay_v1",
        "application_version": VERSION,
        "generation_id": GENERATION_ID,
        "gpu_runtime": "g",
        "runtime_installation_sha256": _sha256(
            gpu / "runtime-installation.json"
        ),
        "cpu_runtime_installation_sha256": _sha256(
            cpu.cpu_runtime / "runtime-installation.json"
        ),
        "model_manifest_sha256": _sha256(
            cpu.models_dir / "model-manifest.json"
        ),
        "worker_source_sha256": "b" * 64,
        "precision": "fp16",
        "batch_size": 6,
        "memory_safety_ratio": "0.90",
    }
    (package_root / "gpu-addon-manifest.json").write_text(
        json.dumps(internal, sort_keys=True),
        encoding="utf-8",
    )
    package = tmp_path / (
        "DaHe-Logistics-Automation-Tool-1.1.2-gpu-addon-win-x64.zip"
    )
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(package_root.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(package_root).as_posix())
    release_manifest = tmp_path / "update-manifest.json"
    release_manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository": "Tastal/DaHe-Logistics-Automation-Tool",
                "version": VERSION,
                "release_tag": "v1.1.2",
                "build_git_commit": "c" * 40,
                "application": {
                    "file_name": "DaHe-Logistics-Automation-Tool-1.1.2-win-x64.zip",
                    "sha256": "e" * 64,
                    "size": 1,
                    "url": (
                        "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                        "releases/download/v1.1.2/"
                        "DaHe-Logistics-Automation-Tool-1.1.2-win-x64.zip"
                    ),
                },
                "gpu_addon": {
                    "file_name": package.name,
                    "sha256": _sha256(package),
                    "size": package.stat().st_size,
                    "url": (
                        "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                        f"releases/download/v1.1.2/{package.name}"
                    ),
                },
                "minimum_schema_revision": "0039_network_batch_default",
                "target_schema_revision": "0041_contract_subject_scope",
                "alembic_revision": "0041_contract_subject_scope",
                "minimum_updater_version": "1.0.0",
                "resource_sha256": "d" * 64,
            }
        ),
        encoding="utf-8",
    )
    return package, release_manifest


def _qualify(
    *,
    cpu_runtime_root: Path,
    gpu_runtime: Path,
    qualification_path: Path,
    **_kwargs: object,
) -> None:
    assert gpu_runtime.name == "g"
    cpu_qualification = json.loads(
        (
            cpu_runtime_root / "q" / "qualification.json"
        ).read_text(encoding="utf-8")
    )
    qualification_path.parent.mkdir(parents=True)
    qualification_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "reports": [
                    *cpu_qualification["reports"],
                    {"runtime_kind": "gpu", "status": "qualified"},
                ],
                "difference_report": {
                    "sample_count": 2,
                    "critical_match_count": 2,
                    "all_critical_fields_match": True,
                    "items": [],
                },
            }
        ),
        encoding="utf-8",
    )


def test_gpu_addon_installs_qualifies_and_activates_atomically(tmp_path: Path) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    cpu_root = _cpu_composition(install_root)
    package, manifest = _gpu_package(tmp_path, cpu_root)

    result = install_gpu_addon(
        manifest_path=manifest,
        package_path=package,
        install_root=install_root,
        qualifier=_qualify,
    )

    assert result.state == "active"
    assert result.primary_runtime == "gpu"
    assert (install_root / "runtimes" / "g" / "python.exe").is_file()
    assert (install_root / "runtimes" / "gq" / "qualification.json").is_file()
    assert (install_root / "runtimes" / "active-gpu-addon.json").is_file()
    status = gpu_addon_status(install_root)
    assert status.state == "active"
    assert status.gpu_qualified is True
    assert status.package_version == VERSION
    combined = resolve_gpu_overlay_composition(cpu_root)
    assert combined.gpu_runtime == (install_root / "runtimes" / "g").resolve()
    assert combined.qualification_path == (
        install_root / "runtimes" / "gq" / "qualification.json"
    ).resolve()


def test_gpu_addon_rejects_release_hash_without_leaving_partial_runtime(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    cpu_root = _cpu_composition(install_root)
    package, manifest = _gpu_package(tmp_path, cpu_root)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["gpu_addon"]["sha256"] = "0" * 64
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(GpuAddonError) as failure:
        install_gpu_addon(
            manifest_path=manifest,
            package_path=package,
            install_root=install_root,
            qualifier=_qualify,
        )

    assert failure.value.error_code == "gpu_package_invalid"
    assert not (install_root / "runtimes" / "g").exists()
    assert not (install_root / "runtimes" / "active-gpu-addon.json").exists()


def test_gpu_addon_rejects_cpu_generation_mismatch(tmp_path: Path) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    cpu_root = _cpu_composition(install_root)
    package, manifest = _gpu_package(tmp_path, cpu_root)
    rewritten = tmp_path / "rewritten"
    with zipfile.ZipFile(package) as bundle:
        bundle.extractall(rewritten)
    internal_path = rewritten / "gpu-addon-manifest.json"
    internal = json.loads(internal_path.read_text(encoding="utf-8"))
    internal["generation_id"] = "f" * 32
    internal_path.write_text(json.dumps(internal), encoding="utf-8")
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(rewritten.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(rewritten).as_posix())
    release = json.loads(manifest.read_text(encoding="utf-8"))
    release["gpu_addon"]["sha256"] = _sha256(package)
    release["gpu_addon"]["size"] = package.stat().st_size
    manifest.write_text(json.dumps(release), encoding="utf-8")

    with pytest.raises(GpuAddonError) as failure:
        install_gpu_addon(
            manifest_path=manifest,
            package_path=package,
            install_root=install_root,
            qualifier=_qualify,
        )

    assert failure.value.error_code == "gpu_cpu_composition_mismatch"
    assert not (install_root / "runtimes" / "active-gpu-addon.json").exists()


def test_gpu_addon_qualification_failure_keeps_cpu_and_can_retry(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    cpu_root = _cpu_composition(install_root)
    package, manifest = _gpu_package(tmp_path, cpu_root)

    def fail(**_kwargs: object) -> None:
        raise RuntimeError("simulated driver incompatibility")

    with pytest.raises(GpuAddonError) as failure:
        install_gpu_addon(
            manifest_path=manifest,
            package_path=package,
            install_root=install_root,
            qualifier=fail,
        )
    assert failure.value.error_code == "gpu_qualification_failed"
    assert resolve_active_composition(cpu_root, allow_legacy=False).gpu_runtime is None
    assert not tuple((install_root / "runtimes").glob(".g-*"))

    install_gpu_addon(
        manifest_path=manifest,
        package_path=package,
        install_root=install_root,
        qualifier=_qualify,
    )
    assert gpu_addon_status(install_root).state == "active"


def test_gpu_addon_same_package_install_is_idempotent(tmp_path: Path) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    cpu_root = _cpu_composition(install_root)
    package, manifest = _gpu_package(tmp_path, cpu_root)
    calls = 0

    def qualify(**kwargs: object) -> None:
        nonlocal calls
        calls += 1
        _qualify(**kwargs)

    install_gpu_addon(
        manifest_path=manifest,
        package_path=package,
        install_root=install_root,
        qualifier=qualify,
    )
    install_gpu_addon(
        manifest_path=manifest,
        package_path=package,
        install_root=install_root,
        qualifier=qualify,
    )

    assert calls == 1
    assert gpu_addon_status(install_root).state == "active"


def test_gpu_addon_status_rejects_stale_device_qualification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    cpu_root = _cpu_composition(install_root)
    package, manifest = _gpu_package(tmp_path, cpu_root)
    install_gpu_addon(
        manifest_path=manifest,
        package_path=package,
        install_root=install_root,
        qualifier=_qualify,
    )
    monkeypatch.setattr(
        "dahe.release.gpu_addon._qualification_matches_current_device",
        lambda _path: False,
    )

    status = gpu_addon_status(install_root)

    assert status.state == "invalid"
    assert status.primary_runtime == "cpu"
    assert status.cpu_fallback_available is True
    assert status.diagnostic_code == "gpu_qualification_stale"


def test_same_gpu_package_can_requalify_after_driver_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    cpu_root = _cpu_composition(install_root)
    package, manifest = _gpu_package(tmp_path, cpu_root)
    install_gpu_addon(
        manifest_path=manifest,
        package_path=package,
        install_root=install_root,
        qualifier=_qualify,
    )
    checks = iter((False, True, True))
    monkeypatch.setattr(
        "dahe.release.gpu_addon._qualification_matches_current_device",
        lambda _path: next(checks),
    )

    result = install_gpu_addon(
        manifest_path=manifest,
        package_path=package,
        install_root=install_root,
        qualifier=_qualify,
    )

    assert result.state == "active"
    assert gpu_addon_status(install_root).state == "active"
