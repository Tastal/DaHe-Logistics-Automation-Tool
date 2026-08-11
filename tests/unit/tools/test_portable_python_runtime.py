from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tools.portable_python_runtime import (
    PortableRuntimeError,
    scrub_portable_python_bytecode,
    stage_portable_python_runtime,
    validate_portable_python_runtime,
    validate_release_tree_no_developer_provenance,
)


def _embed_archive(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("python.exe", b"python")
        bundle.writestr("python3.dll", b"python3")
        bundle.writestr("python312.dll", b"python312")
        bundle.writestr("python312.zip", b"stdlib")
        bundle.writestr("python312._pth", "python312.zip\n.\n#import site\n")
    return path


def test_stage_portable_runtime_replaces_venv_and_scrubs_provenance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-venv"
    site_packages = source / "Lib" / "site-packages"
    (site_packages / "dependency").mkdir(parents=True)
    (site_packages / "dependency" / "__init__.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    dist_info = site_packages / "worker-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: worker\nVersion: 1.0\n")
    (dist_info / "direct_url.json").write_text(
        '{"url":"file:///C:/Users/developer/source"}',
        encoding="utf-8",
    )
    (site_packages / "__pycache__").mkdir()
    (site_packages / "__pycache__" / "cached.pyc").write_bytes(b"cache")
    (source / "Scripts").mkdir()
    (source / "Scripts" / "python.exe").write_bytes(b"venv")
    (source / "pyvenv.cfg").write_text(
        "home = C:/Users/developer/AppData/Local/Programs/Python\n",
        encoding="utf-8",
    )
    worker = tmp_path / "approved-worker"
    worker.mkdir()
    (worker / "__init__.py").write_text("VERSION = 2\n", encoding="utf-8")

    target = tmp_path / "portable"
    evidence = stage_portable_python_runtime(
        source_runtime=source,
        target_runtime=target,
        embed_archive=_embed_archive(tmp_path / "python-embed.zip"),
        embed_archive_sha256=None,
        python_version="3.12.10",
        worker_source=worker,
        worker_package="worker",
    )

    assert (target / "python.exe").is_file()
    assert not (target / "Scripts").exists()
    assert not (target / "pyvenv.cfg").exists()
    assert not tuple(target.rglob("direct_url.json"))
    assert not tuple(target.rglob("*.pyc"))
    assert (target / "Lib" / "site-packages" / "dependency" / "__init__.py").is_file()
    assert (target / "Lib" / "site-packages" / "worker" / "__init__.py").read_text(
        encoding="utf-8"
    ) == "VERSION = 2\n"
    assert (target / "python312._pth").read_text(encoding="utf-8") == (
        "python312.zip\n.\nLib\\site-packages\nimport site\n"
    )
    assert evidence["layout"] == "portable_embed"
    assert evidence["python_version"] == "3.12.10"
    assert evidence["interpreter"] == "python.exe"


def test_scrub_removes_only_generated_python_bytecode(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    package = runtime / "Lib" / "site-packages" / "package"
    cache = package / "__pycache__"
    cache.mkdir(parents=True)
    source = package / "module.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    (cache / "module.pyc").write_bytes(b"cache")

    scrub_portable_python_bytecode(runtime)

    assert source.is_file()
    assert not cache.exists()


def test_release_tree_gate_rejects_embedded_developer_root(tmp_path: Path) -> None:
    release = tmp_path / "release"
    release.mkdir()
    (release / "runtime.txt").write_text(
        "C:/Users/developer/OneDrive/source",
        encoding="utf-8",
    )

    with pytest.raises(PortableRuntimeError, match="developer provenance"):
        validate_release_tree_no_developer_provenance(
            release,
            developer_roots=(Path("C:/Users/developer/OneDrive/source"),),
        )


@pytest.mark.parametrize(
    "relative_path",
    (
        "src/package/__pycache__/module.cpython-312.pyc",
        "src/package/module.pyo",
    ),
)
def test_release_tree_gate_rejects_generated_bytecode(
    tmp_path: Path,
    relative_path: str,
) -> None:
    release = tmp_path / "release"
    leaked = release / relative_path
    leaked.parent.mkdir(parents=True)
    leaked.write_bytes(b"bytecode")

    with pytest.raises(PortableRuntimeError, match="bytecode"):
        validate_release_tree_no_developer_provenance(
            release,
            developer_roots=(),
        )


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        ("pyvenv.cfg", b"home = C:/Python"),
        ("Scripts/python.exe", b"venv"),
        ("Lib/site-packages/pkg/direct_url.json", b"{}"),
        ("Lib/site-packages/pkg/metadata.txt", b"file:///C:/Users/developer/source"),
        ("Lib/site-packages/pkg/path.txt", b"C:\\Users\\developer\\OneDrive\\source"),
    ],
)
def test_portable_runtime_gate_rejects_venv_or_developer_provenance(
    tmp_path: Path,
    relative_path: str,
    content: bytes,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "python.exe").write_bytes(b"python")
    (runtime / "python312._pth").write_text(
        "python312.zip\n.\nLib\\site-packages\nimport site\n",
        encoding="utf-8",
    )
    leaked = runtime / relative_path
    leaked.parent.mkdir(parents=True, exist_ok=True)
    leaked.write_bytes(content)

    with pytest.raises(PortableRuntimeError):
        validate_portable_python_runtime(
            runtime,
            developer_roots=(Path("C:/Users/developer/OneDrive/source"),),
            run_smoke=False,
        )
