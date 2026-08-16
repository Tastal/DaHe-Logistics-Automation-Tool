from __future__ import annotations

import json
from pathlib import Path

import pytest

from dahe.release.local_release import (
    LocalReleaseError,
    _copy_formal_pipeline_project_sources,
    _payload_files,
    _require_current_browser_runtime,
    _write_hidden_launcher,
    _write_launcher,
)


def test_launcher_uses_only_the_fixed_production_read_only_entry(
    tmp_path: Path,
) -> None:
    launcher = tmp_path / "start-dahe.cmd"
    _write_launcher(launcher)
    content = launcher.read_text(encoding="utf-8")

    assert "--production-read-only" in content
    assert "%LOCALAPPDATA%\\DaHeLogistics\\production" in content
    assert "--enable-chengfeng-shadow" not in content
    assert "--enable-test-fixtures" not in content


def test_release_manifest_excludes_the_mutable_runtime_environment(
    tmp_path: Path,
) -> None:
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "mutable.txt").write_text("mutable", encoding="utf-8")
    (tmp_path / "runtime-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "start-dahe.cmd").write_text("start", encoding="utf-8")

    assert [path.name for path in _payload_files(tmp_path)] == ["start-dahe.cmd"]


def test_hidden_launcher_runs_the_diagnostic_launcher_without_a_window(
    tmp_path: Path,
) -> None:
    launcher = tmp_path / "start-dahe.vbs"
    _write_hidden_launcher(
        launcher,
        diagnostic_launcher_name="start-dahe-diagnostic.cmd",
    )
    payload = launcher.read_bytes()
    content = payload.decode("ascii")

    assert not payload.startswith(b"\xef\xbb\xbf")
    assert '"start-dahe-diagnostic.cmd"' in content
    assert ", 0, False" in content


def test_release_copies_formal_pipeline_tool_sources(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    release_root = tmp_path / "release"
    for name in (
        "loop7_controlled_non_ticket_challenge.py",
        "loop7_locked_set_release.py",
        "loop7_shadow_authority_rollover.py",
    ):
        source = project_root / "tools" / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"# {name}\n", encoding="utf-8")

    _copy_formal_pipeline_project_sources(
        project_root=project_root,
        release_root=release_root,
    )

    assert sorted(path.name for path in (release_root / "tools").iterdir()) == [
        "loop7_controlled_non_ticket_challenge.py",
        "loop7_locked_set_release.py",
        "loop7_shadow_authority_rollover.py",
    ]


def test_release_refuses_a_stale_browser_runtime(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    source = project_root / "browser-runtime" / "src" / "dahe_browser_worker"
    source.mkdir(parents=True)
    (source / "engine.py").write_text("CURRENT = True\n", encoding="utf-8")
    lock = project_root / "browser-runtime" / "requirements.lock"
    lock.write_text("playwright==1.61.0\n", encoding="utf-8")
    runtime_root = tmp_path / "runtime"
    python = runtime_root / "python" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"runtime")
    (runtime_root / "runtime-installation.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "runtime_kind": "browser",
                "dependency_lock": "browser-runtime/requirements.lock",
                "dependency_lock_sha256": "0" * 64,
                "worker_source_sha256": "0" * 64,
                "packages": ["playwright==1.61.0"],
                "smoke_selected_browser": "msedge",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(LocalReleaseError, match=r"bootstrap_browser\.py"):
        _require_current_browser_runtime(
            project_root=project_root,
            runtime_root=runtime_root,
        )
