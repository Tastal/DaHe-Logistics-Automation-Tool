from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from dahe import __version__
from dahe.release.launcher import (
    LauncherError,
    VersionPointer,
    compute_resource_sha256,
    install_seed_data,
    migrate_existing_user_data,
    read_version_pointer,
    run_launcher,
    validate_version_root,
    write_version_pointer_atomic,
)


def _installed_version(tmp_path: Path) -> tuple[Path, VersionPointer]:
    install_root = tmp_path / "install"
    version_root = install_root / "versions" / __version__
    version_root.mkdir(parents=True)
    (version_root / "DaHeApp.exe").write_bytes(b"app")
    (version_root / "frontend").mkdir()
    (version_root / "frontend" / "index.html").write_text("ready")
    resource = compute_resource_sha256(version_root)
    identity = {
        "schema_version": 1,
        "application_version": __version__,
        "build_git_commit": "a" * 40,
        "resource_sha256": resource,
    }
    (version_root / "release-identity.json").write_text(
        json.dumps(identity),
        encoding="utf-8",
    )
    pointer = VersionPointer(
        version=__version__,
        build_git_commit="a" * 40,
        resource_sha256=resource,
        schema_revision="0039_network_batch_default",
    )
    write_version_pointer_atomic(install_root, pointer)
    return install_root, pointer


def test_pointer_and_release_resources_must_have_one_identity(tmp_path: Path) -> None:
    install_root, pointer = _installed_version(tmp_path)

    assert read_version_pointer(install_root) == pointer
    assert validate_version_root(install_root, pointer).name == __version__

    app = install_root / "versions" / __version__ / "DaHeApp.exe"
    app.write_bytes(b"changed")
    with pytest.raises(LauncherError, match="resources"):
        validate_version_root(install_root, pointer)


def test_pointer_rejects_a_version_path_escape(tmp_path: Path) -> None:
    install_root, pointer = _installed_version(tmp_path)
    write_version_pointer_atomic(
        install_root,
        VersionPointer(
            version="../../outside",
            build_git_commit=pointer.build_git_commit,
            resource_sha256=pointer.resource_sha256,
            schema_revision=pointer.schema_revision,
        ),
    )

    with pytest.raises(LauncherError):
        read_version_pointer(install_root)


def test_cold_start_allows_five_minutes_for_packaged_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_root, _ = _installed_version(tmp_path)
    readiness_timeouts: list[float] = []

    def fake_readiness(_pointer: VersionPointer, *, timeout_seconds: float) -> bool:
        readiness_timeouts.append(timeout_seconds)
        return len(readiness_timeouts) == 2

    local_app_data = tmp_path / "local-app-data"
    local_app_data.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setattr("dahe.release.launcher.readiness", fake_readiness)
    monkeypatch.setattr("dahe.release.launcher.subprocess.Popen", lambda *a, **k: object())

    assert (
        run_launcher(
            install_root=install_root,
            data_root=tmp_path / "data",
            open_browser=False,
        )
        == 0
    )
    assert readiness_timeouts == [0.3, 300]


def test_existing_data_is_copied_once_without_modifying_the_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "old"
    target = tmp_path / "new"
    database = source / "database" / "dahe.sqlite3"
    database.parent.mkdir(parents=True)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('original')")
        connection.commit()
    (source / "evidence").mkdir()
    (source / "evidence" / "proof.bin").write_bytes(b"proof")
    before = database.read_bytes()

    migrate_existing_user_data(source_root=source, target_root=target)
    migrate_existing_user_data(source_root=source, target_root=target)

    assert database.read_bytes() == before
    with closing(sqlite3.connect(target / "database" / "dahe.sqlite3")) as copied:
        assert copied.execute("SELECT value FROM sample").fetchone() == ("original",)
    assert (target / "evidence" / "proof.bin").read_bytes() == b"proof"
    assert (target / "migration-from-0.8.json").is_file()


def test_existing_data_repairs_missing_declared_operational_contract_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "old"
    target = tmp_path / "new"
    relative_path = Path("platform-read-contract") / "active-candidate.json"
    contract = source / relative_path
    contract.parent.mkdir(parents=True)
    payload = b'{"kind":"active-candidate"}\n'
    contract.write_bytes(payload)
    install_marker = {
        "schema_version": 1,
        "kind": "chengfeng_operational_read_contract_install",
        "classification": "operational_only",
        "credential_material_retained": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "platform_write_authorization": False,
        "copied_files": [
            {
                "relative_path": relative_path.as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        ],
    }
    (source / "operational-contract-install.json").write_text(
        json.dumps(install_marker),
        encoding="utf-8",
    )
    target.mkdir(parents=True)
    (target / "migration-from-0.8.json").write_text(
        json.dumps({"schema_version": 1, "source": "DaHeLogistics/production"}),
        encoding="utf-8",
    )

    migrate_existing_user_data(source_root=source, target_root=target)

    assert (target / relative_path).read_bytes() == payload
    assert contract.read_bytes() == payload


def test_fresh_install_copies_declared_operational_contract_files(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    seed_root = install_root / "seed"
    data_root = tmp_path / "data"
    relative_path = Path("platform-read-contract") / "active-candidate.json"
    contract = seed_root / relative_path
    contract.parent.mkdir(parents=True)
    payload = b'{"kind":"active-candidate"}\n'
    contract.write_bytes(payload)
    (seed_root / "operational-template-bundle.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (seed_root / "operational-contract-install.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "chengfeng_operational_read_contract_install",
                "classification": "operational_only",
                "credential_material_retained": False,
                "request_values_retained": False,
                "response_values_retained": False,
                "platform_write_authorization": False,
                "copied_files": [
                    {
                        "relative_path": relative_path.as_posix(),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    install_seed_data(install_root=install_root, data_root=data_root)
    install_seed_data(install_root=install_root, data_root=data_root)

    assert (data_root / relative_path).read_bytes() == payload
    assert (data_root / "operational-contract-install.json").is_file()
