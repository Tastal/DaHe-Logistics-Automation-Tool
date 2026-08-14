from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dahe.release.update_service import (
    UpdateInstallBlocked,
    UpdateService,
)


def _content(version: str = "1.0.0") -> bytes:
    payload = {
        "schema_version": 1,
        "repository": "Tastal/DaHe-Logistics-Automation-Tool",
        "version": version,
        "release_tag": f"v{version}",
        "build_git_commit": "d" * 40,
        "application": {
            "file_name": (
                f"DaHe-Logistics-Automation-Tool-{version}-win-x64.zip"
            ),
            "sha256": "a" * 64,
            "size": 100,
            "url": (
                "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                f"releases/download/v{version}/"
                f"DaHe-Logistics-Automation-Tool-{version}-win-x64.zip"
            ),
        },
        "gpu_addon": {
            "file_name": (
                f"DaHe-Logistics-Automation-Tool-{version}-"
                "gpu-addon-win-x64.zip"
            ),
            "sha256": "b" * 64,
            "size": 100,
            "url": (
                "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                f"releases/download/v{version}/"
                f"DaHe-Logistics-Automation-Tool-{version}-"
                "gpu-addon-win-x64.zip"
            ),
        },
        "minimum_schema_revision": "0039_network_batch_default",
        "target_schema_revision": "0039_network_batch_default",
        "alembic_revision": "0039_network_batch_default",
        "minimum_updater_version": "1.0.0",
        "resource_sha256": "c" * 64,
    }
    return json.dumps(payload).encode()


class Fetcher:
    def __init__(self, content: bytes | Exception) -> None:
        self.content = content
        self.calls = 0

    def fetch(self) -> bytes:
        self.calls += 1
        if isinstance(self.content, Exception):
            raise self.content
        return self.content


class Launcher:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, Path, Path, int, Path | None]] = []

    def launch(
        self,
        *,
        updater_path: Path,
        manifest_path: Path,
        data_root: Path,
        process_id: int,
        application_path: Path | None,
    ) -> None:
        self.calls.append(
            (
                updater_path,
                manifest_path,
                data_root,
                process_id,
                application_path,
            )
        )


def _service(
    tmp_path: Path,
    *,
    fetcher: Fetcher,
    launcher: Launcher | None = None,
) -> UpdateService:
    updater = tmp_path / "install" / "DaHeUpdater.exe"
    updater.parent.mkdir(exist_ok=True)
    updater.write_bytes(b"updater")
    return UpdateService(
        current_version="0.8.1",
        updater_version="1.0.0",
        data_root=tmp_path / "data",
        updater_path=updater,
        fetcher=fetcher,
        launcher=launcher or Launcher(),
    )


def test_check_persists_an_available_release(tmp_path: Path) -> None:
    service = _service(tmp_path, fetcher=Fetcher(_content()))

    status = service.check()

    assert status.state == "available"
    assert status.current_version == "0.8.1"
    assert status.available_version == "1.0.0"
    assert status.update_available is True
    assert service.manifest_path.read_bytes() == _content()
    assert service.status().state == "available"


def test_network_failure_never_changes_the_current_version(
    tmp_path: Path,
) -> None:
    service = _service(
        tmp_path,
        fetcher=Fetcher(OSError("offline")),
    )

    status = service.check()

    assert status.state == "failed"
    assert status.current_version == "0.8.1"
    assert status.available_version is None
    assert status.error_code == "update_check_failed"


def test_same_version_is_up_to_date(tmp_path: Path) -> None:
    service = _service(tmp_path, fetcher=Fetcher(_content("0.8.1")))

    status = service.check()

    assert status.state == "up_to_date"
    assert status.update_available is False


def test_downgrade_manifest_is_rejected(tmp_path: Path) -> None:
    service = _service(tmp_path, fetcher=Fetcher(_content("0.7.9")))

    status = service.check()

    assert status.state == "failed"
    assert status.error_code == "update_downgrade_rejected"


def test_install_requires_user_action_and_blocks_active_work(
    tmp_path: Path,
) -> None:
    launcher = Launcher()
    service = _service(
        tmp_path,
        fetcher=Fetcher(_content()),
        launcher=launcher,
    )
    service.check()
    assert launcher.calls == []

    with pytest.raises(UpdateInstallBlocked, match="active"):
        service.install(active_job_count=1, process_id=123)
    assert launcher.calls == []

    status = service.install(active_job_count=0, process_id=123)

    assert status.state == "installing"
    assert len(launcher.calls) == 1
    assert launcher.calls[0][1] == service.manifest_path
    assert launcher.calls[0][3] == 123


def test_install_rejects_a_missing_updater(tmp_path: Path) -> None:
    service = _service(tmp_path, fetcher=Fetcher(_content()))
    service.check()
    service.updater_path.unlink()

    with pytest.raises(UpdateInstallBlocked, match="unavailable"):
        service.install(active_job_count=0, process_id=123)


def test_local_import_validates_manifest_and_application_before_install(
    tmp_path: Path,
) -> None:
    content = b"verified application archive"
    manifest = json.loads(_content().decode())
    manifest["application"]["size"] = len(content)
    manifest["application"]["sha256"] = hashlib.sha256(content).hexdigest()
    launcher = Launcher()
    service = _service(
        tmp_path,
        fetcher=Fetcher(OSError("offline")),
        launcher=launcher,
    )

    created = service.create_import(json.dumps(manifest).encode())
    status = service.upload_import(created.import_id, [content[:7], content[7:]])
    installed = service.install(active_job_count=0, process_id=123)

    assert status.state == "available"
    assert installed.state == "installing"
    assert launcher.calls[0][4].read_bytes() == content


def test_verified_local_import_survives_service_restart(tmp_path: Path) -> None:
    content = b"verified application archive"
    manifest = json.loads(_content().decode())
    manifest["application"]["size"] = len(content)
    manifest["application"]["sha256"] = hashlib.sha256(content).hexdigest()
    first = _service(tmp_path, fetcher=Fetcher(OSError("offline")))
    created = first.create_import(json.dumps(manifest).encode())
    first.upload_import(created.import_id, [content])
    launcher = Launcher()

    restarted = _service(
        tmp_path,
        fetcher=Fetcher(OSError("offline")),
        launcher=launcher,
    )
    restarted.install(active_job_count=0, process_id=123)

    assert launcher.calls[0][4] is not None
    assert launcher.calls[0][4].read_bytes() == content


def test_local_import_rejects_hash_mismatch_and_cannot_install(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, fetcher=Fetcher(OSError("offline")))
    created = service.create_import(_content())

    with pytest.raises(ValueError, match="hash"):
        service.upload_import(created.import_id, [b"wrong"])

    with pytest.raises(UpdateInstallBlocked):
        service.install(active_job_count=0, process_id=123)
