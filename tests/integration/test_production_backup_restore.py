from __future__ import annotations

import json
from pathlib import Path

import pytest

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.production_backup_restore import (
    ProductionBackupRestoreError,
    load_production_backup_restore_evidence,
    verify_production_backup_restore,
)


def test_production_backup_is_restored_and_counted(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "production"
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="prepare-production-backup-test",
    )
    runtime.close()
    output = tmp_path / "verification" / "backup.json"

    evidence = verify_production_backup_restore(
        project_root=project_root,
        data_root=data_root,
        output=output,
    )

    assert evidence.payload["integrity_check"] == "ok"
    assert output.is_file()
    loaded = load_production_backup_restore_evidence(
        output,
        expected_build_sha256=current_loop9_build_sha256(project_root),
    )
    assert loaded.canonical_sha256 == evidence.canonical_sha256


def test_backup_evidence_tampering_is_rejected(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "production"
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id="prepare-production-backup-tamper-test",
    )
    runtime.close()
    output = tmp_path / "verification" / "backup.json"
    verify_production_backup_restore(
        project_root=project_root,
        data_root=data_root,
        output=output,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["evidence_count"] = 999
    output.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProductionBackupRestoreError):
        load_production_backup_restore_evidence(
            output,
            expected_build_sha256=current_loop9_build_sha256(project_root),
        )
