from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.maintenance.backup import SqliteBackupService
from dahe.verification.loop9_build import current_loop9_build_sha256


class ProductionBackupRestoreError(RuntimeError):
    """Raised when a production backup cannot be proven recoverable."""


@dataclass(frozen=True, slots=True)
class ProductionBackupRestoreEvidence:
    payload: dict[str, object]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.payload)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _validated_root(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or _is_reparse_point(path):
        raise ProductionBackupRestoreError(f"{label} is unsafe")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProductionBackupRestoreError(f"{label} is unavailable") from exc
    if not resolved.is_dir() or resolved.is_symlink() or _is_reparse_point(resolved):
        raise ProductionBackupRestoreError(f"{label} is unsafe")
    return resolved


def _database_counts(path: Path) -> dict[str, int]:
    try:
        with closing(
            sqlite3.connect(
                f"{path.resolve(strict=True).as_uri()}?mode=ro",
                uri=True,
            )
        ) as db:
            db.execute("PRAGMA query_only=ON")
            integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_keys = tuple(db.execute("PRAGMA foreign_key_check"))
            if integrity != "ok" or foreign_keys:
                raise ProductionBackupRestoreError(
                    "database integrity or foreign keys are invalid"
                )
            tables = {
                str(row[0])
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            required = {
                "daily_reports",
                "evidence_references",
                "jobs",
                "production_read_only_guard_items",
                "work_items",
            }
            if not required <= tables:
                raise ProductionBackupRestoreError(
                    "production database schema is incomplete"
                )
            return {
                table: int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in sorted(required)
            }
    except sqlite3.Error as exc:
        raise ProductionBackupRestoreError("production database is unreadable") from exc


def verify_production_backup_restore(
    *,
    project_root: Path,
    data_root: Path,
    output: Path,
) -> ProductionBackupRestoreEvidence:
    project_root = _validated_root(project_root, label="project root")
    data_root = _validated_root(data_root, label="production data root")
    output = Path(os.path.abspath(os.fspath(output)))
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ProductionBackupRestoreError("output must be a new absolute path")
    if output.is_relative_to(data_root / "database"):
        raise ProductionBackupRestoreError("output overlaps the live database")

    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=f"production-backup-verification-{uuid4().hex}",
    )
    try:
        evidence_store = ContentAddressedEvidenceStore(data_root / "evidence")
        service = SqliteBackupService(
            runtime=runtime,
            evidence_store=evidence_store,
            backup_root=data_root / "backups" / "production-cutover",
        )
        source_counts = _database_counts(runtime.database_path)
        backup = service.create_online_backup()
        with tempfile.TemporaryDirectory(
            prefix="DaHeProductionRestore-",
        ) as temporary:
            restore_root = Path(temporary) / "restored"
            report = service.restore_to_temporary(backup.path, restore_root)
            restored_counts = _database_counts(report.database_path)
            if source_counts != restored_counts:
                raise ProductionBackupRestoreError(
                    "restored record counts differ from the source"
                )
            manifest = backup.path / "manifest.json"
            payload = {
                "backup_id": backup.backup_id,
                "backup_manifest_sha256": _sha256_file(manifest),
                "created_at": datetime.now(UTC).isoformat(),
                "database_counts": source_counts,
                "evidence_count": report.evidence_count,
                "integrity_check": report.integrity_check,
                "kind": "production_backup_restore_evidence",
                "schema_version": 1,
                "source_build_sha256": current_loop9_build_sha256(project_root),
            }
    finally:
        runtime.close()

    evidence = ProductionBackupRestoreEvidence(payload=payload)
    document = {**payload, "canonical_sha256": evidence.canonical_sha256}
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(f".{output.name}.{uuid4().hex}.partial")
    try:
        with staging.open("xb") as handle:
            handle.write(
                json.dumps(
                    document,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        if output.exists():
            raise ProductionBackupRestoreError("output appeared during write")
        os.replace(staging, output)
    finally:
        staging.unlink(missing_ok=True)
    return evidence


def load_production_backup_restore_evidence(
    path: Path,
    *,
    expected_build_sha256: str,
) -> ProductionBackupRestoreEvidence:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProductionBackupRestoreError("backup evidence is unreadable") from exc
    if not isinstance(payload, dict):
        raise ProductionBackupRestoreError("backup evidence is invalid")
    canonical = payload.pop("canonical_sha256", None)
    evidence = ProductionBackupRestoreEvidence(payload=payload)
    if (
        canonical != evidence.canonical_sha256
        or payload.get("kind") != "production_backup_restore_evidence"
        or payload.get("schema_version") != 1
        or payload.get("source_build_sha256") != expected_build_sha256
        or payload.get("integrity_check") != "ok"
        or not isinstance(payload.get("database_counts"), dict)
        or type(payload.get("evidence_count")) is not int
    ):
        raise ProductionBackupRestoreError("backup evidence verification failed")
    return evidence
