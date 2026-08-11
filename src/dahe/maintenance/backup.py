from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.adapters.sqlite.runtime import SqliteRuntime


class BackupIntegrityError(RuntimeError):
    """Raised when a backup package is incomplete or has changed."""


class UnsafeRestoreTargetError(RuntimeError):
    """Raised when restore could overwrite an existing or active directory."""


@dataclass(frozen=True, slots=True)
class BackupResult:
    backup_id: str
    path: Path


@dataclass(frozen=True, slots=True)
class RestoreReport:
    data_root: Path
    database_path: Path
    integrity_check: str
    evidence_count: int


_ACTIVE_EVIDENCE_SQL = (
    "SELECT DISTINCT b.sha256, b.relative_path "
    "FROM evidence_blobs AS b "
    "WHERE EXISTS ("
    "  SELECT 1 FROM evidence_references AS r "
    "  WHERE r.sha256 = b.sha256 AND r.released_at IS NULL"
    ") OR EXISTS ("
    "  SELECT 1 FROM evidence_holds AS h "
    "  WHERE h.sha256 = b.sha256 AND h.released_at IS NULL"
    ") ORDER BY b.sha256"
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_json(path: Path, document: dict[str, object]) -> None:
    encoded = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    _atomic_write_bytes(path, encoded)


def _restore_staging_path(target: Path) -> Path:
    target_parent = target.parent.resolve()
    staging = (
        target_parent / f".{target.name}.{uuid4().hex}.restore-staging"
    ).resolve()
    if staging.parent != target_parent or staging == target:
        raise UnsafeRestoreTargetError("restore staging must be a sibling of its target")
    return staging


def _remove_restore_staging(
    staging: Path,
    *,
    target: Path,
    target_parent: Path,
) -> None:
    expected_prefix = f".{target.name}."
    if (
        staging.parent != target_parent
        or not expected_prefix
        or not staging.name.startswith(expected_prefix)
        or not staging.name.endswith(".restore-staging")
    ):
        raise UnsafeRestoreTargetError("refusing to remove an unverified restore staging path")
    if staging.is_symlink():
        staging.unlink(missing_ok=True)
    elif staging.exists():
        shutil.rmtree(staging)


def _validated_manifest_evidence(
    evidence_entries: list[object],
) -> tuple[tuple[dict[str, object], str, str, int], ...]:
    validated: list[tuple[dict[str, object], str, str, int]] = []
    seen_identities: set[tuple[str, str]] = set()
    path_by_sha256: dict[str, str] = {}
    sha256_by_path: dict[str, str] = {}
    for entry in evidence_entries:
        if not isinstance(entry, dict):
            raise BackupIntegrityError("backup evidence entry is invalid")
        relative_path = entry.get("relative_path")
        sha256 = entry.get("sha256")
        byte_size = entry.get("byte_size")
        if (
            not isinstance(relative_path, str)
            or not isinstance(sha256, str)
            or not isinstance(byte_size, int)
            or isinstance(byte_size, bool)
        ):
            raise BackupIntegrityError("backup evidence identity is invalid")
        identity = (sha256, relative_path)
        if identity in seen_identities:
            raise BackupIntegrityError("backup evidence manifest contains a duplicate identity")
        existing_path = path_by_sha256.get(sha256)
        if existing_path is not None and existing_path != relative_path:
            raise BackupIntegrityError("backup evidence manifest maps one hash to multiple paths")
        existing_sha256 = sha256_by_path.get(relative_path)
        if existing_sha256 is not None and existing_sha256 != sha256:
            raise BackupIntegrityError("backup evidence manifest maps one path to multiple hashes")
        seen_identities.add(identity)
        path_by_sha256[sha256] = relative_path
        sha256_by_path[relative_path] = sha256
        validated.append((entry, sha256, relative_path, byte_size))
    return tuple(validated)


def _validate_required_evidence(
    *,
    database_rows: tuple[tuple[object, object], ...],
    manifest_entries: tuple[tuple[dict[str, object], str, str, int], ...],
) -> None:
    required_identities: list[tuple[str, str]] = []
    required_paths_by_sha256: dict[str, str] = {}
    required_sha256s_by_path: dict[str, str] = {}
    for sha256_value, relative_path_value in database_rows:
        sha256 = str(sha256_value)
        relative_path = str(relative_path_value)
        existing_path = required_paths_by_sha256.get(sha256)
        if existing_path is not None and existing_path != relative_path:
            raise BackupIntegrityError("backup database maps one evidence hash to multiple paths")
        existing_sha256 = required_sha256s_by_path.get(relative_path)
        if existing_sha256 is not None and existing_sha256 != sha256:
            raise BackupIntegrityError("backup database maps one evidence path to multiple hashes")
        required_paths_by_sha256[sha256] = relative_path
        required_sha256s_by_path[relative_path] = sha256
        required_identities.append((sha256, relative_path))

    manifest_identities = [(sha256, path) for _, sha256, path, _ in manifest_entries]
    if len(required_identities) != len(set(required_identities)):
        raise BackupIntegrityError("backup database contains duplicate evidence identities")
    if len(manifest_identities) != len(required_identities):
        raise BackupIntegrityError(
            "backup evidence manifest does not contain every active database identity"
        )
    if set(manifest_identities) != set(required_identities):
        raise BackupIntegrityError(
            "backup evidence manifest disagrees with active database identities"
        )


class SqliteBackupService:
    """Create a self-contained SQLite and referenced-evidence backup package."""

    def __init__(
        self,
        *,
        runtime: SqliteRuntime,
        evidence_store: ContentAddressedEvidenceStore,
        backup_root: Path,
    ) -> None:
        self.runtime = runtime
        self.evidence_store = evidence_store
        self.backup_root = backup_root.resolve()
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.staging_root = self.backup_root / ".staging"
        self.staging_root.mkdir(parents=True, exist_ok=True)

    def create_online_backup(self) -> BackupResult:
        backup_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid4().hex[:12]
        staging = self.staging_root / f"{backup_id}.partial"
        final = self.backup_root / backup_id
        staging.mkdir(parents=True, exist_ok=False)
        database_copy = staging / "database" / "dahe.sqlite3"
        database_copy.parent.mkdir(parents=True, exist_ok=True)

        with (
            closing(sqlite3.connect(self.runtime.database_path)) as source,
            closing(sqlite3.connect(database_copy)) as destination,
        ):
            source.backup(destination)
            destination.execute("PRAGMA foreign_keys=ON")
            integrity = str(destination.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_key_errors = destination.execute("PRAGMA foreign_key_check").fetchall()
            if integrity != "ok" or foreign_key_errors:
                raise BackupIntegrityError("online SQLite backup failed integrity validation")
            destination.commit()

        with closing(
            sqlite3.connect(
                f"{database_copy.resolve().as_uri()}?mode=ro",
                uri=True,
            )
        ) as snapshot:
            snapshot.execute("PRAGMA query_only=ON")
            evidence_rows = tuple(snapshot.execute(_ACTIVE_EVIDENCE_SQL))
            revision_row = snapshot.execute("SELECT version_num FROM alembic_version").fetchone()
        if revision_row is None:
            raise BackupIntegrityError("backup database has no Alembic revision")

        package_store = ContentAddressedEvidenceStore(staging / "evidence")
        evidence_manifest: list[dict[str, object]] = []
        for sha256_value, relative_path_value in evidence_rows:
            sha256 = str(sha256_value)
            content = self.evidence_store.read_bytes(sha256)
            stored = package_store.put_bytes(content)
            if stored.relative_path != str(relative_path_value):
                raise BackupIntegrityError("evidence path disagrees with database metadata")
            evidence_manifest.append(
                {
                    "byte_size": len(content),
                    "relative_path": stored.relative_path,
                    "sha256": sha256,
                }
            )

        _atomic_write_json(
            staging / "manifest.json",
            {
                "backup_id": backup_id,
                "created_at": datetime.now(UTC).isoformat(),
                "database": {
                    "relative_path": "database/dahe.sqlite3",
                    "sha256": _sha256_file(database_copy),
                },
                "evidence": evidence_manifest,
                "migration_revision": str(revision_row[0]),
                "schema_version": 1,
            },
        )
        staging.rename(final)
        return BackupResult(backup_id=backup_id, path=final)

    def restore_to_temporary(
        self,
        backup_path: Path,
        target_root: Path,
    ) -> RestoreReport:
        package = backup_path.resolve()
        target = target_root.resolve()
        if not package.is_dir():
            raise BackupIntegrityError("backup package does not exist")
        if target == self.runtime.data_root or target.is_relative_to(self.runtime.data_root):
            raise UnsafeRestoreTargetError("restore target overlaps the active data root")
        if self.runtime.data_root.is_relative_to(target):
            raise UnsafeRestoreTargetError("restore target contains the active data root")
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise UnsafeRestoreTargetError("restore target must be an empty directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        target_parent = target.parent.resolve()
        staging = _restore_staging_path(target)
        staging.mkdir(parents=False, exist_ok=False)
        try:
            manifest_path = package / "manifest.json"
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise BackupIntegrityError("backup manifest is unreadable") from exc
            if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
                raise BackupIntegrityError("backup manifest version is unsupported")
            database_entry = manifest.get("database")
            evidence_entries = manifest.get("evidence")
            if not isinstance(database_entry, dict) or not isinstance(evidence_entries, list):
                raise BackupIntegrityError("backup manifest is incomplete")

            database_relative = database_entry.get("relative_path")
            database_sha256 = database_entry.get("sha256")
            if not isinstance(database_relative, str) or not isinstance(database_sha256, str):
                raise BackupIntegrityError("backup database identity is invalid")
            source_database = (package / database_relative).resolve()
            if not source_database.is_relative_to(package):
                raise BackupIntegrityError("backup database path escaped its package")
            try:
                source_database_hash = _sha256_file(source_database)
                database_content = source_database.read_bytes()
            except OSError as exc:
                raise BackupIntegrityError("backup database is unreadable") from exc
            if source_database_hash != database_sha256:
                raise BackupIntegrityError("backup database hash does not match its manifest")

            restored_database = staging / "database" / "dahe.sqlite3"
            _atomic_write_bytes(restored_database, database_content)
            manifest_evidence = _validated_manifest_evidence(evidence_entries)
            try:
                with closing(sqlite3.connect(restored_database)) as connection:
                    connection.execute("PRAGMA foreign_keys=ON")
                    database_evidence = tuple(
                        connection.execute(_ACTIVE_EVIDENCE_SQL)
                    )
                    integrity = str(
                        connection.execute("PRAGMA integrity_check").fetchone()[0]
                    )
                    foreign_key_errors = connection.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchall()
                    revision = connection.execute(
                        "SELECT version_num FROM alembic_version"
                    ).fetchone()
            except sqlite3.Error as exc:
                raise BackupIntegrityError(
                    "restored database cannot prove its evidence requirements"
                ) from exc
            _validate_required_evidence(
                database_rows=database_evidence,
                manifest_entries=manifest_evidence,
            )

            restored_store = ContentAddressedEvidenceStore(staging / "evidence")
            evidence_root = (package / "evidence").resolve()
            if not evidence_root.is_relative_to(package):
                raise BackupIntegrityError("backup evidence root escaped its package")
            for _, sha256, relative_path, byte_size in manifest_evidence:
                source_evidence = (evidence_root / relative_path).resolve()
                if not source_evidence.is_relative_to(evidence_root):
                    raise BackupIntegrityError("backup evidence path escaped its package")
                try:
                    content = source_evidence.read_bytes()
                except OSError as exc:
                    raise BackupIntegrityError("backup evidence is unreadable") from exc
                if len(content) != byte_size or hashlib.sha256(content).hexdigest() != sha256:
                    raise BackupIntegrityError("backup evidence hash does not match its manifest")
                restored = restored_store.put_bytes(content)
                if restored.relative_path != relative_path:
                    raise BackupIntegrityError("restored evidence path is non-canonical")

            if integrity != "ok" or foreign_key_errors:
                raise BackupIntegrityError("restored database failed integrity validation")
            if revision is None or str(revision[0]) != str(manifest.get("migration_revision")):
                raise BackupIntegrityError("restored database revision differs from its manifest")

            report = RestoreReport(
                data_root=target,
                database_path=target / "database" / "dahe.sqlite3",
                integrity_check=integrity,
                evidence_count=len(evidence_entries),
            )
            if target.exists():
                try:
                    target.rmdir()
                except OSError as exc:
                    raise UnsafeRestoreTargetError(
                        "restore target stopped being an empty directory"
                    ) from exc
            os.replace(staging, target)
            return report
        finally:
            _remove_restore_staging(
                staging,
                target=target,
                target_parent=target_parent,
            )
