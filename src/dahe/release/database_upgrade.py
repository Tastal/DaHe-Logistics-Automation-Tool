from __future__ import annotations

import os
import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError

from dahe.adapters.sqlite.runtime import (
    DatabaseMigrationError,
    SqliteRuntime,
    create_pre_migration_backup,
)


class DatabaseUpgradeError(RuntimeError):
    """Raised before an unsupported database can be changed."""


@dataclass(frozen=True, slots=True)
class DatabasePreflightResult:
    source_revision: str | None
    target_revision: str
    database_path: Path


@dataclass(frozen=True, slots=True)
class DatabaseUpgradeResult:
    source_revision: str | None
    target_revision: str
    backup_path: Path | None


class ReleaseDatabaseUpgrade:
    def __init__(
        self,
        *,
        project_root: Path,
        data_root: Path,
        staging_root: Path,
        minimum_revision: str,
        target_revision: str,
    ) -> None:
        self.project_root = project_root.resolve(strict=True)
        self.data_root = data_root.resolve()
        self.staging_root = staging_root.resolve()
        self.minimum_revision = minimum_revision
        self.target_revision = target_revision
        self.database_path = self.data_root / "database" / "dahe.sqlite3"
        self._script = self._load_script()
        self._supported_revisions = self._load_supported_revisions()

    def _load_script(self) -> ScriptDirectory:
        ini_path = self.project_root / "alembic.ini"
        script_location = (
            self.project_root
            / "src"
            / "dahe"
            / "adapters"
            / "sqlite"
            / "migrations"
        )
        if not ini_path.is_file() or not script_location.is_dir():
            raise DatabaseUpgradeError("release migration files are unavailable")
        config = Config(os.fspath(ini_path))
        config.set_main_option("script_location", os.fspath(script_location))
        return ScriptDirectory.from_config(config)

    def _load_supported_revisions(self) -> frozenset[str]:
        if self._script.get_current_head() != self.target_revision:
            raise DatabaseUpgradeError("release target is not the migration head")
        revisions = [
            str(revision.revision)
            for revision in self._script.iterate_revisions(
                self.target_revision,
                "base",
            )
        ]
        try:
            minimum_index = revisions.index(self.minimum_revision)
        except ValueError as exc:
            raise DatabaseUpgradeError(
                "minimum supported schema is outside the release lineage"
            ) from exc
        return frozenset(revisions[: minimum_index + 1])

    def inspect_revision(self, database_path: Path | None = None) -> str | None:
        path = (database_path or self.database_path).resolve()
        if not path.exists() or path.stat().st_size == 0:
            return None
        try:
            with closing(
                sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
            ) as database:
                database.execute("PRAGMA query_only=ON")
                integrity = str(database.execute("PRAGMA integrity_check").fetchone()[0])
                if integrity != "ok":
                    raise DatabaseUpgradeError("database integrity check failed")
                tables = {
                    str(row[0])
                    for row in database.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if not tables:
                    return None
                if "alembic_version" not in tables:
                    raise DatabaseUpgradeError(
                        "existing database has no supported schema identity"
                    )
                revisions = tuple(
                    str(row[0])
                    for row in database.execute(
                        "SELECT version_num FROM alembic_version"
                    )
                )
        except sqlite3.DatabaseError as exc:
            raise DatabaseUpgradeError("database is not readable SQLite") from exc
        if len(revisions) != 1 or not revisions[0]:
            raise DatabaseUpgradeError("database schema identity is invalid")
        revision = revisions[0]
        try:
            known = self._script.get_revision(revision)
        except CommandError as exc:
            raise DatabaseUpgradeError(
                "database schema is outside the supported release range"
            ) from exc
        if known is None or revision not in self._supported_revisions:
            raise DatabaseUpgradeError(
                "database schema is outside the supported release range"
            )
        return revision

    @staticmethod
    def _online_copy(source: Path, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with (
                closing(
                    sqlite3.connect(
                        f"{source.resolve().as_uri()}?mode=ro",
                        uri=True,
                    )
                ) as source_database,
                closing(sqlite3.connect(target)) as target_database,
            ):
                source_database.backup(target_database)
                target_database.commit()
        except sqlite3.DatabaseError as exc:
            raise DatabaseUpgradeError("database online copy failed") from exc

    def preflight(self) -> DatabasePreflightResult:
        source_revision = self.inspect_revision()
        candidate_root = self.staging_root / f"database-preflight-{uuid4().hex}"
        candidate_database = candidate_root / "database" / "dahe.sqlite3"
        candidate_root.mkdir(parents=True, exist_ok=False)
        if self.database_path.exists() and self.database_path.stat().st_size:
            self._online_copy(self.database_path, candidate_database)
        try:
            runtime = SqliteRuntime(
                data_root=candidate_root,
                project_root=self.project_root,
                instance_id=f"update-preflight-{uuid4().hex}",
            )
            try:
                if runtime.current_revision() != self.target_revision:
                    raise DatabaseUpgradeError(
                        "preflight schema differs from the release target"
                    )
            finally:
                runtime.close()
            if self.inspect_revision(candidate_database) != self.target_revision:
                raise DatabaseUpgradeError("preflight database identity is invalid")
        except (DatabaseMigrationError, OSError) as exc:
            raise DatabaseUpgradeError("database migration preflight failed") from exc
        return DatabasePreflightResult(
            source_revision=source_revision,
            target_revision=self.target_revision,
            database_path=candidate_database,
        )

    def apply(self) -> DatabaseUpgradeResult:
        source_revision = self.inspect_revision()
        backup_path: Path | None = None
        if self.database_path.exists() and self.database_path.stat().st_size:
            try:
                backup_path = create_pre_migration_backup(
                    database_path=self.database_path,
                    backup_root=self.data_root / "backups" / "software-update",
                    from_revision=source_revision or "empty",
                    to_revision=self.target_revision,
                )
            except (DatabaseMigrationError, OSError, sqlite3.DatabaseError) as exc:
                raise DatabaseUpgradeError("formal database backup failed") from exc
        try:
            runtime = SqliteRuntime(
                data_root=self.data_root,
                project_root=self.project_root,
                instance_id=f"software-update-{uuid4().hex}",
            )
            try:
                if runtime.current_revision() != self.target_revision:
                    raise DatabaseUpgradeError(
                        "formal database migration missed its target"
                    )
            finally:
                runtime.close()
        except DatabaseMigrationError as exc:
            raise DatabaseUpgradeError("formal database migration failed") from exc
        return DatabaseUpgradeResult(
            source_revision=source_revision,
            target_revision=self.target_revision,
            backup_path=backup_path,
        )

    def restore(self, backup_path: Path | None) -> None:
        if backup_path is None:
            raise DatabaseUpgradeError("database rollback backup is unavailable")
        source = backup_path.resolve(strict=True) / "dahe.sqlite3"
        if not source.is_file():
            raise DatabaseUpgradeError("database rollback backup is incomplete")
        self.inspect_revision(source)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        staging = self.database_path.with_name(
            f".{self.database_path.name}.restore-{uuid4().hex}.tmp"
        )
        shutil.copy2(source, staging)
        for suffix in ("-wal", "-shm"):
            Path(f"{self.database_path}{suffix}").unlink(missing_ok=True)
        os.replace(staging, self.database_path)
        if self.inspect_revision() not in self._supported_revisions:
            raise DatabaseUpgradeError("restored database identity is invalid")
