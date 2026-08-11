from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from uuid import uuid4

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import URL, Connection, Engine


class DatabaseMigrationError(RuntimeError):
    """Raised when a database cannot be identified or migrated safely."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_pre_migration_backup(
    *,
    database_path: Path,
    backup_root: Path,
    from_revision: str,
    to_revision: str,
) -> Path:
    """Create and validate a recoverable database copy before schema writes."""
    backup_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid4().hex[:12]
    root = backup_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f".{backup_id}.partial"
    final = root / backup_id
    staging.mkdir(parents=False, exist_ok=False)
    database_copy = staging / "dahe.sqlite3"
    try:
        source_uri = f"{database_path.resolve().as_uri()}?mode=ro"
        with (
            closing(sqlite3.connect(source_uri, uri=True)) as source,
            closing(sqlite3.connect(database_copy)) as destination,
        ):
            source.backup(destination)
            integrity = str(destination.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity != "ok":
                raise DatabaseMigrationError("pre-migration backup failed integrity validation")
            destination.commit()
        manifest = {
            "backup_kind": "pre_migration",
            "created_at": datetime.now(UTC).isoformat(),
            "database_sha256": _sha256_file(database_copy),
            "from_revision": from_revision,
            "to_revision": to_revision,
        }
        manifest_path = staging / "manifest.json"
        with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        staging.rename(final)
        return final
    except Exception:
        for child in staging.iterdir() if staging.exists() else ():
            child.unlink(missing_ok=True)
        staging.rmdir()
        raise


class ShortTransactionCommitGate:
    """Serialize main-process write transactions without holding file I/O."""

    def __init__(self) -> None:
        self._lock = threading.RLock()

    def __enter__(self) -> ShortTransactionCommitGate:
        self._lock.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._lock.release()

    @contextmanager
    def transaction(self, engine: Engine) -> Iterator[Connection]:
        with self, engine.begin() as connection:
            yield connection


def _configure_connection(
    dbapi_connection: sqlite3.Connection,
    _: object,
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA journal_mode=WAL")
    finally:
        cursor.close()


class SqliteRuntime:
    """Open the durable database only after its Alembic contract is current."""

    def __init__(
        self,
        *,
        data_root: Path,
        project_root: Path,
        instance_id: str,
    ) -> None:
        if not instance_id.strip():
            raise ValueError("instance_id is required")
        self.data_root = data_root.resolve()
        self.project_root = project_root.resolve()
        self.instance_id = instance_id
        database_directory = self.data_root / "database"
        database_directory.mkdir(parents=True, exist_ok=True)
        self.database_path = database_directory / "dahe.sqlite3"
        self.commit_gate = ShortTransactionCommitGate()
        self._alembic_config = self._build_alembic_config()
        existing_revision = self._inspect_existing_database()
        self.pre_migration_backup_path: Path | None = None
        if existing_revision is not None and existing_revision != self.head_revision:
            self.pre_migration_backup_path = create_pre_migration_backup(
                database_path=self.database_path,
                backup_root=self.data_root / "backups" / "pre-migration",
                from_revision=existing_revision,
                to_revision=self.head_revision,
            )
        try:
            command.upgrade(self._alembic_config, "head")
        except Exception as exc:
            raise DatabaseMigrationError(
                "database migration failed; the application did not start"
            ) from exc

        url = URL.create("sqlite+pysqlite", database=str(self.database_path))
        self.engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
        )
        event.listen(self.engine, "connect", _configure_connection)
        self._verify_runtime()

    def _build_alembic_config(self) -> Config:
        ini_path = self.project_root / "alembic.ini"
        script_location = self.project_root / "src" / "dahe" / "adapters" / "sqlite" / "migrations"
        if not ini_path.is_file() or not script_location.is_dir():
            raise DatabaseMigrationError("checked-in Alembic configuration is missing")
        config = Config(str(ini_path))
        config.set_main_option("script_location", str(script_location))
        url = URL.create("sqlite+pysqlite", database=str(self.database_path))
        config.set_main_option(
            "sqlalchemy.url",
            url.render_as_string(hide_password=False).replace("%", "%%"),
        )
        return config

    def _inspect_existing_database(self) -> str | None:
        if not self.database_path.exists() or self.database_path.stat().st_size == 0:
            return None
        try:
            with closing(
                sqlite3.connect(
                    f"{self.database_path.resolve().as_uri()}?mode=ro",
                    uri=True,
                )
            ) as connection:
                connection.execute("PRAGMA query_only=ON")
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if not tables:
                    return None
                if "alembic_version" not in tables:
                    raise DatabaseMigrationError(
                        "existing database has no Alembic identity and was not modified"
                    )
                revisions = tuple(
                    str(row[0])
                    for row in connection.execute("SELECT version_num FROM alembic_version")
                )
        except sqlite3.DatabaseError as exc:
            raise DatabaseMigrationError("existing database is not a readable SQLite file") from exc
        if len(revisions) != 1 or not revisions[0]:
            raise DatabaseMigrationError("existing database has an invalid Alembic revision record")
        revision = revisions[0]
        try:
            known_revision = ScriptDirectory.from_config(self._alembic_config).get_revision(
                revision
            )
        except CommandError as exc:
            raise DatabaseMigrationError(
                "existing database revision is unknown and was not modified"
            ) from exc
        if known_revision is None:
            raise DatabaseMigrationError(
                "existing database revision is unknown and was not modified"
            )
        return revision

    @property
    def head_revision(self) -> str:
        head = ScriptDirectory.from_config(self._alembic_config).get_current_head()
        if head is None:
            raise DatabaseMigrationError("Alembic has no migration head")
        return head

    def current_revision(self) -> str:
        with self.engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version"))
            value = revision.scalar_one()
        return str(value)

    def _verify_runtime(self) -> None:
        with self.engine.connect() as connection:
            journal_mode = str(
                connection.exec_driver_sql("PRAGMA journal_mode").scalar_one()
            ).lower()
            foreign_keys = int(connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one())
            busy_timeout = int(connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one())
            integrity = str(connection.exec_driver_sql("PRAGMA integrity_check").scalar_one())
        if journal_mode != "wal":
            raise DatabaseMigrationError("SQLite WAL mode could not be enabled")
        if foreign_keys != 1:
            raise DatabaseMigrationError("SQLite foreign keys could not be enabled")
        if busy_timeout < 1000:
            raise DatabaseMigrationError("SQLite busy timeout is unsafe")
        if integrity != "ok":
            raise DatabaseMigrationError("SQLite integrity check failed")
        if self.current_revision() != self.head_revision:
            raise DatabaseMigrationError("database migration head does not match the application")

    def close(self) -> None:
        self.engine.dispose()
