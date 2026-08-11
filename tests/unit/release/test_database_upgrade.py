from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.release.database_upgrade import (
    DatabaseUpgradeError,
    ReleaseDatabaseUpgrade,
)

PROJECT_ROOT = Path(__file__).parents[3]
REVISION = "0039_network_batch_default"


def _database(data_root: Path) -> Path:
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id="release-database-test",
    )
    database_path = runtime.database_path
    runtime.close()
    return database_path


def _upgrade(tmp_path: Path) -> ReleaseDatabaseUpgrade:
    return ReleaseDatabaseUpgrade(
        project_root=PROJECT_ROOT,
        data_root=tmp_path / "data",
        staging_root=tmp_path / "staging",
        minimum_revision=REVISION,
        target_revision=REVISION,
    )


def test_empty_database_preflight_reaches_the_release_revision(
    tmp_path: Path,
) -> None:
    upgrade = _upgrade(tmp_path)

    result = upgrade.preflight()

    assert result.source_revision is None
    assert result.target_revision == REVISION
    assert result.database_path.is_file()
    with sqlite3.connect(result.database_path) as database:
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert database.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone() == (REVISION,)


def test_current_schema_preflight_uses_an_online_copy_and_is_repeatable(
    tmp_path: Path,
) -> None:
    upgrade = _upgrade(tmp_path)
    original = _database(upgrade.data_root)

    first = upgrade.preflight()
    second = upgrade.preflight()

    assert first.source_revision == REVISION
    assert second.source_revision == REVISION
    assert first.database_path != original
    assert second.database_path != original
    assert original.is_file()


@pytest.mark.parametrize("content", [b"not sqlite", b""])
def test_invalid_or_unidentified_existing_database_is_rejected(
    tmp_path: Path,
    content: bytes,
) -> None:
    upgrade = _upgrade(tmp_path)
    database_path = upgrade.database_path
    database_path.parent.mkdir(parents=True)
    database_path.write_bytes(content)
    if not content:
        with sqlite3.connect(database_path) as database:
            database.execute("CREATE TABLE unsafe(value TEXT)")

    with pytest.raises(DatabaseUpgradeError):
        upgrade.preflight()


def test_unknown_schema_is_rejected_without_modifying_the_database(
    tmp_path: Path,
) -> None:
    upgrade = _upgrade(tmp_path)
    upgrade.database_path.parent.mkdir(parents=True)
    with sqlite3.connect(upgrade.database_path) as database:
        database.execute("CREATE TABLE alembic_version(version_num TEXT)")
        database.execute(
            "INSERT INTO alembic_version VALUES ('9999_unknown_release')"
        )
    before = upgrade.database_path.read_bytes()

    with pytest.raises(DatabaseUpgradeError, match="supported"):
        upgrade.preflight()

    assert upgrade.database_path.read_bytes() == before


def test_formal_upgrade_creates_a_backup_that_can_restore_before_readiness(
    tmp_path: Path,
) -> None:
    upgrade = _upgrade(tmp_path)
    database_path = _database(upgrade.data_root)

    result = upgrade.apply()

    assert result.source_revision == REVISION
    assert result.backup_path is not None
    with closing(sqlite3.connect(database_path)) as database:
        database.execute("CREATE TABLE post_upgrade_user_action(value TEXT)")
        database.commit()
    upgrade.restore(result.backup_path)
    with closing(sqlite3.connect(database_path)) as database:
        tables = {
            row[0]
            for row in database.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert "post_upgrade_user_action" not in tables
    assert upgrade.inspect_revision() == REVISION


def test_formal_upgrade_is_idempotent_for_the_current_release(tmp_path: Path) -> None:
    upgrade = _upgrade(tmp_path)
    _database(upgrade.data_root)

    first = upgrade.apply()
    second = upgrade.apply()

    assert first.target_revision == REVISION
    assert second.target_revision == REVISION
    assert upgrade.inspect_revision() == REVISION
