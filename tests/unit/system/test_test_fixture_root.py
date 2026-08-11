from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from dahe.system.test_fixture_root import (
    TEST_FIXTURE_MARKER,
    FixtureDataRootError,
    enforce_test_fixture_root,
)


def test_fixture_root_is_claimed_once_and_cannot_be_used_as_normal_data(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "fixture-data"
    (data_root / "runtime").mkdir(parents=True)

    enforce_test_fixture_root(data_root, fixtures_enabled=True)
    marker = data_root / "runtime" / TEST_FIXTURE_MARKER
    assert marker.is_file()
    first_content = marker.read_bytes()

    enforce_test_fixture_root(data_root, fixtures_enabled=True)
    assert marker.read_bytes() == first_content
    with pytest.raises(FixtureDataRootError, match="cannot run"):
        enforce_test_fixture_root(data_root, fixtures_enabled=False)


def test_fixture_root_rejects_existing_unmarked_data(tmp_path: Path) -> None:
    data_root = tmp_path / "existing-data"
    database = data_root / "database" / "dahe.sqlite3"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"existing production-like data")

    with pytest.raises(FixtureDataRootError, match="new or previously marked"):
        enforce_test_fixture_root(data_root, fixtures_enabled=True)
    assert not (data_root / "runtime" / TEST_FIXTURE_MARKER).exists()


def test_copied_fixture_marker_is_rejected_for_another_root(
    tmp_path: Path,
) -> None:
    original = tmp_path / "original"
    (original / "runtime").mkdir(parents=True)
    enforce_test_fixture_root(original, fixtures_enabled=True)

    copied = tmp_path / "copied"
    (copied / "runtime").mkdir(parents=True)
    shutil.copyfile(
        original / "runtime" / TEST_FIXTURE_MARKER,
        copied / "runtime" / TEST_FIXTURE_MARKER,
    )

    with pytest.raises(FixtureDataRootError, match="does not match"):
        enforce_test_fixture_root(copied, fixtures_enabled=True)
