from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

TEST_FIXTURE_MARKER = "test-fixture-root.json"


class FixtureDataRootError(RuntimeError):
    """Raised when test fixtures could touch a non-test data root."""


def _root_identity(data_root: Path) -> str:
    canonical = str(data_root.resolve()).casefold().encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _marker_path(data_root: Path) -> Path:
    return data_root.resolve() / "runtime" / TEST_FIXTURE_MARKER


def _read_marker(marker: Path, *, data_root: Path) -> None:
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FixtureDataRootError(
            "test fixture data-root marker is unreadable"
        ) from exc
    expected = {
        "data_root_identity": _root_identity(data_root),
        "profile": "test_fixture",
        "schema_version": 1,
    }
    if payload != expected:
        raise FixtureDataRootError(
            "test fixture data-root marker does not match this directory"
        )


def enforce_test_fixture_root(
    data_root: Path,
    *,
    fixtures_enabled: bool,
) -> None:
    """Claim an empty root for fixtures and prevent later profile mixing."""

    resolved_root = data_root.resolve()
    marker = _marker_path(resolved_root)
    if marker.exists():
        _read_marker(marker, data_root=resolved_root)
        if not fixtures_enabled:
            raise FixtureDataRootError(
                "a test-fixture data root cannot run without the fixture gate"
            )
        return
    if not fixtures_enabled:
        return

    existing_files = tuple(
        path
        for path in resolved_root.rglob("*")
        if path.is_file()
    )
    if existing_files:
        raise FixtureDataRootError(
            "test fixtures require a new or previously marked data root"
        )
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "data_root_identity": _root_identity(resolved_root),
        "profile": "test_fixture",
        "schema_version": 1,
    }
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    try:
        file_descriptor = os.open(
            marker,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError:
        _read_marker(marker, data_root=resolved_root)
        return
    try:
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        marker.unlink(missing_ok=True)
        raise
