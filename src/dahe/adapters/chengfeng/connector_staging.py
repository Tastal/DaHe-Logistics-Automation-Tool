from __future__ import annotations

import hashlib
import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

_COMMAND_DIRECTORY_PATTERN_LENGTH = 64
_REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_STAGING_LOCK = threading.RLock()
_ACTIVE_COMMAND_DIRECTORIES: set[tuple[str, str]] = set()


class ConnectorStagingError(RuntimeError):
    """The connector staging area cannot be consumed or recovered safely."""


@dataclass(frozen=True, slots=True)
class ConnectorStagingRecoveryReport:
    removed_command_directories: int
    retained_active_directories: int


def command_staging_directory_name(command_id: str) -> str:
    return hashlib.sha256(command_id.encode("utf-8")).hexdigest()


def ensure_connector_staging_root(data_root: Path) -> Path:
    lexical_root = data_root.absolute()
    lexical_root.mkdir(parents=True, exist_ok=True)
    _require_normal_directory(lexical_root)
    staging_root = lexical_root / "connector-staging"
    staging_root.mkdir(exist_ok=True)
    _require_normal_directory(staging_root)
    return staging_root


def begin_command_staging(*, data_root: Path, command_id: str) -> Path:
    staging_root = ensure_connector_staging_root(data_root)
    directory_name = command_staging_directory_name(command_id)
    key = _active_key(data_root, directory_name)
    with _STAGING_LOCK:
        if key in _ACTIVE_COMMAND_DIRECTORIES:
            raise ConnectorStagingError("connector command staging is already active")
        _ACTIVE_COMMAND_DIRECTORIES.add(key)
        command_directory = staging_root / directory_name
        try:
            command_directory.mkdir(exist_ok=False)
        except OSError as error:
            _ACTIVE_COMMAND_DIRECTORIES.discard(key)
            raise ConnectorStagingError("connector command staging cannot be created") from error
        return command_directory


def cleanup_command_staging(*, data_root: Path, command_id: str) -> bool:
    staging_root = ensure_connector_staging_root(data_root)
    directory_name = command_staging_directory_name(command_id)
    key = _active_key(data_root, directory_name)
    command_directory = staging_root / directory_name
    with _STAGING_LOCK:
        try:
            command_directory.lstat()
        except FileNotFoundError:
            _ACTIVE_COMMAND_DIRECTORIES.discard(key)
            return False
        try:
            _remove_command_directory(command_directory)
            return True
        finally:
            _ACTIVE_COMMAND_DIRECTORIES.discard(key)


def recover_connector_staging(data_root: Path) -> ConnectorStagingRecoveryReport:
    """Remove safe orphan command directories before a connector runtime starts."""

    staging_root = ensure_connector_staging_root(data_root)
    removed = 0
    retained = 0
    with _STAGING_LOCK:
        for candidate in staging_root.iterdir():
            if (
                len(candidate.name) != _COMMAND_DIRECTORY_PATTERN_LENGTH
                or any(character not in "0123456789abcdef" for character in candidate.name)
            ):
                raise ConnectorStagingError("connector staging contains an unknown entry")
            if _active_key(data_root, candidate.name) in _ACTIVE_COMMAND_DIRECTORIES:
                retained += 1
                continue
            _remove_command_directory(candidate)
            removed += 1
    return ConnectorStagingRecoveryReport(
        removed_command_directories=removed,
        retained_active_directories=retained,
    )


def _remove_command_directory(directory: Path) -> None:
    _require_normal_directory(directory)
    children = tuple(directory.iterdir())
    for child in children:
        metadata = child.lstat()
        if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise ConnectorStagingError("connector command staging contains an unsafe entry")
    for child in children:
        child.unlink()
    try:
        directory.rmdir()
    except OSError as error:
        raise ConnectorStagingError("connector command staging changed during cleanup") from error


def _require_normal_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ConnectorStagingError("connector staging directory is unavailable") from error
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ConnectorStagingError("connector staging path must be a normal directory")


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT_ATTRIBUTE)


def _active_key(data_root: Path, directory_name: str) -> tuple[str, str]:
    return os.path.normcase(str(data_root.absolute())), directory_name
