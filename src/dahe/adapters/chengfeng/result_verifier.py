from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from dahe.adapters.chengfeng.protocol import (
    ConnectorCommand,
    ConnectorPayloadKind,
    ConnectorResult,
)
from dahe.ports.chengfeng import BrowserNavigationAuthorizer

_STAGING_DIRECTORY = "connector-staging"
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "AUX",
        "CON",
        "CONIN$",
        "CONOUT$",
        "NUL",
        "PRN",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)
_REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class ResultFileVerificationError(ValueError):
    """The connector result points to an unsafe or invalid staged file."""


@dataclass(frozen=True, slots=True)
class VerifiedConnectorPayload:
    """Immutable staged content whose declared metadata has been reverified."""

    kind: ConnectorPayloadKind
    relative_path: str
    sha256: str
    media_type: str
    byte_size: int
    content: bytes


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT_ATTRIBUTE)


def _validate_relative_parts(relative_path: str) -> tuple[str, ...]:
    parts = tuple(relative_path.split("/"))
    if (
        len(parts) < 2
        or parts[0] != _STAGING_DIRECTORY
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ResultFileVerificationError(
            "payload path must be beneath the dedicated connector-staging directory"
        )
    for part in parts:
        if part.endswith((" ", ".")):
            raise ResultFileVerificationError("payload path contains an unsafe component")
        base_name = part.split(".", maxsplit=1)[0].upper()
        if base_name in _WINDOWS_RESERVED_NAMES:
            raise ResultFileVerificationError("payload path contains a Windows reserved name")
    return parts


def _stat_component(path: Path, *, expect_directory: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ResultFileVerificationError("staged payload path does not exist") from error
    if _is_link_or_reparse(metadata):
        raise ResultFileVerificationError("staged payload path contains a symlink or reparse point")
    if expect_directory and not stat.S_ISDIR(metadata.st_mode):
        raise ResultFileVerificationError("staged payload parent component is not a directory")
    if not expect_directory and not stat.S_ISREG(metadata.st_mode):
        raise ResultFileVerificationError("staged payload is not a regular file")
    return metadata


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _validate_media(
    content: bytes,
    *,
    kind: ConnectorPayloadKind,
    media_type: str,
) -> None:
    if kind in {
        ConnectorPayloadKind.WAYBILL_PAGE,
        ConnectorPayloadKind.WAYBILL_DETAIL,
    }:
        if media_type != "application/json":
            raise ResultFileVerificationError(
                "staged JSON payload has an invalid declared media type"
            )
        try:
            json.loads(content.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ResultFileVerificationError(
                "staged JSON payload is not valid UTF-8 JSON"
            ) from error
        return
    if media_type == "image/png" and content.startswith(_PNG_SIGNATURE):
        return
    if (
        media_type == "image/jpeg"
        and content.startswith(b"\xff\xd8\xff")
        and content.endswith(b"\xff\xd9")
    ):
        return
    raise ResultFileVerificationError(
        "staged ticket payload does not match a supported image signature"
    )


def _read_verified_file(
    *,
    data_root: Path,
    relative_path: str,
    expected_size: int,
    expected_sha256: str,
    kind: ConnectorPayloadKind,
    media_type: str,
) -> bytes:
    parts = _validate_relative_parts(relative_path)
    lexical_root = data_root.absolute()
    target = lexical_root.joinpath(*parts)
    try:
        contained = os.path.commonpath((str(lexical_root), str(target))) == str(lexical_root)
    except ValueError as error:
        raise ResultFileVerificationError("staged payload path escapes data root") from error
    if not contained:
        raise ResultFileVerificationError("staged payload path escapes data root")

    _stat_component(lexical_root, expect_directory=True)
    current = lexical_root
    for component in parts[:-1]:
        current /= component
        _stat_component(current, expect_directory=True)
    before = _stat_component(target, expect_directory=False)
    if before.st_size != expected_size:
        raise ResultFileVerificationError("staged payload size does not match result")

    with target.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if _is_link_or_reparse(opened) or not stat.S_ISREG(opened.st_mode):
            raise ResultFileVerificationError("staged payload is not a safe regular file")
        if _stat_identity(opened) != _stat_identity(before):
            raise ResultFileVerificationError("staged payload changed before it was opened")
        content = handle.read(expected_size + 1)
    after = _stat_component(target, expect_directory=False)
    if _stat_identity(after) != _stat_identity(before):
        raise ResultFileVerificationError("staged payload changed while it was read")
    if len(content) != expected_size:
        raise ResultFileVerificationError("staged payload size does not match result")
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ResultFileVerificationError("staged payload SHA-256 does not match result")
    _validate_media(content, kind=kind, media_type=media_type)
    return content


def verify_connector_result_files(
    *,
    command: ConnectorCommand,
    result: ConnectorResult,
    data_root: Path,
    authorizer: BrowserNavigationAuthorizer,
) -> tuple[VerifiedConnectorPayload, ...]:
    """Verify staged connector outputs between two browser-authority fences."""

    result.validate_for(command)
    expected_command_directory = hashlib.sha256(command.command_id.encode("utf-8")).hexdigest()
    for reference in result.payload_references:
        parts = _validate_relative_parts(reference.relative_path)
        if len(parts) != 3 or parts[1] != expected_command_directory:
            raise ResultFileVerificationError(
                "staged payload does not belong to the originating connector command"
            )
    authorizer.authorize(command.authority)
    verified = tuple(
        VerifiedConnectorPayload(
            kind=reference.kind,
            relative_path=reference.relative_path,
            sha256=reference.sha256,
            media_type=reference.media_type,
            byte_size=reference.byte_size,
            content=_read_verified_file(
                data_root=data_root,
                relative_path=reference.relative_path,
                expected_size=reference.byte_size,
                expected_sha256=reference.sha256,
                kind=reference.kind,
                media_type=reference.media_type,
            ),
        )
        for reference in result.payload_references
    )
    authorizer.authorize(command.authority)
    return verified
