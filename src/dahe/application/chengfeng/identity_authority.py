from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dahe.application.chengfeng.shadow_batch import (
    chengfeng_shadow_identity_context_sha256,
)

IDENTITY_NAMESPACE = "chengfeng:waybill"
_KEY_BYTES = 32
_KEY_NAME = "loop9-platform-identity.key"


class Loop9IdentityAuthorityError(RuntimeError):
    """Raised when the local cross-dataset identity authority is unsafe."""


@dataclass(frozen=True, slots=True)
class Loop9IdentityAuthority:
    salt: bytes = field(repr=False)
    namespace: str = IDENTITY_NAMESPACE
    context_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.salt, bytes) or len(self.salt) != _KEY_BYTES:
            raise Loop9IdentityAuthorityError(
                "platform identity key is invalid"
            )
        if self.namespace != IDENTITY_NAMESPACE:
            raise Loop9IdentityAuthorityError(
                "platform identity namespace is invalid"
            )
        object.__setattr__(
            self,
            "context_sha256",
            chengfeng_shadow_identity_context_sha256(
                salt=self.salt,
                namespace=self.namespace,
            ),
        )


def load_or_create_loop9_identity_authority(
    data_root: Path,
) -> Loop9IdentityAuthority:
    """Load one installation-local key without exposing it in evidence."""

    root = _real_directory(data_root, label="data root")
    secrets_root = root / "secrets"
    if secrets_root.is_symlink():
        raise Loop9IdentityAuthorityError(
            "platform identity authority directory is unsafe"
        )
    secrets_root.mkdir(mode=0o700, parents=False, exist_ok=True)
    secrets_root = _real_directory(
        secrets_root,
        label="platform identity authority directory",
    )
    key_path = secrets_root / _KEY_NAME
    if key_path.is_symlink():
        raise Loop9IdentityAuthorityError(
            "platform identity authority is unsafe"
        )
    if not key_path.exists():
        _create_key(key_path)
    return Loop9IdentityAuthority(salt=_read_stable_key(key_path))


def load_loop9_identity_authority(
    data_root: Path,
) -> Loop9IdentityAuthority:
    """Load an existing formal identity key without creating any state."""

    root = _real_directory(data_root, label="data root")
    secrets_root = root / "secrets"
    if secrets_root.is_symlink():
        raise Loop9IdentityAuthorityError(
            "platform identity authority directory is unsafe"
        )
    try:
        secrets_root = _real_directory(
            secrets_root,
            label="platform identity authority directory",
        )
    except Loop9IdentityAuthorityError as exc:
        raise Loop9IdentityAuthorityError(
            "platform identity authority is unavailable"
        ) from exc
    key_path = secrets_root / _KEY_NAME
    if not key_path.exists():
        raise Loop9IdentityAuthorityError(
            "platform identity authority is unavailable"
        )
    return Loop9IdentityAuthority(salt=_read_stable_key(key_path))


def _real_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise Loop9IdentityAuthorityError(f"{label} is unsafe")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9IdentityAuthorityError(f"{label} is unavailable") from exc
    if resolved != path or not resolved.is_dir():
        raise Loop9IdentityAuthorityError(f"{label} is unsafe")
    return resolved


def _create_key(path: Path) -> None:
    value = secrets.token_bytes(_KEY_BYTES)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        return
    except OSError as exc:
        raise Loop9IdentityAuthorityError(
            "platform identity authority could not be created"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise Loop9IdentityAuthorityError(
            "platform identity authority could not be committed"
        ) from exc


def _read_stable_key(path: Path) -> bytes:
    try:
        before = path.stat()
        if (
            path.is_symlink()
            or not path.is_file()
            or path.resolve(strict=True) != path
            or before.st_size != _KEY_BYTES
        ):
            raise Loop9IdentityAuthorityError(
                "platform identity authority is invalid"
            )
        value = path.read_bytes()
        after = path.stat()
    except Loop9IdentityAuthorityError:
        raise
    except OSError as exc:
        raise Loop9IdentityAuthorityError(
            "platform identity authority is unavailable"
        ) from exc
    if (
        len(value) != _KEY_BYTES
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise Loop9IdentityAuthorityError(
            "platform identity authority changed while being read"
        )
    return value
