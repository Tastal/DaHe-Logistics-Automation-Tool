from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class PlatformCredentialError(RuntimeError):
    """Raised when the local platform credential cannot be handled safely."""


class CredentialNotFoundError(PlatformCredentialError):
    """Raised when no credential exists for the fixed platform target."""


@dataclass(frozen=True, slots=True)
class StoredPlatformCredential:
    username: str
    password: str


class PlatformCredentialVault(Protocol):
    def read(self) -> StoredPlatformCredential: ...

    def write(self, *, username: str, password: str) -> None: ...

    def delete(self) -> bool: ...
