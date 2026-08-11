from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from threading import RLock
from typing import Protocol

from dahe.ports.platform_credentials import (
    CredentialNotFoundError,
    PlatformCredentialVault,
    StoredPlatformCredential,
)


class PlatformCredentialConflictError(RuntimeError):
    """Raised when credential metadata changes concurrently."""


@dataclass(frozen=True, slots=True)
class PlatformCredentialConfig:
    configured: bool
    masked_username: str | None
    record_version: int


class PlatformCredentialConfigStore(Protocol):
    def get(self) -> PlatformCredentialConfig: ...

    def replay(
        self,
        *,
        operation: str,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> PlatformCredentialConfig | None: ...

    def commit(
        self,
        *,
        operation: str,
        configured: bool,
        masked_username: str | None,
        expected_record_version: int,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> PlatformCredentialConfig: ...


def mask_username(username: str) -> str:
    if len(username) <= 2:
        return "*" * len(username)
    if len(username) <= 4:
        return f"{username[0]}{'*' * (len(username) - 2)}{username[-1]}"
    return f"{username[:2]}{'*' * (len(username) - 4)}{username[-2:]}"


def _request_fingerprint(
    *,
    operation: str,
    username: str | None,
    password: str | None,
    expected_record_version: int,
) -> str:
    payload = {
        "expected_record_version": expected_record_version,
        "operation": operation,
        "password_sha256": (
            None
            if password is None
            else hashlib.sha256(password.encode("utf-8")).hexdigest()
        ),
        "username": username,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class PlatformCredentialService:
    def __init__(
        self,
        *,
        vault: PlatformCredentialVault,
        store: PlatformCredentialConfigStore,
    ) -> None:
        self._vault = vault
        self._store = store
        self._lock = RLock()

    def status(self) -> PlatformCredentialConfig:
        configured = self._store.get()
        if not configured.configured:
            return configured
        try:
            self._vault.read()
        except CredentialNotFoundError:
            return PlatformCredentialConfig(
                configured=False,
                masked_username=None,
                record_version=configured.record_version,
            )
        return configured

    def save(
        self,
        *,
        username: str,
        password: str,
        expected_record_version: int,
        idempotency_key: str,
    ) -> PlatformCredentialConfig:
        fingerprint = _request_fingerprint(
            operation="save",
            username=username,
            password=password,
            expected_record_version=expected_record_version,
        )
        with self._lock:
            replay = self._store.replay(
                operation="save",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
            )
            if replay is not None:
                return replay
            current = self._store.get()
            if current.record_version != expected_record_version:
                raise PlatformCredentialConflictError(
                    "credential record version changed"
                )
            previous: StoredPlatformCredential | None
            try:
                previous = self._vault.read()
            except CredentialNotFoundError:
                previous = None
            self._vault.write(username=username, password=password)
            try:
                return self._store.commit(
                    operation="save",
                    configured=True,
                    masked_username=mask_username(username),
                    expected_record_version=expected_record_version,
                    idempotency_key=idempotency_key,
                    request_fingerprint=fingerprint,
                )
            except Exception:
                if previous is None:
                    self._vault.delete()
                else:
                    self._vault.write(
                        username=previous.username,
                        password=previous.password,
                    )
                raise

    def delete(
        self,
        *,
        expected_record_version: int,
        idempotency_key: str,
    ) -> PlatformCredentialConfig:
        fingerprint = _request_fingerprint(
            operation="delete",
            username=None,
            password=None,
            expected_record_version=expected_record_version,
        )
        with self._lock:
            replay = self._store.replay(
                operation="delete",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
            )
            if replay is not None:
                return replay
            current = self._store.get()
            if current.record_version != expected_record_version:
                raise PlatformCredentialConflictError(
                    "credential record version changed"
                )
            previous: StoredPlatformCredential | None
            try:
                previous = self._vault.read()
            except CredentialNotFoundError:
                previous = None
            self._vault.delete()
            try:
                return self._store.commit(
                    operation="delete",
                    configured=False,
                    masked_username=None,
                    expected_record_version=expected_record_version,
                    idempotency_key=idempotency_key,
                    request_fingerprint=fingerprint,
                )
            except Exception:
                if previous is not None:
                    self._vault.write(
                        username=previous.username,
                        password=previous.password,
                    )
                raise
