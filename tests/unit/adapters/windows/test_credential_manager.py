from __future__ import annotations

import pytest

from dahe.adapters.windows.credential_manager import (
    CredentialNotFoundError,
    StoredPlatformCredential,
    WindowsCredentialVault,
)


class FakeCredentialBackend:
    def __init__(self) -> None:
        self.values: dict[str, StoredPlatformCredential] = {}

    def read(self, target_name: str) -> StoredPlatformCredential:
        try:
            return self.values[target_name]
        except KeyError as exc:
            raise CredentialNotFoundError("credential is not configured") from exc

    def write(
        self,
        target_name: str,
        credential: StoredPlatformCredential,
    ) -> None:
        self.values[target_name] = credential

    def delete(self, target_name: str) -> bool:
        return self.values.pop(target_name, None) is not None


def test_vault_round_trips_and_replaces_secret_without_exposing_backend() -> None:
    backend = FakeCredentialBackend()
    vault = WindowsCredentialVault(backend=backend)

    vault.write(username="finance-user", password="first-secret")
    assert vault.read() == StoredPlatformCredential(
        username="finance-user",
        password="first-secret",
    )

    vault.write(username="finance-user", password="second-secret")
    assert vault.read().password == "second-secret"
    assert tuple(backend.values) == ("DaHeLogistics/Chengfeng/Primary",)


def test_vault_delete_is_idempotent() -> None:
    vault = WindowsCredentialVault(backend=FakeCredentialBackend())

    assert vault.delete() is False
    vault.write(username="finance-user", password="secret")
    assert vault.delete() is True
    assert vault.delete() is False


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("", "secret"),
        ("finance-user", ""),
        (" finance-user", "secret"),
        ("finance-user", "secret\x00suffix"),
    ],
)
def test_vault_rejects_invalid_values(username: str, password: str) -> None:
    vault = WindowsCredentialVault(backend=FakeCredentialBackend())

    with pytest.raises(ValueError):
        vault.write(username=username, password=password)
