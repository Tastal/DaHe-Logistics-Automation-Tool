from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from dahe import __version__
from dahe.adapters.windows.credential_manager import (
    CredentialNotFoundError,
    StoredPlatformCredential,
)
from dahe.api.app import create_app

ORIGIN = "http://127.0.0.1:8877"
PROJECT_ROOT = Path(__file__).parents[2]


class FakeCredentialVault:
    def __init__(self) -> None:
        self.value: StoredPlatformCredential | None = None

    def read(self) -> StoredPlatformCredential:
        if self.value is None:
            raise CredentialNotFoundError("credential is not configured")
        return self.value

    def write(self, *, username: str, password: str) -> None:
        self.value = StoredPlatformCredential(username=username, password=password)

    def delete(self) -> bool:
        existed = self.value is not None
        self.value = None
        return existed


def _read_headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }


def _write_headers(csrf: str, key: str) -> dict[str, str]:
    return {
        **_read_headers(),
        "X-CSRF-Token": csrf,
        "Idempotency-Key": key,
    }


@pytest.fixture
def client(tmp_path: Path) -> Iterator[tuple[TestClient, FakeCredentialVault]]:
    vault = FakeCredentialVault()
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=uuid4().hex,
        auto_run_jobs=False,
        stage_delay_seconds=0,
        platform_credential_vault=vault,
    )
    with TestClient(app) as test_client:
        yield test_client, vault


def _csrf(client: TestClient) -> str:
    response = client.get("/api/v1/session", headers=_read_headers())
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def test_credentials_can_be_saved_replaced_and_deleted_without_password_echo(
    client: tuple[TestClient, FakeCredentialVault],
) -> None:
    test_client, vault = client
    csrf = _csrf(test_client)

    initial = test_client.get(
        "/api/v1/platform/credentials",
        headers=_read_headers(),
    )
    assert initial.status_code == 200
    assert initial.json() == {
        "configured": False,
        "masked_username": None,
        "record_version": 0,
    }
    assert initial.headers["cache-control"] == "no-store"

    saved = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-save"),
        json={
            "username": "finance-user",
            "password": "top-secret-password",
            "expected_record_version": 0,
        },
    )
    assert saved.status_code == 200
    assert saved.json() == {
        "configured": True,
        "masked_username": "fi********er",
        "record_version": 1,
    }
    assert "top-secret-password" not in saved.text
    assert saved.headers["cache-control"] == "no-store"
    assert vault.value is not None
    assert vault.value.password == "top-secret-password"

    replay = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-save"),
        json={
            "username": "finance-user",
            "password": "top-secret-password",
            "expected_record_version": 0,
        },
    )
    assert replay.status_code == 200
    assert replay.json() == saved.json()

    changed_secret_replay = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-save"),
        json={
            "username": "finance-user",
            "password": "different-secret",
            "expected_record_version": 0,
        },
    )
    assert changed_secret_replay.status_code == 409
    assert vault.value is not None
    assert vault.value.password == "top-secret-password"

    replaced = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-replace"),
        json={
            "username": "finance-user-2",
            "password": "replacement-secret",
            "expected_record_version": 1,
        },
    )
    assert replaced.status_code == 200
    assert replaced.json()["record_version"] == 2
    assert vault.value == StoredPlatformCredential(
        username="finance-user-2",
        password="replacement-secret",
    )

    old_replay = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-save"),
        json={
            "username": "finance-user",
            "password": "top-secret-password",
            "expected_record_version": 0,
        },
    )
    assert old_replay.status_code == 200
    assert old_replay.json() == saved.json()
    assert vault.value == StoredPlatformCredential(
        username="finance-user-2",
        password="replacement-secret",
    )

    deleted = test_client.request(
        "DELETE",
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-delete"),
        json={"expected_record_version": 2},
    )
    assert deleted.status_code == 200
    assert deleted.json() == {
        "configured": False,
        "masked_username": None,
        "record_version": 3,
    }
    assert vault.value is None
    data_root = test_client.app.state.sqlite_runtime.data_root
    for path in data_root.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert b"top-secret-password" not in content
            assert b"replacement-secret" not in content


def test_credentials_reject_unknown_fields_stale_versions_and_missing_write_guards(
    client: tuple[TestClient, FakeCredentialVault],
) -> None:
    test_client, _ = client
    csrf = _csrf(test_client)

    unknown = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-unknown"),
        json={
            "username": "finance-user",
            "password": "secret",
            "expected_record_version": 0,
            "operator": "not-allowed",
        },
    )
    assert unknown.status_code == 422

    missing_guard = test_client.put(
        "/api/v1/platform/credentials",
        headers=_read_headers(),
        json={
            "username": "finance-user",
            "password": "secret",
            "expected_record_version": 0,
        },
    )
    assert missing_guard.status_code == 403

    first = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-first"),
        json={
            "username": "finance-user",
            "password": "secret",
            "expected_record_version": 0,
        },
    )
    assert first.status_code == 200

    stale = test_client.put(
        "/api/v1/platform/credentials",
        headers=_write_headers(csrf, "credential-stale"),
        json={
            "username": "finance-user",
            "password": "new-secret",
            "expected_record_version": 0,
        },
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "credential_record_version_conflict"
