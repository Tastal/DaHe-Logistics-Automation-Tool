from __future__ import annotations

from pathlib import Path

import pytest

from dahe.application.chengfeng.identity_authority import (
    Loop9IdentityAuthorityError,
    load_loop9_identity_authority,
    load_or_create_loop9_identity_authority,
)


def test_identity_authority_is_stable_and_does_not_expose_key(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()

    first = load_or_create_loop9_identity_authority(root)
    second = load_or_create_loop9_identity_authority(root)

    assert first.salt == second.salt
    assert first.context_sha256 == second.context_sha256
    assert len(first.salt) == 32
    assert first.salt.hex() not in repr(first)
    assert first.namespace == "chengfeng:waybill"


def test_identity_authority_rejects_tampered_or_linked_key(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    load_or_create_loop9_identity_authority(root)
    key = root / "secrets" / "loop9-platform-identity.key"
    key.write_bytes(b"short")

    with pytest.raises(Loop9IdentityAuthorityError, match="invalid"):
        load_or_create_loop9_identity_authority(root)


def test_formal_identity_authority_loader_never_creates_missing_state(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()

    with pytest.raises(Loop9IdentityAuthorityError, match="unavailable"):
        load_loop9_identity_authority(root)

    assert not (root / "secrets").exists()

    created = load_or_create_loop9_identity_authority(root)
    loaded = load_loop9_identity_authority(root)
    assert loaded == created
