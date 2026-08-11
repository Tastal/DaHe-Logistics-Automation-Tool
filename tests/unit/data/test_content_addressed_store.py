from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from types import ModuleType

import pytest

SYNTHETIC_EVIDENCE = b"\x89PNG\r\n\x1a\nDaHe Loop 4 synthetic evidence"


def _module() -> ModuleType:
    return importlib.import_module("dahe.adapters.files.content_addressed")


def _store(module: ModuleType, root: Path) -> object:
    return module.ContentAddressedEvidenceStore(root)


def test_put_bytes_is_content_addressed_and_deduplicated(tmp_path: Path) -> None:
    module = _module()
    evidence_root = tmp_path / "evidence"
    store = _store(module, evidence_root)
    expected_sha256 = hashlib.sha256(SYNTHETIC_EVIDENCE).hexdigest()

    first = store.put_bytes(SYNTHETIC_EVIDENCE)
    second = store.put_bytes(SYNTHETIC_EVIDENCE)

    assert first.sha256 == expected_sha256
    assert second.sha256 == expected_sha256
    assert first.relative_path == second.relative_path
    assert not Path(first.relative_path).is_absolute()
    canonical_path = (evidence_root / first.relative_path).resolve()
    assert canonical_path.is_relative_to(evidence_root.resolve())
    assert canonical_path.read_bytes() == SYNTHETIC_EVIDENCE
    assert store.read_bytes(expected_sha256) == SYNTHETIC_EVIDENCE
    assert [path for path in (evidence_root / "sha256").rglob("*") if path.is_file()] == [
        canonical_path
    ]


def test_read_bytes_rejects_a_corrupted_canonical_blob(tmp_path: Path) -> None:
    module = _module()
    evidence_root = tmp_path / "evidence"
    store = _store(module, evidence_root)
    stored = store.put_bytes(SYNTHETIC_EVIDENCE)
    (evidence_root / stored.relative_path).write_bytes(b"corrupted")

    with pytest.raises(module.EvidenceIntegrityError):
        store.read_bytes(stored.sha256)


def test_recover_staging_removes_only_uncommitted_parts(tmp_path: Path) -> None:
    module = _module()
    evidence_root = tmp_path / "evidence"
    store = _store(module, evidence_root)
    stored = store.put_bytes(SYNTHETIC_EVIDENCE)
    staging = evidence_root / ".staging"
    staging.mkdir(parents=True, exist_ok=True)
    orphan = staging / "interrupted-write.part"
    orphan.write_bytes(b"incomplete")

    report = store.recover_staging()

    assert report.removed_count == 1
    assert not orphan.exists()
    assert store.read_bytes(stored.sha256) == SYNTHETIC_EVIDENCE


@pytest.mark.parametrize("unsafe_identity", ["../outside", "not-a-sha256", "A" * 64])
def test_read_bytes_rejects_unsafe_or_noncanonical_identity(
    tmp_path: Path,
    unsafe_identity: str,
) -> None:
    module = _module()
    store = _store(module, tmp_path / "evidence")

    with pytest.raises(module.InvalidEvidenceIdentityError):
        store.read_bytes(unsafe_identity)
