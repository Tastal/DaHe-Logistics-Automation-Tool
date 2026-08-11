from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tools import bootstrap_dev_quality as module
from tools.dev_quality import load_manifest


def test_quality_lock_matches_the_approved_manifest() -> None:
    manifest = load_manifest()

    assert module._locked_python_requirements(manifest) == (
        "pip-audit==2.10.1",
        "py-spy==0.4.2",
        "schemathesis==4.24.3",
    )


def test_archive_digest_must_match_before_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "tool.zip"
    archive.write_bytes(b"not an approved release")

    with pytest.raises(ValueError, match="SHA-256"):
        module._verify_sha256(archive, "0" * 64)

    expected = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert module._verify_sha256(archive, expected) == expected


@pytest.mark.parametrize(
    "member",
    ["../outside.exe", "/absolute.exe", "folder/../../outside.exe"],
)
def test_zip_members_must_remain_inside_the_runtime(member: str) -> None:
    with pytest.raises(ValueError, match="archive member"):
        module._validated_zip_member(member)
