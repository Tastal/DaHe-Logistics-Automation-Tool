from __future__ import annotations

from pathlib import Path

from dahe import __version__
from dahe.system.versioning import load_version_manifest


def test_version_manifest_matches_package(project_root: Path) -> None:
    manifest = load_version_manifest(project_root / "version-manifest.json")
    assert manifest.application_id == "DaHeLogistics"
    assert manifest.application_version == __version__
    assert manifest.config_schema_version == 1
    assert manifest.ledger_schema_version == 1
    assert manifest.default_run_mode == "shadow"
    assert manifest.real_platform_access is False
