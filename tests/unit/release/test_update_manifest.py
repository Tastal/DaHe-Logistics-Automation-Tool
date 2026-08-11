from __future__ import annotations

import json

import pytest

from dahe.release.update_manifest import (
    UpdateManifestError,
    parse_update_manifest,
)


def _manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "repository": "Tastal/DaHe-Logistics-Automation-Tool",
        "version": "1.0.0",
        "release_tag": "v1.0.0",
        "build_git_commit": "d" * 40,
        "application": {
            "file_name": "DaHe-Logistics-Automation-Tool-1.0.0-win-x64.zip",
            "sha256": "a" * 64,
            "size": 123_456,
            "url": (
                "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                "releases/download/v1.0.0/"
                "DaHe-Logistics-Automation-Tool-1.0.0-win-x64.zip"
            ),
        },
        "gpu_addon": {
            "file_name": (
                "DaHe-Logistics-Automation-Tool-1.0.0-"
                "gpu-addon-win-x64.zip"
            ),
            "sha256": "b" * 64,
            "size": 234_567,
            "url": (
                "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/"
                "releases/download/v1.0.0/"
                "DaHe-Logistics-Automation-Tool-1.0.0-"
                "gpu-addon-win-x64.zip"
            ),
        },
        "minimum_schema_revision": "0039_network_batch_default",
        "target_schema_revision": "0039_network_batch_default",
        "alembic_revision": "0039_network_batch_default",
        "minimum_updater_version": "1.0.0",
        "resource_sha256": "c" * 64,
    }


def _parse(
    payload: dict[str, object],
    *,
    current_version: str = "0.8.1",
    updater_version: str = "1.0.0",
):
    return parse_update_manifest(
        json.dumps(payload).encode(),
        current_version=current_version,
        updater_version=updater_version,
    )


def test_accepts_only_the_fixed_formal_github_release() -> None:
    manifest = _parse(_manifest())

    assert manifest.version == "1.0.0"
    assert manifest.application.file_name.endswith("-1.0.0-win-x64.zip")
    assert manifest.target_schema_revision == "0039_network_batch_default"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository", "SomeoneElse/DaHe-Logistics-Automation-Tool"),
        ("version", "1.0"),
        ("release_tag", "latest"),
        ("minimum_schema_revision", "../../database"),
        ("resource_sha256", "not-a-hash"),
    ],
)
def test_rejects_invalid_release_identity(field: str, value: str) -> None:
    payload = _manifest()
    payload[field] = value

    with pytest.raises(UpdateManifestError):
        _parse(payload)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/Tastal/DaHe-Logistics-Automation-Tool/releases/download/v1.0.0/app.zip",
        "https://example.com/app.zip",
        "https://github.com/Other/repo/releases/download/v1.0.0/app.zip",
        "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/releases/download/v1.0.0/../app.zip",
        "https://github.com/Tastal/DaHe-Logistics-Automation-Tool/releases/download/v1.0.0/app.zip?token=secret",
    ],
)
def test_rejects_untrusted_application_urls(url: str) -> None:
    payload = _manifest()
    payload["application"] = {**payload["application"], "url": url}  # type: ignore[arg-type]

    with pytest.raises(UpdateManifestError):
        _parse(payload)


def test_rejects_version_downgrade_or_reinstall() -> None:
    with pytest.raises(UpdateManifestError, match="newer"):
        _parse(_manifest(), current_version="1.0.0")

    payload = _manifest()
    payload["version"] = "0.9.0"
    payload["release_tag"] = "v0.9.0"
    with pytest.raises(UpdateManifestError, match="newer"):
        _parse(payload, current_version="1.0.0")


def test_rejects_an_updater_below_the_manifest_minimum() -> None:
    payload = _manifest()
    payload["minimum_updater_version"] = "1.1.0"

    with pytest.raises(UpdateManifestError, match="updater"):
        _parse(payload, updater_version="1.0.0")


@pytest.mark.parametrize(
    "file_name",
    [
        "../app.zip",
        "app.exe",
        "DaHe-Logistics-Automation-Tool-1.0.1-win-x64.zip",
        "DaHe Logistics Automation Tool.zip",
    ],
)
def test_rejects_an_unexpected_application_file_name(file_name: str) -> None:
    payload = _manifest()
    payload["application"] = {  # type: ignore[assignment]
        **payload["application"],  # type: ignore[arg-type]
        "file_name": file_name,
    }

    with pytest.raises(UpdateManifestError):
        _parse(payload)
