from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_REPOSITORY = "Tastal/DaHe-Logistics-Automation-Tool"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_REVISION = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_MAX_MANIFEST_BYTES = 64 * 1024


class UpdateManifestError(ValueError):
    """Raised when an update manifest crosses the release trust boundary."""


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    file_name: str
    sha256: str
    size: int
    url: str


@dataclass(frozen=True, slots=True)
class UpdateManifest:
    repository: str
    version: str
    release_tag: str
    build_git_commit: str
    application: ReleaseAsset
    gpu_addon: ReleaseAsset
    minimum_schema_revision: str
    target_schema_revision: str
    alembic_revision: str
    minimum_updater_version: str
    resource_sha256: str


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise UpdateManifestError("update manifest has duplicate fields")
        result[key] = value
    return result


def _exact_object(
    value: object,
    fields: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise UpdateManifestError(f"{label} fields are invalid")
    return value


def _version(value: object, *, label: str) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise UpdateManifestError(f"{label} is invalid")
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise UpdateManifestError(f"{label} is invalid")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def compare_versions(left: str, right: str) -> int:
    """Compare two strict numeric semantic versions."""
    left_value = _version(left, label="left version")
    right_value = _version(right, label="right version")
    return (left_value > right_value) - (left_value < right_value)


def _revision(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _REVISION.fullmatch(value) is None:
        raise UpdateManifestError(f"{label} is invalid")
    return value


def _asset(
    value: object,
    *,
    version: str,
    kind: str,
) -> ReleaseAsset:
    raw = _exact_object(
        value,
        {"file_name", "sha256", "size", "url"},
        label=f"{kind} asset",
    )
    expected_name = (
        f"DaHe-Logistics-Automation-Tool-{version}-win-x64.zip"
        if kind == "application"
        else (
            f"DaHe-Logistics-Automation-Tool-{version}-"
            "gpu-addon-win-x64.zip"
        )
    )
    file_name = raw["file_name"]
    sha256 = raw["sha256"]
    size = raw["size"]
    url = raw["url"]
    if file_name != expected_name:
        raise UpdateManifestError(f"{kind} asset file name is invalid")
    if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
        raise UpdateManifestError(f"{kind} asset SHA-256 is invalid")
    if type(size) is not int or not 1 <= size <= 8 * 1024**3:
        raise UpdateManifestError(f"{kind} asset size is invalid")
    if not isinstance(url, str):
        raise UpdateManifestError(f"{kind} asset URL is invalid")
    parsed = urlsplit(url)
    expected_path = (
        f"/{_REPOSITORY}/releases/download/v{version}/{expected_name}"
    )
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise UpdateManifestError(f"{kind} asset URL is invalid")
    return ReleaseAsset(
        file_name=expected_name,
        sha256=sha256,
        size=size,
        url=url,
    )


def parse_update_manifest(
    content: bytes,
    *,
    current_version: str,
    updater_version: str,
) -> UpdateManifest:
    if not content or len(content) > _MAX_MANIFEST_BYTES:
        raise UpdateManifestError("update manifest size is invalid")
    try:
        payload = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateManifestError("update manifest JSON is invalid") from exc
    root = _exact_object(
        payload,
        {
            "alembic_revision",
            "application",
            "build_git_commit",
            "gpu_addon",
            "minimum_schema_revision",
            "minimum_updater_version",
            "release_tag",
            "repository",
            "resource_sha256",
            "schema_version",
            "target_schema_revision",
            "version",
        },
        label="update manifest",
    )
    if root["schema_version"] != 1 or root["repository"] != _REPOSITORY:
        raise UpdateManifestError("update manifest identity is invalid")
    release_version = root["version"]
    release_version_tuple = _version(
        release_version,
        label="release version",
    )
    current_version_tuple = _version(
        current_version,
        label="current version",
    )
    if release_version_tuple <= current_version_tuple:
        raise UpdateManifestError("release version is not newer")
    assert isinstance(release_version, str)
    if root["release_tag"] != f"v{release_version}":
        raise UpdateManifestError("release tag is invalid")
    build_git_commit = root["build_git_commit"]
    if (
        not isinstance(build_git_commit, str)
        or _COMMIT.fullmatch(build_git_commit) is None
    ):
        raise UpdateManifestError("build Git commit is invalid")
    minimum_updater_version = root["minimum_updater_version"]
    if _version(
        updater_version,
        label="updater version",
    ) < _version(minimum_updater_version, label="minimum updater version"):
        raise UpdateManifestError("updater version is below the release minimum")
    assert isinstance(minimum_updater_version, str)
    minimum_schema_revision = _revision(
        root["minimum_schema_revision"],
        label="minimum schema revision",
    )
    target_schema_revision = _revision(
        root["target_schema_revision"],
        label="target schema revision",
    )
    alembic_revision = _revision(
        root["alembic_revision"],
        label="Alembic revision",
    )
    if alembic_revision != target_schema_revision:
        raise UpdateManifestError("target and Alembic revisions differ")
    resource_sha256 = root["resource_sha256"]
    if (
        not isinstance(resource_sha256, str)
        or _SHA256.fullmatch(resource_sha256) is None
    ):
        raise UpdateManifestError("resource SHA-256 is invalid")
    return UpdateManifest(
        repository=_REPOSITORY,
        version=release_version,
        release_tag=f"v{release_version}",
        build_git_commit=build_git_commit,
        application=_asset(
            root["application"],
            version=release_version,
            kind="application",
        ),
        gpu_addon=_asset(
            root["gpu_addon"],
            version=release_version,
            kind="gpu_addon",
        ),
        minimum_schema_revision=minimum_schema_revision,
        target_schema_revision=target_schema_revision,
        alembic_revision=alembic_revision,
        minimum_updater_version=minimum_updater_version,
        resource_sha256=resource_sha256,
    )
