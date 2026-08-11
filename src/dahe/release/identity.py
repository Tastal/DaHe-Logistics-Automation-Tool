from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from dahe import __version__

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    application_version: str
    build_git_commit: str
    resource_sha256: str


def load_release_identity(
    project_root: Path,
    *,
    fallback_resource_sha256: str,
    expected_version: str = __version__,
) -> ReleaseIdentity:
    """Load the immutable build identity without consulting the network."""
    candidates = (
        project_root / "release-identity.json",
        project_root / "runtime-manifest.json",
    )
    for candidate in candidates:
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
        version = payload.get("application_version")
        commit = payload.get("build_git_commit")
        resource = payload.get(
            "resource_sha256",
            payload.get("source_build_sha256"),
        )
        if (
            version == expected_version
            and isinstance(commit, str)
            and _COMMIT.fullmatch(commit) is not None
            and isinstance(resource, str)
            and _SHA256.fullmatch(resource) is not None
        ):
            return ReleaseIdentity(version, commit, resource)
    resource = (
        fallback_resource_sha256
        if _SHA256.fullmatch(fallback_resource_sha256) is not None
        else "0" * 64
    )
    return ReleaseIdentity(expected_version, "development", resource)
