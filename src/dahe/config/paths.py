from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from dahe.config.schema import AppConfig


class ConfigurationPathError(RuntimeError):
    """Raised when application data cannot be resolved or safely prepared."""


@dataclass(frozen=True, slots=True)
class ApplicationPaths:
    root: Path
    database: Path
    evidence: Path
    browser_profile: Path
    credentials: Path
    logs: Path
    backups: Path
    quarantine: Path
    runtime: Path

    def all_directories(self) -> tuple[Path, ...]:
        return (
            self.database,
            self.evidence,
            self.browser_profile,
            self.credentials,
            self.logs,
            self.backups,
            self.quarantine,
            self.runtime,
        )


def safe_child(root: Path, relative: str) -> Path:
    candidate_part = Path(relative)
    if candidate_part.is_absolute():
        raise ConfigurationPathError("application subpaths must be relative")

    resolved_root = root.resolve()
    resolved_candidate = (resolved_root / candidate_part).resolve()
    try:
        common = Path(os.path.commonpath((resolved_root, resolved_candidate)))
    except ValueError as exc:
        raise ConfigurationPathError("application subpath is outside the data root") from exc
    if common != resolved_root:
        raise ConfigurationPathError("application subpath is outside the data root")
    return resolved_candidate


def resolve_data_root(
    config: AppConfig,
    environ: Mapping[str, str] | None = None,
) -> Path:
    if config.data_root is not None:
        return config.data_root.resolve()

    environment = os.environ if environ is None else environ
    local_app_data = environment.get("LOCALAPPDATA", "").strip()
    if not local_app_data:
        raise ConfigurationPathError("LOCALAPPDATA is required; no fallback is allowed")

    base = Path(local_app_data)
    if not base.is_absolute():
        raise ConfigurationPathError("LOCALAPPDATA must be an absolute path")
    return safe_child(base, config.application_id)


def resolve_desktop_directory(
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the current user's Windows desktop without a machine path."""

    environment = os.environ if environ is None else environ
    one_drive = environment.get("OneDrive", "").strip()
    user_profile = environment.get("USERPROFILE", "").strip()
    candidates = [
        Path(one_drive) / "Desktop" if one_drive else None,
        Path(user_profile) / "Desktop" if user_profile else None,
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_absolute() and candidate.is_dir():
            return candidate.resolve()
    if user_profile and Path(user_profile).is_absolute():
        return (Path(user_profile) / "Desktop").resolve()
    raise ConfigurationPathError("the current Windows desktop could not be resolved")


def prepare_application_paths(root: Path) -> ApplicationPaths:
    resolved_root = root.resolve()
    if resolved_root.exists() and not resolved_root.is_dir():
        raise ConfigurationPathError("the application data root is not a directory")

    try:
        resolved_root.mkdir(parents=True, exist_ok=True)
        probe = resolved_root / f".write-probe-{uuid4().hex}.tmp"
        with probe.open("x", encoding="utf-8") as handle:
            handle.write("DaHeLogistics")
            handle.flush()
            os.fsync(handle.fileno())
        probe.unlink()
    except OSError as exc:
        raise ConfigurationPathError("the application data root is not writable") from exc

    paths = ApplicationPaths(
        root=resolved_root,
        database=safe_child(resolved_root, "database"),
        evidence=safe_child(resolved_root, "evidence"),
        browser_profile=safe_child(resolved_root, "browser-profile"),
        credentials=safe_child(resolved_root, "credentials"),
        logs=safe_child(resolved_root, "logs"),
        backups=safe_child(resolved_root, "backups"),
        quarantine=safe_child(resolved_root, "quarantine"),
        runtime=safe_child(resolved_root, "runtime"),
    )
    try:
        for path in paths.all_directories():
            path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigurationPathError("the application data layout could not be created") from exc
    return paths
