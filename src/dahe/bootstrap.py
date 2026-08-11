from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from dahe import __version__
from dahe.config.paths import prepare_application_paths, resolve_data_root
from dahe.config.schema import AppConfig
from dahe.system.environment import assert_project_venv
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.system.port_guard import reserve_loopback_port
from dahe.system.versioning import load_version_manifest


class StartupCheckError(RuntimeError):
    """Raised when checked-in contracts disagree during startup."""


@dataclass(frozen=True, slots=True)
class StartupReport:
    application_id: str
    application_version: str
    config_schema_version: int
    host: str
    port: int
    data_root: str
    runtime_profile: str
    run_mode: str
    real_platform_access: bool
    external_connections: int

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def prepare_startup_environment(config: AppConfig, project_root: Path) -> Path:
    """Validate checked-in contracts and prepare only the new application's paths."""
    assert_project_venv(project_root)
    manifest = load_version_manifest(project_root / "version-manifest.json")
    if manifest.application_version != __version__:
        raise StartupCheckError("package and version manifest do not match")
    if manifest.config_schema_version != config.schema_version:
        raise StartupCheckError("configuration and version manifest do not match")

    data_root = resolve_data_root(config)
    prepare_application_paths(data_root)
    return data_root


def run_startup_check(config: AppConfig, project_root: Path) -> StartupReport:
    data_root = prepare_startup_environment(config, project_root)
    with (
        SingleInstanceGuard(data_root, config.port, __version__),
        reserve_loopback_port(config.host, config.port) as reservation,
    ):
        return StartupReport(
            application_id=config.application_id,
            application_version=__version__,
            config_schema_version=config.schema_version,
            host=reservation.host,
            port=reservation.port,
            data_root=str(data_root),
            runtime_profile=config.runtime_profile.value,
            run_mode=config.module_modes.audit.value,
            real_platform_access=config.real_platform_access,
            external_connections=0,
        )
