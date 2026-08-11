from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from dahe.config.schema import AppConfig, ModuleMode, OcrPreference, RuntimeProfile


def test_default_configuration_is_shadow_and_local_only() -> None:
    config = AppConfig()

    assert config.schema_version == 1
    assert config.application_id == "DaHeLogistics"
    assert config.host == "127.0.0.1"
    assert config.port == 8877
    assert config.runtime_profile is RuntimeProfile.DEVELOPMENT
    assert config.ocr.preference is OcrPreference.AUTO
    assert config.ocr.preferred_device_id is None
    assert config.ocr.allow_cpu_fallback is True
    assert config.real_platform_access is False
    assert config.module_modes.audit is ModuleMode.SHADOW
    assert config.module_modes.daily is ModuleMode.DISABLED
    assert config.module_modes.settlement is ModuleMode.DISABLED
    assert config.module_modes.dispatch is ModuleMode.DISABLED
    assert config.maintenance_gates.production_image_cleanup_enabled is False
    assert config.maintenance_gates.legacy_import_commit_enabled is False
    assert config.maintenance_gates.backup_restore_enabled is False


@pytest.mark.parametrize("host", ["0.0.0.0", "localhost", "192.168.1.2", "::1"])
def test_configuration_rejects_noncanonical_host(host: str) -> None:
    with pytest.raises(ValidationError):
        AppConfig(host=host)


def test_configuration_rejects_legacy_port() -> None:
    with pytest.raises(ValidationError):
        AppConfig(port=8765)


def test_configuration_rejects_unknown_fields_and_schema_versions() -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"schema_version": 1, "unexpected": True})

    with pytest.raises(ValidationError):
        AppConfig(schema_version=2)


def test_test_profile_requires_explicit_absolute_data_root(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        AppConfig(runtime_profile=RuntimeProfile.TEST)

    with pytest.raises(ValidationError):
        AppConfig(runtime_profile=RuntimeProfile.TEST, data_root=Path("relative"))

    config = AppConfig(runtime_profile=RuntimeProfile.TEST, data_root=tmp_path)
    assert config.data_root == tmp_path


def test_real_platform_access_cannot_be_enabled_in_phase_one() -> None:
    with pytest.raises(ValidationError):
        AppConfig(real_platform_access=True)
