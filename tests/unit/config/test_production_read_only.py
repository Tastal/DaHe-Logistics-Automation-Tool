from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from dahe.config.schema import AppConfig, ModuleMode, RuntimeProfile


def test_production_read_only_profile_has_fixed_module_boundary(tmp_path: Path) -> None:
    config = AppConfig.for_production_read_only(data_root=tmp_path.resolve())

    assert config.runtime_profile is RuntimeProfile.PRODUCTION
    assert config.port == 8877
    assert config.real_platform_access is True
    assert config.production_read_only is True
    assert config.module_modes.audit is ModuleMode.OPERATIONAL
    assert config.module_modes.daily is ModuleMode.OPERATIONAL
    assert config.module_modes.settlement is ModuleMode.DISABLED
    assert config.module_modes.dispatch is ModuleMode.DISABLED


def test_real_platform_access_requires_production_read_only_factory(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        AppConfig(
            runtime_profile=RuntimeProfile.PRODUCTION,
            data_root=tmp_path.resolve(),
            real_platform_access=True,
        )
