from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ModuleMode(StrEnum):
    DISABLED = "disabled"
    SHADOW = "shadow"
    OPERATIONAL = "operational"


class RuntimeProfile(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class OcrPreference(StrEnum):
    AUTO = "auto"
    PREFER_GPU = "prefer_gpu"
    CPU_ONLY = "cpu_only"


class OcrSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    preference: OcrPreference = OcrPreference.AUTO
    preferred_device_id: str | None = Field(default=None, min_length=1)
    allow_cpu_fallback: bool = True


class ModuleModes(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    audit: ModuleMode = ModuleMode.SHADOW
    daily: ModuleMode = ModuleMode.DISABLED
    settlement: ModuleMode = ModuleMode.DISABLED
    dispatch: ModuleMode = ModuleMode.DISABLED


class MaintenanceGates(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    production_image_cleanup_enabled: bool = False
    legacy_import_commit_enabled: bool = False
    backup_restore_enabled: bool = False


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    application_id: Literal["DaHeLogistics"] = "DaHeLogistics"
    host: Literal["127.0.0.1"] = "127.0.0.1"
    port: int = Field(default=8877, ge=1, le=65535)
    runtime_profile: RuntimeProfile = RuntimeProfile.DEVELOPMENT
    data_root: Path | None = None
    real_platform_access: bool = False
    production_read_only: bool = False
    ocr: OcrSettings = Field(default_factory=OcrSettings)
    module_modes: ModuleModes = Field(default_factory=ModuleModes)
    maintenance_gates: MaintenanceGates = Field(default_factory=MaintenanceGates)

    @field_validator("port")
    @classmethod
    def reject_legacy_port(cls, value: int) -> int:
        if value == 8765:
            raise ValueError("port 8765 is reserved for the legacy application")
        return value

    @field_validator("data_root")
    @classmethod
    def require_absolute_explicit_root(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("an explicit data_root must be absolute")
        return value

    @model_validator(mode="after")
    def require_test_root(self) -> Self:
        if self.runtime_profile is RuntimeProfile.TEST and self.data_root is None:
            raise ValueError("the test profile requires an explicit temporary data_root")
        if self.real_platform_access and not self.production_read_only:
            raise ValueError(
                "real platform access requires the production read-only profile"
            )
        if self.production_read_only and (
            self.runtime_profile is not RuntimeProfile.PRODUCTION
            or self.data_root is None
            or not self.real_platform_access
            or self.port != 8877
            or self.module_modes.audit is not ModuleMode.OPERATIONAL
            or self.module_modes.daily is not ModuleMode.OPERATIONAL
            or self.module_modes.settlement is not ModuleMode.DISABLED
            or self.module_modes.dispatch is not ModuleMode.DISABLED
        ):
            raise ValueError("the production read-only boundary is fixed")
        return self

    @classmethod
    def for_production_read_only(cls, *, data_root: Path) -> Self:
        return cls(
            runtime_profile=RuntimeProfile.PRODUCTION,
            data_root=data_root,
            port=8877,
            real_platform_access=True,
            production_read_only=True,
            module_modes=ModuleModes(
                audit=ModuleMode.OPERATIONAL,
                daily=ModuleMode.OPERATIONAL,
                settlement=ModuleMode.DISABLED,
                dispatch=ModuleMode.DISABLED,
            ),
        )
