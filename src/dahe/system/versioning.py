from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError


class VersionManifestError(RuntimeError):
    """Raised when the checked-in version manifest is missing or invalid."""


class VersionManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    application_id: Literal["DaHeLogistics"]
    application_version: str
    config_schema_version: Literal[1]
    ledger_schema_version: Literal[1]
    local_api_protocol_version: Literal["v1"]
    default_run_mode: Literal["shadow"]
    real_platform_access: Literal[False]


def load_version_manifest(path: Path) -> VersionManifest:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        return VersionManifest.model_validate(document)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise VersionManifestError(f"invalid version manifest: {path.name}") from exc
