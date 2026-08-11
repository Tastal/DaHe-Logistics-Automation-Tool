from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from pydantic import ValidationError

from dahe.adapters.chengfeng.daily_manifest import (
    DAILY_LIST_PATH,
    DAILY_ORIGIN,
    DailyParameterRule,
    DailyReadContractManifest,
    DailyResponseField,
)
from dahe.adapters.chengfeng.discovery import DiscoveryObservation

_ResponseType = Literal[
    "null",
    "boolean",
    "integer",
    "number",
    "string",
    "empty_array",
]
_CONTROLLED_REQUEST_TYPES = {
    "loadStartTime": "string",
    "loadEndTime": "string",
    "receivePlace": "string",
    "pageNumber": "integer",
    "pageSize": "integer",
}
_REQUIRED_RESPONSE_TYPES: dict[str, frozenset[_ResponseType]] = {
    "$.data.list[].id": frozenset({"integer", "string"}),
    "$.data.list[].sn": frozenset({"string"}),
    "$.data.list[].carNumber": frozenset({"null", "string"}),
    "$.data.list[].loadPunchDate": frozenset({"null", "string"}),
    "$.data.total": frozenset({"integer"}),
}


class DailyContractFreezeError(RuntimeError):
    """Raised when discovery shapes cannot become a safe daily read contract."""


@dataclass(frozen=True, slots=True)
class DailyContractFreezeResult:
    contract_path: Path
    contract_canonical_sha256: str
    contract_file_sha256: str
    evidence_path: Path
    freeze_evidence_sha256: str
    source_discovery_sha256: str


def freeze_daily_read_contract(
    *,
    discovery_evidence_path: Path,
    data_root: Path,
) -> DailyContractFreezeResult:
    root = _require_data_root(data_root)
    document, observations = _load_discovery(
        path=discovery_evidence_path,
        data_root=root,
    )
    matches = tuple(
        observation
        for observation in observations
        if (
            observation.method == "POST"
            and observation.origin == DAILY_ORIGIN
            and observation.path == DAILY_LIST_PATH
            and observation.resource_kind == "json_api"
            and observation.response_status == 200
            and observation.content_kind == "json"
        )
    )
    if len(matches) != 1:
        raise DailyContractFreezeError(
            "discovery must contain exactly one exact daily list observation"
        )
    observation = matches[0]
    request_types = _top_level_field_types(observation, response=False)
    for name, expected_type in _CONTROLLED_REQUEST_TYPES.items():
        if request_types.get(name) != expected_type:
            raise DailyContractFreezeError(
                "daily controlled request field shape is incomplete"
            )
    for name, observed_type in request_types.items():
        if name not in _CONTROLLED_REQUEST_TYPES and observed_type not in {
            "string",
            "empty_array",
            "null",
        }:
            raise DailyContractFreezeError(
                "daily request cannot derive a safe empty baseline"
            )

    discovered_response_types: dict[str, _ResponseType] = {
        field.path: _response_type(field.type) for field in observation.response_fields
    }
    if len(discovered_response_types) != len(observation.response_fields):
        raise DailyContractFreezeError("daily response field paths are duplicated")
    for path, allowed_types in _REQUIRED_RESPONSE_TYPES.items():
        if discovered_response_types.get(path) not in allowed_types:
            raise DailyContractFreezeError(
                "daily response identity or count shape is incomplete"
            )

    manifest = DailyReadContractManifest(
        schema_version=1,
        contract_kind="loop9_daily_read_only",
        run_mode="shadow",
        origin=DAILY_ORIGIN,
        method="POST",
        path=DAILY_LIST_PATH,
        parameters_location="json",
        source_discovery_sha256=str(document["canonical_sha256"]),
        source_observation_count=len(observations),
        request_fields={
            name: _parameter_rule(name=name, field_type=field_type)
            for name, field_type in sorted(request_types.items())
        },
        response_fields=tuple(
            DailyResponseField(
                path=path,
                types=tuple(sorted(allowed_types)),
            )
            for path, allowed_types in sorted(_REQUIRED_RESPONSE_TYPES.items())
        ),
    )

    contract_bytes = _canonical_bytes(manifest.canonical_document) + b"\n"
    contract_file_sha256 = hashlib.sha256(contract_bytes).hexdigest()
    contract_directory = root / "daily-platform-read-contract"
    contract_directory.mkdir(exist_ok=True)
    _require_regular_directory(contract_directory)
    contract_path = contract_directory / f"{manifest.canonical_sha256}.json"
    _write_idempotent(contract_path, contract_bytes)

    evidence_body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_daily_read_contract_freeze",
        "classification": "development_only",
        "source_discovery_sha256": manifest.source_discovery_sha256,
        "source_observation_count": len(observations),
        "contract_canonical_sha256": manifest.canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "request_field_count": len(manifest.request_fields),
        "response_field_count": len(manifest.response_fields),
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    freeze_sha256 = hashlib.sha256(_canonical_bytes(evidence_body)).hexdigest()
    evidence_directory = root / "daily-platform-read-contract-evidence"
    evidence_directory.mkdir(exist_ok=True)
    _require_regular_directory(evidence_directory)
    evidence_path = evidence_directory / f"{freeze_sha256}.json"
    _write_idempotent(
        evidence_path,
        _canonical_bytes({**evidence_body, "canonical_sha256": freeze_sha256}) + b"\n",
    )
    return DailyContractFreezeResult(
        contract_path=contract_path,
        contract_canonical_sha256=manifest.canonical_sha256,
        contract_file_sha256=contract_file_sha256,
        evidence_path=evidence_path,
        freeze_evidence_sha256=freeze_sha256,
        source_discovery_sha256=manifest.source_discovery_sha256,
    )


def _parameter_rule(*, name: str, field_type: str) -> DailyParameterRule:
    if name == "pageNumber":
        return DailyParameterRule(type="integer", minimum=1, maximum=10_000)
    if name == "pageSize":
        return DailyParameterRule(type="integer", minimum=1, maximum=100)
    if field_type not in {"string", "empty_array", "null"}:
        raise DailyContractFreezeError("daily request cannot derive a safe empty baseline")
    return DailyParameterRule.model_validate({"type": field_type}, strict=True)


def _response_type(value: str) -> _ResponseType:
    if value not in {
        "null",
        "boolean",
        "integer",
        "number",
        "string",
        "empty_array",
    }:
        raise DailyContractFreezeError("daily response field type is unsupported")
    return cast("_ResponseType", value)


def _top_level_field_types(
    observation: DiscoveryObservation,
    *,
    response: bool,
) -> dict[str, str]:
    fields = observation.response_fields if response else observation.request_fields
    result: dict[str, str] = {}
    for field in fields:
        if (
            not field.path.startswith("$.")
            or field.path.count(".") != 1
            or "[]" in field.path
        ):
            raise DailyContractFreezeError(
                "daily request fields must be top-level scalar or empty values"
            )
        name = field.path[2:]
        if name in result:
            raise DailyContractFreezeError("daily request field paths are duplicated")
        result[name] = field.type
    return result


def _require_data_root(data_root: Path) -> Path:
    if not data_root.is_absolute() or data_root.is_symlink():
        raise DailyContractFreezeError("data root must be an absolute regular directory")
    root = data_root.resolve()
    if not root.is_dir():
        raise DailyContractFreezeError("data root must already exist")
    return root


def _load_discovery(
    *,
    path: Path,
    data_root: Path,
) -> tuple[dict[str, object], tuple[DiscoveryObservation, ...]]:
    if not path.is_absolute():
        raise DailyContractFreezeError("discovery evidence path must be absolute")
    resolved = path.resolve()
    if (
        data_root not in resolved.parents
        or not resolved.is_file()
        or resolved.is_symlink()
    ):
        raise DailyContractFreezeError("discovery evidence path is unsafe")
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DailyContractFreezeError("discovery evidence is unreadable") from exc
    if not isinstance(document, dict):
        raise DailyContractFreezeError("discovery evidence is invalid")
    declared = document.get("canonical_sha256")
    body = {key: value for key, value in document.items() if key != "canonical_sha256"}
    if (
        type(declared) is not str
        or declared != hashlib.sha256(_canonical_bytes(body)).hexdigest()
        or resolved.name != f"{declared}.json"
        or document.get("kind") != "chengfeng_contract_discovery"
        or document.get("observation_count") != len(document.get("observations", ()))
    ):
        raise DailyContractFreezeError("discovery evidence integrity check failed")
    raw_observations = document.get("observations")
    if not isinstance(raw_observations, list):
        raise DailyContractFreezeError("discovery evidence observations are invalid")
    try:
        observations = tuple(
            DiscoveryObservation.model_validate(value) for value in raw_observations
        )
    except ValidationError as exc:
        raise DailyContractFreezeError("discovery evidence observations are unsafe") from exc
    return document, observations


def _require_regular_directory(path: Path) -> None:
    if not path.is_dir() or path.is_symlink():
        raise DailyContractFreezeError("contract output directory is unsafe")


def _write_idempotent(path: Path, content: bytes) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
            raise DailyContractFreezeError("existing contract evidence does not match")
        return
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise DailyContractFreezeError("contract evidence could not be written") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
