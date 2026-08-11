from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal
from uuid import uuid4

from dahe.adapters.chengfeng.discovery import (
    DiscoveryObservation,
)
from dahe.adapters.chengfeng.live_manifest import (
    LiveParameterRule,
    LiveReadContractManifest,
    LiveReadDeclaration,
    LiveResponseField,
)

_Operation = Literal[
    "list_waybills",
    "get_waybill_detail",
    "download_ticket_image",
]
_ResponseType = Literal[
    "null",
    "boolean",
    "integer",
    "number",
    "string",
    "empty_array",
]

CHENGFENG_ORIGIN = "https://pc.chengfengkuaiyun.com"
LIST_PATH = (
    "/api/order-center-server/app/clientOrderItem/"
    "queryWaitSettlementOrderItemListPC"
)
DETAIL_PATH = (
    "/api/order-center-server/app/clientOrderItem/"
    "getOrderItemDetailsByIdPC"
)
RESPONSE_DERIVED_IMAGE_PATH = "/__response-derived-ticket-image__"

_LIST_RESPONSE_FIELDS: MappingProxyType[str, _ResponseType] = MappingProxyType(
    {
        "$.data.list[].id": "string",
        "$.data.list[].orderItemSn": "string",
        "$.data.list[].carNumber": "string",
        "$.data.pageNo": "integer",
        "$.data.pageSize": "integer",
        "$.data.total": "integer",
    }
)
_DETAIL_RESPONSE_FIELDS: MappingProxyType[str, _ResponseType] = MappingProxyType(
    {
        "$.data[].id": "string",
        "$.data[].sn": "string",
        "$.data[].carNumber": "string",
        "$.data[].originalTon": "string",
        "$.data[].currentTon": "string",
        "$.data[].originalTonImageUrl": "string",
        "$.data[].image": "string",
    }
)
_MUTATION_MARKERS = (
    "cancel",
    "confirm",
    "create",
    "delete",
    "modify",
    "payment",
    "remove",
    "save",
    "submit",
    "switch",
    "update",
)


class LiveContractFreezeError(RuntimeError):
    """Raised when discovery evidence cannot produce a safe read contract."""


@dataclass(frozen=True, slots=True)
class LiveContractFreezeResult:
    contract_path: Path
    contract_canonical_sha256: str
    contract_file_sha256: str
    evidence_path: Path
    freeze_evidence_sha256: str
    source_discovery_sha256: str
    selected_observation_count: int
    excluded_observation_count: int
    potentially_mutating_observation_count: int


def freeze_live_read_contract(
    *,
    discovery_evidence_path: Path,
    data_root: Path,
) -> LiveContractFreezeResult:
    """Freeze only the three approved read shapes from sealed discovery evidence."""

    root = _require_data_root(data_root)
    document, observations = _load_discovery(
        path=discovery_evidence_path,
        data_root=root,
    )
    source_sha256 = str(document["canonical_sha256"])
    list_observation = _one_json_observation(observations, LIST_PATH)
    detail_observation = _one_json_observation(observations, DETAIL_PATH)
    _require_response_fields(list_observation, _LIST_RESPONSE_FIELDS)
    _require_response_fields(detail_observation, _DETAIL_RESPONSE_FIELDS)

    signed_images = tuple(
        observation
        for observation in observations
        if (
            observation.resource_kind == "image"
            and observation.method == "GET"
            and observation.response_status == 200
            and observation.content_kind == "image"
            and any("signature" in key.casefold() for key in observation.query_keys)
        )
    )
    image_origins = tuple(sorted({observation.origin for observation in signed_images}))
    if not image_origins:
        raise LiveContractFreezeError(
            "discovery evidence contains no signed ticket-image origin"
        )

    manifest = LiveReadContractManifest(
        schema_version=1,
        contract_kind="loop9_read_only",
        run_mode="shadow",
        origin=CHENGFENG_ORIGIN,
        image_origins=image_origins,
        source_discovery_sha256=source_sha256,
        source_observation_count=len(observations),
        requests=(
            _declaration(
                operation="list_waybills",
                observation=list_observation,
                response_fields=_LIST_RESPONSE_FIELDS,
            ),
            _declaration(
                operation="get_waybill_detail",
                observation=detail_observation,
                response_fields=_DETAIL_RESPONSE_FIELDS,
            ),
            LiveReadDeclaration(
                operation="download_ticket_image",
                method="GET",
                path=RESPONSE_DERIVED_IMAGE_PATH,
                parameters_location="query",
                parameters={"ticket_ref": LiveParameterRule(type="string")},
                response_fields=(),
            ),
        ),
    )

    contract_directory = root / "platform-read-contract"
    contract_directory.mkdir(exist_ok=True)
    _require_normal_directory(contract_directory)
    contract_bytes = _canonical_bytes(manifest.canonical_document) + b"\n"
    contract_sha256 = manifest.canonical_sha256
    contract_path = contract_directory / f"{contract_sha256}.json"
    _write_idempotent(contract_path, contract_bytes)
    contract_file_sha256 = hashlib.sha256(contract_bytes).hexdigest()

    selected_ids = {
        id(list_observation),
        id(detail_observation),
        *(id(observation) for observation in signed_images),
    }
    excluded = tuple(
        observation
        for observation in observations
        if id(observation) not in selected_ids
    )
    potentially_mutating = tuple(
        observation
        for observation in excluded
        if observation.path is not None
        and any(marker in observation.path.casefold() for marker in _MUTATION_MARKERS)
    )
    freeze_body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_freeze",
        "classification": "development_only",
        "source_discovery_sha256": source_sha256,
        "source_observation_count": len(observations),
        "contract_canonical_sha256": contract_sha256,
        "contract_file_sha256": contract_file_sha256,
        "selected_observation_count": len(selected_ids),
        "excluded_observation_count": len(excluded),
        "potentially_mutating_observation_count": len(potentially_mutating),
        "potentially_mutating_path_sha256s": sorted(
            hashlib.sha256(observation.path.encode("utf-8")).hexdigest()
            for observation in potentially_mutating
            if observation.path is not None
        ),
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    freeze_sha256 = hashlib.sha256(_canonical_bytes(freeze_body)).hexdigest()
    freeze_document = {**freeze_body, "canonical_sha256": freeze_sha256}
    evidence_path = contract_directory / f"{contract_sha256}.freeze-evidence.json"
    _write_idempotent(
        evidence_path,
        _canonical_bytes(freeze_document) + b"\n",
    )
    return LiveContractFreezeResult(
        contract_path=contract_path,
        contract_canonical_sha256=contract_sha256,
        contract_file_sha256=contract_file_sha256,
        evidence_path=evidence_path,
        freeze_evidence_sha256=freeze_sha256,
        source_discovery_sha256=source_sha256,
        selected_observation_count=len(selected_ids),
        excluded_observation_count=len(excluded),
        potentially_mutating_observation_count=len(potentially_mutating),
    )


def rollover_live_list_request_contract(
    *,
    request_structure_evidence_path: Path,
    data_root: Path,
) -> LiveContractFreezeResult:
    """Freeze a candidate after an official reset changes only list fields."""

    from dahe.adapters.chengfeng.live_contract_selection import (
        load_selected_live_read_contract,
    )

    root = _require_data_root(data_root)
    document, observations = _load_request_structure_evidence(
        path=request_structure_evidence_path,
        data_root=root,
    )
    if len(observations) != 1:
        raise LiveContractFreezeError(
            "request structure evidence must contain exactly one observation"
        )
    list_observation = observations[0]
    if (
        list_observation.origin != CHENGFENG_ORIGIN
        or list_observation.path != LIST_PATH
        or list_observation.method != "POST"
        or list_observation.resource_kind != "json_api"
        or list_observation.query_keys != ("t",)
        or list_observation.response_status is not None
        or list_observation.content_kind is not None
        or list_observation.response_fields
    ):
        raise LiveContractFreezeError(
            "request structure evidence is not an exact reset-list shape"
        )
    request_names = {
        field.path[2:-2] if field.path.endswith("[]") else field.path[2:]
        for field in list_observation.request_fields
        if field.path.startswith("$.")
    }
    if not {
        "order",
        "pageNumber",
        "pageSize",
        "queryType",
        "settleQueryType",
    }.issubset(request_names):
        raise LiveContractFreezeError(
            "request structure evidence is missing required controls"
        )

    selected = load_selected_live_read_contract(root)
    diagnostic_parent = document.get(
        "parent_contract_canonical_sha256"
    )
    if (
        diagnostic_parent is not None
        and diagnostic_parent != selected.manifest.canonical_sha256
    ):
        raise LiveContractFreezeError(
            "request structure evidence belongs to another contract"
        )
    parent_requests = {
        declaration.operation: declaration
        for declaration in selected.manifest.requests
    }
    if set(parent_requests) != {
        "list_waybills",
        "get_waybill_detail",
        "download_ticket_image",
    }:
        raise LiveContractFreezeError("selected parent contract is incomplete")

    source_body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_request_rollover_source",
        "classification": "development_only",
        "parent_contract_canonical_sha256": (
            selected.manifest.canonical_sha256
        ),
        "parent_contract_file_sha256": selected.contract_file_sha256,
        "parent_freeze_evidence_sha256": selected.freeze_evidence_sha256,
        "parent_source_discovery_sha256": (
            selected.manifest.source_discovery_sha256
        ),
        "request_structure_discovery_sha256": document[
            "canonical_sha256"
        ],
        "request_structure_observation": list_observation.model_dump(
            mode="json"
        ),
        "response_contract_inherited": True,
        "requires_live_validation": True,
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    source_sha256 = hashlib.sha256(
        _canonical_bytes(source_body)
    ).hexdigest()
    source_document = {
        **source_body,
        "canonical_sha256": source_sha256,
    }
    source_root = root / "platform-contract-discovery"
    source_root.mkdir(exist_ok=True)
    _require_normal_directory(source_root)
    source_path = (
        source_root / f"{source_sha256}.request-rollover.json"
    )
    _write_idempotent(
        source_path,
        _canonical_bytes(source_document) + b"\n",
    )

    list_declaration = _declaration(
        operation="list_waybills",
        observation=list_observation,
        response_fields=_LIST_RESPONSE_FIELDS,
    )
    manifest = LiveReadContractManifest(
        schema_version=1,
        contract_kind="loop9_read_only",
        run_mode="shadow",
        origin=selected.manifest.origin,
        image_origins=selected.manifest.image_origins,
        source_discovery_sha256=source_sha256,
        source_observation_count=(
            selected.manifest.source_observation_count + 1
        ),
        requests=(
            list_declaration,
            parent_requests["get_waybill_detail"],
            parent_requests["download_ticket_image"],
        ),
    )
    contract_directory = root / "platform-read-contract"
    contract_directory.mkdir(exist_ok=True)
    _require_normal_directory(contract_directory)
    contract_bytes = _canonical_bytes(manifest.canonical_document) + b"\n"
    contract_sha256 = manifest.canonical_sha256
    contract_path = contract_directory / f"{contract_sha256}.json"
    _write_idempotent(contract_path, contract_bytes)
    contract_file_sha256 = hashlib.sha256(contract_bytes).hexdigest()

    freeze_body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_request_rollover",
        "classification": "development_only",
        "source_discovery_sha256": source_sha256,
        "source_observation_count": manifest.source_observation_count,
        "contract_canonical_sha256": contract_sha256,
        "contract_file_sha256": contract_file_sha256,
        "parent_contract_canonical_sha256": (
            selected.manifest.canonical_sha256
        ),
        "parent_contract_file_sha256": selected.contract_file_sha256,
        "parent_freeze_evidence_sha256": selected.freeze_evidence_sha256,
        "request_structure_discovery_sha256": document[
            "canonical_sha256"
        ],
        "selected_observation_count": 1,
        "excluded_observation_count": 0,
        "potentially_mutating_observation_count": 0,
        "potentially_mutating_path_sha256s": [],
        "response_contract_inherited": True,
        "requires_live_validation": True,
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    freeze_sha256 = hashlib.sha256(
        _canonical_bytes(freeze_body)
    ).hexdigest()
    freeze_document = {
        **freeze_body,
        "canonical_sha256": freeze_sha256,
    }
    evidence_path = (
        contract_directory
        / f"{contract_sha256}.freeze-evidence.json"
    )
    _write_idempotent(
        evidence_path,
        _canonical_bytes(freeze_document) + b"\n",
    )
    return LiveContractFreezeResult(
        contract_path=contract_path,
        contract_canonical_sha256=contract_sha256,
        contract_file_sha256=contract_file_sha256,
        evidence_path=evidence_path,
        freeze_evidence_sha256=freeze_sha256,
        source_discovery_sha256=source_sha256,
        selected_observation_count=1,
        excluded_observation_count=0,
        potentially_mutating_observation_count=0,
    )


def rollover_live_detail_encoding_contract(
    *,
    data_root: Path,
) -> LiveContractFreezeResult:
    """Create a form-encoded detail candidate from the active JSON contract."""

    from dahe.adapters.chengfeng.live_contract_selection import (
        load_selected_live_read_contract,
    )

    root = _require_data_root(data_root)
    selected = load_selected_live_read_contract(root)
    parent_requests = {
        declaration.operation: declaration
        for declaration in selected.manifest.requests
    }
    if set(parent_requests) != {
        "list_waybills",
        "get_waybill_detail",
        "download_ticket_image",
    }:
        raise LiveContractFreezeError("selected parent contract is incomplete")
    detail = parent_requests["get_waybill_detail"]
    if detail.parameters_location == "form":
        freeze_path = (
            root
            / "platform-read-contract"
            / (
                f"{selected.manifest.canonical_sha256}"
                ".freeze-evidence.json"
            )
        )
        try:
            freeze_document = json.loads(freeze_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise LiveContractFreezeError(
                "selected form detail rollover is unreadable"
            ) from exc
        if (
            not isinstance(freeze_document, dict)
            or freeze_document.get("kind")
            != "loop9_live_read_contract_detail_encoding_rollover"
            or freeze_document.get("canonical_sha256")
            != selected.freeze_evidence_sha256
        ):
            raise LiveContractFreezeError(
                "selected detail contract was not produced by this rollover"
            )
        contract_path = (
            root
            / "platform-read-contract"
            / f"{selected.manifest.canonical_sha256}.json"
        )
        return LiveContractFreezeResult(
            contract_path=contract_path,
            contract_canonical_sha256=(
                selected.manifest.canonical_sha256
            ),
            contract_file_sha256=selected.contract_file_sha256,
            evidence_path=freeze_path,
            freeze_evidence_sha256=selected.freeze_evidence_sha256,
            source_discovery_sha256=(
                selected.manifest.source_discovery_sha256
            ),
            selected_observation_count=1,
            excluded_observation_count=0,
            potentially_mutating_observation_count=0,
        )
    if detail.parameters_location != "json":
        raise LiveContractFreezeError(
            "selected detail contract encoding is unsupported"
        )

    encoding_change = {
        "operation": "get_waybill_detail",
        "from": "json",
        "to": "form",
    }
    source_body: dict[str, object] = {
        "schema_version": 1,
        "kind": (
            "loop9_live_read_contract_detail_encoding_rollover_source"
        ),
        "classification": "development_only",
        "parent_contract_canonical_sha256": (
            selected.manifest.canonical_sha256
        ),
        "parent_contract_file_sha256": selected.contract_file_sha256,
        "parent_freeze_evidence_sha256": (
            selected.freeze_evidence_sha256
        ),
        "parent_source_discovery_sha256": (
            selected.manifest.source_discovery_sha256
        ),
        "encoding_change": encoding_change,
        "request_and_response_fields_inherited": True,
        "requires_live_validation": True,
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    source_sha256 = hashlib.sha256(
        _canonical_bytes(source_body)
    ).hexdigest()
    source_document = {
        **source_body,
        "canonical_sha256": source_sha256,
    }
    source_root = root / "platform-contract-discovery"
    source_root.mkdir(exist_ok=True)
    _require_normal_directory(source_root)
    source_path = (
        source_root
        / f"{source_sha256}.detail-encoding-rollover.json"
    )
    _write_idempotent(
        source_path,
        _canonical_bytes(source_document) + b"\n",
    )

    form_detail = LiveReadDeclaration(
        operation=detail.operation,
        method=detail.method,
        path=detail.path,
        parameters_location="form",
        parameters=dict(detail.parameters),
        response_fields=detail.response_fields,
    )
    manifest = LiveReadContractManifest(
        schema_version=1,
        contract_kind="loop9_read_only",
        run_mode="shadow",
        origin=selected.manifest.origin,
        image_origins=selected.manifest.image_origins,
        source_discovery_sha256=source_sha256,
        source_observation_count=(
            selected.manifest.source_observation_count + 1
        ),
        requests=(
            parent_requests["list_waybills"],
            form_detail,
            parent_requests["download_ticket_image"],
        ),
    )
    contract_directory = root / "platform-read-contract"
    contract_directory.mkdir(exist_ok=True)
    _require_normal_directory(contract_directory)
    contract_bytes = _canonical_bytes(manifest.canonical_document) + b"\n"
    contract_sha256 = manifest.canonical_sha256
    contract_path = contract_directory / f"{contract_sha256}.json"
    _write_idempotent(contract_path, contract_bytes)
    contract_file_sha256 = hashlib.sha256(contract_bytes).hexdigest()

    freeze_body: dict[str, object] = {
        "schema_version": 1,
        "kind": (
            "loop9_live_read_contract_detail_encoding_rollover"
        ),
        "classification": "development_only",
        "source_discovery_sha256": source_sha256,
        "source_observation_count": manifest.source_observation_count,
        "contract_canonical_sha256": contract_sha256,
        "contract_file_sha256": contract_file_sha256,
        "parent_contract_canonical_sha256": (
            selected.manifest.canonical_sha256
        ),
        "parent_contract_file_sha256": selected.contract_file_sha256,
        "parent_freeze_evidence_sha256": (
            selected.freeze_evidence_sha256
        ),
        "encoding_change": encoding_change,
        "selected_observation_count": 1,
        "excluded_observation_count": 0,
        "potentially_mutating_observation_count": 0,
        "potentially_mutating_path_sha256s": [],
        "request_and_response_fields_inherited": True,
        "requires_live_validation": True,
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    freeze_sha256 = hashlib.sha256(
        _canonical_bytes(freeze_body)
    ).hexdigest()
    freeze_document = {
        **freeze_body,
        "canonical_sha256": freeze_sha256,
    }
    evidence_path = (
        contract_directory
        / f"{contract_sha256}.freeze-evidence.json"
    )
    _write_idempotent(
        evidence_path,
        _canonical_bytes(freeze_document) + b"\n",
    )
    return LiveContractFreezeResult(
        contract_path=contract_path,
        contract_canonical_sha256=contract_sha256,
        contract_file_sha256=contract_file_sha256,
        evidence_path=evidence_path,
        freeze_evidence_sha256=freeze_sha256,
        source_discovery_sha256=source_sha256,
        selected_observation_count=1,
        excluded_observation_count=0,
        potentially_mutating_observation_count=0,
    )


def _require_data_root(data_root: Path) -> Path:
    if not data_root.is_absolute() or data_root.is_symlink():
        raise LiveContractFreezeError("data root must be an absolute normal directory")
    data_root.mkdir(parents=True, exist_ok=True)
    resolved = data_root.resolve()
    _require_normal_directory(resolved)
    return resolved


def _load_discovery(
    *,
    path: Path,
    data_root: Path,
) -> tuple[dict[str, object], tuple[DiscoveryObservation, ...]]:
    if not path.is_absolute() or path.is_symlink():
        raise LiveContractFreezeError(
            "discovery evidence must be an absolute regular file"
        )
    resolved = path.resolve()
    expected_parent = (data_root / "platform-contract-discovery").resolve()
    if resolved.parent != expected_parent or not resolved.is_file():
        raise LiveContractFreezeError(
            "discovery evidence is outside the selected data root"
        )
    try:
        raw = resolved.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContractFreezeError("discovery evidence is unreadable") from exc
    if not isinstance(document, dict):
        raise LiveContractFreezeError("discovery evidence root is invalid")
    declared = document.get("canonical_sha256")
    body = {key: value for key, value in document.items() if key != "canonical_sha256"}
    if (
        not isinstance(declared, str)
        or hashlib.sha256(_canonical_bytes(body)).hexdigest() != declared
        or resolved.name != f"{declared}.json"
        or document.get("kind") != "chengfeng_contract_discovery"
        or document.get("classification") != "development_only"
        or document.get("status") != "captured"
    ):
        raise LiveContractFreezeError("discovery evidence integrity check failed")
    raw_observations = document.get("observations")
    if (
        not isinstance(raw_observations, list)
        or document.get("observation_count") != len(raw_observations)
    ):
        raise LiveContractFreezeError("discovery evidence count is invalid")
    try:
        observations = tuple(
            DiscoveryObservation.model_validate(observation)
            for observation in raw_observations
        )
    except ValueError as exc:
        raise LiveContractFreezeError("discovery observation is unsafe") from exc
    return document, observations


def _load_request_structure_evidence(
    *,
    path: Path,
    data_root: Path,
) -> tuple[dict[str, object], tuple[DiscoveryObservation, ...]]:
    discovery_root = (data_root / "platform-contract-discovery").resolve()
    diagnostic_root = (
        data_root / "platform-contract-diagnostics"
    ).resolve()
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise LiveContractFreezeError(
            "request structure evidence is unavailable"
        ) from exc
    if resolved.parent == discovery_root:
        return _load_discovery(path=path, data_root=data_root)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or resolved.parent != diagnostic_root
        or not resolved.is_file()
    ):
        raise LiveContractFreezeError(
            "request structure evidence is outside the selected data root"
        )
    try:
        document = json.loads(resolved.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContractFreezeError(
            "request structure evidence is unreadable"
        ) from exc
    if not isinstance(document, dict):
        raise LiveContractFreezeError(
            "request structure evidence root is invalid"
        )
    declared = document.get("canonical_sha256")
    body = {
        key: value
        for key, value in document.items()
        if key != "canonical_sha256"
    }
    if (
        not isinstance(declared, str)
        or hashlib.sha256(_canonical_bytes(body)).hexdigest() != declared
        or resolved.name != f"{declared}.json"
        or document.get("kind")
        != "chengfeng_reset_list_structure_diagnostic"
        or document.get("classification") != "development_only"
        or document.get("platform_write_authorization") is not False
        or document.get("request_values_retained") is not False
        or document.get("response_values_retained") is not False
        or document.get("credential_material_retained") is not False
    ):
        raise LiveContractFreezeError(
            "request structure evidence integrity check failed"
        )
    observation = document.get("observation")
    try:
        validated = DiscoveryObservation.model_validate(observation)
    except ValueError as exc:
        raise LiveContractFreezeError(
            "request structure observation is unsafe"
        ) from exc
    return document, (validated,)


def _one_json_observation(
    observations: tuple[DiscoveryObservation, ...],
    path: str,
) -> DiscoveryObservation:
    matches = tuple(
        observation
        for observation in observations
        if (
            observation.origin == CHENGFENG_ORIGIN
            and observation.path == path
            and observation.method == "POST"
            and observation.resource_kind == "json_api"
            and observation.response_status == 200
            and observation.content_kind == "json"
        )
    )
    if len(matches) != 1:
        raise LiveContractFreezeError(
            "discovery evidence does not contain one exact required read shape"
        )
    return matches[0]


def _declaration(
    *,
    operation: _Operation,
    observation: DiscoveryObservation,
    response_fields: MappingProxyType[str, _ResponseType],
) -> LiveReadDeclaration:
    parameters: dict[str, LiveParameterRule] = {}
    for field in observation.request_fields:
        if not field.path.startswith("$.") or "." in field.path[2:]:
            raise LiveContractFreezeError("read request contains a nested parameter")
        name = field.path[2:]
        if name.endswith("[]"):
            name = name[:-2]
            if field.type != "empty_array":
                raise LiveContractFreezeError("read request contains a populated array")
            parameters[name] = LiveParameterRule(type="empty_list")
        elif field.type == "string":
            parameters[name] = LiveParameterRule(type="string", allow_empty=True)
        elif field.type == "integer":
            maximum = 100 if name == "pageSize" else 10_000
            parameters[name] = LiveParameterRule(
                type="integer",
                minimum=1,
                maximum=maximum,
            )
        else:
            raise LiveContractFreezeError("read request parameter type is unsupported")
    return LiveReadDeclaration(
        operation=operation,
        method="POST",
        path=str(observation.path),
        parameters_location="json",
        parameters=parameters,
        response_fields=tuple(
            LiveResponseField(path=path, types=(field_type,))
            for path, field_type in response_fields.items()
        ),
    )


def _require_response_fields(
    observation: DiscoveryObservation,
    requirements: MappingProxyType[str, _ResponseType],
) -> None:
    observed = {(field.path, field.type) for field in observation.response_fields}
    if any((path, field_type) not in observed for path, field_type in requirements.items()):
        raise LiveContractFreezeError("required response field shape is missing")


def _write_idempotent(path: Path, content: bytes) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
            raise LiveContractFreezeError("existing contract output does not match")
        return
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise LiveContractFreezeError("contract output could not be written") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _require_normal_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise LiveContractFreezeError("contract directory must be a normal directory")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
