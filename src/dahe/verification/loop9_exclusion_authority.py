from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from dahe.application.chengfeng.shadow_batch import (
    chengfeng_shadow_identity_context_sha256,
)
from dahe.verification.image_similarity import ImagePerceptualFingerprint
from dahe.verification.loop9_dataset_isolation import (
    ExclusionKind,
    Loop9DatasetExclusionInventory,
    Loop9DatasetIsolationError,
    Loop9ExclusionChildIndexNode,
    Loop9ExclusionSourceBoundary,
    Loop9FullHistoryExclusionAuthority,
    build_loop9_full_history_exclusion_authority,
    parse_loop9_exclusion_inventory,
    parse_loop9_full_history_exclusion_authority,
    platform_identity_sha256,
)

_HEAD_SCHEMA_VERSION = 1
_MAX_JSON_BYTES = 10 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STORE_RELATIVE = Path("verification") / "loop9-exclusion-authority"
_DEVELOPMENT_PRODUCER_REGISTRY = Path("loop9-development-exclusions")
_DISCOVERY_EVIDENCE_ROOT = Path("platform-contract-discovery")
_DISCOVERY_EXCLUSION_ROOT = Path(
    "platform-contract-discovery-exclusions"
)
_DISCOVERY_DETAIL_SUFFIX = "getOrderItemDetailsByIdPC"
_DISCOVERY_EVIDENCE_NAME = re.compile(r"^[0-9a-f]{64}\.json$")
_REQUEST_ROLLOVER_EVIDENCE_NAME = re.compile(
    r"^(?P<sha256>[0-9a-f]{64})\.request-rollover\.json$"
)
_DETAIL_ENCODING_ROLLOVER_EVIDENCE_NAME = re.compile(
    r"^(?P<sha256>[0-9a-f]{64})\.detail-encoding-rollover\.json$"
)
_ANCHOR_TABLE = "loop9_exclusion_authority_anchors"
_ANCHOR_COLUMNS = (
    "authority_context_sha256",
    "sequence",
    "node_sha256",
    "previous_head_sha256",
    "source_boundary_sha256",
    "source_inventory_high_watermark",
    "identity_context_sha256",
    "expected_current_build_sha256",
    "expected_settlement_contract_sha256",
    "expected_daily_contract_sha256",
    "expected_settlement_selection_sha256",
    "expected_daily_selection_sha256",
    "child_inventory_sha256",
    "child_exclusion_kind",
    "child_platform_identity_count",
    "child_image_count",
    "child_scope_exclusion_token_count",
    "child_perceptual_fingerprint_count",
)


@dataclass(frozen=True, slots=True)
class Loop9VerifiedExclusionSnapshot:
    """Read-only, fully verified exclusion view for pre-selection filtering."""

    authority_sha256: str
    child_index_head_sha256: str
    source_boundary_sha256: str
    source_inventory_high_watermark: int
    identity_context_sha256: str
    expected_current_build_sha256: str
    expected_settlement_contract_sha256: str
    expected_daily_contract_sha256: str
    expected_settlement_selection_sha256: str
    expected_daily_selection_sha256: str
    development_exclusions: Loop9DatasetExclusionInventory
    legacy_loop7_exclusions: Loop9DatasetExclusionInventory
    excluded_platform_identity_sha256s: tuple[str, ...]
    excluded_image_sha256s: tuple[str, ...]
    excluded_scope_exclusion_tokens: tuple[str, ...]
    excluded_perceptual_fingerprints: tuple[
        ImagePerceptualFingerprint,
        ...,
    ]


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _authority_context_sha256(
    *,
    source_boundary: Loop9ExclusionSourceBoundary,
    identity_context_sha256: str,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> str:
    return _canonical_sha256(
        {
            "expected_current_build_sha256": expected_current_build_sha256,
            "expected_daily_contract_sha256": expected_daily_contract_sha256,
            "expected_daily_selection_sha256": expected_daily_selection_sha256,
            "expected_settlement_contract_sha256": (
                expected_settlement_contract_sha256
            ),
            "expected_settlement_selection_sha256": (
                expected_settlement_selection_sha256
            ),
            "identity_context_sha256": identity_context_sha256,
            "kind": "loop9_exclusion_authority_anchor_context",
            "schema_version": 1,
            "source_boundary_sha256": source_boundary.canonical_sha256,
            "source_inventory_high_watermark": (
                source_boundary.source_inventory_high_watermark
            ),
        }
    )


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9DatasetIsolationError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _json_object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(
        type(key) is not str for key in value
    ):
        raise Loop9DatasetIsolationError(f"{label} is invalid")
    return value


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9DatasetIsolationError(
                "exclusion authority JSON contains duplicate keys"
            )
        result[key] = value
    return result


def _json_bytes(payload: object) -> bytes:
    return (_canonical_json(payload) + "\n").encode("utf-8")


def _safe_data_root(data_root: Path) -> Path:
    if not isinstance(data_root, Path) or not data_root.is_absolute():
        raise Loop9DatasetIsolationError(
            "exclusion authority data root must be absolute"
        )
    try:
        resolved = data_root.resolve()
    except OSError as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority data root is unavailable"
        ) from exc
    if resolved != data_root or data_root.is_symlink():
        raise Loop9DatasetIsolationError(
            "exclusion authority data root is unsafe"
        )
    return resolved


def _store_root(data_root: Path) -> Path:
    return _safe_data_root(data_root) / _STORE_RELATIVE


def load_loop9_development_exclusion_registry(
    data_root: Path,
) -> tuple[Loop9DatasetExclusionInventory, ...]:
    """Load every immutable development inventory produced under this data root."""

    root = _safe_data_root(data_root)
    registry = root / _DEVELOPMENT_PRODUCER_REGISTRY
    try:
        resolved = registry.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise Loop9DatasetIsolationError(
            "development exclusion producer registry is missing"
        ) from exc
    if (
        resolved != registry
        or registry.is_symlink()
        or not resolved.is_dir()
    ):
        raise Loop9DatasetIsolationError(
            "development exclusion producer registry is unsafe"
        )

    inventories: list[Loop9DatasetExclusionInventory] = []
    inventory_sha256s: set[str] = set()
    inventory_ids: set[str] = set()
    try:
        paths = tuple(sorted(registry.glob("*.json")))
    except OSError as exc:
        raise Loop9DatasetIsolationError(
            "development exclusion producer registry is unavailable"
        ) from exc
    if not paths:
        raise Loop9DatasetIsolationError(
            "development exclusion producer registry is empty"
        )
    for path in paths:
        if (
            path.parent != registry
            or path.is_symlink()
            or not path.is_file()
        ):
            raise Loop9DatasetIsolationError(
                "development exclusion producer registry is unsafe"
            )
        try:
            inventory = parse_loop9_exclusion_inventory(
                _load_json(
                    path,
                    label="development exclusion producer registry entry",
                )
            )
        except Loop9DatasetIsolationError as exc:
            raise Loop9DatasetIsolationError(
                "development exclusion producer registry entry is invalid"
            ) from exc
        if (
            inventory.exclusion_kind is not ExclusionKind.DEVELOPMENT
            or inventory.artifact_schema_version != 2
            or inventory.identity_context_sha256 is None
            or path.name != f"{inventory.canonical_sha256}.json"
            or inventory.canonical_sha256 in inventory_sha256s
            or inventory.inventory_id in inventory_ids
        ):
            raise Loop9DatasetIsolationError(
                "development exclusion producer registry entry is invalid"
            )
        inventory_sha256s.add(inventory.canonical_sha256)
        inventory_ids.add(inventory.inventory_id)
        inventories.append(inventory)
    return tuple(
        sorted(
            inventories,
            key=lambda inventory: inventory.canonical_sha256,
        )
    )


def register_loop9_development_exclusion_inventory(
    *,
    data_root: Path,
    inventory: Loop9DatasetExclusionInventory,
) -> Path:
    """Publish one immutable producer artifact to the authoritative registry."""

    root = _safe_data_root(data_root)
    if (
        not isinstance(inventory, Loop9DatasetExclusionInventory)
        or inventory.exclusion_kind is not ExclusionKind.DEVELOPMENT
        or inventory.artifact_schema_version != 2
        or inventory.identity_context_sha256 is None
    ):
        raise Loop9DatasetIsolationError(
            "development exclusion producer inventory is invalid"
        )
    inventory.verify_integrity()
    registry = root / _DEVELOPMENT_PRODUCER_REGISTRY
    try:
        registry.mkdir(parents=False, exist_ok=True)
    except OSError as exc:
        raise Loop9DatasetIsolationError(
            "development exclusion producer registry is unavailable"
        ) from exc
    if (
        registry.is_symlink()
        or registry.resolve(strict=True) != registry
        or not registry.is_dir()
    ):
        raise Loop9DatasetIsolationError(
            "development exclusion producer registry is unsafe"
        )
    existing_paths = tuple(sorted(registry.glob("*.json")))
    for path in existing_paths:
        try:
            existing = parse_loop9_exclusion_inventory(
                _load_json(
                    path,
                    label=(
                        "development exclusion producer registry entry"
                    ),
                )
            )
        except Loop9DatasetIsolationError as exc:
            raise Loop9DatasetIsolationError(
                "development exclusion producer registry entry is invalid"
            ) from exc
        if (
            existing.inventory_id == inventory.inventory_id
            and existing.canonical_sha256 != inventory.canonical_sha256
        ):
            raise Loop9DatasetIsolationError(
                "development exclusion producer inventory ID already exists"
            )
    target = registry / f"{inventory.canonical_sha256}.json"
    _write_once(target, inventory.to_payload())
    return target


def _load_contract_discovery_evidence(
    *,
    data_root: Path,
    path: Path,
) -> tuple[dict[str, object], bool]:
    root = _safe_data_root(data_root)
    evidence_root = root / _DISCOVERY_EVIDENCE_ROOT
    if (
        not path.is_absolute()
        or path.parent != evidence_root
        or path.is_symlink()
    ):
        raise Loop9DatasetIsolationError(
            "contract discovery producer evidence path is unsafe"
        )
    document = _load_json(
        path,
        label="contract discovery producer evidence",
    )
    declared = document.get("canonical_sha256")
    body = {
        key: value
        for key, value in document.items()
        if key != "canonical_sha256"
    }
    observations = document.get("observations")
    if (
        not isinstance(declared, str)
        or _SHA256.fullmatch(declared) is None
        or declared != _canonical_sha256(body)
        or path.name != f"{declared}.json"
        or document.get("schema_version") != 1
        or document.get("kind") != "chengfeng_contract_discovery"
        or document.get("classification") != "development_only"
        or not isinstance(observations, list)
        or any(not isinstance(value, dict) for value in observations)
    ):
        raise Loop9DatasetIsolationError(
            "contract discovery producer evidence is invalid"
        )
    requires_exclusion = any(
        observation.get("resource_kind") == "image"
        or (
            observation.get("resource_kind") == "json_api"
            and isinstance(observation.get("path"), str)
            and str(observation["path"]).endswith(
                _DISCOVERY_DETAIL_SUFFIX
            )
        )
        for observation in observations
    )
    return document, requires_exclusion


def _verify_request_rollover_side_evidence(path: Path) -> None:
    match = _REQUEST_ROLLOVER_EVIDENCE_NAME.fullmatch(path.name)
    if match is None:
        raise Loop9DatasetIsolationError(
            "contract discovery producer registry contains unknown JSON"
        )
    document = _load_json(
        path,
        label="contract discovery request-rollover side evidence",
    )
    declared = document.get("canonical_sha256")
    body = {
        key: value
        for key, value in document.items()
        if key != "canonical_sha256"
    }
    required_hash_fields = (
        "parent_contract_canonical_sha256",
        "parent_contract_file_sha256",
        "parent_freeze_evidence_sha256",
        "parent_source_discovery_sha256",
        "request_structure_discovery_sha256",
    )
    if (
        set(document)
        != {
            "canonical_sha256",
            "classification",
            "credential_material_retained",
            "kind",
            "parent_contract_canonical_sha256",
            "parent_contract_file_sha256",
            "parent_freeze_evidence_sha256",
            "parent_source_discovery_sha256",
            "platform_write_authorization",
            "request_structure_discovery_sha256",
            "request_structure_observation",
            "request_values_retained",
            "requires_live_validation",
            "response_contract_inherited",
            "response_values_retained",
            "schema_version",
        }
        or not isinstance(declared, str)
        or declared != match.group("sha256")
        or declared != _canonical_sha256(body)
        or document.get("schema_version") != 1
        or document.get("kind")
        != "loop9_live_read_contract_request_rollover_source"
        or document.get("classification") != "development_only"
        or document.get("requires_live_validation") is not True
        or document.get("response_contract_inherited") is not True
        or document.get("platform_write_authorization") is not False
        or document.get("request_values_retained") is not False
        or document.get("response_values_retained") is not False
        or document.get("credential_material_retained") is not False
        or not isinstance(
            document.get("request_structure_observation"),
            dict,
        )
        or any(
            not isinstance(document.get(field), str)
            or _SHA256.fullmatch(str(document[field])) is None
            for field in required_hash_fields
        )
    ):
        raise Loop9DatasetIsolationError(
            "contract discovery request-rollover side evidence is invalid"
        )


def _verify_detail_encoding_rollover_side_evidence(
    path: Path,
) -> None:
    match = _DETAIL_ENCODING_ROLLOVER_EVIDENCE_NAME.fullmatch(path.name)
    if match is None:
        raise Loop9DatasetIsolationError(
            "contract discovery producer registry contains unknown JSON"
        )
    document = _load_json(
        path,
        label="contract discovery detail-encoding rollover side evidence",
    )
    declared = document.get("canonical_sha256")
    body = {
        key: value
        for key, value in document.items()
        if key != "canonical_sha256"
    }
    required_hash_fields = (
        "parent_contract_canonical_sha256",
        "parent_contract_file_sha256",
        "parent_freeze_evidence_sha256",
        "parent_source_discovery_sha256",
    )
    if (
        set(document)
        != {
            "canonical_sha256",
            "classification",
            "credential_material_retained",
            "encoding_change",
            "kind",
            "parent_contract_canonical_sha256",
            "parent_contract_file_sha256",
            "parent_freeze_evidence_sha256",
            "parent_source_discovery_sha256",
            "platform_write_authorization",
            "request_and_response_fields_inherited",
            "request_values_retained",
            "requires_live_validation",
            "response_values_retained",
            "schema_version",
        }
        or not isinstance(declared, str)
        or declared != match.group("sha256")
        or declared != _canonical_sha256(body)
        or document.get("schema_version") != 1
        or document.get("kind")
        != "loop9_live_read_contract_detail_encoding_rollover_source"
        or document.get("classification") != "development_only"
        or document.get("encoding_change")
        != {
            "operation": "get_waybill_detail",
            "from": "json",
            "to": "form",
        }
        or document.get("request_and_response_fields_inherited")
        is not True
        or document.get("requires_live_validation") is not True
        or document.get("platform_write_authorization") is not False
        or document.get("request_values_retained") is not False
        or document.get("response_values_retained") is not False
        or document.get("credential_material_retained") is not False
        or any(
            not isinstance(document.get(field), str)
            or _SHA256.fullmatch(str(document[field])) is None
            for field in required_hash_fields
        )
    ):
        raise Loop9DatasetIsolationError(
            "contract discovery detail-encoding rollover side evidence "
            "is invalid"
        )


def register_loop9_contract_discovery_exclusion(
    *,
    data_root: Path,
    discovery_evidence_path: Path,
    source_identities: tuple[str, ...],
    identity_salt: bytes,
    identity_namespace: str,
) -> Loop9DatasetExclusionInventory:
    """Bind manually observed discovery identities without persisting raw IDs."""

    document, requires_exclusion = _load_contract_discovery_evidence(
        data_root=data_root,
        path=discovery_evidence_path,
    )
    if not requires_exclusion:
        raise Loop9DatasetIsolationError(
            "contract discovery evidence has no detail exposure"
        )
    if (
        not isinstance(source_identities, tuple)
        or not source_identities
        or len(source_identities) > 100
    ):
        raise Loop9DatasetIsolationError(
            "contract discovery source identities are invalid"
        )
    identity_sha256s = tuple(
        sorted(
            {
                platform_identity_sha256(
                    identity_salt=identity_salt,
                    identity_namespace=identity_namespace,
                    source_identity=value,
                )
                for value in source_identities
            }
        )
    )
    if len(identity_sha256s) != len(source_identities):
        raise Loop9DatasetIsolationError(
            "contract discovery source identities contain duplicates"
        )
    source_sha256 = str(document["canonical_sha256"])
    identity_context_sha256 = (
        chengfeng_shadow_identity_context_sha256(
            salt=identity_salt,
            namespace=identity_namespace,
        )
    )
    inventory = Loop9DatasetExclusionInventory(
        inventory_id=f"contract-discovery-{source_sha256[:32]}",
        exclusion_kind=ExclusionKind.DEVELOPMENT,
        platform_identity_sha256s=identity_sha256s,
        image_sha256s=(),
        scope_exclusion_tokens=(),
        perceptual_fingerprints=(),
        identity_context_sha256=identity_context_sha256,
    )
    register_loop9_development_exclusion_inventory(
        data_root=data_root,
        inventory=inventory,
    )
    root = _safe_data_root(data_root)
    binding_root = root / _DISCOVERY_EXCLUSION_ROOT
    try:
        binding_root.mkdir(parents=False, exist_ok=True)
    except OSError as exc:
        raise Loop9DatasetIsolationError(
            "contract discovery producer registry is unavailable"
        ) from exc
    if (
        binding_root.is_symlink()
        or binding_root.resolve(strict=True) != binding_root
        or not binding_root.is_dir()
    ):
        raise Loop9DatasetIsolationError(
            "contract discovery producer registry is unsafe"
        )
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_contract_discovery_development_exclusion",
        "classification": "development_only",
        "source_discovery_sha256": source_sha256,
        "inventory_sha256": inventory.canonical_sha256,
        "identity_context_sha256": identity_context_sha256,
        "platform_identity_count": len(identity_sha256s),
        "image_count": 0,
        "raw_platform_identity_retained": False,
        "raw_business_values_retained": False,
        "raw_image_bytes_retained": False,
    }
    canonical_sha256 = _canonical_sha256(body)
    _write_once(
        binding_root / f"{canonical_sha256}.json",
        {**body, "canonical_sha256": canonical_sha256},
    )
    return inventory


def _verify_contract_discovery_producer_registry(
    *,
    data_root: Path,
    producer_registry: tuple[Loop9DatasetExclusionInventory, ...],
) -> None:
    root = _safe_data_root(data_root)
    evidence_root = root / _DISCOVERY_EVIDENCE_ROOT
    required_sources: set[str] = set()
    if evidence_root.exists():
        if (
            evidence_root.is_symlink()
            or evidence_root.resolve(strict=True) != evidence_root
            or not evidence_root.is_dir()
        ):
            raise Loop9DatasetIsolationError(
                "contract discovery producer registry is unsafe"
            )
        for path in sorted(evidence_root.glob("*.json")):
            if _DISCOVERY_EVIDENCE_NAME.fullmatch(path.name):
                document, requires_exclusion = (
                    _load_contract_discovery_evidence(
                        data_root=root,
                        path=path,
                    )
                )
            elif _REQUEST_ROLLOVER_EVIDENCE_NAME.fullmatch(path.name):
                _verify_request_rollover_side_evidence(path)
                continue
            elif _DETAIL_ENCODING_ROLLOVER_EVIDENCE_NAME.fullmatch(
                path.name
            ):
                _verify_detail_encoding_rollover_side_evidence(path)
                continue
            else:
                raise Loop9DatasetIsolationError(
                    "contract discovery producer registry contains "
                    "unknown JSON"
                )
            if requires_exclusion:
                required_sources.add(str(document["canonical_sha256"]))

    binding_root = root / _DISCOVERY_EXCLUSION_ROOT
    binding_by_source: dict[str, dict[str, object]] = {}
    if binding_root.exists():
        if (
            binding_root.is_symlink()
            or binding_root.resolve(strict=True) != binding_root
            or not binding_root.is_dir()
        ):
            raise Loop9DatasetIsolationError(
                "contract discovery producer registry is unsafe"
            )
        for path in sorted(binding_root.glob("*.json")):
            binding = _load_json(
                path,
                label="contract discovery producer registry binding",
            )
            declared = binding.get("canonical_sha256")
            body = {
                key: value
                for key, value in binding.items()
                if key != "canonical_sha256"
            }
            source_sha256 = binding.get("source_discovery_sha256")
            if (
                set(binding)
                != {
                    "canonical_sha256",
                    "classification",
                    "identity_context_sha256",
                    "image_count",
                    "inventory_sha256",
                    "kind",
                    "platform_identity_count",
                    "raw_business_values_retained",
                    "raw_image_bytes_retained",
                    "raw_platform_identity_retained",
                    "schema_version",
                    "source_discovery_sha256",
                }
                or not isinstance(declared, str)
                or _SHA256.fullmatch(declared) is None
                or declared != _canonical_sha256(body)
                or path.name != f"{declared}.json"
                or binding.get("schema_version") != 1
                or binding.get("kind")
                != "loop9_contract_discovery_development_exclusion"
                or binding.get("classification") != "development_only"
                or not isinstance(source_sha256, str)
                or _SHA256.fullmatch(source_sha256) is None
                or binding.get("raw_platform_identity_retained")
                is not False
                or binding.get("raw_business_values_retained") is not False
                or binding.get("raw_image_bytes_retained") is not False
                or binding.get("image_count") != 0
                or source_sha256 in binding_by_source
            ):
                raise Loop9DatasetIsolationError(
                    "contract discovery producer registry binding is invalid"
                )
            binding_by_source[source_sha256] = binding
    if set(binding_by_source) != required_sources:
        raise Loop9DatasetIsolationError(
            "contract discovery producer registry is incomplete"
        )
    inventory_by_sha256 = {
        inventory.canonical_sha256: inventory
        for inventory in producer_registry
    }
    for binding in binding_by_source.values():
        inventory_sha256 = binding.get("inventory_sha256")
        identity_count = binding.get("platform_identity_count")
        inventory = inventory_by_sha256.get(str(inventory_sha256))
        if (
            inventory is None
            or inventory.exclusion_kind is not ExclusionKind.DEVELOPMENT
            or inventory.artifact_schema_version != 2
            or inventory.identity_context_sha256
            != binding.get("identity_context_sha256")
            or type(identity_count) is not int
            or identity_count < 1
            or len(inventory.platform_identity_sha256s)
            != identity_count
            or inventory.image_sha256s
            or inventory.perceptual_fingerprints
            or inventory.scope_exclusion_tokens
        ):
            raise Loop9DatasetIsolationError(
                "contract discovery producer registry binding is invalid"
            )


def _verify_development_producer_registry(
    *,
    child_inventories: tuple[Loop9DatasetExclusionInventory, ...],
    producer_registry: tuple[Loop9DatasetExclusionInventory, ...],
) -> None:
    chain_development = {
        inventory.canonical_sha256: inventory
        for inventory in child_inventories
        if inventory.exclusion_kind is ExclusionKind.DEVELOPMENT
    }
    registered = {
        inventory.canonical_sha256: inventory
        for inventory in producer_registry
    }
    if set(chain_development) != set(registered):
        raise Loop9DatasetIsolationError(
            "development exclusion producer registry does not exactly match "
            "the authority chain"
        )
    for sha256, inventory in registered.items():
        if (
            chain_development[sha256].to_payload()
            != inventory.to_payload()
        ):
            raise Loop9DatasetIsolationError(
                "development exclusion producer registry does not exactly "
                "match the authority chain"
            )


def validate_loop9_exclusion_producer_registries(
    *,
    data_root: Path,
    child_inventories: tuple[Loop9DatasetExclusionInventory, ...],
) -> None:
    """Validate all producer registries before mutating the authority chain."""

    producer_registry = load_loop9_development_exclusion_registry(
        data_root
    )
    _verify_development_producer_registry(
        child_inventories=child_inventories,
        producer_registry=producer_registry,
    )
    _verify_contract_discovery_producer_registry(
        data_root=data_root,
        producer_registry=producer_registry,
    )


def _ensure_directory(path: Path, *, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority directory escapes the data root"
        ) from exc
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.resolve() != path:
        raise Loop9DatasetIsolationError(
            "exclusion authority directory is unsafe"
        )


def _load_json(path: Path, *, label: str) -> dict[str, object]:
    try:
        resolved = path.resolve(strict=True)
        if (
            resolved != path
            or path.is_symlink()
            or not resolved.is_file()
            or resolved.stat().st_size > _MAX_JSON_BYTES
        ):
            raise Loop9DatasetIsolationError(f"{label} is invalid")
        content = resolved.read_bytes()
    except FileNotFoundError as exc:
        raise Loop9DatasetIsolationError(f"{label} is missing") from exc
    except OSError as exc:
        raise Loop9DatasetIsolationError(f"{label} is unavailable") from exc
    try:
        return _json_object(
            json.loads(
                content.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_keys,
            ),
            label=label,
        )
    except Loop9DatasetIsolationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9DatasetIsolationError(f"{label} is invalid") from exc


def _write_once(path: Path, payload: object) -> None:
    content = _json_bytes(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if (
            path.is_symlink()
            or not path.is_file()
            or path.read_bytes() != content
        ):
            raise Loop9DatasetIsolationError(
                "exclusion authority immutable artifact conflicts"
            )
        return
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if (
                path.is_symlink()
                or not path.is_file()
                or path.read_bytes() != content
            ):
                raise Loop9DatasetIsolationError(
                    "exclusion authority immutable artifact conflicts"
                ) from None
    except OSError as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority immutable artifact could not be written"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _replace_atomic(path: Path, payload: object) -> None:
    content = _json_bytes(payload)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority head could not be updated"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


@contextmanager
def _store_lock(
    store: Path,
    *,
    create: bool,
) -> Iterator[None]:
    import msvcrt

    lock_path = store / "append.lock"
    try:
        stream = lock_path.open("a+b" if create else "r+b")
    except OSError as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority lock is missing"
        ) from exc
    with stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


@dataclass(frozen=True, slots=True)
class _ExclusionChildIndexHead:
    head_sha256: str
    sequence: int
    source_boundary_sha256: str
    source_inventory_high_watermark: int
    identity_context_sha256: str
    expected_current_build_sha256: str
    expected_settlement_contract_sha256: str
    expected_daily_contract_sha256: str
    expected_settlement_selection_sha256: str
    expected_daily_selection_sha256: str
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for value, label in (
            (self.head_sha256, "exclusion authority head SHA-256"),
            (
                self.source_boundary_sha256,
                "exclusion authority source boundary SHA-256",
            ),
            (
                self.identity_context_sha256,
                "exclusion authority identity context SHA-256",
            ),
            (
                self.expected_current_build_sha256,
                "exclusion authority build SHA-256",
            ),
            (
                self.expected_settlement_contract_sha256,
                "exclusion authority settlement contract SHA-256",
            ),
            (
                self.expected_daily_contract_sha256,
                "exclusion authority daily contract SHA-256",
            ),
            (
                self.expected_settlement_selection_sha256,
                "exclusion authority settlement selection SHA-256",
            ),
            (
                self.expected_daily_selection_sha256,
                "exclusion authority daily selection SHA-256",
            ),
        ):
            _sha256(value, label=label)
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or isinstance(self.source_inventory_high_watermark, bool)
            or not isinstance(self.source_inventory_high_watermark, int)
            or self.source_inventory_high_watermark < 1
        ):
            raise Loop9DatasetIsolationError(
                "exclusion authority head counts are invalid"
            )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "expected_current_build_sha256": (
                self.expected_current_build_sha256
            ),
            "expected_daily_contract_sha256": (
                self.expected_daily_contract_sha256
            ),
            "expected_daily_selection_sha256": (
                self.expected_daily_selection_sha256
            ),
            "expected_settlement_contract_sha256": (
                self.expected_settlement_contract_sha256
            ),
            "expected_settlement_selection_sha256": (
                self.expected_settlement_selection_sha256
            ),
            "head_sha256": self.head_sha256,
            "identity_context_sha256": self.identity_context_sha256,
            "kind": "loop9_exclusion_child_index_head",
            "schema_version": _HEAD_SCHEMA_VERSION,
            "sequence": self.sequence,
            "source_boundary_sha256": self.source_boundary_sha256,
            "source_inventory_high_watermark": (
                self.source_inventory_high_watermark
            ),
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    @classmethod
    def from_payload(cls, value: object) -> _ExclusionChildIndexHead:
        raw = _json_object(value, label="exclusion authority head")
        expected = {
            "canonical_sha256",
            "expected_current_build_sha256",
            "expected_daily_contract_sha256",
            "expected_daily_selection_sha256",
            "expected_settlement_contract_sha256",
            "expected_settlement_selection_sha256",
            "head_sha256",
            "identity_context_sha256",
            "kind",
            "schema_version",
            "sequence",
            "source_boundary_sha256",
            "source_inventory_high_watermark",
        }
        sequence = raw.get("sequence")
        high_watermark = raw.get("source_inventory_high_watermark")
        if (
            set(raw) != expected
            or raw.get("schema_version") != _HEAD_SCHEMA_VERSION
            or raw.get("kind") != "loop9_exclusion_child_index_head"
            or type(sequence) is not int
            or type(high_watermark) is not int
        ):
            raise Loop9DatasetIsolationError(
                "exclusion authority head contract is invalid"
            )
        head = cls(
            head_sha256=_sha256(
                raw.get("head_sha256"),
                label="exclusion authority head SHA-256",
            ),
            sequence=sequence,
            source_boundary_sha256=_sha256(
                raw.get("source_boundary_sha256"),
                label="exclusion authority source boundary SHA-256",
            ),
            source_inventory_high_watermark=high_watermark,
            identity_context_sha256=_sha256(
                raw.get("identity_context_sha256"),
                label="exclusion authority identity context SHA-256",
            ),
            expected_current_build_sha256=_sha256(
                raw.get("expected_current_build_sha256"),
                label="exclusion authority build SHA-256",
            ),
            expected_settlement_contract_sha256=_sha256(
                raw.get("expected_settlement_contract_sha256"),
                label="exclusion authority settlement contract SHA-256",
            ),
            expected_daily_contract_sha256=_sha256(
                raw.get("expected_daily_contract_sha256"),
                label="exclusion authority daily contract SHA-256",
            ),
            expected_settlement_selection_sha256=_sha256(
                raw.get("expected_settlement_selection_sha256"),
                label="exclusion authority settlement selection SHA-256",
            ),
            expected_daily_selection_sha256=_sha256(
                raw.get("expected_daily_selection_sha256"),
                label="exclusion authority daily selection SHA-256",
            ),
        )
        if (
            _sha256(
                raw.get("canonical_sha256"),
                label="exclusion authority head canonical SHA-256",
            )
            != head.canonical_sha256
            or raw != head.to_payload()
        ):
            raise Loop9DatasetIsolationError(
                "exclusion authority head integrity is invalid"
            )
        return head


def _head_from_node(
    node: Loop9ExclusionChildIndexNode,
) -> _ExclusionChildIndexHead:
    return _ExclusionChildIndexHead(
        head_sha256=node.canonical_sha256,
        sequence=node.sequence,
        source_boundary_sha256=node.source_boundary_sha256,
        source_inventory_high_watermark=(
            node.source_inventory_high_watermark
        ),
        identity_context_sha256=node.identity_context_sha256,
        expected_current_build_sha256=node.expected_current_build_sha256,
        expected_settlement_contract_sha256=(
            node.expected_settlement_contract_sha256
        ),
        expected_daily_contract_sha256=(
            node.expected_daily_contract_sha256
        ),
        expected_settlement_selection_sha256=(
            node.expected_settlement_selection_sha256
        ),
        expected_daily_selection_sha256=(
            node.expected_daily_selection_sha256
        ),
    )


def _prepare_store(
    data_root: Path,
    *,
    create: bool,
) -> tuple[Path, Path, Path, Path]:
    root = _safe_data_root(data_root)
    store = _store_root(root)
    children = store / "children"
    nodes = store / "nodes"
    authorities = store / "authorities"
    if create:
        for directory in (store, children, nodes, authorities):
            _ensure_directory(directory, root=root)
    elif any(
        not directory.is_dir()
        or directory.is_symlink()
        or directory.resolve() != directory
        for directory in (store, children, nodes, authorities)
    ):
        raise Loop9DatasetIsolationError(
            "exclusion authority store is missing or unsafe"
        )
    return store, children, nodes, authorities


@contextmanager
def _anchor_connection(
    data_root: Path,
    *,
    write: bool,
) -> Iterator[sqlite3.Connection]:
    root = _safe_data_root(data_root)
    database = root / "database" / "dahe.sqlite3"
    try:
        resolved = database.resolve(strict=True)
        resolved.relative_to(root)
        if database.is_symlink() or not resolved.is_file():
            raise Loop9DatasetIsolationError(
                "exclusion authority SQLite anchor is unavailable"
            )
        mode = "rw" if write else "ro"
        connection = sqlite3.connect(
            f"{resolved.as_uri()}?mode={mode}",
            uri=True,
            timeout=5.0,
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority SQLite anchor is unavailable"
        ) from exc
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        if not write:
            connection.execute("PRAGMA query_only=ON")
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (_ANCHOR_TABLE,),
        ).fetchone()
        if table is None:
            raise Loop9DatasetIsolationError(
                "exclusion authority SQLite anchor schema is missing"
            )
        yield connection
    except sqlite3.Error as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority SQLite anchor is invalid"
        ) from exc
    finally:
        connection.close()


def _node_from_anchor_row(row: sqlite3.Row) -> Loop9ExclusionChildIndexNode:
    try:
        node = Loop9ExclusionChildIndexNode(
            sequence=int(row["sequence"]),
            previous_head_sha256=(
                None
                if row["previous_head_sha256"] is None
                else str(row["previous_head_sha256"])
            ),
            source_boundary_sha256=str(row["source_boundary_sha256"]),
            source_inventory_high_watermark=int(
                row["source_inventory_high_watermark"]
            ),
            identity_context_sha256=str(row["identity_context_sha256"]),
            expected_current_build_sha256=str(
                row["expected_current_build_sha256"]
            ),
            expected_settlement_contract_sha256=str(
                row["expected_settlement_contract_sha256"]
            ),
            expected_daily_contract_sha256=str(
                row["expected_daily_contract_sha256"]
            ),
            expected_settlement_selection_sha256=str(
                row["expected_settlement_selection_sha256"]
            ),
            expected_daily_selection_sha256=str(
                row["expected_daily_selection_sha256"]
            ),
            child_inventory_sha256=str(row["child_inventory_sha256"]),
            child_exclusion_kind=ExclusionKind(
                str(row["child_exclusion_kind"])
            ),
            child_platform_identity_count=int(
                row["child_platform_identity_count"]
            ),
            child_image_count=int(row["child_image_count"]),
            child_scope_exclusion_token_count=int(
                row["child_scope_exclusion_token_count"]
            ),
            child_perceptual_fingerprint_count=int(
                row["child_perceptual_fingerprint_count"]
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority SQLite anchor row is invalid"
        ) from exc
    if str(row["node_sha256"]) != node.canonical_sha256:
        raise Loop9DatasetIsolationError(
            "exclusion authority SQLite anchor integrity is invalid"
        )
    return node


def _load_anchor_nodes(
    connection: sqlite3.Connection,
    *,
    authority_context_sha256: str,
) -> tuple[Loop9ExclusionChildIndexNode, ...]:
    columns = ", ".join(_ANCHOR_COLUMNS)
    try:
        rows = connection.execute(
            f"SELECT {columns} FROM {_ANCHOR_TABLE} "
            "WHERE authority_context_sha256 = ? ORDER BY sequence",
            (authority_context_sha256,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority SQLite anchor is invalid"
        ) from exc
    return tuple(_node_from_anchor_row(row) for row in rows)


def _verify_sqlite_anchor(
    *,
    anchor_nodes: tuple[Loop9ExclusionChildIndexNode, ...],
    file_nodes: tuple[Loop9ExclusionChildIndexNode, ...],
    head: _ExclusionChildIndexHead,
) -> None:
    if (
        not anchor_nodes
        or len(anchor_nodes) != len(file_nodes)
        or tuple(
            (node.sequence, node.canonical_sha256)
            for node in anchor_nodes
        )
        != tuple(
            (node.sequence, node.canonical_sha256)
            for node in file_nodes
        )
        or anchor_nodes[-1].canonical_sha256 != head.head_sha256
        or anchor_nodes[-1].sequence != head.sequence
    ):
        raise Loop9DatasetIsolationError(
            "exclusion authority SQLite anchor does not match the file chain"
        )


def _insert_anchor_node(
    connection: sqlite3.Connection,
    *,
    authority_context_sha256: str,
    node: Loop9ExclusionChildIndexNode,
) -> None:
    placeholders = ", ".join("?" for _ in _ANCHOR_COLUMNS)
    columns = ", ".join(_ANCHOR_COLUMNS)
    values = (
        authority_context_sha256,
        node.sequence,
        node.canonical_sha256,
        node.previous_head_sha256,
        node.source_boundary_sha256,
        node.source_inventory_high_watermark,
        node.identity_context_sha256,
        node.expected_current_build_sha256,
        node.expected_settlement_contract_sha256,
        node.expected_daily_contract_sha256,
        node.expected_settlement_selection_sha256,
        node.expected_daily_selection_sha256,
        node.child_inventory_sha256,
        node.child_exclusion_kind.value,
        node.child_platform_identity_count,
        node.child_image_count,
        node.child_scope_exclusion_token_count,
        node.child_perceptual_fingerprint_count,
    )
    try:
        connection.execute(
            f"INSERT INTO {_ANCHOR_TABLE} ({columns}) VALUES ({placeholders})",
            values,
        )
    except sqlite3.IntegrityError as exc:
        raise Loop9DatasetIsolationError(
            "exclusion authority SQLite anchor append was rejected"
        ) from exc


def _load_child(path: Path) -> Loop9DatasetExclusionInventory:
    try:
        child = parse_loop9_exclusion_inventory(
            _load_json(path, label="exclusion child inventory")
        )
    except Loop9DatasetIsolationError as exc:
        if "missing" in str(exc):
            raise Loop9DatasetIsolationError(
                "exclusion child inventory is missing"
            ) from exc
        raise
    if path.stem != child.canonical_sha256:
        raise Loop9DatasetIsolationError(
            "exclusion child inventory path integrity is invalid"
        )
    return child


def _load_node(path: Path) -> Loop9ExclusionChildIndexNode:
    try:
        node = Loop9ExclusionChildIndexNode.from_payload(
            _load_json(path, label="exclusion child index node")
        )
    except Loop9DatasetIsolationError as exc:
        if "integrity" not in str(exc):
            raise Loop9DatasetIsolationError(
                "exclusion child index node integrity is invalid"
            ) from exc
        raise
    if path.stem != node.canonical_sha256:
        raise Loop9DatasetIsolationError(
            "exclusion child index node path integrity is invalid"
        )
    return node


def _binding_tuple(
    *,
    source_boundary: Loop9ExclusionSourceBoundary,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> tuple[object, ...]:
    return (
        source_boundary.canonical_sha256,
        source_boundary.source_inventory_high_watermark,
        expected_current_build_sha256,
        expected_settlement_contract_sha256,
        expected_daily_contract_sha256,
        expected_settlement_selection_sha256,
        expected_daily_selection_sha256,
    )


def _load_chain(
    *,
    children_root: Path,
    nodes_root: Path,
    head_path: Path,
    source_boundary: Loop9ExclusionSourceBoundary,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> tuple[
    _ExclusionChildIndexHead,
    tuple[Loop9ExclusionChildIndexNode, ...],
    tuple[Loop9DatasetExclusionInventory, ...],
]:
    if not head_path.exists():
        raise Loop9DatasetIsolationError(
            "exclusion authority head is missing"
        )
    head = _ExclusionChildIndexHead.from_payload(
        _load_json(head_path, label="exclusion authority head")
    )
    node_paths = tuple(sorted(nodes_root.glob("*.json")))
    if not node_paths or any(path.is_symlink() for path in node_paths):
        raise Loop9DatasetIsolationError(
            "exclusion child index history is missing"
        )
    loaded_nodes = tuple(_load_node(path) for path in node_paths)
    nodes = {node.canonical_sha256: node for node in loaded_nodes}
    if len(nodes) != len(loaded_nodes):
        raise Loop9DatasetIsolationError(
            "exclusion child index node is duplicated"
        )
    children_by_parent: dict[str | None, list[Loop9ExclusionChildIndexNode]] = {}
    for node in nodes.values():
        children_by_parent.setdefault(node.previous_head_sha256, []).append(
            node
        )
    if any(len(values) != 1 for values in children_by_parent.values()):
        raise Loop9DatasetIsolationError(
            "exclusion child index fork is not allowed"
        )
    genesis = children_by_parent.get(None, [])
    if len(genesis) != 1:
        raise Loop9DatasetIsolationError(
            "exclusion child index fork is not allowed"
        )
    ordered: list[Loop9ExclusionChildIndexNode] = []
    current = genesis[0]
    visited: set[str] = set()
    while True:
        if current.canonical_sha256 in visited:
            raise Loop9DatasetIsolationError(
                "exclusion child index cycle is invalid"
            )
        visited.add(current.canonical_sha256)
        ordered.append(current)
        descendants = children_by_parent.get(current.canonical_sha256, [])
        if not descendants:
            break
        current = descendants[0]
    if visited != set(nodes):
        raise Loop9DatasetIsolationError(
            "exclusion child index fork is not allowed"
        )
    tip = ordered[-1]
    if head.head_sha256 != tip.canonical_sha256:
        if head.head_sha256 in visited:
            raise Loop9DatasetIsolationError(
                "exclusion child index head rollback is not allowed"
            )
        raise Loop9DatasetIsolationError(
            "exclusion authority head does not identify the chain tip"
        )
    if head.sequence != tip.sequence or any(
        node.sequence != index
        for index, node in enumerate(ordered, start=1)
    ):
        raise Loop9DatasetIsolationError(
            "exclusion child index sequence is incomplete"
        )
    expected_binding = _binding_tuple(
        source_boundary=source_boundary,
        expected_current_build_sha256=expected_current_build_sha256,
        expected_settlement_contract_sha256=(
            expected_settlement_contract_sha256
        ),
        expected_daily_contract_sha256=expected_daily_contract_sha256,
        expected_settlement_selection_sha256=(
            expected_settlement_selection_sha256
        ),
        expected_daily_selection_sha256=(
            expected_daily_selection_sha256
        ),
    )
    head_binding = (
        head.source_boundary_sha256,
        head.source_inventory_high_watermark,
        head.expected_current_build_sha256,
        head.expected_settlement_contract_sha256,
        head.expected_daily_contract_sha256,
        head.expected_settlement_selection_sha256,
        head.expected_daily_selection_sha256,
    )
    if head_binding != expected_binding:
        raise Loop9DatasetIsolationError(
            "exclusion child index does not match the current build or contract authority"
        )
    child_inventories: list[Loop9DatasetExclusionInventory] = []
    for node in ordered:
        child = _load_child(
            children_root / f"{node.child_inventory_sha256}.json"
        )
        node.verify_bindings(
            source_boundary=source_boundary,
            child_inventory=child,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
        )
        if node.identity_context_sha256 != head.identity_context_sha256:
            raise Loop9DatasetIsolationError(
                "exclusion child index identity context changed"
            )
        child_inventories.append(child)
    referenced_children = {
        node.child_inventory_sha256 for node in ordered
    }
    stored_children = {
        path.stem for path in children_root.glob("*.json")
    }
    if referenced_children != stored_children:
        raise Loop9DatasetIsolationError(
            "exclusion child index has an unreferenced or missing child"
        )
    return head, tuple(ordered), tuple(child_inventories)


def append_loop9_exclusion_child(
    *,
    data_root: Path,
    source_boundary: Loop9ExclusionSourceBoundary,
    child_inventory: Loop9DatasetExclusionInventory,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> Loop9ExclusionChildIndexNode:
    source_boundary.verify_integrity()
    child_inventory.verify_integrity()
    store, children_root, nodes_root, _ = _prepare_store(
        data_root,
        create=True,
    )
    head_path = store / "head.json"
    with (
        _store_lock(store, create=True),
        _anchor_connection(data_root, write=True) as anchor_connection,
    ):
        if head_path.exists():
            head, nodes, children = _load_chain(
                children_root=children_root,
                nodes_root=nodes_root,
                head_path=head_path,
                source_boundary=source_boundary,
                expected_current_build_sha256=(
                    expected_current_build_sha256
                ),
                expected_settlement_contract_sha256=(
                    expected_settlement_contract_sha256
                ),
                expected_daily_contract_sha256=(
                    expected_daily_contract_sha256
                ),
                expected_settlement_selection_sha256=(
                    expected_settlement_selection_sha256
                ),
                expected_daily_selection_sha256=(
                    expected_daily_selection_sha256
                ),
            )
            authority_context_sha256 = _authority_context_sha256(
                source_boundary=source_boundary,
                identity_context_sha256=head.identity_context_sha256,
                expected_current_build_sha256=(
                    expected_current_build_sha256
                ),
                expected_settlement_contract_sha256=(
                    expected_settlement_contract_sha256
                ),
                expected_daily_contract_sha256=(
                    expected_daily_contract_sha256
                ),
                expected_settlement_selection_sha256=(
                    expected_settlement_selection_sha256
                ),
                expected_daily_selection_sha256=(
                    expected_daily_selection_sha256
                ),
            )
            _verify_sqlite_anchor(
                anchor_nodes=_load_anchor_nodes(
                    anchor_connection,
                    authority_context_sha256=authority_context_sha256,
                ),
                file_nodes=nodes,
                head=head,
            )
            for node, child in zip(nodes, children, strict=True):
                if child.canonical_sha256 == child_inventory.canonical_sha256:
                    return node
            sequence = head.sequence + 1
            previous = head.head_sha256
            expected_context = head.identity_context_sha256
            if child_inventory.identity_context_sha256 != expected_context:
                raise Loop9DatasetIsolationError(
                    "exclusion child index identity context changed"
                )
        else:
            identity_context_sha256 = child_inventory.identity_context_sha256
            if identity_context_sha256 is None:
                raise Loop9DatasetIsolationError(
                    "legacy exclusion child cannot start the current index"
                )
            authority_context_sha256 = _authority_context_sha256(
                source_boundary=source_boundary,
                identity_context_sha256=identity_context_sha256,
                expected_current_build_sha256=(
                    expected_current_build_sha256
                ),
                expected_settlement_contract_sha256=(
                    expected_settlement_contract_sha256
                ),
                expected_daily_contract_sha256=(
                    expected_daily_contract_sha256
                ),
                expected_settlement_selection_sha256=(
                    expected_settlement_selection_sha256
                ),
                expected_daily_selection_sha256=(
                    expected_daily_selection_sha256
                ),
            )
            if _load_anchor_nodes(
                anchor_connection,
                authority_context_sha256=authority_context_sha256,
            ):
                raise Loop9DatasetIsolationError(
                    "exclusion authority SQLite anchor does not match "
                    "the missing file chain"
                )
            if any(nodes_root.glob("*.json")) or any(
                children_root.glob("*.json")
            ):
                raise Loop9DatasetIsolationError(
                    "exclusion child index head is missing"
                )
            sequence = 1
            previous = None
        node = Loop9ExclusionChildIndexNode.create(
            sequence=sequence,
            previous_head_sha256=previous,
            source_boundary=source_boundary,
            child_inventory=child_inventory,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
        )
        _write_once(
            children_root / f"{child_inventory.canonical_sha256}.json",
            child_inventory.to_payload(),
        )
        _write_once(
            nodes_root / f"{node.canonical_sha256}.json",
            node.to_payload(),
        )
        try:
            anchor_connection.execute("BEGIN IMMEDIATE")
            current_anchors = _load_anchor_nodes(
                anchor_connection,
                authority_context_sha256=authority_context_sha256,
            )
            if (
                len(current_anchors) != sequence - 1
                or (
                    current_anchors
                    and current_anchors[-1].canonical_sha256 != previous
                )
            ):
                raise Loop9DatasetIsolationError(
                    "exclusion authority SQLite anchor changed during append"
                )
            _insert_anchor_node(
                anchor_connection,
                authority_context_sha256=authority_context_sha256,
                node=node,
            )
            anchor_connection.commit()
        except Exception:
            anchor_connection.rollback()
            raise
        _replace_atomic(head_path, _head_from_node(node).to_payload())
        return node


def load_sealed_loop9_full_history_exclusion_authority(
    *,
    data_root: Path,
    source_boundary: Loop9ExclusionSourceBoundary,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> Loop9FullHistoryExclusionAuthority:
    store, children_root, nodes_root, _ = _prepare_store(
        data_root,
        create=False,
    )
    with (
        _store_lock(store, create=False),
        _anchor_connection(data_root, write=False) as anchor_connection,
    ):
        head, nodes, children = _load_chain(
            children_root=children_root,
            nodes_root=nodes_root,
            head_path=store / "head.json",
            source_boundary=source_boundary,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
        )
        authority_context_sha256 = _authority_context_sha256(
            source_boundary=source_boundary,
            identity_context_sha256=head.identity_context_sha256,
            expected_current_build_sha256=expected_current_build_sha256,
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=expected_daily_contract_sha256,
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
        )
        _verify_sqlite_anchor(
            anchor_nodes=_load_anchor_nodes(
                anchor_connection,
                authority_context_sha256=authority_context_sha256,
            ),
            file_nodes=nodes,
            head=head,
        )
        authority = build_loop9_full_history_exclusion_authority(
            source_boundary=source_boundary,
            child_inventories=children,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
        )
        if authority.child_index_head_sha256 != head.head_sha256:
            raise Loop9DatasetIsolationError(
                "full-history exclusion authority head is inconsistent"
            )
        return authority


def load_current_loop9_full_history_exclusion_authority(
    *,
    data_root: Path,
    source_boundary: Loop9ExclusionSourceBoundary,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> Loop9FullHistoryExclusionAuthority:
    authority = load_sealed_loop9_full_history_exclusion_authority(
        data_root=data_root,
        source_boundary=source_boundary,
        expected_current_build_sha256=expected_current_build_sha256,
        expected_settlement_contract_sha256=(
            expected_settlement_contract_sha256
        ),
        expected_daily_contract_sha256=expected_daily_contract_sha256,
        expected_settlement_selection_sha256=(
            expected_settlement_selection_sha256
        ),
        expected_daily_selection_sha256=expected_daily_selection_sha256,
    )
    producer_registry = load_loop9_development_exclusion_registry(data_root)
    _verify_development_producer_registry(
        child_inventories=authority.child_inventories,
        producer_registry=producer_registry,
    )
    _verify_contract_discovery_producer_registry(
        data_root=data_root,
        producer_registry=producer_registry,
    )
    return authority


def load_current_persisted_loop9_full_history_exclusion_authority(
    *,
    data_root: Path,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> Loop9FullHistoryExclusionAuthority:
    """Bootstrap the source boundary from the immutable current authority.

    The active Loop 9 database is intentionally independent from the Loop 7
    template database. The persisted full-history authority is therefore the
    only allowed bootstrap source, and it is accepted only when its immutable
    payload identifies the current append-only chain tip and every current
    build and contract binding.
    """

    expected_bindings = (
        _sha256(
            expected_current_build_sha256,
            label="expected current build SHA-256",
        ),
        _sha256(
            expected_settlement_contract_sha256,
            label="expected settlement contract SHA-256",
        ),
        _sha256(
            expected_daily_contract_sha256,
            label="expected daily contract SHA-256",
        ),
        _sha256(
            expected_settlement_selection_sha256,
            label="expected settlement selection SHA-256",
        ),
        _sha256(
            expected_daily_selection_sha256,
            label="expected daily selection SHA-256",
        ),
    )
    store, _, _, authorities_root = _prepare_store(
        data_root,
        create=False,
    )
    candidates: list[Loop9FullHistoryExclusionAuthority] = []
    with _store_lock(store, create=False):
        head = _ExclusionChildIndexHead.from_payload(
            _load_json(
                store / "head.json",
                label="exclusion authority head",
            )
        )
        head_bindings = (
            head.expected_current_build_sha256,
            head.expected_settlement_contract_sha256,
            head.expected_daily_contract_sha256,
            head.expected_settlement_selection_sha256,
            head.expected_daily_selection_sha256,
        )
        if head_bindings != expected_bindings:
            raise Loop9DatasetIsolationError(
                "exclusion child index does not match the current build or "
                "contract authority"
            )
        try:
            authority_paths = tuple(sorted(authorities_root.iterdir()))
        except OSError as exc:
            raise Loop9DatasetIsolationError(
                "persisted full-history exclusion authority is unavailable"
            ) from exc
        if not authority_paths:
            raise Loop9DatasetIsolationError(
                "persisted full-history exclusion authority is missing"
            )
        for path in authority_paths:
            if (
                path.is_symlink()
                or not path.is_file()
                or path.suffix != ".json"
                or _SHA256.fullmatch(path.stem) is None
            ):
                raise Loop9DatasetIsolationError(
                    "persisted full-history exclusion authority store is "
                    "unsafe"
                )
            authority = parse_loop9_full_history_exclusion_authority(
                _load_json(
                    path,
                    label="persisted full-history exclusion authority",
                )
            )
            if authority.canonical_sha256 != path.stem:
                raise Loop9DatasetIsolationError(
                    "persisted full-history exclusion authority path "
                    "integrity is invalid"
                )
            if (
                authority.child_index_head_sha256 == head.head_sha256
                and authority.source_boundary.canonical_sha256
                == head.source_boundary_sha256
                and authority.source_inventory_high_watermark
                == head.source_inventory_high_watermark
                and authority.identity_context_sha256
                == head.identity_context_sha256
                and (
                    authority.expected_current_build_sha256,
                    authority.expected_settlement_contract_sha256,
                    authority.expected_daily_contract_sha256,
                    authority.expected_settlement_selection_sha256,
                    authority.expected_daily_selection_sha256,
                )
                == expected_bindings
            ):
                candidates.append(authority)
        if len(candidates) != 1:
            raise Loop9DatasetIsolationError(
                "persisted full-history exclusion authority for the current "
                "chain is missing or ambiguous"
            )
        persisted = candidates[0]

    replayed = load_current_loop9_full_history_exclusion_authority(
        data_root=data_root,
        source_boundary=persisted.source_boundary,
        expected_current_build_sha256=expected_current_build_sha256,
        expected_settlement_contract_sha256=(
            expected_settlement_contract_sha256
        ),
        expected_daily_contract_sha256=expected_daily_contract_sha256,
        expected_settlement_selection_sha256=(
            expected_settlement_selection_sha256
        ),
        expected_daily_selection_sha256=expected_daily_selection_sha256,
    )
    if (
        replayed.canonical_sha256 != persisted.canonical_sha256
        or replayed.to_payload() != persisted.to_payload()
    ):
        raise Loop9DatasetIsolationError(
            "persisted full-history exclusion authority does not match the "
            "replayed current chain"
        )
    return replayed


def _verified_snapshot_from_authority(
    authority: Loop9FullHistoryExclusionAuthority,
) -> Loop9VerifiedExclusionSnapshot:
    children = authority.child_inventories
    fingerprint_by_image = {
        fingerprint.content_sha256: fingerprint
        for child in children
        for fingerprint in child.perceptual_fingerprints
    }
    return Loop9VerifiedExclusionSnapshot(
        authority_sha256=authority.canonical_sha256,
        child_index_head_sha256=authority.child_index_head_sha256,
        source_boundary_sha256=(
            authority.source_boundary.canonical_sha256
        ),
        source_inventory_high_watermark=(
            authority.source_inventory_high_watermark
        ),
        identity_context_sha256=authority.identity_context_sha256,
        expected_current_build_sha256=(
            authority.expected_current_build_sha256
        ),
        expected_settlement_contract_sha256=(
            authority.expected_settlement_contract_sha256
        ),
        expected_daily_contract_sha256=(
            authority.expected_daily_contract_sha256
        ),
        expected_settlement_selection_sha256=(
            authority.expected_settlement_selection_sha256
        ),
        expected_daily_selection_sha256=(
            authority.expected_daily_selection_sha256
        ),
        development_exclusions=authority.development_exclusions,
        legacy_loop7_exclusions=authority.legacy_loop7_exclusions,
        excluded_platform_identity_sha256s=tuple(
            sorted(
                {
                    value
                    for child in children
                    for value in child.platform_identity_sha256s
                }
            )
        ),
        excluded_image_sha256s=tuple(
            sorted(
                {
                    value
                    for child in children
                    for value in child.image_sha256s
                }
            )
        ),
        excluded_scope_exclusion_tokens=tuple(
            sorted(
                {
                    value
                    for child in children
                    for value in child.scope_exclusion_tokens
                }
            )
        ),
        excluded_perceptual_fingerprints=tuple(
            fingerprint_by_image[key]
            for key in sorted(fingerprint_by_image)
        ),
    )


def load_verified_loop9_exclusion_snapshot(
    *,
    data_root: Path,
    source_boundary: Loop9ExclusionSourceBoundary,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> Loop9VerifiedExclusionSnapshot:
    """Load the only pre-selection exclusion view accepted by Loop 9."""

    authority = load_current_loop9_full_history_exclusion_authority(
        data_root=data_root,
        source_boundary=source_boundary,
        expected_current_build_sha256=(
            expected_current_build_sha256
        ),
        expected_settlement_contract_sha256=(
            expected_settlement_contract_sha256
        ),
        expected_daily_contract_sha256=(
            expected_daily_contract_sha256
        ),
        expected_settlement_selection_sha256=(
            expected_settlement_selection_sha256
        ),
        expected_daily_selection_sha256=(
            expected_daily_selection_sha256
        ),
    )
    return _verified_snapshot_from_authority(authority)


def load_verified_loop9_exclusion_snapshot_from_persisted_authority(
    *,
    data_root: Path,
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> Loop9VerifiedExclusionSnapshot:
    """Load the current exclusion view without rebuilding Loop 7 state."""

    authority = (
        load_current_persisted_loop9_full_history_exclusion_authority(
            data_root=data_root,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
        )
    )
    return _verified_snapshot_from_authority(authority)


def persist_loop9_full_history_exclusion_authority(
    *,
    data_root: Path,
    authority: Loop9FullHistoryExclusionAuthority,
) -> Path:
    authority.verify_integrity()
    _, _, _, authorities_root = _prepare_store(
        data_root,
        create=False,
    )
    output = authorities_root / f"{authority.canonical_sha256}.json"
    _write_once(output, authority.to_payload())
    return output


def load_stored_loop9_full_history_exclusion_authority(
    *,
    data_root: Path,
    authority_sha256: str,
) -> Loop9FullHistoryExclusionAuthority:
    expected = _sha256(
        authority_sha256,
        label="full-history exclusion authority SHA-256",
    )
    _, _, _, authorities_root = _prepare_store(
        data_root,
        create=False,
    )
    authority = parse_loop9_full_history_exclusion_authority(
        _load_json(
            authorities_root / f"{expected}.json",
            label="stored full-history exclusion authority",
        )
    )
    if authority.canonical_sha256 != expected:
        raise Loop9DatasetIsolationError(
            "stored full-history exclusion authority integrity is invalid"
        )
    return authority
