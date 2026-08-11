from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from dahe.adapters.chengfeng.daily_contract_freezer import (
    DailyContractFreezeResult,
)
from dahe.adapters.chengfeng.daily_manifest import DailyReadContractManifest

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SELECTION_NAME = "active-candidate.json"
_ROLLOVER_KIND = "loop9_daily_read_contract_selection_rollover"
_ROLLOVER_REASON = "minimal_required_projection_v1"
_REQUIRED_RESPONSE_TYPES = {
    "$.data.list[].carNumber": frozenset({"null", "string"}),
    "$.data.list[].id": frozenset({"integer", "string"}),
    "$.data.list[].loadPunchDate": frozenset({"null", "string"}),
    "$.data.list[].sn": frozenset({"string"}),
    "$.data.total": frozenset({"integer"}),
}


class DailyContractSelectionError(RuntimeError):
    """Raised when the selected daily contract cannot be reverified."""


@dataclass(frozen=True, slots=True)
class SelectedDailyReadContract:
    manifest: DailyReadContractManifest
    contract_file_sha256: str
    freeze_evidence_sha256: str
    selection_sha256: str
    selection_path: Path


@dataclass(frozen=True, slots=True)
class DailyContractRolloverResult:
    selected: SelectedDailyReadContract
    evidence_path: Path
    evidence_sha256: str
    idempotent_replay: bool


def select_daily_read_contract(
    *,
    data_root: Path,
    frozen: DailyContractFreezeResult,
) -> SelectedDailyReadContract:
    root = _root(data_root)
    manifest = _load_frozen(
        root=root,
        contract_canonical_sha256=frozen.contract_canonical_sha256,
        contract_file_sha256=frozen.contract_file_sha256,
        freeze_evidence_sha256=frozen.freeze_evidence_sha256,
    )
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_daily_read_contract_selection",
        "contract_canonical_sha256": manifest.canonical_sha256,
        "contract_file_sha256": frozen.contract_file_sha256,
        "freeze_evidence_sha256": frozen.freeze_evidence_sha256,
        "source_discovery_sha256": manifest.source_discovery_sha256,
    }
    selection_sha256 = hashlib.sha256(_canonical(body)).hexdigest()
    document = {**body, "canonical_sha256": selection_sha256}
    path = root / _SELECTION_NAME
    _write_idempotent(path, _canonical(document) + b"\n")
    return load_selected_daily_read_contract(data_root)


def load_selected_daily_read_contract(
    data_root: Path,
) -> SelectedDailyReadContract:
    root = _root(data_root)
    path = root / _SELECTION_NAME
    if (
        not path.is_file()
        or path.is_symlink()
        or path.resolve().parent != root
    ):
        raise DailyContractSelectionError(
            "daily contract selection is unavailable"
        )
    try:
        document = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise DailyContractSelectionError(
            "daily contract selection is unreadable"
        ) from exc
    expected = {
        "schema_version",
        "kind",
        "contract_canonical_sha256",
        "contract_file_sha256",
        "freeze_evidence_sha256",
        "source_discovery_sha256",
        "canonical_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise DailyContractSelectionError(
            "daily contract selection schema is invalid"
        )
    declared = document["canonical_sha256"]
    body = {
        key: value
        for key, value in document.items()
        if key != "canonical_sha256"
    }
    if (
        document["schema_version"] != 1
        or document["kind"] != "loop9_daily_read_contract_selection"
        or not isinstance(declared, str)
        or _SHA256.fullmatch(declared) is None
        or hashlib.sha256(_canonical(body)).hexdigest() != declared
    ):
        raise DailyContractSelectionError(
            "daily contract selection integrity failed"
        )
    manifest = _load_frozen(
        root=root,
        contract_canonical_sha256=_sha(
            document["contract_canonical_sha256"]
        ),
        contract_file_sha256=_sha(document["contract_file_sha256"]),
        freeze_evidence_sha256=_sha(document["freeze_evidence_sha256"]),
    )
    if document["source_discovery_sha256"] != manifest.source_discovery_sha256:
        raise DailyContractSelectionError(
            "daily contract discovery identity changed"
        )
    return SelectedDailyReadContract(
        manifest=manifest,
        contract_file_sha256=str(document["contract_file_sha256"]),
        freeze_evidence_sha256=str(document["freeze_evidence_sha256"]),
        selection_sha256=declared,
        selection_path=path,
    )


def rollover_daily_read_contract(
    *,
    data_root: Path,
    frozen: DailyContractFreezeResult,
) -> DailyContractRolloverResult:
    """Replace an expanded daily contract with the same minimal projection."""

    root = _root(data_root)
    current = load_selected_daily_read_contract(data_root)
    replacement = _load_frozen(
        root=root,
        contract_canonical_sha256=frozen.contract_canonical_sha256,
        contract_file_sha256=frozen.contract_file_sha256,
        freeze_evidence_sha256=frozen.freeze_evidence_sha256,
    )
    if current.manifest.canonical_sha256 == replacement.canonical_sha256:
        return _load_completed_rollover(
            data_root=data_root,
            selected=current,
        )
    _validate_minimal_rollover(
        current=current.manifest,
        replacement=replacement,
    )
    replacement_body = _selection_body(
        manifest=replacement,
        contract_file_sha256=frozen.contract_file_sha256,
        freeze_evidence_sha256=frozen.freeze_evidence_sha256,
    )
    replacement_selection_sha256 = hashlib.sha256(
        _canonical(replacement_body)
    ).hexdigest()
    replacement_document = {
        **replacement_body,
        "canonical_sha256": replacement_selection_sha256,
    }
    current_bytes = current.selection_path.read_bytes()
    history_root = root / "selection-history"
    history_root.mkdir(exist_ok=True)
    _require_regular_directory(history_root, label="selection history")
    _write_idempotent(
        history_root / f"{current.selection_sha256}.json",
        current_bytes,
    )
    evidence_body: dict[str, object] = {
        "schema_version": 1,
        "kind": _ROLLOVER_KIND,
        "reason": _ROLLOVER_REASON,
        "source_discovery_sha256": replacement.source_discovery_sha256,
        "previous_selection_sha256": current.selection_sha256,
        "previous_contract_canonical_sha256": (
            current.manifest.canonical_sha256
        ),
        "replacement_selection_sha256": (
            replacement_selection_sha256
        ),
        "replacement_contract_canonical_sha256": (
            replacement.canonical_sha256
        ),
        "replacement_contract_file_sha256": (
            frozen.contract_file_sha256
        ),
        "replacement_freeze_evidence_sha256": (
            frozen.freeze_evidence_sha256
        ),
        "request_contract_unchanged": True,
        "response_contract_change": "required_projection_only",
        "platform_write_authorization": False,
    }
    evidence_sha256 = hashlib.sha256(
        _canonical(evidence_body)
    ).hexdigest()
    evidence_root = root.parent / (
        "daily-platform-read-contract-rollovers"
    )
    evidence_root.mkdir(exist_ok=True)
    _require_regular_directory(evidence_root, label="rollover evidence")
    evidence_path = evidence_root / f"{evidence_sha256}.json"
    _write_idempotent(
        evidence_path,
        _canonical(
            {
                **evidence_body,
                "canonical_sha256": evidence_sha256,
            }
        )
        + b"\n",
    )
    _replace_exact(
        current.selection_path,
        expected=current_bytes,
        replacement=_canonical(replacement_document) + b"\n",
    )
    selected = load_selected_daily_read_contract(data_root)
    if selected.selection_sha256 != replacement_selection_sha256:
        raise DailyContractSelectionError(
            "daily contract rollover did not become active"
        )
    return DailyContractRolloverResult(
        selected=selected,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
        idempotent_replay=False,
    )


def _selection_body(
    *,
    manifest: DailyReadContractManifest,
    contract_file_sha256: str,
    freeze_evidence_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "loop9_daily_read_contract_selection",
        "contract_canonical_sha256": manifest.canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "freeze_evidence_sha256": freeze_evidence_sha256,
        "source_discovery_sha256": manifest.source_discovery_sha256,
    }


def _validate_minimal_rollover(
    *,
    current: DailyReadContractManifest,
    replacement: DailyReadContractManifest,
) -> None:
    if (
        current.source_discovery_sha256
        != replacement.source_discovery_sha256
        or current.source_observation_count
        != replacement.source_observation_count
        or current.request_fields != replacement.request_fields
    ):
        raise DailyContractSelectionError(
            "daily contract rollover changed its source or request contract"
        )
    replacement_fields = {
        field.path: frozenset(field.types)
        for field in replacement.response_fields
    }
    if replacement_fields != _REQUIRED_RESPONSE_TYPES:
        raise DailyContractSelectionError(
            "daily contract rollover is not the approved minimal projection"
        )
    current_fields = {
        field.path: frozenset(field.types)
        for field in current.response_fields
    }
    if any(
        path not in current_fields
        or not current_fields[path].issubset(allowed_types)
        for path, allowed_types in _REQUIRED_RESPONSE_TYPES.items()
    ):
        raise DailyContractSelectionError(
            "daily contract rollover changed a required response field"
        )


def _load_completed_rollover(
    *,
    data_root: Path,
    selected: SelectedDailyReadContract,
) -> DailyContractRolloverResult:
    root = _root(data_root)
    evidence_root = root.parent / (
        "daily-platform-read-contract-rollovers"
    )
    if (
        not evidence_root.is_dir()
        or evidence_root.is_symlink()
    ):
        raise DailyContractSelectionError(
            "daily contract is already selected without rollover evidence"
        )
    matches: list[tuple[Path, dict[str, object]]] = []
    for path in evidence_root.glob("*.json"):
        if path.is_symlink() or not path.is_file():
            continue
        document = _load_rollover_document(path)
        if (
            document["replacement_selection_sha256"]
            == selected.selection_sha256
            and document["replacement_contract_canonical_sha256"]
            == selected.manifest.canonical_sha256
        ):
            matches.append((path, document))
    if len(matches) != 1:
        raise DailyContractSelectionError(
            "daily contract rollover evidence is ambiguous"
        )
    path, document = matches[0]
    return DailyContractRolloverResult(
        selected=selected,
        evidence_path=path,
        evidence_sha256=str(document["canonical_sha256"]),
        idempotent_replay=True,
    )


def _load_rollover_document(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise DailyContractSelectionError(
            "daily contract rollover evidence is unreadable"
        ) from exc
    expected = {
        "schema_version",
        "kind",
        "reason",
        "source_discovery_sha256",
        "previous_selection_sha256",
        "previous_contract_canonical_sha256",
        "replacement_selection_sha256",
        "replacement_contract_canonical_sha256",
        "replacement_contract_file_sha256",
        "replacement_freeze_evidence_sha256",
        "request_contract_unchanged",
        "response_contract_change",
        "platform_write_authorization",
        "canonical_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise DailyContractSelectionError(
            "daily contract rollover evidence schema is invalid"
        )
    body = {
        key: value
        for key, value in document.items()
        if key != "canonical_sha256"
    }
    declared = document["canonical_sha256"]
    if (
        document["schema_version"] != 1
        or document["kind"] != _ROLLOVER_KIND
        or document["reason"] != _ROLLOVER_REASON
        or document["request_contract_unchanged"] is not True
        or document["response_contract_change"]
        != "required_projection_only"
        or document["platform_write_authorization"] is not False
        or not isinstance(declared, str)
        or _SHA256.fullmatch(declared) is None
        or path.name != f"{declared}.json"
        or hashlib.sha256(_canonical(body)).hexdigest() != declared
    ):
        raise DailyContractSelectionError(
            "daily contract rollover evidence integrity failed"
        )
    return document


def _load_frozen(
    *,
    root: Path,
    contract_canonical_sha256: str,
    contract_file_sha256: str,
    freeze_evidence_sha256: str,
) -> DailyReadContractManifest:
    contract_path = root / f"{contract_canonical_sha256}.json"
    if (
        not contract_path.is_file()
        or contract_path.is_symlink()
        or contract_path.resolve().parent != root
    ):
        raise DailyContractSelectionError("daily contract file is unavailable")
    raw = contract_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != contract_file_sha256:
        raise DailyContractSelectionError("daily contract file changed")
    try:
        manifest = DailyReadContractManifest.model_validate_json(
            raw,
            strict=True,
        )
    except ValidationError as exc:
        raise DailyContractSelectionError(
            "daily contract schema is invalid"
        ) from exc
    if manifest.canonical_sha256 != contract_canonical_sha256:
        raise DailyContractSelectionError(
            "daily contract canonical identity changed"
        )
    evidence_root = root.parent / "daily-platform-read-contract-evidence"
    evidence_path = evidence_root / f"{freeze_evidence_sha256}.json"
    if (
        not evidence_path.is_file()
        or evidence_path.is_symlink()
        or evidence_path.resolve().parent != evidence_root.resolve()
    ):
        raise DailyContractSelectionError(
            "daily contract freeze evidence is unavailable"
        )
    try:
        evidence = json.loads(evidence_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise DailyContractSelectionError(
            "daily contract freeze evidence is unreadable"
        ) from exc
    if not isinstance(evidence, dict):
        raise DailyContractSelectionError(
            "daily contract freeze evidence schema is invalid"
        )
    evidence_body = {
        key: value
        for key, value in evidence.items()
        if key != "canonical_sha256"
    }
    if (
        evidence.get("canonical_sha256") != freeze_evidence_sha256
        or hashlib.sha256(_canonical(evidence_body)).hexdigest()
        != freeze_evidence_sha256
        or evidence.get("kind") != "loop9_daily_read_contract_freeze"
        or evidence.get("classification") != "development_only"
        or evidence.get("contract_canonical_sha256")
        != contract_canonical_sha256
        or evidence.get("contract_file_sha256") != contract_file_sha256
        or evidence.get("source_discovery_sha256")
        != manifest.source_discovery_sha256
        or evidence.get("platform_write_authorization") is not False
        or evidence.get("request_values_retained") is not False
        or evidence.get("response_values_retained") is not False
        or evidence.get("credential_material_retained") is not False
    ):
        raise DailyContractSelectionError(
            "daily contract freeze evidence integrity failed"
        )
    return manifest


def _root(data_root: Path) -> Path:
    if not data_root.is_absolute() or data_root.is_symlink():
        raise DailyContractSelectionError(
            "daily contract data root must be absolute"
        )
    data = data_root.resolve()
    root = data / "daily-platform-read-contract"
    root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve()
    if data not in resolved.parents or root.is_symlink() or not root.is_dir():
        raise DailyContractSelectionError(
            "daily contract selection directory is unsafe"
        )
    return resolved


def _write_idempotent(path: Path, content: bytes) -> None:
    if path.exists():
        if path.is_symlink() or path.read_bytes() != content:
            raise DailyContractSelectionError(
                "a different daily contract is already selected"
            )
        return
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise DailyContractSelectionError(
            "daily contract selection could not be written"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _replace_exact(
    path: Path,
    *,
    expected: bytes,
    replacement: bytes,
) -> None:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.read_bytes() != expected
    ):
        raise DailyContractSelectionError(
            "daily contract selection changed during rollover"
        )
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(replacement)
            handle.flush()
            os.fsync(handle.fileno())
        if path.read_bytes() != expected:
            raise DailyContractSelectionError(
                "daily contract selection changed during rollover"
            )
        os.replace(temporary, path)
    except OSError as exc:
        raise DailyContractSelectionError(
            "daily contract selection rollover could not be written"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _require_regular_directory(path: Path, *, label: str) -> None:
    if not path.is_dir() or path.is_symlink():
        raise DailyContractSelectionError(f"{label} directory is unsafe")


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DailyContractSelectionError("daily contract SHA-256 is invalid")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
