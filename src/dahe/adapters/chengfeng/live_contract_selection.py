from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from dahe.adapters.chengfeng.live_manifest import (
    LiveContractError,
    LiveReadContractManifest,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SELECTION_NAME = "active-candidate.json"


class LiveContractSelectionError(RuntimeError):
    """Raised when an active candidate cannot be selected or reverified."""


@dataclass(frozen=True, slots=True)
class SelectedLiveReadContract:
    manifest: LiveReadContractManifest
    contract_file_sha256: str
    freeze_evidence_sha256: str
    selection_sha256: str
    selection_path: Path


def select_live_read_contract(
    *,
    data_root: Path,
    contract_canonical_sha256: str,
    contract_file_sha256: str,
    freeze_evidence_sha256: str,
) -> SelectedLiveReadContract:
    root = _contract_root(data_root)
    _require_sha256(contract_canonical_sha256)
    _require_sha256(contract_file_sha256)
    _require_sha256(freeze_evidence_sha256)
    selection_path = root / _SELECTION_NAME
    existing_selection: SelectedLiveReadContract | None = None
    existing_content: bytes | None = None
    if selection_path.exists():
        selected = load_selected_live_read_contract(data_root)
        if selected.manifest.canonical_sha256 == contract_canonical_sha256:
            if (
                selected.contract_file_sha256 != contract_file_sha256
                or selected.freeze_evidence_sha256
                != freeze_evidence_sha256
            ):
                raise LiveContractSelectionError(
                    "active selection belongs to a different candidate"
                )
            return selected
        else:
            existing_selection = selected
            existing_content = selection_path.read_bytes()
    manifest = _load_candidate(
        root=root,
        contract_canonical_sha256=contract_canonical_sha256,
        contract_file_sha256=contract_file_sha256,
        freeze_evidence_sha256=freeze_evidence_sha256,
    )
    if existing_selection is not None and not _rolls_over_selected(
        root=root,
        candidate_contract_sha256=contract_canonical_sha256,
        selected=existing_selection,
    ):
        raise LiveContractSelectionError(
            "active selection belongs to a different candidate"
        )
    body = _selection_body(
        manifest=manifest,
        contract_file_sha256=contract_file_sha256,
        freeze_evidence_sha256=freeze_evidence_sha256,
    )
    selection_sha256 = hashlib.sha256(_canonical(body)).hexdigest()
    document = {**body, "canonical_sha256": selection_sha256}
    selection_content = _canonical(document) + b"\n"
    if existing_content is None:
        _write_once(selection_path, selection_content)
    else:
        _replace_exact(
            selection_path,
            expected=existing_content,
            content=selection_content,
        )
    return SelectedLiveReadContract(
        manifest=manifest,
        contract_file_sha256=contract_file_sha256,
        freeze_evidence_sha256=freeze_evidence_sha256,
        selection_sha256=selection_sha256,
        selection_path=selection_path,
    )


def _rolls_over_selected(
    *,
    root: Path,
    candidate_contract_sha256: str,
    selected: SelectedLiveReadContract,
) -> bool:
    freeze_path = root / f"{candidate_contract_sha256}.freeze-evidence.json"
    try:
        document = json.loads(freeze_path.read_bytes())
    except (OSError, json.JSONDecodeError):
        return False
    return bool(
        isinstance(document, dict)
        and document.get("kind")
        in {
            "loop9_live_read_contract_request_rollover",
            "loop9_live_read_contract_detail_encoding_rollover",
        }
        and document.get("parent_contract_canonical_sha256")
        == selected.manifest.canonical_sha256
        and document.get("parent_contract_file_sha256")
        == selected.contract_file_sha256
        and document.get("parent_freeze_evidence_sha256")
        == selected.freeze_evidence_sha256
    )


def load_selected_live_read_contract(data_root: Path) -> SelectedLiveReadContract:
    root = _contract_root(data_root)
    selection_path = root / _SELECTION_NAME
    if (
        not selection_path.is_file()
        or selection_path.is_symlink()
        or selection_path.resolve().parent != root
    ):
        raise LiveContractSelectionError("active candidate selection is unavailable")
    try:
        document = json.loads(selection_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContractSelectionError("active candidate selection is unreadable") from exc
    expected_fields = {
        "schema_version",
        "kind",
        "contract_canonical_sha256",
        "contract_file_sha256",
        "freeze_evidence_sha256",
        "source_discovery_sha256",
        "canonical_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise LiveContractSelectionError("active candidate selection schema is invalid")
    declared = document["canonical_sha256"]
    body = {key: value for key, value in document.items() if key != "canonical_sha256"}
    if (
        document["schema_version"] != 1
        or document["kind"] != "loop9_live_read_contract_selection"
        or not isinstance(declared, str)
        or _SHA256.fullmatch(declared) is None
        or hashlib.sha256(_canonical(body)).hexdigest() != declared
    ):
        raise LiveContractSelectionError("active candidate selection integrity failed")
    canonical_sha256 = _string_sha(document["contract_canonical_sha256"])
    contract_file_sha256 = _string_sha(document["contract_file_sha256"])
    freeze_evidence_sha256 = _string_sha(document["freeze_evidence_sha256"])
    manifest = _load_candidate(
        root=root,
        contract_canonical_sha256=canonical_sha256,
        contract_file_sha256=contract_file_sha256,
        freeze_evidence_sha256=freeze_evidence_sha256,
    )
    if document["source_discovery_sha256"] != manifest.source_discovery_sha256:
        raise LiveContractSelectionError("active candidate source identity changed")
    return SelectedLiveReadContract(
        manifest=manifest,
        contract_file_sha256=contract_file_sha256,
        freeze_evidence_sha256=freeze_evidence_sha256,
        selection_sha256=declared,
        selection_path=selection_path,
    )


def _load_candidate(
    *,
    root: Path,
    contract_canonical_sha256: str,
    contract_file_sha256: str,
    freeze_evidence_sha256: str,
) -> LiveReadContractManifest:
    contract_path = root / f"{contract_canonical_sha256}.json"
    try:
        manifest = LiveReadContractManifest.load(
            contract_path,
            allowed_root=root,
            expected_sha256=contract_file_sha256,
        )
    except LiveContractError as exc:
        raise LiveContractSelectionError("candidate contract verification failed") from exc
    if manifest.canonical_sha256 != contract_canonical_sha256:
        raise LiveContractSelectionError("candidate canonical identity changed")
    freeze_path = root / f"{contract_canonical_sha256}.freeze-evidence.json"
    if (
        not freeze_path.is_file()
        or freeze_path.is_symlink()
        or freeze_path.resolve().parent != root
    ):
        raise LiveContractSelectionError("candidate freeze evidence is unavailable")
    try:
        document = json.loads(freeze_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContractSelectionError("candidate freeze evidence is unreadable") from exc
    if not isinstance(document, dict):
        raise LiveContractSelectionError("candidate freeze evidence schema is invalid")
    declared = document.get("canonical_sha256")
    body = {key: value for key, value in document.items() if key != "canonical_sha256"}
    freeze_kind = document.get("kind")
    if (
        declared != freeze_evidence_sha256
        or hashlib.sha256(_canonical(body)).hexdigest() != freeze_evidence_sha256
        or freeze_kind
        not in {
            "loop9_live_read_contract_freeze",
            "loop9_live_read_contract_request_rollover",
            "loop9_live_read_contract_detail_encoding_rollover",
        }
        or document.get("classification") != "development_only"
        or document.get("contract_canonical_sha256") != contract_canonical_sha256
        or document.get("contract_file_sha256") != contract_file_sha256
        or document.get("source_discovery_sha256")
        != manifest.source_discovery_sha256
        or document.get("platform_write_authorization") is not False
        or document.get("request_values_retained") is not False
        or document.get("response_values_retained") is not False
        or document.get("credential_material_retained") is not False
    ):
        raise LiveContractSelectionError("candidate freeze evidence integrity failed")
    if freeze_kind == "loop9_live_read_contract_request_rollover":
        source_sha256 = manifest.source_discovery_sha256
        source_path = (
            root.parent
            / "platform-contract-discovery"
            / f"{source_sha256}.request-rollover.json"
        )
        if (
            not source_path.is_file()
            or source_path.is_symlink()
            or source_path.resolve().parent
            != (root.parent / "platform-contract-discovery").resolve()
        ):
            raise LiveContractSelectionError(
                "candidate rollover source is unavailable"
            )
        try:
            source_document = json.loads(source_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise LiveContractSelectionError(
                "candidate rollover source is unreadable"
            ) from exc
        if not isinstance(source_document, dict):
            raise LiveContractSelectionError(
                "candidate rollover source schema is invalid"
            )
        source_body = {
            key: value
            for key, value in source_document.items()
            if key != "canonical_sha256"
        }
        if (
            source_document.get("canonical_sha256") != source_sha256
            or hashlib.sha256(_canonical(source_body)).hexdigest()
            != source_sha256
            or source_document.get("kind")
            != "loop9_live_read_contract_request_rollover_source"
            or source_document.get("classification")
            != "development_only"
            or source_document.get("requires_live_validation") is not True
            or source_document.get("response_contract_inherited") is not True
            or source_document.get("platform_write_authorization") is not False
            or source_document.get("request_values_retained") is not False
            or source_document.get("response_values_retained") is not False
            or source_document.get("credential_material_retained") is not False
            or document.get("requires_live_validation") is not True
            or document.get("response_contract_inherited") is not True
            or document.get("parent_contract_canonical_sha256")
            != source_document.get("parent_contract_canonical_sha256")
            or document.get("parent_contract_file_sha256")
            != source_document.get("parent_contract_file_sha256")
            or document.get("parent_freeze_evidence_sha256")
            != source_document.get("parent_freeze_evidence_sha256")
            or document.get("request_structure_discovery_sha256")
            != source_document.get("request_structure_discovery_sha256")
        ):
            raise LiveContractSelectionError(
                "candidate rollover source integrity failed"
            )
    elif (
        freeze_kind
        == "loop9_live_read_contract_detail_encoding_rollover"
    ):
        source_sha256 = manifest.source_discovery_sha256
        source_path = (
            root.parent
            / "platform-contract-discovery"
            / f"{source_sha256}.detail-encoding-rollover.json"
        )
        if (
            not source_path.is_file()
            or source_path.is_symlink()
            or source_path.resolve().parent
            != (root.parent / "platform-contract-discovery").resolve()
        ):
            raise LiveContractSelectionError(
                "detail encoding rollover source is unavailable"
            )
        try:
            source_document = json.loads(source_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise LiveContractSelectionError(
                "detail encoding rollover source is unreadable"
            ) from exc
        if not isinstance(source_document, dict):
            raise LiveContractSelectionError(
                "detail encoding rollover source schema is invalid"
            )
        source_body = {
            key: value
            for key, value in source_document.items()
            if key != "canonical_sha256"
        }
        encoding_change = {
            "operation": "get_waybill_detail",
            "from": "json",
            "to": "form",
        }
        if (
            source_document.get("canonical_sha256") != source_sha256
            or hashlib.sha256(_canonical(source_body)).hexdigest()
            != source_sha256
            or source_document.get("kind")
            != (
                "loop9_live_read_contract_"
                "detail_encoding_rollover_source"
            )
            or source_document.get("classification")
            != "development_only"
            or source_document.get("encoding_change")
            != encoding_change
            or source_document.get(
                "request_and_response_fields_inherited"
            )
            is not True
            or source_document.get("requires_live_validation") is not True
            or source_document.get("platform_write_authorization")
            is not False
            or source_document.get("request_values_retained") is not False
            or source_document.get("response_values_retained") is not False
            or source_document.get("credential_material_retained")
            is not False
            or document.get("encoding_change") != encoding_change
            or document.get(
                "request_and_response_fields_inherited"
            )
            is not True
            or document.get("requires_live_validation") is not True
            or document.get("parent_contract_canonical_sha256")
            != source_document.get("parent_contract_canonical_sha256")
            or document.get("parent_contract_file_sha256")
            != source_document.get("parent_contract_file_sha256")
            or document.get("parent_freeze_evidence_sha256")
            != source_document.get("parent_freeze_evidence_sha256")
        ):
            raise LiveContractSelectionError(
                "detail encoding rollover source integrity failed"
            )
    return manifest


def _selection_body(
    *,
    manifest: LiveReadContractManifest,
    contract_file_sha256: str,
    freeze_evidence_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_selection",
        "contract_canonical_sha256": manifest.canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "freeze_evidence_sha256": freeze_evidence_sha256,
        "source_discovery_sha256": manifest.source_discovery_sha256,
    }


def _contract_root(data_root: Path) -> Path:
    if not data_root.is_absolute() or data_root.is_symlink():
        raise LiveContractSelectionError("data root must be an absolute normal directory")
    resolved_data_root = data_root.resolve()
    root = resolved_data_root / "platform-read-contract"
    root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve()
    if (
        resolved_data_root not in resolved.parents
        or root.is_symlink()
        or not root.is_dir()
    ):
        raise LiveContractSelectionError("contract directory is unsafe")
    return resolved


def _write_once(path: Path, content: bytes) -> None:
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise LiveContractSelectionError("active selection could not be written") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _replace_exact(
    path: Path,
    *,
    expected: bytes,
    content: bytes,
) -> None:
    if path.is_symlink() or path.read_bytes() != expected:
        raise LiveContractSelectionError(
            "active candidate changed during rollover"
        )
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or path.read_bytes() != expected:
            raise LiveContractSelectionError(
                "active candidate changed during rollover"
            )
        os.replace(temporary, path)
    except OSError as exc:
        raise LiveContractSelectionError(
            "active candidate rollover could not be saved"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _require_sha256(value: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise LiveContractSelectionError("candidate SHA-256 is invalid")


def _string_sha(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise LiveContractSelectionError("active candidate SHA-256 is invalid")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
