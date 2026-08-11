from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import stat
import sys
from ctypes import wintypes
from pathlib import Path
from uuid import uuid4

from dahe.adapters.chengfeng.daily_contract_selection import (
    DailyContractSelectionError,
    load_selected_daily_read_contract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    LiveContractSelectionError,
    load_selected_live_read_contract,
)
from dahe.verification.loop9_build import current_loop9_build_sha256

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ERROR_FILE_NOT_FOUND = 2
_SYNCHRONIZE = 0x00100000


class OperationalContractInstallError(RuntimeError):
    """Raised when operational contracts cannot be installed safely."""


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Install verified Chengfeng read contracts into an isolated "
            "operational data root without connecting to Chengfeng."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--source-root", type=_absolute_path, required=True)
    parser.add_argument("--target-root", type=_absolute_path, required=True)
    parser.add_argument("--output", type=_absolute_path, required=True)
    return parser


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return bool(
        path.is_symlink()
        or getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _require_safe_root(path: Path, *, must_exist: bool, label: str) -> Path:
    if not path.is_absolute():
        raise OperationalContractInstallError(f"{label} must be absolute")
    if path.exists():
        if not path.is_dir() or _is_reparse_point(path):
            raise OperationalContractInstallError(
                f"{label} is a link or reparse point"
            )
    elif must_exist:
        raise OperationalContractInstallError(f"{label} is unavailable")
    else:
        path.mkdir(parents=True, exist_ok=False)
    resolved = path.resolve(strict=True)
    if _is_reparse_point(resolved):
        raise OperationalContractInstallError(
            f"{label} is a link or reparse point"
        )
    return resolved


def _require_safe_file(path: Path, *, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise OperationalContractInstallError(
            "contract dependency is unavailable"
        ) from exc
    current = resolved
    while current != root:
        if _is_reparse_point(current):
            raise OperationalContractInstallError(
                "contract dependency uses a reparse point"
            )
        current = current.parent
    if not resolved.is_file() or _is_reparse_point(root):
        raise OperationalContractInstallError(
            "contract dependency is not a regular file"
        )
    return resolved


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _document(path: Path, *, root: Path) -> dict[str, object]:
    safe = _require_safe_file(path, root=root)
    try:
        value = json.loads(safe.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationalContractInstallError(
            "contract dependency is unreadable"
        ) from exc
    if not isinstance(value, dict):
        raise OperationalContractInstallError(
            "contract dependency schema is invalid"
        )
    return value


def _settlement_dependencies(
    source_root: Path,
) -> tuple[Path, ...]:
    selected = load_selected_live_read_contract(source_root)
    contract_root = source_root / "platform-read-contract"
    canonical = selected.manifest.canonical_sha256
    freeze_path = contract_root / f"{canonical}.freeze-evidence.json"
    freeze = _document(freeze_path, root=source_root)
    dependencies = [
        contract_root / f"{canonical}.json",
        freeze_path,
    ]
    freeze_kind = freeze.get("kind")
    source_sha256 = selected.manifest.source_discovery_sha256
    if freeze_kind == "loop9_live_read_contract_request_rollover":
        dependencies.append(
            source_root
            / "platform-contract-discovery"
            / f"{source_sha256}.request-rollover.json"
        )
    elif freeze_kind == "loop9_live_read_contract_detail_encoding_rollover":
        dependencies.append(
            source_root
            / "platform-contract-discovery"
            / f"{source_sha256}.detail-encoding-rollover.json"
        )
    dependencies.append(contract_root / "active-candidate.json")
    return tuple(_require_safe_file(path, root=source_root) for path in dependencies)


def _daily_dependencies(source_root: Path) -> tuple[Path, ...]:
    selected = load_selected_daily_read_contract(source_root)
    contract_root = source_root / "daily-platform-read-contract"
    dependencies = (
        contract_root / f"{selected.manifest.canonical_sha256}.json",
        source_root
        / "daily-platform-read-contract-evidence"
        / f"{selected.freeze_evidence_sha256}.json",
        contract_root / "active-candidate.json",
    )
    return tuple(_require_safe_file(path, root=source_root) for path in dependencies)


def _mutex_name(data_root: Path) -> str:
    identity = os.path.normcase(os.fspath(data_root)).encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()[:32]
    return f"Local\\DaHeLogistics-{digest}"


def _require_target_stopped(data_root: Path) -> None:
    if sys.platform != "win32":
        raise OperationalContractInstallError("Windows is required")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_mutex = kernel32.OpenMutexW
    open_mutex.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR)
    open_mutex.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    handle = open_mutex(_SYNCHRONIZE, False, _mutex_name(data_root))
    if handle:
        close_handle(handle)
        raise OperationalContractInstallError(
            "target DaHe data root is still running"
        )
    error = ctypes.get_last_error()
    if error not in {0, _ERROR_FILE_NOT_FOUND}:
        raise OperationalContractInstallError(
            "target DaHe instance state could not be verified"
        )


def _ensure_safe_parent(path: Path, *, target_root: Path) -> None:
    try:
        path.relative_to(target_root)
    except ValueError as exc:
        raise OperationalContractInstallError(
            "target dependency escapes the target data root"
        ) from exc
    pending: list[Path] = []
    current = path.parent
    while current != target_root and not current.exists():
        pending.append(current)
        current = current.parent
    if current != target_root and (
        not current.is_dir() or _is_reparse_point(current)
    ):
        raise OperationalContractInstallError(
            "target dependency parent uses a reparse point"
        )
    for directory in reversed(pending):
        directory.mkdir(exist_ok=False)
    current = path.parent
    while current != target_root:
        if not current.is_dir() or _is_reparse_point(current):
            raise OperationalContractInstallError(
                "target dependency parent uses a reparse point"
            )
        current = current.parent


def _write_once(path: Path, content: bytes, *, target_root: Path) -> None:
    _ensure_safe_parent(path, target_root=target_root)
    if path.exists() or path.is_symlink():
        if _is_reparse_point(path) or not path.is_file():
            raise OperationalContractInstallError(
                "target contract conflict uses a reparse point"
            )
        if path.read_bytes() != content:
            raise OperationalContractInstallError(
                "target contract conflict would overwrite different content"
            )
        return
    staging = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with staging.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staging, path)
        except FileExistsError as exc:
            if (
                _is_reparse_point(path)
                or not path.is_file()
                or path.read_bytes() != content
            ):
                raise OperationalContractInstallError(
                    "target contract conflict appeared during install"
                ) from exc
    finally:
        staging.unlink(missing_ok=True)


def install_operational_read_contracts(
    *,
    source_root: Path,
    target_root: Path,
    output: Path,
) -> dict[str, object]:
    source = _require_safe_root(source_root, must_exist=True, label="source root")
    target_candidate = target_root.resolve()
    if source == target_candidate:
        raise OperationalContractInstallError(
            "source and target data roots must be different"
        )
    _require_target_stopped(target_candidate)
    target = _require_safe_root(
        target_root,
        must_exist=False,
        label="target root",
    )
    try:
        output.resolve().relative_to(target)
    except ValueError as exc:
        raise OperationalContractInstallError(
            "output must stay inside the target data root"
        ) from exc

    try:
        settlement_source = load_selected_live_read_contract(source)
        daily_source = load_selected_daily_read_contract(source)
        dependencies = (
            *_settlement_dependencies(source),
            *_daily_dependencies(source),
        )
    except (LiveContractSelectionError, DailyContractSelectionError) as exc:
        raise OperationalContractInstallError(
            "source contract verification failed"
        ) from exc

    copied: list[dict[str, object]] = []
    pointers: list[tuple[Path, bytes]] = []
    for source_path in dependencies:
        relative = source_path.relative_to(source)
        content = source_path.read_bytes()
        record = {
            "relative_path": relative.as_posix(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        copied.append(record)
        if source_path.name == "active-candidate.json":
            pointers.append((target / relative, content))
        else:
            _write_once(target / relative, content, target_root=target)
    for target_path, content in pointers:
        _write_once(target_path, content, target_root=target)

    settlement_target = load_selected_live_read_contract(target)
    daily_target = load_selected_daily_read_contract(target)
    settlement_identity_matches = (
        settlement_target.manifest == settlement_source.manifest
        and settlement_target.contract_file_sha256
        == settlement_source.contract_file_sha256
        and settlement_target.freeze_evidence_sha256
        == settlement_source.freeze_evidence_sha256
        and settlement_target.selection_sha256
        == settlement_source.selection_sha256
    )
    daily_identity_matches = (
        daily_target.manifest == daily_source.manifest
        and daily_target.contract_file_sha256
        == daily_source.contract_file_sha256
        and daily_target.freeze_evidence_sha256
        == daily_source.freeze_evidence_sha256
        and daily_target.selection_sha256
        == daily_source.selection_sha256
    )
    if not settlement_identity_matches or not daily_identity_matches:
        raise OperationalContractInstallError(
            "installed contract identity does not match the verified source"
        )
    copied.sort(key=lambda item: str(item["relative_path"]))
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": "chengfeng_operational_read_contract_install",
        "classification": "operational_only",
        "current_build_sha256": current_loop9_build_sha256(ROOT),
        "settlement_selection_sha256": settlement_target.selection_sha256,
        "daily_selection_sha256": daily_target.selection_sha256,
        "copied_files": copied,
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
        "formal_loop9_gate_eligible": False,
    }
    canonical_sha256 = hashlib.sha256(_canonical(body)).hexdigest()
    evidence = {**body, "canonical_sha256": canonical_sha256}
    _write_once(
        output.resolve(),
        _canonical(evidence) + b"\n",
        target_root=target,
    )
    return evidence


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    evidence = install_operational_read_contracts(
        source_root=arguments.source_root,
        target_root=arguments.target_root,
        output=arguments.output,
    )
    print(
        json.dumps(
            {
                "canonical_sha256": evidence["canonical_sha256"],
                "classification": evidence["classification"],
                "settlement_selection_sha256": evidence[
                    "settlement_selection_sha256"
                ],
                "daily_selection_sha256": evidence[
                    "daily_selection_sha256"
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
