from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
LOOP_PATTERN = re.compile(r"^loop-[0-9]+$")
LEDGER_STATUSES = {
    "in_progress",
    "accepted",
    "failed",
    "blocked",
    "closed_with_waiver",
    "shadow_accepted",
    "operational_read_only_with_guard",
    "operational_read_only_accepted",
    "operational_read_only_active",
}
GATE_STATUSES = {"pending", "passed", "failed", "blocked"}
WAIVER_FIELDS = {
    "accepted_by",
    "accepted_at",
    "evidence",
    "permits_next_loop",
    "prohibited_claims",
    "reason",
}
ACCEPTANCE_FIELDS = {
    "accepted_at",
    "evidence",
    "kind",
    "previous_last_accepted_git_commit",
    "previous_status",
    "sha256",
}
OPERATIONAL_ACCEPTANCE_FIELDS = {
    "accepted_at",
    "build_git_commit",
    "evidence",
    "kind",
    "previous_status",
    "sha256",
    "status",
}
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()
_THREAD_LOCK_STATE = threading.local()
_LOOP9_SHADOW_UPDATABLE_GATE_IDS = frozenset(
    {
        "loop-9-current-build-locked-set",
        "loop-9-real-request-contract",
        "loop-9-real-shadow-batch",
        "loop-9-recovery-scheduling-and-ui",
    }
)
_LOOP9_SHADOW_FINAL_GATE_ID = "loop-9-final-shadow-acceptance"


def _open_guarded_file(
    path: Path,
    *,
    allow_replace: bool,
) -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if os.name != "nt":
        return os.open(path, flags)

    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        os.fspath(path),
        0x80000000,  # GENERIC_READ
        (
            0x00000001  # FILE_SHARE_READ: always deny content writes
            | (0x00000004 if allow_replace else 0)
        ),
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in {None, invalid}:
        error = ctypes.get_last_error()
        raise OSError(
            error,
            "shadow acceptance evidence could not be opened safely",
            path,
        )
    try:
        return msvcrt.open_osfhandle(int(handle), flags)
    except Exception:
        kernel32.CloseHandle(handle)
        raise


class LedgerError(RuntimeError):
    """Base error for the persistent Loop ledger."""


class LedgerConflictError(LedgerError):
    """Raised when a caller tries to overwrite a newer ledger revision."""


class LedgerValidationError(LedgerError):
    """Raised when a ledger document violates the persistent contract."""


class _ShadowEvidenceGuard:
    """Hold and reverify one immutable acceptance-evidence identity."""

    def __init__(
        self,
        *,
        path: Path,
        expected_content: bytes,
        allow_replace: bool = False,
        label: str = "shadow acceptance evidence",
    ) -> None:
        try:
            self._descriptor = _open_guarded_file(
                path,
                allow_replace=allow_replace,
            )
        except OSError as exc:
            raise LedgerValidationError(
                f"{label} could not be secured"
            ) from exc
        self.path = path
        self.expected_content = expected_content
        self._label = label
        self._closed = False
        try:
            self._identity = self._descriptor_identity()
            self.revalidate()
        except Exception:
            self.close()
            raise

    def _descriptor_identity(self) -> tuple[int, int]:
        try:
            metadata = os.fstat(self._descriptor)
        except OSError as exc:
            raise LedgerValidationError(
                f"{self._label} handle is unavailable"
            ) from exc
        return metadata.st_dev, metadata.st_ino

    def _read_descriptor(self) -> bytes:
        try:
            os.lseek(self._descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(self._descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            os.lseek(self._descriptor, 0, os.SEEK_SET)
        except OSError as exc:
            raise LedgerValidationError(
                f"{self._label} handle is unreadable"
            ) from exc
        return b"".join(chunks)

    def revalidate(self) -> None:
        if self._closed:
            raise LedgerValidationError(
                f"{self._label} handle is closed"
            )
        try:
            path_identity = (
                self.path.stat(follow_symlinks=False).st_dev,
                self.path.stat(follow_symlinks=False).st_ino,
            )
            resolved = self.path.resolve(strict=True)
        except OSError as exc:
            raise LedgerValidationError(
                f"{self._label} identity changed"
            ) from exc
        if (
            self.path.is_symlink()
            or _is_reparse_point(self.path)
            or resolved != self.path
            or path_identity != self._identity
            or self._descriptor_identity() != self._identity
            or self._read_descriptor() != self.expected_content
        ):
            raise LedgerValidationError(
                f"{self._label} changed before ledger commit"
            )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        os.close(self._descriptor)


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LedgerValidationError(
            "acceptance evidence is not canonical JSON"
        ) from exc


def _normalize_remaining_risks(value: object) -> list[str]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
    ):
        raise LedgerValidationError(
            "shadow acceptance remaining risks are invalid"
        )
    normalized: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or item != item.strip()
            or len(item) > 500
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in item
            )
        ):
            raise LedgerValidationError(
                "shadow acceptance remaining risks are invalid"
            )
        normalized.append(item)
    return normalized


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(
        attributes
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LedgerValidationError(
                "acceptance evidence contains duplicate fields"
            )
        result[key] = value
    return result


def _process_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(os.fspath(path.resolve(strict=False)))
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(key, threading.RLock())


def _lock_stream(stream: BinaryIO) -> None:
    stream.seek(0)
    if os.name == "nt":
        import msvcrt

        last_error: OSError | None = None
        for _ in range(600):
            stream.seek(0)
            try:
                msvcrt.locking(
                    stream.fileno(),
                    msvcrt.LK_NBLCK,
                    1,
                )
                return
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        assert last_error is not None
        raise last_error
    import fcntl

    fcntl.flock(  # type: ignore[attr-defined]
        stream.fileno(),
        fcntl.LOCK_EX,  # type: ignore[attr-defined]
    )


def _unlock_stream(stream: BinaryIO) -> None:
    stream.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(  # type: ignore[attr-defined]
        stream.fileno(),
        fcntl.LOCK_UN,  # type: ignore[attr-defined]
    )


def _require_relative_path(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise LedgerValidationError(f"{field} must be a non-empty relative path")
    if Path(value).is_absolute() or ".." in Path(value).parts:
        raise LedgerValidationError(f"{field} must stay inside the repository")


def validate_document(document: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "revision",
        "project_id",
        "current_loop",
        "status",
        "run_id",
        "input_manifest",
        "gate_results",
        "unresolved_risks",
        "next_inputs",
        "last_accepted_git_commit",
    }
    schema_version = document.get("schema_version")
    if schema_version == 2:
        required.add("waiver")
    if schema_version == 3:
        required.update({"waiver", "acceptance"})
    if schema_version == 4:
        required.update({"waiver", "acceptance", "operational_acceptance"})
    if set(document) != required:
        raise LedgerValidationError("ledger fields do not match schema version")
    if schema_version not in {1, 2, 3, 4} or document["project_id"] != "DaHeLogistics":
        raise LedgerValidationError("ledger identity or schema version is invalid")
    if not isinstance(document["revision"], int) or document["revision"] < 0:
        raise LedgerValidationError("ledger revision must be a non-negative integer")
    if not isinstance(document["current_loop"], str) or not LOOP_PATTERN.fullmatch(
        document["current_loop"]
    ):
        raise LedgerValidationError("current_loop is invalid")
    if (
        document["status"] not in LEDGER_STATUSES
        or (
            document["status"] == "closed_with_waiver"
            and schema_version not in {2, 3}
        )
        or (
            document["status"] == "shadow_accepted"
            and schema_version != 3
        )
        or (
            document["status"]
            in {
                "operational_read_only_with_guard",
                "operational_read_only_accepted",
                "operational_read_only_active",
            }
            and schema_version != 4
        )
    ):
        raise LedgerValidationError("ledger status is invalid")
    if not isinstance(document["run_id"], str) or not document["run_id"]:
        raise LedgerValidationError("run_id is required")

    input_manifest = document["input_manifest"]
    if not isinstance(input_manifest, dict) or set(input_manifest) != {"path", "sha256"}:
        raise LedgerValidationError("input_manifest is invalid")
    _require_relative_path(input_manifest["path"], "input_manifest.path")
    if not isinstance(input_manifest["sha256"], str) or not SHA256_PATTERN.fullmatch(
        input_manifest["sha256"]
    ):
        raise LedgerValidationError("input_manifest.sha256 is invalid")

    gates = document["gate_results"]
    if not isinstance(gates, list) or not gates:
        raise LedgerValidationError("gate_results must be a non-empty list")
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) != {"id", "status", "evidence"}:
            raise LedgerValidationError("gate result fields are invalid")
        if not isinstance(gate["id"], str) or not gate["id"]:
            raise LedgerValidationError("gate result id is required")
        if gate["status"] not in GATE_STATUSES:
            raise LedgerValidationError("gate result status is invalid")
        if gate["evidence"] is not None:
            _require_relative_path(gate["evidence"], "gate result evidence")

    for field in ("unresolved_risks", "next_inputs"):
        value = document[field]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise LedgerValidationError(f"{field} must be a list of strings")

    commit = document["last_accepted_git_commit"]
    if commit is not None and (
        not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit)
    ):
        raise LedgerValidationError("last_accepted_git_commit is invalid")
    if document["status"] in {"accepted", "shadow_accepted"} and (
        commit is None or any(gate["status"] != "passed" for gate in gates)
    ):
        raise LedgerValidationError(
            "accepted ledgers require a commit and passed gates"
        )
    if document["status"] in {
        "operational_read_only_with_guard",
        "operational_read_only_accepted",
        "operational_read_only_active",
    } and commit is None:
        raise LedgerValidationError(
            "operational acceptance requires a Git baseline"
        )
    if schema_version in {2, 3, 4}:
        waiver = document["waiver"]
        if waiver is not None:
            if not isinstance(waiver, dict) or set(waiver) != WAIVER_FIELDS:
                raise LedgerValidationError("ledger waiver is invalid")
            for field in ("accepted_by", "accepted_at", "reason"):
                value = waiver[field]
                if not isinstance(value, str) or not value.strip():
                    raise LedgerValidationError(
                        f"waiver {field} is required"
                    )
            _require_relative_path(waiver["evidence"], "waiver.evidence")
            if waiver["permits_next_loop"] is not True:
                raise LedgerValidationError(
                    "waiver must explicitly permit the next Loop"
                )
            prohibited = waiver["prohibited_claims"]
            if (
                not isinstance(prohibited, list)
                or not prohibited
                or not all(
                    isinstance(item, str) and item.strip()
                    for item in prohibited
                )
            ):
                raise LedgerValidationError(
                    "waiver prohibited claims are required"
                )
        if document["status"] == "closed_with_waiver":
            if (
                waiver is None
                or not document["unresolved_risks"]
                or not any(gate["status"] == "failed" for gate in gates)
            ):
                raise LedgerValidationError(
                    "waiver closure requires evidence, risks, and a failed gate"
                )
        elif waiver is not None:
            raise LedgerValidationError(
                "only a waiver closure may carry waiver evidence"
            )
    if schema_version == 3:
        acceptance = document["acceptance"]
        if document["status"] == "shadow_accepted":
            if (
                document["current_loop"] != "loop-9"
                or not isinstance(acceptance, dict)
                or set(acceptance) != ACCEPTANCE_FIELDS
                or acceptance.get("kind") != "loop9_shadow_acceptance"
                or acceptance.get("previous_status") != "in_progress"
            ):
                raise LedgerValidationError(
                    "shadow acceptance authority is invalid"
                )
            _require_relative_path(
                acceptance["evidence"],
                "acceptance.evidence",
            )
            sha256 = acceptance["sha256"]
            if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(
                sha256
            ):
                raise LedgerValidationError(
                    "acceptance.sha256 is invalid"
                )
            accepted_at = acceptance["accepted_at"]
            if not isinstance(accepted_at, str):
                raise LedgerValidationError(
                    "acceptance.accepted_at is invalid"
                )
            try:
                parsed = datetime.fromisoformat(accepted_at)
            except ValueError as exc:
                raise LedgerValidationError(
                    "acceptance.accepted_at is invalid"
                ) from exc
            if (
                parsed.tzinfo is None
                or parsed.utcoffset() is None
                or parsed.isoformat() != accepted_at
            ):
                raise LedgerValidationError(
                    "acceptance.accepted_at is invalid"
                )
            previous_commit = acceptance[
                "previous_last_accepted_git_commit"
            ]
            if (
                previous_commit is None
                or not isinstance(previous_commit, str)
                or not COMMIT_PATTERN.fullmatch(previous_commit)
                or previous_commit != commit
            ):
                raise LedgerValidationError(
                    "shadow acceptance must preserve the previous accepted commit"
                )
            if any(gate["status"] != "passed" for gate in gates):
                raise LedgerValidationError(
                    "shadow acceptance requires passed gates"
                )
            if waiver is not None:
                raise LedgerValidationError(
                    "shadow acceptance cannot carry waiver evidence"
                )
        elif acceptance is not None:
            raise LedgerValidationError(
                "only shadow acceptance may carry acceptance evidence"
            )
    if schema_version == 4:
        if document["acceptance"] is not None or document["waiver"] is not None:
            raise LedgerValidationError(
                "operational acceptance cannot carry strict acceptance or waiver"
            )
        operational = document["operational_acceptance"]
        statuses = {
            "operational_read_only_with_guard",
            "operational_read_only_accepted",
            "operational_read_only_active",
        }
        if document["status"] in statuses:
            active_policy = document["status"] == "operational_read_only_active"
            expected_kind = (
                "loop9_operational_read_only_policy_change"
                if active_policy
                else "loop9_operational_read_only_acceptance"
            )
            valid_previous_statuses = (
                {
                    "operational_read_only_with_guard",
                    "operational_read_only_accepted",
                }
                if active_policy
                else {"in_progress"}
            )
            if (
                document["current_loop"] != "loop-9"
                or not isinstance(operational, dict)
                or set(operational) != OPERATIONAL_ACCEPTANCE_FIELDS
                or operational.get("kind") != expected_kind
                or operational.get("previous_status")
                not in valid_previous_statuses
                or operational.get("status") != document["status"]
                or operational.get("build_git_commit") != commit
            ):
                raise LedgerValidationError(
                    "operational acceptance authority is invalid"
                )
            _require_relative_path(
                operational["evidence"],
                "operational_acceptance.evidence",
            )
            sha256 = operational["sha256"]
            if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(sha256):
                raise LedgerValidationError(
                    "operational acceptance SHA-256 is invalid"
                )
            accepted_at = operational["accepted_at"]
            if not isinstance(accepted_at, str):
                raise LedgerValidationError(
                    "operational acceptance time is invalid"
                )
            try:
                parsed = datetime.fromisoformat(accepted_at)
            except ValueError as exc:
                raise LedgerValidationError(
                    "operational acceptance time is invalid"
                ) from exc
            if (
                parsed.tzinfo is None
                or parsed.utcoffset() is None
                or parsed.isoformat() != accepted_at
            ):
                raise LedgerValidationError(
                    "operational acceptance time is invalid"
                )
        elif operational is not None:
            raise LedgerValidationError(
                "only operational acceptance may carry its evidence"
            )


class LedgerStore:
    def __init__(
        self,
        path: Path,
        before_replace: Callable[[Path], None] | None = None,
    ) -> None:
        self.path = path
        self.before_replace = before_replace

    def read(self) -> dict[str, Any]:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LedgerValidationError("the Loop ledger is unreadable") from exc
        if not isinstance(document, dict):
            raise LedgerValidationError("the Loop ledger root must be an object")
        validate_document(document)
        return document

    @contextmanager
    def locked_write(self) -> Iterator[LedgerStore]:
        """Hold the shared process and OS lock across one write decision."""

        with self._exclusive_write_lock():
            yield self

    def replace(
        self,
        expected_revision: int,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        if document.get("status") in {
            "shadow_accepted",
            "operational_read_only_with_guard",
            "operational_read_only_accepted",
            "operational_read_only_active",
        }:
            raise LedgerValidationError(
                "use a dedicated Loop 9 acceptance writer"
            )
        return self._replace(
            expected_revision=expected_revision,
            document=document,
        )

    def commit_operational_read_only_acceptance(
        self,
        *,
        expected_revision: int,
        evidence_path: str,
        evidence_sha256: str,
        status: str,
        build_git_commit: str,
        accepted_at: str,
        unresolved_risks: Sequence[str],
        next_inputs: Sequence[str],
    ) -> dict[str, Any]:
        if status not in {
            "operational_read_only_with_guard",
            "operational_read_only_accepted",
        }:
            raise LedgerValidationError(
                "operational acceptance status is invalid"
            )
        current = self.read()
        if (
            current["revision"] != expected_revision
            or current["current_loop"] != "loop-9"
            or current["status"] != "in_progress"
        ):
            raise LedgerConflictError(
                "operational acceptance no longer matches the active Loop"
            )
        gates = deepcopy(current["gate_results"])
        operational_gate = {
            "id": "loop-9-operational-read-only-cutover",
            "status": "passed",
            "evidence": evidence_path,
        }
        for index, gate in enumerate(gates):
            if gate["id"] == operational_gate["id"]:
                gates[index] = operational_gate
                break
        else:
            gates.append(operational_gate)
        document = {
            **current,
            "schema_version": 4,
            "revision": expected_revision + 1,
            "status": status,
            "gate_results": gates,
            "unresolved_risks": list(unresolved_risks),
            "next_inputs": list(next_inputs),
            "last_accepted_git_commit": build_git_commit,
            "waiver": None,
            "acceptance": None,
            "operational_acceptance": {
                "accepted_at": accepted_at,
                "build_git_commit": build_git_commit,
                "evidence": evidence_path,
                "kind": "loop9_operational_read_only_acceptance",
                "previous_status": "in_progress",
                "sha256": evidence_sha256,
                "status": status,
            },
        }
        return self._replace(
            expected_revision=expected_revision,
            document=document,
        )

    def commit_operational_read_only_policy_change(
        self,
        *,
        expected_revision: int,
        evidence_path: str,
        evidence_sha256: str,
        build_git_commit: str,
        changed_at: str,
        unresolved_risks: Sequence[str],
        next_inputs: Sequence[str],
    ) -> dict[str, Any]:
        current = self.read()
        previous_status = str(current.get("status"))
        if (
            current["revision"] != expected_revision
            or current["current_loop"] != "loop-9"
            or previous_status
            not in {
                "operational_read_only_with_guard",
                "operational_read_only_accepted",
            }
        ):
            raise LedgerConflictError(
                "operational policy change no longer matches the active baseline"
            )
        document = {
            **current,
            "revision": expected_revision + 1,
            "status": "operational_read_only_active",
            "unresolved_risks": list(unresolved_risks),
            "next_inputs": list(next_inputs),
            "last_accepted_git_commit": build_git_commit,
            "operational_acceptance": {
                "accepted_at": changed_at,
                "build_git_commit": build_git_commit,
                "evidence": evidence_path,
                "kind": "loop9_operational_read_only_policy_change",
                "previous_status": previous_status,
                "sha256": evidence_sha256,
                "status": "operational_read_only_active",
            },
        }
        return self._replace(
            expected_revision=expected_revision,
            document=document,
        )

    def _commit_verified_shadow_acceptance(
        self,
        *,
        expected_revision: int,
        evidence_path: str,
        evidence_sha256: str,
        accepted_at: str,
        remaining_risks: object,
        inputs: object,
    ) -> dict[str, Any]:
        """Replay all authorities and construct the sole terminal document."""

        ledger_key = os.path.normcase(
            os.fspath(self.path.resolve(strict=False))
        )
        lock_depths = getattr(_THREAD_LOCK_STATE, "depths", {})
        if int(lock_depths.get(ledger_key, 0)) < 1:
            raise LedgerValidationError(
                "shadow acceptance requires the existing ledger write lock"
            )
        # Import lazily to keep the general ledger reader independent from the
        # Loop 9 verifier while making the sole terminal writer reload all
        # formal authorities from strongly typed inputs.
        from dahe.verification.loop9_final_acceptance import (
            REPOSITORY_ROOT,
            Loop9FinalAcceptanceError,
            Loop9FinalAcceptanceInputs,
            _canonical_acceptance_payload,
            replay_loop9_final_acceptance,
        )

        if not isinstance(inputs, Loop9FinalAcceptanceInputs):
            raise LedgerValidationError(
                "shadow acceptance requires typed final acceptance inputs"
            )
        if not isinstance(accepted_at, str):
            raise LedgerValidationError(
                "shadow acceptance ledger time is invalid"
            )
        try:
            parsed_accepted_at = datetime.fromisoformat(accepted_at)
        except ValueError as exc:
            raise LedgerValidationError(
                "shadow acceptance ledger time is invalid"
            ) from exc
        if (
            parsed_accepted_at.tzinfo is None
            or parsed_accepted_at.utcoffset() is None
            or parsed_accepted_at.isoformat() != accepted_at
        ):
            raise LedgerValidationError(
                "shadow acceptance ledger time is invalid"
            )
        normalized_risks = _normalize_remaining_risks(
            remaining_risks
        )
        try:
            active_project = REPOSITORY_ROOT.resolve(strict=True)
            input_project = inputs.project_root.resolve(strict=True)
            ledger_project = self.path.parent.parent.resolve(strict=True)
            ledger_file = self.path.resolve(strict=True)
            expected_ledger = (
                active_project / "verification" / "loop-ledger.json"
            )
            expected_ledger_file = expected_ledger.resolve(strict=True)
        except OSError as exc:
            raise LedgerValidationError(
                "shadow acceptance project authority is unavailable"
            ) from exc
        input_ledger = (
            inputs.project_root / "verification" / "loop-ledger.json"
        )
        if (
            input_project != active_project
            or ledger_project != active_project
            or ledger_file != expected_ledger_file
            or os.path.normcase(os.path.abspath(self.path))
            != os.path.normcase(os.path.abspath(expected_ledger))
            or os.path.normcase(os.path.abspath(self.path))
            != os.path.normcase(os.path.abspath(input_ledger))
            or self.path.is_symlink()
            or _is_reparse_point(self.path)
            or not self.path.is_file()
        ):
            raise LedgerValidationError(
                "shadow acceptance requires the active repository ledger"
            )
        current = self.read()
        if current["revision"] != expected_revision:
            raise LedgerConflictError(
                "the Loop ledger has a newer revision"
            )
        if current["status"] == "shadow_accepted":
            raise LedgerValidationError(
                "shadow acceptance is a terminal ledger state"
            )
        if (
            current["schema_version"] not in {2, 3}
            or current["current_loop"] != "loop-9"
            or current["status"] != "in_progress"
            or current.get("waiver") is not None
            or current["last_accepted_git_commit"] is None
            or (
                current["schema_version"] == 3
                and current.get("acceptance") is not None
            )
        ):
            raise LedgerValidationError(
                "the Loop ledger is not eligible for shadow acceptance"
            )
        gates = current["gate_results"]
        if not isinstance(gates, list):
            raise LedgerValidationError(
                "the Loop ledger Gate authority is invalid"
            )
        gate_ids = [
            gate.get("id")
            for gate in gates
            if isinstance(gate, dict)
        ]
        pending_gate_ids = {
            gate["id"]
            for gate in gates
            if isinstance(gate, dict)
            and gate.get("status") == "pending"
        }
        if (
            len(gate_ids) != len(gates)
            or len(set(gate_ids)) != len(gate_ids)
            or _LOOP9_SHADOW_FINAL_GATE_ID in gate_ids
            or not _LOOP9_SHADOW_UPDATABLE_GATE_IDS.issubset(
                set(gate_ids)
            )
            or any(
                not isinstance(gate, dict)
                or gate.get("status") in {"failed", "blocked"}
                for gate in gates
            )
            or not pending_gate_ids.issubset(
                _LOOP9_SHADOW_UPDATABLE_GATE_IDS
            )
        ):
            raise LedgerValidationError(
                "the Loop ledger Gate authority is invalid"
            )
        manifest_guard = self._open_input_manifest_guard(
            project_root=active_project,
            document=current,
        )
        evidence_guard: _ShadowEvidenceGuard | None = None
        replacement_guard: _ShadowEvidenceGuard | None = None
        temporary: Path | None = None
        try:
            # The terminal path never trusts a caller-authored replay object.
            # It reloads all formal Gate authorities from the typed inputs
            # while the same process and OS ledger lock are still held.
            try:
                replay = replay_loop9_final_acceptance(inputs)
                replay.verify()
                verified_payload = _canonical_acceptance_payload(
                    replay.evidence_payload(accepted_at=accepted_at)
                )
            except Loop9FinalAcceptanceError as exc:
                raise LedgerValidationError(
                    "shadow acceptance typed replay verification failed"
                ) from exc
            manifest_guard.revalidate()
            expected_evidence_content = (
                _canonical_bytes(verified_payload) + b"\n"
            )
            if (
                verified_payload.get("canonical_sha256")
                != evidence_sha256
                or verified_payload.get("accepted_at") != accepted_at
            ):
                raise LedgerValidationError(
                    "shadow acceptance typed replay binding changed"
                )
            evidence_guard = self._open_shadow_evidence_guard(
                evidence_path=evidence_path,
                evidence_sha256=evidence_sha256,
                expected_content=expected_evidence_content,
            )

            replacement = deepcopy(current)
            replacement["schema_version"] = 3
            replacement["revision"] = expected_revision + 1
            replacement["status"] = "shadow_accepted"
            replacement["waiver"] = None
            replacement["unresolved_risks"] = normalized_risks
            replacement["next_inputs"] = []
            replacement["acceptance"] = {
                "kind": "loop9_shadow_acceptance",
                "accepted_at": accepted_at,
                "evidence": evidence_path,
                "sha256": evidence_sha256,
                "previous_status": "in_progress",
                "previous_last_accepted_git_commit": current[
                    "last_accepted_git_commit"
                ],
            }
            replacement_gates = replacement["gate_results"]
            if not isinstance(replacement_gates, list):
                raise LedgerValidationError(
                    "the Loop ledger Gate authority is invalid"
                )
            for gate in replacement_gates:
                if (
                    isinstance(gate, dict)
                    and gate.get("id")
                    in _LOOP9_SHADOW_UPDATABLE_GATE_IDS
                ):
                    gate["status"] = "passed"
                    gate["evidence"] = evidence_path
            replacement_gates.append(
                {
                    "id": _LOOP9_SHADOW_FINAL_GATE_ID,
                    "status": "passed",
                    "evidence": evidence_path,
                }
            )
            validate_document(replacement)
            payload = (
                json.dumps(
                    replacement,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            replacement_content = payload.encode("utf-8")
            temporary = self.path.with_name(
                f".{self.path.name}.{uuid4().hex}.tmp"
            )
            current_content = self.path.read_bytes()
            current_metadata = self.path.stat(follow_symlinks=False)
            current_identity = (
                current_metadata.st_dev,
                current_metadata.st_ino,
            )
            try:
                current_from_bytes = json.loads(
                    current_content.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                )
            except (
                UnicodeError,
                json.JSONDecodeError,
                LedgerValidationError,
            ) as exc:
                raise LedgerValidationError(
                    "the Loop ledger changed before shadow acceptance"
                ) from exc
            if current_from_bytes != current:
                raise LedgerConflictError(
                    "the Loop ledger changed before shadow acceptance"
                )
            manifest_guard.revalidate()
            with temporary.open(
                "x",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if self.before_replace is not None:
                self.before_replace(temporary)
            replacement_guard = _ShadowEvidenceGuard(
                path=temporary,
                expected_content=replacement_content,
                allow_replace=True,
                label="ledger replacement",
            )
            for attempt in range(3):
                try:
                    if (
                        replacement.get("acceptance", {}).get(
                            "accepted_at"
                        )
                        != accepted_at
                        or replacement.get("acceptance", {}).get(
                            "evidence"
                        )
                        != evidence_path
                        or replacement.get("acceptance", {}).get(
                            "sha256"
                        )
                        != evidence_sha256
                    ):
                        raise LedgerValidationError(
                            "shadow acceptance binding changed before commit"
                        )
                    manifest_guard.revalidate()
                    evidence_guard.revalidate()
                    try:
                        current_stat = self.path.stat(
                            follow_symlinks=False
                        )
                        current_path_identity = (
                            current_stat.st_dev,
                            current_stat.st_ino,
                        )
                        current_bytes = self.path.read_bytes()
                    except OSError as exc:
                        raise LedgerConflictError(
                            "the Loop ledger changed before shadow acceptance"
                        ) from exc
                    if (
                        self.path.is_symlink()
                        or _is_reparse_point(self.path)
                        or current_path_identity != current_identity
                        or current_bytes != current_content
                    ):
                        raise LedgerConflictError(
                            "the Loop ledger changed before shadow acceptance"
                        )
                    replacement_guard.revalidate()
                    os.replace(temporary, self.path)
                    break
                except PermissionError:
                    if attempt == 2:
                        raise
                    time.sleep(0.05 * (attempt + 1))
            else:  # pragma: no cover - the loop exits or raises
                raise LedgerValidationError(
                    "shadow acceptance replacement did not complete"
                )
        finally:
            if replacement_guard is not None:
                replacement_guard.close()
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            if evidence_guard is not None:
                evidence_guard.close()
            manifest_guard.close()
        return self.read()

    def _replace(
        self,
        *,
        expected_revision: int,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        with self._exclusive_write_lock():
            current = self.read()
            if current["revision"] != expected_revision:
                raise LedgerConflictError(
                    "the Loop ledger has a newer revision"
                )
            if current["status"] == "shadow_accepted":
                raise LedgerValidationError(
                    "shadow acceptance is a terminal ledger state"
                )
            if document.get("status") == "shadow_accepted":
                raise LedgerValidationError(
                    "use the dedicated Loop 9 acceptance writer"
                )
            if document.get("revision") != expected_revision + 1:
                raise LedgerValidationError(
                    "replacement revision must increment by one"
                )
            validate_document(document)

            temporary = self.path.with_name(
                f".{self.path.name}.{uuid4().hex}.tmp"
            )
            payload = (
                json.dumps(
                    document,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            replacement_content = payload.encode("utf-8")
            replacement_guard: _ShadowEvidenceGuard | None = None
            try:
                with temporary.open(
                    "x",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                if self.before_replace is not None:
                    self.before_replace(temporary)
                replacement_guard = _ShadowEvidenceGuard(
                    path=temporary,
                    expected_content=replacement_content,
                    allow_replace=True,
                    label="ledger replacement",
                )
                self._replace_with_bounded_retry(
                    temporary,
                    replacement_guard=replacement_guard,
                )
            finally:
                if replacement_guard is not None:
                    replacement_guard.close()
                temporary.unlink(missing_ok=True)
            return self.read()

    @contextmanager
    def _exclusive_write_lock(self) -> Iterator[None]:
        path = self.path.resolve(strict=False)
        key = os.path.normcase(os.fspath(path))
        process_lock = _process_lock(path)
        with process_lock:
            depths = getattr(_THREAD_LOCK_STATE, "depths", None)
            if depths is None:
                depths = {}
                _THREAD_LOCK_STATE.depths = depths
            depth = int(depths.get(key, 0))
            if depth:
                depths[key] = depth + 1
                try:
                    yield
                finally:
                    depths[key] -= 1
                return

            lock_path = self.path.with_name(
                f".{self.path.name}.lock"
            )
            if lock_path.exists() and (
                lock_path.is_symlink()
                or _is_reparse_point(lock_path)
                or not lock_path.is_file()
            ):
                raise LedgerValidationError(
                    "the Loop ledger lock file is unsafe"
                )
            try:
                stream = lock_path.open("a+b")
            except OSError as exc:
                raise LedgerValidationError(
                    "the Loop ledger lock file is unavailable"
                ) from exc
            depths[key] = 1
            acquired = False
            try:
                try:
                    _lock_stream(stream)
                    acquired = True
                except OSError as exc:
                    raise LedgerValidationError(
                        "the Loop ledger lock could not be acquired"
                    ) from exc
                yield
            finally:
                try:
                    if acquired:
                        _unlock_stream(stream)
                finally:
                    stream.close()
                    depths.pop(key, None)

    def _open_input_manifest_guard(
        self,
        *,
        project_root: Path,
        document: dict[str, Any],
    ) -> _ShadowEvidenceGuard:
        reference = document.get("input_manifest")
        if (
            not isinstance(reference, dict)
            or set(reference) != {"path", "sha256"}
        ):
            raise LedgerValidationError(
                "ledger input manifest is invalid"
            )
        raw_path = reference.get("path")
        expected_sha256 = reference.get("sha256")
        _require_relative_path(raw_path, "input_manifest.path")
        if (
            not isinstance(raw_path, str)
            or not isinstance(expected_sha256, str)
            or SHA256_PATTERN.fullmatch(expected_sha256) is None
        ):
            raise LedgerValidationError(
                "ledger input manifest is invalid"
            )
        candidate = project_root / Path(raw_path)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise LedgerValidationError(
                "ledger input manifest is unavailable"
            ) from exc
        if (
            resolved != candidate
            or candidate.is_symlink()
            or _is_reparse_point(candidate)
            or not candidate.is_file()
        ):
            raise LedgerValidationError(
                "ledger input manifest path is unsafe"
            )
        current = candidate.parent
        while current != project_root:
            if (
                current == current.parent
                or current.is_symlink()
                or _is_reparse_point(current)
                or not current.is_dir()
            ):
                raise LedgerValidationError(
                    "ledger input manifest path is unsafe"
                )
            current = current.parent
        try:
            content = candidate.read_bytes()
        except OSError as exc:
            raise LedgerValidationError(
                "ledger input manifest is unavailable"
            ) from exc
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            raise LedgerValidationError(
                "ledger input manifest changed"
            )
        return _ShadowEvidenceGuard(
            path=candidate,
            expected_content=content,
            label="ledger input manifest",
        )

    def _open_shadow_evidence_guard(
        self,
        *,
        evidence_path: str,
        evidence_sha256: str,
        expected_content: bytes,
    ) -> _ShadowEvidenceGuard:
        if (
            not isinstance(evidence_sha256, str)
            or SHA256_PATTERN.fullmatch(evidence_sha256) is None
        ):
            raise LedgerValidationError(
                "shadow acceptance evidence SHA-256 is invalid"
            )
        project_root = self.path.parent.parent
        expected_reference = (
            "verification/loops/loop-9/formal/"
            f"{evidence_sha256}.json"
        )
        if evidence_path != expected_reference:
            raise LedgerValidationError(
                "shadow acceptance evidence path is not content-addressed"
            )
        candidate = project_root / Path(evidence_path)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise LedgerValidationError(
                "shadow acceptance evidence is unavailable"
            ) from exc
        if (
            resolved != candidate
            or candidate.is_symlink()
            or _is_reparse_point(candidate)
            or not candidate.is_file()
            or candidate.name != f"{evidence_sha256}.json"
        ):
            raise LedgerValidationError(
                "shadow acceptance evidence path is unsafe"
            )
        current = candidate.parent
        while current != project_root:
            if (
                current.is_symlink()
                or _is_reparse_point(current)
                or not current.is_dir()
            ):
                raise LedgerValidationError(
                    "shadow acceptance evidence path is unsafe"
                )
            current = current.parent
        try:
            payload = json.loads(
                expected_content.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    LedgerValidationError(
                        "acceptance evidence contains "
                        f"non-finite JSON: {value}"
                    )
                ),
            )
        except LedgerValidationError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LedgerValidationError(
                "shadow acceptance expected evidence is unreadable"
            ) from exc
        if not isinstance(payload, dict):
            raise LedgerValidationError(
                "shadow acceptance evidence root is invalid"
            )
        declared = payload.get("canonical_sha256")
        body = {
            key: value
            for key, value in payload.items()
            if key != "canonical_sha256"
        }
        actual = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        if (
            declared != evidence_sha256
            or actual != evidence_sha256
            or expected_content != _canonical_bytes(payload) + b"\n"
        ):
            raise LedgerValidationError(
                "shadow acceptance evidence canonical binding is invalid"
            )
        guard = _ShadowEvidenceGuard(
            path=candidate,
            expected_content=expected_content,
        )
        try:
            content = guard._read_descriptor()
            payload = json.loads(
                content.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    LedgerValidationError(
                        "acceptance evidence contains "
                        f"non-finite JSON: {value}"
                    )
                ),
            )
        except LedgerValidationError:
            guard.close()
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            guard.close()
            raise LedgerValidationError(
                "shadow acceptance evidence is unreadable"
            ) from exc
        if not isinstance(payload, dict):
            guard.close()
            raise LedgerValidationError(
                "shadow acceptance evidence root is invalid"
            )
        declared = payload.get("canonical_sha256")
        body = {
            key: value
            for key, value in payload.items()
            if key != "canonical_sha256"
        }
        actual = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        if (
            declared != evidence_sha256
            or actual != evidence_sha256
            or content != _canonical_bytes(payload) + b"\n"
        ):
            guard.close()
            raise LedgerValidationError(
                "shadow acceptance evidence canonical binding is invalid"
            )
        return guard

    def _replace_with_bounded_retry(
        self,
        temporary: Path,
        *,
        replacement_guard: _ShadowEvidenceGuard,
    ) -> None:
        for attempt in range(3):
            try:
                replacement_guard.revalidate()
                os.replace(temporary, self.path)
                return
            except PermissionError:
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
