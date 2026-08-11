from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import cast
from uuid import uuid4

from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.verification.loop9_human_review import (
    _load_and_validate_seal,
    load_loop9_review_package,
)
from dahe.verification.loop9_machine_results import (
    evaluate_sealed_machine_results,
    load_machine_result_manifest,
    load_machine_truth_evaluation,
)

SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 32 * 1024 * 1024


class Loop9CurrentLockedGateError(RuntimeError):
    """Raised when the current-build locked-set gate cannot be trusted."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Loop9CurrentLockedGateError(
            "current locked gate is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9CurrentLockedGateError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(
        attributes
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _safe_root(data_root: Path) -> Path:
    if (
        not isinstance(data_root, Path)
        or not data_root.is_absolute()
        or data_root.is_symlink()
        or _is_reparse_point(data_root)
    ):
        raise Loop9CurrentLockedGateError(
            "formal data root must be an absolute normal directory"
        )
    try:
        root = data_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9CurrentLockedGateError(
            "formal data root is unavailable"
        ) from exc
    if root != data_root or not root.is_dir():
        raise Loop9CurrentLockedGateError(
            "formal data root must be an absolute normal directory"
        )
    return root


def _safe_child(parent: Path, name: str) -> Path:
    child = parent / name
    if child.exists() and (
        child.is_symlink() or _is_reparse_point(child)
    ):
        raise Loop9CurrentLockedGateError(
            "current locked gate storage is unsafe"
        )
    child.mkdir(mode=0o700, parents=False, exist_ok=True)
    try:
        resolved = child.resolve(strict=True)
    except OSError as exc:
        raise Loop9CurrentLockedGateError(
            "current locked gate storage is unavailable"
        ) from exc
    if resolved != child or resolved.parent != parent or not resolved.is_dir():
        raise Loop9CurrentLockedGateError(
            "current locked gate storage is unsafe"
        )
    return resolved


def _relative_reference(root: Path, path: Path, *, label: str) -> str:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.is_symlink()
        or _is_reparse_point(path)
    ):
        raise Loop9CurrentLockedGateError(
            f"{label} must be an absolute normal path"
        )
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise Loop9CurrentLockedGateError(
            f"{label} must be inside the formal data root"
        ) from exc
    if resolved != path or not (resolved.is_file() or resolved.is_dir()):
        raise Loop9CurrentLockedGateError(f"{label} is unsafe")
    return PurePosixPath(relative.as_posix()).as_posix()


def _resolve_reference(
    root: Path,
    reference: object,
    *,
    label: str,
    directory: bool,
) -> Path:
    if (
        not isinstance(reference, str)
        or not reference
        or "\\" in reference
        or ":" in reference
    ):
        raise Loop9CurrentLockedGateError(f"{label} reference is unsafe")
    relative = PurePosixPath(reference)
    if (
        relative.is_absolute()
        or "." in relative.parts
        or ".." in relative.parts
    ):
        raise Loop9CurrentLockedGateError(f"{label} reference is unsafe")
    candidate = root / Path(relative.as_posix())
    if candidate.is_symlink() or _is_reparse_point(candidate):
        raise Loop9CurrentLockedGateError(f"{label} reference is unsafe")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise Loop9CurrentLockedGateError(
            f"{label} reference is unavailable"
        ) from exc
    if resolved != candidate or (
        directory and not resolved.is_dir()
    ) or (not directory and not resolved.is_file()):
        raise Loop9CurrentLockedGateError(f"{label} reference is unsafe")
    return resolved


def _write_once(path: Path, content: bytes) -> None:
    staged = path.parent / f".{path.name}.{uuid4().hex}.part"
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, path)
        except FileExistsError:
            if (
                path.is_symlink()
                or _is_reparse_point(path)
                or path.read_bytes() != content
            ):
                raise Loop9CurrentLockedGateError(
                    "existing current locked gate authority differs"
                ) from None
        except OSError as exc:
            raise Loop9CurrentLockedGateError(
                "current locked gate authority could not be committed"
            ) from exc
    except Loop9CurrentLockedGateError:
        raise
    except OSError as exc:
        raise Loop9CurrentLockedGateError(
            "current locked gate authority could not be committed"
        ) from exc
    finally:
        staged.unlink(missing_ok=True)


def _read_canonical_json(path: Path, *, label: str) -> dict[str, object]:
    if path.is_symlink() or _is_reparse_point(path):
        raise Loop9CurrentLockedGateError(f"{label} path is unsafe")
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except Loop9CurrentLockedGateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Loop9CurrentLockedGateError(
            f"{label} is unreadable"
        ) from exc
    if (
        resolved != path
        or not resolved.is_file()
        or not 2 <= len(content) <= _MAX_JSON_BYTES
        or not isinstance(payload, dict)
        or content != _canonical(payload) + b"\n"
    ):
        raise Loop9CurrentLockedGateError(f"{label} is not canonical")
    return cast(dict[str, object], payload)


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9CurrentLockedGateError(
                "current locked gate contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise Loop9CurrentLockedGateError(
        f"current locked gate contains non-finite JSON: {value}"
    )


@dataclass(frozen=True, slots=True)
class CurrentLockedGateAuthority:
    """Selection-scoped proof that the current 50-item machine gate passed."""

    selection_sha256: str
    source_batch_sha256: str
    source_build_sha256: str
    settlement_contract_sha256: str
    package_sha256: str
    human_review_seal_sha256: str
    machine_result_sha256: str
    machine_evaluation_sha256: str
    package_relative_path: str
    seal_relative_path: str
    machine_result_relative_path: str
    machine_evaluation_relative_path: str
    item_count: int = 50
    image_count: int = 100
    gate_passed: bool = True
    kind: str = "loop9_current_locked_gate"
    schema_version: int = SCHEMA_VERSION
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for value, label in (
            (self.selection_sha256, "locked selection"),
            (self.source_batch_sha256, "source batch"),
            (self.source_build_sha256, "source build"),
            (self.settlement_contract_sha256, "settlement contract"),
            (self.package_sha256, "human review package"),
            (self.human_review_seal_sha256, "human review seal"),
            (self.machine_result_sha256, "machine result"),
            (self.machine_evaluation_sha256, "machine evaluation"),
        ):
            _required_sha256(value, label=label)
        if (
            self.kind != "loop9_current_locked_gate"
            or self.schema_version != SCHEMA_VERSION
            or self.item_count != 50
            or self.image_count != 100
            or self.gate_passed is not True
        ):
            raise Loop9CurrentLockedGateError(
                "current locked gate did not pass"
            )
        for reference in (
            self.package_relative_path,
            self.seal_relative_path,
            self.machine_result_relative_path,
            self.machine_evaluation_relative_path,
        ):
            if (
                not isinstance(reference, str)
                or not reference
                or "\\" in reference
                or ":" in reference
                or PurePosixPath(reference).is_absolute()
                or "." in PurePosixPath(reference).parts
                or ".." in PurePosixPath(reference).parts
            ):
                raise Loop9CurrentLockedGateError(
                    "current locked gate evidence reference is unsafe"
                )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._payload_without_hash()),
        )

    def _payload_without_hash(self) -> dict[str, object]:
        return {
            "gate_passed": self.gate_passed,
            "human_review_seal_sha256": (
                self.human_review_seal_sha256
            ),
            "image_count": self.image_count,
            "item_count": self.item_count,
            "kind": self.kind,
            "machine_evaluation_relative_path": (
                self.machine_evaluation_relative_path
            ),
            "machine_evaluation_sha256": (
                self.machine_evaluation_sha256
            ),
            "machine_result_relative_path": (
                self.machine_result_relative_path
            ),
            "machine_result_sha256": self.machine_result_sha256,
            "package_relative_path": self.package_relative_path,
            "package_sha256": self.package_sha256,
            "schema_version": self.schema_version,
            "seal_relative_path": self.seal_relative_path,
            "selection_sha256": self.selection_sha256,
            "settlement_contract_sha256": (
                self.settlement_contract_sha256
            ),
            "source_batch_sha256": self.source_batch_sha256,
            "source_build_sha256": self.source_build_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._payload_without_hash(),
            "canonical_sha256": self.canonical_sha256,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> CurrentLockedGateAuthority:
        if not isinstance(value, Mapping):
            raise Loop9CurrentLockedGateError(
                "current locked gate manifest must be an object"
            )
        raw = dict(value)
        expected = {
            "canonical_sha256",
            "gate_passed",
            "human_review_seal_sha256",
            "image_count",
            "item_count",
            "kind",
            "machine_evaluation_relative_path",
            "machine_evaluation_sha256",
            "machine_result_relative_path",
            "machine_result_sha256",
            "package_relative_path",
            "package_sha256",
            "schema_version",
            "seal_relative_path",
            "selection_sha256",
            "settlement_contract_sha256",
            "source_batch_sha256",
            "source_build_sha256",
        }
        if set(raw) != expected:
            raise Loop9CurrentLockedGateError(
                "current locked gate manifest contract is invalid"
            )
        authority = cls(
            selection_sha256=cast(str, raw["selection_sha256"]),
            source_batch_sha256=cast(
                str,
                raw["source_batch_sha256"],
            ),
            source_build_sha256=cast(str, raw["source_build_sha256"]),
            settlement_contract_sha256=cast(
                str,
                raw["settlement_contract_sha256"],
            ),
            package_sha256=cast(str, raw["package_sha256"]),
            human_review_seal_sha256=cast(
                str,
                raw["human_review_seal_sha256"],
            ),
            machine_result_sha256=cast(
                str,
                raw["machine_result_sha256"],
            ),
            machine_evaluation_sha256=cast(
                str,
                raw["machine_evaluation_sha256"],
            ),
            package_relative_path=cast(
                str,
                raw["package_relative_path"],
            ),
            seal_relative_path=cast(str, raw["seal_relative_path"]),
            machine_result_relative_path=cast(
                str,
                raw["machine_result_relative_path"],
            ),
            machine_evaluation_relative_path=cast(
                str,
                raw["machine_evaluation_relative_path"],
            ),
            item_count=cast(int, raw["item_count"]),
            image_count=cast(int, raw["image_count"]),
            gate_passed=cast(bool, raw["gate_passed"]),
            kind=cast(str, raw["kind"]),
            schema_version=cast(int, raw["schema_version"]),
        )
        if raw["canonical_sha256"] != authority.canonical_sha256:
            raise Loop9CurrentLockedGateError(
                "current locked gate manifest integrity is invalid"
            )
        return authority


class CurrentLockedGateAuthorityStore:
    """Publish and replay one immutable Gate per locked selection."""

    def __init__(self, data_root: Path) -> None:
        self.data_root = _safe_root(data_root)
        verification = _safe_child(self.data_root, "verification")
        loop9 = _safe_child(verification, "loop9")
        self.root = _safe_child(loop9, "current-locked-gates")

    def _manifest_path(self, digest: str) -> Path:
        _required_sha256(digest, label="current locked gate")
        bucket = _safe_child(self.root, digest[:2])
        return bucket / f"{digest}.json"

    def _active_path(self, selection_sha256: str) -> Path:
        _required_sha256(selection_sha256, label="locked selection")
        return (
            self.root
            / f"active-current-locked-gate-{selection_sha256}.json"
        )

    def _replay(
        self,
        *,
        locked_selection: FormalShadowSelectionManifest,
        package_dir: Path,
        seal_path: Path,
        evaluation_path: Path,
    ) -> CurrentLockedGateAuthority:
        locked_selection.verify_integrity()
        if (
            locked_selection.target_kind
            is not ShadowBatchTargetKind.CURRENT_LOCKED_50
        ):
            raise Loop9CurrentLockedGateError(
                "current locked gate requires the 50-item selection"
            )
        package_reference = _relative_reference(
            self.data_root,
            package_dir,
            label="human review package",
        )
        seal_reference = _relative_reference(
            self.data_root,
            seal_path,
            label="human review seal",
        )
        evaluation_reference = _relative_reference(
            self.data_root,
            evaluation_path,
            label="machine truth evaluation",
        )
        try:
            package = load_loop9_review_package(package_dir)
            seal = _load_and_validate_seal(
                package=package,
                seal_path=seal_path,
            )
            evaluation = load_machine_truth_evaluation(
                evaluation_path
            )
        except Exception as exc:
            raise Loop9CurrentLockedGateError(
                "current locked gate evidence replay failed"
            ) from exc
        batch = locked_selection.batch_manifest
        if (
            package.source_batch.target_kind
            is not ShadowBatchTargetKind.CURRENT_LOCKED_50
            or package.formal_selection.to_payload()
            != locked_selection.to_payload()
            or package.source_batch.canonical_sha256
            != batch.canonical_sha256
            or package.source_batch.source_build_sha256
            != batch.source_build_sha256
            or package.source_batch.contract_canonical_sha256
            != batch.contract_canonical_sha256
            or package.payload.get("canonical_sha256")
            != evaluation.get("package_sha256")
            or seal.get("canonical_sha256")
            != evaluation.get("seal_sha256")
            or seal.get("review_count") != 50
            or seal.get("image_truth_count") != 100
            or seal.get("human_review_complete") is not True
            or cast(
                Mapping[str, object],
                seal.get("quality_coverage"),
            ).get("passed")
            is not True
        ):
            raise Loop9CurrentLockedGateError(
                "current locked gate human truth binding changed"
            )
        machine_result_sha256 = _required_sha256(
            evaluation.get("machine_result_sha256"),
            label="machine result",
        )
        machine_result_path = (
            self.data_root
            / "verification"
            / "loop9"
            / "machine-results"
            / machine_result_sha256[:2]
            / f"{machine_result_sha256}.json"
        )
        machine_result_reference = _relative_reference(
            self.data_root,
            machine_result_path,
            label="machine result",
        )
        try:
            machine_result = load_machine_result_manifest(
                machine_result_path
            )
            replayed = evaluate_sealed_machine_results(
                package_dir=package_dir,
                seal_path=seal_path,
                machine_result_path=machine_result_path,
            )
        except Exception as exc:
            raise Loop9CurrentLockedGateError(
                "current locked machine evaluation replay failed"
            ) from exc
        authority = machine_result.get("authority")
        source = machine_result.get("source")
        item_results = evaluation.get("item_results")
        expected_identities = {
            item.item_identity_sha256 for item in batch.items
        }
        observed_identities = (
            {
                value.get("item_identity_sha256")
                for value in item_results
                if isinstance(value, Mapping)
            }
            if isinstance(item_results, list)
            else set()
        )
        if (
            replayed != evaluation
            or not isinstance(authority, Mapping)
            or authority.get("current_loop9_build_sha256")
            != batch.source_build_sha256
            or evaluation.get("authority_sha256")
            != authority.get("authority_sha256")
            or not isinstance(source, Mapping)
            or source.get("formal_selection_sha256")
            != locked_selection.canonical_sha256
            or source.get("locked_gate_evidence_sha256") is not None
            or source.get("source_batch_sha256")
            != batch.canonical_sha256
            or source.get("source_build_sha256")
            != batch.source_build_sha256
            or evaluation.get("review_kind")
            != ShadowBatchTargetKind.CURRENT_LOCKED_50.value
            or evaluation.get("source_batch_sha256")
            != batch.canonical_sha256
            or evaluation.get("gate_passed") is not True
            or evaluation.get("item_count") != 50
            or evaluation.get("image_count") != 100
            or evaluation.get("runtime_observation_count") != 200
            or evaluation.get("technical_failure_count") != 0
            or evaluation.get("wrong_auto_pass_count") != 0
            or evaluation.get("high_confidence_role_error_count") != 0
            or observed_identities != expected_identities
            or len(cast(list[object], item_results)) != 50
        ):
            raise Loop9CurrentLockedGateError(
                "current locked machine gate did not pass"
            )
        return CurrentLockedGateAuthority(
            selection_sha256=locked_selection.canonical_sha256,
            source_batch_sha256=batch.canonical_sha256,
            source_build_sha256=batch.source_build_sha256,
            settlement_contract_sha256=(
                batch.contract_canonical_sha256
            ),
            package_sha256=cast(
                str,
                package.payload["canonical_sha256"],
            ),
            human_review_seal_sha256=cast(
                str,
                seal["canonical_sha256"],
            ),
            machine_result_sha256=machine_result_sha256,
            machine_evaluation_sha256=cast(
                str,
                evaluation["canonical_sha256"],
            ),
            package_relative_path=package_reference,
            seal_relative_path=seal_reference,
            machine_result_relative_path=machine_result_reference,
            machine_evaluation_relative_path=evaluation_reference,
        )

    def publish(
        self,
        *,
        locked_selection: FormalShadowSelectionManifest,
        package_dir: Path,
        seal_path: Path,
        evaluation_path: Path,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> CurrentLockedGateAuthority:
        expected_build = _required_sha256(
            expected_current_build_sha256,
            label="expected current build",
        )
        expected_contract = _required_sha256(
            expected_settlement_contract_sha256,
            label="expected settlement contract",
        )
        if (
            locked_selection.batch_manifest.source_build_sha256
            != expected_build
            or locked_selection.batch_manifest.contract_canonical_sha256
            != expected_contract
        ):
            raise Loop9CurrentLockedGateError(
                "current locked gate build or contract authority changed"
            )
        authority = self._replay(
            locked_selection=locked_selection,
            package_dir=package_dir,
            seal_path=seal_path,
            evaluation_path=evaluation_path,
        )
        content = _canonical(authority.to_payload()) + b"\n"
        _write_once(
            self._manifest_path(authority.canonical_sha256),
            content,
        )
        pointer_core = {
            "gate_evidence_sha256": authority.canonical_sha256,
            "kind": "loop9_current_locked_gate_target",
            "schema_version": SCHEMA_VERSION,
            "selection_sha256": authority.selection_sha256,
        }
        pointer = {
            **pointer_core,
            "canonical_sha256": _canonical_sha256(pointer_core),
        }
        _write_once(
            self._active_path(authority.selection_sha256),
            _canonical(pointer) + b"\n",
        )
        return self.load_for_selection(
            locked_selection=locked_selection,
            expected_current_build_sha256=expected_build,
            expected_settlement_contract_sha256=expected_contract,
        )

    def load_for_selection(
        self,
        *,
        locked_selection: FormalShadowSelectionManifest,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> CurrentLockedGateAuthority:
        locked_selection.verify_integrity()
        expected_build = _required_sha256(
            expected_current_build_sha256,
            label="expected current build",
        )
        expected_contract = _required_sha256(
            expected_settlement_contract_sha256,
            label="expected settlement contract",
        )
        pointer_path = self._active_path(
            locked_selection.canonical_sha256
        )
        if not pointer_path.is_file():
            raise Loop9CurrentLockedGateError(
                "current locked gate authority is unavailable"
            )
        pointer = _read_canonical_json(
            pointer_path,
            label="current locked gate target",
        )
        pointer_core = {
            key: value
            for key, value in pointer.items()
            if key != "canonical_sha256"
        }
        expected_pointer_fields = {
            "canonical_sha256",
            "gate_evidence_sha256",
            "kind",
            "schema_version",
            "selection_sha256",
        }
        if (
            set(pointer) != expected_pointer_fields
            or pointer.get("kind")
            != "loop9_current_locked_gate_target"
            or pointer.get("schema_version") != SCHEMA_VERSION
            or pointer.get("selection_sha256")
            != locked_selection.canonical_sha256
            or pointer.get("canonical_sha256")
            != _canonical_sha256(pointer_core)
        ):
            raise Loop9CurrentLockedGateError(
                "current locked gate target integrity is invalid"
            )
        gate_sha256 = _required_sha256(
            pointer.get("gate_evidence_sha256"),
            label="current locked gate evidence",
        )
        manifest_path = self._manifest_path(gate_sha256)
        manifest = CurrentLockedGateAuthority.from_payload(
            _read_canonical_json(
                manifest_path,
                label="current locked gate manifest",
            )
        )
        if (
            manifest.canonical_sha256 != gate_sha256
            or manifest.selection_sha256
            != locked_selection.canonical_sha256
            or manifest.source_batch_sha256
            != locked_selection.batch_manifest.canonical_sha256
            or manifest.source_build_sha256 != expected_build
            or manifest.settlement_contract_sha256 != expected_contract
        ):
            raise Loop9CurrentLockedGateError(
                "current locked gate build or selection binding changed"
            )
        replayed = self._replay(
            locked_selection=locked_selection,
            package_dir=_resolve_reference(
                self.data_root,
                manifest.package_relative_path,
                label="human review package",
                directory=True,
            ),
            seal_path=_resolve_reference(
                self.data_root,
                manifest.seal_relative_path,
                label="human review seal",
                directory=False,
            ),
            evaluation_path=_resolve_reference(
                self.data_root,
                manifest.machine_evaluation_relative_path,
                label="machine truth evaluation",
                directory=False,
            ),
        )
        if replayed != manifest:
            raise Loop9CurrentLockedGateError(
                "current locked gate replay does not reconcile"
            )
        return manifest
