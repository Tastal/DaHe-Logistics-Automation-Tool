from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from dahe.adapters.files.settlement_capture_manifest import (
    SettlementCaptureManifestStore,
    SettlementCaptureManifestStoreError,
)
from dahe.adapters.files.shadow_selection_lifecycle import (
    FormalSelectionLifecycleStore,
    FormalSelectionLifecycleStoreError,
)
from dahe.application.chengfeng.settlement_capture import (
    SettlementCaptureManifest,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalSelectionExclusionSnapshot,
    FormalShadowSelectionContractError,
    FormalShadowSelectionManifest,
    SelectionSeedAuthority,
    select_formal_shadow_batch,
)
from dahe.application.chengfeng.shadow_selection_lifecycle import (
    FormalSelectionLifecycleEvent,
    FormalSelectionLifecycleNode,
)
from dahe.verification.loop9_locked_gate import (
    CurrentLockedGateAuthority,
    CurrentLockedGateAuthorityStore,
    Loop9CurrentLockedGateError,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_SEED_NAME = "loop9-formal-selection-seed.key"


class FormalShadowSelectionStoreError(RuntimeError):
    """Raised when a formal selection authority cannot be trusted."""


class FormalShadowSelectionTransientStoreError(
    FormalShadowSelectionStoreError
):
    """Raised only for an explicit, potentially transient file I/O error."""


class CurrentLockedGateAuthorityReader(Protocol):
    def load_for_selection(
        self,
        *,
        locked_selection: FormalShadowSelectionManifest,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> CurrentLockedGateAuthority: ...


class SettlementCaptureAuthorityReader(Protocol):
    def load(
        self,
        canonical_sha256: str,
    ) -> SettlementCaptureManifest: ...


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(
        attributes
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _manifest_content(
    manifest: FormalShadowSelectionManifest,
) -> bytes:
    return _canonical(manifest.to_payload()) + b"\n"


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FormalShadowSelectionStoreError(
                "formal selection contains duplicate fields"
            )
        result[key] = value
    return result


def _safe_data_root(data_root: Path) -> Path:
    if (
        not isinstance(data_root, Path)
        or not data_root.is_absolute()
        or data_root.is_symlink()
        or _is_reparse_point(data_root)
    ):
        raise FormalShadowSelectionStoreError(
            "data root must be an absolute normal directory"
        )
    root = data_root.resolve(strict=True)
    if root != data_root or not root.is_dir():
        raise FormalShadowSelectionStoreError(
            "data root must be an absolute normal directory"
        )
    return root


def _safe_child(root: Path, name: str) -> Path:
    child = root / name
    if child.exists() and (
        child.is_symlink() or _is_reparse_point(child)
    ):
        raise FormalShadowSelectionStoreError(
            "formal selection storage is unsafe"
        )
    child.mkdir(mode=0o700, parents=False, exist_ok=True)
    resolved = child.resolve(strict=True)
    if (
        resolved != child
        or resolved.parent != root
        or not resolved.is_dir()
        or _is_reparse_point(resolved)
    ):
        raise FormalShadowSelectionStoreError(
            "formal selection storage is unsafe"
        )
    return resolved


def _write_once(path: Path, content: bytes) -> None:
    staged = path.parent / f".{uuid4().hex}.part"
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, path)
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != content:
                raise FormalShadowSelectionStoreError(
                    "existing formal selection authority differs"
                ) from None
    except FormalShadowSelectionStoreError:
        raise
    except OSError as exc:
        raise FormalShadowSelectionTransientStoreError(
            "formal selection authority could not be committed"
        ) from exc
    finally:
        staged.unlink(missing_ok=True)


def _load_seed(path: Path) -> SelectionSeedAuthority:
    if path.exists() and (
        path.is_symlink() or _is_reparse_point(path)
    ):
        raise FormalShadowSelectionStoreError(
            "formal selection seed authority is unsafe"
        )
    if not path.exists():
        raw = secrets.token_bytes(32)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except FileExistsError:
            pass
        except OSError as exc:
            raise FormalShadowSelectionTransientStoreError(
                "formal selection seed authority could not be created"
            ) from exc
        else:
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(path, 0o600)
            except OSError as exc:
                path.unlink(missing_ok=True)
                raise FormalShadowSelectionTransientStoreError(
                    "formal selection seed authority could not be committed"
                ) from exc
    try:
        before = path.stat()
        content = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise FormalShadowSelectionTransientStoreError(
            "formal selection seed authority is unavailable"
        ) from exc
    if (
        path.is_symlink()
        or _is_reparse_point(path)
        or not path.is_file()
        or path.resolve(strict=True) != path
        or len(content) != 32
        or before.st_size != 32
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise FormalShadowSelectionStoreError(
            "formal selection seed authority is invalid"
        )
    try:
        return SelectionSeedAuthority(seed=content)
    except FormalShadowSelectionContractError as exc:
        raise FormalShadowSelectionStoreError(
            "formal selection seed authority is invalid"
        ) from exc


class FormalShadowSelectionStore:
    """Own the stable policy/seed and immutable exact target selections."""

    def __init__(
        self,
        data_root: Path,
        *,
        gate_authority_store: CurrentLockedGateAuthorityReader | None = None,
        capture_authority_store: (
            SettlementCaptureAuthorityReader | None
        ) = None,
    ) -> None:
        root = _safe_data_root(data_root)
        self.data_root = root
        self.root = _safe_child(root, "loop9-formal-selections")
        secret_root = _safe_child(root, "secrets")
        self._seed_authority = _load_seed(secret_root / _SEED_NAME)
        self._lifecycle = FormalSelectionLifecycleStore(root)
        self._gate_authority = (
            gate_authority_store or CurrentLockedGateAuthorityStore(root)
        )
        self._capture_authority = (
            capture_authority_store
            or SettlementCaptureManifestStore(root)
        )

    @property
    def seed_authority_sha256(self) -> str:
        return self._seed_authority.authority_sha256

    def _manifest_path(self, canonical_sha256: str) -> Path:
        if _SHA256.fullmatch(canonical_sha256) is None:
            raise FormalShadowSelectionStoreError(
                "formal selection identity is invalid"
            )
        path = self.root / f"{canonical_sha256}.json"
        if (
            path.parent != self.root
            or path.is_symlink()
            or (path.exists() and _is_reparse_point(path))
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection path is unsafe"
            )
        return path

    def _active_path(self, target_kind: ShadowBatchTargetKind) -> Path:
        if not isinstance(target_kind, ShadowBatchTargetKind):
            raise FormalShadowSelectionStoreError(
                "formal selection target is invalid"
            )
        return self.root / f"active-{target_kind.value}.json"

    def _read_manifest(
        self,
        canonical_sha256: str,
    ) -> FormalShadowSelectionManifest:
        path = self._manifest_path(canonical_sha256)
        if (
            not path.is_file()
            or path.is_symlink()
            or _is_reparse_point(path)
            or path.resolve(strict=True).parent != self.root
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection manifest is unavailable"
            )
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise FormalShadowSelectionTransientStoreError(
                "formal selection manifest could not be read"
            ) from exc
        try:
            payload = json.loads(
                content,
                object_pairs_hook=_reject_duplicate_keys,
            )
            manifest = FormalShadowSelectionManifest.from_payload(payload)
        except FormalShadowSelectionStoreError:
            raise
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            FormalShadowSelectionContractError,
            ValueError,
        ) as exc:
            raise FormalShadowSelectionStoreError(
                "formal selection manifest integrity is invalid"
            ) from exc
        if (
            not content
            or len(content) > _MAX_MANIFEST_BYTES
            or manifest.canonical_sha256 != canonical_sha256
            or content != _manifest_content(manifest)
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection manifest integrity is invalid"
            )
        return manifest

    def load_manifest(
        self,
        canonical_sha256: str,
    ) -> FormalShadowSelectionManifest:
        """Load one immutable selection by its exact content address."""

        manifest = self._read_manifest(canonical_sha256)
        if (
            manifest.selection_seed_authority_sha256
            != self.seed_authority_sha256
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection belongs to another seed authority"
            )
        self._verify_capture_authority(manifest)
        return manifest

    def _load_trusted_capture(
        self,
        canonical_sha256: str,
    ) -> SettlementCaptureManifest:
        try:
            capture = self._capture_authority.load(canonical_sha256)
        except SettlementCaptureManifestStoreError as exc:
            raise FormalShadowSelectionStoreError(
                "formal selection source capture is unavailable"
            ) from exc
        if capture.canonical_sha256 != canonical_sha256:
            raise FormalShadowSelectionStoreError(
                "formal selection source capture changed"
            )
        return capture

    def _verify_capture_authority(
        self,
        manifest: FormalShadowSelectionManifest,
    ) -> None:
        capture = self._load_trusted_capture(
            manifest.source_capture_sha256
        )
        batch = manifest.batch_manifest
        capture_items = {
            item.item_identity_sha256: item
            for item in capture.items
        }
        if (
            batch.source_capture_sha256
            != capture.canonical_sha256
            or batch.source_build_sha256
            != capture.source_build_sha256
            or batch.contract_canonical_sha256
            != capture.contract_canonical_sha256
            or batch.contract_file_sha256
            != capture.contract_file_sha256
            or batch.contract_selection_sha256
            != capture.contract_selection_sha256
            or batch.identity_context_sha256
            != capture.identity_context_sha256
            or batch.sources != capture.sources
            or batch.request_audit_sha256
            != capture.request_audit_sha256
            or batch.request_audit_counts
            != capture.request_audit_counts
            or any(
                capture_items.get(item.item_identity_sha256) != item
                for item in batch.items
            )
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection source capture changed"
            )

    def _load_active(
        self,
        target_kind: ShadowBatchTargetKind,
    ) -> FormalShadowSelectionManifest | None:
        path = self._active_path(target_kind)
        if not path.exists():
            return None
        if (
            not path.is_file()
            or path.is_symlink()
            or _is_reparse_point(path)
            or path.resolve(strict=True).parent != self.root
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection target authority is unsafe"
            )
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise FormalShadowSelectionTransientStoreError(
                "formal selection target authority could not be read"
            ) from exc
        try:
            document = json.loads(
                content,
                object_pairs_hook=_reject_duplicate_keys,
            )
        except FormalShadowSelectionStoreError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FormalShadowSelectionStoreError(
                "formal selection target authority is invalid"
            ) from exc
        expected = {
            "canonical_sha256",
            "kind",
            "selection_sha256",
            "selection_seed_authority_sha256",
            "source_capture_sha256",
            "target_kind",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise FormalShadowSelectionStoreError(
                "formal selection target authority is invalid"
            )
        body = {
            key: value
            for key, value in document.items()
            if key != "canonical_sha256"
        }
        declared = document.get("canonical_sha256")
        selection_sha = document.get("selection_sha256")
        if (
            document.get("kind") != "loop9_formal_selection_target"
            or document.get("target_kind") != target_kind.value
            or document.get("selection_seed_authority_sha256")
            != self.seed_authority_sha256
            or not isinstance(declared, str)
            or declared != hashlib.sha256(_canonical(body)).hexdigest()
            or not isinstance(selection_sha, str)
            or _SHA256.fullmatch(selection_sha) is None
            or content != _canonical(document) + b"\n"
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection target authority is invalid"
            )
        manifest = self.load_manifest(selection_sha)
        if (
            manifest.target_kind is not target_kind
            or manifest.source_capture_sha256
            != document.get("source_capture_sha256")
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection target authority is invalid"
            )
        return manifest

    def _lifecycle_tip_for_existing(
        self,
        existing: FormalShadowSelectionManifest | None,
    ) -> FormalSelectionLifecycleNode | None:
        try:
            state = self._lifecycle.load_state()
            if state is None and existing is not None:
                self._lifecycle.bootstrap_current_locked_selection(existing)
            tip = self._lifecycle.load_tip()
        except FormalSelectionLifecycleStoreError as exc:
            raise FormalShadowSelectionStoreError(str(exc)) from exc
        if tip is not None and existing is None:
            raise FormalShadowSelectionStoreError(
                "formal selection target authority is unavailable"
            )
        return tip

    @staticmethod
    def _verify_lifecycle_manifest_binding(
        *,
        manifest: FormalShadowSelectionManifest,
        tip: FormalSelectionLifecycleNode,
    ) -> None:
        batch = manifest.batch_manifest
        if (
            tip.selection_sha256 != manifest.canonical_sha256
            or tip.source_build_sha256 != batch.source_build_sha256
            or tip.pipeline_fingerprint != batch.pipeline_fingerprint
            or tip.identity_context_sha256 != batch.identity_context_sha256
            or tip.exclusion_authority_sha256
            != manifest.full_history_exclusion_authority_sha256
            or tip.exclusion_child_head_sha256
            != manifest.exclusion_child_index_head_sha256
        ):
            raise FormalShadowSelectionStoreError(
                "formal selection lifecycle binding is inconsistent"
            )

    def load_active_current_locked_manifest(
        self,
        canonical_sha256: str,
    ) -> FormalShadowSelectionManifest:
        """Load only the exact current locked generation that remains active."""

        existing = self._load_active(
            ShadowBatchTargetKind.CURRENT_LOCKED_50
        )
        tip = self._lifecycle_tip_for_existing(existing)
        if (
            tip is None
            or tip.event_kind is not FormalSelectionLifecycleEvent.ACTIVATED
            or tip.selection_sha256 != canonical_sha256
        ):
            raise FormalShadowSelectionStoreError(
                "formal locked selection is not the active lifecycle generation"
            )
        manifest = self.load_manifest(canonical_sha256)
        if manifest.target_kind is not ShadowBatchTargetKind.CURRENT_LOCKED_50:
            raise FormalShadowSelectionStoreError(
                "formal locked selection target is invalid"
            )
        self._verify_lifecycle_manifest_binding(
            manifest=manifest,
            tip=tip,
        )
        return manifest

    def _load_current_locked_active(
        self,
    ) -> FormalShadowSelectionManifest | None:
        existing = self._load_active(
            ShadowBatchTargetKind.CURRENT_LOCKED_50
        )
        tip = self._lifecycle_tip_for_existing(existing)
        if tip is None:
            return None
        if tip.event_kind is FormalSelectionLifecycleEvent.INVALIDATED:
            raise FormalShadowSelectionStoreError(
                "formal locked selection is invalidated"
            )
        return self.load_active_current_locked_manifest(
            tip.selection_sha256
        )

    def _load_gate_for_locked_selection(
        self,
        *,
        locked: FormalShadowSelectionManifest,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> CurrentLockedGateAuthority:
        try:
            return self._gate_authority.load_for_selection(
                locked_selection=locked,
                expected_current_build_sha256=(
                    expected_current_build_sha256
                ),
                expected_settlement_contract_sha256=(
                    expected_settlement_contract_sha256
                ),
            )
        except Loop9CurrentLockedGateError as exc:
            raise FormalShadowSelectionStoreError(str(exc)) from exc

    def require_current_locked_gate(
        self,
        *,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> CurrentLockedGateAuthority:
        """Replay the Gate for the one currently active locked generation."""

        locked = self._load_current_locked_active()
        if locked is None:
            raise FormalShadowSelectionStoreError(
                "locked selection authority is unavailable"
            )
        return self._load_gate_for_locked_selection(
            locked=locked,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
        )

    def load(
        self,
        target_kind: ShadowBatchTargetKind,
    ) -> FormalShadowSelectionManifest:
        if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
            manifest = self._load_current_locked_active()
            if manifest is None:
                raise FormalShadowSelectionStoreError(
                    "formal selection target authority is unavailable"
                )
            return manifest
        locked = self._load_current_locked_active()
        if locked is None:
            raise FormalShadowSelectionStoreError(
                "locked selection authority is unavailable"
            )
        manifest = self._load_active(target_kind)
        if manifest is None:
            raise FormalShadowSelectionStoreError(
                "formal selection target authority is unavailable"
            )
        if manifest.prior_selection_sha256s != (
            locked.canonical_sha256,
        ):
            raise FormalShadowSelectionStoreError(
                "real shadow selection belongs to another locked generation"
            )
        gate = self._load_gate_for_locked_selection(
            locked=locked,
            expected_current_build_sha256=(
                manifest.batch_manifest.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                manifest.batch_manifest.contract_canonical_sha256
            ),
        )
        if (
            manifest.locked_gate_evidence_sha256
            != gate.canonical_sha256
        ):
            raise FormalShadowSelectionStoreError(
                "real shadow selection locked gate binding changed"
            )
        return manifest

    def load_active_real_shadow_manifest(
        self,
        canonical_sha256: str,
        *,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> FormalShadowSelectionManifest:
        """Load active real-30 only against current external authorities."""

        active = self._load_active(
            ShadowBatchTargetKind.REAL_SHADOW_30
        )
        if (
            active is None
            or active.canonical_sha256 != canonical_sha256
        ):
            raise FormalShadowSelectionStoreError(
                "real shadow selection is not the active target"
            )
        locked = self._load_current_locked_active()
        if locked is None:
            raise FormalShadowSelectionStoreError(
                "locked selection authority is unavailable"
            )
        if active.prior_selection_sha256s != (
            locked.canonical_sha256,
        ):
            raise FormalShadowSelectionStoreError(
                "real shadow selection belongs to another locked generation"
            )
        gate = self._load_gate_for_locked_selection(
            locked=locked,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
        )
        if active.locked_gate_evidence_sha256 != gate.canonical_sha256:
            raise FormalShadowSelectionStoreError(
                "real shadow selection locked gate binding changed"
            )
        return active

    def select(
        self,
        *,
        capture: SettlementCaptureManifest,
        target_kind: ShadowBatchTargetKind,
        pipeline_fingerprint: str,
        exclusion_snapshot: FormalSelectionExclusionSnapshot,
        expected_current_build_sha256: str | None = None,
        expected_settlement_contract_sha256: str | None = None,
    ) -> FormalShadowSelectionManifest:
        capture.verify_integrity()
        trusted_capture = self._load_trusted_capture(
            capture.canonical_sha256
        )
        if trusted_capture != capture:
            raise FormalShadowSelectionStoreError(
                "formal selection source capture changed"
            )
        capture = trusted_capture
        if not isinstance(
            exclusion_snapshot,
            FormalSelectionExclusionSnapshot,
        ):
            raise FormalShadowSelectionStoreError(
                "verified full-history exclusion snapshot is required"
            )
        locked: FormalShadowSelectionManifest | None = None
        locked_gate: CurrentLockedGateAuthority | None = None
        tip: FormalSelectionLifecycleNode | None = None
        if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
            if (
                expected_current_build_sha256 is not None
                or expected_settlement_contract_sha256 is not None
            ):
                raise FormalShadowSelectionStoreError(
                    "locked selection must not receive real-shadow authorities"
                )
            legacy_existing = self._load_active(target_kind)
            tip = self._lifecycle_tip_for_existing(legacy_existing)
            if (
                tip is not None
                and tip.event_kind
                is FormalSelectionLifecycleEvent.ACTIVATED
            ):
                existing = self.load_active_current_locked_manifest(
                    tip.selection_sha256
                )
            elif tip is None:
                existing = None
            else:
                existing = None
        else:
            if (
                expected_current_build_sha256 is None
                or expected_settlement_contract_sha256 is None
                or capture.source_build_sha256
                != expected_current_build_sha256
                or capture.contract_canonical_sha256
                != expected_settlement_contract_sha256
            ):
                raise FormalShadowSelectionStoreError(
                    "real shadow current build or contract authority changed"
                )
            locked = self._load_current_locked_active()
            if locked is None:
                raise FormalShadowSelectionStoreError(
                    "locked selection authority is unavailable"
                )
            locked_gate = self._load_gate_for_locked_selection(
                locked=locked,
                expected_current_build_sha256=(
                    expected_current_build_sha256
                ),
                expected_settlement_contract_sha256=(
                    expected_settlement_contract_sha256
                ),
            )
            existing = self._load_active(target_kind)
        if existing is not None:
            if (
                existing.source_capture_sha256
                != capture.canonical_sha256
                or existing.batch_manifest.pipeline_fingerprint
                != pipeline_fingerprint
                or existing.full_history_exclusion_authority_sha256
                != exclusion_snapshot.authority_sha256
                or existing.exclusion_child_index_head_sha256
                != exclusion_snapshot.child_index_head_sha256
                or (
                    target_kind is ShadowBatchTargetKind.REAL_SHADOW_30
                    and (
                        locked is None
                        or existing.prior_selection_sha256s
                        != (locked.canonical_sha256,)
                        or locked_gate is None
                        or existing.locked_gate_evidence_sha256
                        != locked_gate.canonical_sha256
                    )
                )
            ):
                raise FormalShadowSelectionStoreError(
                    "formal selection target belongs to another capture"
                )
            return existing

        prior: tuple[FormalShadowSelectionManifest, ...]
        if target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
            assert locked is not None
            assert locked_gate is not None
            prior = (locked,)
        else:
            prior = ()
        try:
            manifest = select_formal_shadow_batch(
                capture=capture,
                target_kind=target_kind,
                pipeline_fingerprint=pipeline_fingerprint,
                seed_authority=self._seed_authority,
                exclusion_snapshot=exclusion_snapshot,
                prior_selections=prior,
                locked_gate_evidence_sha256=(
                    locked_gate.canonical_sha256
                    if locked_gate is not None
                    else None
                ),
            )
        except FormalShadowSelectionContractError as exc:
            raise FormalShadowSelectionStoreError(str(exc)) from exc

        manifest_content = _manifest_content(manifest)
        _write_once(
            self._manifest_path(manifest.canonical_sha256),
            manifest_content,
        )
        if (
            target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50
            and tip is not None
            and tip.event_kind
            is FormalSelectionLifecycleEvent.INVALIDATED
        ):
            try:
                self._lifecycle.activate_replacement(
                    selection=manifest,
                    exclusion_snapshot=exclusion_snapshot,
                )
            except FormalSelectionLifecycleStoreError as exc:
                raise FormalShadowSelectionStoreError(str(exc)) from exc
            return self.load_active_current_locked_manifest(
                manifest.canonical_sha256
            )
        active_body = {
            "kind": "loop9_formal_selection_target",
            "selection_sha256": manifest.canonical_sha256,
            "selection_seed_authority_sha256": (
                self.seed_authority_sha256
            ),
            "source_capture_sha256": capture.canonical_sha256,
            "target_kind": target_kind.value,
        }
        active = {
            **active_body,
            "canonical_sha256": hashlib.sha256(
                _canonical(active_body)
            ).hexdigest(),
        }
        _write_once(
            self._active_path(target_kind),
            _canonical(active) + b"\n",
        )
        if target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50:
            try:
                self._lifecycle.bootstrap_current_locked_selection(
                    manifest
                )
            except FormalSelectionLifecycleStoreError as exc:
                raise FormalShadowSelectionStoreError(str(exc)) from exc
        return self.load(target_kind)
