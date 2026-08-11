from __future__ import annotations

import json
import os
import re
from pathlib import Path
from uuid import uuid4

from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditError,
    PlatformReadAuditEvidenceStore,
)
from dahe.application.chengfeng.settlement_capture import (
    SCHEMA_VERSION,
    SettlementCaptureContractError,
    SettlementCaptureManifest,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024


class SettlementCaptureManifestStoreError(RuntimeError):
    """Raised when an immutable settlement capture cannot be trusted."""


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SettlementCaptureManifestStoreError(
                "settlement capture contains duplicate fields"
            )
        result[key] = value
    return result


def _canonical_content(manifest: SettlementCaptureManifest) -> bytes:
    return (
        json.dumps(
            manifest.to_payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _safe_root(data_root: Path) -> Path:
    if (
        not isinstance(data_root, Path)
        or not data_root.is_absolute()
        or data_root.is_symlink()
    ):
        raise SettlementCaptureManifestStoreError(
            "data root must be an absolute normal directory"
        )
    root = data_root.resolve(strict=True)
    if root != data_root or not root.is_dir():
        raise SettlementCaptureManifestStoreError(
            "data root must be an absolute normal directory"
        )
    target = root / "loop9-settlement-captures"
    if target.is_symlink():
        raise SettlementCaptureManifestStoreError(
            "settlement capture directory is unsafe"
        )
    target.mkdir(parents=False, exist_ok=True)
    resolved = target.resolve(strict=True)
    if resolved.parent != root or resolved != target or not resolved.is_dir():
        raise SettlementCaptureManifestStoreError(
            "settlement capture directory is unsafe"
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
                raise SettlementCaptureManifestStoreError(
                    "existing settlement capture manifest differs"
                ) from None
    except SettlementCaptureManifestStoreError:
        raise
    except OSError as exc:
        raise SettlementCaptureManifestStoreError(
            "settlement capture manifest could not be committed"
        ) from exc
    finally:
        staged.unlink(missing_ok=True)


class SettlementCaptureManifestStore:
    """Store outward-safe complete captures under their canonical identity."""

    def __init__(self, data_root: Path) -> None:
        self.root = _safe_root(data_root)
        self._request_audit = PlatformReadAuditEvidenceStore(data_root)

    @staticmethod
    def _validate_sha256(value: str) -> None:
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise SettlementCaptureManifestStoreError(
                "settlement capture identity must be lowercase SHA-256"
            )

    def path_for(self, canonical_sha256: str) -> Path:
        self._validate_sha256(canonical_sha256)
        candidate = self.root / f"{canonical_sha256}.json"
        if candidate.parent != self.root or candidate.is_symlink():
            raise SettlementCaptureManifestStoreError(
                "settlement capture path is unsafe"
            )
        return candidate

    def seal(self, manifest: SettlementCaptureManifest) -> Path:
        if not isinstance(manifest, SettlementCaptureManifest):
            raise SettlementCaptureManifestStoreError(
                "settlement capture manifest is invalid"
            )
        manifest.verify_integrity()
        content = _canonical_content(manifest)
        target = self.path_for(manifest.canonical_sha256)
        if target.exists():
            if target.is_symlink() or target.read_bytes() != content:
                raise SettlementCaptureManifestStoreError(
                    "existing settlement capture manifest differs"
                )
            self.load(manifest.canonical_sha256)
            return target
        _write_once(target, content)
        self.load(manifest.canonical_sha256)
        return target

    def load(self, canonical_sha256: str) -> SettlementCaptureManifest:
        path = self.path_for(canonical_sha256)
        if (
            not path.is_file()
            or path.is_symlink()
            or path.resolve(strict=True).parent != self.root
        ):
            raise SettlementCaptureManifestStoreError(
                "settlement capture manifest is unavailable"
            )
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise SettlementCaptureManifestStoreError(
                "settlement capture manifest is unreadable"
            ) from exc
        if not content or len(content) > _MAX_MANIFEST_BYTES:
            raise SettlementCaptureManifestStoreError(
                "settlement capture manifest size is invalid"
            )
        try:
            payload = json.loads(
                content,
                object_pairs_hook=_reject_duplicate_keys,
            )
            manifest = SettlementCaptureManifest.from_payload(payload)
        except SettlementCaptureManifestStoreError:
            raise
        except (
            SettlementCaptureContractError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise SettlementCaptureManifestStoreError(
                "settlement capture manifest integrity is invalid"
            ) from exc
        if (
            manifest.canonical_sha256 != canonical_sha256
            or content != _canonical_content(manifest)
        ):
            raise SettlementCaptureManifestStoreError(
                "settlement capture manifest integrity is invalid"
            )
        if manifest.schema_version == SCHEMA_VERSION:
            assert manifest.request_audit_sha256 is not None
            assert manifest.request_audit_counts is not None
            try:
                audit = self._request_audit.load(
                    manifest.request_audit_sha256,
                    expected_job_id=manifest.source_job_id,
                    expected_authority=PlatformReadAuditAuthority(
                        build_sha256=manifest.source_build_sha256,
                        settlement_contract_sha256=(
                            manifest.contract_canonical_sha256
                        ),
                        settlement_contract_selection_sha256=(
                            manifest.contract_selection_sha256
                        ),
                    ),
                )
            except PlatformReadAuditError as exc:
                raise SettlementCaptureManifestStoreError(
                    "settlement capture request audit is unavailable"
                ) from exc
            audit_payload = audit.to_payload()
            audit_payload.pop("canonical_sha256")
            expected_purpose = {
                "formal_locked_set": "current_locked_50",
                "production_shadow": "real_shadow_30",
            }.get(
                manifest.access_window_lineage.purpose
                if manifest.access_window_lineage is not None
                else ""
            )
            if (
                audit.purpose != expected_purpose
                or audit_payload != manifest.request_audit_counts
            ):
                raise SettlementCaptureManifestStoreError(
                    "settlement capture request audit changed"
                )
        return manifest
