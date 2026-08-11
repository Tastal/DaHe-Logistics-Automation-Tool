from __future__ import annotations

import json
import os
import re
from pathlib import Path
from uuid import uuid4

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 32 * 1024 * 1024


class ShadowBatchManifestStoreError(RuntimeError):
    """Raised when an immutable shadow-batch manifest cannot be trusted."""


class ShadowBatchManifestTransientStoreError(
    ShadowBatchManifestStoreError
):
    """Raised only for an explicit, potentially transient file I/O error."""


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ShadowBatchManifestStoreError(
                "shadow batch manifest contains duplicate fields"
            )
        result[key] = value
    return result


def _canonical_content(manifest: ChengfengShadowBatchManifest) -> bytes:
    return (
        json.dumps(
            manifest.to_payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


class ShadowBatchManifestStore:
    """Store immutable batch manifests under their canonical identity."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _validate_sha256(value: str) -> None:
        if _SHA256.fullmatch(value) is None:
            raise ShadowBatchManifestStoreError(
                "shadow batch identity must be lowercase SHA-256"
            )

    def path_for(self, canonical_sha256: str) -> Path:
        self._validate_sha256(canonical_sha256)
        candidate = (self.root / f"{canonical_sha256}.json").resolve()
        if candidate.parent != self.root:
            raise ShadowBatchManifestStoreError(
                "shadow batch path escaped its storage root"
            )
        return candidate

    def seal(
        self,
        manifest: ChengfengShadowBatchManifest,
    ) -> ChengfengShadowBatchManifest:
        manifest.verify_integrity()
        content = _canonical_content(manifest)
        target = self.path_for(manifest.canonical_sha256)
        if target.exists():
            if target.is_symlink() or target.read_bytes() != content:
                raise ShadowBatchManifestStoreError(
                    "existing shadow batch manifest differs"
                )
            return self.load(manifest.canonical_sha256)
        staged = self.root / f".{uuid4().hex}.part"
        try:
            with staged.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staged, target)
        except OSError as exc:
            raise ShadowBatchManifestTransientStoreError(
                "shadow batch manifest could not be committed"
            ) from exc
        finally:
            staged.unlink(missing_ok=True)
        return manifest

    def load(
        self,
        canonical_sha256: str,
    ) -> ChengfengShadowBatchManifest:
        path = self.path_for(canonical_sha256)
        if (
            not path.is_file()
            or path.is_symlink()
            or path.resolve().parent != self.root
        ):
            raise ShadowBatchManifestStoreError(
                "shadow batch manifest is unavailable"
            )
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ShadowBatchManifestTransientStoreError(
                "shadow batch manifest is unreadable"
            ) from exc
        if not content or len(content) > _MAX_MANIFEST_BYTES:
            raise ShadowBatchManifestStoreError(
                "shadow batch manifest size is invalid"
            )
        try:
            payload = json.loads(
                content,
                object_pairs_hook=_reject_duplicate_keys,
            )
            manifest = ChengfengShadowBatchManifest.from_payload(payload)
        except ShadowBatchManifestStoreError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ShadowBatchManifestStoreError(
                "shadow batch manifest contract is invalid"
            ) from exc
        if (
            manifest.canonical_sha256 != canonical_sha256
            or content != _canonical_content(manifest)
        ):
            raise ShadowBatchManifestStoreError(
                "shadow batch manifest is not canonical"
            )
        return manifest


class ContentAddressedShadowImageReader:
    """Read only content-addressed image evidence under the application root."""

    def __init__(self, evidence_store: ContentAddressedEvidenceStore) -> None:
        self._evidence_store = evidence_store

    def read_verified_image(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
    ) -> bytes:
        expected = (
            f"sha256/{expected_sha256[:2]}/{expected_sha256[2:4]}/"
            f"{expected_sha256}.blob"
        )
        if relative_path != expected:
            raise ShadowBatchManifestStoreError(
                "shadow image path does not match its content identity"
            )
        return self._evidence_store.read_bytes(expected_sha256)
