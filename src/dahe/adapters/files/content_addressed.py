from __future__ import annotations

import hashlib
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class EvidenceIntegrityError(RuntimeError):
    """Raised when a stored object no longer matches its content identity."""


class InvalidEvidenceIdentityError(ValueError):
    """Raised when a caller supplies a non-canonical SHA-256 identity."""


@dataclass(frozen=True, slots=True)
class StoredEvidence:
    sha256: str
    relative_path: str
    byte_size: int
    media_type: str


@dataclass(frozen=True, slots=True)
class StagingRecoveryReport:
    removed_count: int


class ContentAddressedEvidenceStore:
    """Persist immutable evidence below a caller-owned root."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.objects_root = self.root / "sha256"
        self.staging_root = self.root / ".staging"
        self.objects_root.mkdir(parents=True, exist_ok=True)
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()

    @staticmethod
    def _validate_identity(sha256: str) -> None:
        if _SHA256_PATTERN.fullmatch(sha256) is None:
            raise InvalidEvidenceIdentityError("evidence identity must be lowercase SHA-256")

    def _relative_path(self, sha256: str) -> Path:
        self._validate_identity(sha256)
        return Path("sha256") / sha256[:2] / sha256[2:4] / f"{sha256}.blob"

    def path_for(self, sha256: str) -> Path:
        candidate = (self.root / self._relative_path(sha256)).resolve()
        if not candidate.is_relative_to(self.root):
            raise InvalidEvidenceIdentityError("evidence path escaped its storage root")
        return candidate

    def put_bytes(
        self,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
    ) -> StoredEvidence:
        sha256 = hashlib.sha256(content).hexdigest()
        relative_path = self._relative_path(sha256)
        target = self.root / relative_path
        with self._write_lock:
            if target.exists():
                self.read_bytes(sha256)
                return StoredEvidence(
                    sha256=sha256,
                    relative_path=relative_path.as_posix(),
                    byte_size=len(content),
                    media_type=media_type,
                )

            target.parent.mkdir(parents=True, exist_ok=True)
            staged = self.staging_root / f"{uuid4().hex}.part"
            try:
                with staged.open("xb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(staged, target)
            finally:
                staged.unlink(missing_ok=True)

        return StoredEvidence(
            sha256=sha256,
            relative_path=relative_path.as_posix(),
            byte_size=len(content),
            media_type=media_type,
        )

    def read_bytes(self, sha256: str) -> bytes:
        path = self.path_for(sha256)
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise EvidenceIntegrityError("evidence object is missing or unreadable") from exc
        if hashlib.sha256(content).hexdigest() != sha256:
            raise EvidenceIntegrityError("evidence object does not match its SHA-256 identity")
        return content

    def recover_staging(self) -> StagingRecoveryReport:
        removed = 0
        with self._write_lock:
            for candidate in self.staging_root.iterdir():
                if not candidate.is_file():
                    continue
                candidate.unlink()
                removed += 1
        return StagingRecoveryReport(removed_count=removed)
