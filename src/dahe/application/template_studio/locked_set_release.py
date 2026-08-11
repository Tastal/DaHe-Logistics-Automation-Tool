from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dahe.adapters.sqlite.locked_set import (
    LockedSetDatasetRecord,
    LockedSetPreflightAttestationRecord,
    PersistedExclusionSnapshot,
    SqliteLockedSetRepository,
)
from dahe.verification.locked_set import (
    LockedSetReleaseAttestation,
    load_locked_set_manifest_for_development,
    preflight_locked_set_release,
)


@dataclass(frozen=True, slots=True)
class PreparedLockedSetPreflight:
    dataset: LockedSetDatasetRecord
    snapshot: PersistedExclusionSnapshot
    attestation: LockedSetReleaseAttestation


@dataclass(frozen=True, slots=True)
class LockedSetReleaseResult:
    dataset: LockedSetDatasetRecord
    snapshot: PersistedExclusionSnapshot
    attestation: LockedSetPreflightAttestationRecord
    applied: bool


class LockedSetReleaseService:
    """Separate external file verification from short authority transactions."""

    def __init__(self, *, repository: SqliteLockedSetRepository) -> None:
        self.repository = repository

    def prepare_preflight(
        self,
        *,
        manifest_path: Path,
        dataset_root: Path,
        actor_id: str,
    ) -> PreparedLockedSetPreflight:
        snapshot = self.repository.build_exclusion_snapshot()
        manifest = load_locked_set_manifest_for_development(
            manifest_path,
            template_reference_hashes=(snapshot.snapshot.template_reference_image_hashes),
        )
        attestation = preflight_locked_set_release(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            exclusion_snapshot=snapshot.snapshot,
        )
        # Verify every external byte before creating durable dataset state.
        sealed = self.repository.seal_manifest(
            manifest,
            actor_id=actor_id,
        )
        return PreparedLockedSetPreflight(
            dataset=sealed.dataset,
            snapshot=snapshot,
            attestation=attestation,
        )

    def commit_preflight(
        self,
        prepared: PreparedLockedSetPreflight,
        *,
        actor_id: str,
    ) -> LockedSetReleaseResult:
        outcome = self.repository.persist_preflight_attestation(
            dataset_id=prepared.dataset.dataset_id,
            expected_record_version=prepared.dataset.record_version,
            snapshot=prepared.snapshot,
            attestation=prepared.attestation,
            actor_id=actor_id,
        )
        return LockedSetReleaseResult(
            dataset=outcome.dataset,
            snapshot=prepared.snapshot,
            attestation=outcome.attestation,
            applied=outcome.applied,
        )

    def seal_and_preflight(
        self,
        *,
        manifest_path: Path,
        dataset_root: Path,
        actor_id: str,
    ) -> LockedSetReleaseResult:
        prepared = self.prepare_preflight(
            manifest_path=manifest_path,
            dataset_root=dataset_root,
            actor_id=actor_id,
        )
        return self.commit_preflight(prepared, actor_id=actor_id)
