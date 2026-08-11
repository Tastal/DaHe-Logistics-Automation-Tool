from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from dahe import __version__
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.ocr.locked_set_evaluator import (
    LocalOcrLockedImageEvaluator,
)
from dahe.adapters.sqlite.locked_set import (
    LockedSetFormalEvaluationRecord,
    LockedSetNotFoundError,
    LockedSetPersistenceError,
    LockedSetPreflightAuthority,
    LockedSetSimilarityScanRecord,
    LockedSetStateTransitionError,
    PersistedExclusionSnapshot,
    SqliteLockedSetRepository,
    require_current_preflight_authority,
)
from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.candidate_review_seal import (
    CandidateReviewSeal,
    CandidateReviewSealError,
    validate_candidate_review_seal,
)
from dahe.application.template_studio.candidate_review_semantics import (
    CandidateReviewSemanticError,
    candidate_review_manifest_payload,
    validate_candidate_review_semantic_authority,
)
from dahe.application.template_studio.development_authority_rollover import (
    DevelopmentAuthorityRollover,
    DevelopmentAuthorityRolloverError,
    load_persisted_development_authority_rollover,
    persist_development_authority_rollover,
    validate_development_authority_rollover,
)
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_manifest,
)
from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
    FormalDevelopmentAuthorityError,
    load_formal_development_authority,
    load_persisted_formal_development_authority,
    parse_formal_development_authority,
    persist_formal_development_authority,
    require_approved_development_dataset_binding,
)
from dahe.application.template_studio.locked_set_evidence import (
    stage_locked_set_evidence,
)
from dahe.application.template_studio.locked_set_release import (
    LockedSetReleaseService,
)
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrFormalAuthority,
    RuntimeKindName,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    NearDuplicateDecision,
    ReviewOutcome,
    build_image_fingerprint,
)
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedSetReleaseAttestation,
    load_locked_set_manifest_for_development,
)
from dahe.verification.locked_set_acceptance import (
    REQUIRED_NATURAL_QUALITY_CONDITIONS,
    build_locked_set_derived_adversarial_suite,
    locked_set_quality_coverage_sha256,
    validate_candidate_review_source_authority_binding,
    validate_locked_set_quality_coverage,
)
from dahe.verification.locked_set_runner import (
    run_locked_set_role_evaluation,
)
from dahe.verification.locked_set_similarity_scan import (
    LockedSetSimilarityScan,
    PersistedFingerprintRecord,
    PersistedFingerprintRecordLike,
    bind_similarity_decisions,
    scan_locked_set_similarity,
)

_LOCKED_OCR_TIMEOUT_SECONDS = 180.0


class FormalLockedSetReleaseError(RuntimeError):
    """Raised when the supported formal release boundary cannot proceed."""


@dataclass(frozen=True, slots=True)
class PreparedFormalLockedSetReview:
    dataset_id: str
    manifest_sha256: str
    exclusion_snapshot_sha256: str
    inventory_high_watermark: int
    scan: LockedSetSimilarityScan
    persisted_scan: LockedSetSimilarityScanRecord
    status: str
    dataset_record_version: int
    quality_coverage: Mapping[str, object]
    candidate_review_source_authority: Mapping[str, object] | None = None
    development_authority_sha256: str | None = None
    source_development_authority_sha256: str | None = None
    execution_development_authority_sha256: str | None = None
    development_authority_rollover_sha256: str | None = None
    formal_accuracy_claim: bool = False


@dataclass(frozen=True, slots=True)
class FormalLockedSetEvaluationResult:
    evaluation: LockedSetFormalEvaluationRecord
    committed_report: Mapping[str, object]
    replayed: bool


@dataclass(frozen=True, slots=True)
class ValidatedFormalLockedSetReview:
    dataset_id: str
    manifest_sha256: str
    dataset_record_version: int
    dataset_state: str
    scan_fingerprint: str
    candidate_count: int
    decision_count: int
    quality_entry_count: int
    derived_adversarial_scenario_count: int
    derived_adversarial_suite_sha256: str
    status: str = "ready_for_ocr_evaluation"
    formal_accuracy_claim: bool = False


@dataclass(frozen=True, slots=True)
class _BoundFormalLockedSetReview:
    manifest: LockedSetManifest
    persisted_scan: LockedSetSimilarityScanRecord
    historical_snapshot: PersistedExclusionSnapshot
    scan: LockedSetSimilarityScan
    decisions: list[dict[str, object]]
    quality_coverage: dict[str, object]
    candidate_review_source_authority: dict[str, object]
    development_authority: FormalDevelopmentAuthority | None
    dataset_state: str
    dataset_record_version: int


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise FormalLockedSetReleaseError("formal release evidence is not canonical JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_file_object(
    path: Path,
    *,
    label: str,
) -> dict[str, object]:
    try:
        content = path.read_bytes()
        payload = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FormalLockedSetReleaseError(f"{label} is unreadable") from exc
    if not isinstance(payload, dict):
        raise FormalLockedSetReleaseError(f"{label} must be an object")
    if content != (_canonical_json(payload) + "\n").encode("utf-8"):
        raise FormalLockedSetReleaseError(f"{label} is not canonical")
    return payload


def _seal_source_authority_binding(
    seal: CandidateReviewSeal,
) -> dict[str, object]:
    raw = {
        "schema_version": 1,
        "seal_sha256": seal.seal_sha256,
        "package_sha256": seal.seal_payload.get("package_sha256"),
        "record_set_sha256": seal.seal_payload.get("record_set_sha256"),
        "review_history_authority_sha256": seal.seal_payload.get("review_history_authority_sha256"),
        "source_authority_sha256": seal.seal_payload.get("source_authority_sha256"),
    }
    try:
        return validate_candidate_review_source_authority_binding(raw)
    except ValueError as exc:
        raise FormalLockedSetReleaseError(
            "candidate-review seal source authority is invalid"
        ) from exc


def _truth_manifest_payload(
    manifest: LockedSetManifest,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "waybill_count": manifest.waybill_count,
        "image_count": manifest.image_count,
        "pairs": [
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "truth_role": image.role.value,
                    }
                    for image in waybill.images
                ],
                "submitted_slots": {
                    image.slot.value: image.image_sha256 for image in waybill.images
                },
            }
            for waybill in manifest.waybills
        ],
    }


def _quality_coverage_for_manifest(
    manifest: LockedSetManifest,
) -> dict[str, object]:
    quality_coverage: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "required_conditions": sorted(REQUIRED_NATURAL_QUALITY_CONDITIONS),
        "entries": [],
        "derived_adversarial_suite": (
            build_locked_set_derived_adversarial_suite(_truth_manifest_payload(manifest))
        ),
    }
    quality_coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(
        quality_coverage
    )
    return quality_coverage


def _authoritative_evidence_store(
    repository: SqliteLockedSetRepository,
) -> ContentAddressedEvidenceStore:
    return ContentAddressedEvidenceStore(repository.runtime.data_root / "evidence")


def _require_formal_backend_authority(
    *,
    repository: SqliteLockedSetRepository,
    backend: AsyncOcrExecutionBackend,
) -> OcrFormalAuthority:
    if not isinstance(backend, AsyncOcrExecutionBackend):
        raise FormalLockedSetReleaseError(
            "formal evaluation requires the verified local OCR backend"
        )
    authority = backend.formal_authority
    if authority is None:
        raise FormalLockedSetReleaseError(
            "formal evaluation rejects a manually composed OCR backend"
        )
    runtime = repository.runtime
    if (
        authority.data_root != runtime.data_root
        or authority.repository_root != runtime.project_root
    ):
        raise FormalLockedSetReleaseError(
            "formal OCR authority belongs to another application runtime"
        )
    runtime_kinds: tuple[RuntimeKindName, ...] = ("cpu", "gpu")
    current_identities = tuple(
        sorted(
            (
                backend.identity_for(runtime_kind)
                for runtime_kind in runtime_kinds
                if backend.has_runtime(runtime_kind)
            ),
            key=lambda identity: (
                identity.runtime_kind,
                identity.profile_id,
                identity.runtime_fingerprint,
            ),
        )
    )
    if current_identities != authority.runtime_identities:
        raise FormalLockedSetReleaseError(
            "formal OCR runtime identities changed after qualification"
        )
    return authority


def _persisted_fingerprint_records(
    snapshot: PersistedExclusionSnapshot,
) -> tuple[PersistedFingerprintRecordLike, ...]:
    if (
        snapshot.missing_fingerprint_count != 0
        or snapshot.fingerprinted_image_count != snapshot.inventory_image_count
    ):
        raise FormalLockedSetReleaseError("authoritative exclusion fingerprints are incomplete")
    return tuple(
        PersistedFingerprintRecord(
            image_sha256=item.content_sha256,
            fingerprint_json=item.perceptual_fingerprint_json,
            fingerprint_json_sha256=item.fingerprint_sha256,
        )
        for item in snapshot.perceptual_fingerprints
    )


def _locked_probe_fingerprints(
    manifest: LockedSetManifest,
    *,
    evidence_store: ContentAddressedEvidenceStore,
) -> tuple[ImagePerceptualFingerprint, ...]:
    image_hashes = sorted(
        image.image_sha256 for waybill in manifest.waybills for image in waybill.images
    )
    if len(image_hashes) != 100 or len(set(image_hashes)) != 100:
        raise FormalLockedSetReleaseError("formal locked set requires 100 unique image identities")
    fingerprints: list[ImagePerceptualFingerprint] = []
    for image_sha256 in image_hashes:
        try:
            content = evidence_store.read_bytes(image_sha256)
            fingerprint = build_image_fingerprint(content)
        except (OSError, RuntimeError, ValueError) as exc:
            raise FormalLockedSetReleaseError(
                "content-addressed locked evidence is unavailable"
            ) from exc
        if fingerprint.content_sha256 != image_sha256:
            raise FormalLockedSetReleaseError(
                "locked evidence fingerprint changed its image identity"
            )
        fingerprints.append(fingerprint)
    return tuple(fingerprints)


def complete_existing_exclusion_fingerprints(
    *,
    repository: SqliteLockedSetRepository,
    evidence_store: ContentAddressedEvidenceStore,
) -> None:
    """Append missing fingerprints after verifying local content-addressed evidence."""

    pending = repository.list_unfingerprinted_exclusion_images()
    for item in pending:
        expected_relative_path = (
            evidence_store.path_for(item.sha256).relative_to(evidence_store.root).as_posix()
        )
        if item.relative_path != expected_relative_path:
            raise FormalLockedSetReleaseError("exclusion evidence path is not content-addressed")
        try:
            content = evidence_store.read_bytes(item.sha256)
            fingerprint = build_image_fingerprint(content)
        except (OSError, RuntimeError, ValueError) as exc:
            raise FormalLockedSetReleaseError("exclusion evidence cannot be fingerprinted") from exc
        repository.register_exclusion_fingerprint(
            category=item.category,
            identity_sha256=item.sha256,
            fingerprint=fingerprint,
        )


def _scan_from_authority(
    *,
    manifest: LockedSetManifest,
    snapshot: PersistedExclusionSnapshot,
    evidence_store: ContentAddressedEvidenceStore,
) -> tuple[LockedSetSimilarityScan, tuple[ImagePerceptualFingerprint, ...]]:
    probes = _locked_probe_fingerprints(
        manifest,
        evidence_store=evidence_store,
    )
    scan = scan_locked_set_similarity(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256=snapshot.snapshot.canonical_sha256,
        probes=probes,
        persisted_inventory=_persisted_fingerprint_records(snapshot),
    )
    return scan, probes


def prepare_formal_locked_set_release(
    *,
    repository: SqliteLockedSetRepository,
    manifest_path: Path,
    dataset_root: Path,
    actor_id: str,
) -> PreparedFormalLockedSetReview:
    """Prepare one code-owned scan without starting OCR or claiming accuracy."""

    evidence_store = _authoritative_evidence_store(repository)
    complete_existing_exclusion_fingerprints(
        repository=repository,
        evidence_store=evidence_store,
    )
    release = LockedSetReleaseService(repository=repository).seal_and_preflight(
        manifest_path=manifest_path,
        dataset_root=dataset_root,
        actor_id=actor_id,
    )
    manifest = load_locked_set_manifest_for_development(
        manifest_path,
        template_reference_hashes=(release.snapshot.snapshot.template_reference_image_hashes),
    )
    if manifest.canonical_sha256 != release.attestation.manifest_sha256:
        raise FormalLockedSetReleaseError(
            "prepared manifest no longer matches its preflight authority"
        )
    staged_evidence = stage_locked_set_evidence(
        manifest=manifest,
        dataset_root=dataset_root,
        evidence_store=evidence_store,
    )
    repository.register_evidence_membership(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        images=staged_evidence.images,
    )
    scan, probes = _scan_from_authority(
        manifest=manifest,
        snapshot=release.snapshot,
        evidence_store=evidence_store,
    )
    persisted = repository.persist_similarity_scan(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256=(release.attestation.exclusion_snapshot_sha256),
        inventory_high_watermark=(release.attestation.inventory_high_watermark),
        scan=scan.to_payload(),
        locked_image_fingerprints=probes,
        actor_id=actor_id,
    ).scan
    dataset = repository.get_dataset(manifest.dataset_id)
    return PreparedFormalLockedSetReview(
        dataset_id=manifest.dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256=(release.attestation.exclusion_snapshot_sha256),
        inventory_high_watermark=(release.attestation.inventory_high_watermark),
        scan=scan,
        persisted_scan=persisted,
        status="awaiting_human_review",
        dataset_record_version=dataset.record_version,
        quality_coverage=_quality_coverage_for_manifest(manifest),
    )


def prepare_candidate_review_formal_release(
    *,
    repository: SqliteLockedSetRepository,
    candidate_review_seal: CandidateReviewSeal,
    source_development_authority: FormalDevelopmentAuthority,
    live_development_authority: FormalDevelopmentAuthority,
    development_authority_rollover: DevelopmentAuthorityRollover,
    expected_source_development_authority_sha256: str,
    expected_execution_development_authority_sha256: str,
    actor_id: str,
) -> PreparedFormalLockedSetReview:
    """Prepare only a revalidated immutable candidate-review seal."""

    if not isinstance(candidate_review_seal, CandidateReviewSeal):
        raise FormalLockedSetReleaseError("formal candidate review requires a validated seal")
    if (
        not isinstance(
            source_development_authority,
            FormalDevelopmentAuthority,
        )
        or not isinstance(
            live_development_authority,
            FormalDevelopmentAuthority,
        )
        or not isinstance(
            development_authority_rollover,
            DevelopmentAuthorityRollover,
        )
        or not isinstance(
            expected_source_development_authority_sha256,
            str,
        )
        or not isinstance(
            expected_execution_development_authority_sha256,
            str,
        )
        or source_development_authority.authority_sha256
        != expected_source_development_authority_sha256
        or live_development_authority.authority_sha256
        != expected_execution_development_authority_sha256
    ):
        raise FormalLockedSetReleaseError(
            "formal candidate review requires the expected live development authority"
        )
    try:
        seal_root = candidate_review_seal.seal_root.resolve(strict=True)
        review_root = seal_root.parent.parent.resolve(strict=True)
    except OSError as exc:
        raise FormalLockedSetReleaseError("candidate-review seal is unavailable") from exc
    expected_root = review_root / "seals" / candidate_review_seal.seal_sha256
    if seal_root != expected_root:
        raise FormalLockedSetReleaseError("candidate-review seal path is invalid")
    try:
        validated = validate_candidate_review_seal(
            review_data_root=review_root,
            seal_sha256=candidate_review_seal.seal_sha256,
        )
    except CandidateReviewSealError as exc:
        raise FormalLockedSetReleaseError("candidate-review seal failed validation") from exc
    if validated != candidate_review_seal:
        raise FormalLockedSetReleaseError("candidate-review seal changed after validation")
    try:
        sealed_development_authority = load_formal_development_authority(
            seal_root / "development-authority.json",
            expected_sha256=(
                expected_source_development_authority_sha256
            ),
        )
    except FormalDevelopmentAuthorityError as exc:
        raise FormalLockedSetReleaseError(
            "candidate-review development authority failed validation"
        ) from exc
    if (
        validated.seal_payload.get("development_authority_sha256")
        != expected_source_development_authority_sha256
        or sealed_development_authority
        != source_development_authority
    ):
        raise FormalLockedSetReleaseError(
            "candidate-review development authority is stale or changed"
        )
    try:
        validate_development_authority_rollover(
            development_authority_rollover,
            source_authority=source_development_authority,
            execution_authority=live_development_authority,
        )
    except DevelopmentAuthorityRolloverError as exc:
        raise FormalLockedSetReleaseError(
            "candidate-review development authority rollover is invalid"
        ) from exc

    binding = _seal_source_authority_binding(validated)
    source_payload = _canonical_file_object(
        seal_root / "source-authority.json",
        label="candidate-review source authority",
    )
    quality_coverage = _canonical_file_object(
        seal_root / "quality-coverage.json",
        label="candidate-review quality coverage",
    )
    manifest_sha256 = validated.seal_payload.get("manifest_sha256")
    dataset_id = source_payload.get("dataset_id")
    declared_quality_sha256 = quality_coverage.get("quality_coverage_sha256")
    if (
        not isinstance(dataset_id, str)
        or not dataset_id
        or not isinstance(declared_quality_sha256, str)
        or locked_set_quality_coverage_sha256(quality_coverage) != declared_quality_sha256
        or source_payload.get("quality_coverage_sha256") != declared_quality_sha256
        or validated.seal_payload.get("quality_coverage_sha256") != declared_quality_sha256
        or source_payload.get("manifest_sha256") != manifest_sha256
        or source_payload.get("package_sha256") != binding["package_sha256"]
        or source_payload.get("record_set_sha256") != binding["record_set_sha256"]
        or source_payload.get("source_authority_sha256") != binding["source_authority_sha256"]
        or quality_coverage.get("dataset_id") != dataset_id
        or quality_coverage.get("manifest_sha256") != manifest_sha256
    ):
        raise FormalLockedSetReleaseError("candidate-review seal artifacts do not reconcile")

    try:
        imported_snapshot = repository.import_formal_development_exclusions(
            authority_sha256=live_development_authority.authority_sha256,
            exclusion_snapshot=live_development_authority.exclusion_snapshot,
            perceptual_fingerprints=(
                live_development_authority.perceptual_fingerprints
            ),
        )
        persist_formal_development_authority(
            repository.runtime.data_root,
            source_development_authority,
        )
        persist_formal_development_authority(
            repository.runtime.data_root,
            live_development_authority,
        )
        persist_development_authority_rollover(
            repository.runtime.data_root,
            development_authority_rollover,
        )
    except (
        DevelopmentAuthorityRolloverError,
        FormalDevelopmentAuthorityError,
        LockedSetPersistenceError,
    ) as exc:
        raise FormalLockedSetReleaseError(
            "formal development authority import failed"
        ) from exc
    prepared = prepare_formal_locked_set_release(
        repository=repository,
        manifest_path=seal_root / "manifest.json",
        dataset_root=review_root,
        actor_id=actor_id,
    )
    if prepared.dataset_id != dataset_id or prepared.manifest_sha256 != manifest_sha256:
        raise FormalLockedSetReleaseError(
            "prepared locked set does not match the candidate-review seal"
        )
    if (
        imported_snapshot.snapshot.canonical_sha256
        != prepared.exclusion_snapshot_sha256
        or imported_snapshot.inventory_high_watermark
        != prepared.inventory_high_watermark
    ):
        raise FormalLockedSetReleaseError(
            "prepared locked set does not match imported development exclusions"
        )
    repository.register_development_authority(
        dataset_id=prepared.dataset_id,
        manifest_sha256=prepared.manifest_sha256,
        authority_sha256=live_development_authority.authority_sha256,
        source_exclusion_snapshot_sha256=(
            live_development_authority.exclusion_snapshot.canonical_sha256
        ),
        formal_exclusion_snapshot_sha256=(
            prepared.exclusion_snapshot_sha256
        ),
        source_inventory_high_watermark=(
            live_development_authority.inventory_high_watermark
        ),
        shadow_template_set_fingerprint=str(
            live_development_authority.payload[
                "shadow_template_set_fingerprint"
            ]
        ),
        payload=live_development_authority.payload,
    )
    repository.register_candidate_review_source_authority(
        dataset_id=prepared.dataset_id,
        manifest_sha256=prepared.manifest_sha256,
        seal_sha256=str(binding["seal_sha256"]),
        package_sha256=str(binding["package_sha256"]),
        record_set_sha256=str(binding["record_set_sha256"]),
        review_history_authority_sha256=str(binding["review_history_authority_sha256"]),
        source_authority_sha256=str(binding["source_authority_sha256"]),
        payload=source_payload,
    )
    return replace(
        prepared,
        quality_coverage=quality_coverage,
        candidate_review_source_authority=binding,
        development_authority_sha256=(
            live_development_authority.authority_sha256
        ),
        source_development_authority_sha256=(
            source_development_authority.authority_sha256
        ),
        execution_development_authority_sha256=(
            live_development_authority.authority_sha256
        ),
        development_authority_rollover_sha256=(
            development_authority_rollover.rollover_sha256
        ),
    )


def _parse_review_decisions(
    value: Mapping[str, object],
    *,
    scan: LockedSetSimilarityScan,
    expected_reviewer_id: str,
) -> list[dict[str, object]]:
    configured_reviewer = expected_reviewer_id.strip()
    if (
        not configured_reviewer
        or configured_reviewer != expected_reviewer_id
        or len(configured_reviewer) > 100
    ):
        raise FormalLockedSetReleaseError(
            "configured reviewer identity is invalid"
        )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("dataset_id") != scan.dataset_id
        or value.get("manifest_sha256") != scan.manifest_sha256
        or value.get("scan_fingerprint") != scan.scan_fingerprint
    ):
        raise FormalLockedSetReleaseError("similarity review is not bound to the current scan")
    raw_decisions = value.get("decisions")
    if not isinstance(raw_decisions, list):
        raise FormalLockedSetReleaseError("similarity review decisions must be a list")
    candidates = {candidate.candidate_id: candidate for candidate in scan.review_candidates}
    decisions: list[NearDuplicateDecision] = []
    seen: set[str] = set()
    for raw in raw_decisions:
        if not isinstance(raw, Mapping):
            raise FormalLockedSetReleaseError("similarity review decision is invalid")
        candidate_id = raw.get("candidate_id")
        if (
            not isinstance(candidate_id, str)
            or candidate_id in seen
            or candidate_id not in candidates
        ):
            raise FormalLockedSetReleaseError("similarity review decision has no current candidate")
        seen.add(candidate_id)
        verdict = raw.get("verdict")
        try:
            outcome = ReviewOutcome(str(verdict))
        except ValueError as exc:
            raise FormalLockedSetReleaseError("similarity review verdict is invalid") from exc
        reviewer_id = raw.get("reviewer_id")
        decided_at = raw.get("decided_at")
        reason = raw.get("reason")
        if not all(
            isinstance(item, str) and item.strip() for item in (reviewer_id, decided_at, reason)
        ):
            raise FormalLockedSetReleaseError(
                "similarity review requires reviewer, time, and reason"
            )
        if reviewer_id != configured_reviewer:
            raise FormalLockedSetReleaseError(
                "similarity review decision must use the configured reviewer"
            )
        try:
            decisions.append(
                NearDuplicateDecision.create(
                    candidate=candidates[candidate_id],
                    outcome=outcome,
                    operator_id=str(reviewer_id),
                    note=str(reason),
                    decided_at=str(decided_at),
                )
            )
        except ValueError as exc:
            raise FormalLockedSetReleaseError(
                "similarity review decision failed integrity validation"
            ) from exc
    try:
        return bind_similarity_decisions(
            scan=scan,
            decisions=tuple(decisions),
        )
    except ValueError as exc:
        raise FormalLockedSetReleaseError(
            "similarity review does not resolve the current scan"
        ) from exc


def _configured_candidate_reviewer_id(
    *,
    repository: SqliteLockedSetRepository,
    dataset_id: str,
) -> str:
    try:
        record = repository.get_candidate_review_source_authority(
            dataset_id
        )
        source_payload = json.loads(record.payload_json)
    except (LockedSetPersistenceError, TypeError, json.JSONDecodeError) as exc:
        raise FormalLockedSetReleaseError(
            "persisted candidate-review configured reviewer is unavailable"
        ) from exc
    reviewer_id = (
        source_payload.get("configured_reviewer_id")
        if isinstance(source_payload, Mapping)
        else None
    )
    if (
        not isinstance(reviewer_id, str)
        or not reviewer_id
        or reviewer_id.strip() != reviewer_id
        or len(reviewer_id) > 100
    ):
        raise FormalLockedSetReleaseError(
            "persisted candidate-review configured reviewer is invalid"
        )
    return reviewer_id


def _release_attestation(
    *,
    authority: LockedSetPreflightAuthority,
) -> LockedSetReleaseAttestation:
    attestation = authority.attestation
    snapshot = authority.exclusion_snapshot.snapshot
    verified = LockedSetReleaseAttestation(
        dataset_id=attestation.dataset_id,
        manifest_sha256=attestation.manifest_sha256,
        exclusion_source_id=attestation.exclusion_source_id,
        exclusion_snapshot_sha256=(attestation.exclusion_snapshot_sha256),
        waybill_count=attestation.waybill_count,
        image_count=attestation.image_count,
        total_bytes=attestation.total_bytes,
        exclusion_counts=snapshot.exclusion_counts,
    )
    if verified.attestation_sha256 != attestation.attestation_sha256:
        raise FormalLockedSetReleaseError(
            "persisted preflight attestation failed integrity validation"
        )
    return verified


def _quality_authority(
    manifest: LockedSetManifest,
) -> tuple[dict[str, tuple[str, str]], dict[str, tuple[str, str]]]:
    image_truth: dict[str, tuple[str, str]] = {}
    pair_slots: dict[str, tuple[str, str]] = {}
    for waybill in manifest.waybills:
        by_slot = {image.slot.value: image for image in waybill.images}
        if set(by_slot) != {"loading", "unloading"}:
            raise FormalLockedSetReleaseError("locked-set submitted slots do not reconcile")
        for image in waybill.images:
            image_truth[image.image_sha256] = (
                waybill.sample_id,
                image.role.value,
            )
        pair_slots[waybill.sample_id] = (
            by_slot["loading"].image_sha256,
            by_slot["unloading"].image_sha256,
        )
    if len(image_truth) != 100 or len(pair_slots) != 50:
        raise FormalLockedSetReleaseError("locked-set quality authority does not reconcile")
    return image_truth, pair_slots


def _quality_from_review_package(
    review_package: Mapping[str, object],
) -> dict[str, object]:
    quality = review_package.get("quality_coverage")
    if not isinstance(quality, Mapping):
        raise FormalLockedSetReleaseError("review package requires bound quality coverage")
    return dict(quality)


def _derived_suite_identity(
    quality_coverage: Mapping[str, object],
) -> tuple[dict[str, object], int, str]:
    suite = quality_coverage.get("derived_adversarial_suite")
    if not isinstance(suite, Mapping):
        raise FormalLockedSetReleaseError("quality coverage derived adversarial suite is invalid")
    normalized_suite = dict(suite)
    scenarios = normalized_suite.get("scenarios")
    suite_sha256 = normalized_suite.get("suite_sha256")
    if (
        not isinstance(scenarios, list)
        or len(scenarios) != 4
        or not isinstance(suite_sha256, str)
        or len(suite_sha256) != 64
        or _canonical_sha256(
            {key: value for key, value in normalized_suite.items() if key != "suite_sha256"}
        )
        != suite_sha256
    ):
        raise FormalLockedSetReleaseError("quality coverage derived adversarial suite is invalid")
    return normalized_suite, len(scenarios), suite_sha256


def _bind_candidate_review_source_authority(
    *,
    repository: SqliteLockedSetRepository,
    manifest: LockedSetManifest,
    review_package: Mapping[str, object],
    quality_coverage: Mapping[str, object],
) -> dict[str, object]:
    dataset_id = manifest.dataset_id
    manifest_sha256 = manifest.canonical_sha256
    raw_binding = review_package.get("candidate_review_source_authority")
    try:
        binding = validate_candidate_review_source_authority_binding(
            dict(raw_binding) if isinstance(raw_binding, Mapping) else raw_binding
        )
    except ValueError as exc:
        raise FormalLockedSetReleaseError(
            "review package requires candidate-review source authority"
        ) from exc
    try:
        record = repository.get_candidate_review_source_authority(dataset_id)
    except LockedSetPersistenceError as exc:
        raise FormalLockedSetReleaseError(
            "persisted candidate-review source authority is unavailable"
        ) from exc
    expected = {
        "schema_version": 1,
        "seal_sha256": record.seal_sha256,
        "package_sha256": record.package_sha256,
        "record_set_sha256": record.record_set_sha256,
        "review_history_authority_sha256": (record.review_history_authority_sha256),
        "source_authority_sha256": (record.source_authority_sha256),
    }
    try:
        expected_binding = validate_candidate_review_source_authority_binding(expected)
    except ValueError as exc:
        raise FormalLockedSetReleaseError(
            "persisted candidate-review source authority is invalid"
        ) from exc
    if (
        binding != expected_binding
        or record.dataset_id != dataset_id
        or record.manifest_sha256 != manifest_sha256
    ):
        raise FormalLockedSetReleaseError(
            "candidate-review source authority does not match the persisted locked set"
        )
    try:
        source_payload = json.loads(record.payload_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise FormalLockedSetReleaseError(
            "persisted candidate-review source payload is invalid"
        ) from exc
    if not isinstance(source_payload, dict):
        raise FormalLockedSetReleaseError("persisted candidate-review source payload is invalid")
    source_without_hash = dict(source_payload)
    source_without_hash.pop("source_authority_sha256", None)
    declared_quality_sha256 = quality_coverage.get("quality_coverage_sha256")
    if (
        _canonical_json(source_payload) != record.payload_json
        or source_payload.get("schema_version") != 3
        or source_payload.get("kind") != "candidate_review_formal_source_authority"
        or source_payload.get("dataset_id") != dataset_id
        or source_payload.get("manifest_sha256") != manifest_sha256
        or source_payload.get("package_sha256") != record.package_sha256
        or source_payload.get("record_set_sha256") != record.record_set_sha256
        or source_payload.get("source_authority_sha256") != record.source_authority_sha256
        or _canonical_sha256(source_without_hash) != record.source_authority_sha256
    ):
        raise FormalLockedSetReleaseError(
            "persisted candidate-review source payload is inconsistent"
        )
    if (
        not isinstance(declared_quality_sha256, str)
        or locked_set_quality_coverage_sha256(quality_coverage) != declared_quality_sha256
        or source_payload.get("quality_coverage_sha256") != declared_quality_sha256
    ):
        raise FormalLockedSetReleaseError(
            "candidate-review quality coverage does not match persisted source authority"
        )
    try:
        validate_candidate_review_semantic_authority(
            manifest_payload=candidate_review_manifest_payload(manifest),
            source_authority_payload=source_payload,
        )
    except CandidateReviewSemanticError as exc:
        raise FormalLockedSetReleaseError(
            "persisted candidate-review source payload semantic bindings are inconsistent"
        ) from exc
    return binding


def _require_no_confirmed_near_duplicates(
    decisions: list[dict[str, object]],
) -> None:
    if any(decision.get("verdict") == ReviewOutcome.DUPLICATE.value for decision in decisions):
        raise FormalLockedSetReleaseError(
            "formal locked set contains a human-confirmed near duplicate"
        )


def _bind_development_authority(
    *,
    repository: SqliteLockedSetRepository,
    dataset_id: str,
    manifest_sha256: str,
    persisted_scan: LockedSetSimilarityScanRecord,
    review_package: Mapping[str, object],
) -> FormalDevelopmentAuthority:
    source_authority_sha256 = review_package.get(
        "source_development_authority_sha256"
    )
    execution_authority_sha256 = review_package.get(
        "execution_development_authority_sha256"
    )
    rollover_sha256 = review_package.get(
        "development_authority_rollover_sha256"
    )
    if (
        not isinstance(source_authority_sha256, str)
        or not isinstance(execution_authority_sha256, str)
        or not isinstance(rollover_sha256, str)
        or review_package.get("development_authority_sha256")
        != execution_authority_sha256
    ):
        raise FormalLockedSetReleaseError(
            "review package requires a development authority rollover"
        )
    try:
        record = repository.get_development_authority(dataset_id)
        payload = json.loads(record.payload_json)
        if not isinstance(payload, dict):
            raise TypeError
        authority = parse_formal_development_authority(payload)
        persisted_execution = load_persisted_formal_development_authority(
            repository.runtime.data_root,
            authority_sha256=record.authority_sha256,
        )
        persisted_source = load_persisted_formal_development_authority(
            repository.runtime.data_root,
            authority_sha256=source_authority_sha256,
        )
        rollover = load_persisted_development_authority_rollover(
            repository.runtime.data_root,
            rollover_sha256=rollover_sha256,
        )
        validate_development_authority_rollover(
            rollover,
            source_authority=persisted_source,
            execution_authority=persisted_execution,
        )
    except (
        DevelopmentAuthorityRolloverError,
        FormalDevelopmentAuthorityError,
        LockedSetPersistenceError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        raise FormalLockedSetReleaseError(
            "persisted formal development authority is unavailable"
        ) from exc
    shadow_template_set_fingerprint = authority.payload.get(
        "shadow_template_set_fingerprint"
    )
    if (
        execution_authority_sha256 != record.authority_sha256
        or record.authority_sha256 != authority.authority_sha256
        or persisted_execution != authority
        or record.dataset_id != dataset_id
        or record.manifest_sha256 != manifest_sha256
        or record.source_exclusion_snapshot_sha256
        != authority.exclusion_snapshot.canonical_sha256
        or record.formal_exclusion_snapshot_sha256
        != persisted_scan.exclusion_snapshot_sha256
        or record.source_inventory_high_watermark
        != authority.inventory_high_watermark
        or record.shadow_template_set_fingerprint
        != shadow_template_set_fingerprint
    ):
        raise FormalLockedSetReleaseError(
            "formal development authority does not match the review"
        )
    return authority


def _bind_formal_review(
    *,
    repository: SqliteLockedSetRepository,
    dataset_id: str,
    review_package: Mapping[str, object],
) -> _BoundFormalLockedSetReview:
    quality_coverage = _quality_from_review_package(review_package)
    dataset = repository.get_dataset(dataset_id)
    if dataset.state == "invalidated_to_development":
        raise FormalLockedSetReleaseError(
            "a permanently invalidated locked set cannot be evaluated"
        )
    evidence_store = _authoritative_evidence_store(repository)
    manifest = repository.get_manifest(dataset_id)
    candidate_review_source_authority = _bind_candidate_review_source_authority(
        repository=repository,
        manifest=manifest,
        review_package=review_package,
        quality_coverage=quality_coverage,
    )
    persisted_scan = repository.get_similarity_scan(dataset_id)
    development_authority = (
        _bind_development_authority(
            repository=repository,
            dataset_id=dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            persisted_scan=persisted_scan,
            review_package=review_package,
        )
        if review_package.get("command") == "prepare-candidate"
        else None
    )
    historical_snapshot = repository.get_exclusion_snapshot(persisted_scan.exclusion_snapshot_id)
    if (
        historical_snapshot.snapshot_id != persisted_scan.exclusion_snapshot_id
        or historical_snapshot.snapshot.canonical_sha256 != persisted_scan.exclusion_snapshot_sha256
        or historical_snapshot.inventory_high_watermark != persisted_scan.inventory_high_watermark
    ):
        raise FormalLockedSetReleaseError("persisted similarity authority is inconsistent")
    scan, probes = _scan_from_authority(
        manifest=manifest,
        snapshot=historical_snapshot,
        evidence_store=evidence_store,
    )
    if (
        _canonical_json(scan.to_payload()) != persisted_scan.scan_json
        or scan.scan_fingerprint != persisted_scan.scan_fingerprint
        or tuple(fingerprint.canonical_sha256 for fingerprint in probes)
        != tuple(
            fingerprint.canonical_sha256 for fingerprint in persisted_scan.locked_image_fingerprints
        )
    ):
        raise FormalLockedSetReleaseError("persisted similarity scan cannot be reproduced")
    decisions = _parse_review_decisions(
        review_package,
        scan=scan,
        expected_reviewer_id=_configured_candidate_reviewer_id(
            repository=repository,
            dataset_id=dataset_id,
        ),
    )
    _require_no_confirmed_near_duplicates(decisions)
    image_truth, pair_slots = _quality_authority(manifest)
    try:
        validate_locked_set_quality_coverage(
            quality_coverage,
            dataset_id=dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            image_truth=image_truth,
            pair_slots=pair_slots,
        )
    except ValueError as exc:
        raise FormalLockedSetReleaseError("human quality coverage is incomplete") from exc
    return _BoundFormalLockedSetReview(
        manifest=manifest,
        persisted_scan=persisted_scan,
        historical_snapshot=historical_snapshot,
        scan=scan,
        decisions=decisions,
        quality_coverage=quality_coverage,
        candidate_review_source_authority=(candidate_review_source_authority),
        development_authority=development_authority,
        dataset_state=dataset.state,
        dataset_record_version=dataset.record_version,
    )


def validate_formal_locked_set_review(
    *,
    locked_repository: SqliteLockedSetRepository,
    dataset_id: str,
    review_package: Mapping[str, object],
) -> ValidatedFormalLockedSetReview:
    """Validate human review evidence without starting an OCR runtime."""

    bound = _bind_formal_review(
        repository=locked_repository,
        dataset_id=dataset_id,
        review_package=review_package,
    )
    if bound.dataset_state == "formal_evaluated":
        _replayable_evaluation(
            locked_repository,
            dataset_id=dataset_id,
        )
    else:
        with locked_repository.runtime.engine.connect() as connection:
            authority = require_current_preflight_authority(
                connection,
                dataset_id=dataset_id,
                manifest_sha256=bound.persisted_scan.manifest_sha256,
                exclusion_snapshot_sha256=(bound.persisted_scan.exclusion_snapshot_sha256),
                inventory_high_watermark=(bound.persisted_scan.inventory_high_watermark),
            )
        if authority.exclusion_snapshot != bound.historical_snapshot:
            raise FormalLockedSetReleaseError(
                "current preflight authority changed before review validation"
            )
    entries = bound.quality_coverage.get("entries")
    if not isinstance(entries, list):
        raise FormalLockedSetReleaseError("human quality coverage is incomplete")
    (
        _suite,
        scenario_count,
        suite_sha256,
    ) = _derived_suite_identity(bound.quality_coverage)
    return ValidatedFormalLockedSetReview(
        dataset_id=bound.manifest.dataset_id,
        manifest_sha256=bound.manifest.canonical_sha256,
        dataset_record_version=bound.dataset_record_version,
        dataset_state=bound.dataset_state,
        scan_fingerprint=bound.scan.scan_fingerprint,
        candidate_count=len(bound.scan.candidate_entries),
        decision_count=len(bound.decisions),
        quality_entry_count=len(entries),
        derived_adversarial_scenario_count=scenario_count,
        derived_adversarial_suite_sha256=suite_sha256,
    )


def _existing_evaluation(
    repository: SqliteLockedSetRepository,
    *,
    dataset_id: str,
) -> LockedSetFormalEvaluationRecord | None:
    try:
        return repository.get_formal_release_evaluation(dataset_id)
    except LockedSetNotFoundError:
        return None


def _replayable_evaluation(
    repository: SqliteLockedSetRepository,
    *,
    dataset_id: str,
) -> LockedSetFormalEvaluationRecord:
    try:
        return repository.get_replayable_formal_release_evaluation(dataset_id)
    except LockedSetStateTransitionError as exc:
        raise FormalLockedSetReleaseError(
            "a permanently invalidated locked set cannot replay accuracy"
        ) from exc


def _require_formal_report_claim_boundary(
    *,
    evaluation: LockedSetFormalEvaluationRecord,
    committed_report: Mapping[str, object],
    quality_coverage: Mapping[str, object],
) -> None:
    try:
        source_authority = validate_candidate_review_source_authority_binding(
            committed_report.get("candidate_review_source_authority")
        )
    except ValueError as exc:
        raise FormalLockedSetReleaseError(
            "persisted formal report claim boundary is inconsistent"
        ) from exc
    declared_quality_sha256 = quality_coverage.get("quality_coverage_sha256")
    suite, scenario_count, _suite_sha256 = _derived_suite_identity(quality_coverage)
    observed_gate = committed_report.get("observed_locked_set_gate")
    derived_gate = committed_report.get("derived_adversarial_gate")
    runtime_gate = committed_report.get("runtime_execution_gate")
    report_suite = committed_report.get("derived_adversarial_suite")
    if (
        not isinstance(declared_quality_sha256, str)
        or committed_report.get("candidate_review_source_authority_sha256")
        != _canonical_sha256(source_authority)
        or declared_quality_sha256 != locked_set_quality_coverage_sha256(quality_coverage)
        or committed_report.get("quality_coverage_sha256") != declared_quality_sha256
        or not isinstance(report_suite, Mapping)
        or dict(report_suite) != suite
        or not isinstance(observed_gate, Mapping)
        or not isinstance(derived_gate, Mapping)
        or not isinstance(runtime_gate, Mapping)
        or not isinstance(observed_gate.get("passed"), bool)
        or not isinstance(derived_gate.get("passed"), bool)
        or not isinstance(runtime_gate.get("passed"), bool)
        or derived_gate.get("scenario_count") != scenario_count
    ):
        raise FormalLockedSetReleaseError("persisted formal report claim boundary is inconsistent")
    observed_passed = observed_gate["passed"] is True
    derived_passed = derived_gate["passed"] is True
    runtime_passed = runtime_gate["passed"] is True
    gate_passed = observed_passed and derived_passed and runtime_passed
    expected_scope = "observed_real_locked_set_only" if evaluation.formal_accuracy_claim else "none"
    if (
        committed_report.get("formal_report") is not True
        or evaluation.formal_report is not True
        or committed_report.get("formal_accuracy_claim") is not gate_passed
        or evaluation.formal_accuracy_claim is not gate_passed
        or committed_report.get("gate_passed") is not gate_passed
        or evaluation.gate_passed is not gate_passed
        or committed_report.get("eligible_accuracy_scope") != "observed_real_locked_set_only"
        or committed_report.get("formal_accuracy_claim_scope") != expected_scope
        or evaluation.formal_accuracy_claim_scope != expected_scope
        or committed_report.get("derived_scenario_accuracy_claim") is not False
        or evaluation.derived_scenario_accuracy_claim is not False
        or committed_report.get("derived_prevalence_claim") is not False
        or evaluation.derived_prevalence_claim is not False
    ):
        raise FormalLockedSetReleaseError("persisted formal report claim boundary is inconsistent")


def _committed_replay(
    existing: LockedSetFormalEvaluationRecord,
    *,
    dataset_state: str,
    persisted_scan: LockedSetSimilarityScanRecord,
    quality_coverage: Mapping[str, object],
    decisions: list[dict[str, object]],
    run_context: Mapping[str, object],
    actor_id: str,
    idempotency_key: str,
) -> FormalLockedSetEvaluationResult:
    if dataset_state != "formal_evaluated":
        raise FormalLockedSetReleaseError(
            "a permanently invalidated locked set cannot replay accuracy"
        )
    if (
        existing.idempotency_key != idempotency_key
        or existing.actor_id != actor_id
        or existing.manifest_sha256 != persisted_scan.manifest_sha256
        or existing.exclusion_snapshot_id != persisted_scan.exclusion_snapshot_id
        or existing.exclusion_snapshot_sha256 != persisted_scan.exclusion_snapshot_sha256
        or existing.inventory_high_watermark != persisted_scan.inventory_high_watermark
        or existing.scan_id != persisted_scan.scan_id
        or existing.scan_fingerprint != persisted_scan.scan_fingerprint
        or existing.quality_coverage_sha256 != _canonical_sha256(dict(quality_coverage))
        or existing.decision_set_sha256 != _canonical_sha256(decisions)
        or existing.run_context_sha256 != _canonical_sha256(dict(run_context))
    ):
        raise FormalLockedSetReleaseError(
            "formal evaluation idempotency input does not match the committed report"
        )
    try:
        payload = json.loads(existing.committed_report_json)
    except json.JSONDecodeError as exc:
        raise FormalLockedSetReleaseError("persisted formal report is unreadable") from exc
    if not isinstance(payload, dict):
        raise FormalLockedSetReleaseError("persisted formal report is invalid")
    if (
        payload.get("formal_report") is not True
        or payload.get("formal_accuracy_claim") is not existing.formal_accuracy_claim
        or payload.get("gate_passed") is not existing.gate_passed
    ):
        raise FormalLockedSetReleaseError("persisted formal report authority is inconsistent")
    _require_formal_report_claim_boundary(
        evaluation=existing,
        committed_report=payload,
        quality_coverage=quality_coverage,
    )
    return FormalLockedSetEvaluationResult(
        evaluation=existing,
        committed_report=payload,
        replayed=True,
    )


def evaluate_formal_locked_set_release(
    *,
    locked_repository: SqliteLockedSetRepository,
    ocr_backend: AsyncOcrExecutionBackend,
    live_development_authority: FormalDevelopmentAuthority,
    dataset_id: str,
    review_package: Mapping[str, object],
    actor_id: str,
    idempotency_key: str,
) -> FormalLockedSetEvaluationResult:
    """Run and atomically persist the only supported formal role gate."""

    normalized_actor = actor_id.strip()
    normalized_key = idempotency_key.strip()
    if not normalized_actor or not normalized_key:
        raise FormalLockedSetReleaseError(
            "formal evaluation actor and idempotency key are required"
        )
    if not isinstance(
        live_development_authority,
        FormalDevelopmentAuthority,
    ):
        raise FormalLockedSetReleaseError(
            "formal evaluation requires a live development authority"
        )
    backend_authority = _require_formal_backend_authority(
        repository=locked_repository,
        backend=ocr_backend,
    )
    existing = _existing_evaluation(
        locked_repository,
        dataset_id=dataset_id,
    )
    if existing is not None:
        existing = _replayable_evaluation(
            locked_repository,
            dataset_id=dataset_id,
        )
    bound = _bind_formal_review(
        repository=locked_repository,
        dataset_id=dataset_id,
        review_package=review_package,
    )
    manifest = bound.manifest
    persisted_scan = bound.persisted_scan
    historical_snapshot = bound.historical_snapshot
    scan = bound.scan
    decisions = bound.decisions
    quality_coverage = bound.quality_coverage
    if (
        bound.development_authority is None
        or live_development_authority != bound.development_authority
    ):
        raise FormalLockedSetReleaseError(
            "live development authority changed after formal preparation"
        )

    build_manifest = current_template_pipeline_build_manifest(
        application_version=__version__,
    )
    build_fingerprint = build_manifest.canonical_sha256
    approved_development = load_approved_authorizing_development_dataset(
        approved_authorizing_development_dataset_path()
    )
    development_contract = live_development_authority.eligibility_contract
    try:
        require_approved_development_dataset_binding(
            live_development_authority,
            approved_manifest_sha256=(
                approved_development.manifest_sha256
            ),
        )
    except FormalDevelopmentAuthorityError as exc:
        raise FormalLockedSetReleaseError(
            "live development authority is stale for the formal runtime"
        ) from exc
    if (
        development_contract.matcher_fingerprint
        != development_matcher_fingerprint()
        or development_contract.policy_fingerprint
        != development_policy_fingerprint()
        or development_contract.build_fingerprint != build_fingerprint
        or development_contract.runtime_fingerprint
        != backend_authority.runtime_set_sha256
    ):
        raise FormalLockedSetReleaseError(
            "live development authority is stale for the formal runtime"
        )
    templates = live_development_authority.shadow_templates
    evaluator = LocalOcrLockedImageEvaluator(
        backend=ocr_backend,
        templates=templates,
        application_build_sha256=build_fingerprint,
        application_build_manifest=build_manifest,
        timeout_seconds=_LOCKED_OCR_TIMEOUT_SECONDS,
    )
    if (
        evaluator.run_context.runtime_set_sha256 != backend_authority.runtime_set_sha256
        or evaluator.run_context.ocr_composition_evidence_sha256
        != backend_authority.composition_evidence_sha256
        or evaluator.run_context.expected_runtime_kinds
        != tuple(identity.runtime_kind for identity in backend_authority.runtime_identities)
    ):
        raise FormalLockedSetReleaseError("formal evaluator runtime identity is not factory-bound")
    if existing is not None:
        existing = _replayable_evaluation(
            locked_repository,
            dataset_id=dataset_id,
        )
        return _committed_replay(
            existing,
            dataset_state="formal_evaluated",
            persisted_scan=persisted_scan,
            quality_coverage=quality_coverage,
            decisions=decisions,
            run_context=evaluator.run_context.to_payload(),
            actor_id=normalized_actor,
            idempotency_key=normalized_key,
        )

    with locked_repository.runtime.engine.connect() as connection:
        authority = require_current_preflight_authority(
            connection,
            dataset_id=dataset_id,
            manifest_sha256=persisted_scan.manifest_sha256,
            exclusion_snapshot_sha256=(persisted_scan.exclusion_snapshot_sha256),
            inventory_high_watermark=(persisted_scan.inventory_high_watermark),
        )
    if authority.exclusion_snapshot != historical_snapshot:
        raise FormalLockedSetReleaseError("current preflight authority changed before evaluation")
    report = run_locked_set_role_evaluation(
        manifest=manifest,
        preflight_attestation=_release_attestation(
            authority=authority,
        ),
        evaluator=evaluator,
        run_context=evaluator.run_context,
        quality_coverage=quality_coverage,
        near_duplicate_scan=scan.to_payload(),
        near_duplicate_decisions=decisions,
        eligibility_history=authority.eligibility_history,
        candidate_review_source_authority=(bound.candidate_review_source_authority),
    )
    outcome = locked_repository.persist_formal_release_evaluation(
        dataset_id=dataset_id,
        manifest_sha256=manifest.canonical_sha256,
        exclusion_snapshot_sha256=(persisted_scan.exclusion_snapshot_sha256),
        inventory_high_watermark=(persisted_scan.inventory_high_watermark),
        scan_fingerprint=scan.scan_fingerprint,
        runner_report=report,
        quality_coverage=quality_coverage,
        near_duplicate_decisions=decisions,
        actor_id=normalized_actor,
        idempotency_key=normalized_key,
    )
    try:
        committed = json.loads(outcome.evaluation.committed_report_json)
    except json.JSONDecodeError as exc:
        raise FormalLockedSetReleaseError("committed formal report is unreadable") from exc
    if not isinstance(committed, dict):
        raise FormalLockedSetReleaseError("committed formal report is invalid")
    _require_formal_report_claim_boundary(
        evaluation=outcome.evaluation,
        committed_report=committed,
        quality_coverage=quality_coverage,
    )
    return FormalLockedSetEvaluationResult(
        evaluation=outcome.evaluation,
        committed_report=committed,
        replayed=not outcome.applied,
    )
