from __future__ import annotations

import hashlib
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateReferenceOriginInput,
)
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TicketField,
)


class InjectedOriginFailure(RuntimeError):
    pass


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _runtime(tmp_path: Path, project_root: Path, *, instance_id: str) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id=instance_id,
    )


def _repository(
    runtime: SqliteRuntime,
    *,
    failpoint: object | None = None,
) -> SqliteTemplateRepository:
    return SqliteTemplateRepository(
        runtime=runtime,
        accepted_build_fingerprint="8" * 64,
        accepted_runtime_fingerprint="9" * 64,
        accepted_development_manifest_sha256="4" * 64,
        accepted_matcher_fingerprint="6" * 64,
        accepted_policy_fingerprint="7" * 64,
        failpoint=failpoint,  # type: ignore[arg-type]
    )


def _definition() -> TemplateDefinition:
    return TemplateDefinition(
        family_id="candidate-loading-family",
        name="Candidate loading ticket",
        role=TicketRole.LOADING,
        anchors=(
            TemplateAnchor(
                anchor_id="loading-title",
                expected_text="装货磅单",
                box=NormalizedRect(
                    x=Decimal("0.10"),
                    y=Decimal("0.05"),
                    width=Decimal("0.35"),
                    height=Decimal("0.10"),
                ),
                required=True,
                weight=Decimal("1"),
                max_edit_distance=Decimal("0.15"),
                loading_evidence=Decimal("0.8"),
                unloading_evidence=Decimal("-0.2"),
                match_kind=AnchorMatchKind.LITERAL,
            ),
        ),
        regions=(
            RecognitionRegion(
                region_id="ordinary-net",
                field=TicketField.ORDINARY_NET,
                box=NormalizedRect(
                    x=Decimal("0.55"),
                    y=Decimal("0.55"),
                    width=Decimal("0.30"),
                    height=Decimal("0.12"),
                ),
                relative_to_anchor_id=None,
                unit="t",
                format_pattern=r"^\d{1,3}(?:\.\d{1,2})?$",
                required=True,
                layout_scope="full_ticket",
            ),
        ),
    )


def _evidence_path(sha256: str) -> str:
    return f"sha256/{sha256[:2]}/{sha256[2:4]}/{sha256}.blob"


def _seed_reference_evidence(
    runtime: SqliteRuntime,
    *,
    image_sha256: str,
    mask_sha256: str,
) -> None:
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        for digest in (image_sha256, mask_sha256):
            connection.execute(
                text(
                    """
                    INSERT INTO evidence_blobs (
                        sha256, relative_path, byte_size, media_type,
                        storage_state, record_version, created_at, verified_at
                    ) VALUES (
                        :sha256, :relative_path, 10, 'image/png',
                        'available', 1, :created_at, :verified_at
                    )
                    """
                ),
                {
                    "sha256": digest,
                    "relative_path": _evidence_path(digest),
                    "created_at": "2026-07-26T00:00:00+00:00",
                    "verified_at": "2026-07-26T00:00:00+00:00",
                },
            )


def _origin() -> TemplateReferenceOriginInput:
    source_image = _sha256("source-image")
    source_record = _sha256("source-record-blob")
    return TemplateReferenceOriginInput(
        candidate_evidence_sha256=_sha256("candidate-evidence"),
        candidate_record_blob_sha256=source_record,
        candidate_record_relative_path=_evidence_path(source_record),
        candidate_record_byte_size=512,
        source_image_sha256=source_image,
        source_image_relative_path=_evidence_path(source_image),
        source_image_byte_size=128,
        source_image_media_type="image/jpeg",
        waybill_identity_sha256=_sha256("waybill"),
        sample_id="L7-010",
        submitted_slot="unloading",
        confirmed_role=TicketRole.LOADING,
        package_sha256=_sha256("package"),
        review_history_authority_sha256=_sha256("review-history"),
        source_authority_sha256=_sha256("source-authority"),
        review_record_evidence_sha256=_sha256("review-record"),
    )


def test_candidate_origin_is_append_only_and_committed_with_all_exclusions(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="candidate-origin")
    try:
        repository = _repository(runtime)
        reference = _sha256("normalized-reference")
        mask = _sha256("reference-mask")
        _seed_reference_evidence(runtime, image_sha256=reference, mask_sha256=mask)
        origin = _origin()

        version, created = repository.create_draft(
            definition=_definition(),
            reference_image_sha256=reference,
            reference_mask_sha256=mask,
            alignment_fingerprint=_sha256("alignment"),
            actor_id="developer-a",
            idempotency_key="candidate-template-seed-1",
            reference_origin=origin,
        )

        assert created is True
        stored = repository.get_reference_origin(version.version_id)
        assert stored.version_id == version.version_id
        assert stored.candidate_evidence_sha256 == origin.candidate_evidence_sha256
        assert stored.source_image_sha256 == origin.source_image_sha256
        assert stored.waybill_identity_sha256 == origin.waybill_identity_sha256
        assert stored.sample_id == "L7-010"
        assert stored.submitted_slot == "unloading"
        assert stored.confirmed_role is TicketRole.LOADING

        with runtime.engine.connect() as connection:
            exclusions = set(
                connection.execute(
                    text(
                        """
                        SELECT category, identity_sha256, source_kind, source_id
                        FROM locked_set_exclusion_inventory
                        WHERE source_id = :version_id
                        """
                    ),
                    {"version_id": version.version_id},
                ).tuples()
            )
            holds = set(
                connection.execute(
                    text(
                        """
                        SELECT sha256, hold_kind, owner_id, released_at
                        FROM evidence_holds
                        WHERE owner_id = :version_id
                        """
                    ),
                    {"version_id": version.version_id},
                ).tuples()
            )
        assert (
            "development_image",
            origin.source_image_sha256,
            "template_reference_origin",
            version.version_id,
        ) in exclusions
        assert (
            "prior_waybill_identity",
            origin.waybill_identity_sha256,
            "template_reference_origin",
            version.version_id,
        ) in exclusions
        assert (
            origin.source_image_sha256,
            "template_reference_origin_image",
            version.version_id,
            None,
        ) in holds
        assert (
            origin.candidate_record_blob_sha256,
            "template_reference_origin_record",
            version.version_id,
            None,
        ) in holds

        with (
            pytest.raises(IntegrityError, match="append-only"),
            runtime.commit_gate.transaction(runtime.engine) as connection,
        ):
            connection.execute(
                text(
                    """
                    UPDATE template_reference_origins
                    SET sample_id = 'changed'
                    WHERE version_id = :version_id
                    """
                ),
                {"version_id": version.version_id},
            )
        with (
            pytest.raises(IntegrityError, match="append-only"),
            runtime.commit_gate.transaction(runtime.engine) as connection,
        ):
            connection.execute(
                text(
                    """
                    DELETE FROM template_reference_origins
                    WHERE version_id = :version_id
                    """
                ),
                {"version_id": version.version_id},
            )
    finally:
        runtime.close()


def test_candidate_origin_role_must_match_template_role(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root, instance_id="candidate-origin-role")
    try:
        repository = _repository(runtime)
        reference = _sha256("normalized-reference")
        mask = _sha256("reference-mask")
        _seed_reference_evidence(runtime, image_sha256=reference, mask_sha256=mask)
        origin = _origin()
        mismatched = TemplateReferenceOriginInput(
            **{
                field: getattr(origin, field)
                for field in origin.__dataclass_fields__
                if field != "confirmed_role"
            },
            confirmed_role=TicketRole.UNLOADING,
        )

        with pytest.raises(ValueError, match="confirmed role"):
            repository.create_draft(
                definition=_definition(),
                reference_image_sha256=reference,
                reference_mask_sha256=mask,
                alignment_fingerprint=_sha256("alignment"),
                actor_id="developer-a",
                idempotency_key="candidate-template-seed-role",
                reference_origin=mismatched,
            )
    finally:
        runtime.close()


def test_candidate_origin_and_draft_roll_back_together(
    tmp_path: Path,
    project_root: Path,
) -> None:
    def failpoint(name: str) -> None:
        if name == "after_reference_origin":
            raise InjectedOriginFailure

    runtime = _runtime(tmp_path, project_root, instance_id="candidate-origin-rollback")
    try:
        repository = _repository(runtime, failpoint=failpoint)
        reference = _sha256("normalized-reference")
        mask = _sha256("reference-mask")
        _seed_reference_evidence(runtime, image_sha256=reference, mask_sha256=mask)

        with pytest.raises(InjectedOriginFailure):
            repository.create_draft(
                definition=_definition(),
                reference_image_sha256=reference,
                reference_mask_sha256=mask,
                alignment_fingerprint=_sha256("alignment"),
                actor_id="developer-a",
                idempotency_key="candidate-template-seed-rollback",
                reference_origin=_origin(),
            )

        with runtime.engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        """
                        SELECT
                            (SELECT count(*) FROM template_versions),
                            (SELECT count(*) FROM template_reference_origins),
                            (
                                SELECT count(*)
                                FROM locked_set_exclusion_inventory
                                WHERE source_kind = 'template_reference_origin'
                            ),
                            (
                                SELECT count(*)
                                FROM evidence_holds
                                WHERE hold_kind LIKE 'template_reference_origin_%'
                            )
                        """
                    )
                ).one()
                == (0, 0, 0, 0)
            )
    finally:
        runtime.close()
