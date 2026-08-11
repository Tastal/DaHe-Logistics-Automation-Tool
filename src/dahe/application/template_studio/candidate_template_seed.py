from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import cast

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
    EvidenceIntegrityError,
)
from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateReferenceOriginInput,
    TemplateReferenceOriginRecord,
    serialize_template_definition,
)
from dahe.application.template_studio.candidate_development_ocr_run_authority import (
    CandidateDevelopmentOcrRunAuthorityError,
    load_authorized_candidate_development_ocr_evidence,
)
from dahe.application.template_studio.reference_images import (
    TemplateReferenceImageError,
    build_template_reference_mask,
    normalize_template_reference_image,
    template_reference_alignment_fingerprint,
)
from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TemplateVersion,
    TicketField,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SLOTS = frozenset({"loading", "unloading"})
_KNOWN_ROLES = frozenset({"loading", "unloading"})
_UNSUITABLE_QUALITY = frozenset({"unknown_layout", "non_ticket"})
_MAX_DEFINITION_BYTES = 512 * 1024


class CandidateTemplateSeedError(RuntimeError):
    """Raised when a development-only template source is not trustworthy."""


@dataclass(frozen=True, slots=True)
class CandidateDevelopmentTemplateSource:
    candidate_evidence_sha256: str
    candidate_record_content: bytes
    source_image_sha256: str
    source_image_content: bytes
    source_image_media_type: str
    waybill_identity_sha256: str
    sample_id: str
    submitted_slot: str
    confirmed_role: TicketRole
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    review_record_evidence_sha256: str


@dataclass(frozen=True, slots=True)
class CandidateTemplateSeedResult:
    version: TemplateVersion
    origin: TemplateReferenceOriginRecord
    created: bool


def _object(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CandidateTemplateSeedError(f"{label} must be an object")
    return value


def _objects(value: object, *, label: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(
        not isinstance(item, Mapping) for item in value
    ):
        raise CandidateTemplateSeedError(f"{label} must be an object list")
    return cast(list[Mapping[str, object]], value)


def _text(
    value: object,
    *,
    label: str,
    maximum: int = 200,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > maximum
    ):
        raise CandidateTemplateSeedError(f"{label} is invalid")
    return value


def _sha256(value: object, *, label: str) -> str:
    digest = _text(value, label=label, maximum=64)
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise CandidateTemplateSeedError(
            f"{label} must be a lowercase SHA-256"
        )
    return digest


def _selected_human_source(
    *,
    manifest: Mapping[str, object],
    source_authority: Mapping[str, object],
    sample_id: str,
    submitted_slot: str,
    expected_role: str,
) -> tuple[str, str, str, str]:
    if submitted_slot not in _SLOTS:
        raise CandidateTemplateSeedError("submitted slot is invalid")
    if expected_role not in _KNOWN_ROLES:
        raise CandidateTemplateSeedError("expected ticket role is invalid")
    manifest_waybill = next(
        (
            item
            for item in _objects(
                manifest.get("waybills"),
                label="candidate manifest waybills",
            )
            if item.get("sample_id") == sample_id
        ),
        None,
    )
    source_record = next(
        (
            item
            for item in _objects(
                source_authority.get("records"),
                label="candidate source records",
            )
            if item.get("sample_id") == sample_id
        ),
        None,
    )
    if manifest_waybill is None or source_record is None:
        raise CandidateTemplateSeedError(
            "selected candidate sample does not exist"
        )
    manifest_image = next(
        (
            item
            for item in _objects(
                manifest_waybill.get("images"),
                label="candidate manifest images",
            )
            if item.get("submitted_slot") == submitted_slot
        ),
        None,
    )
    review_payload = _object(
        source_record.get("review_payload"),
        label="candidate review payload",
    )
    review_image = next(
        (
            item
            for item in _objects(
                review_payload.get("images"),
                label="candidate review images",
            )
            if item.get("submitted_slot") == submitted_slot
        ),
        None,
    )
    if manifest_image is None or review_image is None:
        raise CandidateTemplateSeedError(
            "selected candidate image does not exist"
        )
    quality = review_image.get("quality_conditions")
    if not isinstance(quality, list) or any(
        not isinstance(item, str) for item in quality
    ):
        raise CandidateTemplateSeedError(
            "selected candidate quality authority is invalid"
        )
    role = manifest_image.get("role")
    if (
        role not in _KNOWN_ROLES
        or review_image.get("role") != role
        or _UNSUITABLE_QUALITY.intersection(quality)
    ):
        raise CandidateTemplateSeedError(
            "selected candidate is unknown or non-ticket evidence"
        )
    if role != expected_role:
        raise CandidateTemplateSeedError(
            "selected candidate role does not match the expected role"
        )
    role_text = _text(
        role,
        label="selected candidate confirmed role",
        maximum=20,
    )
    return (
        _sha256(
            manifest_image.get("image_sha256"),
            label="selected candidate image SHA-256",
        ),
        _sha256(
            manifest_waybill.get("waybill_identity_sha256"),
            label="selected candidate waybill identity SHA-256",
        ),
        _sha256(
            source_record.get("record_evidence_sha256"),
            label="selected review record evidence SHA-256",
        ),
        role_text,
    )


def load_candidate_development_template_source(
    *,
    run_repository: SqliteCandidateDevelopmentOcrRunRepository,
    data_root: Path,
    evidence_path: Path,
    expected_evidence_sha256: str,
    sample_id: str,
    submitted_slot: str,
    expected_role: str,
) -> CandidateDevelopmentTemplateSource:
    """Revalidate and select one human-confirmed development source image."""

    evidence_identity = _sha256(
        expected_evidence_sha256,
        label="expected candidate evidence SHA-256",
    )
    sample = _text(
        sample_id,
        label="selected candidate sample ID",
        maximum=100,
    )
    try:
        authorized = (
            load_authorized_candidate_development_ocr_evidence(
                run_repository,
                data_root=data_root,
                evidence_path=evidence_path,
                expected_evidence_sha256=evidence_identity,
            )
        )
    except CandidateDevelopmentOcrRunAuthorityError as exc:
        raise CandidateTemplateSeedError(str(exc)) from exc
    payload = authorized.payload
    source = _object(
        payload.get("source"),
        label="candidate evidence source",
    )
    manifest = _object(
        source.get("manifest_payload"),
        label="candidate manifest",
    )
    source_authority = _object(
        source.get("source_authority_payload"),
        label="candidate source authority",
    )
    (
        source_image_sha256,
        waybill_identity_sha256,
        review_record_evidence_sha256,
        confirmed_role,
    ) = _selected_human_source(
        manifest=manifest,
        source_authority=source_authority,
        sample_id=sample,
        submitted_slot=submitted_slot,
        expected_role=expected_role,
    )
    copied_image = next(
        (
            item
            for item in _objects(
                payload.get("copied_images"),
                label="candidate copied images",
            )
            if item.get("image_sha256") == source_image_sha256
        ),
        None,
    )
    if copied_image is None:
        raise CandidateTemplateSeedError(
            "selected candidate image is absent from OCR evidence"
        )
    relative_path = PurePosixPath(
        _text(
            copied_image.get("relative_path"),
            label="selected candidate image path",
            maximum=500,
        )
    )
    source_image_media_type = _text(
        copied_image.get("media_type"),
        label="selected candidate image media type",
        maximum=100,
    )
    source_image_path = data_root.joinpath(*relative_path.parts)
    try:
        source_image_content = source_image_path.read_bytes()
    except OSError as exc:
        raise CandidateTemplateSeedError(
            "selected candidate image is unavailable"
        ) from exc
    if (
        hashlib.sha256(source_image_content).hexdigest()
        != source_image_sha256
        or len(source_image_content)
        != copied_image.get("byte_size")
    ):
        raise CandidateTemplateSeedError(
            "selected candidate image integrity changed"
        )
    try:
        normalize_template_reference_image(
            source_image_content,
            declared_media_type=source_image_media_type,
        )
    except TemplateReferenceImageError as exc:
        raise CandidateTemplateSeedError(
            "selected candidate is not a supported JPEG or PNG"
        ) from exc
    authority = authorized.authority
    return CandidateDevelopmentTemplateSource(
        candidate_evidence_sha256=evidence_identity,
        candidate_record_content=authorized.record_content,
        source_image_sha256=source_image_sha256,
        source_image_content=source_image_content,
        source_image_media_type=source_image_media_type,
        waybill_identity_sha256=waybill_identity_sha256,
        sample_id=sample,
        submitted_slot=submitted_slot,
        confirmed_role=TicketRole(confirmed_role),
        package_sha256=authority.package_sha256,
        review_history_authority_sha256=(
            authority.review_history_authority_sha256
        ),
        source_authority_sha256=authority.source_authority_sha256,
        review_record_evidence_sha256=(
            review_record_evidence_sha256
        ),
    )


def _strict_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CandidateTemplateSeedError(f"{label} must be an object")
    return value


def _strict_sequence(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise CandidateTemplateSeedError(f"{label} must be an array")
    return value


def _definition_text(
    payload: Mapping[str, object],
    field: str,
) -> str:
    return _text(
        payload.get(field),
        label=f"template definition {field}",
        maximum=512,
    )


def _definition_bool(
    payload: Mapping[str, object],
    field: str,
) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise CandidateTemplateSeedError(
            f"template definition {field} must be boolean"
        )
    return value


def _definition_rect(value: object) -> NormalizedRect:
    payload = _strict_mapping(
        value,
        label="template definition rectangle",
    )
    if set(payload) != {"x", "y", "width", "height"}:
        raise CandidateTemplateSeedError(
            "template definition rectangle contract is invalid"
        )
    try:
        return NormalizedRect(
            x=Decimal(_definition_text(payload, "x")),
            y=Decimal(_definition_text(payload, "y")),
            width=Decimal(_definition_text(payload, "width")),
            height=Decimal(_definition_text(payload, "height")),
        )
    except (ArithmeticError, DomainContractError) as exc:
        raise CandidateTemplateSeedError(
            "template definition rectangle is invalid"
        ) from exc


def _template_definition_from_payload(
    value: object,
) -> TemplateDefinition:
    payload = _strict_mapping(
        value,
        label="template definition",
    )
    if set(payload) != {
        "anchors",
        "family_id",
        "name",
        "regions",
        "role",
    }:
        raise CandidateTemplateSeedError(
            "template definition contract is invalid"
        )
    try:
        anchors = tuple(
            TemplateAnchor(
                anchor_id=_definition_text(anchor, "anchor_id"),
                expected_text=_definition_text(
                    anchor,
                    "expected_text",
                ),
                box=_definition_rect(anchor.get("box")),
                required=_definition_bool(anchor, "required"),
                weight=Decimal(_definition_text(anchor, "weight")),
                max_edit_distance=Decimal(
                    _definition_text(anchor, "max_edit_distance")
                ),
                loading_evidence=Decimal(
                    _definition_text(anchor, "loading_evidence")
                ),
                unloading_evidence=Decimal(
                    _definition_text(anchor, "unloading_evidence")
                ),
                match_kind=AnchorMatchKind(
                    _definition_text(anchor, "match_kind")
                ),
            )
            for anchor in (
                _strict_mapping(
                    item,
                    label="template definition anchor",
                )
                for item in _strict_sequence(
                    payload.get("anchors"),
                    label="template definition anchors",
                )
            )
            if set(anchor)
            == {
                "anchor_id",
                "box",
                "expected_text",
                "loading_evidence",
                "match_kind",
                "max_edit_distance",
                "required",
                "unloading_evidence",
                "weight",
            }
        )
        raw_anchors = _strict_sequence(
            payload.get("anchors"),
            label="template definition anchors",
        )
        if len(anchors) != len(raw_anchors):
            raise CandidateTemplateSeedError(
                "template definition anchor contract is invalid"
            )
        regions = tuple(
            RecognitionRegion(
                region_id=_definition_text(region, "region_id"),
                field=TicketField(
                    _definition_text(region, "field")
                ),
                box=_definition_rect(region.get("box")),
                relative_to_anchor_id=(
                    None
                    if region.get("relative_to_anchor_id") is None
                    else _definition_text(
                        region,
                        "relative_to_anchor_id",
                    )
                ),
                unit=(
                    None
                    if region.get("unit") is None
                    else _definition_text(region, "unit")
                ),
                format_pattern=_definition_text(
                    region,
                    "format_pattern",
                ),
                required=_definition_bool(region, "required"),
                layout_scope=_definition_text(
                    region,
                    "layout_scope",
                ),
            )
            for region in (
                _strict_mapping(
                    item,
                    label="template definition region",
                )
                for item in _strict_sequence(
                    payload.get("regions"),
                    label="template definition regions",
                )
            )
            if set(region)
            == {
                "box",
                "field",
                "format_pattern",
                "layout_scope",
                "region_id",
                "relative_to_anchor_id",
                "required",
                "unit",
            }
        )
        raw_regions = _strict_sequence(
            payload.get("regions"),
            label="template definition regions",
        )
        if len(regions) != len(raw_regions):
            raise CandidateTemplateSeedError(
                "template definition region contract is invalid"
            )
        definition = TemplateDefinition(
            family_id=_definition_text(payload, "family_id"),
            name=_definition_text(payload, "name"),
            role=TicketRole(_definition_text(payload, "role")),
            anchors=anchors,
            regions=regions,
        )
    except (
        ArithmeticError,
        DomainContractError,
        ValueError,
    ) as exc:
        if isinstance(exc, CandidateTemplateSeedError):
            raise
        raise CandidateTemplateSeedError(
            "template definition is invalid"
        ) from exc
    if serialize_template_definition(definition) != payload:
        raise CandidateTemplateSeedError(
            "template definition must use the canonical JSON contract"
        )
    return definition


def load_template_definition(path: Path) -> TemplateDefinition:
    if not path.is_absolute():
        raise CandidateTemplateSeedError(
            "template definition path must be absolute"
        )
    try:
        resolved = path.resolve(strict=True)
        if (
            resolved != path
            or not resolved.is_file()
            or resolved.stat().st_size > _MAX_DEFINITION_BYTES
        ):
            raise CandidateTemplateSeedError(
                "template definition path is invalid"
            )
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateTemplateSeedError(
            "template definition is unreadable"
        ) from exc
    return _template_definition_from_payload(payload)


def _derived_idempotency_key(
    operation: str,
    idempotency_key: str,
) -> str:
    return hashlib.sha256(
        f"{operation}\0{idempotency_key}".encode()
    ).hexdigest()


def seed_candidate_development_template(
    repository: SqliteTemplateRepository,
    *,
    definition: TemplateDefinition,
    source: CandidateDevelopmentTemplateSource,
    actor_id: str,
    idempotency_key: str,
) -> CandidateTemplateSeedResult:
    """Normalize, mask, and atomically bind one candidate-sourced draft."""

    if not isinstance(repository, SqliteTemplateRepository):
        raise CandidateTemplateSeedError(
            "template repository is invalid"
        )
    if not isinstance(definition, TemplateDefinition):
        raise CandidateTemplateSeedError(
            "template definition is invalid"
        )
    if not isinstance(source, CandidateDevelopmentTemplateSource):
        raise CandidateTemplateSeedError(
            "candidate template source is invalid"
        )
    if definition.role is not source.confirmed_role:
        raise CandidateTemplateSeedError(
            "template definition role does not match the candidate source"
        )
    evidence_store = ContentAddressedEvidenceStore(
        repository.runtime.data_root / "evidence"
    )
    try:
        original = evidence_store.put_bytes(
            source.source_image_content,
            media_type=source.source_image_media_type,
        )
        candidate_record = evidence_store.put_bytes(
            source.candidate_record_content,
            media_type="application/json",
        )
        normalized = normalize_template_reference_image(
            source.source_image_content,
            declared_media_type=source.source_image_media_type,
        )
        reference = evidence_store.put_bytes(
            normalized.content,
            media_type=normalized.media_type,
        )
        mask_content = build_template_reference_mask(
            width=normalized.width,
            height=normalized.height,
            anchors=tuple(anchor.box for anchor in definition.anchors),
        )
        mask = evidence_store.put_bytes(
            mask_content,
            media_type="image/png",
        )
    except (
        EvidenceIntegrityError,
        OSError,
        TemplateReferenceImageError,
    ) as exc:
        raise CandidateTemplateSeedError(
            "candidate template evidence could not be normalized safely"
        ) from exc
    if original.sha256 != source.source_image_sha256:
        raise CandidateTemplateSeedError(
            "candidate source image changed before template creation"
        )
    staged, _ = repository.stage_reference_upload(
        image_sha256=reference.sha256,
        relative_path=reference.relative_path,
        byte_size=reference.byte_size,
        media_type=reference.media_type,
        width=normalized.width,
        height=normalized.height,
        actor_id=actor_id,
        idempotency_key=_derived_idempotency_key(
            "stage-reference",
            idempotency_key,
        ),
    )
    repository.register_derived_template_mask(
        sha256=mask.sha256,
        relative_path=mask.relative_path,
        byte_size=mask.byte_size,
        actor_id=actor_id,
        idempotency_key=_derived_idempotency_key(
            "register-mask",
            idempotency_key,
        ),
    )
    version, created = repository.create_draft(
        definition=definition,
        reference_image_sha256=reference.sha256,
        reference_mask_sha256=mask.sha256,
        alignment_fingerprint=template_reference_alignment_fingerprint(
            image_sha256=reference.sha256,
            width=normalized.width,
            height=normalized.height,
        ),
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        staged_reference_id=staged.staged_reference_id,
        expected_staged_reference_record_version=staged.record_version,
        reference_origin=TemplateReferenceOriginInput(
            candidate_evidence_sha256=(
                source.candidate_evidence_sha256
            ),
            candidate_record_blob_sha256=candidate_record.sha256,
            candidate_record_relative_path=(
                candidate_record.relative_path
            ),
            candidate_record_byte_size=candidate_record.byte_size,
            source_image_sha256=original.sha256,
            source_image_relative_path=original.relative_path,
            source_image_byte_size=original.byte_size,
            source_image_media_type=original.media_type,
            waybill_identity_sha256=(
                source.waybill_identity_sha256
            ),
            sample_id=source.sample_id,
            submitted_slot=source.submitted_slot,
            confirmed_role=source.confirmed_role,
            package_sha256=source.package_sha256,
            review_history_authority_sha256=(
                source.review_history_authority_sha256
            ),
            source_authority_sha256=(
                source.source_authority_sha256
            ),
            review_record_evidence_sha256=(
                source.review_record_evidence_sha256
            ),
        ),
    )
    return CandidateTemplateSeedResult(
        version=version,
        origin=repository.get_reference_origin(version.version_id),
        created=created,
    )
