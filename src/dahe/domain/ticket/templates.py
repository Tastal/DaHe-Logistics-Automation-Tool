from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from decimal import Decimal
from enum import StrEnum

from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.ticket_roles import TicketRole

MAX_ANCHOR_REGEX_CHARS = 512


class TicketField(StrEnum):
    ORDINARY_NET = "ordinary_net"
    FACTORY_NET = "factory_net"
    GROSS = "gross"
    TARE = "tare"
    LOADING_WEIGH_TIME = "loading_weigh_time"
    UNLOADING_TARE_TIME = "unloading_tare_time"
    PRINT_TIME = "print_time"


class AnchorMatchKind(StrEnum):
    LITERAL = "literal"
    CONTAINS = "contains"
    REGEX = "regex"


class TemplateLifecycle(StrEnum):
    DRAFT = "draft"
    DEVELOPMENT_TESTED = "development_tested"
    SHADOW = "shadow"
    ACTIVE = "active"
    RETIRED = "retired"


class TemplateTransitionError(DomainContractError):
    """Raised when a template lifecycle transition violates the current gate."""


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainContractError(f"{label} is required")


def _require_finite_decimal(value: Decimal, label: str) -> None:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise DomainContractError(f"{label} must be a finite decimal")


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


@dataclass(frozen=True, slots=True)
class NormalizedRect:
    x: Decimal
    y: Decimal
    width: Decimal
    height: Decimal

    def __post_init__(self) -> None:
        for label, value in (
            ("x", self.x),
            ("y", self.y),
            ("width", self.width),
            ("height", self.height),
        ):
            _require_finite_decimal(value, label)
        if self.x < 0 or self.y < 0:
            raise DomainContractError("normalized rectangle origin cannot be negative")
        if self.width <= 0 or self.height <= 0:
            raise DomainContractError("normalized rectangle dimensions must be positive")
        if self.x + self.width > 1 or self.y + self.height > 1:
            raise DomainContractError("normalized rectangle must stay inside the image")


@dataclass(frozen=True, slots=True)
class TemplateAnchor:
    anchor_id: str
    expected_text: str
    box: NormalizedRect
    required: bool
    weight: Decimal
    max_edit_distance: Decimal
    loading_evidence: Decimal
    unloading_evidence: Decimal
    match_kind: AnchorMatchKind = AnchorMatchKind.LITERAL

    def __post_init__(self) -> None:
        _require_text(self.anchor_id, "anchor_id")
        _require_text(self.expected_text, "expected_text")
        if not isinstance(self.match_kind, AnchorMatchKind):
            raise DomainContractError("anchor match kind is invalid")
        if self.match_kind is AnchorMatchKind.REGEX:
            if len(self.expected_text) > MAX_ANCHOR_REGEX_CHARS:
                raise DomainContractError("anchor regex exceeds its character limit")
            try:
                compiled = re.compile(self.expected_text)
            except re.error as exc:
                raise DomainContractError("anchor regex is invalid") from exc
            if compiled.search("") is not None:
                raise DomainContractError("anchor regex must not match empty text")
        if not isinstance(self.box, NormalizedRect):
            raise DomainContractError("anchor box is invalid")
        if not isinstance(self.required, bool):
            raise DomainContractError("anchor required flag is invalid")
        for label, value in (
            ("weight", self.weight),
            ("max_edit_distance", self.max_edit_distance),
            ("loading_evidence", self.loading_evidence),
            ("unloading_evidence", self.unloading_evidence),
        ):
            _require_finite_decimal(value, label)
        if self.weight <= 0:
            raise DomainContractError("anchor weight must be positive")
        if not 0 <= self.max_edit_distance <= 1:
            raise DomainContractError("anchor edit distance must be between zero and one")
        if not -1 <= self.loading_evidence <= 1:
            raise DomainContractError("loading role evidence must be between minus one and one")
        if not -1 <= self.unloading_evidence <= 1:
            raise DomainContractError(
                "unloading role evidence must be between minus one and one"
            )


@dataclass(frozen=True, slots=True)
class RecognitionRegion:
    region_id: str
    field: TicketField
    box: NormalizedRect
    relative_to_anchor_id: str | None
    unit: str | None
    format_pattern: str
    required: bool
    layout_scope: str

    def __post_init__(self) -> None:
        _require_text(self.region_id, "region_id")
        if not isinstance(self.field, TicketField):
            raise DomainContractError("recognition region field is invalid")
        if not isinstance(self.box, NormalizedRect):
            raise DomainContractError("recognition region box is invalid")
        if self.relative_to_anchor_id is not None:
            _require_text(self.relative_to_anchor_id, "relative_to_anchor_id")
        if self.unit is not None:
            _require_text(self.unit, "unit")
        _require_text(self.format_pattern, "format_pattern")
        _require_text(self.layout_scope, "layout_scope")
        if not isinstance(self.required, bool):
            raise DomainContractError("recognition region required flag is invalid")
        try:
            re.compile(self.format_pattern)
        except re.error as exc:
            raise DomainContractError("recognition region format pattern is invalid") from exc


@dataclass(frozen=True, slots=True)
class TemplateDefinition:
    family_id: str
    name: str
    role: TicketRole
    anchors: tuple[TemplateAnchor, ...]
    regions: tuple[RecognitionRegion, ...]

    def __post_init__(self) -> None:
        _require_text(self.family_id, "family_id")
        _require_text(self.name, "template name")
        if (
            not isinstance(self.role, TicketRole)
            or self.role is TicketRole.UNKNOWN
        ):
            raise DomainContractError(
                "template family role must be loading or unloading"
            )
        if not self.anchors:
            raise DomainContractError("template definition requires at least one anchor")
        anchor_ids = tuple(anchor.anchor_id for anchor in self.anchors)
        if len(set(anchor_ids)) != len(anchor_ids):
            raise DomainContractError("template anchor identifiers must be unique")
        region_ids = tuple(region.region_id for region in self.regions)
        if len(set(region_ids)) != len(region_ids):
            raise DomainContractError("template region identifiers must be unique")
        known_anchors = set(anchor_ids)
        if any(
            region.relative_to_anchor_id is not None
            and region.relative_to_anchor_id not in known_anchors
            for region in self.regions
        ):
            raise DomainContractError(
                "recognition region references an unknown template anchor"
            )


def _rect_payload(rectangle: NormalizedRect) -> dict[str, str]:
    return {
        "height": _decimal_text(rectangle.height),
        "width": _decimal_text(rectangle.width),
        "x": _decimal_text(rectangle.x),
        "y": _decimal_text(rectangle.y),
    }


def _anchor_payload(anchor: TemplateAnchor) -> dict[str, object]:
    return {
        "anchor_id": anchor.anchor_id,
        "box": _rect_payload(anchor.box),
        "expected_text": anchor.expected_text,
        "loading_evidence": _decimal_text(anchor.loading_evidence),
        "match_kind": anchor.match_kind.value,
        "max_edit_distance": _decimal_text(anchor.max_edit_distance),
        "required": anchor.required,
        "unloading_evidence": _decimal_text(anchor.unloading_evidence),
        "weight": _decimal_text(anchor.weight),
    }


def _region_payload(region: RecognitionRegion) -> dict[str, object]:
    return {
        "box": _rect_payload(region.box),
        "field": region.field.value,
        "format_pattern": region.format_pattern,
        "layout_scope": region.layout_scope,
        "region_id": region.region_id,
        "relative_to_anchor_id": region.relative_to_anchor_id,
        "required": region.required,
        "unit": region.unit,
    }


def canonical_template_hash(definition: TemplateDefinition) -> str:
    if not isinstance(definition, TemplateDefinition):
        raise DomainContractError("template definition is invalid")
    payload = {
        "anchors": [
            _anchor_payload(anchor)
            for anchor in sorted(definition.anchors, key=lambda item: item.anchor_id)
        ],
        "family_id": definition.family_id,
        "name": definition.name,
        "regions": [
            _region_payload(region)
            for region in sorted(definition.regions, key=lambda item: item.region_id)
        ],
        "role": definition.role.value,
        "schema_version": 1,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class TemplateVersion:
    version_id: str
    definition: TemplateDefinition
    lifecycle: TemplateLifecycle
    parent_version_id: str | None
    record_version: int
    version_number: int = 1

    def __post_init__(self) -> None:
        _require_text(self.version_id, "version_id")
        if not isinstance(self.definition, TemplateDefinition):
            raise DomainContractError("template version definition is invalid")
        if not isinstance(self.lifecycle, TemplateLifecycle):
            raise DomainContractError("template lifecycle is invalid")
        if self.parent_version_id is not None:
            _require_text(self.parent_version_id, "parent_version_id")
            if self.parent_version_id == self.version_id:
                raise DomainContractError("template version cannot be its own parent")
        if not isinstance(self.record_version, int) or self.record_version < 1:
            raise DomainContractError("template record version must be positive")
        if not isinstance(self.version_number, int) or self.version_number < 1:
            raise DomainContractError("template version number must be positive")

    @property
    def content_sha256(self) -> str:
        return canonical_template_hash(self.definition)


def transition_template_version(
    version: TemplateVersion,
    target: TemplateLifecycle,
    development_evaluation_passed: bool,
    authorized: bool,
) -> TemplateVersion:
    if not isinstance(version, TemplateVersion):
        raise TemplateTransitionError("template version is invalid")
    if not isinstance(target, TemplateLifecycle):
        raise TemplateTransitionError("template lifecycle target is invalid")
    if not isinstance(development_evaluation_passed, bool):
        raise TemplateTransitionError("development evaluation gate is invalid")
    if not isinstance(authorized, bool):
        raise TemplateTransitionError("template authorization gate is invalid")
    if target in {TemplateLifecycle.ACTIVE, TemplateLifecycle.RETIRED}:
        raise TemplateTransitionError(
            "Loop 7 templates cannot advance beyond shadow"
        )
    if target is version.lifecycle:
        return version
    if (
        version.lifecycle is TemplateLifecycle.DRAFT
        and target is TemplateLifecycle.DEVELOPMENT_TESTED
    ):
        if not development_evaluation_passed:
            raise TemplateTransitionError(
                "development evaluation must pass before promotion"
            )
    elif (
        version.lifecycle is TemplateLifecycle.DEVELOPMENT_TESTED
        and target is TemplateLifecycle.SHADOW
    ):
        if not development_evaluation_passed:
            raise TemplateTransitionError(
                "development evaluation must remain valid for shadow"
            )
        if not authorized:
            raise TemplateTransitionError(
                "shadow promotion requires protected maintenance authorization"
            )
    else:
        raise TemplateTransitionError("template lifecycle transition is not allowed")
    return replace(
        version,
        lifecycle=target,
        record_version=version.record_version + 1,
    )
