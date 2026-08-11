from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateTransitionError,
    TemplateVersion,
    TicketField,
    canonical_template_hash,
    transition_template_version,
)


def _rect(
    x: str = "0.10",
    y: str = "0.10",
    width: str = "0.30",
    height: str = "0.10",
) -> NormalizedRect:
    return NormalizedRect(
        x=Decimal(x),
        y=Decimal(y),
        width=Decimal(width),
        height=Decimal(height),
    )


def _anchor(
    anchor_id: str,
    *,
    expected_text: str,
    box: NormalizedRect | None = None,
) -> TemplateAnchor:
    return TemplateAnchor(
        anchor_id=anchor_id,
        expected_text=expected_text,
        box=box or _rect(),
        required=True,
        weight=Decimal("1"),
        max_edit_distance=Decimal("0.15"),
        loading_evidence=Decimal("0.8"),
        unloading_evidence=Decimal("-0.2"),
    )


def _region(
    region_id: str,
    *,
    field: TicketField,
    relative_to_anchor_id: str | None,
    box: NormalizedRect | None = None,
    unit: str | None = "t",
) -> RecognitionRegion:
    return RecognitionRegion(
        region_id=region_id,
        field=field,
        box=box or _rect("0.55", "0.10", "0.25", "0.12"),
        relative_to_anchor_id=relative_to_anchor_id,
        unit=unit,
        format_pattern=r"^\d{1,4}(?:\.\d{1,3})?$",
        required=True,
        layout_scope="ticket",
    )


def _definition(
    *,
    role: TicketRole = TicketRole.LOADING,
    anchors: tuple[TemplateAnchor, ...] | None = None,
    regions: tuple[RecognitionRegion, ...] | None = None,
) -> TemplateDefinition:
    actual_anchors = anchors or (
        _anchor("title", expected_text="装货磅单"),
        _anchor(
            "ordinary-net-label",
            expected_text="净重",
            box=_rect("0.10", "0.55", "0.20", "0.10"),
        ),
    )
    actual_regions = regions or (
        _region(
            "ordinary-net",
            field=TicketField.ORDINARY_NET,
            relative_to_anchor_id="ordinary-net-label",
            box=_rect("0.45", "0.55", "0.25", "0.10"),
        ),
    )
    return TemplateDefinition(
        family_id="synthetic-loading-family",
        name="Synthetic loading ticket",
        role=role,
        anchors=actual_anchors,
        regions=actual_regions,
    )


def _version(
    lifecycle: TemplateLifecycle = TemplateLifecycle.DRAFT,
) -> TemplateVersion:
    return TemplateVersion(
        version_id="synthetic-loading-v1",
        definition=_definition(),
        lifecycle=lifecycle,
        parent_version_id=None,
        record_version=1,
    )


@pytest.mark.parametrize(
    ("x", "y", "width", "height"),
    [
        ("-0.01", "0", "0.1", "0.1"),
        ("0", "-0.01", "0.1", "0.1"),
        ("0", "0", "0", "0.1"),
        ("0", "0", "0.1", "0"),
        ("0.90", "0", "0.11", "0.1"),
        ("0", "0.95", "0.1", "0.06"),
    ],
)
def test_normalized_rect_rejects_out_of_bounds_geometry(
    x: str,
    y: str,
    width: str,
    height: str,
) -> None:
    with pytest.raises(DomainContractError):
        _rect(x, y, width, height)


def test_template_fields_model_business_values_separately() -> None:
    required = {
        TicketField.ORDINARY_NET,
        TicketField.FACTORY_NET,
        TicketField.GROSS,
        TicketField.TARE,
        TicketField.LOADING_WEIGH_TIME,
        TicketField.UNLOADING_TARE_TIME,
        TicketField.PRINT_TIME,
    }

    assert required.issubset(set(TicketField))


def test_template_family_rejects_unknown_as_a_declared_role() -> None:
    with pytest.raises(DomainContractError):
        _definition(role=TicketRole.UNKNOWN)


def test_recognition_region_must_reference_an_anchor_in_the_same_template() -> None:
    with pytest.raises(DomainContractError):
        _definition(
            regions=(
                _region(
                    "ordinary-net",
                    field=TicketField.ORDINARY_NET,
                    relative_to_anchor_id="missing-anchor",
                ),
            )
        )


def test_recognition_region_can_use_an_absolute_normalized_box() -> None:
    region = _region(
        "absolute-ordinary-net",
        field=TicketField.ORDINARY_NET,
        relative_to_anchor_id=None,
    )

    definition = _definition(regions=(region,))

    assert definition.regions[0].relative_to_anchor_id is None


def test_time_recognition_region_can_omit_a_unit() -> None:
    region = _region(
        "print-time",
        field=TicketField.PRINT_TIME,
        relative_to_anchor_id=None,
        unit=None,
    )

    definition = _definition(regions=(region,))

    assert definition.regions[0].unit is None


def test_template_identifiers_are_unique_within_one_definition() -> None:
    repeated = _anchor("title", expected_text="装货磅单")
    with pytest.raises(DomainContractError):
        _definition(anchors=(repeated, repeated))


def test_canonical_hash_is_stable_across_order_and_decimal_spelling() -> None:
    first = _definition()
    reordered = _definition(
        anchors=tuple(reversed(first.anchors)),
        regions=tuple(reversed(first.regions)),
    )
    normalized_decimal = _definition(
        anchors=(
            replace(first.anchors[0], box=_rect("0.1", "0.1", "0.3", "0.1")),
            first.anchors[1],
        )
    )

    assert canonical_template_hash(first) == canonical_template_hash(reordered)
    assert canonical_template_hash(first) == canonical_template_hash(normalized_decimal)
    assert len(canonical_template_hash(first)) == 64


def test_canonical_hash_changes_for_role_anchor_or_region_changes() -> None:
    original = _definition()
    changed_role = replace(original, role=TicketRole.UNLOADING)
    changed_anchor = replace(
        original,
        anchors=(
            replace(original.anchors[0], expected_text="卸货磅单"),
            *original.anchors[1:],
        ),
    )
    changed_region = replace(
        original,
        regions=(
            replace(
                original.regions[0],
                box=_rect("0.50", "0.55", "0.25", "0.10"),
            ),
        ),
    )

    hashes = {
        canonical_template_hash(original),
        canonical_template_hash(changed_role),
        canonical_template_hash(changed_anchor),
        canonical_template_hash(changed_region),
    }
    assert len(hashes) == 4


def test_anchor_match_kind_defaults_to_literal_and_changes_content_identity() -> None:
    literal = _definition()
    contains = replace(
        literal,
        anchors=(
            replace(
                literal.anchors[0],
                match_kind=AnchorMatchKind.CONTAINS,
            ),
            *literal.anchors[1:],
        ),
    )

    assert literal.anchors[0].match_kind is AnchorMatchKind.LITERAL
    assert canonical_template_hash(literal) != canonical_template_hash(contains)


@pytest.mark.parametrize(
    "pattern",
    [
        "[unterminated",
        "a" * 513,
    ],
)
def test_regex_anchor_rejects_invalid_or_oversized_patterns(pattern: str) -> None:
    with pytest.raises(DomainContractError):
        replace(
            _anchor("regex-title", expected_text="装货.*磅单"),
            expected_text=pattern,
            match_kind=AnchorMatchKind.REGEX,
        )


@pytest.mark.parametrize("pattern", [".*", "^", "a*", "(?:)"])
def test_regex_anchor_rejects_patterns_that_match_empty_text(pattern: str) -> None:
    with pytest.raises(DomainContractError, match="empty"):
        replace(
            _anchor("regex-title", expected_text="装货.*磅单"),
            expected_text=pattern,
            match_kind=AnchorMatchKind.REGEX,
        )


def test_template_version_content_hash_does_not_include_lifecycle_state() -> None:
    draft = _version()
    tested = replace(draft, lifecycle=TemplateLifecycle.DEVELOPMENT_TESTED)

    assert draft.content_sha256 == canonical_template_hash(draft.definition)
    assert tested.content_sha256 == draft.content_sha256


def test_draft_requires_a_passing_development_evaluation_before_promotion() -> None:
    with pytest.raises(TemplateTransitionError):
        transition_template_version(
            _version(),
            target=TemplateLifecycle.DEVELOPMENT_TESTED,
            development_evaluation_passed=False,
            authorized=True,
        )

    tested = transition_template_version(
        _version(),
        target=TemplateLifecycle.DEVELOPMENT_TESTED,
        development_evaluation_passed=True,
        authorized=True,
    )
    assert tested.lifecycle is TemplateLifecycle.DEVELOPMENT_TESTED


def test_template_cannot_skip_directly_from_draft_to_shadow() -> None:
    with pytest.raises(TemplateTransitionError):
        transition_template_version(
            _version(),
            target=TemplateLifecycle.SHADOW,
            development_evaluation_passed=True,
            authorized=True,
        )


def test_shadow_promotion_requires_protected_maintenance_authorization() -> None:
    tested = _version(TemplateLifecycle.DEVELOPMENT_TESTED)

    with pytest.raises(TemplateTransitionError):
        transition_template_version(
            tested,
            target=TemplateLifecycle.SHADOW,
            development_evaluation_passed=True,
            authorized=False,
        )

    shadow = transition_template_version(
        tested,
        target=TemplateLifecycle.SHADOW,
        development_evaluation_passed=True,
        authorized=True,
    )
    assert shadow.lifecycle is TemplateLifecycle.SHADOW


@pytest.mark.parametrize(
    "source",
    [
        TemplateLifecycle.DRAFT,
        TemplateLifecycle.DEVELOPMENT_TESTED,
        TemplateLifecycle.SHADOW,
    ],
)
def test_loop7_never_allows_an_active_template(
    source: TemplateLifecycle,
) -> None:
    with pytest.raises(TemplateTransitionError):
        transition_template_version(
            _version(source),
            target=TemplateLifecycle.ACTIVE,
            development_evaluation_passed=True,
            authorized=True,
        )
