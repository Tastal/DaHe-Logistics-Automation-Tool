from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from decimal import Decimal
from difflib import SequenceMatcher
from time import perf_counter_ns

from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.role_assessment import (
    RoleAssessmentPolicy,
    RoleEvidence,
    RoleEvidenceSource,
    RoleObservation,
    TicketRoleAssessment,
    assess_ticket_role,
)
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    TemplateAnchor,
    TemplateLifecycle,
    TemplateVersion,
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GEOMETRY_TOLERANCE = Decimal("0.12")
SCORE_QUANTUM = Decimal("0.000001")
LOADING_TERMS = (
    "装货",
    "装车",
    "客户名称",
    "提示信息",
    "保存成功",
    "loading",
)
UNLOADING_TERMS = (
    "卸货",
    "卸车",
    "工厂净重",
    "称重来源",
    "收货单位",
    "进货",
    "到达站",
    "unloading",
)
LOADING_KIOSK_TERMS = ("全程禁止下车", "服务热线")
LOADING_KIOSK_MATCH_ID = "loading:kiosk-safety-hotline"
TICKET_TERMS = ("磅单", "毛重", "皮重", "净重", "称重", "ticket", "gross", "tare", "net")
MATCHER_VERSION = "loop7-template-matcher-v5"


@dataclass(frozen=True, slots=True)
class ObservedTextLine:
    text: str
    confidence: Decimal
    box: NormalizedRect

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise DomainContractError("observed text is required")
        if (
            not isinstance(self.confidence, Decimal)
            or not self.confidence.is_finite()
            or not 0 <= self.confidence <= 1
        ):
            raise DomainContractError("observed text confidence must be between zero and one")
        if not isinstance(self.box, NormalizedRect):
            raise DomainContractError("observed text box is invalid")


@dataclass(frozen=True, slots=True)
class TemplateRoleInput:
    image_sha256: str
    text_lines: tuple[ObservedTextLine, ...]
    fixed_text: tuple[str, ...]
    ordinary_net_reliable: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.image_sha256, str)
            or SHA256_PATTERN.fullmatch(self.image_sha256) is None
        ):
            raise DomainContractError("role input image identity must be a lowercase SHA-256")
        if any(not isinstance(line, ObservedTextLine) for line in self.text_lines):
            raise DomainContractError("role input contains an invalid text line")
        if any(not isinstance(text, str) or not text.strip() for text in self.fixed_text):
            raise DomainContractError("role input fixed text is invalid")
        if not isinstance(self.ordinary_net_reliable, bool):
            raise DomainContractError("role input ordinary net reliability is invalid")

    def _with_authoritative_ordinary_net(
        self,
        *,
        reliable: bool,
    ) -> TemplateRoleInput:
        if not isinstance(reliable, bool):
            raise DomainContractError("ordinary net reliability must be a boolean")
        object.__setattr__(self, "ordinary_net_reliable", reliable)
        return self


@dataclass(frozen=True, slots=True)
class TemplateRoleRun:
    observation: RoleObservation
    assessment: TicketRoleAssessment
    template_set_fingerprint: str
    elapsed_ms: Decimal


@dataclass(frozen=True, slots=True)
class DevelopmentEvaluationTemplateSet:
    """A lifecycle-checked template set that cannot be used by production matching."""

    versions: tuple[TemplateVersion, ...]
    fingerprint: str


@dataclass(frozen=True, slots=True)
class _OrientationScores:
    orientation: int
    template_loading: Decimal
    template_unloading: Decimal
    layout_loading: Decimal
    layout_unloading: Decimal
    alignment_score: Decimal
    template_loading_provenance: frozenset[str]
    template_unloading_provenance: frozenset[str]
    template_matches: tuple[str, ...]
    layout_matches: tuple[str, ...]

    @property
    def rank(
        self,
    ) -> tuple[Decimal, Decimal, Decimal, Decimal, Decimal, int]:
        template_peak = max(self.template_loading, self.template_unloading)
        template_total = self.template_loading + self.template_unloading
        layout_peak = max(self.layout_loading, self.layout_unloading)
        layout_total = self.layout_loading + self.layout_unloading
        return (
            template_peak,
            template_total,
            self.alignment_score,
            layout_peak,
            layout_total,
            -self.orientation,
        )


@dataclass(frozen=True, slots=True)
class _AnchorMatch:
    text_score: Decimal
    geometry_score: Decimal
    provenance: frozenset[str]


@dataclass(frozen=True, slots=True)
class _VersionScores:
    template_loading: Decimal
    template_unloading: Decimal
    layout_loading: Decimal
    layout_unloading: Decimal
    alignment_score: Decimal
    loading_provenance: frozenset[str]
    unloading_provenance: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ObservedRoleText:
    text: str
    provenance: frozenset[str]


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


def _canonical_fingerprint(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_template_set_fingerprint(
    versions: tuple[TemplateVersion, ...],
) -> str:
    if any(version.lifecycle is not TemplateLifecycle.SHADOW for version in versions):
        raise ValueError("template matching accepts shadow versions only")
    _require_unique_families(versions, label="shadow")
    identities = [
        {
            "content_sha256": version.content_sha256,
            "family_id": version.definition.family_id,
            "role": version.definition.role.value,
            "version_id": version.version_id,
            "version_number": version.version_number,
        }
        for version in sorted(versions, key=lambda item: item.version_id)
    ]
    return _canonical_fingerprint(
        {
            "matcher_version": MATCHER_VERSION,
            "schema_version": 1,
            "shadow_templates": identities,
        }
    )


def _require_unique_families(
    versions: tuple[TemplateVersion, ...],
    *,
    label: str,
) -> None:
    families = tuple(version.definition.family_id for version in versions)
    if len(families) != len(set(families)):
        raise ValueError(f"{label} templates require a unique family per version")


def build_development_evaluation_template_set(
    *,
    candidates: tuple[TemplateVersion, ...],
    current_shadow: tuple[TemplateVersion, ...],
) -> DevelopmentEvaluationTemplateSet:
    """Build the explicit development-only set.

    Candidates replace the current shadow version for the same family. The
    lifecycle and evaluation purpose are part of the fingerprint, so a draft
    run cannot be mistaken for an ordinary shadow match.
    """

    if not candidates:
        raise ValueError("development evaluation requires at least one candidate")
    if any(
        version.lifecycle
        not in {TemplateLifecycle.DRAFT, TemplateLifecycle.DEVELOPMENT_TESTED}
        for version in candidates
    ):
        raise ValueError(
            "development evaluation candidates must be draft or development_tested"
        )
    if any(
        version.lifecycle is not TemplateLifecycle.SHADOW
        for version in current_shadow
    ):
        raise ValueError("current shadow templates must use the shadow lifecycle")
    _require_unique_families(candidates, label="candidate")
    _require_unique_families(current_shadow, label="current shadow")

    candidate_families = {
        version.definition.family_id
        for version in candidates
    }
    selected = tuple(
        sorted(
            (
                *candidates,
                *(
                    version
                    for version in current_shadow
                    if version.definition.family_id not in candidate_families
                ),
            ),
            key=lambda item: (item.definition.family_id, item.version_id),
        )
    )
    identities = [
        {
            "content_sha256": version.content_sha256,
            "family_id": version.definition.family_id,
            "lifecycle": version.lifecycle.value,
            "role": version.definition.role.value,
            "source": (
                "candidate"
                if version.definition.family_id in candidate_families
                else "current_shadow"
            ),
            "version_id": version.version_id,
            "version_number": version.version_number,
        }
        for version in selected
    ]
    return DevelopmentEvaluationTemplateSet(
        versions=selected,
        fingerprint=_canonical_fingerprint(
            {
                "matcher_version": MATCHER_VERSION,
                "purpose": "development_evaluation",
                "schema_version": 1,
                "templates": identities,
            }
        ),
    )


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _contains_text(expected: str, actual: str) -> bool:
    expected_normalized = _normalize_text(expected)
    actual_normalized = _normalize_text(actual)
    if not expected_normalized or not actual_normalized:
        return False
    if expected_normalized.isascii() and expected_normalized.isalnum():
        pattern = re.compile(
            rf"(?<![a-z0-9]){re.escape(expected_normalized)}(?![a-z0-9])"
        )
        return pattern.search(actual_normalized) is not None

    start = 0
    while True:
        index = actual_normalized.find(expected_normalized, start)
        if index < 0:
            return False
        if index == 0 or actual_normalized[index - 1] not in "未不无非没勿莫":
            return True
        start = index + 1


def _rotate(rectangle: NormalizedRect, degrees: int) -> NormalizedRect:
    if degrees == 0:
        return rectangle
    if degrees == 90:
        return NormalizedRect(
            x=Decimal(1) - rectangle.y - rectangle.height,
            y=rectangle.x,
            width=rectangle.height,
            height=rectangle.width,
        )
    if degrees == 180:
        return NormalizedRect(
            x=Decimal(1) - rectangle.x - rectangle.width,
            y=Decimal(1) - rectangle.y - rectangle.height,
            width=rectangle.width,
            height=rectangle.height,
        )
    return NormalizedRect(
        x=rectangle.y,
        y=Decimal(1) - rectangle.x - rectangle.width,
        width=rectangle.height,
        height=rectangle.width,
    )


def _geometry_score(expected: NormalizedRect, actual: NormalizedRect) -> Decimal:
    distance = max(
        abs(expected.x - actual.x),
        abs(expected.y - actual.y),
        abs(expected.width - actual.width),
        abs(expected.height - actual.height),
    )
    if distance >= GEOMETRY_TOLERANCE:
        return Decimal(0)
    return (Decimal(1) - (distance / GEOMETRY_TOLERANCE)).quantize(SCORE_QUANTUM)


def _text_score(anchor: TemplateAnchor, actual: str) -> Decimal:
    expected = anchor.expected_text
    if anchor.match_kind is AnchorMatchKind.REGEX:
        return Decimal(1) if re.search(expected, actual) is not None else Decimal(0)
    expected_normalized = _normalize_text(expected)
    actual_normalized = _normalize_text(actual)
    if not expected_normalized or not actual_normalized:
        return Decimal(0)
    if anchor.match_kind is AnchorMatchKind.CONTAINS:
        return Decimal(1) if _contains_text(expected, actual) else Decimal(0)
    ratio = SequenceMatcher(
        None,
        expected_normalized,
        actual_normalized,
        autojunk=False,
    ).ratio()
    return Decimal(str(ratio)).quantize(SCORE_QUANTUM)


def _line_provenance(index: int, text: str) -> frozenset[str]:
    identities = {f"line:{index}"}
    normalized = _normalize_text(text)
    if normalized:
        identities.add(f"text:{normalized}")
    return frozenset(identities)


def _anchor_match(
    anchor: TemplateAnchor,
    lines: tuple[ObservedTextLine, ...],
    orientation: int,
) -> _AnchorMatch:
    expected_box = _rotate(anchor.box, orientation)
    best = _AnchorMatch(
        text_score=Decimal(0),
        geometry_score=Decimal(0),
        provenance=frozenset(),
    )
    best_rank: tuple[Decimal, Decimal, int] = (
        Decimal(0),
        Decimal(0),
        0,
    )
    for index, line in enumerate(lines):
        text_score = _text_score(anchor, line.text)
        if text_score == 0:
            continue
        if (
            anchor.match_kind is AnchorMatchKind.LITERAL
            and Decimal(1) - text_score > anchor.max_edit_distance
        ):
            continue
        geometry_score = _geometry_score(expected_box, line.box)
        weighted_text_score = (text_score * line.confidence).quantize(
            SCORE_QUANTUM
        )
        rank = (weighted_text_score, geometry_score, -index)
        if rank > best_rank:
            best_rank = rank
            best = _AnchorMatch(
                text_score=weighted_text_score,
                geometry_score=geometry_score,
                provenance=_line_provenance(index, line.text),
            )
    return best


def _version_score(
    version: TemplateVersion,
    lines: tuple[ObservedTextLine, ...],
    orientation: int,
) -> _VersionScores:
    weighted_text = Decimal(0)
    weighted_layout = Decimal(0)
    text_loading_signal = Decimal(0)
    text_unloading_signal = Decimal(0)
    layout_loading_signal = Decimal(0)
    layout_unloading_signal = Decimal(0)
    total_weight = Decimal(0)
    required_text_missing = False
    loading_provenance: set[str] = set()
    unloading_provenance: set[str] = set()
    for anchor in version.definition.anchors:
        anchor_match = _anchor_match(anchor, lines, orientation)
        text_score = anchor_match.text_score
        layout_score = anchor_match.geometry_score
        aligned_layout_score = layout_score * text_score
        if anchor.required and text_score == 0:
            required_text_missing = True
        weighted_text += text_score * anchor.weight
        weighted_layout += aligned_layout_score * anchor.weight
        text_loading_signal += (
            text_score * anchor.weight * anchor.loading_evidence
        )
        text_unloading_signal += (
            text_score * anchor.weight * anchor.unloading_evidence
        )
        layout_loading_signal += (
            aligned_layout_score
            * anchor.weight
            * anchor.loading_evidence
        )
        layout_unloading_signal += (
            aligned_layout_score
            * anchor.weight
            * anchor.unloading_evidence
        )
        if text_score > 0 and anchor.loading_evidence > 0:
            loading_provenance.update(anchor_match.provenance)
        if text_score > 0 and anchor.unloading_evidence > 0:
            unloading_provenance.update(anchor_match.provenance)
        total_weight += anchor.weight
    if total_weight == 0:
        return _VersionScores(
            template_loading=Decimal(0),
            template_unloading=Decimal(0),
            layout_loading=Decimal(0),
            layout_unloading=Decimal(0),
            alignment_score=Decimal(0),
            loading_provenance=frozenset(),
            unloading_provenance=frozenset(),
        )

    text_match = (
        Decimal(0)
        if required_text_missing
        else (weighted_text / total_weight).quantize(SCORE_QUANTUM)
    )
    layout_match = (
        Decimal(0)
        if required_text_missing
        else (weighted_layout / total_weight).quantize(SCORE_QUANTUM)
    )
    template_loading = (
        text_match if text_loading_signal > 0 else Decimal(0)
    )
    template_unloading = (
        text_match if text_unloading_signal > 0 else Decimal(0)
    )
    return _VersionScores(
        template_loading=template_loading,
        template_unloading=template_unloading,
        layout_loading=(
            layout_match if layout_loading_signal > 0 else Decimal(0)
        ),
        layout_unloading=(
            layout_match if layout_unloading_signal > 0 else Decimal(0)
        ),
        alignment_score=layout_match,
        loading_provenance=(
            frozenset(loading_provenance)
            if template_loading > 0
            else frozenset()
        ),
        unloading_provenance=(
            frozenset(unloading_provenance)
            if template_unloading > 0
            else frozenset()
        ),
    )


def _orientation_scores(
    role_input: TemplateRoleInput,
    versions: tuple[TemplateVersion, ...],
    orientation: int,
) -> _OrientationScores:
    template_scores = {
        TicketRole.LOADING: Decimal(0),
        TicketRole.UNLOADING: Decimal(0),
    }
    template_provenance: dict[TicketRole, set[str]] = {
        TicketRole.LOADING: set(),
        TicketRole.UNLOADING: set(),
    }
    layout_scores = {
        TicketRole.LOADING: Decimal(0),
        TicketRole.UNLOADING: Decimal(0),
    }
    alignment_score = Decimal(0)
    template_matches: list[str] = []
    layout_matches: list[str] = []
    for version in versions:
        version_scores = _version_score(
            version,
            role_input.text_lines,
            orientation,
        )
        alignment_score = max(
            alignment_score,
            version_scores.alignment_score,
        )
        for role, score, provenance in (
            (
                TicketRole.LOADING,
                version_scores.template_loading,
                version_scores.loading_provenance,
            ),
            (
                TicketRole.UNLOADING,
                version_scores.template_unloading,
                version_scores.unloading_provenance,
            ),
        ):
            if score > template_scores[role]:
                template_scores[role] = score
                template_provenance[role] = set(provenance)
            elif score == template_scores[role] and score > 0:
                template_provenance[role].update(provenance)
        layout_scores[TicketRole.LOADING] = max(
            layout_scores[TicketRole.LOADING],
            version_scores.layout_loading,
        )
        layout_scores[TicketRole.UNLOADING] = max(
            layout_scores[TicketRole.UNLOADING],
            version_scores.layout_unloading,
        )
        if (
            max(
                version_scores.template_loading,
                version_scores.template_unloading,
            )
            > 0
        ):
            template_matches.append(version.version_id)
        if (
            max(
                version_scores.layout_loading,
                version_scores.layout_unloading,
            )
            > 0
        ):
            layout_matches.append(version.version_id)
    layout_loading = max(
        Decimal(0),
        layout_scores[TicketRole.LOADING] - layout_scores[TicketRole.UNLOADING],
    )
    layout_unloading = max(
        Decimal(0),
        layout_scores[TicketRole.UNLOADING] - layout_scores[TicketRole.LOADING],
    )
    return _OrientationScores(
        orientation=orientation,
        template_loading=template_scores[TicketRole.LOADING],
        template_unloading=template_scores[TicketRole.UNLOADING],
        layout_loading=layout_loading,
        layout_unloading=layout_unloading,
        alignment_score=alignment_score,
        template_loading_provenance=frozenset(
            template_provenance[TicketRole.LOADING]
        ),
        template_unloading_provenance=frozenset(
            template_provenance[TicketRole.UNLOADING]
        ),
        template_matches=tuple(sorted(template_matches)),
        layout_matches=tuple(sorted(layout_matches)),
    )


def _observed_role_texts(
    role_input: TemplateRoleInput,
) -> tuple[_ObservedRoleText, ...]:
    observed = [
        _ObservedRoleText(
            text=line.text,
            provenance=_line_provenance(index, line.text),
        )
        for index, line in enumerate(role_input.text_lines)
    ]
    for index, text in enumerate(role_input.fixed_text):
        normalized = _normalize_text(text)
        provenance = {f"fixed:{index}"}
        if normalized:
            provenance.add(f"text:{normalized}")
            provenance.update(
                f"line:{line_index}"
                for line_index, line in enumerate(role_input.text_lines)
                if _contains_text(text, line.text)
            )
        observed.append(
            _ObservedRoleText(
                text=text,
                provenance=frozenset(provenance),
            )
        )
    return tuple(observed)


def _matched_terms(
    observed: tuple[_ObservedRoleText, ...],
    terms: tuple[str, ...],
    *,
    excluded_provenance: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    return tuple(
        term
        for term in terms
        if any(
            _contains_text(term, item.text)
            and item.provenance.isdisjoint(excluded_provenance)
            for item in observed
        )
    )


def _term_scores(
    role_input: TemplateRoleInput,
    *,
    loading_template_provenance: frozenset[str],
    unloading_template_provenance: frozenset[str],
) -> tuple[Decimal, Decimal, tuple[str, ...]]:
    observed = _observed_role_texts(role_input)
    loading = _matched_terms(
        observed,
        LOADING_TERMS,
        excluded_provenance=loading_template_provenance,
    )
    unloading = _matched_terms(
        observed,
        UNLOADING_TERMS,
        excluded_provenance=unloading_template_provenance,
    )
    kiosk_terms = _matched_terms(
        observed,
        LOADING_KIOSK_TERMS,
        excluded_provenance=loading_template_provenance,
    )
    kiosk_match = (
        (LOADING_KIOSK_MATCH_ID,)
        if len(kiosk_terms) == len(LOADING_KIOSK_TERMS)
        else ()
    )
    loading_score = Decimal(1) if loading or kiosk_match else Decimal(0)
    unloading_score = Decimal(1) if unloading else Decimal(0)
    return loading_score, unloading_score, tuple(
        sorted(
            {f"loading:{term}" for term in loading}
            | {f"unloading:{term}" for term in unloading}
            | set(kiosk_match)
        )
    )


def _ticket_likelihood(role_input: TemplateRoleInput) -> Decimal:
    term_hits = len(
        _matched_terms(
            _observed_role_texts(role_input),
            TICKET_TERMS,
        )
    )
    text_likelihood = min(Decimal(1), Decimal(term_hits) / Decimal(2))
    ordinary_net_likelihood = (
        Decimal(1) if role_input.ordinary_net_reliable else Decimal(0)
    )
    return max(text_likelihood, ordinary_net_likelihood).quantize(SCORE_QUANTUM)


def _evidence(
    *,
    source: RoleEvidenceSource,
    loading: Decimal,
    unloading: Decimal,
    matched_ids: tuple[str, ...],
    template_set_fingerprint: str,
    orientation: int,
) -> RoleEvidence:
    return RoleEvidence(
        source=source,
        loading_score=max(Decimal(0), min(Decimal(1), loading)),
        unloading_score=max(Decimal(0), min(Decimal(1), unloading)),
        matched_ids=matched_ids,
        evidence_fingerprint=_canonical_fingerprint(
            {
                "loading": _decimal_text(loading),
                "matched_ids": matched_ids,
                "orientation": orientation,
                "source": source.value,
                "template_set_fingerprint": template_set_fingerprint,
                "unloading": _decimal_text(unloading),
            }
        ),
    )


def _match_ticket_role(
    role_input: TemplateRoleInput,
    versions: tuple[TemplateVersion, ...],
    policy: RoleAssessmentPolicy,
    *,
    template_set_fingerprint: str,
    started_ns: int,
) -> TemplateRoleRun:
    if not isinstance(role_input, TemplateRoleInput):
        raise DomainContractError("template role input is invalid")
    candidates = tuple(
        _orientation_scores(role_input, versions, orientation)
        for orientation in (0, 90, 180, 270)
    )
    selected = max(candidates, key=lambda item: item.rank)
    fixed_loading, fixed_unloading, fixed_matches = _term_scores(
        role_input,
        loading_template_provenance=selected.template_loading_provenance,
        unloading_template_provenance=selected.template_unloading_provenance,
    )
    evidence = (
        _evidence(
            source=RoleEvidenceSource.FIXED_TEXT,
            loading=fixed_loading,
            unloading=fixed_unloading,
            matched_ids=fixed_matches,
            template_set_fingerprint=template_set_fingerprint,
            orientation=selected.orientation,
        ),
        _evidence(
            source=RoleEvidenceSource.TEMPLATE,
            loading=selected.template_loading,
            unloading=selected.template_unloading,
            matched_ids=selected.template_matches,
            template_set_fingerprint=template_set_fingerprint,
            orientation=selected.orientation,
        ),
        _evidence(
            source=RoleEvidenceSource.LAYOUT,
            loading=selected.layout_loading,
            unloading=selected.layout_unloading,
            matched_ids=selected.layout_matches,
            template_set_fingerprint=template_set_fingerprint,
            orientation=selected.orientation,
        ),
    )
    observation = RoleObservation(
        image_sha256=role_input.image_sha256,
        orientation_degrees=selected.orientation,
        ticket_likelihood=_ticket_likelihood(role_input),
        evidence=evidence,
    )
    assessment = assess_ticket_role(observation, policy)
    elapsed_ms = Decimal(perf_counter_ns() - started_ns) / Decimal(1_000_000)
    return TemplateRoleRun(
        observation=observation,
        assessment=assessment,
        template_set_fingerprint=template_set_fingerprint,
        elapsed_ms=elapsed_ms,
    )


def match_ticket_role(
    role_input: TemplateRoleInput,
    versions: tuple[TemplateVersion, ...],
    policy: RoleAssessmentPolicy,
) -> TemplateRoleRun:
    """Use shadow templates and existing OCR output only.

    No slot, webpage expectation, or platform value is accepted.
    """

    started = perf_counter_ns()
    template_set_fingerprint = build_template_set_fingerprint(versions)
    return _match_ticket_role(
        role_input,
        versions,
        policy,
        template_set_fingerprint=template_set_fingerprint,
        started_ns=started,
    )


def match_ticket_role_for_development_evaluation(
    role_input: TemplateRoleInput,
    *,
    candidates: tuple[TemplateVersion, ...],
    current_shadow: tuple[TemplateVersion, ...],
    policy: RoleAssessmentPolicy,
) -> TemplateRoleRun:
    """Run candidates only through the explicit development-evaluation path."""

    started = perf_counter_ns()
    template_set = build_development_evaluation_template_set(
        candidates=candidates,
        current_shadow=current_shadow,
    )
    return _match_ticket_role(
        role_input,
        template_set.versions,
        policy,
        template_set_fingerprint=template_set.fingerprint,
        started_ns=started,
    )
