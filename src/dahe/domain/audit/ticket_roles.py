from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from dahe.domain.audit.errors import DomainContractError, SystemEvidenceError

if TYPE_CHECKING:
    from dahe.domain.audit.evidence import TicketEvidence


class TicketSlot(StrEnum):
    LOADING = "loading"
    UNLOADING = "unloading"


class TicketRole(StrEnum):
    LOADING = "loading"
    UNLOADING = "unloading"
    UNKNOWN = "unknown"


class RoleIssue(StrEnum):
    DUPLICATE_IMAGE = "duplicate_image"
    SUSPECTED_SWAPPED = "suspected_swapped"
    BOTH_LOADING = "both_loading"
    BOTH_UNLOADING = "both_unloading"
    MISSING_EVIDENCE = "missing_evidence"
    ROLE_UNKNOWN = "role_unknown"
    ROLE_UNRELIABLE = "role_unreliable"


@dataclass(frozen=True, slots=True)
class RoleAssessment:
    issue: RoleIssue | None
    roles_valid: bool


def _validate_positions(
    loading: TicketEvidence | None,
    unloading: TicketEvidence | None,
) -> None:
    if loading is not None and loading.slot is not TicketSlot.LOADING:
        raise DomainContractError("loading evidence has the wrong slot")
    if unloading is not None and unloading.slot is not TicketSlot.UNLOADING:
        raise DomainContractError("unloading evidence has the wrong slot")


def assess_ticket_roles(
    loading: TicketEvidence | None,
    unloading: TicketEvidence | None,
) -> RoleAssessment:
    from dahe.domain.audit.evidence import EvidenceQuality

    _validate_positions(loading, unloading)
    tickets = tuple(ticket for ticket in (loading, unloading) if ticket is not None)
    if any(ticket.role_quality is EvidenceQuality.SYSTEM_FAILURE for ticket in tickets):
        raise SystemEvidenceError("ticket role classification failed")

    if (
        loading is not None
        and unloading is not None
        and loading.image_sha256 == unloading.image_sha256
    ):
        return RoleAssessment(RoleIssue.DUPLICATE_IMAGE, False)

    if (
        loading is None
        or unloading is None
        or loading.role_quality is EvidenceQuality.MISSING
        or unloading.role_quality is EvidenceQuality.MISSING
    ):
        return RoleAssessment(RoleIssue.MISSING_EVIDENCE, False)

    if (
        loading.machine_role is TicketRole.UNKNOWN
        or unloading.machine_role is TicketRole.UNKNOWN
    ):
        return RoleAssessment(RoleIssue.ROLE_UNKNOWN, False)

    if (
        loading.role_quality is not EvidenceQuality.RELIABLE
        or unloading.role_quality is not EvidenceQuality.RELIABLE
    ):
        return RoleAssessment(RoleIssue.ROLE_UNRELIABLE, False)

    if (
        loading.machine_role is TicketRole.UNLOADING
        and unloading.machine_role is TicketRole.LOADING
    ):
        return RoleAssessment(RoleIssue.SUSPECTED_SWAPPED, False)
    if (
        loading.machine_role is TicketRole.LOADING
        and unloading.machine_role is TicketRole.LOADING
    ):
        return RoleAssessment(RoleIssue.BOTH_LOADING, False)
    if (
        loading.machine_role is TicketRole.UNLOADING
        and unloading.machine_role is TicketRole.UNLOADING
    ):
        return RoleAssessment(RoleIssue.BOTH_UNLOADING, False)
    return RoleAssessment(None, True)
