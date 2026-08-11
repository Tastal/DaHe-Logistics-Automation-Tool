from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.domain.audit.weights import WeightReading

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class EvidenceQuality(StrEnum):
    RELIABLE = "reliable"
    UNCERTAIN = "uncertain"
    MISSING = "missing"
    SYSTEM_FAILURE = "system_failure"


class WeightEvidenceIssue(StrEnum):
    FORMAT_SUSPICIOUS = "ticket_weight_format_suspicious"
    RUNTIME_DISAGREEMENT = "ocr_weight_disagreement"


@dataclass(frozen=True, slots=True)
class WeightFieldEvidence:
    reading: WeightReading | None
    quality: EvidenceQuality
    issue: WeightEvidenceIssue | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.quality, EvidenceQuality):
            raise DomainContractError("weight evidence quality is invalid")
        if self.issue is not None and not isinstance(
            self.issue,
            WeightEvidenceIssue,
        ):
            raise DomainContractError("weight evidence issue is invalid")
        if self.quality is EvidenceQuality.RELIABLE and self.reading is None:
            raise DomainContractError("reliable weight evidence requires a reading")
        if self.quality is EvidenceQuality.RELIABLE and self.issue is not None:
            raise DomainContractError(
                "reliable weight evidence cannot require review"
            )
        if (
            self.quality in {EvidenceQuality.MISSING, EvidenceQuality.SYSTEM_FAILURE}
            and self.reading is not None
        ):
            raise DomainContractError(
                "missing or failed weight evidence cannot contain a reading"
            )
        if (
            self.quality in {EvidenceQuality.MISSING, EvidenceQuality.SYSTEM_FAILURE}
            and self.issue is not None
        ):
            raise DomainContractError(
                "missing or failed weight evidence cannot carry a business issue"
            )


@dataclass(frozen=True, slots=True)
class TicketWeightEvidence:
    ordinary_net: WeightFieldEvidence
    factory_net: WeightFieldEvidence
    gross: WeightFieldEvidence
    tare: WeightFieldEvidence


@dataclass(frozen=True, slots=True)
class TicketEvidence:
    slot: TicketSlot
    image_sha256: str
    machine_role: TicketRole
    role_quality: EvidenceQuality
    weights: TicketWeightEvidence
    extraction_fingerprint: str
    role_fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.slot, TicketSlot):
            raise DomainContractError("ticket slot is invalid")
        if not SHA256_PATTERN.fullmatch(self.image_sha256):
            raise DomainContractError("image_sha256 must be a lowercase SHA-256")
        if not isinstance(self.machine_role, TicketRole):
            raise DomainContractError("machine role is invalid")
        if not isinstance(self.role_quality, EvidenceQuality):
            raise DomainContractError("role evidence quality is invalid")
        if (
            self.role_quality is EvidenceQuality.RELIABLE
            and self.machine_role is TicketRole.UNKNOWN
        ):
            raise DomainContractError("a reliable role cannot be unknown")
        if not self.extraction_fingerprint.strip():
            raise DomainContractError("extraction_fingerprint is required")
        if not self.role_fingerprint.strip():
            raise DomainContractError("role_fingerprint is required")


@dataclass(frozen=True, slots=True)
class AuditEvidence:
    snapshot_id: str
    platform_loading_net: WeightFieldEvidence
    platform_unloading_net: WeightFieldEvidence
    loading_ticket_quality: EvidenceQuality
    unloading_ticket_quality: EvidenceQuality
    loading_ticket: TicketEvidence | None
    unloading_ticket: TicketEvidence | None

    def __post_init__(self) -> None:
        if not self.snapshot_id.strip():
            raise DomainContractError("snapshot_id is required")
        for label, quality, ticket in (
            ("loading", self.loading_ticket_quality, self.loading_ticket),
            ("unloading", self.unloading_ticket_quality, self.unloading_ticket),
        ):
            if not isinstance(quality, EvidenceQuality):
                raise DomainContractError(f"{label} ticket quality is invalid")
            if quality is EvidenceQuality.RELIABLE and ticket is None:
                raise DomainContractError(
                    f"reliable {label} ticket evidence requires a ticket"
                )
            if quality is not EvidenceQuality.RELIABLE and ticket is not None:
                raise DomainContractError(
                    f"non-reliable {label} ticket acquisition cannot contain a ticket"
                )


@dataclass(frozen=True, slots=True)
class EvidenceIdentity:
    fingerprint: str
    comparison_rule_version: str


def _reading_payload(reading: WeightReading | None) -> object:
    if reading is None:
        return None
    return {
        "amount": str(reading.amount),
        "unit": reading.unit.value,
        "raw_text": reading.raw_text,
    }


def _field_payload(field: WeightFieldEvidence) -> dict[str, object]:
    return {
        "issue": None if field.issue is None else field.issue.value,
        "quality": field.quality.value,
        "reading": _reading_payload(field.reading),
    }


def _ticket_payload(ticket: TicketEvidence | None) -> object:
    if ticket is None:
        return None
    return {
        "slot": ticket.slot.value,
        "image_sha256": ticket.image_sha256,
        "machine_role": ticket.machine_role.value,
        "role_quality": ticket.role_quality.value,
        "extraction_fingerprint": ticket.extraction_fingerprint,
        "role_fingerprint": ticket.role_fingerprint,
        "weights": {
            "ordinary_net": _field_payload(ticket.weights.ordinary_net),
            "factory_net": _field_payload(ticket.weights.factory_net),
            "gross": _field_payload(ticket.weights.gross),
            "tare": _field_payload(ticket.weights.tare),
        },
    }


def build_evidence_identity(
    evidence: AuditEvidence,
    comparison_rule_version: str,
) -> EvidenceIdentity:
    if not comparison_rule_version.strip():
        raise DomainContractError("comparison_rule_version is required")
    payload = {
        "snapshot_id": evidence.snapshot_id,
        "platform_loading_net": _field_payload(evidence.platform_loading_net),
        "platform_unloading_net": _field_payload(evidence.platform_unloading_net),
        "loading_ticket_quality": evidence.loading_ticket_quality.value,
        "unloading_ticket_quality": evidence.unloading_ticket_quality.value,
        "loading_ticket": _ticket_payload(evidence.loading_ticket),
        "unloading_ticket": _ticket_payload(evidence.unloading_ticket),
        "comparison_rule_version": comparison_rule_version,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return EvidenceIdentity(
        fingerprint=hashlib.sha256(canonical).hexdigest(),
        comparison_rule_version=comparison_rule_version,
    )
