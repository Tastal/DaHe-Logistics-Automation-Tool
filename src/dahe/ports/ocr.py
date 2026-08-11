from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from dahe.domain.audit.evidence import EvidenceQuality, TicketEvidence


@dataclass(frozen=True, slots=True)
class EvidenceImageInput:
    image_sha256: str
    relative_path: str


@dataclass(frozen=True, slots=True)
class EvidenceExtractionInput:
    evidence_set_id: str
    loading_image: EvidenceImageInput
    unloading_image: EvidenceImageInput


@dataclass(frozen=True, slots=True)
class ExtractedTicketEvidence:
    loading_ticket_quality: EvidenceQuality
    unloading_ticket_quality: EvidenceQuality
    loading_ticket: TicketEvidence | None
    unloading_ticket: TicketEvidence | None


class EvidenceExtractor(Protocol):
    def extract(
        self,
        extraction_input: EvidenceExtractionInput,
    ) -> ExtractedTicketEvidence: ...
