from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from dahe.ports.ocr import EvidenceExtractionInput


@dataclass(frozen=True, slots=True)
class FakeWaybillSnapshot:
    snapshot_id: str
    waybill_number: str
    vehicle_number: str
    platform_loading_net: str
    platform_unloading_net: str
    evidence_input: EvidenceExtractionInput


class AuditSource(Protocol):
    def acquire(self, fixture_id: str) -> FakeWaybillSnapshot: ...
