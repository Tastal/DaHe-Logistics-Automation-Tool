from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.domain.audit.ticket_roles import TicketRole


@dataclass(frozen=True, slots=True)
class OcrImageOutput:
    """Normalized runtime output used only by CPU/GPU comparison reports."""

    image_sha256: str
    runtime_kind: RuntimeKind
    runtime_fingerprint: str
    output_fingerprint: str
    ordinary_net_amount: Decimal | None
    ordinary_net_unit: str | None
    gross_amount: Decimal | None
    tare_amount: Decimal | None
    role: TicketRole
    role_reliable: bool
    field_reliable: bool
    elapsed_ms: float
