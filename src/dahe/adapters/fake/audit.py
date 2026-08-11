from __future__ import annotations

import hashlib
from decimal import Decimal

from dahe.domain.audit.evidence import (
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.domain.audit.weights import WeightReading, WeightUnit
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.ports.audit import FakeWaybillSnapshot
from dahe.ports.ocr import (
    EvidenceExtractionInput,
    EvidenceImageInput,
    ExtractedTicketEvidence,
)

FIXTURE_ID = "audit-normal-001"
FAKE_OCR_LOADING_NET = "30.00"
FAKE_OCR_UNLOADING_NET = "29.80"
FAKE_LOADING_IMAGE_SHA256 = hashlib.sha256(b"loop2-loading-ticket").hexdigest()
FAKE_UNLOADING_IMAGE_SHA256 = hashlib.sha256(b"loop2-unloading-ticket").hexdigest()
NORMAL_AUDIT_PIPELINE_FINGERPRINT = "loop2-fake-extraction-v1"
NORMAL_AUDIT_JOB_SPEC = ScheduledJobSpec(
    fixture_id=FIXTURE_ID,
    job_kind="business",
    task_type="audit",
    scope_label="单条假数据审核",
    conflict_key="audit:audit-normal-001",
    items=(
        ScheduledWorkItemSpec(
            item_key="TEST-20260725-001",
            expected_outcome="normal_ready",
            loading_image_sha256=FAKE_LOADING_IMAGE_SHA256,
            unloading_image_sha256=FAKE_UNLOADING_IMAGE_SHA256,
            vehicle_number="测试车辆01",
        ),
    ),
    pipeline_fingerprint=NORMAL_AUDIT_PIPELINE_FINGERPRINT,
)


def _reading(value: str) -> WeightFieldEvidence:
    return WeightFieldEvidence(
        reading=WeightReading(
            amount=Decimal(value),
            unit=WeightUnit.TONNE,
            raw_text=value,
        ),
        quality=EvidenceQuality.RELIABLE,
    )


def _missing() -> WeightFieldEvidence:
    return WeightFieldEvidence(reading=None, quality=EvidenceQuality.MISSING)


class FakeAuditSource:
    def acquire(self, fixture_id: str) -> FakeWaybillSnapshot:
        if fixture_id != FIXTURE_ID:
            raise ValueError("unknown deterministic audit fixture")
        return FakeWaybillSnapshot(
            snapshot_id="fake-snapshot-audit-normal-001",
            waybill_number="TEST-20260725-001",
            vehicle_number="测试车辆01",
            platform_loading_net="30.00",
            platform_unloading_net="29.80",
            evidence_input=EvidenceExtractionInput(
                evidence_set_id="fake-evidence-audit-normal-001",
                loading_image=EvidenceImageInput(
                    image_sha256=FAKE_LOADING_IMAGE_SHA256,
                    relative_path="fixtures/audit-normal-001/loading-ticket.png",
                ),
                unloading_image=EvidenceImageInput(
                    image_sha256=FAKE_UNLOADING_IMAGE_SHA256,
                    relative_path="fixtures/audit-normal-001/unloading-ticket.png",
                ),
            ),
        )


class FakeEvidenceExtractor:
    def extract(
        self,
        extraction_input: EvidenceExtractionInput,
    ) -> ExtractedTicketEvidence:
        loading = TicketEvidence(
            slot=TicketSlot.LOADING,
            image_sha256=extraction_input.loading_image.image_sha256,
            machine_role=TicketRole.LOADING,
            role_quality=EvidenceQuality.RELIABLE,
            weights=TicketWeightEvidence(
                ordinary_net=_reading(FAKE_OCR_LOADING_NET),
                factory_net=_missing(),
                gross=_missing(),
                tare=_missing(),
            ),
            extraction_fingerprint="loop2-fake-extraction-v1",
            role_fingerprint="loop2-fake-role-v1",
        )
        unloading = TicketEvidence(
            slot=TicketSlot.UNLOADING,
            image_sha256=extraction_input.unloading_image.image_sha256,
            machine_role=TicketRole.UNLOADING,
            role_quality=EvidenceQuality.RELIABLE,
            weights=TicketWeightEvidence(
                ordinary_net=_reading(FAKE_OCR_UNLOADING_NET),
                factory_net=_missing(),
                gross=_missing(),
                tare=_missing(),
            ),
            extraction_fingerprint="loop2-fake-extraction-v1",
            role_fingerprint="loop2-fake-role-v1",
        )
        return ExtractedTicketEvidence(
            loading_ticket_quality=EvidenceQuality.RELIABLE,
            unloading_ticket_quality=EvidenceQuality.RELIABLE,
            loading_ticket=loading,
            unloading_ticket=unloading,
        )
