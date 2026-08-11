from __future__ import annotations

import time
from dataclasses import dataclass
from decimal import Decimal

from dahe.domain.audit.decisions import (
    AuditDecisionKind,
    BusinessOutcome,
    evaluate_audit,
)
from dahe.domain.audit.evidence import (
    AuditEvidence,
    EvidenceQuality,
    WeightFieldEvidence,
)
from dahe.domain.audit.weights import (
    WeightComparisonPolicy,
    WeightReading,
    WeightUnit,
)
from dahe.jobs.models import JobStatus, WorkItemStatus
from dahe.ports.audit import AuditSource
from dahe.ports.jobs import JobRepository
from dahe.ports.ocr import EvidenceExtractor


def _platform_weight_evidence(value: str) -> WeightFieldEvidence:
    return WeightFieldEvidence(
        reading=WeightReading(
            amount=Decimal(value),
            unit=WeightUnit.TONNE,
            raw_text=value,
        ),
        quality=EvidenceQuality.RELIABLE,
    )


@dataclass(slots=True)
class Loop2AuditService:
    repository: JobRepository
    audit_source: AuditSource
    evidence_extractor: EvidenceExtractor
    stage_delay_seconds: float

    def _delay(self) -> None:
        if self.stage_delay_seconds > 0:
            time.sleep(self.stage_delay_seconds)

    def run(self, job_id: str) -> None:
        job = self.repository.get_job(job_id)
        try:
            self.repository.transition(
                job_id,
                status=JobStatus.RUNNING,
                current_stage="audit.acquire_list",
                work_item_status=WorkItemStatus.RUNNING,
            )
            self._delay()
            snapshot = self.audit_source.acquire(job.scope_fixture_id)
            self.repository.transition(
                job_id,
                status=JobStatus.RUNNING,
                current_stage="audit.download_evidence",
                work_item_status=WorkItemStatus.RUNNING,
                waybill_number=snapshot.waybill_number,
                vehicle_number=snapshot.vehicle_number,
            )
            self._delay()
            self.repository.transition(
                job_id,
                status=JobStatus.RUNNING,
                current_stage="audit.recognize",
                work_item_status=WorkItemStatus.RUNNING,
            )
            extracted_tickets = self.evidence_extractor.extract(
                snapshot.evidence_input
            )
            self._delay()
            self.repository.transition(
                job_id,
                status=JobStatus.RUNNING,
                current_stage="audit.compare",
                work_item_status=WorkItemStatus.RUNNING,
            )
            evidence = AuditEvidence(
                snapshot_id=snapshot.snapshot_id,
                platform_loading_net=_platform_weight_evidence(
                    snapshot.platform_loading_net
                ),
                platform_unloading_net=_platform_weight_evidence(
                    snapshot.platform_unloading_net
                ),
                loading_ticket_quality=extracted_tickets.loading_ticket_quality,
                unloading_ticket_quality=extracted_tickets.unloading_ticket_quality,
                loading_ticket=extracted_tickets.loading_ticket,
                unloading_ticket=extracted_tickets.unloading_ticket,
            )
            decision = evaluate_audit(
                evidence,
                WeightComparisonPolicy(
                    decimal_places=2,
                    rule_version="loop2-exact-weight-v1",
                ),
            )
            if (
                decision.kind is not AuditDecisionKind.PASS
                or decision.business_outcome is not BusinessOutcome.NORMAL_READY
            ):
                raise RuntimeError("the normal Loop 2 fixture did not pass")
            self._delay()
            self.repository.transition(
                job_id,
                status=JobStatus.RUNNING,
                current_stage="audit.finalize",
                work_item_status=WorkItemStatus.RUNNING,
            )
            assert evidence.loading_ticket is not None
            assert evidence.unloading_ticket is not None
            platform_loading = evidence.platform_loading_net.reading
            platform_unloading = evidence.platform_unloading_net.reading
            ticket_loading = evidence.loading_ticket.weights.ordinary_net.reading
            ticket_unloading = evidence.unloading_ticket.weights.ordinary_net.reading
            assert platform_loading is not None
            assert platform_unloading is not None
            assert ticket_loading is not None
            assert ticket_unloading is not None
            self.repository.complete_normal(
                job_id,
                platform_loading_net=str(platform_loading.amount),
                platform_unloading_net=str(platform_unloading.amount),
                ticket_loading_net=str(ticket_loading.amount),
                ticket_unloading_net=str(ticket_unloading.amount),
                decision=decision.kind.value,
                business_outcome=decision.business_outcome.value,
            )
        except Exception as exc:
            diagnostic_code = f"LOOP2-{type(exc).__name__.upper()}"
            try:
                self.repository.fail_job(job_id, diagnostic_code)
            except Exception as persistence_error:
                raise RuntimeError(
                    "failed to persist the Loop 2 job failure "
                    f"({diagnostic_code})"
                ) from persistence_error
