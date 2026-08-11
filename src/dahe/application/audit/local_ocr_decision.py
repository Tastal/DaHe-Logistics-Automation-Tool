from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from pydantic import ValidationError

from dahe.adapters.ocr.protocol import OcrResult, OcrResultStatus
from dahe.adapters.ocr.template_role_input import (
    ordinary_net_review_reason_from_ocr_v1,
    template_role_input_from_ocr_v1,
)
from dahe.application.template_studio.matcher import (
    build_template_set_fingerprint,
    match_ticket_role,
)
from dahe.domain.audit.decisions import evaluate_audit
from dahe.domain.audit.evidence import (
    AuditEvidence,
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightEvidenceIssue,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import TicketSlot
from dahe.domain.audit.weights import (
    WeightComparisonPolicy,
    WeightReading,
    WeightUnit,
)
from dahe.domain.ticket.role_assessment import RoleAssessmentPolicy
from dahe.domain.ticket.templates import TemplateVersion
from dahe.jobs.audit_execution import (
    LocalAuditEvaluation,
    LocalAuditEvaluationInput,
    LocalAuditObservationProjection,
    LocalAuditTechnicalError,
)

_DEFAULT_WEIGHT_POLICY = WeightComparisonPolicy(
    decimal_places=2,
    rule_version="loop9-exact-weight-v1",
)


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _missing_weight() -> WeightFieldEvidence:
    return WeightFieldEvidence(
        reading=None,
        quality=EvidenceQuality.MISSING,
    )


def _platform_weight(value: str) -> WeightFieldEvidence:
    try:
        amount = Decimal(value)
        reading = WeightReading(
            amount=amount,
            unit=WeightUnit.TONNE,
            raw_text=value,
        )
    except (InvalidOperation, ValueError) as exc:
        raise LocalAuditTechnicalError(
            "captured platform weight is invalid",
            diagnostic_code="AUDIT-PLATFORM-EVIDENCE-INVALID",
        ) from exc
    return WeightFieldEvidence(
        reading=reading,
        quality=EvidenceQuality.RELIABLE,
    )


def _ordinary_net(
    result: OcrResult,
) -> tuple[WeightFieldEvidence, str | None]:
    field = result.fields.get("ordinary_net")
    if field is None or field.amount is None:
        return _missing_weight(), None
    raw_amount = field.amount
    try:
        amount = Decimal(raw_amount)
    except InvalidOperation:
        return (
            WeightFieldEvidence(
                reading=None,
                quality=EvidenceQuality.UNCERTAIN,
            ),
            raw_amount,
        )
    if not amount.is_finite() or amount < 0:
        return (
            WeightFieldEvidence(
                reading=None,
                quality=EvidenceQuality.UNCERTAIN,
            ),
            raw_amount,
        )
    unit_text = None if field.unit is None else field.unit.strip().lower()
    unit = (
        WeightUnit.TONNE
        if unit_text == "t"
        else WeightUnit.KILOGRAM
        if unit_text == "kg"
        else None
    )
    if unit is None:
        return (
            WeightFieldEvidence(
                reading=None,
                quality=EvidenceQuality.UNCERTAIN,
            ),
            raw_amount,
        )
    reading = WeightReading(
        amount=amount,
        unit=unit,
        raw_text=field.raw_text,
    )
    review_reason = ordinary_net_review_reason_from_ocr_v1(result)
    if review_reason is not None:
        return (
            WeightFieldEvidence(
                reading=reading,
                quality=EvidenceQuality.UNCERTAIN,
                issue=WeightEvidenceIssue.FORMAT_SUSPICIOUS,
            ),
            raw_amount,
        )
    return (
        WeightFieldEvidence(
            reading=reading,
            quality=EvidenceQuality.RELIABLE,
        ),
        raw_amount,
    )


@dataclass(frozen=True, slots=True)
class LocalOcrAuditEvaluator:
    """Translate independent OCR outputs into the existing audit domain."""

    templates: tuple[TemplateVersion, ...]
    role_policy: RoleAssessmentPolicy
    weight_policy: WeightComparisonPolicy = _DEFAULT_WEIGHT_POLICY

    def __post_init__(self) -> None:
        if not self.templates:
            raise ValueError("local audit evaluation requires shadow templates")

    @staticmethod
    def _parse_result(
        *,
        output_json: str,
        expected_image_sha256: str,
        expected_runtime_fingerprint: str,
    ) -> OcrResult:
        try:
            result = OcrResult.model_validate_json(output_json)
        except (ValidationError, ValueError) as exc:
            raise LocalAuditTechnicalError(
                "OCR result does not match the accepted protocol",
                diagnostic_code="AUDIT-OCR-EVIDENCE-INVALID",
            ) from exc
        if (
            result.status is not OcrResultStatus.OK
            or result.verified_image_sha256 != expected_image_sha256
            or result.runtime_fingerprint != expected_runtime_fingerprint
        ):
            raise LocalAuditTechnicalError(
                "OCR result identity or status is invalid",
                diagnostic_code="AUDIT-OCR-EVIDENCE-INVALID",
            )
        return result

    def _ticket(
        self,
        *,
        slot: TicketSlot,
        result: OcrResult,
        pipeline_fingerprint: str,
    ) -> tuple[TicketEvidence, str | None]:
        try:
            role_input = template_role_input_from_ocr_v1(result)
            role_run = match_ticket_role(
                role_input,
                self.templates,
                self.role_policy,
            )
            ordinary_net, raw_amount = _ordinary_net(result)
        except LocalAuditTechnicalError:
            raise
        except Exception as exc:
            raise LocalAuditTechnicalError(
                "OCR result could not be evaluated by the accepted role contract",
                diagnostic_code="AUDIT-ROLE-EVALUATION-FAILED",
            ) from exc
        missing = _missing_weight()
        return (
            TicketEvidence(
                slot=slot,
                image_sha256=role_input.image_sha256,
                machine_role=role_run.assessment.role,
                role_quality=role_run.assessment.quality,
                weights=TicketWeightEvidence(
                    ordinary_net=ordinary_net,
                    factory_net=missing,
                    gross=missing,
                    tare=missing,
                ),
                extraction_fingerprint=_canonical_sha256(
                    {
                        "image_sha256": role_input.image_sha256,
                        "pipeline_fingerprint": pipeline_fingerprint,
                        "protocol_version": result.protocol_version,
                        "runtime_fingerprint": result.runtime_fingerprint,
                    }
                ),
                role_fingerprint=role_run.assessment.fingerprint,
            ),
            raw_amount,
        )

    def project_observation(
        self,
        *,
        output_json: str,
        expected_image_sha256: str,
        expected_runtime_fingerprint: str,
    ) -> LocalAuditObservationProjection:
        """Project only bounded role and weight fields into the audit timeline."""

        result = self._parse_result(
            output_json=output_json,
            expected_image_sha256=expected_image_sha256,
            expected_runtime_fingerprint=expected_runtime_fingerprint,
        )
        try:
            role_input = template_role_input_from_ocr_v1(result)
            role_run = match_ticket_role(
                role_input,
                self.templates,
                self.role_policy,
            )
            ordinary_net, raw_amount = _ordinary_net(result)
        except LocalAuditTechnicalError:
            raise
        except Exception as exc:
            raise LocalAuditTechnicalError(
                "OCR result could not be projected by the accepted role contract",
                diagnostic_code="AUDIT-ROLE-EVALUATION-FAILED",
            ) from exc
        reading = ordinary_net.reading
        return LocalAuditObservationProjection(
            ticket_role=role_run.assessment.role.value,
            role_quality=role_run.assessment.quality.value,
            role_fingerprint=role_run.assessment.fingerprint,
            role_high_confidence=role_run.assessment.high_confidence,
            template_set_fingerprint=build_template_set_fingerprint(
                self.templates
            ),
            ordinary_net_amount=raw_amount,
            ordinary_net_unit=(
                None if reading is None else reading.unit.value
            ),
            ordinary_net_reliable=(
                ordinary_net.quality is EvidenceQuality.RELIABLE
            ),
            weight_review_reason=ordinary_net_review_reason_from_ocr_v1(
                result
            ),
        )

    def evaluate(
        self,
        request: LocalAuditEvaluationInput,
    ) -> LocalAuditEvaluation:
        loading_result = self._parse_result(
            output_json=request.loading_output_json,
            expected_image_sha256=request.loading_image_sha256,
            expected_runtime_fingerprint=request.runtime_fingerprint,
        )
        unloading_result = self._parse_result(
            output_json=request.unloading_output_json,
            expected_image_sha256=request.unloading_image_sha256,
            expected_runtime_fingerprint=request.runtime_fingerprint,
        )
        loading_ticket, loading_net = self._ticket(
            slot=TicketSlot.LOADING,
            result=loading_result,
            pipeline_fingerprint=request.pipeline_fingerprint,
        )
        unloading_ticket, unloading_net = self._ticket(
            slot=TicketSlot.UNLOADING,
            result=unloading_result,
            pipeline_fingerprint=request.pipeline_fingerprint,
        )
        try:
            decision = evaluate_audit(
                AuditEvidence(
                    snapshot_id=request.snapshot_id,
                    platform_loading_net=_platform_weight(
                        request.platform_loading_net
                    ),
                    platform_unloading_net=_platform_weight(
                        request.platform_unloading_net
                    ),
                    loading_ticket_quality=EvidenceQuality.RELIABLE,
                    unloading_ticket_quality=EvidenceQuality.RELIABLE,
                    loading_ticket=loading_ticket,
                    unloading_ticket=unloading_ticket,
                ),
                self.weight_policy,
            )
        except LocalAuditTechnicalError:
            raise
        except Exception as exc:
            raise LocalAuditTechnicalError(
                "audit evidence could not be evaluated",
                diagnostic_code="AUDIT-DOMAIN-EVALUATION-FAILED",
            ) from exc
        return LocalAuditEvaluation(
            business_outcome=decision.business_outcome.value,
            decision=decision.kind.value,
            review_reason=(
                None if not decision.reasons else decision.reasons[0].value
            ),
            ticket_loading_net=loading_net,
            ticket_unloading_net=unloading_net,
        )
