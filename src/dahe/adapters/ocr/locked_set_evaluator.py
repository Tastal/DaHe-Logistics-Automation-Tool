from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from uuid import uuid4

from dahe.adapters.ocr.protocol import OcrResult
from dahe.adapters.ocr.template_role_input import (
    ordinary_net_review_reason_from_ocr_v1,
    template_role_input_from_ocr_v1,
)
from dahe.application.template_studio.development_evaluation import (
    default_development_policy,
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
)
from dahe.application.template_studio.matcher import (
    TemplateRoleRun,
    build_template_set_fingerprint,
    match_ticket_role,
)
from dahe.domain.audit.evidence import EvidenceQuality
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    TemplateLifecycle,
    TemplateVersion,
)
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageWork,
    OcrRuntimeIdentity,
    OcrStageExecution,
    OcrStageWork,
    RuntimeKindName,
)
from dahe.verification.application_build import ApplicationBuildManifest
from dahe.verification.locked_set_acceptance import (
    LOCAL_OCR_RUNTIME_SOURCE,
)
from dahe.verification.locked_set_runner import (
    IndependentLockedImage,
    LockedOcrRuntimeComparison,
    LockedOcrRuntimeFailure,
    LockedOcrRuntimeOutput,
    LockedRolePrediction,
    LockedSetRunContext,
    LockedSetRunnerError,
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EVALUATOR_VERSION = "dahe.loop7.local-ocr-locked-evaluator.v3"
_CRITICAL_OUTPUT_FIELDS = (
    "ordinary_net_amount",
    "ordinary_net_unit",
    "ordinary_net_reliable",
    "weight_review_reason",
    "role",
    "role_quality",
    "role_high_confidence",
    "safety_route",
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class _SuccessfulRuntimeEvaluation:
    role_run: TemplateRoleRun
    evidence: LockedOcrRuntimeOutput


@dataclass(frozen=True, slots=True)
class _FailedRuntimeEvaluation:
    evidence: LockedOcrRuntimeFailure


_RuntimeEvaluation = _SuccessfulRuntimeEvaluation | _FailedRuntimeEvaluation


class LocalOcrLockedImageEvaluator:
    """Use a dedicated qualified OCR backend without seeing locked truth."""

    def __init__(
        self,
        *,
        backend: AsyncOcrExecutionBackend,
        templates: tuple[TemplateVersion, ...],
        application_build_sha256: str,
        application_build_manifest: ApplicationBuildManifest,
        timeout_seconds: float,
    ) -> None:
        if not isinstance(backend, AsyncOcrExecutionBackend):
            raise LockedSetRunnerError("qualified OCR backend is required")
        if backend.has_runtime("gpu") and not backend.has_runtime("cpu"):
            raise LockedSetRunnerError("formal GPU evaluation requires a qualified CPU fallback")
        if SHA256_PATTERN.fullmatch(application_build_sha256) is None:
            raise LockedSetRunnerError("application build fingerprint is invalid")
        if (
            not isinstance(application_build_manifest, ApplicationBuildManifest)
            or application_build_manifest.canonical_sha256 != application_build_sha256
        ):
            raise LockedSetRunnerError("application build evidence is inconsistent")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise LockedSetRunnerError("OCR evaluation timeout is invalid")
        if not templates or any(
            not isinstance(template, TemplateVersion)
            or template.lifecycle is not TemplateLifecycle.SHADOW
            for template in templates
        ):
            raise LockedSetRunnerError("locked evaluation requires current shadow templates")
        roles = {template.definition.role for template in templates}
        if roles != {TicketRole.LOADING, TicketRole.UNLOADING}:
            raise LockedSetRunnerError(
                "locked evaluation requires loading and unloading shadow templates"
            )

        self._backend = backend
        self._templates = templates
        runtime_kinds: tuple[RuntimeKindName, ...] = ("cpu", "gpu")
        self._runtime_identities = tuple(
            backend.identity_for(runtime_kind)
            for runtime_kind in runtime_kinds
            if backend.has_runtime(runtime_kind)
        )
        self._policy = default_development_policy()
        self._timeout_seconds = float(timeout_seconds)
        template_set_sha256 = build_template_set_fingerprint(templates)
        matcher_sha256 = development_matcher_fingerprint()
        policy_sha256 = development_policy_fingerprint(self._policy)
        runtime_identities: list[dict[str, str]] = []
        for runtime_kind in runtime_kinds:
            if not backend.has_runtime(runtime_kind):
                continue
            identity = backend.identity_for(runtime_kind)
            runtime_identities.append(
                {
                    "profile_id": identity.profile_id,
                    "runtime_fingerprint": identity.runtime_fingerprint,
                    "runtime_kind": identity.runtime_kind,
                }
            )
        runtime_set_sha256 = current_template_ocr_runtime_set_fingerprint(runtime_identities)
        expected_runtime_kinds = tuple(identity["runtime_kind"] for identity in runtime_identities)
        formal_authority = backend.formal_authority
        composition_evidence_sha256 = (
            formal_authority.composition_evidence_sha256
            if formal_authority is not None
            else _canonical_sha256(
                {
                    "authority": "unverified_manual_composition",
                    "runtime_set_sha256": runtime_set_sha256,
                    "schema_version": 1,
                }
            )
        )
        self._pipeline_contract_sha256 = _canonical_sha256(
            {
                "application_build_sha256": application_build_sha256,
                "evaluator_version": EVALUATOR_VERSION,
                "expected_runtime_kinds": list(expected_runtime_kinds),
                "matcher_sha256": matcher_sha256,
                "ocr_composition_evidence_sha256": (composition_evidence_sha256),
                "policy_sha256": policy_sha256,
                "purpose": "formal_locked_set_role_evaluation",
                "runtime_set_sha256": runtime_set_sha256,
                "template_set_sha256": template_set_sha256,
            }
        )
        self.run_context = LockedSetRunContext(
            application_build_sha256=application_build_sha256,
            application_build_manifest=application_build_manifest,
            runtime_set_sha256=runtime_set_sha256,
            ocr_composition_evidence_sha256=(composition_evidence_sha256),
            template_set_sha256=template_set_sha256,
            matcher_sha256=matcher_sha256,
            policy_sha256=policy_sha256,
            expected_runtime_kinds=expected_runtime_kinds,
        )

    @property
    def templates(self) -> tuple[TemplateVersion, ...]:
        """Return the immutable shadow set used by this formal evaluator."""

        return self._templates

    @property
    def runtime_identities(self) -> tuple[OcrRuntimeIdentity, ...]:
        """Return the qualified runtime identities without exposing workers."""

        return self._runtime_identities

    @property
    def pipeline_contract_sha256(self) -> str:
        """Return the common formal pipeline contract bound before execution."""

        return self._pipeline_contract_sha256

    @property
    def runtime_pipeline_fingerprints(self) -> dict[str, str]:
        """Return the runtime-specific pipeline identities used for OCR calls."""

        return {
            identity.runtime_kind: self._backend.pipeline_fingerprint_for(
                identity.runtime_kind,
                pipeline_contract_fingerprint=self._pipeline_contract_sha256,
            )
            for identity in self._runtime_identities
        }

    def _execute(
        self,
        image: IndependentLockedImage,
        runtime_kind: RuntimeKindName,
    ) -> OcrStageExecution:
        identity = self._backend.identity_for(runtime_kind)
        runtime_pipeline = self._backend.pipeline_fingerprint_for(
            runtime_kind,
            pipeline_contract_fingerprint=self._pipeline_contract_sha256,
        )
        attempt_id = uuid4().hex
        work = OcrStageWork(
            stage_attempt_id=attempt_id,
            shared_work_id=_canonical_sha256(
                {
                    "image_sha256": image.image_sha256,
                    "pipeline_fingerprint": runtime_pipeline,
                    "purpose": "formal_locked_set_role_evaluation",
                }
            ),
            pipeline_fingerprint=runtime_pipeline,
            identity=identity,
            image=OcrImageWork(
                image_sha256=image.image_sha256,
                relative_path=image.relative_path,
            ),
        )
        self._backend.submit(work)
        deadline = time.monotonic() + self._timeout_seconds
        while time.monotonic() < deadline:
            completed = self._backend.pop_completed()
            unexpected = set(completed).difference({attempt_id})
            if unexpected:
                raise LockedSetRunnerError("dedicated locked OCR backend returned unrelated work")
            execution = completed.get(attempt_id)
            if execution is not None:
                return execution
            time.sleep(0.005)
        raise LockedSetRunnerError("locked OCR runtime timed out")

    @staticmethod
    def _ordinary_net_output(
        result: OcrResult,
    ) -> tuple[Decimal | None, str | None, Decimal | None]:
        field = result.fields.get("ordinary_net")
        if field is None:
            return None, None, None
        unit = field.unit.strip().lower() if field.unit is not None else None
        amount: Decimal | None = None
        if field.amount is not None:
            try:
                parsed = Decimal(field.amount)
            except InvalidOperation:
                parsed = None
            if parsed is not None and parsed.is_finite() and parsed > 0:
                amount = parsed
        return amount, unit, field.confidence

    def _failed_runtime(
        self,
        *,
        image: IndependentLockedImage,
        runtime_kind: RuntimeKindName,
        started_ns: int,
        error_kind: str,
        diagnostic_code: str,
    ) -> _FailedRuntimeEvaluation:
        identity = self._backend.identity_for(runtime_kind)
        elapsed_ms = Decimal(time.perf_counter_ns() - started_ns) / Decimal(1_000_000)
        return _FailedRuntimeEvaluation(
            evidence=LockedOcrRuntimeFailure(
                image_sha256=image.image_sha256,
                runtime_kind=runtime_kind,
                runtime_fingerprint=identity.runtime_fingerprint,
                wall_elapsed_ms=elapsed_ms,
                error_kind=error_kind,
                diagnostic_code=diagnostic_code,
            )
        )

    def _evaluate_runtime(
        self,
        image: IndependentLockedImage,
        runtime_kind: RuntimeKindName,
    ) -> _RuntimeEvaluation:
        started_ns = time.perf_counter_ns()
        try:
            execution = self._execute(image, runtime_kind)
        except LockedSetRunnerError:
            return self._failed_runtime(
                image=image,
                runtime_kind=runtime_kind,
                started_ns=started_ns,
                error_kind="execution_boundary",
                diagnostic_code="LOCKED-OCR-EXECUTION-BOUNDARY",
            )
        except Exception:
            return self._failed_runtime(
                image=image,
                runtime_kind=runtime_kind,
                started_ns=started_ns,
                error_kind="execution_boundary",
                diagnostic_code="LOCKED-OCR-UNEXPECTED-FAILURE",
            )
        if not execution.succeeded or execution.output is None:
            return self._failed_runtime(
                image=image,
                runtime_kind=runtime_kind,
                started_ns=started_ns,
                error_kind=(
                    execution.error_kind.value
                    if execution.error_kind is not None
                    else "runtime_failure"
                ),
                diagnostic_code=(execution.diagnostic_code or "LOCKED-OCR-RUNTIME-FAILURE"),
            )
        try:
            result = OcrResult.model_validate_json(execution.output.output_json)
            if (
                result.runtime_fingerprint != execution.identity.runtime_fingerprint
                or result.verified_image_sha256 != image.image_sha256
            ):
                raise LockedSetRunnerError("OCR runtime identity or image evidence changed")
            role_input = template_role_input_from_ocr_v1(result)
            role_run = match_ticket_role(
                role_input,
                self._templates,
                self._policy,
            )
            (
                ordinary_net_amount,
                ordinary_net_unit,
                ordinary_net_confidence,
            ) = self._ordinary_net_output(result)
            ordinary_net_reliable = role_input.ordinary_net_reliable
            weight_review_reason = ordinary_net_review_reason_from_ocr_v1(result)
            safety_route = (
                "eligible_for_downstream_comparison"
                if (
                    role_run.assessment.role is not TicketRole.UNKNOWN
                    and role_run.assessment.quality is EvidenceQuality.RELIABLE
                    and ordinary_net_reliable
                )
                else "non_automatic"
            )
            elapsed_ms = Decimal(time.perf_counter_ns() - started_ns) / Decimal(1_000_000)
            evidence = LockedOcrRuntimeOutput(
                image_sha256=image.image_sha256,
                runtime_kind=runtime_kind,
                runtime_fingerprint=result.runtime_fingerprint,
                output_fingerprint=execution.output.output_fingerprint,
                worker_elapsed_ms=Decimal(str(result.elapsed_ms)),
                wall_elapsed_ms=elapsed_ms,
                ordinary_net_amount=ordinary_net_amount,
                ordinary_net_unit=ordinary_net_unit,
                ordinary_net_confidence=ordinary_net_confidence,
                ordinary_net_reliable=ordinary_net_reliable,
                role=role_run.assessment.role,
                role_quality=role_run.assessment.quality,
                role_confidence=role_run.assessment.confidence,
                role_high_confidence=role_run.assessment.high_confidence,
                safety_route=safety_route,
                assessment_fingerprint=role_run.assessment.fingerprint,
                weight_review_reason=weight_review_reason,
                role_elapsed_ms=role_run.elapsed_ms,
            )
        except (TypeError, ValueError, LockedSetRunnerError):
            return self._failed_runtime(
                image=image,
                runtime_kind=runtime_kind,
                started_ns=started_ns,
                error_kind="invalid_output",
                diagnostic_code="LOCKED-OCR-INVALID-EVIDENCE",
            )
        return _SuccessfulRuntimeEvaluation(
            role_run=role_run,
            evidence=evidence,
        )

    @staticmethod
    def _critical_differences(
        *,
        cpu: LockedOcrRuntimeOutput,
        gpu: LockedOcrRuntimeOutput,
    ) -> tuple[str, ...]:
        cpu_payload = cpu.critical_payload()
        gpu_payload = gpu.critical_payload()
        return tuple(
            field for field in _CRITICAL_OUTPUT_FIELDS if cpu_payload[field] != gpu_payload[field]
        )

    def __call__(
        self,
        image: IndependentLockedImage,
    ) -> LockedRolePrediction:
        if not isinstance(image, IndependentLockedImage):
            raise LockedSetRunnerError("locked evaluator accepts independent image evidence only")
        started = time.perf_counter_ns()
        runtime_order: list[RuntimeKindName] = [self._backend.primary_runtime_kind]
        for runtime_kind in ("cpu", "gpu"):
            typed_kind: RuntimeKindName = runtime_kind
            if self._backend.has_runtime(typed_kind) and typed_kind not in runtime_order:
                runtime_order.append(typed_kind)

        evaluations: dict[RuntimeKindName, _RuntimeEvaluation] = {}
        for runtime_kind in runtime_order:
            evaluations[runtime_kind] = self._evaluate_runtime(
                image,
                runtime_kind,
            )

        cpu = evaluations.get("cpu")
        gpu = evaluations.get("gpu")
        selected: _SuccessfulRuntimeEvaluation
        comparison: LockedOcrRuntimeComparison
        if gpu is None:
            if not isinstance(cpu, _SuccessfulRuntimeEvaluation):
                raise LockedSetRunnerError("every qualified OCR runtime failed for locked evidence")
            selected = cpu
            comparison = LockedOcrRuntimeComparison(
                status="single_cpu",
                source=LOCAL_OCR_RUNTIME_SOURCE,
                reason="single_qualified_cpu",
                selected_runtime_kind="cpu",
                critical_fields_match=None,
                differences=(),
                outputs=(cpu.evidence,),
                failures=(),
            )
        elif isinstance(cpu, _SuccessfulRuntimeEvaluation) and isinstance(
            gpu,
            _SuccessfulRuntimeEvaluation,
        ):
            differences = self._critical_differences(
                cpu=cpu.evidence,
                gpu=gpu.evidence,
            )
            if differences:
                selected = cpu
                comparison = LockedOcrRuntimeComparison(
                    status="dual_different",
                    source=LOCAL_OCR_RUNTIME_SOURCE,
                    reason="critical_outputs_differ",
                    selected_runtime_kind="cpu",
                    critical_fields_match=False,
                    differences=differences,
                    outputs=tuple(
                        sorted(
                            (cpu.evidence, gpu.evidence),
                            key=lambda value: value.runtime_kind,
                        )
                    ),
                    failures=(),
                )
            else:
                selected_kind = self._backend.primary_runtime_kind
                selected_evaluation = evaluations[selected_kind]
                if not isinstance(
                    selected_evaluation,
                    _SuccessfulRuntimeEvaluation,
                ):
                    raise LockedSetRunnerError(
                        "primary OCR runtime did not produce evaluable evidence"
                    )
                selected = selected_evaluation
                comparison = LockedOcrRuntimeComparison(
                    status="dual_consistent",
                    source=LOCAL_OCR_RUNTIME_SOURCE,
                    reason=None,
                    selected_runtime_kind=selected_kind,
                    critical_fields_match=True,
                    differences=(),
                    outputs=tuple(
                        sorted(
                            (cpu.evidence, gpu.evidence),
                            key=lambda value: value.runtime_kind,
                        )
                    ),
                    failures=(),
                )
        elif isinstance(cpu, _SuccessfulRuntimeEvaluation) and isinstance(
            gpu,
            _FailedRuntimeEvaluation,
        ):
            selected = cpu
            comparison = LockedOcrRuntimeComparison(
                status="gpu_failed_cpu_fallback",
                source=LOCAL_OCR_RUNTIME_SOURCE,
                reason="gpu_runtime_failed",
                selected_runtime_kind="cpu",
                critical_fields_match=None,
                differences=(),
                outputs=(cpu.evidence,),
                failures=(gpu.evidence,),
            )
        else:
            raise LockedSetRunnerError(
                "every qualified OCR runtime returned invalid locked evidence"
            )

        elapsed_ms = Decimal(time.perf_counter_ns() - started) / Decimal(1_000_000)
        automatic_review_reason: str | None = None
        weight_difference_fields = {
            "ordinary_net_amount",
            "ordinary_net_unit",
            "ordinary_net_reliable",
            "weight_review_reason",
            "safety_route",
        }
        if comparison.status == "dual_different" and weight_difference_fields.intersection(
            comparison.differences
        ):
            automatic_review_reason = "ocr_weight_disagreement"
        elif selected.evidence.weight_review_reason is not None:
            automatic_review_reason = selected.evidence.weight_review_reason
        return LockedRolePrediction(
            image_sha256=image.image_sha256,
            role=selected.role_run.assessment.role,
            quality=selected.role_run.assessment.quality,
            confidence=selected.role_run.assessment.confidence,
            high_confidence=selected.role_run.assessment.high_confidence,
            assessment_fingerprint=selected.role_run.assessment.fingerprint,
            incremental_elapsed_ms=elapsed_ms,
            runtime_comparison=comparison,
            automatic_review_reason=automatic_review_reason,
        )
