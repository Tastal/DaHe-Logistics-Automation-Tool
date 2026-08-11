from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import func, select, update

from dahe.adapters.ocr.protocol import OcrResult, OcrResultStatus
from dahe.adapters.ocr.template_role_input import (
    ordinary_net_review_reason_from_ocr_v1,
)
from dahe.adapters.sqlite.production_guard import ProductionReadOnlyGuardStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    AUDIT_DECISION_REVISIONS,
    AUDIT_EVIDENCE_REVISIONS,
    AUDIT_OCR_OBSERVATIONS,
    AUDIT_REVIEW_ACTIONS,
    AUDIT_TIMELINE_EVENTS,
    IDEMPOTENCY_RECORDS,
    JOBS,
    OCR_RUN_GENERATIONS,
    OPERATIONAL_CAPTURE_RUNS,
    WORK_ITEMS,
)
from dahe.application.audit.layered_records import (
    EvidenceRevisionInput,
    build_decision_fingerprint,
    build_evidence_fingerprint,
)
from dahe.jobs.audit_execution import LocalAuditObservationProjector
from dahe.ports.jobs import (
    IdempotencyConflictError,
    RecordVersionConflictError,
)

_SHA256 = frozenset("0123456789abcdef")


class AuditItemNotFoundError(LookupError):
    pass


class AuditActionConflictError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_utc(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _progress_timing(
    *,
    started_at: object,
    phase_started_at: object,
    updated_at: object,
    current: int,
    total: int,
    is_terminal: bool,
) -> dict[str, object]:
    """Build a stable server-time basis for the one-second UI clock."""

    now = datetime.now(UTC)
    started = _parse_utc(started_at)
    phase_started = _parse_utc(phase_started_at)
    finished = _parse_utc(updated_at) if is_terminal else None
    elapsed_at = finished or now
    elapsed = max(0, int((elapsed_at - started).total_seconds()))
    phase_elapsed = max(0, (now - phase_started).total_seconds())
    if is_terminal:
        remaining: int | None = 0
        estimate_state = "complete"
    elif current >= 3 and total > current and phase_elapsed >= 5:
        remaining = max(
            1,
            round((total - current) / (current / phase_elapsed)),
        )
        estimate_state = "estimated"
    else:
        remaining = None
        estimate_state = "estimating"
    return {
        "started_at": str(started_at),
        "phase_started_at": str(phase_started_at),
        "updated_at": str(updated_at) if is_terminal else now.isoformat(),
        "finished_at": None if finished is None else str(updated_at),
        "elapsed_seconds": elapsed,
        "estimated_remaining_seconds": remaining,
        "estimate_state": estimate_state,
        "is_terminal": is_terminal,
    }


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _hash(value: object) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _require_sha(value: str, field: str) -> None:
    if len(value) != 64 or value != value.lower() or any(c not in _SHA256 for c in value):
        raise ValueError(f"{field} must be a lowercase SHA-256")


def _row_dict(row: Any) -> dict[str, object]:
    return {str(key): value for key, value in row.items()}


def _field_issues(
    item: Any,
    *,
    observations: tuple[Any, ...] = (),
) -> dict[str, dict[str, bool]]:
    """Point every review issue at recognition weight fields only."""

    fields = {
        name: {"has_issue": False}
        for name in (
            "loading_ticket",
            "loading_ocr_weight",
            "loading_platform_weight",
            "unloading_ticket",
            "unloading_ocr_weight",
            "unloading_platform_weight",
        )
    }
    if item["business_outcome"] != "awaiting_review":
        return fields

    marked_sides: set[str] = set()

    def mark(side: str) -> None:
        if side in {"loading", "unloading"}:
            marked_sides.add(side)

    observations_by_side: dict[str, list[Any]] = {
        "loading": [],
        "unloading": [],
    }
    for observation in observations:
        side = str(observation["image_role"])
        if side in observations_by_side:
            observations_by_side[side].append(observation)

    reason = str(item["review_reason"] or "")
    if reason in {"weight_mismatch", "numeric_mismatch"}:
        for side in ("loading", "unloading"):
            ticket_value = item[f"ticket_{side}_net"]
            platform_value = item[f"platform_{side}_net"]
            different = False
            if ticket_value is not None and platform_value is not None:
                try:
                    different = Decimal(str(ticket_value)) != Decimal(
                        str(platform_value)
                    )
                except InvalidOperation:
                    different = str(ticket_value) != str(platform_value)
            if different:
                mark(side)
    elif reason in {
        "ticket_weight_format_suspicious",
        "ocr_weight_disagreement",
        "ticket_net_missing",
        "ticket_net_unreliable",
        "ticket_weight_unit_requires_review",
        "ticket_weight_precision_requires_review",
    }:
        for side in ("loading", "unloading"):
            side_observations = observations_by_side[side]
            normalized_values = {
                str(observation["ordinary_net_normalized"])
                for observation in side_observations
                if observation["ordinary_net_normalized"] is not None
            }
            if (
                item[f"ticket_{side}_net"] is None
                or len(normalized_values) > 1
                or any(
                    not bool(observation["reliable"])
                    or observation["anomaly_reason"] is not None
                    for observation in side_observations
                )
            ):
                mark(side)
    elif reason in {
        "platform_weight_missing",
        "platform_weight_unreliable",
        "platform_weight_unit_requires_review",
        "platform_weight_precision_requires_review",
    }:
        for side in ("loading", "unloading"):
            if item[f"platform_{side}_net"] is None:
                mark(side)
    elif reason == "missing_ticket":
        for side in ("loading", "unloading"):
            if item[f"{side}_image_sha256"] is None:
                mark(side)
    elif reason in {
        "duplicate_image",
        "suspected_swapped",
        "role_conflict",
        "role_unknown",
        "role_unreliable",
        "wrong_ticket",
    }:
        if reason == "duplicate_image":
            marked_sides.update(("loading", "unloading"))
        else:
            for side in ("loading", "unloading"):
                for observation in observations_by_side[side]:
                    payload: dict[str, object] = {}
                    raw_payload = observation["payload_json"]
                    if isinstance(raw_payload, str):
                        try:
                            parsed_payload = json.loads(raw_payload)
                        except (TypeError, ValueError):
                            parsed_payload = None
                        if isinstance(parsed_payload, dict):
                            payload = parsed_payload
                    elif isinstance(raw_payload, dict):
                        payload = raw_payload
                    if (
                        str(observation["ticket_role"]) != side
                        or payload.get("role_high_confidence") == 0
                    ):
                        mark(side)
                        break
    if not marked_sides:
        # Historical or ambiguous reasons must still show where to look, but
        # the UI now has one vocabulary: recognition net weight.
        marked_sides.update(("loading", "unloading"))
    for side in marked_sides:
        fields[f"{side}_ocr_weight"]["has_issue"] = True
    return fields


def _review_highlight_roles(
    item: Any,
    *,
    observations: tuple[Any, ...] = (),
) -> list[str]:
    """Return the backend-authoritative recognition fields requiring review."""

    issues = _field_issues(item, observations=observations)
    return [
        side
        for side in ("loading", "unloading")
        if issues[f"{side}_ocr_weight"]["has_issue"]
    ]


def _field_issue_diagnostic_code(item: Any) -> str | None:
    """Expose a stable diagnostic when an unknown review reason used fallback."""

    if item["business_outcome"] != "awaiting_review":
        return None
    known_reasons = {
        "weight_mismatch",
        "numeric_mismatch",
        "ticket_weight_format_suspicious",
        "ocr_weight_disagreement",
        "ticket_net_missing",
        "ticket_net_unreliable",
        "ticket_weight_unit_requires_review",
        "ticket_weight_precision_requires_review",
        "platform_weight_missing",
        "platform_weight_unreliable",
        "platform_weight_unit_requires_review",
        "platform_weight_precision_requires_review",
        "missing_ticket",
        "duplicate_image",
        "suspected_swapped",
        "role_conflict",
        "role_unknown",
        "role_unreliable",
        "wrong_ticket",
    }
    return (
        None
        if str(item["review_reason"] or "") in known_reasons
        else "AUDIT-FIELD-ISSUE-FALLBACK"
    )


class SqliteAuditWorkflowRepository:
    """Append-only audit evidence and identity-free manual actions."""

    def __init__(
        self,
        runtime: SqliteRuntime,
        *,
        local_observation_projector: LocalAuditObservationProjector | None = None,
        production_guard: ProductionReadOnlyGuardStore | None = None,
    ) -> None:
        self._runtime = runtime
        self._local_observation_projector = local_observation_projector
        self._production_guard = production_guard

    def sync_loop8_offline_results(self) -> int:
        """Materialize scheduler results into the immutable Loop 8 layers."""
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(WORK_ITEMS)
                    .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                    .outerjoin(
                        AUDIT_EVIDENCE_REVISIONS,
                        AUDIT_EVIDENCE_REVISIONS.c.work_item_id
                        == WORK_ITEMS.c.work_item_id,
                    )
                    .where(
                        JOBS.c.scope_fixture_id == "loop8-offline-v1",
                        WORK_ITEMS.c.status.in_(
                            ("waiting_user", "succeeded", "failed")
                        ),
                        AUDIT_EVIDENCE_REVISIONS.c.evidence_revision_id.is_(
                            None
                        ),
                    )
                    .order_by(WORK_ITEMS.c.item_index)
                ).mappings()
            )
        for item in rows:
            self._append_offline_result(item)
        return len(rows)

    def sync_business_audit_results(self) -> int:
        """Materialize committed audit jobs without inventing OCR evidence."""

        synchronized = self.sync_loop8_offline_results()
        with self._runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(
                        WORK_ITEMS,
                        JOBS.c.scope_fingerprint.label(
                            "job_scope_fingerprint"
                        ),
                        OCR_RUN_GENERATIONS.c.status.label(
                            "generation_status"
                        ),
                        OCR_RUN_GENERATIONS.c.committed_runtime_kind.label(
                            "generation_runtime_kind"
                        ),
                        OCR_RUN_GENERATIONS.c.committed_runtime_fingerprint.label(
                            "generation_runtime_fingerprint"
                        ),
                        OCR_RUN_GENERATIONS.c.committed_profile_id.label(
                            "generation_profile_id"
                        ),
                        OCR_RUN_GENERATIONS.c.loading_output_json.label(
                            "generation_loading_output_json"
                        ),
                        OCR_RUN_GENERATIONS.c.unloading_output_json.label(
                            "generation_unloading_output_json"
                        ),
                        OCR_RUN_GENERATIONS.c.loading_output_fingerprint.label(
                            "generation_loading_output_fingerprint"
                        ),
                        OCR_RUN_GENERATIONS.c.unloading_output_fingerprint.label(
                            "generation_unloading_output_fingerprint"
                        ),
                    )
                    .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                    .outerjoin(
                        OCR_RUN_GENERATIONS,
                        OCR_RUN_GENERATIONS.c.work_item_id
                        == WORK_ITEMS.c.work_item_id,
                    )
                    .outerjoin(
                        AUDIT_EVIDENCE_REVISIONS,
                        AUDIT_EVIDENCE_REVISIONS.c.work_item_id
                        == WORK_ITEMS.c.work_item_id,
                    )
                    .where(
                        JOBS.c.job_kind == "business",
                        JOBS.c.task_type == "audit",
                        JOBS.c.ocr_execution_mode == "local",
                        WORK_ITEMS.c.status.in_(
                            ("waiting_user", "succeeded", "failed")
                        ),
                        AUDIT_EVIDENCE_REVISIONS.c.evidence_revision_id.is_(
                            None
                        ),
                    )
                    .order_by(
                        JOBS.c.created_sequence,
                        WORK_ITEMS.c.item_index,
                    )
                ).mappings()
            )
        for item in rows:
            try:
                self._append_local_result(item)
            except AuditActionConflictError:
                failed_item = dict(item)
                with self._runtime.commit_gate.transaction(
                    self._runtime.engine
                ) as connection:
                    result = connection.execute(
                        update(WORK_ITEMS)
                        .where(
                            WORK_ITEMS.c.work_item_id
                            == item["work_item_id"],
                            WORK_ITEMS.c.record_version
                            == item["record_version"],
                        )
                        .values(
                            status="failed",
                            current_stage="audit.role_validate",
                            business_outcome=None,
                            decision="failed",
                            review_reason=None,
                            waiting_reason_kind=None,
                            waiting_reason=None,
                            diagnostic_code=(
                                "AUDIT-COMMITTED-EVIDENCE-INVALID"
                            ),
                            record_version=int(item["record_version"]) + 1,
                        )
                    )
                    if result.rowcount != 1:
                        continue
                failed_item.update(
                    status="failed",
                    business_outcome=None,
                    decision="failed",
                    review_reason=None,
                    diagnostic_code="AUDIT-COMMITTED-EVIDENCE-INVALID",
                    record_version=int(item["record_version"]) + 1,
                )
                self._append_local_result(failed_item)
                synchronized += 1
                continue
            if (
                self._production_guard is not None
                and str(item["status"]) != "failed"
            ):
                self._production_guard.register_result(
                    work_item_id=str(item["work_item_id"]),
                    machine_outcome=str(item["business_outcome"]),
                )
            synchronized += 1
        return synchronized

    def _local_observation(
        self,
        *,
        image_role: str,
        image_sha256: str,
        pipeline_fingerprint: str,
        runtime_kind: str,
        runtime_fingerprint: str,
        output_json: str,
        output_fingerprint: str,
        profile_id: str,
        work_item_id: str,
    ) -> dict[str, object]:
        try:
            result = OcrResult.model_validate_json(output_json)
        except (ValidationError, ValueError) as exc:
            raise AuditActionConflictError(
                "committed OCR evidence is invalid"
            ) from exc
        if (
            result.status is not OcrResultStatus.OK
            or result.verified_image_sha256 != image_sha256
            or result.runtime_fingerprint != runtime_fingerprint
        ):
            raise AuditActionConflictError(
                "committed OCR evidence identity changed"
            )
        field = result.fields.get("ordinary_net")
        raw_amount = None if field is None else field.amount
        unit = None if field is None else field.unit
        anomaly = ordinary_net_review_reason_from_ocr_v1(result)
        reliable = bool(
            raw_amount is not None
            and unit in {"t", "kg"}
            and anomaly is None
        )
        ticket_role = "unknown"
        role_metadata: dict[str, object] = {}
        if self._local_observation_projector is not None:
            try:
                projection = (
                    self._local_observation_projector.project_observation(
                        output_json=output_json,
                        expected_image_sha256=image_sha256,
                        expected_runtime_fingerprint=runtime_fingerprint,
                    )
                )
            except Exception as exc:
                raise AuditActionConflictError(
                    "committed OCR role evidence is invalid"
                ) from exc
            ticket_role = projection.ticket_role
            raw_amount = projection.ordinary_net_amount
            unit = projection.ordinary_net_unit
            anomaly = projection.weight_review_reason
            reliable = projection.ordinary_net_reliable
            role_metadata = {
                "role_fingerprint": projection.role_fingerprint,
                "role_high_confidence": int(
                    projection.role_high_confidence
                ),
                "role_quality": projection.role_quality,
                "template_set_fingerprint": (
                    projection.template_set_fingerprint
                ),
            }
        payload: dict[str, object] = {
            "anomaly_reason": anomaly,
            "evidence_scope": work_item_id,
            "image_role": image_role,
            "image_sha256": image_sha256,
            "ordinary_net_normalized": raw_amount,
            "ordinary_net_raw": raw_amount,
            "output_fingerprint": output_fingerprint,
            "pipeline_fingerprint": pipeline_fingerprint,
            "profile_id": profile_id,
            "reliable": int(reliable),
            "runtime_fingerprint": runtime_fingerprint,
            "runtime_kind": runtime_kind,
            "template_version_id": None,
            # The upload slot never supplies this value. When configured, the
            # accepted template projector supplies the machine role.
            "ticket_role": ticket_role,
            "unit": unit,
            **role_metadata,
        }
        payload["observation_sha256"] = _hash(payload)
        return payload

    def _append_local_result(self, item: Any) -> None:
        work_item_id = str(item["work_item_id"])
        failed = str(item["status"]) == "failed"
        observations: tuple[dict[str, object], ...] = ()
        if not failed:
            required = {
                "loading_image_sha256": item["loading_image_sha256"],
                "unloading_image_sha256": item[
                    "unloading_image_sha256"
                ],
                "pipeline_fingerprint": item["pipeline_fingerprint"],
                "runtime_kind": item["generation_runtime_kind"],
                "runtime_fingerprint": item[
                    "generation_runtime_fingerprint"
                ],
                "profile_id": item["generation_profile_id"],
                "loading_output_json": item[
                    "generation_loading_output_json"
                ],
                "unloading_output_json": item[
                    "generation_unloading_output_json"
                ],
                "loading_output_fingerprint": item[
                    "generation_loading_output_fingerprint"
                ],
                "unloading_output_fingerprint": item[
                    "generation_unloading_output_fingerprint"
                ],
            }
            if (
                item["generation_status"] != "succeeded"
                or any(value is None for value in required.values())
            ):
                raise AuditActionConflictError(
                    "committed local audit result is incomplete"
                )
            observations = tuple(
                self._local_observation(
                    image_role=image_role,
                    image_sha256=str(required[f"{image_role}_image_sha256"]),
                    pipeline_fingerprint=str(
                        required["pipeline_fingerprint"]
                    ),
                    runtime_kind=str(required["runtime_kind"]),
                    runtime_fingerprint=str(
                        required["runtime_fingerprint"]
                    ),
                    output_json=str(
                        required[f"{image_role}_output_json"]
                    ),
                    output_fingerprint=str(
                        required[f"{image_role}_output_fingerprint"]
                    ),
                    profile_id=str(required["profile_id"]),
                    work_item_id=work_item_id,
                )
                for image_role in ("loading", "unloading")
            )

        snapshot_payload = {
            "job_scope_fingerprint": item["job_scope_fingerprint"],
            "platform_loading_net": item["platform_loading_net"],
            "platform_unloading_net": item["platform_unloading_net"],
            "waybill_id": item["waybill_number"],
        }
        self.append_initial_revision(
            work_item_id=work_item_id,
            platform_snapshot_sha256=_hash(snapshot_payload),
            loading_image_sha256=(
                None
                if item["loading_image_sha256"] is None
                else str(item["loading_image_sha256"])
            ),
            unloading_image_sha256=(
                None
                if item["unloading_image_sha256"] is None
                else str(item["unloading_image_sha256"])
            ),
            platform_loading_net=(
                None
                if item["platform_loading_net"] is None
                else str(item["platform_loading_net"])
            ),
            platform_unloading_net=(
                None
                if item["platform_unloading_net"] is None
                else str(item["platform_unloading_net"])
            ),
            ticket_loading_net=(
                None
                if item["ticket_loading_net"] is None
                else str(item["ticket_loading_net"])
            ),
            ticket_unloading_net=(
                None
                if item["ticket_unloading_net"] is None
                else str(item["ticket_unloading_net"])
            ),
            business_outcome=(
                "technical_failure"
                if failed
                else str(item["business_outcome"])
            ),
            review_reason=(
                None
                if failed or item["review_reason"] is None
                else str(item["review_reason"])
            ),
            decision=(
                "failed"
                if failed
                else "review"
                if str(item["status"]) == "waiting_user"
                else "pass"
            ),
            rules_fingerprint=_hash(
                {
                    "contract": "dahe.audit.rules.loop9.v1",
                    "pipeline_fingerprint": item[
                        "pipeline_fingerprint"
                    ],
                }
            ),
            observations=observations,
        )

    def _append_offline_result(self, item: Any) -> None:
        work_item_id = str(item["work_item_id"])
        reason = (
            None
            if item["review_reason"] is None
            else str(item["review_reason"])
        )
        loading_sha = (
            None
            if item["loading_image_sha256"] in (None, "0" * 64)
            else str(item["loading_image_sha256"])
        )
        unloading_sha = (
            None
            if item["unloading_image_sha256"] in (None, "0" * 64)
            else str(item["unloading_image_sha256"])
        )
        snapshot_payload = {
            "platform_loading_net": item["platform_loading_net"],
            "platform_unloading_net": item["platform_unloading_net"],
            "waybill_id": item["waybill_number"],
        }
        observations: list[dict[str, object]] = []

        def add_observation(
            *,
            image_role: str,
            image_sha256: str | None,
            runtime_kind: str,
            ticket_role: str,
            raw: str | None,
            normalized: str | None,
            reliable: bool,
            anomaly: str | None = None,
        ) -> None:
            if image_sha256 is None:
                return
            payload: dict[str, object] = {
                "anomaly_reason": anomaly,
                "evidence_scope": work_item_id,
                "image_role": image_role,
                "image_sha256": image_sha256,
                "ordinary_net_normalized": normalized,
                "ordinary_net_raw": raw,
                "pipeline_fingerprint": _hash(
                    "dahe.loop8.offline.acceptance.v1"
                ),
                "reliable": int(reliable),
                "runtime_fingerprint": _hash(
                    f"loop8-{runtime_kind}-fixture-runtime"
                ),
                "runtime_kind": runtime_kind,
                "template_version_id": None,
                "ticket_role": ticket_role,
                "unit": "t" if raw is not None else None,
            }
            payload["observation_sha256"] = _hash(payload)
            observations.append(payload)

        role_map = {
            "suspected_swapped": ("unloading", "loading"),
            "both_loading": ("loading", "loading"),
            "both_unloading": ("unloading", "unloading"),
            "role_unknown": ("unknown", "unknown"),
            "duplicate_image": ("unknown", "unknown"),
        }
        loading_role, unloading_role = role_map.get(
            reason or "",
            ("loading", "unloading"),
        )
        loading_raw = (
            None
            if item["ticket_loading_net"] is None
            else str(item["ticket_loading_net"])
        )
        unloading_raw = (
            None
            if item["ticket_unloading_net"] is None
            else str(item["ticket_unloading_net"])
        )
        if reason == "ocr_weight_disagreement":
            add_observation(
                image_role="loading",
                image_sha256=loading_sha,
                runtime_kind="cpu",
                ticket_role="loading",
                raw="3270",
                normalized="3270",
                reliable=False,
                anomaly="ticket_weight_format_suspicious",
            )
            add_observation(
                image_role="loading",
                image_sha256=loading_sha,
                runtime_kind="gpu",
                ticket_role="loading",
                raw="32.7",
                normalized="32.70",
                reliable=True,
            )
        else:
            add_observation(
                image_role="loading",
                image_sha256=loading_sha,
                runtime_kind="fixture",
                ticket_role=loading_role,
                raw=loading_raw,
                normalized=loading_raw,
                reliable=(
                    loading_raw is not None
                    and reason != "ticket_weight_format_suspicious"
                ),
                anomaly=(
                    "ticket_weight_format_suspicious"
                    if reason == "ticket_weight_format_suspicious"
                    else None
                ),
            )
        add_observation(
            image_role="unloading",
            image_sha256=unloading_sha,
            runtime_kind="fixture",
            ticket_role=unloading_role,
            raw=unloading_raw,
            normalized=unloading_raw,
            reliable=unloading_raw is not None,
        )
        decision = (
            "failed"
            if item["status"] == "failed"
            else "review"
            if item["status"] == "waiting_user"
            else "pass"
        )
        outcome = (
            "technical_failure"
            if item["status"] == "failed"
            else str(item["business_outcome"])
        )
        self.append_initial_revision(
            work_item_id=work_item_id,
            platform_snapshot_sha256=_hash(snapshot_payload),
            loading_image_sha256=loading_sha,
            unloading_image_sha256=unloading_sha,
            platform_loading_net=(
                None
                if item["platform_loading_net"] is None
                else str(item["platform_loading_net"])
            ),
            platform_unloading_net=(
                None
                if item["platform_unloading_net"] is None
                else str(item["platform_unloading_net"])
            ),
            ticket_loading_net=loading_raw,
            ticket_unloading_net=unloading_raw,
            business_outcome=outcome,
            review_reason=reason,
            decision=decision,
            rules_fingerprint=_hash("dahe.audit.rules.loop8.v1"),
            observations=tuple(observations),
        )

    def append_initial_revision(
        self,
        *,
        work_item_id: str,
        platform_snapshot_sha256: str,
        loading_image_sha256: str | None,
        unloading_image_sha256: str | None,
        platform_loading_net: str | None,
        platform_unloading_net: str | None,
        ticket_loading_net: str | None,
        ticket_unloading_net: str | None,
        business_outcome: str,
        review_reason: str | None,
        decision: str,
        rules_fingerprint: str,
        observations: tuple[dict[str, object], ...] = (),
    ) -> dict[str, object]:
        _require_sha(platform_snapshot_sha256, "platform_snapshot_sha256")
        _require_sha(rules_fingerprint, "rules_fingerprint")
        for value, field in (
            (loading_image_sha256, "loading_image_sha256"),
            (unloading_image_sha256, "unloading_image_sha256"),
        ):
            if value is not None:
                _require_sha(value, field)
        now = _now()
        evidence_payload = {
            "loading_image_sha256": loading_image_sha256,
            "platform_loading_net": platform_loading_net,
            "platform_snapshot_sha256": platform_snapshot_sha256,
            "platform_unloading_net": platform_unloading_net,
            "unloading_image_sha256": unloading_image_sha256,
        }
        evidence_input = EvidenceRevisionInput(
            platform_snapshot_sha256=platform_snapshot_sha256,
            loading_image_sha256=loading_image_sha256,
            unloading_image_sha256=unloading_image_sha256,
        )
        evidence_fingerprint = build_evidence_fingerprint(evidence_input)
        decision_payload = {
            "business_outcome": business_outcome,
            "decision": decision,
            "evidence_fingerprint": evidence_fingerprint,
            "review_reason": review_reason,
            "rules_fingerprint": rules_fingerprint,
            "ticket_loading_net": ticket_loading_net,
            "ticket_unloading_net": ticket_unloading_net,
        }
        observation_by_role = {
            str(item["image_role"]): str(item["observation_sha256"])
            for item in observations
        }
        decision_fingerprint = build_decision_fingerprint(
            evidence_fingerprint=evidence_fingerprint,
            loading_ocr_fingerprint=observation_by_role.get("loading"),
            unloading_ocr_fingerprint=observation_by_role.get("unloading"),
            rule_version=rules_fingerprint,
        )
        with self._runtime.commit_gate.transaction(
            self._runtime.engine
        ) as connection:
            item = (
                connection.execute(
                    select(WORK_ITEMS).where(
                        WORK_ITEMS.c.work_item_id == work_item_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if item is None:
                raise AuditItemNotFoundError(work_item_id)
            existing = connection.execute(
                select(AUDIT_EVIDENCE_REVISIONS).where(
                    AUDIT_EVIDENCE_REVISIONS.c.work_item_id == work_item_id
                )
            ).mappings().one_or_none()
            if existing is not None:
                return self._get_item_no_sync(work_item_id)
            evidence_revision_id = uuid4().hex
            decision_revision_id = uuid4().hex
            connection.execute(
                AUDIT_EVIDENCE_REVISIONS.insert().values(
                    evidence_revision_id=evidence_revision_id,
                    work_item_id=work_item_id,
                    revision_number=1,
                    platform_snapshot_sha256=platform_snapshot_sha256,
                    loading_image_sha256=loading_image_sha256,
                    unloading_image_sha256=unloading_image_sha256,
                    payload_json=_json(evidence_payload),
                    fingerprint=evidence_fingerprint,
                    created_at=now,
                )
            )
            for observation in observations:
                stored_observation = {
                    key: observation[key]
                    for key in (
                        "anomaly_reason",
                        "image_role",
                        "image_sha256",
                        "observation_sha256",
                        "ordinary_net_normalized",
                        "ordinary_net_raw",
                        "pipeline_fingerprint",
                        "reliable",
                        "runtime_fingerprint",
                        "runtime_kind",
                        "template_version_id",
                        "ticket_role",
                        "unit",
                    )
                }
                connection.execute(
                    AUDIT_OCR_OBSERVATIONS.insert().values(
                        ocr_observation_id=uuid4().hex,
                        evidence_revision_id=evidence_revision_id,
                        **stored_observation,
                        payload_json=_json(observation),
                        created_at=now,
                    )
                )
            connection.execute(
                AUDIT_DECISION_REVISIONS.insert().values(
                    decision_revision_id=decision_revision_id,
                    work_item_id=work_item_id,
                    evidence_revision_id=evidence_revision_id,
                    revision_number=1,
                    rules_fingerprint=rules_fingerprint,
                    business_outcome=business_outcome,
                    review_reason=review_reason,
                    decision=decision,
                    payload_json=_json(decision_payload),
                    fingerprint=decision_fingerprint,
                    created_at=now,
                )
            )
            connection.execute(
                AUDIT_TIMELINE_EVENTS.insert().values(
                    timeline_event_id=uuid4().hex,
                    work_item_id=work_item_id,
                    event_type="audit_decision_created",
                    reference_id=decision_revision_id,
                    payload_json=_json(
                        {
                            "business_outcome": business_outcome,
                            "review_reason": review_reason,
                        }
                    ),
                    created_at=now,
                )
            )
        return self._get_item_no_sync(work_item_id)

    def list_review_items(self) -> tuple[dict[str, object], ...]:
        return self.list_audit_items(view="waiting_review")

    def list_audit_items(
        self,
        *,
        view: str = "all",
        job_id: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        workspace = self.get_audit_workspace(view=view, job_id=job_id)
        items = workspace["items"]
        assert isinstance(items, tuple)
        return items

    def get_audit_workspace(
        self,
        *,
        view: str = "all",
        job_id: str | None = None,
    ) -> dict[str, object]:
        self.sync_business_audit_results()
        if view not in {
            "all",
            "waiting_review",
            "confirmed_problem",
            "normal_ready",
        }:
            raise ValueError("unsupported audit workspace view")
        statement = (
            select(WORK_ITEMS)
            .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
            .where(JOBS.c.task_type == "audit")
            .order_by(
                WORK_ITEMS.c.ready_sequence.desc(),
                WORK_ITEMS.c.item_index,
            )
        )
        if job_id:
            statement = statement.where(WORK_ITEMS.c.job_id == job_id)
        with self._runtime.engine.connect() as connection:
            all_items = tuple(
                self._project_item(connection, row)
                for row in connection.execute(statement).mappings()
            )
        counts = {
            "all": len(all_items),
            "waiting_review": sum(
                item.get("status") == "waiting_user" for item in all_items
            ),
            "confirmed_problem": sum(
                item.get("business_outcome") == "confirmed_problem"
                for item in all_items
            ),
            "normal_ready": sum(
                item.get("business_outcome") == "normal_ready"
                for item in all_items
            ),
        }
        if view == "waiting_review":
            items = tuple(
                item for item in all_items if item.get("status") == "waiting_user"
            )
        elif view in {"confirmed_problem", "normal_ready"}:
            items = tuple(
                item
                for item in all_items
                if item.get("business_outcome") == view
            )
        else:
            items = all_items
        result: dict[str, object] = {"items": items, "counts": counts}
        if self._production_guard is not None:
            result["production_guard"] = (
                self._production_guard.status().to_payload()
            )
        return result

    def get_settlement_workspace(
        self,
        *,
        view: str = "all",
    ) -> dict[str, object]:
        """Project one business fetch across its internal OCR batch jobs."""

        self.sync_business_audit_results()
        if view not in {
            "all",
            "waiting_review",
            "confirmed_problem",
            "normal_ready",
        }:
            raise ValueError("unsupported settlement workspace view")
        with self._runtime.engine.connect() as connection:
            capture = (
                connection.execute(
                    select(JOBS)
                    .where(
                        JOBS.c.task_type == "settlement_capture",
                        JOBS.c.conflict_key
                        == "settlement_capture:operational_compat",
                    )
                    .order_by(JOBS.c.created_sequence.desc())
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
            if capture is None:
                return {
                    "latest_fetch": None,
                    "items": (),
                    "counts": {
                        "all": 0,
                        "waiting_review": 0,
                        "confirmed_problem": 0,
                        "normal_ready": 0,
                    },
                }

            capture_job_id = str(capture["job_id"])
            links = tuple(
                connection.execute(
                    select(IDEMPOTENCY_RECORDS)
                    .where(
                        IDEMPOTENCY_RECORDS.c.operation
                        == "POST:/api/v1/jobs",
                        IDEMPOTENCY_RECORDS.c.idempotency_key.like(
                            f"operational-materialize:{capture_job_id}:%"
                        ),
                    )
                    .order_by(IDEMPOTENCY_RECORDS.c.created_at)
                )
                .mappings()
            )
            audit_job_ids = tuple(str(link["job_id"]) for link in links)
            latest_audit_job_update = None
            rows: tuple[Any, ...] = ()
            if audit_job_ids:
                latest_audit_job_update = connection.execute(
                    select(func.max(JOBS.c.updated_at)).where(
                        JOBS.c.job_id.in_(audit_job_ids)
                    )
                ).scalar_one()
                rows = tuple(
                    connection.execute(
                        select(WORK_ITEMS)
                        .where(WORK_ITEMS.c.job_id.in_(audit_job_ids))
                        .order_by(
                            WORK_ITEMS.c.ready_sequence,
                            WORK_ITEMS.c.item_index,
                        )
                    ).mappings()
                )
            projected = tuple(
                self._project_item(connection, row) for row in rows
            )
            capture_run = (
                connection.execute(
                    select(OPERATIONAL_CAPTURE_RUNS).where(
                        OPERATIONAL_CAPTURE_RUNS.c.job_id == capture_job_id
                    )
                )
                .mappings()
                .one_or_none()
            )

        business_items = tuple(
            item
            for item in projected
            if item.get("diagnostic_code") is None
            and item.get("business_outcome")
            in {"awaiting_review", "confirmed_problem", "normal_ready"}
        )
        counts = {
            "all": len(business_items),
            "waiting_review": sum(
                item.get("business_outcome") == "awaiting_review"
                for item in business_items
            ),
            "confirmed_problem": sum(
                item.get("business_outcome") == "confirmed_problem"
                for item in business_items
            ),
            "normal_ready": sum(
                item.get("business_outcome") == "normal_ready"
                for item in business_items
            ),
        }
        if view == "all":
            items = business_items
        else:
            expected_outcome = (
                "awaiting_review" if view == "waiting_review" else view
            )
            items = tuple(
                item
                for item in business_items
                if item.get("business_outcome") == expected_outcome
            )

        capture_status = str(capture["status"])
        total = (
            len(projected)
            if capture_run is None
            else int(capture_run["total"])
        )
        fetched = (
            len(projected)
            if capture_run is None
            else int(capture_run["next_item_index"])
        )
        recognized = sum(
            item.get("latest_decision") is not None for item in projected
        )
        ocr_images_completed = sum(
            int(bool(row["loading_ocr_complete"]))
            + int(bool(row["unloading_ocr_complete"]))
            for row in rows
        )
        technical_failures = sum(
            item.get("diagnostic_code") is not None
            or item.get("business_outcome") == "technical_failure"
            for item in projected
        )
        capture_complete = bool(
            capture_status == "succeeded"
            and (
                capture_run is None
                or str(capture_run["status"]) == "complete"
            )
        )
        is_complete = capture_complete and recognized >= total
        if capture_status in {"failed", "cancelled"}:
            phase = "本次获取未完整"
            phase_code = "incomplete"
        elif is_complete:
            phase = "已完成"
            phase_code = "complete"
        elif (
            capture_status in {"paused", "waiting_external"}
            and capture.get("diagnostic_code")
            in {
                "CF-CREDENTIAL-REQUIRED",
                "CF-LOGIN-INTERVENTION-REQUIRED",
                "CF-LOGIN-REQUIRED",
            }
        ):
            phase = "正在登录平台"
            phase_code = "login"
        elif fetched < total or capture_run is None:
            phase = "正在下载磅单" if total else "正在读取运单"
            phase_code = "download" if total else "read"
        elif recognized < total:
            phase = "正在识别磅单"
            phase_code = "recognize"
        else:
            phase = "正在整理结果"
            phase_code = "finalize"
        progress_total = max(total, 0)
        progress_value = (
            recognized if fetched >= total and total else fetched
        )
        latest_fetch = {
            "created_at": capture["created_at"],
            "updated_at": capture["updated_at"],
            "status": (
                "complete"
                if is_complete
                else "incomplete"
                if capture_status in {"failed", "cancelled"}
                else "running"
            ),
            "is_complete": is_complete,
            "phase_label": phase,
            "phase": phase_code,
            "progress_current": min(progress_value, progress_total),
            "progress_total": progress_total,
            "fetched_count": fetched,
            "recognized_count": recognized,
            "technical_failure_count": technical_failures,
            "metadata_checked": (
                fetched
                if capture_run is None
                else int(capture_run["metadata_checked_count"])
            ),
            "reused": (
                0
                if capture_run is None
                else int(capture_run["reused_count"])
            ),
            "images_downloaded": (
                0
                if capture_run is None
                else int(capture_run["images_downloaded_count"])
            ),
            "ocr_completed": recognized,
            "ocr_images_completed": ocr_images_completed,
            "ocr_images_total": len(rows) * 2,
            "finalized": len(projected),
        }
        phase_started_at = capture["created_at"]
        if phase_code in {"recognize", "finalize", "complete"} and links:
            phase_started_at = min(str(link["created_at"]) for link in links)
        latest_fetch.update(
            _progress_timing(
                started_at=capture["created_at"],
                phase_started_at=phase_started_at,
                updated_at=(
                    max(
                        (str(capture["updated_at"]), str(latest_audit_job_update)),
                        key=_parse_utc,
                    )
                    if is_complete and latest_audit_job_update is not None
                    else capture["updated_at"]
                ),
                current=min(progress_value, progress_total),
                total=progress_total,
                is_terminal=(
                    is_complete
                    or capture_status in {"failed", "cancelled"}
                ),
            )
        )
        return {
            "latest_fetch": latest_fetch,
            "items": items,
            "counts": counts,
        }

    def list_latest_settlement_ready_waybill_numbers(self) -> tuple[str, ...]:
        """Return one stable, deduplicated list for the visible business handoff."""

        workspace = self.get_settlement_workspace(view="normal_ready")
        items = workspace["items"]
        assert isinstance(items, tuple)
        ordered: list[str] = []
        seen: set[str] = set()
        for item in items:
            value = str(item.get("waybill_id") or "").strip()
            if value and value not in seen:
                ordered.append(value)
                seen.add(value)
        return tuple(ordered)

    def list_waybills(
        self,
        *,
        query: str | None = None,
        business_outcome: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        self.sync_business_audit_results()
        statement = (
            select(WORK_ITEMS)
            .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
            .where(JOBS.c.task_type == "audit")
            .order_by(
                WORK_ITEMS.c.ready_sequence.desc(),
                WORK_ITEMS.c.item_index,
            )
        )
        if query:
            statement = statement.where(
                WORK_ITEMS.c.waybill_number.contains(query)
            )
        if business_outcome:
            statement = statement.where(
                WORK_ITEMS.c.business_outcome == business_outcome
            )
        with self._runtime.engine.connect() as connection:
            return tuple(
                self._project_item(connection, row)
                for row in connection.execute(statement).mappings()
            )

    def get_item(self, work_item_id: str) -> dict[str, object]:
        self.sync_business_audit_results()
        return self._get_item_no_sync(work_item_id)

    def _get_item_no_sync(self, work_item_id: str) -> dict[str, object]:
        with self._runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    select(WORK_ITEMS).where(
                        WORK_ITEMS.c.work_item_id == work_item_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise AuditItemNotFoundError(work_item_id)
            return self._project_item(connection, row, include_timeline=True)

    def record_action(
        self,
        *,
        work_item_id: str,
        action_type: str,
        reason_code: str,
        correct_value: str | None,
        note: str | None,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
        revokes_action_id: str | None = None,
    ) -> tuple[dict[str, object], bool]:
        if action_type == "correction":
            raise ValueError("manual weight correction is retired")
        if action_type in {
            "problem_confirmation",
            "problem_dismissal",
        } and (correct_value is not None or note is not None):
            raise ValueError(
                "manual decisions do not accept a corrected weight or note"
            )
        if action_type == "revocation":
            if revokes_action_id is None or correct_value is not None:
                raise ValueError("revocation must reference one action")
        elif action_type not in {
            "problem_confirmation",
            "problem_dismissal",
        }:
            raise ValueError("unsupported review action")
        if not reason_code.strip():
            raise ValueError("reason_code is required")
        _require_sha(request_hash, "request_hash")
        now = _now()
        with self._runtime.commit_gate.transaction(
            self._runtime.engine
        ) as connection:
            replay = (
                connection.execute(
                    select(AUDIT_REVIEW_ACTIONS).where(
                        AUDIT_REVIEW_ACTIONS.c.idempotency_key
                        == idempotency_key
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if replay["request_hash"] != request_hash:
                    raise IdempotencyConflictError(
                        "the idempotency key belongs to another request"
                    )
                return (
                    self._project_item_by_id(
                        connection,
                        str(replay["work_item_id"]),
                        include_timeline=True,
                    ),
                    True,
                )
            item = (
                connection.execute(
                    select(WORK_ITEMS).where(
                        WORK_ITEMS.c.work_item_id == work_item_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if item is None:
                raise AuditItemNotFoundError(work_item_id)
            if int(item["record_version"]) != expected_record_version:
                raise RecordVersionConflictError("audit item version is stale")
            evidence = (
                connection.execute(
                    select(AUDIT_EVIDENCE_REVISIONS)
                    .where(
                        AUDIT_EVIDENCE_REVISIONS.c.work_item_id
                        == work_item_id
                    )
                    .order_by(
                        AUDIT_EVIDENCE_REVISIONS.c.revision_number.desc()
                    )
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
            if evidence is None:
                raise AuditActionConflictError(
                    "the item has no immutable evidence revision"
                )
            if action_type == "revocation":
                original = (
                    connection.execute(
                        select(AUDIT_REVIEW_ACTIONS).where(
                            AUDIT_REVIEW_ACTIONS.c.action_id
                            == revokes_action_id,
                            AUDIT_REVIEW_ACTIONS.c.work_item_id
                            == work_item_id,
                            AUDIT_REVIEW_ACTIONS.c.action_type
                            != "revocation",
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if original is None:
                    raise AuditActionConflictError(
                        "the referenced action does not exist"
                    )
                already_revoked = connection.execute(
                    select(AUDIT_REVIEW_ACTIONS.c.action_id).where(
                        AUDIT_REVIEW_ACTIONS.c.revokes_action_id
                        == revokes_action_id
                    )
                ).scalar_one_or_none()
                if already_revoked is not None:
                    raise AuditActionConflictError(
                        "the referenced action is already revoked"
                    )
            action_id = uuid4().hex
            next_version = int(item["record_version"]) + 1
            connection.execute(
                AUDIT_REVIEW_ACTIONS.insert().values(
                    action_id=action_id,
                    work_item_id=work_item_id,
                    evidence_revision_id=evidence["evidence_revision_id"],
                    action_type=action_type,
                    reason_code=reason_code,
                    correct_value=correct_value,
                    note=note,
                    revokes_action_id=revokes_action_id,
                    record_version=next_version,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    created_at=now,
                )
            )
            latest_decision = (
                connection.execute(
                    select(AUDIT_DECISION_REVISIONS)
                    .where(
                        AUDIT_DECISION_REVISIONS.c.work_item_id
                        == work_item_id
                    )
                    .order_by(
                        AUDIT_DECISION_REVISIONS.c.revision_number.desc()
                    )
                    .limit(1)
                )
                .mappings()
                .one()
            )
            source_decision = (
                connection.execute(
                    select(AUDIT_DECISION_REVISIONS)
                    .where(
                        AUDIT_DECISION_REVISIONS.c.work_item_id
                        == work_item_id
                    )
                    .order_by(
                        AUDIT_DECISION_REVISIONS.c.revision_number.asc()
                    )
                    .limit(1)
                )
                .mappings()
                .one()
            )
            active_actions = self._active_actions(
                connection,
                work_item_id,
            )
            business_outcome, decision, review_reason, status = (
                self._result_after_actions(
                    base=source_decision,
                    active_actions=active_actions,
                )
            )
            decision_revision = int(latest_decision["revision_number"]) + 1
            decision_revision_id = uuid4().hex
            action_hashes = tuple(
                _hash(
                    {
                        "action_id": row["action_id"],
                        "action_type": row["action_type"],
                        "correct_value": row["correct_value"],
                        "reason_code": row["reason_code"],
                    }
                )
                for row in active_actions
            )
            base_decision_fingerprint = build_decision_fingerprint(
                evidence_fingerprint=str(evidence["fingerprint"]),
                loading_ocr_fingerprint=self._observation_fingerprint(
                    connection,
                    evidence_revision_id=str(
                        evidence["evidence_revision_id"]
                    ),
                    image_role="loading",
                ),
                unloading_ocr_fingerprint=self._observation_fingerprint(
                    connection,
                    evidence_revision_id=str(
                        evidence["evidence_revision_id"]
                    ),
                    image_role="unloading",
                ),
                rule_version=str(latest_decision["rules_fingerprint"]),
            )
            decision_fingerprint = _hash(
                {
                    "active_manual_action_sha256s": action_hashes,
                    "base_decision_fingerprint": base_decision_fingerprint,
                }
            )
            decision_payload = {
                "active_action_ids": [
                    str(row["action_id"]) for row in active_actions
                ],
                "business_outcome": business_outcome,
                "decision": decision,
                "review_reason": review_reason,
            }
            connection.execute(
                AUDIT_DECISION_REVISIONS.insert().values(
                    decision_revision_id=decision_revision_id,
                    work_item_id=work_item_id,
                    evidence_revision_id=evidence["evidence_revision_id"],
                    revision_number=decision_revision,
                    rules_fingerprint=latest_decision["rules_fingerprint"],
                    business_outcome=business_outcome,
                    review_reason=review_reason,
                    decision=decision,
                    payload_json=_json(decision_payload),
                    fingerprint=decision_fingerprint,
                    created_at=now,
                )
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == work_item_id)
                .values(
                    record_version=next_version,
                    status=status,
                    current_stage="audit.recheck",
                    business_outcome=business_outcome,
                    decision=decision,
                    review_reason=review_reason,
                    waiting_reason_kind=(
                        "user" if status == "waiting_user" else None
                    ),
                    waiting_reason=(
                        review_reason if status == "waiting_user" else None
                    ),
                    ticket_loading_net=item["ticket_loading_net"],
                    ticket_unloading_net=item["ticket_unloading_net"],
                )
            )
            connection.execute(
                AUDIT_TIMELINE_EVENTS.insert().values(
                    timeline_event_id=uuid4().hex,
                    work_item_id=work_item_id,
                    event_type=action_type,
                    reference_id=action_id,
                    payload_json=_json(
                        {
                            "correct_value": correct_value,
                            "note": note,
                            "reason_code": reason_code,
                            "revokes_action_id": revokes_action_id,
                        }
                    ),
                    created_at=now,
                )
            )
            return (
                self._project_item_by_id(
                    connection,
                    work_item_id,
                    include_timeline=True,
                ),
                False,
            )

    @staticmethod
    def _observation_fingerprint(
        connection: Any,
        *,
        evidence_revision_id: str,
        image_role: str,
    ) -> str | None:
        value = connection.execute(
            select(AUDIT_OCR_OBSERVATIONS.c.observation_sha256)
            .where(
                AUDIT_OCR_OBSERVATIONS.c.evidence_revision_id
                == evidence_revision_id,
                AUDIT_OCR_OBSERVATIONS.c.image_role == image_role,
            )
            .order_by(AUDIT_OCR_OBSERVATIONS.c.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return None if value is None else str(value)

    @staticmethod
    def _result_after_actions(
        *,
        base: Any,
        active_actions: tuple[Any, ...],
    ) -> tuple[str, str, str | None, str]:
        if not active_actions:
            outcome = str(base["business_outcome"])
            decision = str(base["decision"])
            reason = (
                None
                if base["review_reason"] is None
                else str(base["review_reason"])
            )
            return (
                outcome,
                decision,
                reason,
                "waiting_user" if decision == "review" else "succeeded",
            )
        latest = active_actions[-1]
        action_type = str(latest["action_type"])
        if action_type == "problem_confirmation":
            return "confirmed_problem", "problem", None, "succeeded"
        if action_type == "problem_dismissal":
            return "normal_ready", "pass", None, "succeeded"
        raise AuditActionConflictError("unsupported active action")

    @staticmethod
    def _active_actions(
        connection: Any,
        work_item_id: str,
    ) -> tuple[Any, ...]:
        rows = tuple(
            connection.execute(
                select(AUDIT_REVIEW_ACTIONS)
                .where(
                    AUDIT_REVIEW_ACTIONS.c.work_item_id == work_item_id
                )
                .order_by(AUDIT_REVIEW_ACTIONS.c.created_at)
            ).mappings()
        )
        revoked = {
            str(row["revokes_action_id"])
            for row in rows
            if row["action_type"] == "revocation"
        }
        return tuple(
            row
            for row in rows
            if row["action_type"] != "revocation"
            and str(row["action_id"]) not in revoked
        )

    def _project_item_by_id(
        self,
        connection: Any,
        work_item_id: str,
        *,
        include_timeline: bool,
    ) -> dict[str, object]:
        row = connection.execute(
            select(WORK_ITEMS).where(
                WORK_ITEMS.c.work_item_id == work_item_id
            )
        ).mappings().one()
        return self._project_item(
            connection,
            row,
            include_timeline=include_timeline,
        )

    def _project_item(
        self,
        connection: Any,
        item: Any,
        *,
        include_timeline: bool = False,
    ) -> dict[str, object]:
        evidence = (
            connection.execute(
                select(AUDIT_EVIDENCE_REVISIONS)
                .where(
                    AUDIT_EVIDENCE_REVISIONS.c.work_item_id
                    == item["work_item_id"]
                )
                .order_by(
                    AUDIT_EVIDENCE_REVISIONS.c.revision_number.desc()
                )
                .limit(1)
            )
            .mappings()
            .one_or_none()
        )
        observations = (
            ()
            if evidence is None
            else tuple(
                connection.execute(
                    select(AUDIT_OCR_OBSERVATIONS)
                    .where(
                        AUDIT_OCR_OBSERVATIONS.c.evidence_revision_id
                        == evidence["evidence_revision_id"]
                    )
                    .order_by(
                        AUDIT_OCR_OBSERVATIONS.c.image_role,
                        AUDIT_OCR_OBSERVATIONS.c.created_at,
                        AUDIT_OCR_OBSERVATIONS.c.ocr_observation_id,
                    )
                ).mappings()
            )
        )
        decision = (
            connection.execute(
                select(AUDIT_DECISION_REVISIONS)
                .where(
                    AUDIT_DECISION_REVISIONS.c.work_item_id
                    == item["work_item_id"]
                )
                .order_by(
                    AUDIT_DECISION_REVISIONS.c.revision_number.desc()
                )
                .limit(1)
            )
            .mappings()
            .one_or_none()
        )
        result: dict[str, object] = {
            "business_outcome": item["business_outcome"],
            "decision": item["decision"],
            "diagnostic_code": item["diagnostic_code"],
            "evidence": None if evidence is None else _row_dict(evidence),
            "platform_loading_net": item["platform_loading_net"],
            "platform_unloading_net": item["platform_unloading_net"],
            "record_version": item["record_version"],
            "review_reason": item["review_reason"],
            "status": item["status"],
            "ticket_loading_net": item["ticket_loading_net"],
            "ticket_unloading_net": item["ticket_unloading_net"],
            "vehicle_number": item["vehicle_number"],
            "waybill_id": item["waybill_number"],
            "work_item_id": item["work_item_id"],
            "job_id": item["job_id"],
            "run_mode": connection.execute(
                select(JOBS.c.run_mode).where(
                    JOBS.c.job_id == item["job_id"]
                )
            ).scalar_one_or_none()
            or "shadow",
            "available_actions": self._available_actions(
                connection,
                item,
            ),
            "latest_decision": (
                None if decision is None else _row_dict(decision)
            ),
            "field_issues": _field_issues(
                item,
                observations=observations,
            ),
            "review_highlight_roles": _review_highlight_roles(
                item,
                observations=observations,
            ),
            "field_issue_diagnostic_code": _field_issue_diagnostic_code(item),
        }
        if include_timeline:
            result["timeline"] = [
                _row_dict(row)
                for row in connection.execute(
                    select(AUDIT_TIMELINE_EVENTS)
                    .where(
                        AUDIT_TIMELINE_EVENTS.c.work_item_id
                        == item["work_item_id"]
                    )
                    .order_by(AUDIT_TIMELINE_EVENTS.c.created_at)
                ).mappings()
            ]
            result["review_actions"] = [
                _row_dict(row)
                for row in connection.execute(
                    select(AUDIT_REVIEW_ACTIONS)
                    .where(
                        AUDIT_REVIEW_ACTIONS.c.work_item_id
                        == item["work_item_id"]
                    )
                    .order_by(AUDIT_REVIEW_ACTIONS.c.created_at)
                ).mappings()
            ]
        return result

    @staticmethod
    def _available_actions(
        connection: Any,
        item: Any,
    ) -> dict[str, dict[str, object]]:
        has_decision = (
            connection.execute(
                select(AUDIT_DECISION_REVISIONS.c.decision_revision_id)
                .where(
                    AUDIT_DECISION_REVISIONS.c.work_item_id
                    == item["work_item_id"]
                )
                .limit(1)
            ).scalar_one_or_none()
            is not None
        )
        valid_business_item = (
            has_decision
            and item["diagnostic_code"] is None
            and item["business_outcome"]
            in {"awaiting_review", "confirmed_problem", "normal_ready"}
        )
        active = SqliteAuditWorkflowRepository._active_actions(
            connection,
            str(item["work_item_id"]),
        )
        can_revoke = bool(active)
        return {
            "confirm_normal": {
                "visible": valid_business_item,
                "enabled": valid_business_item,
                "reason": (
                    None
                    if valid_business_item
                    else "当前记录不是可操作的业务运单"
                ),
            },
            "confirm_problem": {
                "visible": valid_business_item,
                "enabled": valid_business_item,
                "reason": (
                    None
                    if valid_business_item
                    else "当前记录不是可操作的业务运单"
                ),
            },
            "revoke": {
                "visible": can_revoke,
                "enabled": can_revoke,
                "reason": None if can_revoke else "当前没有可撤销的人工决定",
            },
        }
