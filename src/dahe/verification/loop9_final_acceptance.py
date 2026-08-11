from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import cast
from uuid import uuid4

from dahe.adapters.chengfeng.daily_contract_selection import (
    SelectedDailyReadContract,
    load_selected_daily_read_contract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    SelectedLiveReadContract,
    load_selected_live_read_contract,
)
from dahe.adapters.chengfeng.live_contract_validation import _load_result
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
)
from dahe.application.chengfeng.identity_authority import (
    load_or_create_loop9_identity_authority,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.application.template_studio.formal_development_authority import (
    load_formal_development_authority,
)
from dahe.verification.daily_snapshot_validation import (
    replay_current_daily_snapshot_validation_from_store,
)
from dahe.verification.ledger import (
    _LOOP9_SHADOW_FINAL_GATE_ID,
    _LOOP9_SHADOW_UPDATABLE_GATE_IDS,
    LedgerStore,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_dataset_artifacts import (
    CURRENT_DAILY_DATASET_ID,
    replay_current_daily_dataset_manifest_from_store,
)
from dahe.verification.loop9_dataset_isolation import (
    DatasetKind,
    Loop9DatasetManifest,
    exclusion_source_boundary_from_formal_development_authority,
    load_loop9_dataset_isolation_evidence,
    load_loop9_dataset_manifest,
    validate_loop9_dataset_isolation,
)
from dahe.verification.loop9_exclusion_authority import (
    load_stored_loop9_full_history_exclusion_authority,
)
from dahe.verification.loop9_human_review import (
    _load_and_validate_seal,
    load_loop9_review_package,
    replay_loop9_review,
)
from dahe.verification.loop9_machine_results import (
    evaluate_sealed_machine_results,
    load_machine_truth_evaluation,
)
from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
    Loop9FormalRunEvidence,
    Loop9FormalRunEvidenceStore,
    Loop9FormalRunRequest,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_AUDIT_SCOPES = {
    "current_locked_50",
    "daily_validation",
    "real_shadow_30",
}
_FAULT_SCENARIOS = {
    "browser_closed",
    "gpu_worker_failure",
    "main_application_restart",
    "transient_network_failure",
}
_PERFORMANCE_SCOPES = {
    "cpu_ocr",
    "end_to_end",
    "gpu_ocr",
    "role_validation",
}
_PERFORMANCE_SAMPLE_COUNTS = {
    "cpu_ocr": 160,
    "end_to_end": 80,
    "gpu_ocr": 160,
    "role_validation": 160,
}
_UPDATABLE_GATE_IDS = _LOOP9_SHADOW_UPDATABLE_GATE_IDS
_FINAL_GATE_ID = _LOOP9_SHADOW_FINAL_GATE_ID
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_OPERATIONAL_FIELDS = {
    "canonical_sha256",
    "current_locked_gate_sha256",
    "current_locked_selection_sha256",
    "daily_snapshot_validation_sha256",
    "dataset_isolation_sha256",
    "fault_injections",
    "kind",
    "no_silent_omission",
    "performance",
    "real_shadow_machine_evaluation_sha256",
    "real_shadow_reconciliation",
    "real_shadow_selection_sha256",
    "schema_version",
    "request_audit_summaries",
    "settlement_contract_sha256",
    "settlement_selection_sha256",
    "source_build_sha256",
}
_REQUEST_AUDIT_FIELDS = {
    "allowed_request_count",
    "attempted_request_count",
    "canonical_sha256",
    "contract_canonical_sha256",
    "contract_selection_sha256",
    "denied_request_count",
    "evidence_image_count",
    "kind",
    "operation_counts",
    "platform_write_request_count",
    "redirect_count",
    "schema_version",
    "scope",
    "source_authority_sha256",
    "source_build_sha256",
    "source_item_count",
    "succeeded_request_count",
    "terminal_result_count",
}
_REQUEST_AUDIT_SUMMARY_FIELDS = {
    "allowed_request_count",
    "attempted_request_count",
    "canonical_sha256",
    "denied_request_count",
    "operation_counts",
    "platform_write_request_count",
    "redirect_count",
    "succeeded_request_count",
}


class Loop9FinalAcceptanceError(RuntimeError):
    """Raised when the complete Loop 9 authority cannot be replayed."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Loop9FinalAcceptanceError(
            "acceptance evidence is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9FinalAcceptanceError(f"{label} SHA-256 is invalid")
    return value


def _plain_text(
    value: object,
    *,
    label: str,
    maximum: int = 160,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise Loop9FinalAcceptanceError(f"{label} is invalid")
    return value


def _exact_mapping(
    value: object,
    *,
    fields: set[str],
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise Loop9FinalAcceptanceError(f"{label} shape is invalid")
    return cast(Mapping[str, object], value)


def _nonnegative_int(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise Loop9FinalAcceptanceError(f"{label} is invalid")
    return value


def _positive_int(value: object, *, label: str) -> int:
    result = _nonnegative_int(value, label=label)
    if result < 1:
        raise Loop9FinalAcceptanceError(f"{label} is invalid")
    return result


def _nonnegative_number(value: object, *, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise Loop9FinalAcceptanceError(f"{label} is invalid")
    return float(value)


def verify_formal_request_audit_evidence(
    value: object,
) -> dict[str, object]:
    """Validate one content-addressed, per-job read-request audit."""

    raw = _exact_mapping(
        value,
        fields=_REQUEST_AUDIT_FIELDS,
        label="formal request audit",
    )
    core = {
        key: nested
        for key, nested in raw.items()
        if key != "canonical_sha256"
    }
    declared = _sha256(
        raw.get("canonical_sha256"),
        label="formal request audit",
    )
    scope = _plain_text(
        raw.get("scope"),
        label="formal request audit scope",
    )
    if (
        raw.get("schema_version") != 1
        or raw.get("kind") != "loop9_formal_request_audit"
        or declared != _canonical_sha256(core)
        or scope not in _REQUEST_AUDIT_SCOPES
    ):
        raise Loop9FinalAcceptanceError(
            "formal request audit integrity is invalid"
        )
    for field, label in (
        ("source_build_sha256", "request audit source build"),
        (
            "contract_canonical_sha256",
            "request audit contract",
        ),
        (
            "contract_selection_sha256",
            "request audit contract selection",
        ),
        ("source_authority_sha256", "request audit source authority"),
    ):
        _sha256(raw.get(field), label=label)
    operation_counts = raw.get("operation_counts")
    if (
        not isinstance(operation_counts, Mapping)
        or not operation_counts
        or any(
            not isinstance(name, str)
            or not name
            or type(count) is not int
            or count < 0
            for name, count in operation_counts.items()
        )
    ):
        raise Loop9FinalAcceptanceError(
            "formal request audit operation counts are invalid"
        )
    attempted = _positive_int(
        raw.get("attempted_request_count"),
        label="attempted request count",
    )
    allowed = _positive_int(
        raw.get("allowed_request_count"),
        label="allowed request count",
    )
    succeeded = _positive_int(
        raw.get("succeeded_request_count"),
        label="succeeded request count",
    )
    if (
        attempted != allowed
        or allowed != succeeded
        or sum(cast(Mapping[str, int], operation_counts).values())
        != attempted
        or any(
            raw.get(field) != 0
            for field in (
                "denied_request_count",
                "platform_write_request_count",
                "redirect_count",
            )
        )
    ):
        raise Loop9FinalAcceptanceError(
            "formal request audit safety counts are invalid"
        )
    item_count = _positive_int(
        raw.get("source_item_count"),
        label="request audit source item count",
    )
    image_count = _positive_int(
        raw.get("evidence_image_count"),
        label="request audit evidence image count",
    )
    terminal_count = _positive_int(
        raw.get("terminal_result_count"),
        label="request audit terminal result count",
    )
    if scope == "current_locked_50" and (
        item_count != 50
        or image_count != 100
        or terminal_count != 50
    ):
        raise Loop9FinalAcceptanceError(
            "current locked request audit counts are invalid"
        )
    if scope == "real_shadow_30" and (
        item_count != 30
        or image_count != 60
        or terminal_count != 30
    ):
        raise Loop9FinalAcceptanceError(
            "real shadow request audit counts are invalid"
        )
    if scope == "daily_validation" and terminal_count != 3:
        raise Loop9FinalAcceptanceError(
            "daily request audit terminal count is invalid"
        )
    return dict(raw)


def verify_operational_acceptance_evidence(
    value: object,
) -> dict[str, object]:
    """Validate mandatory formal-run counts, recovery and performance."""

    raw = _exact_mapping(
        value,
        fields=_OPERATIONAL_FIELDS,
        label="operational acceptance evidence",
    )
    core = {
        key: nested
        for key, nested in raw.items()
        if key != "canonical_sha256"
    }
    declared = _sha256(
        raw.get("canonical_sha256"),
        label="operational evidence",
    )
    if (
        raw.get("schema_version") != 1
        or raw.get("kind")
        != "loop9_operational_acceptance_evidence"
        or declared != _canonical_sha256(core)
    ):
        raise Loop9FinalAcceptanceError(
            "operational acceptance evidence integrity is invalid"
        )
    for field, label in (
        ("source_build_sha256", "source build"),
        ("settlement_contract_sha256", "settlement contract"),
        ("settlement_selection_sha256", "settlement selection"),
        ("current_locked_selection_sha256", "current locked selection"),
        ("current_locked_gate_sha256", "current locked gate"),
        ("real_shadow_selection_sha256", "real shadow selection"),
        (
            "real_shadow_machine_evaluation_sha256",
            "real shadow machine evaluation",
        ),
        (
            "daily_snapshot_validation_sha256",
            "daily snapshot validation",
        ),
        ("dataset_isolation_sha256", "dataset isolation"),
    ):
        _sha256(raw.get(field), label=label)

    summaries = _exact_mapping(
        raw.get("request_audit_summaries"),
        fields=set(_REQUEST_AUDIT_SCOPES),
        label="request audit summaries",
    )
    for scope in _REQUEST_AUDIT_SCOPES:
        summary = _exact_mapping(
            summaries.get(scope),
            fields=_REQUEST_AUDIT_SUMMARY_FIELDS,
            label=f"{scope} request audit summary",
        )
        _sha256(
            summary.get("canonical_sha256"),
            label=f"{scope} request audit",
        )
        operation_counts = summary.get("operation_counts")
        if (
            not isinstance(operation_counts, Mapping)
            or not operation_counts
            or any(
                not isinstance(name, str)
                or not name
                or type(count) is not int
                or count < 0
                for name, count in operation_counts.items()
            )
        ):
            raise Loop9FinalAcceptanceError(
                f"{scope} request audit summary is invalid"
            )
        attempted = _positive_int(
            summary.get("attempted_request_count"),
            label=f"{scope} attempted request count",
        )
        if (
            summary.get("allowed_request_count") != attempted
            or summary.get("succeeded_request_count") != attempted
            or sum(
                cast(Mapping[str, int], operation_counts).values()
            )
            != attempted
            or any(
                summary.get(field) != 0
                for field in (
                    "denied_request_count",
                    "platform_write_request_count",
                    "redirect_count",
                )
            )
        ):
            raise Loop9FinalAcceptanceError(
                f"{scope} request audit summary is invalid"
            )

    reconciliation = _exact_mapping(
        raw.get("real_shadow_reconciliation"),
        fields={
            "duplicate_submission_count",
            "human_review_count",
            "machine_item_count",
            "missing_item_count",
            "source_item_count",
            "technical_failure_in_review_count",
            "terminal_outcome_count",
            "unique_item_count",
        },
        label="real shadow reconciliation",
    )
    if (
        any(
            reconciliation.get(field) != 30
            for field in (
                "source_item_count",
                "unique_item_count",
                "machine_item_count",
                "human_review_count",
                "terminal_outcome_count",
            )
        )
        or any(
            reconciliation.get(field) != 0
            for field in (
                "missing_item_count",
                "duplicate_submission_count",
                "technical_failure_in_review_count",
            )
        )
    ):
        raise Loop9FinalAcceptanceError(
            "real shadow reconciliation is incomplete"
        )

    faults = raw.get("fault_injections")
    if not isinstance(faults, Sequence) or isinstance(faults, (str, bytes)):
        raise Loop9FinalAcceptanceError(
            "fault injection evidence is invalid"
        )
    fault_fields = {
        "committed_result_loss_count",
        "duplicate_submission_count",
        "evidence_sha256",
        "passed",
        "scenario",
        "technical_failure_in_review_count",
    }
    observed_faults: set[str] = set()
    for entry in faults:
        fault = _exact_mapping(
            entry,
            fields=fault_fields,
            label="fault injection evidence",
        )
        scenario = _plain_text(
            fault.get("scenario"),
            label="fault injection scenario",
        )
        if (
            scenario not in _FAULT_SCENARIOS
            or scenario in observed_faults
            or fault.get("passed") is not True
            or any(
                fault.get(field) != 0
                for field in (
                    "committed_result_loss_count",
                    "duplicate_submission_count",
                    "technical_failure_in_review_count",
                )
            )
        ):
            raise Loop9FinalAcceptanceError(
                "fault injection gate did not pass"
            )
        _sha256(
            fault.get("evidence_sha256"),
            label=f"{scenario} evidence",
        )
        observed_faults.add(scenario)
    if observed_faults != _FAULT_SCENARIOS:
        raise Loop9FinalAcceptanceError(
            "fault injection evidence is incomplete"
        )

    performance = _exact_mapping(
        raw.get("performance"),
        fields=set(_PERFORMANCE_SCOPES),
        label="performance evidence",
    )
    for scope in _PERFORMANCE_SCOPES:
        metrics = _exact_mapping(
            performance.get(scope),
            fields={"p50_ms", "p95_ms", "sample_count"},
            label=f"{scope} performance",
        )
        sample_count = _positive_int(
            metrics.get("sample_count"),
            label=f"{scope} performance sample count",
        )
        p50 = _nonnegative_number(
            metrics.get("p50_ms"),
            label=f"{scope} P50",
        )
        p95 = _nonnegative_number(
            metrics.get("p95_ms"),
            label=f"{scope} P95",
        )
        if (
            sample_count != _PERFORMANCE_SAMPLE_COUNTS[scope]
            or p95 < p50
        ):
            raise Loop9FinalAcceptanceError(
                f"{scope} performance percentiles are invalid"
            )
    if raw.get("no_silent_omission") is not True:
        raise Loop9FinalAcceptanceError(
            "silent omission gate did not pass"
        )
    return dict(raw)


def _safe_reference(value: object, *, label: str) -> str:
    raw = _plain_text(value, label=label, maximum=400)
    path = PurePosixPath(raw)
    if (
        "\\" in raw
        or ":" in raw
        or path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
    ):
        raise Loop9FinalAcceptanceError(f"{label} is unsafe")
    return raw


@dataclass(frozen=True, slots=True)
class Loop9FinalAcceptanceReplay:
    source_build_sha256: str
    settlement_contract_sha256: str
    settlement_selection_sha256: str
    daily_contract_sha256: str
    daily_selection_sha256: str
    read_contract_validation_sha256: str
    current_locked_selection_sha256: str
    current_locked_gate_sha256: str
    current_locked_machine_evaluation_sha256: str
    real_shadow_selection_sha256: str
    real_shadow_human_review_seal_sha256: str
    real_shadow_machine_evaluation_sha256: str
    daily_snapshot_validation_sha256: str
    dataset_isolation_sha256: str
    formal_run_evidence_sha256: str
    operational_evidence: Mapping[str, object]
    request_audits: Mapping[str, Mapping[str, object]]
    data_references: Mapping[str, str]

    def verify(self) -> None:
        for value, label in (
            (self.source_build_sha256, "source build"),
            (self.settlement_contract_sha256, "settlement contract"),
            (self.settlement_selection_sha256, "settlement selection"),
            (self.daily_contract_sha256, "daily contract"),
            (self.daily_selection_sha256, "daily selection"),
            (
                self.read_contract_validation_sha256,
                "read contract validation",
            ),
            (
                self.current_locked_selection_sha256,
                "current locked selection",
            ),
            (self.current_locked_gate_sha256, "current locked gate"),
            (
                self.current_locked_machine_evaluation_sha256,
                "current locked machine evaluation",
            ),
            (
                self.real_shadow_selection_sha256,
                "real shadow selection",
            ),
            (
                self.real_shadow_human_review_seal_sha256,
                "real shadow human review seal",
            ),
            (
                self.real_shadow_machine_evaluation_sha256,
                "real shadow machine evaluation",
            ),
            (
                self.daily_snapshot_validation_sha256,
                "daily snapshot validation",
            ),
            (self.dataset_isolation_sha256, "dataset isolation"),
            (
                self.formal_run_evidence_sha256,
                "formal run evidence",
            ),
        ):
            _sha256(value, label=label)
        expected_references = {
            "current_locked_gate",
            "daily_snapshot_validation",
            "dataset_isolation",
            "formal_run_evidence",
            "read_contract_validation",
            "real_shadow_machine_evaluation",
            "real_shadow_package",
            "real_shadow_seal",
        }
        if set(self.data_references) != expected_references:
            raise Loop9FinalAcceptanceError(
                "acceptance data references are incomplete"
            )
        for label, reference in self.data_references.items():
            _safe_reference(reference, label=label)
        operational = verify_operational_acceptance_evidence(
            self.operational_evidence
        )
        if set(self.request_audits) != _REQUEST_AUDIT_SCOPES:
            raise Loop9FinalAcceptanceError(
                "formal request audit set is incomplete"
            )
        request_audits = {
            scope: verify_formal_request_audit_evidence(
                self.request_audits[scope]
            )
            for scope in _REQUEST_AUDIT_SCOPES
        }
        expected_request_bindings = {
            "current_locked_50": (
                self.settlement_contract_sha256,
                self.settlement_selection_sha256,
                self.current_locked_selection_sha256,
            ),
            "real_shadow_30": (
                self.settlement_contract_sha256,
                self.settlement_selection_sha256,
                self.real_shadow_selection_sha256,
            ),
            "daily_validation": (
                self.daily_contract_sha256,
                self.daily_selection_sha256,
                self.daily_snapshot_validation_sha256,
            ),
        }
        for scope, (
            contract_sha256,
            selection_sha256,
            source_authority_sha256,
        ) in expected_request_bindings.items():
            audit = request_audits[scope]
            if (
                audit.get("source_build_sha256")
                != self.source_build_sha256
                or audit.get("contract_canonical_sha256")
                != contract_sha256
                or audit.get("contract_selection_sha256")
                != selection_sha256
                or audit.get("source_authority_sha256")
                != source_authority_sha256
            ):
                raise Loop9FinalAcceptanceError(
                    f"{scope} request audit authority binding changed"
                )
            expected_summary = {
                key: audit[key]
                for key in _REQUEST_AUDIT_SUMMARY_FIELDS
            }
            summaries = cast(
                Mapping[str, Mapping[str, object]],
                operational["request_audit_summaries"],
            )
            if summaries[scope] != expected_summary:
                raise Loop9FinalAcceptanceError(
                    f"{scope} request audit summary does not reconcile"
                )
        expected_bindings = {
            "source_build_sha256": self.source_build_sha256,
            "settlement_contract_sha256": (
                self.settlement_contract_sha256
            ),
            "settlement_selection_sha256": (
                self.settlement_selection_sha256
            ),
            "current_locked_selection_sha256": (
                self.current_locked_selection_sha256
            ),
            "current_locked_gate_sha256": (
                self.current_locked_gate_sha256
            ),
            "real_shadow_selection_sha256": (
                self.real_shadow_selection_sha256
            ),
            "real_shadow_machine_evaluation_sha256": (
                self.real_shadow_machine_evaluation_sha256
            ),
            "daily_snapshot_validation_sha256": (
                self.daily_snapshot_validation_sha256
            ),
            "dataset_isolation_sha256": (
                self.dataset_isolation_sha256
            ),
        }
        if any(
            operational.get(field) != expected
            for field, expected in expected_bindings.items()
        ):
            raise Loop9FinalAcceptanceError(
                "operational acceptance authority binding changed"
            )

    def evidence_payload(self, *, accepted_at: str) -> dict[str, object]:
        self.verify()
        operational = dict(self.operational_evidence)
        body: dict[str, object] = {
            "schema_version": 1,
            "kind": "loop9_shadow_acceptance",
            "accepted_at": accepted_at,
            "gate_passed": True,
            "source_build_sha256": self.source_build_sha256,
            "settlement_contract_sha256": (
                self.settlement_contract_sha256
            ),
            "settlement_selection_sha256": (
                self.settlement_selection_sha256
            ),
            "daily_contract_sha256": self.daily_contract_sha256,
            "daily_selection_sha256": self.daily_selection_sha256,
            "read_contract_validation_sha256": (
                self.read_contract_validation_sha256
            ),
            "current_locked_selection_sha256": (
                self.current_locked_selection_sha256
            ),
            "current_locked_gate_sha256": (
                self.current_locked_gate_sha256
            ),
            "current_locked_machine_evaluation_sha256": (
                self.current_locked_machine_evaluation_sha256
            ),
            "real_shadow_selection_sha256": (
                self.real_shadow_selection_sha256
            ),
            "real_shadow_human_review_seal_sha256": (
                self.real_shadow_human_review_seal_sha256
            ),
            "real_shadow_machine_evaluation_sha256": (
                self.real_shadow_machine_evaluation_sha256
            ),
            "daily_snapshot_validation_sha256": (
                self.daily_snapshot_validation_sha256
            ),
            "dataset_isolation_sha256": (
                self.dataset_isolation_sha256
            ),
            "formal_run_evidence_sha256": (
                self.formal_run_evidence_sha256
            ),
            "request_audit_summaries": operational[
                "request_audit_summaries"
            ],
            "real_shadow_reconciliation": operational[
                "real_shadow_reconciliation"
            ],
            "fault_injections": operational["fault_injections"],
            "performance": operational["performance"],
            "no_silent_omission": True,
            "forbidden_request_count": 0,
            "platform_write_request_count": 0,
            "redirect_count": 0,
            "data_references": dict(self.data_references),
        }
        return {**body, "canonical_sha256": _canonical_sha256(body)}


@dataclass(frozen=True, slots=True)
class Loop9FinalAcceptanceInputs:
    project_root: Path
    data_root: Path
    read_contract_validation_path: Path
    current_locked_selection_sha256: str
    real_shadow_selection_sha256: str
    real_shadow_package_dir: Path
    real_shadow_seal_path: Path
    real_shadow_machine_evaluation_path: Path
    daily_snapshot_validation_path: Path
    discovery_development_path: Path
    current_locked_50_path: Path
    real_shadow_30_path: Path
    daily_validation_dataset_path: Path
    source_development_authority_path: Path
    dataset_isolation_path: Path
    formal_run_evidence_sha256: str
    locked_job_id: str
    real_shadow_job_id: str
    fault_scenarios: Mapping[str, FaultScenarioIdentity]


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(
        attributes
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _real_directory(path: Path, *, label: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.is_symlink()
        or _is_reparse_point(path)
    ):
        raise Loop9FinalAcceptanceError(f"{label} is unsafe")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9FinalAcceptanceError(f"{label} is unavailable") from exc
    if resolved != path or not resolved.is_dir():
        raise Loop9FinalAcceptanceError(f"{label} is unsafe")
    return resolved


def _existing_under(
    *,
    root: Path,
    path: Path,
    label: str,
    directory: bool,
) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise Loop9FinalAcceptanceError(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9FinalAcceptanceError(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or _is_reparse_point(path)
        or resolved != path
        or root not in resolved.parents
        or (directory and not resolved.is_dir())
        or (not directory and not resolved.is_file())
    ):
        raise Loop9FinalAcceptanceError(f"{label} path is unsafe")
    current = resolved
    while current != root:
        if current.is_symlink() or _is_reparse_point(current):
            raise Loop9FinalAcceptanceError(f"{label} path is unsafe")
        current = current.parent
    return resolved


def _relative(root: Path, path: Path, *, label: str) -> str:
    try:
        reference = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise Loop9FinalAcceptanceError(
            f"{label} is outside its authority root"
        ) from exc
    return _safe_reference(reference, label=label)


def _load_json_file(path: Path, *, label: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except Loop9FinalAcceptanceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Loop9FinalAcceptanceError(f"{label} is unreadable") from exc
    if not isinstance(payload, dict):
        raise Loop9FinalAcceptanceError(f"{label} must be an object")
    return cast(dict[str, object], payload)


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9FinalAcceptanceError(
                "acceptance evidence contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise Loop9FinalAcceptanceError(
        f"acceptance evidence contains non-finite JSON: {value}"
    )


def _validate_read_contract_gate(
    *,
    data_root: Path,
    validation_path: Path,
    source_build_sha256: str,
    identity_context_sha256: str,
    settlement: SelectedLiveReadContract,
    daily: SelectedDailyReadContract,
) -> str:
    try:
        result, document = _load_result(validation_path)
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "current build read contract Gate replay failed"
        ) from exc
    settlement_manifest = settlement.manifest
    daily_manifest = daily.manifest
    if (
        document.get("schema_version") != 4
        or document.get("build_sha256") != source_build_sha256
        or document.get("contract_canonical_sha256")
        != settlement_manifest.canonical_sha256
        or document.get("contract_file_sha256")
        != settlement.contract_file_sha256
        or document.get("freeze_evidence_sha256")
        != settlement.freeze_evidence_sha256
        or document.get("selection_sha256")
        != settlement.selection_sha256
        or document.get("source_discovery_sha256")
        != settlement_manifest.source_discovery_sha256
        or result.identity_context_sha256 != identity_context_sha256
        or result.development_exclusion_sha256 is None
        or result.development_exclusion_inventory_sha256 is None
        or any(
            document.get(field) != 0
            for field in (
                "forbidden_request_count",
                "platform_write_request_count",
                "redirect_count",
            )
        )
    ):
        raise Loop9FinalAcceptanceError(
            "current build read contract Gate authority changed"
        )
    if (
        document.get("validation_mode")
        != "settlement_empty_daily_nonempty"
    ):
        raise Loop9FinalAcceptanceError(
            "current build read contract Gate is not the approved composite mode"
        )
    if (
        document.get("daily_contract_canonical_sha256")
        != daily_manifest.canonical_sha256
        or document.get("daily_contract_file_sha256")
        != daily.contract_file_sha256
        or document.get("daily_contract_freeze_evidence_sha256")
        != daily.freeze_evidence_sha256
        or document.get("daily_contract_selection_sha256")
        != daily.selection_sha256
        or document.get("daily_contract_source_discovery_sha256")
        != daily_manifest.source_discovery_sha256
    ):
        raise Loop9FinalAcceptanceError(
            "current build daily read authority changed"
        )
    expected_root = data_root / "platform-read-contract-validation"
    if validation_path.parent != expected_root:
        raise Loop9FinalAcceptanceError(
            "read contract validation path is outside its authority root"
        )
    return result.canonical_sha256


def _validate_daily_gate(
    *,
    payload: object,
    data_root: Path,
    project_root: Path,
    source_build_sha256: str,
    daily: SelectedDailyReadContract,
) -> dict[str, object]:
    try:
        validated = replay_current_daily_snapshot_validation_from_store(
            payload,
            data_root=data_root,
            project_root=project_root,
            source_build_sha256=source_build_sha256,
        )
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "daily three-snapshot Gate replay failed"
        ) from exc
    if (
        validated.get("schema_version") != 5
        or validated.get("build_sha256") != source_build_sha256
        or validated.get("contract_sha256")
        != daily.manifest.canonical_sha256
        or cast(
            Mapping[str, object],
            validated.get("contract_selection"),
        ).get("selection_sha256")
        != daily.selection_sha256
        or validated.get("snapshot_count") != 3
        or not isinstance(validated.get("candidate_count"), int)
        or cast(int, validated["candidate_count"]) < 1
        or any(
            validated.get(field) != 0
            for field in (
                "forbidden_request_count",
                "platform_write_request_count",
                "redirect_count",
            )
        )
    ):
        raise Loop9FinalAcceptanceError(
            "daily three-snapshot Gate authority changed"
        )
    return validated


def _validate_daily_dataset_gate_binding(
    *,
    daily_manifest: Loop9DatasetManifest,
    daily_gate: Mapping[str, object],
) -> None:
    """Bind the isolated daily inventory to this exact three-snapshot Gate."""

    if (
        not isinstance(daily_manifest, Loop9DatasetManifest)
        or daily_manifest.dataset_kind is not DatasetKind.DAILY_VALIDATION
        or daily_manifest.source_snapshot_sha256
        != _sha256(
            daily_gate.get("canonical_sha256"),
            label="current daily Gate",
        )
    ):
        raise Loop9FinalAcceptanceError(
            "daily validation dataset is not bound to the current daily Gate"
        )
    snapshots = daily_gate.get("snapshot_evidence")
    if (
        daily_gate.get("snapshot_count") != 3
        or not isinstance(snapshots, list)
        or len(snapshots) != 3
    ):
        raise Loop9FinalAcceptanceError(
            "daily validation dataset does not bind three snapshot authorities"
        )
    authority_fields = (
        "snapshot_id",
        "job_id",
        "access_window_id",
        "snapshot_fingerprint",
    )
    identities: dict[str, list[str]] = {
        field: [] for field in authority_fields
    }
    for snapshot in snapshots:
        if not isinstance(snapshot, Mapping):
            raise Loop9FinalAcceptanceError(
                "daily validation dataset does not bind three snapshot authorities"
            )
        for field in authority_fields:
            value = snapshot.get(field)
            if (
                not isinstance(value, str)
                or not value
                or (
                    field == "snapshot_fingerprint"
                    and _SHA256.fullmatch(value) is None
                )
            ):
                raise Loop9FinalAcceptanceError(
                    "daily validation dataset does not bind three snapshot authorities"
                )
            identities[field].append(value)
    if any(
        len(set(values)) != 3 for values in identities.values()
    ):
        raise Loop9FinalAcceptanceError(
            "daily validation dataset does not bind three snapshot authorities"
        )


def _replay_dataset_isolation(
    *,
    inputs: Loop9FinalAcceptanceInputs,
    data_root: Path,
    source_build_sha256: str,
    settlement: SelectedLiveReadContract,
    daily: SelectedDailyReadContract,
    daily_gate: Mapping[str, object],
) -> str:
    try:
        source_authority = load_formal_development_authority(
            inputs.source_development_authority_path
        )
        source_boundary = (
            exclusion_source_boundary_from_formal_development_authority(
                source_authority
            )
        )
        persisted = load_loop9_dataset_isolation_evidence(
            inputs.dataset_isolation_path
        )
        full_history = (
            load_stored_loop9_full_history_exclusion_authority(
                data_root=data_root,
                authority_sha256=(
                    persisted.full_history_exclusion_authority_sha256
                ),
            )
        )
        persisted_daily_manifest = load_loop9_dataset_manifest(
            inputs.daily_validation_dataset_path
        )
        daily_manifest = (
            replay_current_daily_dataset_manifest_from_store(
                persisted_daily_manifest,
                daily_validation=daily_gate,
                data_root=data_root,
                project_root=inputs.project_root,
                source_build_sha256=source_build_sha256,
                expected_dataset_id=CURRENT_DAILY_DATASET_ID,
            ).manifest
        )
        _validate_daily_dataset_gate_binding(
            daily_manifest=daily_manifest,
            daily_gate=daily_gate,
        )
        replayed = validate_loop9_dataset_isolation(
            expected_current_build_sha256=source_build_sha256,
            expected_settlement_contract_sha256=(
                settlement.manifest.canonical_sha256
            ),
            expected_daily_contract_sha256=(
                daily.manifest.canonical_sha256
            ),
            expected_settlement_selection_sha256=(
                settlement.selection_sha256
            ),
            expected_daily_selection_sha256=daily.selection_sha256,
            discovery_development=load_loop9_dataset_manifest(
                inputs.discovery_development_path
            ),
            current_locked_50=load_loop9_dataset_manifest(
                inputs.current_locked_50_path
            ),
            real_shadow_30=load_loop9_dataset_manifest(
                inputs.real_shadow_30_path
            ),
            daily_validation=daily_manifest,
            development_exclusions=full_history.development_exclusions,
            legacy_loop7_exclusions=(
                full_history.legacy_loop7_exclusions
            ),
            expected_exclusion_source_boundary=source_boundary,
            full_history_exclusion_authority=full_history,
        )
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "dataset isolation replay failed"
        ) from exc
    if (
        replayed.canonical_sha256 != persisted.canonical_sha256
        or replayed.to_payload() != persisted.to_payload()
    ):
        raise Loop9FinalAcceptanceError(
            "dataset isolation replay does not reconcile"
        )
    return replayed.canonical_sha256


def _legacy_request_audit_from_formal_run(
    *,
    scope: str,
    source_build_sha256: str,
    contract_sha256: str,
    contract_selection_sha256: str,
    source_authority_sha256: str,
    audit_summaries: Sequence[Mapping[str, object]],
    source_item_count: int,
    evidence_image_count: int,
    terminal_result_count: int,
) -> dict[str, object]:
    operation_counts: dict[str, int] = {}
    attempted = 0
    allowed = 0
    succeeded = 0
    denied = 0
    write_count = 0
    redirect_count = 0
    for summary in audit_summaries:
        request_counts = cast(
            Mapping[str, int],
            summary["request_counts"],
        )
        attempted += request_counts["attempted"]
        allowed += request_counts["allowed"]
        succeeded += request_counts["succeeded"]
        denied += request_counts["denied"]
        write_count += cast(
            int,
            summary["platform_write_request_count"],
        )
        redirect_count += cast(int, summary["redirect_count"])
        operations = cast(
            Mapping[str, Mapping[str, int]],
            summary["operation_counts"],
        )
        for operation, counts in operations.items():
            operation_counts[operation] = (
                operation_counts.get(operation, 0)
                + counts["succeeded"]
            )
    body: dict[str, object] = {
        "allowed_request_count": allowed,
        "attempted_request_count": attempted,
        "contract_canonical_sha256": contract_sha256,
        "contract_selection_sha256": contract_selection_sha256,
        "denied_request_count": denied,
        "evidence_image_count": evidence_image_count,
        "kind": "loop9_formal_request_audit",
        "operation_counts": operation_counts,
        "platform_write_request_count": write_count,
        "redirect_count": redirect_count,
        "schema_version": 1,
        "scope": scope,
        "source_authority_sha256": source_authority_sha256,
        "source_build_sha256": source_build_sha256,
        "source_item_count": source_item_count,
        "succeeded_request_count": succeeded,
        "terminal_result_count": terminal_result_count,
    }
    return {
        **body,
        "canonical_sha256": _canonical_sha256(body),
    }


def _legacy_documents_from_formal_run(
    *,
    evidence: Loop9FormalRunEvidence,
    daily_candidate_count: int,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    audits = evidence.request_audits
    request_audits = {
        "current_locked_50": _legacy_request_audit_from_formal_run(
            scope="current_locked_50",
            source_build_sha256=evidence.source_build_sha256,
            contract_sha256=evidence.settlement_contract_sha256,
            contract_selection_sha256=(
                evidence.settlement_contract_selection_sha256
            ),
            source_authority_sha256=(
                evidence.current_locked_selection_sha256
            ),
            audit_summaries=(audits["current_locked_50"],),
            source_item_count=50,
            evidence_image_count=100,
            terminal_result_count=50,
        ),
        "real_shadow_30": _legacy_request_audit_from_formal_run(
            scope="real_shadow_30",
            source_build_sha256=evidence.source_build_sha256,
            contract_sha256=evidence.settlement_contract_sha256,
            contract_selection_sha256=(
                evidence.settlement_contract_selection_sha256
            ),
            source_authority_sha256=(
                evidence.real_shadow_selection_sha256
            ),
            audit_summaries=(audits["real_shadow_30"],),
            source_item_count=30,
            evidence_image_count=60,
            terminal_result_count=30,
        ),
        "daily_validation": _legacy_request_audit_from_formal_run(
            scope="daily_validation",
            source_build_sha256=evidence.source_build_sha256,
            contract_sha256=evidence.daily_contract_sha256,
            contract_selection_sha256=(
                evidence.daily_contract_selection_sha256
            ),
            source_authority_sha256=(
                evidence.daily_snapshot_validation_sha256
            ),
            audit_summaries=tuple(
                audits[f"daily_snapshot_{index}"]
                for index in range(1, 4)
            ),
            source_item_count=max(1, daily_candidate_count),
            evidence_image_count=max(1, daily_candidate_count * 2),
            terminal_result_count=3,
        ),
    }
    summaries = {
        scope: {
            key: audit[key]
            for key in _REQUEST_AUDIT_SUMMARY_FIELDS
        }
        for scope, audit in request_audits.items()
    }
    faults = [
        {
            "committed_result_loss_count": 0,
            "duplicate_submission_count": 0,
            "evidence_sha256": _canonical_sha256(
                evidence.fault_injections[scenario]
            ),
            "passed": True,
            "scenario": scenario,
            "technical_failure_in_review_count": cast(
                int,
                evidence.fault_injections[scenario][
                    "technical_review_leak_count"
                ],
            ),
        }
        for scenario in sorted(_FAULT_SCENARIOS)
    ]
    real_projection = evidence.scheduler_projections["real_shadow_30"]
    real_item_count = cast(int, real_projection["item_count"])
    real_terminal_count = cast(
        int,
        real_projection["terminal_result_count"],
    )
    real_technical_review_leaks = cast(
        int,
        real_projection["technical_review_leak_count"],
    )
    performance: dict[str, dict[str, object]] = {}
    for scope in _PERFORMANCE_SCOPES:
        metrics = evidence.performance[scope]
        performance[scope] = {
            "p50_ms": _nonnegative_number(
                metrics["p50_ms"],
                label=f"{scope} P50",
            ),
            "p95_ms": _nonnegative_number(
                metrics["p95_ms"],
                label=f"{scope} P95",
            ),
            "sample_count": _positive_int(
                metrics["sample_size"],
                label=f"{scope} sample count",
            ),
        }
    body: dict[str, object] = {
        "current_locked_gate_sha256": (
            evidence.current_locked_gate_sha256
        ),
        "current_locked_selection_sha256": (
            evidence.current_locked_selection_sha256
        ),
        "daily_snapshot_validation_sha256": (
            evidence.daily_snapshot_validation_sha256
        ),
        "dataset_isolation_sha256": evidence.dataset_isolation_sha256,
        "fault_injections": faults,
        "kind": "loop9_operational_acceptance_evidence",
        "no_silent_omission": True,
        "performance": performance,
        "real_shadow_machine_evaluation_sha256": (
            evidence.real_shadow_machine_evaluation_sha256
        ),
        "real_shadow_reconciliation": {
            "duplicate_submission_count": 0,
            "human_review_count": real_item_count,
            "machine_item_count": real_item_count,
            "missing_item_count": 0,
            "source_item_count": real_item_count,
            "technical_failure_in_review_count": (
                real_technical_review_leaks
            ),
            "terminal_outcome_count": real_terminal_count,
            "unique_item_count": real_item_count,
        },
        "real_shadow_selection_sha256": (
            evidence.real_shadow_selection_sha256
        ),
        "request_audit_summaries": summaries,
        "schema_version": 1,
        "settlement_contract_sha256": (
            evidence.settlement_contract_sha256
        ),
        "settlement_selection_sha256": (
            evidence.settlement_contract_selection_sha256
        ),
        "source_build_sha256": evidence.source_build_sha256,
    }
    operational = {
        **body,
        "canonical_sha256": _canonical_sha256(body),
    }
    return operational, request_audits


def replay_loop9_final_acceptance(
    inputs: Loop9FinalAcceptanceInputs,
) -> Loop9FinalAcceptanceReplay:
    """Reload every final Gate from the current source tree and data root."""

    project_root = _real_directory(
        inputs.project_root,
        label="project root",
    )
    data_root = _real_directory(inputs.data_root, label="data root")
    path_contracts = (
        (
            inputs.read_contract_validation_path,
            "read contract validation",
            False,
        ),
        (
            inputs.real_shadow_package_dir,
            "real shadow review package",
            True,
        ),
        (
            inputs.real_shadow_seal_path,
            "real shadow human review seal",
            False,
        ),
        (
            inputs.real_shadow_machine_evaluation_path,
            "real shadow machine evaluation",
            False,
        ),
        (
            inputs.daily_snapshot_validation_path,
            "daily snapshot validation",
            False,
        ),
        (
            inputs.discovery_development_path,
            "discovery development dataset",
            False,
        ),
        (
            inputs.current_locked_50_path,
            "current locked dataset",
            False,
        ),
        (
            inputs.real_shadow_30_path,
            "real shadow dataset",
            False,
        ),
        (
            inputs.daily_validation_dataset_path,
            "daily validation dataset",
            False,
        ),
        (
            inputs.source_development_authority_path,
            "source development authority",
            False,
        ),
        (
            inputs.dataset_isolation_path,
            "dataset isolation evidence",
            False,
        ),
    )
    for path, label, directory in path_contracts:
        _existing_under(
            root=data_root,
            path=path,
            label=label,
            directory=directory,
        )
    _sha256(
        inputs.current_locked_selection_sha256,
        label="current locked selection",
    )
    _sha256(
        inputs.real_shadow_selection_sha256,
        label="real shadow selection",
    )
    _sha256(
        inputs.formal_run_evidence_sha256,
        label="formal run evidence",
    )
    identity_key = data_root / "secrets" / "loop9-platform-identity.key"
    _existing_under(
        root=data_root,
        path=identity_key,
        label="platform identity authority",
        directory=False,
    )
    selection_seed = (
        data_root / "secrets" / "loop9-formal-selection-seed.key"
    )
    _existing_under(
        root=data_root,
        path=selection_seed,
        label="formal selection seed authority",
        directory=False,
    )

    try:
        source_build_sha256 = current_loop9_build_sha256(project_root)
        settlement = load_selected_live_read_contract(data_root)
        daily = load_selected_daily_read_contract(data_root)
        identity = load_or_create_loop9_identity_authority(data_root)
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "current Loop 9 authority replay failed"
        ) from exc

    read_gate_sha256 = _validate_read_contract_gate(
        data_root=data_root,
        validation_path=inputs.read_contract_validation_path,
        source_build_sha256=source_build_sha256,
        identity_context_sha256=identity.context_sha256,
        settlement=settlement,
        daily=daily,
    )
    daily_payload = _load_json_file(
        inputs.daily_snapshot_validation_path,
        label="daily snapshot validation",
    )
    daily_gate = _validate_daily_gate(
        payload=daily_payload,
        data_root=data_root,
        project_root=project_root,
        source_build_sha256=source_build_sha256,
        daily=daily,
    )

    try:
        selection_store = FormalShadowSelectionStore(data_root)
        locked = selection_store.load_active_current_locked_manifest(
            inputs.current_locked_selection_sha256
        )
        locked_gate = selection_store.require_current_locked_gate(
            expected_current_build_sha256=source_build_sha256,
            expected_settlement_contract_sha256=(
                settlement.manifest.canonical_sha256
            ),
        )
        real_shadow = (
            selection_store.load_active_real_shadow_manifest(
                inputs.real_shadow_selection_sha256,
                expected_current_build_sha256=source_build_sha256,
                expected_settlement_contract_sha256=(
                    settlement.manifest.canonical_sha256
                ),
            )
        )
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "active formal selection or current locked Gate replay failed"
        ) from exc
    if (
        locked.target_kind
        is not ShadowBatchTargetKind.CURRENT_LOCKED_50
        or locked.batch_manifest.source_build_sha256
        != source_build_sha256
        or locked.batch_manifest.contract_canonical_sha256
        != settlement.manifest.canonical_sha256
        or locked_gate.selection_sha256 != locked.canonical_sha256
        or real_shadow.target_kind
        is not ShadowBatchTargetKind.REAL_SHADOW_30
        or real_shadow.prior_selection_sha256s
        != (locked.canonical_sha256,)
        or real_shadow.locked_gate_evidence_sha256
        != locked_gate.canonical_sha256
    ):
        raise Loop9FinalAcceptanceError(
            "active formal selection authority changed"
        )

    try:
        package = load_loop9_review_package(
            inputs.real_shadow_package_dir
        )
        seal = _load_and_validate_seal(
            package=package,
            seal_path=inputs.real_shadow_seal_path,
        )
        persisted_evaluation = load_machine_truth_evaluation(
            inputs.real_shadow_machine_evaluation_path
        )
        machine_result_sha256 = _sha256(
            persisted_evaluation.get("machine_result_sha256"),
            label="real shadow machine result",
        )
        machine_result_path = (
            data_root
            / "verification"
            / "loop9"
            / "machine-results"
            / machine_result_sha256[:2]
            / f"{machine_result_sha256}.json"
        )
        _existing_under(
            root=data_root,
            path=machine_result_path,
            label="real shadow machine result",
            directory=False,
        )
        replayed_evaluation = evaluate_sealed_machine_results(
            package_dir=inputs.real_shadow_package_dir,
            seal_path=inputs.real_shadow_seal_path,
            machine_result_path=machine_result_path,
        )
        human_replay = replay_loop9_review(
            package_dir=inputs.real_shadow_package_dir,
            seal_path=inputs.real_shadow_seal_path,
            isolation_evidence_path=inputs.dataset_isolation_path,
        )
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "real shadow human and machine evidence replay failed"
        ) from exc
    if (
        package.source_batch.target_kind
        is not ShadowBatchTargetKind.REAL_SHADOW_30
        or package.formal_selection.to_payload()
        != real_shadow.to_payload()
        or package.source_batch.canonical_sha256
        != real_shadow.batch_manifest.canonical_sha256
        or replayed_evaluation != persisted_evaluation
        or persisted_evaluation.get("gate_passed") is not True
        or persisted_evaluation.get("review_kind")
        != ShadowBatchTargetKind.REAL_SHADOW_30.value
        or persisted_evaluation.get("item_count") != 30
        or persisted_evaluation.get("image_count") != 60
        or persisted_evaluation.get("runtime_observation_count") != 120
        or persisted_evaluation.get("technical_failure_count") != 0
        or persisted_evaluation.get("wrong_auto_pass_count") != 0
        or persisted_evaluation.get(
            "high_confidence_role_error_count"
        )
        != 0
        or seal.get("review_count") != 30
        or seal.get("image_truth_count") != 60
        or seal.get("human_review_complete") is not True
        or seal.get("shadow_gate_passed") is not True
        or human_replay.get("replay_passed") is not True
        or human_replay.get("machine_comparison_gate_passed")
        is not True
    ):
        raise Loop9FinalAcceptanceError(
            "real shadow human or machine Gate did not pass"
        )

    isolation_sha256 = _replay_dataset_isolation(
        inputs=inputs,
        data_root=data_root,
        source_build_sha256=source_build_sha256,
        settlement=settlement,
        daily=daily,
        daily_gate=daily_gate,
    )
    formal_request = Loop9FormalRunRequest(
        locked_job_id=inputs.locked_job_id,
        real_shadow_selection_sha256=(
            inputs.real_shadow_selection_sha256
        ),
        real_shadow_job_id=inputs.real_shadow_job_id,
        real_shadow_machine_evaluation_sha256=_sha256(
            persisted_evaluation.get("canonical_sha256"),
            label="real shadow machine evaluation",
        ),
        daily_snapshot_validation_sha256=_sha256(
            daily_gate.get("canonical_sha256"),
            label="daily snapshot validation",
        ),
        dataset_isolation_sha256=isolation_sha256,
        fault_scenarios=inputs.fault_scenarios,
    )
    formal_store = Loop9FormalRunEvidenceStore(data_root)
    try:
        formal_run = formal_store.load_and_replay(
            inputs.formal_run_evidence_sha256,
            project_root=project_root,
            request=formal_request,
        )
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "formal run evidence replay failed"
        ) from exc
    expected_formal_bindings = {
        "source_build_sha256": source_build_sha256,
        "settlement_contract_sha256": (
            settlement.manifest.canonical_sha256
        ),
        "settlement_contract_selection_sha256": (
            settlement.selection_sha256
        ),
        "daily_contract_sha256": daily.manifest.canonical_sha256,
        "daily_contract_selection_sha256": daily.selection_sha256,
        "current_locked_selection_sha256": locked.canonical_sha256,
        "current_locked_gate_sha256": locked_gate.canonical_sha256,
        "real_shadow_selection_sha256": real_shadow.canonical_sha256,
        "real_shadow_machine_evaluation_sha256": (
            formal_request.real_shadow_machine_evaluation_sha256
        ),
        "daily_snapshot_validation_sha256": (
            formal_request.daily_snapshot_validation_sha256
        ),
        "dataset_isolation_sha256": isolation_sha256,
    }
    if any(
        getattr(formal_run, field) != expected
        for field, expected in expected_formal_bindings.items()
    ):
        raise Loop9FinalAcceptanceError(
            "formal run evidence authority binding changed"
        )
    daily_candidate_count = daily_gate.get("candidate_count")
    if (
        type(daily_candidate_count) is not int
        or daily_candidate_count < 0
    ):
        raise Loop9FinalAcceptanceError(
            "daily snapshot candidate count is invalid"
        )
    operational, request_audits = _legacy_documents_from_formal_run(
        evidence=formal_run,
        daily_candidate_count=daily_candidate_count,
    )
    replay = Loop9FinalAcceptanceReplay(
        source_build_sha256=source_build_sha256,
        settlement_contract_sha256=(
            settlement.manifest.canonical_sha256
        ),
        settlement_selection_sha256=settlement.selection_sha256,
        daily_contract_sha256=daily.manifest.canonical_sha256,
        daily_selection_sha256=daily.selection_sha256,
        read_contract_validation_sha256=read_gate_sha256,
        current_locked_selection_sha256=locked.canonical_sha256,
        current_locked_gate_sha256=locked_gate.canonical_sha256,
        current_locked_machine_evaluation_sha256=(
            locked_gate.machine_evaluation_sha256
        ),
        real_shadow_selection_sha256=real_shadow.canonical_sha256,
        real_shadow_human_review_seal_sha256=_sha256(
            seal.get("canonical_sha256"),
            label="real shadow human review seal",
        ),
        real_shadow_machine_evaluation_sha256=_sha256(
            persisted_evaluation.get("canonical_sha256"),
            label="real shadow machine evaluation",
        ),
        daily_snapshot_validation_sha256=_sha256(
            daily_gate.get("canonical_sha256"),
            label="daily snapshot validation",
        ),
        dataset_isolation_sha256=isolation_sha256,
        formal_run_evidence_sha256=formal_run.canonical_sha256,
        operational_evidence=operational,
        request_audits=request_audits,
        data_references={
            "read_contract_validation": _relative(
                data_root,
                inputs.read_contract_validation_path,
                label="read contract validation",
            ),
            "current_locked_gate": (
                "verification/loop9/current-locked-gates/"
                f"{locked_gate.canonical_sha256[:2]}/"
                f"{locked_gate.canonical_sha256}.json"
            ),
            "real_shadow_package": _relative(
                data_root,
                inputs.real_shadow_package_dir,
                label="real shadow review package",
            ),
            "real_shadow_seal": _relative(
                data_root,
                inputs.real_shadow_seal_path,
                label="real shadow human review seal",
            ),
            "real_shadow_machine_evaluation": _relative(
                data_root,
                inputs.real_shadow_machine_evaluation_path,
                label="real shadow machine evaluation",
            ),
            "daily_snapshot_validation": _relative(
                data_root,
                inputs.daily_snapshot_validation_path,
                label="daily snapshot validation",
            ),
            "dataset_isolation": _relative(
                data_root,
                inputs.dataset_isolation_path,
                label="dataset isolation evidence",
            ),
            "formal_run_evidence": _relative(
                data_root,
                formal_store.path_for(formal_run.canonical_sha256),
                label="formal run evidence",
            ),
        },
    )
    replay.verify()
    return replay


def _canonical_acceptance_payload(
    payload: object,
) -> dict[str, object]:
    raw = _exact_mapping(
        payload,
        fields={
            "accepted_at",
            "canonical_sha256",
            "current_locked_gate_sha256",
            "current_locked_machine_evaluation_sha256",
            "current_locked_selection_sha256",
            "daily_contract_sha256",
            "daily_selection_sha256",
            "daily_snapshot_validation_sha256",
            "data_references",
            "dataset_isolation_sha256",
            "fault_injections",
            "forbidden_request_count",
            "gate_passed",
            "kind",
            "no_silent_omission",
            "formal_run_evidence_sha256",
            "performance",
            "platform_write_request_count",
            "read_contract_validation_sha256",
            "real_shadow_human_review_seal_sha256",
            "real_shadow_machine_evaluation_sha256",
            "real_shadow_reconciliation",
            "real_shadow_selection_sha256",
            "request_audit_summaries",
            "redirect_count",
            "schema_version",
            "settlement_contract_sha256",
            "settlement_selection_sha256",
            "source_build_sha256",
        },
        label="Loop 9 acceptance evidence",
    )
    declared = _sha256(
        raw.get("canonical_sha256"),
        label="Loop 9 acceptance evidence",
    )
    body = {
        key: value
        for key, value in raw.items()
        if key != "canonical_sha256"
    }
    if (
        raw.get("schema_version") != 1
        or raw.get("kind") != "loop9_shadow_acceptance"
        or raw.get("gate_passed") is not True
        or raw.get("no_silent_omission") is not True
        or any(
            raw.get(field) != 0
            for field in (
                "forbidden_request_count",
                "platform_write_request_count",
                "redirect_count",
            )
        )
        or declared != _canonical_sha256(body)
    ):
        raise Loop9FinalAcceptanceError(
            "Loop 9 acceptance evidence integrity is invalid"
        )
    accepted_at = _plain_text(
        raw.get("accepted_at"),
        label="acceptance time",
        maximum=40,
    )
    try:
        parsed = datetime.fromisoformat(accepted_at)
    except ValueError as exc:
        raise Loop9FinalAcceptanceError(
            "acceptance time is invalid"
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.isoformat() != accepted_at
    ):
        raise Loop9FinalAcceptanceError(
            "acceptance time is invalid"
        )
    return dict(raw)


def _write_once(path: Path, payload: Mapping[str, object]) -> None:
    content = _canonical_bytes(payload) + b"\n"
    if path.exists():
        if (
            path.is_symlink()
            or _is_reparse_point(path)
            or not path.is_file()
            or path.read_bytes() != content
        ):
            raise Loop9FinalAcceptanceError(
                "acceptance evidence identity collision"
            )
        return
    staged = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, path)
        except FileExistsError:
            if (
                path.is_symlink()
                or _is_reparse_point(path)
                or path.read_bytes() != content
            ):
                raise Loop9FinalAcceptanceError(
                    "acceptance evidence identity collision"
                ) from None
        except OSError as exc:
            raise Loop9FinalAcceptanceError(
                "acceptance evidence could not be published atomically"
            ) from exc
    finally:
        staged.unlink(missing_ok=True)


def _verify_input_manifest(
    *,
    project_root: Path,
    ledger: Mapping[str, object],
) -> None:
    reference = cast(Mapping[str, object], ledger["input_manifest"])
    raw_path = _safe_reference(
        reference.get("path"),
        label="ledger input manifest",
    )
    path = project_root / PurePosixPath(raw_path)
    resolved = _existing_under(
        root=project_root,
        path=path,
        label="ledger input manifest",
        directory=False,
    )
    expected = _sha256(
        reference.get("sha256"),
        label="ledger input manifest",
    )
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != expected:
        raise Loop9FinalAcceptanceError(
            "ledger input manifest changed"
        )


def _evidence_from_accepted_ledger(
    *,
    project_root: Path,
    ledger: Mapping[str, object],
    replay: Loop9FinalAcceptanceReplay,
) -> dict[str, object]:
    acceptance = _exact_mapping(
        ledger.get("acceptance"),
        fields={
            "accepted_at",
            "evidence",
            "kind",
            "previous_last_accepted_git_commit",
            "previous_status",
            "sha256",
        },
        label="ledger acceptance",
    )
    reference = _safe_reference(
        acceptance.get("evidence"),
        label="ledger acceptance evidence",
    )
    path = _existing_under(
        root=project_root,
        path=project_root / PurePosixPath(reference),
        label="ledger acceptance evidence",
        directory=False,
    )
    payload = _canonical_acceptance_payload(
        _load_json_file(path, label="Loop 9 acceptance evidence")
    )
    if (
        path.name != f"{payload['canonical_sha256']}.json"
        or payload.get("canonical_sha256") != acceptance.get("sha256")
    ):
        raise Loop9FinalAcceptanceError(
            "ledger acceptance evidence binding changed"
        )
    expected = replay.evidence_payload(
        accepted_at=cast(str, acceptance["accepted_at"])
    )
    if payload != expected:
        raise Loop9FinalAcceptanceError(
            "accepted Loop 9 evidence no longer replays"
        )
    return payload


def accept_loop9_shadow(
    *,
    inputs: Loop9FinalAcceptanceInputs,
    ledger_path: Path,
    output_directory: Path,
    expected_ledger_revision: int,
    clock: Callable[[], datetime],
    remaining_risks: Sequence[str] = (),
) -> dict[str, object]:
    """Publish the immutable Gate and atomically close Loop 9."""

    if not isinstance(inputs, Loop9FinalAcceptanceInputs):
        raise Loop9FinalAcceptanceError(
            "final acceptance inputs are invalid"
        )
    project = _real_directory(
        inputs.project_root,
        label="project root",
    )
    expected_root = _real_directory(
        REPOSITORY_ROOT,
        label="repository root",
    )
    if project != expected_root:
        raise Loop9FinalAcceptanceError(
            "project root must be the active repository root"
        )
    ledger_file = _existing_under(
        root=project,
        path=ledger_path,
        label="Loop ledger",
        directory=False,
    )
    if ledger_file != project / "verification" / "loop-ledger.json":
        raise Loop9FinalAcceptanceError(
            "Loop ledger must be the active repository ledger"
        )
    output = _existing_under(
        root=project,
        path=output_directory,
        label="acceptance output directory",
        directory=True,
    )
    required_output = (
        project / "verification" / "loops" / "loop-9" / "formal"
    )
    if output != required_output:
        raise Loop9FinalAcceptanceError(
            "acceptance output must be the formal content-addressed directory"
        )
    if (
        not isinstance(expected_ledger_revision, int)
        or expected_ledger_revision < 0
    ):
        raise Loop9FinalAcceptanceError(
            "expected ledger revision is invalid"
        )
    normalized_risks = [
        _plain_text(value, label="remaining risk", maximum=500)
        for value in remaining_risks
    ]
    store = LedgerStore(ledger_file)
    with store.locked_write():
        return _accept_loop9_shadow_locked(
            inputs=inputs,
            project=project,
            output=output,
            expected_ledger_revision=expected_ledger_revision,
            clock=clock,
            normalized_risks=normalized_risks,
            store=store,
        )


def _accept_loop9_shadow_locked(
    *,
    inputs: Loop9FinalAcceptanceInputs,
    project: Path,
    output: Path,
    expected_ledger_revision: int,
    clock: Callable[[], datetime],
    normalized_risks: list[str],
    store: LedgerStore,
) -> dict[str, object]:
    ledger = store.read()
    _verify_input_manifest(project_root=project, ledger=ledger)
    replay = replay_loop9_final_acceptance(inputs)
    replay.verify()
    if ledger["status"] == "shadow_accepted":
        return _evidence_from_accepted_ledger(
            project_root=project,
            ledger=ledger,
            replay=replay,
        )
    if (
        ledger["schema_version"] not in {2, 3}
        or ledger["current_loop"] != "loop-9"
        or ledger["status"] != "in_progress"
        or ledger["revision"] != expected_ledger_revision
        or ledger.get("waiver") is not None
        or ledger["last_accepted_git_commit"] is None
        or (
            ledger["schema_version"] == 3
            and ledger.get("acceptance") is not None
        )
    ):
        raise Loop9FinalAcceptanceError(
            "Loop ledger is not eligible for shadow acceptance"
        )
    gates = cast(list[dict[str, object]], ledger["gate_results"])
    pending = {
        cast(str, gate["id"])
        for gate in gates
        if gate["status"] == "pending"
    }
    if (
        any(gate["status"] in {"failed", "blocked"} for gate in gates)
        or not pending.issubset(_UPDATABLE_GATE_IDS)
        or not _UPDATABLE_GATE_IDS.issubset(
            {cast(str, gate["id"]) for gate in gates}
        )
    ):
        raise Loop9FinalAcceptanceError(
            "Loop ledger has an unresolved non-final Gate"
        )
    accepted_at = clock()
    if (
        not isinstance(accepted_at, datetime)
        or accepted_at.tzinfo is None
        or accepted_at.utcoffset() is None
    ):
        raise Loop9FinalAcceptanceError(
            "acceptance clock must be timezone-aware"
        )
    payload = _canonical_acceptance_payload(
        replay.evidence_payload(accepted_at=accepted_at.isoformat())
    )
    digest = cast(str, payload["canonical_sha256"])
    evidence_path = output / f"{digest}.json"
    _write_once(evidence_path, payload)
    evidence_reference = _relative(
        project,
        evidence_path,
        label="Loop 9 acceptance evidence",
    )

    try:
        store._commit_verified_shadow_acceptance(
            expected_revision=expected_ledger_revision,
            evidence_path=evidence_reference,
            evidence_sha256=digest,
            accepted_at=accepted_at.isoformat(),
            remaining_risks=normalized_risks,
            inputs=inputs,
        )
    except Exception as exc:
        raise Loop9FinalAcceptanceError(
            "Loop ledger shadow acceptance update failed"
        ) from exc
    return payload
