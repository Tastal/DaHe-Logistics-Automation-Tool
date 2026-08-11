from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import stat
import subprocess
import zipfile
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import uuid4
from xml.etree import ElementTree

from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditEvidenceStore,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_fault_injection import (
    FAULT_SCENARIOS,
    load_fault_injection_result,
)
from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
    replay_persisted_fault_scenario,
)
from dahe.verification.operational_fast_capture import (
    replay_operational_fast_capture_evidence,
)
from dahe.verification.production_backup_restore import (
    load_production_backup_restore_evidence,
)

WITH_GUARD = "operational_read_only_with_guard"
ACCEPTED = "operational_read_only_accepted"
ACTIVE = "operational_read_only_active"


class OperationalReadOnlyAcceptanceError(RuntimeError):
    """Raised when the guarded production evidence is incomplete."""


@dataclass(frozen=True, slots=True)
class OperationalReadOnlyAcceptanceInputs:
    project_root: Path
    data_root: Path
    release_manifest: Path
    regression_report: Path
    settlement_capture_evidence: Path
    daily_capture_evidence: Path
    fault_injection_evidence: Path
    backup_restore_evidence: Path
    ocr_qualification: Path
    daily_report_id: str
    output: Path


@dataclass(frozen=True, slots=True)
class OperationalReadOnlyAcceptanceEvidence:
    payload: dict[str, object]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.payload)

    @property
    def status(self) -> str:
        return cast(str, self.payload["status"])


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _normal_root(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or _is_reparse_point(path):
        raise OperationalReadOnlyAcceptanceError(f"{label} is unsafe")
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        raise OperationalReadOnlyAcceptanceError(
            f"{label} is unavailable"
        ) from exc
    if not root.is_dir() or root.is_symlink() or _is_reparse_point(root):
        raise OperationalReadOnlyAcceptanceError(f"{label} is unsafe")
    return root


def _normal_file(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or _is_reparse_point(path):
        raise OperationalReadOnlyAcceptanceError(f"{label} is unsafe")
    try:
        result = path.resolve(strict=True)
    except OSError as exc:
        raise OperationalReadOnlyAcceptanceError(
            f"{label} is unavailable"
        ) from exc
    if not result.is_file() or result.is_symlink() or _is_reparse_point(result):
        raise OperationalReadOnlyAcceptanceError(f"{label} is unsafe")
    return result


def _read_json(path: Path, *, label: str) -> dict[str, object]:
    target = _normal_file(path, label=label)
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationalReadOnlyAcceptanceError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise OperationalReadOnlyAcceptanceError(f"{label} is invalid")
    return cast(dict[str, object], value)


def _git_head(project_root: Path) -> str:
    completed = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    commit = completed.stdout.strip()
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise OperationalReadOnlyAcceptanceError("Git build identity is invalid")
    return commit


def _verify_release(
    path: Path,
    *,
    build_sha256: str,
    git_commit: str,
) -> dict[str, object]:
    manifest = _read_json(path, label="release manifest")
    if (
        manifest.get("kind") != "dahe_local_production_read_only_release"
        or manifest.get("schema_version") != 1
        or manifest.get("build_git_commit") != git_commit
        or manifest.get("source_build_sha256") != build_sha256
        or manifest.get("module_modes")
        != {
            "audit": "operational",
            "daily": "operational",
            "dispatch": "disabled",
            "settlement": "disabled",
        }
    ):
        raise OperationalReadOnlyAcceptanceError(
            "release manifest does not describe the final production build"
        )
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise OperationalReadOnlyAcceptanceError("release file manifest is empty")
    root = path.parent.resolve(strict=True)
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise OperationalReadOnlyAcceptanceError(
                "release file manifest is invalid"
            )
        candidate = (root / relative).resolve(strict=True)
        if (
            not candidate.is_relative_to(root)
            or candidate.is_symlink()
            or not candidate.is_file()
            or _sha256_file(candidate) != expected
        ):
            raise OperationalReadOnlyAcceptanceError(
                "release payload changed after build"
            )
    return {
        "build_git_commit": git_commit,
        "manifest_file_sha256": _sha256_file(path),
        "payload_file_count": len(files),
    }


def _verify_regression(path: Path) -> dict[str, object]:
    document = _read_json(path, label="historical locked-set regression")
    report = document.get("committed_report", document)
    if not isinstance(report, dict):
        raise OperationalReadOnlyAcceptanceError(
            "historical locked-set regression is invalid"
        )
    metrics = report.get("metrics")
    reconciliation = report.get("reconciliation")
    if (
        not isinstance(metrics, dict)
        or not isinstance(reconciliation, dict)
        or metrics.get("real_pair_sample_count") != 50
        or metrics.get("real_image_sample_count") != 100
        or metrics.get("wrong_auto_pass_count") != 0
        or reconciliation.get("expected_pair_count") != 50
        or reconciliation.get("result_pair_count") != 50
        or reconciliation.get("expected_image_count") != 100
        or reconciliation.get("result_image_count") != 100
        or any(
            reconciliation.get(field)
            for field in (
                "duplicate_image_results",
                "duplicate_pair_results",
                "missing_image_results",
                "missing_pair_results",
                "unexpected_image_results",
                "unexpected_pair_results",
            )
        )
    ):
        raise OperationalReadOnlyAcceptanceError(
            "historical locked-set regression has an unsafe result"
        )
    return {
        "file_sha256": _sha256_file(path),
        "image_count": 100,
        "pair_count": 50,
        "wrong_auto_pass_count": 0,
    }


def _qualified_smoke_image(image: object, *, expected_id: str) -> bool:
    if not isinstance(image, dict):
        return False
    image_sha256 = image.get("image_sha256")
    elapsed_ms = image.get("elapsed_ms")
    return (
        isinstance(image_sha256, str)
        and len(image_sha256) == 64
        and all(character in "0123456789abcdef" for character in image_sha256)
        and image.get("verified_image_sha256") == image_sha256
        and image.get("role") == expected_id
        and image.get("field_reliable") is True
        and isinstance(elapsed_ms, (int, float))
        and not isinstance(elapsed_ms, bool)
        and math.isfinite(elapsed_ms)
        and elapsed_ms > 0
    )


def _verify_ocr_qualification(path: Path) -> dict[str, object]:
    document = _read_json(path, label="OCR qualification")
    reports = document.get("reports")
    if document.get("schema_version") != 2 or not isinstance(reports, list):
        raise OperationalReadOnlyAcceptanceError("OCR qualification is invalid")
    if (
        len(reports) != 2
        or any(not isinstance(report, dict) for report in reports)
        or any(
            report.get("runtime_kind") not in {"cpu", "gpu"}
            for report in reports
            if isinstance(report, dict)
        )
    ):
        raise OperationalReadOnlyAcceptanceError(
            "both CPU and GPU OCR must be qualified"
        )
    by_kind = {
        cast(str, report.get("runtime_kind")): report
        for report in reports
        if isinstance(report, dict)
    }
    if set(by_kind) != {"cpu", "gpu"}:
        raise OperationalReadOnlyAcceptanceError(
            "both CPU and GPU OCR must be qualified"
        )
    for kind, report in by_kind.items():
        images = report.get("images")
        images_by_id = (
            {
                cast(str, image.get("image_id")): image
                for image in images
                if isinstance(image, dict)
                and image.get("image_id") in {"loading", "unloading"}
            }
            if isinstance(images, list)
            else {}
        )

        if (
            report.get("status") != "qualified"
            or not isinstance(report.get("profile_id"), str)
            or not report.get("profile_id")
            or not isinstance(images, list)
            or len(images) != 2
            or set(images_by_id) != {"loading", "unloading"}
            or not _qualified_smoke_image(
                images_by_id.get("loading"),
                expected_id="loading",
            )
            or not _qualified_smoke_image(
                images_by_id.get("unloading"),
                expected_id="unloading",
            )
            or (
                kind == "gpu"
                and (
                    not isinstance(report.get("stable_device_id"), str)
                    or not report.get("stable_device_id")
                )
            )
        ):
            raise OperationalReadOnlyAcceptanceError(
                f"{kind} OCR qualification did not pass"
            )
    return {
        "cpu_profile_id": by_kind["cpu"].get("profile_id"),
        "file_sha256": _sha256_file(path),
        "gpu_profile_id": by_kind["gpu"].get("profile_id"),
    }


def _database(data_root: Path) -> sqlite3.Connection:
    path = data_root / "database" / "dahe.sqlite3"
    if not path.is_file() or path.is_symlink():
        raise OperationalReadOnlyAcceptanceError(
            "production database is unavailable"
        )
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _verify_guard(data_root: Path) -> dict[str, object]:
    with closing(_database(data_root)) as db:
        row = db.execute(
            "SELECT status, target_count, registered_count, "
            "reviewed_target_count, false_normal_count, record_version "
            "FROM production_read_only_guard WHERE guard_id = 'primary'"
        ).fetchone()
        if row is None:
            raise OperationalReadOnlyAcceptanceError(
                "first-batch protection has no evidence"
            )
        guard_rows = tuple(
            db.execute(
            "SELECT business_identity_sha256, counts_toward_gate, "
            "machine_outcome, manual_outcome, manual_action_id, "
            "protected, released "
                "FROM production_read_only_guard_items "
                "ORDER BY ordinal"
            )
        )
    target_rows = tuple(
        item for item in guard_rows if item["counts_toward_gate"] == 1
    )
    identities = {str(item["business_identity_sha256"]) for item in guard_rows}
    target_identities = {
        str(item["business_identity_sha256"]) for item in target_rows
    }
    normal_identities = {
        str(item["business_identity_sha256"])
        for item in guard_rows
        if item["machine_outcome"] == "normal_ready"
    }
    reviewed = sum(item["manual_outcome"] is not None for item in target_rows)
    false_normals = sum(
        item["manual_outcome"] == "confirmed_problem"
        and item["business_identity_sha256"] in normal_identities
        for item in target_rows
    )
    stored_status = str(row["status"])
    expected_status = (
        ACTIVE
        if stored_status == ACTIVE
        else (
            ACCEPTED
            if reviewed == int(row["target_count"]) and false_normals == 0
            else WITH_GUARD
        )
    )
    expected_target_rows = min(len(identities), int(row["target_count"]))
    if (
        int(row["target_count"]) != 30
        or int(row["registered_count"]) != len(identities)
        or int(row["reviewed_target_count"]) != reviewed
        or len(target_rows) != expected_target_rows
        or len(target_identities) != len(target_rows)
        or any(len(identity) != 64 for identity in identities)
        or any(
            (
                item["manual_outcome"] is None
                and item["manual_action_id"] is not None
            )
            or (
                item["manual_outcome"] in {"normal_ready", "confirmed_problem"}
                and not item["manual_action_id"]
            )
            or item["manual_outcome"]
            not in {None, "normal_ready", "confirmed_problem"}
            for item in target_rows
        )
        or int(row["false_normal_count"]) != false_normals
        or stored_status != expected_status
        or (
            stored_status == ACTIVE
            and any(
                bool(item["protected"]) and not bool(item["released"])
                for item in guard_rows
            )
        )
    ):
        raise OperationalReadOnlyAcceptanceError(
            "first-batch protection is incomplete or inconsistent"
        )
    return {
        "false_normal_count": false_normals,
        "record_version": int(row["record_version"]),
        "registered_count": len(identities),
        "reviewed_count": reviewed,
        "status": expected_status,
        "target_count": 30,
    }


def _validate_workbook(path: Path, *, row_count: int) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise OperationalReadOnlyAcceptanceError(
                    "daily report archive is corrupt"
                )
            sheet = ElementTree.fromstring(
                archive.read("xl/worksheets/sheet1.xml")
            )
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise OperationalReadOnlyAcceptanceError(
            "daily report cannot be reopened"
        ) from exc
    namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    rows = sheet.findall("x:sheetData/x:row", namespace)
    auto_filter = sheet.find("x:autoFilter", namespace)
    if (
        len(rows) != row_count + 2
        or auto_filter is None
        or auto_filter.attrib.get("ref") != f"A1:J{row_count + 1}"
    ):
        raise OperationalReadOnlyAcceptanceError(
            "daily report row count or ten-column filter changed"
        )


def _verify_daily_report(data_root: Path, report_id: str) -> dict[str, object]:
    with closing(_database(data_root)) as db:
        row = db.execute(
            "SELECT status, output_directory, file_name, file_sha256, "
            "data_snapshot_sha256, data_json, row_count, loading_net_total, "
            "business_date FROM daily_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
    if row is None or row["status"] != "confirmed":
        raise OperationalReadOnlyAcceptanceError(
            "daily report has not been confirmed"
        )
    path = (Path(str(row["output_directory"])) / str(row["file_name"])).resolve()
    try:
        data = json.loads(str(row["data_json"]))
    except json.JSONDecodeError as exc:
        raise OperationalReadOnlyAcceptanceError(
            "daily report data snapshot is invalid"
        ) from exc
    row_count = int(row["row_count"])
    if (
        not path.is_file()
        or path.is_symlink()
        or _sha256_file(path) != row["file_sha256"]
        or not isinstance(data, dict)
        or not isinstance(data.get("rows"), list)
        or len(data["rows"]) != row_count
    ):
        raise OperationalReadOnlyAcceptanceError(
            "daily report file or data snapshot changed"
        )
    _validate_workbook(path, row_count=row_count)
    return {
        "business_date": row["business_date"],
        "data_snapshot_sha256": row["data_snapshot_sha256"],
        "file_sha256": row["file_sha256"],
        "loading_net_total": row["loading_net_total"],
        "report_id_sha256": hashlib.sha256(report_id.encode()).hexdigest(),
        "row_count": row_count,
    }


def _verify_fast_capture(
    *,
    project_root: Path,
    data_root: Path,
    path: Path,
    task_type: str,
    build_sha256: str,
) -> dict[str, object]:
    evidence = replay_operational_fast_capture_evidence(
        project_root=project_root,
        data_root=data_root,
        path=path,
    )
    payload = evidence.payload
    if payload.get("task_type") != task_type:
        raise OperationalReadOnlyAcceptanceError(
            "fast capture task type is not the required business scope"
        )
    capture = cast(Mapping[str, object], payload["capture"])
    performance = cast(Mapping[str, object], payload["performance"])
    if (
        payload.get("source_build_sha256") != build_sha256
        or capture.get("dynamic_total") != capture.get("fetched")
        or capture.get("dynamic_total") != capture.get("unique_identity_count")
        or performance.get("gate_passed") is not True
    ):
        raise OperationalReadOnlyAcceptanceError(
            "fast capture reconciliation or performance failed"
        )
    if task_type == "daily":
        ocr = payload.get("ocr")
        if not isinstance(ocr, dict) or ocr.get("technical_failed") != 0:
            raise OperationalReadOnlyAcceptanceError(
                "daily OCR has a technical failure"
            )
    job_id = cast(str, payload["job_id"])
    audit = PlatformReadAuditEvidenceStore(data_root).load_sealed_for_job(
        job_id=job_id
    )
    if (
        audit.authority.build_sha256 != build_sha256
        or audit.request_counts.denied != 0
        or audit.platform_write_request_count != 0
        or audit.redirect_count != 0
    ):
        raise OperationalReadOnlyAcceptanceError(
            "platform request audit is not clean"
        )
    return {
        "audit_sha256": audit.canonical_sha256,
        "capture_sha256": evidence.canonical_sha256,
        "dynamic_total": capture["dynamic_total"],
        "missing_ticket_count": capture["missing_ticket_count"],
        "waybills_per_minute": performance["waybills_per_minute"],
    }


def build_operational_read_only_acceptance(
    inputs: OperationalReadOnlyAcceptanceInputs,
) -> OperationalReadOnlyAcceptanceEvidence:
    project_root = _normal_root(inputs.project_root, label="project root")
    data_root = _normal_root(inputs.data_root, label="production data root")
    build_sha256 = current_loop9_build_sha256(project_root)
    git_commit = _git_head(project_root)
    release = _verify_release(
        _normal_file(inputs.release_manifest, label="release manifest"),
        build_sha256=build_sha256,
        git_commit=git_commit,
    )
    regression = _verify_regression(inputs.regression_report)
    ocr = _verify_ocr_qualification(inputs.ocr_qualification)
    settlement = _verify_fast_capture(
        project_root=project_root,
        data_root=data_root,
        path=inputs.settlement_capture_evidence,
        task_type="settlement_capture",
        build_sha256=build_sha256,
    )
    daily = _verify_fast_capture(
        project_root=project_root,
        data_root=data_root,
        path=inputs.daily_capture_evidence,
        task_type="daily",
        build_sha256=build_sha256,
    )
    guard = _verify_guard(data_root)
    report = _verify_daily_report(data_root, inputs.daily_report_id)
    fault = load_fault_injection_result(
        _normal_file(inputs.fault_injection_evidence, label="fault evidence"),
        expected_build_sha256=build_sha256,
    )
    fault_projections: dict[str, object] = {}
    for scenario in FAULT_SCENARIOS:
        identity = fault.scenarios[scenario]
        fault_projections[scenario] = replay_persisted_fault_scenario(
            data_root=data_root,
            scenario=scenario,
            identity=FaultScenarioIdentity(
                run_id=identity.run_id,
                job_id=identity.job_id,
            ),
            current_build_sha256=build_sha256,
        )
    backup = load_production_backup_restore_evidence(
        _normal_file(inputs.backup_restore_evidence, label="backup evidence"),
        expected_build_sha256=build_sha256,
    )
    payload = {
        "backup_restore": {
            "canonical_sha256": backup.canonical_sha256,
            "evidence_count": backup.payload["evidence_count"],
        },
        "daily_capture": daily,
        "daily_report": report,
        "fault_injection": {
            "result_sha256": fault.result_sha256,
            "scenario_projection_sha256": _canonical_sha256(fault_projections),
        },
        "first_batch_guard": guard,
        "historical_locked_set_regression": regression,
        "kind": "loop9_operational_read_only_acceptance",
        "ocr_qualification": ocr,
        "release": release,
        "schema_version": 1,
        "settlement_capture": settlement,
        "source_build_sha256": build_sha256,
        "status": guard["status"],
    }
    return OperationalReadOnlyAcceptanceEvidence(payload=payload)


def publish_operational_read_only_acceptance(
    inputs: OperationalReadOnlyAcceptanceInputs,
) -> OperationalReadOnlyAcceptanceEvidence:
    evidence = build_operational_read_only_acceptance(inputs)
    output = Path(os.path.abspath(os.fspath(inputs.output)))
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise OperationalReadOnlyAcceptanceError(
            "acceptance output must be a new absolute path"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    document = {**evidence.payload, "canonical_sha256": evidence.canonical_sha256}
    staging = output.with_name(f".{output.name}.{uuid4().hex}.partial")
    try:
        with staging.open("xb") as handle:
            handle.write(
                json.dumps(
                    document,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        if output.exists():
            raise OperationalReadOnlyAcceptanceError(
                "acceptance output appeared during write"
            )
        os.replace(staging, output)
    finally:
        staging.unlink(missing_ok=True)
    return evidence
