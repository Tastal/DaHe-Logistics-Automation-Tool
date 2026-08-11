from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

from dahe.verification.loop9_build import current_loop9_build_sha256

_BASELINE_TOTAL = 315
_BASELINE_SECONDS = 44 * 60 + 31
_MINIMUM_WAYBILLS_PER_MINUTE = 21.0
_MINIMUM_SPEEDUP = 3.0


class OperationalFastCaptureEvidenceError(RuntimeError):
    """Raised when a fast business capture is incomplete or inconsistent."""


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(root: Path, relative_path: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise OperationalFastCaptureEvidenceError(
            "capture evidence path is not data-root relative"
        )
    evidence_root = (root / "evidence").resolve(strict=True)
    candidate = (evidence_root / relative).resolve(strict=True)
    if evidence_root not in candidate.parents or candidate.is_symlink():
        raise OperationalFastCaptureEvidenceError(
            "capture evidence path escaped the data root"
        )
    return candidate


def _one(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[object, ...],
) -> sqlite3.Row:
    row = connection.execute(query, parameters).fetchone()
    if row is None:
        raise OperationalFastCaptureEvidenceError(
            "capture execution record is missing"
        )
    return cast(sqlite3.Row, row)


@dataclass(frozen=True, slots=True)
class OperationalFastCaptureEvidence:
    payload: dict[str, object]

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(_canonical(self.payload)).hexdigest()


def build_operational_fast_capture_evidence(
    *,
    project_root: Path,
    data_root: Path,
    job_id: str,
) -> OperationalFastCaptureEvidence:
    project_root = project_root.resolve(strict=True)
    data_root = data_root.resolve(strict=True)
    if len(job_id) != 32 or any(character not in "0123456789abcdef" for character in job_id):
        raise OperationalFastCaptureEvidenceError(
            "capture job identity is invalid"
        )
    database_path = data_root / "database" / "dahe.sqlite3"
    if not database_path.is_file() or database_path.is_symlink():
        raise OperationalFastCaptureEvidenceError(
            "capture database is unavailable"
        )
    uri = f"{database_path.resolve(strict=True).as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        job = _one(
            connection,
            "SELECT task_type, status, diagnostic_code, created_at "
            "FROM jobs WHERE job_id = ?",
            (job_id,),
        )
        run = _one(
            connection,
            "SELECT scope, total, items_json, items_sha256, "
            "next_item_index, committed_batch_count, batch_size, "
            "detail_concurrency, image_concurrency, status, "
            "created_at, updated_at FROM operational_capture_runs "
            "WHERE job_id = ?",
            (job_id,),
        )
        if str(job["status"]) != "succeeded" or job["diagnostic_code"] is not None:
            raise OperationalFastCaptureEvidenceError(
                "capture job is not a clean success"
            )
        task_type = str(job["task_type"])
        scope = str(run["scope"])
        if task_type == "daily":
            if not scope.startswith("daily:"):
                raise OperationalFastCaptureEvidenceError(
                    "daily capture scope is invalid"
                )
        elif task_type == "settlement_capture":
            if scope != "current":
                raise OperationalFastCaptureEvidenceError(
                    "settlement capture scope is invalid"
                )
        else:
            raise OperationalFastCaptureEvidenceError(
                "job is not a supported business capture"
            )
        total = int(run["total"])
        fetched = int(run["next_item_index"])
        batch_size = int(run["batch_size"])
        batch_count = int(run["committed_batch_count"])
        expected_batches = max(1, math.ceil(total / batch_size))
        if (
            str(run["status"]) != "complete"
            or total != fetched
            or batch_size not in {15, 20, 50, 100}
            or batch_count != expected_batches
            or int(run["detail_concurrency"]) != 4
            or int(run["image_concurrency"]) != 6
        ):
            raise OperationalFastCaptureEvidenceError(
                "capture run is incomplete or uses another strategy"
            )
        items_json = str(run["items_json"])
        if hashlib.sha256(items_json.encode("utf-8")).hexdigest() != str(
            run["items_sha256"]
        ):
            raise OperationalFastCaptureEvidenceError(
                "frozen list hash is inconsistent"
            )
        items = json.loads(items_json)
        identities = [str(item["platform_waybill_id"]) for item in items]
        if len(items) != total or len(set(identities)) != total:
            raise OperationalFastCaptureEvidenceError(
                "frozen list count or identity set is inconsistent"
            )

        rows = tuple(
            connection.execute(
                "SELECT payload_json FROM checkpoints "
                "WHERE owner_kind = 'chengfeng_capture' AND job_id = ? "
                "ORDER BY sequence",
                (job_id,),
            )
        )
        if len(rows) != batch_count:
            raise OperationalFastCaptureEvidenceError(
                "capture checkpoint count is inconsistent"
            )
        captured_ids: list[str] = []
        image_hashes: list[str] = []
        missing_ticket_count = 0
        for batch_number, row in enumerate(rows, start=1):
            checkpoint = json.loads(str(row["payload_json"]))
            page = checkpoint.get("page")
            details = checkpoint.get("details")
            images = checkpoint.get("ticket_images")
            if (
                checkpoint.get("job_id") != job_id
                or checkpoint.get("scope") != scope
                or checkpoint.get("page_number") != batch_number
                or not isinstance(page, dict)
                or not isinstance(details, list)
                or not isinstance(images, dict)
                or len(page.get("items", [])) != len(details)
            ):
                raise OperationalFastCaptureEvidenceError(
                    "capture checkpoint shape is inconsistent"
                )
            expected_refs: set[str] = set()
            for detail in details:
                captured_ids.append(str(detail["platform_waybill_id"]))
                tickets = detail.get("tickets", [])
                slots = {str(ticket["slot"]) for ticket in tickets}
                missing_ticket_count += 2 - len(slots)
                expected_refs.update(str(ticket["ticket_ref"]) for ticket in tickets)
            if set(images) != expected_refs:
                raise OperationalFastCaptureEvidenceError(
                    "capture checkpoint image references are incomplete"
                )
            for image in images.values():
                path = _inside(data_root, str(image["relative_path"]))
                image_sha256 = str(image["sha256"])
                if (
                    path.stat().st_size != int(image["byte_size"])
                    or _sha256_file(path) != image_sha256
                ):
                    raise OperationalFastCaptureEvidenceError(
                        "content-addressed ticket image is inconsistent"
                    )
                image_hashes.append(image_sha256)
        if captured_ids != identities or len(set(captured_ids)) != total:
            raise OperationalFastCaptureEvidenceError(
                "captured detail identity order is inconsistent"
            )

        ocr: dict[str, object] | None = None
        if task_type == "daily":
            links = tuple(
                connection.execute(
                    "SELECT batch_number, ocr_job_id, eligible_item_count, "
                    "missing_ticket_count FROM daily_operational_ocr_batches "
                    "WHERE daily_job_id = ? ORDER BY batch_number",
                    (job_id,),
                )
            )
            if len(links) != batch_count:
                raise OperationalFastCaptureEvidenceError(
                    "daily OCR batch links are incomplete"
                )
            eligible = sum(int(link["eligible_item_count"]) for link in links)
            linked_missing = sum(int(link["missing_ticket_count"]) for link in links)
            ocr_job_ids = [str(link["ocr_job_id"]) for link in links if link["ocr_job_id"]]
            status_counts: dict[str, int] = {}
            if ocr_job_ids:
                placeholders = ",".join("?" for _ in ocr_job_ids)
                status_counts = {
                    str(row["status"]): int(row["count"])
                    for row in connection.execute(
                        f"SELECT status, COUNT(*) AS count FROM work_items "
                        f"WHERE job_id IN ({placeholders}) GROUP BY status",
                        tuple(ocr_job_ids),
                    )
                }
            recognized = status_counts.get("succeeded", 0)
            technical_failed = status_counts.get("failed", 0)
            if (
                eligible + linked_missing != total
                or recognized + technical_failed != eligible
            ):
                raise OperationalFastCaptureEvidenceError(
                    "daily OCR outcomes are not terminal and complete"
                )
            ocr = {
                "eligible": eligible,
                "missing_ticket": linked_missing,
                "recognized": recognized,
                "technical_failed": technical_failed,
            }

        started_at = datetime.fromisoformat(str(job["created_at"]))
        completed_at = datetime.fromisoformat(str(run["updated_at"]))
        duration_seconds = (completed_at - started_at).total_seconds()
        if duration_seconds <= 0:
            raise OperationalFastCaptureEvidenceError(
                "capture duration is invalid"
            )
        rate = total / (duration_seconds / 60)
        baseline_rate = _BASELINE_TOTAL / (_BASELINE_SECONDS / 60)
        speedup = rate / baseline_rate
        progress_points = batch_count + 1
        progress_limit = expected_batches + 5
        throughput_gate_applied = (
            task_type == "settlement_capture" and total >= batch_size
        )
        throughput_gate_reason = None
        if task_type == "daily":
            throughput_gate_reason = "daily_completeness_only"
        elif total < batch_size:
            throughput_gate_reason = "dynamic_total_below_one_batch"
        throughput_passed = (
            rate >= _MINIMUM_WAYBILLS_PER_MINUTE
            and speedup >= _MINIMUM_SPEEDUP
        )
        progress_passed = progress_points <= progress_limit
        performance_passed = progress_passed and (
            not throughput_gate_applied or throughput_passed
        )
        payload: dict[str, object] = {
            "schema_version": 1,
            "kind": "operational_fast_capture_evidence",
            "source_build_sha256": current_loop9_build_sha256(project_root),
            "job_id": job_id,
            "task_type": task_type,
            "scope": scope,
            "capture": {
                "dynamic_total": total,
                "fetched": fetched,
                "unique_identity_count": len(set(identities)),
                "identity_manifest_sha256": str(run["items_sha256"]),
                "committed_batch_count": batch_count,
                "batch_size": batch_size,
                "detail_concurrency": int(run["detail_concurrency"]),
                "image_concurrency": int(run["image_concurrency"]),
                "ticket_image_count": len(image_hashes),
                "ticket_image_manifest_sha256": hashlib.sha256(
                    _canonical(image_hashes)
                ).hexdigest(),
                "missing_ticket_count": missing_ticket_count,
            },
            "ocr": ocr,
            "performance": {
                "duration_seconds": round(duration_seconds, 6),
                "waybills_per_minute": round(rate, 6),
                "speedup_vs_44m31s_315_baseline": round(speedup, 6),
                "progress_point_count": progress_points,
                "progress_point_limit": progress_limit,
                "progress_gate_passed": progress_passed,
                "throughput_gate_applied": throughput_gate_applied,
                "throughput_gate_reason": throughput_gate_reason,
                "throughput_gate_passed": (
                    throughput_passed if throughput_gate_applied else None
                ),
                "gate_passed": performance_passed,
            },
        }
        if not performance_passed:
            raise OperationalFastCaptureEvidenceError(
                "capture performance gate did not pass"
            )
        return OperationalFastCaptureEvidence(payload=payload)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise OperationalFastCaptureEvidenceError(
            "capture evidence payload is invalid"
        ) from exc
    finally:
        connection.close()


def publish_operational_fast_capture_evidence(
    *,
    evidence: OperationalFastCaptureEvidence,
    output: Path,
) -> Path:
    output = Path(os.path.abspath(os.fspath(output)))
    if output.exists() or output.is_symlink():
        raise OperationalFastCaptureEvidenceError(
            "capture evidence output already exists"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(f".{output.name}.{os.getpid()}.partial")
    if staging.exists() or staging.is_symlink():
        raise OperationalFastCaptureEvidenceError(
            "capture evidence staging path already exists"
        )
    payload = {
        **evidence.payload,
        "canonical_sha256": evidence.canonical_sha256,
    }
    try:
        with staging.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if output.exists():
            raise OperationalFastCaptureEvidenceError(
                "capture evidence output appeared during publish"
            )
        staging.rename(output)
    except Exception:
        staging.unlink(missing_ok=True)
        raise
    return output


def replay_operational_fast_capture_evidence(
    *,
    project_root: Path,
    data_root: Path,
    path: Path,
) -> OperationalFastCaptureEvidence:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationalFastCaptureEvidenceError(
            "capture evidence is unreadable"
        ) from exc
    if not isinstance(document, dict):
        raise OperationalFastCaptureEvidenceError(
            "capture evidence is invalid"
        )
    canonical = document.pop("canonical_sha256", None)
    job_id = document.get("job_id")
    if not isinstance(job_id, str):
        raise OperationalFastCaptureEvidenceError(
            "capture evidence job identity is invalid"
        )
    rebuilt = build_operational_fast_capture_evidence(
        project_root=project_root,
        data_root=data_root,
        job_id=job_id,
    )
    if document != rebuilt.payload or canonical != rebuilt.canonical_sha256:
        raise OperationalFastCaptureEvidenceError(
            "capture evidence replay changed"
        )
    return rebuilt
