from __future__ import annotations

import io
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import zipfile
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dahe.diagnostics.breadcrumbs import BreadcrumbStore
from dahe.diagnostics.runtime_log import redact_runtime_text
from dahe.release.identity import ReleaseIdentity

MAX_BUNDLE_BYTES = 20 * 1024 * 1024


def _runtime_version(runtime_root: Path) -> str | None:
    active = runtime_root / "active-composition.json"
    try:
        payload = json.loads(active.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        generation = payload.get("generation_id")
        if isinstance(generation, str) and generation:
            return generation

    installation = runtime_root / "runtime-installation.json"
    try:
        payload = json.loads(installation.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("runtime_kind") != "browser":
        return None
    selected_browser = payload.get("smoke_selected_browser")
    worker_sha256 = payload.get("worker_source_sha256")
    packages = payload.get("packages")
    if (
        selected_browser not in {"chromium", "msedge"}
        or not isinstance(worker_sha256, str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", worker_sha256) is None
        or not isinstance(packages, list)
    ):
        return None
    playwright_versions = [
        package.removeprefix("playwright==")
        for package in packages
        if isinstance(package, str) and package.startswith("playwright==")
    ]
    if len(playwright_versions) != 1 or re.fullmatch(
        r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", playwright_versions[0]
    ) is None:
        return None
    return (
        f"{selected_browser}; playwright={playwright_versions[0]}; "
        f"worker={worker_sha256.lower()}"
    )


def _gpu_snapshot() -> dict[str, object]:
    try:
        completed = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,driver_version",
                "--format=csv,noheader",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "device_count": 0}
    devices = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    return {
        "available": completed.returncode == 0 and bool(devices),
        "device_count": len(devices),
        "devices": devices[:8],
    }


def environment_snapshot(
    *,
    data_root: Path,
    identity: ReleaseIdentity,
    schema_revision: str,
    browser_runtime_root: Path,
    ocr_runtime_root: Path,
) -> dict[str, object]:
    database_path = data_root / "database" / "dahe.sqlite3"
    database_integrity = "missing"
    if database_path.is_file():
        try:
            with closing(
                sqlite3.connect(
                    f"{database_path.resolve().as_uri()}?mode=ro",
                    uri=True,
                )
            ) as database:
                database_integrity = str(
                    database.execute("PRAGMA integrity_check").fetchone()[0]
                )
        except sqlite3.DatabaseError:
            database_integrity = "unreadable"
    disk = shutil.disk_usage(data_root)
    return {
        "application": {
            "version": identity.application_version,
            "commit": identity.build_git_commit,
            "resource_sha256": identity.resource_sha256,
        },
        "windows": {
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
        },
        "database": {
            "schema_revision": schema_revision,
            "integrity": database_integrity,
        },
        "runtime": {
            "edge_worker": _runtime_version(browser_runtime_root),
            "ocr_cpu": _runtime_version(ocr_runtime_root),
        },
        "resources": {
            "disk_free_bytes": disk.free,
            "cpu_count": os.cpu_count(),
            "gpu": _gpu_snapshot(),
        },
    }


def _recent_log_content(
    log_root: Path,
    budget: int,
    *,
    now: datetime | None = None,
    retention: timedelta = timedelta(days=7),
) -> bytes:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("diagnostic log cutoff must include a timezone")
    current = current.astimezone(UTC)
    cutoff = current - retention
    files = sorted(
        (path for path in log_root.glob("*.jsonl") if path.is_file()),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    safe_lines: list[bytes] = []
    selected_bytes = 0
    for path in files:
        for line in reversed(path.read_bytes().splitlines()):
            try:
                source = json.loads(line)
                if not isinstance(source, dict):
                    continue
                created_at = datetime.fromisoformat(str(source.get("created_at", "")))
                if created_at.tzinfo is None:
                    continue
                created_at = created_at.astimezone(UTC)
                if created_at < cutoff or created_at > current:
                    continue
                safe = {
                    "event_id": str(source.get("event_id", ""))[:32],
                    "created_at": str(source.get("created_at", ""))[:40],
                    "level": str(source.get("level", "info"))[:10],
                    "source": str(source.get("source", "application"))[:80],
                    "event_code": str(source.get("event_code", "runtime_event"))[:100],
                    "stream": str(source.get("stream", "application"))[:20],
                    "message": redact_runtime_text(str(source.get("message", ""))),
                    "diagnostic_code": source.get("diagnostic_code"),
                    "job_id": source.get("job_id"),
                }
                encoded = (
                    json.dumps(safe, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8")
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
            if selected_bytes + len(encoded) > budget:
                return b"".join(reversed(safe_lines))
            safe_lines.append(encoded)
            selected_bytes += len(encoded)
    return b"".join(reversed(safe_lines))


def build_support_bundle(
    *,
    data_root: Path,
    snapshot: dict[str, object],
    breadcrumbs: BreadcrumbStore,
    maximum_bytes: int = MAX_BUNDLE_BYTES,
    now: datetime | None = None,
) -> bytes:
    environment = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")
    breadcrumb_content = breadcrumbs.export(maximum_bytes=2 * 1024 * 1024)
    fixed_overhead = len(environment) + len(breadcrumb_content) + 512 * 1024
    log_budget = max(0, maximum_bytes - fixed_overhead)
    logs = _recent_log_content(data_root / "logs", log_budget, now=now)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("environment.json", environment)
        bundle.writestr("breadcrumbs.jsonl", breadcrumb_content)
        bundle.writestr("runtime-logs.jsonl", logs)
        bundle.writestr(
            "README.txt",
            (
                "This local diagnostic package excludes databases, images, "
                "browser profiles, credentials, platform responses, and OCR text.\n"
            ),
        )
    content = output.getvalue()
    if len(content) > maximum_bytes:
        raise ValueError("diagnostic package exceeded its maximum size")
    return content
