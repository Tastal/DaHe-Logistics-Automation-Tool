from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from dahe import __version__
from dahe.verification.batch_benchmark import (
    ALLOWED_NETWORK_BATCH_SIZES,
    NetworkBatchTrial,
    requires_third_trial,
    select_default_batch_size,
    summarize_trials,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
PRIMARY_SEQUENCE = (20, 50, 100, 100, 50, 20)
MAX_AUTOMATIC_RESUMES = 3
AUTOMATIC_RECOVERY_COOLDOWN_SECONDS = 30.0


class LocalApiError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class NetworkBatchFailure:
    batch_size: int
    elapsed_seconds: float
    job_id: str
    reason: str
    safe_stop_status: str


class NetworkTrialFailed(LocalApiError):
    def __init__(self, failure: NetworkBatchFailure) -> None:
        super().__init__(failure.reason)
        self.failure = failure


class LocalApiClient:
    def __init__(self, base_url: str) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise ValueError("base_url must use loopback HTTP")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("base_url must not include a path, query, or fragment")
        self.base_url = base_url.rstrip("/")
        self.origin = self.base_url
        self._cookies = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookies)
        )
        session = self.request(
            "GET",
            "/api/v1/session",
            extra_headers={"Sec-Fetch-Site": "none"},
        )
        csrf = session.get("csrf_token")
        if not isinstance(csrf, str) or not csrf:
            raise LocalApiError("local session did not provide a CSRF token")
        if session.get("application_version") != __version__:
            raise LocalApiError("local application version does not match this build")
        self._csrf_token = csrf

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        idempotency_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
        timeout: float = 30,
    ) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "X-DaHe-Client-Version": __version__,
        }
        if extra_headers:
            headers.update(extra_headers)
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if method != "GET":
            headers.update(
                {
                    "Origin": self.origin,
                    "X-CSRF-Token": self._csrf_token,
                    "Idempotency-Key": idempotency_key or str(uuid4()),
                }
            )
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                decoded = json.load(response)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise LocalApiError(
                f"local API {method} {path} failed with HTTP {exc.code}: {body}"
            ) from exc
        except (OSError, ValueError) as exc:
            raise LocalApiError(f"local API {method} {path} failed") from exc
        if not isinstance(decoded, dict):
            raise LocalApiError(f"local API {method} {path} returned a non-object")
        return cast(dict[str, Any], decoded)


def _percentile_95(samples: list[float]) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1))
    return ordered[index]


def _save_settings(
    client: LocalApiClient,
    current: dict[str, Any],
    *,
    batch_size: int,
) -> dict[str, Any]:
    payload = {
        "preset": current["preset"],
        "detail_concurrency": current["detail_concurrency"],
        "image_concurrency": current["image_concurrency"],
        "cpu_ocr_threads": current["cpu_ocr_threads"],
        "gpu_idle_minutes": current["gpu_idle_minutes"],
        "keep_gpu_ready": current["keep_gpu_ready"],
        "network_batch_size": batch_size,
        "expected_record_version": current["record_version"],
    }
    return client.request(
        "PUT",
        "/api/v1/settings/performance",
        payload=payload,
    )


def _job_record_version(job: object) -> int:
    if not isinstance(job, dict):
        raise LocalApiError("business-read response is missing its job")
    value = job.get("record_version")
    if not isinstance(value, int) or value < 0:
        raise LocalApiError("business-read response has an invalid record version")
    return value


def _safe_automatic_recovery_allowed(
    job: object,
    *,
    automatic_recoveries: int,
) -> bool:
    """Allow only the official business-read login recovery path."""
    return bool(
        automatic_recoveries < MAX_AUTOMATIC_RESUMES
        and isinstance(job, dict)
        and job.get("job_status") in {"paused", "waiting_external"}
        and job.get("diagnostic_code")
        in {"CF-BROWSER-CLOSED", "CF-DAILY-LOGIN-REQUIRED"}
        and job.get("waiting_reason") == "access_window_expired"
    )


def _failure_reason(error: LocalApiError) -> str:
    message = str(error)
    for token in message.replace("(", " ").replace(")", " ").split():
        candidate = token.strip(".,:;")
        if candidate.startswith("CF-") and all(
            character.isupper() or character.isdigit() or character in {"-", "_"}
            for character in candidate
        ):
            return candidate
    if "timed out" in message:
        return "trial_timeout"
    if "paused outside" in message:
        return "unsafe_pause"
    return "local_api_error"


def _attempt_safe_stop(
    client: LocalApiClient,
    *,
    job_id: str,
    deadline: float,
) -> str:
    try:
        projected_job = client.request(
            "GET", f"/api/v1/jobs/{urllib.parse.quote(job_id)}"
        )
        current_status = projected_job.get("job_status")
        if current_status in {"cancelled", "failed", "succeeded"}:
            return str(current_status)
        actions = projected_job.get("actions")
        cancel_action = actions.get("cancel") if isinstance(actions, dict) else None
        if not isinstance(cancel_action, dict) or cancel_action.get("enabled") is not True:
            return "cancel_unavailable"
        client.request(
            "POST",
            f"/api/v1/jobs/{urllib.parse.quote(job_id)}/cancel",
            payload={"expected_record_version": _job_record_version(projected_job)},
        )
        stop_deadline = min(deadline, time.monotonic() + 30.0)
        while time.monotonic() < stop_deadline:
            projected_job = client.request(
                "GET", f"/api/v1/jobs/{urllib.parse.quote(job_id)}"
            )
            current_status = projected_job.get("job_status")
            if current_status in {"cancelled", "failed", "succeeded"}:
                return str(current_status)
            time.sleep(0.2)
        return "cancel_timeout"
    except LocalApiError:
        return "cancel_request_failed"


def _run_trial(
    client: LocalApiClient,
    *,
    business_date: date,
    batch_size: int,
    timeout_seconds: float,
) -> NetworkBatchTrial:
    started = client.request(
        "POST",
        "/api/v1/platform/business-reads",
        payload={
            "business_scope": "daily",
            "business_date": business_date.isoformat(),
            "network_only_measurement": True,
            "expected_record_version": 0,
        },
    )
    job = started.get("job")
    if not isinstance(job, dict) or not isinstance(job.get("job_id"), str):
        raise LocalApiError("business-read response is missing its job id")
    job_id = job["job_id"]
    deadline = time.monotonic() + timeout_seconds
    started_at = time.perf_counter()
    response_samples: list[float] = []
    final_progress: dict[str, Any] | None = None
    automatic_recoveries = 0
    last_recovery_requested_at: float | None = None
    try:
        while time.monotonic() < deadline:
            projected_job = client.request(
                "GET", f"/api/v1/jobs/{urllib.parse.quote(job_id)}"
            )
            job_status = projected_job.get("job_status")
            if job_status == "failed":
                diagnostic_code = projected_job.get("diagnostic_code")
                raise LocalApiError(
                    f"daily network trial {job_id} failed ({diagnostic_code})"
                )
            if job_status in {"paused", "waiting_external"}:
                if not _safe_automatic_recovery_allowed(
                    projected_job,
                    automatic_recoveries=automatic_recoveries,
                ):
                    diagnostic_code = projected_job.get("diagnostic_code")
                    waiting_reason = projected_job.get("waiting_reason")
                    raise LocalApiError(
                        "daily network trial paused outside the safe benchmark "
                        f"handoff ({diagnostic_code}, {waiting_reason})"
                    )
                now = time.monotonic()
                if (
                    last_recovery_requested_at is None
                    or now - last_recovery_requested_at
                    >= AUTOMATIC_RECOVERY_COOLDOWN_SECONDS
                ):
                    attached = client.request(
                        "POST",
                        "/api/v1/platform/business-reads",
                        payload={
                            "business_scope": "daily",
                            "business_date": business_date.isoformat(),
                            "network_only_measurement": True,
                            "expected_record_version": 0,
                        },
                    )
                    attached_job = attached.get("job")
                    if (
                        not isinstance(attached_job, dict)
                        or attached_job.get("job_id") != job_id
                    ):
                        raise LocalApiError(
                            "automatic login recovery attached to another job"
                        )
                    automatic_recoveries += 1
                    last_recovery_requested_at = now
                time.sleep(0.4)
                continue
            request_started = time.perf_counter()
            progress = client.request(
                "GET",
                f"/api/v1/platform/business-reads/{urllib.parse.quote(job_id)}/progress",
            )
            response_samples.append(time.perf_counter() - request_started)
            phase = progress.get("phase")
            if phase == "incomplete":
                raise LocalApiError(f"daily network trial {job_id} became incomplete")
            total = progress.get("total")
            fetched = progress.get("fetched")
            if (
                isinstance(total, int)
                and total > 0
                and isinstance(fetched, int)
                and fetched >= total
            ):
                final_progress = progress
                break
            time.sleep(0.4)
        if final_progress is None:
            raise LocalApiError(f"daily network trial {job_id} timed out")
    except LocalApiError as exc:
        elapsed = time.perf_counter() - started_at
        safe_stop_status = _attempt_safe_stop(
            client,
            job_id=job_id,
            deadline=deadline,
        )
        raise NetworkTrialFailed(
            NetworkBatchFailure(
                batch_size=batch_size,
                elapsed_seconds=elapsed,
                job_id=job_id,
                reason=_failure_reason(exc),
                safe_stop_status=safe_stop_status,
            )
        ) from exc
    elapsed = time.perf_counter() - started_at

    stop_status = _attempt_safe_stop(client, job_id=job_id, deadline=deadline)
    if stop_status not in {"cancelled", "failed", "succeeded"}:
        raise LocalApiError(
            f"daily network trial {job_id} did not reach a safe stop ({stop_status})"
        )

    total = cast(int, final_progress["total"])
    committed_batches = final_progress.get("committed_batches", 0)
    return NetworkBatchTrial(
        batch_size=batch_size,
        elapsed_seconds=elapsed,
        waybill_count=total,
        ui_response_p95_seconds=_percentile_95(response_samples),
        retries=automatic_recoveries,
        committed_batches=(
            committed_batches if isinstance(committed_batches, int) else 0
        ),
    )


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark read-only daily network commit sizes against a local DaHe service."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8877")
    parser.add_argument("--business-date", required=True, type=date.fromisoformat)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--trial-timeout-minutes", type=int, default=30)
    return parser


def main() -> None:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit(f"Use the project interpreter: {EXPECTED_PYTHON}")
    arguments = _parser().parse_args()
    output = arguments.output
    if not output.is_absolute():
        raise SystemExit("--output must be absolute")
    if arguments.trial_timeout_minutes < 1 or arguments.trial_timeout_minutes > 120:
        raise SystemExit("--trial-timeout-minutes must be between 1 and 120")

    client = LocalApiClient(arguments.base_url)
    original = client.request("GET", "/api/v1/settings/performance")
    current = original
    trials: dict[int, list[NetworkBatchTrial]] = {
        batch_size: [] for batch_size in ALLOWED_NETWORK_BATCH_SIZES
    }
    failures: dict[int, list[NetworkBatchFailure]] = {
        batch_size: [] for batch_size in ALLOWED_NETWORK_BATCH_SIZES
    }
    run_order: list[int] = []
    try:
        for batch_size in PRIMARY_SEQUENCE:
            current = _save_settings(client, current, batch_size=batch_size)
            run_order.append(batch_size)
            try:
                trial = _run_trial(
                    client,
                    business_date=arguments.business_date,
                    batch_size=batch_size,
                    timeout_seconds=arguments.trial_timeout_minutes * 60,
                )
            except NetworkTrialFailed as exc:
                failures[batch_size].append(exc.failure)
            else:
                trials[batch_size].append(trial)
        for batch_size in ALLOWED_NETWORK_BATCH_SIZES:
            pair = tuple(trials[batch_size])
            if not failures[batch_size] and requires_third_trial(pair):
                current = _save_settings(client, current, batch_size=batch_size)
                run_order.append(batch_size)
                try:
                    trial = _run_trial(
                        client,
                        business_date=arguments.business_date,
                        batch_size=batch_size,
                        timeout_seconds=arguments.trial_timeout_minutes * 60,
                    )
                except NetworkTrialFailed as exc:
                    failures[batch_size].append(exc.failure)
                else:
                    trials[batch_size].append(trial)
        summaries = tuple(
            summarize_trials(tuple(trials[batch_size]))
            for batch_size in ALLOWED_NETWORK_BATCH_SIZES
            if len(trials[batch_size]) >= 2 and not failures[batch_size]
        )
        ineligible_batch_sizes = frozenset(
            batch_size
            for batch_size in ALLOWED_NETWORK_BATCH_SIZES
            if len(trials[batch_size]) < 2 or failures[batch_size]
        )
        selected = select_default_batch_size(
            summaries,
            ineligible_batch_sizes=ineligible_batch_sizes,
        )
    finally:
        latest = client.request("GET", "/api/v1/settings/performance")
        _save_settings(
            client,
            latest,
            batch_size=int(original["network_batch_size"]),
        )

    payload: dict[str, object] = {
        "schema_version": 2,
        "created_at": datetime.now(UTC).isoformat(),
        "business_date": arguments.business_date.isoformat(),
        "base_url": arguments.base_url,
        "run_order": run_order,
        "trials": {
            str(size): [asdict(trial) for trial in trials[size]]
            for size in ALLOWED_NETWORK_BATCH_SIZES
        },
        "failures": {
            str(size): [asdict(failure) for failure in failures[size]]
            for size in ALLOWED_NETWORK_BATCH_SIZES
        },
        "ineligible_batch_sizes": sorted(ineligible_batch_sizes),
        "summaries": [asdict(summary) for summary in summaries],
        "selected_default_batch_size": selected,
        "ui_response_p95_gate_seconds": 0.5,
        "network_only_measurement": True,
        "job_cancelled_after_network_commit": True,
    }
    _atomic_write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
