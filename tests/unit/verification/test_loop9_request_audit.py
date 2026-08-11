from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dahe.verification.loop9_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditError,
    PlatformReadAuditEvidenceStore,
)

BUILD_SHA = "a" * 64
CONTRACT_SHA = "b" * 64
SELECTION_SHA = "e" * 64
DAILY_CONTRACT_SHA = "f" * 64
DAILY_SELECTION_SHA = "1" * 64
SETTLEMENT_AUTHORITY = PlatformReadAuditAuthority(
    build_sha256=BUILD_SHA,
    settlement_contract_sha256=CONTRACT_SHA,
    settlement_contract_selection_sha256=SELECTION_SHA,
)
DAILY_AUTHORITY = PlatformReadAuditAuthority(
    build_sha256=BUILD_SHA,
    settlement_contract_sha256=CONTRACT_SHA,
    settlement_contract_selection_sha256=SELECTION_SHA,
    daily_contract_sha256=DAILY_CONTRACT_SHA,
    daily_contract_selection_sha256=DAILY_SELECTION_SHA,
)


class _Clock:
    def __init__(self) -> None:
        self.current = datetime(2026, 7, 30, 8, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        value = self.current
        self.current += timedelta(milliseconds=1)
        return value


def _successful_request(
    store: PlatformReadAuditEvidenceStore,
    *,
    job_id: str,
    operation: str,
) -> None:
    token = store.attempt(
        job_id=job_id,
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation=operation,
    )
    store.allowed(token)
    store.succeeded(token)


def test_seals_and_deep_replays_content_addressed_per_job_audit(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    store = PlatformReadAuditEvidenceStore(tmp_path, clock=clock)
    _successful_request(store, job_id="job-locked-50", operation="list_waybills")
    for _ in range(2):
        _successful_request(
            store,
            job_id="job-locked-50",
            operation="get_waybill_detail",
        )
    for _ in range(4):
        _successful_request(
            store,
            job_id="job-locked-50",
            operation="download_ticket_image",
        )

    evidence = store.seal(
        job_id="job-locked-50",
        authority=SETTLEMENT_AUTHORITY,
        purpose="current_locked_50",
        expected_succeeded_operations={
            "list_waybills": 1,
            "get_waybill_detail": 2,
            "download_ticket_image": 4,
        },
    )

    assert evidence.request_counts.to_payload() == {
        "allowed": 7,
        "attempted": 7,
        "denied": 0,
        "succeeded": 7,
    }
    assert evidence.operation_counts["get_waybill_detail"].succeeded == 2
    assert evidence.platform_write_request_count == 0
    assert evidence.redirect_count == 0
    assert store.path_for(evidence.canonical_sha256).relative_to(tmp_path) == Path(
        "platform-request-audit",
        "evidence",
        "sha256",
        evidence.canonical_sha256[:2],
        evidence.canonical_sha256[2:4],
        f"{evidence.canonical_sha256}.json",
    )
    replayed = store.load(
        evidence.canonical_sha256,
        expected_job_id="job-locked-50",
        expected_authority=SETTLEMENT_AUTHORITY,
    )
    assert replayed == evidence


def test_denied_unknown_operation_is_persisted_and_blocks_seal(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path, clock=_Clock())
    token = store.attempt(
        job_id="job-denied",
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation="confirm_settlement",
    )
    store.denied(token)

    with pytest.raises(PlatformReadAuditError, match="not clean"):
        store.seal(
            job_id="job-denied",
            authority=SETTLEMENT_AUTHORITY,
            purpose="real_shadow_30",
            expected_succeeded_operations={},
        )

    serialized = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "platform-request-audit" / "events").rglob(
            "*.json"
        )
    )
    assert "confirm_settlement" not in serialized
    assert '"operation":"unsafe_operation"' in serialized


def test_redirect_and_expected_operation_mismatch_block_seal(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path, clock=_Clock())
    token = store.attempt(
        job_id="job-redirect",
        build_sha256=BUILD_SHA,
        contract_sha256=DAILY_CONTRACT_SHA,
        contract_selection_sha256=DAILY_SELECTION_SHA,
        operation="list_daily_waybills",
    )
    store.allowed(token)
    store.redirected(token)

    with pytest.raises(PlatformReadAuditError, match="not clean"):
        store.seal(
            job_id="job-redirect",
            authority=DAILY_AUTHORITY,
            purpose="daily_snapshot",
            expected_succeeded_operations={"list_daily_waybills": 1},
        )

    clean = PlatformReadAuditEvidenceStore(
        tmp_path / "other",
        clock=_Clock(),
    )
    _successful_request(
        clean,
        job_id="job-mismatch",
        operation="list_waybills",
    )
    with pytest.raises(PlatformReadAuditError, match="operation counts"):
        clean.seal(
            job_id="job-mismatch",
            authority=SETTLEMENT_AUTHORITY,
            purpose="current_locked_50",
            expected_succeeded_operations={
                "list_waybills": 1,
                "get_waybill_detail": 1,
            },
        )


def test_restart_recovers_incomplete_attempt_as_failed_without_losing_history(
    tmp_path: Path,
) -> None:
    first = PlatformReadAuditEvidenceStore(tmp_path, clock=_Clock())
    token = first.attempt(
        job_id="job-restart",
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation="list_waybills",
    )
    first.allowed(token)

    restarted = PlatformReadAuditEvidenceStore(tmp_path, clock=_Clock())
    assert restarted.recover_incomplete(
        job_id="job-restart",
        build_sha256=BUILD_SHA,
    ) == 1
    _successful_request(
        restarted,
        job_id="job-restart",
        operation="list_waybills",
    )
    evidence = restarted.seal(
        job_id="job-restart",
        authority=SETTLEMENT_AUTHORITY,
        purpose="current_locked_50",
        expected_succeeded_operations={"list_waybills": 1},
    )

    assert evidence.operation_counts["list_waybills"].attempted == 2
    assert evidence.operation_counts["list_waybills"].allowed == 2
    assert evidence.operation_counts["list_waybills"].failed == 1
    assert evidence.operation_counts["list_waybills"].succeeded == 1


def test_tampered_event_or_evidence_fails_deep_replay(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path, clock=_Clock())
    _successful_request(store, job_id="job-tamper", operation="list_waybills")
    evidence = store.seal(
        job_id="job-tamper",
        authority=SETTLEMENT_AUTHORITY,
        purpose="current_locked_50",
        expected_succeeded_operations={"list_waybills": 1},
    )

    event = next(
        (tmp_path / "platform-request-audit" / "events").rglob("*.json")
    )
    payload = json.loads(event.read_text(encoding="utf-8"))
    payload["phase"] = "denied"
    event.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PlatformReadAuditError):
        store.load(
            evidence.canonical_sha256,
            expected_job_id="job-tamper",
            expected_authority=SETTLEMENT_AUTHORITY,
        )


def test_audit_files_never_retain_url_identifiers_or_ocr_text(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path, clock=_Clock())
    sensitive = (
        "https://pc.chengfengkuaiyun.com/private?id=900000001"
        "&signature=secret OCR正文"
    )
    token = store.attempt(
        job_id="job-private",
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation="download_ticket_image",
        request_material=sensitive,
    )
    store.allowed(token)
    store.succeeded(token)
    evidence = store.seal(
        job_id="job-private",
        authority=SETTLEMENT_AUTHORITY,
        purpose="real_shadow_30",
        expected_succeeded_operations={"download_ticket_image": 1},
    )

    serialized = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "platform-request-audit").rglob("*.json")
    )
    assert evidence.canonical_sha256 in serialized
    for forbidden in (
        "https://",
        "900000001",
        "signature",
        "secret",
        "OCR正文",
    ):
        assert forbidden not in serialized


def test_concurrent_store_instances_append_without_losing_events(
    tmp_path: Path,
) -> None:
    stores = (
        PlatformReadAuditEvidenceStore(tmp_path),
        PlatformReadAuditEvidenceStore(tmp_path),
    )

    def record(index: int) -> None:
        _successful_request(
            stores[index % 2],
            job_id="job-concurrent",
            operation="download_ticket_image",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record, range(20)))

    evidence = stores[0].seal(
        job_id="job-concurrent",
        authority=SETTLEMENT_AUTHORITY,
        purpose="real_shadow_30",
        expected_succeeded_operations={"download_ticket_image": 20},
    )
    assert evidence.request_counts.succeeded == 20
    assert evidence.event_count == 60


def test_duplicate_phase_is_rejected_without_changing_counts(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path)
    token = store.attempt(
        job_id="job-duplicate-phase",
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation="list_waybills",
    )
    store.allowed(token)
    with pytest.raises(PlatformReadAuditError, match="transition"):
        store.allowed(token)
    store.succeeded(token)
    with pytest.raises(PlatformReadAuditError, match="transition"):
        store.succeeded(token)

    evidence = store.seal(
        job_id="job-duplicate-phase",
        authority=SETTLEMENT_AUTHORITY,
        purpose="current_locked_50",
        expected_succeeded_operations={"list_waybills": 1},
    )
    assert evidence.event_count == 3


def test_seal_rejects_inflight_request_and_blocks_post_seal_append(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path)
    token = store.attempt(
        job_id="job-seal-race",
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation="list_waybills",
    )
    store.allowed(token)
    with pytest.raises(PlatformReadAuditError, match="incomplete"):
        store.seal(
            job_id="job-seal-race",
            authority=SETTLEMENT_AUTHORITY,
            purpose="current_locked_50",
            expected_succeeded_operations={"list_waybills": 1},
        )
    store.succeeded(token)
    store.seal(
        job_id="job-seal-race",
        authority=SETTLEMENT_AUTHORITY,
        purpose="current_locked_50",
        expected_succeeded_operations={"list_waybills": 1},
    )

    with pytest.raises(PlatformReadAuditError, match="sealed"):
        store.attempt(
            job_id="job-seal-race",
            build_sha256=BUILD_SHA,
            contract_sha256=CONTRACT_SHA,
            contract_selection_sha256=SELECTION_SHA,
            operation="list_waybills",
        )


@pytest.mark.parametrize(
    ("other_job", "other_build", "other_contract"),
    (
        ("job-authority-other", BUILD_SHA, CONTRACT_SHA),
        ("job-authority", "c" * 64, CONTRACT_SHA),
        ("job-authority", BUILD_SHA, "d" * 64),
    ),
)
def test_job_build_and_contract_authorities_cannot_be_mixed(
    tmp_path: Path,
    other_job: str,
    other_build: str,
    other_contract: str,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path)
    _successful_request(
        store,
        job_id="job-authority",
        operation="list_waybills",
    )
    if other_job == "job-authority":
        with pytest.raises(PlatformReadAuditError, match="chain"):
            store.attempt(
                job_id=other_job,
                build_sha256=other_build,
                contract_sha256=other_contract,
                contract_selection_sha256=SELECTION_SHA,
                operation="list_waybills",
            )
    else:
        _successful_request(
            store,
            job_id=other_job,
            operation="list_waybills",
        )
        evidence = store.seal(
            job_id=other_job,
            authority=PlatformReadAuditAuthority(
                build_sha256=other_build,
                settlement_contract_sha256=other_contract,
                settlement_contract_selection_sha256=SELECTION_SHA,
            ),
            purpose="real_shadow_30",
            expected_succeeded_operations={"list_waybills": 1},
        )
        assert evidence.job_id_sha256 != store.job_id_sha256(
            "job-authority"
        )


@pytest.mark.parametrize("tamper_kind", ("delete", "reorder"))
def test_deleted_or_reordered_event_chain_cannot_be_replayed(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path)
    _successful_request(
        store,
        job_id="job-chain-tamper",
        operation="list_waybills",
    )
    evidence = store.seal(
        job_id="job-chain-tamper",
        authority=SETTLEMENT_AUTHORITY,
        purpose="current_locked_50",
        expected_succeeded_operations={"list_waybills": 1},
    )
    event_paths = sorted(
        (tmp_path / "platform-request-audit" / "events").rglob("*.json")
    )
    if tamper_kind == "delete":
        event_paths[1].unlink()
    else:
        first = event_paths[0]
        first.rename(
            first.with_name("99999999-" + first.name.split("-", 1)[1])
        )

    with pytest.raises(PlatformReadAuditError, match="chain"):
        store.load(
            evidence.canonical_sha256,
            expected_job_id="job-chain-tamper",
            expected_authority=SETTLEMENT_AUTHORITY,
        )


def test_failed_attempt_can_be_retried_and_only_successes_are_expected(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path)
    failed = store.attempt(
        job_id="job-retry",
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation="get_waybill_detail",
    )
    store.allowed(failed)
    store.failed(failed)
    _successful_request(
        store,
        job_id="job-retry",
        operation="get_waybill_detail",
    )

    evidence = store.seal(
        job_id="job-retry",
        authority=SETTLEMENT_AUTHORITY,
        purpose="real_shadow_30",
        expected_succeeded_operations={"get_waybill_detail": 1},
    )
    counts = evidence.operation_counts["get_waybill_detail"]
    assert (counts.attempted, counts.failed, counts.succeeded) == (2, 1, 1)


def test_new_process_recovers_request_left_open_by_exited_process(
    tmp_path: Path,
) -> None:
    script = """
from pathlib import Path
from dahe.verification.loop9_request_audit import PlatformReadAuditEvidenceStore
store = PlatformReadAuditEvidenceStore(Path(__import__("sys").argv[1]))
token = store.attempt(
    job_id="job-process-restart",
    build_sha256="a" * 64,
    contract_sha256="b" * 64,
    contract_selection_sha256="e" * 64,
    operation="list_waybills",
)
store.allowed(token)
"""
    subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    restarted = PlatformReadAuditEvidenceStore(tmp_path)
    assert restarted.recover_incomplete(
        job_id="job-process-restart",
        build_sha256=BUILD_SHA,
    ) == 1
    _successful_request(
        restarted,
        job_id="job-process-restart",
        operation="list_waybills",
    )
    evidence = restarted.seal(
        job_id="job-process-restart",
        authority=SETTLEMENT_AUTHORITY,
        purpose="current_locked_50",
        expected_succeeded_operations={"list_waybills": 1},
    )
    assert evidence.operation_counts["list_waybills"].failed == 1


def test_daily_audit_binds_operations_to_two_distinct_contracts(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path)
    daily = store.attempt(
        job_id="job-daily-dual-contract",
        build_sha256=BUILD_SHA,
        contract_sha256=DAILY_CONTRACT_SHA,
        contract_selection_sha256=DAILY_SELECTION_SHA,
        operation="list_daily_waybills",
    )
    store.allowed(daily)
    store.succeeded(daily)
    _successful_request(
        store,
        job_id="job-daily-dual-contract",
        operation="get_waybill_detail",
    )
    _successful_request(
        store,
        job_id="job-daily-dual-contract",
        operation="download_ticket_image",
    )

    evidence = store.seal(
        job_id="job-daily-dual-contract",
        authority=DAILY_AUTHORITY,
        purpose="daily_snapshot",
        expected_succeeded_operations={
            "list_daily_waybills": 1,
            "get_waybill_detail": 1,
            "download_ticket_image": 1,
        },
    )
    assert evidence.authority == DAILY_AUTHORITY


def test_wrong_operation_contract_or_daily_binding_for_shadow_is_rejected(
    tmp_path: Path,
) -> None:
    store = PlatformReadAuditEvidenceStore(tmp_path)
    wrong_daily = store.attempt(
        job_id="job-wrong-operation-contract",
        build_sha256=BUILD_SHA,
        contract_sha256=CONTRACT_SHA,
        contract_selection_sha256=SELECTION_SHA,
        operation="list_daily_waybills",
    )
    store.allowed(wrong_daily)
    store.succeeded(wrong_daily)
    with pytest.raises(PlatformReadAuditError, match="operation contract"):
        store.seal(
            job_id="job-wrong-operation-contract",
            authority=DAILY_AUTHORITY,
            purpose="daily_snapshot",
            expected_succeeded_operations={"list_daily_waybills": 1},
        )

    shadow = PlatformReadAuditEvidenceStore(tmp_path / "shadow")
    _successful_request(
        shadow,
        job_id="job-shadow-no-daily",
        operation="list_waybills",
    )
    with pytest.raises(PlatformReadAuditError, match="cannot bind a daily"):
        shadow.seal(
            job_id="job-shadow-no-daily",
            authority=DAILY_AUTHORITY,
            purpose="real_shadow_30",
            expected_succeeded_operations={"list_waybills": 1},
        )


def test_concurrent_processes_share_one_non_overwriting_event_chain(
    tmp_path: Path,
) -> None:
    script = """
from pathlib import Path
from dahe.verification.loop9_request_audit import PlatformReadAuditEvidenceStore
store = PlatformReadAuditEvidenceStore(Path(__import__("sys").argv[1]))
for _ in range(3):
    token = store.attempt(
        job_id="job-process-concurrent",
        build_sha256="a" * 64,
        contract_sha256="b" * 64,
        contract_selection_sha256="e" * 64,
        operation="download_ticket_image",
    )
    store.allowed(token)
    store.succeeded(token)
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(tmp_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, (stdout, stderr)

    store = PlatformReadAuditEvidenceStore(tmp_path)
    evidence = store.seal(
        job_id="job-process-concurrent",
        authority=SETTLEMENT_AUTHORITY,
        purpose="real_shadow_30",
        expected_succeeded_operations={"download_ticket_image": 12},
    )
    assert evidence.event_count == 36
