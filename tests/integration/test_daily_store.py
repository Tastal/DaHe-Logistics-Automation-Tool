from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import text

from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditEvidenceStore,
)
from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationAuthority,
)
from dahe.adapters.sqlite.daily_store import (
    DailyStoreConflictError,
    SqliteDailyStore,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.daily.capture import (
    DailyCaptureCheckpoint,
    DailyCaptureRequest,
)
from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyWaybillObservation,
)
from dahe.ports.daily import (
    DailyDetailCaptureState,
    DailyTicketSlotCapture,
    DailyWaybillPage,
    DailyWaybillSummary,
)

PROJECT_ROOT = Path(__file__).parents[2]
HASH_A = hashlib.sha256(b"contract").hexdigest()
HASH_B = hashlib.sha256(b"loading").hexdigest()
HASH_C = hashlib.sha256(b"detail").hexdigest()


def _runtime(tmp_path: Path) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="daily-store-test",
    )


def _snapshot(*, snapshot_id: str = "snapshot-1") -> DailyCandidateSnapshot:
    captured_at = datetime(2026, 7, 29, 20, 15, tzinfo=SHANGHAI)
    return DailyCandidateSnapshot(
        snapshot_id=snapshot_id,
        target_business_date=date(2026, 7, 29),
        receive_place="Test receiving place",
        query_window=candidate_query_window(
            date(2026, 7, 29),
            now=captured_at,
        ),
        source_contract_sha256=HASH_A,
        candidates=(DailyCandidate("platform-1", "WB-001"),),
        captured_at=captured_at,
    )


def _observation(
    *,
    observation_id: str = "observation-1",
    snapshot_id: str = "snapshot-1",
    loading_net_tonnes: Decimal | None = Decimal("32.80"),
) -> DailyWaybillObservation:
    return DailyWaybillObservation(
        observation_id=observation_id,
        snapshot_id=snapshot_id,
        platform_waybill_id="platform-1",
        waybill_number="WB-001",
        fields=DailyObservationFields(
            shipping_mine="Test mine",
            planned_date=date(2026, 7, 29),
            loading_time=datetime(
                2026,
                7,
                29,
                15,
                0,
                tzinfo=SHANGHAI,
            ),
            vehicle_number="TEST-01",
            loading_net_tonnes=loading_net_tonnes,
            unloading_net_tonnes=None,
            coal_type=None,
            unloading_place=None,
            unloading_time=None,
        ),
        loading_ticket_sha256=HASH_B,
        unloading_ticket_sha256=None,
        source_detail_sha256=HASH_C,
        observed_at=datetime(2026, 7, 29, 20, 16, tzinfo=SHANGHAI),
    )


@pytest.mark.integration
def test_snapshot_save_is_idempotent_and_conflicting_identity_fails(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteDailyStore(runtime)
        first = store.save_snapshot(_snapshot())
        replay = store.save_snapshot(_snapshot())
        assert first.replayed is False
        assert replay.replayed is True
        assert store.get_snapshot("snapshot-1") == _snapshot()

        changed = DailyCandidateSnapshot(
            **{
                **_snapshot().constructor_payload(),
                "candidates": (DailyCandidate("platform-1", "WB-CHANGED"),),
            }
        )
        with pytest.raises(DailyStoreConflictError, match="snapshot"):
            store.save_snapshot(changed)
    finally:
        runtime.close()


@pytest.mark.integration
def test_observation_is_idempotent_and_field_change_appends_revision(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteDailyStore(runtime)
        store.save_snapshot(_snapshot())

        first = store.save_observation(_observation())
        replay = store.save_observation(_observation())
        assert first.replayed is False
        assert first.revision_appended is True
        assert first.revision.revision_number == 1
        assert replay.replayed is True
        assert replay.revision_appended is False

        with pytest.raises(DailyStoreConflictError, match="observation"):
            store.save_observation(
                _observation(
                    observation_id="observation-1",
                    loading_net_tonnes=Decimal("32.81"),
                )
            )

        unchanged_new_capture = store.save_observation(_observation(observation_id="observation-2"))
        assert unchanged_new_capture.replayed is False
        assert unchanged_new_capture.revision_appended is False
        assert unchanged_new_capture.revision.revision_number == 1

        changed = store.save_observation(
            _observation(
                observation_id="observation-3",
                loading_net_tonnes=Decimal("32.81"),
            )
        )
        assert changed.revision_appended is True
        assert changed.revision.revision_number == 2
        replay_after_change = store.save_observation(_observation())
        assert replay_after_change.replayed is True
        assert replay_after_change.revision_appended is False
        assert replay_after_change.revision == first.revision
        assert [revision.revision_number for revision in store.list_revisions("platform-1")] == [
            1,
            2,
        ]
    finally:
        runtime.close()


@pytest.mark.integration
def test_observation_requires_snapshot_and_keeps_missing_values_null(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteDailyStore(runtime)
        with pytest.raises(DailyStoreConflictError, match="snapshot"):
            store.save_observation(_observation())

        store.save_snapshot(_snapshot())
        store.save_observation(_observation(loading_net_tonnes=None))
        with runtime.engine.connect() as connection:
            payload = connection.execute(
                text(
                    "SELECT payload_json FROM daily_observations "
                    "WHERE observation_id = 'observation-1'"
                )
            ).scalar_one()
        assert '"loading_net_tonnes":null' in str(payload)
        assert '""' not in str(payload)

        outside_snapshot = replace(
            _observation(observation_id="observation-outside"),
            platform_waybill_id="platform-outside",
        )
        with pytest.raises(DailyStoreConflictError, match="not part"):
            store.save_observation(outside_snapshot)
    finally:
        runtime.close()


@pytest.mark.integration
def test_snapshot_observation_inventory_is_read_back_in_stable_order(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteDailyStore(runtime)
        snapshot = replace(
            _snapshot(),
            candidates=(
                DailyCandidate("platform-2", "WB-002"),
                DailyCandidate("platform-1", "WB-001"),
            ),
        )
        store.save_snapshot(snapshot)
        store.save_observation(_observation())
        store.save_observation(
            replace(
                _observation(observation_id="observation-2"),
                platform_waybill_id="platform-2",
                waybill_number="WB-002",
            )
        )

        observations = store.list_snapshot_observations("snapshot-1")

        assert tuple(
            observation.platform_waybill_id
            for observation in observations
        ) == ("platform-1", "platform-2")
        assert all(
            observation.snapshot_id == snapshot.snapshot_id
            for observation in observations
        )
    finally:
        runtime.close()


@pytest.mark.integration
def test_daily_records_are_append_only_and_have_no_identity_fields(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteDailyStore(runtime)
        store.save_snapshot(_snapshot())
        store.save_observation(_observation())

        for table_name in (
            "daily_candidate_snapshots",
            "daily_observations",
            "daily_record_revisions",
        ):
            with (
                runtime.engine.begin() as connection,
                pytest.raises(Exception, match="append-only"),
            ):
                connection.exec_driver_sql(f"UPDATE {table_name} SET payload_json = payload_json")

        forbidden = {
            "operator",
            "operator_id",
            "reviewer",
            "reviewer_id",
            "actor",
            "actor_id",
            "employee_id",
            "windows_sid",
        }
        with runtime.engine.connect() as connection:
            for table_name in (
                "daily_candidate_snapshots",
                "daily_observations",
                "daily_record_revisions",
            ):
                columns = {
                    str(row[1]).lower()
                    for row in connection.exec_driver_sql(f"PRAGMA table_info({table_name})")
                }
                assert columns.isdisjoint(forbidden)
    finally:
        runtime.close()


@pytest.mark.integration
def test_formal_snapshot_authority_joins_actual_terminal_capture_state(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteDailyStore(runtime)
        snapshot = _snapshot()
        request = DailyCaptureRequest(
            invocation_id=snapshot.snapshot_id,
            business_date=snapshot.target_business_date,
            receive_place=snapshot.receive_place,
            now=snapshot.captured_at,
            source_contract_sha256=snapshot.source_contract_sha256,
            page_size=100,
        )
        page = DailyWaybillPage(
            page_number=1,
            page_size=100,
            total=1,
            items=(
                DailyWaybillSummary(
                    platform_waybill_id="platform-1",
                    waybill_number="WB-001",
                    vehicle_number=None,
                    platform_loading_time=None,
                ),
            ),
        )
        detail_capture = DailyDetailCaptureState(
            platform_waybill_id="platform-1",
            waybill_number="WB-001",
            fields=_observation().fields,
            tickets=(
                DailyTicketSlotCapture(
                    slot="loading",
                    ticket_ref="loading-capability",
                    media_type="image/jpeg",
                    image_sha256=HASH_B,
                ),
            ),
            capability_authority_id="generation-1",
            capability_access_window_id=(
                "daily-authority-window"
            ),
            detail_read_access_window_ids=(
                "daily-authority-window",
            ),
            image_read_access_window_ids=(
                ("loading", "daily-authority-window"),
            ),
        )
        checkpoint = DailyCaptureCheckpoint(
            invocation_id=snapshot.snapshot_id,
            invocation_fingerprint=request.fingerprint,
            revision=8,
            pages=(page,),
            verification_pages=(page,),
            list_read_access_window_ids=(
                "daily-authority-window",
                "daily-authority-window",
            ),
            snapshot_captured_at=snapshot.captured_at,
            snapshot=snapshot,
            completed_observation_ids=("observation-1",),
            completed_detail_captures=(detail_capture,),
        )
        invocation_authority = DailyInvocationAuthority(
            source_build_sha256="d" * 64,
            daily_contract_sha256=HASH_A,
            daily_contract_file_sha256="b" * 64,
            daily_contract_selection_sha256="c" * 64,
            settlement_contract_sha256="f" * 64,
            settlement_contract_selection_sha256="e" * 64,
        )
        timestamp = snapshot.captured_at.isoformat()
        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO jobs (
                        job_id, task_type, scope_label, scope_fixture_id,
                        scope_fingerprint, run_mode, status, current_stage,
                        job_kind, ocr_execution_mode, created_sequence,
                        record_version, created_at, updated_at
                    ) VALUES (
                        :job_id, 'daily', 'Daily', 'daily-capture-v1',
                        :scope_fingerprint, 'shadow', 'succeeded',
                        'daily.complete', 'business', 'fake', 1, 1,
                        :timestamp, :timestamp
                    )
                    """
                ),
                {
                    "job_id": snapshot.snapshot_id,
                    "scope_fingerprint": hashlib.sha256(
                        b"daily-authority"
                    ).hexdigest(),
                    "timestamp": timestamp,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO work_items (
                        work_item_id, job_id, record_version,
                        waybill_number, vehicle_number, status,
                        current_stage, item_index, attempt_count,
                        download_complete, loading_ocr_complete,
                        unloading_ocr_complete, ready_sequence
                    ) VALUES (
                        'daily-authority-item', :job_id, 1,
                        'daily:2026-07-29', '', 'succeeded',
                        'daily.complete', 0, 1, 0, 0, 0, 1
                    )
                    """
                ),
                {"job_id": snapshot.snapshot_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO platform_access_windows (
                        access_window_id, purpose, job_id, session_id,
                        build_sha256, token_digest, issued_at, expires_at,
                        consumed_at, record_version, idempotency_key,
                        request_hash, created_at, updated_at
                    ) VALUES (
                        'daily-authority-window', 'production_shadow',
                        :job_id, 'daily-authority-session', :build_sha,
                        :token_digest, :timestamp, :timestamp, :timestamp,
                        2, 'daily-authority-window-key', :request_hash,
                        :timestamp, :timestamp
                    )
                    """
                ),
                {
                    "build_sha": "d" * 64,
                    "job_id": snapshot.snapshot_id,
                    "request_hash": hashlib.sha256(
                        b"daily-authority-request"
                    ).hexdigest(),
                    "timestamp": timestamp,
                    "token_digest": hashlib.sha256(
                        b"daily-authority-token"
                    ).hexdigest(),
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO daily_capture_invocations (
                        invocation_id, job_id, access_window_id,
                        request_fingerprint, request_json, authority_json,
                        checkpoint_json, next_stage, status,
                        diagnostic_code, record_version,
                        created_at, updated_at
                    ) VALUES (
                        :invocation_id, :job_id,
                        'daily-authority-window', :request_fingerprint,
                        :request_json, :authority_json,
                        :checkpoint_json, 'daily.complete',
                        'succeeded', NULL, 2, :timestamp, :timestamp
                    )
                    """
                ),
                {
                    "invocation_id": snapshot.snapshot_id,
                    "job_id": snapshot.snapshot_id,
                    "request_fingerprint": request.fingerprint,
                    "request_json": json.dumps(
                        request.to_payload(),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "authority_json": json.dumps(
                        invocation_authority.to_payload(),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "checkpoint_json": json.dumps(
                        checkpoint.to_payload(),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "timestamp": timestamp,
                },
            )
        store.save_snapshot(snapshot)
        store.save_observation(_observation())
        audit_store = PlatformReadAuditEvidenceStore(runtime.data_root)
        settlement_contract = "f" * 64
        settlement_selection = "e" * 64
        daily_selection = "c" * 64
        for operation, contract, selection in (
            ("list_daily_waybills", HASH_A, daily_selection),
            ("list_daily_waybills", HASH_A, daily_selection),
            (
                "get_waybill_detail",
                settlement_contract,
                settlement_selection,
            ),
            (
                "download_ticket_image",
                settlement_contract,
                settlement_selection,
            ),
        ):
            token = audit_store.attempt(
                job_id=snapshot.snapshot_id,
                build_sha256="d" * 64,
                contract_sha256=contract,
                contract_selection_sha256=selection,
                operation=operation,
            )
            audit_store.allowed(token)
            audit_store.succeeded(token)
        sealed_audit = audit_store.seal(
            job_id=snapshot.snapshot_id,
            authority=PlatformReadAuditAuthority(
                build_sha256="d" * 64,
                settlement_contract_sha256=settlement_contract,
                settlement_contract_selection_sha256=(
                    settlement_selection
                ),
                daily_contract_sha256=HASH_A,
                daily_contract_selection_sha256=daily_selection,
            ),
            purpose="daily_snapshot",
            expected_succeeded_operations={
                "list_daily_waybills": 2,
                "get_waybill_detail": 1,
                "download_ticket_image": 1,
            },
        )

        authority = store.get_formal_snapshot_authority(
            snapshot.snapshot_id
        )

        assert authority.snapshot == snapshot
        assert authority.capture_build_sha256 == "d" * 64
        assert authority.access_purpose == "production_shadow"
        assert authority.access_consumed is True
        assert authority.invocation_contract_sha256 == HASH_A
        assert authority.invocation_status == "succeeded"
        assert authority.invocation_next_stage == "daily.complete"
        assert authority.job_status == "succeeded"
        assert authority.job_current_stage == "daily.complete"
        assert authority.work_item_count == 1
        assert authority.succeeded_work_item_count == 1
        assert authority.completed_stage_work_item_count == 1
        assert authority.observation_count == 1
        assert authority.access_window_ids == (
            "daily-authority-window",
        )
        assert set(authority.read_access_window_ids.values()) == {
            "daily-authority-window",
        }
        assert len(authority.read_access_window_ids) == 4
        assert (
            authority.request_audit_sha256
            == sealed_audit.canonical_sha256
        )
        assert authority.request_audit_request_counts["succeeded"] == 4
        assert authority.forbidden_request_count == 0
        assert authority.platform_write_request_count == 0
        assert authority.redirect_count == 0
    finally:
        runtime.close()
