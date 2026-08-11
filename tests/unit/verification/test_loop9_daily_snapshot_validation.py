from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import dahe.verification.daily_snapshot_validation as validation_module
from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
)
from dahe.ports.daily import DailySnapshotCaptureAuthority
from dahe.verification.daily_snapshot_validation import (
    DailyContractSelectionBinding,
    DailySnapshotValidationError,
    replay_current_daily_snapshot_validation_from_store,
    validate_daily_snapshot_triplet,
    verify_current_daily_snapshot_validation_evidence,
    verify_daily_snapshot_validation_evidence,
)

CONTRACT_SHA = "a" * 64
BUILD_SHA = "b" * 64
SETTLEMENT_CONTRACT_SHA = "9" * 64
SETTLEMENT_SELECTION_SHA = "8" * 64
QUERY_CUTOFF = datetime(2026, 7, 30, 14, 30, tzinfo=SHANGHAI)
CONTRACT_SELECTION = DailyContractSelectionBinding(
    contract_canonical_sha256=CONTRACT_SHA,
    contract_file_sha256="c" * 64,
    freeze_evidence_sha256="d" * 64,
    selection_sha256="e" * 64,
    source_discovery_sha256="f" * 64,
)


def _snapshot(
    index: int,
    *,
    cutoff: datetime = QUERY_CUTOFF,
    identities: tuple[tuple[str, str], ...] = (
        ("platform-1", "WB-001"),
        ("platform-2", "WB-002"),
    ),
    contract_sha256: str = CONTRACT_SHA,
) -> DailyCandidateSnapshot:
    return DailyCandidateSnapshot(
        snapshot_id=f"daily-snapshot-{index}",
        target_business_date=date(2026, 7, 29),
        receive_place="榆林",
        query_window=candidate_query_window(
            date(2026, 7, 29),
            now=cutoff,
        ),
        source_contract_sha256=contract_sha256,
        candidates=tuple(
            DailyCandidate(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=None,
                platform_loading_time=None,
            )
            for platform_id, waybill_number in identities
        ),
        captured_at=QUERY_CUTOFF + timedelta(minutes=index),
    )


def _authority(
    index: int,
    **changes: object,
) -> DailySnapshotCaptureAuthority:
    snapshot = _snapshot(index)
    audit_job_sha256 = hashlib.sha256(
        snapshot.snapshot_id.encode()
    ).hexdigest()
    audit_event_chain_sha256 = hashlib.sha256(
        f"request-audit-chain-{index}".encode()
    ).hexdigest()
    values: dict[str, object] = {
        "snapshot": snapshot,
        "invocation_id": snapshot.snapshot_id,
        "job_id": snapshot.snapshot_id,
        "access_window_id": f"daily-window-{index}",
        "capture_build_sha256": BUILD_SHA,
        "access_purpose": "production_shadow",
        "access_consumed": True,
        "invocation_contract_sha256": CONTRACT_SHA,
        "invocation_status": "succeeded",
        "invocation_next_stage": "daily.complete",
        "invocation_diagnostic_code": None,
        "job_status": "succeeded",
        "job_current_stage": "daily.complete",
        "job_diagnostic_code": None,
        "work_item_count": 1,
        "succeeded_work_item_count": 1,
        "completed_stage_work_item_count": 1,
        "observation_count": len(snapshot.candidates),
        "request_audit_sha256": "",
        "request_audit_job_id_sha256": audit_job_sha256,
        "request_audit_purpose": "daily_snapshot",
        "request_audit_authority": {
            "build_sha256": BUILD_SHA,
            "daily_contract_selection_sha256": (
                CONTRACT_SELECTION.selection_sha256
            ),
            "daily_contract_sha256": CONTRACT_SHA,
            "settlement_contract_selection_sha256": (
                SETTLEMENT_SELECTION_SHA
            ),
            "settlement_contract_sha256": SETTLEMENT_CONTRACT_SHA,
        },
        "request_audit_request_counts": {
            "allowed": 8,
            "attempted": 8,
            "denied": 0,
            "succeeded": 8,
        },
        "request_audit_operation_counts": {
            "download_ticket_image": {
                "allowed": 4,
                "attempted": 4,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 4,
            },
            "get_waybill_detail": {
                "allowed": 2,
                "attempted": 2,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 2,
            },
            "list_daily_waybills": {
                "allowed": 2,
                "attempted": 2,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 2,
            },
            "list_waybills": {
                "allowed": 0,
                "attempted": 0,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 0,
            },
        },
        "request_audit_event_count": 24,
        "request_audit_event_chain_sha256": audit_event_chain_sha256,
        "request_audit_expected_succeeded_operations": {
            "download_ticket_image": 4,
            "get_waybill_detail": 2,
            "list_daily_waybills": 2,
        },
        "request_audit_kind": "loop9_platform_read_audit",
        "request_audit_schema_version": 1,
        "forbidden_request_count": 0,
        "platform_write_request_count": 0,
        "redirect_count": 0,
    }
    values.update(changes)
    if "access_window_ids" not in changes:
        values["access_window_ids"] = (
            str(values["access_window_id"]),
        )
    if "read_access_window_ids" not in changes:
        current_window = str(values["access_window_id"])
        expected = values[
            "request_audit_expected_succeeded_operations"
        ]
        assert isinstance(expected, dict)
        read_bindings: dict[str, str] = {}
        for read_index in range(
            int(expected.get("list_daily_waybills", 0))
        ):
            read_bindings[f"list:{read_index + 1}"] = current_window
        for read_index in range(
            int(expected.get("get_waybill_detail", 0))
        ):
            detail_identity = hashlib.sha256(
                f"detail-binding-{index}-{read_index}".encode()
            ).hexdigest()
            read_bindings[
                f"detail:{detail_identity}:1"
            ] = current_window
        for read_index in range(
            int(expected.get("download_ticket_image", 0))
        ):
            image_identity = hashlib.sha256(
                f"image-binding-{index}-{read_index}".encode()
            ).hexdigest()
            slot = "loading" if read_index % 2 == 0 else "unloading"
            read_bindings[
                f"image:{image_identity}:{slot}"
            ] = current_window
        values["read_access_window_ids"] = read_bindings
    if "request_audit_sha256" not in changes:
        values["request_audit_sha256"] = hashlib.sha256(
            json.dumps(
                {
                    "authority": values["request_audit_authority"],
                    "event_chain_sha256": values[
                        "request_audit_event_chain_sha256"
                    ],
                    "event_count": values["request_audit_event_count"],
                    "expected_succeeded_operations": values[
                        "request_audit_expected_succeeded_operations"
                    ],
                    "job_id_sha256": values[
                        "request_audit_job_id_sha256"
                    ],
                    "kind": values["request_audit_kind"],
                    "operation_counts": values[
                        "request_audit_operation_counts"
                    ],
                    "platform_write_request_count": values[
                        "platform_write_request_count"
                    ],
                    "purpose": values["request_audit_purpose"],
                    "redirect_count": values["redirect_count"],
                    "request_counts": values[
                        "request_audit_request_counts"
                    ],
                    "schema_version": values[
                        "request_audit_schema_version"
                    ],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return DailySnapshotCaptureAuthority(**values)  # type: ignore[arg-type]


def test_three_independent_snapshots_with_one_scope_are_replay_verifiable() -> None:
    authorities = tuple(_authority(index) for index in range(1, 4))

    evidence = validate_daily_snapshot_triplet(
        authorities,
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )

    assert evidence["gate_passed"] is True
    assert evidence["snapshot_count"] == 3
    assert evidence["candidate_count"] == 2
    assert len(evidence["snapshot_evidence"]) == 3
    assert "platform-1" not in str(evidence)
    assert evidence["schema_version"] == 5
    assert evidence["contract_selection"] == {
        "contract_canonical_sha256": CONTRACT_SHA,
        "contract_file_sha256": "c" * 64,
        "freeze_evidence_sha256": "d" * 64,
        "selection_sha256": "e" * 64,
        "source_discovery_sha256": "f" * 64,
    }
    assert evidence["forbidden_request_count"] == 0
    assert evidence["platform_write_request_count"] == 0
    assert evidence["redirect_count"] == 0
    assert all(
        snapshot["capture_build_sha256"] == BUILD_SHA
        for snapshot in evidence["snapshot_evidence"]
    )
    assert verify_daily_snapshot_validation_evidence(evidence) == evidence


def test_historical_schema_four_evidence_remains_read_only_verifiable() -> None:
    current = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    historical_snapshots = []
    for raw_snapshot in current["snapshot_evidence"]:
        snapshot = dict(raw_snapshot)
        snapshot.pop("access_window_ids")
        snapshot.pop("read_access_window_ids")
        historical_snapshots.append(snapshot)
    historical = _rehash_evidence(
        {
            **current,
            "schema_version": 4,
            "snapshot_evidence": historical_snapshots,
        }
    )

    assert (
        verify_daily_snapshot_validation_evidence(historical)
        == historical
    )


def test_current_formal_gate_rejects_historical_schema_four() -> None:
    current = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    historical_snapshots = []
    for raw_snapshot in current["snapshot_evidence"]:
        snapshot = dict(raw_snapshot)
        snapshot.pop("access_window_ids")
        snapshot.pop("read_access_window_ids")
        historical_snapshots.append(snapshot)
    historical = _rehash_evidence(
        {
            **current,
            "schema_version": 4,
            "snapshot_evidence": historical_snapshots,
        }
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match=r"current formal.*schema version 5",
    ):
        verify_current_daily_snapshot_validation_evidence(historical)


def test_current_formal_gate_accepts_schema_five() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )

    assert (
        verify_current_daily_snapshot_validation_evidence(evidence)
        == evidence
    )


def test_current_formal_store_rebuild_accepts_unchanged_schema_five(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorities = tuple(_authority(index) for index in range(1, 4))
    evidence = validate_daily_snapshot_triplet(
        authorities,
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    monkeypatch.setattr(
        validation_module,
        "_load_current_daily_replay_inputs",
        lambda **_values: (
            CONTRACT_SHA,
            CONTRACT_SELECTION,
            authorities,
        ),
    )

    assert (
        replay_current_daily_snapshot_validation_from_store(
            evidence,
            data_root=tmp_path.resolve(),
            project_root=tmp_path.resolve(),
            source_build_sha256=BUILD_SHA,
        )
        == evidence
    )


def test_current_formal_replay_inputs_reload_selected_contract_and_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dahe.adapters.chengfeng import daily_contract_selection
    from dahe.adapters.sqlite import daily_store, runtime

    authorities = tuple(_authority(index) for index in range(1, 4))
    loaded_ids: list[str] = []
    closed: list[bool] = []

    class FakeRuntime:
        def __init__(self, **values: object) -> None:
            assert values["data_root"] == tmp_path.resolve()
            assert values["project_root"] == tmp_path.resolve()
            assert str(values["instance_id"]).startswith(
                "loop9-daily-replay-"
            )

        def close(self) -> None:
            closed.append(True)

    class FakeStore:
        def __init__(self, runtime_value: object) -> None:
            assert isinstance(runtime_value, FakeRuntime)

        def get_formal_snapshot_authority(
            self,
            snapshot_id: str,
        ) -> DailySnapshotCaptureAuthority:
            loaded_ids.append(snapshot_id)
            return authorities[int(snapshot_id.rsplit("-", 1)[1]) - 1]

    monkeypatch.setattr(
        daily_contract_selection,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=CONTRACT_SHA,
                source_discovery_sha256=(
                    CONTRACT_SELECTION.source_discovery_sha256
                ),
            ),
            contract_file_sha256=(
                CONTRACT_SELECTION.contract_file_sha256
            ),
            freeze_evidence_sha256=(
                CONTRACT_SELECTION.freeze_evidence_sha256
            ),
            selection_sha256=CONTRACT_SELECTION.selection_sha256,
        ),
    )
    monkeypatch.setattr(runtime, "SqliteRuntime", FakeRuntime)
    monkeypatch.setattr(daily_store, "SqliteDailyStore", FakeStore)

    contract_sha256, selection, loaded = (
        validation_module._load_current_daily_replay_inputs(
            data_root=tmp_path.resolve(),
            project_root=tmp_path.resolve(),
            snapshot_ids=(
                "daily-snapshot-1",
                "daily-snapshot-2",
                "daily-snapshot-3",
            ),
        )
    )

    assert contract_sha256 == CONTRACT_SHA
    assert selection == CONTRACT_SELECTION
    assert loaded == authorities
    assert loaded_ids == [
        "daily-snapshot-1",
        "daily-snapshot-2",
        "daily-snapshot-3",
    ]
    assert closed == [True]


@pytest.mark.parametrize(
    "mutation",
    (
        "unused_window",
        "swapped_lineage_prefix",
        "changed_image_identity",
        "changed_image_slot",
    ),
)
def test_current_formal_store_rebuild_rejects_self_consistent_lineage_tampering(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _authority(
        1,
        access_window_ids=(
            "daily-window-1-old-a",
            "daily-window-1-old-b",
            "daily-window-1",
        ),
    )
    authorities = (first, _authority(2), _authority(3))
    evidence = validate_daily_snapshot_triplet(
        authorities,
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    tampered = deepcopy(evidence)
    snapshots = tampered["snapshot_evidence"]
    assert isinstance(snapshots, list)
    first_snapshot = snapshots[0]
    assert isinstance(first_snapshot, dict)
    lineage = first_snapshot["access_window_ids"]
    bindings = first_snapshot["read_access_window_ids"]
    assert isinstance(lineage, list)
    assert isinstance(bindings, dict)
    if mutation == "unused_window":
        lineage.insert(-1, "daily-window-1-unused")
    elif mutation == "swapped_lineage_prefix":
        lineage[0], lineage[1] = lineage[1], lineage[0]
    else:
        image_key = next(
            key
            for key in bindings
            if isinstance(key, str) and key.startswith("image:")
        )
        prefix, _identity, slot = image_key.split(":")
        if mutation == "changed_image_identity":
            replacement = f"{prefix}:{'7' * 64}:{slot}"
        else:
            replacement_slot = (
                "unloading" if slot == "loading" else "loading"
            )
            replacement = (
                f"{prefix}:{_identity}:{replacement_slot}"
            )
        bindings[replacement] = bindings.pop(image_key)
    tampered = _rehash_evidence(tampered)
    assert (
        verify_current_daily_snapshot_validation_evidence(tampered)
        == tampered
    )
    monkeypatch.setattr(
        validation_module,
        "_load_current_daily_replay_inputs",
        lambda **_values: (
            CONTRACT_SHA,
            CONTRACT_SELECTION,
            authorities,
        ),
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="does not match formal SQLite authorities",
    ):
        replay_current_daily_snapshot_validation_from_store(
            tampered,
            data_root=tmp_path.resolve(),
            project_root=tmp_path.resolve(),
            source_build_sha256=BUILD_SHA,
        )


def test_triplet_preserves_rollover_lineage_and_detail_refresh_reads() -> None:
    old_window = "daily-window-2-old"
    current_window = "daily-window-2"
    detail_a = hashlib.sha256(b"detail-a").hexdigest()
    detail_b = hashlib.sha256(b"detail-b").hexdigest()
    image_keys = tuple(
        hashlib.sha256(f"image-{index}".encode()).hexdigest()
        for index in range(4)
    )
    rollover = _authority(
        2,
        access_window_ids=(old_window, current_window),
        read_access_window_ids={
            "list:1": old_window,
            "list:2": old_window,
            f"detail:{detail_a}:1": old_window,
            f"detail:{detail_a}:2": current_window,
            f"detail:{detail_b}:1": current_window,
            f"image:{image_keys[0]}:loading": old_window,
            f"image:{image_keys[1]}:unloading": current_window,
            f"image:{image_keys[2]}:loading": current_window,
            f"image:{image_keys[3]}:unloading": current_window,
        },
        request_audit_request_counts={
            "allowed": 9,
            "attempted": 9,
            "denied": 0,
            "succeeded": 9,
        },
        request_audit_operation_counts={
            "download_ticket_image": {
                "allowed": 4,
                "attempted": 4,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 4,
            },
            "get_waybill_detail": {
                "allowed": 3,
                "attempted": 3,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 3,
            },
            "list_daily_waybills": {
                "allowed": 2,
                "attempted": 2,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 2,
            },
            "list_waybills": {
                "allowed": 0,
                "attempted": 0,
                "denied": 0,
                "failed": 0,
                "redirect": 0,
                "succeeded": 0,
            },
        },
        request_audit_event_count=27,
        request_audit_expected_succeeded_operations={
            "download_ticket_image": 4,
            "get_waybill_detail": 3,
            "list_daily_waybills": 2,
        },
    )

    evidence = validate_daily_snapshot_triplet(
        (_authority(1), rollover, _authority(3)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )

    second = evidence["snapshot_evidence"][1]
    assert second["access_window_ids"] == [
        old_window,
        current_window,
    ]
    assert second["request_audit_expected_succeeded_operations"][
        "get_waybill_detail"
    ] == 3
    assert set(second["read_access_window_ids"].values()) == {
        old_window,
        current_window,
    }
    assert verify_daily_snapshot_validation_evidence(evidence) == evidence


def test_rehashed_evidence_cannot_move_a_read_outside_its_lineage() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    bindings = dict(snapshots[0]["read_access_window_ids"])
    first_key = next(iter(bindings))
    bindings[first_key] = "unrelated-window"
    snapshots[0]["read_access_window_ids"] = bindings
    body = _rehash_evidence(
        {
            **evidence,
            "snapshot_evidence": snapshots,
        }
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="read access binding",
    ):
        verify_current_daily_snapshot_validation_evidence(body)


@pytest.mark.parametrize(
    ("authorities", "message"),
    [
        (
            (_authority(1), _authority(2)),
            "exactly three",
        ),
        (
            (_authority(1), _authority(1), _authority(3)),
            "independent",
        ),
        (
            (
                _authority(1),
                _authority(
                    2,
                    snapshot=_snapshot(
                        2,
                        cutoff=QUERY_CUTOFF - timedelta(minutes=1),
                    ),
                ),
                _authority(3),
            ),
            "query scope",
        ),
        (
            (
                _authority(1),
                _authority(
                    2,
                    snapshot=_snapshot(
                        2,
                        identities=(
                            ("platform-1", "WB-001"),
                            ("platform-3", "WB-003"),
                        ),
                    ),
                ),
                _authority(3),
            ),
            "identity",
        ),
        (
            (
                _authority(1),
                _authority(
                    2,
                    snapshot=_snapshot(2, contract_sha256="c" * 64),
                    invocation_contract_sha256="c" * 64,
                ),
                _authority(3),
            ),
            "contract",
        ),
    ],
)
def test_triplet_rejects_noncomparable_or_replayed_snapshots(
    authorities: tuple[DailySnapshotCaptureAuthority, ...],
    message: str,
) -> None:
    with pytest.raises(DailySnapshotValidationError, match=message):
        validate_daily_snapshot_triplet(
            authorities,
            build_sha256=BUILD_SHA,
            expected_contract_sha256=CONTRACT_SHA,
            contract_selection=CONTRACT_SELECTION,
        )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"capture_build_sha256": "c" * 64}, "build"),
        ({"access_purpose": "contract_discovery"}, "access"),
        ({"access_consumed": False}, "access"),
        ({"invocation_status": "running"}, "invocation"),
        ({"invocation_next_stage": "daily.detail"}, "invocation"),
        ({"job_status": "running"}, "job"),
        ({"job_current_stage": "daily.detail"}, "job"),
        ({"work_item_count": 2}, "work item"),
        ({"succeeded_work_item_count": 0}, "work item"),
        ({"completed_stage_work_item_count": 0}, "work item"),
        ({"observation_count": 1}, "observation"),
    ],
)
def test_triplet_rejects_stale_or_incomplete_capture_authority(
    change: dict[str, object],
    message: str,
) -> None:
    authorities = (
        _authority(1),
        _authority(2, **change),
        _authority(3),
    )

    with pytest.raises(DailySnapshotValidationError, match=message):
        validate_daily_snapshot_triplet(
            authorities,
            build_sha256=BUILD_SHA,
            expected_contract_sha256=CONTRACT_SHA,
            contract_selection=CONTRACT_SELECTION,
        )


def test_triplet_creation_rejects_reused_access_window() -> None:
    authorities = (
        _authority(1),
        _authority(2, access_window_id="daily-window-1"),
        _authority(3),
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="access windows",
    ):
        validate_daily_snapshot_triplet(
            authorities,
            build_sha256=BUILD_SHA,
            expected_contract_sha256=CONTRACT_SHA,
            contract_selection=CONTRACT_SELECTION,
        )


@pytest.mark.parametrize(
    "field",
    (
        "forbidden_request_count",
        "platform_write_request_count",
        "redirect_count",
    ),
)
def test_triplet_rejects_nonzero_read_only_counter(field: str) -> None:
    authorities = (
        _authority(1),
        _authority(2, **{field: 1}),
        _authority(3),
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="read-only counters",
    ):
        validate_daily_snapshot_triplet(
            authorities,
            build_sha256=BUILD_SHA,
            expected_contract_sha256=CONTRACT_SHA,
            contract_selection=CONTRACT_SELECTION,
        )


def test_triplet_rejects_selection_for_a_different_contract() -> None:
    changed = DailyContractSelectionBinding(
        contract_canonical_sha256="9" * 64,
        contract_file_sha256=CONTRACT_SELECTION.contract_file_sha256,
        freeze_evidence_sha256=CONTRACT_SELECTION.freeze_evidence_sha256,
        selection_sha256=CONTRACT_SELECTION.selection_sha256,
        source_discovery_sha256=CONTRACT_SELECTION.source_discovery_sha256,
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="selected daily contract",
    ):
        validate_daily_snapshot_triplet(
            tuple(_authority(index) for index in range(1, 4)),
            build_sha256=BUILD_SHA,
            expected_contract_sha256=CONTRACT_SHA,
            contract_selection=changed,
        )


def test_evidence_tampering_is_rejected() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    tampered = {
        **evidence,
        "candidate_count": 999,
    }

    with pytest.raises(DailySnapshotValidationError, match="integrity"):
        verify_daily_snapshot_validation_evidence(tampered)


def test_rehashed_evidence_cannot_hide_an_inconsistent_snapshot() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    snapshots[1]["identity_set_sha256"] = "c" * 64
    body = {
        **evidence,
        "snapshot_evidence": snapshots,
    }
    body.pop("canonical_sha256")
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(
        DailySnapshotValidationError,
        match="identity is inconsistent",
    ):
        verify_daily_snapshot_validation_evidence(body)


def test_rehashed_evidence_cannot_reuse_an_access_window() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    snapshots[1]["access_window_id"] = snapshots[0]["access_window_id"]
    body = {
        **evidence,
        "snapshot_evidence": snapshots,
    }
    body.pop("canonical_sha256")
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(
        DailySnapshotValidationError,
        match="read access lineage",
    ):
        verify_daily_snapshot_validation_evidence(body)


def test_rehashed_evidence_cannot_hide_a_partial_capture() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    snapshots[1]["observation_count"] = 1
    body = {
        **evidence,
        "snapshot_evidence": snapshots,
    }
    body.pop("canonical_sha256")
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(
        DailySnapshotValidationError,
        match="observation",
    ):
        verify_daily_snapshot_validation_evidence(body)


def test_rehashed_evidence_cannot_hide_a_nonzero_read_only_counter() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    snapshots[0]["forbidden_request_count"] = 1
    body = {
        **evidence,
        "forbidden_request_count": 1,
        "snapshot_evidence": snapshots,
    }
    body.pop("canonical_sha256")
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(
        DailySnapshotValidationError,
        match="read-only counters",
    ):
        verify_daily_snapshot_validation_evidence(body)


def test_rehashed_evidence_cannot_substitute_contract_selection() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    selection = dict(evidence["contract_selection"])
    selection["contract_canonical_sha256"] = "9" * 64
    body = {
        **evidence,
        "contract_selection": selection,
    }
    body.pop("canonical_sha256")
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(
        DailySnapshotValidationError,
        match="selected daily contract",
    ):
        verify_daily_snapshot_validation_evidence(body)


def _rehash_evidence(body: dict[str, object]) -> dict[str, object]:
    body.pop("canonical_sha256", None)
    body["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return body


def test_rehashed_evidence_cannot_swap_request_audits_between_jobs() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    first_sha = snapshots[0]["request_audit_sha256"]
    second_sha = snapshots[1]["request_audit_sha256"]
    snapshots[0]["request_audit_sha256"] = second_sha
    snapshots[1]["request_audit_sha256"] = first_sha
    body = _rehash_evidence(
        {
            **evidence,
            "request_audit_sha256s": [
                snapshot["request_audit_sha256"]
                for snapshot in snapshots
            ],
            "snapshot_evidence": snapshots,
        }
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="request audit integrity",
    ):
        verify_daily_snapshot_validation_evidence(body)


def test_rehashed_evidence_cannot_change_request_audit_authority() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    authority = dict(snapshots[0]["request_audit_authority"])
    authority["daily_contract_selection_sha256"] = "7" * 64
    snapshots[0]["request_audit_authority"] = authority
    body = _rehash_evidence(
        {
            **evidence,
            "snapshot_evidence": snapshots,
        }
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="request audit integrity",
    ):
        verify_daily_snapshot_validation_evidence(body)


def test_rehashed_evidence_cannot_change_request_audit_counts() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    operation_counts = {
        operation: dict(counts)
        for operation, counts in snapshots[0][
            "request_audit_operation_counts"
        ].items()
    }
    operation_counts["download_ticket_image"]["succeeded"] = 5
    operation_counts["download_ticket_image"]["attempted"] = 5
    operation_counts["download_ticket_image"]["allowed"] = 5
    snapshots[0]["request_audit_operation_counts"] = operation_counts
    snapshots[0]["request_audit_request_counts"] = {
        "allowed": 9,
        "attempted": 9,
        "denied": 0,
        "succeeded": 9,
    }
    snapshots[0]["request_audit_event_count"] = 27
    body = _rehash_evidence(
        {
            **evidence,
            "snapshot_evidence": snapshots,
        }
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="request audit integrity",
    ):
        verify_daily_snapshot_validation_evidence(body)


def test_rehashed_evidence_cannot_remove_request_audit_binding() -> None:
    evidence = validate_daily_snapshot_triplet(
        tuple(_authority(index) for index in range(1, 4)),
        build_sha256=BUILD_SHA,
        expected_contract_sha256=CONTRACT_SHA,
        contract_selection=CONTRACT_SELECTION,
    )
    snapshots = [
        dict(snapshot)
        for snapshot in evidence["snapshot_evidence"]
    ]
    snapshots[0].pop("request_audit_job_id_sha256")
    body = _rehash_evidence(
        {
            **evidence,
            "snapshot_evidence": snapshots,
        }
    )

    with pytest.raises(
        DailySnapshotValidationError,
        match="snapshot evidence",
    ):
        verify_daily_snapshot_validation_evidence(body)
