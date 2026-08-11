from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
from dahe.adapters.sqlite.evidence import DurableEvidenceRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime

SHARED_BYTES = b"DaHe Loop 4 shared synthetic ticket"
LOADING_BYTES = b"DaHe Loop 4 loading synthetic ticket"
UNLOADING_BYTES = b"DaHe Loop 4 unloading synthetic ticket"


def _bundle(*, capture_id: str = "atomic-capture") -> dict[str, object]:
    return {
        "capture_id": capture_id,
        "captured_at": "2026-07-25T08:00:00+00:00",
        "request_contract_version": "loop4-frozen-v1",
        "waybills": [
            {
                "platform_waybill_id": "atomic-waybill-001",
                "waybill_number": "L4-ATOMIC-001",
                "business_fields": {
                    "vehicle_number": "TEST-001",
                    "loading_net": "30.00",
                    "unloading_net": "29.80",
                },
                "images": [
                    {
                        "slot": "loading",
                        "content": LOADING_BYTES,
                        "media_type": "application/octet-stream",
                    },
                    {
                        "slot": "unloading",
                        "content": SHARED_BYTES,
                        "media_type": "application/octet-stream",
                    },
                ],
                "audit_decision": {
                    "decision": "pass",
                    "business_outcome": "normal_ready",
                    "rule_version": "loop4-rule-v1",
                    "eligible_for_handoff": False,
                },
            },
            {
                "platform_waybill_id": "atomic-waybill-002",
                "waybill_number": "L4-ATOMIC-002",
                "business_fields": {
                    "vehicle_number": "TEST-002",
                    "loading_net": "28.50",
                    "unloading_net": "28.20",
                },
                "images": [
                    {
                        "slot": "loading",
                        "content": SHARED_BYTES,
                        "media_type": "application/octet-stream",
                    },
                    {
                        "slot": "unloading",
                        "content": UNLOADING_BYTES,
                        "media_type": "application/octet-stream",
                    },
                ],
                "audit_decision": {
                    "decision": "review",
                    "business_outcome": "awaiting_review",
                    "rule_version": "loop4-rule-v1",
                    "eligible_for_handoff": False,
                },
            },
        ],
    }


def _open(
    tmp_path: Path,
    project_root: Path,
) -> tuple[SqliteRuntime, DurableEvidenceRepository]:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop4-audit-atomicity",
    )
    evidence_store = ContentAddressedEvidenceStore(tmp_path / "evidence")
    return runtime, DurableEvidenceRepository(
        runtime=runtime,
        evidence_store=evidence_store,
    )


def _count(runtime: SqliteRuntime, table: str) -> int:
    with runtime.engine.connect() as connection:
        return int(connection.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one())


def test_snapshots_decisions_and_references_commit_as_one_revision(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime, repository = _open(tmp_path, project_root)
    try:
        result = repository.import_bundle(
            _bundle(),
            idempotency_key="atomic-import-001",
        )

        assert result.created is True
        assert _count(runtime, "platform_snapshots") == 2
        assert _count(runtime, "audit_decisions") == 2
        assert _count(runtime, "evidence_blobs") == 3
        assert _count(runtime, "evidence_references") == 4
    finally:
        runtime.close()


def test_failure_after_decision_insert_rolls_back_the_entire_database_revision(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime, repository = _open(tmp_path, project_root)

    def failpoint(name: str) -> None:
        if name == "after_decision_insert":
            raise RuntimeError("simulated crash before commit")

    try:
        with pytest.raises(RuntimeError, match="simulated crash"):
            repository.import_bundle(
                _bundle(),
                idempotency_key="atomic-import-crash",
                failpoint=failpoint,
            )

        for table in (
            "evidence_imports",
            "platform_snapshots",
            "audit_decisions",
            "evidence_blobs",
            "evidence_references",
        ):
            assert _count(runtime, table) == 0
    finally:
        runtime.close()


def test_process_crash_inside_snapshot_transaction_is_rolled_back_on_reopen(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "process-crash"
    initialized, _ = _open(data_root, project_root)
    initialized.close()
    child_code = textwrap.dedent(
        """
        import os
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(sys.argv[2]) / "src"))

        from dahe.adapters.files.content_addressed import ContentAddressedEvidenceStore
        from dahe.adapters.sqlite.evidence import DurableEvidenceRepository
        from dahe.adapters.sqlite.runtime import SqliteRuntime

        data_root = Path(sys.argv[1])
        project_root = Path(sys.argv[2])
        runtime = SqliteRuntime(
            data_root=data_root,
            project_root=project_root,
            instance_id="loop4-crash-child",
        )
        repository = DurableEvidenceRepository(
            runtime=runtime,
            evidence_store=ContentAddressedEvidenceStore(data_root / "evidence"),
        )
        bundle = {
            "capture_id": "atomic-capture",
            "captured_at": "2026-07-25T08:00:00+00:00",
            "request_contract_version": "loop4-frozen-v1",
            "waybills": [{
                "platform_waybill_id": "atomic-waybill-child",
                "waybill_number": "L4-ATOMIC-CHILD",
                "business_fields": {
                    "vehicle_number": "TEST-CHILD",
                    "loading_net": "30.00",
                    "unloading_net": "29.80",
                },
                "images": [{
                    "slot": "loading",
                    "content": b"Loop 4 child crash evidence",
                    "media_type": "application/octet-stream",
                }],
                "audit_decision": {
                    "decision": "pass",
                    "business_outcome": "normal_ready",
                    "rule_version": "loop4-rule-v1",
                    "eligible_for_handoff": False,
                },
            }],
        }

        def crash(name: str) -> None:
            if name == "after_decision_insert":
                os._exit(73)

        repository.import_bundle(
            bundle,
            idempotency_key="atomic-process-crash",
            failpoint=crash,
        )
        raise SystemExit(74)
        """
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            child_code,
            str(data_root),
            str(project_root),
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 73, completed.stderr

    runtime, repository = _open(data_root, project_root)
    try:
        with runtime.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA integrity_check").scalar_one() == "ok"
        for table in (
            "evidence_imports",
            "platform_snapshots",
            "audit_decisions",
            "evidence_blobs",
            "evidence_references",
        ):
            assert _count(runtime, table) == 0

        recovered = repository.import_bundle(
            _bundle(capture_id="atomic-capture"),
            idempotency_key="atomic-process-crash",
        )
        assert recovered.created is True
        assert _count(runtime, "platform_snapshots") == 2
        assert _count(runtime, "audit_decisions") == 2
    finally:
        runtime.close()


@pytest.mark.parametrize("table", ["platform_snapshots", "audit_decisions"])
def test_committed_business_evidence_is_immutable(
    tmp_path: Path,
    project_root: Path,
    table: str,
) -> None:
    runtime, repository = _open(tmp_path, project_root)
    try:
        repository.import_bundle(
            _bundle(),
            idempotency_key=f"immutable-{table}",
        )

        with (
            pytest.raises(DatabaseError, match="immutable"),
            runtime.commit_gate.transaction(runtime.engine) as connection,
        ):
            connection.execute(text(f'UPDATE "{table}" SET record_version = 99'))
    finally:
        runtime.close()
