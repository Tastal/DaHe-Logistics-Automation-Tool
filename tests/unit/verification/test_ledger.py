from __future__ import annotations

import json
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import dahe.verification.ledger as ledger_module
from dahe.verification.ledger import (
    LedgerConflictError,
    LedgerStore,
    LedgerValidationError,
)


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _active_loop9_ledger(project_root: Path) -> dict[str, object]:
    """Build the mutable Loop 9 fixture independently of repository status."""
    document = _load_json(
        project_root / "tests" / "fixtures" / "loop9-active-ledger.json"
    )
    if document.get("schema_version") == 4:
        document["schema_version"] = 2
        document["status"] = "in_progress"
        document.pop("acceptance", None)
        document.pop("operational_acceptance", None)
        document["gate_results"] = [
            gate
            for gate in document["gate_results"]
            if gate["id"] != "loop-9-operational-read-only-cutover"
        ]
    return document


def _write_active_loop9_ledger(path: Path, project_root: Path) -> None:
    path.write_text(
        json.dumps(
            _active_loop9_ledger(project_root),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _project_ledger(project_root: Path, tmp_path: Path) -> Path:
    path = tmp_path / "project" / "verification" / "loop-ledger.json"
    path.parent.mkdir(parents=True)
    _write_active_loop9_ledger(path, project_root)
    return path


def test_repository_ledger_matches_json_schema(project_root: Path) -> None:
    schema = _load_json(project_root / "verification" / "loop-ledger.schema.json")
    ledger = _load_json(project_root / "verification" / "loop-ledger.json")
    Draft202012Validator(schema).validate(ledger)


@pytest.mark.parametrize(
    "status",
    (
        "operational_read_only_with_guard",
        "operational_read_only_accepted",
    ),
)
def test_operational_acceptance_uses_only_the_dedicated_writer(
    project_root: Path,
    tmp_path: Path,
    status: str,
) -> None:
    ledger_path = _project_ledger(project_root, tmp_path)
    store = LedgerStore(ledger_path)
    before = store.read()
    revision = int(before["revision"])
    evidence = "verification/loops/loop-9/operational/acceptance.json"
    commit = "c" * 40

    forged = deepcopy(before)
    forged["revision"] = revision + 1
    forged["status"] = status
    with pytest.raises(
        LedgerValidationError,
        match="dedicated Loop 9 acceptance writer",
    ):
        store.replace(expected_revision=revision, document=forged)

    updated = store.commit_operational_read_only_acceptance(
        expected_revision=revision,
        evidence_path=evidence,
        evidence_sha256="a" * 64,
        status=status,
        build_git_commit=commit,
        accepted_at="2026-08-02T12:00:00+00:00",
        unresolved_risks=["strict shadow acceptance remains pending"],
        next_inputs=["continue guarded read-only operation"],
    )

    assert updated["schema_version"] == 4
    assert updated["status"] == status
    assert updated["last_accepted_git_commit"] == commit
    assert updated["operational_acceptance"] == {
        "accepted_at": "2026-08-02T12:00:00+00:00",
        "build_git_commit": commit,
        "evidence": evidence,
        "kind": "loop9_operational_read_only_acceptance",
        "previous_status": "in_progress",
        "sha256": "a" * 64,
        "status": status,
    }
    strict_gates = {
        gate["id"]: gate["status"]
        for gate in before["gate_results"]
    }
    assert {
        gate["id"]: gate["status"]
        for gate in updated["gate_results"]
        if gate["id"] in strict_gates
    } == strict_gates
    assert updated["gate_results"][-1] == {
        "evidence": evidence,
        "id": "loop-9-operational-read-only-cutover",
        "status": "passed",
    }

    schema = _load_json(project_root / "verification" / "loop-ledger.schema.json")
    Draft202012Validator(schema).validate(updated)


def test_operational_acceptance_rejects_invalid_status(
    project_root: Path,
    tmp_path: Path,
) -> None:
    store = LedgerStore(_project_ledger(project_root, tmp_path))
    with pytest.raises(
        LedgerValidationError,
        match="operational acceptance status",
    ):
        store.commit_operational_read_only_acceptance(
            expected_revision=int(store.read()["revision"]),
            evidence_path="verification/acceptance.json",
            evidence_sha256="a" * 64,
            status="shadow_accepted",
            build_git_commit="b" * 40,
            accepted_at="2026-08-02T12:00:00+00:00",
            unresolved_risks=[],
            next_inputs=[],
        )


def test_operational_policy_change_preserves_strict_pending_gates(
    project_root: Path,
    tmp_path: Path,
) -> None:
    store = LedgerStore(_project_ledger(project_root, tmp_path))
    active = store.read()
    accepted = store.commit_operational_read_only_acceptance(
        expected_revision=int(active["revision"]),
        evidence_path="verification/operational-acceptance.json",
        evidence_sha256="a" * 64,
        status="operational_read_only_with_guard",
        build_git_commit="b" * 40,
        accepted_at="2026-08-02T12:00:00+00:00",
        unresolved_risks=["first-batch protection remains active"],
        next_inputs=["review 30 unique waybills"],
    )
    strict_before = {
        gate["id"]: gate["status"]
        for gate in accepted["gate_results"]
        if gate["id"] != "loop-9-operational-read-only-cutover"
    }

    updated = store.commit_operational_read_only_policy_change(
        expected_revision=int(accepted["revision"]),
        evidence_path="verification/operational-policy-change.json",
        evidence_sha256="c" * 64,
        build_git_commit="d" * 40,
        changed_at="2026-08-07T01:30:00+00:00",
        unresolved_risks=["strict shadow acceptance remains pending"],
        next_inputs=["monitor production business outcomes"],
    )

    assert updated["status"] == "operational_read_only_active"
    assert updated["last_accepted_git_commit"] == "d" * 40
    assert updated["operational_acceptance"] == {
        "accepted_at": "2026-08-07T01:30:00+00:00",
        "build_git_commit": "d" * 40,
        "evidence": "verification/operational-policy-change.json",
        "kind": "loop9_operational_read_only_policy_change",
        "previous_status": "operational_read_only_with_guard",
        "sha256": "c" * 64,
        "status": "operational_read_only_active",
    }
    assert {
        gate["id"]: gate["status"]
        for gate in updated["gate_results"]
        if gate["id"] != "loop-9-operational-read-only-cutover"
    } == strict_before
    schema = _load_json(project_root / "verification" / "loop-ledger.schema.json")
    Draft202012Validator(schema).validate(updated)


def test_ledger_update_is_atomic_and_revision_guarded(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "loop-ledger.json"
    _write_active_loop9_ledger(ledger_path, project_root)
    store = LedgerStore(ledger_path)
    original = store.read()
    original_revision = int(original["revision"])
    replacement = deepcopy(original)
    replacement["revision"] = original_revision + 1
    replacement["status"] = "blocked"
    replacement["waiver"] = None
    replacement["unresolved_risks"] = ["test risk"]

    updated = store.replace(expected_revision=original_revision, document=replacement)
    assert updated["revision"] == original_revision + 1
    assert store.read()["unresolved_risks"] == ["test risk"]

    with pytest.raises(LedgerConflictError):
        store.replace(expected_revision=original_revision, document=replacement)


def test_failure_before_replace_preserves_previous_ledger(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "loop-ledger.json"
    _write_active_loop9_ledger(ledger_path, project_root)
    before = ledger_path.read_bytes()

    def fail_before_replace(_: Path) -> None:
        raise OSError("injected failure")

    store = LedgerStore(ledger_path, before_replace=fail_before_replace)
    replacement = deepcopy(store.read())
    original_revision = int(replacement["revision"])
    replacement["revision"] = original_revision + 1
    replacement["status"] = "blocked"
    replacement["waiver"] = None

    with pytest.raises(OSError, match="injected failure"):
        store.replace(expected_revision=original_revision, document=replacement)

    assert ledger_path.read_bytes() == before
    assert list(tmp_path.glob("*.tmp")) == []


def test_accepted_ledger_requires_passed_gates_and_commit(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "loop-ledger.json"
    _write_active_loop9_ledger(ledger_path, project_root)
    store = LedgerStore(ledger_path)
    replacement = deepcopy(store.read())
    original_revision = int(replacement["revision"])
    replacement["revision"] = original_revision + 1
    replacement["schema_version"] = 2
    replacement["status"] = "accepted"
    replacement["last_accepted_git_commit"] = None

    with pytest.raises(LedgerValidationError):
        store.replace(expected_revision=original_revision, document=replacement)


def test_closed_with_waiver_preserves_failed_gate_and_requires_evidence(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "loop-ledger.json"
    _write_active_loop9_ledger(ledger_path, project_root)
    store = LedgerStore(ledger_path)
    replacement = deepcopy(store.read())
    original_revision = int(replacement["revision"])
    original_commit = replacement["last_accepted_git_commit"]
    replacement["revision"] = original_revision + 1
    replacement["schema_version"] = 2
    replacement["status"] = "closed_with_waiver"
    replacement["gate_results"][-1]["status"] = "failed"
    replacement["gate_results"][-1]["evidence"] = (
        "verification/loops/loop-7/waiver/gate-results.json"
    )
    replacement["unresolved_risks"] = ["CPU/GPU parity was not established."]
    replacement["waiver"] = {
        "accepted_by": "operator-01",
        "accepted_at": "2026-07-27T16:00:00+08:00",
        "evidence": "verification/loops/loop-7/waiver/waiver.json",
        "permits_next_loop": True,
        "prohibited_claims": [
            "loop_7_accepted",
            "shadow_accepted",
            "cpu_gpu_parity",
        ],
        "reason": "The operator declined a replacement locked set.",
    }

    updated = store.replace(
        expected_revision=original_revision,
        document=replacement,
    )

    assert updated["status"] == "closed_with_waiver"
    assert updated["gate_results"][-1]["status"] == "failed"
    assert updated["last_accepted_git_commit"] == original_commit


def test_waiver_cannot_turn_a_failed_loop_into_accepted(
    project_root: Path,
    tmp_path: Path,
) -> None:
    document = _active_loop9_ledger(project_root)
    document["schema_version"] = 2
    document["status"] = "accepted"
    document["waiver"] = {
        "accepted_by": "operator-01",
        "accepted_at": "2026-07-27T16:00:00+08:00",
        "evidence": "verification/loops/loop-7/waiver/waiver.json",
        "permits_next_loop": True,
        "prohibited_claims": ["loop_7_accepted"],
        "reason": "Synthetic waiver.",
    }
    document["gate_results"][-1]["status"] = "failed"
    document["gate_results"][-1]["evidence"] = (
        "verification/loops/loop-7/waiver/gate-results.json"
    )

    with pytest.raises(LedgerValidationError):
        from dahe.verification.ledger import validate_document

        validate_document(document)


def test_general_replace_cannot_write_shadow_acceptance(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "loop-ledger.json"
    _write_active_loop9_ledger(ledger_path, project_root)
    store = LedgerStore(ledger_path)
    replacement = deepcopy(store.read())
    original_revision = int(replacement["revision"])
    replacement["revision"] = original_revision + 1
    replacement["schema_version"] = 3
    replacement["status"] = "shadow_accepted"
    replacement["waiver"] = None
    replacement["acceptance"] = {
        "kind": "loop9_shadow_acceptance",
        "accepted_at": "2026-07-30T12:00:00+00:00",
        "evidence": (
            "verification/loops/loop-9/formal/"
            + "a" * 64
            + ".json"
        ),
        "sha256": "a" * 64,
        "previous_status": "in_progress",
        "previous_last_accepted_git_commit": replacement[
            "last_accepted_git_commit"
        ],
    }
    for gate in replacement["gate_results"]:
        gate["status"] = "passed"
        gate["evidence"] = replacement["acceptance"]["evidence"]

    with pytest.raises(
        LedgerValidationError,
        match="dedicated Loop 9 acceptance",
    ):
        store.replace(
            expected_revision=original_revision,
            document=replacement,
        )


def test_ledger_store_exposes_no_public_shadow_acceptance_writer() -> None:
    assert not hasattr(LedgerStore, "replace_shadow_accepted")


def test_generic_replace_rejects_duck_typed_shadow_permit(
    project_root: Path,
    tmp_path: Path,
) -> None:
    class FakeGuard:
        def revalidate(self) -> None:
            return

    class FakePermit:
        def guard_for(self, **_: object) -> FakeGuard:
            return FakeGuard()

        def consume(self) -> None:
            return

    ledger_path = _project_ledger(project_root, tmp_path)
    store = LedgerStore(ledger_path)
    before = ledger_path.read_bytes()
    replacement = deepcopy(store.read())
    revision = int(replacement["revision"])
    reference = (
        "verification/loops/loop-9/formal/"
        + "a" * 64
        + ".json"
    )
    replacement["revision"] = revision + 1
    replacement["schema_version"] = 3
    replacement["status"] = "shadow_accepted"
    replacement["waiver"] = None
    replacement["unresolved_risks"] = []
    replacement["next_inputs"] = []
    replacement["acceptance"] = {
        "kind": "loop9_shadow_acceptance",
        "accepted_at": "2026-07-30T12:00:00+00:00",
        "evidence": reference,
        "sha256": "a" * 64,
        "previous_status": "in_progress",
        "previous_last_accepted_git_commit": replacement[
            "last_accepted_git_commit"
        ],
    }
    for gate in replacement["gate_results"]:
        gate["status"] = "passed"
        gate["evidence"] = reference

    with pytest.raises((LedgerValidationError, TypeError)):
        store._replace(
            expected_revision=revision,
            document=replacement,
            acceptance_permit=FakePermit(),  # type: ignore[arg-type]
        )

    assert ledger_path.read_bytes() == before


def test_private_shadow_permit_is_not_constructible() -> None:
    assert not hasattr(ledger_module, "_ShadowAcceptancePermit")
    assert not hasattr(
        ledger_module,
        "_SHADOW_ACCEPTANCE_PERMIT_KEY",
    )


def test_internal_shadow_writer_rejects_copied_ledger(
    project_root: Path,
    tmp_path: Path,
) -> None:
    from dahe.verification.loop9_final_acceptance import (
        Loop9FinalAcceptanceInputs,
    )

    ledger_path = _project_ledger(project_root, tmp_path)
    copied_project = ledger_path.parents[1]
    data_root = copied_project / "data"
    inputs = Loop9FinalAcceptanceInputs(
        project_root=copied_project,
        data_root=data_root,
        read_contract_validation_path=data_root / "read.json",
        current_locked_selection_sha256="a" * 64,
        real_shadow_selection_sha256="b" * 64,
        real_shadow_package_dir=data_root / "review",
        real_shadow_seal_path=data_root / "seal.json",
        real_shadow_machine_evaluation_path=data_root / "machine.json",
        daily_snapshot_validation_path=data_root / "daily.json",
        discovery_development_path=data_root / "discovery.json",
        current_locked_50_path=data_root / "locked.json",
        real_shadow_30_path=data_root / "shadow.json",
        daily_validation_dataset_path=data_root / "daily-data.json",
        source_development_authority_path=data_root / "authority.json",
        dataset_isolation_path=data_root / "isolation.json",
        formal_run_evidence_sha256="c" * 64,
        locked_job_id="locked-job",
        real_shadow_job_id="shadow-job",
        fault_scenarios={},
    )
    store = LedgerStore(ledger_path)

    with store.locked_write(), pytest.raises(
        LedgerValidationError,
        match="active repository ledger",
    ):
        store._commit_verified_shadow_acceptance(
            expected_revision=int(store.read()["revision"]),
            evidence_path="invalid",
            evidence_sha256="d" * 64,
            accepted_at="2026-07-30T12:00:00+00:00",
            remaining_risks=[],
            inputs=inputs,
        )


def test_internal_shadow_writer_rejects_untyped_inputs(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = _project_ledger(project_root, tmp_path)
    store = LedgerStore(ledger_path)
    before = ledger_path.read_bytes()
    replacement = deepcopy(store.read())
    revision = int(replacement["revision"])
    digest = "a" * 64
    reference = (
        "verification/loops/loop-9/formal/"
        f"{digest}.json"
    )
    replacement["revision"] = revision + 1
    replacement["schema_version"] = 3
    replacement["status"] = "shadow_accepted"
    replacement["waiver"] = None
    replacement["acceptance"] = {
        "kind": "loop9_shadow_acceptance",
        "accepted_at": "2026-07-30T12:00:00+00:00",
        "evidence": reference,
        "sha256": digest,
        "previous_status": "in_progress",
        "previous_last_accepted_git_commit": replacement[
            "last_accepted_git_commit"
        ],
    }

    with pytest.raises(
        LedgerValidationError,
        match="existing ledger write lock",
    ):
        store._commit_verified_shadow_acceptance(
            expected_revision=revision,
            evidence_path=reference,
            evidence_sha256=digest,
            accepted_at="2026-07-30T12:00:00+00:00",
            remaining_risks=[],
            inputs={"gate_passed": True},
        )

    with store.locked_write(), pytest.raises(
        LedgerValidationError,
        match="typed final acceptance inputs",
    ):
        store._commit_verified_shadow_acceptance(
            expected_revision=revision,
            evidence_path=reference,
            evidence_sha256=digest,
            accepted_at="2026-07-30T12:00:00+00:00",
            remaining_risks=[],
            inputs={"gate_passed": True},
        )

    assert ledger_path.read_bytes() == before
    assert store.read()["revision"] == revision


def test_shadow_acceptance_requires_loop9_passed_gates_and_preserved_commit(
    project_root: Path,
) -> None:
    from dahe.verification.ledger import validate_document

    document = _active_loop9_ledger(project_root)
    document["schema_version"] = 3
    document["status"] = "shadow_accepted"
    document["waiver"] = None
    document["acceptance"] = {
        "kind": "loop9_shadow_acceptance",
        "accepted_at": "2026-07-30T12:00:00+00:00",
        "evidence": (
            "verification/loops/loop-9/formal/"
            + "a" * 64
            + ".json"
        ),
        "sha256": "a" * 64,
        "previous_status": "in_progress",
        "previous_last_accepted_git_commit": document[
            "last_accepted_git_commit"
        ],
    }
    for gate in document["gate_results"]:
        gate["status"] = "passed"
        gate["evidence"] = document["acceptance"]["evidence"]

    validate_document(document)

    forged = deepcopy(document)
    forged["last_accepted_git_commit"] = "b" * 40
    with pytest.raises(LedgerValidationError, match="preserve"):
        validate_document(forged)

    forged = deepcopy(document)
    forged["gate_results"][0]["status"] = "failed"
    with pytest.raises(LedgerValidationError, match="passed gates"):
        validate_document(forged)


def test_shadow_acceptance_is_terminal(
    project_root: Path,
    tmp_path: Path,
) -> None:
    from dahe.verification.ledger import validate_document

    document = _active_loop9_ledger(project_root)
    document["schema_version"] = 3
    document["status"] = "shadow_accepted"
    document["waiver"] = None
    document["acceptance"] = {
        "kind": "loop9_shadow_acceptance",
        "accepted_at": "2026-07-30T12:00:00+00:00",
        "evidence": (
            "verification/loops/loop-9/formal/"
            + "a" * 64
            + ".json"
        ),
        "sha256": "a" * 64,
        "previous_status": "in_progress",
        "previous_last_accepted_git_commit": document[
            "last_accepted_git_commit"
        ],
    }
    for gate in document["gate_results"]:
        gate["status"] = "passed"
        gate["evidence"] = document["acceptance"]["evidence"]
    validate_document(document)

    path = tmp_path / "loop-ledger.json"
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    replacement = deepcopy(document)
    replacement["revision"] = int(document["revision"]) + 1
    replacement["status"] = "in_progress"
    replacement["acceptance"] = None

    with pytest.raises(
        LedgerValidationError,
        match="terminal ledger state",
    ):
        LedgerStore(path).replace(
            expected_revision=int(document["revision"]),
            document=replacement,
        )


def test_concurrent_stale_writer_cannot_overwrite_new_revision(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = _project_ledger(project_root, tmp_path)
    first_entered = threading.Event()
    release_first = threading.Event()

    def pause_before_replace(_: Path) -> None:
        first_entered.set()
        assert release_first.wait(timeout=5)

    first_store = LedgerStore(
        ledger_path,
        before_replace=pause_before_replace,
    )
    second_store = LedgerStore(ledger_path)
    original = first_store.read()
    revision = int(original["revision"])
    first = deepcopy(original)
    first["revision"] = revision + 1
    first["status"] = "blocked"
    first["unresolved_risks"] = ["first writer"]
    second = deepcopy(original)
    second["revision"] = revision + 1
    second["status"] = "blocked"
    second["unresolved_risks"] = ["second writer"]

    def write(
        store: LedgerStore,
        document: dict[str, object],
    ) -> str:
        try:
            store.replace(
                expected_revision=revision,
                document=document,
            )
        except LedgerConflictError:
            return "conflict"
        return "written"

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(write, first_store, first)
        assert first_entered.wait(timeout=5)
        second_future = executor.submit(write, second_store, second)
        time.sleep(0.1)
        release_first.set()
        outcomes = {
            first_future.result(timeout=5),
            second_future.result(timeout=5),
        }

    assert outcomes == {"written", "conflict"}
    assert LedgerStore(ledger_path).read()["revision"] == revision + 1


def test_os_file_lock_rejects_cross_process_stale_writer(
    project_root: Path,
    tmp_path: Path,
) -> None:
    ledger_path = _project_ledger(project_root, tmp_path)
    revision = int(LedgerStore(ledger_path).read()["revision"])
    start = tmp_path / "start"
    script = """
import sys
import time
from copy import deepcopy
from pathlib import Path
from dahe.verification.ledger import LedgerConflictError, LedgerStore

path = Path(sys.argv[1])
expected = int(sys.argv[2])
risk = sys.argv[3]
ready = Path(sys.argv[4])
start = Path(sys.argv[5])
ready.write_text("ready", encoding="utf-8")
while not start.exists():
    time.sleep(0.01)
store = LedgerStore(path, before_replace=lambda _path: time.sleep(0.4))
document = deepcopy(store.read())
document["revision"] = expected + 1
document["status"] = "blocked"
document["waiver"] = None
document["unresolved_risks"] = [risk]
try:
    store.replace(expected_revision=expected, document=document)
except LedgerConflictError:
    print("conflict")
else:
    print("written")
"""
    processes: list[subprocess.Popen[str]] = []
    ready_paths: list[Path] = []
    for index in range(2):
        ready = tmp_path / f"ready-{index}"
        ready_paths.append(ready)
        processes.append(
            subprocess.Popen(
                [
                    str(
                        project_root
                        / ".venv"
                        / "Scripts"
                        / "python.exe"
                    ),
                    "-c",
                    script,
                    str(ledger_path),
                    str(revision),
                    f"writer-{index}",
                    str(ready),
                    str(start),
                ],
                cwd=project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        )
    deadline = time.monotonic() + 5
    while (
        not all(path.exists() for path in ready_paths)
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert all(path.exists() for path in ready_paths)
    start.write_text("start", encoding="utf-8")

    results = [
        process.communicate(timeout=10)
        for process in processes
    ]
    assert {stdout.strip() for stdout, _ in results} == {
        "written",
        "conflict",
    }, results
    assert all(process.returncode == 0 for process in processes)
    assert LedgerStore(ledger_path).read()["revision"] == revision + 1
