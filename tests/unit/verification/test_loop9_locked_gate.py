from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.verification.loop9_human_review import (
    load_loop9_review_package,
)
from dahe.verification.loop9_locked_gate import (
    CurrentLockedGateAuthorityStore,
    Loop9CurrentLockedGateError,
)
from dahe.verification.loop9_machine_results import (
    persist_machine_truth_evaluation,
)
from tests.unit.verification.test_loop9_human_review import (
    _answers,
    _prepare_locked,
    _with_hash,
    _write_json,
    seal_loop9_review,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _selection(
    batch: object,
    *,
    rank: str = "rank-v1",
) -> FormalShadowSelectionManifest:
    return FormalShadowSelectionManifest(
        target_kind=batch.target_kind,
        source_capture_sha256=_sha("capture"),
        full_history_exclusion_authority_sha256=_sha("exclusions"),
        exclusion_child_index_head_sha256=_sha("child-index"),
        exclusion_source_boundary_sha256=_sha("source-boundary"),
        exclusion_source_inventory_high_watermark=1,
        selection_seed_authority_sha256=_sha("seed"),
        rank_commitment_sha256=_sha(rank),
        prior_selection_sha256s=(),
        batch_manifest=batch,
    )


def _gate_inputs(
    tmp_path: Path,
    *,
    gate_passed: bool = True,
) -> tuple[
    FormalShadowSelectionManifest,
    Path,
    Path,
    Path,
    dict[str, object],
]:
    package_dir, batch, package_payload = _prepare_locked(tmp_path)
    answers_path = _write_json(
        (tmp_path / "answers.json").resolve(),
        _answers(
            package_payload=package_payload,
            batch=batch,
            locked=True,
        ),
    )
    seal_path = (tmp_path / "seal.json").resolve()
    seal = seal_loop9_review(
        package_dir=package_dir,
        review_answers_path=answers_path,
        output_path=seal_path,
    )
    item_results = [
        {
            "actual_outcome": "normal_ready",
            "classification": "match",
            "diagnostic_code": None,
            "expected_outcome": "normal_ready",
            "high_confidence_role_error_count": 0,
            "image_difference_count": 0,
            "item_identity_sha256": item.item_identity_sha256,
            "wrong_auto_pass": False,
        }
        for item in batch.items
    ]
    evaluation = _with_hash(
        {
            "authority_sha256": _sha("machine-authority"),
            "gate_passed": gate_passed,
            "high_confidence_role_error_count": 0,
            "image_count": 100,
            "item_count": 50,
            "item_results": item_results,
            "kind": "loop9_machine_truth_evaluation",
            "machine_result_sha256": _sha("machine-result"),
            "package_sha256": package_payload["canonical_sha256"],
            "performance": {},
            "review_kind": "current_locked_50",
            "runtime_observation_count": 200,
            "schema_version": 1,
            "seal_sha256": seal["canonical_sha256"],
            "selected_image_difference_count": 0,
            "source_batch_sha256": batch.canonical_sha256,
            "technical_failure_count": 0,
            "wrong_auto_pass_count": 0,
        }
    )
    machine_result_sha256 = cast(
        str,
        evaluation["machine_result_sha256"],
    )
    machine_result_path = (
        tmp_path.resolve()
        / "verification"
        / "loop9"
        / "machine-results"
        / machine_result_sha256[:2]
        / f"{machine_result_sha256}.json"
    )
    machine_result_path.parent.mkdir(parents=True, exist_ok=True)
    machine_result_path.write_text("{}\n", encoding="utf-8")
    evaluation_path = persist_machine_truth_evaluation(
        data_root=tmp_path.resolve(),
        payload=evaluation,
    )
    return (
        load_loop9_review_package(package_dir).formal_selection,
        package_dir,
        seal_path,
        evaluation_path,
        evaluation,
    )


def _patch_machine_replay(
    monkeypatch: pytest.MonkeyPatch,
    *,
    selection: FormalShadowSelectionManifest,
    evaluation: dict[str, object],
    machine_selection_sha256: str | None = None,
) -> None:
    monkeypatch.setattr(
        "dahe.verification.loop9_locked_gate."
        "evaluate_sealed_machine_results",
        lambda **_kwargs: evaluation,
    )
    monkeypatch.setattr(
        "dahe.verification.loop9_locked_gate."
        "load_machine_result_manifest",
        lambda _path: {
            "authority": {
                "authority_sha256": evaluation["authority_sha256"],
                "current_loop9_build_sha256": (
                    selection.batch_manifest.source_build_sha256
                ),
            },
            "source": {
                "formal_selection_sha256": (
                    machine_selection_sha256
                    or selection.canonical_sha256
                ),
                "locked_gate_evidence_sha256": None,
                "source_batch_sha256": (
                    selection.batch_manifest.canonical_sha256
                ),
                "source_build_sha256": (
                    selection.batch_manifest.source_build_sha256
                ),
            },
        },
    )


def test_gate_rejects_machine_result_bound_to_another_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, package_dir, seal_path, evaluation_path, evaluation = (
        _gate_inputs(tmp_path)
    )
    _patch_machine_replay(
        monkeypatch,
        selection=selection,
        evaluation=evaluation,
        machine_selection_sha256=_sha("another-selection"),
    )
    store = CurrentLockedGateAuthorityStore(tmp_path.resolve())

    with pytest.raises(
        Loop9CurrentLockedGateError,
        match="machine gate",
    ):
        store.publish(
            locked_selection=selection,
            package_dir=package_dir,
            seal_path=seal_path,
            evaluation_path=evaluation_path,
            expected_current_build_sha256=(
                selection.batch_manifest.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                selection.batch_manifest.contract_canonical_sha256
            ),
        )


def test_selection_scoped_gate_replays_and_loads_write_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, package_dir, seal_path, evaluation_path, evaluation = (
        _gate_inputs(tmp_path)
    )
    _patch_machine_replay(
        monkeypatch,
        selection=selection,
        evaluation=evaluation,
    )
    store = CurrentLockedGateAuthorityStore(tmp_path.resolve())

    gate = store.publish(
        locked_selection=selection,
        package_dir=package_dir,
        seal_path=seal_path,
        evaluation_path=evaluation_path,
        expected_current_build_sha256=(
            selection.batch_manifest.source_build_sha256
        ),
        expected_settlement_contract_sha256=(
            selection.batch_manifest.contract_canonical_sha256
        ),
    )
    assert gate.selection_sha256 == selection.canonical_sha256
    assert gate.gate_passed is True
    assert gate.item_count == 50
    assert gate.image_count == 100
    assert store.publish(
        locked_selection=selection,
        package_dir=package_dir,
        seal_path=seal_path,
        evaluation_path=evaluation_path,
        expected_current_build_sha256=(
            selection.batch_manifest.source_build_sha256
        ),
        expected_settlement_contract_sha256=(
            selection.batch_manifest.contract_canonical_sha256
        ),
    ) == gate
    assert (
        store.load_for_selection(
            locked_selection=selection,
            expected_current_build_sha256=(
                selection.batch_manifest.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                selection.batch_manifest.contract_canonical_sha256
            ),
        )
        == gate
    )
    assert (
        store.root
        / (
            "active-current-locked-gate-"
            f"{selection.canonical_sha256}.json"
        )
    ).is_file()


def test_gate_rejects_failed_gate_old_build_and_different_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, package_dir, seal_path, evaluation_path, evaluation = (
        _gate_inputs(tmp_path, gate_passed=False)
    )
    _patch_machine_replay(
        monkeypatch,
        selection=selection,
        evaluation=evaluation,
    )
    store = CurrentLockedGateAuthorityStore(tmp_path.resolve())
    with pytest.raises(
        Loop9CurrentLockedGateError,
        match="did not pass",
    ):
        store.publish(
            locked_selection=selection,
            package_dir=package_dir,
            seal_path=seal_path,
            evaluation_path=evaluation_path,
            expected_current_build_sha256=(
                selection.batch_manifest.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                selection.batch_manifest.contract_canonical_sha256
            ),
        )

    passing = {**evaluation, "gate_passed": True}
    passing["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            {
                key: value
                for key, value in passing.items()
                if key != "canonical_sha256"
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    passing_path = persist_machine_truth_evaluation(
        data_root=tmp_path.resolve(),
        payload=passing,
    )
    _patch_machine_replay(
        monkeypatch,
        selection=selection,
        evaluation=passing,
    )
    gate = store.publish(
        locked_selection=selection,
        package_dir=package_dir,
        seal_path=seal_path,
        evaluation_path=passing_path,
        expected_current_build_sha256=(
            selection.batch_manifest.source_build_sha256
        ),
        expected_settlement_contract_sha256=(
            selection.batch_manifest.contract_canonical_sha256
        ),
    )
    assert gate.gate_passed is True

    with pytest.raises(
        Loop9CurrentLockedGateError,
        match="build",
    ):
        store.load_for_selection(
            locked_selection=selection,
            expected_current_build_sha256=_sha("old-build"),
            expected_settlement_contract_sha256=(
                selection.batch_manifest.contract_canonical_sha256
            ),
        )
    different = replace(
        selection,
        rank_commitment_sha256=_sha("another-rank"),
    )
    with pytest.raises(
        Loop9CurrentLockedGateError,
        match="unavailable",
    ):
        store.load_for_selection(
            locked_selection=different,
            expected_current_build_sha256=(
                different.batch_manifest.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                different.batch_manifest.contract_canonical_sha256
            ),
        )


def test_gate_manifest_tampering_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, package_dir, seal_path, evaluation_path, evaluation = (
        _gate_inputs(tmp_path)
    )
    _patch_machine_replay(
        monkeypatch,
        selection=selection,
        evaluation=evaluation,
    )
    store = CurrentLockedGateAuthorityStore(tmp_path.resolve())
    gate = store.publish(
        locked_selection=selection,
        package_dir=package_dir,
        seal_path=seal_path,
        evaluation_path=evaluation_path,
        expected_current_build_sha256=(
            selection.batch_manifest.source_build_sha256
        ),
        expected_settlement_contract_sha256=(
            selection.batch_manifest.contract_canonical_sha256
        ),
    )
    manifest_path = (
        store.root
        / gate.canonical_sha256[:2]
        / f"{gate.canonical_sha256}.json"
    )
    payload = cast(
        dict[str, object],
        json.loads(manifest_path.read_text(encoding="utf-8")),
    )
    payload["gate_passed"] = False
    manifest_path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        Loop9CurrentLockedGateError,
        match=r"canonical|integrity",
    ):
        store.load_for_selection(
            locked_selection=selection,
            expected_current_build_sha256=(
                selection.batch_manifest.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                selection.batch_manifest.contract_canonical_sha256
            ),
        )


def test_gate_publish_rejects_selection_self_trust_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, package_dir, seal_path, evaluation_path, evaluation = (
        _gate_inputs(tmp_path)
    )
    _patch_machine_replay(
        monkeypatch,
        selection=selection,
        evaluation=evaluation,
    )
    store = CurrentLockedGateAuthorityStore(tmp_path.resolve())

    with pytest.raises(
        Loop9CurrentLockedGateError,
        match="build or contract",
    ):
        store.publish(
            locked_selection=selection,
            package_dir=package_dir,
            seal_path=seal_path,
            evaluation_path=evaluation_path,
            expected_current_build_sha256=_sha("actual-current-build"),
            expected_settlement_contract_sha256=(
                selection.batch_manifest.contract_canonical_sha256
            ),
        )

    assert not any(store.root.iterdir())
