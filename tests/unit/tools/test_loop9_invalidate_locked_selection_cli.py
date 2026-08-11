from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.application.chengfeng.shadow_selection_lifecycle import (
    FormalSelectionLifecycleEvent,
)
from tools import loop9_invalidate_locked_selection as module

EXPECTED_BUILD = "a" * 64
EXPECTED_SELECTION = "b" * 64
REPLACEMENT_SELECTION = "c" * 64
SETTLEMENT_CONTRACT = "d" * 64
SETTLEMENT_SELECTION = "e" * 64
DAILY_CONTRACT = "f" * 64
DAILY_SELECTION = "1" * 64


def _arguments(tmp_path: Path) -> list[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    package = (tmp_path / "review-package").resolve()
    package.mkdir(exist_ok=True)
    answers = (tmp_path / "answers.json").resolve()
    answers.write_text("{}\n", encoding="utf-8")
    return [
        "--data-root",
        str(tmp_path.resolve()),
        "--selection-sha256",
        EXPECTED_SELECTION,
        "--review-package",
        str(package),
        "--review-answers",
        str(answers),
        "--expected-current-build-sha256",
        EXPECTED_BUILD,
        "--output",
        str((tmp_path / "invalidation.json").resolve()),
    ]


def _install_success_fakes(
    *,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[SimpleNamespace, list[dict[str, object]]]:
    batch = SimpleNamespace(
        source_build_sha256=EXPECTED_BUILD,
        contract_canonical_sha256=SETTLEMENT_CONTRACT,
        contract_selection_sha256=SETTLEMENT_SELECTION,
        pipeline_fingerprint="2" * 64,
        identity_context_sha256="3" * 64,
    )
    selection = SimpleNamespace(
        canonical_sha256=EXPECTED_SELECTION,
        batch_manifest=batch,
        exclusion_source_boundary_sha256="4" * 64,
        exclusion_source_inventory_high_watermark=9,
    )
    active = SimpleNamespace(
        canonical_sha256="5" * 64,
        event_kind=FormalSelectionLifecycleEvent.ACTIVATED,
        selection_sha256=EXPECTED_SELECTION,
        generation=1,
        source_build_sha256=EXPECTED_BUILD,
        pipeline_fingerprint=batch.pipeline_fingerprint,
        identity_context_sha256=batch.identity_context_sha256,
    )
    invalidated = SimpleNamespace(
        canonical_sha256="6" * 64,
        event_kind=FormalSelectionLifecycleEvent.INVALIDATED,
        selection_sha256=EXPECTED_SELECTION,
        generation=1,
        source_build_sha256=EXPECTED_BUILD,
        pipeline_fingerprint=batch.pipeline_fingerprint,
        identity_context_sha256=batch.identity_context_sha256,
    )
    lifecycle = SimpleNamespace(tip=active)
    lifecycle.load_state = lambda: SimpleNamespace(
        event_kind=lifecycle.tip.event_kind,
        active_selection_sha256=(
            EXPECTED_SELECTION
            if lifecycle.tip.event_kind
            is FormalSelectionLifecycleEvent.ACTIVATED
            else None
        ),
    )
    lifecycle.load_tip = lambda: lifecycle.tip
    lifecycle.invalidate_current_locked_selection = (
        lambda **_values: setattr(lifecycle, "tip", invalidated)
        or invalidated
    )
    store = SimpleNamespace(
        load_manifest=lambda value: (
            selection
            if value == EXPECTED_SELECTION
            else pytest.fail("unexpected selection")
        ),
        load_active_current_locked_manifest=lambda value: (
            selection
            if value == EXPECTED_SELECTION
            else pytest.fail("unexpected active selection")
        ),
    )
    runtime = SimpleNamespace(close=lambda: None)
    source_boundary = SimpleNamespace(
        canonical_sha256=selection.exclusion_source_boundary_sha256,
        source_inventory_high_watermark=(
            selection.exclusion_source_inventory_high_watermark
        ),
    )
    attestation = SimpleNamespace(
        canonical_sha256="7" * 64,
        missing_conditions=("blur", "rotation_90"),
        gate_passed=False,
        review_answers_sha256="8" * 64,
    )
    inventory = SimpleNamespace(canonical_sha256="9" * 64)
    snapshot = SimpleNamespace(
        authority_sha256="0" * 64,
        child_index_head_sha256="1" * 64,
    )
    authority = SimpleNamespace(canonical_sha256=snapshot.authority_sha256)
    calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: EXPECTED_BUILD,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=SETTLEMENT_CONTRACT
            ),
            selection_sha256=SETTLEMENT_SELECTION,
        ),
    )
    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(canonical_sha256=DAILY_CONTRACT),
            selection_sha256=DAILY_SELECTION,
        ),
    )
    monkeypatch.setattr(module, "SqliteRuntime", lambda **_values: runtime)
    monkeypatch.setattr(
        module,
        "FormalShadowSelectionStore",
        lambda _root: store,
    )
    monkeypatch.setattr(
        module,
        "FormalSelectionLifecycleStore",
        lambda _root: lifecycle,
    )
    monkeypatch.setattr(
        module,
        "build_current_formal_development_authority",
        lambda _runtime: object(),
    )
    monkeypatch.setattr(
        module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda _authority: source_boundary,
    )
    monkeypatch.setattr(
        module,
        "load_loop9_review_package",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        module,
        "build_locked_selection_coverage_failure_attestation",
        lambda **_values: attestation,
    )
    monkeypatch.setattr(
        module,
        "development_inventory_from_failed_locked_selection",
        lambda **_values: inventory,
    )
    monkeypatch.setattr(
        module,
        "persist_locked_selection_failure_attestation",
        lambda **_values: (
            tmp_path / "verification" / "failure" / "failure.json"
        ),
    )
    monkeypatch.setattr(
        module,
        "register_loop9_development_exclusion_inventory",
        lambda **_values: (
            tmp_path / "loop9-development-exclusions" / "inventory.json"
        ),
    )

    def append(**values: object) -> object:
        calls.append(values)
        return object()

    monkeypatch.setattr(module, "append_loop9_exclusion_child", append)
    monkeypatch.setattr(
        module,
        "load_current_loop9_full_history_exclusion_authority",
        lambda **_values: authority,
    )
    monkeypatch.setattr(
        module,
        "persist_loop9_full_history_exclusion_authority",
        lambda **_values: (
            tmp_path / "verification" / "authority" / "authority.json"
        ),
    )
    monkeypatch.setattr(
        module,
        "load_verified_loop9_exclusion_snapshot",
        lambda **_values: snapshot,
    )
    return lifecycle, calls


def test_cli_invalidates_current_generation_and_retries_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lifecycle, append_calls = _install_success_fakes(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )
    arguments = _arguments(tmp_path)

    assert module.main(arguments) == 0
    first_output = Path(arguments[-1]).read_bytes()
    assert module.main(arguments) == 0

    result = json.loads(first_output)
    assert Path(arguments[-1]).read_bytes() == first_output
    assert result["status"] == "invalidated"
    assert result["coverage_gate_passed"] is False
    assert result["selection_sha256"] == EXPECTED_SELECTION
    assert result["missing_conditions"] == ["blur", "rotation_90"]
    assert result["lifecycle_generation"] == 1
    assert result["lifecycle_head_sha256"] == "6" * 64
    assert (
        lifecycle.tip.event_kind
        is FormalSelectionLifecycleEvent.INVALIDATED
    )
    assert len(append_calls) == 2
    assert all(
        call["child_inventory"].canonical_sha256 == "9" * 64
        for call in append_calls
    )
    terminal = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
    ]
    assert terminal[0] == terminal[1] == {
        "canonical_sha256": result["canonical_sha256"],
        "coverage_gate_passed": False,
        "lifecycle_generation": 1,
        "missing_conditions": ["blur", "rotation_90"],
        "selection_sha256": EXPECTED_SELECTION,
        "status": "invalidated",
    }


def test_cli_rejects_invalidated_old_generation_after_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle, _ = _install_success_fakes(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
    )
    lifecycle.tip = SimpleNamespace(
        canonical_sha256="a" * 64,
        event_kind=FormalSelectionLifecycleEvent.ACTIVATED,
        selection_sha256=REPLACEMENT_SELECTION,
        generation=2,
    )
    monkeypatch.setattr(
        module,
        "persist_locked_selection_failure_attestation",
        lambda **_values: pytest.fail("old generation was mutated"),
    )

    with pytest.raises(
        module.Loop9LockedSelectionInvalidationError,
        match="not the current lifecycle generation",
    ):
        module.main(_arguments(tmp_path))


def test_cli_rejects_build_drift_relative_paths_and_symlink_answers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _arguments(tmp_path)
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: "f" * 64,
    )
    with pytest.raises(
        module.Loop9LockedSelectionInvalidationError,
        match="build fingerprint changed",
    ):
        module.main(arguments)

    relative = _arguments(tmp_path / "relative")
    relative[1] = "relative"
    with pytest.raises(SystemExit):
        module.main(relative)

    unsafe_root = tmp_path / "reparse-case"
    symlink_arguments = _arguments(unsafe_root)
    unsafe_answers = Path(symlink_arguments[7])
    original_reparse_check = module._is_reparse_point
    monkeypatch.setattr(
        module,
        "_is_reparse_point",
        lambda path: path == unsafe_answers
        or original_reparse_check(path),
    )
    with pytest.raises(
        module.Loop9LockedSelectionInvalidationError,
        match="human review answers path is unsafe",
    ):
        module.main(symlink_arguments)
