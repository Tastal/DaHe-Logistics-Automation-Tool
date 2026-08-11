from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.application.template_studio.development_evaluation import (
    FrozenDevelopmentFixtureError,
)
from tools import loop7_composite_lifecycle_evaluation as module


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _arguments(
    *,
    data_root: Path,
    evidence: Path,
    output: Path,
) -> list[str]:
    return [
        "--data-root",
        str(data_root),
        "--ocr-evidence",
        str(evidence),
        "--candidate-version",
        "candidate-loading",
        "--candidate-version",
        "candidate-unloading",
        "--output",
        str(output),
    ]


def test_parser_has_no_external_role_or_synthetic_manifest_import() -> None:
    options = {
        option
        for action in module._parser()._actions
        for option in action.option_strings
    }

    assert "--ocr-evidence" in options
    assert "--candidate-version" in options
    assert "--role-report" not in options
    assert "--role-json" not in options
    assert "--manifest" not in options


def test_protected_ocr_evidence_path_is_required(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    outside = (tmp_path / "outside.json").resolve()
    outside.write_text("{}\n", encoding="utf-8")

    with pytest.raises(
        module.CompositeLifecycleToolError,
        match="protected",
    ):
        module._validate_evidence_path(
            outside,
            data_root=data_root,
        )


@pytest.mark.parametrize(
    "failure_stage",
    ("none", "prepare", "frozen_contract", "persist"),
)
def test_run_records_terminal_outcome_and_persists_only_successful_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_stage: str,
) -> None:
    data_root = (tmp_path / "data").resolve()
    evidence_sha256 = _sha256("ocr-evidence")
    evidence = (
        data_root
        / "development"
        / "protected-candidate-review-ocr"
        / "records"
        / "sha256"
        / evidence_sha256[:2]
        / evidence_sha256[2:4]
        / f"{evidence_sha256}.json"
    )
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")
    output = (tmp_path / "output" / "composite.json").resolve()
    build_sha256 = _sha256("current-role-evaluator-build")
    runtime_sha256 = _sha256("current-runtime-set")
    composite_payload = {
        "authorization_scope": "ticket_role_evidence",
        "authorizing_lifecycle_evidence": True,
        "dataset_manifest_sha256": _sha256("composite-dataset"),
        "evaluation_id": "dev-role-composite-parent",
        "evaluation_sha256": _sha256("composite-evaluation"),
        "kind": "composite_template_lifecycle_evaluation",
        "stable_outcome_sha256": _sha256("composite-stable"),
    }
    composite = SimpleNamespace(
        payload=composite_payload,
        dataset_manifest_sha256=composite_payload[
            "dataset_manifest_sha256"
        ],
        evaluation_id=composite_payload["evaluation_id"],
        evaluation_sha256=composite_payload["evaluation_sha256"],
        stable_outcome_sha256=composite_payload[
            "stable_outcome_sha256"
        ],
    )
    synthetic = SimpleNamespace(
        matcher_fingerprint=_sha256("matcher"),
        policy_fingerprint=_sha256("policy"),
        stable_outcome_sha256=_sha256("synthetic-stable"),
    )
    real = SimpleNamespace(
        evaluation_sha256=_sha256("real-evaluation"),
        payload={
            "authorizing_lifecycle_evidence": False,
            "development_only": True,
            "evaluation_sha256": _sha256("real-evaluation"),
        },
    )
    prepared = SimpleNamespace(
        composite=composite,
        real_component=real,
        synthetic_component=synthetic,
    )
    attempt_scope = object()
    calls: list[str] = []

    class FakeGuard:
        instance_id = "guard"

        def __init__(
            self,
            root: Path,
            port: int,
            version: str,
        ) -> None:
            del port, version
            assert root == data_root

        def __enter__(self):
            calls.append("guard-enter")
            return self

        def __exit__(self, *args: object) -> None:
            del args
            calls.append("guard-exit")

    class FakeRuntime:
        def __init__(
            self,
            *,
            data_root: Path,
            project_root: Path,
            instance_id: str,
        ) -> None:
            del project_root
            assert data_root == globals_data_root
            assert instance_id == "guard"
            calls.append("runtime-open")

        def close(self) -> None:
            calls.append("runtime-close")

    class FakeBackend:
        def close(self) -> None:
            calls.append("backend-close")

    globals_data_root = data_root
    repository_instances: list[dict[str, object]] = []
    run_repository_instances: list[object] = []

    class FakeRepository:
        def __init__(self, **kwargs: object) -> None:
            self.contract = kwargs
            repository_instances.append(kwargs)

        def record_composite_lifecycle_failure(
            self,
            **kwargs: object,
        ) -> object:
            failed_during_prepare = failure_stage in {
                "prepare",
                "frozen_contract",
            }
            assert kwargs == {
                "scope": attempt_scope,
                "terminal_status": (
                    "technical_failed"
                    if failed_during_prepare
                    else "business_failed"
                ),
                "failure_code": (
                    "LOOP7-COMPOSITE-TECHNICAL-FAILURE"
                    if failed_during_prepare
                    else "LOOP7-COMPOSITE-BUSINESS-GATE"
                ),
                "actor_id": (
                    "loop7-composite-lifecycle-evaluator"
                ),
            }
            calls.append("record-failure")
            return object()

    class FakeRunRepository:
        def __init__(self, *, runtime: object) -> None:
            run_repository_instances.append(runtime)

    def prepare(
        repository: object,
        **kwargs: object,
    ) -> object:
        del repository
        assert kwargs["candidate_ocr_run_repository"].__class__ is (
            FakeRunRepository
        )
        assert kwargs["candidate_ocr_evidence_path"] == evidence
        assert kwargs["candidate_ocr_data_root"] == data_root
        assert kwargs["candidate_version_ids"] == (
            "candidate-loading",
            "candidate-unloading",
        )
        assert kwargs["role_evaluator_build_sha256"] == build_sha256
        assert kwargs["runtime_set_sha256"] == runtime_sha256
        calls.append("prepare")
        if failure_stage == "prepare":
            raise module.CandidateRoleEvaluationError(
                "prepared role evidence is invalid"
            )
        if failure_stage == "frozen_contract":
            raise FrozenDevelopmentFixtureError(
                "candidate versions are not covered by authorizing "
                "observations: candidate-loading-success"
            )
        return prepared

    def prepare_scope(
        repository: object,
        **kwargs: object,
    ) -> object:
        assert isinstance(repository, FakeRepository)
        # Scope preparation validates every current shadow before it can
        # create a terminal-attempt identity.
        assert repository.contract[
            "accepted_build_fingerprint"
        ] == build_sha256
        assert repository.contract[
            "accepted_runtime_fingerprint"
        ] == runtime_sha256
        assert repository.contract[
            "accepted_development_manifest_sha256"
        ] == composite.dataset_manifest_sha256
        assert repository.contract[
            "accepted_matcher_fingerprint"
        ] == synthetic.matcher_fingerprint
        assert repository.contract[
            "accepted_policy_fingerprint"
        ] == synthetic.policy_fingerprint
        assert kwargs["candidate_ocr_run_repository"].__class__ is (
            FakeRunRepository
        )
        assert kwargs["candidate_ocr_evidence_path"] == evidence
        assert kwargs["candidate_version_ids"] == (
            "candidate-loading",
            "candidate-unloading",
        )
        assert kwargs["role_evaluator_build_sha256"] == build_sha256
        assert kwargs["runtime_set_sha256"] == runtime_sha256
        calls.append("prepare-scope")
        return attempt_scope

    def persist(
        repository: object,
        value: object,
        *,
        actor_id: str,
    ) -> object:
        del repository
        assert value is prepared
        assert actor_id == "loop7-composite-lifecycle-evaluator"
        calls.append("persist")
        if failure_stage == "persist":
            raise module.CompositeLifecyclePersistenceError(
                "composite lifecycle gate did not pass"
            )
        return SimpleNamespace(
            evaluation_id=composite.evaluation_id,
            gate_passed=True,
            verification_source="frozen_runner",
        )

    monkeypatch.setattr(module, "SingleInstanceGuard", FakeGuard)
    monkeypatch.setattr(
        module,
        "prepare_startup_environment",
        lambda config, root: Path(config.data_root),
    )
    monkeypatch.setattr(module, "SqliteRuntime", FakeRuntime)
    monkeypatch.setattr(module, "SqliteTemplateRepository", FakeRepository)
    monkeypatch.setattr(
        module,
        "SqliteCandidateDevelopmentOcrRunRepository",
        FakeRunRepository,
    )
    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        lambda **kwargs: FakeBackend(),
    )
    monkeypatch.setattr(
        module,
        "_qualified_runtime_fingerprint",
        lambda backend: runtime_sha256,
    )
    monkeypatch.setattr(
        module,
        "current_template_pipeline_build_fingerprint",
        lambda **kwargs: build_sha256,
    )
    monkeypatch.setattr(
        module,
        "load_approved_authorizing_development_dataset",
        lambda path: SimpleNamespace(
            manifest_sha256=composite.dataset_manifest_sha256
        ),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "development_matcher_fingerprint",
        lambda: synthetic.matcher_fingerprint,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "development_policy_fingerprint",
        lambda: synthetic.policy_fingerprint,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "prepare_composite_lifecycle_attempt_scope",
        prepare_scope,
    )
    monkeypatch.setattr(
        module,
        "prepare_composite_lifecycle_evaluation",
        prepare,
    )
    monkeypatch.setattr(
        module,
        "persist_composite_lifecycle_evaluation",
        persist,
    )

    exit_code = module.main(
        _arguments(
            data_root=data_root,
            evidence=evidence,
            output=output,
        )
    )
    assert exit_code == (0 if failure_stage == "none" else 2)

    expected_calls = [
        "guard-enter",
        "runtime-open",
        "prepare-scope",
        "prepare",
    ]
    if failure_stage not in {"prepare", "frozen_contract"}:
        expected_calls.append("persist")
    if failure_stage != "none":
        expected_calls.append("record-failure")
    expected_calls.extend(
        [
            "runtime-close",
            "backend-close",
            "guard-exit",
        ]
    )
    assert calls == expected_calls
    assert len(repository_instances) == (
        1
        if failure_stage in {"prepare", "frozen_contract"}
        else 2
    )
    assert len(run_repository_instances) == 1
    assert repository_instances[0]["accepted_build_fingerprint"] == (
        build_sha256
    )
    if failure_stage not in {"prepare", "frozen_contract"}:
        assert repository_instances[1][
            "accepted_development_manifest_sha256"
        ] == composite.dataset_manifest_sha256
    if failure_stage != "none":
        assert not output.exists()
        error_output = capsys.readouterr().err
        if failure_stage == "frozen_contract":
            assert error_output == (
                "ERROR: candidate versions are not covered by authorizing "
                "observations: candidate-loading-success\n"
            )
            assert "Traceback" not in error_output
        else:
            assert (
                "prepared role evidence is invalid"
                if failure_stage == "prepare"
                else "gate did not pass"
            ) in error_output
        return
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload == {
        "composite": composite_payload,
        "kind": "loop7_composite_lifecycle_evidence",
        "persisted": {
            "evaluation_id": composite.evaluation_id,
            "verification_source": "frozen_runner",
        },
        "real_component": real.payload,
        "schema_version": 1,
        "synthetic_component_stable_outcome_sha256": (
            synthetic.stable_outcome_sha256
        ),
    }
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "authorization_scope": "ticket_role_evidence",
        "evaluation_id": composite.evaluation_id,
        "gate_passed": True,
        "output": str(output),
    }
