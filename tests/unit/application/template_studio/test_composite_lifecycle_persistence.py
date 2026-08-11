from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.adapters.sqlite import template_evaluation as module
from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    CandidateDevelopmentRoleEvaluation,
)
from dahe.application.template_studio.composite_lifecycle_evaluation import (
    CompositeLifecycleEvaluation,
)
from dahe.application.template_studio.development_evaluation import (
    DevelopmentEvaluationReport,
    run_authorizing_development_evaluation,
)
from tests.fixtures.loop7_current_candidate_templates import (
    current_candidate_versions,
)


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _synthetic_report() -> DevelopmentEvaluationReport:
    dataset = load_approved_authorizing_development_dataset(
        approved_authorizing_development_dataset_path()
    )
    candidates = current_candidate_versions()
    return run_authorizing_development_evaluation(
        dataset,
        candidates=candidates,
    )


def _composite(
    synthetic: DevelopmentEvaluationReport,
) -> CompositeLifecycleEvaluation:
    stable = _sha256("composite-stable")
    evaluation_id = f"dev-role-composite-{stable[:28]}"
    dataset_manifest = _sha256("composite-dataset")
    payload: dict[str, object] = {
        "authorization_scope": "ticket_role_evidence",
        "authorizing_lifecycle_evidence": True,
        "bindings": {
            "candidate_set_sha256": _sha256("candidate-set"),
            "composite_gate_policy_sha256": _sha256("composite-policy"),
            "frozen_synthetic_dataset_sha256": (
                synthetic.dataset_manifest_sha256
            ),
            "matcher_fingerprint": synthetic.matcher_fingerprint,
            "ocr_capture_build_sha256": _sha256("ocr-capture-build"),
            "policy_fingerprint": synthetic.policy_fingerprint,
            "role_evaluator_build_sha256": _sha256("role-evaluator-build"),
            "runtime_set_sha256": _sha256("runtime-set"),
            "template_set_fingerprint": synthetic.template_set_fingerprint,
        },
        "components": {
            "frozen_synthetic": {
                "gate_passed": True,
                "stable_outcome_sha256": synthetic.stable_outcome_sha256,
            },
            "real_candidate_roles": {
                "authorizing_lifecycle_evidence": False,
                "development_only": True,
                "evaluation_sha256": _sha256("real-component"),
            },
        },
        "dataset_id": "loop7-role-composite-test",
        "dataset_manifest_sha256": dataset_manifest,
        "evaluation_id": evaluation_id,
        "evaluator_version": "dahe.loop7.composite-lifecycle-evaluation.v1",
        "gate": {"checks": {"both_components": True}, "passed": True},
        "kind": "composite_template_lifecycle_evaluation",
        "schema_version": 1,
        "stable_outcome_sha256": stable,
    }
    evaluation_sha256 = _sha256("composite-evaluation")
    payload["evaluation_sha256"] = evaluation_sha256
    return CompositeLifecycleEvaluation(
        payload=payload,
        evaluation_id=evaluation_id,
        evaluation_sha256=evaluation_sha256,
        dataset_id="loop7-role-composite-test",
        dataset_manifest_sha256=dataset_manifest,
        stable_outcome_sha256=stable,
        gate_passed=True,
    )


class _CandidateRepository:
    def __init__(self, synthetic: DevelopmentEvaluationReport) -> None:
        self._versions = {
            candidate.version_id: candidate
            for candidate in current_candidate_versions()
        }
        assert set(self._versions) == {
            candidate.version_id for candidate in synthetic.candidates
        }

    def get_version(self, version_id: str):
        return self._versions[version_id]

    def list_current_shadow_versions_for_development_evaluation(
        self,
        *,
        candidates: tuple[object, ...],
    ):
        assert {
            candidate.version_id for candidate in candidates
        } == set(self._versions)
        return ()


class _AuthorizingRepository:
    def __init__(
        self,
        synthetic: DevelopmentEvaluationReport,
        composite: CompositeLifecycleEvaluation,
    ) -> None:
        self.accepted_build_fingerprint = _sha256("role-evaluator-build")
        self.accepted_runtime_fingerprint = _sha256("runtime-set")
        self.accepted_development_manifest_sha256 = (
            composite.dataset_manifest_sha256
        )
        self.accepted_matcher_fingerprint = synthetic.matcher_fingerprint
        self.accepted_policy_fingerprint = synthetic.policy_fingerprint
        self.calls: list[dict[str, object]] = []

    def _record_frozen_development_evaluation(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            evaluation_id=kwargs["evaluation_id"],
            gate_passed=kwargs["gate_passed"],
            verification_source="frozen_runner",
        )


def test_prepare_runs_both_components_inside_one_typed_call_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic = _synthetic_report()
    repository = _CandidateRepository(synthetic)
    real = CandidateDevelopmentRoleEvaluation(
        payload={"kind": "in-process-real-component"},
        evaluation_sha256=_sha256("real-component"),
    )
    composite = _composite(synthetic)
    evidence_path = tmp_path / "protected-evidence.json"
    run_repository = object()
    calls: list[str] = []

    def load_authorized(
        repository: object,
        *,
        data_root: Path,
        evidence_path: Path,
        expected_evidence_sha256: str,
    ) -> object:
        assert repository is run_repository
        assert evidence_path == tmp_path / "protected-evidence.json"
        assert expected_evidence_sha256 == "protected-evidence"
        assert data_root == tmp_path
        calls.append("authorized")
        return SimpleNamespace(payload={"strict": "evidence"})

    def evaluate_real(
        evidence: object,
        *,
        candidates: tuple[object, ...],
        current_shadow: tuple[object, ...],
        role_evaluator_build_sha256: str,
    ) -> CandidateDevelopmentRoleEvaluation:
        assert evidence == {"strict": "evidence"}
        assert {
            candidate.version_id for candidate in candidates
        } == set(repository._versions)
        assert current_shadow == ()
        assert role_evaluator_build_sha256 == _sha256(
            "role-evaluator-build"
        )
        calls.append("real")
        return real

    def evaluate_synthetic(
        dataset: object,
        *,
        candidates: tuple[object, ...],
        current_shadow: tuple[object, ...],
    ) -> DevelopmentEvaluationReport:
        del dataset
        assert {
            candidate.version_id for candidate in candidates
        } == set(repository._versions)
        assert current_shadow == ()
        calls.append("synthetic")
        return synthetic

    def build_composite(**kwargs: object) -> CompositeLifecycleEvaluation:
        assert kwargs == {
            "expected_role_evaluator_build_sha256": _sha256(
                "role-evaluator-build"
            ),
            "expected_runtime_set_sha256": _sha256("runtime-set"),
            "real_component": real,
            "synthetic_component": synthetic,
        }
        calls.append("composite")
        return composite

    monkeypatch.setattr(
        module,
        "load_authorized_candidate_development_ocr_evidence",
        load_authorized,
    )
    monkeypatch.setattr(
        module,
        "evaluate_candidate_development_roles",
        evaluate_real,
    )
    monkeypatch.setattr(
        module,
        "run_authorizing_development_evaluation",
        evaluate_synthetic,
    )
    monkeypatch.setattr(
        module,
        "build_composite_lifecycle_evaluation",
        build_composite,
    )

    prepared = module.prepare_composite_lifecycle_evaluation(
        repository,  # type: ignore[arg-type]
        candidate_ocr_run_repository=run_repository,  # type: ignore[arg-type]
        manifest_path=approved_authorizing_development_dataset_path(),
        candidate_ocr_evidence_path=evidence_path,
        candidate_ocr_data_root=tmp_path,
        candidate_version_ids=tuple(repository._versions),
        role_evaluator_build_sha256=_sha256("role-evaluator-build"),
        runtime_set_sha256=_sha256("runtime-set"),
    )

    assert calls == ["authorized", "real", "synthetic", "composite"]
    assert prepared.real_component is real
    assert prepared.synthetic_component is synthetic
    assert prepared.composite is composite


def test_persist_records_only_the_parent_composite_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic = _synthetic_report()
    repository = _CandidateRepository(synthetic)
    real = CandidateDevelopmentRoleEvaluation(
        payload={"kind": "in-process-real-component"},
        evaluation_sha256=_sha256("real-component"),
    )
    composite = _composite(synthetic)
    monkeypatch.setattr(
        module,
        "load_authorized_candidate_development_ocr_evidence",
        lambda *args, **kwargs: SimpleNamespace(
            payload={"strict": "evidence"}
        ),
    )
    monkeypatch.setattr(
        module,
        "evaluate_candidate_development_roles",
        lambda *args, **kwargs: real,
    )
    monkeypatch.setattr(
        module,
        "run_authorizing_development_evaluation",
        lambda *args, **kwargs: synthetic,
    )
    monkeypatch.setattr(
        module,
        "build_composite_lifecycle_evaluation",
        lambda **kwargs: composite,
    )
    prepared = module.prepare_composite_lifecycle_evaluation(
        repository,  # type: ignore[arg-type]
        candidate_ocr_run_repository=object(),  # type: ignore[arg-type]
        manifest_path=approved_authorizing_development_dataset_path(),
        candidate_ocr_evidence_path=tmp_path / "protected-evidence.json",
        candidate_ocr_data_root=tmp_path,
        candidate_version_ids=tuple(repository._versions),
        role_evaluator_build_sha256=_sha256("role-evaluator-build"),
        runtime_set_sha256=_sha256("runtime-set"),
    )
    authorizing = _AuthorizingRepository(synthetic, composite)

    record = module.persist_composite_lifecycle_evaluation(
        authorizing,  # type: ignore[arg-type]
        prepared,
        actor_id="loop7-composite-evaluator",
    )

    assert record.evaluation_id == composite.evaluation_id
    assert len(authorizing.calls) == 1
    call = authorizing.calls[0]
    assert call["evaluation_id"] == composite.evaluation_id
    assert call["dataset_id"] == composite.dataset_id
    assert (
        call["dataset_manifest_sha256"]
        == composite.dataset_manifest_sha256
    )
    assert call["stable_outcome_sha256"] == (
        composite.stable_outcome_sha256
    )
    assert call["gate_passed"] is True
    assert call["expected_count"] == call["result_count"] == (
        synthetic.result_count
    )
    assert call["metrics"]["composite_lifecycle"] == composite.payload
    assert {
        candidate.version_id for candidate in call["candidates"]
    } == {
        candidate.version_id for candidate in synthetic.candidates
    }
    assert all(
        item.sample_id
        not in {
            real.evaluation_sha256,
            composite.evaluation_sha256,
        }
        for item in call["items"]
    )


def test_persistence_rejects_a_forged_prepared_value() -> None:
    with pytest.raises(
        module.CompositeLifecyclePersistenceError,
        match="prepared",
    ):
        module.persist_composite_lifecycle_evaluation(
            SimpleNamespace(),  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            actor_id="loop7-composite-evaluator",
        )


def test_attempt_scope_uses_candidate_aware_shadow_selection(
    tmp_path: Path,
) -> None:
    synthetic = _synthetic_report()
    repository = _CandidateRepository(synthetic)
    evidence_sha256 = "a" * 64
    authority = SimpleNamespace(
        evidence_sha256=evidence_sha256,
        package_sha256=_sha256("package"),
        review_history_authority_sha256=_sha256("review-history"),
        source_authority_sha256=_sha256("source-authority"),
        reviewer_id="developer-test",
        application_build_sha256=_sha256("ocr-capture-build"),
        composition_evidence_sha256=_sha256("composition"),
        runtime_set_sha256=_sha256("runtime-set"),
        pipeline_contract_sha256=_sha256("pipeline-contract"),
    )

    class _RunRepository:
        def get(self, requested_sha256: str) -> object:
            assert requested_sha256 == evidence_sha256
            return authority

        def require_latest_success(self, requested_sha256: str) -> object:
            assert requested_sha256 == evidence_sha256
            return authority

    scope = module.prepare_composite_lifecycle_attempt_scope(
        repository,  # type: ignore[arg-type]
        candidate_ocr_run_repository=_RunRepository(),  # type: ignore[arg-type]
        manifest_path=approved_authorizing_development_dataset_path(),
        candidate_ocr_evidence_path=tmp_path / f"{evidence_sha256}.json",
        candidate_version_ids=tuple(repository._versions),
        role_evaluator_build_sha256=_sha256("role-evaluator-build"),
        runtime_set_sha256=_sha256("runtime-set"),
    )

    assert scope.ocr_evidence_sha256 == evidence_sha256
    assert scope.template_set_fingerprint == (
        synthetic.template_set_fingerprint
    )
