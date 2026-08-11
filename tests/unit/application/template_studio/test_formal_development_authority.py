from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from dahe.adapters.sqlite.template_studio import TemplateEligibilityContract
from dahe.application.template_studio import (
    formal_development_authority as module,
)
from tests.fixtures.formal_development_authority import (
    formal_development_authority,
)


def _authority() -> module.FormalDevelopmentAuthority:
    payload = {
        "authority_sha256": "a" * 64,
        "kind": "atomic-write-test",
        "schema_version": 1,
    }
    return cast(
        module.FormalDevelopmentAuthority,
        SimpleNamespace(
            authority_sha256="a" * 64,
            payload=payload,
        ),
    )


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _composite_manifest_sha256(
    approved_manifest_sha256: str,
) -> str:
    payload = {
        "authorization_scope": "ticket_role_evidence",
        "candidate_set_sha256": _sha256("candidate-set"),
        "frozen_synthetic_dataset_sha256": approved_manifest_sha256,
        "ocr_evidence_sha256": _sha256("ocr-evidence"),
        "real_source_authority_sha256": _sha256("source-authority"),
        "schema_version": 1,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _composite_metrics(
    *,
    approved_manifest_sha256: str,
    composite_manifest_sha256: str,
) -> dict[str, object]:
    candidate_set_sha256 = _sha256("candidate-set")
    ocr_evidence_sha256 = _sha256("ocr-evidence")
    source_authority_sha256 = _sha256("source-authority")
    return {
        "lifecycle_authorization_schema_version": 2,
        "composite_lifecycle": {
            "authorization_scope": "ticket_role_evidence",
            "authorizing_lifecycle_evidence": True,
            "bindings": {
                "candidate_set_sha256": candidate_set_sha256,
                "composite_gate_policy_sha256": _sha256(
                    "composite-policy"
                ),
                "frozen_synthetic_dataset_sha256": (
                    approved_manifest_sha256
                ),
                "matcher_fingerprint": _sha256("matcher"),
                "policy_fingerprint": _sha256("policy"),
                "role_evaluator_build_sha256": _sha256("build"),
                "runtime_set_sha256": _sha256("runtime"),
                "template_set_fingerprint": _sha256(
                    "template-set"
                ),
            },
            "components": {
                "frozen_synthetic": {
                    "dataset_manifest_sha256": (
                        approved_manifest_sha256
                    ),
                },
            },
            "dataset_manifest_sha256": composite_manifest_sha256,
            "kind": "composite_template_lifecycle_evaluation",
            "schema_version": 1,
        },
        "composite_lifecycle_components": {
            "real_candidate_roles": {
                "source": {
                    "composition_evidence_sha256": _sha256(
                        "composition-evidence"
                    ),
                    "ocr_evidence_sha256": ocr_evidence_sha256,
                    "ocr_capture_build_sha256": _sha256(
                        "ocr-capture-build"
                    ),
                    "ocr_pipeline_contract_sha256": _sha256(
                        "ocr-pipeline-contract"
                    ),
                    "package_sha256": _sha256("package"),
                    "review_history_authority_sha256": _sha256(
                        "review-history"
                    ),
                    "reviewer_id_sha256": hashlib.sha256(
                        json.dumps(
                            "reviewer",
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode("utf-8")
                    ).hexdigest(),
                    "runtime_set_sha256": _sha256("runtime"),
                    "source_authority_sha256": (
                        source_authority_sha256
                    ),
                },
            },
            "frozen_synthetic": {
                "dataset_manifest_sha256": approved_manifest_sha256,
            },
        },
    }


def test_current_authority_accepts_composite_parent_bound_to_approved_dataset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved_manifest = _sha256("approved-synthetic-development")
    composite_manifest = _composite_manifest_sha256(
        approved_manifest
    )
    contract = TemplateEligibilityContract(
        dataset_manifest_sha256=composite_manifest,
        matcher_fingerprint=_sha256("matcher"),
        policy_fingerprint=_sha256("policy"),
        build_fingerprint=_sha256("build"),
        runtime_fingerprint=_sha256("runtime"),
    )
    publication = SimpleNamespace(
        lifecycle_attempt=SimpleNamespace(reviewer_id="reviewer"),
        publication_evaluation=SimpleNamespace(
            dataset_manifest_sha256=composite_manifest,
            metrics=_composite_metrics(
                approved_manifest_sha256=approved_manifest,
                composite_manifest_sha256=composite_manifest,
            ),
        )
    )
    expected_authority = object()

    class FakeTemplateRepository:
        @staticmethod
        def current_shadow_eligibility_contract(
            runtime: object,
        ) -> TemplateEligibilityContract:
            assert runtime is runtime_identity
            return contract

        def __init__(self, **kwargs: object) -> None:
            assert kwargs["accepted_development_manifest_sha256"] == (
                composite_manifest
            )

        def list_current_shadow_publication_authorities(
            self,
        ) -> tuple[object, ...]:
            return (publication,)

    class FakeLockedSetRepository:
        def __init__(self, *, runtime: object) -> None:
            assert runtime is runtime_identity

        def build_exclusion_snapshot(self) -> object:
            return exclusion_snapshot

    runtime_identity = object()
    exclusion_snapshot = object()
    monkeypatch.setattr(
        module,
        "SqliteTemplateRepository",
        FakeTemplateRepository,
    )
    monkeypatch.setattr(
        module,
        "SqliteLockedSetRepository",
        FakeLockedSetRepository,
    )
    monkeypatch.setattr(
        module,
        "approved_authorizing_development_dataset_path",
        lambda: Path("approved.json"),
    )
    monkeypatch.setattr(
        module,
        "load_approved_authorizing_development_dataset",
        lambda _: SimpleNamespace(manifest_sha256=approved_manifest),
    )
    monkeypatch.setattr(
        module,
        "development_matcher_fingerprint",
        lambda: contract.matcher_fingerprint,
    )
    monkeypatch.setattr(
        module,
        "development_policy_fingerprint",
        lambda: contract.policy_fingerprint,
    )
    monkeypatch.setattr(
        module,
        "current_template_pipeline_build_fingerprint",
        lambda **_: contract.build_fingerprint,
    )

    def build_authority(**kwargs: object) -> object:
        assert kwargs == {
            "eligibility_contract": contract,
            "exclusion_snapshot": exclusion_snapshot,
            "shadow_publications": (publication,),
        }
        return expected_authority

    monkeypatch.setattr(
        module,
        "build_formal_development_authority",
        build_authority,
    )

    assert (
        module.build_current_formal_development_authority(
            cast(Any, runtime_identity)
        )
        is expected_authority
    )


def test_approved_dataset_binding_rejects_a_different_synthetic_manifest() -> None:
    approved_manifest = _sha256("approved-synthetic-development")
    unapproved_manifest = _sha256("unapproved-synthetic-development")
    composite_manifest = _composite_manifest_sha256(
        unapproved_manifest
    )
    authority = SimpleNamespace(
        eligibility_contract=TemplateEligibilityContract(
            dataset_manifest_sha256=composite_manifest,
            matcher_fingerprint=_sha256("matcher"),
            policy_fingerprint=_sha256("policy"),
            build_fingerprint=_sha256("build"),
            runtime_fingerprint=_sha256("runtime"),
        ),
        payload={
            "shadow_publications": [
                    {
                        "lifecycle_attempt": {
                            "reviewer_id": "reviewer",
                        },
                        "publication_evaluation": {
                        "dataset_manifest_sha256": composite_manifest,
                        "metrics": _composite_metrics(
                            approved_manifest_sha256=unapproved_manifest,
                            composite_manifest_sha256=(
                                composite_manifest
                            ),
                        ),
                    },
                },
            ],
        },
    )

    with pytest.raises(
        module.FormalDevelopmentAuthorityError,
        match="approved development dataset",
    ):
        module.require_approved_development_dataset_binding(
            cast(Any, authority),
            approved_manifest_sha256=approved_manifest,
        )


def test_serialized_authority_distinguishes_synthetic_and_composite_manifests() -> None:
    authority = formal_development_authority()
    publication = authority.payload["shadow_publications"][0]
    evaluation = publication["publication_evaluation"]
    attempt = publication["lifecycle_attempt"]
    frozen_manifest = evaluation["metrics"][
        "composite_lifecycle"
    ]["bindings"]["frozen_synthetic_dataset_sha256"]

    assert frozen_manifest == attempt["dataset_manifest_sha256"]
    assert frozen_manifest != (
        authority.eligibility_contract.dataset_manifest_sha256
    )
    assert evaluation["dataset_manifest_sha256"] == (
        authority.eligibility_contract.dataset_manifest_sha256
    )


def test_legacy_real_source_without_reviewer_binding_is_rejected() -> None:
    approved_manifest = _sha256("approved-synthetic-development")
    composite_manifest = _composite_manifest_sha256(
        approved_manifest
    )
    metrics = _composite_metrics(
        approved_manifest_sha256=approved_manifest,
        composite_manifest_sha256=composite_manifest,
    )
    del metrics["composite_lifecycle_components"][
        "real_candidate_roles"
    ]["source"]["reviewer_id_sha256"]

    with pytest.raises(
        module.FormalDevelopmentAuthorityError,
        match="reviewer authority",
    ):
        module._composite_lifecycle_scope_from_metrics(
            metrics,
            composite_manifest_sha256=composite_manifest,
            reviewer_id="reviewer",
        )


def test_authority_publish_failure_leaves_no_final_or_staging_file(
    tmp_path: Path,
) -> None:
    output = tmp_path / "authority.json"

    def failpoint(name: str) -> None:
        if name == "after_authority_staged_fsync":
            raise RuntimeError("injected crash boundary")

    with pytest.raises(RuntimeError, match="injected crash boundary"):
        module.write_formal_development_authority(
            output,
            _authority(),
            failpoint=failpoint,
        )

    assert not output.exists()
    assert tuple(tmp_path.glob(".authority.json.*.tmp")) == ()


def test_stale_staging_file_does_not_block_atomic_retry(
    tmp_path: Path,
) -> None:
    output = tmp_path / "authority.json"
    stale = tmp_path / ".authority.json.interrupted.tmp"
    stale.write_bytes(b'{"partial":')

    written = module.write_formal_development_authority(
        output,
        _authority(),
    )

    assert written == output
    assert not stale.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == (
        _authority().payload
    )
    assert tuple(tmp_path.glob(".authority.json.*.tmp")) == ()


def test_existing_authority_is_only_replayed_when_content_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "authority.json"
    output.write_text("{}\n", encoding="utf-8")
    authority = _authority()
    loaded: list[tuple[Path, str | None]] = []

    def load(
        path: Path,
        *,
        expected_sha256: str | None = None,
    ) -> Any:
        loaded.append((path, expected_sha256))
        return authority

    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        load,
    )
    assert (
        module.write_formal_development_authority(output, authority)
        == output
    )
    assert loaded == [(output, authority.authority_sha256)]

    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda *args, **kwargs: object(),
    )
    with pytest.raises(
        module.FormalDevelopmentAuthorityError,
        match="conflicts",
    ):
        module.write_formal_development_authority(
            output,
            authority,
        )
