from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from dahe.adapters.sqlite.template_studio import serialize_template_definition
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.operational_bundle import (
    OperationalTemplateBundleError,
    build_operational_template_bundle,
    canonical_json,
    load_operational_template_bundle,
)
from dahe.domain.ticket.templates import TemplateLifecycle, canonical_template_hash
from tests.unit.domain.ticket.test_templates import _definition


def _bundle() -> dict[str, object]:
    templates: list[dict[str, object]] = []
    for index in range(4):
        definition = replace(
            _definition(),
            family_id=f"operational-family-{index}",
            name=f"Operational template {index}",
        )
        templates.append(
            {
                "version_id": f"operational-version-{index}",
                "version_number": 9,
                "parent_version_id": f"operational-parent-{index}",
                "record_version": 3,
                "lifecycle": TemplateLifecycle.SHADOW.value,
                "content_sha256": canonical_template_hash(definition),
                "definition": serialize_template_definition(definition),
            }
        )
    return build_operational_template_bundle(
        templates=templates,
        evaluation={
            "evaluation_id": "operational-evaluation",
            "dataset_manifest_sha256": "d" * 64,
            "matcher_fingerprint": development_matcher_fingerprint(),
            "policy_fingerprint": development_policy_fingerprint(),
            "source_build_fingerprint": "b" * 64,
            "runtime_fingerprint": "r" * 64,
            "verification_source": "frozen_runner",
            "gate_passed": True,
        },
    )


def test_loads_exactly_four_operational_shadow_templates(tmp_path: Path) -> None:
    path = (tmp_path / "operational-template-bundle.json").resolve()
    path.write_bytes(canonical_json(_bundle()))

    versions = load_operational_template_bundle(
        path,
        expected_matcher_fingerprint=development_matcher_fingerprint(),
        expected_policy_fingerprint=development_policy_fingerprint(),
    )

    assert len(versions) == 4
    assert all(item.lifecycle is TemplateLifecycle.SHADOW for item in versions)
    assert len({item.definition.family_id for item in versions}) == 4


def test_rejects_bundle_or_template_semantic_tampering(tmp_path: Path) -> None:
    path = (tmp_path / "operational-template-bundle.json").resolve()
    bundle = _bundle()
    bundle["templates"][0]["content_sha256"] = "0" * 64  # type: ignore[index]
    path.write_bytes(canonical_json(bundle))

    with pytest.raises(OperationalTemplateBundleError):
        load_operational_template_bundle(
            path,
            expected_matcher_fingerprint=development_matcher_fingerprint(),
            expected_policy_fingerprint=development_policy_fingerprint(),
        )

    bundle = _bundle()
    raw = json.loads(canonical_json(bundle))
    raw["evaluation"]["gate_passed"] = False
    body = dict(raw)
    body.pop("bundle_sha256")
    raw["bundle_sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    path.write_bytes(canonical_json(raw))
    with pytest.raises(OperationalTemplateBundleError):
        load_operational_template_bundle(
            path,
            expected_matcher_fingerprint=development_matcher_fingerprint(),
            expected_policy_fingerprint=development_policy_fingerprint(),
        )
