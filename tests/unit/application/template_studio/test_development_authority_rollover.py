from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from dahe.application.template_studio.development_authority_rollover import (
    DevelopmentAuthorityRolloverError,
    build_development_authority_rollover,
    load_development_authority_rollover,
    parse_development_authority_rollover,
    validate_development_authority_rollover,
)
from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
)
from tests.fixtures.formal_development_authority import (
    formal_development_authority,
)


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _execution(
    source: FormalDevelopmentAuthority,
    *,
    changed_definition: bool = False,
) -> FormalDevelopmentAuthority:
    source_publication = dict(source.payload["shadow_publications"][0])
    definition = dict(source_publication["definition"])
    if changed_definition:
        definition["name"] = "changed"
    execution_version = replace(
        source.shadow_templates[0],
        version_id="e" * 32,
        parent_version_id=source.shadow_templates[0].version_id,
        version_number=source.shadow_templates[0].version_number + 1,
        definition=replace(
            source.shadow_templates[0].definition,
            name=str(definition["name"]),
        ),
    )
    publication = {
        **source_publication,
        "content_sha256": execution_version.content_sha256,
        "definition": definition,
        "parent_version_id": execution_version.parent_version_id,
        "version_id": execution_version.version_id,
        "version_number": execution_version.version_number,
    }
    payload = {
        **source.payload,
        "authority_sha256": _sha256("execution-authority"),
        "eligibility_contract": {
            **source.payload["eligibility_contract"],
            "build_fingerprint": _sha256("execution-build"),
        },
        "shadow_publications": [publication],
        "shadow_template_set_fingerprint": _sha256(
            "execution-template-set"
        ),
    }
    return replace(
        source,
        authority_sha256=str(payload["authority_sha256"]),
        payload=payload,
        shadow_templates=(execution_version,),
        eligibility_contract=replace(
            source.eligibility_contract,
            build_fingerprint=str(
                payload["eligibility_contract"]["build_fingerprint"]
            ),
        ),
    )


def _references(
    source: FormalDevelopmentAuthority,
) -> dict[str, dict[str, str]]:
    return {
        source.shadow_templates[0].definition.family_id: {
            "source_reference_image_sha256": _sha256("image"),
            "source_reference_mask_sha256": _sha256("mask"),
            "source_alignment_fingerprint": _sha256("alignment"),
            "execution_reference_image_sha256": _sha256("image"),
            "execution_reference_mask_sha256": _sha256("mask"),
            "execution_alignment_fingerprint": _sha256("alignment"),
        }
    }


def test_rollover_allows_only_identical_direct_template_revision() -> None:
    source = formal_development_authority()
    execution = _execution(source)

    rollover = build_development_authority_rollover(
        source_authority=source,
        execution_authority=execution,
        reference_evidence_by_family=_references(source),
    )

    assert rollover.source_authority_sha256 == source.authority_sha256
    assert rollover.execution_authority_sha256 == execution.authority_sha256
    assert parse_development_authority_rollover(rollover.payload) == rollover
    validate_development_authority_rollover(
        rollover,
        source_authority=source,
        execution_authority=execution,
    )


def test_rollover_rejects_template_or_reference_semantic_change() -> None:
    source = formal_development_authority()

    with pytest.raises(
        DevelopmentAuthorityRolloverError,
        match="not an identical revision",
    ):
        build_development_authority_rollover(
            source_authority=source,
            execution_authority=_execution(
                source,
                changed_definition=True,
            ),
            reference_evidence_by_family=_references(source),
        )

    changed_references = _references(source)
    changed_references[source.shadow_templates[0].definition.family_id][
        "execution_reference_image_sha256"
    ] = _sha256("changed-image")
    with pytest.raises(
        DevelopmentAuthorityRolloverError,
        match="reference evidence",
    ):
        build_development_authority_rollover(
            source_authority=source,
            execution_authority=_execution(source),
            reference_evidence_by_family=changed_references,
        )


def test_rollover_rejects_changed_dataset_or_exclusion_inventory() -> None:
    source = formal_development_authority()
    execution = _execution(source)
    changed_payload = {
        **execution.payload,
        "source_inventory_high_watermark": 99,
    }
    changed_execution = replace(execution, payload=changed_payload)

    with pytest.raises(
        DevelopmentAuthorityRolloverError,
        match="development evidence changed",
    ):
        build_development_authority_rollover(
            source_authority=source,
            execution_authority=changed_execution,
            reference_evidence_by_family=_references(source),
        )


def test_loader_accepts_the_audited_rollover_result_wrapper(
    tmp_path: Path,
) -> None:
    source = formal_development_authority()
    execution = _execution(source)
    rollover = build_development_authority_rollover(
        source_authority=source,
        execution_authority=execution,
        reference_evidence_by_family=_references(source),
    )
    result: dict[str, object] = {
        "build_fingerprint": _sha256("build"),
        "composite_evaluation_id": "evaluation-1",
        "composite_evaluation_sha256": _sha256("evaluation"),
        "execution_authority_sha256": (
            execution.authority_sha256
        ),
        "kind": "loop7_shadow_authority_rollover_result",
        "rollover": rollover.payload,
        "schema_version": 1,
        "source_authority_sha256": source.authority_sha256,
        "template_version_mappings": [],
    }
    def canonical(value: object) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    result["result_sha256"] = hashlib.sha256(
        canonical(result).encode("utf-8")
    ).hexdigest()
    path = tmp_path / "rollover-result.json"
    path.write_bytes(
        (canonical(result) + "\n").encode("utf-8")
    )

    assert load_development_authority_rollover(path) == rollover
