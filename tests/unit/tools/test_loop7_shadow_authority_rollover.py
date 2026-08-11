from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dahe.domain.ticket.templates import TemplateLifecycle
from tests.fixtures.loop7_current_candidate_templates import (
    current_candidate_versions,
)
from tools import loop7_shadow_authority_rollover as module


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class _Repository:
    def __init__(self) -> None:
        self.source = current_candidate_versions()[0]
        self.source = self.source.__class__(
            version_id=self.source.version_id,
            definition=self.source.definition,
            lifecycle=TemplateLifecycle.SHADOW,
            parent_version_id=self.source.parent_version_id,
            record_version=3,
            version_number=self.source.version_number,
        )
        self.current = self.source
        self.revisions = 0

    def get_family_current(self, family_id: str):
        assert family_id == self.source.definition.family_id
        return type(
            "Current",
            (),
            {
                "summary": type(
                    "Summary",
                    (),
                    {"shadow_version_id": self.source.version_id},
                )(),
                "version": self.current,
                "reference_image_sha256": _sha256("image"),
                "reference_mask_sha256": _sha256("mask"),
                "alignment_fingerprint": _sha256("alignment"),
            },
        )()

    def revise_draft(self, **_: object):
        self.revisions += 1
        self.current = self.source.__class__(
            version_id="e" * 32,
            definition=self.source.definition,
            lifecycle=TemplateLifecycle.DRAFT,
            parent_version_id=self.source.version_id,
            record_version=1,
            version_number=self.source.version_number + 1,
        )
        return self.current, True


def _state(repository: _Repository) -> dict[str, object]:
    return {
        "families": [
            {
                "family_id": repository.source.definition.family_id,
                "source_alignment_fingerprint": _sha256("alignment"),
                "source_content_sha256": repository.source.content_sha256,
                "source_record_version": 3,
                "source_reference_image_sha256": _sha256("image"),
                "source_reference_mask_sha256": _sha256("mask"),
                "source_version_id": repository.source.version_id,
            }
        ]
        * 4
    }


def test_parser_rejects_relative_paths() -> None:
    with pytest.raises(SystemExit):
        module._parser().parse_args(
            [
                "--data-root",
                "relative",
                "--ocr-evidence",
                "relative.json",
                "--output",
                "relative.json",
            ]
        )


def test_output_must_stay_outside_application_data(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        module.ShadowAuthorityRolloverToolError,
        match="outside application data",
    ):
        module._validate_output(
            tmp_path / "inside.json",
            data_root=tmp_path,
        )


def test_composite_candidate_binding_uses_both_runtime_support_sets(
    tmp_path: Path,
) -> None:
    candidates = current_candidate_versions()
    candidate_ids = [
        candidate.version_id for candidate in candidates
    ]
    output = tmp_path / "composite.json"
    output.write_text(
        json.dumps(
            {
                "composite": {
                    "gate": {"passed": True},
                    "bindings": {
                        "candidate_set_sha256": _sha256("candidate-set")
                    },
                },
                "persisted": {"evaluation_id": "evaluation-1"},
                "real_component": {
                    "runtimes": {
                        runtime_kind: {
                            "candidate_support": {
                                "results": [
                                    {
                                        "candidate_version_id": (
                                            candidate_id
                                        )
                                    }
                                    for candidate_id in candidate_ids
                                ]
                            }
                        }
                        for runtime_kind in ("cpu", "gpu")
                    }
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = module._run_composite(
        data_root=tmp_path,
        ocr_evidence=tmp_path / "unused.json",
        candidate_versions=candidates,
        output=output,
    )

    assert result["persisted"] == {
        "evaluation_id": "evaluation-1"
    }
