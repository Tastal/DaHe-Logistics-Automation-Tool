from __future__ import annotations

import hashlib
from pathlib import Path

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.operational_bundle import (
    canonical_json,
    load_operational_template_bundle,
)
from tests.unit.application.template_studio.test_operational_bundle import _bundle
from tools.install_operational_template_bundle import (
    install_operational_template_bundle,
)


def _empty_source_root(path: Path) -> Path:
    source = path.resolve()
    runtime = SqliteRuntime(
        data_root=source,
        project_root=Path(__file__).resolve().parents[3],
        instance_id="operational-template-install-test",
    )
    runtime.close()
    return source


def test_installs_a_previously_sealed_bundle_when_source_database_has_no_templates(
    tmp_path: Path,
) -> None:
    source = _empty_source_root(tmp_path / "source")
    target = (tmp_path / "target").resolve()
    output = (target / "operational-template-install.json").resolve()
    source_bundle = source / "operational-template-bundle.json"
    source_bytes = canonical_json(_bundle())
    source_bundle.write_bytes(source_bytes)

    evidence = install_operational_template_bundle(
        source_root=source,
        target_root=target,
        output=output,
    )

    target_bundle = target / "operational-template-bundle.json"
    assert target_bundle.read_bytes() == source_bytes
    assert evidence["source_kind"] == "sealed_bundle"
    assert evidence["source_bundle_file_sha256"] == hashlib.sha256(source_bytes).hexdigest()
    assert len(
        load_operational_template_bundle(
            target_bundle,
            expected_matcher_fingerprint=development_matcher_fingerprint(),
            expected_policy_fingerprint=development_policy_fingerprint(),
        )
    ) == 4
