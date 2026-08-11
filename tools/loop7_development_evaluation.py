from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_evaluation import (
    run_and_persist_frozen_development_evaluation,
)
from dahe.adapters.sqlite.template_studio import SqliteTemplateRepository
from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.development_evaluation import (
    RUNNER_VERSION,
    development_matcher_fingerprint,
    development_policy_fingerprint,
    run_frozen_development_evaluation,
)
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
    current_template_pipeline_build_fingerprint,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.jobs.ocr_execution import AsyncOcrExecutionBackend, RuntimeKindName
from dahe.system.instance_lock import SingleInstanceGuard

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT
    / "verification"
    / "loops"
    / "loop-7"
    / "20260725T232143+0800"
    / "fixture-manifest.json"
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _runtime_fingerprint() -> str:
    return _canonical_sha256(
        {
            "application_version": __version__,
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "runner_version": RUNNER_VERSION,
        }
    )


def _manifest_label(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return f"external:{path.name}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the frozen, offline Loop 7 development evaluation."
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--data-root", type=Path)
    parser.add_argument(
        "--candidate-version",
        action="append",
        default=[],
        dest="candidate_versions",
    )
    return parser


def _qualified_runtime_fingerprint(
    backend: AsyncOcrExecutionBackend,
) -> str:
    runtime_kinds: tuple[RuntimeKindName, ...] = ("cpu", "gpu")
    identities: list[dict[str, str]] = []
    for runtime_kind in runtime_kinds:
        if not backend.has_runtime(runtime_kind):
            continue
        identity = backend.identity_for(runtime_kind)
        identities.append(
            {
                "profile_id": identity.profile_id,
                "runtime_fingerprint": identity.runtime_fingerprint,
                "runtime_kind": identity.runtime_kind,
            }
        )
    return current_template_ocr_runtime_set_fingerprint(identities)


def main() -> int:
    args = _parser().parse_args()
    if args.persist and args.data_root is None:
        raise SystemExit("--persist requires --data-root")
    if args.persist and not args.candidate_versions:
        raise SystemExit("--persist requires at least one --candidate-version")
    if not args.persist and (args.data_root is not None or args.candidate_versions):
        raise SystemExit(
            "--data-root and --candidate-version require --persist"
        )
    selected_manifest = (
        approved_authorizing_development_dataset_path()
        if args.persist and args.manifest is None
        else DEFAULT_MANIFEST
        if args.manifest is None
        else args.manifest
    )
    manifest = selected_manifest.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() and output.is_dir():
        raise SystemExit("--output must identify a JSON file")
    build_fingerprint = current_template_pipeline_build_fingerprint(
        application_version=__version__,
    )
    persisted_evaluation: dict[str, object] | None = None
    if args.persist:
        dataset = load_approved_authorizing_development_dataset(manifest)
        requested_root = args.data_root.resolve()
        config = AppConfig(
            runtime_profile=RuntimeProfile.DEVELOPMENT,
            data_root=requested_root,
        )
        data_root = prepare_startup_environment(config, ROOT)
        with SingleInstanceGuard(data_root, config.port, __version__) as guard:
            backend = build_ocr_execution_backend(
                config=config,
                repository_root=ROOT,
            )
            try:
                runtime = SqliteRuntime(
                    data_root=data_root,
                    project_root=ROOT,
                    instance_id=guard.instance_id,
                )
                try:
                    runtime_fingerprint = _qualified_runtime_fingerprint(backend)
                    repository = SqliteTemplateRepository(
                        runtime=runtime,
                        accepted_build_fingerprint=build_fingerprint,
                        accepted_runtime_fingerprint=runtime_fingerprint,
                        accepted_development_manifest_sha256=(
                            dataset.manifest_sha256
                        ),
                        accepted_matcher_fingerprint=(
                            development_matcher_fingerprint()
                        ),
                        accepted_policy_fingerprint=(
                            development_policy_fingerprint()
                        ),
                    )
                    report, evaluation = (
                        run_and_persist_frozen_development_evaluation(
                            repository,
                            manifest_path=manifest,
                            candidate_version_ids=tuple(
                                args.candidate_versions
                            ),
                            actor_id="loop7-development-evaluator",
                        )
                    )
                    persisted_evaluation = {
                        "data_root_kind": "explicit_local",
                        "evaluation_id": evaluation.evaluation_id,
                        "verification_source": evaluation.verification_source,
                    }
                finally:
                    runtime.close()
            finally:
                backend.close()
    else:
        report = run_frozen_development_evaluation(manifest)
        runtime_fingerprint = _runtime_fingerprint()
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "offline": True,
        "production_data": False,
        "manifest_path": _manifest_label(manifest),
        "stable_outcome_sha256": report.stable_outcome_sha256,
        "record_evaluation": report.to_record_evaluation_payload(
            build_fingerprint=build_fingerprint,
            runtime_fingerprint=runtime_fingerprint,
        ),
        "pair_results": [item.to_payload() for item in report.pair_items],
        "persisted_evaluation": persisted_evaluation,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        staged.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(staged, output)
    finally:
        staged.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "gate_passed": report.gate_passed,
                "output": os.fspath(output),
                "result_count": report.result_count,
                "stable_outcome_sha256": report.stable_outcome_sha256,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if report.gate_passed else 1


if __name__ == "__main__":
    sys.exit(main())
