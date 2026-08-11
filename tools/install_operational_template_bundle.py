from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dahe.application.template_studio.development_evaluation import (  # noqa: E402
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.operational_bundle import (  # noqa: E402
    OperationalTemplateBundleError,
    build_operational_template_bundle,
    canonical_json,
    load_operational_template_bundle,
)
from dahe.verification.loop9_build import (  # noqa: E402
    current_loop9_build_sha256,
)
from tools.install_operational_read_contracts import (  # noqa: E402
    OperationalContractInstallError,
    _absolute_path,
    _require_safe_file,
    _require_safe_root,
    _require_target_stopped,
    _write_once,
)

EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


class OperationalTemplateInstallError(RuntimeError):
    """Raised when operational shadow templates cannot be isolated safely."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--source-root", type=_absolute_path, required=True)
    parser.add_argument("--target-root", type=_absolute_path, required=True)
    parser.add_argument("--output", type=_absolute_path, required=True)
    return parser


def _source_rows(database: Path) -> list[sqlite3.Row]:
    connection = sqlite3.connect(
        f"file:{database.as_posix()}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        return list(
            connection.execute(
                """
                SELECT
                    pointer.family_id,
                    version.version_id,
                    version.version_number,
                    version.parent_version_id,
                    version.definition_json,
                    version.content_sha256,
                    state.lifecycle,
                    state.record_version,
                    evaluation.evaluation_id,
                    evaluation.dataset_manifest_sha256,
                    evaluation.matcher_fingerprint,
                    evaluation.policy_fingerprint,
                    evaluation.build_fingerprint,
                    evaluation.runtime_fingerprint,
                    evaluation.verification_source,
                    evaluation.expected_count,
                    evaluation.result_count,
                    evaluation.gate_passed,
                    (SELECT count(*) FROM template_evaluation_items AS item
                     WHERE item.evaluation_id = evaluation.evaluation_id)
                        AS item_count,
                    (SELECT count(*) FROM template_evaluation_pairs AS pair
                     WHERE pair.evaluation_id = evaluation.evaluation_id)
                        AS pair_count,
                    (SELECT count(*) FROM template_evaluation_invalidations AS invalidation
                     WHERE invalidation.evaluation_id = evaluation.evaluation_id)
                        AS invalidation_count,
                    (SELECT count(*) FROM template_lifecycle_attempts AS attempt
                     WHERE attempt.evaluation_id = evaluation.evaluation_id
                       AND attempt.terminal_status = 'succeeded')
                        AS successful_attempt_count
                FROM template_shadow_pointers AS pointer
                JOIN template_versions AS version
                  ON version.version_id = pointer.version_id
                JOIN template_version_states AS state
                  ON state.version_id = version.version_id
                JOIN template_lifecycle_events AS lifecycle
                  ON lifecycle.event_id = (
                    SELECT latest.event_id
                    FROM template_lifecycle_events AS latest
                    WHERE latest.version_id = version.version_id
                      AND latest.operation = 'publish_shadow'
                    ORDER BY latest.created_at DESC, latest.event_id DESC
                    LIMIT 1
                  )
                JOIN template_evaluations AS evaluation
                  ON evaluation.evaluation_id = lifecycle.evaluation_id
                JOIN template_evaluation_candidates AS candidate
                  ON candidate.evaluation_id = evaluation.evaluation_id
                 AND candidate.version_id = version.version_id
                 AND candidate.content_sha256 = version.content_sha256
                ORDER BY pointer.family_id
                """
            )
        )
    finally:
        connection.close()


def install_operational_template_bundle(
    *, source_root: Path, target_root: Path, output: Path
) -> dict[str, object]:
    try:
        source = _require_safe_root(source_root, must_exist=True, label="source root")
        _require_target_stopped(source)
        target_candidate = target_root.resolve()
        _require_target_stopped(target_candidate)
        target = _require_safe_root(target_root, must_exist=False, label="target root")
        database = _require_safe_file(
            source / "database" / "dahe.sqlite3",
            root=source,
        )
    except OperationalContractInstallError as exc:
        raise OperationalTemplateInstallError(str(exc)) from exc
    try:
        output.resolve().relative_to(target)
    except ValueError as exc:
        raise OperationalTemplateInstallError(
            "output must stay inside the target data root"
        ) from exc
    rows = _source_rows(database)
    if len(rows) not in {0, 4}:
        raise OperationalTemplateInstallError(
            "source must contain exactly four current shadow templates"
        )
    matcher = development_matcher_fingerprint()
    policy = development_policy_fingerprint()

    source_kind: str
    source_database_sha256: str | None
    source_bundle_file_sha256: str | None
    source_evaluation_id: str
    if rows:
        evaluation_keys = {
            "evaluation_id",
            "dataset_manifest_sha256",
            "matcher_fingerprint",
            "policy_fingerprint",
            "build_fingerprint",
            "runtime_fingerprint",
            "verification_source",
        }
        evaluation_identities = {
            tuple(str(row[key]) for key in sorted(evaluation_keys)) for row in rows
        }
        if len(evaluation_identities) != 1:
            raise OperationalTemplateInstallError(
                "source shadow templates do not share one evaluation authority"
            )
        for row in rows:
            if (
                row["lifecycle"] != "shadow"
                or row["verification_source"] != "frozen_runner"
                or row["matcher_fingerprint"] != matcher
                or row["policy_fingerprint"] != policy
                or int(row["gate_passed"]) != 1
                or int(row["expected_count"]) != int(row["result_count"])
                or int(row["result_count"]) != int(row["item_count"])
                or int(row["pair_count"]) < 1
                or int(row["invalidation_count"]) != 0
                or int(row["successful_attempt_count"]) < 1
            ):
                raise OperationalTemplateInstallError(
                    "source shadow template evaluation is not eligible"
                )
        templates = []
        for row in rows:
            try:
                definition = json.loads(str(row["definition_json"]))
            except json.JSONDecodeError as exc:
                raise OperationalTemplateInstallError(
                    "source template definition is invalid"
                ) from exc
            templates.append(
                {
                    "version_id": str(row["version_id"]),
                    "version_number": int(row["version_number"]),
                    "parent_version_id": row["parent_version_id"],
                    "record_version": int(row["record_version"]),
                    "lifecycle": "shadow",
                    "content_sha256": str(row["content_sha256"]),
                    "definition": definition,
                }
            )
        first = rows[0]
        source_evaluation_id = str(first["evaluation_id"])
        evaluation = {
            "evaluation_id": source_evaluation_id,
            "dataset_manifest_sha256": str(first["dataset_manifest_sha256"]),
            "matcher_fingerprint": matcher,
            "policy_fingerprint": policy,
            "source_build_fingerprint": str(first["build_fingerprint"]),
            "runtime_fingerprint": str(first["runtime_fingerprint"]),
            "verification_source": "frozen_runner",
            "gate_passed": True,
        }
        bundle = build_operational_template_bundle(
            templates=templates,
            evaluation=evaluation,
        )
        source_kind = "database"
        source_database_sha256 = hashlib.sha256(database.read_bytes()).hexdigest()
        source_bundle_file_sha256 = None
    else:
        try:
            source_bundle_path = _require_safe_file(
                source / "operational-template-bundle.json",
                root=source,
            )
            source_bundle_bytes = source_bundle_path.read_bytes()
            load_operational_template_bundle(
                source_bundle_path,
                expected_matcher_fingerprint=matcher,
                expected_policy_fingerprint=policy,
            )
            parsed_bundle = json.loads(source_bundle_bytes)
        except (
            OperationalContractInstallError,
            OperationalTemplateBundleError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise OperationalTemplateInstallError(
                "source has neither current templates nor a valid sealed template bundle"
            ) from exc
        if (
            not isinstance(parsed_bundle, dict)
            or canonical_json(parsed_bundle) != source_bundle_bytes
        ):
            raise OperationalTemplateInstallError(
                "source sealed template bundle is not canonical"
            )
        parsed_evaluation = parsed_bundle.get("evaluation")
        if not isinstance(parsed_evaluation, dict) or not isinstance(
            parsed_evaluation.get("evaluation_id"), str
        ):
            raise OperationalTemplateInstallError(
                "source sealed template evaluation is invalid"
            )
        bundle = parsed_bundle
        source_kind = "sealed_bundle"
        source_database_sha256 = None
        source_bundle_file_sha256 = hashlib.sha256(source_bundle_bytes).hexdigest()
        source_evaluation_id = str(parsed_evaluation["evaluation_id"])
    bundle_path = target / "operational-template-bundle.json"
    try:
        _write_once(bundle_path, canonical_json(bundle), target_root=target)
        loaded = load_operational_template_bundle(
            bundle_path,
            expected_matcher_fingerprint=matcher,
            expected_policy_fingerprint=policy,
        )
    except Exception as exc:
        raise OperationalTemplateInstallError(
            "installed operational template bundle failed verification"
        ) from exc
    evidence = {
        "schema_version": 1,
        "kind": "dahe_operational_template_bundle_install",
        "classification": "operational_only",
        "formal_loop9_gate_eligible": False,
        "current_build_sha256": current_loop9_build_sha256(ROOT),
        "source_kind": source_kind,
        "source_database_sha256": source_database_sha256,
        "source_bundle_file_sha256": source_bundle_file_sha256,
        "bundle_sha256": str(bundle["bundle_sha256"]),
        "template_count": len(loaded),
        "source_evaluation_id_sha256": hashlib.sha256(
            source_evaluation_id.encode("utf-8")
        ).hexdigest(),
    }
    try:
        _write_once(output, canonical_json(evidence), target_root=target)
    except OperationalContractInstallError as exc:
        raise OperationalTemplateInstallError(str(exc)) from exc
    return evidence


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise OperationalTemplateInstallError("project .venv is required")
    arguments = _parser().parse_args(argv)
    evidence = install_operational_template_bundle(
        source_root=arguments.source_root,
        target_root=arguments.target_root,
        output=arguments.output,
    )
    print(json.dumps(evidence, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
