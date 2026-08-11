from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
    Loop9FormalRunEvidenceStore,
    Loop9FormalRunRequest,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (
    ROOT / ".venv" / "Scripts" / "python.exe"
).resolve()
FAULT_SCENARIOS = (
    "browser_closed",
    "gpu_worker_failure",
    "main_application_restart",
    "transient_network_failure",
)


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _sha256(value: str) -> str:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise argparse.ArgumentTypeError(
            "SHA-256 must contain 64 lowercase hexadecimal characters"
        )
    return value


def _technical_id(value: str) -> str:
    if (
        not value
        or value != value.strip()
        or len(value) > 160
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("technical identity is invalid")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Derive immutable Loop 9 formal-run evidence from the active "
            "50/30 authorities, SQLite execution records, request-audit "
            "seals and raw timing observations. The command performs no "
            "network request and accepts no user-supplied result counts."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument(
        "--locked-job-id",
        type=_technical_id,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-selection-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-job-id",
        type=_technical_id,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-machine-evaluation-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        "--daily-snapshot-validation-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        "--dataset-isolation-sha256",
        type=_sha256,
        required=True,
    )
    for scenario in FAULT_SCENARIOS:
        option = scenario.replace("_", "-")
        parser.add_argument(
            f"--{option}-run-id",
            type=_technical_id,
            required=True,
        )
        parser.add_argument(
            f"--{option}-job-id",
            type=_technical_id,
            required=True,
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    request = Loop9FormalRunRequest(
        locked_job_id=arguments.locked_job_id,
        real_shadow_selection_sha256=(
            arguments.real_shadow_selection_sha256
        ),
        real_shadow_job_id=arguments.real_shadow_job_id,
        real_shadow_machine_evaluation_sha256=(
            arguments.real_shadow_machine_evaluation_sha256
        ),
        daily_snapshot_validation_sha256=(
            arguments.daily_snapshot_validation_sha256
        ),
        dataset_isolation_sha256=(
            arguments.dataset_isolation_sha256
        ),
        fault_scenarios={
            scenario: FaultScenarioIdentity(
                run_id=getattr(arguments, f"{scenario}_run_id"),
                job_id=getattr(arguments, f"{scenario}_job_id"),
            )
            for scenario in FAULT_SCENARIOS
        },
    )
    store = Loop9FormalRunEvidenceStore(arguments.data_root)
    evidence = store.publish(project_root=ROOT, request=request)
    print(
        json.dumps(
            {
                "canonical_sha256": evidence.canonical_sha256,
                "kind": evidence.kind,
                "relative_path": store.path_for(
                    evidence.canonical_sha256
                )
                .relative_to(arguments.data_root)
                .as_posix(),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
