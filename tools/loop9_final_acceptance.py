from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from dahe.verification.loop9_final_acceptance import (
    Loop9FinalAcceptanceInputs,
    accept_loop9_shadow,
)
from dahe.verification.loop9_operational_evidence import (
    FaultScenarioIdentity,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (
    ROOT / ".venv" / "Scripts" / "python.exe"
).resolve()


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


def _technical_identity(value: str) -> str:
    if (
        not value
        or value != value.strip()
        or len(value) > 160
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in value
        )
    ):
        raise argparse.ArgumentTypeError(
            "technical identity is invalid"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay every offline Loop 9 Gate, publish immutable "
            "shadow-acceptance evidence, and atomically update the Loop "
            "ledger. This command performs no Chengfeng or other network "
            "request."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument("--ledger", type=_absolute_path, required=True)
    parser.add_argument(
        "--output-directory",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--read-contract-validation",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--current-locked-selection-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-selection-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-package",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-seal",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-machine-evaluation",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--daily-snapshot-validation",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--discovery-development",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--current-locked-50",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-30",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--daily-validation-dataset",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--source-development-authority",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--dataset-isolation",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--formal-run-evidence-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        "--locked-job-id",
        type=_technical_identity,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-job-id",
        type=_technical_identity,
        required=True,
    )
    for scenario in (
        "browser-closed",
        "gpu-worker-failure",
        "main-application-restart",
        "transient-network-failure",
    ):
        parser.add_argument(
            f"--{scenario}-run-id",
            type=_technical_identity,
            required=True,
        )
        parser.add_argument(
            f"--{scenario}-job-id",
            type=_technical_identity,
            required=True,
        )
    parser.add_argument(
        "--expected-ledger-revision",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--remaining-risk",
        action="append",
        default=[],
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    evidence = accept_loop9_shadow(
        inputs=Loop9FinalAcceptanceInputs(
            project_root=ROOT,
            data_root=arguments.data_root,
            read_contract_validation_path=(
                arguments.read_contract_validation
            ),
            current_locked_selection_sha256=(
                arguments.current_locked_selection_sha256
            ),
            real_shadow_selection_sha256=(
                arguments.real_shadow_selection_sha256
            ),
            real_shadow_package_dir=arguments.real_shadow_package,
            real_shadow_seal_path=arguments.real_shadow_seal,
            real_shadow_machine_evaluation_path=(
                arguments.real_shadow_machine_evaluation
            ),
            daily_snapshot_validation_path=(
                arguments.daily_snapshot_validation
            ),
            discovery_development_path=(
                arguments.discovery_development
            ),
            current_locked_50_path=arguments.current_locked_50,
            real_shadow_30_path=arguments.real_shadow_30,
            daily_validation_dataset_path=(
                arguments.daily_validation_dataset
            ),
            source_development_authority_path=(
                arguments.source_development_authority
            ),
            dataset_isolation_path=arguments.dataset_isolation,
            formal_run_evidence_sha256=(
                arguments.formal_run_evidence_sha256
            ),
            locked_job_id=arguments.locked_job_id,
            real_shadow_job_id=arguments.real_shadow_job_id,
            fault_scenarios={
                "browser_closed": FaultScenarioIdentity(
                    run_id=arguments.browser_closed_run_id,
                    job_id=arguments.browser_closed_job_id,
                ),
                "gpu_worker_failure": FaultScenarioIdentity(
                    run_id=arguments.gpu_worker_failure_run_id,
                    job_id=arguments.gpu_worker_failure_job_id,
                ),
                "main_application_restart": FaultScenarioIdentity(
                    run_id=arguments.main_application_restart_run_id,
                    job_id=arguments.main_application_restart_job_id,
                ),
                "transient_network_failure": FaultScenarioIdentity(
                    run_id=arguments.transient_network_failure_run_id,
                    job_id=arguments.transient_network_failure_job_id,
                ),
            },
        ),
        ledger_path=arguments.ledger,
        output_directory=arguments.output_directory,
        expected_ledger_revision=arguments.expected_ledger_revision,
        clock=lambda: datetime.now(UTC),
        remaining_risks=tuple(arguments.remaining_risk),
    )
    print(
        json.dumps(
            {
                "canonical_sha256": evidence["canonical_sha256"],
                "gate_passed": True,
                "ledger_status": "shadow_accepted",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
