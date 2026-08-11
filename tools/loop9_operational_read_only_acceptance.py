from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from dahe.verification.ledger import LedgerStore
from dahe.verification.operational_read_only_acceptance import (
    ACCEPTED,
    WITH_GUARD,
    OperationalReadOnlyAcceptanceError,
    OperationalReadOnlyAcceptanceInputs,
    publish_operational_read_only_acceptance,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


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
            "Replay the guarded read-only production evidence and atomically "
            "record the resulting Loop 9 operational status."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute, required=True)
    parser.add_argument("--release-manifest", type=_absolute, required=True)
    parser.add_argument("--regression-report", type=_absolute, required=True)
    parser.add_argument(
        "--settlement-capture-evidence",
        type=_absolute,
        required=True,
    )
    parser.add_argument("--daily-capture-evidence", type=_absolute, required=True)
    parser.add_argument("--fault-injection-evidence", type=_absolute, required=True)
    parser.add_argument("--backup-restore-evidence", type=_absolute, required=True)
    parser.add_argument("--ocr-qualification", type=_absolute, required=True)
    parser.add_argument("--daily-report-id", type=_technical_id, required=True)
    parser.add_argument("--output", type=_absolute, required=True)
    return parser


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    return completed.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    parser = _parser()
    arguments = parser.parse_args(argv)
    if _git("status", "--porcelain"):
        parser.error("operational acceptance requires a clean committed checkout")
    try:
        relative_output = arguments.output.resolve(strict=False).relative_to(ROOT)
    except ValueError:
        parser.error("acceptance output must be inside the project repository")
    inputs = OperationalReadOnlyAcceptanceInputs(
        project_root=ROOT,
        data_root=arguments.data_root,
        release_manifest=arguments.release_manifest,
        regression_report=arguments.regression_report,
        settlement_capture_evidence=arguments.settlement_capture_evidence,
        daily_capture_evidence=arguments.daily_capture_evidence,
        fault_injection_evidence=arguments.fault_injection_evidence,
        backup_restore_evidence=arguments.backup_restore_evidence,
        ocr_qualification=arguments.ocr_qualification,
        daily_report_id=arguments.daily_report_id,
        output=arguments.output,
    )
    try:
        evidence = publish_operational_read_only_acceptance(inputs)
    except OperationalReadOnlyAcceptanceError as exc:
        parser.error(str(exc))

    build_commit = _git("rev-parse", "HEAD")
    if evidence.status == ACCEPTED:
        risks = [
            "The independent unseen 50-waybill strict shadow gate remains pending.",
            (
                "The first release is local to the development computer without "
                "an installer or automatic upgrade."
            ),
        ]
        next_inputs = [
            (
                "Operate the read-only production build and retain the legacy "
                "program only as a stopped rollback option."
            ),
            (
                "Complete the strict shadow_accepted path later without changing "
                "this operational evidence."
            ),
        ]
    elif evidence.status == WITH_GUARD:
        guard = evidence.payload["first_batch_guard"]
        if not isinstance(guard, dict):
            parser.error("first-batch guard projection is invalid")
        reviewed_count = int(guard["reviewed_count"])
        false_normal_count = int(guard["false_normal_count"])
        if false_normal_count:
            guard_risk = (
                "A machine-normal result was classified as a business problem "
                "during the first 30 unique waybill checks."
            )
            guard_next = (
                "Diagnose the false-normal evidence without weakening the review "
                "boundary, then repeat a protected guard batch on a new build."
            )
        else:
            guard_risk = (
                f"First-batch protection is still in progress at "
                f"{reviewed_count}/30 unique waybills."
            )
            guard_next = (
                "Continue the two-button manual decisions until 30 unique "
                "production waybills have been reviewed."
            )
        risks = [
            guard_risk,
            (
                "All machine-normal results remain subject to manual confirmation "
                "while the guard is active."
            ),
            "The independent unseen 50-waybill strict shadow gate remains pending.",
        ]
        next_inputs = [
            "Keep the read-only business workflow under manual confirmation.",
            guard_next,
        ]
    else:
        parser.error("operational acceptance returned an unsupported status")

    ledger_path = ROOT / "verification" / "loop-ledger.json"
    ledger = LedgerStore(ledger_path)
    current = ledger.read()
    accepted_at = datetime.now(UTC).isoformat()
    updated = ledger.commit_operational_read_only_acceptance(
        expected_revision=int(current["revision"]),
        evidence_path=relative_output.as_posix(),
        evidence_sha256=evidence.canonical_sha256,
        status=evidence.status,
        build_git_commit=build_commit,
        accepted_at=accepted_at,
        unresolved_risks=risks,
        next_inputs=next_inputs,
    )
    print(
        json.dumps(
            {
                "evidence_sha256": evidence.canonical_sha256,
                "ledger_revision": updated["revision"],
                "status": updated["status"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
