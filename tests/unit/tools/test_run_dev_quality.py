from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tools import run_dev_quality as module


def test_gitleaks_ignore_contains_only_exact_historical_test_fingerprints() -> None:
    entries = [
        line
        for line in (module.ROOT / ".gitleaksignore").read_text(
            encoding="utf-8"
        ).splitlines()
        if line and not line.startswith("#")
    ]

    assert len(entries) == 7
    assert all(
        re.fullmatch(
            r"[0-9a-f]{40}:tests/(unit|integration)/[^:]+:generic-api-key:\d+",
            entry,
        )
        for entry in entries
    )


def test_gitleaks_summary_does_not_copy_secret_or_path_fields(tmp_path: Path) -> None:
    report = tmp_path / "raw.json"
    report.write_text(
        json.dumps(
            [
                {
                    "RuleID": "generic-api-key",
                    "Secret": "must-not-survive",
                    "File": "sensitive/path.txt",
                    "Commit": "abc",
                }
            ]
        ),
        encoding="utf-8",
    )

    summary = module._summarize_gitleaks(report)

    assert summary["finding_count"] == 1
    assert summary["rule_ids"] == ["generic-api-key"]
    assert "must-not-survive" not in json.dumps(summary)
    assert "sensitive/path.txt" not in json.dumps(summary)


def test_local_api_child_never_enables_chengfeng(tmp_path: Path) -> None:
    command = module._local_api_command(port=49152, data_root=tmp_path.resolve())

    assert "--serve" in command
    assert "--enable-test-fixtures" in command
    assert "--no-browser" in command
    assert "--enable-chengfeng-shadow" not in command
    assert "--enable-loop9-scheduler-probe" not in command


def test_local_api_output_removes_the_temporary_session_cookie() -> None:
    cookie = "temporary-session-cookie-1234567890"

    output = module._sanitize_api_output(
        stdout=f"Cookie: dahe_local_session={cookie}",
        stderr=f"replay {cookie}",
        session_cookie=cookie,
    )

    assert cookie not in output
    assert output.count("[REDACTED]") == 2


def test_installed_tool_manifest_must_match_current_source_manifest(
    tmp_path: Path,
) -> None:
    installation = tmp_path / "runtime-installation.json"
    installation.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "isolated_development_quality_tool",
                "name": "pip-audit",
                "version": "2.10.1",
                "source_manifest_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="bootstrap_dev_quality"):
        module._validate_installation(
            installation=installation,
            name="pip-audit",
            version="2.10.1",
        )


def test_run_output_must_stay_inside_the_quality_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="quality root"):
        module._validate_run_root(tmp_path.resolve(), quality_root=(tmp_path / "other").resolve())


def test_gpu_audit_fallback_excludes_only_the_vendor_package(tmp_path: Path) -> None:
    source = tmp_path / "gpu.lock"
    source.write_text(
        "--extra-index-url https://vendor.invalid/simple/\n\n"
        "pillow==12.0.0\n"
        "paddlepaddle-gpu==3.3.1\n",
        encoding="utf-8",
    )
    target = tmp_path / "pypi-only.lock"

    excluded = module._write_pypi_audit_fallback(source=source, target=target)

    assert excluded == ["paddlepaddle-gpu==3.3.1"]
    assert target.read_text(encoding="utf-8") == "pillow==12.0.0\n"
