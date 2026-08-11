from __future__ import annotations

from pathlib import Path

import pytest

from tools import dev_quality


def test_quality_manifest_pins_only_approved_isolated_tools() -> None:
    manifest = dev_quality.load_manifest()

    assert manifest.python_tools == {
        "pip-audit": "2.10.1",
        "py-spy": "0.4.2",
        "schemathesis": "4.24.3",
    }
    assert manifest.gitleaks_version == "8.30.1"
    assert (
        manifest.gitleaks_archive_sha256
        == "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
    )
    assert all("development-tools" in part for part in manifest.runtime_parts)


def test_dependency_audit_never_fixes_or_resolves_release_locks(
    tmp_path: Path,
) -> None:
    manifest = dev_quality.load_manifest()
    commands = dev_quality.dependency_audit_commands(
        manifest=manifest,
        output_root=tmp_path.resolve(),
    )

    assert [lock.relative_to(dev_quality.ROOT).as_posix() for lock, _ in commands] == [
        "requirements.lock",
        "browser-runtime/requirements.lock",
        "ocr-runtime/requirements-cpu.lock",
        "ocr-runtime/requirements-gpu.lock",
    ]
    for lock, command in commands:
        assert lock.is_absolute()
        assert "--no-deps" in command
        assert "--disable-pip" in command
        assert "--strict" in command
        assert "--fix" not in command
        assert "--dry-run" not in command
        assert command[-1] == str(lock)


@pytest.mark.parametrize(
    "url",
    [
        "https://pc.chengfengkuaiyun.com/api/v1/openapi.json",
        "http://0.0.0.0:8877/api/v1/openapi.json",
        "http://localhost:8877/api/v1/openapi.json?token=secret",
        "http://127.0.0.1:8877/other.json",
    ],
)
def test_api_contract_command_rejects_external_or_ambiguous_targets(
    url: str,
) -> None:
    with pytest.raises(ValueError):
        dev_quality.schemathesis_command(
            schema_url=url,
            base_url="http://127.0.0.1:8877",
            session_cookie="a" * 43,
        )


def test_api_contract_command_is_bounded_to_loopback_meta_routes() -> None:
    command = dev_quality.schemathesis_command(
        schema_url="http://127.0.0.1:49152/api/v1/openapi.json",
        base_url="http://127.0.0.1:49152",
        session_cookie="a" * 43,
    )

    joined = " ".join(command)
    assert "127.0.0.1:49152" in joined
    assert "--max-examples" in command
    assert "--include-path-regex" in command
    assert "chengfeng" not in joined.casefold()


def test_profiler_always_launches_a_new_offline_child(tmp_path: Path) -> None:
    command = dev_quality.py_spy_command(
        output_path=(tmp_path / "profile.json").resolve(),
        owned_child_pid=43210,
    )

    assert command[command.index("--pid") + 1] == "43210"
    assert "--enable-chengfeng-shadow" not in command
    assert "--serve" not in command
    assert "--" not in command


def test_secret_scan_redacts_and_keeps_raw_findings_temporary(
    tmp_path: Path,
) -> None:
    command = dev_quality.gitleaks_command(
        temporary_report=(tmp_path / "raw.json").resolve(),
    )

    assert "--redact=100" in command
    assert "--report-format=json" in command
    assert "--report-path" in command
    assert "--verbose" not in command
    assert command[-1] == str(dev_quality.ROOT)
