from __future__ import annotations

import hashlib
import json
import socket
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from dahe.system.instance_lock import SingleInstanceGuard

pytestmark = pytest.mark.integration


def _run_check(data_root: Path, port: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "dahe",
            "--check",
            "--data-root",
            str(data_root),
            "--port",
            str(port),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _run_serve(data_root: Path, port: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "dahe",
            "--serve",
            "--no-browser",
            "--data-root",
            str(data_root),
            "--port",
            str(port),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )


def test_cli_startup_check_succeeds_offline(tmp_path: Path) -> None:
    result = _run_check(tmp_path / "data", _free_port())
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["application_id"] == "DaHeLogistics"
    assert report["real_platform_access"] is False
    assert report["external_connections"] == 0


def test_cli_protected_fixtures_require_an_explicit_data_root() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "dahe",
            "--serve",
            "--no-browser",
            "--enable-test-fixtures",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 2
    assert "--data-root" in result.stderr


def test_cli_template_studio_requires_an_explicit_data_root() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "dahe",
            "--serve",
            "--no-browser",
            "--enable-template-studio",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 2
    assert "--data-root" in result.stderr


@pytest.mark.parametrize(
    "arguments,required_option",
    [
        (
            [
                "--serve",
                "--no-browser",
                "--enable-locked-set-review",
            ],
            "--data-root",
        ),
        (
            [
                "--check",
                "--data-root",
                "C:/explicit-review-data",
                "--enable-locked-set-review",
            ],
            "--serve",
        ),
    ],
)
def test_cli_locked_set_review_requires_serve_and_explicit_data_root(
    arguments: list[str],
    required_option: str,
) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "dahe", *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 2
    assert required_option in result.stderr


@pytest.mark.parametrize(
    "arguments,required_text",
    [
        (
            [
                "--serve",
                "--no-browser",
                "--loop9-review-package",
                "C:/loop9/review-package",
            ],
            "--data-root",
        ),
        (
            [
                "--check",
                "--data-root",
                "C:/loop9/review-data",
                "--loop9-review-package",
                "C:/loop9/review-package",
            ],
            "--serve",
        ),
        (
            [
                "--serve",
                "--no-browser",
                "--data-root",
                "C:/loop9/review-data",
                "--loop9-review-package",
                "relative/review-package",
            ],
            "absolute path",
        ),
        (
            [
                "--serve",
                "--no-browser",
                "--data-root",
                "C:/loop9/review-data",
                "--loop9-review-package",
                "C:/loop9/review-package",
                "--enable-chengfeng-shadow",
            ],
            "offline mode",
        ),
    ],
)
def test_cli_loop9_review_is_explicit_offline_and_isolated(
    arguments: list[str],
    required_text: str,
) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "dahe", *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 2
    assert required_text in result.stderr


@pytest.mark.parametrize(
    "other_mode",
    ["--enable-template-studio", "--enable-test-fixtures"],
)
def test_cli_locked_set_review_runs_without_tuning_or_test_modes(
    tmp_path: Path,
    other_mode: str,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "dahe",
            "--serve",
            "--no-browser",
            "--data-root",
            str(tmp_path / "review-data"),
            "--enable-locked-set-review",
            other_mode,
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 2
    assert "must run alone" in result.stderr


def test_cli_test_fixtures_reject_an_unmarked_existing_data_root(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "company-like-data"
    database_path = data_root / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    database_path.write_bytes(b"do not mutate")
    before_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "dahe",
            "--serve",
            "--no-browser",
            "--enable-test-fixtures",
            "--data-root",
            str(data_root),
            "--port",
            str(_free_port()),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert result.returncode == 2
    assert "new or previously marked data root" in result.stderr
    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == before_sha256


def test_cli_port_conflict_stops_without_replacing_owner(tmp_path: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            owner.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        owner.bind(("127.0.0.1", 0))
        owner.listen(1)
        port = int(owner.getsockname()[1])

        result = _run_check(tmp_path / "data", port)

        assert result.returncode != 0
        assert "port" in result.stderr.lower()
        assert owner.fileno() >= 0
        assert owner.getsockname()[1] == port


def test_cli_second_instance_is_rejected(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    port = _free_port()
    with SingleInstanceGuard(data_root, port, "0.1.0"):
        result = _run_check(data_root, port)

    assert result.returncode != 0
    assert "already running" in result.stderr.lower()


def test_cli_unmanaged_formal_database_stops_cleanly_without_mutation(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    database_path = data_root / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("CREATE TABLE jobs (placeholder TEXT)")
        connection.commit()
    original_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()

    result = _run_serve(data_root, _free_port())

    assert result.returncode == 2
    assert "no Alembic identity" in result.stderr
    assert "Traceback" not in result.stderr
    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == original_sha256
    assert not database_path.with_name(f"{database_path.name}-wal").exists()
    assert not database_path.with_name(f"{database_path.name}-shm").exists()
