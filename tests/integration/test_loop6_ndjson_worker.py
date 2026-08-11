from __future__ import annotations

import sys
from pathlib import Path

import pytest

from dahe.adapters.ocr.protocol import OCR_PROTOCOL_VERSION, OcrCommand, OcrOperation
from dahe.adapters.ocr.worker_session import (
    SupervisedNdjsonWorker,
    WorkerProcessError,
    WorkerProtocolError,
    WorkerTimeoutError,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="DaHeLogistics process supervision is Windows-only",
    ),
]


def _command(*, profile_id: str = "test-profile") -> OcrCommand:
    return OcrCommand(
        protocol_version=OCR_PROTOCOL_VERSION,
        command_id="command-001",
        operation=OcrOperation.EXTRACT,
        image_sha256="a" * 64,
        relative_path="evidence/sha256/aa/ticket.png",
        pipeline_fingerprint="b" * 64,
        runtime_fingerprint="c" * 64,
        profile_id=profile_id,
    )


def _worker(project_root: Path, tmp_path: Path) -> SupervisedNdjsonWorker:
    return SupervisedNdjsonWorker(
        worker_id="loop6-fake-worker",
        argv=(
            sys.executable,
            "-I",
            str(project_root / "tests" / "fixtures" / "ocr" / "fake_ndjson_worker.py"),
        ),
        runtime_dir=tmp_path,
    )


def test_supervised_worker_round_trip_and_clean_shutdown(
    project_root: Path,
    tmp_path: Path,
) -> None:
    worker = _worker(project_root, tmp_path)
    try:
        result = worker.request(_command(), timeout_seconds=3)
        assert result.command_id == "command-001"
        assert result.worker_identity == "fake-worker"
        assert worker.is_alive
    finally:
        worker.close()
    assert not worker.is_alive


def test_worker_hello_and_heartbeat_bind_one_worker_identity(
    project_root: Path,
    tmp_path: Path,
) -> None:
    worker = _worker(project_root, tmp_path)
    try:
        hello = worker.hello(
            runtime_fingerprint="c" * 64,
            profile_id="test-profile",
            timeout_seconds=3,
        )
        heartbeat = worker.heartbeat(
            runtime_fingerprint="c" * 64,
            profile_id="test-profile",
            timeout_seconds=3,
        )
        assert hello.worker_identity == heartbeat.worker_identity == "fake-worker"
        assert worker.last_heartbeat_monotonic is not None
    finally:
        worker.close()


def test_worker_crash_timeout_and_malformed_output_are_distinct(
    project_root: Path,
    tmp_path: Path,
) -> None:
    crashing = _worker(project_root, tmp_path / "crash")
    try:
        with pytest.raises(WorkerProcessError):
            crashing.request(
                _command(profile_id="test-crash"),
                timeout_seconds=3,
            )
    finally:
        crashing.close()

    hanging = _worker(project_root, tmp_path / "hang")
    try:
        with pytest.raises(WorkerTimeoutError):
            hanging.request(
                _command(profile_id="test-hang"),
                timeout_seconds=0.05,
            )
    finally:
        hanging.close()

    malformed = _worker(project_root, tmp_path / "malformed")
    try:
        with pytest.raises(WorkerProtocolError):
            malformed.request(
                _command(profile_id="test-malformed"),
                timeout_seconds=3,
            )
        assert not malformed.is_alive
    finally:
        malformed.close()

    invalid_utf8 = _worker(project_root, tmp_path / "invalid-utf8")
    try:
        with pytest.raises(WorkerProtocolError):
            invalid_utf8.request(
                _command(profile_id="test-invalid-utf8"),
                timeout_seconds=3,
            )
        assert not invalid_utf8.is_alive
    finally:
        invalid_utf8.close()
