from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from dahe.system.supervision import OwnedProcessSupervisor, ProcessOwnershipError

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="DaHeLogistics process supervision is Windows-only",
)

HELPER_ARGUMENTS = (
    sys.executable,
    "-I",
    "-c",
    "import time; time.sleep(60)",
)


def _wait_until_stopped(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float = 3,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert process.poll() is not None


def _stop_external_helper(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def _spawn_external_helper() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        HELPER_ARGUMENTS,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def test_supervisor_close_stops_owned_helper_but_not_unknown_process(
    tmp_path: Path,
) -> None:
    supervisor = OwnedProcessSupervisor(
        instance_id="instance-a",
        runtime_dir=tmp_path,
    )
    owned = supervisor.spawn(
        worker_id="owned-helper",
        argv=HELPER_ARGUMENTS,
    )
    unknown = _spawn_external_helper()
    try:
        assert supervisor.is_alive("owned-helper")
        assert unknown.poll() is None

        supervisor.close()

        assert not supervisor.is_alive("owned-helper")
        assert unknown.poll() is None
    finally:
        supervisor.close()
        _stop_external_helper(unknown)

    assert owned.pid != unknown.pid


def test_forged_worker_identity_cannot_terminate_owned_or_unknown_process(
    tmp_path: Path,
) -> None:
    supervisor = OwnedProcessSupervisor(
        instance_id="instance-a",
        runtime_dir=tmp_path,
    )
    owned = supervisor.spawn(
        worker_id="owned-helper",
        argv=HELPER_ARGUMENTS,
    )
    unknown = _spawn_external_helper()
    try:
        with pytest.raises(ProcessOwnershipError):
            supervisor.stop_owned(
                worker_id="forged-worker",
                expected_pid=unknown.pid,
                expected_process_started_at="forged-start-time",
                timeout_seconds=1,
            )
        assert unknown.poll() is None
        assert supervisor.is_alive("owned-helper")

        with pytest.raises(ProcessOwnershipError):
            supervisor.stop_owned(
                worker_id="owned-helper",
                expected_pid=unknown.pid,
                expected_process_started_at=owned.process_started_at,
                timeout_seconds=1,
            )
        assert unknown.poll() is None
        assert supervisor.is_alive("owned-helper")
    finally:
        supervisor.close()
        _stop_external_helper(unknown)


def test_correct_owned_identity_can_stop_only_that_helper(
    tmp_path: Path,
) -> None:
    supervisor = OwnedProcessSupervisor(
        instance_id="instance-a",
        runtime_dir=tmp_path,
    )
    owned = supervisor.spawn(
        worker_id="owned-helper",
        argv=HELPER_ARGUMENTS,
    )
    unknown = _spawn_external_helper()
    try:
        supervisor.stop_owned(
            worker_id="owned-helper",
            expected_pid=owned.pid,
            expected_process_started_at=owned.process_started_at,
            timeout_seconds=3,
        )

        assert not supervisor.is_alive("owned-helper")
        assert unknown.poll() is None
    finally:
        supervisor.close()
        _stop_external_helper(unknown)


def test_process_identity_mismatch_never_falls_back_to_pid_only(
    tmp_path: Path,
) -> None:
    supervisor = OwnedProcessSupervisor(
        instance_id="instance-a",
        runtime_dir=tmp_path,
    )
    owned = supervisor.spawn(
        worker_id="owned-helper",
        argv=HELPER_ARGUMENTS,
    )
    try:
        with pytest.raises(ProcessOwnershipError):
            supervisor.stop_owned(
                worker_id="owned-helper",
                expected_pid=owned.pid,
                expected_process_started_at="different-process-start",
                timeout_seconds=1,
            )

        assert supervisor.is_alive("owned-helper")
    finally:
        supervisor.close()
