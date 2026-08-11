from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="DaHeLogistics process supervision is Windows-only",
    ),
]

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
SYNCHRONIZE = 0x00100000
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

SLEEP_HELPER = (
    sys.executable,
    "-I",
    "-c",
    "import time; time.sleep(60)",
)

SUPERVISOR_HELPER = """
import json
import sys
import time
from pathlib import Path

from dahe.system.supervision import OwnedProcessSupervisor

runtime_dir = Path(sys.argv[1])
identity_path = Path(sys.argv[2])
supervisor = OwnedProcessSupervisor(
    instance_id="orphan-integration-supervisor",
    runtime_dir=runtime_dir,
)
child = supervisor.spawn(
    worker_id="orphan-integration-child",
    argv=(sys.executable, "-I", "-c", "import time; time.sleep(60)"),
)
temporary = identity_path.with_suffix(".tmp")
temporary.write_text(
    json.dumps(
        {
            "pid": child.pid,
            "process_started_at": child.process_started_at,
        },
        sort_keys=True,
    ),
    encoding="utf-8",
)
temporary.replace(identity_path)
while True:
    time.sleep(1)
"""


def _open_known_process(pid: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    open_process.restype = ctypes.c_void_p
    handle = open_process(
        SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )
    if not handle:
        raise AssertionError(
            f"could not open controlled helper process ({ctypes.get_last_error()})"
        )
    return int(handle)


def _wait_for_process(handle: int, timeout_ms: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    wait = kernel32.WaitForSingleObject
    wait.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
    wait.restype = ctypes.c_ulong
    return int(wait(handle, timeout_ms))


def _terminate_known_process(handle: int) -> None:
    if _wait_for_process(handle, 0) == WAIT_OBJECT_0:
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    terminate = kernel32.TerminateProcess
    terminate.argtypes = (ctypes.c_void_p, ctypes.c_uint)
    terminate.restype = ctypes.c_int
    assert terminate(handle, 97), ctypes.get_last_error()
    assert _wait_for_process(handle, 3000) == WAIT_OBJECT_0


def _close_process_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close = kernel32.CloseHandle
    close.argtypes = (ctypes.c_void_p,)
    close.restype = ctypes.c_int
    assert close(handle), ctypes.get_last_error()


def _stop_popen(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def _wait_for_identity_file(
    identity_path: Path,
    supervisor_process: subprocess.Popen[bytes],
) -> dict[str, object]:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if identity_path.is_file():
            return dict(json.loads(identity_path.read_text(encoding="utf-8")))
        if supervisor_process.poll() is not None:
            raise AssertionError(
                f"controlled supervisor exited with {supervisor_process.returncode}"
            )
        time.sleep(0.02)
    raise AssertionError("controlled supervisor did not report its child identity")


def test_supervisor_crash_closes_job_and_stops_only_its_owned_child(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    identity_path = runtime_dir / "child-identity.json"
    unknown = subprocess.Popen(
        SLEEP_HELPER,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    supervisor_process = subprocess.Popen(
        (
            sys.executable,
            "-I",
            "-c",
            SUPERVISOR_HELPER,
            str(runtime_dir),
            str(identity_path),
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    child_handle: int | None = None
    try:
        identity = _wait_for_identity_file(identity_path, supervisor_process)
        child_handle = _open_known_process(int(identity["pid"]))
        assert _wait_for_process(child_handle, 0) == WAIT_TIMEOUT
        assert unknown.poll() is None

        supervisor_process.terminate()
        supervisor_process.wait(timeout=3)

        assert _wait_for_process(child_handle, 5000) == WAIT_OBJECT_0
        assert unknown.poll() is None
    finally:
        _stop_popen(supervisor_process)
        if child_handle is not None:
            _terminate_known_process(child_handle)
            _close_process_handle(child_handle)
        _stop_popen(unknown)
