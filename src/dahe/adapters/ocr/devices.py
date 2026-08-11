from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

MEMORY_PATTERN = re.compile(r"^(?P<mib>[0-9]+)\s*MiB$", re.IGNORECASE)


class DeviceDiscoveryError(RuntimeError):
    """Raised when available hardware cannot be enumerated safely."""


@dataclass(frozen=True, slots=True)
class NvidiaDevice:
    current_index: int
    stable_id: str
    name: str
    memory_mib: int
    driver_version: str
    compute_capability: str


def parse_nvidia_smi_csv(output: str) -> tuple[NvidiaDevice, ...]:
    devices: list[NvidiaDevice] = []
    for raw_line in output.splitlines():
        if not raw_line.strip():
            continue
        parts = tuple(part.strip() for part in raw_line.split(","))
        if len(parts) != 6:
            raise DeviceDiscoveryError("nvidia-smi returned an unexpected row shape")
        raw_index, stable_id, name, raw_memory, driver, compute = parts
        try:
            index = int(raw_index)
        except ValueError as exc:
            raise DeviceDiscoveryError("nvidia-smi returned an invalid device index") from exc
        memory_match = MEMORY_PATTERN.fullmatch(raw_memory)
        if (
            index < 0
            or not stable_id
            or not stable_id.startswith("GPU-")
            or not name
            or memory_match is None
            or not driver
            or not compute
        ):
            raise DeviceDiscoveryError("nvidia-smi returned incomplete device evidence")
        devices.append(
            NvidiaDevice(
                current_index=index,
                stable_id=stable_id,
                name=name,
                memory_mib=int(memory_match.group("mib")),
                driver_version=driver,
                compute_capability=compute,
            )
        )
    stable_ids = [device.stable_id for device in devices]
    if len(stable_ids) != len(set(stable_ids)):
        raise DeviceDiscoveryError("nvidia-smi returned duplicate stable device identities")
    return tuple(devices)


def discover_nvidia_devices(
    *,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[NvidiaDevice, ...]:
    executable = which("nvidia-smi.exe") or which("nvidia-smi")
    if executable is None:
        return ()
    try:
        completed = runner(
            (
                executable,
                "--query-gpu=index,uuid,name,memory.total,driver_version,compute_cap",
                "--format=csv,noheader",
            ),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DeviceDiscoveryError("nvidia-smi timed out") from exc
    except OSError as exc:
        raise DeviceDiscoveryError("nvidia-smi could not be started") from exc
    if completed.returncode != 0:
        raise DeviceDiscoveryError("nvidia-smi returned a failure status")
    return parse_nvidia_smi_csv(completed.stdout)

