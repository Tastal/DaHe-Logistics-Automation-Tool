from __future__ import annotations

import subprocess

import pytest

from dahe.adapters.ocr.devices import (
    DeviceDiscoveryError,
    NvidiaDevice,
    discover_nvidia_devices,
    parse_nvidia_smi_csv,
)


def test_nvidia_csv_uses_uuid_as_stable_identity_and_index_as_ephemeral() -> None:
    devices = parse_nvidia_smi_csv(
        "1, GPU-stable-b, NVIDIA RTX Example, 8192 MiB, 610.62, 8.9\n"
        "0, GPU-stable-a, NVIDIA RTX Other, 4096 MiB, 610.62, 8.6\n"
    )

    assert devices == (
        NvidiaDevice(
            current_index=1,
            stable_id="GPU-stable-b",
            name="NVIDIA RTX Example",
            memory_mib=8192,
            driver_version="610.62",
            compute_capability="8.9",
        ),
        NvidiaDevice(
            current_index=0,
            stable_id="GPU-stable-a",
            name="NVIDIA RTX Other",
            memory_mib=4096,
            driver_version="610.62",
            compute_capability="8.6",
        ),
    )


def test_same_uuid_can_map_to_a_different_index_after_restart() -> None:
    before = parse_nvidia_smi_csv(
        "0, GPU-stable, NVIDIA RTX Example, 8192 MiB, 610.62, 8.9\n"
    )[0]
    after = parse_nvidia_smi_csv(
        "2, GPU-stable, NVIDIA RTX Example, 8192 MiB, 610.62, 8.9\n"
    )[0]

    assert before.stable_id == after.stable_id
    assert before.current_index != after.current_index


def test_discovery_returns_empty_when_nvidia_smi_is_absent() -> None:
    assert discover_nvidia_devices(which=lambda _: None) == ()


def test_discovery_classifies_timeout_without_guessing_devices() -> None:
    def timeout(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("nvidia-smi", 3)

    with pytest.raises(DeviceDiscoveryError, match="timed out"):
        discover_nvidia_devices(which=lambda _: "nvidia-smi.exe", runner=timeout)


@pytest.mark.parametrize(
    "line",
    [
        "0, , NVIDIA RTX Example, 8192 MiB, 610.62, 8.9",
        "gpu-zero, GPU-a, NVIDIA RTX Example, 8192 MiB, 610.62, 8.9",
        "0, GPU-a, NVIDIA RTX Example, unknown, 610.62, 8.9",
        "0, GPU-a, NVIDIA RTX Example, 8192 MiB, 610.62",
    ],
)
def test_malformed_device_rows_are_rejected(line: str) -> None:
    with pytest.raises(DeviceDiscoveryError):
        parse_nvidia_smi_csv(line)

