from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def _result(
    command: dict[str, object],
    *,
    status: str = "ok",
    error: dict[str, str] | None = None,
) -> dict[str, object]:
    image_sha256 = command.get("image_sha256")
    fields: dict[str, object] = {}
    if status == "ok" and image_sha256 is not None:
        fields = {
            "ordinary_net": {
                "raw_text": "12.34 t",
                "amount": "12.34",
                "unit": "t",
                "confidence": "0.99",
            }
        }
    return {
        "protocol_version": 1,
        "command_id": command["command_id"],
        "status": status,
        "worker_identity": f"scheduled-{command['profile_id']}",
        "runtime_fingerprint": command["runtime_fingerprint"],
        "verified_image_sha256": image_sha256,
        "elapsed_ms": 1,
        "text_lines": [],
        "fields": fields,
        "role_observation": None,
        "error": error,
    }


for raw_line in sys.stdin:
    command = json.loads(raw_line)
    operation = command["operation"]
    profile_id = str(command["profile_id"])
    relative_path = str(command.get("relative_path") or "")

    if profile_id == "test-crash-once" and operation == "extract":
        marker = Path("crash-once.marker")
        if not marker.exists():
            marker.write_text("crashed", encoding="utf-8")
            raise SystemExit(41)

    if profile_id.endswith("-slow"):
        time.sleep(0.15)

    if (
        operation == "extract"
        and profile_id.startswith("gpu-fail-second")
        and relative_path.endswith("unloading.png")
    ):
        payload = _result(
            command,
            status="error",
            error={
                "kind": "out_of_memory",
                "message": "Synthetic GPU memory failure.",
                "diagnostic_code": "LOOP6-FAKE-GPU-OOM",
            },
        )
    elif operation == "extract" and profile_id.startswith("cpu-fail"):
        payload = _result(
            command,
            status="error",
            error={
                "kind": "worker_crashed",
                "message": "Synthetic CPU worker failure.",
                "diagnostic_code": "LOOP6-FAKE-CPU-FAILURE",
            },
        )
    else:
        payload = _result(command)

    print(json.dumps(payload, separators=(",", ":")), flush=True)
    if operation == "shutdown":
        break
