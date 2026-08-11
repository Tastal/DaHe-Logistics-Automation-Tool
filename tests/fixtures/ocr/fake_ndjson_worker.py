from __future__ import annotations

import json
import sys
import time

for raw_line in sys.stdin:
    command = json.loads(raw_line)
    profile_id = command.get("profile_id")
    if profile_id == "test-crash":
        raise SystemExit(41)
    if profile_id == "test-hang":
        time.sleep(60)
        continue
    if profile_id == "test-malformed":
        print("{not-json", flush=True)
        continue
    if profile_id == "test-invalid-utf8":
        sys.stdout.buffer.write(b"\xff\n")
        sys.stdout.buffer.flush()
        continue
    operation = command.get("operation")
    if operation == "shutdown":
        print(
            json.dumps(
                {
                    "protocol_version": 1,
                    "command_id": command["command_id"],
                    "status": "ok",
                    "worker_identity": "fake-worker",
                    "runtime_fingerprint": command["runtime_fingerprint"],
                    "verified_image_sha256": None,
                    "elapsed_ms": 0,
                    "text_lines": [],
                    "fields": {},
                    "role_observation": None,
                    "error": None,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )
        break
    print(
        json.dumps(
            {
                "protocol_version": 1,
                "command_id": command["command_id"],
                "status": "ok",
                "worker_identity": "fake-worker",
                "runtime_fingerprint": command["runtime_fingerprint"],
                "verified_image_sha256": command.get("image_sha256"),
                "elapsed_ms": 1,
                "text_lines": [],
                "fields": {},
                "role_observation": None,
                "error": None,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
