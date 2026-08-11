from __future__ import annotations

import http.client
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from threading import Event

from fastapi.testclient import TestClient

from dahe import __version__
from dahe.api.app import create_app

PROJECT_ROOT = Path(__file__).parents[2]
ORIGIN = "http://127.0.0.1:8877"


def _headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }


def test_shutdown_is_local_versioned_idempotent_and_deferred(tmp_path: Path) -> None:
    app = create_app(
        data_root=tmp_path / "shutdown",
        project_root=PROJECT_ROOT,
        instance_id="shutdown-api-test",
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    requested = Event()
    calls: list[str] = []

    def request_shutdown() -> None:
        calls.append("requested")
        requested.set()

    app.state.request_shutdown = request_shutdown
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        csrf = str(session.json()["csrf_token"])
        headers = {
            **_headers(),
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "shutdown-once",
        }

        first = client.post("/api/v1/system/shutdown", headers=headers)
        assert first.status_code == 202
        assert first.json() == {"accepted": True, "idempotent_replay": False}
        assert requested.wait(timeout=1.0)

        replay = client.post("/api/v1/system/shutdown", headers=headers)
        assert replay.status_code == 202
        assert replay.json() == {"accepted": True, "idempotent_replay": True}
        time.sleep(0.2)
        assert calls == ["requested"]


def test_shutdown_rejects_when_server_callback_is_unavailable(tmp_path: Path) -> None:
    app = create_app(
        data_root=tmp_path / "shutdown-unavailable",
        project_root=PROJECT_ROOT,
        instance_id="shutdown-api-unavailable-test",
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_headers())
        response = client.post(
            "/api/v1/system/shutdown",
            headers={
                **_headers(),
                "X-CSRF-Token": str(session.json()["csrf_token"]),
                "Idempotency-Key": "shutdown-unavailable",
            },
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "application_shutdown_unavailable"


def test_shutdown_stops_the_owned_temporary_server(tmp_path: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])

    data_root = (tmp_path / "owned-shutdown-server").resolve()
    command = [
        sys.executable,
        "-m",
        "dahe",
        "--serve",
        "--data-root",
        str(data_root),
        "--port",
        str(port),
        "--enable-test-fixtures",
        "--no-browser",
    ]
    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    origin = f"http://127.0.0.1:{port}"
    base_headers = {
        "Host": f"127.0.0.1:{port}",
        "Origin": origin,
        "X-DaHe-Client-Version": __version__,
    }
    try:
        deadline = time.monotonic() + 20
        csrf_token: str | None = None
        session_cookie: str | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.communicate(timeout=1)[0]
                raise AssertionError(
                    f"temporary server exited before readiness: {output}"
                )
            try:
                connection = http.client.HTTPConnection(
                    "127.0.0.1",
                    port,
                    timeout=1,
                )
                connection.request("GET", "/api/v1/session", headers=base_headers)
                response = connection.getresponse()
                body = response.read()
                response_cookie = response.getheader("Set-Cookie")
                connection.close()
                if response.status == 200:
                    csrf_token = str(json.loads(body)["csrf_token"])
                    if response_cookie is not None:
                        session_cookie = response_cookie.split(";", 1)[0]
                    break
            except OSError:
                time.sleep(0.1)
        assert csrf_token is not None, "temporary server did not become ready"
        assert session_cookie is not None, "temporary server did not issue a session"

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request(
            "POST",
            "/api/v1/system/shutdown",
            headers={
                **base_headers,
                "X-CSRF-Token": csrf_token,
                "Idempotency-Key": "owned-server-shutdown",
                "Cookie": session_cookie,
                "Content-Length": "0",
            },
        )
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        assert response.status == 202
        assert body["accepted"] is True
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
