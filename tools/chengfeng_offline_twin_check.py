from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
TWIN_TOTAL = 137
TWIN_PRIVATE_SENTINEL = "must-stay-inside-offline-twin"
TWIN_TRANSITIONS = (
    "settle-ready",
    "settlement-tab",
    "waybill-tab",
    "reset",
    "waybill-tab-confirmed",
)


def _default_runtime_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise SystemExit("LOCALAPPDATA is unavailable")
    return (
        Path(local_app_data)
        / "DaHeLogistics"
        / "development-tools"
        / "playwright-twin"
        / "1.61.0"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline Chengfeng query twin in isolated Playwright."
    )
    parser.add_argument(
        "--runtime-root",
        type=Path,
        default=_default_runtime_root(),
    )
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    return parser


def _shape(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _shape(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, list):
        return [] if not value else [_shape(value[0])]
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _validate_result(value: object) -> dict[str, object]:
    expected = {
        "schema_version",
        "kind",
        "browser",
        "service_workers",
        "iframe_loaded",
        "hidden_field_preserved",
        "blocked_transition_total",
        "transition_read_count",
        "dynamic_total",
        "query_trace",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("offline twin result fields are invalid")
    trace = value.get("query_trace")
    if (
        value.get("schema_version") != 2
        or value.get("kind") != "chengfeng_offline_query_twin"
        or value.get("browser") not in {"chromium", "msedge"}
        or value.get("service_workers") != "blocked"
        or value.get("iframe_loaded") is not True
        or value.get("hidden_field_preserved") is not True
        or value.get("blocked_transition_total") != 0
        or value.get("transition_read_count") != len(TWIN_TRANSITIONS)
        or value.get("dynamic_total") != TWIN_TOTAL
        or not isinstance(trace, dict)
        or set(trace)
        != {
            "query_attempt_id",
            "observed_request_count",
            "approved_request_count",
            "blocked_request_count",
            "request_method",
            "request_path",
            "resource_type",
            "response_status",
            "response_byte_size",
            "response_structure_sha256",
            "duration_ms",
        }
        or not isinstance(trace.get("query_attempt_id"), str)
        or len(trace["query_attempt_id"]) != 32
        or trace.get("observed_request_count") != 3
        or trace.get("approved_request_count") != 1
        or trace.get("blocked_request_count") != 2
        or trace.get("request_method") != "POST"
        or trace.get("request_path") != "/api/list"
        or trace.get("resource_type") != "fetch"
        or trace.get("response_status") != 200
        or type(trace.get("response_byte_size")) is not int
        or not 1 <= trace["response_byte_size"] <= 2 * 1024 * 1024
        or not isinstance(trace.get("response_structure_sha256"), str)
        or len(trace["response_structure_sha256"]) != 64
        or type(trace.get("duration_ms")) is not int
        or not 0 <= trace["duration_ms"] <= 10_000
    ):
        raise ValueError("offline twin result values are invalid")
    serialized = json.dumps(value, sort_keys=True)
    if TWIN_PRIVATE_SENTINEL in serialized or "pageNumber" in serialized:
        raise ValueError("offline twin leaked private request values")
    return value


class _TwinServer(ThreadingHTTPServer):
    transition_index: int = 0


class _TwinHandler(BaseHTTPRequestHandler):
    server_version = "DaHeOfflineTwin/1"

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _send(self, status: int, media_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/frame":
            self._send(200, "text/html; charset=utf-8", b"<p id='frame-ready'>ready</p>")
            return
        if self.path == "/sw.js":
            self._send(
                200,
                "text/javascript; charset=utf-8",
                b"self.addEventListener('fetch', () => {});",
            )
            return
        if self.path != "/":
            self._send(404, "text/plain", b"not found")
            return
        html = f"""<!doctype html>
  <meta charset="utf-8">
  <iframe id="child" src="/frame"></iframe>
  <button id="settle-ready">settle-ready</button>
  <button id="settlement-tab">settlement-tab</button>
  <button id="waybill-tab">waybill-tab</button>
  <button id="reset">reset</button>
  <button id="waybill-tab-confirmed">waybill-tab-confirmed</button>
  <button id="query">query</button>
  <script>
navigator.serviceWorker.register('/sw.js').catch(() => {{}});
const body = {{
  order: 'desc', queryType: '2', settleQueryType: 1,
  pageNumber: 1, pageSize: 30,
  futureHiddenAccountScope: '{TWIN_PRIVATE_SENTINEL}',
  futureEmptyFilter: '', futureArrayFilter: []
}};
document.querySelector('#query').addEventListener('click', () => {{
  const options = {{method: 'POST', headers: {{'content-type': 'application/json'}},
                   body: JSON.stringify(body)}};
  void fetch('/api/noise', options).catch(() => {{}});
  void fetch('/api/list?stage=final', options).catch(() => {{}});
  void fetch('/api/list?stage=final&duplicate=1', options).catch(() => {{}});
}});
for (const stage of {json.dumps(TWIN_TRANSITIONS)}) {{
  document.querySelector(`#${{stage}}`).addEventListener('click', () => {{
    const options = {{method: 'POST', headers: {{'content-type': 'application/json'}},
                     body: JSON.stringify(body)}};
    void fetch(`/api/list?stage=${{stage}}`, options).catch(() => {{}});
  }});
}}
</script>""".encode()
        self._send(200, "text/html; charset=utf-8", html)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        _ = self.rfile.read(length)
        parsed_path = urlsplit(self.path)
        if parsed_path.path != "/api/list":
            self._send(404, "application/json", b"{}")
            return
        query = parse_qs(parsed_path.query)
        stage = query.get("stage", [""])[0]
        if not isinstance(self.server, _TwinServer):
            raise RuntimeError("offline twin server type changed")
        transition_index = self.server.transition_index
        if (
            transition_index < len(TWIN_TRANSITIONS)
            and stage == TWIN_TRANSITIONS[transition_index]
        ):
            self.server.transition_index = transition_index + 1
            transition_index += 1
        ready = stage == "final" and transition_index == len(TWIN_TRANSITIONS)
        time.sleep(0.15)
        body = json.dumps(
            {
                "data": {
                    "list": (
                        [{"id": "private", "orderItemSn": "private"}]
                        if ready
                        else []
                    ),
                    "pageNo": 1,
                    "pageSize": 30,
                    "total": TWIN_TOTAL if ready else 0,
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self._send(200, "application/json", body)


def _child_check() -> dict[str, object]:
    sync_playwright = importlib.import_module("playwright.sync_api").sync_playwright

    server = _TwinServer(("127.0.0.1", 0), _TwinHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="msedge", headless=True)
            try:
                context = browser.new_context(service_workers="block")
                page = context.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                page.frame_locator("#child").locator("#frame-ready").wait_for()
                baseline_continued = False

                def baseline_route(route: Any) -> None:
                    nonlocal baseline_continued
                    request = route.request
                    parsed = urlsplit(request.url)
                    query = parse_qs(parsed.query)
                    if (
                        not baseline_continued
                        and parsed.path == "/api/list"
                        and query.get("stage") == ["final"]
                        and "duplicate" not in query
                        and request.method == "POST"
                    ):
                        baseline_continued = True
                        route.continue_()
                        return
                    route.abort("blockedbyclient")

                page.route("**/api/**", baseline_route)
                with page.expect_response(
                    lambda response: (
                        urlsplit(response.url).path == "/api/list"
                        and parse_qs(urlsplit(response.url).query).get("stage")
                        == ["final"]
                    ),
                    timeout=5_000,
                ) as baseline_info:
                    page.locator("#query").click()
                baseline_payload = baseline_info.value.json()
                blocked_transition_total = baseline_payload["data"]["total"]
                page.unroute("**/api/**", baseline_route)

                counts = {"observed": 0, "approved": 0, "blocked": 0}
                approved_body: dict[str, object] | None = None
                final_armed = False
                transition_read_count = 0

                def route_request(route: Any) -> None:
                    nonlocal approved_body
                    nonlocal transition_read_count
                    request = route.request
                    parsed = urlsplit(request.url)
                    path = parsed.path
                    query = parse_qs(parsed.query)
                    stage = query.get("stage", [""])[0]
                    if (
                        not final_armed
                        and path == "/api/list"
                        and stage in TWIN_TRANSITIONS
                        and request.method == "POST"
                        and request.resource_type == "fetch"
                    ):
                        transition_read_count += 1
                        route.continue_()
                        return
                    counts["observed"] += 1
                    if (
                        path == "/api/list"
                        and stage == "final"
                        and "duplicate" not in query
                        and final_armed
                        and counts["approved"] == 0
                        and request.method == "POST"
                        and request.resource_type == "fetch"
                    ):
                        raw = request.post_data_json
                        if isinstance(raw, dict):
                            approved_body = dict(raw)
                        counts["approved"] += 1
                        route.continue_()
                        return
                    counts["blocked"] += 1
                    route.abort("blockedbyclient")

                page.route("**/api/**", route_request)
                for stage in TWIN_TRANSITIONS:
                    with page.expect_response(
                        lambda response, expected=stage: (
                            urlsplit(response.url).path == "/api/list"
                            and parse_qs(urlsplit(response.url).query).get("stage")
                            == [expected]
                        ),
                        timeout=5_000,
                    ):
                        page.locator(f"#{stage}").click()
                final_armed = True
                started = time.monotonic()
                with page.expect_response(
                    lambda response: (
                        urlsplit(response.url).path == "/api/list"
                        and parse_qs(urlsplit(response.url).query).get("stage")
                        == ["final"]
                    ),
                    timeout=5_000,
                ) as response_info:
                    page.locator("#query").click()
                response = response_info.value
                payload = response.json()
                duration_ms = int((time.monotonic() - started) * 1000)
                if not isinstance(payload, dict):
                    raise RuntimeError("offline twin response is invalid")
                data = payload.get("data")
                if not isinstance(data, dict):
                    raise RuntimeError("offline twin data is invalid")
                raw_response = response.body()
                result = {
                    "schema_version": 2,
                    "kind": "chengfeng_offline_query_twin",
                    "browser": "msedge",
                    "service_workers": "blocked",
                    "iframe_loaded": True,
                    "hidden_field_preserved": bool(
                        approved_body
                        and approved_body.get("futureHiddenAccountScope")
                        == TWIN_PRIVATE_SENTINEL
                    ),
                    "blocked_transition_total": blocked_transition_total,
                    "transition_read_count": transition_read_count,
                    "dynamic_total": data.get("total"),
                    "query_trace": {
                        "query_attempt_id": uuid4().hex,
                        "observed_request_count": counts["observed"],
                        "approved_request_count": counts["approved"],
                        "blocked_request_count": counts["blocked"],
                        "request_method": "POST",
                        "request_path": "/api/list",
                        "resource_type": "fetch",
                        "response_status": response.status,
                        "response_byte_size": len(raw_response),
                        "response_structure_sha256": _canonical_sha256(_shape(payload)),
                        "duration_ms": duration_ms,
                    },
                }
                return _validate_result(result)
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def main() -> int:
    args = _parser().parse_args()
    if args.child:
        print(
            json.dumps(
                _child_check(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("Use the project .venv to run the offline twin check")
    runtime_root = args.runtime_root.resolve()
    portable = runtime_root / "python" / "python.exe"
    python = (
        portable
        if portable.is_file()
        else runtime_root / "python" / "Scripts" / "python.exe"
    )
    manifest = runtime_root / "runtime-installation.json"
    if not python.is_file() or not manifest.is_file():
        raise SystemExit(
            "Build the isolated twin runtime with tools/bootstrap_browser.py first"
        )
    with tempfile.TemporaryDirectory(prefix="dahe-offline-twin-") as temp:
        completed = subprocess.run(
            [
                os.fspath(python),
                "-I",
                "-B",
                os.fspath(Path(__file__).resolve()),
                "--child",
                "--runtime-root",
                os.fspath(runtime_root),
            ],
            cwd=temp,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
    if completed.returncode != 0:
        raise SystemExit("isolated offline twin check failed")
    try:
        result = _validate_result(json.loads(completed.stdout))
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("isolated offline twin returned unsafe output") from exc
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
