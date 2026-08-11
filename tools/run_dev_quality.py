from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import socket
import subprocess
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from dahe import __version__

try:
    from tools.dev_quality import (
        EXPECTED_MAIN_PYTHON,
        MANIFEST_PATH,
        ROOT,
        _quality_root,
        dependency_audit_commands,
        gitleaks_command,
        gitleaks_executable,
        load_manifest,
        py_spy_command,
        require_project_venv,
        schemathesis_command,
        tool_executable,
        tool_python,
    )
except ModuleNotFoundError:  # Direct execution puts tools/ on sys.path.
    from dev_quality import (  # type: ignore[import-not-found,no-redef]
        EXPECTED_MAIN_PYTHON,
        MANIFEST_PATH,
        ROOT,
        _quality_root,
        dependency_audit_commands,
        gitleaks_command,
        gitleaks_executable,
        load_manifest,
        py_spy_command,
        require_project_venv,
        schemathesis_command,
        tool_executable,
        tool_python,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run isolated DaHe development quality checks."
    )
    parser.add_argument(
        "check",
        choices=("all", "secrets", "dependencies", "api", "profile"),
    )
    return parser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _validate_run_root(path: Path, *, quality_root: Path) -> Path:
    resolved = path.resolve()
    root = quality_root.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError("development check output must stay inside the quality root")
    return resolved


def _new_run_root() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = _quality_root() / "runs" / f"{stamp}-{uuid4().hex[:12]}"
    validated = _validate_run_root(path, quality_root=_quality_root())
    validated.mkdir(parents=True, exist_ok=False)
    return validated


def _validate_installation(*, installation: Path, name: str, version: str) -> None:
    try:
        payload = json.loads(installation.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"{name} is not ready; run tools/bootstrap_dev_quality.py"
        ) from exc
    expected_source = _sha256(MANIFEST_PATH)
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or payload.get("kind") != "isolated_development_quality_tool"
        or payload.get("name") != name
        or payload.get("version") != version
        or payload.get("source_manifest_sha256") != expected_source
    ):
        raise RuntimeError(
            f"{name} is not ready; run tools/bootstrap_dev_quality.py"
        )


def _require_tool(name: str) -> None:
    manifest = load_manifest()
    if name == "gitleaks":
        version = manifest.gitleaks_version
        executable = gitleaks_executable(manifest)
        installation = executable.parent / "runtime-installation.json"
    else:
        version = manifest.python_tools[name]
        executable = (
            tool_executable(name, version)
            if name in {"py-spy", "schemathesis"}
            else tool_python(name, version)
        )
        installation = tool_python(name, version).parents[2] / "runtime-installation.json"
    _validate_installation(
        installation=installation,
        name=name,
        version=version,
    )
    if not executable.is_file():
        raise RuntimeError(
            f"{name} is not ready; run tools/bootstrap_dev_quality.py"
        )


def _summarize_gitleaks(report: Path) -> dict[str, object]:
    raw = report.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise ValueError("gitleaks report is invalid")
    rule_ids = sorted(
        {
            str(item.get("RuleID"))
            for item in payload
            if isinstance(item.get("RuleID"), str)
        }
    )
    return {
        "schema_version": 1,
        "check": "release_secret_scan",
        "finding_count": len(payload),
        "rule_ids": rule_ids,
        "raw_report_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_report_retained": False,
    }


def _run_secrets(run_root: Path) -> bool:
    _require_tool("gitleaks")
    raw_report = run_root / ".gitleaks-raw.json"
    completed = subprocess.run(
        gitleaks_command(temporary_report=raw_report),
        cwd=ROOT,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        if completed.returncode not in {0, 1} or not raw_report.is_file():
            raise RuntimeError("gitleaks execution failed")
        summary = _summarize_gitleaks(raw_report)
    finally:
        raw_report.unlink(missing_ok=True)
    passed = summary["finding_count"] == 0 and completed.returncode == 0
    summary["passed"] = passed
    _atomic_json(run_root / "secret-scan.json", summary)
    return passed


def _write_pypi_audit_fallback(*, source: Path, target: Path) -> list[str]:
    excluded: list[str] = []
    retained: list[str] = []
    for raw_line in source.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--extra-index-url "):
            continue
        if line.startswith("paddlepaddle-gpu=="):
            excluded.append(line)
            continue
        retained.append(line)
    if excluded != ["paddlepaddle-gpu==3.3.1"]:
        raise RuntimeError("GPU dependency audit exclusion is not the approved vendor pin")
    target.write_text("\n".join(retained) + "\n", encoding="utf-8")
    return excluded


def _run_dependencies(run_root: Path) -> bool:
    _require_tool("pip-audit")
    manifest = load_manifest()
    results: list[dict[str, object]] = []
    passed = True
    for lock, command in dependency_audit_commands(
        manifest=manifest,
        output_root=run_root,
    ):
        completed = subprocess.run(
            command,
            cwd=run_root,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output_path = Path(command[command.index("--output") + 1])
        unaudited: list[str] = []
        if (
            completed.returncode == 1
            and not output_path.is_file()
            and lock == (ROOT / "ocr-runtime" / "requirements-gpu.lock").resolve()
        ):
            fallback = run_root / "dependency-audit-4-pypi-only.lock"
            unaudited = _write_pypi_audit_fallback(source=lock, target=fallback)
            fallback_command = [*command]
            fallback_command[-1] = os.fspath(fallback)
            completed = subprocess.run(
                fallback_command,
                cwd=ROOT,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        if completed.returncode not in {0, 1} or not output_path.is_file():
            raise RuntimeError(f"dependency audit failed for {lock.name}")
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
        if not isinstance(dependencies, list):
            raise RuntimeError(f"dependency audit output is invalid for {lock.name}")
        vulnerabilities = {
            (str(item.get("name")), str(vulnerability.get("id")))
            for item in dependencies
            if isinstance(item, dict) and isinstance(item.get("vulns"), list)
            for vulnerability in item["vulns"]
            if isinstance(vulnerability, dict)
            and isinstance(vulnerability.get("id"), str)
        }
        vulnerability_count = len(vulnerabilities)
        lock_passed = (
            completed.returncode == 0
            and vulnerability_count == 0
            and not unaudited
        )
        passed = passed and lock_passed
        results.append(
            {
                "lock": lock.relative_to(ROOT).as_posix(),
                "lock_sha256": _sha256(lock),
                "dependency_count": len(dependencies),
                "vulnerability_count": vulnerability_count,
                "vulnerable_packages": sorted({name for name, _ in vulnerabilities}),
                "unaudited_requirements": unaudited,
                "coverage_complete": not unaudited,
                "passed": lock_passed,
                "report": output_path.name,
                "report_sha256": _sha256(output_path),
            }
        )
    _atomic_json(
        run_root / "dependency-audit.json",
        {
            "schema_version": 1,
            "check": "release_dependency_audit",
            "passed": passed,
            "results": results,
            "automatic_fixes": False,
        },
    )
    return passed


def _find_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _local_api_command(*, port: int, data_root: Path) -> list[str]:
    return [
        os.fspath(EXPECTED_MAIN_PYTHON),
        "-I",
        "-m",
        "dahe",
        "--serve",
        "--no-browser",
        "--enable-test-fixtures",
        "--data-root",
        os.fspath(data_root),
        "--port",
        str(port),
    ]


def _wait_for_meta(*, port: int, process: subprocess.Popen[bytes]) -> None:
    url = f"http://127.0.0.1:{port}/api/v1/meta"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("isolated local API stopped before it was ready")
        request = urllib.request.Request(
            url,
            headers={"X-DaHe-Client-Version": __version__},
        )
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                payload = json.load(response)
            if (
                isinstance(payload, dict)
                and payload.get("application_id") == "DaHeLogistics"
                and payload.get("real_platform_access") is False
                and payload.get("platform_adapter") == "fake"
            ):
                return
            raise RuntimeError("isolated local API returned an unsafe mode")
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("isolated local API did not become ready")


def _obtain_fixture_session(*, port: int) -> str:
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/session",
        headers={
            "X-DaHe-Client-Version": __version__,
            "Sec-Fetch-Site": "none",
        },
    )
    with opener.open(request, timeout=5) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or payload.get("application_version") != __version__:
        raise RuntimeError("isolated local API session response is invalid")
    matching = [
        cookie.value
        for cookie in cookies
        if cookie.name == "dahe_local_session" and isinstance(cookie.value, str)
    ]
    if len(matching) != 1:
        raise RuntimeError("isolated local API session cookie is unavailable")
    return matching[0]


def _stop_known_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _sanitize_api_output(*, stdout: str, stderr: str, session_cookie: str) -> str:
    return (stdout + "\n" + stderr).replace(session_cookie, "[REDACTED]")


def _run_api(run_root: Path) -> bool:
    _require_tool("schemathesis")
    port = _find_loopback_port()
    data_root = run_root / "api-fixture-data"
    data_root.mkdir(parents=True, exist_ok=False)
    process = subprocess.Popen(
        _local_api_command(port=port, data_root=data_root),
        cwd=ROOT,
        shell=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    started = time.monotonic()
    try:
        _wait_for_meta(port=port, process=process)
        session_cookie = _obtain_fixture_session(port=port)
        completed = subprocess.run(
            schemathesis_command(
                schema_url=f"http://127.0.0.1:{port}/api/v1/openapi.json",
                base_url=f"http://127.0.0.1:{port}",
                session_cookie=session_cookie,
            ),
            cwd=run_root,
            env={
                **os.environ,
                "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8",
                "NO_COLOR": "1",
                "TERM": "dumb",
            },
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    finally:
        _stop_known_child(process)
    passed = completed.returncode == 0
    sanitized_output = _sanitize_api_output(
        stdout=completed.stdout,
        stderr=completed.stderr,
        session_cookie=session_cookie,
    )
    output = sanitized_output.encode("utf-8")
    output_path = run_root / "api-contract-output.txt"
    output_path.write_bytes(output)
    _atomic_json(
        run_root / "api-contract.json",
        {
            "schema_version": 1,
            "check": "bounded_local_api_contract",
            "passed": passed,
            "exit_code": completed.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "tested_paths": ["/api/v1/meta", "/api/v1/resources"],
            "real_platform_access": False,
            "output_sha256": hashlib.sha256(output).hexdigest(),
            "output_retained": True,
            "output": output_path.name,
        },
    )
    return passed


def _run_profile(run_root: Path) -> bool:
    _require_tool("py-spy")
    data_root = run_root / "profile-fixture-data"
    output = run_root / "offline-startup-profile.json"
    pid_file = run_root / "profile-child.pid"
    child = subprocess.Popen(
        [
            os.fspath(EXPECTED_MAIN_PYTHON),
            "-I",
            os.fspath((ROOT / "tools" / "profile_offline_check_target.py").resolve()),
            "--check",
            "--data-root",
            os.fspath(data_root),
            "--port",
            str(_find_loopback_port()),
            "--pid-file",
            os.fspath(pid_file),
        ],
        cwd=ROOT,
        shell=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not pid_file.is_file():
        if child.poll() is not None:
            raise RuntimeError("offline profile child stopped before publishing its PID")
        time.sleep(0.05)
    if not pid_file.is_file():
        _stop_known_child(child)
        raise RuntimeError("offline profile child did not publish its PID")
    owned_child_pid = int(pid_file.read_text(encoding="ascii").strip())
    try:
        completed = subprocess.run(
            py_spy_command(
                output_path=output,
                owned_child_pid=owned_child_pid,
            ),
            cwd=ROOT,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    finally:
        _stop_known_child(child)
    passed = completed.returncode == 0 and output.is_file()
    _atomic_json(
        run_root / "profile-check.json",
        {
            "schema_version": 1,
            "check": "new_offline_child_profile",
            "passed": passed,
            "exit_code": completed.returncode,
            "attached_existing_pid": False,
            "real_platform_access": False,
            "profile": output.name if output.is_file() else None,
            "profile_sha256": _sha256(output) if output.is_file() else None,
        },
    )
    return passed


def _run_selected(check: str, run_root: Path) -> dict[str, bool]:
    runners = {
        "secrets": _run_secrets,
        "dependencies": _run_dependencies,
        "api": _run_api,
        "profile": _run_profile,
    }
    selected = tuple(runners) if check == "all" else (check,)
    return {name: runners[name](run_root) for name in selected}


def main() -> int:
    require_project_venv()
    args = _parser().parse_args()
    run_root = _new_run_root()
    results = _run_selected(args.check, run_root)
    passed = all(results.values())
    _atomic_json(
        run_root / "result.json",
        {
            "schema_version": 1,
            "kind": "isolated_development_quality_run",
            "checks": results,
            "passed": passed,
            "git_commit": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=ROOT,
                shell=False,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            ).stdout.strip(),
        },
    )
    print(run_root)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
