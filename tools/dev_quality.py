from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dahe import __version__

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "dev-tools" / "quality-tools.json"
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
RELEASE_LOCKS = (
    ROOT / "requirements.lock",
    ROOT / "browser-runtime" / "requirements.lock",
    ROOT / "ocr-runtime" / "requirements-cpu.lock",
    ROOT / "ocr-runtime" / "requirements-gpu.lock",
)

_EXPECTED_PYTHON_TOOLS = {
    "pip-audit": "2.10.1",
    "py-spy": "0.4.2",
    "schemathesis": "4.24.3",
}
_EXPECTED_GITLEAKS_VERSION = "8.30.1"
_EXPECTED_GITLEAKS_ARCHIVE_SHA256 = (
    "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
)


@dataclass(frozen=True)
class QualityManifest:
    python_tools: dict[str, str]
    python_packages: dict[str, str]
    gitleaks_version: str
    gitleaks_archive: str
    gitleaks_archive_sha256: str
    gitleaks_url: str

    @property
    def runtime_parts(self) -> tuple[str, ...]:
        python_parts = tuple(
            f"development-tools/quality/{name}/{version}"
            for name, version in self.python_tools.items()
        )
        return (
            *python_parts,
            f"development-tools/quality/gitleaks/{self.gitleaks_version}",
        )


def _quality_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is unavailable")
    return Path(local_app_data) / "DaHeLogistics" / "development-tools" / "quality"


def require_project_venv() -> None:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise RuntimeError("development quality tools must run from the project .venv")


def _require_exact_fields(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    return value


def load_manifest(path: Path = MANIFEST_PATH) -> QualityManifest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    root = _require_exact_fields(
        payload,
        {"schema_version", "gitleaks", "python_tools"},
        label="quality manifest",
    )
    if root["schema_version"] != 1:
        raise ValueError("quality manifest schema is unsupported")
    python_payload = root["python_tools"]
    if not isinstance(python_payload, dict) or set(python_payload) != set(
        _EXPECTED_PYTHON_TOOLS
    ):
        raise ValueError("quality Python tool set is invalid")
    versions: dict[str, str] = {}
    packages: dict[str, str] = {}
    for name, expected_version in _EXPECTED_PYTHON_TOOLS.items():
        item = _require_exact_fields(
            python_payload[name],
            {"license", "package", "source", "version"},
            label=f"quality tool {name}",
        )
        version = item["version"]
        package = item["package"]
        source = item["source"]
        if (
            version != expected_version
            or package != name
            or not isinstance(source, str)
            or urlsplit(source).scheme != "https"
            or urlsplit(source).hostname not in {"pypi.org", "www.pypi.org"}
        ):
            raise ValueError(f"quality tool {name} pin is invalid")
        versions[name] = expected_version
        packages[name] = name
    gitleaks = _require_exact_fields(
        root["gitleaks"],
        {"archive", "archive_sha256", "license", "source", "url", "version"},
        label="gitleaks",
    )
    archive = gitleaks["archive"]
    archive_sha256 = gitleaks["archive_sha256"]
    url = gitleaks["url"]
    if (
        gitleaks["version"] != _EXPECTED_GITLEAKS_VERSION
        or archive != "gitleaks_8.30.1_windows_x64.zip"
        or archive_sha256 != _EXPECTED_GITLEAKS_ARCHIVE_SHA256
        or not isinstance(url, str)
        or url
        != "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_windows_x64.zip"
    ):
        raise ValueError("gitleaks pin is invalid")
    return QualityManifest(
        python_tools=versions,
        python_packages=packages,
        gitleaks_version=_EXPECTED_GITLEAKS_VERSION,
        gitleaks_archive=str(archive),
        gitleaks_archive_sha256=str(archive_sha256),
        gitleaks_url=url,
    )


def _tool_root(name: str, version: str) -> Path:
    return (_quality_root() / name / version).resolve()


def tool_python(name: str, version: str) -> Path:
    return _tool_root(name, version) / "python" / "Scripts" / "python.exe"


def tool_executable(name: str, version: str) -> Path:
    return _tool_root(name, version) / "python" / "Scripts" / f"{name}.exe"


def gitleaks_executable(manifest: QualityManifest | None = None) -> Path:
    selected = manifest or load_manifest()
    return _tool_root("gitleaks", selected.gitleaks_version) / "gitleaks.exe"


def _require_absolute(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    return path.resolve()


def dependency_audit_commands(
    *,
    manifest: QualityManifest,
    output_root: Path,
) -> list[tuple[Path, list[str]]]:
    output = _require_absolute(output_root, label="audit output root")
    python = tool_python("pip-audit", manifest.python_tools["pip-audit"])
    commands: list[tuple[Path, list[str]]] = []
    for index, lock in enumerate(RELEASE_LOCKS, start=1):
        report = output / f"dependency-audit-{index}.json"
        command = [
            os.fspath(python),
            "-I",
            "-m",
            "pip_audit",
            "--strict",
            "--no-deps",
            "--disable-pip",
            "--progress-spinner=off",
            "--format=json",
            "--output",
            os.fspath(report),
            "--requirement",
            os.fspath(lock.resolve()),
        ]
        commands.append((lock.resolve(), command))
    return commands


def _validate_loopback_url(url: str, *, expected_path: str | None = None) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (expected_path is not None and parsed.path != expected_path)
    ):
        raise ValueError("development API target must be an exact loopback URL")


def schemathesis_command(
    *,
    schema_url: str,
    base_url: str,
    session_cookie: str,
) -> list[str]:
    _validate_loopback_url(schema_url, expected_path="/api/v1/openapi.json")
    _validate_loopback_url(base_url, expected_path="")
    schema = urlsplit(schema_url)
    base = urlsplit(base_url)
    if (schema.hostname, schema.port) != (base.hostname, base.port):
        raise ValueError("schema and API base must use the same loopback origin")
    if (
        not isinstance(session_cookie, str)
        or not 32 <= len(session_cookie) <= 200
        or any(character in session_cookie for character in "\r\n; ")
    ):
        raise ValueError("local fixture session cookie is invalid")
    manifest = load_manifest()
    executable = tool_executable(
        "schemathesis",
        manifest.python_tools["schemathesis"],
    )
    return [
        os.fspath(executable),
        "run",
        schema_url,
        "--url",
        base_url,
        "--workers",
        "1",
        "--phases",
        "fuzzing",
        "--max-examples",
        "5",
        "--seed",
        "20260731",
        "--output-sanitize",
        "true",
        "--header",
        f"X-DaHe-Client-Version:{__version__}",
        "--header",
        f"Cookie:dahe_local_session={session_cookie}",
        "--checks",
        "not_a_server_error,status_code_conformance,content_type_conformance,"
        "response_schema_conformance",
        "--include-path-regex",
        r"^/api/v1/(meta|resources)$",
    ]


def py_spy_command(*, output_path: Path, owned_child_pid: int) -> list[str]:
    output = _require_absolute(output_path, label="profile output")
    if not 1 <= owned_child_pid <= 2_147_483_647:
        raise ValueError("owned profile child PID is invalid")
    manifest = load_manifest()
    executable = tool_executable("py-spy", manifest.python_tools["py-spy"])
    return [
        os.fspath(executable),
        "record",
        "--format",
        "speedscope",
        "--output",
        os.fspath(output),
        "--pid",
        str(owned_child_pid),
    ]


def gitleaks_command(*, temporary_report: Path) -> list[str]:
    report = _require_absolute(temporary_report, label="temporary gitleaks report")
    manifest = load_manifest()
    return [
        os.fspath(gitleaks_executable(manifest)),
        "git",
        "--no-banner",
        "--redact=100",
        "--report-format=json",
        "--report-path",
        os.fspath(report),
        os.fspath(ROOT),
    ]
