from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "dev-tools" / "windows-release-tools.json"
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


@dataclass(frozen=True)
class NsisPin:
    version: str
    asset: str
    asset_sha256: str
    url: str
    source: str
    license_source: str
    license: str


@dataclass(frozen=True)
class PythonEmbedPin:
    version: str
    asset: str
    asset_sha256: str
    url: str
    source: str
    license_source: str
    license: str


@dataclass(frozen=True)
class WindowsReleaseManifest:
    nsis: NsisPin
    python_embed: PythonEmbedPin


def require_project_venv() -> None:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise RuntimeError("Windows release tools must run from the project .venv")


def _https(value: object, *, hosts: set[str], label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in hosts
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"{label} URL is invalid")
    return value


def load_windows_release_manifest(
    path: Path = MANIFEST_PATH,
) -> WindowsReleaseManifest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "nsis",
        "python_embed",
    }:
        raise ValueError("Windows release manifest fields are invalid")
    if payload["schema_version"] != 3:
        raise ValueError("Windows release manifest schema is unsupported")
    nsis = payload["nsis"]
    fields = {
        "asset",
        "asset_sha256",
        "license",
        "license_source",
        "source",
        "url",
        "version",
    }
    if not isinstance(nsis, dict) or set(nsis) != fields:
        raise ValueError("NSIS pin fields are invalid")
    if (
        nsis["version"] != "3.12"
        or nsis["asset"] != "nsis-3.12.zip"
        or nsis["asset_sha256"]
        != "56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f"
        or nsis["license"] != "zlib/libpng"
    ):
        raise ValueError("NSIS pin is invalid")
    python_embed = payload["python_embed"]
    if not isinstance(python_embed, dict) or set(python_embed) != fields:
        raise ValueError("CPython embed pin fields are invalid")
    if (
        python_embed["version"] != "3.12.10"
        or python_embed["asset"] != "python-3.12.10-embed-amd64.zip"
        or python_embed["asset_sha256"]
        != "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
        or python_embed["license"] != "PSF-2.0"
    ):
        raise ValueError("CPython embed pin is invalid")
    return WindowsReleaseManifest(
        nsis=NsisPin(
            version="3.12",
            asset="nsis-3.12.zip",
            asset_sha256=str(nsis["asset_sha256"]),
            url=_https(
                nsis["url"],
                hosts={"netix.dl.sourceforge.net"},
                label="NSIS asset",
            ),
            source=_https(
                nsis["source"],
                hosts={"nsis.sourceforge.io"},
                label="NSIS source",
            ),
            license_source=_https(
                nsis["license_source"],
                hosts={"nsis.sourceforge.io"},
                label="NSIS license",
            ),
            license="zlib/libpng",
        ),
        python_embed=PythonEmbedPin(
            version="3.12.10",
            asset="python-3.12.10-embed-amd64.zip",
            asset_sha256=str(python_embed["asset_sha256"]),
            url=_https(
                python_embed["url"],
                hosts={"www.python.org"},
                label="CPython embed asset",
            ),
            source=_https(
                python_embed["source"],
                hosts={"www.python.org"},
                label="CPython embed source",
            ),
            license_source=_https(
                python_embed["license_source"],
                hosts={"docs.python.org"},
                label="CPython license",
            ),
            license="PSF-2.0",
        ),
    )


def windows_release_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is unavailable")
    return (
        Path(local_app_data)
        / "DaHeLogistics"
        / "development-tools"
        / "windows-release"
    )


def nsis_archive_path(manifest: WindowsReleaseManifest | None = None) -> Path:
    selected = manifest or load_windows_release_manifest()
    return (
        windows_release_root()
        / "nsis"
        / selected.nsis.version
        / selected.nsis.asset
    )


def nsis_install_root(manifest: WindowsReleaseManifest | None = None) -> Path:
    selected = manifest or load_windows_release_manifest()
    return windows_release_root() / "nsis" / selected.nsis.version / "installed"


def makensis_path(manifest: WindowsReleaseManifest | None = None) -> Path:
    return nsis_install_root(manifest) / "makensis.exe"


def python_embed_archive_path(
    manifest: WindowsReleaseManifest | None = None,
) -> Path:
    selected = manifest or load_windows_release_manifest()
    return (
        windows_release_root()
        / "python-embed"
        / selected.python_embed.version
        / selected.python_embed.asset
    )
