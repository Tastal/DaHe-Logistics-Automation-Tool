from __future__ import annotations

from pathlib import Path

import pytest

from tools import build_windows_installer
from tools.windows_release import load_windows_release_manifest


def test_windows_release_manifest_pins_free_nsis_312() -> None:
    manifest = load_windows_release_manifest()

    assert manifest.nsis.version == "3.12"
    assert manifest.nsis.asset_sha256 == (
        "56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f"
    )
    assert manifest.nsis.license == "zlib/libpng"


def test_windows_release_manifest_pins_official_cpython_embed() -> None:
    manifest = load_windows_release_manifest()

    assert manifest.python_embed.version == "3.12.10"
    assert manifest.python_embed.asset == "python-3.12.10-embed-amd64.zip"
    assert manifest.python_embed.asset_sha256 == (
        "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
    )
    assert manifest.python_embed.url == (
        "https://www.python.org/ftp/python/3.12.10/"
        "python-3.12.10-embed-amd64.zip"
    )
    assert manifest.python_embed.license == "PSF-2.0"


def test_installer_command_uses_only_explicit_payload_and_per_user_script(
    tmp_path: Path,
) -> None:
    compiler = tmp_path / "makensis.exe"
    compiler.write_bytes(b"compiler")
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "DaHeLauncher.exe").write_bytes(b"launcher")
    output = tmp_path / "output"
    output.mkdir()

    command = build_windows_installer.installer_command(
        makensis=compiler,
        payload_root=payload,
        output_root=output,
        app_version="1.0.0",
    )

    assert command[0] == str(compiler)
    assert command[1:3] == ["/INPUTCHARSET", "UTF8"]
    assert "/DAPP_VERSION=1.0.0" in command
    assert str(build_windows_installer.NSI_PATH) == command[-1]


def test_installer_rejects_symlinks_when_supported(tmp_path: Path) -> None:
    compiler = tmp_path / "makensis.exe"
    compiler.write_bytes(b"compiler")
    payload = tmp_path / "payload"
    payload.mkdir()
    target = payload / "target"
    target.write_bytes(b"target")
    link = payload / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this Windows account cannot create symbolic links")
    output = tmp_path / "output"
    output.mkdir()

    with pytest.raises(ValueError, match="symbolic"):
        build_windows_installer.installer_command(
            makensis=compiler,
            payload_root=payload,
            output_root=output,
            app_version="1.0.0",
        )


def test_nsis_script_is_per_user_and_preserves_user_data() -> None:
    script = build_windows_installer.NSI_PATH.read_text(encoding="utf-8")

    assert "RequestExecutionLevel user" in script
    assert "$LOCALAPPDATA\\Programs\\DaHeLogisticsAutomationTool" in script
    assert "CreateShortcut" in script
    assert script.count("bootstrap-cpu-runtime") == 2
    assert "Sleep 2000" in script
    assert "remove-cpu-runtime" in script
    assert "/TIMEOUT=900000" in script
    assert 'Delete "$INSTDIR\\runtimes\\ocr-cpu.zip"' in script
    assert "大禾物流自动化平台.lnk" in script
    assert "大禾物流.lnk" in script
    assert "DaHeLogisticsAutomationTool is intentionally retained" in script
    assert "restic" not in script.casefold()
    assert "inno" not in script.casefold()
