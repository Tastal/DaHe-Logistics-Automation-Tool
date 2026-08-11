from __future__ import annotations

from pathlib import Path

import pytest

from dahe.cli import _application_root, run
from dahe.config.schema import ModuleMode, RuntimeProfile


def test_cli_builds_the_fixed_production_read_only_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        "dahe.server.run_local_console",
        lambda **kwargs: captured.append(dict(kwargs)),
    )
    data_root = (tmp_path / "production").resolve()

    result = run(
        [
            "--serve",
            "--production-read-only",
            "--data-root",
            str(data_root),
            "--no-browser",
        ]
    )

    assert result == 0
    config = captured[0]["config"]
    assert config.runtime_profile is RuntimeProfile.PRODUCTION  # type: ignore[union-attr]
    assert config.module_modes.audit is ModuleMode.OPERATIONAL  # type: ignore[union-attr]
    assert config.module_modes.daily is ModuleMode.OPERATIONAL  # type: ignore[union-attr]
    assert captured[0]["production_read_only"] is True


def test_application_root_resolves_a_self_contained_release(tmp_path: Path) -> None:
    release = tmp_path / "release"
    executable = release / ".venv" / "Scripts" / "python.exe"
    executable.parent.mkdir(parents=True)
    executable.touch()
    (release / "frontend" / "dist").mkdir(parents=True)
    (release / "frontend" / "dist" / "index.html").write_text("ok", encoding="utf-8")
    (release / "src" / "dahe").mkdir(parents=True)
    (release / "version-manifest.json").write_text("{}", encoding="utf-8")

    assert _application_root(executable) == release


@pytest.mark.parametrize(
    "arguments",
    [
        ["--serve", "--production-read-only"],
        [
            "--serve",
            "--production-read-only",
            "--data-root",
            "relative-production",
        ],
        [
            "--serve",
            "--production-read-only",
            "--data-root",
            "C:/production",
            "--port",
            "8899",
        ],
        [
            "--serve",
            "--production-read-only",
            "--data-root",
            "C:/production",
            "--enable-chengfeng-shadow",
        ],
    ],
)
def test_cli_rejects_unsafe_production_combinations(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        run(arguments)
    assert raised.value.code == 2
