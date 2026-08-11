from __future__ import annotations

import ast
import tomllib
from pathlib import Path

FORBIDDEN_PHASE_TWO_IMPORTS = {
    "httpx",
    "httpx2",
    "paddle",
    "paddleocr",
    "playwright",
    "requests",
    "selenium",
}

FORBIDDEN_DOMAIN_IMPORTS = {
    "fastapi",
    "pydantic",
    "sqlalchemy",
    "sqlite3",
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".", 1)[0])
    return found


def test_phase_two_source_has_no_real_platform_or_ocr_runtime_dependencies(
    project_root: Path,
) -> None:
    imported: set[str] = set()
    for path in (project_root / "src").rglob("*.py"):
        imported.update(_imports(path))
    assert imported.isdisjoint(FORBIDDEN_PHASE_TWO_IMPORTS)

    pyproject = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = " ".join(pyproject["project"]["dependencies"]).lower()
    assert all(name not in dependencies for name in FORBIDDEN_PHASE_TWO_IMPORTS)


def test_domain_layer_stays_independent_of_framework_and_persistence(
    project_root: Path,
) -> None:
    imported: set[str] = set()
    for path in (project_root / "src" / "dahe" / "domain").rglob("*.py"):
        imported.update(_imports(path))
    assert imported.isdisjoint(FORBIDDEN_DOMAIN_IMPORTS)


def test_source_contains_no_developer_absolute_path(project_root: Path) -> None:
    source_text = "\n".join(
        path.read_text(encoding="utf-8") for path in (project_root / "src").rglob("*.py")
    )
    assert "C:\\Users\\" not in source_text
    assert "C:/Users/" not in source_text


def test_agents_remains_a_short_execution_rule_file(project_root: Path) -> None:
    agents = (project_root / "AGENTS.md").read_text(encoding="utf-8")
    assert 80 <= len(agents.splitlines()) <= 120
    assert "## Safety Boundaries" in agents
    assert "## Verification" in agents
    assert "JobStatus" not in agents
    assert "BusinessOutcome" not in agents
