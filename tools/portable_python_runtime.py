from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote


class PortableRuntimeError(RuntimeError):
    """Raised when a formal Python runtime is not self-contained."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _unsafe_archive_member(member: zipfile.ZipInfo) -> bool:
    logical = PurePosixPath(member.filename)
    unix_mode = member.external_attr >> 16
    return (
        logical.is_absolute()
        or not logical.parts
        or any(part in {"", ".", ".."} for part in logical.parts)
        or bool(unix_mode & 0o170000 == 0o120000)
    )


def _extract_embed_archive(archive: Path, target: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if not members or any(_unsafe_archive_member(member) for member in members):
            raise PortableRuntimeError("CPython embed archive contains an unsafe path")
        for member in members:
            destination = target.joinpath(*PurePosixPath(member.filename).parts)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, destination.open("xb") as output:
                shutil.copyfileobj(source, output)


def _copy_site_packages(source: Path, target: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise PortableRuntimeError("source site-packages is unavailable")
    target.mkdir(parents=True)
    pending = [(source, target)]
    while pending:
        source_dir, target_dir = pending.pop()
        for entry in os.scandir(source_dir):
            source_path = Path(entry.path)
            name = entry.name
            lower_name = name.casefold()
            if entry.is_symlink():
                raise PortableRuntimeError("source site-packages contains a link")
            if entry.is_dir(follow_symlinks=False):
                if lower_name == "__pycache__":
                    continue
                child = target_dir / name
                child.mkdir()
                pending.append((source_path, child))
                continue
            if not entry.is_file(follow_symlinks=False):
                raise PortableRuntimeError("source site-packages contains a special file")
            if (
                lower_name == "direct_url.json"
                or lower_name.endswith((".pyc", ".pyo", ".egg-link"))
            ):
                continue
            shutil.copy2(source_path, target_dir / name)


def _developer_needles(developer_roots: tuple[Path, ...]) -> tuple[bytes, ...]:
    values: set[bytes] = {
        b"file:///c:/users/",
    }
    for root in developer_roots:
        raw = os.fspath(root).replace("/", "\\").rstrip("\\").casefold()
        forward = raw.replace("\\", "/")
        values.update(
            {
                raw.encode("utf-8"),
                forward.encode("utf-8"),
                ("file:///" + forward).encode("utf-8"),
                quote("file:///" + forward, safe=":/").casefold().encode("ascii"),
            }
        )
    return tuple(sorted((value for value in values if value), key=len, reverse=True))


def _file_contains(path: Path, needles: tuple[bytes, ...]) -> bool:
    utf16_needles = tuple(needle.decode("utf-8").encode("utf-16le") for needle in needles)
    all_needles = needles + utf16_needles
    overlap = max((len(needle) for needle in all_needles), default=1) - 1
    previous = b""
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            content = (previous + block).lower()
            if any(needle in content for needle in all_needles):
                return True
            previous = content[-overlap:] if overlap else b""
    return False


def scrub_portable_python_bytecode(runtime: Path) -> None:
    resolved = runtime.resolve(strict=True)
    if not resolved.is_dir() or runtime.is_symlink():
        raise PortableRuntimeError("formal runtime root is unsafe")
    for path in sorted(resolved.rglob("*.pyc")):
        if path.is_symlink():
            raise PortableRuntimeError("formal runtime cache path is unsafe")
        path.unlink()
    caches = sorted(
        resolved.rglob("__pycache__"),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for cache in caches:
        if cache.is_symlink():
            raise PortableRuntimeError("formal runtime cache path is unsafe")
        shutil.rmtree(cache)


def validate_release_tree_no_developer_provenance(
    root: Path,
    *,
    developer_roots: tuple[Path, ...],
) -> None:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or root.is_symlink():
        raise PortableRuntimeError("formal release tree is unsafe")
    needles = _developer_needles(developer_roots)
    for path in sorted(resolved.rglob("*")):
        if path.is_symlink():
            raise PortableRuntimeError("formal release tree contains a link")
        if path.name.casefold() == "__pycache__" and path.is_dir():
            raise PortableRuntimeError("formal release tree contains bytecode cache")
        if not path.is_file():
            continue
        if path.suffix.casefold() in {".pyc", ".pyo"}:
            raise PortableRuntimeError("formal release tree contains bytecode")
        if path.name.casefold() in {"direct_url.json", "pyvenv.cfg"}:
            raise PortableRuntimeError("formal release tree contains venv provenance")
        if _file_contains(path, needles):
            raise PortableRuntimeError("formal release tree contains developer provenance")


def validate_portable_python_runtime(
    runtime: Path,
    *,
    developer_roots: tuple[Path, ...] = (),
    run_smoke: bool = True,
    required_import: str | None = None,
    expected_python_version: str = "3.12.10",
) -> None:
    resolved = runtime.resolve(strict=True)
    python = resolved / "python.exe"
    pth = resolved / "python312._pth"
    if (
        not resolved.is_dir()
        or runtime.is_symlink()
        or not python.is_file()
        or python.is_symlink()
        or not pth.is_file()
        or (resolved / "Scripts").exists()
        or tuple(resolved.rglob("pyvenv.cfg"))
        or tuple(resolved.rglob("direct_url.json"))
        or tuple(resolved.rglob("*.pyc"))
        or tuple(resolved.rglob("__pycache__"))
    ):
        raise PortableRuntimeError("formal runtime contains a venv or cache artifact")
    if pth.read_text(encoding="utf-8") != (
        "python312.zip\n.\nLib\\site-packages\nimport site\n"
    ):
        raise PortableRuntimeError("formal runtime import path is invalid")
    needles = _developer_needles(developer_roots)
    for path in sorted(candidate for candidate in resolved.rglob("*") if candidate.is_file()):
        if _file_contains(path, needles):
            raise PortableRuntimeError("formal runtime contains developer provenance")
    if not run_smoke:
        return
    smoke = "import platform"
    if required_import:
        smoke += f";import {required_import}"
    smoke += ";print(platform.python_version())"
    try:
        completed = subprocess.run(
            (os.fspath(python), "-I", "-B", "-c", smoke),
            cwd=resolved,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PortableRuntimeError("formal runtime Python smoke failed") from exc
    if completed.stdout.strip() != expected_python_version:
        raise PortableRuntimeError("formal runtime Python version is invalid")


def stage_portable_python_runtime(
    *,
    source_runtime: Path,
    target_runtime: Path,
    embed_archive: Path,
    embed_archive_sha256: str | None,
    python_version: str,
    worker_source: Path,
    worker_package: str,
    developer_roots: tuple[Path, ...] = (),
    run_smoke: bool = False,
) -> dict[str, object]:
    if target_runtime.exists():
        raise PortableRuntimeError("portable runtime target already exists")
    source = source_runtime.resolve(strict=True)
    archive = embed_archive.resolve(strict=True)
    worker = worker_source.resolve(strict=True)
    if embed_archive_sha256 is not None and _sha256(archive) != embed_archive_sha256:
        raise PortableRuntimeError("CPython embed archive SHA-256 does not match its pin")
    if not worker.is_dir() or worker.is_symlink():
        raise PortableRuntimeError("approved worker source is unavailable")
    target_runtime.mkdir(parents=True)
    try:
        _extract_embed_archive(archive, target_runtime)
        site_packages = target_runtime / "Lib" / "site-packages"
        _copy_site_packages(source / "Lib" / "site-packages", site_packages)
        installed_worker = site_packages / worker_package
        if installed_worker.exists():
            shutil.rmtree(installed_worker)
        shutil.copytree(worker, installed_worker)
        for cache in installed_worker.rglob("__pycache__"):
            shutil.rmtree(cache)
        for cache in installed_worker.rglob("*.pyc"):
            cache.unlink()
        (target_runtime / "python312._pth").write_text(
            "python312.zip\n.\nLib\\site-packages\nimport site\n",
            encoding="utf-8",
            newline="\n",
        )
        validate_portable_python_runtime(
            target_runtime,
            developer_roots=developer_roots,
            run_smoke=run_smoke,
            required_import=worker_package,
            expected_python_version=python_version,
        )
    except Exception:
        shutil.rmtree(target_runtime, ignore_errors=True)
        raise
    return {
        "layout": "portable_embed",
        "python_version": python_version,
        "python_embed_archive": archive.name,
        "python_embed_archive_sha256": _sha256(archive),
        "interpreter": "python.exe",
        "content_sha256": _tree_sha256(target_runtime),
    }
