from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_GPU_UUID = re.compile(
    r"GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
DOUBLED_USER_PATH = re.compile(
    r"C:\\\\Users\\\\[^\\\"<]+",
    re.IGNORECASE,
)
PYTEST_USER_DIRECTORY = re.compile(
    r"pytest-of-[A-Za-z0-9._-]+",
    re.IGNORECASE,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_json() -> None:
    for path in sorted(ROOT.rglob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))
    for path in sorted(ROOT.rglob("*.jsonl")):
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                raise AssertionError(
                    f"{path.name}:{line_number} is not valid JSON"
                ) from exc


def _validate_junit() -> dict[str, dict[str, int]]:
    expected = {
        "test-results.xml": {
            "tests": 526,
            "failures": 0,
            "errors": 0,
            "skipped": 2,
        },
        "loop6-test-results.xml": {
            "tests": 150,
            "failures": 0,
            "errors": 0,
            "skipped": 1,
        },
        "frontend-test-results.xml": {
            "tests": 25,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        },
    }
    observed: dict[str, dict[str, int]] = {}
    for name, expected_counts in expected.items():
        root = ET.parse(ROOT / name).getroot()
        suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
        counts = {
            field: sum(int(suite.attrib.get(field, "0")) for suite in suites)
            for field in ("tests", "failures", "errors", "skipped")
        }
        if counts != expected_counts:
            raise AssertionError(f"{name} counts changed: {counts}")
        hostnames = {
            suite.attrib.get("hostname")
            for suite in suites
            if suite.attrib.get("hostname") is not None
        }
        if hostnames != {"local-windows-host"}:
            raise AssertionError(f"{name} contains unsanitized hostnames")
        observed[name] = counts
    return observed


def _validate_privacy() -> None:
    local_host = socket.gethostname().casefold()
    user_profile = os.environ.get("USERPROFILE", "").strip().casefold()
    user_name = os.environ.get("USERNAME", "").strip().casefold()
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        lowered = text.casefold()
        if local_host and local_host in lowered:
            raise AssertionError(f"{path.name} contains the local hostname")
        if user_profile and user_profile in lowered:
            raise AssertionError(f"{path.name} contains the local user profile")
        if user_name and user_name in lowered:
            raise AssertionError(f"{path.name} contains the local user name")
        if DOUBLED_USER_PATH.search(text):
            raise AssertionError(
                f"{path.name} contains a doubled-backslash user path"
            )
        if PYTEST_USER_DIRECTORY.search(text):
            raise AssertionError(f"{path.name} contains a pytest user directory")
        if RAW_GPU_UUID.search(text):
            raise AssertionError(f"{path.name} contains a raw GPU UUID")


def _validate_qualification_hashes() -> None:
    summary = json.loads(
        (ROOT / "runtime-qualification-summary.json").read_text(encoding="utf-8")
    )
    provenance = json.loads(
        (ROOT / "runtime-check" / "provenance.json").read_text(encoding="utf-8")
    )
    qualification = ROOT / "runtime-check" / "qualification.json"
    observed = _sha256(qualification)
    expected = summary["active_composition"][
        "independent_qualification_sanitized_sha256"
    ]
    if observed != expected or observed != provenance["sanitized_qualification_sha256"]:
        raise AssertionError("sanitized qualification hash is inconsistent")


def _validate_file_manifest() -> None:
    manifest = ROOT / "files.sha256"
    declared: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", maxsplit=1)
        declared[relative] = digest
    actual_files = {
        path.relative_to(ROOT).as_posix(): _sha256(path)
        for path in ROOT.rglob("*")
        if path.is_file() and path != manifest
    }
    if declared != actual_files:
        raise AssertionError("files.sha256 does not exactly seal the evidence tree")


def main() -> None:
    _validate_json()
    junit = _validate_junit()
    _validate_privacy()
    _validate_qualification_hashes()
    _validate_file_manifest()
    print(
        json.dumps(
            {
                "evidence_files_sealed": len(
                    (ROOT / "files.sha256").read_text(encoding="utf-8").splitlines()
                ),
                "junit": junit,
                "privacy": "passed",
                "qualification_hashes": "passed",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
