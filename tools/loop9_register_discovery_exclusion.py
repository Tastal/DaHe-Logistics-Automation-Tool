from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.application.chengfeng.identity_authority import (
    Loop9IdentityAuthorityError,
    load_or_create_loop9_identity_authority,
)
from dahe.verification.loop9_dataset_isolation import (
    Loop9DatasetIsolationError,
)
from dahe.verification.loop9_exclusion_authority import (
    register_loop9_contract_discovery_exclusion,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (
    ROOT / ".venv" / "Scripts" / "python.exe"
).resolve()


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Register platform identities viewed during one Loop 9 contract "
            "discovery as irreversible development exclusions. Read one raw "
            "platform identity per stdin line; raw values are never persisted."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument(
        "--discovery-evidence",
        type=_absolute_path,
        required=True,
    )
    return parser


def _source_identities_from_stdin() -> tuple[str, ...]:
    binary_stream = getattr(sys.stdin, "buffer", None)
    if binary_stream is None:
        text = sys.stdin.read()
    else:
        try:
            text = binary_stream.read().decode(
                "utf-8-sig",
                errors="strict",
            )
        except UnicodeDecodeError as exc:
            raise SystemExit("stdin must be UTF-8 text") from exc
    values: list[str] = []
    for raw_line in text.splitlines():
        value = raw_line.rstrip("\r\n")
        if (
            not value
            or value != value.strip()
            or len(value) > 500
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in value
            )
        ):
            raise SystemExit(
                "stdin must contain one non-empty platform identity per line"
            )
        values.append(value)
        if len(values) > 100:
            raise SystemExit(
                "stdin contains too many platform identities"
            )
    if not values:
        raise SystemExit(
            "stdin must contain one or more platform identities"
        )
    return tuple(values)


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    source_identities = _source_identities_from_stdin()
    try:
        identity_authority = load_or_create_loop9_identity_authority(
            arguments.data_root
        )
        inventory = register_loop9_contract_discovery_exclusion(
            data_root=arguments.data_root,
            discovery_evidence_path=arguments.discovery_evidence,
            source_identities=source_identities,
            identity_salt=identity_authority.salt,
            identity_namespace=identity_authority.namespace,
        )
    except (
        Loop9DatasetIsolationError,
        Loop9IdentityAuthorityError,
    ) as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "canonical_sha256": inventory.canonical_sha256,
                "identity_context_sha256": (
                    inventory.identity_context_sha256
                ),
                "platform_identity_count": len(
                    inventory.platform_identity_sha256s
                ),
                "raw_platform_identity_retained": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
