from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from PIL import Image

from dahe.verification.locked_set import source_waybill_identity_sha256


def _load_tool(project_root: Path) -> ModuleType:
    path = project_root / "tools" / "loop7_legacy_candidate_review.py"
    spec = importlib.util.spec_from_file_location("loop7_legacy_candidate_review", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _image(path: Path, color: tuple[int, int, int]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (4, 4), color=color).save(path, format="PNG")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exclusion_collection_hashes_images_and_deidentifies_waybills(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    image_root = tmp_path / "exclusions"
    first_hash = _image(image_root / "first.png", (1, 2, 3))
    ignored = image_root / ".venv-gpu" / "ignored.png"
    _image(ignored, (3, 2, 1))
    manifest = tmp_path / "source.json"
    manifest.write_text(
        json.dumps(
            {
                "waybills": [
                    {"waybill_no": "REAL-001"},
                    {"nested": {"waybill_no": "REAL-002"}},
                ]
            }
        ),
        encoding="utf-8",
    )

    snapshot = module.collect_external_exclusions(
        image_roots=(image_root,),
        waybill_jsons=(manifest,),
        explicit_hash_files=(),
    )

    assert snapshot.image_hashes == frozenset({first_hash})
    assert snapshot.waybill_identity_hashes == frozenset(
        {
            source_waybill_identity_sha256(
                source_namespace="chengfeng_waybill_no",
                source_id="REAL-001",
            ),
            source_waybill_identity_sha256(
                source_namespace="chengfeng_waybill_no",
                source_id="REAL-002",
            ),
        }
    )
    encoded = json.dumps(snapshot.to_payload(), ensure_ascii=False)
    assert "REAL-001" not in encoded
    assert "REAL-002" not in encoded
    assert ".venv-gpu" not in encoded


def test_hash_file_requires_canonical_sha256_lines(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("0" * 64 + "\n", encoding="utf-8")

    snapshot = module.collect_external_exclusions(
        image_roots=(),
        waybill_jsons=(),
        explicit_hash_files=(hash_file,),
    )

    assert snapshot.image_hashes == frozenset({"0" * 64})


def test_review_data_roots_merge_published_package_identities_and_source_hashes(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_tool(project_root)
    first_root = tmp_path / "first-review-data"
    second_root = tmp_path / "second-review-data"
    loaded_roots: list[Path] = []
    expected_source_hashes: list[str] = []
    packages: dict[Path, object] = {}
    inherited_image_hashes: set[str] = set()
    inherited_waybill_hashes: set[str] = set()
    for index, root in enumerate((first_root, second_root), start=1):
        review_root = root / "locked-set-review"
        review_root.mkdir(parents=True)
        package_path = review_root / "review-package.json"
        exclusion_path = review_root / "external-exclusion-snapshot.json"
        package_path.write_text(
            json.dumps({"package": index}),
            encoding="utf-8",
        )
        inherited_image_hash = hashlib.sha256(
            f"inherited-image-{index}".encode()
        ).hexdigest()
        inherited_waybill_hash = hashlib.sha256(
            f"inherited-waybill-{index}".encode()
        ).hexdigest()
        inherited_image_hashes.add(inherited_image_hash)
        inherited_waybill_hashes.add(inherited_waybill_hash)
        exclusion_path.write_text(
            json.dumps(
                {
                    "image_sha256s": [inherited_image_hash],
                    "waybill_identity_sha256s": [inherited_waybill_hash],
                }
            ),
            encoding="utf-8",
        )
        expected_source_hashes.extend(
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (package_path, exclusion_path)
        )
        packages[root.resolve()] = SimpleNamespace(
            review_root=review_root.resolve(),
            images_by_sha256={
                hashlib.sha256(f"image-{index}".encode()).hexdigest(): object()
            },
            items=(
                SimpleNamespace(
                    waybill_identity_sha256=hashlib.sha256(
                        f"waybill-{index}".encode()
                    ).hexdigest()
                ),
            ),
        )

    def load_package(data_root: Path) -> object:
        resolved = data_root.resolve(strict=True)
        loaded_roots.append(resolved)
        return packages[resolved]

    monkeypatch.setattr(
        module,
        "load_locked_set_review_package",
        load_package,
        raising=False,
    )

    snapshot = module.collect_external_exclusions(
        image_roots=(),
        waybill_jsons=(),
        explicit_hash_files=(),
        review_data_roots=(first_root, second_root),
    )

    assert loaded_roots == [first_root.resolve(), second_root.resolve()]
    assert snapshot.image_hashes == frozenset(
        {
            *inherited_image_hashes,
            *(
                package_hash
                for package in packages.values()
                for package_hash in package.images_by_sha256
            ),
        }
    )
    assert snapshot.waybill_identity_hashes == frozenset(
        {
            *inherited_waybill_hashes,
            *(
                item.waybill_identity_sha256
                for package in packages.values()
                for item in package.items
            ),
        }
    )
    assert snapshot.source_file_sha256s == tuple(
        sorted(set(expected_source_hashes))
    )


def test_review_data_root_duplicate_is_rejected_before_package_loading(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_tool(project_root)
    review_data_root = tmp_path / "review-data"
    review_data_root.mkdir()

    def unexpected_load(_data_root: Path) -> object:
        raise AssertionError("duplicate roots must reject before package loading")

    monkeypatch.setattr(
        module,
        "load_locked_set_review_package",
        unexpected_load,
        raising=False,
    )

    with pytest.raises(
        module.LegacyReviewToolError,
        match="review data roots must be unique",
    ):
        module.collect_external_exclusions(
            image_roots=(),
            waybill_jsons=(),
            explicit_hash_files=(),
            review_data_roots=(review_data_root, review_data_root),
        )


def test_invalid_review_data_root_is_rejected_as_a_tool_error(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    invalid_root = tmp_path / "invalid-review-data"
    invalid_root.mkdir()

    with pytest.raises(
        module.LegacyReviewToolError,
        match="published review package is invalid",
    ):
        module.collect_external_exclusions(
            image_roots=(),
            waybill_jsons=(),
            explicit_hash_files=(),
            review_data_roots=(invalid_root,),
        )


def test_source_commands_accept_repeatable_review_data_roots(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    legacy_root = tmp_path / "legacy"
    acquisition_root = tmp_path / "acquisition"
    first_root = tmp_path / "first-review-data"
    second_root = tmp_path / "second-review-data"
    development_authority = tmp_path / "development-authority.json"
    output = tmp_path / "discovery.json"

    arguments = module._parser().parse_args(
        [
            "discover",
            "--legacy-data-root",
            str(legacy_root),
            "--acquisition-root",
            str(acquisition_root),
            "--development-authority",
            str(development_authority),
            "--exclude-review-data-root",
            str(first_root),
            "--exclude-review-data-root",
            str(second_root),
            "--output",
            str(output),
        ]
    )

    assert arguments.exclude_review_data_root == [
        first_root.resolve(),
        second_root.resolve(),
    ]


@pytest.mark.parametrize("command", ("discover", "contact-sheets", "stage"))
def test_formal_candidate_commands_require_development_authority(
    project_root: Path,
    tmp_path: Path,
    command: str,
) -> None:
    module = _load_tool(project_root)
    legacy_root = tmp_path / "legacy"
    acquisition_root = tmp_path / "acquisition"
    arguments = [
        command,
        "--legacy-data-root",
        str(legacy_root),
        "--acquisition-root",
        str(acquisition_root),
    ]
    if command == "discover":
        arguments.extend(("--output", str(tmp_path / "discovery.json")))
    elif command == "contact-sheets":
        arguments.extend(
            (
                "--selection",
                str(tmp_path / "selection.json"),
                "--output-root",
                str(tmp_path / "sheets"),
            )
        )
    else:
        arguments.extend(
            (
                "--selection",
                str(tmp_path / "selection.json"),
                "--output-root",
                str(tmp_path / "review"),
                "--package-id",
                "formal-candidate",
            )
        )

    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(arguments)

    assert error.value.code == 2


def test_selection_is_bound_to_the_exact_candidate_index(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    selection = tmp_path / "selection.json"
    selection.write_text(
        json.dumps({"candidate_ids": ["candidate-001"]}),
        encoding="utf-8",
    )
    index = SimpleNamespace(
        source_manifest_sha256s=("a" * 64,),
        exclusion_snapshot_sha256="b" * 64,
        to_payload=lambda: {"canonical_sha256": "c" * 64},
    )

    with pytest.raises(
        module.LegacyReviewToolError,
        match="candidate index snapshot",
    ):
        module._selection(
            selection,
            index,
            development_authority_sha256="d" * 64,
        )

    selection.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "locked_set_candidate_selection",
                "candidate_index_sha256": "c" * 64,
                "source_manifest_sha256s": ["a" * 64],
                "exclusion_snapshot_sha256": "b" * 64,
                "development_authority_sha256": "d" * 64,
                "candidate_ids": ["candidate-001"],
            }
        ),
        encoding="utf-8",
    )

    assert module._selection(
        selection,
        index,
        development_authority_sha256="d" * 64,
    ) == ["candidate-001"]


def test_create_selection_writes_the_exact_discovery_snapshot_contract(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    candidate_ids = [f"candidate-{index:03d}" for index in range(1, 51)]
    candidate_index_without_hash = {
        "schema_version": 1,
        "kind": "legacy_locked_set_candidate_index",
        "source_manifest_sha256s": ["a" * 64, "b" * 64],
        "exclusion_snapshot_sha256": "c" * 64,
        "waybills": [
            {"candidate_id": candidate_id}
            for candidate_id in candidate_ids
        ],
    }
    candidate_index = {
        **candidate_index_without_hash,
        "canonical_sha256": module._canonical_sha256(
            candidate_index_without_hash
        ),
    }
    discovery = tmp_path / "discovery.json"
    discovery.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "legacy_locked_set_discovery",
                "offline": True,
                "legacy_database_opened": False,
                "development_authority_sha256": "d" * 64,
                "candidate_index": candidate_index,
            }
        ),
        encoding="utf-8",
    )
    frozen_ids = tmp_path / "candidate-ids.txt"
    frozen_ids.write_text(
        "\n".join(reversed(candidate_ids)) + "\n",
        encoding="utf-8",
    )
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    output = tmp_path / "selection.json"

    assert (
        module.main(
            [
                "create-selection",
                "--legacy-data-root",
                str(legacy_root),
                "--discovery",
                str(discovery),
                "--candidate-ids-file",
                str(frozen_ids),
                "--output",
                str(output),
            ]
        )
        == 0
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": 1,
        "kind": "locked_set_candidate_selection",
        "candidate_index_sha256": candidate_index["canonical_sha256"],
        "source_manifest_sha256s": ["a" * 64, "b" * 64],
        "exclusion_snapshot_sha256": "c" * 64,
        "development_authority_sha256": "d" * 64,
        "candidate_ids": list(reversed(candidate_ids)),
    }


def test_create_selection_rejects_duplicate_or_unknown_candidate_ids(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    candidate_ids = [f"candidate-{index:03d}" for index in range(1, 51)]
    candidate_index_without_hash = {
        "schema_version": 1,
        "kind": "legacy_locked_set_candidate_index",
        "source_manifest_sha256s": ["a" * 64],
        "exclusion_snapshot_sha256": "b" * 64,
        "waybills": [
            {"candidate_id": candidate_id}
            for candidate_id in candidate_ids
        ],
    }
    discovery = tmp_path / "discovery.json"
    discovery.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "legacy_locked_set_discovery",
                "offline": True,
                "legacy_database_opened": False,
                "development_authority_sha256": "d" * 64,
                "candidate_index": {
                    **candidate_index_without_hash,
                    "canonical_sha256": module._canonical_sha256(
                        candidate_index_without_hash
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    frozen_ids = tmp_path / "candidate-ids.txt"
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    frozen_ids.write_text(
        "\n".join([*candidate_ids[:-1], candidate_ids[0]]) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        module.LegacyReviewToolError,
        match="unique",
    ):
        module.create_selection_file(
            legacy_data_root=legacy_root,
            discovery_path=discovery,
            candidate_ids_path=frozen_ids,
            output_path=tmp_path / "duplicate-selection.json",
        )

    frozen_ids.write_text(
        "\n".join([*candidate_ids[:-1], "candidate-not-in-discovery"]) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        module.LegacyReviewToolError,
        match="not present",
    ):
        module.create_selection_file(
            legacy_data_root=legacy_root,
            discovery_path=discovery,
            candidate_ids_path=frozen_ids,
            output_path=tmp_path / "unknown-selection.json",
        )


def test_discover_rejects_json_output_inside_legacy_before_build_or_write(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_tool(project_root)
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    output = legacy_root / "discovery.json"

    def unexpected_build(_arguments: object) -> object:
        raise AssertionError("discovery must reject before reading source inputs")

    monkeypatch.setattr(module, "_build_index", unexpected_build)

    with pytest.raises(
        module.LegacyReviewToolError,
        match="outside the legacy data root",
    ):
        module._discover(
            SimpleNamespace(
                legacy_data_root=legacy_root,
                output=output,
            )
        )

    assert not output.exists()


def test_contact_sheets_reject_output_inside_legacy_before_directory_creation(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_tool(project_root)
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    def unexpected_build(_arguments: object) -> object:
        raise AssertionError("contact sheets must reject before reading sources")

    monkeypatch.setattr(module, "_build_index", unexpected_build)

    for output_root in (
        legacy_root,
        legacy_root / "contact-sheets",
    ):
        with pytest.raises(
            module.LegacyReviewToolError,
            match="outside the legacy data root",
        ):
            module._contact_sheets(
                SimpleNamespace(
                    legacy_data_root=legacy_root,
                    output_root=output_root,
                )
            )

    assert not (legacy_root / "contact-sheets").exists()


def test_create_selection_rejects_legacy_output_before_reading_or_writing(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    output = legacy_root / "selection.json"

    with pytest.raises(
        module.LegacyReviewToolError,
        match="outside the legacy data root",
    ):
        module.create_selection_file(
            legacy_data_root=legacy_root,
            discovery_path=tmp_path / "missing-discovery.json",
            candidate_ids_path=tmp_path / "missing-candidate-ids.txt",
            output_path=output,
        )

    assert not output.exists()


def test_discover_rejects_an_external_alias_that_resolves_into_legacy(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_tool(project_root)
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    alias = tmp_path / "legacy-alias"
    try:
        alias.symlink_to(legacy_root, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("directory symlinks are unavailable on this host")
        result = subprocess.run(
            [
                "cmd.exe",
                "/d",
                "/c",
                "mklink",
                "/J",
                os.fspath(alias),
                os.fspath(legacy_root),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("directory symlinks and junctions are unavailable")
    output = alias / "discovery.json"

    def unexpected_build(_arguments: object) -> object:
        raise AssertionError("resolved aliases must reject before source reads")

    monkeypatch.setattr(module, "_build_index", unexpected_build)

    try:
        with pytest.raises(
            module.LegacyReviewToolError,
            match="outside the legacy data root",
        ):
            module._discover(
                SimpleNamespace(
                    legacy_data_root=legacy_root,
                    output=output,
                )
            )
        assert not output.exists()
    finally:
        alias.rmdir()


def test_create_selection_formal_round_trip_failure_leaves_no_output(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_tool(project_root)
    candidate_ids = [f"candidate-{index:03d}" for index in range(1, 51)]
    candidate_index_without_hash = {
        "schema_version": 1,
        "kind": "legacy_locked_set_candidate_index",
        "source_manifest_sha256s": ["a" * 64],
        "exclusion_snapshot_sha256": "b" * 64,
        "waybills": [
            {"candidate_id": candidate_id}
            for candidate_id in candidate_ids
        ],
    }
    discovery = tmp_path / "discovery.json"
    discovery.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "legacy_locked_set_discovery",
                "offline": True,
                "legacy_database_opened": False,
                "development_authority_sha256": "d" * 64,
                "candidate_index": {
                    **candidate_index_without_hash,
                    "canonical_sha256": module._canonical_sha256(
                        candidate_index_without_hash
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    frozen_ids = tmp_path / "candidate-ids.txt"
    frozen_ids.write_text("\n".join(candidate_ids) + "\n", encoding="utf-8")
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    output = tmp_path / "selection.json"

    def rejecting_consumer(
        _path: Path,
        _index: object,
        *,
        development_authority_sha256: str,
    ) -> list[str]:
        assert development_authority_sha256 == "d" * 64
        raise module.LegacyReviewToolError("injected formal selection rejection")

    monkeypatch.setattr(module, "_selection", rejecting_consumer)

    with pytest.raises(
        module.LegacyReviewToolError,
        match="formal selection rejection",
    ):
        module.create_selection_file(
            legacy_data_root=legacy_root,
            discovery_path=discovery,
            candidate_ids_path=frozen_ids,
            output_path=output,
        )

    assert not output.exists()
    assert not list(tmp_path.glob(".selection.json.*.tmp.json"))


def test_create_selection_never_overwrites_a_published_output(
    project_root: Path,
    tmp_path: Path,
) -> None:
    module = _load_tool(project_root)
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    output = tmp_path / "selection.json"
    output.write_text("published selection", encoding="utf-8")

    with pytest.raises(
        module.LegacyReviewToolError,
        match="must not already exist",
    ):
        module.create_selection_file(
            legacy_data_root=legacy_root,
            discovery_path=tmp_path / "missing-discovery.json",
            candidate_ids_path=tmp_path / "missing-candidate-ids.txt",
            output_path=output,
        )

    assert output.read_text(encoding="utf-8") == "published selection"


def test_json_publish_race_never_silently_overwrites_another_writer(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_tool(project_root)
    output = (tmp_path / "race.json").resolve()
    publish_barrier = threading.Barrier(2)
    original_replace = Path.replace

    def synchronized_replace(
        source: Path,
        target: str | Path,
    ) -> Path:
        if Path(target).resolve() == output:
            publish_barrier.wait(timeout=5)
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", synchronized_replace)

    def publish(value: str) -> tuple[str, str]:
        try:
            module._write_json_new(output, {"writer": value})
        except module.LegacyReviewToolError as exc:
            return "error", str(exc)
        return "success", value

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(publish, ("first", "second"))
        )

    assert sorted(status for status, _ in results) == [
        "error",
        "success",
    ]
    assert json.loads(output.read_text(encoding="utf-8")) in (
        {"writer": "first"},
        {"writer": "second"},
    )
    assert not list(tmp_path.glob(".race.json.*.tmp"))
