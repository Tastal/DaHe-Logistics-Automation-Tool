from __future__ import annotations

import hashlib
import json
import random
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from PIL import Image

from dahe.application.template_studio.candidate_review_semantics import (
    candidate_review_waybill_membership_sha256,
)
from tools import loop7_locked_set_release as module


def _write_locked_set(
    root: Path,
    *,
    dataset_id: str = "locked-cli-fixture",
) -> tuple[Path, Path]:
    dataset_root = root / dataset_id
    image_root = dataset_root / "images"
    image_root.mkdir(parents=True)
    images: list[dict[str, object]] = []
    for index in range(100):
        pixels = random.Random(index + 104729).randbytes(64 * 64)
        image_path = image_root / f"{index + 1:03d}.png"
        Image.frombytes("L", (64, 64), pixels).save(image_path)
        content = image_path.read_bytes()
        images.append(
            {
                "image_sha256": hashlib.sha256(content).hexdigest(),
                "relative_path": f"images/{index + 1:03d}.png",
                "submitted_slot": ("loading" if index % 2 == 0 else "unloading"),
                "role": ("loading" if index % 2 == 0 else "unloading"),
                "ordinary_net": ("30.00" if index % 2 == 0 else "29.98"),
            }
        )
    images[0]["role"] = "unloading"
    images[1]["role"] = "loading"
    images[2]["role"] = "loading"
    images[3]["role"] = "loading"
    for index in (4, 5):
        images[index]["role"] = "unknown"
        images[index]["ordinary_net"] = None
    waybills = [
        {
            "sample_id": f"waybill-{index + 1:03d}",
            "waybill_identity_sha256": hashlib.sha256(
                f"{dataset_id}:waybill:{index + 1}".encode()
            ).hexdigest(),
            "human_confirmed": True,
            "label_source": "direct_image_review",
            "images": images[index * 2 : index * 2 + 2],
        }
        for index in range(50)
    ]
    manifest = {
        "schema_version": 1,
        "dataset_id": dataset_id,
        "dataset_kind": "locked",
        "tuning_prohibited": True,
        "waybills": waybills,
    }
    manifest_path = dataset_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_path, dataset_root


def _complete_review_package(
    *,
    review_path: Path,
    manifest_path: Path,
) -> None:
    review = json.loads(review_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    waybills = manifest["waybills"]
    images = [image for waybill in waybills for image in waybill["images"]]
    image_for_condition = {
        "blur": images[8]["image_sha256"],
        "crop": images[9]["image_sha256"],
        "glare": images[10]["image_sha256"],
        "non_ticket": images[4]["image_sha256"],
        "printed": images[11]["image_sha256"],
        "rotation_0": images[12]["image_sha256"],
        "rotation_90": images[13]["image_sha256"],
        "rotation_180": images[14]["image_sha256"],
        "rotation_270": images[15]["image_sha256"],
        "screen": images[16]["image_sha256"],
        "unknown_layout": images[5]["image_sha256"],
    }
    entries: list[dict[str, object]] = []
    for condition in sorted(module.REQUIRED_NATURAL_QUALITY_CONDITIONS):
        entry: dict[str, object] = {
            "condition": condition,
            "reviewer_id": "reviewer-test",
            "reviewed_at": "2026-07-26T09:00:00+08:00",
            "image_sha256": image_for_condition[condition],
        }
        entries.append(entry)
    review["quality_coverage"]["entries"] = entries
    review_path.write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _register_candidate_source_authority_for_test(
    *,
    data_root: Path,
    review_path: Path,
) -> None:
    review = json.loads(review_path.read_text(encoding="utf-8"))
    dataset_id = str(review["dataset_id"])
    manifest_sha256 = str(review["manifest_sha256"])
    quality = review["quality_coverage"]
    for entry in quality["entries"]:
        entry["review_evidence_sha256"] = module.quality_review_evidence_sha256(
            dataset_id=dataset_id,
            manifest_sha256=manifest_sha256,
            entry=entry,
        )
    quality["quality_coverage_sha256"] = module.locked_set_quality_coverage_sha256(quality)
    runtime = module.SqliteRuntime(
        data_root=data_root,
        project_root=module.ROOT,
        instance_id="candidate-source-authority-test",
    )
    try:
        repository = module.SqliteLockedSetRepository(runtime=runtime)
        manifest = repository.get_manifest(dataset_id)
        records: list[dict[str, object]] = []
        verified_images: list[dict[str, object]] = []
        memberships: list[dict[str, object]] = []
        for waybill in manifest.waybills:
            review_images: list[dict[str, object]] = []
            member_images: list[dict[str, object]] = []
            roles: dict[str, str] = {}
            for image in waybill.images:
                role = image.role.value
                roles[image.slot.value] = role
                ordinary_net = (
                    None if image.ordinary_net is None else format(image.ordinary_net, "f")
                )
                review_images.append(
                    {
                        "submitted_slot": image.slot.value,
                        "role": role,
                        "ordinary_net": ordinary_net,
                        "quality_conditions": [
                            "rotation_0",
                            ("printed" if image.slot.value == "loading" else "screen"),
                        ],
                        "notes": None,
                    }
                )
                verified_images.append(
                    {
                        "sample_id": waybill.sample_id,
                        "submitted_slot": image.slot.value,
                        "image_sha256": image.image_sha256,
                        "relative_path": image.relative_path,
                        "width": 64,
                        "height": 64,
                        "media_type": "image/png",
                        "byte_count": 100,
                    }
                )
                member_images.append(
                    {
                        "submitted_slot": image.slot.value,
                        "image_sha256": image.image_sha256,
                        "relative_path": image.relative_path,
                        "ticket_role": role,
                        "ordinary_net_kg": (
                            None
                            if image.ordinary_net is None
                            else str(int(image.ordinary_net * 1000))
                        ),
                    }
                )
            role_pair = (roles["loading"], roles["unloading"])
            if "unknown" in role_pair:
                pair_condition = "pair_unknown"
            elif role_pair == ("unloading", "loading"):
                pair_condition = "swapped_pair"
            elif role_pair[0] == role_pair[1]:
                pair_condition = "same_role_pair"
            else:
                pair_condition = "normal_pair"
            records.append(
                {
                    "sample_id": waybill.sample_id,
                    "record_version": 1,
                    "review_status": "confirmed",
                    "decision": "confirmed",
                    "review_payload": {
                        "reviewer_id": "reviewer-test",
                        "decision": "confirmed",
                        "images": review_images,
                        "pair_conditions": [pair_condition],
                        "pair_notes": None,
                        "replace_reason": None,
                    },
                    "created_at": "2026-07-26T09:00:00+08:00",
                    "updated_at": "2026-07-26T09:00:00+08:00",
                    "record_evidence_sha256": "f" * 64,
                }
            )
            memberships.append(
                {
                    "sample_id": waybill.sample_id,
                    "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                    "images": member_images,
                }
            )
        verified_image_set_sha256 = module._canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": "b" * 64,
                "images": verified_images,
            }
        )
        membership_sha256 = candidate_review_waybill_membership_sha256(
            package_sha256="b" * 64,
            waybills=memberships,
        )
        source_without_hash = {
            "schema_version": 3,
            "kind": "candidate_review_formal_source_authority",
            "authority_scope": "computed_unsealed_snapshot",
            "persistent_seal": False,
            "dataset_id": dataset_id,
            "manifest_sha256": manifest_sha256,
            "quality_coverage_sha256": review["quality_coverage"]["quality_coverage_sha256"],
            "package_id": "candidate-source-authority-test",
            "package_sha256": "b" * 64,
            "configured_reviewer_id": "reviewer-test",
            "record_count": 50,
            "record_set_sha256": "c" * 64,
            "records": records,
            "verified_image_count": 100,
            "verified_image_set_sha256": (verified_image_set_sha256),
            "verified_images": verified_images,
            "waybill_membership_count": 50,
            "waybill_membership_sha256": membership_sha256,
            "waybill_membership": memberships,
        }
        source_authority_sha256 = module._canonical_sha256(source_without_hash)
        source_payload = {
            **source_without_hash,
            "source_authority_sha256": source_authority_sha256,
        }
        binding = {
            "schema_version": 1,
            "seal_sha256": "a" * 64,
            "package_sha256": "b" * 64,
            "record_set_sha256": "c" * 64,
            "review_history_authority_sha256": "d" * 64,
            "source_authority_sha256": source_authority_sha256,
        }
        repository.register_candidate_review_source_authority(
            dataset_id=dataset_id,
            manifest_sha256=manifest_sha256,
            seal_sha256=str(binding["seal_sha256"]),
            package_sha256=str(binding["package_sha256"]),
            record_set_sha256=str(binding["record_set_sha256"]),
            review_history_authority_sha256=str(binding["review_history_authority_sha256"]),
            source_authority_sha256=source_authority_sha256,
            payload=source_payload,
        )
    finally:
        runtime.close()
    review["candidate_review_source_authority"] = binding
    review_path.write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _evaluate_arguments(tmp_path: Path) -> list[str]:
    development_root = (tmp_path / "development-data").resolve()
    development_root.mkdir(exist_ok=True)
    review = tmp_path / "review-package.json"
    review.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "dataset_id": "locked-cli-fixture",
                "development_authority_sha256": "f" * 64,
                "source_development_authority_sha256": "e" * 64,
                "quality_coverage": {
                    "schema_version": 1,
                    "dataset_id": "locked-cli-fixture",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return [
        "evaluate",
        "--data-root",
        str((tmp_path / "data").resolve()),
        "--development-data-root",
        str(development_root),
        "--dataset-id",
        "locked-cli-fixture",
        "--review-package",
        str(review),
        "--actor",
        "developer-test",
        "--idempotency-key",
        "locked-cli-evaluation",
        "--report-output",
        str(tmp_path / "report.json"),
    ]


def _invalidate_arguments(tmp_path: Path) -> list[str]:
    return [
        "invalidate",
        "--data-root",
        str((tmp_path / "data").resolve()),
        "--dataset-id",
        "locked-cli-fixture",
        "--expected-record-version",
        "4",
        "--influence-kind",
        "template",
        "--reason",
        "Locked-set evidence influenced a template change.",
        "--actor",
        "developer-test",
        "--idempotency-key",
        "locked-cli-invalidation",
        "--output",
        str(tmp_path / "invalidation.json"),
    ]


def _prepare_candidate_arguments(tmp_path: Path) -> list[str]:
    candidate_review_root = (tmp_path / "candidate-review").resolve()
    candidate_review_root.mkdir(exist_ok=True)
    development_root = (tmp_path / "development-data").resolve()
    development_root.mkdir(exist_ok=True)
    return [
        "prepare-candidate",
        "--data-root",
        str((tmp_path / "formal-data").resolve()),
        "--candidate-review-root",
        str(candidate_review_root),
        "--development-data-root",
        str(development_root),
        "--seal-sha256",
        "a" * 64,
        "--development-authority-sha256",
        "f" * 64,
        "--source-development-authority-sha256",
        "e" * 64,
        "--development-authority-rollover",
        str((tmp_path / "authority-rollover.json").resolve()),
        "--actor",
        "developer-test",
        "--review-output",
        str(tmp_path / "candidate-review-package.json"),
    ]


def test_parser_requires_an_explicit_absolute_data_root(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    dataset_root = tmp_path / "dataset"
    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(
            [
                "prepare",
                "--data-root",
                "relative-data",
                "--manifest",
                str(manifest),
                "--dataset-root",
                str(dataset_root),
                "--actor",
                "developer-test",
                "--review-output",
                str(tmp_path / "review.json"),
            ]
        )

    assert error.value.code == 2


def test_prepare_candidate_parser_requires_an_absolute_review_root_and_seal(
    tmp_path: Path,
) -> None:
    arguments = _prepare_candidate_arguments(tmp_path)
    review_root_index = arguments.index("--candidate-review-root") + 1
    arguments[review_root_index] = "relative-review-root"

    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(arguments)

    assert error.value.code == 2


def test_prepare_candidate_requires_explicit_development_authority_hash(
    tmp_path: Path,
) -> None:
    arguments = _prepare_candidate_arguments(tmp_path)
    option_index = arguments.index("--development-authority-sha256")
    del arguments[option_index : option_index + 2]

    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(arguments)

    assert error.value.code == 2

    arguments = _prepare_candidate_arguments(tmp_path)
    seal_index = arguments.index("--seal-sha256") + 1
    arguments[seal_index] = "not-a-sha256"
    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(arguments)

    assert error.value.code == 2


def test_bind_review_parser_requires_an_explicit_absolute_data_root(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(
            [
                "bind-review",
                "--data-root",
                "relative-data",
                "--review-package",
                str(tmp_path / "review.json"),
                "--output",
                str(tmp_path / "bound.json"),
            ]
        )

    assert error.value.code == 2


@pytest.mark.parametrize(
    "forbidden_option",
    (
        "--evaluator",
        "--truth-override",
        "--scan",
        "--eligibility-history",
        "--run-context",
        "--template-id",
        "--runtime-fingerprint",
        "--quality-coverage",
        "--similarity-review",
    ),
)
def test_evaluate_parser_rejects_caller_owned_gate_inputs(
    tmp_path: Path,
    forbidden_option: str,
) -> None:
    with pytest.raises(SystemExit) as error:
        module._parser().parse_args([*_evaluate_arguments(tmp_path), forbidden_option, "forged"])

    assert error.value.code == 2


@pytest.mark.parametrize(
    ("option", "value"),
    (
        ("--expected-record-version", "0"),
        ("--expected-record-version", "not-an-integer"),
        ("--influence-kind", "other"),
    ),
)
def test_invalidate_parser_rejects_unbounded_authority_inputs(
    tmp_path: Path,
    option: str,
    value: str,
) -> None:
    arguments = _invalidate_arguments(tmp_path)
    index = arguments.index(option)
    arguments[index + 1] = value

    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(arguments)

    assert error.value.code == 2


def test_atomic_output_refuses_protected_or_existing_files(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    protected = data_root / "database" / "metadata.json"
    protected.parent.mkdir(parents=True)
    protected.write_bytes(b"protected-database-metadata")
    unrelated = tmp_path / "unrelated.json"
    unrelated.write_bytes(b'{"owner":"another-tool"}\n')
    payload = {
        "schema_version": 1,
        "command": "prepare",
        "dataset_id": "locked-cli-fixture",
    }

    with pytest.raises(RuntimeError, match="overlaps protected"):
        module._write_json_atomic(
            protected,
            payload,
            protected_roots=(data_root,),
        )
    with pytest.raises(RuntimeError, match="already exists"):
        module._write_json_atomic(unrelated, payload)

    assert protected.read_bytes() == b"protected-database-metadata"
    assert unrelated.read_bytes() == b'{"owner":"another-tool"}\n'


def test_export_development_authority_completes_fingerprints_before_freeze(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "development-data").resolve()
    data_root.mkdir()
    output = (tmp_path / "development-authority.json").resolve()
    runtime_identity = SimpleNamespace(data_root=data_root)
    events: list[str] = []

    class FakeRuntimeContext:
        def __enter__(self) -> dict[str, object]:
            return {"development": runtime_identity}

        def __exit__(self, *_: object) -> None:
            return None

    class FakeRepository:
        def __init__(self, *, runtime: object) -> None:
            assert runtime is runtime_identity
            events.append("repository")

    authority = SimpleNamespace(
        authority_sha256="a" * 64,
        image_sha256s=frozenset({"b" * 64}),
        shadow_templates=(object(),),
        inventory_high_watermark=7,
        waybill_identity_sha256s=frozenset({"c" * 64}),
    )

    monkeypatch.setattr(
        module,
        "_guarded_runtimes",
        lambda roots: FakeRuntimeContext(),
    )
    monkeypatch.setattr(
        module,
        "SqliteLockedSetRepository",
        FakeRepository,
    )

    def complete_fingerprints(**values: object) -> None:
        assert isinstance(values["repository"], FakeRepository)
        evidence_store = values["evidence_store"]
        assert isinstance(
            evidence_store,
            module.ContentAddressedEvidenceStore,
        )
        assert evidence_store.root == data_root / "evidence"
        events.append("complete")

    monkeypatch.setattr(
        module,
        "complete_existing_exclusion_fingerprints",
        complete_fingerprints,
        raising=False,
    )

    def build_authority(value: object) -> object:
        assert value is runtime_identity
        assert events == ["repository", "complete"]
        events.append("build")
        return authority

    monkeypatch.setattr(
        module,
        "build_current_formal_development_authority",
        build_authority,
    )
    monkeypatch.setattr(
        module,
        "write_formal_development_authority",
        lambda path, value: events.append("write"),
    )

    assert (
        module.main(
            [
                "export-development-authority",
                "--data-root",
                str(data_root),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert events == ["repository", "complete", "build", "write"]


def test_prepare_stages_100_local_images_without_building_ocr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path, dataset_root = _write_locked_set(tmp_path / "fixture")
    data_root = (tmp_path / "application-data").resolve()
    output = tmp_path / "similarity-review.json"

    def fail_if_ocr_is_built(**_: object) -> None:
        raise AssertionError("prepare must not build an OCR backend")

    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        fail_if_ocr_is_built,
    )

    exit_code = module.main(
        [
            "prepare",
            "--data-root",
            str(data_root),
            "--manifest",
            str(manifest_path),
            "--dataset-root",
            str(dataset_root),
            "--actor",
            "developer-test",
            "--review-output",
            str(output),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    scan = payload["scan"]
    assert exit_code == 0
    assert payload["dataset_id"] == "locked-cli-fixture"
    assert payload["formal_accuracy_claim"] is False
    assert payload["offline"] is True
    assert payload["platform_access"] is False
    assert payload["source_data_classification"] == ("operator_supplied_locked_set")
    assert payload["classification_authority"] == "operator_declared"
    assert payload["dataset_record_version"] >= 1
    assert scan["locked_image_count"] == 100
    assert payload["scan_fingerprint"] == scan["scan_fingerprint"]
    assert payload["candidates"] == scan["candidates"]
    assert payload["decisions"] == []
    quality = payload["quality_coverage"]
    assert set(quality) == {
        "schema_version",
        "dataset_id",
        "manifest_sha256",
        "required_conditions",
        "entries",
        "derived_adversarial_suite",
        "quality_coverage_sha256",
    }
    assert quality["schema_version"] == 2
    assert quality["dataset_id"] == payload["dataset_id"]
    assert quality["manifest_sha256"] == payload["manifest_sha256"]
    assert set(quality["required_conditions"]) == set(
        module.REQUIRED_NATURAL_QUALITY_CONDITIONS
    )
    assert quality["entries"] == []
    suite = quality["derived_adversarial_suite"]
    assert suite["generator_version"] == (module.DERIVED_ADVERSARIAL_GENERATOR_VERSION)
    assert len(suite["scenarios"]) == 4
    assert suite["suite_sha256"] == module._canonical_sha256(
        {key: value for key, value in suite.items() if key != "suite_sha256"}
    )
    assert quality["quality_coverage_sha256"] == (
        module.locked_set_quality_coverage_sha256(quality)
    )
    assert payload["review_contract"]["tuning_prohibited"] is True
    assert len(tuple((data_root / "evidence").rglob("*.blob"))) == 100
    database_path = data_root / "database" / "dahe.sqlite3"
    assert database_path.is_file()
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT count(*) FROM evidence_blobs").fetchone() == (100,)
        assert connection.execute(
            "SELECT count(*) FROM evidence_references "
            "WHERE owner_kind = 'locked_set_dataset' "
            "AND released_at IS NULL"
        ).fetchone() == (100,)
        assert connection.execute(
            "SELECT count(*) FROM evidence_holds "
            "WHERE hold_kind = 'locked_set_member' "
            "AND released_at IS NULL"
        ).fetchone() == (100,)


def test_prepare_candidate_revalidates_seal_and_binds_source_without_ocr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _prepare_candidate_arguments(tmp_path)
    candidate_review_root = (tmp_path / "candidate-review").resolve()
    state: dict[str, object] = {}

    class FakeGuard:
        instance_id = "candidate-prepare-instance"

        def __enter__(self) -> FakeGuard:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    class FakeRuntime:
        def __init__(self, **values: object) -> None:
            state["runtime"] = self
            self.data_root = Path(str(values["data_root"]))
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeRepository:
        def __init__(self, **_: object) -> None:
            state["repository"] = self

    class FakeScan:
        candidate_entries: tuple[object, ...] = ()
        scan_fingerprint = "6" * 64

        def to_payload(self) -> dict[str, object]:
            return {
                "schema_version": 1,
                "scan_fingerprint": self.scan_fingerprint,
                "candidates": [],
            }

    source_binding = {
        "seal_sha256": "a" * 64,
        "package_sha256": "b" * 64,
        "record_set_sha256": "c" * 64,
        "review_history_authority_sha256": "d" * 64,
        "source_authority_sha256": "e" * 64,
    }
    quality = {
        "schema_version": 2,
        "dataset_id": "candidate-sealed-fixture",
        "manifest_sha256": "1" * 64,
        "required_conditions": list(module.REQUIRED_NATURAL_QUALITY_CONDITIONS),
        "entries": [],
        "derived_adversarial_suite": {
            "schema_version": 1,
            "generator_version": module.DERIVED_ADVERSARIAL_GENERATOR_VERSION,
            "source_truth_sha256": "2" * 64,
            "scenarios": [],
            "suite_sha256": "3" * 64,
        },
        "quality_coverage_sha256": "4" * 64,
    }
    prepared = SimpleNamespace(
        dataset_id="candidate-sealed-fixture",
        dataset_record_version=3,
        manifest_sha256="1" * 64,
        exclusion_snapshot_sha256="5" * 64,
        inventory_high_watermark=17,
        scan=FakeScan(),
        status="awaiting_human_review",
        quality_coverage=quality,
        candidate_review_source_authority=source_binding,
        development_authority_sha256="f" * 64,
        source_development_authority_sha256="e" * 64,
        execution_development_authority_sha256="f" * 64,
        development_authority_rollover_sha256="9" * 64,
    )
    validated_seal = SimpleNamespace(
        seal_root=(
            candidate_review_root / "seals" / ("a" * 64)
        ),
    )

    monkeypatch.setattr(
        module,
        "prepare_startup_environment",
        lambda config, root: config.data_root,
    )
    monkeypatch.setattr(module, "SingleInstanceGuard", lambda *args: FakeGuard())
    monkeypatch.setattr(module, "SqliteRuntime", FakeRuntime)
    monkeypatch.setattr(module, "SqliteLockedSetRepository", FakeRepository)
    live_development_authority = SimpleNamespace(
        authority_sha256="f" * 64,
    )
    source_development_authority = SimpleNamespace(
        authority_sha256="e" * 64,
        exclusion_snapshot=SimpleNamespace(
            canonical_sha256="1" * 64,
        ),
    )
    authority_rollover = SimpleNamespace(
        rollover_sha256="9" * 64,
    )
    monkeypatch.setattr(
        module,
        "build_current_formal_development_authority",
        lambda runtime, **kwargs: live_development_authority,
    )
    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda *args, **kwargs: source_development_authority,
    )
    monkeypatch.setattr(
        module,
        "load_development_authority_rollover",
        lambda *args, **kwargs: authority_rollover,
    )

    def validate_seal(**values: object) -> object:
        state["seal_validation"] = values
        return validated_seal

    def prepare_candidate(**values: object) -> object:
        state["prepare_candidate"] = values
        return prepared

    monkeypatch.setattr(module, "validate_candidate_review_seal", validate_seal)
    monkeypatch.setattr(
        module,
        "prepare_candidate_review_formal_release",
        prepare_candidate,
    )
    monkeypatch.setattr(
        module,
        "prepare_formal_locked_set_release",
        lambda **_: pytest.fail(
            "candidate preparation must not use the unsealed manifest entrypoint"
        ),
    )
    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        lambda **_: pytest.fail("candidate preparation must not build OCR"),
    )

    assert module.main(arguments) == 0

    output = json.loads((tmp_path / "candidate-review-package.json").read_text(encoding="utf-8"))
    assert state["seal_validation"] == {
        "review_data_root": candidate_review_root,
        "seal_sha256": "a" * 64,
    }
    assert state["prepare_candidate"] == {
        "repository": state["repository"],
        "candidate_review_seal": validated_seal,
        "source_development_authority": source_development_authority,
        "live_development_authority": live_development_authority,
        "development_authority_rollover": authority_rollover,
        "expected_source_development_authority_sha256": "e" * 64,
        "expected_execution_development_authority_sha256": "f" * 64,
        "actor_id": "developer-test",
    }
    assert state["runtime"].closed is True
    assert output["dataset_id"] == "candidate-sealed-fixture"
    assert output["source_data_classification"] == ("sealed_human_reviewed_candidate")
    assert output["classification_authority"] == ("immutable_candidate_review_seal")
    assert output["candidate_review_source_authority"] == source_binding
    assert output["seal_sha256"] == "a" * 64
    assert output["development_authority_sha256"] == "f" * 64
    assert output["source_development_authority_sha256"] == "e" * 64
    assert output["execution_development_authority_sha256"] == "f" * 64
    assert output["development_authority_rollover_sha256"] == "9" * 64
    assert output["quality_coverage"] == quality
    assert output["formal_accuracy_claim"] is False
    assert output["review_contract"]["tuning_prohibited"] is True


def test_prepare_candidate_rejects_overlapping_source_and_target_roots(
    tmp_path: Path,
) -> None:
    candidate_review_root = (tmp_path / "candidate-review").resolve()
    candidate_review_root.mkdir()
    development_root = (tmp_path / "development-data").resolve()
    development_root.mkdir()
    protected_target = candidate_review_root / "formal-data"

    with pytest.raises(RuntimeError, match="must be independent"):
        module.main(
            [
                "prepare-candidate",
                "--data-root",
                str(protected_target),
                "--candidate-review-root",
                str(candidate_review_root),
                "--development-data-root",
                str(development_root),
                "--development-authority-sha256",
                "f" * 64,
                "--source-development-authority-sha256",
                "e" * 64,
                "--development-authority-rollover",
                str((tmp_path / "authority-rollover.json").resolve()),
                "--seal-sha256",
                "a" * 64,
                "--actor",
                "developer-test",
                "--review-output",
                str(tmp_path / "should-not-exist.json"),
            ]
        )

    assert not (tmp_path / "should-not-exist.json").exists()


def test_evaluate_closes_backend_and_returns_failure_without_formal_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    state: dict[str, Any] = {}

    class FakeGuard:
        instance_id = "locked-cli-test-instance"

        def __enter__(self) -> FakeGuard:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    class FakeRuntime:
        def __init__(self, **values: object) -> None:
            state["runtime"] = self
            self.data_root = Path(str(values["data_root"]))
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeBackend:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeRepository:
        def __init__(self, **_: object) -> None:
            pass

        def get_dataset(self, dataset_id: str) -> SimpleNamespace:
            assert dataset_id == "locked-cli-fixture"
            return SimpleNamespace(
                state="formal_evaluated",
                record_version=5,
            )

    backend = FakeBackend()
    evaluation = SimpleNamespace(
        dataset_id="locked-cli-fixture",
        evaluation_id="evaluation-001",
        idempotency_key="locked-cli-evaluation",
        committed_report_sha256="a" * 64,
        gate_passed=False,
        formal_report=True,
        formal_accuracy_claim=False,
    )
    service_result = SimpleNamespace(
        evaluation=evaluation,
        committed_report={
            "formal_report": True,
            "formal_accuracy_claim": False,
        },
        replayed=False,
    )
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        module,
        "prepare_startup_environment",
        lambda config, root: config.data_root,
    )
    monkeypatch.setattr(
        module,
        "SingleInstanceGuard",
        lambda *args: FakeGuard(),
    )
    monkeypatch.setattr(module, "SqliteRuntime", FakeRuntime)
    live_development_authority = SimpleNamespace(
        authority_sha256="f" * 64,
    )
    source_development_authority = SimpleNamespace(
        authority_sha256="e" * 64,
        exclusion_snapshot=SimpleNamespace(
            canonical_sha256="1" * 64,
        ),
    )
    monkeypatch.setattr(
        module,
        "build_current_formal_development_authority",
        lambda runtime, **kwargs: live_development_authority,
    )
    monkeypatch.setattr(
        module,
        "load_persisted_formal_development_authority",
        lambda *args, **kwargs: source_development_authority,
    )
    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        lambda **kwargs: backend,
    )
    monkeypatch.setattr(module, "SqliteLockedSetRepository", FakeRepository)
    monkeypatch.setattr(
        module,
        "validate_formal_locked_set_review",
        lambda **kwargs: SimpleNamespace(status="ready_for_ocr_evaluation"),
    )

    def fake_evaluate(**kwargs: object) -> SimpleNamespace:
        captured.update(kwargs)
        return service_result

    monkeypatch.setattr(
        module,
        "evaluate_formal_locked_set_release",
        fake_evaluate,
    )

    exit_code = module.main(_evaluate_arguments(tmp_path))
    output = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert exit_code == 1
    assert backend.closed is True
    assert state["runtime"].closed is True
    assert captured["ocr_backend"] is backend
    assert captured["dataset_id"] == "locked-cli-fixture"
    assert captured["review_package"] == {
        "schema_version": 1,
            "dataset_id": "locked-cli-fixture",
            "development_authority_sha256": "f" * 64,
            "source_development_authority_sha256": "e" * 64,
            "quality_coverage": {
            "schema_version": 1,
            "dataset_id": "locked-cli-fixture",
        },
    }
    assert "template_repository" not in captured
    assert "evidence_store" not in captured
    assert "repository_root" not in captured
    assert captured["live_development_authority"] is (
        live_development_authority
    )
    assert output["gate_passed"] is False
    assert output["formal_report"] is True
    assert output["formal_accuracy_claim"] is False
    assert output["locked_set_gate_passed"] is False
    assert output["loop_7_accepted"] is False
    assert output["dataset_record_version"] == 5
    assert output["committed_report"] == service_result.committed_report


def test_evaluate_gate_requires_observed_and_derived_committed_boundaries() -> None:
    evaluation = SimpleNamespace(
        gate_passed=True,
        formal_report=True,
        formal_accuracy_claim=True,
        formal_accuracy_claim_scope="observed_real_locked_set_only",
        derived_scenario_accuracy_claim=False,
        derived_prevalence_claim=False,
    )
    committed_report: dict[str, object] = {
        "gate_passed": True,
        "formal_report": True,
        "formal_accuracy_claim": True,
        "formal_accuracy_claim_scope": "observed_real_locked_set_only",
        "observed_locked_set_gate": {"passed": True},
        "derived_adversarial_gate": {"passed": True},
        "derived_scenario_accuracy_claim": False,
        "derived_prevalence_claim": False,
    }

    assert (
        module._committed_locked_set_gate_passed(
            evaluation=evaluation,
            committed_report=committed_report,
        )
        is True
    )
    mutations: tuple[tuple[str, object], ...] = (
        ("formal_accuracy_claim_scope", "none"),
        ("observed_locked_set_gate", {"passed": False}),
        ("derived_adversarial_gate", {"passed": False}),
        ("derived_scenario_accuracy_claim", True),
        ("derived_prevalence_claim", True),
    )
    for field, replacement in mutations:
        changed = dict(committed_report)
        changed[field] = replacement
        assert (
            module._committed_locked_set_gate_passed(
                evaluation=evaluation,
                committed_report=changed,
            )
            is False
        )
    evaluation_mutations: tuple[tuple[str, object], ...] = (
        ("formal_accuracy_claim_scope", "none"),
        ("derived_scenario_accuracy_claim", True),
        ("derived_prevalence_claim", True),
    )
    for field, replacement in evaluation_mutations:
        changed_evaluation = SimpleNamespace(
            gate_passed=True,
            formal_report=True,
            formal_accuracy_claim=True,
            formal_accuracy_claim_scope=(
                replacement
                if field == "formal_accuracy_claim_scope"
                else "observed_real_locked_set_only"
            ),
            derived_scenario_accuracy_claim=(
                replacement if field == "derived_scenario_accuracy_claim" else False
            ),
            derived_prevalence_claim=(
                replacement if field == "derived_prevalence_claim" else False
            ),
        )
        assert (
            module._committed_locked_set_gate_passed(
                evaluation=changed_evaluation,
                committed_report=committed_report,
            )
            is False
        )


def test_validate_review_package_is_offline_and_does_not_build_ocr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path, dataset_root = _write_locked_set(tmp_path / "fixture")
    data_root = (tmp_path / "application-data").resolve()
    review_path = tmp_path / "review-package.json"
    bound_review_path = tmp_path / "bound-review-package.json"
    validation_path = tmp_path / "review-validation.json"
    assert (
        module.main(
            [
                "prepare",
                "--data-root",
                str(data_root),
                "--manifest",
                str(manifest_path),
                "--dataset-root",
                str(dataset_root),
                "--actor",
                "developer-test",
                "--review-output",
                str(review_path),
            ]
        )
        == 0
    )
    review = json.loads(review_path.read_text(encoding="utf-8"))
    assert review["candidates"] == []
    prepared_suite = review["quality_coverage"]["derived_adversarial_suite"]
    _complete_review_package(
        review_path=review_path,
        manifest_path=manifest_path,
    )
    _register_candidate_source_authority_for_test(
        data_root=data_root,
        review_path=review_path,
    )
    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        lambda **kwargs: pytest.fail("review binding and validation must not build OCR"),
    )
    assert (
        module.main(
            [
                "bind-review",
                "--data-root",
                str(data_root),
                "--review-package",
                str(review_path),
                "--output",
                str(bound_review_path),
            ]
        )
        == 0
    )
    bound_review = json.loads(bound_review_path.read_text(encoding="utf-8"))
    assert all(
        len(entry["review_evidence_sha256"]) == 64
        for entry in bound_review["quality_coverage"]["entries"]
    )
    assert bound_review["quality_coverage"]["derived_adversarial_suite"] == prepared_suite
    assert bound_review["quality_coverage"]["quality_coverage_sha256"] == (
        module.locked_set_quality_coverage_sha256(bound_review["quality_coverage"])
    )
    exit_code = module.main(
        [
            "validate",
            "--data-root",
            str(data_root),
            "--dataset-id",
            "locked-cli-fixture",
            "--review-package",
            str(bound_review_path),
            "--output",
            str(validation_path),
        ]
    )
    output = json.loads(validation_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert output["status"] == "ready_for_ocr_evaluation"
    assert output["ready_for_ocr_evaluation"] is True
    assert output["quality_entry_count"] == len(
        module.REQUIRED_NATURAL_QUALITY_CONDITIONS
    )
    assert output["derived_adversarial_scenario_count"] == 4
    assert output["derived_adversarial_suite_sha256"] == (prepared_suite["suite_sha256"])
    assert output["formal_accuracy_claim"] is False
    assert output["loop_7_accepted"] is False


def test_bind_review_rejects_a_rehashed_changed_derived_suite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path, dataset_root = _write_locked_set(tmp_path / "fixture")
    data_root = (tmp_path / "application-data").resolve()
    review_path = tmp_path / "review-package.json"
    output_path = tmp_path / "bound-review-package.json"
    assert (
        module.main(
            [
                "prepare",
                "--data-root",
                str(data_root),
                "--manifest",
                str(manifest_path),
                "--dataset-root",
                str(dataset_root),
                "--actor",
                "developer-test",
                "--review-output",
                str(review_path),
            ]
        )
        == 0
    )
    _complete_review_package(
        review_path=review_path,
        manifest_path=manifest_path,
    )
    _register_candidate_source_authority_for_test(
        data_root=data_root,
        review_path=review_path,
    )
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["quality_coverage"]["derived_adversarial_suite"]["scenarios"][0][
        "loading_slot_image_sha256"
    ] = "1" * 64
    suite = review["quality_coverage"]["derived_adversarial_suite"]
    suite["suite_sha256"] = module._canonical_sha256(
        {key: value for key, value in suite.items() if key != "suite_sha256"}
    )
    review["quality_coverage"]["quality_coverage_sha256"] = (
        module.locked_set_quality_coverage_sha256(review["quality_coverage"])
    )
    review_path.write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        lambda **kwargs: pytest.fail("bind-review must not build OCR"),
    )

    with pytest.raises(RuntimeError, match="quality coverage"):
        module.main(
            [
                "bind-review",
                "--data-root",
                str(data_root),
                "--review-package",
                str(review_path),
                "--output",
                str(output_path),
            ]
        )

    assert not output_path.exists()


def test_bind_review_rejects_changed_candidate_sealed_quality_before_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path, dataset_root = _write_locked_set(tmp_path / "fixture")
    data_root = (tmp_path / "application-data").resolve()
    review_path = tmp_path / "candidate-review-package.json"
    output_path = tmp_path / "bound-review-package.json"
    assert (
        module.main(
            [
                "prepare",
                "--data-root",
                str(data_root),
                "--manifest",
                str(manifest_path),
                "--dataset-root",
                str(dataset_root),
                "--actor",
                "developer-test",
                "--review-output",
                str(review_path),
            ]
        )
        == 0
    )
    _complete_review_package(
        review_path=review_path,
        manifest_path=manifest_path,
    )
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["command"] = "prepare-candidate"
    review["candidate_review_source_authority"] = {
        "schema_version": 1,
        "seal_sha256": "a" * 64,
        "package_sha256": "b" * 64,
        "record_set_sha256": "c" * 64,
        "review_history_authority_sha256": "d" * 64,
        "source_authority_sha256": "e" * 64,
    }
    quality = review["quality_coverage"]
    for entry in quality["entries"]:
        entry["review_evidence_sha256"] = module.quality_review_evidence_sha256(
            dataset_id=review["dataset_id"],
            manifest_sha256=review["manifest_sha256"],
            entry=entry,
        )
    quality["quality_coverage_sha256"] = module.locked_set_quality_coverage_sha256(quality)
    quality["entries"][0]["reviewer_id"] = "changed-after-seal"
    review_path.write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "prepare_startup_environment",
        lambda *_: pytest.fail("tampered candidate quality must fail before runtime startup"),
    )

    with pytest.raises(
        RuntimeError,
        match="sealed candidate-review quality coverage changed",
    ):
        module.main(
            [
                "bind-review",
                "--data-root",
                str(data_root),
                "--review-package",
                str(review_path),
                "--output",
                str(output_path),
            ]
        )

    assert not output_path.exists()


def test_bind_review_refuses_output_inside_application_data(
    tmp_path: Path,
) -> None:
    manifest_path, dataset_root = _write_locked_set(tmp_path / "fixture")
    data_root = (tmp_path / "application-data").resolve()
    review_path = tmp_path / "review-package.json"
    assert (
        module.main(
            [
                "prepare",
                "--data-root",
                str(data_root),
                "--manifest",
                str(manifest_path),
                "--dataset-root",
                str(dataset_root),
                "--actor",
                "developer-test",
                "--review-output",
                str(review_path),
            ]
        )
        == 0
    )
    _complete_review_package(
        review_path=review_path,
        manifest_path=manifest_path,
    )
    protected_output = data_root / "bound-review.json"

    with pytest.raises(RuntimeError, match="overlaps protected"):
        module.main(
            [
                "bind-review",
                "--data-root",
                str(data_root),
                "--review-package",
                str(review_path),
                "--output",
                str(protected_output),
            ]
        )

    assert not protected_output.exists()


def test_invalidate_is_offline_and_never_builds_ocr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    state: dict[str, Any] = {}

    class FakeGuard:
        instance_id = "locked-cli-test-instance"

        def __enter__(self) -> FakeGuard:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    class FakeRuntime:
        def __init__(self, **_: object) -> None:
            state["runtime"] = self
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeRepository:
        def __init__(self, **_: object) -> None:
            state["repository"] = self

        def invalidate_locked_set(self, **kwargs: object) -> SimpleNamespace:
            state["request"] = kwargs
            return SimpleNamespace(
                dataset=SimpleNamespace(
                    dataset_id="locked-cli-fixture",
                    state="invalidated_to_development",
                    record_version=5,
                ),
                invalidation=SimpleNamespace(
                    invalidation_id="invalidation-001",
                    influence_kind="template",
                    reason="Locked-set evidence influenced a template change.",
                    actor_id="developer-test",
                    idempotency_key="locked-cli-invalidation",
                    created_at="2026-07-25T12:00:00+00:00",
                ),
                applied=True,
            )

    monkeypatch.setattr(
        module,
        "prepare_startup_environment",
        lambda config, root: data_root,
    )
    monkeypatch.setattr(module, "SingleInstanceGuard", lambda *args: FakeGuard())
    monkeypatch.setattr(module, "SqliteRuntime", FakeRuntime)
    monkeypatch.setattr(module, "SqliteLockedSetRepository", FakeRepository)
    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        lambda **kwargs: pytest.fail("invalidate must not build OCR"),
    )

    exit_code = module.main(_invalidate_arguments(tmp_path))
    output = json.loads((tmp_path / "invalidation.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert state["runtime"].closed is True
    assert state["request"] == {
        "dataset_id": "locked-cli-fixture",
        "expected_record_version": 4,
        "influence_kind": "template",
        "reason": "Locked-set evidence influenced a template change.",
        "actor_id": "developer-test",
        "idempotency_key": "locked-cli-invalidation",
    }
    assert output["dataset_state"] == "invalidated_to_development"
    assert output["record_version"] == 5
    assert output["applied"] is True
    assert output["formal_accuracy_claim"] is False
    assert output["platform_access"] is False
