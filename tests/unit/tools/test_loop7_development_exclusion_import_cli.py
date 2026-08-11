from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from tools import loop7_development_exclusion_import as module

_REVIEW_AUTHORITY_PAYLOAD: dict[str, object] = {
    "schema_version": 1,
    "kind": "test-review-authority",
}
_REVIEW_AUTHORITY_SHA256 = module._canonical_sha256(_REVIEW_AUTHORITY_PAYLOAD)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_image(path: Path, color: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (20, 16), color).save(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _development_snapshot(
    *,
    package_sha256: str = _hash("package"),
    dataset_id: str = "development-candidate-001",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "candidate_review_development_snapshot",
        "development_only": True,
        "formal_release_eligible": False,
        "reason": "Labels influenced template development.",
        "dataset_id": dataset_id,
        "package_sha256": package_sha256,
        "record_count": 50,
        "record_set_sha256": _hash("record-set"),
        "history_record_count": 57,
        "review_history_authority_sha256": _REVIEW_AUTHORITY_SHA256,
        "verified_image_count": 100,
        "verified_image_set_sha256": _hash("verified-images"),
        "manifest_sha256": _hash("manifest"),
        "quality_coverage_sha256": _hash("quality"),
        "source_authority_sha256": _hash("source-authority"),
    }
    payload["snapshot_sha256"] = module._canonical_sha256(payload)
    return payload


def _write_snapshot(
    path: Path,
    payload: dict[str, object] | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            payload or _development_snapshot(),
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _arguments(
    *,
    source: Path,
    snapshot: Path,
    target: Path,
    image_roots: tuple[Path, ...],
) -> list[str]:
    values = [
        "--review-data-root",
        str(source),
        "--development-snapshot",
        str(snapshot),
        "--data-root",
        str(target),
    ]
    for root in image_roots:
        values.extend(["--image-root", str(root)])
    return values


def test_parser_requires_absolute_paths_and_image_roots(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as relative_error:
        module._parser().parse_args(
            [
                "--review-data-root",
                "relative-source",
                "--development-snapshot",
                str((tmp_path / "snapshot.json").resolve()),
                "--data-root",
                str((tmp_path / "target").resolve()),
                "--image-root",
                str((tmp_path / "images").resolve()),
            ]
        )
    with pytest.raises(SystemExit) as missing_root_error:
        module._parser().parse_args(
            [
                "--review-data-root",
                str((tmp_path / "source").resolve()),
                "--development-snapshot",
                str((tmp_path / "snapshot.json").resolve()),
                "--data-root",
                str((tmp_path / "target").resolve()),
            ]
        )

    assert relative_error.value.code == 2
    assert missing_root_error.value.code == 2


@pytest.mark.parametrize(
    "case",
    ("target-in-source", "source-in-target", "duplicate-image-root"),
)
def test_root_contract_rejects_overlap_and_duplicate_parameters(
    tmp_path: Path,
    case: str,
) -> None:
    source = (tmp_path / "source").resolve()
    source.mkdir()
    snapshot = _write_snapshot((tmp_path / "snapshot.json").resolve())
    first_images = (tmp_path / "images").resolve()
    first_images.mkdir()
    target = (tmp_path / "target").resolve()
    image_roots = (first_images,)
    if case == "target-in-source":
        target = source / "target"
    elif case == "source-in-target":
        target = tmp_path.resolve()
    else:
        image_roots = (first_images, first_images)

    with pytest.raises(
        module.DevelopmentExclusionImportError,
        match=r"overlap|duplicate",
    ):
        module._validate_root_contract(
            review_data_root=source,
            development_snapshot=snapshot,
            data_root=target,
            image_roots=image_roots,
        )


def test_development_snapshot_requires_nonformal_complete_hash_bindings(
    tmp_path: Path,
) -> None:
    path = _write_snapshot(tmp_path / "development.json")
    package = SimpleNamespace(
        canonical_sha256=_hash("package"),
    )
    authority = SimpleNamespace(
        package_sha256=_hash("package"),
        payload=_REVIEW_AUTHORITY_PAYLOAD,
        canonical_sha256=_REVIEW_AUTHORITY_SHA256,
        latest_records=tuple(range(50)),
        history_records=tuple(range(57)),
    )
    formal_export = SimpleNamespace(
        manifest=SimpleNamespace(dataset_id="development-candidate-001"),
        manifest_sha256=_hash("manifest"),
        record_set_sha256=_hash("record-set"),
        source_authority_sha256=_hash("source-authority"),
        quality_coverage_sha256=_hash("quality"),
        source_authority_payload={
            "record_count": 50,
            "verified_image_count": 100,
            "verified_image_set_sha256": _hash("verified-images"),
        },
    )

    validated = module._validate_development_snapshot(
        path,
        package=package,
        authority=authority,
        formal_export=formal_export,
    )

    assert validated.snapshot_sha256 == _development_snapshot()["snapshot_sha256"]
    assert validated.dataset_id == "development-candidate-001"

    for field, forged_value in (
        ("formal_release_eligible", True),
        ("development_only", False),
        ("record_set_sha256", _hash("forged-records")),
        ("snapshot_sha256", _hash("forged-snapshot")),
    ):
        forged = _development_snapshot()
        forged[field] = forged_value
        forged_path = _write_snapshot(
            tmp_path / f"{field}.json",
            forged,
        )
        with pytest.raises(
            module.DevelopmentExclusionImportError,
            match=r"snapshot|formal|binding",
        ):
            module._validate_development_snapshot(
                forged_path,
                package=package,
                authority=authority,
                formal_export=formal_export,
            )


def test_prior_image_resolution_requires_every_hash_and_rehashes_files(
    tmp_path: Path,
) -> None:
    root = (tmp_path / "legacy-images").resolve()
    first_hash = _write_image(root / "a" / "first.png", "red")
    second_hash = _write_image(root / "b" / "second.jpg", "blue")
    _write_image(root / "unrelated.png", "green")

    resolved = module._resolve_prior_image_paths(
        image_roots=(root,),
        expected_sha256s=frozenset({first_hash, second_hash}),
    )

    assert set(resolved) == {first_hash, second_hash}
    assert all(path.is_file() for path in resolved.values())
    assert all(module._file_sha256(path) == digest for digest, path in resolved.items())

    resolved[first_hash].write_bytes(b"changed-after-resolution")
    with pytest.raises(
        module.DevelopmentExclusionImportError,
        match="changed",
    ):
        module._read_prior_image(
            resolved[first_hash],
            expected_sha256=first_hash,
        )

    with pytest.raises(
        module.DevelopmentExclusionImportError,
        match="missing",
    ):
        module._resolve_prior_image_paths(
            image_roots=(root,),
            expected_sha256s=frozenset({first_hash, _hash("not-present")}),
        )


def test_path_links_fail_closed_when_supported(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    real_root = tmp_path / "real-images"
    real_root.mkdir()
    linked_root = tmp_path / "linked-images"
    try:
        linked_root.symlink_to(
            real_root,
            target_is_directory=True,
        )
    except OSError:
        pytest.skip("this Windows account cannot create symbolic links")

    with pytest.raises(
        module.DevelopmentExclusionImportError,
        match="link",
    ):
        module._validate_root_contract(
            review_data_root=source.resolve(),
            development_snapshot=_write_snapshot(tmp_path / "snapshot.json"),
            data_root=(tmp_path / "target").resolve(),
            image_roots=(linked_root.absolute(),),
        )


def test_path_link_contract_fails_closed_without_platform_link_privileges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = (tmp_path / "source").resolve()
    image_root = (tmp_path / "images").resolve()
    source.mkdir()
    image_root.mkdir()
    snapshot = _write_snapshot((tmp_path / "snapshot.json").resolve())
    real_is_path_link = module._is_path_link

    def marked_link(path: Path) -> bool:
        return path == image_root or real_is_path_link(path)

    monkeypatch.setattr(module, "_is_path_link", marked_link)

    with pytest.raises(
        module.DevelopmentExclusionImportError,
        match="link",
    ):
        module._validate_root_contract(
            review_data_root=source,
            development_snapshot=snapshot,
            data_root=(tmp_path / "target").resolve(),
            image_roots=(image_root,),
        )


def test_main_holds_both_guards_and_imports_complete_redacted_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = (tmp_path / "source").resolve()
    target = (tmp_path / "target").resolve()
    image_root = (tmp_path / "prior-images").resolve()
    source.mkdir()
    image_root.mkdir()
    snapshot = _write_snapshot((tmp_path / "development.json").resolve())
    current_images = tuple(_hash(f"current-image-{index}") for index in range(100))
    current_waybills = tuple(_hash(f"current-waybill-{index}") for index in range(50))
    prior_image = _hash("prior-image")
    prior_waybill = _hash("prior-waybill")
    package = SimpleNamespace(
        canonical_sha256=_hash("package"),
        review_root=source / "review-package",
        images_by_sha256={digest: object() for digest in current_images},
        items=tuple(SimpleNamespace(waybill_identity_sha256=digest) for digest in current_waybills),
    )
    latest_records = tuple(
        SimpleNamespace(review_payload={"reviewer_id": "reviewer-fixed"}) for _ in range(50)
    )
    authority = SimpleNamespace(
        package_sha256=_hash("package"),
        payload=_REVIEW_AUTHORITY_PAYLOAD,
        canonical_sha256=_REVIEW_AUTHORITY_SHA256,
        latest_records=latest_records,
        history_records=tuple(range(57)),
    )
    formal_export = SimpleNamespace(
        manifest=SimpleNamespace(dataset_id="development-candidate-001"),
        manifest_sha256=_hash("manifest"),
        record_set_sha256=_hash("record-set"),
        source_authority_sha256=_hash("source-authority"),
        quality_coverage_sha256=_hash("quality"),
        source_authority_payload={
            "record_count": 50,
            "verified_image_count": 100,
            "verified_image_set_sha256": _hash("verified-images"),
        },
    )
    external = module.ExternalExclusions(
        canonical_sha256=_hash("external-exclusions"),
        image_sha256s=frozenset({prior_image}),
        waybill_identity_sha256s=frozenset({prior_waybill}),
    )
    active_roots: set[Path] = set()
    guard_events: list[tuple[str, Path]] = []

    class FakeGuard:
        def __init__(
            self,
            data_root: Path,
            port: int,
            application_version: str,
        ) -> None:
            del port, application_version
            self.data_root = data_root
            self.instance_id = "source-instance" if data_root == source else "target-instance"

        def __enter__(self) -> FakeGuard:
            active_roots.add(self.data_root)
            guard_events.append(("enter", self.data_root))
            return self

        def __exit__(
            self,
            exc_type: object,
            exc_value: object,
            traceback: object,
        ) -> None:
            del exc_type, exc_value, traceback
            guard_events.append(("exit", self.data_root))
            active_roots.remove(self.data_root)

    def prepare(config: module.AppConfig, project_root: Path) -> Path:
        del project_root
        data_root = Path(config.data_root)
        data_root.mkdir(parents=True, exist_ok=True)
        return data_root.resolve()

    def load_package(data_root: Path) -> object:
        assert data_root == source
        assert active_roots == {source, target}
        return package

    def read_authority(**kwargs: object) -> object:
        assert kwargs["data_root"] == source
        assert kwargs["instance_id"] == "source-instance"
        assert active_roots == {source, target}
        return authority

    def build_export(**kwargs: object) -> object:
        assert kwargs["package"] is package
        assert kwargs["records"] == latest_records
        assert kwargs["configured_reviewer_id"] == "reviewer-fixed"
        assert kwargs["dataset_id"] == "development-candidate-001"
        return formal_export

    def resolve_prior(**kwargs: object) -> dict[str, Path]:
        assert kwargs["image_roots"] == (image_root,)
        assert kwargs["expected_sha256s"] == frozenset({prior_image})
        return {prior_image: image_root / "prior.png"}

    prepared = tuple(
        SimpleNamespace(image_sha256=digest) for digest in sorted((*current_images, prior_image))
    )

    def prepare_images(**kwargs: object) -> tuple[object, ...]:
        assert kwargs["package"] is package
        assert kwargs["data_root"] == target
        return prepared

    imported_authority: list[module.DevelopmentImportAuthority] = []

    def import_target(**kwargs: object) -> module.DevelopmentExclusionImportOutcome:
        assert active_roots == {source, target}
        assert kwargs["data_root"] == target
        assert kwargs["instance_id"] == "target-instance"
        assert kwargs["images"] == prepared
        imported = kwargs["authority"]
        assert isinstance(imported, module.DevelopmentImportAuthority)
        assert len(imported.development_image_sha256s) == 101
        assert len(imported.prior_waybill_identity_sha256s) == 51
        imported_authority.append(imported)
        return module.DevelopmentExclusionImportOutcome(
            source_authority_sha256=imported.canonical_sha256,
            development_image_count=101,
            prior_waybill_identity_count=51,
            applied=True,
        )

    monkeypatch.setattr(module, "SingleInstanceGuard", FakeGuard)
    monkeypatch.setattr(module, "prepare_startup_environment", prepare)
    monkeypatch.setattr(module, "load_locked_set_review_package", load_package)
    monkeypatch.setattr(module, "_review_authority", read_authority)
    monkeypatch.setattr(module, "build_candidate_review_formal_export", build_export)
    monkeypatch.setattr(module, "_load_external_exclusions", lambda **_: external)
    monkeypatch.setattr(module, "_resolve_prior_image_paths", resolve_prior)
    monkeypatch.setattr(module, "_prepare_import_images", prepare_images)
    monkeypatch.setattr(module, "_import_target", import_target)

    assert (
        module.main(
            _arguments(
                source=source,
                snapshot=snapshot,
                target=target,
                image_roots=(image_root,),
            )
        )
        == 0
    )

    assert active_roots == set()
    assert {event[1] for event in guard_events if event[0] == "enter"} == {
        source,
        target,
    }
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "applied": True,
        "development_image_count": 101,
        "development_image_set_sha256": (imported_authority[0].development_image_set_sha256),
        "import_authority_sha256": imported_authority[0].canonical_sha256,
        "prior_waybill_identity_count": 51,
        "prior_waybill_identity_set_sha256": (
            imported_authority[0].prior_waybill_identity_set_sha256
        ),
        "status": "development_exclusions_imported",
    }
    serialized = json.dumps(result, ensure_ascii=False)
    assert "reviewer-fixed" not in serialized
    assert "development-candidate-001" not in serialized
    assert str(source) not in serialized
    assert str(target) not in serialized
