from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.verification.loop9_dataset_isolation import (
    Loop9DatasetIsolationError,
)
from tools import loop9_build_exclusion_authority as module

EXPECTED_BUILD = "a" * 64
EXPECTED_SETTLEMENT_CONTRACT = "b" * 64
EXPECTED_DAILY_CONTRACT = "c" * 64
EXPECTED_SETTLEMENT_SELECTION = "d" * 64
EXPECTED_DAILY_SELECTION = "e" * 64


def _arguments(tmp_path: Path) -> list[str]:
    source = (tmp_path / "source-authority.json").resolve()
    loop7 = (tmp_path / "loop7.json").resolve()
    for path in (source, loop7):
        path.write_text("{}", encoding="utf-8")
    return [
        "--data-root",
        str(tmp_path.resolve()),
        "--source-development-authority",
        str(source),
        "--child-inventory",
        str(loop7),
        "--output",
        str((tmp_path / "full-history-authority.json").resolve()),
    ]


@dataclass(frozen=True)
class _FakeAuthority:
    canonical_sha256: str = "f" * 64
    source_completeness_sha256: str = "1" * 64
    child_inventory_count: int = 2
    child_index_head_sha256: str = "2" * 64

    def to_payload(self) -> dict[str, object]:
        return {
            "canonical_sha256": self.canonical_sha256,
            "child_inventory_count": self.child_inventory_count,
            "source_completeness_sha256": self.source_completeness_sha256,
        }


@dataclass(frozen=True)
class _FakeInventory:
    name: str
    canonical_sha256: str

    def to_payload(self) -> dict[str, object]:
        return {
            "canonical_sha256": self.canonical_sha256,
            "name": self.name,
        }


def test_cli_builds_canonical_authority_from_source_and_all_children(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_authority = object()
    source_boundary = object()
    loaded_children: list[Path] = []
    appended: list[dict[str, object]] = []
    loaded: dict[str, object] = {}
    validated: dict[str, object] = {}

    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda _path: source_authority,
    )
    monkeypatch.setattr(
        module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda value: source_boundary
        if value is source_authority
        else pytest.fail("unexpected source authority"),
    )

    registry_child = _FakeInventory(
        name="registry-development",
        canonical_sha256="3" * 64,
    )
    explicit_child = _FakeInventory(
        name="loop7.json",
        canonical_sha256="4" * 64,
    )

    def load_child(path: Path) -> object:
        loaded_children.append(path)
        return explicit_child

    monkeypatch.setattr(module, "load_loop9_exclusion_inventory", load_child)
    monkeypatch.setattr(
        module,
        "load_loop9_development_exclusion_registry",
        lambda _data_root: (registry_child,),
    )
    monkeypatch.setattr(
        module,
        "validate_loop9_exclusion_producer_registries",
        lambda **values: validated.update(values),
    )
    preflight: dict[str, object] = {}
    monkeypatch.setattr(
        module,
        "build_loop9_full_history_exclusion_authority",
        lambda **values: preflight.update(values) or _FakeAuthority(),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: EXPECTED_BUILD,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_SETTLEMENT_CONTRACT
            ),
            selection_sha256=EXPECTED_SETTLEMENT_SELECTION,
        ),
    )
    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_DAILY_CONTRACT
            ),
            selection_sha256=EXPECTED_DAILY_SELECTION,
        ),
    )

    def append(**values: object) -> object:
        appended.append(values)
        return object()

    monkeypatch.setattr(
        module,
        "append_loop9_exclusion_child",
        append,
    )
    monkeypatch.setattr(
        module,
        "load_current_loop9_full_history_exclusion_authority",
        lambda **values: loaded.update(values) or _FakeAuthority(),
    )
    monkeypatch.setattr(
        module,
        "persist_loop9_full_history_exclusion_authority",
        lambda **_values: (
            tmp_path
            / "verification"
            / "loop9-exclusion-authority"
            / "authorities"
            / f"{'f' * 64}.json"
        ),
    )
    arguments = _arguments(tmp_path)

    assert module.main(arguments) == 0

    output = Path(arguments[-1])
    assert json.loads(output.read_text(encoding="utf-8")) == (
        _FakeAuthority().to_payload()
    )
    assert loaded_children == [(tmp_path / "loop7.json").resolve()]
    assert validated == {
        "data_root": tmp_path.resolve(),
        "child_inventories": (
            registry_child,
            explicit_child,
        ),
    }
    assert [values["child_inventory"] for values in appended] == [
        registry_child,
        explicit_child,
    ]
    expected_common = {
        "data_root": tmp_path.resolve(),
        "expected_current_build_sha256": EXPECTED_BUILD,
        "expected_daily_contract_sha256": EXPECTED_DAILY_CONTRACT,
        "expected_daily_selection_sha256": EXPECTED_DAILY_SELECTION,
        "expected_settlement_contract_sha256": (
            EXPECTED_SETTLEMENT_CONTRACT
        ),
        "expected_settlement_selection_sha256": (
            EXPECTED_SETTLEMENT_SELECTION
        ),
        "source_boundary": source_boundary,
    }
    assert all(
        {
            key: value
            for key, value in values.items()
            if key != "child_inventory"
        }
        == expected_common
        for values in appended
    )
    assert loaded == expected_common
    assert preflight == {
        **{
            key: value
            for key, value in expected_common.items()
            if key != "data_root"
        },
        "child_inventories": (
            registry_child,
            explicit_child,
        ),
    }
    assert json.loads(capsys.readouterr().out) == {
        "canonical_sha256": "f" * 64,
        "child_inventory_count": 2,
        "child_index_head_sha256": "2" * 64,
        "output": output.name,
        "source_completeness_sha256": "1" * 64,
    }

    with pytest.raises(Loop9DatasetIsolationError, match="already exists"):
        module.main(arguments)


def test_cli_preflight_failure_writes_no_exclusion_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _arguments(tmp_path)
    development = _FakeInventory(
        name="development",
        canonical_sha256="3" * 64,
    )
    appended: list[object] = []

    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda _value: object(),
    )
    monkeypatch.setattr(
        module,
        "load_loop9_exclusion_inventory",
        lambda _path: development,
    )
    monkeypatch.setattr(
        module,
        "load_loop9_development_exclusion_registry",
        lambda _root: (development,),
    )
    monkeypatch.setattr(
        module,
        "validate_loop9_exclusion_producer_registries",
        lambda **_values: None,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_SETTLEMENT_CONTRACT
            ),
            selection_sha256=EXPECTED_SETTLEMENT_SELECTION,
        ),
    )
    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_DAILY_CONTRACT
            ),
            selection_sha256=EXPECTED_DAILY_SELECTION,
        ),
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: EXPECTED_BUILD,
    )
    monkeypatch.setattr(
        module,
        "build_loop9_full_history_exclusion_authority",
        lambda **_values: (_ for _ in ()).throw(
            Loop9DatasetIsolationError("missing legacy_loop7")
        ),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "append_loop9_exclusion_child",
        lambda **values: appended.append(values),
    )

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="missing legacy_loop7",
    ):
        module.main(arguments)

    assert appended == []


def test_cli_deduplicates_the_same_child_before_preflight_and_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _arguments(tmp_path)
    duplicate = _FakeInventory(
        name="same-child",
        canonical_sha256="3" * 64,
    )
    loop7 = _FakeInventory(
        name="loop7",
        canonical_sha256="4" * 64,
    )
    appended: list[object] = []
    preflight_children: list[tuple[object, ...]] = []

    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda _value: object(),
    )
    monkeypatch.setattr(
        module,
        "load_loop9_exclusion_inventory",
        lambda _path: loop7,
    )
    monkeypatch.setattr(
        module,
        "load_loop9_development_exclusion_registry",
        lambda _root: (duplicate, duplicate),
    )
    monkeypatch.setattr(
        module,
        "validate_loop9_exclusion_producer_registries",
        lambda **_values: None,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_SETTLEMENT_CONTRACT
            ),
            selection_sha256=EXPECTED_SETTLEMENT_SELECTION,
        ),
    )
    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_DAILY_CONTRACT
            ),
            selection_sha256=EXPECTED_DAILY_SELECTION,
        ),
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: EXPECTED_BUILD,
    )

    def preflight(**values: object) -> _FakeAuthority:
        preflight_children.append(values["child_inventories"])  # type: ignore[arg-type]
        return _FakeAuthority()

    monkeypatch.setattr(
        module,
        "build_loop9_full_history_exclusion_authority",
        preflight,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "append_loop9_exclusion_child",
        lambda **values: appended.append(values["child_inventory"]),
    )
    monkeypatch.setattr(
        module,
        "load_current_loop9_full_history_exclusion_authority",
        lambda **_values: _FakeAuthority(),
    )
    monkeypatch.setattr(
        module,
        "persist_loop9_full_history_exclusion_authority",
        lambda **_values: tmp_path / "persisted.json",
    )

    assert module.main(arguments) == 0
    assert preflight_children == [(duplicate, loop7)]
    assert appended == [duplicate, loop7]


def test_existing_append_order_is_preserved_when_a_new_sha_sorts_first() -> None:
    existing_first = _FakeInventory(
        name="existing-first",
        canonical_sha256="8" * 64,
    )
    existing_second = _FakeInventory(
        name="existing-second",
        canonical_sha256="9" * 64,
    )
    newly_registered = _FakeInventory(
        name="newly-registered",
        canonical_sha256="1" * 64,
    )

    ordered = module._merge_child_inventories_preserving_append_order(
        existing=(existing_first, existing_second),
        candidates=(newly_registered, existing_first, existing_second),
    )

    assert ordered == (
        existing_first,
        existing_second,
        newly_registered,
    )


def test_existing_append_child_cannot_disappear_from_registry() -> None:
    existing = _FakeInventory(
        name="existing",
        canonical_sha256="8" * 64,
    )

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="existing exclusion child is missing",
    ):
        module._merge_child_inventories_preserving_append_order(
            existing=(existing,),
            candidates=(),
        )


def test_cli_rejects_relative_paths_and_abbreviated_options(
    tmp_path: Path,
) -> None:
    relative = _arguments(tmp_path)
    relative[1] = "relative"
    with pytest.raises(SystemExit):
        module.main(relative)

    abbreviated = _arguments(tmp_path)
    abbreviated[0] = "--data"
    with pytest.raises(SystemExit):
        module.main(abbreviated)
