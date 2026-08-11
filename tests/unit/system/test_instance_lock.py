from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from dahe.system.instance_lock import AlreadyRunningError, SingleInstanceGuard

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only contract")


def test_second_instance_for_same_data_root_is_rejected(tmp_path: Path) -> None:
    data_root = tmp_path / "profile"
    first = SingleInstanceGuard(data_root=data_root, port=8877, application_version="0.1.0")
    second = SingleInstanceGuard(data_root=data_root, port=8877, application_version="0.1.0")

    with first:
        metadata_before = first.metadata_path.read_text(encoding="utf-8")
        first_instance_id = first.instance_id
        with pytest.raises(AlreadyRunningError):
            second.acquire()
        assert first.metadata_path.read_text(encoding="utf-8") == metadata_before

    with second:
        assert json.loads(second.metadata_path.read_text(encoding="utf-8"))["pid"] > 0
        assert second.previous_instance_id == first_instance_id


def test_different_data_roots_can_hold_independent_instances(tmp_path: Path) -> None:
    first = SingleInstanceGuard(tmp_path / "one", 8877, "0.1.0")
    second = SingleInstanceGuard(tmp_path / "two", 8877, "0.1.0")

    with first, second:
        assert first.mutex_name != second.mutex_name


def test_stale_diagnostic_file_is_not_treated_as_an_active_instance(tmp_path: Path) -> None:
    data_root = tmp_path / "profile"
    runtime = data_root / "runtime"
    runtime.mkdir(parents=True)
    metadata = runtime / "instance.json"
    metadata.write_text("{not valid json", encoding="utf-8")

    with SingleInstanceGuard(data_root, 8877, "0.1.0") as guard:
        current = json.loads(metadata.read_text(encoding="utf-8"))
        assert current["instance_id"] == guard.instance_id
