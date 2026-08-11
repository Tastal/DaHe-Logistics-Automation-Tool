from __future__ import annotations

import dataclasses
from pathlib import Path

from dahe.adapters.sqlite.schema import METADATA
from dahe.domain.audit.manual_actions import (
    ActionRevocation,
    ConfirmNormalAction,
    ProblemConfirmationAction,
)

FORBIDDEN_ACTIVE_FIELDS = {
    "actor",
    "actor_id",
    "employee_id",
    "operator",
    "operator_id",
    "reviewer",
    "reviewer_id",
}


def test_active_manual_action_contract_has_no_human_identity_fields() -> None:
    for action_type in (
        ProblemConfirmationAction,
        ConfirmNormalAction,
        ActionRevocation,
    ):
        fields = {field.name for field in dataclasses.fields(action_type)}
        assert fields.isdisjoint(FORBIDDEN_ACTIVE_FIELDS)


def test_loop8_tables_have_no_human_identity_columns() -> None:
    for table_name in (
        "audit_evidence_revisions",
        "audit_ocr_observations",
        "audit_decision_revisions",
        "audit_review_actions",
        "audit_timeline_events",
    ):
        columns = {column.name.lower() for column in METADATA.tables[table_name].columns}
        assert columns.isdisjoint(FORBIDDEN_ACTIVE_FIELDS)


def test_operator_console_cli_has_no_reviewer_identity_option() -> None:
    source = Path("src/dahe/cli.py").read_text(encoding="utf-8")
    assert "--locked-set-reviewer-id" not in source


def test_finance_frontend_does_not_request_human_identity() -> None:
    frontend = Path("frontend/src")
    active_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in frontend.rglob("*")
        if path.is_file() and path.suffix in {".ts", ".tsx"}
    )
    for forbidden in ("reviewer_id", "reviewerId", "operator_id", "operatorId"):
        assert forbidden not in active_source
