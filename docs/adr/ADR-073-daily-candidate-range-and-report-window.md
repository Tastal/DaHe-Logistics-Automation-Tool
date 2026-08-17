# ADR-073: Separate the daily candidate range from the report window

## Context

The Chengfeng candidate query is intentionally broader than the accounting report. Earlier releases treated every reconciled candidate as a report row. A production workbook for 2026-08-13 therefore contained 90 rows even though only 82 effective loading times fell in the required 24-hour window. Narrowing the captured snapshot would damage completeness evidence and make later review impossible.

## Decision

Each new daily task freezes a versioned candidate range. Its default is the selected business date at 14:00 through the server time at task start. An operator may instead choose a fixed end on day zero or day one. A range that does not cover the complete report window is allowed with a visible warning because it can be useful for a partial read, but its frozen bounds remain part of the task snapshot.

The formal workbook independently applies `[business date 14:00, next day 14:00)`. Effective loading time uses a valid manual revision first, then a loading-ticket OCR value. Platform time never determines inclusion. A manually confirmed blank loading time may be included with a blank workbook cell; an unconfirmed missing loading time blocks report generation. ADR-075 defines the only remaining platform-time use: an in-memory sort key when both business times are blank.

Report creation returns candidate, included, outside-window and missing-effective-time counts. Filtering occurs only in the report projection and never mutates the reconciled candidate snapshot, observation, OCR evidence or manual history.

## Consequences

- Candidate completeness and accounting scope have separate, inspectable contracts.
- Historical tasks remain reproducible because their frozen query bounds are retained.
- Platform evidence cannot silently keep or remove a report row.
- ADR-064 remains authoritative for capture identity reconciliation but no longer requires every candidate to become a report row.
