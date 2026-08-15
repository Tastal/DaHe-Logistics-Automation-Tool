# ADR-073: Separate the daily candidate range from the report window

## Context

The Chengfeng candidate query is intentionally broader than the accounting report. Earlier releases treated every reconciled candidate as a report row. A production workbook for 2026-08-13 therefore contained 90 rows even though only 82 effective loading times fell in the required 24-hour window. Narrowing the captured snapshot would damage completeness evidence and make later review impossible.

## Decision

Each new daily task freezes a versioned candidate range. Its default is the selected business date at 14:00 through the server time at task start. An operator may instead choose a fixed end on day zero or day one. A range that does not cover the complete report window is allowed with a visible warning because it can be useful for a partial read, but its frozen bounds remain part of the task snapshot.

The formal workbook independently applies `[business date 14:00, next day 14:00)`. Effective loading time uses a valid manual revision first, then a loading-ticket OCR value. Only when the image value is absent may the platform loading time determine inclusion and ordering; that fallback must not be written into the workbook's loading-time cell. A record with neither time remains in local review data and is excluded from the workbook.

Report creation returns candidate, included, outside-window and missing-effective-time counts. Filtering occurs only in the report projection and never mutates the reconciled candidate snapshot, observation, OCR evidence or manual history.

## Consequences

- Candidate completeness and accounting scope have separate, inspectable contracts.
- Historical tasks remain reproducible because their frozen query bounds are retained.
- Platform fallback can keep a row in the correct report without pretending that the ticket supplied a time.
- ADR-064 remains authoritative for capture identity reconciliation but no longer requires every candidate to become a report row.
