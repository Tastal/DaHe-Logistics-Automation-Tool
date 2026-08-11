# ADR-063: Daily scope and identity reconciliation

Status: Superseded in part by ADR-066 for page-display total comparability.

## Context

Several August 8 snapshots contained 62 unique waybills while staff observed 68 for the same business day and location keyword. A syntactically valid platform response is not sufficient proof that the intended business scope was applied.

## Decision

New daily reads start at the real 14:00 business boundary and may retain only the next-day 14:30 candidate safety tail. The former 13:30 start is accepted solely for replaying sealed historical evidence and cannot create a new production snapshot. The daily connector lets the Chengfeng page produce the final authoritative query without pressing Reset first. It replaces only the validated business date, location and pagination fields, while bounded non-sensitive page-owned filter values remain private inside the browser worker. This preserves account- and page-scope values that Reset can replace with a narrower default. Each snapshot records only redacted completeness evidence: displayed total, response total, response page count, pages actually read, unique identity total, scope hash, completeness result and diagnostic code.

`scope_complete` is true only when the displayed, response and unique totals reconcile, the platform page count equals the pages actually read, pagination is complete and identities contain no duplicates. A mismatch returns an incomplete business read even when records were downloaded. It must not fall back to an older snapshot or cached 62-item result.

The reconciliation tool may compare identity sets and report missing waybill identities and the filtering stage that excluded them. Request bodies, cookies, signed URLs and raw responses remain worker-private.

## Consequences

- A plausible but incomplete platform result can no longer be presented as success.
- Page-owned business scope is preserved without exposing or interpreting its private values.
- Business staff receive an actionable count discrepancy instead of a cache fallback.
- Completeness evidence remains replayable without storing sensitive platform payloads.
