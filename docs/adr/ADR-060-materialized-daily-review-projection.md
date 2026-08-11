# ADR-060: Materialized daily review projection

## Context

The daily workspace previously placed records into the review list before OCR and final materialization had completed. It also used the label "complete" for both machine processing completion and business review completion. This made counts misleading and caused a manually corrected row to disappear without a clear destination.

## Decision

Daily records have three projection states:

- `pending_processing`: download, OCR or final materialization is incomplete; the record is visible only through job progress.
- `needs_review`: machine materialization is complete and at least one business field remains unresolved.
- `reviewed`: all fields are reliable machine observations or have been resolved by an effective manual revision, including an explicit decision to leave a field blank.

The production filters are `all`, `reviewed` and `needs_review`. `all` is exactly the union of the two visible terminal review states. The historical `complete` query is retained only as a read-compatible alias.

Manual corrections append revisions and never overwrite machine observations. When every unresolved field is supplied or explicitly cleared, the item moves from `needs_review` to `reviewed`. Evidence changes continue to invalidate only the affected revisions.

Chinese date-time editing uses separate numeric fields and non-editable unit labels. Loading time retains seconds; unloading time truncates seconds without rounding. Reliable platform direction dates, snapshot dates and the business date provide date-only prefill without inventing unknown time values.

## Consequences

- Business counts no longer include work that is still processing.
- A saved item has a predictable destination and remains immediately discoverable.
- Explicit blank values are auditable business decisions instead of missing form data.
- Existing machine evidence and historical `complete` consumers remain readable.
