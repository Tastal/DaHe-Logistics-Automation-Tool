# ADR-051: Latest settlement workspace

## Decision

The freight-settlement workspace shows only the latest `settlement_capture` business result. A capture may materialize several internal OCR Jobs, but their durable idempotency links are aggregated by the backend into one projection. The business UI does not expose an audit-batch selector or a second start-audit action.

The latest capture is authoritative even when it is empty, cancelled, or partially failed. An empty capture produces an empty state. A partial capture shows only its atomically committed items and is labelled incomplete; the projection never falls back to an older complete capture. Older captures, internal Jobs, and existing review decisions remain immutable and queryable through history or diagnostics.

Every valid business waybill exposes `confirm_normal` and `confirm_problem`. A decision that already matches the current outcome is an idempotent no-op. Technical failures never become business review items.

## Consequences

- Business users see one fetch and one result instead of scheduler internals.
- The capture-to-OCR relationship must remain durable and replayable.
- A newly completed zero-result read intentionally replaces the previous visible list.
- Existing audit APIs remain for history and compatibility, but the production workspace does not call them.
